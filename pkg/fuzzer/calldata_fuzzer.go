package fuzzer

import (
	"autopath/pkg/simulator"
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// CallFrame 调用帧结构 (从 monitor 包复制以避免循环导入)
type CallFrame struct {
	Type    string      `json:"type"`
	From    string      `json:"from"`
	To      string      `json:"to"`
	Value   string      `json:"value"`
	Gas     string      `json:"gas"`
	GasUsed string      `json:"gasUsed"`
	Input   string      `json:"input"`
	Output  string      `json:"output"`
	Error   string      `json:"error"`
	Calls   []CallFrame `json:"calls"`
}

// ContractJumpDest 合约维度的 JUMPDEST (从 simulator 包复制以避免循环导入)
type ContractJumpDest struct {
	Contract string `json:"contract"` // 合约地址
	PC       uint64 `json:"pc"`       // 程序计数器
}

// TransactionTracer 交易追踪器 (从 monitor 包复制以避免循环导入)
type TransactionTracer struct {
	rpcClient *rpc.Client
}

// NewTransactionTracer 创建交易追踪器
func NewTransactionTracer(rpcClient *rpc.Client) *TransactionTracer {
	return &TransactionTracer{
		rpcClient: rpcClient,
	}
}

// TraceTransaction 追踪交易
func (t *TransactionTracer) TraceTransaction(txHash common.Hash) (*CallFrame, error) {
	var result CallFrame

	err := t.rpcClient.Call(&result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": "callTracer",
		"tracerConfig": map[string]interface{}{
			"onlyTopCall": false,
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to trace transaction %s: %w", txHash.Hex(), err)
	}

	return &result, nil
}

// CallDataFuzzer 主控制器
type CallDataFuzzer struct {
	// 核心组件
	simulator  *simulator.EVMSimulator
	parser     *ABIParser
	generator  *ParamGenerator
	comparator *PathComparator
	merger     *ResultMerger
	tracer     *TransactionTracer

	// 配置
	threshold  float64
	maxWorkers int
	timeout    time.Duration

	// 客户端
	client    *ethclient.Client
	rpcClient *rpc.Client

	// 统计
	stats *FuzzerStats

	// 不变量评估器（新增）
	invariantEvaluator   InvariantEvaluator // 通过接口避免循环依赖
	enableInvariantCheck bool               // 是否启用不变量检查
}

// NewCallDataFuzzer 创建模糊测试器
func NewCallDataFuzzer(config *Config) (*CallDataFuzzer, error) {
	// 创建EVM模拟器
	sim, err := simulator.NewEVMSimulator(config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create simulator: %w", err)
	}

	// 创建RPC客户端
	rpcClient, err := rpc.Dial(config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	// 创建以太坊客户端
	client, err := ethclient.Dial(config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ethereum: %w", err)
	}

	// 创建参数生成器
	var gen *ParamGenerator
	if config.Strategies.Integers.IncludeBoundaries {
		gen = NewParamGeneratorWithStrategy(config.MaxVariations, &config.Strategies)
	} else {
		gen = NewParamGenerator(config.MaxVariations)
	}

	return &CallDataFuzzer{
		simulator:            sim,
		parser:               NewABIParser(),
		generator:            gen,
		comparator:           NewPathComparator(),
		merger:               NewResultMerger(),
		tracer:               NewTransactionTracer(rpcClient),
		threshold:            config.Threshold,
		maxWorkers:           config.Workers,
		timeout:              config.Timeout,
		client:               client,
		rpcClient:            rpcClient,
		stats:                &FuzzerStats{StartTime: time.Now()},
		invariantEvaluator:   &EmptyInvariantEvaluator{}, // 默认使用空实现
		enableInvariantCheck: config.InvariantCheck.Enabled,
	}, nil
}

// extractProtectedContractCalls 从trace中提取调用受保护合约的call frame
func (f *CallDataFuzzer) extractProtectedContractCalls(
	trace *CallFrame,
	targetContract common.Address,
) []*CallFrame {
	var calls []*CallFrame
	targetAddr := strings.ToLower(targetContract.Hex())

	// 递归遍历调用树
	var walk func(frame *CallFrame)
	walk = func(frame *CallFrame) {
		// 检查当前调用是否是调用目标合约
		if strings.ToLower(frame.To) == targetAddr {
			calls = append(calls, frame)
		}

		// 递归处理子调用
		for i := range frame.Calls {
			walk(&frame.Calls[i])
		}
	}

	walk(trace)
	return calls
}

// FuzzTransaction 对交易进行模糊测试
func (f *CallDataFuzzer) FuzzTransaction(
	ctx context.Context,
	txHash common.Hash,
	contractAddr common.Address,
	blockNumber uint64,
) (*AttackParameterReport, error) {
	startTime := time.Now()
	f.stats.StartTime = startTime

	// 步骤1: 获取原始交易信息和执行路径（传入受保护合约地址）
	log.Printf("[Fuzzer] Fetching original transaction: %s", txHash.Hex())
	_, originalPath, stateOverride, err := f.getOriginalExecution(ctx, txHash, blockNumber, contractAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get original execution: %w", err)
	}
	log.Printf("[Fuzzer] Original path has %d JUMPDESTs (total), %d ContractJumpDests, protected start index: %d",
		len(originalPath.JumpDests), len(originalPath.ContractJumpDests), originalPath.ProtectedStartIndex)

	// 步骤1.5: 追踪交易获取调用树
	log.Printf("[Fuzzer] Tracing transaction to extract call tree...")
	trace, err := f.tracer.TraceTransaction(txHash)
	if err != nil {
		return nil, fmt.Errorf("failed to trace transaction: %w", err)
	}

	// 步骤2: 从调用树中提取调用受保护合约的call
	log.Printf("[Fuzzer] Extracting calls to protected contract %s", contractAddr.Hex())
	protectedCalls := f.extractProtectedContractCalls(trace, contractAddr)
	if len(protectedCalls) == 0 {
		return nil, fmt.Errorf("no calls to protected contract %s found in transaction", contractAddr.Hex())
	}
	log.Printf("[Fuzzer] Found %d calls to protected contract", len(protectedCalls))

	// 选择第一个调用作为fuzzing目标（后续可优化为选择策略）
	targetCall := protectedCalls[0]
	log.Printf("[Fuzzer] Target call: from=%s, input=%s", targetCall.From, targetCall.Input[:10])

	// 步骤3: 解析受保护合约调用的calldata
	callDataBytes, err := hexutil.Decode(targetCall.Input)
	if err != nil {
		return nil, fmt.Errorf("failed to decode target call input: %w", err)
	}
	log.Printf("[Fuzzer] Parsing protected contract calldata (%d bytes)", len(callDataBytes))

	parsedData, err := f.parser.ParseCallData(callDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse protected contract calldata: %w", err)
	}
	log.Printf("[Fuzzer] Parsed: selector=0x%s, %d parameters", hex.EncodeToString(parsedData.Selector), len(parsedData.Parameters))

	// 步骤4: 生成参数组合
	log.Printf("[Fuzzer] Generating parameter combinations...")
	combinations := f.generator.GenerateCombinations(parsedData.Parameters)

	// 步骤5: 并发执行模糊测试
	log.Printf("[Fuzzer] Starting fuzzing with %d workers, threshold: %.2f", f.maxWorkers, f.threshold)
	results := f.executeFuzzing(ctx, combinations, parsedData.Selector, originalPath, targetCall, contractAddr, blockNumber, stateOverride)
	log.Printf("[Fuzzer] Found %d valid combinations", len(results))

	// 步骤5: 生成报告
	log.Printf("[Fuzzer] Generating report...")
	report := f.merger.MergeResults(
		results,
		contractAddr,
		parsedData.Selector,
		txHash,
		blockNumber,
		startTime,
	)

	// 附带高相似度结果样本（按相似度排序，最多100条）
	if len(results) > 0 {
		sorted := make([]FuzzingResult, len(results))
		copy(sorted, results)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i].Similarity > sorted[j].Similarity })
		if len(sorted) > 100 {
			sorted = sorted[:100]
		}
		report.HighSimilarityResults = ToPublicResults(sorted)
	}

	// 更新统计
	f.stats.EndTime = time.Now()
	f.stats.ValidCombinations = len(results)

	log.Printf("[Fuzzer] Fuzzing completed in %v", f.stats.EndTime.Sub(f.stats.StartTime))

	return report, nil
}

// getOriginalExecution 获取原始交易的执行路径
func (f *CallDataFuzzer) getOriginalExecution(ctx context.Context, txHash common.Hash, blockNumber uint64, contractAddr common.Address) (*types.Transaction, *simulator.ReplayResult, simulator.StateOverride, error) {
	// 获取交易
	tx, _, err := f.client.TransactionByHash(ctx, txHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get transaction: %w", err)
	}

	// 获取执行路径，传入受保护合约地址
	result, err := f.simulator.ForkAndReplay(ctx, blockNumber, txHash, contractAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to replay transaction: %w", err)
	}

	override, err := f.simulator.BuildStateOverride(ctx, txHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build state override: %w", err)
	}

	return tx, result, override, nil
}

// executeFuzzing 执行模糊测试
func (f *CallDataFuzzer) executeFuzzing(
	ctx context.Context,
	combinations <-chan []interface{},
	selector []byte,
	originalPath *simulator.ReplayResult,
	targetCall *CallFrame,
	contractAddr common.Address,
	blockNumber uint64,
	stateOverride simulator.StateOverride,
) []FuzzingResult {
	// 结果收集
	results := []FuzzingResult{}
	resultMutex := &sync.Mutex{}

	// 统计
	var testedCount int32
	var validCount int32

	// 创建worker池
	var wg sync.WaitGroup
	workerChan := make(chan []interface{}, f.maxWorkers*2)

	// 启动workers
	for i := 0; i < f.maxWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			f.worker(
				ctx,
				workerID,
				workerChan,
				selector,
				originalPath,
				targetCall,
				contractAddr,
				blockNumber,
				stateOverride,
				&results,
				resultMutex,
				&testedCount,
				&validCount,
			)
		}(i)
	}

	// 分发任务
	go func() {
		for combo := range combinations {
			select {
			case workerChan <- combo:
			case <-ctx.Done():
				close(workerChan)
				return
			}
		}
		close(workerChan)
	}()

	// 等待完成
	wg.Wait()

	// 更新统计
	f.stats.TestedCombinations = int(testedCount)
	f.stats.ValidCombinations = int(validCount)

	log.Printf("[Fuzzer] Tested %d combinations, found %d valid", testedCount, validCount)

	return results
}

// worker 工作协程
func (f *CallDataFuzzer) worker(
	ctx context.Context,
	workerID int,
	combinations <-chan []interface{},
	selector []byte,
	originalPath *simulator.ReplayResult,
	targetCall *CallFrame,
	contractAddr common.Address,
	blockNumber uint64,
	stateOverride simulator.StateOverride,
	results *[]FuzzingResult,
	resultMutex *sync.Mutex,
	testedCount *int32,
	validCount *int32,
) {
	for combo := range combinations {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 增加测试计数
		atomic.AddInt32(testedCount, 1)

		// 重构calldata（使用受保护合约调用的selector和变异参数）
		newCallData, err := f.parser.ReconstructCallData(selector, combo)
		if err != nil {
			log.Printf("[Worker %d] Failed to reconstruct calldata: %v", workerID, err)
			continue
		}

		// 创建模拟请求：直接模拟调用受保护合约
		from := common.HexToAddress(targetCall.From) // 使用原始调用者地址

		// 解析value（如果有）
		value := big.NewInt(0)
		if targetCall.Value != "" && targetCall.Value != "0x0" {
			if v, err := hexutil.DecodeBig(targetCall.Value); err == nil {
				value = v
			}
		}

		simReq := &SimulationRequest{
			From:          from,         // 原始调用者
			To:            contractAddr, // 受保护合约
			CallData:      newCallData,  // 变异后的calldata
			Value:         value,        // 原始调用的value
			BlockNumber:   blockNumber,
			Timeout:       f.timeout,
			StateOverride: stateOverride,
		}

		// 执行模拟
		simResult := f.simulateExecution(ctx, simReq, workerID)
		if simResult == nil {
			continue
		}

		// 比较路径相似度 - 使用带合约地址的 JUMPDEST 序列
		// 需要将 simulator.ContractJumpDest 转换为 fuzzer.ContractJumpDest
		origContractJumpDests := make([]ContractJumpDest, len(originalPath.ContractJumpDests))
		for i, cjd := range originalPath.ContractJumpDests {
			origContractJumpDests[i] = ContractJumpDest{
				Contract: cjd.Contract,
				PC:       cjd.PC,
			}
		}

		similarity := f.comparator.CompareContractJumpDests(
			origContractJumpDests,
			simResult.ContractJumpDests,
			originalPath.ProtectedStartIndex,
		)

		// 如果相似度超过阈值，进行后续检查
		if similarity >= f.threshold {
			// 如果启用了不变量检查,先进行不变量验证
			var violations []interface{}
			if f.enableInvariantCheck && f.invariantEvaluator != nil {
				// 转换状态为ChainState格式
				chainState := ConvertToChainStateFromSimResult(
					simResult,
					blockNumber,
					common.Hash{}, // worker中使用零哈希,因为是模拟交易
				)

				// 执行不变量评估
				violations = f.invariantEvaluator.EvaluateTransaction(
					[]common.Address{contractAddr},
					chainState,
				)

				// 如果没有不变量违规,跳过此参数组合
				if len(violations) == 0 {
					// 路径相似但未打破不变量，不记录
					continue
				}
			}

			// 通过路径相似度检查(以及可选的不变量检查),记录结果
			atomic.AddInt32(validCount, 1)

			// 创建参数值列表
			paramValues := f.extractParameterValues(combo, selector)

			result := FuzzingResult{
				CallData:            newCallData,
				Parameters:          paramValues,
				Similarity:          similarity,
				JumpDests:           simResult.JumpDests,
				GasUsed:             simResult.GasUsed,
				Success:             simResult.Success,
				InvariantViolations: violations, // 记录违规信息
				StateChanges:        simResult.StateChanges,
			}

			// 线程安全地添加结果
			resultMutex.Lock()
			*results = append(*results, result)
			resultMutex.Unlock()

			if int(atomic.LoadInt32(validCount))%10 == 0 {
				log.Printf("[Worker %d] Found valid combination #%d with similarity %.4f (violations: %d)",
					workerID, atomic.LoadInt32(validCount), similarity, len(violations))
			}
		}
	}
}

// simulateExecution 执行单个模拟
func (f *CallDataFuzzer) simulateExecution(ctx context.Context, req *SimulationRequest, workerID int) *SimulationResult {
	// 创建带超时的context
	simCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	// 调用simulator执行
	result, err := f.simulator.SimulateWithCallData(
		simCtx,
		req.From,
		req.To,
		req.CallData,
		req.Value,
		req.BlockNumber,
		req.StateOverride,
	)

	if err != nil {
		// 记录错误但继续
		if err.Error() != "execution reverted" {
			// 只记录非revert错误
			if f.stats.FailedSimulations < 100 { // 限制日志数量
				log.Printf("[Worker %d] Simulation failed: %v", workerID, err)
			}
		}
		f.stats.FailedSimulations++
		return nil
	}

	// 需要将 simulator.ContractJumpDest 转换为 fuzzer.ContractJumpDest
	contractJumpDests := make([]ContractJumpDest, len(result.ContractJumpDests))
	for i, cjd := range result.ContractJumpDests {
		contractJumpDests[i] = ContractJumpDest{
			Contract: cjd.Contract,
			PC:       cjd.PC,
		}
	}

	// 转换状态变更信息
	stateChanges := make(map[string]StateChange, len(result.StateChanges))
	for addr, change := range result.StateChanges {
		storageChanges := make(map[string]StorageUpdate, len(change.StorageChanges))
		for slot, update := range change.StorageChanges {
			storageChanges[slot] = StorageUpdate{
				Before: update.Before,
				After:  update.After,
			}
		}
		stateChanges[addr] = StateChange{
			BalanceBefore:  change.BalanceBefore,
			BalanceAfter:   change.BalanceAfter,
			StorageChanges: storageChanges,
		}
	}

	return &SimulationResult{
		Success:           result.Success,
		JumpDests:         result.JumpDests,
		ContractJumpDests: contractJumpDests,
		GasUsed:           result.GasUsed,
		StateChanges:      stateChanges,
	}
}

// extractParameterValues 提取参数值
func (f *CallDataFuzzer) extractParameterValues(combo []interface{}, selector []byte) []ParameterValue {
	values := make([]ParameterValue, len(combo))

	for i, val := range combo {
		values[i] = ParameterValue{
			Index:   i,
			Type:    f.detectType(val),
			Value:   val,
			IsRange: false,
		}
	}

	return values
}

// detectType 检测值的类型
func (f *CallDataFuzzer) detectType(value interface{}) string {
	switch value.(type) {
	case *big.Int:
		return "uint256"
	case common.Address:
		return "address"
	case bool:
		return "bool"
	case []byte:
		return "bytes"
	case string:
		return "string"
	default:
		return "unknown"
	}
}

// GetStats 获取统计信息
func (f *CallDataFuzzer) GetStats() *FuzzerStats {
	return f.stats
}

// 注意：不在此处为 simulator.EVMSimulator 声明跨包方法，直接使用 simulator 包内已实现的方法。
