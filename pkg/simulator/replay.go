package simulator

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// EVMSimulator EVM模拟器（简化版本）
type EVMSimulator struct {
	client    *ethclient.Client
	rpcClient *rpc.Client
}

// NewEVMSimulator 创建EVM模拟器
func NewEVMSimulator(rpcURL string) (*EVMSimulator, error) {
	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	client := ethclient.NewClient(rpcClient)

	return &EVMSimulator{
		client:    client,
		rpcClient: rpcClient,
	}, nil
}

// ContractJumpDest 合约维度的 JUMPDEST
type ContractJumpDest struct {
	Contract string `json:"contract"` // 合约地址
	PC       uint64 `json:"pc"`       // 程序计数器
}

// ReplayResult 重放结果
type ReplayResult struct {
	Success             bool                   `json:"success"`
	GasUsed             uint64                 `json:"gas_used"`
	ReturnData          string                 `json:"return_data"`
	Logs                []Log                  `json:"logs"`
	StateChanges        map[string]StateChange `json:"state_changes"`
	JumpDests           []uint64               `json:"jump_dests"`            // 保留向后兼容
	ContractJumpDests   []ContractJumpDest     `json:"contract_jump_dests"`   // 新增：带合约地址的路径
	ProtectedStartIndex int                    `json:"protected_start_index"` // 新增：受保护合约开始索引
	ProtectedEndIndex   int                    `json:"protected_end_index"`   // 新增：受保护合约结束索引
	ExecutionPath       []PathStep             `json:"execution_path"`
	Error               string                 `json:"error,omitempty"`
}

// Log 日志
type Log struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    string         `json:"data"`
}

// StorageUpdate 存储槽位的前后状态
type StorageUpdate struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// StateChange 状态变化
type StateChange struct {
	BalanceBefore  string                   `json:"balance_before"`
	BalanceAfter   string                   `json:"balance_after"`
	StorageChanges map[string]StorageUpdate `json:"storage_changes"`
}

// PathStep 执行路径步骤
type PathStep struct {
	PC       uint64         `json:"pc"`       // 程序计数器
	Op       string         `json:"op"`       // 操作码
	Gas      uint64         `json:"gas"`      // 剩余Gas
	GasCost  uint64         `json:"gas_cost"` // Gas消耗
	Depth    int            `json:"depth"`    // 调用深度
	Stack    []string       `json:"stack"`    // 栈内容（简化）
	Memory   string         `json:"memory"`   // 内存内容（简化）
	Contract common.Address `json:"contract"` // 当前合约地址
}

// ForkAndReplay Fork状态并重放交易
func (s *EVMSimulator) ForkAndReplay(ctx context.Context, blockNumber uint64, txHash common.Hash, protectedContract common.Address) (*ReplayResult, error) {
	// 使用 debug_traceTransaction 获取执行轨迹
	result, err := s.traceTransactionWithCustomTracer(txHash, protectedContract)
	if err != nil {
		// 兼容不支持JS Tracer的节点（如某些 anvil 版本）
		if strings.Contains(err.Error(), "unsupported tracer type") || strings.Contains(err.Error(), "unsupported tracer") {
			// 回退到 callTracer，并使用伪 JumpDests 表示调用序列
			return s.traceTransactionWithCallTracer(txHash)
		}
		return nil, fmt.Errorf("failed to trace transaction: %w", err)
	}

	return result, nil
}

// traceTransactionWithCustomTracer 使用自定义追踪器追踪交易
func (s *EVMSimulator) traceTransactionWithCustomTracer(txHash common.Hash, protectedContract common.Address) (*ReplayResult, error) {
	recordAll := protectedContract == (common.Address{})
	protectedAddr := ""
	if !recordAll {
		protectedAddr = strings.ToLower(protectedContract.Hex())
	}

	tracerCode := fmt.Sprintf(`{
		data: {
			jumpDests: [],
			contractJumpDests: [],
			protectedContract: "%s",
			recordingStarted: false,
			recordAll: %t,
			protectedStartIndex: -1,
			protectedEndIndex: -1,
			executionPath: [],
			stateChanges: {},
			logs: [],
			gasUsed: 0,
			success: true,
			returnData: ""
		},
		formatHex: function(value) {
			var hex = toHex(value);
			if (hex === "0x") {
				return "0x0";
			}
			var body = hex.slice(2);
			if (body.length === 0) {
				return "0x0";
			}
			if (body.length %% 2 === 1) {
				body = "0" + body;
			}
			return "0x" + body;
		},
		formatWord: function(value) {
			var body = this.formatHex(value).slice(2);
			while (body.length < 64) {
				body = "0" + body;
			}
			if (body.length > 64) {
				body = body.slice(body.length - 64);
			}
			return "0x" + body;
		},
		fault: function(log, db) {
			this.data.success = false;
			this.data.error = log.getError();
		},
		step: function(log, db) {
			var currentContract = toHex(log.contract.getAddress());
			var currentLower = currentContract.toLowerCase();

			if (this.data.recordAll && this.data.protectedStartIndex === -1) {
				this.data.protectedStartIndex = 0;
			}

			if (!this.data.recordAll && this.data.protectedContract !== "" && currentLower === this.data.protectedContract) {
				if (!this.data.recordingStarted) {
					this.data.recordingStarted = true;
					if (this.data.protectedStartIndex === -1) {
						this.data.protectedStartIndex = this.data.contractJumpDests.length;
					}
				}
			}

			var shouldRecord = this.data.recordAll || this.data.recordingStarted;
			if (!shouldRecord) {
				return;
			}

			if (log.op.toString() === "JUMPDEST") {
				this.data.jumpDests.push(log.getPC());
				this.data.contractJumpDests.push({
					contract: currentContract,
					pc: log.getPC()
				});
			}

			var step = {
				pc: log.getPC(),
				op: log.op.toString(),
				gas: log.getGas(),
				gasCost: log.getCost(),
				depth: log.getDepth(),
				stack: [],
				memory: "",
				contract: currentContract
			};

			var stackLength = log.stack.length();
			for (var i = 0; i < Math.min(3, stackLength); i++) {
				step.stack.push(this.formatWord(log.stack.peek(i)));
			}

			this.data.executionPath.push(step);

			if (log.op.toString() === "SSTORE") {
				var addrKey = currentLower;
				if (!this.data.stateChanges[addrKey]) {
					var balance = this.formatHex(db.getBalance(log.contract.getAddress()));
					this.data.stateChanges[addrKey] = {
						address: currentContract,
						balanceBefore: balance,
						balanceAfter: balance,
						storageChanges: {}
					};
				}
				var state = this.data.stateChanges[addrKey];
				var slotKey = this.formatWord(log.stack.peek(0));
				var newValue = this.formatWord(log.stack.peek(1));
				var previousValue = db.getState(log.contract.getAddress(), log.stack.peek(0));
				var formattedPrev = previousValue ? this.formatWord(previousValue) : "0x0";
				state.storageChanges[slotKey] = {
					before: formattedPrev,
					after: newValue
				};
				state.balanceAfter = this.formatHex(db.getBalance(log.contract.getAddress()));
			}
		},
		result: function(ctx, db) {
			this.data.gasUsed = ctx.gasUsed;
			if (ctx.type === "REVERT") {
				this.data.success = false;
			}
			this.data.returnData = toHex(ctx.output);

			if (this.data.recordingStarted && this.data.protectedEndIndex === -1) {
				this.data.protectedEndIndex = this.data.contractJumpDests.length;
			}

			if (this.data.protectedEndIndex === -1) {
				this.data.protectedEndIndex = this.data.contractJumpDests.length;
			}
			if (this.data.recordAll && this.data.protectedStartIndex === -1) {
				this.data.protectedStartIndex = 0;
			}

			this.data.logs = [];
			var logs = ctx.logs || [];
			for (var i = 0; i < logs.length; i++) {
				var entry = logs[i];
				var topics = [];
				if (entry.topics) {
					for (var j = 0; j < entry.topics.length; j++) {
						var topicValue = entry.topics[j];
						if (typeof topicValue === "string") {
							topics.push(topicValue.toLowerCase());
						} else {
							topics.push(this.formatWord(topicValue));
						}
					}
				}
				var logData = entry.data;
				if (typeof logData === "string") {
					logData = logData.toLowerCase();
				} else {
					logData = this.formatHex(logData);
				}
				var addressValue = entry.address;
				if (typeof addressValue !== "string") {
					addressValue = toHex(addressValue);
				}
				this.data.logs.push({
					address: addressValue.toLowerCase(),
					topics: topics,
					data: logData
				});
			}

			return this.data;
		}
	}`, protectedAddr, recordAll)

	var result json.RawMessage
	err := s.rpcClient.Call(&result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": tracerCode,
	})

	if err != nil {
		return nil, err
	}

	// 解析结果（注意：JS tracer 返回为驼峰命名）
	var raw struct {
		Success             bool               `json:"success"`
		GasUsed             uint64             `json:"gasUsed"`
		ReturnData          string             `json:"returnData"`
		Error               string             `json:"error,omitempty"`
		JumpDests           []uint64           `json:"jumpDests"`
		ContractJumpDests   []ContractJumpDest `json:"contractJumpDests"`
		ProtectedStartIndex int                `json:"protectedStartIndex"`
		ProtectedEndIndex   int                `json:"protectedEndIndex"`
		ExecutionPath       []PathStep         `json:"executionPath"`
		StateChanges        map[string]struct {
			BalanceBefore  string `json:"balanceBefore"`
			BalanceAfter   string `json:"balanceAfter"`
			StorageChanges map[string]struct {
				Before string `json:"before"`
				After  string `json:"after"`
			} `json:"storageChanges"`
		} `json:"stateChanges"`
		Logs []Log `json:"logs"`
	}
	if err := json.Unmarshal(result, &raw); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trace result: %w", err)
	}

	// 若 jumpDests 为空但有执行路径，做一次兜底提取
	jumpDests := raw.JumpDests
	if len(jumpDests) == 0 && len(raw.ExecutionPath) > 0 {
		for _, s := range raw.ExecutionPath {
			if s.Op == "JUMPDEST" {
				jumpDests = append(jumpDests, s.PC)
			}
		}
	}
	if len(jumpDests) == 0 && len(raw.ExecutionPath) > 0 {
		for _, s := range raw.ExecutionPath {
			jumpDests = append(jumpDests, s.PC)
		}
	}

	contractJumpDests := raw.ContractJumpDests
	if len(contractJumpDests) == 0 && len(raw.ExecutionPath) > 0 {
		for _, s := range raw.ExecutionPath {
			contractJumpDests = append(contractJumpDests, ContractJumpDest{
				Contract: s.Contract.Hex(),
				PC:       s.PC,
			})
		}
	}

	stateChanges := make(map[string]StateChange, len(raw.StateChanges))
	for addr, change := range raw.StateChanges {
		updates := make(map[string]StorageUpdate, len(change.StorageChanges))
		for slot, diff := range change.StorageChanges {
			updates[slot] = StorageUpdate{
				Before: diff.Before,
				After:  diff.After,
			}
		}
		stateChanges[addr] = StateChange{
			BalanceBefore:  change.BalanceBefore,
			BalanceAfter:   change.BalanceAfter,
			StorageChanges: updates,
		}
	}

	replay := &ReplayResult{
		Success:             raw.Success,
		GasUsed:             raw.GasUsed,
		ReturnData:          raw.ReturnData,
		JumpDests:           jumpDests,
		ContractJumpDests:   contractJumpDests,
		ProtectedStartIndex: raw.ProtectedStartIndex,
		ProtectedEndIndex:   raw.ProtectedEndIndex,
		ExecutionPath:       raw.ExecutionPath,
		StateChanges:        stateChanges,
		Logs:                raw.Logs,
		Error:               raw.Error,
	}
	return replay, nil
}

// SimulateTransaction 模拟交易执行
func (s *EVMSimulator) SimulateTransaction(ctx context.Context, from common.Address, to common.Address, data []byte, value *big.Int, blockNumber uint64) (*SimulateResult, error) {
	// 构建调用参数
	msg := map[string]interface{}{
		"from": from,
		"to":   to,
		"data": common.Bytes2Hex(data),
	}

	if value != nil {
		msg["value"] = fmt.Sprintf("0x%x", value)
	}

	// 使用 eth_call 模拟执行
	var result string
	err := s.rpcClient.Call(&result, "eth_call", msg, fmt.Sprintf("0x%x", blockNumber))

	if err != nil {
		return nil, err
	}

	return &SimulateResult{
		Success:    err == nil,
		ReturnData: result,
	}, nil
}

// SimulateResult 模拟结果
type SimulateResult struct {
	Success    bool   `json:"success"`
	ReturnData string `json:"return_data"`
	Error      string `json:"error,omitempty"`
}

// PathAnalyzer 路径分析器
type PathAnalyzer struct {
	paths map[common.Hash]*ReplayResult // 交易哈希 -> 执行结果
}

// NewPathAnalyzer 创建路径分析器
func NewPathAnalyzer() *PathAnalyzer {
	return &PathAnalyzer{
		paths: make(map[common.Hash]*ReplayResult),
	}
}

// StorePath 存储路径
func (a *PathAnalyzer) StorePath(txHash common.Hash, result *ReplayResult) {
	a.paths[txHash] = result
}

// GetPath 获取路径
func (a *PathAnalyzer) GetPath(txHash common.Hash) (*ReplayResult, bool) {
	result, exists := a.paths[txHash]
	return result, exists
}

// AnalyzePath 分析路径特征
func (a *PathAnalyzer) AnalyzePath(result *ReplayResult) *PathAnalysis {
	analysis := &PathAnalysis{
		TotalSteps:       len(result.ExecutionPath),
		UniqueOpcodes:    make(map[string]int),
		MaxDepth:         0,
		TotalGasUsed:     result.GasUsed,
		JumpDestCount:    len(result.JumpDests),
		StateChangeCount: len(result.StateChanges),
	}

	for _, step := range result.ExecutionPath {
		analysis.UniqueOpcodes[step.Op]++

		if step.Depth > analysis.MaxDepth {
			analysis.MaxDepth = step.Depth
		}
	}

	// 识别常见模式
	analysis.Patterns = a.identifyPatterns(result.ExecutionPath)

	return analysis
}

// PathAnalysis 路径分析结果
type PathAnalysis struct {
	TotalSteps       int            `json:"total_steps"`
	UniqueOpcodes    map[string]int `json:"unique_opcodes"`
	MaxDepth         int            `json:"max_depth"`
	TotalGasUsed     uint64         `json:"total_gas_used"`
	JumpDestCount    int            `json:"jump_dest_count"`
	StateChangeCount int            `json:"state_change_count"`
	Patterns         []string       `json:"patterns"`
}

// identifyPatterns 识别执行模式
func (a *PathAnalyzer) identifyPatterns(path []PathStep) []string {
	var patterns []string

	// 检查是否有循环模式
	if a.hasLoopPattern(path) {
		patterns = append(patterns, "LOOP_DETECTED")
	}

	// 检查是否有递归调用
	if a.hasRecursivePattern(path) {
		patterns = append(patterns, "RECURSIVE_CALL")
	}

	// 检查是否有大量存储操作
	sstoreCount := 0
	for _, step := range path {
		if step.Op == "SSTORE" {
			sstoreCount++
		}
	}
	if sstoreCount > 10 {
		patterns = append(patterns, "HEAVY_STORAGE_OPS")
	}

	// 检查是否有外部调用
	for _, step := range path {
		if step.Op == "CALL" || step.Op == "DELEGATECALL" || step.Op == "STATICCALL" {
			patterns = append(patterns, "EXTERNAL_CALLS")
			break
		}
	}

	return patterns
}

// hasLoopPattern 检测循环模式
func (a *PathAnalyzer) hasLoopPattern(path []PathStep) bool {
	// 简化的循环检测：查找重复的PC序列
	if len(path) < 10 {
		return false
	}

	pcSequence := make([]uint64, 0)
	for _, step := range path {
		if step.Op == "JUMPDEST" {
			pcSequence = append(pcSequence, step.PC)
		}
	}

	// 查找重复序列
	for i := 0; i < len(pcSequence)/2; i++ {
		for j := i + 1; j < len(pcSequence); j++ {
			if pcSequence[i] == pcSequence[j] {
				// 发现重复的JUMPDEST
				return true
			}
		}
	}

	return false
}

// hasRecursivePattern 检测递归模式
func (a *PathAnalyzer) hasRecursivePattern(path []PathStep) bool {
	maxDepth := 0
	for _, step := range path {
		if step.Depth > maxDepth {
			maxDepth = step.Depth
		}
	}
	return maxDepth > 3 // 深度超过3可能是递归
}

// ComparePaths 比较两个执行结果的JUMPDEST序列相似度（基于LCS）
func (a *PathAnalyzer) ComparePaths(r1, r2 *ReplayResult) float64 {
	if r1 == nil || r2 == nil {
		return 0.0
	}
	seq1 := r1.JumpDests
	seq2 := r2.JumpDests
	if len(seq1) == 0 && len(seq2) == 0 {
		return 1.0
	}
	if len(seq1) == 0 || len(seq2) == 0 {
		return 0.0
	}
	lcs := lcsLength(seq1, seq2)
	return (2.0 * float64(lcs)) / float64(len(seq1)+len(seq2))
}

// lcsLength 计算两个uint64序列的最长公共子序列长度
func lcsLength(aSeq, bSeq []uint64) int {
	m, n := len(aSeq), len(bSeq)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if aSeq[i-1] == bSeq[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] >= dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}
	return dp[m][n]
}

// GetRpcClient 获取RPC客户端
func (s *EVMSimulator) GetRpcClient() *rpc.Client {
	return s.rpcClient
}

// SimulateWithCallData 使用自定义calldata模拟交易执行
// 这个方法专门为模糊测试设计，返回带合约地址的JUMPDEST序列
func (s *EVMSimulator) SimulateWithCallData(
	ctx context.Context,
	from common.Address,
	to common.Address,
	callData []byte,
	value *big.Int,
	blockNumber uint64,
	override StateOverride,
) (*ReplayResult, error) {
	// 使用自定义tracer记录带合约地址的JUMPDEST
	tracerCode := `{
		data: {
			jumpDests: [],
			contractJumpDests: [],
			gasUsed: 0,
			success: true,
			returnData: ""
		},
		fault: function(log, db) {
			this.data.success = false;
			if (log.getError) {
				this.data.error = log.getError();
			}
		},
		step: function(log, db) {
			var currentContract = toHex(log.contract.getAddress());

			// 记录JUMPDEST操作码
			if (log.op.toString() === "JUMPDEST") {
				// 旧格式（向后兼容）
				this.data.jumpDests.push(log.getPC());

				// 新格式：带合约地址
				var jumpDest = {
					contract: currentContract,
					pc: log.getPC()
				};
				this.data.contractJumpDests.push(jumpDest);
			}
		},
		result: function(ctx, db) {
			this.data.gasUsed = ctx.gasUsed;
			if (ctx.type === "REVERT") {
				this.data.success = false;
				this.data.returnData = toHex(ctx.output);
			} else {
				this.data.returnData = toHex(ctx.output);
			}
			return this.data;
		}
	}`

	// 构建调用消息
	msg := map[string]interface{}{
		"from": from.Hex(),
		"to":   to.Hex(),
		"data": "0x" + common.Bytes2Hex(callData),
	}

	if value != nil && value.Sign() > 0 {
		msg["value"] = fmt.Sprintf("0x%x", value)
	}

	// 使用debug_traceCall执行模拟
	params := []interface{}{
		msg,
		fmt.Sprintf("0x%x", blockNumber),
		map[string]interface{}{"tracer": tracerCode},
	}
	if override != nil && len(override) > 0 {
		params = append(params, override)
	}

	var result json.RawMessage
	err := s.rpcClient.CallContext(ctx, &result, "debug_traceCall", params...)

	if err != nil {
		errStr := err.Error()
		// Anvil 等节点尚未支持 stateOverride 作为第4参数，回退为无 override 调用
		if len(params) == 4 && (strings.Contains(errStr, "did not match any variant of untagged enum EthRpcCall") || strings.Contains(errStr, "unexpected EOF") || strings.Contains(errStr, "invalid length")) {
			paramsFallback := []interface{}{
				msg,
				fmt.Sprintf("0x%x", blockNumber),
				map[string]interface{}{"tracer": tracerCode},
			}
			var retryResult json.RawMessage
			if retryErr := s.rpcClient.CallContext(ctx, &retryResult, "debug_traceCall", paramsFallback...); retryErr == nil {
				result = retryResult
				err = nil
			} else {
				err = retryErr
			}
		}
	}

	if err != nil {
		// 回退到 callTracer（无指令级JUMPDEST，但可用调用序列近似比较）
		if strings.Contains(err.Error(), "unsupported tracer type") || strings.Contains(err.Error(), "unsupported tracer") {
			return s.simulateWithCallTracer(ctx, from, to, callData, value, blockNumber, override)
		}
		return nil, fmt.Errorf("failed to trace call: %w", err)
	}

	// 解析结果
	var traceResult struct {
		JumpDests         []uint64           `json:"jumpDests"`
		ContractJumpDests []ContractJumpDest `json:"contractJumpDests"`
		GasUsed           uint64             `json:"gasUsed"`
		Success           bool               `json:"success"`
		ReturnData        string             `json:"returnData"`
		Error             string             `json:"error,omitempty"`
	}

	if err := json.Unmarshal(result, &traceResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trace result: %w", err)
	}

	// 转换为ReplayResult
	// 直接调用受保护合约，从头开始就是受保护合约，所以 ProtectedStartIndex = 0
	replayResult := &ReplayResult{
		Success:             traceResult.Success,
		GasUsed:             traceResult.GasUsed,
		ReturnData:          traceResult.ReturnData,
		JumpDests:           traceResult.JumpDests,
		ContractJumpDests:   traceResult.ContractJumpDests,
		ProtectedStartIndex: 0, // 直接调用受保护合约，从头开始
		Error:               traceResult.Error,
	}

	return replayResult, nil
}

// --- 回退：使用 callTracer 提取调用序列并转换为伪 JumpDests ---

type callTracerFrame struct {
	Type   string            `json:"type"`
	From   string            `json:"from"`
	To     string            `json:"to"`
	Input  string            `json:"input"`
	Output string            `json:"output"`
	Error  string            `json:"error"`
	Calls  []callTracerFrame `json:"calls"`
}

// traceTransactionWithCallTracer 使用内置 callTracer 追踪已上链交易
func (s *EVMSimulator) traceTransactionWithCallTracer(txHash common.Hash) (*ReplayResult, error) {
	var raw json.RawMessage
	err := s.rpcClient.Call(&raw, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer":       "callTracer",
		"tracerConfig": map[string]interface{}{"onlyTopCall": false},
	})
	if err != nil {
		return nil, fmt.Errorf("callTracer fallback failed: %w", err)
	}
	var frame callTracerFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil, fmt.Errorf("failed to unmarshal callTracer frame: %w", err)
	}
	addrs := flattenCallAddresses(frame)
	pseudo := addressesToPseudoJumpDests(addrs)
	return &ReplayResult{
		Success:       true,
		GasUsed:       0,
		ReturnData:    "",
		JumpDests:     pseudo,
		ExecutionPath: nil,
		Error:         "",
	}, nil
}

// simulateWithCallTracer 使用内置 callTracer 追踪 eth_call 模拟
func (s *EVMSimulator) simulateWithCallTracer(
	ctx context.Context,
	from common.Address,
	to common.Address,
	callData []byte,
	value *big.Int,
	blockNumber uint64,
	override StateOverride,
) (*ReplayResult, error) {
	msg := map[string]interface{}{
		"from": from.Hex(),
		"to":   to.Hex(),
		"data": "0x" + common.Bytes2Hex(callData),
	}
	if value != nil && value.Sign() > 0 {
		msg["value"] = fmt.Sprintf("0x%x", value)
	}

	params := []interface{}{
		msg,
		fmt.Sprintf("0x%x", blockNumber),
		map[string]interface{}{"tracer": "callTracer", "tracerConfig": map[string]interface{}{"onlyTopCall": false}},
	}
	if override != nil && len(override) > 0 {
		params = append(params, override)
	}

	var raw json.RawMessage
	err := s.rpcClient.CallContext(ctx, &raw, "debug_traceCall", params...)
	if err != nil {
		return nil, fmt.Errorf("callTracer fallback failed: %w", err)
	}
	var frame callTracerFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil, fmt.Errorf("failed to unmarshal callTracer frame: %w", err)
	}
	addrs := flattenCallAddresses(frame)
	pseudo := addressesToPseudoJumpDests(addrs)
	return &ReplayResult{
		Success:    true,
		GasUsed:    0,
		ReturnData: "",
		JumpDests:  pseudo,
		Error:      "",
	}, nil
}

func flattenCallAddresses(frame callTracerFrame) []string {
	var res []string
	var dfs func(f callTracerFrame)
	dfs = func(f callTracerFrame) {
		if f.To != "" {
			res = append(res, strings.ToLower(f.To))
		}
		for _, c := range f.Calls {
			dfs(c)
		}
	}
	dfs(frame)
	return res
}

func addressesToPseudoJumpDests(addrs []string) []uint64 {
	out := make([]uint64, 0, len(addrs))
	for _, a := range addrs {
		// 使用地址后8字节生成伪指令位置（稳定且可比较）
		if len(a) >= 2+16 { // 0x + 16 hex chars => 8 bytes
			tail := a[len(a)-16:]
			// 解析为 uint64
			var v uint64
			fmt.Sscanf(tail, "%016x", &v)
			out = append(out, v)
		} else {
			out = append(out, 0)
		}
	}
	return out
}

// SimulateTransactionWithParams 使用指定参数模拟交易
func (s *EVMSimulator) SimulateTransactionWithParams(
	ctx context.Context,
	req *SimulateRequest,
) (*SimulateResult, error) {
	// 使用 eth_call 进行基本模拟
	msg := map[string]interface{}{
		"from": req.From.Hex(),
		"to":   req.To.Hex(),
		"data": "0x" + common.Bytes2Hex(req.Data),
	}

	if req.Value != nil {
		msg["value"] = fmt.Sprintf("0x%x", req.Value)
	}

	var result string
	err := s.rpcClient.CallContext(ctx, &result, "eth_call", msg, fmt.Sprintf("0x%x", req.BlockNumber))

	if err != nil {
		// 检查是否为revert错误
		if err.Error() == "execution reverted" {
			return &SimulateResult{
				Success:    false,
				ReturnData: result,
				Error:      "execution reverted",
			}, nil
		}
		return nil, err
	}

	return &SimulateResult{
		Success:    true,
		ReturnData: result,
	}, nil
}

// SimulateRequest 模拟请求参数
type SimulateRequest struct {
	From        common.Address
	To          common.Address
	Data        []byte
	Value       *big.Int
	BlockNumber uint64
}
