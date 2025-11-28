package fuzzer

import (
	"autopath/pkg/fuzzer/symbolic"
	"autopath/pkg/simulator"
	"autopath/pkg/simulator/local"
	"autopath/pkg/simulator/local/strategies"
	apptypes "autopath/pkg/types"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// CallFrame 调用帧结构
type CallFrame = simulator.CallFrame

// ContractJumpDest 合约维度的 JUMPDEST
type ContractJumpDest = simulator.ContractJumpDest

// TransactionTracer 交易追踪器 (从 monitor 包复制以避免循环导入)
type TransactionTracer struct {
	rpcClient *rpc.Client
}

// attack_state路径与内容缓存，减少重复IO
var attackStatePathCache sync.Map // key: 项目/合约 -> 路径
var attackStateCache sync.Map     // key: 路径 -> *attackStateFile

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
	simulator      *simulator.EVMSimulator      // RPC模式模拟器
	dualSimulator  *simulator.DualModeSimulator // 🆕 双模式模拟器（支持本地执行）
	localExecution bool                         // 🆕 是否启用本地执行模式
	parser         *ABIParser
	generator      *ParamGenerator
	comparator     *PathComparator
	merger         *ResultMerger
	tracer         *TransactionTracer

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

	// 种子驱动模糊测试（新增）
	seedConfig *SeedConfig // 种子配置

	// Layer 3: 符号执行（新增）
	symbolicExtractor *symbolic.ConstraintExtractor
	symbolicSolver    *symbolic.ConstraintSolver

	// 🆕 无限制fuzzing模式
	targetSimilarity  float64 // 目标相似度阈值
	maxHighSimResults int     // 最大高相似度结果数
	unlimitedMode     bool    // 无限制模式

	// Entry Call 限制
	entryCallProtectedOnly bool // 仅允许对受保护合约进行Entry模式

	// 循环场景下使用受保护合约子路径作为基准
	useLoopBodyBaseline bool

	// 项目标识（用于定位attack_state等外部状态）
	projectID string

	// === 新架构组件 (Phase 3集成) ===
	registry       local.ProtectedRegistry // 受保护合约注册表
	poolManager    local.ParamPoolManager  // 参数池管理器
	mutationEngine local.MutationEngine    // 变异引擎

	localExecMu sync.Mutex // 本地执行器锁，避免多线程竞争

	// 约束收集器（高相似样本生成规则）
	constraintCollector *ConstraintCollector
}

// NewCallDataFuzzer 创建模糊测试器
func NewCallDataFuzzer(config *Config) (*CallDataFuzzer, error) {
	// 如果启用了新架构但未显式开启本地执行，自动开启本地执行
	if config.EnableNewArch && !config.LocalExecution {
		log.Printf("[Fuzzer] EnableNewArch=true，自动开启本地执行模式")
		config.LocalExecution = true
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

	fuzzer := &CallDataFuzzer{
		parser:                 NewABIParser(),
		generator:              gen,
		comparator:             NewPathComparator(),
		merger:                 NewResultMerger(),
		tracer:                 NewTransactionTracer(rpcClient),
		threshold:              config.Threshold,
		maxWorkers:             config.Workers,
		timeout:                config.Timeout,
		client:                 client,
		rpcClient:              rpcClient,
		stats:                  &FuzzerStats{StartTime: time.Now()},
		invariantEvaluator:     &EmptyInvariantEvaluator{}, // 默认使用空实现
		enableInvariantCheck:   config.InvariantCheck.Enabled,
		seedConfig:             config.SeedConfig,        // 新增：种子配置
		symbolicExtractor:      nil,                      // 延迟初始化
		symbolicSolver:         nil,                      // 延迟初始化
		targetSimilarity:       config.TargetSimilarity,  // 🆕 无限制模式配置
		maxHighSimResults:      config.MaxHighSimResults, // 🆕 无限制模式配置
		unlimitedMode:          config.UnlimitedMode,     // 🆕 无限制模式配置
		entryCallProtectedOnly: config.EntryCallProtectedOnly,
		projectID:              config.ProjectID,
		localExecution:         config.LocalExecution, // 🆕 本地执行模式
		constraintCollector:    NewConstraintCollector(10),
	}

	// 🆕 根据配置选择模拟器类型
	if config.LocalExecution {
		log.Printf("[Fuzzer] 🖥️ 使用本地EVM执行模式")
		dualSim, err := simulator.NewDualModeSimulator(config.RPCURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create dual mode simulator: %w", err)
		}
		dualSim.SetExecutionMode(simulator.ModeLocal)
		fuzzer.dualSimulator = dualSim
		fuzzer.simulator = dualSim.EVMSimulator // 保持兼容性
	} else {
		log.Printf("[Fuzzer] 🌐 使用RPC执行模式")
		sim, err := simulator.NewEVMSimulator(config.RPCURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create simulator: %w", err)
		}
		fuzzer.simulator = sim
	}

	return fuzzer, nil
}

// NewCallDataFuzzerWithClients 使用现有的RPC和Ethereum客户端创建模糊测试器
// 这个方法允许复用Monitor的连接，避免创建多个独立的RPC连接
func NewCallDataFuzzerWithClients(config *Config, rpcClient *rpc.Client, client *ethclient.Client) (*CallDataFuzzer, error) {
	log.Printf("[Fuzzer] 🔄 复用现有的RPC连接（避免创建新连接）")

	// 创建参数生成器
	var gen *ParamGenerator
	if config.Strategies.Integers.IncludeBoundaries {
		gen = NewParamGeneratorWithStrategy(config.MaxVariations, &config.Strategies)
	} else {
		gen = NewParamGenerator(config.MaxVariations)
	}

	// 如果启用了新架构但未显式开启本地执行，自动开启本地执行
	if config.EnableNewArch && !config.LocalExecution {
		log.Printf("[Fuzzer] EnableNewArch=true，自动开启本地执行模式")
		config.LocalExecution = true
	}

	fuzzer := &CallDataFuzzer{
		parser:                 NewABIParser(),
		generator:              gen,
		comparator:             NewPathComparator(),
		merger:                 NewResultMerger(),
		tracer:                 NewTransactionTracer(rpcClient),
		threshold:              config.Threshold,
		maxWorkers:             config.Workers,
		timeout:                config.Timeout,
		client:                 client,
		rpcClient:              rpcClient,
		stats:                  &FuzzerStats{StartTime: time.Now()},
		invariantEvaluator:     &EmptyInvariantEvaluator{}, // 默认使用空实现
		enableInvariantCheck:   config.InvariantCheck.Enabled,
		seedConfig:             config.SeedConfig,        // 新增：种子配置
		symbolicExtractor:      nil,                      // 延迟初始化
		symbolicSolver:         nil,                      // 延迟初始化
		targetSimilarity:       config.TargetSimilarity,  // 🆕 无限制模式配置
		maxHighSimResults:      config.MaxHighSimResults, // 🆕 无限制模式配置
		unlimitedMode:          config.UnlimitedMode,     // 🆕 无限制模式配置
		entryCallProtectedOnly: config.EntryCallProtectedOnly,
		projectID:              config.ProjectID,
		localExecution:         config.LocalExecution, // 🆕 本地执行模式
		constraintCollector:    NewConstraintCollector(10),
	}

	// 🆕 根据配置选择模拟器类型
	if config.LocalExecution {
		log.Printf("[Fuzzer] 🖥️ 使用本地EVM执行模式（复用RPC连接获取状态）")
		dualSim := simulator.NewDualModeSimulatorWithClients(rpcClient, client)
		dualSim.SetExecutionMode(simulator.ModeLocal)
		fuzzer.dualSimulator = dualSim
		fuzzer.simulator = dualSim.EVMSimulator // 保持兼容性
	} else {
		log.Printf("[Fuzzer] 🌐 使用RPC执行模式")
		sim := simulator.NewEVMSimulatorWithClients(rpcClient, client)
		fuzzer.simulator = sim
	}

	return fuzzer, nil
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

// hookFirstProtectedCall 遍历调用树，对每个外部调用执行“hook”检查并返回首个命中受保护合约的调用
func (f *CallDataFuzzer) hookFirstProtectedCall(trace *CallFrame, targetContract common.Address) (*CallFrame, int) {
	targetAddr := strings.ToLower(targetContract.Hex())
	visited := 0

	var shortSelector = func(input string) string {
		if len(input) >= 10 {
			return input[:10]
		}
		return input
	}

	var walk func(frame *CallFrame) *CallFrame
	walk = func(frame *CallFrame) *CallFrame {
		if visited < 20 { // 避免日志过多，只记录前20次hook
			log.Printf("[Fuzzer] 🪝 Hook外部调用 #%d: to=%s selector=%s", visited+1, frame.To, shortSelector(frame.Input))
		}
		visited++

		if strings.ToLower(frame.To) == targetAddr {
			return frame
		}

		for i := range frame.Calls {
			if hit := walk(&frame.Calls[i]); hit != nil {
				return hit
			}
		}
		return nil
	}

	found := walk(trace)
	return found, visited
}

// selectTargetCall 智能选择fuzzing目标调用
// 优先选择非标准ERC20函数（跳过approve、transfer、transferFrom等）
func (f *CallDataFuzzer) selectTargetCall(calls []*CallFrame) *CallFrame {
	if len(calls) == 0 {
		return nil
	}

	// ERC20标准函数选择器（应该跳过的）
	standardSelectors := map[string]bool{
		"0x095ea7b3": true, // approve(address,uint256)
		"0xa9059cbb": true, // transfer(address,uint256)
		"0x23b872dd": true, // transferFrom(address,address,uint256)
		"0x70a08231": true, // balanceOf(address)
		"0xdd62ed3e": true, // allowance(address,address)
		"0x18160ddd": true, // totalSupply()
		"0x06fdde03": true, // name()
		"0x95d89b41": true, // symbol()
		"0x313ce567": true, // decimals()
	}

	// 🔄 新增：统计每个函数选择器的调用频率（识别循环）
	callFrequency := make(map[string]int)
	callDetails := make(map[string]*CallFrame) // 保存每个selector的第一个调用
	for _, call := range calls {
		if len(call.Input) >= 10 {
			selector := call.Input[:10]
			if !standardSelectors[selector] {
				callFrequency[selector]++
				if callDetails[selector] == nil {
					callDetails[selector] = call
				}
			}
		}
	}

	// 🎯 第一优先级：高频调用函数（循环攻击的核心）
	// 找出调用次数最多的函数
	var maxFreq int
	var highFreqSelector string
	for selector, freq := range callFrequency {
		if freq > maxFreq && freq > 1 { // 至少调用2次才认为是循环
			maxFreq = freq
			highFreqSelector = selector
		}
	}

	if highFreqSelector != "" {
		log.Printf("[Fuzzer] 🔄 High frequency selection: selector=%s called %d times (likely loop attack)",
			highFreqSelector, maxFreq)
		return callDetails[highFreqSelector]
	}

	// 📋 第二优先级：配置文件中标记为priority="high"的函数
	// 正确的选择器：flash=0xbdbc91ab, bond=0xa515366a, debond=0xee9c79da
	highPrioritySelectors := map[string]bool{
		"0xbdbc91ab": true, // flash(address,address,uint256,bytes)
		"0xa515366a": true, // bond(address,uint256)
	}
	for selector, call := range callDetails {
		if highPrioritySelectors[selector] {
			log.Printf("[Fuzzer] 📋 Config priority selection: selector=%s (marked as high priority)", selector)
			return call
		}
	}

	// 🔍 第三优先级：选择非标准函数且input较长的（通常是业务逻辑函数）
	for _, call := range calls {
		if len(call.Input) >= 10 {
			selector := call.Input[:10]
			if !standardSelectors[selector] && len(call.Input) > 68 {
				// 非标准函数且有多个参数
				log.Printf("[Fuzzer] Length-based selection: Non-standard function with parameters (selector=%s)", selector)
				return call
			}
		}
	}

	// 🔄 第四优先级：选择非标准函数（即使参数少）
	for _, call := range calls {
		if len(call.Input) >= 10 {
			selector := call.Input[:10]
			if !standardSelectors[selector] {
				log.Printf("[Fuzzer] Secondary selection: Non-standard function (selector=%s)", selector)
				return call
			}
		}
	}

	// 🔙 回退：如果所有调用都是标准函数，选择第一个
	log.Printf("[Fuzzer] Fallback selection: Using first call (all are standard functions)")
	return calls[0]
}

// selectEntryCall 选择攻击交易的入口调用
// 用于fuzzing整个攻击流程而非单个受保护合约函数
func (f *CallDataFuzzer) selectEntryCall(trace *CallFrame) *CallFrame {
	// 交易的根调用就是入口点
	log.Printf("[Fuzzer] Selecting entry call: from=%s, to=%s, input_length=%d bytes",
		trace.From, trace.To, len(trace.Input)/2-1)
	return trace
}

// hasRepeatedSelector 检测调用树中是否对受保护合约的同一选择器进行了多次调用
func (f *CallDataFuzzer) hasRepeatedSelector(trace *CallFrame, contract common.Address) bool {
	target := strings.ToLower(contract.Hex())
	counts := make(map[string]int)

	var dfs func(cf *CallFrame)
	dfs = func(cf *CallFrame) {
		if cf == nil {
			return
		}
		if strings.EqualFold(cf.To, target) && len(cf.Input) >= 10 {
			selector := strings.ToLower(cf.Input[:10]) // 包含0x前缀
			counts[selector]++
		}
		for i := range cf.Calls {
			dfs(&cf.Calls[i])
		}
	}

	dfs(trace)
	for _, c := range counts {
		if c > 1 {
			return true
		}
	}
	return false
}

// hasBackEdgeForContract 检测路径中同一合约的PC是否重复出现，作为回边启发
func hasBackEdgeForContract(path *simulator.ReplayResult, contract common.Address) bool {
	if path == nil || len(path.ContractJumpDests) == 0 {
		return false
	}
	target := strings.ToLower(contract.Hex())
	seen := make(map[uint64]bool)
	for _, jd := range path.ContractJumpDests {
		if !strings.EqualFold(jd.Contract, target) {
			continue
		}
		if seen[jd.PC] {
			return true
		}
		seen[jd.PC] = true
	}
	return false
}

// findFunctionEntryIndex 在路径中查找特定函数入口PC的位置
// 用于对齐基准路径和fuzz路径，确保从相同的函数入口开始比较
func findFunctionEntryIndex(path []ContractJumpDest, contract common.Address, entryPC uint64) int {
	target := strings.ToLower(contract.Hex())
	for i, jd := range path {
		if strings.EqualFold(jd.Contract, target) && jd.PC == entryPC {
			return i
		}
	}
	return -1
}

// containsPC 判断路径中是否包含指定PC（已按合约过滤）
func containsPC(path []ContractJumpDest, pc uint64) bool {
	for _, jd := range path {
		if jd.PC == pc {
			return true
		}
	}
	return false
}

// extractProtectedContractPath 提取受保护合约在原始路径中的子路径（用于循环体基准）
func extractProtectedContractPath(path []ContractJumpDest, contract common.Address, startIndex int) []ContractJumpDest {
	target := strings.ToLower(contract.Hex())
	if startIndex < 0 {
		startIndex = 0
	}

	var res []ContractJumpDest

	// 🔍 调试：统计原始路径中所有PC值
	pcCountMap := make(map[uint64]int)
	var targetContractPCs []uint64
	for _, jd := range path {
		if strings.EqualFold(jd.Contract, target) {
			pcCountMap[jd.PC]++
			targetContractPCs = append(targetContractPCs, jd.PC)
		}
	}
	if len(targetContractPCs) > 0 {
		// 打印前20个和最后20个PC
		log.Printf("[extractProtectedContractPath] 🔍 目标合约%s在原始路径中共有%d个JUMPDEST，前20个PC=%v",
			target, len(targetContractPCs), func() []uint64 {
				if len(targetContractPCs) > 20 {
					return targetContractPCs[:20]
				}
				return targetContractPCs
			}())
		// 检查是否包含PC=100
		if count, exists := pcCountMap[100]; exists {
			log.Printf("[extractProtectedContractPath] ✅ 原始路径包含PC=100，出现%d次", count)
		} else {
			log.Printf("[extractProtectedContractPath] ❌ 原始路径不包含PC=100")
		}
		// 检查是否包含PC=247
		if count, exists := pcCountMap[247]; exists {
			log.Printf("[extractProtectedContractPath] ✅ 原始路径包含PC=247，出现%d次", count)
		}
	}

	// 从startIndex开始搜索受保护合约的路径片段
	for i := startIndex; i < len(path); i++ {
		if strings.EqualFold(path[i].Contract, target) {
			res = append(res, path[i])
		}
	}

	// 关键修复：如果从startIndex没找到，扫描整个路径
	if len(res) == 0 && startIndex > 0 {
		log.Printf("[extractProtectedContractPath] 从startIndex=%d未找到合约%s，尝试全路径搜索", startIndex, target)
		for i := 0; i < len(path); i++ {
			if strings.EqualFold(path[i].Contract, target) {
				res = append(res, path[i])
			}
		}
	}

	// 🔧 关键修复：即使startIndex=0，也需要扫描整个路径提取受保护合约的所有JUMPDEST
	// 原问题：原始路径包含多个合约（攻击合约+wBARL），但只有wBARL是受保护的
	// 需要过滤出属于受保护合约的路径片段
	if len(res) == 0 && startIndex == 0 {
		// startIndex=0但结果为空，说明路径第一个元素不是目标合约
		// 需要扫描整个路径找到目标合约的所有JUMPDEST
		for i := 0; i < len(path); i++ {
			if strings.EqualFold(path[i].Contract, target) {
				res = append(res, path[i])
			}
		}
		if len(res) > 0 {
			log.Printf("[extractProtectedContractPath] 全路径扫描成功提取 %d 个JUMPDEST (合约=%s)", len(res), target)
		}
	}

	// 添加调试日志
	if len(res) > 0 {
		log.Printf("[extractProtectedContractPath] 成功提取 %d 个JUMPDEST (合约=%s, 原始路径长度=%d)", len(res), target, len(path))
	} else {
		log.Printf("[extractProtectedContractPath] ⚠️ 未能提取任何JUMPDEST (合约=%s, 路径长度=%d)", target, len(path))
	}

	return res
}

// hasParameters 检查调用是否有参数（除了函数选择器）
func hasParameters(input string) bool {
	// input格式: "0x" + 8位selector + 参数
	// 4字节selector = 8个hex字符，加上"0x"前缀 = 10个字符
	return len(input) > 10
}

// findCallIndex 返回目标调用在受保护调用列表中的索引，未找到则返回-1
func findCallIndex(calls []*CallFrame, target *CallFrame) int {
	if target == nil {
		return -1
	}
	for i, c := range calls {
		if c == target {
			return i
		}
	}
	return -1
}

// syntheticSelectorAliases 为缺失ABI的入口函数提供占位方法名，避免解析失败
var syntheticSelectorAliases = map[string]string{
	"422490ee": "attackEntry",
}

// selectSnapshotIndex 根据selector与caller优先匹配合适的快照
func selectSnapshotIndex(snapshots []*simulator.CallSnapshot, selector string, caller string, fallback int) int {
	selector = strings.ToLower(selector)
	caller = strings.ToLower(caller)

	best := -1
	bestByCaller := -1
	targetCount := 0

	for i, snap := range snapshots {
		sel := strings.ToLower(snap.Selector)
		if sel == selector {
			if strings.EqualFold(snap.Caller.Hex(), caller) {
				return i
			}
			if bestByCaller == -1 && caller != "" && strings.EqualFold(snap.Caller.Hex(), caller) {
				bestByCaller = i
			}
			if best == -1 {
				best = i
			}
			targetCount++
		}
	}

	if bestByCaller != -1 {
		return bestByCaller
	}

	if best != -1 {
		return best
	}

	if fallback >= 0 && fallback < len(snapshots) {
		return fallback
	}

	return len(snapshots) - 1
}

// selectSnapshotWithPriority 在未命中目标selector时，按高优先级列表进行二次匹配
func selectSnapshotWithPriority(snapshots []*simulator.CallSnapshot, targetSelector string, caller string, fallback int) int {
	primary := selectSnapshotIndex(snapshots, targetSelector, caller, -1)
	if primary >= 0 && primary < len(snapshots) {
		return primary
	}

	// 优先尝试flash，再尝试bond
	priorities := []string{"0xbdbc91ab", "0xa515366a"}
	for _, sel := range priorities {
		alt := selectSnapshotIndex(snapshots, sel, caller, -1)
		if alt >= 0 && alt < len(snapshots) {
			return alt
		}
	}

	// 回退原始索引
	if fallback >= 0 && fallback < len(snapshots) {
		return fallback
	}
	return len(snapshots) - 1
}

// ensureCodeInOverride 确保指定地址的代码已注入到StateOverride，避免回调缺失导致模拟直接revert
func ensureCodeInOverride(ctx context.Context, rpcClient *rpc.Client, addr common.Address, ov *simulator.StateOverride) {
	if ov == nil {
		return
	}
	lower := strings.ToLower(addr.Hex())
	if lower == "0x0000000000000000000000000000000000000000" {
		return
	}

	entry := (*ov)[lower]
	if entry != nil && entry.Code != "" && entry.Code != "0x" {
		return
	}

	var code string
	if err := rpcClient.CallContext(ctx, &code, "eth_getCode", addr, "latest"); err != nil {
		log.Printf("[Fuzzer] ⚠️  查询合约代码失败(%s): %v", addr.Hex(), err)
		return
	}
	if code == "" || code == "0x" {
		log.Printf("[Fuzzer] ⚠️  合约代码为空(%s)，无法注入", addr.Hex())
		return
	}

	if entry == nil {
		entry = &simulator.AccountOverride{}
	}
	entry.Code = strings.ToLower(code)
	(*ov)[lower] = entry
	log.Printf("[Fuzzer] 🧩 已注入合约代码: %s (size=%d bytes)", addr.Hex(), (len(code)-2)/2)
}

// ensureCodeForSnapshots 为快照涉及的所有caller/callee注入代码
func ensureCodeForSnapshots(ctx context.Context, rpcClient *rpc.Client, snapshots []*simulator.CallSnapshot, ov *simulator.StateOverride) {
	seen := make(map[string]bool)
	for _, snap := range snapshots {
		if snap == nil {
			continue
		}
		if !seen[strings.ToLower(snap.Caller.Hex())] {
			ensureCodeInOverride(ctx, rpcClient, snap.Caller, ov)
			seen[strings.ToLower(snap.Caller.Hex())] = true
		}
		if !seen[strings.ToLower(snap.Callee.Hex())] {
			ensureCodeInOverride(ctx, rpcClient, snap.Callee, ov)
			seen[strings.ToLower(snap.Callee.Hex())] = true
		}
	}
}

// mergeSnapshotsIntoOverride 将多个快照的余额与存储批量注入
func mergeSnapshotsIntoOverride(base simulator.StateOverride, snapshots []*simulator.CallSnapshot) simulator.StateOverride {
	for _, snap := range snapshots {
		base = simulator.BuildStateOverrideFromSnapshot(base, snap)
	}
	return base
}

// extractInvolvedContracts 从快照中提取所有参与的caller/callee地址（去重）
func extractInvolvedContracts(snapshots []*simulator.CallSnapshot) []common.Address {
	seen := make(map[string]bool)
	var res []common.Address
	for _, snap := range snapshots {
		if snap == nil {
			continue
		}
		caller := strings.ToLower(snap.Caller.Hex())
		if caller != "0x0000000000000000000000000000000000000000" && !seen[caller] {
			res = append(res, snap.Caller)
			seen[caller] = true
		}
		callee := strings.ToLower(snap.Callee.Hex())
		if callee != "0x0000000000000000000000000000000000000000" && !seen[callee] {
			res = append(res, snap.Callee)
			seen[callee] = true
		}
	}
	return res
}

// attack_state.json 结构体（只保留必要字段）
type attackStateEntry struct {
	BalanceWei interface{}       `json:"balance_wei"`
	Nonce      interface{}       `json:"nonce"`
	Code       string            `json:"code"`
	Storage    map[string]string `json:"storage"`
}

type attackStateFile struct {
	Addresses map[string]attackStateEntry `json:"addresses"`
}

// isZeroLikeHex 判断字符串是否等价于0
func isZeroLikeHex(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" || lower == "0x" || lower == "0x0" {
		return true
	}
	body := strings.TrimPrefix(lower, "0x")
	body = strings.TrimLeft(body, "0")
	return body == ""
}

// normalizeAttackQuantity 将balance/nonce统一转为0x前缀十六进制
func normalizeAttackQuantity(v interface{}) string {
	switch val := v.(type) {
	case nil:
		return ""
	case string:
		s := strings.TrimSpace(val)
		if s == "" {
			return ""
		}
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			return strings.ToLower(s)
		}
		s = strings.ReplaceAll(s, "_", "")
		if bi, ok := new(big.Int).SetString(s, 10); ok {
			return "0x" + strings.ToLower(bi.Text(16))
		}
	case json.Number:
		if bi, ok := new(big.Int).SetString(string(val), 10); ok {
			return "0x" + strings.ToLower(bi.Text(16))
		}
	case float64:
		return fmt.Sprintf("0x%x", uint64(val))
	case int:
		return fmt.Sprintf("0x%x", val)
	case int64:
		return fmt.Sprintf("0x%x", val)
	case uint64:
		return fmt.Sprintf("0x%x", val)
	}
	return ""
}

// normalizeAttackSlotKey 将attack_state中的slot索引格式化为32字节
func normalizeAttackSlotKey(slot string) string {
	raw := strings.TrimSpace(slot)
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
	} else {
		raw = strings.ReplaceAll(raw, "_", "")
		if bi, ok := new(big.Int).SetString(raw, 10); ok {
			raw = bi.Text(16)
		}
	}
	raw = strings.TrimLeft(strings.ToLower(raw), "0")
	if raw == "" {
		raw = "0"
	}
	if len(raw) < 64 {
		raw = strings.Repeat("0", 64-len(raw)) + raw
	} else if len(raw) > 64 {
		raw = raw[len(raw)-64:]
	}
	return "0x" + raw
}

// normalizeAttackSlotValue 将槽值格式化为32字节十六进制
func normalizeAttackSlotValue(value string) string {
	raw := strings.TrimSpace(value)
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		raw = raw[2:]
	} else {
		raw = strings.ReplaceAll(raw, "_", "")
		if bi, ok := new(big.Int).SetString(raw, 10); ok {
			raw = bi.Text(16)
		}
	}
	raw = strings.ToLower(raw)
	if len(raw) < 64 {
		raw = strings.Repeat("0", 64-len(raw)) + raw
	} else if len(raw) > 64 {
		raw = raw[len(raw)-64:]
	}
	return "0x" + raw
}

// locateAttackStatePath 基于项目ID/受保护合约地址定位attack_state.json
func (f *CallDataFuzzer) locateAttackStatePath(contractAddr common.Address) (string, error) {
	cacheKey := f.projectID
	if cacheKey == "" {
		cacheKey = strings.ToLower(contractAddr.Hex())
	}
	if cached, ok := attackStatePathCache.Load(cacheKey); ok {
		if path, ok2 := cached.(string); ok2 && path != "" {
			return path, nil
		}
	}

	baseDir, err := f.parser.locateExtractedRoot()
	if err != nil {
		return "", err
	}

	var candidates []string
	if f.projectID != "" {
		pattern := filepath.Join(baseDir, "*", f.projectID, "attack_state.json")
		if matches, _ := filepath.Glob(pattern); len(matches) > 0 {
			candidates = append(candidates, matches...)
		}
	}

	// 回退：扫描包含 attack_state.json 的目录，优先匹配地址片段
	if len(candidates) == 0 {
		lowerAddr := strings.ToLower(contractAddr.Hex())
		errStop := errors.New("found-attack-state")
		_ = filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.IsDir() || !strings.EqualFold(d.Name(), "attack_state.json") {
				return nil
			}

			// 目录名包含项目ID/地址片段直接命中
			if f.projectID != "" && strings.Contains(strings.ToLower(path), strings.ToLower(f.projectID)) {
				candidates = append(candidates, path)
				return errStop
			}
			if strings.Contains(strings.ToLower(path), lowerAddr[2:]) {
				candidates = append(candidates, path)
				return errStop
			}

			// 读取文件并检查是否包含地址
			if data, readErr := os.ReadFile(path); readErr == nil {
				if strings.Contains(strings.ToLower(string(data)), lowerAddr) {
					candidates = append(candidates, path)
					return errStop
				}
			}
			return nil
		})
	}

	if len(candidates) == 0 {
		return "", fmt.Errorf("未找到attack_state.json")
	}

	attackStatePathCache.Store(cacheKey, candidates[0])
	return candidates[0], nil
}

// loadAttackState 读取并缓存attack_state.json
func (f *CallDataFuzzer) loadAttackState(contractAddr common.Address) (*attackStateFile, string) {
	path, err := f.locateAttackStatePath(contractAddr)
	if err != nil {
		log.Printf("[AttackState] ⚠️  未找到attack_state.json: %v", err)
		return nil, ""
	}

	if cached, ok := attackStateCache.Load(path); ok {
		if parsed, ok2 := cached.(*attackStateFile); ok2 && parsed != nil {
			return parsed, path
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[AttackState] ⚠️  读取attack_state失败(%s): %v", path, err)
		return nil, ""
	}

	var parsed attackStateFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		log.Printf("[AttackState] ⚠️  解析attack_state失败(%s): %v", path, err)
		return nil, ""
	}
	if len(parsed.Addresses) == 0 {
		log.Printf("[AttackState] ⚠️  attack_state(%s)未包含addresses字段", path)
		return nil, ""
	}

	attackStateCache.Store(path, &parsed)
	return &parsed, path
}

// mergeAttackStateIntoOverride 将attack_state中的余额/nonce/代码/存储注入StateOverride
func mergeAttackStateIntoOverride(base simulator.StateOverride, attack *attackStateFile, path string) simulator.StateOverride {
	if attack == nil || len(attack.Addresses) == 0 {
		return base
	}

	if base == nil {
		base = make(simulator.StateOverride)
	}

	injected := 0
	skipped := 0
	for rawAddr, entry := range attack.Addresses {
		lowerAddr := strings.ToLower(rawAddr)
		if lowerAddr == "0x0000000000000000000000000000000000000000" || lowerAddr == "" {
			continue
		}

		ov := base[lowerAddr]
		if ov == nil {
			ov = &simulator.AccountOverride{}
		}

		if balHex := normalizeAttackQuantity(entry.BalanceWei); balHex != "" && !isZeroLikeHex(balHex) {
			if ov.Balance == "" || isZeroLikeHex(ov.Balance) {
				ov.Balance = balHex
			}
		}

		if nonceHex := normalizeAttackQuantity(entry.Nonce); nonceHex != "" && !isZeroLikeHex(nonceHex) {
			if ov.Nonce == "" || isZeroLikeHex(ov.Nonce) {
				ov.Nonce = nonceHex
			}
		}

		if entry.Code != "" && (ov.Code == "" || ov.Code == "0x") {
			ov.Code = strings.ToLower(entry.Code)
		}

		if len(entry.Storage) > 0 {
			if ov.State == nil {
				ov.State = make(map[string]string)
			}
			for slot, val := range entry.Storage {
				nSlot := normalizeAttackSlotKey(slot)
				nVal := normalizeAttackSlotValue(val)
				if exist, ok := ov.State[nSlot]; ok && !isZeroLikeHex(exist) {
					skipped++
					continue
				}
				if exist, ok := ov.State[nSlot]; !ok || isZeroLikeHex(exist) {
					ov.State[nSlot] = nVal
				}
			}
		}

		base[lowerAddr] = ov
		injected++
	}

	if injected > 0 {
		log.Printf("[AttackState] 🧊 已从%s注入状态：%d个账户，跳过已存在非零槽位 %d 个", path, injected, skipped)
	}
	return base
}

// injectAttackStateIfAvailable 尝试注入attack_state.json中的状态
func (f *CallDataFuzzer) injectAttackStateIfAvailable(base simulator.StateOverride, contractAddr common.Address) simulator.StateOverride {
	attackState, path := f.loadAttackState(contractAddr)
	if attackState == nil {
		return base
	}
	return mergeAttackStateIntoOverride(base, attackState, path)
}

// primeSeedsWithOriginalParams 如果某个参数没有种子，则注入原始调用参数作为种子，避免只生成极少组合
func primeSeedsWithOriginalParams(seedCfg *SeedConfig, params []Parameter) bool {
	if seedCfg == nil || !seedCfg.Enabled {
		return false
	}
	if seedCfg.AttackSeeds == nil {
		seedCfg.AttackSeeds = make(map[int][]interface{})
	}

	injected := false
	for _, p := range params {
		if p.Value == nil {
			continue
		}
		exist := false
		for _, s := range seedCfg.AttackSeeds[p.Index] {
			if reflect.DeepEqual(s, p.Value) {
				exist = true
				break
			}
		}
		if !exist {
			seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], p.Value)
			log.Printf("[SeedGen] 🌱 注入原始参数作为种子 param#%d=%v", p.Index, p.Value)
			injected = true
			// 对数值参数添加若干倍数/偏移，避免全部为0导致无状态变更
			if strings.HasPrefix(p.Type, "uint") || strings.HasPrefix(p.Type, "int") {
				switch v := p.Value.(type) {
				case *big.Int:
					mults := []int64{2, 5, 10}
					half := new(big.Int).Div(v, big.NewInt(2))
					if half.Sign() > 0 {
						seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], half)
					}
					for _, m := range mults {
						seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], new(big.Int).Mul(v, big.NewInt(m)))
					}
				case uint64:
					for _, m := range []uint64{2, 5, 10} {
						seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], new(big.Int).Mul(big.NewInt(int64(v)), big.NewInt(int64(m))))
					}
					if v > 1 {
						seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], new(big.Int).Div(big.NewInt(int64(v)), big.NewInt(2)))
					}
				case int:
					val := int64(v)
					for _, m := range []int64{2, 5, 10} {
						seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], new(big.Int).Mul(big.NewInt(val), big.NewInt(m)))
					}
					if val > 1 {
						seedCfg.AttackSeeds[p.Index] = append(seedCfg.AttackSeeds[p.Index], new(big.Int).Div(big.NewInt(val), big.NewInt(2)))
					}
				}
			}
		}
	}

	return injected
}

// sanitizeAddressSeeds 过滤掉非地址类型的种子，回退到原始参数，并限制地址变异只用原值
func sanitizeAddressSeeds(seedCfg *SeedConfig, params []Parameter) {
	if seedCfg == nil || !seedCfg.Enabled {
		return
	}
	if seedCfg.AttackSeeds == nil {
		return
	}

	for _, p := range params {
		if !strings.HasPrefix(p.Type, "address") {
			continue
		}

		// 只保留一个可靠的地址：优先原始参数，其次合法种子
		var candidate common.Address
		if p.Value != nil {
			switch v := p.Value.(type) {
			case common.Address:
				candidate = v
			case string:
				if common.IsHexAddress(v) {
					candidate = common.HexToAddress(v)
				}
			}
		}
		if (candidate == common.Address{}) {
			seeds, ok := seedCfg.AttackSeeds[p.Index]
			if ok {
				for _, s := range seeds {
					switch v := s.(type) {
					case common.Address:
						candidate = v
					case string:
						if common.IsHexAddress(v) {
							candidate = common.HexToAddress(v)
						}
					}
					if (candidate != common.Address{}) {
						break
					}
				}
			}
		}
		if (candidate != common.Address{}) {
			seedCfg.AttackSeeds[p.Index] = []interface{}{candidate}
		}
	}

	// 限制地址变异策略，仅保留原始地址，避免生成无代码的随机地址导致revert
	seedCfg.RangeConfig.AddressMutationTypes = []string{"original"}
}

// restrictComplexSeeds 对 bytes/数组类型的种子收紧，只保留原始值，避免无效payload导致必然revert
func restrictComplexSeeds(seedCfg *SeedConfig, params []Parameter) {
	if seedCfg == nil || !seedCfg.Enabled || seedCfg.AttackSeeds == nil {
		return
	}

	for _, p := range params {
		if strings.Contains(p.Type, "bytes") || strings.HasSuffix(p.Type, "[]") {
			seeds := seedCfg.AttackSeeds[p.Index]
			var original interface{}
			if p.Value != nil {
				original = p.Value
			} else if len(seeds) > 0 {
				original = seeds[0]
			}
			if original != nil {
				seedCfg.AttackSeeds[p.Index] = []interface{}{original}
			}
		}
	}
}

// decodeRevertMessage 尝试从返回数据解码revert原因
func decodeRevertMessage(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if msg, err := abi.UnpackRevert(data); err == nil {
		return msg
	}
	return fmt.Sprintf("0x%x", data)
}

// formatReturnDataForLog 将返回数据裁剪后用于日志
func formatReturnDataForLog(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	hexStr := hexutil.Encode(data)
	if len(hexStr) > 74 { // 超长返回按32字节截断
		return hexStr[:74] + "..."
	}
	return hexStr
}

// FuzzTransaction 对交易进行模糊测试
// tx 参数可选：如果提供则直接使用，否则通过 txHash 查询
func (f *CallDataFuzzer) FuzzTransaction(
	ctx context.Context,
	txHash common.Hash,
	contractAddr common.Address,
	blockNumber uint64,
	tx *types.Transaction, // 新增：可选的交易对象
) (*AttackParameterReport, error) {
	startTime := time.Now()
	f.stats.StartTime = startTime

	// 步骤1: 获取原始交易信息和执行路径（传入受保护合约地址）
	log.Printf("[Fuzzer] Fetching original transaction: %s", txHash.Hex())
	txObj, originalPath, stateOverride, err := f.getOriginalExecution(ctx, txHash, blockNumber, contractAddr, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to get original execution: %w", err)
	}
	log.Printf("[Fuzzer] Original path has %d JUMPDESTs (total), %d ContractJumpDests, protected start index: %d",
		len(originalPath.JumpDests), len(originalPath.ContractJumpDests), originalPath.ProtectedStartIndex)

	// 使用纯 prestate 作为基线执行环境，不合并原始交易的后置状态变更
	log.Printf("[Fuzzer] 🧊 使用交易 prestate 作为模糊测试基线 (success=%v, gas=%d, jumpDests=%d, contractJumpDests=%d)",
		originalPath.Success, originalPath.GasUsed, len(originalPath.JumpDests), len(originalPath.ContractJumpDests))
	if stateOverride != nil {
		if ov, ok := stateOverride[strings.ToLower(contractAddr.Hex())]; ok && ov != nil && len(ov.State) > 0 {
			log.Printf("[Fuzzer] 🧊 当前StateOverride包含受保护合约槽位: %d", len(ov.State))
		}
		if daiOv, ok := stateOverride[strings.ToLower("0x6B175474E89094C44Da98b954EedeAC495271d0F")]; ok && daiOv != nil && len(daiOv.State) > 0 {
			log.Printf("[Fuzzer] 🧊 当前StateOverride包含DAI槽位: %d", len(daiOv.State))
			// 关键授权槽位：allowance[0x356e...][wBARL]，DAI slot3
			allowSlot := "0x3d87c91f878fde976b5e092bfe8d85850194c887f898e23b950a17e7e2210300"
			if val, ok2 := daiOv.State[allowSlot]; ok2 {
				log.Printf("[Fuzzer] 🧊 DAI 授权槽位[356E->wBARL slot3]: %s", val)
			} else {
				log.Printf("[Fuzzer] ⚠️ 未找到DAI授权槽位[356E->wBARL slot3]")
			}
		}
	}

	// 步骤1.5: 基于 prestate 重放交易，提取调用树
	log.Printf("[Fuzzer] Tracing transaction (prestate) to extract call tree...")
	trace, err := f.simulator.TraceCallTreeWithOverride(ctx, txObj, blockNumber, stateOverride)
	if err != nil {
		log.Printf("[Fuzzer] ⚠️  基于 prestate 的 traceCall 失败，回退链上 callTracer: %v", err)
		trace, err = f.tracer.TraceTransaction(txHash)
		if err != nil {
			return nil, fmt.Errorf("failed to trace transaction: %w", err)
		}
	}
	log.Printf("[Fuzzer] Trace captured: calls=%d, rootFrom=%s, rootTo=%s", len(trace.Calls), trace.From, trace.To)

	// 若调用树为空，回退使用 callTracer 再取一次调用序列
	if len(trace.Calls) == 0 {
		log.Printf("[Fuzzer] ⚠️ trace.Calls 为空，尝试使用 callTracer 重新获取调用树")
		if ct, err2 := f.tracer.TraceTransaction(txHash); err2 == nil && ct != nil && len(ct.Calls) > 0 {
			trace = ct
			log.Printf("[Fuzzer] ✅ callTracer 获取成功: calls=%d, rootFrom=%s, rootTo=%s", len(trace.Calls), trace.From, trace.To)
		} else {
			log.Printf("[Fuzzer] ⚠️ callTracer 也未获取到调用树: %v", err2)
		}
	}

	// 如果仍然没有调用树，使用交易本身构造一个伪调用帧继续Fuzz，避免直接中止
	if len(trace.Calls) == 0 {
		if txObj == nil {
			return nil, fmt.Errorf("trace.Calls is empty for tx %s, cannot extract protected calls", txHash.Hex())
		}
		log.Printf("[Fuzzer] ⚠️ trace.Calls 仍为空，使用交易入口构造伪调用树继续Fuzzing")
		trace = f.buildFallbackCallFrame(txObj, "", "", txObj.Data())
		log.Printf("[Fuzzer] ✅ 伪调用帧: from=%s, to=%s, inputLen=%d", trace.From, trace.To, len(trace.Input))
	}

	// 在重放过程中hook外部调用，捕获首个命中的受保护合约
	hookTarget, hookVisited := f.hookFirstProtectedCall(trace, contractAddr)
	if hookTarget != nil {
		selector := hookTarget.Input
		if len(selector) > 10 {
			selector = selector[:10]
		}
		log.Printf("[Fuzzer] 🪝 首次命中受保护合约: to=%s selector=%s (hook顺序=%d)", hookTarget.To, selector, hookVisited)
	}

	// 步骤2: 从调用树中提取调用受保护合约的call
	log.Printf("[Fuzzer] Extracting calls to protected contract %s", contractAddr.Hex())
	protectedCalls := f.extractProtectedContractCalls(trace, contractAddr)
	if len(protectedCalls) == 0 {
		log.Printf("[Fuzzer] ⚠️ 未在调用树中找到受保护合约 %s，回退到入口调用", contractAddr.Hex())
		// 尝试使用交易本身的调用作为fallback
		if txObj == nil {
			return nil, fmt.Errorf("no calls to protected contract %s found in transaction", contractAddr.Hex())
		}
		input := txObj.Data()
		fromStr := ""
		// 若trace包含顶层调用，尽量使用其from地址
		if len(trace.Calls) > 0 {
			fromStr = trace.Calls[0].From
		}
		to := contractAddr.Hex()
		targetCall := f.buildFallbackCallFrame(txObj, fromStr, to, input)
		protectedCalls = []*CallFrame{targetCall}
		log.Printf("[Fuzzer] ⚙️ fallback 使用交易入口: from=%s to=%s selector=%s", targetCall.From, targetCall.To, targetCall.Input[:10])
	}
	log.Printf("[Fuzzer] Found %d calls to protected contract (hook扫描次数=%d)", len(protectedCalls), hookVisited)

	// 直接使用执行过程中首次命中的受保护合约调用；若是标准只读函数，则回退到启发式选择
	targetCall := protectedCalls[0]
	targetCallIndex := 0
	if hookTarget != nil {
		targetCall = hookTarget
		if idx := findCallIndex(protectedCalls, hookTarget); idx >= 0 {
			targetCallIndex = idx
		}
	}
	standardSelectors := map[string]bool{
		"0x70a08231": true, // balanceOf
		"0xdd62ed3e": true, // allowance
		"0x18160ddd": true, // totalSupply
		"0x313ce567": true, // decimals
	}
	selector := targetCall.Input
	if len(selector) > 10 {
		selector = selector[:10]
	}
	if standardSelectors[selector] || len(targetCall.Input) <= 10 {
		// 使用已有启发式挑选更有意义的调用（可能包含可变参数）
		if alt := f.selectTargetCall(protectedCalls); alt != nil {
			targetCall = alt
			targetCallIndex = findCallIndex(protectedCalls, alt)
			log.Printf("[Fuzzer] ⚙️  首个受保护调用为标准只读函数，回退到启发式选择 selector=%s idx=%d", selector, targetCallIndex)
		}
	}
	originalTargetCall := targetCall // 保存原始受保护合约调用，用于入口模式回退
	originalTargetIndex := targetCallIndex
	log.Printf("[Fuzzer] Selected first protected call: from=%s, input=%s", targetCall.From, targetCall.Input[:10])

	// 标记是否切换到Entry Call Fuzzing
	isEntryCallFuzzing := false
	useLoopBaseline := false

	// ========== 智能检测1：无参数函数自动回退到入口fuzzing ==========
	// 检查选中的函数是否有参数
	if !hasParameters(targetCall.Input) {
		log.Printf("[Fuzzer] ⚠️  WARNING: Selected function has no parameters (selector=%s)", targetCall.Input[:10])
		log.Printf("[Fuzzer] 🔄 Switching to ENTRY CALL fuzzing strategy...")
		log.Printf("[Fuzzer] Reason: Parameter fuzzing requires functions with parameters")
		log.Printf("[Fuzzer] New strategy: Fuzzing the attack transaction's entry point instead")

		// 切换到攻击交易的入口调用
		targetCall = f.selectEntryCall(trace)
		isEntryCallFuzzing = true
		log.Printf("[Fuzzer] 🎯 Entry call selected: from=%s, to=%s", targetCall.From, targetCall.To)
	}

	// ========== 智能检测2：循环函数检测（路径长度诊断）==========
	// 执行一次快速模拟，检查单次调用的路径长度
	testCallData, err := hexutil.Decode(targetCall.Input)
	if err == nil && hasParameters(targetCall.Input) {
		from := common.HexToAddress(targetCall.From)
		to := common.HexToAddress(targetCall.To)
		value := big.NewInt(0)
		if targetCall.Value != "" && targetCall.Value != "0x0" {
			if v, err := hexutil.DecodeBig(targetCall.Value); err == nil {
				value = v
			}
		}

		// 快速模拟单次调用，获取路径长度
		testResult, err := f.simulator.SimulateWithCallData(ctx, from, to, testCallData, value, blockNumber, stateOverride)
		if err == nil {
			singleCallPathLen := len(testResult.ContractJumpDests)
			originalPathLen := len(originalPath.ContractJumpDests)
			ratio := float64(singleCallPathLen) / float64(originalPathLen)

			log.Printf("[Fuzzer] 🔍 Path length diagnostic:")
			log.Printf("[Fuzzer]    - Single call path length: %d JUMPDESTs", singleCallPathLen)
			log.Printf("[Fuzzer]    - Original attack path length: %d JUMPDESTs", originalPathLen)
			log.Printf("[Fuzzer]    - Ratio: %.2f%% (single/original)", ratio*100)

			// 多重信号判定是否为循环函数
			pathMismatchLoop := ratio < 0.5 && singleCallPathLen > 0           // 路径长度启发
			repeatSelectorLoop := f.hasRepeatedSelector(trace, contractAddr)   // 调用树重复同一选择器
			backEdgeLoop := hasBackEdgeForContract(originalPath, contractAddr) // CFG 回边检测

			if repeatSelectorLoop {
				log.Printf("[Fuzzer] 🔁 检测到同一选择器多次调用，疑似循环攻击")
			}
			if backEdgeLoop {
				log.Printf("[Fuzzer] 🔁 检测到受保护合约存在回边/重复PC，疑似循环攻击")
			}

			if pathMismatchLoop || repeatSelectorLoop || backEdgeLoop {
				useLoopBaseline = true
				log.Printf("[Fuzzer] 🔁 检测到循环攻击，启用loopBaseline模式")

				// 如果配置要求仅对受保护合约启用Entry模式，则避免切换到攻击合约
				if f.entryCallProtectedOnly && !strings.EqualFold(trace.To, contractAddr.Hex()) {
					log.Printf("[Fuzzer] ⚠️  检测为循环函数，但入口合约非受保护对象，保持函数级Fuzz")
					log.Printf("[Fuzzer] 🔁 将使用loopBaseline子路径模式进行相似度比较，从原始路径中提取受保护合约的JUMPDEST子集")
				} else {
					log.Printf("[Fuzzer] ⚠️  WARNING: Likely LOOP FUNCTION detected (path/trace/CFG signals)")
					log.Printf("[Fuzzer] 🔄 Auto-switching to ENTRY CALL fuzzing strategy...")
					log.Printf("[Fuzzer] Reason: Cannot reproduce loop attacks by fuzzing single function call")
					log.Printf("[Fuzzer] Solution: Fuzzing the complete attack transaction entry point")

					// 切换到攻击交易的入口调用
					targetCall = f.selectEntryCall(trace)
					isEntryCallFuzzing = true
					log.Printf("[Fuzzer] 🎯 Entry call selected: from=%s, to=%s", targetCall.From, targetCall.To)
				}
			} else if singleCallPathLen == 0 {
				log.Printf("[Fuzzer] ⚠️  WARNING: Test simulation returned empty path (possible revert)")
			} else {
				log.Printf("[Fuzzer] ✅ Path length check passed, proceeding with function-level fuzzing")
			}
		} else {
			log.Printf("[Fuzzer] ⚠️  Path length diagnostic failed: %v", err)
		}
	}
	// ================================================================

	// 步骤3: 解析受保护合约调用的calldata
	callDataBytes, err := hexutil.Decode(targetCall.Input)
	if err != nil {
		return nil, fmt.Errorf("failed to decode target call input: %w", err)
	}
	log.Printf("[Fuzzer] Parsing protected contract calldata (%d bytes)", len(callDataBytes))

	// ✅ 智能ABI解析：Entry Call可能失败，需要回退机制
	parsedData, targetMethod, err := f.parseCallDataWithABI(contractAddr, callDataBytes)
	if err != nil {
		// 如果是Entry Call且ABI解析失败（攻击合约函数不在受保护合约ABI中）
		if isEntryCallFuzzing {
			log.Printf("[Fuzzer] ⚠️  Entry Call ABI parsing failed: %v", err)
			log.Printf("[Fuzzer] ⚠️  Entry call function (likely attack contract) not in protected contract ABI")
			log.Printf("[Fuzzer] 🔄 Fallback: Heuristic parsing of entry calldata (no ABI)")

			// 仍然使用入口调用，启发式解析参数
			if f.parser != nil {
				if parsed, perr := f.parser.ParseCallData(callDataBytes); perr == nil {
					parsedData = parsed
					targetMethod = nil
					err = nil
				} else {
					return nil, fmt.Errorf("failed to heuristically parse entry calldata: %w", perr)
				}
			} else {
				return nil, fmt.Errorf("parser not initialized for entry call fallback")
			}
		} else {
			return nil, fmt.Errorf("failed to parse protected contract calldata: %w", err)
		}
	}

	// Entry模式但无可变参数（仅选择器），先跑一次入口调用预热状态，然后回退到受保护合约函数级Fuzz
	if isEntryCallFuzzing && len(parsedData.Parameters) == 0 {
		log.Printf("[Fuzzer] ⚠️  Entry Call无参数可变，先重放入口调用以预热状态，再回退到受保护合约函数级Fuzz")

		// 🔧 检查并补充攻击合约代码
		attackContractAddr := strings.ToLower(targetCall.To)
		if stateOverride == nil {
			stateOverride = make(simulator.StateOverride)
		}
		if _, exists := stateOverride[attackContractAddr]; !exists {
			stateOverride[attackContractAddr] = &simulator.AccountOverride{}
		}
		existingCode := stateOverride[attackContractAddr].Code
		if existingCode == "" || existingCode == "0x" {
			// 从本地 RPC 查询攻击合约代码
			var localCode string
			if err := f.rpcClient.CallContext(ctx, &localCode, "eth_getCode", targetCall.To, "latest"); err == nil {
				if localCode != "" && localCode != "0x" && len(localCode) > 2 {
					stateOverride[attackContractAddr].Code = strings.ToLower(localCode)
					log.Printf("[Fuzzer] 🔧 从本地节点补充攻击合约代码: %s (size=%d bytes)",
						attackContractAddr, (len(localCode)-2)/2)
				} else {
					log.Printf("[Fuzzer] ⚠️  攻击合约 %s 本地代码为空，Entry预热可能失败", attackContractAddr)
				}
			} else {
				log.Printf("[Fuzzer] ⚠️  查询攻击合约代码失败: %v", err)
			}
		}

		// 重放入口调用，获取状态变更
		entryCallData, _ := hexutil.Decode(targetCall.Input)
		entryValue := big.NewInt(0)
		if targetCall.Value != "" && targetCall.Value != "0x0" {
			if v, err := hexutil.DecodeBig(targetCall.Value); err == nil {
				entryValue = v
			}
		}
		log.Printf("[Fuzzer] 🔍 调试: 开始模拟入口调用 from=%s to=%s calldata=%x value=%s block=%d",
			targetCall.From, targetCall.To, entryCallData, entryValue.String(), blockNumber)
		res, simErr := f.simulator.SimulateWithCallData(ctx, common.HexToAddress(targetCall.From), common.HexToAddress(targetCall.To), entryCallData, entryValue, blockNumber, stateOverride)
		if simErr != nil {
			log.Printf("[Fuzzer] ⚠️  入口调用模拟失败: %v", simErr)
			log.Printf("[Fuzzer] ⚠️  入口调用预热跳过（模拟错误），继续函数级Fuzz")
		} else if res == nil {
			log.Printf("[Fuzzer] ⚠️  入口调用模拟返回nil结果")
			log.Printf("[Fuzzer] ⚠️  入口调用预热跳过（结果为空），继续函数级Fuzz")
		} else if !res.Success {
			// 🔧 关键修复：入口调用revert是预期行为（攻击合约通常需要回调机制）
			// 不应阻塞后续fuzz，但也不应声称"预热成功"
			log.Printf("[Fuzzer] ⚠️  入口调用模拟revert (gas=%d, jumpDests=%d)", res.GasUsed, len(res.JumpDests))
			log.Printf("[Fuzzer] ⚠️  原因: 攻击合约入口函数可能依赖闪电贷回调等机制，单独调用必然revert")

			// 🆕 尝试从原始交易trace中提取调用受保护合约时的状态快照
			log.Printf("[Fuzzer] 🔍 尝试提取调用受保护合约时的状态快照...")
			snapshotSelector := ""
			callerSelector := ""
			if originalTargetCall != nil {
				callerSelector = originalTargetCall.From
				if len(originalTargetCall.Input) >= 10 {
					snapshotSelector = strings.ToLower(originalTargetCall.Input[:10])
				}
			}
			if snapshotSelector == "" && len(targetCall.Input) >= 10 {
				// 回退：若原始调用为空，使用入口selector尝试匹配
				snapshotSelector = strings.ToLower(targetCall.Input[:10])
			}
			callerAddr := strings.ToLower(callerSelector)
			snapshots, snapErr := f.simulator.ExtractAllCallSnapshots(ctx, txHash, contractAddr)
			if snapErr == nil && len(snapshots) > 0 {
				stateOverride = mergeSnapshotsIntoOverride(stateOverride, snapshots)
				ensureCodeForSnapshots(ctx, f.rpcClient, snapshots, &stateOverride)
				bestIdx := selectSnapshotWithPriority(snapshots, snapshotSelector, callerAddr, originalTargetIndex)
				if bestIdx >= 0 && bestIdx < len(snapshots) && !strings.EqualFold(snapshots[bestIdx].Selector, snapshotSelector) && snapshotSelector != "" {
					log.Printf("[Fuzzer] ⚠️  Selector未命中目标(%s)，使用优先级选择 idx=%d selector=%s", snapshotSelector, bestIdx, snapshots[bestIdx].Selector)
				}
				if bestIdx >= 0 && bestIdx < len(snapshots) {
					chosen := snapshots[bestIdx]
					stateOverride = simulator.BuildStateOverrideFromSnapshot(stateOverride, chosen)
					// 确保调用方/被调方代码可用，避免回调缺失导致revert
					ensureCodeInOverride(ctx, f.rpcClient, chosen.Caller, &stateOverride)
					ensureCodeInOverride(ctx, f.rpcClient, chosen.Callee, &stateOverride)
					log.Printf("[Fuzzer] ✅ 已根据selector选择并注入快照 (idx=%d selector=%s caller=%s)",
						bestIdx, chosen.Selector, chosen.Caller.Hex())
				} else {
					log.Printf("[Fuzzer] ⚠️  无法根据selector定位快照，使用索引回退")
				}
			} else {
				log.Printf("[Fuzzer] ⚠️  提取全部快照失败或为空，回退按索引提取: %v", snapErr)
				snapshotIndex := originalTargetIndex
				if snapshotIndex < 0 {
					snapshotIndex = 0
				}
				snapshot, snapErr := f.simulator.ExtractSnapshotForProtectedCall(ctx, txHash, contractAddr, snapshotIndex)
				if snapErr != nil {
					log.Printf("[Fuzzer] ⚠️  无法提取状态快照: %v", snapErr)
					log.Printf("[Fuzzer] ⚠️  入口调用预热跳过（revert），继续函数级Fuzz（使用prestate）")
				} else {
					// 使用快照注入正确的调用者状态
					stateOverride = simulator.BuildStateOverrideFromSnapshot(stateOverride, snapshot)
					ensureCodeInOverride(ctx, f.rpcClient, snapshot.Caller, &stateOverride)
					ensureCodeInOverride(ctx, f.rpcClient, snapshot.Callee, &stateOverride)
					log.Printf("[Fuzzer] ✅ 已提取调用时状态快照并注入 (caller=%s, balance=%s)",
						snapshot.Caller.Hex(), snapshot.CallerBalance)
				}
			}
		} else {
			// 模拟成功且有状态变更
			log.Printf("[Fuzzer] 🔍 调试: 模拟结果 success=%v, gasUsed=%d, jumpDests=%d, stateChanges=%d",
				res.Success, res.GasUsed, len(res.JumpDests), len(res.StateChanges))
			if len(res.StateChanges) > 0 {
				stateOverride = applyStateChangesToOverride(stateOverride, res.StateChanges)
				log.Printf("[Fuzzer] ✅ 入口调用预热完成，合并状态变更 %d 个合约", len(res.StateChanges))
			} else {
				log.Printf("[Fuzzer] ⚠️  入口调用成功但无状态变更 (可能为只读调用)")
			}
		}

		// 回退到受保护合约函数
		targetCall = originalTargetCall
		isEntryCallFuzzing = false
		callDataBytes, err = hexutil.Decode(targetCall.Input)
		if err != nil {
			return nil, fmt.Errorf("failed to decode protected call input after entry fallback: %w", err)
		}
		parsedData, targetMethod, err = f.parseCallDataWithABI(contractAddr, callDataBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse protected calldata after entry fallback: %w", err)
		}
	}

	// Entry模式下允许无ABI，仅使用启发式解析，不再回退到受保护合约函数
	log.Printf("[Fuzzer] Parsed: selector=0x%s, %d parameters", hex.EncodeToString(parsedData.Selector), len(parsedData.Parameters))

	// ========== Layer 3: 符号执行约束提取 ==========
	var symbolicSeeds []symbolic.SymbolicSeed
	if f.seedConfig != nil && f.seedConfig.SymbolicConfig != nil && f.seedConfig.SymbolicConfig.Enabled {
		log.Printf("[Fuzzer] 🔮 Symbolic execution enabled (mode=%s)", f.seedConfig.SymbolicConfig.Mode)

		// 初始化符号执行组件(延迟初始化)
		if f.symbolicExtractor == nil {
			f.symbolicExtractor = symbolic.NewConstraintExtractor(f.seedConfig.SymbolicConfig, f.rpcClient)
			f.symbolicSolver = symbolic.NewConstraintSolver(f.seedConfig.SymbolicConfig)
		}

		// 提取原始参数值
		paramValues := make([]interface{}, len(parsedData.Parameters))
		for i, p := range parsedData.Parameters {
			paramValues[i] = p.Value
		}

		// 从交易trace提取约束
		analysisResult, err := f.symbolicExtractor.ExtractFromTransaction(ctx, txHash, paramValues)
		if err != nil {
			log.Printf("[Symbolic] Warning: constraint extraction failed: %v", err)
		} else {
			log.Printf("[Symbolic] Extracted %d constraints, coverage=%.1f%%",
				len(analysisResult.Constraints), analysisResult.CoverageInfo.Coverage)

			// 求解约束
			solutions, err := f.symbolicSolver.SolveConstraints(ctx, analysisResult.Constraints)
			if err != nil {
				log.Printf("[Symbolic] Warning: constraint solving failed: %v", err)
			} else {
				log.Printf("[Symbolic] Solved %d parameter constraints", len(solutions))
			}

			// 收集符号种子
			symbolicSeeds = analysisResult.SymbolicSeeds
			log.Printf("[Symbolic] Generated %d symbolic seeds", len(symbolicSeeds))
		}
	}
	// ==================================================

	// 步骤4: 生成参数组合并执行模糊测试
	// 🔒 flash 函数：手工构造限幅组合，避免 SafeERC20 大量 revert
	var results []FuzzingResult

	if targetMethod != nil && strings.EqualFold(targetMethod.Name, "flash") {
		if len(parsedData.Parameters) < 4 {
			return nil, fmt.Errorf("flash parameter length mismatch: got %d", len(parsedData.Parameters))
		}

		// 尝试注入必要的授权与余额，避免 SafeERC20 revert
		injectFlashSeedOverrides(stateOverride, contractAddr, targetCall, parsedData.Parameters)

		param0 := parsedData.Parameters[0].Value
		param1 := parsedData.Parameters[1].Value
		origAmount := normalizeBigInt(parsedData.Parameters[2].Value)
		param3Orig := parsedData.Parameters[3].Value
		if origAmount == nil || origAmount.Sign() == 0 {
			return nil, fmt.Errorf("invalid flash amount seed")
		}

		amounts := []*big.Int{new(big.Int).Set(origAmount)}
		for _, denom := range []int64{2, 4} {
			v := new(big.Int).Div(origAmount, big.NewInt(denom))
			if v.Sign() > 0 {
				amounts = append(amounts, v)
			}
		}

		byteOpts := []interface{}{param3Orig}
		switch param3Orig.(type) {
		case []byte:
			byteOpts = append(byteOpts, []byte{})
		case string:
			byteOpts = append(byteOpts, "")
		default:
			byteOpts = append(byteOpts, nil)
		}

		seen := make(map[string]bool)
		dedup := make([]*big.Int, 0, len(amounts))
		for _, a := range amounts {
			key := a.String()
			if !seen[key] {
				seen[key] = true
				dedup = append(dedup, a)
			}
		}
		amounts = dedup

		combCh := make(chan []interface{}, len(amounts)*len(byteOpts))
		for _, amt := range amounts {
			for _, b := range byteOpts {
				combo := make([]interface{}, len(parsedData.Parameters))
				combo[0] = param0
				combo[1] = param1
				combo[2] = amt
				combo[3] = b
				combCh <- combo
			}
		}
		close(combCh)

		log.Printf("[Fuzzer] 🎯 flash函数使用限幅组合: amount<=%s, combos=%d", origAmount.String(), len(combCh))
		results = f.executeFuzzing(ctx, combCh, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, blockNumber, stateOverride, trace, useLoopBaseline)

		// 生成报告并返回
		log.Printf("[Fuzzer] Generating report...")
		report := f.merger.MergeResults(results, contractAddr, parsedData.Selector, txHash, blockNumber, startTime)

		// 应用约束规则（若已生成）
		f.applyConstraintRule(report, contractAddr, parsedData.Selector)

		if len(results) > 0 {
			sorted := make([]FuzzingResult, len(results))
			copy(sorted, results)
			sort.Slice(sorted, func(i, j int) bool { return sorted[i].Similarity > sorted[j].Similarity })
			if len(sorted) > 100 {
				sorted = sorted[:100]
			}
			report.HighSimilarityResults = ToPublicResults(sorted)
		}

		f.stats.EndTime = time.Now()
		f.stats.ValidCombinations = len(results)
		log.Printf("[Fuzzer] Fuzzing completed in %v", f.stats.EndTime.Sub(f.stats.StartTime))
		return report, nil
	}

	log.Printf("[Fuzzer] Generating parameter combinations...")

	// 对BarleyFinance关键函数收紧种子：地址仅使用原始值，数值不超过原始值，避免SafeERC20因余额/授权不足反复revert
	if f.seedConfig != nil && f.seedConfig.Enabled && targetMethod != nil &&
		(strings.EqualFold(targetMethod.Name, "flash") ||
			strings.EqualFold(targetMethod.Name, "bond") ||
			strings.EqualFold(targetMethod.Name, "debond")) {
		for _, p := range parsedData.Parameters {
			// 地址参数：只保留原始地址
			if strings.HasPrefix(p.Type, "address") {
				idx := p.Index
				f.seedConfig.AttackSeeds[idx] = []interface{}{p.Value}
			}

			// 数值参数：过滤掉大于原始值的种子，降低转账失败概率
			if strings.HasPrefix(p.Type, "uint") {
				orig := normalizeBigInt(p.Value)
				if orig == nil {
					continue
				}
				idx := p.Index
				if seeds, ok := f.seedConfig.AttackSeeds[idx]; ok {
					filtered := make([]interface{}, 0, len(seeds))
					for _, s := range seeds {
						if val := normalizeBigInt(s); val != nil && val.Cmp(orig) <= 0 {
							filtered = append(filtered, s)
						}
					}
					if len(filtered) > 0 {
						f.seedConfig.AttackSeeds[idx] = filtered
					} else {
						// 若过滤后为空，回退仅使用原始值
						f.seedConfig.AttackSeeds[idx] = []interface{}{p.Value}
					}
				} else {
					// 没有种子时也至少保留原始值
					f.seedConfig.AttackSeeds[idx] = []interface{}{p.Value}
				}
			}
		}
	}

	// 若未提供显式种子，注入原始调用参数作为基础种子，避免组合数过少
	if f.seedConfig != nil && f.seedConfig.Enabled {
		injected := primeSeedsWithOriginalParams(f.seedConfig, parsedData.Parameters)
		if injected || true {
			// 过滤地址类种子，保留原始地址，避免随机地址导致回调缺失
			sanitizeAddressSeeds(f.seedConfig, parsedData.Parameters)
			restrictComplexSeeds(f.seedConfig, parsedData.Parameters)
		}
	}

	// 判断是否启用自适应迭代模式
	if f.seedConfig != nil && f.seedConfig.Enabled &&
		f.seedConfig.AdaptiveConfig != nil && f.seedConfig.AdaptiveConfig.Enabled {
		log.Printf("[Fuzzer] 🎯 Adaptive iteration mode enabled (max_iterations=%d)", f.seedConfig.AdaptiveConfig.MaxIterations)
		results = f.executeAdaptiveFuzzing(ctx, parsedData, targetMethod, originalPath, targetCall, contractAddr, blockNumber, stateOverride, symbolicSeeds, trace, useLoopBaseline)
	} else {
		var combinations <-chan []interface{}
		if f.seedConfig != nil && f.seedConfig.Enabled {
			// 使用种子驱动生成器
			seedGen := NewSeedGenerator(f.seedConfig, f.generator.maxVariations)

			// 约束范围集成：如果有约束范围配置，合并约束种子
			if seedGen.HasConstraintRanges() {
				if targetMethod != nil {
					seedGen.MergeConstraintSeeds(targetMethod.Name)
					log.Printf("[Fuzzer] 📊 Merged constraint seeds for function: %s", targetMethod.Name)
				} else {
					for funcName := range f.seedConfig.ConstraintRanges {
						seedGen.MergeConstraintSeeds(funcName)
						log.Printf("[Fuzzer] 📊 Merged constraint seeds for function: %s", funcName)
					}
				}
				log.Printf("[Fuzzer] 📊 Using constraint ranges")
			}

			// Layer 3: 设置符号种子
			if len(symbolicSeeds) > 0 {
				seedGen.SetSymbolicSeeds(symbolicSeeds)
				log.Printf("[Fuzzer] 🔮 Applied %d symbolic seeds to generator", len(symbolicSeeds))
			}

			combinations = seedGen.GenerateSeedBasedCombinations(parsedData.Parameters)
			log.Printf("[Fuzzer] 🌱 Using seed-driven generation with %d attack seeds", len(f.seedConfig.AttackSeeds))
		} else {
			// 使用默认随机生成器
			combinations = f.generator.GenerateCombinations(parsedData.Parameters)
			log.Printf("[Fuzzer] Using default random generation")
		}

		log.Printf("[Fuzzer] Starting fuzzing with %d workers, threshold: %.2f", f.maxWorkers, f.threshold)
		results = f.executeFuzzing(ctx, combinations, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, blockNumber, stateOverride, trace, useLoopBaseline)
		log.Printf("[Fuzzer] Found %d valid combinations", len(results))
	}

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

	// 应用约束规则（若已生成）
	f.applyConstraintRule(report, contractAddr, parsedData.Selector)

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

// parseCallDataWithABI 优先使用ABI解析，失败则回退到启发式解析
func (f *CallDataFuzzer) parseCallDataWithABI(contractAddr common.Address, callData []byte) (*ParsedCallData, *abi.Method, error) {
	var contractABI *abi.ABI

	if f.parser != nil {
		if loaded, err := f.parser.LoadABIForAddress(contractAddr); err == nil {
			contractABI = loaded
		} else {
			log.Printf("[Fuzzer] ⚠️  加载ABI失败(%s)，将回退启发式解析: %v", contractAddr.Hex(), err)
		}
	}

	if contractABI != nil {
		parsed, err := f.parser.ParseCallDataWithABI(callData, contractABI)
		if err == nil {
			var method *abi.Method
			if m, err := contractABI.MethodById(parsed.Selector); err == nil {
				method = m
			} else {
				selectorHex := hex.EncodeToString(parsed.Selector)
				if alias, ok := syntheticSelectorAliases[selectorHex]; ok {
					// 针对缺失ABI但已知的入口选择器使用占位Method，避免完全失效
					log.Printf("[Fuzzer] ℹ️  使用内置占位ABI解析选择器0x%s (%s)", selectorHex, alias)
					method = &abi.Method{
						Name:            alias,
						RawName:         alias,
						Type:            abi.Function,
						StateMutability: "nonpayable",
						Inputs:          abi.Arguments{},
						Outputs:         abi.Arguments{},
					}
				} else {
					log.Printf("[Fuzzer] ⚠️  ABI中未找到选择器0x%s: %v", selectorHex, err)
				}
			}
			return parsed, method, nil
		}
		log.Printf("[Fuzzer] ⚠️  使用ABI解析失败，改用启发式解析: %v", err)
	}

	parsed, err := f.parser.ParseCallData(callData)
	return parsed, nil, err
}

// waitForTraceAvailable 智能等待trace数据就绪
// 先轮询TransactionReceipt确认交易已上链，然后额外等待让trace生成
func (f *CallDataFuzzer) waitForTraceAvailable(ctx context.Context, txHash common.Hash, timeout time.Duration) error {
	log.Printf("[Fuzzer] 🔍 智能等待：检查交易收据和trace数据就绪状态...")
	start := time.Now()

	// 第1步：轮询交易收据，确认交易已上链
	for {
		receipt, err := f.client.TransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			elapsed := time.Since(start)
			log.Printf("[Fuzzer] ✅ 交易收据已就绪 (区块 %d, 状态 %d, 耗时 %v)",
				receipt.BlockNumber.Uint64(), receipt.Status, elapsed)
			break
		}

		if time.Since(start) > timeout {
			return fmt.Errorf("timeout (%v) waiting for transaction receipt", timeout)
		}

		time.Sleep(200 * time.Millisecond)
	}

	// 第2步：收据就绪后，额外等待让Anvil生成trace数据
	// 原因：Anvil的trace生成是异步的，在交易上链后可能还需要几秒钟
	traceWaitTime := 5 * time.Second
	log.Printf("[Fuzzer] ⏳ 收据已就绪，再等待%v让Anvil生成trace数据...", traceWaitTime)
	time.Sleep(traceWaitTime)
	log.Printf("[Fuzzer] ✅ 智能等待完成，trace数据应该已就绪")

	return nil
}

// getOriginalExecution 获取原始交易的执行路径
// providedTx 参数可选：如果提供则直接使用，否则通过 txHash 查询（带重试）
func (f *CallDataFuzzer) getOriginalExecution(ctx context.Context, txHash common.Hash, blockNumber uint64, contractAddr common.Address, providedTx *types.Transaction) (*types.Transaction, *simulator.ReplayResult, simulator.StateOverride, error) {
	var tx *types.Transaction
	var err error

	// 优先使用传入的交易对象
	if providedTx != nil {
		log.Printf("[Fuzzer] 使用传入的交易对象（无需RPC查询）")
		tx = providedTx
	} else {
		// 如果没有提供交易对象，则通过 TransactionByHash 查询（带重试）
		log.Printf("[Fuzzer] 未提供交易对象，通过 TransactionByHash 查询...")
		tx, err = f.getTransactionWithRetry(ctx, txHash)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get transaction: %w", err)
		}
	}

	// 🔑 新增：智能等待trace数据就绪
	// 先确认交易收据可用，然后额外等待让trace生成
	log.Printf("[Fuzzer] 🎯 启动智能等待机制...")
	if err := f.waitForTraceAvailable(ctx, txHash, 30*time.Second); err != nil {
		log.Printf("[Fuzzer] ⚠️  智能等待超时: %v，继续尝试重试机制", err)
		// 不直接返回错误，让后续的重试机制继续尝试
	}

	// 构建交易执行前的 prestate，用于离线重放
	override, err := f.simulator.BuildStateOverride(ctx, txHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build state override: %w", err)
	}

	// 使用RPC重放原始攻击交易，作为基线路径
	result, err := f.simulator.ReplayTransactionWithOverride(ctx, tx, blockNumber, override, contractAddr)
	if err != nil {
		// 当节点不支持 stateOverrides 时，回退到本地EVM重放，保持prestate基线
		if f.localExecution && f.dualSimulator != nil {
			localExec := f.dualSimulator.GetLocalExecutor()
			if localExec != nil {
				// 基线重放时禁用变异，仅记录路径
				interceptor := localExec.GetInterceptor()
				if interceptor != nil {
					interceptor.ResetProtectedTracking()
					interceptor.SetMutationEnabled(false)
				}

				f.localExecMu.Lock()
				localRes, localErr := f.dualSimulator.ReplayTransactionLocal(ctx, tx, blockNumber, override)
				f.localExecMu.Unlock()

				if interceptor != nil {
					interceptor.SetMutationEnabled(true)
					if hit := interceptor.GetFirstProtectedHit(); hit != nil {
						log.Printf("[Fuzzer] 🪝 本地重放首个受保护调用: to=%s selector=%s depth=%d caller=%s",
							hit.Target.Hex(), hit.Selector, hit.Depth, hit.Caller.Hex())
					}
				}

				if localErr == nil && localRes != nil {
					log.Printf("[Fuzzer] 🔬 本地回退原始执行摘要: success=%v, gas=%d, stateChanges=%d, contractJumpDests=%d",
						localRes.Success, localRes.GasUsed, len(localRes.StateChanges), len(localRes.ContractJumpDests))
					return tx, localRes, override, nil
				}
				log.Printf("[Fuzzer] ⚠️ 本地回退重放失败: %v", localErr)
			}
		}

		return nil, nil, nil, fmt.Errorf("failed to replay transaction with prestate: %w", err)
	}

	log.Printf("[Fuzzer] 🔬 原始执行摘要(基于prestate RPC): success=%v, gas=%d, stateChanges=%d, jumpDests=%d, contractJumpDests=%d",
		result.Success, result.GasUsed, len(result.StateChanges), len(result.JumpDests), len(result.ContractJumpDests))

	return tx, result, override, nil
}

// getTransactionWithRetry 使用指数退避重试机制获取交易
func (f *CallDataFuzzer) getTransactionWithRetry(ctx context.Context, txHash common.Hash) (*types.Transaction, error) {
	maxRetries := 3
	retryDelays := []time.Duration{50 * time.Millisecond, 100 * time.Millisecond, 200 * time.Millisecond}

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		tx, _, err := f.client.TransactionByHash(ctx, txHash)
		if err == nil {
			if attempt > 0 {
				log.Printf("[Fuzzer] ✅ 第 %d 次重试成功获取交易", attempt+1)
			}
			return tx, nil
		}

		lastErr = err
		if attempt < maxRetries-1 {
			delay := retryDelays[attempt]
			log.Printf("[Fuzzer] ⚠️  获取交易失败 (尝试 %d/%d): %v，%v 后重试...",
				attempt+1, maxRetries, err, delay)
			time.Sleep(delay)
		}
	}

	log.Printf("[Fuzzer] ❌ 经过 %d 次重试仍无法获取交易", maxRetries)
	return nil, lastErr
}

// executeFuzzing 执行模糊测试
func (f *CallDataFuzzer) executeFuzzing(
	ctx context.Context,
	combinations <-chan []interface{},
	selector []byte,
	targetMethod *abi.Method,
	originalPath *simulator.ReplayResult,
	targetCall *CallFrame,
	contractAddr common.Address,
	blockNumber uint64,
	stateOverride simulator.StateOverride,
	callTree *CallFrame,
	loopBaseline bool,
) []FuzzingResult {
	// 🆕 创建可取消的context用于提前停止
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 结果收集
	results := []FuzzingResult{}
	resultMutex := &sync.Mutex{}

	// 统计
	var testedCount int32
	var validCount int32
	var highSimCount int32 // 🆕 高相似度结果计数
	batchTracker := newBatchBestTracker()

	// 🆕 检查是否启用目标相似度停止
	targetSimEnabled := f.targetSimilarity > 0 && f.maxHighSimResults > 0
	if targetSimEnabled {
		log.Printf("[Fuzzer] 🎯 Target similarity mode: stop when finding %d valid results (sim >= %.4f)",
			f.maxHighSimResults, f.targetSimilarity)
	}

	// 预计算函数级基准路径，避免循环场景误用非目标函数起点
	var functionBaseline []ContractJumpDest
	if loopBaseline {
		functionBaseline = f.buildFunctionBaseline(ctx, targetCall, contractAddr, blockNumber, stateOverride)
	}

	// 输出StateOverride概况，便于诊断无状态变更场景
	overrideAccounts, overrideSlots, overrideTargetSlots := summarizeOverride(stateOverride, contractAddr)
	log.Printf("[Fuzzer] 🧊 StateOverride概要: 账户=%d, 槽位总数=%d, 受保护合约槽位=%d",
		overrideAccounts, overrideSlots, overrideTargetSlots)

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
				targetMethod,
				originalPath,
				targetCall,
				contractAddr,
				blockNumber,
				stateOverride,
				callTree,
				&results,
				resultMutex,
				&testedCount,
				&validCount,
				&highSimCount, // 🆕 传递高相似度计数器
				batchTracker,
				cancel, // 🆕 传递cancel函数
				functionBaseline,
				loopBaseline,
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

	log.Printf("[Fuzzer] Tested %d combinations, found %d valid (high-sim: %d)",
		testedCount, validCount, highSimCount)

	return results
}

// buildFunctionBaseline 基于原始调用参数构建函数级基准路径，避免基准起点落在debond等非目标函数
func (f *CallDataFuzzer) buildFunctionBaseline(
	ctx context.Context,
	targetCall *CallFrame,
	contractAddr common.Address,
	blockNumber uint64,
	stateOverride simulator.StateOverride,
) []ContractJumpDest {
	if targetCall == nil {
		return nil
	}

	callData, err := hexutil.Decode(targetCall.Input)
	if err != nil {
		log.Printf("[Fuzzer] ⚠️  无法解码原始调用输入，跳过函数级基准构建: %v", err)
		return nil
	}

	value := big.NewInt(0)
	if targetCall.Value != "" && targetCall.Value != "0x0" {
		if v, err := hexutil.DecodeBig(targetCall.Value); err == nil {
			value = v
		}
	}

	req := &SimulationRequest{
		From:          common.HexToAddress(targetCall.From),
		To:            common.HexToAddress(targetCall.To),
		CallData:      callData,
		Value:         value,
		BlockNumber:   blockNumber,
		Timeout:       f.timeout,
		StateOverride: stateOverride,
	}

	simResult, err := f.simulateExecution(ctx, req, -1)
	if err != nil {
		log.Printf("[Fuzzer] ⚠️  函数级基准构建模拟失败: %v", err)
		return nil
	}

	baseline := extractProtectedContractPath(simResult.ContractJumpDests, contractAddr, 0)
	if len(baseline) > 0 {
		head := make([]uint64, 0, 5)
		for i := 0; i < len(baseline) && i < 5; i++ {
			head = append(head, baseline[i].PC)
		}
		log.Printf("[Fuzzer] 📌 函数级基准路径就绪: len=%d, 前5个PC=%v", len(baseline), head)
	} else {
		log.Printf("[Fuzzer] ⚠️  函数级基准路径为空，跳过对齐优化")
	}

	return baseline
}

// applyStateChangesToOverride 将模拟得到的状态变更合并进StateOverride，用于后续Fuzz保持前置调用效果
func applyStateChangesToOverride(base simulator.StateOverride, changes map[string]simulator.StateChange) simulator.StateOverride {
	if base == nil {
		base = make(simulator.StateOverride)
	}

	for addr, change := range changes {
		lowerAddr := strings.ToLower(addr)
		ov, exists := base[lowerAddr]
		if !exists {
			ov = &simulator.AccountOverride{}
			base[lowerAddr] = ov
		}

		if change.BalanceAfter != "" {
			ov.Balance = change.BalanceAfter
		}

		if len(change.StorageChanges) > 0 {
			if ov.State == nil {
				ov.State = make(map[string]string)
			}
			for slot, upd := range change.StorageChanges {
				if upd.After != "" {
					ov.State[strings.ToLower(slot)] = upd.After
				}
			}
		}
	}

	return base
}

// applySimulatorStateChangesToOverride 将ReplayResult的StateChanges合并到StateOverride
func applySimulatorStateChangesToOverride(base simulator.StateOverride, changes map[string]simulator.StateChange) simulator.StateOverride {
	return applyStateChangesToOverride(base, changes)
}

// summarizeOverride 汇总StateOverride的账户和槽位信息，便于日志诊断无状态变更问题
func summarizeOverride(override simulator.StateOverride, target common.Address) (int, int, int) {
	if override == nil {
		return 0, 0, 0
	}

	accountCount := len(override)
	totalSlots := 0
	targetSlots := 0
	targetKey := strings.ToLower(target.Hex())

	for addr, ov := range override {
		if ov == nil || ov.State == nil {
			continue
		}
		slotCount := len(ov.State)
		totalSlots += slotCount
		if addr == targetKey {
			targetSlots = slotCount
		}
	}

	return accountCount, totalSlots, targetSlots
}

// formatParamValuesForLog 将参数组合格式化为简洁字符串
func formatParamValuesForLog(combo []interface{}) string {
	if len(combo) == 0 {
		return "[]"
	}
	parts := make([]string, 0, len(combo))
	for i, v := range combo {
		parts = append(parts, fmt.Sprintf("#%d=%s", i, ValueToString(v)))
	}
	return strings.Join(parts, ", ")
}

// formatSelectorForLog 返回4字节selector的16进制展示
func formatSelectorForLog(calldata []byte) string {
	if len(calldata) >= 4 {
		return hexutil.Encode(calldata[:4])
	}
	return hexutil.Encode(calldata)
}

// worker 工作协程
func (f *CallDataFuzzer) worker(
	ctx context.Context,
	workerID int,
	combinations <-chan []interface{},
	selector []byte,
	targetMethod *abi.Method,
	originalPath *simulator.ReplayResult,
	targetCall *CallFrame,
	contractAddr common.Address,
	blockNumber uint64,
	stateOverride simulator.StateOverride,
	callTree *CallFrame,
	results *[]FuzzingResult,
	resultMutex *sync.Mutex,
	testedCount *int32,
	validCount *int32,
	highSimCount *int32, // 🆕 高相似度计数器
	batchTracker *batchBestTracker, // 🆕 批次最佳路径记录器
	cancel context.CancelFunc, // 🆕 cancel函数用于提前停止
	functionBaseline []ContractJumpDest, // 函数级基准路径（对齐bond入口）
	loopBaseline bool, // 循环场景使用子路径基准
) {
	// 预先汇总一次StateOverride，供后续日志使用
	overrideAccounts, overrideSlots, overrideTargetSlots := summarizeOverride(stateOverride, contractAddr)

	for combo := range combinations {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 增加测试计数
		currentCount := atomic.AddInt32(testedCount, 1)

		// 重构calldata（使用受保护合约调用的selector和变异参数）
		newCallData, err := f.reconstructCallData(selector, combo, targetMethod, workerID)
		if err != nil {
			log.Printf("[Worker %d] Failed to reconstruct calldata: %v", workerID, err)
			continue
		}

		// 创建模拟请求：直接模拟调用受保护合约
		from := common.HexToAddress(targetCall.From) // 使用原始调用者地址
		to := common.HexToAddress(targetCall.To)     // 使用目标合约地址（entry call时为攻击合约入口）

		// 解析value（如果有）
		value := big.NewInt(0)
		if targetCall.Value != "" && targetCall.Value != "0x0" {
			if v, err := hexutil.DecodeBig(targetCall.Value); err == nil {
				value = v
			}
		}

		// 执行全交易Hook模拟：本地模式使用DualModeSimulator，RPC模式保持原逻辑
		var simResult *SimulationResult

		if f.localExecution && f.dualSimulator != nil {
			// 构造入口调用参数（优先使用调用树根节点）
			entry := callTree
			if entry == nil {
				entry = targetCall
			}
			if entry == nil {
				log.Printf("[Worker %d] ⚠️ 无法获取入口调用，跳过本次组合", workerID)
				continue
			}

			entryFrom := common.HexToAddress(entry.From)
			entryTo := common.HexToAddress(entry.To)
			entryData, decodeErr := hexutil.Decode(entry.Input)
			if decodeErr != nil {
				log.Printf("[Worker %d] ⚠️ 解码入口calldata失败: %v", workerID, decodeErr)
				continue
			}
			entryValue := big.NewInt(0)
			if entry.Value != "" && entry.Value != "0x0" {
				if v, err := hexutil.DecodeBig(entry.Value); err == nil {
					entryValue = v
				}
			}

			// 新架构：如果已注册受保护合约，使用拦截器自动变异
			var mutators map[common.Address]local.CallMutatorV2
			if f.registry == nil {
				// 回退：仅对目标合约使用显式mutator（旧逻辑）
				hookMutator := func(frame *CallFrame, original []byte) ([]byte, bool, error) {
					if strings.EqualFold(frame.To, contractAddr.Hex()) {
						mutated, err := f.reconstructCallData(selector, combo, targetMethod, workerID)
						if err != nil {
							return nil, false, err
						}
						return mutated, true, nil
					}
					return original, false, nil
				}
				mutators = map[common.Address]local.CallMutatorV2{
					contractAddr: simulator.AdaptCallMutator(hookMutator),
				}
			}

			f.localExecMu.Lock()
			hookRes, simErr := f.dualSimulator.SimulateWithCallDataV2(
				ctx,
				entryFrom,
				entryTo,
				entryData,
				entryValue,
				blockNumber,
				stateOverride,
				mutators,
			)
			f.localExecMu.Unlock()

			if simErr != nil {
				log.Printf("[Worker %d] ⚠️ 本地Hook执行失败: %v", workerID, simErr)
				continue
			}

			simResult = &SimulationResult{
				Success:           hookRes.Success,
				JumpDests:         hookRes.JumpDests,
				ContractJumpDests: convertSimulatorCJDs(hookRes.ContractJumpDests),
				GasUsed:           hookRes.GasUsed,
				Error:             nil,
				StateChanges:      convertSimulatorStateChanges(hookRes.StateChanges),
			}
			if hookRes.Error != "" {
				simResult.Error = fmt.Errorf(hookRes.Error)
			}
			if hookRes.ReturnData != "" && hookRes.ReturnData != "0x" {
				if decoded, err := hexutil.Decode(hookRes.ReturnData); err == nil {
					simResult.ReturnData = decoded
				}
			}

		} else {
			hookMutator := func(frame *CallFrame, original []byte) ([]byte, bool, error) {
				if strings.EqualFold(frame.To, contractAddr.Hex()) {
					mutated, err := f.reconstructCallData(selector, combo, targetMethod, workerID)
					if err != nil {
						return nil, false, err
					}
					return mutated, true, nil
				}
				return original, false, nil
			}

			hookRes, simErr := f.simulator.ExecuteWithHooks(
				ctx,
				callTree,
				blockNumber,
				stateOverride,
				map[string]simulator.CallMutator{strings.ToLower(contractAddr.Hex()): hookMutator},
			)
			if simErr != nil {
				if isFatalRPCError(simErr) {
					log.Printf("[Worker %d] 🚨 RPC不可用 (%v)，触发全局取消", workerID, simErr)
					cancel()
					return
				}
				log.Printf("[Worker %d] ⚠️  Hook执行失败: %v", workerID, simErr)
				continue
			}

			simResult = &SimulationResult{
				Success:           hookRes.Success,
				JumpDests:         hookRes.JumpDests,
				ContractJumpDests: convertSimulatorCJDs(hookRes.ContractJumpDests),
				GasUsed:           hookRes.GasUsed,
				Error:             nil,
				StateChanges:      convertSimulatorStateChanges(hookRes.StateChanges),
			}
			if hookRes.Error != "" {
				simResult.Error = fmt.Errorf(hookRes.Error)
			}
			if hookRes.ReturnData != "" && hookRes.ReturnData != "0x" {
				if decoded, err := hexutil.Decode(hookRes.ReturnData); err == nil {
					simResult.ReturnData = decoded
				}
			}
		}

		if !simResult.Success {
			revertMsg := decodeRevertMessage(simResult.ReturnData)
			if revertMsg == "" && simResult.Error != nil {
				revertMsg = simResult.Error.Error()
			}

			traceErr := ""
			if simResult.Error != nil {
				traceErr = simResult.Error.Error()
			}

			lastPath := ""
			if len(simResult.ContractJumpDests) > 0 {
				start := len(simResult.ContractJumpDests) - 3
				if start < 0 {
					start = 0
				}
				lastPath = formatPathSnippet(simResult.ContractJumpDests, start)
			}

			selectorHex := hexutil.Encode(newCallData)
			if len(newCallData) > 4 {
				selectorHex = hexutil.Encode(newCallData[:4])
			}

			log.Printf("[Worker %d] ⚠️  模拟交易revert，跳过相似度计算 (gas=%d, msg=%s, traceErr=%s, lastPath=%s, return=%s, selector=%s, len=%d, from=%s, to=%s, value=%s)",
				workerID, simResult.GasUsed, revertMsg, traceErr, lastPath, formatReturnDataForLog(simResult.ReturnData), selectorHex, len(newCallData), from.Hex(), to.Hex(), value.String())
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

		startIndex := originalPath.ProtectedStartIndex
		// 若 tracer 未能正确标记受保护起点，尝试根据目标合约地址回退定位
		if startIndex < 0 || startIndex >= len(origContractJumpDests) {
			if idx := findProtectedStartIndex(origContractJumpDests, contractAddr); idx >= 0 {
				startIndex = idx
				log.Printf("[Worker %d] ⚙️  修正 ProtectedStartIndex 为 %d（基于目标合约 %s）", workerID, startIndex, contractAddr.Hex())
			} else {
				startIndex = 0
				log.Printf("[Worker %d] ⚠️  未能定位受保护合约，使用起始索引 0", workerID)
			}
		}

		// 循环场景：使用受保护合约子路径作为基准，避免外层路径稀释相似度
		baseline := origContractJumpDests
		baselineStart := startIndex

		// 变异路径也裁剪到受保护合约片段，避免被外层调用稀释
		var candidatePath []ContractJumpDest
		if loopBaseline {
			if seg := extractProtectedContractPath(simResult.ContractJumpDests, contractAddr, 0); len(seg) > 0 {
				candidatePath = seg
			} else {
				candidatePath = simResult.ContractJumpDests
				log.Printf("[Worker %d] ⚠️  变异路径未找到受保护片段，使用完整路径", workerID)
			}
		} else {
			candidatePath = simResult.ContractJumpDests
		}

		// 🔧 关键修复：循环场景下，按函数入口PC对齐基准路径
		// 原因1：原始攻击可能先调用balanceOf/decimals等，导致基准路径从非目标函数开始
		// 原因2：原始攻击包含20次循环，但fuzz只模拟单次调用
		// 原因3：原始攻击流程为 debond→flash→bond×20，但fuzz只执行bond
		// 解决方案：从fuzz路径的第一个PC（函数入口）在【完整原始路径】中找到对应位置，而非从startIndex截取的子路径
		if loopBaseline {
			loopSeg := extractProtectedContractPath(origContractJumpDests, contractAddr, startIndex)

			// 如果基准不含当前入口PC，使用函数级基准（通常对应bond路径），避免落在debond起点
			if len(functionBaseline) > 0 {
				fuzzEntryPC := uint64(0)
				if len(candidatePath) > 0 {
					fuzzEntryPC = candidatePath[0].PC
				}
				if len(loopSeg) == 0 || (fuzzEntryPC != 0 && !containsPC(loopSeg, fuzzEntryPC)) {
					loopSeg = functionBaseline
					startIndex = 0
					if currentCount <= 2 {
						log.Printf("[Worker %d] 🔁 使用函数级基准路径对齐 (入口PC=%d, len=%d)", workerID, fuzzEntryPC, len(loopSeg))
					}
				}
			}

			if len(loopSeg) > 0 {
				// 🆕 函数入口对齐：获取fuzz路径的第一个PC作为函数入口参考点
				var alignedLoopSeg []ContractJumpDest
				if len(candidatePath) > 0 {
					fuzzEntryPC := candidatePath[0].PC
					// 🔧 核心修复：在【完整原始路径】中搜索fuzz入口PC，而非仅在loopSeg中搜索
					// 原因：loopSeg从startIndex（debond）开始提取，不包含bond的路径
					// 而原始攻击路径包含：debond_path + 20*(flash_path + bond_path)
					// 所以bond的PC=149只存在于完整路径中，不在debond开始的loopSeg中
					alignIndex := -1
					for i, jd := range origContractJumpDests {
						if strings.EqualFold(jd.Contract, strings.ToLower(contractAddr.Hex())) && jd.PC == fuzzEntryPC {
							alignIndex = i
							break
						}
					}
					if alignIndex >= 0 && alignIndex < len(origContractJumpDests) {
						// 🔧 修复：从origContractJumpDests的对齐位置开始提取受保护合约的路径
						// 而不是从loopSeg中提取（loopSeg可能不包含目标函数的路径）
						alignedLoopSeg = extractProtectedContractPath(origContractJumpDests, contractAddr, alignIndex)
						if currentCount <= 2 {
							log.Printf("[Worker %d] 🎯 函数入口对齐成功: fuzz入口PC=%d, 在完整路径中的索引=%d, 提取后基准长度=%d",
								workerID, fuzzEntryPC, alignIndex, len(alignedLoopSeg))
						}
					} else {
						// 🆕 对齐失败，使用滑动窗口法找最佳对齐位置
						// 原因：原始攻击可能先调用其他函数（debond等），fuzz入口PC在基准中找不到精确匹配
						bestAlignIdx := 0
						bestAlignSim := float64(0)
						windowSize := len(candidatePath)
						maxSearchWindow := len(loopSeg) - windowSize + 1
						if maxSearchWindow > 30 {
							maxSearchWindow = 30 // 限制搜索范围，避免性能问题
						}
						if maxSearchWindow < 1 {
							maxSearchWindow = 1
						}

						for offset := 0; offset < maxSearchWindow; offset++ {
							// 计算从offset开始的子路径与fuzz路径的相似度
							endIdx := offset + windowSize
							if endIdx > len(loopSeg) {
								endIdx = len(loopSeg)
							}
							windowSeg := loopSeg[offset:endIdx]
							sim := f.comparator.CompareContractJumpDests(windowSeg, candidatePath, 0)
							if sim > bestAlignSim {
								bestAlignSim = sim
								bestAlignIdx = offset
							}
						}

						// 使用最佳对齐位置
						alignedLoopSeg = loopSeg[bestAlignIdx:]
						if currentCount <= 2 {
							log.Printf("[Worker %d] 🔄 滑动窗口对齐: fuzz入口PC=%d在基准中无精确匹配，使用滑动窗口找到最佳对齐位置=%d (相似度=%.4f)",
								workerID, fuzzEntryPC, bestAlignIdx, bestAlignSim)
							// 打印对齐后的前几个PC
							var alignedPCs []uint64
							for i := 0; i < len(alignedLoopSeg) && i < 5; i++ {
								alignedPCs = append(alignedPCs, alignedLoopSeg[i].PC)
							}
							log.Printf("[Worker %d] 🔍 对齐后基准前5个PC=%v, fuzz前5个PC=[%d,%d,...]",
								workerID, alignedPCs, candidatePath[0].PC, func() uint64 {
									if len(candidatePath) > 1 {
										return candidatePath[1].PC
									}
									return 0
								}())
						}
					}
				} else {
					alignedLoopSeg = loopSeg
				}

				// 计算合适的基准长度：约为fuzz路径的1.5倍
				targetLen := int(float64(len(candidatePath)) * 1.5)
				if targetLen < len(candidatePath) {
					targetLen = len(candidatePath) // 至少与fuzz路径一样长
				}
				if targetLen > len(alignedLoopSeg) {
					targetLen = len(alignedLoopSeg) // 不超过对齐后的子路径长度
				}

				// 截取前targetLen个JUMPDEST作为基准
				baseline = alignedLoopSeg[:targetLen]
				baselineStart = 0
				if currentCount <= 2 { // 首次和第二次都打印，便于验证
					log.Printf("[Worker %d] 🔁 使用对齐后的循环体子路径作为基准 (原始len=%d -> 子路径len=%d -> 对齐后len=%d -> 截取len=%d, fuzz路径len=%d)",
						workerID, len(origContractJumpDests), len(loopSeg), len(alignedLoopSeg), targetLen, len(candidatePath))
				}
			} else {
				log.Printf("[Worker %d] ⚠️  循环体子路径为空，回退使用完整路径 (len=%d)",
					workerID, len(origContractJumpDests))
			}
		}

		similarity := f.comparator.CompareContractJumpDests(
			baseline,
			candidatePath,
			baselineStart,
		)

		// 记录批次最佳路径（每100个组合汇总一次）
		if batchTracker != nil {
			batchTracker.Update(currentCount, similarity, simResult.ContractJumpDests, workerID)
			if currentCount%100 == 0 {
				windowID := currentCount/100 - 1
				if bestSim, bestPath, bestWorker, ok := batchTracker.Snapshot(windowID); ok && len(bestPath) > 0 {
					batchStart := int(windowID*100 + 1)
					batchEnd := int((windowID + 1) * 100)
					log.Printf("[Fuzzer] 📌 批次%d-%d最佳相似度=%.4f (来自Worker %d), JUMPDEST路径: %s",
						batchStart, batchEnd, bestSim, bestWorker, formatPathSnippet(bestPath, 0))
				}
			}
		}

		// 仅在达标时打印路径片段，避免日志爆炸；按测试计数采样
		// 🔧 修复：打印实际比较的baseline和candidatePath，而非原始的origContractJumpDests
		if similarity >= f.threshold && (currentCount <= 5 || currentCount%500 == 0) {
			log.Printf("[Worker %d] 路径片段: 基准%s ; Fuzz%s (sim=%.4f)", workerID,
				formatPathSnippet(baseline, baselineStart),
				formatPathSnippet(candidatePath, 0),
				similarity,
			)
		}

		// 🆕 需求1: 记录每个组合的相似度（每100个组合记录一次，避免日志刷屏）
		if currentCount%100 == 0 {
			log.Printf("[Worker %d] 进度: 已测试%d个组合, 当前相似度=%.4f (阈值=%.4f)",
				workerID, currentCount, similarity, f.threshold)
		}

		// 如果相似度超过阈值，进行后续检查
		if similarity >= f.threshold {
			// 记录模拟执行概况，便于诊断“高相似度但无违规”的原因
			stateChangeCount := len(simResult.StateChanges)
			if stateChangeCount == 0 {
				if currentCount <= 5 || currentCount%50 == 0 {
					log.Printf("[Worker %d] 🧾 无状态变更详情: selector=%s, params=%s, fuzzPathLen=%d, baselineLen=%d, jumpDests=%d, override(accounts=%d,slots=%d,targetSlots=%d)",
						workerID,
						formatSelectorForLog(newCallData),
						formatParamValuesForLog(combo),
						len(candidatePath),
						len(baseline),
						len(simResult.ContractJumpDests),
						overrideAccounts, overrideSlots, overrideTargetSlots)
				}
				log.Printf("[Worker %d] 📊 相似度达标 sim=%.4f，但无状态变更 (success=%v, gas=%d)，不会计入有效结果", workerID, similarity, simResult.Success, simResult.GasUsed)
			} else {
				// 打印前3个有变化的合约地址，避免日志爆炸
				changedAddrs := make([]string, 0, 3)
				for addr := range simResult.StateChanges {
					changedAddrs = append(changedAddrs, addr)
					if len(changedAddrs) >= 3 {
						break
					}
				}
				log.Printf("[Worker %d] 📊 相似度达标 sim=%.4f, 状态变更=%d 个 (success=%v, gas=%d, 变更合约前3: %v)",
					workerID, similarity, stateChangeCount, simResult.Success, simResult.GasUsed, changedAddrs)
			}

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

			// 没有状态变更且无违规，视为无效，不计数
			if stateChangeCount == 0 && len(violations) == 0 {
				continue
			}

			// 通过路径相似度检查(以及可选的不变量检查),记录结果
			atomic.AddInt32(validCount, 1)

			// 创建参数值列表
			paramValues := f.extractParameterValues(combo, selector)

			// 记录高相似样本用于约束生成
			if f.constraintCollector != nil && similarity >= f.threshold {
				if rule := f.constraintCollector.RecordSample(contractAddr, selector, paramValues, simResult.StateChanges, similarity); rule != nil {
					log.Printf("[Worker %d] 📐 已生成约束规则: %s selector=%s 样本=%d", workerID, contractAddr.Hex(), rule.FunctionSelector, rule.SampleCount)
				}
			}

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

			// 🆕 检查是否达到目标相似度
			targetSimEnabled := f.targetSimilarity > 0 && f.maxHighSimResults > 0
			if targetSimEnabled && similarity >= f.targetSimilarity {
				currentHighSim := atomic.AddInt32(highSimCount, 1)
				log.Printf("[Worker %d] ✅ Found high-similarity result #%d (sim=%.4f >= %.4f)",
					workerID, currentHighSim, similarity, f.targetSimilarity)

				// 达到目标数量，触发全局停止
				if int(currentHighSim) >= f.maxHighSimResults {
					log.Printf("[Fuzzer] 🎯 Found %d high-similarity results (>= %.4f), stopping all workers",
						currentHighSim, f.targetSimilarity)
					cancel() // 取消所有worker
					return
				}
			}

			if int(atomic.LoadInt32(validCount))%10 == 0 {
				log.Printf("[Worker %d] Found valid combination #%d with similarity %.4f (violations: %d)",
					workerID, atomic.LoadInt32(validCount), similarity, len(violations))
			}
		}
	}
}

// reconstructCallData 使用ABI优先编码动态参数，失败时回退到启发式编码
func (f *CallDataFuzzer) reconstructCallData(selector []byte, params []interface{}, method *abi.Method, workerID int) ([]byte, error) {
	if method != nil {
		normalized := normalizeParamsForABI(params, method)
		if packed, err := method.Inputs.Pack(normalized...); err == nil {
			return append(selector, packed...), nil
		} else {
			log.Printf("[Worker %d] ⚠️  ABI编码失败，改用启发式编码: %v", workerID, err)
		}
	}
	return f.parser.ReconstructCallData(selector, params)
}

// normalizeParamsForABI 根据ABI类型将变异参数转换为go-ethereum期望的类型
func normalizeParamsForABI(params []interface{}, method *abi.Method) []interface{} {
	if method == nil || len(method.Inputs) != len(params) {
		return params
	}

	normalized := make([]interface{}, len(params))
	for i, arg := range method.Inputs {
		normalized[i] = normalizeSingleParam(params[i], arg.Type.String())
	}
	return normalized
}

func normalizeSingleParam(val interface{}, typeStr string) interface{} {
	switch {
	case typeStr == "address":
		return normalizeAddress(val)
	case strings.HasPrefix(typeStr, "uint") && !strings.HasSuffix(typeStr, "[]"):
		if typeStr == "uint8" {
			if v, ok := normalizeUint8(val); ok {
				return v
			}
		}
		if bi := normalizeBigInt(val); bi != nil {
			return bi
		}
	case typeStr == "address[]":
		if addrs := normalizeAddressSlice(val); addrs != nil {
			return addrs
		}
	case typeStr == "uint8[]":
		if arr := normalizeUint8Slice(val); arr != nil {
			return arr
		}
		// 标量种子（如 *big.Int、string）包装为单元素数组，避免 ABI 误判为标量
		if n, ok := normalizeUint8(val); ok {
			return []uint8{n}
		}
	case strings.HasPrefix(typeStr, "uint") && strings.HasSuffix(typeStr, "[]"):
		if arr := normalizeUintSlice(val); arr != nil {
			return arr
		}
	case strings.HasPrefix(typeStr, "bytes"):
		if b := normalizeBytes(val); b != nil {
			return b
		}
	}

	return val
}

func normalizeAddress(val interface{}) common.Address {
	switch v := val.(type) {
	case common.Address:
		return v
	case string:
		// 检查是否是数字字符串（配置错误）
		if !strings.HasPrefix(v, "0x") {
			// 尝试作为数字解析
			if bi, ok := new(big.Int).SetString(v, 10); ok {
				return common.BigToAddress(bi)
			}
		}
		return common.HexToAddress(v)
	case *big.Int:
		// 大整数转地址
		return common.BigToAddress(v)
	case int, int64, uint64:
		// 整数转地址
		val64 := reflect.ValueOf(v).Int()
		return common.BigToAddress(big.NewInt(val64))
	case []byte:
		if len(v) >= 20 {
			return common.BytesToAddress(v[len(v)-20:])
		}
	}
	return common.Address{}
}

func normalizeAddressSlice(val interface{}) []common.Address {
	switch v := val.(type) {
	case []common.Address:
		return v
	case []string:
		addrs := make([]common.Address, 0, len(v))
		for _, s := range v {
			addrs = append(addrs, common.HexToAddress(s))
		}
		return addrs
	case []interface{}:
		addrs := make([]common.Address, 0, len(v))
		for _, item := range v {
			addrs = append(addrs, normalizeAddress(item))
		}
		return addrs
	}
	return nil
}

func normalizeUint8(val interface{}) (uint8, bool) {
	switch v := val.(type) {
	case uint8:
		return v, true
	case int:
		return uint8(v), true
	case int64:
		return uint8(v), true
	case uint64:
		return uint8(v), true
	case *big.Int:
		return uint8(v.Uint64()), true
	case string:
		if strings.HasPrefix(v, "0x") {
			if b, err := hexutil.Decode(v); err == nil && len(b) > 0 {
				return uint8(b[len(b)-1]), true
			}
		} else if n, ok := new(big.Int).SetString(v, 10); ok {
			return uint8(n.Uint64()), true
		}
	}
	return 0, false
}

func normalizeUint8Slice(val interface{}) []uint8 {
	switch v := val.(type) {
	case []byte:
		return v
	case []interface{}:
		arr := make([]uint8, 0, len(v))
		for _, item := range v {
			if n, ok := normalizeUint8(item); ok {
				arr = append(arr, n)
			}
		}
		return arr
	case *big.Int:
		// ✅ 新增：大整数包装为单元素数组
		if v.Cmp(big.NewInt(255)) <= 0 && v.Sign() >= 0 {
			return []uint8{uint8(v.Uint64())}
		}
		log.Printf("[Normalize] ⚠️  big.Int %s out of uint8 range, using fallback", v.String())
		return nil
	case string:
		// ✅ 新增：字符串处理（可能是hex或数字）
		if strings.HasPrefix(v, "0x") {
			// hex字符串转bytes
			bytes := common.FromHex(v)
			return bytes
		} else if n, ok := new(big.Int).SetString(v, 10); ok {
			// 数字字符串
			if n.Cmp(big.NewInt(255)) <= 0 && n.Sign() >= 0 {
				return []uint8{uint8(n.Uint64())}
			}
		}
		return nil
	}
	return nil
}

func normalizeUintSlice(val interface{}) []*big.Int {
	switch v := val.(type) {
	case []*big.Int:
		return v
	case []interface{}:
		arr := make([]*big.Int, 0, len(v))
		for _, item := range v {
			if bi := normalizeBigInt(item); bi != nil {
				arr = append(arr, bi)
			}
		}
		return arr
	case []string:
		arr := make([]*big.Int, 0, len(v))
		for _, s := range v {
			if bi := normalizeBigInt(s); bi != nil {
				arr = append(arr, bi)
			}
		}
		return arr
	}
	return nil
}

func normalizeBigInt(val interface{}) *big.Int {
	switch v := val.(type) {
	case *big.Int:
		return v
	case int:
		return big.NewInt(int64(v))
	case int64:
		return big.NewInt(v)
	case uint64:
		return new(big.Int).SetUint64(v)
	case string:
		base := 10
		str := v
		if strings.HasPrefix(v, "0x") {
			base = 16
			str = strings.TrimPrefix(v, "0x")
		}
		if n, ok := new(big.Int).SetString(str, base); ok {
			return n
		}
	case []byte:
		return new(big.Int).SetBytes(v)
	}
	return nil
}

func normalizeBytes(val interface{}) []byte {
	switch v := val.(type) {
	case []byte:
		return v
	case string:
		if strings.HasPrefix(v, "0x") {
			if b, err := hexutil.Decode(v); err == nil {
				return b
			}
		}
		return []byte(v)
	}
	return nil
}

// simulateExecution 执行单个模拟
func (f *CallDataFuzzer) simulateExecution(ctx context.Context, req *SimulationRequest, workerID int) (*SimulationResult, error) {
	// 创建带超时的context
	simCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	var result *simulator.ReplayResult
	var err error

	if f.localExecution && f.dualSimulator != nil {
		// 本地模式：使用双模式模拟器，避免与RPC竞争；加锁保证线程安全
		f.localExecMu.Lock()
		result, err = f.dualSimulator.SimulateWithCallDataV2(
			simCtx,
			req.From,
			req.To,
			req.CallData,
			req.Value,
			req.BlockNumber,
			req.StateOverride,
			nil, // 不需要显式mutators，交给拦截器判断
		)
		f.localExecMu.Unlock()
	} else {
		// 默认RPC模式
		result, err = f.simulator.SimulateWithCallData(
			simCtx,
			req.From,
			req.To,
			req.CallData,
			req.Value,
			req.BlockNumber,
			req.StateOverride,
		)
	}

	if err != nil {
		// 记录错误但继续
		if err.Error() != "execution reverted" {
			// 只记录非revert错误
			if f.stats.FailedSimulations < 100 { // 限制日志数量
				log.Printf("[Worker %d] Simulation failed: %v", workerID, err)
			}
		}
		f.stats.FailedSimulations++
		return nil, err
	}

	// 需要将 simulator.ContractJumpDest 转换为 fuzzer.ContractJumpDest
	contractJumpDests := make([]ContractJumpDest, len(result.ContractJumpDests))
	for i, cjd := range result.ContractJumpDests {
		contractJumpDests[i] = ContractJumpDest{
			Contract: cjd.Contract,
			PC:       cjd.PC,
		}
	}

	var returnData []byte
	if result.ReturnData != "" && result.ReturnData != "0x" {
		if decoded, decodeErr := hexutil.Decode(result.ReturnData); decodeErr == nil {
			returnData = decoded
		} else {
			log.Printf("[Worker %d] ⚠️  无法解码模拟返回数据: %v (raw=%s)", workerID, decodeErr, result.ReturnData)
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

	var traceErr error
	if result.Error != "" {
		traceErr = fmt.Errorf(result.Error)
	}

	return &SimulationResult{
		Success:           result.Success,
		JumpDests:         result.JumpDests,
		ContractJumpDests: contractJumpDests,
		GasUsed:           result.GasUsed,
		ReturnData:        returnData,
		Error:             traceErr,
		StateChanges:      stateChanges,
	}, nil
}

// convertSimulatorCJDs 转换simulator的ContractJumpDest为fuzzer内部类型
func convertSimulatorCJDs(in []simulator.ContractJumpDest) []ContractJumpDest {
	out := make([]ContractJumpDest, len(in))
	for i, cjd := range in {
		out[i] = ContractJumpDest{
			Contract: cjd.Contract,
			PC:       cjd.PC,
		}
	}
	return out
}

// convertSimulatorStateChanges 转换状态变更
func convertSimulatorStateChanges(in map[string]simulator.StateChange) map[string]StateChange {
	out := make(map[string]StateChange, len(in))
	for addr, change := range in {
		storage := make(map[string]StorageUpdate, len(change.StorageChanges))
		for slot, diff := range change.StorageChanges {
			storage[slot] = StorageUpdate{
				Before: diff.Before,
				After:  diff.After,
			}
		}
		out[addr] = StateChange{
			BalanceBefore:  change.BalanceBefore,
			BalanceAfter:   change.BalanceAfter,
			StorageChanges: storage,
		}
	}
	return out
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

// batchBestTracker 记录每100个组合的最佳相似度及对应路径
type batchBestTracker struct {
	mutex      sync.Mutex
	windowID   int32
	bestSim    float64
	bestPath   []ContractJumpDest
	bestWorker int
}

func newBatchBestTracker() *batchBestTracker {
	return &batchBestTracker{
		windowID: 0,
		bestSim:  -1,
	}
}

func (b *batchBestTracker) Update(currentCount int32, similarity float64, path []ContractJumpDest, workerID int) {
	windowID := (currentCount - 1) / 100

	b.mutex.Lock()
	defer b.mutex.Unlock()

	if windowID != b.windowID {
		b.windowID = windowID
		b.bestSim = -1
		b.bestPath = nil
		b.bestWorker = 0
	}

	if similarity > b.bestSim {
		b.bestSim = similarity
		b.bestWorker = workerID
		b.bestPath = append([]ContractJumpDest{}, path...)
	}
}

func (b *batchBestTracker) Snapshot(windowID int32) (float64, []ContractJumpDest, int, bool) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if windowID != b.windowID || b.bestSim < 0 {
		return 0, nil, 0, false
	}

	pathCopy := append([]ContractJumpDest{}, b.bestPath...)
	return b.bestSim, pathCopy, b.bestWorker, true
}

// findProtectedStartIndex 基于目标合约地址在 ContractJumpDests 中定位受保护起点
func findProtectedStartIndex(jumps []ContractJumpDest, target common.Address) int {
	targetHex := strings.ToLower(target.Hex())
	for i, j := range jumps {
		if strings.ToLower(j.Contract) == targetHex {
			return i
		}
	}
	return -1
}

// formatPathSnippet 格式化路径片段，避免日志过长
func formatPathSnippet(jumps []ContractJumpDest, start int) string {
	total := len(jumps)
	if start < 0 {
		start = 0
	}
	if start > total {
		start = total
	}

	maxEntries := 5
	end := start + maxEntries
	if end > total {
		end = total
	}

	snippets := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		snippets = append(snippets, fmt.Sprintf("%s:%d", jumps[i].Contract, jumps[i].PC))
	}
	if end < total {
		snippets = append(snippets, "...")
	}

	return fmt.Sprintf("[len=%d,start=%d,head=%s]", total, start, strings.Join(snippets, " | "))
}

// GetStats 获取统计信息
func (f *CallDataFuzzer) GetStats() *FuzzerStats {
	return f.stats
}

// ========== Layer 2: 自适应迭代模糊测试 ==========

// executeAdaptiveFuzzing 执行自适应迭代模糊测试
func (f *CallDataFuzzer) executeAdaptiveFuzzing(
	ctx context.Context,
	parsedData *ParsedCallData,
	targetMethod *abi.Method,
	originalPath *simulator.ReplayResult,
	targetCall *CallFrame,
	contractAddr common.Address,
	blockNumber uint64,
	stateOverride simulator.StateOverride,
	symbolicSeeds []symbolic.SymbolicSeed,
	callTree *CallFrame,
	loopBaseline bool,
) []FuzzingResult {
	seedGen := NewSeedGenerator(f.seedConfig, f.generator.maxVariations)
	allResults := []FuzzingResult{}

	// 约束范围集成：如果有约束范围配置，合并约束种子
	if seedGen.HasConstraintRanges() {
		if targetMethod != nil {
			seedGen.MergeConstraintSeeds(targetMethod.Name)
			log.Printf("[Adaptive] 📊 Merged constraint seeds for function: %s", targetMethod.Name)
		} else {
			for funcName := range f.seedConfig.ConstraintRanges {
				seedGen.MergeConstraintSeeds(funcName)
				log.Printf("[Adaptive] 📊 Merged constraint seeds for function: %s", funcName)
			}
		}
		log.Printf("[Adaptive] 📊 Using constraint ranges")
	}

	// Layer 3: 设置符号种子
	if len(symbolicSeeds) > 0 {
		seedGen.SetSymbolicSeeds(symbolicSeeds)
		log.Printf("[Adaptive] 🔮 Applied %d symbolic seeds from constraint extraction", len(symbolicSeeds))
	}

	// 第0轮：初始探索（使用 Layer 1 固定范围）
	log.Printf("[Adaptive] ========== Iteration 0: Initial Exploration ==========")
	log.Printf("[Adaptive] Using fixed seed-based ranges")

	initialCombos := seedGen.GenerateSeedBasedCombinations(parsedData.Parameters)
	initialResults := f.executeFuzzing(ctx, initialCombos, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, blockNumber, stateOverride, callTree, loopBaseline)
	allResults = append(allResults, initialResults...)

	log.Printf("[Adaptive] Iteration 0 completed: %d valid results, total: %d",
		len(initialResults), len(allResults))

	// 初始探索无结果时直接退出，避免无效的空循环
	if len(allResults) == 0 {
		log.Printf("[Adaptive] ⚠️ 初始探索未找到有效结果，停止自适应迭代")
		return allResults
	}

	// 迭代优化
	for iter := 1; iter <= f.seedConfig.AdaptiveConfig.MaxIterations; iter++ {
		log.Printf("[Adaptive] ========== Iteration %d: Adaptive Refinement ==========", iter)

		seedGen.currentIteration = iter

		// 1. 分析上一轮反馈
		log.Printf("[Adaptive] Analyzing feedback from %d results...", len(allResults))
		feedback := seedGen.AnalyzeFeedback(allResults, parsedData.Parameters)
		seedGen.feedbackHistory = append(seedGen.feedbackHistory, feedback...)

		// 2. 检查收敛
		if seedGen.HasConverged(feedback) {
			log.Printf("[Adaptive] ✅ 检测到收敛 (iteration=%d)，停止自适应迭代", iter)
			break
		}

		// 3. 生成新一轮参数（基于反馈调整）
		log.Printf("[Adaptive] Generating adaptive combinations based on feedback...")
		adaptiveCombos := seedGen.GenerateAdaptiveRound(parsedData.Parameters, feedback)

		// 4. 执行新一轮模糊测试
		log.Printf("[Adaptive] Executing fuzzing with adaptive ranges...")
		iterResults := f.executeFuzzing(ctx, adaptiveCombos, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, blockNumber, stateOverride, callTree, loopBaseline)

		// 5. 累积结果
		allResults = append(allResults, iterResults...)

		log.Printf("[Adaptive] Iteration %d completed: %d new results, total: %d",
			iter, len(iterResults), len(allResults))

		// 如果这一轮没有新的有效结果，认为已饱和，退出
		if len(iterResults) == 0 {
			log.Printf("[Adaptive] ⚠️ 本轮无新增有效结果 (iteration=%d)，停止自适应迭代", iter)
			break
		}
	}

	log.Printf("[Adaptive] ========== Adaptive Fuzzing Completed ==========")
	log.Printf("[Adaptive] Total iterations: %d, Total valid results: %d", seedGen.currentIteration+1, len(allResults))

	return allResults
}

// isFatalRPCError 判断是否为无法继续的RPC错误
func isFatalRPCError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "unexpected EOF") ||
		strings.Contains(msg, "EOF") ||
		strings.Contains(msg, "context canceled")
}

// injectFlashSeedOverrides 为 flash 调用注入基础余额/授权，降低 SafeERC20 revert 概率
func injectFlashSeedOverrides(stateOverride simulator.StateOverride, wbarlAddr common.Address, targetCall *CallFrame, params []Parameter) {
	if stateOverride == nil || targetCall == nil || len(params) < 3 {
		return
	}

	owner := common.HexToAddress(targetCall.From)
	spender := wbarlAddr
	dai := common.HexToAddress("0x6B175474E89094C44Da98b954EedeAC495271d0F")

	origAmount := normalizeBigInt(params[2].Value)
	if origAmount == nil || origAmount.Sign() == 0 {
		origAmount = big.NewInt(1)
	}
	// 额外提供 2x 余额，避免边界转账失败
	balance := new(big.Int).Mul(origAmount, big.NewInt(2))
	maxAllowance := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

	setERC20BalanceAndAllowance(stateOverride, dai, owner, spender, balance, maxAllowance)
}

// setERC20BalanceAndAllowance 在 StateOverride 中设置余额与授权槽位
func setERC20BalanceAndAllowance(override simulator.StateOverride, token, owner, spender common.Address, balance, allowance *big.Int) {
	if override == nil {
		return
	}

	tokenKey := strings.ToLower(token.Hex())
	ov, ok := override[tokenKey]
	if !ok || ov == nil {
		ov = &simulator.AccountOverride{}
		override[tokenKey] = ov
	}
	if ov.State == nil {
		ov.State = make(map[string]string)
	}

	// balance slot (balances mapping at slot 0)
	bSlot := computeMappingSlot(owner, big.NewInt(0))
	ov.State[bSlot] = hexutil.EncodeBig(balance)

	// allowance slot：对 DAI 使用已知slot；其他代币使用 slot 1 约定
	var aSlot string
	if tokenKey == strings.ToLower("0x6B175474E89094C44Da98b954EedeAC495271d0F") {
		// 预计算的 allowance[owner][spender] 槽位（DAI slot3），与旧日志一致
		aSlot = "0x3d87c91f878fde976b5e092bfe8d85850194c887f898e23b950a17e7e2210300"
	} else {
		aSlot = computeDoubleMappingSlot(owner, spender, big.NewInt(1))
	}
	ov.State[aSlot] = hexutil.EncodeBig(allowance)
}

// computeMappingSlot 计算 keccak(key . slotIndex)
func computeMappingSlot(key common.Address, slotIndex *big.Int) string {
	keyBytes := common.LeftPadBytes(key.Bytes(), 32)
	slotBytes := common.LeftPadBytes(slotIndex.Bytes(), 32)
	hash := crypto.Keccak256(append(keyBytes, slotBytes...))
	return common.BytesToHash(hash).Hex()
}

// computeDoubleMappingSlot 计算 keccak(spender . keccak(owner . slotIndex))
func computeDoubleMappingSlot(owner, spender common.Address, slotIndex *big.Int) string {
	inner := crypto.Keccak256(append(common.LeftPadBytes(owner.Bytes(), 32), common.LeftPadBytes(slotIndex.Bytes(), 32)...))
	hash := crypto.Keccak256(append(common.LeftPadBytes(spender.Bytes(), 32), inner...))
	return common.BytesToHash(hash).Hex()
}

// buildFallbackCallFrame 根据交易和可选的from/to构造一个 CallFrame，用于trace缺失时回退
func (f *CallDataFuzzer) buildFallbackCallFrame(tx *types.Transaction, fromStr, toStr string, input []byte) *CallFrame {
	gas := apptypes.NewFlexibleUint64(tx.Gas())
	if fromStr == "" {
		fromStr = "<unknown>"
	}
	if toStr == "" && tx.To() != nil {
		toStr = tx.To().Hex()
	}
	inHex := hexutil.Encode(input)
	if len(inHex) == 0 {
		inHex = "0x"
	}

	return &CallFrame{
		Type:    "call",
		From:    fromStr,
		To:      toStr,
		Value:   tx.Value().String(),
		Gas:     gas,
		GasUsed: gas,
		Input:   inHex,
	}
}

// 注意：不在此处为 simulator.EVMSimulator 声明跨包方法，直接使用 simulator 包内已实现的方法。

// ========== 新架构集成方法 ==========

// InitializeArchitecture 初始化新架构组件（registry、poolManager、mutationEngine）
// 此方法应在fuzzing开始前调用，仅在本地执行模式下有效
func (f *CallDataFuzzer) InitializeArchitecture(poolSize int) error {
	if !f.localExecution || f.dualSimulator == nil {
		log.Printf("[Fuzzer] ⚠️  跳过架构初始化：非本地执行模式")
		return nil
	}

	log.Printf("[Fuzzer] 🔧 开始初始化新架构组件...")

	// 获取LocalExecutor和CallInterceptor
	localExec := f.dualSimulator.GetLocalExecutor()
	if localExec == nil {
		return fmt.Errorf("local executor is nil")
	}

	interceptor := localExec.GetInterceptor()
	if interceptor == nil {
		return fmt.Errorf("interceptor is nil")
	}

	// 1. 创建Registry
	registry := local.NewProtectedRegistry()
	log.Printf("[Fuzzer] ✅ 创建ProtectedRegistry")

	// 2. 创建ParamPoolManager (最多缓存100个池)
	poolManager, err := local.NewParamPoolManager(100)
	if err != nil {
		return fmt.Errorf("failed to create pool manager: %w", err)
	}
	log.Printf("[Fuzzer] ✅ 创建ParamPoolManager (maxPools=100)")

	// 3. 创建MutationEngine
	engine := local.NewMutationEngine()
	log.Printf("[Fuzzer] ✅ 创建MutationEngine")

	// 4. 注册变异策略（按优先级顺序）

	// 4.1 SeedDrivenStrategy (优先级100)
	var seedConfig *local.SeedConfig
	if f.seedConfig != nil && f.seedConfig.Enabled {
		// 转换fuzzer.SeedConfig为local.SeedConfig
		seedConfig = &local.SeedConfig{
			Enabled:     f.seedConfig.Enabled,
			AttackSeeds: f.seedConfig.AttackSeeds,
		}
		log.Printf("[Fuzzer] 🌱 种子配置已启用，种子数: %d", len(f.seedConfig.AttackSeeds))
	}
	seedStrategy := strategies.NewSeedDrivenStrategy(seedConfig)
	engine.RegisterStrategy(seedStrategy)
	log.Printf("[Fuzzer] ✅ 注册SeedDrivenStrategy (优先级=%d)", seedStrategy.Priority())

	// 4.2 ABIBasedStrategy (优先级50)
	abiStrategy := strategies.NewABIBasedStrategy()
	engine.RegisterStrategy(abiStrategy)
	log.Printf("[Fuzzer] ✅ 注册ABIBasedStrategy (优先级=%d)", abiStrategy.Priority())

	// 4.3 RangeMutationStrategy (优先级30)
	rangeStrategy := strategies.NewRangeMutationStrategy()
	engine.RegisterStrategy(rangeStrategy)
	log.Printf("[Fuzzer] ✅ 注册RangeMutationStrategy (优先级=%d)", rangeStrategy.Priority())

	// 5. 用新组件替换interceptor
	collector := localExec.GetCollector()
	newInterceptor := local.NewCallInterceptorWithComponents(
		collector,
		registry,
		poolManager,
		engine,
	)

	// 替换LocalExecutor中的interceptor
	localExec.SetInterceptor(newInterceptor)
	log.Printf("[Fuzzer] ✅ 已替换CallInterceptor为新架构版本")

	// 保存组件到Fuzzer字段
	f.registry = registry
	f.poolManager = poolManager
	f.mutationEngine = engine

	log.Printf("[Fuzzer] 🎉 新架构初始化完成")
	log.Printf("[Fuzzer] 📊 已注册策略: %d个", len(engine.GetStrategies()))

	return nil
}

// RegisterProtectedContract 注册受保护合约到registry
// contractAddr: 合约地址
// contractABI: 合约ABI (JSON字符串或*abi.ABI对象)
func (f *CallDataFuzzer) RegisterProtectedContract(
	contractAddr common.Address,
	contractABI interface{},
) error {
	if !f.localExecution || f.dualSimulator == nil {
		return fmt.Errorf("only supported in local execution mode")
	}

	if f.registry == nil {
		return fmt.Errorf("registry not initialized, call InitializeArchitecture first")
	}

	// 解析ABI
	var parsedABI *abi.ABI
	switch v := contractABI.(type) {
	case *abi.ABI:
		parsedABI = v
	case string:
		// 从JSON字符串解析
		parsed, err := abi.JSON(strings.NewReader(v))
		if err != nil {
			return fmt.Errorf("failed to parse ABI JSON: %w", err)
		}
		parsedABI = &parsed
	default:
		return fmt.Errorf("unsupported ABI type: %T", contractABI)
	}

	// 转换SeedConfig
	var seedConfig *local.SeedConfig
	if f.seedConfig != nil && f.seedConfig.Enabled {
		seedConfig = &local.SeedConfig{
			Enabled:     f.seedConfig.Enabled,
			AttackSeeds: f.seedConfig.AttackSeeds,
		}
	}

	// 创建并注册合约信息
	info := &local.ProtectedContractInfo{
		Address:    contractAddr,
		ABI:        parsedABI,
		SeedConfig: seedConfig,
		Metadata:   make(map[string]interface{}),
	}

	err := f.registry.RegisterContract(info)
	if err != nil {
		return fmt.Errorf("failed to register contract: %w", err)
	}

	log.Printf("[Fuzzer] ✅ 已注册受保护合约: %s (方法数=%d)",
		contractAddr.Hex(), len(parsedABI.Methods))

	return nil
}

// InitializeParamPools 为所有已注册的受保护合约预热参数池
func (f *CallDataFuzzer) InitializeParamPools(poolSize int) error {
	if !f.localExecution || f.dualSimulator == nil {
		return fmt.Errorf("only supported in local execution mode")
	}

	if f.registry == nil || f.poolManager == nil {
		return fmt.Errorf("components not initialized, call InitializeArchitecture first")
	}

	log.Printf("[Fuzzer] 🔥 开始预热参数池 (poolSize=%d)...", poolSize)

	// 获取所有已注册的合约
	contracts := f.registry.GetAll()
	if len(contracts) == 0 {
		log.Printf("[Fuzzer] ⚠️  没有已注册的受保护合约，跳过参数池预热")
		return nil
	}

	// 获取interceptor
	localExec := f.dualSimulator.GetLocalExecutor()
	interceptor := localExec.GetInterceptor()

	// 为每个合约预热参数池
	for _, contract := range contracts {
		err := interceptor.InitializePoolsForContract(contract.Address, poolSize)
		if err != nil {
			log.Printf("[Fuzzer] ⚠️  合约 %s 参数池预热失败: %v", contract.Address.Hex(), err)
			continue
		}
		log.Printf("[Fuzzer] ✅ 合约 %s 参数池预热完成", contract.Address.Hex())
	}

	// 获取统计信息
	stats := interceptor.GetPoolStats()
	log.Printf("[Fuzzer] 📊 参数池统计: 总池数=%d, 总参数=%d, 平均池大小=%d, 缓存命中率=%.2f%%",
		stats.TotalPools, stats.TotalParams, stats.AvgPoolSize, stats.CacheHitRate*100)

	return nil
}

// 应用约束规则到报告（若收集到足够样本）
func (f *CallDataFuzzer) applyConstraintRule(report *AttackParameterReport, contractAddr common.Address, selector []byte) {
	if report == nil || f.constraintCollector == nil {
		return
	}
	rule := f.constraintCollector.GetRule(contractAddr, selector)
	if rule == nil {
		return
	}

	summaries := convertParamConstraintsToSummaries(rule.ParamConstraints)
	if len(summaries) > 0 {
		report.ValidParameters = summaries
	}
	report.ConstraintRule = rule
}

// convertParamConstraintsToSummaries 将参数约束转成参数摘要
func convertParamConstraintsToSummaries(constraints []ParamConstraint) []ParameterSummary {
	var out []ParameterSummary
	for _, c := range constraints {
		ps := ParameterSummary{
			ParamIndex:      c.Index,
			ParamType:       c.Type,
			OccurrenceCount: 1,
		}
		if c.IsRange {
			ps.IsRange = true
			ps.RangeMin = c.RangeMin
			ps.RangeMax = c.RangeMax
		} else if len(c.Values) > 0 {
			ps.SingleValues = c.Values
		}
		out = append(out, ps)
	}
	return out
}
