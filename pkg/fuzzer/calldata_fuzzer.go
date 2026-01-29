package fuzzer

import (
	"autopath/pkg/fuzzer/symbolic"
	"autopath/pkg/simulator"
	"autopath/pkg/simulator/local"
	"autopath/pkg/simulator/local/strategies"
	apptypes "autopath/pkg/types"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
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

// baseline_state路径与内容缓存，减少重复IO
var baselineStatePathCache sync.Map // key: 项目 -> 路径
var baselineStateCache sync.Map     // key: 路径 -> *baselineStateFile

// targetSelectorCache 缓存项目的目标函数选择器（contract -> selectors）
var targetSelectorCache sync.Map // key: cacheKey, value: map[string]map[string]bool
// targetSignatureCache 缓存项目的目标函数签名（contract -> selector -> signature）
var targetSignatureCache sync.Map // key: cacheKey, value: map[string]map[string]string

// projectTargetConfig 用于轻量级解析目标函数配置
type projectTargetConfig struct {
	ProjectID     string `json:"project_id"`
	FuzzingConfig *struct {
		TargetFunctions []struct {
			Contract  string `json:"contract"`
			Signature string `json:"signature"`
			Function  string `json:"function"`
		} `json:"target_functions"`
	} `json:"fuzzing_config"`
}

// signatureToSelector 计算4字节selector
func signatureToSelector(signature string) (string, error) {
	if strings.TrimSpace(signature) == "" {
		return "", fmt.Errorf("empty signature")
	}
	hash := crypto.Keccak256([]byte(signature))
	if len(hash) < 4 {
		return "", fmt.Errorf("keccak result too short")
	}
	return "0x" + hex.EncodeToString(hash[:4]), nil
}

// loadTargetSelectors 解析配置文件中的 target_functions；优先按 projectID 匹配，若无则按合约地址匹配
func loadTargetSelectors(projectID string, contractAddr common.Address) map[string]map[string]bool {
	cacheKey := projectID
	if cacheKey == "" {
		cacheKey = strings.ToLower(contractAddr.Hex())
	}

	// 检查缓存（包括空缓存，避免重复扫描）
	if cached, ok := targetSelectorCache.Load(cacheKey); ok {
		if m, ok2 := cached.(map[string]map[string]bool); ok2 {
			log.Printf("[Fuzzer]  缓存命中 (projectID=%s, contract=%s, selectors=%d)", projectID, contractAddr.Hex(), len(m))
			return m // 直接返回缓存结果（包括空map）
		}
	}

	log.Printf("[Fuzzer]  加载target_functions (projectID=%s, contract=%s)", projectID, contractAddr.Hex())

	// 优先从当前目录向上查找 pkg/invariants/configs，再尝试 autopath/pkg/invariants/configs
	candidateDirs := []string{}
	for depth := 0; depth <= 3; depth++ {
		prefix := strings.Repeat(".."+string(os.PathSeparator), depth)
		candidateDirs = append(candidateDirs, filepath.Join(prefix, "pkg", "invariants", "configs"))
		candidateDirs = append(candidateDirs, filepath.Join(prefix, "autopath", "pkg", "invariants", "configs"))
	}

	var matches []string
	// log.Printf("[Fuzzer]  当前工作目录: %s", wd)  // 降低日志级别：移除详细调试信息
	for _, dir := range candidateDirs {
		pattern := filepath.Join(dir, "*.json")
		// log.Printf("[Fuzzer]  尝试配置目录: %s", pattern)  // 降低日志级别：移除目录扫描日志
		found, globErr := filepath.Glob(pattern)
		if globErr != nil {
			// log.Printf("[Fuzzer]  Glob失败: %v", globErr)  // 降低日志级别：移除错误详情
			continue
		}
		// 过滤掉不存在的路径，防止虚假匹配
		valid := make([]string, 0, len(found))
		for _, m := range found {
			if _, err := os.Stat(m); err == nil {
				valid = append(valid, m)
			}
		}
		if len(valid) > 0 {
			// log.Printf("[Fuzzer]  在目录中找到配置文件 %d 个，示例: %s", len(valid), valid[0])  // 降低日志级别
			matches = append(matches, valid...)
		}
	}
	if len(matches) == 0 {
		log.Printf("[Fuzzer]  未找到任何配置文件，跳过target_functions加载")
		return nil
	}
	log.Printf("[Fuzzer]  扫描配置文件: 共%d个", len(matches))
	// 移除示例输出，减少日志量
	// sample := matches
	// if len(sample) > 5 {
	// 	sample = sample[:5]
	// }
	// log.Printf("[Fuzzer]  配置文件示例: %v", sample)

	result := make(map[string]map[string]bool)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg projectTargetConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if cfg.FuzzingConfig == nil || len(cfg.FuzzingConfig.TargetFunctions) == 0 {
			continue
		}

		cfgProj := strings.TrimSpace(cfg.ProjectID)
		targetProj := strings.TrimSpace(projectID)

		// 降低日志级别：只在找到匹配时输出，不输出每个文件的检查过程
		// if projectID != "" {
		// 	log.Printf("[Fuzzer]  检查配置文件: %s (cfgProjectID=%s)", path, cfgProj)
		// }

		// 过滤匹配：优先项目ID，相同则允许（去空格+不区分大小写）
		if targetProj != "" && !strings.EqualFold(cfgProj, targetProj) {
			continue
		}

		if targetProj != "" && strings.EqualFold(cfgProj, targetProj) {
			log.Printf("[Fuzzer]  命中项目配置文件: %s (projectID=%s)", path, cfgProj)
		}

		for _, tf := range cfg.FuzzingConfig.TargetFunctions {
			if tf.Contract == "" || tf.Signature == "" {
				continue
			}
			addrHex := common.HexToAddress(tf.Contract).Hex()
			// 若未指定projectID，则按合约地址匹配
			if projectID == "" && !strings.EqualFold(addrHex, contractAddr.Hex()) {
				continue
			}
			sel, err := signatureToSelector(tf.Signature)
			if err != nil {
				continue
			}
			addr := strings.ToLower(addrHex)
			if result[addr] == nil {
				result[addr] = make(map[string]bool)
			}
			result[addr][strings.ToLower(sel)] = true
		}

		if len(result) == 0 && projectID != "" {
			log.Printf("[Fuzzer]  命中文件但未解析到target_functions: %s", path)
		}
		if len(result) > 0 && projectID != "" {
			log.Printf("[Fuzzer]  解析target_functions成功 (projectID=%s, selectors=%v)", projectID, result)
		}

		// 如果提供了项目ID，匹配到后即可结束；如果是按合约匹配，继续以防多文件同一合约
		if projectID != "" && len(result) > 0 {
			break
		}
	}

	if len(result) > 0 {
		targetSelectorCache.Store(cacheKey, result)
		return result
	}

	// 若按 projectID 未找到，则回退按合约地址匹配一次（不缓存空结果）
	if projectID != "" {
		return loadTargetSelectors("", contractAddr)
	}
	log.Printf("[Fuzzer]  未在配置中找到target_functions (projectID=%s, contract=%s)", projectID, contractAddr.Hex())
	return result
}

// loadTargetSignatures 解析配置文件中的 target_functions，返回 selector -> signature 映射
func loadTargetSignatures(projectID string, contractAddr common.Address) map[string]map[string]string {
	cacheKey := projectID
	if cacheKey == "" {
		cacheKey = strings.ToLower(contractAddr.Hex())
	}

	if cached, ok := targetSignatureCache.Load(cacheKey); ok {
		if m, ok2 := cached.(map[string]map[string]string); ok2 {
			return m
		}
	}

	candidateDirs := []string{}
	for depth := 0; depth <= 3; depth++ {
		prefix := strings.Repeat(".."+string(os.PathSeparator), depth)
		candidateDirs = append(candidateDirs, filepath.Join(prefix, "pkg", "invariants", "configs"))
		candidateDirs = append(candidateDirs, filepath.Join(prefix, "autopath", "pkg", "invariants", "configs"))
	}

	var matches []string
	for _, dir := range candidateDirs {
		pattern := filepath.Join(dir, "*.json")
		found, globErr := filepath.Glob(pattern)
		if globErr != nil {
			continue
		}
		valid := make([]string, 0, len(found))
		for _, m := range found {
			if _, err := os.Stat(m); err == nil {
				valid = append(valid, m)
			}
		}
		if len(valid) > 0 {
			matches = append(matches, valid...)
		}
	}

	result := make(map[string]map[string]string)
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg projectTargetConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}
		if cfg.FuzzingConfig == nil || len(cfg.FuzzingConfig.TargetFunctions) == 0 {
			continue
		}

		cfgProj := strings.TrimSpace(cfg.ProjectID)
		targetProj := strings.TrimSpace(projectID)
		if targetProj != "" && !strings.EqualFold(cfgProj, targetProj) {
			continue
		}

		for _, tf := range cfg.FuzzingConfig.TargetFunctions {
			if tf.Contract == "" || tf.Signature == "" {
				continue
			}
			addrHex := common.HexToAddress(tf.Contract).Hex()
			if projectID == "" && !strings.EqualFold(addrHex, contractAddr.Hex()) {
				continue
			}
			sel, err := signatureToSelector(tf.Signature)
			if err != nil {
				continue
			}
			addr := strings.ToLower(addrHex)
			if result[addr] == nil {
				result[addr] = make(map[string]string)
			}
			result[addr][strings.ToLower(sel)] = tf.Signature
		}

		if projectID != "" && len(result) > 0 {
			break
		}
	}

	if len(result) > 0 {
		targetSignatureCache.Store(cacheKey, result)
		return result
	}

	if projectID != "" {
		return loadTargetSignatures("", contractAddr)
	}
	return result
}

func lookupTargetSignature(projectID string, contractAddr common.Address, selector []byte) string {
	if len(selector) < 4 {
		return ""
	}
	sigs := loadTargetSignatures(projectID, contractAddr)
	addr := strings.ToLower(contractAddr.Hex())
	if sigMap, ok := sigs[addr]; ok {
		sel := "0x" + hex.EncodeToString(selector[:4])
		if sig, ok := sigMap[strings.ToLower(sel)]; ok {
			return sig
		}
	}
	return ""
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
	simulator       *simulator.EVMSimulator      // RPC模式模拟器
	dualSimulator   *simulator.DualModeSimulator //  双模式模拟器（支持本地执行）
	localExecution  bool                         //  是否启用本地执行模式
	recordFullTrace bool                         //  是否记录全交易路径
	parser          *ABIParser
	generator       *ParamGenerator
	comparator      *PathComparator
	merger          *ResultMerger
	tracer          *TransactionTracer

	// 配置
	threshold  float64
	maxWorkers int
	timeout    time.Duration

	// 客户端
	client    *ethclient.Client
	rpcClient *rpc.Client

	// 统计
	stats *FuzzerStats
	// 达标样本时间统计
	firstHitAt int64  // 纳秒
	maxSimAt   int64  // 纳秒
	maxSimVal  uint64 // math.Float64bits(sim)

	// 全量尝试统计（包含低相似度样本）
	attemptMu sync.Mutex
	attempts  int
	simSum    float64
	simMin    float64
	simMax    float64
	rawSimSum float64
	rawSimMin float64
	rawSimMax float64

	// 不变量评估器（新增）
	invariantEvaluator      InvariantEvaluator // 通过接口避免循环依赖
	enableInvariantCheck    bool               // 是否启用不变量检查
	skipInvariantForHighSim bool               // 高相似度样本是否跳过不变量评估

	// 种子驱动模糊测试（新增）
	seedConfig *SeedConfig // 种子配置

	// Layer 3: 符号执行（新增）
	symbolicExtractor *symbolic.ConstraintExtractor
	symbolicSolver    *symbolic.ConstraintSolver

	//  无限制fuzzing模式
	targetSimilarity  float64 // 目标相似度阈值
	maxHighSimResults int     // 最大高相似度结果数
	unlimitedMode     bool    // 无限制模式

	// Entry Call 限制
	entryCallProtectedOnly bool // 仅允许对受保护合约进行Entry模式
	// 目标函数未命中时是否回退到受保护调用
	targetFunctionFallback bool

	// 循环场景下使用受保护合约子路径作为基准
	useLoopBodyBaseline bool

	// 项目标识（用于定位attack_state等外部状态）
	projectID string
	// 基线状态路径（用于本地EVM补全）
	baselineStatePath string
	// 严格prestate模式（禁止attack_state覆盖，仅允许baseline_state补全）
	strictPrestate bool
	// attack_state仅补代码（不写入余额/存储）
	attackStateCodeOnly bool

	// === 新架构组件 (Phase 3集成) ===
	registry       local.ProtectedRegistry // 受保护合约注册表（首个执行器）
	poolManager    local.ParamPoolManager  // 参数池管理器（首个执行器）
	mutationEngine local.MutationEngine    // 变异引擎（首个执行器）

	dualSimulators []*simulator.DualModeSimulator // 本地执行器池
	archComponents []struct {
		registry       local.ProtectedRegistry
		poolManager    local.ParamPoolManager
		mutationEngine local.MutationEngine
	}

	// 约束收集器（高相似样本生成规则）
	constraintCollector *ConstraintCollector

	// 样本记录器（正/负样本与连锁调用）
	sampleRecorder *sampleRecorder
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
	// 地址参数严格不变异：只使用原始值
	if gen != nil && gen.strategy != nil {
		gen.strategy.Addresses.DisableMutation = true
	}

	// 默认跳过高相似度样本的不变量检查，便于生成约束；可通过配置显式关闭
	skipInv := true
	if config.InvariantCheck.SkipOnHighSimilarity != nil {
		skipInv = *config.InvariantCheck.SkipOnHighSimilarity
	}

	// 构建 basePath 用于加载约束规则
	// Monitor通常在 autopath/ 目录启动，所以 basePath 是 ".." (父目录)
	basePath := ".."
	if _, err := os.Stat(filepath.Join(basePath, "DeFiHackLabs")); err != nil {
		// 如果 "../DeFiHackLabs" 不存在，尝试当前目录
		basePath = "."
	}

	fuzzer := &CallDataFuzzer{
		parser:                  NewABIParser(),
		generator:               gen,
		comparator:              NewPathComparator(),
		merger:                  NewResultMerger(),
		tracer:                  NewTransactionTracer(rpcClient),
		threshold:               config.Threshold,
		maxWorkers:              config.Workers,
		timeout:                 config.Timeout,
		client:                  client,
		rpcClient:               rpcClient,
		stats:                   &FuzzerStats{StartTime: time.Now()},
		invariantEvaluator:      &EmptyInvariantEvaluator{}, // 默认使用空实现
		enableInvariantCheck:    config.InvariantCheck.Enabled,
		skipInvariantForHighSim: skipInv,
		seedConfig:              config.SeedConfig,        // 新增：种子配置
		symbolicExtractor:       nil,                      // 延迟初始化
		symbolicSolver:          nil,                      // 延迟初始化
		targetSimilarity:        config.TargetSimilarity,  //  无限制模式配置
		maxHighSimResults:       config.MaxHighSimResults, //  无限制模式配置
		unlimitedMode:           config.UnlimitedMode,     //  无限制模式配置
		entryCallProtectedOnly:  config.EntryCallProtectedOnly,
		targetFunctionFallback:  config.TargetFunctionFallback,
		projectID:               config.ProjectID,
		baselineStatePath:       config.BaselineStatePath,
		strictPrestate:          config.StrictPrestate,
		attackStateCodeOnly:     config.AttackStateCodeOnly,
		localExecution:          config.LocalExecution, //  本地执行模式
		recordFullTrace:         config.RecordFullTrace,
		constraintCollector:     NewConstraintCollectorWithProject(10, basePath, config.ProjectID),
		sampleRecorder:          newSampleRecorder(),
	}
	if fuzzer.merger != nil {
		fuzzer.merger.SetProjectID(config.ProjectID)
	}
	fuzzer.simMin = math.Inf(1)
	if fuzzer.strictPrestate {
		if fuzzer.attackStateCodeOnly {
			log.Printf("[Fuzzer]  严格prestate已启用：attack_state仅补代码")
		} else {
			log.Printf("[Fuzzer]  严格prestate已启用：跳过attack_state注入")
		}
	}

	//  根据配置选择模拟器类型
	if config.LocalExecution {
		log.Printf("[Fuzzer]  使用本地EVM执行模式")
		poolSize := config.Workers
		if poolSize < 1 {
			poolSize = 1
		}
		for i := 0; i < poolSize; i++ {
			dualSim := simulator.NewDualModeSimulatorWithClients(rpcClient, client)
			dualSim.SetExecutionMode(simulator.ModeLocal)
			dualSim.SetRecordFullTrace(config.RecordFullTrace)
			fuzzer.dualSimulators = append(fuzzer.dualSimulators, dualSim)
		}
		if len(fuzzer.dualSimulators) > 0 {
			fuzzer.dualSimulator = fuzzer.dualSimulators[0]
			fuzzer.simulator = fuzzer.dualSimulator.EVMSimulator // 保持兼容性
		}
	} else {
		log.Printf("[Fuzzer]  使用RPC执行模式")
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
	log.Printf("[Fuzzer]  复用现有的RPC连接（避免创建新连接）")

	// 创建参数生成器
	var gen *ParamGenerator
	if config.Strategies.Integers.IncludeBoundaries {
		gen = NewParamGeneratorWithStrategy(config.MaxVariations, &config.Strategies)
	} else {
		gen = NewParamGenerator(config.MaxVariations)
	}
	// 地址参数严格不变异：只使用原始值
	if gen != nil && gen.strategy != nil {
		gen.strategy.Addresses.DisableMutation = true
	}

	// 如果启用了新架构但未显式开启本地执行，自动开启本地执行
	if config.EnableNewArch && !config.LocalExecution {
		log.Printf("[Fuzzer] EnableNewArch=true，自动开启本地执行模式")
		config.LocalExecution = true
	}

	// 默认跳过高相似度样本的不变量检查，便于生成约束；可通过配置显式关闭
	skipInv := true
	if config.InvariantCheck.SkipOnHighSimilarity != nil {
		skipInv = *config.InvariantCheck.SkipOnHighSimilarity
	}

	// 构建 basePath 用于加载约束规则
	// Monitor通常在 autopath/ 目录启动，所以 basePath 是 ".." (父目录)
	basePath := ".."
	if _, err := os.Stat(filepath.Join(basePath, "DeFiHackLabs")); err != nil {
		// 如果 "../DeFiHackLabs" 不存在，尝试当前目录
		basePath = "."
	}

	fuzzer := &CallDataFuzzer{
		parser:                  NewABIParser(),
		generator:               gen,
		comparator:              NewPathComparator(),
		merger:                  NewResultMerger(),
		tracer:                  NewTransactionTracer(rpcClient),
		threshold:               config.Threshold,
		maxWorkers:              config.Workers,
		timeout:                 config.Timeout,
		client:                  client,
		rpcClient:               rpcClient,
		stats:                   &FuzzerStats{StartTime: time.Now()},
		invariantEvaluator:      &EmptyInvariantEvaluator{}, // 默认使用空实现
		enableInvariantCheck:    config.InvariantCheck.Enabled,
		skipInvariantForHighSim: skipInv,
		seedConfig:              config.SeedConfig,        // 新增：种子配置
		symbolicExtractor:       nil,                      // 延迟初始化
		symbolicSolver:          nil,                      // 延迟初始化
		targetSimilarity:        config.TargetSimilarity,  //  无限制模式配置
		maxHighSimResults:       config.MaxHighSimResults, //  无限制模式配置
		unlimitedMode:           config.UnlimitedMode,     //  无限制模式配置
		entryCallProtectedOnly:  config.EntryCallProtectedOnly,
		targetFunctionFallback:  config.TargetFunctionFallback,
		projectID:               config.ProjectID,
		baselineStatePath:       config.BaselineStatePath,
		strictPrestate:          config.StrictPrestate,
		attackStateCodeOnly:     config.AttackStateCodeOnly,
		localExecution:          config.LocalExecution, //  本地执行模式
		recordFullTrace:         config.RecordFullTrace,
		constraintCollector:     NewConstraintCollectorWithProject(10, basePath, config.ProjectID),
		sampleRecorder:          newSampleRecorder(),
	}
	if fuzzer.merger != nil {
		fuzzer.merger.SetProjectID(config.ProjectID)
	}
	fuzzer.simMin = math.Inf(1)
	if fuzzer.strictPrestate {
		if fuzzer.attackStateCodeOnly {
			log.Printf("[Fuzzer]  严格prestate已启用：attack_state仅补代码")
		} else {
			log.Printf("[Fuzzer]  严格prestate已启用：跳过attack_state注入")
		}
	}

	//  根据配置选择模拟器类型
	if config.LocalExecution {
		log.Printf("[Fuzzer]  使用本地EVM执行模式（复用RPC连接获取状态）")
		poolSize := config.Workers
		if poolSize < 1 {
			poolSize = 1
		}
		for i := 0; i < poolSize; i++ {
			dualSim := simulator.NewDualModeSimulatorWithClients(rpcClient, client)
			dualSim.SetExecutionMode(simulator.ModeLocal)
			dualSim.SetRecordFullTrace(config.RecordFullTrace)
			fuzzer.dualSimulators = append(fuzzer.dualSimulators, dualSim)
		}
		if len(fuzzer.dualSimulators) > 0 {
			fuzzer.dualSimulator = fuzzer.dualSimulators[0]
			fuzzer.simulator = fuzzer.dualSimulator.EVMSimulator // 保持兼容性
		}
	} else {
		log.Printf("[Fuzzer]  使用RPC执行模式")
		sim := simulator.NewEVMSimulatorWithClients(rpcClient, client)
		fuzzer.simulator = sim
	}

	return fuzzer, nil
}

// getSimulatorForWorker 返回指定worker可用的本地执行器（无池则回退首个）
func (f *CallDataFuzzer) getSimulatorForWorker(workerID int) *simulator.DualModeSimulator {
	if len(f.dualSimulators) == 0 {
		return f.dualSimulator
	}
	if workerID < 0 {
		return f.dualSimulators[0]
	}
	idx := workerID % len(f.dualSimulators)
	return f.dualSimulators[idx]
}

// primarySimulator 返回首个可用执行器
func (f *CallDataFuzzer) primarySimulator() *simulator.DualModeSimulator {
	if len(f.dualSimulators) > 0 {
		return f.dualSimulators[0]
	}
	return f.dualSimulator
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
			log.Printf("[Fuzzer]  Hook外部调用 #%d: to=%s selector=%s", visited+1, frame.To, shortSelector(frame.Input))
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

	//  新增：统计每个函数选择器的调用频率（识别循环）
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

	//  第一优先级：高频调用函数（循环攻击的核心）
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
		log.Printf("[Fuzzer]  High frequency selection: selector=%s called %d times (likely loop attack)",
			highFreqSelector, maxFreq)
		return callDetails[highFreqSelector]
	}

	//  第二优先级：配置文件中标记为priority="high"的函数
	// 正确的选择器：flash=0xbdbc91ab, bond=0xa515366a, debond=0xee9c79da
	highPrioritySelectors := map[string]bool{
		"0xbdbc91ab": true, // flash(address,address,uint256,bytes)
		"0xa515366a": true, // bond(address,uint256)
	}
	for selector, call := range callDetails {
		if highPrioritySelectors[selector] {
			log.Printf("[Fuzzer]  Config priority selection: selector=%s (marked as high priority)", selector)
			return call
		}
	}

	//  第三优先级：选择非标准函数且input较长的（通常是业务逻辑函数）
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

	//  第四优先级：选择非标准函数（即使参数少）
	for _, call := range calls {
		if len(call.Input) >= 10 {
			selector := call.Input[:10]
			if !standardSelectors[selector] {
				log.Printf("[Fuzzer] Secondary selection: Non-standard function (selector=%s)", selector)
				return call
			}
		}
	}

	//  回退：如果所有调用都是标准函数，选择第一个
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
func extractProtectedContractPath(path []ContractJumpDest, contract common.Address, startIndex int, label string) []ContractJumpDest {
	target := strings.ToLower(contract.Hex())
	if startIndex < 0 {
		startIndex = 0
	}

	source := "未标记"
	if strings.TrimSpace(label) != "" {
		source = label
	}

	var res []ContractJumpDest

	//  调试：统计原始路径中所有PC值
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
		log.Printf("[extractProtectedContractPath][%s]  目标合约%s在路径中共有%d个JUMPDEST，前20个PC=%v",
			source, target, len(targetContractPCs), func() []uint64 {
				if len(targetContractPCs) > 20 {
					return targetContractPCs[:20]
				}
				return targetContractPCs
			}())
		// 检查是否包含PC=100
		if count, exists := pcCountMap[100]; exists {
			log.Printf("[extractProtectedContractPath][%s]  路径包含PC=100，出现%d次", source, count)
		} else {
			log.Printf("[extractProtectedContractPath][%s]  路径不包含PC=100", source)
		}
		// 检查是否包含PC=247
		if count, exists := pcCountMap[247]; exists {
			log.Printf("[extractProtectedContractPath][%s]  路径包含PC=247，出现%d次", source, count)
		}
	}

	// 从startIndex开始定位目标合约首次命中位置
	firstIdx := -1
	for i := startIndex; i < len(path); i++ {
		if strings.EqualFold(path[i].Contract, target) {
			firstIdx = i
			break
		}
	}
	if firstIdx >= 0 {
		// 只提取目标合约自己的JUMPDESTs，不包括其他合约的调用
		// 这样可以避免相似度被无关合约的JUMPDEST影响
		for i := firstIdx; i < len(path); i++ {
			if strings.EqualFold(path[i].Contract, target) {
				res = append(res, path[i])
			}
		}
		log.Printf("[extractProtectedContractPath][%s]  过滤策略: 仅目标合约 (提取%d个, 从索引%d开始扫描%d个)",
			source, len(res), firstIdx, len(path)-firstIdx)
	}

	// 添加调试日志
	if len(res) > 0 {
		log.Printf("[extractProtectedContractPath][%s] 成功提取 %d 个JUMPDEST (从索引=%d起, 路径总长=%d)", source, len(res), firstIdx, len(path))

		// 详细打印前20个JUMPDEST，标注是否为目标合约
		if len(res) <= 20 {
			for i, jd := range res {
				isTarget := strings.EqualFold(jd.Contract, target)
				marker := ""
				if isTarget {
					marker = " ✓目标"
				} else {
					marker = " ✗其他"
				}
				log.Printf("[extractProtectedContractPath][%s]   #%d: %s:%d%s", source, i, jd.Contract, jd.PC, marker)
			}
		}
	} else {
		// 【增强】列出路径中实际包含的合约地址
		contracts := make(map[string]int)
		for _, jd := range path {
			contracts[strings.ToLower(jd.Contract)]++
		}
		log.Printf("[extractProtectedContractPath][%s] ⚠️ 未找到目标合约 %s (路径长度=%d, 路径包含的合约: %v)",
			source, target, len(path), contracts)
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
		log.Printf("[Fuzzer]   查询合约代码失败(%s): %v", addr.Hex(), err)
		return
	}
	if code == "" || code == "0x" {
		log.Printf("[Fuzzer]   合约代码为空(%s)，无法注入", addr.Hex())
		return
	}

	if entry == nil {
		entry = &simulator.AccountOverride{}
	}
	entry.Code = strings.ToLower(code)
	(*ov)[lower] = entry
	log.Printf("[Fuzzer]  已注入合约代码: %s (size=%d bytes)", addr.Hex(), (len(code)-2)/2)
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

// baseline_state.json 结构体（只保留必要字段）
type baselineContractEntry struct {
	Balance string            `json:"balance"`
	Nonce   string            `json:"nonce,omitempty"`
	Code    string            `json:"code"`
	Storage map[string]string `json:"storage"`
}

type baselineStateFile struct {
	BlockNumber    uint64                           `json:"block_number"`
	BlockTimestamp uint64                           `json:"block_timestamp"`
	Contracts      map[string]baselineContractEntry `json:"contracts"`
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

// normalizeBaselineQuantity 将baseline中的数值统一转为0x前缀十六进制
func normalizeBaselineQuantity(value string) string {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		return strings.ToLower(raw)
	}
	if bi, ok := new(big.Int).SetString(raw, 10); ok {
		return "0x" + strings.ToLower(bi.Text(16))
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

// normalizeSelector 统一 selector 表示：去掉0x前缀并转小写
func normalizeSelector(sel string) string {
	return strings.ToLower(strings.TrimPrefix(sel, "0x"))
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
		log.Printf("[AttackState]   未找到attack_state.json: %v", err)
		return nil, ""
	}

	if cached, ok := attackStateCache.Load(path); ok {
		if parsed, ok2 := cached.(*attackStateFile); ok2 && parsed != nil {
			return parsed, path
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[AttackState]   读取attack_state失败(%s): %v", path, err)
		return nil, ""
	}

	var parsed attackStateFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		log.Printf("[AttackState]   解析attack_state失败(%s): %v", path, err)
		return nil, ""
	}
	if len(parsed.Addresses) == 0 {
		log.Printf("[AttackState]   attack_state(%s)未包含addresses字段", path)
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
		log.Printf("[AttackState]  已从%s注入状态：%d个账户，跳过已存在非零槽位 %d 个", path, injected, skipped)
	}
	return base
}

// mergeAttackStateCodeOnlyIntoOverride 仅从attack_state补齐代码（不写入余额/nonce/存储）
func mergeAttackStateCodeOnlyIntoOverride(base simulator.StateOverride, attack *attackStateFile, path string) simulator.StateOverride {
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
		if entry.Code == "" || entry.Code == "0x" {
			continue
		}

		ov := base[lowerAddr]
		if ov == nil {
			ov = &simulator.AccountOverride{}
		}
		if ov.Code != "" && ov.Code != "0x" {
			skipped++
			base[lowerAddr] = ov
			continue
		}
		ov.Code = strings.ToLower(entry.Code)
		base[lowerAddr] = ov
		injected++
	}

	if injected > 0 {
		log.Printf("[AttackState]  已从%s补齐代码：%d个账户，跳过已有代码 %d 个", path, injected, skipped)
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

// injectAttackStateCodeOnlyIfAvailable 尝试仅从attack_state.json补齐代码
func (f *CallDataFuzzer) injectAttackStateCodeOnlyIfAvailable(base simulator.StateOverride, contractAddr common.Address) simulator.StateOverride {
	attackState, path := f.loadAttackState(contractAddr)
	if attackState == nil {
		return base
	}
	return mergeAttackStateCodeOnlyIntoOverride(base, attackState, path)
}

// locateBaselineStatePath 基于项目ID或显式配置定位baseline_state.json
func (f *CallDataFuzzer) locateBaselineStatePath() (string, error) {
	cacheKey := f.projectID
	if cacheKey == "" {
		cacheKey = "default"
	}
	if cached, ok := baselineStatePathCache.Load(cacheKey); ok {
		if path, ok2 := cached.(string); ok2 && path != "" {
			return path, nil
		}
	}

	if strings.TrimSpace(f.baselineStatePath) != "" {
		baselineStatePathCache.Store(cacheKey, f.baselineStatePath)
		return f.baselineStatePath, nil
	}

	if env := strings.TrimSpace(os.Getenv("AUTOPATH_BASELINE_STATE")); env != "" {
		baselineStatePathCache.Store(cacheKey, env)
		return env, nil
	}
	if env := strings.TrimSpace(os.Getenv("BASELINE_STATE_FILE")); env != "" {
		baselineStatePathCache.Store(cacheKey, env)
		return env, nil
	}

	if f.projectID == "" {
		return "", fmt.Errorf("项目ID为空，无法定位baseline_state.json")
	}

	var candidates []string
	if wd, err := os.Getwd(); err == nil {
		for depth := 0; depth <= 3; depth++ {
			up := wd
			for i := 0; i < depth; i++ {
				up = filepath.Dir(up)
			}
			candidates = append(candidates, filepath.Join(up, "generated", f.projectID, "baseline_state.json"))
		}
	}
	candidates = append(candidates, filepath.Join("generated", f.projectID, "baseline_state.json"))

	for _, cand := range candidates {
		if st, err := os.Stat(cand); err == nil && !st.IsDir() {
			baselineStatePathCache.Store(cacheKey, cand)
			return cand, nil
		}
	}

	return "", fmt.Errorf("未找到baseline_state.json")
}

// loadBaselineState 读取并缓存baseline_state.json
func (f *CallDataFuzzer) loadBaselineState() (*baselineStateFile, string) {
	path, err := f.locateBaselineStatePath()
	if err != nil {
		log.Printf("[BaselineState]  未找到baseline_state.json: %v", err)
		return nil, ""
	}

	if cached, ok := baselineStateCache.Load(path); ok {
		if parsed, ok2 := cached.(*baselineStateFile); ok2 && parsed != nil {
			return parsed, path
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[BaselineState]  读取baseline_state失败(%s): %v", path, err)
		return nil, ""
	}

	var parsed baselineStateFile
	if err := json.Unmarshal(data, &parsed); err != nil {
		log.Printf("[BaselineState]  解析baseline_state失败(%s): %v", path, err)
		return nil, ""
	}
	if len(parsed.Contracts) == 0 {
		log.Printf("[BaselineState]  baseline_state(%s)未包含contracts字段", path)
		return nil, ""
	}

	baselineStateCache.Store(path, &parsed)
	return &parsed, path
}

// resolveLocalExecutionBlockNumber 为本地EVM执行选择更接近prestate的基准区块
func (f *CallDataFuzzer) resolveLocalExecutionBlockNumber(blockNumber uint64) uint64 {
	if !f.localExecution || blockNumber == 0 {
		return blockNumber
	}

	baseline, path := f.loadBaselineState()
	if baseline != nil && baseline.BlockNumber > 0 {
		if baseline.BlockNumber <= blockNumber {
			if baseline.BlockNumber != blockNumber {
				log.Printf("[BaselineState]  本地EVM基准区块调整: tx=%d -> baseline=%d (source=%s)", blockNumber, baseline.BlockNumber, path)
			}
			return baseline.BlockNumber
		}
		log.Printf("[BaselineState]  baseline区块高于交易区块 (baseline=%d, tx=%d)，忽略baseline", baseline.BlockNumber, blockNumber)
	}

	if blockNumber > 0 {
		prev := blockNumber - 1
		log.Printf("[BaselineState]  baseline缺失，使用前一区块作为本地EVM基线: tx=%d -> %d", blockNumber, prev)
		return prev
	}

	return blockNumber
}

// mergeBaselineStateIntoOverride 将baseline_state中的余额/代码/存储注入StateOverride
func mergeBaselineStateIntoOverride(base simulator.StateOverride, baseline *baselineStateFile, path string) simulator.StateOverride {
	if baseline == nil || len(baseline.Contracts) == 0 {
		return base
	}

	if base == nil {
		base = make(simulator.StateOverride)
	}

	injected := 0
	skipped := 0
	for rawAddr, entry := range baseline.Contracts {
		lowerAddr := strings.ToLower(rawAddr)
		if lowerAddr == "0x0000000000000000000000000000000000000000" || lowerAddr == "" {
			continue
		}

		ov := base[lowerAddr]
		if ov == nil {
			ov = &simulator.AccountOverride{}
		}

		if balHex := normalizeBaselineQuantity(entry.Balance); balHex != "" && !isZeroLikeHex(balHex) {
			if ov.Balance == "" || isZeroLikeHex(ov.Balance) {
				ov.Balance = balHex
			}
		}

		if nonceHex := normalizeBaselineQuantity(entry.Nonce); nonceHex != "" && !isZeroLikeHex(nonceHex) {
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
		log.Printf("[BaselineState]  已从%s注入状态：%d个账户，跳过已存在非零槽位 %d 个", path, injected, skipped)
	}
	return base
}

// injectBaselineStateIfAvailable 尝试注入baseline_state.json中的状态
func (f *CallDataFuzzer) injectBaselineStateIfAvailable(base simulator.StateOverride) simulator.StateOverride {
	baseline, path := f.loadBaselineState()
	if baseline == nil {
		return base
	}
	return mergeBaselineStateIntoOverride(base, baseline, path)
}

// applyBaselineBlockTimeIfAvailable 使用baseline_state中的时间戳对齐本地EVM
func (f *CallDataFuzzer) applyBaselineBlockTimeIfAvailable(blockNumber uint64) {
	if !f.localExecution {
		return
	}
	baseline, path := f.loadBaselineState()
	if baseline == nil {
		return
	}
	if baseline.BlockTimestamp == 0 {
		log.Printf("[BaselineState]  baseline_state(%s)未包含block_timestamp，跳过本地EVM时间对齐", path)
		return
	}
	if baseline.BlockNumber != 0 && blockNumber != 0 && baseline.BlockNumber != blockNumber {
		log.Printf("[BaselineState]  block_number不一致，仍使用baseline时间戳 (baseline=%d, tx=%d)", baseline.BlockNumber, blockNumber)
	}

	sims := f.dualSimulators
	if len(sims) == 0 && f.dualSimulator != nil {
		sims = []*simulator.DualModeSimulator{f.dualSimulator}
	}

	updated := 0
	for _, sim := range sims {
		if sim == nil {
			continue
		}
		localExec := sim.GetLocalExecutor()
		if localExec == nil {
			continue
		}
		cfg := localExec.GetConfig()
		if cfg == nil {
			cfg = local.DefaultExecutionConfig()
		}
		cfgCopy := *cfg
		cfgCopy.Time = baseline.BlockTimestamp
		localExec.SetConfig(&cfgCopy)
		updated++
	}

	if updated > 0 {
		log.Printf("[BaselineState]  已对齐本地EVM时间戳=%d (source=%s)", baseline.BlockTimestamp, path)
	}
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
		// 如果已有配置种子，跳过注入原始参数，优先使用配置
		if len(seedCfg.AttackSeeds[p.Index]) > 0 {
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
			log.Printf("[SeedGen]  注入原始参数作为种子 param#%d=%v", p.Index, p.Value)
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
		if strings.Contains(p.Type, "bytes") || isArrayType(p.Type) {
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

// dedupInterfaces 对接口切片去重，保持顺序
func dedupInterfaces(vals []interface{}) []interface{} {
	seen := make(map[string]bool)
	out := make([]interface{}, 0, len(vals))
	for _, v := range vals {
		key := fmt.Sprintf("%v", v)
		if !seen[key] {
			seen[key] = true
			out = append(out, v)
		}
	}
	return out
}

// convertToInterfaceArray 将任意数组转换为 []interface{}
func convertToInterfaceArray(val interface{}) []interface{} {
	switch v := val.(type) {
	case []interface{}:
		return v
	case []common.Address:
		out := make([]interface{}, len(v))
		for i, a := range v {
			out[i] = a
		}
		return out
	case []string:
		out := make([]interface{}, len(v))
		for i, s := range v {
			out[i] = s
		}
		return out
	default:
		rv := reflect.ValueOf(val)
		if rv.IsValid() && (rv.Kind() == reflect.Array || rv.Kind() == reflect.Slice) {
			out := make([]interface{}, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				out[i] = rv.Index(i).Interface()
			}
			return out
		}
		return []interface{}{}
	}
}

// repeatAddress 使用地址池循环生成指定长度的数组
func repeatAddress(pool []interface{}, length int) []interface{} {
	if len(pool) == 0 {
		pool = []interface{}{common.HexToAddress("0x0000000000000000000000000000000000000000")}
	}
	out := make([]interface{}, length)
	for i := 0; i < length; i++ {
		out[i] = pool[i%len(pool)]
	}
	return out
}

func fitInterfaceArrayLength(arr []interface{}, length int, padValue interface{}) []interface{} {
	if length <= 0 {
		return arr
	}
	if len(arr) >= length {
		return arr[:length]
	}
	out := make([]interface{}, length)
	copy(out, arr)
	for i := len(arr); i < length; i++ {
		out[i] = padValue
	}
	return out
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
) ([]*AttackParameterReport, error) {
	// 全局超时控制（整轮Fuzz+规则推送），默认20s
	budget := f.timeout
	if budget <= 0 {
		budget = 20 * time.Second
	}
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, budget)
	}
	if cancel != nil {
		defer cancel()
	}

	deadline, hasDeadline := ctx.Deadline()
	if hasDeadline {
		remaining := time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
		log.Printf("[Fuzzer] 计时 整轮Fuzz+推送时间预算: %v", remaining)
	} else {
		log.Printf("[Fuzzer] 计时 整轮Fuzz时间预算: %v", budget)
	}

	// 步骤1: 获取原始交易信息和执行路径（传入受保护合约地址）
	log.Printf("[Fuzzer] Fetching original transaction: %s", txHash.Hex())
	txObj, originalPath, stateOverride, err := f.getOriginalExecution(ctx, txHash, blockNumber, contractAddr, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to get original execution: %w", err)
	}
	// 计算本地EVM执行所需的基准区块高度（避免Fork场景使用交易后状态导致CREATE碰撞）
	simBlockNumber := blockNumber
	if f.localExecution {
		simBlockNumber = f.resolveLocalExecutionBlockNumber(blockNumber)
	}
	pathContractAddr := resolvePathContractAddr(originalPath, contractAddr)
	if pathContractAddr != contractAddr {
		log.Printf("[Fuzzer]  路径对齐使用实现地址: %s (原目标=%s)", pathContractAddr.Hex(), contractAddr.Hex())
	}
	log.Printf("[Fuzzer] Original path has %d JUMPDESTs (total), %d ContractJumpDests, protected start index: %d",
		len(originalPath.JumpDests), len(originalPath.ContractJumpDests), originalPath.ProtectedStartIndex)

	// 使用纯 prestate 作为基线执行环境，不合并原始交易的后置状态变更
	log.Printf("[Fuzzer]  使用交易 prestate 作为模糊测试基线 (success=%v, gas=%d, jumpDests=%d, contractJumpDests=%d)",
		originalPath.Success, originalPath.GasUsed, len(originalPath.JumpDests), len(originalPath.ContractJumpDests))
	if stateOverride != nil {
		if ov, ok := stateOverride[strings.ToLower(contractAddr.Hex())]; ok && ov != nil && len(ov.State) > 0 {
			log.Printf("[Fuzzer]  当前StateOverride包含受保护合约槽位: %d", len(ov.State))
		}
		if daiOv, ok := stateOverride[strings.ToLower("0x6B175474E89094C44Da98b954EedeAC495271d0F")]; ok && daiOv != nil && len(daiOv.State) > 0 {
			log.Printf("[Fuzzer]  当前StateOverride包含DAI槽位: %d", len(daiOv.State))
			// 关键授权槽位：allowance[0x356e...][wBARL]，DAI slot3
			allowSlot := "0x3d87c91f878fde976b5e092bfe8d85850194c887f898e23b950a17e7e2210300"
			if val, ok2 := daiOv.State[allowSlot]; ok2 {
				log.Printf("[Fuzzer]  DAI 授权槽位[356E->wBARL slot3]: %s", val)
			} else {
				log.Printf("[Fuzzer]  未找到DAI授权槽位[356E->wBARL slot3]")
			}
		}
	}

	// 步骤1.5: 基于 prestate 重放交易，提取调用树
	log.Printf("[Fuzzer] Tracing transaction (prestate) to extract call tree...")
	trace, err := f.simulator.TraceCallTreeWithOverride(ctx, txObj, blockNumber, stateOverride)
	if err != nil {
		log.Printf("[Fuzzer]   基于 prestate 的 traceCall 失败，回退链上 callTracer: %v", err)
		trace, err = f.tracer.TraceTransaction(txHash)
		if err != nil {
			return nil, fmt.Errorf("failed to trace transaction: %w", err)
		}
	}
	log.Printf("[Fuzzer] Trace captured: calls=%d, rootFrom=%s, rootTo=%s", len(trace.Calls), trace.From, trace.To)

	// 若调用树为空，回退使用 callTracer 再取一次调用序列
	if len(trace.Calls) == 0 {
		log.Printf("[Fuzzer]  trace.Calls 为空，尝试使用 callTracer 重新获取调用树")
		if ct, err2 := f.tracer.TraceTransaction(txHash); err2 == nil && ct != nil && len(ct.Calls) > 0 {
			trace = ct
			log.Printf("[Fuzzer]  callTracer 获取成功: calls=%d, rootFrom=%s, rootTo=%s", len(trace.Calls), trace.From, trace.To)
		} else {
			log.Printf("[Fuzzer]  callTracer 也未获取到调用树: %v", err2)
		}
	}

	// 如果仍然没有调用树，使用交易本身构造一个伪调用帧继续Fuzz，避免直接中止
	if len(trace.Calls) == 0 {
		if txObj == nil {
			return nil, fmt.Errorf("trace.Calls is empty for tx %s, cannot extract protected calls", txHash.Hex())
		}
		log.Printf("[Fuzzer]  trace.Calls 仍为空，使用交易入口构造伪调用树继续Fuzzing")
		trace = f.buildFallbackCallFrame(txObj, "", "", txObj.Data())
		log.Printf("[Fuzzer]  伪调用帧: from=%s, to=%s, inputLen=%d", trace.From, trace.To, len(trace.Input))
	}

	// 步骤2: 从调用树中提取调用受保护合约的call
	log.Printf("[Fuzzer] Extracting calls to protected contract %s", contractAddr.Hex())
	protectedCalls := f.extractProtectedContractCalls(trace, contractAddr)
	if len(protectedCalls) == 0 && f.tracer != nil {
		log.Printf("[Fuzzer]  未在调用树中找到受保护合约 %s，尝试使用链上traceTransaction重新提取", contractAddr.Hex())
		if traceFallback, err := f.tracer.TraceTransaction(txHash); err != nil {
			log.Printf("[Fuzzer]  traceTransaction 失败，保持原调用树: %v", err)
		} else if traceFallback != nil {
			trace = traceFallback
			protectedCalls = f.extractProtectedContractCalls(trace, contractAddr)
			if len(protectedCalls) > 0 {
				log.Printf("[Fuzzer]  使用traceTransaction成功匹配受保护合约: %d 个调用", len(protectedCalls))
			} else {
				log.Printf("[Fuzzer]  traceTransaction 仍未命中受保护合约，继续使用fallback入口")
			}
		}
	}

	// 在重放过程中hook外部调用，捕获首个命中的受保护合约
	hookTarget, hookVisited := f.hookFirstProtectedCall(trace, contractAddr)
	if hookTarget != nil {
		selector := hookTarget.Input
		if len(selector) > 10 {
			selector = selector[:10]
		}
		log.Printf("[Fuzzer]  首次命中受保护合约: to=%s selector=%s (hook顺序=%d)", hookTarget.To, selector, hookVisited)
	}

	if len(protectedCalls) == 0 {
		log.Printf("[Fuzzer]  未在调用树中找到受保护合约 %s，回退到入口调用", contractAddr.Hex())
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
		log.Printf("[Fuzzer]  fallback 使用交易入口: from=%s to=%s selector=%s", targetCall.From, targetCall.To, targetCall.Input[:10])
	}
	log.Printf("[Fuzzer] Found %d calls to protected contract (hook扫描次数=%d)", len(protectedCalls), hookVisited)

	// 按项目配置的 target_functions 过滤调用
	targetSelectors := loadTargetSelectors(f.projectID, contractAddr)
	if len(targetSelectors) == 0 {
		if !f.targetFunctionFallback {
			log.Printf("[Fuzzer]  未加载到target_functions配置，跳过Fuzz (fallback已关闭) contract=%s", contractAddr.Hex())
			return nil, nil
		}
	} else {
		contractKey := strings.ToLower(contractAddr.Hex())
		allowed, ok := targetSelectors[contractKey]
		if !ok || len(allowed) == 0 {
			if !f.targetFunctionFallback {
				log.Printf("[Fuzzer]  配置未包含该合约的target_functions，跳过Fuzz (fallback已关闭) contract=%s", contractAddr.Hex())
				return nil, nil
			}
		} else {
			log.Printf("[Fuzzer]  发现配置的 target_functions (projectID=%s, contract=%s, selectors=%v)",
				f.projectID, contractAddr.Hex(), mapKeys(allowed))
			filtered := make([]*CallFrame, 0, len(protectedCalls))
			for _, c := range protectedCalls {
				if len(c.Input) < 10 {
					continue
				}
				selector := strings.ToLower(c.Input[:10])
				if allowed[selector] {
					filtered = append(filtered, c)
				}
			}
			if len(filtered) > 0 {
				protectedCalls = filtered
				log.Printf("[Fuzzer]  依据配置的 target_functions 过滤后，剩余 %d 个调用 (contract=%s)", len(protectedCalls), contractAddr.Hex())
			} else if f.targetFunctionFallback {
				log.Printf("[Fuzzer]  配置的 target_functions 未在调用树中命中，回退使用全部受保护调用 (contract=%s)", contractAddr.Hex())
			} else {
				log.Printf("[Fuzzer]  配置的 target_functions 未在调用树中命中，跳过Fuzz (fallback已关闭) contract=%s", contractAddr.Hex())
				return nil, nil
			}
		}
	}

	// 去重并按selector顺序依次Fuzz，确保同笔交易内的多个目标函数都能被覆盖
	targetCalls := protectedCalls
	if len(targetCalls) > 1 {
		seen := make(map[string]bool)
		dedup := make([]*CallFrame, 0, len(targetCalls))
		for _, c := range targetCalls {
			if len(c.Input) < 10 {
				continue
			}
			selector := strings.ToLower(c.Input[:10])
			key := selector + "|" + strings.ToLower(c.To)
			if seen[key] {
				continue
			}
			seen[key] = true
			dedup = append(dedup, c)
		}
		if len(dedup) > 0 {
			targetCalls = dedup
		}
	}

	// 若hook捕获到的目标在列表中，将其提前
	if hookTarget != nil && len(targetCalls) > 1 {
		for i, c := range targetCalls {
			if c == hookTarget {
				targetCalls[0], targetCalls[i] = targetCalls[i], targetCalls[0]
				break
			}
			if len(c.Input) >= 10 && len(hookTarget.Input) >= 10 &&
				strings.EqualFold(c.Input[:10], hookTarget.Input[:10]) &&
				strings.EqualFold(c.To, hookTarget.To) {
				targetCalls[0], targetCalls[i] = targetCalls[i], targetCalls[0]
				break
			}
		}
	}

	var chainedCalls []*CallFrame
	if len(targetCalls) > 1 {
		chainableSelectors, detectErr := f.detectChainedSampleChanges(ctx, contractAddr, targetCalls, simBlockNumber, stateOverride, trace)
		if detectErr != nil {
			log.Printf("[Fuzzer]  连锁样本试探失败，退化为逐个变异: %v", detectErr)
		}

		pendingTargets := make([]*CallFrame, 0, len(targetCalls))
		if len(targetCalls) > 0 {
			pendingTargets = append(pendingTargets, targetCalls[0])
		}
		for _, c := range targetCalls[1:] {
			if len(c.Input) < 10 {
				continue
			}
			selector := strings.ToLower(c.Input[:10])
			if chainableSelectors != nil && chainableSelectors[selector] {
				chainedCalls = append(chainedCalls, c)
			} else {
				pendingTargets = append(pendingTargets, c)
			}
		}
		targetCalls = pendingTargets

		log.Printf("[Fuzzer]  连锁样本检测结果: 可复用首个函数的=%d，需要单独变异的=%d",
			len(chainedCalls), len(targetCalls)-1)
	}

	log.Printf("[Fuzzer]  将依次Fuzz %d 个目标调用 (合约=%s)", len(targetCalls), contractAddr.Hex())

	var reports []*AttackParameterReport

	if len(targetCalls) == 0 {
		return nil, fmt.Errorf("未找到可Fuzz的受保护调用")
	}

	// 预处理可能耗时较长，预算在此处动态分配，避免被前置流程消耗完
	remaining := budget
	if hasDeadline {
		remaining = time.Until(deadline)
		if remaining < 0 {
			remaining = 0
		}
	}
	pushReserve := 10 * time.Second
	if remaining > 0 {
		maxReserve := remaining / 4
		if pushReserve > maxReserve {
			pushReserve = maxReserve
		}
	}
	fuzzBudget := remaining - pushReserve
	if fuzzBudget < 0 {
		fuzzBudget = 0
	}
	fuzzCtx := ctx
	var fuzzCancel context.CancelFunc
	if fuzzBudget > 0 {
		fuzzCtx, fuzzCancel = context.WithTimeout(ctx, fuzzBudget)
		defer fuzzCancel()
		log.Printf("[Fuzzer] 计时 Fuzz阶段预算: %v，预留推送/规则生成: %v，剩余总时长: %v", fuzzBudget, pushReserve, remaining)
	} else {
		log.Printf("[Fuzzer] 计时 无可用Fuzz时间（remaining=%v，预留%v），将直接生成兜底规则", remaining, pushReserve)
	}

	totalTargets := len(targetCalls)
	fuzzDeadline, fuzzHasDeadline := fuzzCtx.Deadline()
	if fuzzBudget == 0 {
		log.Printf("[Fuzzer] 计时 本次无可用Fuzz时间，所有目标将直接生成兜底规则")
	}
	for i, targetCall := range targetCalls {
		if len(targetCall.Input) < 10 {
			return nil, fmt.Errorf("目标调用输入过短")
		}
		log.Printf("[Fuzzer] 进度 [%d/%d] selector=%s from=%s to=%s", i+1, totalTargets, targetCall.Input[:10], targetCall.From, targetCall.To)

		targetCtx := fuzzCtx
		var targetCancel context.CancelFunc
		if fuzzBudget == 0 {
			report := f.buildFallbackReportForCall(contractAddr, targetCall, txHash, blockNumber, "Fuzz阶段预算为空")
			if report != nil {
				reports = append(reports, report)
			}
			continue
		}
		if fuzzHasDeadline {
			remaining := time.Until(fuzzDeadline)
			if remaining <= 0 {
				report := f.buildFallbackReportForCall(contractAddr, targetCall, txHash, blockNumber, "Fuzz阶段预算耗尽")
				if report != nil {
					reports = append(reports, report)
				}
				continue
			}
			perBudget := remaining / time.Duration(totalTargets-i)
			if perBudget > 0 {
				targetCtx, targetCancel = context.WithTimeout(fuzzCtx, perBudget)
			}
		}

		report, err := f.fuzzSingleTargetCall(targetCtx, txHash, contractAddr, blockNumber, simBlockNumber, targetCall, originalPath, stateOverride, trace)
		if targetCancel != nil {
			targetCancel()
		}
		if err != nil {
			log.Printf("[Fuzzer]  当前目标fuzz失败，使用兜底规则继续: %v", err)
			report = f.buildFallbackReportForCall(contractAddr, targetCall, txHash, blockNumber, "fuzz失败")
		}
		if report == nil {
			continue
		}
		reports = append(reports, report)

		// 仅用首个目标的样本去推导连锁调用规则
		if i == 0 && len(chainedCalls) > 0 {
			if extra := f.buildChainedReportsFromSamples(report, chainedCalls, contractAddr, txHash, blockNumber); len(extra) > 0 {
				reports = append(reports, extra...)
			}
		}
	}

	return reports, nil
}

// fuzzSingleTargetCall 针对单个受保护函数生成规则/表达式
func (f *CallDataFuzzer) fuzzSingleTargetCall(
	ctx context.Context,
	txHash common.Hash,
	contractAddr common.Address,
	blockNumber uint64,
	simBlockNumber uint64,
	targetCall *CallFrame,
	originalPath *simulator.ReplayResult,
	stateOverride simulator.StateOverride,
	trace *CallFrame,
) (*AttackParameterReport, error) {
	if targetCall == nil {
		return nil, fmt.Errorf("target call is nil")
	}

	pathContractAddr := resolvePathContractAddr(originalPath, contractAddr)
	if pathContractAddr != contractAddr {
		log.Printf("[Fuzzer]  单函数路径对齐使用实现地址: %s (原目标=%s)", pathContractAddr.Hex(), contractAddr.Hex())
	}

	// 单函数时间预算：使用全局deadline剩余时间
	budget := time.Second * 20
	if dl, ok := ctx.Deadline(); ok {
		remaining := time.Until(dl)
		if remaining <= 0 {
			log.Printf("[Fuzzer] 计时 当前函数预算耗尽，使用兜底规则")
			return f.buildFallbackReportForCall(contractAddr, targetCall, txHash, blockNumber, "当前函数预算耗尽"), nil
		}
		budget = remaining
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	log.Printf("[Fuzzer] 计时 当前函数Fuzz时间预算: %v", budget)

	startTime := time.Now()
	f.stats.StartTime = startTime
	f.stats.TestedCombinations = 0
	f.stats.ValidCombinations = 0
	f.stats.FailedSimulations = 0
	atomic.StoreInt64(&f.firstHitAt, 0)
	atomic.StoreInt64(&f.maxSimAt, 0)
	atomic.StoreUint64(&f.maxSimVal, 0)
	f.resetAttemptStats()
	if f.sampleRecorder != nil {
		f.sampleRecorder.Reset()
	}
	bestSimilarity := -1.0
	recordedSelectors := make(map[string]struct{})

	// 固定为函数级Fuzz，不做循环/入口模式切换
	useLoopBaseline := false

	// 步骤3: 解析目标调用的calldata
	callDataBytes, err := hexutil.Decode(targetCall.Input)
	if err != nil {
		return nil, fmt.Errorf("failed to decode target call input: %w", err)
	}
	log.Printf("[Fuzzer] Parsing target calldata (%d bytes)", len(callDataBytes))

	parsedData, targetMethod, err := f.parseCallDataWithABI(contractAddr, callDataBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse target contract calldata: %w", err)
	}

	log.Printf("[Fuzzer] Parsed: selector=0x%s, %d parameters", hex.EncodeToString(parsedData.Selector), len(parsedData.Parameters))

	// 拷贝种子配置，避免跨函数交叉污染
	baseSeedCfg := cloneSeedConfig(f.seedConfig)
	targetSeedCfg := cloneSeedConfigForFunction(baseSeedCfg, targetMethod)

	// ========== Layer 3: 符号执行约束提取 ==========
	var symbolicSeeds []symbolic.SymbolicSeed
	if baseSeedCfg != nil && baseSeedCfg.SymbolicConfig != nil && baseSeedCfg.SymbolicConfig.Enabled {
		log.Printf("[Fuzzer]  Symbolic execution enabled (mode=%s)", baseSeedCfg.SymbolicConfig.Mode)

		// 初始化符号执行组件(延迟初始化)
		if f.symbolicExtractor == nil {
			f.symbolicExtractor = symbolic.NewConstraintExtractor(baseSeedCfg.SymbolicConfig, f.rpcClient)
			f.symbolicSolver = symbolic.NewConstraintSolver(baseSeedCfg.SymbolicConfig)
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

	// 预先为本次交易的所有潜在selector准备变异参数，供Hook按selector快速取用
	// 重新加载（会命中缓存，无额外开销）
	targetSelectors := loadTargetSelectors(f.projectID, contractAddr)
	preparedMutations := f.prepareSelectorMutations(contractAddr, trace, targetSelectors, targetSeedCfg)

	// 步骤4: 生成参数组合并执行模糊测试
	log.Printf("[Fuzzer] Generating parameter combinations...")

	var results []FuzzingResult

	// 对BarleyFinance关键函数收紧种子：地址仅使用原始值，数值不超过原始值，避免SafeERC20因余额/授权不足反复revert
	if targetSeedCfg != nil && targetSeedCfg.Enabled && targetMethod != nil &&
		(strings.EqualFold(targetMethod.Name, "flash") ||
			strings.EqualFold(targetMethod.Name, "bond") ||
			strings.EqualFold(targetMethod.Name, "debond")) {
		if targetSeedCfg.AttackSeeds == nil {
			targetSeedCfg.AttackSeeds = make(map[int][]interface{})
		}
		for _, p := range parsedData.Parameters {
			// 地址参数：保留原始地址，并加入极端/随机地址以增加离散度
			if strings.HasPrefix(p.Type, "address") {
				idx := p.Index
				seedPool := []interface{}{
					p.Value,
					common.HexToAddress("0x0000000000000000000000000000000000000000"),
					common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
					common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
					common.BytesToAddress([]byte{0x01}),
					common.BytesToAddress([]byte{0x09}),
				}
				targetSeedCfg.AttackSeeds[idx] = dedupInterfaces(seedPool)

				// address[]/address[N]：加入不同长度的数组以拉低相似度
				if isArrayType(p.Type) {
					fixedLen := p.ArrayLen
					if fixedLen <= 0 {
						fixedLen = arrayFixedLength(p.Type)
					}
					base := convertToInterfaceArray(p.Value)
					if fixedLen > 0 {
						base = fitInterfaceArrayLength(base, fixedLen, common.Address{})
						targetSeedCfg.AttackSeeds[idx] = []interface{}{
							base,
							repeatAddress(seedPool, fixedLen),
						}
					} else {
						if len(base) == 0 {
							base = []interface{}{p.Value}
						}
						targetSeedCfg.AttackSeeds[idx] = []interface{}{
							base,
							[]interface{}{},
							repeatAddress(seedPool, 1),
							repeatAddress(seedPool, 3),
							repeatAddress(seedPool, 10),
						}
					}
				}
				continue
			}

			// bytes 类型：原值+空值+全FF，避免全部落在同一区域
			if strings.HasPrefix(p.Type, "bytes") {
				idx := p.Index
				targetSeedCfg.AttackSeeds[idx] = []interface{}{
					p.Value,
					[]byte{},
					bytes.Repeat([]byte{0xFF}, 32),
				}
				continue
			}

			// uint256 采用微扰策略：原值±1%、0.5x、2x
			if strings.EqualFold(p.Type, "uint256") {
				orig := normalizeBigInt(p.Value)
				idx := p.Index
				if seeds := buildSmartUintSeeds(orig); len(seeds) > 0 {
					targetSeedCfg.AttackSeeds[idx] = seeds
				} else {
					// fallback 保留原值
					targetSeedCfg.AttackSeeds[idx] = []interface{}{p.Value}
				}
				continue
			}

			// 其他uint类型，保留默认种子或原值
			if strings.HasPrefix(p.Type, "uint") {
				idx := p.Index
				if _, ok := targetSeedCfg.AttackSeeds[idx]; !ok {
					targetSeedCfg.AttackSeeds[idx] = []interface{}{p.Value}
				}
			}
		}
	}

	// 若未提供显式种子，注入原始调用参数作为基础种子，避免组合数过少
	if targetSeedCfg != nil && targetSeedCfg.Enabled {
		injected := primeSeedsWithOriginalParams(targetSeedCfg, parsedData.Parameters)
		_ = injected

		// 防御：地址、复杂类型只保留原始值，避免无代码地址/异常payload导致必然revert
		sanitizeAddressSeeds(targetSeedCfg, parsedData.Parameters)
		restrictComplexSeeds(targetSeedCfg, parsedData.Parameters)
	}

	// 判断是否启用自适应迭代模式
	if targetSeedCfg != nil && targetSeedCfg.Enabled &&
		targetSeedCfg.AdaptiveConfig != nil && targetSeedCfg.AdaptiveConfig.Enabled {
		log.Printf("[Fuzzer]  Adaptive iteration mode enabled (max_iterations=%d)", targetSeedCfg.AdaptiveConfig.MaxIterations)
		results = f.executeAdaptiveFuzzing(ctx, parsedData, targetMethod, originalPath, targetCall, contractAddr, pathContractAddr, simBlockNumber, stateOverride, symbolicSeeds, trace, targetSeedCfg, baseSeedCfg, useLoopBaseline, preparedMutations, &bestSimilarity, recordedSelectors)
	} else {
		var combinations <-chan []interface{}
		if targetSeedCfg != nil && targetSeedCfg.Enabled {
			// 使用种子驱动生成器
			seedGen := NewSeedGenerator(targetSeedCfg, f.generator.maxVariations)

			// 约束范围集成：如果有约束范围配置，合并约束种子
			if seedGen.HasConstraintRanges() {
				if targetMethod != nil {
					seedGen.MergeConstraintSeeds(targetMethod.Name)
					log.Printf("[Fuzzer]  Merged constraint seeds for function: %s", targetMethod.Name)
				} else {
					for funcName := range targetSeedCfg.ConstraintRanges {
						seedGen.MergeConstraintSeeds(funcName)
						log.Printf("[Fuzzer]  Merged constraint seeds for function: %s", funcName)
					}
				}
				log.Printf("[Fuzzer]  Using constraint ranges")
			}

			// Layer 3: 设置符号种子
			if len(symbolicSeeds) > 0 {
				seedGen.SetSymbolicSeeds(symbolicSeeds)
				log.Printf("[Fuzzer]  Applied %d symbolic seeds to generator", len(symbolicSeeds))
			}

			combinations = seedGen.GenerateSeedBasedCombinations(parsedData.Parameters)
			log.Printf("[Fuzzer]  Using seed-driven generation with %d attack seeds", len(targetSeedCfg.AttackSeeds))
		} else {
			// 使用默认随机生成器
			combinations = f.generator.GenerateCombinations(parsedData.Parameters)
			log.Printf("[Fuzzer] Using default random generation")
		}

		log.Printf("[Fuzzer] Starting fuzzing with %d workers, threshold: %.2f", f.maxWorkers, f.threshold)
		results = f.executeFuzzing(ctx, combinations, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, pathContractAddr, simBlockNumber, stateOverride, trace, baseSeedCfg, useLoopBaseline, preparedMutations, &bestSimilarity, recordedSelectors)
		log.Printf("[Fuzzer] Found %d valid combinations", len(results))
	}

	// 仅保留相似度>=阈值的组合进入规则生成路径
	const ruleGenMinSimilarity = 0.6
	if len(results) > 0 {
		filtered := results[:0]
		for _, r := range results {
			if r.Similarity >= ruleGenMinSimilarity {
				filtered = append(filtered, r)
			}
		}
		results = filtered
		log.Printf("[Fuzzer] Selected %d rule-gen combinations (sim >= %.2f, max=%.4f)", len(results), ruleGenMinSimilarity, bestSimilarity)
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

	// 记录ABI推导的标准函数签名，便于后续校验selector是否匹配
	if targetMethod != nil {
		report.FunctionSignature = targetMethod.Sig
		if report.FunctionName == "" {
			report.FunctionName = targetMethod.Name
		}
	}

	f.attachSampleRecords(report, contractAddr, parsedData.Selector, targetMethod)
	f.attachPreparedMutations(report, preparedMutations)
	// 补充时间轴统计
	if fh := atomic.LoadInt64(&f.firstHitAt); fh > 0 {
		report.FirstHitSeconds = float64(fh) / float64(time.Second)
	}
	if ms := atomic.LoadInt64(&f.maxSimAt); ms > 0 {
		report.MaxSimSeconds = float64(ms) / float64(time.Second)
	}
	// 使用全量尝试统计（包含低相似度样本）
	if attempts, sum, minSim, maxSim, rawSum, rawMin, rawMax := f.getAttemptStats(); attempts > 0 {
		report.TotalCombinations = attempts
		report.AverageSimilarity = sum / float64(attempts)
		report.MinSimilarity = minSim
		report.MaxSimilarity = maxSim
		report.RawStatsAvailable = true
		report.RawAverageSimilarity = rawSum / float64(attempts)
		report.RawMaxSimilarity = rawMax
		report.RawMinSimilarity = rawMin
		log.Printf("[Fuzzer]  报告统计（含低相似度）：total=%d avg=%.4f min=%.4f max=%.4f 阈值=%.4f 有效=%d, 重叠avg=%.4f min=%.4f max=%.4f",
			attempts, report.AverageSimilarity, report.MinSimilarity, report.MaxSimilarity, f.threshold, len(results),
			report.RawAverageSimilarity, report.RawMinSimilarity, report.RawMaxSimilarity)
	} else {
		// 即便全部revert也要记录尝试的组合数
		if f.stats.TestedCombinations > 0 {
			report.TotalCombinations = f.stats.TestedCombinations
		} else {
			report.TotalCombinations = len(results)
		}
	}
	// 统一以实际执行过的组合数为准，避免报告出现默认值
	if f.stats.TestedCombinations > 0 {
		report.TotalCombinations = f.stats.TestedCombinations
	}

	// 应用约束规则（若已生成）
	f.applyConstraintRule(report, contractAddr, parsedData.Selector)

	// 输出时间轴统计
	if report.FirstHitSeconds > 0 {
		log.Printf("[Fuzzer] 计时 首个达标样本出现在 %.2f 秒", report.FirstHitSeconds)
	}
	if report.MaxSimSeconds > 0 {
		log.Printf("[Fuzzer] 计时 最高相似度出现在 %.2f 秒", report.MaxSimSeconds)
	}

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

// buildFallbackReportForCall 兜底报告已禁用，保留入口以便记录原因
func (f *CallDataFuzzer) buildFallbackReportForCall(
	contractAddr common.Address,
	call *CallFrame,
	txHash common.Hash,
	blockNumber uint64,
	reason string,
) *AttackParameterReport {
	if call == nil {
		return nil
	}

	selector := ""
	if len(call.Input) >= 10 {
		selector = ensureSelectorHex(call.Input[:10])
	}
	if reason != "" {
		log.Printf("[Fuzzer]  兜底报告已禁用: %s selector=%s", reason, selector)
	} else {
		log.Printf("[Fuzzer]  兜底报告已禁用: selector=%s", selector)
	}
	_ = contractAddr
	_ = txHash
	_ = blockNumber
	return nil
}

// parseCallDataWithABI 优先使用ABI解析，失败则回退到启发式解析
func (f *CallDataFuzzer) parseCallDataWithABI(contractAddr common.Address, callData []byte) (*ParsedCallData, *abi.Method, error) {
	var contractABI *abi.ABI

	if f.parser != nil {
		if loaded, err := f.parser.LoadABIForAddress(contractAddr); err == nil {
			contractABI = loaded
		} else {
			log.Printf("[Fuzzer]   加载ABI失败(%s)，将回退启发式解析: %v", contractAddr.Hex(), err)
		}
	}

	if contractABI != nil && len(callData) >= 4 {
		if _, err := contractABI.MethodById(callData[:4]); err != nil && f.parser != nil {
			if loaded, err := f.parser.LoadABIForAddressWithSelector(contractAddr, callData[:4]); err == nil {
				contractABI = loaded
			}
		}
	}

	if contractABI != nil {
		parsed, err := f.parser.ParseCallDataWithABI(callData, contractABI)
		if err == nil {
			var method *abi.Method
			if m, err := contractABI.MethodById(parsed.Selector); err == nil {
				method = m
			} else {
				if f.parser != nil && len(callData) >= 4 {
					if sig := lookupTargetSignature(f.projectID, contractAddr, callData[:4]); sig != "" {
						if synthetic, err := f.parser.BuildABIFromSignature(sig); err == nil {
							if parsedWith, err := f.parser.ParseCallDataWithABI(callData, synthetic); err == nil {
								if m2, err := synthetic.MethodById(callData[:4]); err == nil {
									method = m2
								}
								f.parser.SetABI(contractAddr, synthetic)
								log.Printf("[Fuzzer]   使用目标函数签名解析ABI: %s", sig)
								return parsedWith, method, nil
							}
							log.Printf("[Fuzzer]   使用目标函数签名解析失败: %v", err)
						} else {
							log.Printf("[Fuzzer]   生成目标函数ABI失败: %v", err)
						}
					}
				}

				selectorHex := hex.EncodeToString(parsed.Selector)
				if alias, ok := syntheticSelectorAliases[selectorHex]; ok {
					// 针对缺失ABI但已知的入口选择器使用占位Method，避免完全失效
					log.Printf("[Fuzzer] 信息 使用内置占位ABI解析选择器0x%s (%s)", selectorHex, alias)
					method = &abi.Method{
						Name:            alias,
						RawName:         alias,
						Type:            abi.Function,
						StateMutability: "nonpayable",
						Inputs:          abi.Arguments{},
						Outputs:         abi.Arguments{},
					}
				} else {
					log.Printf("[Fuzzer]   ABI中未找到选择器0x%s: %v", selectorHex, err)
				}
			}
			return parsed, method, nil
		}
		log.Printf("[Fuzzer]   使用ABI解析失败，改用启发式解析: %v", err)
	}

	// 尝试使用配置中的目标函数签名构建ABI（适用于代理/缺失ABI场景）
	if f.parser != nil && len(callData) >= 4 {
		if sig := lookupTargetSignature(f.projectID, contractAddr, callData[:4]); sig != "" {
			if synthetic, err := f.parser.BuildABIFromSignature(sig); err == nil {
				if parsed, err := f.parser.ParseCallDataWithABI(callData, synthetic); err == nil {
					var method *abi.Method
					if m, err := synthetic.MethodById(callData[:4]); err == nil {
						method = m
					}
					f.parser.SetABI(contractAddr, synthetic)
					log.Printf("[Fuzzer]   使用目标函数签名解析ABI: %s", sig)
					return parsed, method, nil
				}
				log.Printf("[Fuzzer]   使用目标函数签名解析失败: %v", err)
			} else {
				log.Printf("[Fuzzer]   生成目标函数ABI失败: %v", err)
			}
		}
	}

	parsed, err := f.parser.ParseCallData(callData)
	return parsed, nil, err
}

// waitForTraceAvailable 智能等待trace数据就绪
// 先轮询TransactionReceipt确认交易已上链，然后额外等待让trace生成
func (f *CallDataFuzzer) waitForTraceAvailable(ctx context.Context, txHash common.Hash, timeout time.Duration) error {
	log.Printf("[Fuzzer]  智能等待：检查交易收据和trace数据就绪状态...")
	start := time.Now()

	// 第1步：轮询交易收据，确认交易已上链
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		receipt, err := f.client.TransactionReceipt(ctx, txHash)
		if err == nil && receipt != nil {
			elapsed := time.Since(start)
			log.Printf("[Fuzzer]  交易收据已就绪 (区块 %d, 状态 %d, 耗时 %v)",
				receipt.BlockNumber.Uint64(), receipt.Status, elapsed)
			break
		}

		if time.Since(start) > timeout {
			return fmt.Errorf("timeout (%v) waiting for transaction receipt", timeout)
		}

		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	// 第2步：收据就绪后，额外等待让Anvil生成trace数据
	// 原因：Anvil的trace生成是异步的，在交易上链后可能还需要几秒钟
	traceWaitTime := 5 * time.Second
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining <= 0 {
			return ctx.Err()
		} else if remaining < traceWaitTime {
			traceWaitTime = remaining
		}
	}
	log.Printf("[Fuzzer] 等待 收据已就绪，再等待%v让Anvil生成trace数据...", traceWaitTime)
	if traceWaitTime > 0 {
		select {
		case <-time.After(traceWaitTime):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	log.Printf("[Fuzzer]  智能等待完成，trace数据应该已就绪")

	return nil
}

// validateBaselinePath 确保基准路径包含目标合约的JUMPDEST（避免对比失真）
func (f *CallDataFuzzer) validateBaselinePath(result *simulator.ReplayResult, contractAddr common.Address, source string) error {
	if result == nil {
		return fmt.Errorf("[基准路径校验] %s 结果为空，无法校验目标合约", source)
	}
	if contractAddr == (common.Address{}) {
		return nil
	}
	if len(result.ContractJumpDests) == 0 {
		return fmt.Errorf("[基准路径校验] %s 未包含合约维度JUMPDEST，无法校验目标合约 %s", source, contractAddr.Hex())
	}

	target := strings.ToLower(contractAddr.Hex())
	found := false
	contracts := make(map[string]int)
	for _, jd := range result.ContractJumpDests {
		addr := strings.ToLower(jd.Contract)
		contracts[addr]++
		if addr == target {
			found = true
		}
	}
	if !found {
		if resolved, hits, mode := resolveDelegateCallTarget(result, contractAddr); resolved != "" {
			if mode != "delegatecall-caller" && mode != "delegatecall-any" {
				log.Printf("[Fuzzer]  基准路径未包含目标合约%s，但仅检测到非delegatecall调用 (mode=%s, resolved=%s)，跳过路径映射",
					contractAddr.Hex(), mode, resolved)
				return nil
			}
			log.Printf("[Fuzzer]  基准路径未包含目标合约%s，检测到代理调用实现%s (hits=%d, mode=%s)，继续使用实现路径",
				contractAddr.Hex(), resolved, hits, mode)
			return nil
		}
		log.Printf("[Fuzzer]  基准路径校验失败详情: callEdges=%d, callTargets=%d, protectedStart=%d",
			len(result.CallEdges), len(result.CallTargets), result.ProtectedStartIndex)
		if len(result.CallEdges) > 0 {
			maxLog := 5
			if len(result.CallEdges) < maxLog {
				maxLog = len(result.CallEdges)
			}
			for i := 0; i < maxLog; i++ {
				edge := result.CallEdges[i]
				log.Printf("[Fuzzer]   CallEdge[%d]: caller=%s -> target=%s op=%s depth=%d", i, edge.Caller, edge.Target, edge.Op, edge.Depth)
			}
		}
		return fmt.Errorf("[基准路径校验] %s 未包含目标合约 %s (合约数量=%d, 合约分布=%v)", source, contractAddr.Hex(), len(contracts), contracts)
	}
	return nil
}

func resolveDelegateCallTarget(result *simulator.ReplayResult, contractAddr common.Address) (string, int, string) {
	if result == nil || contractAddr == (common.Address{}) {
		return "", 0, ""
	}
	if len(result.CallEdges) == 0 {
		// 兼容旧 tracer：尝试根据 callTargets 频次推测实现地址
		if len(result.CallTargets) == 0 {
			return "", 0, ""
		}
		targetLower := strings.ToLower(contractAddr.Hex())
		freq := make(map[string]int)
		for _, t := range result.CallTargets {
			addr := strings.ToLower(t)
			if addr == targetLower {
				continue
			}
			freq[addr]++
		}
		best := ""
		bestCount := 0
		for addr, cnt := range freq {
			if cnt > bestCount {
				best = addr
				bestCount = cnt
			}
		}
		return best, bestCount, "callTargets"
	}

	targetLower := strings.ToLower(contractAddr.Hex())
	candidates := make(map[string]int)
	mode := ""
	for _, edge := range result.CallEdges {
		if edge.Caller == "" || edge.Target == "" {
			continue
		}
		if strings.EqualFold(edge.Caller, targetLower) && (edge.Op == "DELEGATECALL" || edge.Op == "CALLCODE") {
			candidates[strings.ToLower(edge.Target)] = 0
		}
	}
	if len(candidates) > 0 {
		mode = "delegatecall-caller"
	}
	if len(candidates) == 0 {
		// 兜底：未找到caller匹配的delegatecall，尝试收集所有delegatecall目标
		for _, edge := range result.CallEdges {
			if edge.Op == "DELEGATECALL" || edge.Op == "CALLCODE" {
				addr := strings.ToLower(edge.Target)
				if addr != "" && addr != targetLower {
					candidates[addr] = 0
				}
			}
		}
		if len(candidates) > 0 {
			mode = "delegatecall-any"
		}
	}
	if len(candidates) == 0 {
		// 再兜底：尝试收集CALL目标（部分代理使用普通CALL或外部路由）
		for _, edge := range result.CallEdges {
			if edge.Op == "CALL" {
				addr := strings.ToLower(edge.Target)
				if addr != "" && addr != targetLower {
					candidates[addr] = 0
				}
			}
		}
		if len(candidates) > 0 {
			mode = "call-any"
		}
	}
	if len(candidates) == 0 {
		// 最后兜底：允许STATICCALL目标（仅用于路径映射）
		for _, edge := range result.CallEdges {
			if edge.Op == "STATICCALL" {
				addr := strings.ToLower(edge.Target)
				if addr != "" && addr != targetLower {
					candidates[addr] = 0
				}
			}
		}
		if len(candidates) > 0 {
			mode = "staticcall-any"
		}
	}
	if len(candidates) == 0 {
		return "", 0, ""
	}

	for _, jd := range result.ContractJumpDests {
		addr := strings.ToLower(jd.Contract)
		if _, ok := candidates[addr]; ok {
			candidates[addr]++
		}
	}

	best := ""
	bestCount := 0
	for addr, count := range candidates {
		if count > bestCount {
			best = addr
			bestCount = count
		}
	}
	if bestCount == 0 {
		return "", 0, ""
	}
	return best, bestCount, mode
}

func hasCallEdgeTarget(result *simulator.ReplayResult, contractAddr common.Address) bool {
	if result == nil || contractAddr == (common.Address{}) {
		return false
	}
	targetLower := strings.ToLower(contractAddr.Hex())
	for _, edge := range result.CallEdges {
		if strings.EqualFold(edge.Target, targetLower) {
			return true
		}
	}
	for _, target := range result.CallTargets {
		if strings.EqualFold(target, targetLower) {
			return true
		}
	}
	return false
}

func resolvePathContractAddr(result *simulator.ReplayResult, contractAddr common.Address) common.Address {
	if result == nil || contractAddr == (common.Address{}) {
		return contractAddr
	}
	if findProtectedStartIndex(result.ContractJumpDests, contractAddr) >= 0 {
		return contractAddr
	}

	if resolved, hits, mode := resolveDelegateCallTarget(result, contractAddr); resolved != "" {
		if mode != "delegatecall-caller" && mode != "delegatecall-any" {
			log.Printf("[Fuzzer]  路径映射忽略：非delegatecall模式 (mode=%s, target=%s, resolved=%s)",
				mode, contractAddr.Hex(), resolved)
			return contractAddr
		}
		log.Printf("[Fuzzer]  代理路径映射: %s -> %s (hits=%d, mode=%s)",
			contractAddr.Hex(), resolved, hits, mode)
		return common.HexToAddress(resolved)
	}

	return contractAddr
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

	//  新增：智能等待trace数据就绪
	// 先确认交易收据可用，然后额外等待让trace生成
	log.Printf("[Fuzzer]  启动智能等待机制...")
	if err := f.waitForTraceAvailable(ctx, txHash, 30*time.Second); err != nil {
		log.Printf("[Fuzzer]   智能等待超时: %v，继续尝试重试机制", err)
		// 不直接返回错误，让后续的重试机制继续尝试
	}

	// 优先使用 debug_traceTransaction 获取原始执行路径（链上真实轨迹）
	var directResult *simulator.ReplayResult
	if f.simulator != nil {
		traceContract := contractAddr
		if f.recordFullTrace {
			traceContract = common.Address{}
		}
		if res, traceErr := f.simulator.ForkAndReplay(ctx, blockNumber, txHash, traceContract); traceErr != nil {
			log.Printf("[Fuzzer]  debug_traceTransaction失败，无法获取链上轨迹: %v", traceErr)
		} else {
			directResult = res
			if receipt, rerr := f.client.TransactionReceipt(ctx, txHash); rerr == nil && receipt != nil {
				receiptSuccess := receipt.Status == types.ReceiptStatusSuccessful
				if directResult.Success != receiptSuccess {
					log.Printf("[Fuzzer]  以收据状态覆盖trace success: trace=%v, receipt=%v", directResult.Success, receiptSuccess)
					directResult.Success = receiptSuccess
				}
			} else if rerr != nil {
				log.Printf("[Fuzzer]  获取交易收据失败，无法覆盖trace success: %v", rerr)
			}
			log.Printf("[Fuzzer]  原始执行摘要(基于traceTransaction): success=%v, gas=%d, stateChanges=%d, jumpDests=%d, contractJumpDests=%d",
				directResult.Success, directResult.GasUsed, len(directResult.StateChanges), len(directResult.JumpDests), len(directResult.ContractJumpDests))
			if err := f.validateBaselinePath(directResult, contractAddr, "traceTransaction"); err != nil {
				return nil, nil, nil, err
			}
		}
	}

	// 构建交易执行前的 prestate，用于本地模拟/调用树（不作为回放来源）
	override, err := f.simulator.BuildStateOverride(ctx, txHash)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to build state override: %w", err)
	}
	if f.localExecution {
		override = f.injectBaselineStateIfAvailable(override)
		f.applyBaselineBlockTimeIfAvailable(blockNumber)
		if f.strictPrestate {
			if f.attackStateCodeOnly {
				override = f.injectAttackStateCodeOnlyIfAvailable(override, contractAddr)
			}
		} else if f.attackStateCodeOnly {
			override = f.injectAttackStateCodeOnlyIfAvailable(override, contractAddr)
		} else {
			override = f.injectAttackStateIfAvailable(override, contractAddr)
		}
	}

	// 若已成功拿到链上真实轨迹，直接作为原始路径返回
	if directResult != nil {
		return tx, directResult, override, nil
	}

	return nil, nil, nil, fmt.Errorf("未获取到链上trace（已禁用回放），请确认节点已开启debug_traceTransaction")
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
				log.Printf("[Fuzzer]  第 %d 次重试成功获取交易", attempt+1)
			}
			return tx, nil
		}

		lastErr = err
		if attempt < maxRetries-1 {
			delay := retryDelays[attempt]
			log.Printf("[Fuzzer]   获取交易失败 (尝试 %d/%d): %v，%v 后重试...",
				attempt+1, maxRetries, err, delay)
			time.Sleep(delay)
		}
	}

	log.Printf("[Fuzzer]  经过 %d 次重试仍无法获取交易", maxRetries)
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
	pathContractAddr common.Address,
	simBlockNumber uint64,
	stateOverride simulator.StateOverride,
	callTree *CallFrame,
	seedCfg *SeedConfig,
	loopBaseline bool,
	preparedMutations map[string]*PreparedMutation,
	bestSimilarity *float64,
	recordedSelectors map[string]struct{},
) []FuzzingResult {
	if pathContractAddr == (common.Address{}) {
		pathContractAddr = contractAddr
	}
	// 【增强】记录fuzzing配置信息
	log.Printf("[Fuzzer] executeFuzzing配置: localExecution=%v, dualSimulators数量=%d, useRPC=%v",
		f.localExecution, len(f.dualSimulators), !f.localExecution || len(f.dualSimulators) == 0)
	if pathContractAddr != (common.Address{}) && pathContractAddr != contractAddr {
		log.Printf("[Fuzzer]  路径合约: %s (保护目标=%s)", pathContractAddr.Hex(), contractAddr.Hex())
	}

	//  创建带超时的可取消context，限定整轮fuzz耗时；默认使用配置的 timeout_seconds
	totalBudget := f.timeout
	if totalBudget <= 0 {
		totalBudget = 20 * time.Second
	}
	effectiveBudget := totalBudget
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining <= 0 {
			log.Printf("[Fuzzer] 计时 单轮Fuzz预算已耗尽，跳过本轮执行")
			return nil
		} else if remaining < effectiveBudget {
			effectiveBudget = remaining
		}
	}
	ctx, cancel := context.WithTimeout(ctx, effectiveBudget)
	defer cancel()

	log.Printf("[Fuzzer] 计时 单轮Fuzz时间预算: %v", effectiveBudget)

	// 结果收集
	results := []FuzzingResult{}
	resultMutex := &sync.Mutex{}

	// 统计
	var testedCount int32
	var validCount int32
	var highSimCount int32 //  高相似度结果计数
	batchTracker := newBatchBestTracker()

	//  检查是否启用目标相似度停止
	targetSimEnabled := f.targetSimilarity > 0 && f.maxHighSimResults > 0
	if targetSimEnabled {
		log.Printf("[Fuzzer]  Target similarity mode: stop when finding %d valid results (sim >= %.4f)",
			f.maxHighSimResults, f.targetSimilarity)
	}

	// 预计算函数级基准路径，避免循环场景误用非目标函数起点
	var functionBaseline []ContractJumpDest
	if loopBaseline {
		functionBaseline = f.buildFunctionBaseline(ctx, targetCall, pathContractAddr, simBlockNumber, stateOverride)
		if len(functionBaseline) == 0 && pathContractAddr != contractAddr {
			log.Printf("[Fuzzer]  函数级基准为空，回退使用目标合约地址构建 (path=%s, target=%s)",
				pathContractAddr.Hex(), contractAddr.Hex())
			functionBaseline = f.buildFunctionBaseline(ctx, targetCall, contractAddr, simBlockNumber, stateOverride)
		}
	}

	// 基准过短时改用函数级基准，避免窗口被锁死导致相似度恒定
	const minBaselineLen = 30
	const minBaselineRatio = 0.1
	var fallbackBaseline []ContractJumpDest
	if originalPath != nil && len(originalPath.ContractJumpDests) > 0 {
		origContractJumpDests := make([]ContractJumpDest, len(originalPath.ContractJumpDests))
		for i, cjd := range originalPath.ContractJumpDests {
			origContractJumpDests[i] = ContractJumpDest{
				Contract: cjd.Contract,
				PC:       cjd.PC,
			}
		}

		firstIdx := findProtectedStartIndex(origContractJumpDests, pathContractAddr)
		baselineLen := 0
		if firstIdx >= 0 {
			baselineLen = len(origContractJumpDests) - firstIdx
		}
		tooShort := baselineLen == 0 || (baselineLen < minBaselineLen ||
			(float64(baselineLen) < float64(len(origContractJumpDests))*minBaselineRatio))

		if tooShort {
			if len(functionBaseline) == 0 {
				functionBaseline = f.buildFunctionBaseline(ctx, targetCall, pathContractAddr, simBlockNumber, stateOverride)
				if len(functionBaseline) == 0 && pathContractAddr != contractAddr {
					log.Printf("[Fuzzer]  函数级基准为空，回退使用目标合约地址构建 (path=%s, target=%s)",
						pathContractAddr.Hex(), contractAddr.Hex())
					functionBaseline = f.buildFunctionBaseline(ctx, targetCall, contractAddr, simBlockNumber, stateOverride)
				}
			}
			if len(functionBaseline) > 0 {
				fallbackBaseline = functionBaseline
				log.Printf("[Fuzzer]  基准路径过短(len=%d,total=%d)，启用函数级基准(len=%d)用于相似度比较",
					baselineLen, len(origContractJumpDests), len(functionBaseline))
			} else {
				log.Printf("[Fuzzer]  基准路径过短(len=%d,total=%d)，但函数级基准为空，继续使用原始基准",
					baselineLen, len(origContractJumpDests))
			}
		}
	}

	// 输出StateOverride概况，便于诊断无状态变更场景
	overrideAccounts, overrideSlots, overrideTargetSlots := summarizeOverride(stateOverride, contractAddr)
	log.Printf("[Fuzzer]  StateOverride概要: 账户=%d, 槽位总数=%d, 受保护合约槽位=%d",
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
				pathContractAddr,
				simBlockNumber,
				stateOverride,
				callTree,
				preparedMutations,
				&results,
				resultMutex,
				bestSimilarity,
				recordedSelectors,
				&testedCount,
				&validCount,
				&highSimCount, //  传递高相似度计数器
				batchTracker,
				cancel, //  传递cancel函数
				functionBaseline,
				fallbackBaseline,
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

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		log.Printf("[Fuzzer] 计时 已达单轮fuzz时限(%v)，提前停止后续组合", effectiveBudget)
	}

	// 更新统计（累加以支持自适应多轮汇总）
	f.stats.TestedCombinations += int(testedCount)
	f.stats.ValidCombinations += int(validCount)

	log.Printf("[Fuzzer] Tested %d combinations, found %d valid (high-sim: %d)",
		testedCount, validCount, highSimCount)

	return results
}

// buildFunctionBaseline 基于原始调用参数构建函数级基准路径，避免基准起点落在debond等非目标函数
func (f *CallDataFuzzer) buildFunctionBaseline(
	ctx context.Context,
	targetCall *CallFrame,
	pathContractAddr common.Address,
	simBlockNumber uint64,
	stateOverride simulator.StateOverride,
) []ContractJumpDest {
	if targetCall == nil {
		return nil
	}

	callData, err := hexutil.Decode(targetCall.Input)
	if err != nil {
		log.Printf("[Fuzzer]   无法解码原始调用输入，跳过函数级基准构建: %v", err)
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
		BlockNumber:   simBlockNumber,
		Timeout:       f.timeout,
		StateOverride: stateOverride,
	}

	simResult, err := f.simulateExecution(ctx, req, -1)
	if err != nil {
		log.Printf("[Fuzzer]   函数级基准构建模拟失败: %v", err)
		return nil
	}

	baseline := extractProtectedContractPath(simResult.ContractJumpDests, pathContractAddr, 0, "函数级基准")
	if len(baseline) > 0 {
		head := make([]uint64, 0, 5)
		for i := 0; i < len(baseline) && i < 5; i++ {
			head = append(head, baseline[i].PC)
		}
		log.Printf("[Fuzzer]  函数级基准路径就绪: len=%d, 前5个PC=%v", len(baseline), head)
	} else {
		log.Printf("[Fuzzer]   函数级基准路径为空，跳过对齐优化")
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
		switch arr := v.(type) {
		case []interface{}:
			arrLen := len(arr)
			first := ""
			if arrLen > 0 {
				first = ValueToString(arr[0])
			}
			parts = append(parts, fmt.Sprintf("#%d=array(len=%d,first=%s)", i, arrLen, first))
		default:
			parts = append(parts, fmt.Sprintf("#%d=%s", i, ValueToString(v)))
		}
	}
	return strings.Join(parts, ", ")
}

// extractNonZeroNumeric 提取非零数值参数，返回十进制字符串
func extractNonZeroNumeric(val interface{}) (string, bool) {
	if bi := normalizeBigInt(val); bi != nil {
		if bi.Sign() != 0 {
			return bi.String(), true
		}
	}
	return "", false
}

// formatSelectorForLog 返回4字节selector的16进制展示
func formatSelectorForLog(calldata []byte) string {
	if len(calldata) >= 4 {
		return hexutil.Encode(calldata[:4])
	}
	return hexutil.Encode(calldata)
}

// mapKeys 返回map的键列表，便于日志打印
func mapKeys[T comparable](m map[T]bool) []T {
	keys := make([]T, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// cloneSeedConfig 深拷贝种子配置，避免跨函数相互污染
func cloneSeedConfig(cfg *SeedConfig) *SeedConfig {
	if cfg == nil {
		return nil
	}

	cp := *cfg

	// 深拷贝切片字段
	if len(cfg.RangeConfig.NumericRangePercent) > 0 {
		cp.RangeConfig.NumericRangePercent = append([]int(nil), cfg.RangeConfig.NumericRangePercent...)
	}
	if len(cfg.RangeConfig.AddressMutationTypes) > 0 {
		cp.RangeConfig.AddressMutationTypes = append([]string(nil), cfg.RangeConfig.AddressMutationTypes...)
	}

	// 深拷贝AttackSeeds
	if cfg.AttackSeeds != nil {
		cp.AttackSeeds = make(map[int][]interface{}, len(cfg.AttackSeeds))
		for idx, seeds := range cfg.AttackSeeds {
			cp.AttackSeeds[idx] = append([]interface{}(nil), seeds...)
		}
	}

	// 深拷贝约束范围
	if cfg.ConstraintRanges != nil {
		cp.ConstraintRanges = cloneConstraintRangeMap(cfg.ConstraintRanges)
	}

	// 深拷贝范围变异配置
	if cfg.RangeMutationConfig != nil {
		tmp := *cfg.RangeMutationConfig
		cp.RangeMutationConfig = &tmp
	}

	// 深拷贝自适应配置
	if cfg.AdaptiveConfig != nil {
		cp.AdaptiveConfig = cloneAdaptiveConfig(cfg.AdaptiveConfig)
	}

	// 深拷贝符号执行配置
	if cfg.SymbolicConfig != nil {
		tmp := *cfg.SymbolicConfig
		// FocusOpcodes为切片，单独拷贝
		if len(cfg.SymbolicConfig.Extraction.FocusOpcodes) > 0 {
			tmp.Extraction.FocusOpcodes = append([]string(nil), cfg.SymbolicConfig.Extraction.FocusOpcodes...)
		}
		cp.SymbolicConfig = &tmp
	}

	return &cp
}

func cloneConstraintRangeMap(src map[string]map[string]*ConstraintRange) map[string]map[string]*ConstraintRange {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]map[string]*ConstraintRange, len(src))
	for fn, params := range src {
		if len(params) == 0 {
			continue
		}
		inner := make(map[string]*ConstraintRange, len(params))
		for idx, cr := range params {
			if cr == nil {
				continue
			}
			cp := *cr
			cp.AttackValues = append([]string(nil), cr.AttackValues...)
			if cr.Range != nil {
				r := *cr.Range
				cp.Range = &r
			}
			inner[idx] = &cp
		}
		dst[fn] = inner
	}
	return dst
}

func cloneAdaptiveConfig(src *AdaptiveRangeConfig) *AdaptiveRangeConfig {
	if src == nil {
		return nil
	}
	cp := *src
	if src.RangeStrategies != nil {
		cp.RangeStrategies = make(map[string][]int, len(src.RangeStrategies))
		for k, v := range src.RangeStrategies {
			cp.RangeStrategies[k] = append([]int(nil), v...)
		}
	}
	return &cp
}

// cloneSeedConfigForFunction 返回按函数名过滤后的种子配置副本
// 支持两种键格式: 完整签名(如"debond(uint256,address[],uint8[])") 和 简单函数名(如"debond")
func cloneSeedConfigForFunction(cfg *SeedConfig, method *abi.Method) *SeedConfig {
	cloned := cloneSeedConfig(cfg)
	if cloned == nil || method == nil || len(cloned.ConstraintRanges) == 0 {
		return cloned
	}

	// 构造完整函数签名
	var fullSig string
	if method != nil {
		// 构造签名: function(type1,type2,...)
		paramTypes := make([]string, len(method.Inputs))
		for i, input := range method.Inputs {
			paramTypes[i] = input.Type.String()
		}
		fullSig = method.Name + "(" + strings.Join(paramTypes, ",") + ")"
	}

	fnLower := strings.ToLower(method.Name)

	// 1. 优先尝试完整签名匹配(新格式)
	if fullSig != "" {
		if ranges, ok := cloned.ConstraintRanges[fullSig]; ok {
			cloned.ConstraintRanges = map[string]map[string]*ConstraintRange{
				fullSig: ranges,
			}
			return cloned
		}
	}

	// 2. 尝试简单函数名匹配(向后兼容)
	if ranges, ok := cloned.ConstraintRanges[method.Name]; ok {
		cloned.ConstraintRanges = map[string]map[string]*ConstraintRange{
			method.Name: ranges,
		}
		return cloned
	}

	// 3. 尝试小写函数名匹配(向后兼容)
	if ranges, ok := cloned.ConstraintRanges[fnLower]; ok {
		cloned.ConstraintRanges = map[string]map[string]*ConstraintRange{
			fnLower: ranges,
		}
		return cloned
	}

	// 4. 尝试查找任何以函数名开头的完整签名(模糊匹配)
	for key, ranges := range cloned.ConstraintRanges {
		if strings.HasPrefix(key, method.Name+"(") {
			cloned.ConstraintRanges = map[string]map[string]*ConstraintRange{
				key: ranges,
			}
			return cloned
		}
	}

	// 未找到匹配的约束范围
	cloned.ConstraintRanges = nil
	return cloned
}

// PreparedMutation 预先构造的selector级别变异输入
type PreparedMutation struct {
	Selector        string
	FunctionName    string
	Method          *abi.Method
	MutatedCalldata []byte
	MutatedParams   []ParameterValue
	OriginalParams  []ParameterValue
}

// prepareSelectorMutations 为单次重放预先构造多个selector的变异calldata
func (f *CallDataFuzzer) prepareSelectorMutations(contractAddr common.Address, callTree *CallFrame, allowed map[string]map[string]bool, seedCfg *SeedConfig) map[string]*PreparedMutation {
	if callTree == nil {
		return nil
	}

	contractCalls := f.extractProtectedContractCalls(callTree, contractAddr)
	if len(contractCalls) == 0 {
		return nil
	}
	prepared := make(map[string]*PreparedMutation)
	contractKey := strings.ToLower(contractAddr.Hex())
	allowedFor := allowed[contractKey]
	allowAll := len(allowed) == 0 || len(allowedFor) == 0

	for _, c := range contractCalls {
		if len(c.Input) < 10 {
			continue
		}
		selector := strings.ToLower(c.Input[:10])
		if !allowAll && !allowedFor[selector] {
			continue
		}
		if _, exists := prepared[selector]; exists {
			continue
		}
		var origParams []ParameterValue
		var method *abi.Method
		if data, parseErr := hexutil.Decode(c.Input); parseErr == nil {
			if parsed, m, err := f.parseCallDataWithABI(contractAddr, data); err == nil {
				method = m
				origParams = f.convertParsedParamsToValues(parsed, method)
			}
		}

		mutatedCalldata, mutatedParams, err := f.buildMutationForCall(contractAddr, c, seedCfg)
		if err != nil {
			log.Printf("[Fuzzer]  预构造 selector=%s 变异失败: %v", selector, err)
			continue
		}
		if method == nil {
			if parsed, m, err := f.parseCallDataWithABI(contractAddr, mutatedCalldata); err == nil {
				method = m
				if origParams == nil {
					origParams = f.convertParsedParamsToValues(parsed, method)
				}
			}
		}

		name := ""
		if method != nil {
			name = method.Name
		}

		prepared[selector] = &PreparedMutation{
			Selector:        selector,
			FunctionName:    name,
			Method:          method,
			MutatedCalldata: mutatedCalldata,
			MutatedParams:   mutatedParams,
			OriginalParams:  origParams,
		}
	}
	if len(prepared) > 0 {
		log.Printf("[Fuzzer]  已预构造受保护合约的变异输入: %d 个selector", len(prepared))
	}
	return prepared
}

// buildMutationForCall 基于调用本身的参数生成一个简单变异版calldata
func (f *CallDataFuzzer) buildMutationForCall(contractAddr common.Address, call *CallFrame, seedCfg *SeedConfig) ([]byte, []ParameterValue, error) {
	if call == nil || len(call.Input) < 10 {
		return nil, nil, fmt.Errorf("call frame invalid")
	}
	callDataBytes, err := hexutil.Decode(call.Input)
	if err != nil {
		return nil, nil, err
	}
	parsed, method, err := f.parseCallDataWithABI(contractAddr, callDataBytes)
	if err != nil {
		return nil, nil, err
	}
	// 若缺少ABI，无法安全构造变异，直接返回原始calldata避免报错
	if method == nil {
		return callDataBytes, f.convertParsedParamsToValues(parsed, method), nil
	}

	localSeedCfg := cloneSeedConfigForFunction(seedCfg, method)
	if localSeedCfg != nil && localSeedCfg.Enabled {
		primeSeedsWithOriginalParams(localSeedCfg, parsed.Parameters)
		sanitizeAddressSeeds(localSeedCfg, parsed.Parameters)
		restrictComplexSeeds(localSeedCfg, parsed.Parameters)
	}

	combo := f.buildSeedBasedCombo(parsed.Parameters, method, localSeedCfg)
	if len(combo) == 0 {
		combo = buildSimpleMutatedCombo(parsed.Parameters)
	}
	selector := callDataBytes[:4]
	calldata, encodeErr := f.reconstructCallData(selector, combo, method, -1)
	if encodeErr != nil {
		return nil, nil, encodeErr
	}
	params := f.extractParameterValues(combo, selector, method)
	return calldata, params, nil
}

// buildSimpleMutatedCombo 为每个参数生成一个轻量变异值（若无法变异则回退原值）
func buildSimpleMutatedCombo(params []Parameter) []interface{} {
	combo := make([]interface{}, len(params))
	for i, p := range params {
		combo[i] = simpleMutateValue(p.Type, p.Value)
	}
	return combo
}

// buildSeedBasedCombo 基于函数的种子配置预先生成一次变异参数组合
func (f *CallDataFuzzer) buildSeedBasedCombo(params []Parameter, method *abi.Method, seedCfg *SeedConfig) []interface{} {
	if seedCfg == nil || !seedCfg.Enabled {
		return nil
	}

	localCfg := cloneSeedConfigForFunction(seedCfg, method)
	maxVariations := 1
	if f.generator != nil && f.generator.maxVariations > 0 {
		maxVariations = f.generator.maxVariations
	}

	seedGen := NewSeedGenerator(localCfg, maxVariations)
	if method != nil && seedGen.HasConstraintRanges() {
		seedGen.MergeConstraintSeeds(method.Name)
	}

	combo := make([]interface{}, len(params))
	for i, p := range params {
		variations := seedGen.generateParameterVariations(i, p)
		if len(variations) > 0 {
			combo[i] = variations[0]
		} else {
			combo[i] = p.Value
		}
	}
	return combo
}

// simpleMutateValue 尝试基于类型做轻量变异，便于批量替换
func simpleMutateValue(paramType string, original interface{}) interface{} {
	lower := strings.ToLower(paramType)
	if isArrayType(lower) {
		return original
	}
	switch {
	case strings.HasPrefix(lower, "address"):
		if addr, ok := original.(common.Address); ok {
			b := addr.Bytes()
			if len(b) > 0 {
				b[len(b)-1] ^= 0x01
			}
			return common.BytesToAddress(b)
		}
	case strings.HasPrefix(lower, "uint"):
		if bi := normalizeBigInt(original); bi != nil {
			return new(big.Int).Add(bi, big.NewInt(1))
		}
	case strings.HasPrefix(lower, "bytes"):
		if data, ok := original.([]byte); ok {
			return append(data, 0x01)
		}
	case strings.HasPrefix(lower, "bool"):
		if b, ok := original.(bool); ok {
			return !b
		}
	}
	return original
}

// summarizeParamsForChainDetection 将参数列表压缩为用于连锁判定的唯一键（跳过地址与数组）
func summarizeParamsForChainDetection(params []ParameterValue) string {
	if len(params) == 0 {
		return ""
	}
	parts := make([]string, 0, len(params))
	for _, p := range params {
		lower := strings.ToLower(p.Type)
		if isArrayType(lower) {
			continue
		}
		if strings.HasPrefix(lower, "address") {
			continue
		}
		parts = append(parts, fmt.Sprintf("%d=%s", p.Index, ValueToString(p.Value)))
	}
	if len(parts) == 0 {
		return ""
	}
	sort.Strings(parts)
	return strings.Join(parts, "|")
}

// detectChainedSampleChanges 试探首个受保护调用的变异是否会联动后续受保护调用的实参
func (f *CallDataFuzzer) detectChainedSampleChanges(
	ctx context.Context,
	contractAddr common.Address,
	targetCalls []*CallFrame,
	simBlockNumber uint64,
	stateOverride simulator.StateOverride,
	trace *CallFrame,
) (map[string]bool, error) {
	if len(targetCalls) < 2 || trace == nil {
		return nil, nil
	}
	primary := targetCalls[0]
	if len(primary.Input) < 10 {
		return nil, fmt.Errorf("primary call input too short")
	}

	targetSelectorSet := make(map[string]bool)
	for _, c := range targetCalls[1:] {
		if len(c.Input) < 10 {
			continue
		}
		targetSelectorSet[strings.ToLower(c.Input[:10])] = true
	}
	if len(targetSelectorSet) == 0 {
		return nil, nil
	}

	primarySelector := strings.ToLower(primary.Input[:10])
	origCallData, err := hexutil.Decode(primary.Input)
	if err != nil {
		return nil, fmt.Errorf("decode primary call failed: %w", err)
	}

	probeInputs := [][]byte{origCallData}
	if mutatedCalldata, _, mutErr := f.buildMutationForCall(contractAddr, primary, nil); mutErr == nil && mutatedCalldata != nil && !bytes.Equal(mutatedCalldata, origCallData) {
		probeInputs = append(probeInputs, mutatedCalldata)
	} else if mutErr != nil {
		log.Printf("[Fuzzer]  连锁样本试探变异失败，使用原始参数: %v", mutErr)
	}

	if len(probeInputs) < 2 {
		log.Printf("[Fuzzer]  连锁样本试探未生成有效变异，默认对所有受保护函数单独变异")
		return nil, nil
	}

	observed := make(map[string]map[string]struct{})
	recordParams := func(selector string, params []ParameterValue) {
		if !targetSelectorSet[selector] {
			return
		}
		key := summarizeParamsForChainDetection(params)
		if key == "" {
			return
		}
		if observed[selector] == nil {
			observed[selector] = make(map[string]struct{})
		}
		observed[selector][key] = struct{}{}
	}

	for idx, calldata := range probeInputs {
		mutationApplied := false
		hookMutator := func(frame *CallFrame, original []byte) ([]byte, bool, error) {
			if !strings.EqualFold(frame.To, contractAddr.Hex()) || len(frame.Input) < 10 {
				return original, false, nil
			}
			selectorHex := strings.ToLower(frame.Input[:10])

			if selectorHex == primarySelector && !mutationApplied {
				mutationApplied = true
				if params, _ := f.decodeParamsForSample(contractAddr, calldata, nil, selectorHex); len(params) > 0 {
					recordParams(selectorHex, params)
				}
				return calldata, true, nil
			}

			if params, _ := f.decodeParamsForSample(contractAddr, original, nil, selectorHex); len(params) > 0 {
				recordParams(selectorHex, params)
			}
			return original, false, nil
		}

		if f.localExecution {
			localSim := f.primarySimulator()
			if localSim == nil {
				return nil, fmt.Errorf("本地执行器不可用")
			}
			entry := trace
			entryFrom := common.HexToAddress(entry.From)
			entryTo := common.HexToAddress(entry.To)
			entryData, decodeErr := hexutil.Decode(entry.Input)
			if decodeErr != nil {
				return nil, fmt.Errorf("解码入口calldata失败: %w", decodeErr)
			}
			entryValue := big.NewInt(0)
			if entry.Value != "" && entry.Value != "0x0" {
				if v, err := hexutil.DecodeBig(entry.Value); err == nil {
					entryValue = v
				}
			}
			_, simErr := localSim.SimulateWithCallDataV2(
				ctx,
				entryFrom,
				entryTo,
				entryData,
				entryValue,
				simBlockNumber,
				stateOverride,
				map[common.Address]local.CallMutatorV2{
					contractAddr: simulator.AdaptCallMutator(hookMutator),
				},
			)
			if simErr != nil {
				log.Printf("[Fuzzer]  连锁试探执行失败（样本#%d）: %v", idx+1, simErr)
			}
		} else {
			_, simErr := f.simulator.ExecuteWithHooks(
				ctx,
				trace,
				simBlockNumber,
				stateOverride,
				map[string]simulator.CallMutator{strings.ToLower(contractAddr.Hex()): hookMutator},
			)
			if simErr != nil {
				log.Printf("[Fuzzer]  连锁试探执行失败（样本#%d）: %v", idx+1, simErr)
			}
		}
	}

	chainable := make(map[string]bool)
	for sel, vals := range observed {
		if len(vals) > 1 {
			chainable[sel] = true
		}
	}
	if len(chainable) > 0 {
		log.Printf("[Fuzzer]  检测到以下受保护函数输入会随首个调用变异: %v", mapKeys(chainable))
	}
	return chainable, nil
}

type observedCall struct {
	selector     string
	functionName string
	params       []ParameterValue
	mutated      bool
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
	pathContractAddr common.Address,
	simBlockNumber uint64,
	stateOverride simulator.StateOverride,
	callTree *CallFrame,
	preparedMutations map[string]*PreparedMutation,
	results *[]FuzzingResult,
	resultMutex *sync.Mutex,
	bestSimilarity *float64,
	recordedSelectors map[string]struct{},
	testedCount *int32,
	validCount *int32,
	highSimCount *int32, //  高相似度计数器
	batchTracker *batchBestTracker, //  批次最佳路径记录器
	cancel context.CancelFunc, //  cancel函数用于提前停止
	functionBaseline []ContractJumpDest, // 函数级基准路径（对齐bond入口）
	fallbackBaseline []ContractJumpDest, // 基准过短时的回退基准
	loopBaseline bool, // 循环场景使用子路径基准
) {
	// 预先汇总一次StateOverride，供后续日志使用
	overrideAccounts, overrideSlots, overrideTargetSlots := summarizeOverride(stateOverride, contractAddr)
	targetSelectorHex := strings.ToLower(hexutil.Encode(selector))
	targetFunctionName := ""
	if targetMethod != nil {
		targetFunctionName = targetMethod.Name
	}

	for combo := range combinations {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// 增加测试计数
		currentCount := atomic.AddInt32(testedCount, 1)

		observedCalls := []observedCall{}
		recordObserved := func(selector string, params []ParameterValue, fnName string, mutated bool) {
			if selector == "" {
				return
			}
			if len(params) == 0 {
				return
			}
			if fnName == "" {
				if pm, ok := preparedMutations[selector]; ok && pm != nil && pm.FunctionName != "" {
					fnName = pm.FunctionName
				}
			}
			observedCalls = append(observedCalls, observedCall{
				selector:     selector,
				functionName: fnName,
				params:       params,
				mutated:      mutated,
			})
		}

		// 重构calldata（使用受保护合约调用的selector和变异参数），提前准备供Hook直接替换
		newCallData, err := f.reconstructCallData(selector, combo, targetMethod, workerID)
		if err != nil {
			log.Printf("[Worker %d] Failed to reconstruct calldata: %v", workerID, err)
			continue
		}
		mutatedInputs := map[string][]byte{targetSelectorHex: newCallData}
		targetParamValues := f.extractParameterValues(combo, selector, targetMethod)
		mutationApplied := false

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

		if f.localExecution {
			localSim := f.getSimulatorForWorker(workerID)
			if localSim == nil {
				log.Printf("[Worker %d]  本地执行器不可用，跳过本次组合", workerID)
				continue
			}
			// 构造入口调用参数（优先使用调用树根节点）
			entry := callTree
			if entry == nil {
				if workerID == 0 { // 只用worker 0打印一次，避免日志爆炸
					log.Printf("[Worker %d] ⚠️  callTree为nil，使用targetCall作为入口", workerID)
					log.Printf("[Worker %d]   targetCall: from=%s, to=%s, selector=%s",
						workerID, targetCall.From, targetCall.To, targetCall.Input[:10])
				}
				entry = targetCall
			} else {
				if workerID == 0 { // 只用worker 0打印一次
					log.Printf("[Worker %d] ✅ 使用callTree作为入口", workerID)
					log.Printf("[Worker %d]   entry: from=%s, to=%s, selector=%s",
						workerID, entry.From, entry.To, entry.Input[:10])
				}
			}
			if entry == nil {
				log.Printf("[Worker %d]  无法获取入口调用，跳过本次组合", workerID)
				continue
			}

			entryFrom := common.HexToAddress(entry.From)
			entryTo := common.HexToAddress(entry.To)
			entryData, decodeErr := hexutil.Decode(entry.Input)
			if decodeErr != nil {
				log.Printf("[Worker %d]  解码入口calldata失败: %v", workerID, decodeErr)
				continue
			}
			entryValue := big.NewInt(0)
			if entry.Value != "" && entry.Value != "0x0" {
				if v, err := hexutil.DecodeBig(entry.Value); err == nil {
					entryValue = v
				}
			}

			// 新架构/旧架构统一：按selector查表替换预先准备好的变异calldata
			hookMutator := func(frame *CallFrame, original []byte) ([]byte, bool, error) {
				if !strings.EqualFold(frame.To, contractAddr.Hex()) {
					return original, false, nil
				}
				if len(frame.Input) < 10 {
					return original, false, nil
				}
				selectorHex := strings.ToLower(frame.Input[:10])
				mutated := false
				newInput := original

				if !mutationApplied && selectorHex == targetSelectorHex {
					if mutatedData, ok := mutatedInputs[selectorHex]; ok {
						newInput = mutatedData
						mutated = true
						mutationApplied = true
						recordObserved(selectorHex, targetParamValues, targetFunctionName, true)
						return newInput, true, nil
					}
				}

				params, fnName := f.decodeParamsForSample(contractAddr, newInput, preparedMutations, selectorHex)
				if len(params) > 0 {
					recordObserved(selectorHex, params, fnName, mutated)
				}
				return newInput, mutated, nil
			}
			mutators := map[common.Address]local.CallMutatorV2{
				contractAddr: simulator.AdaptCallMutator(hookMutator),
			}

			hookRes, simErr := localSim.SimulateWithCallDataV2(
				ctx,
				entryFrom,
				entryTo,
				entryData,
				entryValue,
				simBlockNumber,
				stateOverride,
				mutators,
			)

			if simErr != nil {
				log.Printf("[Worker %d]  本地Hook执行失败: %v", workerID, simErr)
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
				if !strings.EqualFold(frame.To, contractAddr.Hex()) {
					return original, false, nil
				}
				if len(frame.Input) < 10 {
					return original, false, nil
				}
				selectorHex := strings.ToLower(frame.Input[:10])
				mutated := false
				newInput := original

				if !mutationApplied && selectorHex == targetSelectorHex {
					if mutatedData, ok := mutatedInputs[selectorHex]; ok {
						newInput = mutatedData
						mutated = true
						mutationApplied = true
						recordObserved(selectorHex, targetParamValues, targetFunctionName, true)
						return newInput, true, nil
					}
				}

				params, fnName := f.decodeParamsForSample(contractAddr, newInput, preparedMutations, selectorHex)
				if len(params) > 0 {
					recordObserved(selectorHex, params, fnName, mutated)
				}
				return newInput, mutated, nil
			}

			hookRes, simErr := f.simulator.ExecuteWithHooks(
				ctx,
				callTree,
				simBlockNumber,
				stateOverride,
				map[string]simulator.CallMutator{strings.ToLower(contractAddr.Hex()): hookMutator},
			)
			if simErr != nil {
				if isFatalRPCError(simErr) {
					log.Printf("[Worker %d]  RPC不可用 (%v)，触发全局取消", workerID, simErr)
					cancel()
					return
				}
				log.Printf("[Worker %d]   Hook执行失败: %v", workerID, simErr)
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

		// 记录非零 amount 的执行情况，便于确认是否被revert
		nonZeroAmount := ""
		if targetMethod != nil && strings.EqualFold(targetMethod.Name, "debond") && len(combo) > 0 {
			if amtStr, ok := extractNonZeroNumeric(combo[0]); ok {
				nonZeroAmount = amtStr
				revertMsg := ""
				if !simResult.Success {
					revertMsg = decodeRevertMessage(simResult.ReturnData)
					if revertMsg == "" && simResult.Error != nil {
						revertMsg = simResult.Error.Error()
					}
				}
				log.Printf("[Worker %d]  debond非零amount=%s, success=%v, gas=%d, stateChanges=%d, revert=%s",
					workerID, nonZeroAmount, simResult.Success, simResult.GasUsed, len(simResult.StateChanges), revertMsg)
			}
		}

		revertMsg := ""
		if !simResult.Success {
			revertMsg = decodeRevertMessage(simResult.ReturnData)
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

			log.Printf("[Worker %d]   模拟交易revert，仍计算路径相似度 (gas=%d, msg=%s, traceErr=%s, lastPath=%s, return=%s, selector=%s, len=%d, from=%s, to=%s, value=%s)",
				workerID, simResult.GasUsed, revertMsg, traceErr, lastPath, formatReturnDataForLog(simResult.ReturnData), selectorHex, len(newCallData), from.Hex(), to.Hex(), value.String())
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

		baselineStart := originalPath.ProtectedStartIndex
		if baselineStart < 0 || baselineStart >= len(origContractJumpDests) {
			if idx := findProtectedStartIndex(origContractJumpDests, pathContractAddr); idx >= 0 {
				baselineStart = idx
				log.Printf("[Worker %d]   修正 ProtectedStartIndex 为 %d（基于路径合约 %s）", workerID, baselineStart, pathContractAddr.Hex())
			} else {
				baselineStart = 0
				log.Printf("[Worker %d]   未能定位受保护合约，使用起始索引 0", workerID)
			}
		}

		// 入口对齐 + 固定窗口 + overlap：基准/候选路径从受保护合约首次命中开始截取
		baseline := extractProtectedContractPath(origContractJumpDests, pathContractAddr, baselineStart, "基准入口对齐")
		candidatePath := extractProtectedContractPath(simResult.ContractJumpDests, pathContractAddr, 0, "候选入口对齐")
		if len(fallbackBaseline) > 0 {
			baseline = fallbackBaseline
			if currentCount <= 5 || currentCount%500 == 0 {
				log.Printf("[Worker %d]  基准路径过短，切换为函数级基准 (len=%d)", workerID, len(baseline))
			}
		}
		if len(baseline) == 0 || len(candidatePath) == 0 {
			log.Printf("[Worker %d]  基准或候选路径为空，跳过比较 (baseline=%d, candidate=%d)", workerID, len(baseline), len(candidatePath))
			f.recordAttempt(0, 0)
			continue
		}

		// 入口对齐：用候选入口PC在基准中定位对齐点，找不到则从基准起点开始
		baselineAlignIndex := 0
		if len(candidatePath) > 0 {
			entryPC := candidatePath[0].PC
			if idx := findFunctionEntryIndex(baseline, pathContractAddr, entryPC); idx >= 0 {
				baselineAlignIndex = idx
			}
		}

		alignedBaseline := baseline[baselineAlignIndex:]
		windowLen := len(alignedBaseline)
		if len(candidatePath) < windowLen {
			windowLen = len(candidatePath)
		}
		if windowLen <= 0 {
			log.Printf("[Worker %d]  固定窗口为空，跳过比较 (candidateLen=%d, baselineLen=%d, alignIndex=%d)", workerID, len(candidatePath), len(baseline), baselineAlignIndex)
			f.recordAttempt(0, 0)
			continue
		}

		compareBaseline := alignedBaseline[:windowLen]
		compareCandidate := candidatePath[:windowLen]
		overlapSim := f.comparator.OverlapContractJumpDests(compareBaseline, compareCandidate)
		similarity := overlapSim

		// 相似度校正：当基准明显短于候选且Overlap饱和时，使用长度敏感的Dice相似度避免恒为1
		adjustedSim := overlapSim
		if overlapSim >= 0.999 && len(alignedBaseline) > 0 && len(candidatePath) > 0 {
			baselineLen := len(alignedBaseline)
			candidateLen := len(candidatePath)
			if candidateLen > baselineLen && float64(candidateLen) >= float64(baselineLen)*1.2 {
				adjustedSim = f.comparator.CompareContractJumpDests(alignedBaseline, candidatePath, 0)
				similarity = adjustedSim
				if currentCount <= 5 || currentCount%500 == 0 {
					log.Printf("[Worker %d]  相似度校正: overlap=%.4f -> adjusted=%.4f (baseline=%d, candidate=%d)",
						workerID, overlapSim, adjustedSim, baselineLen, candidateLen)
				}
			}
		}

		// 【新增诊断】检查JUMPDEST序列是否为空
		if len(compareBaseline) == 0 && len(compareCandidate) == 0 && workerID == 0 && currentCount == 1 {
			log.Printf("⚠ [Worker %d] 警告：基准路径和候选路径的JUMPDEST序列都为空", workerID)
			log.Printf("   相似度计算结果: %.4f (可能不准确)", similarity)
			log.Printf("   原始基准长度: %d, 候选路径长度: %d", len(baseline), len(candidatePath))
			log.Printf("   simResult.JumpDests长度: %d", len(simResult.JumpDests))
			log.Printf("   simResult.ContractJumpDests长度: %d", len(simResult.ContractJumpDests))
			log.Printf("   本地执行模式: %v", f.localExecution)
			log.Printf("   可能原因：")
			log.Printf("   1. 本地EVM执行模式下Tracer未正确配置")
			log.Printf("   2. Fork模式下trace收集失败")
			log.Printf("   3. 模拟执行未返回trace数据")
		}

		// 统计集合规模与交集，便于确认相似度来源
		baseSet := make(map[string]struct{}, len(compareBaseline))
		for _, jd := range compareBaseline {
			key := fmt.Sprintf("%s:%d", strings.ToLower(jd.Contract), jd.PC)
			baseSet[key] = struct{}{}
		}
		candSet := make(map[string]struct{}, len(compareCandidate))
		for _, jd := range compareCandidate {
			key := fmt.Sprintf("%s:%d", strings.ToLower(jd.Contract), jd.PC)
			candSet[key] = struct{}{}
		}
		intersection := 0
		for k := range baseSet {
			if _, ok := candSet[k]; ok {
				intersection++
			}
		}
		if currentCount <= 5 || currentCount%500 == 0 {
			log.Printf("[Worker %d] 路径集合统计: 基准唯一=%d, 候选唯一=%d, 交集=%d, 窗口len=%d, baselineAlign=%d", workerID, len(baseSet), len(candSet), intersection, windowLen, baselineAlignIndex)
		}

		// 不再对基线/候选路径做循环体裁剪，保持完整路径对齐
		loopBaseline = false

		//  关键修复：循环场景下，按函数入口PC对齐基准路径
		// 原因1：原始攻击可能先调用balanceOf/decimals等，导致基准路径从非目标函数开始
		// 原因2：原始攻击包含20次循环，但fuzz只模拟单次调用
		// 原因3：原始攻击流程为 debond→flash→bond×20，但fuzz只执行bond
		// 解决方案：从fuzz路径的第一个PC（函数入口）在【完整原始路径】中找到对应位置，而非从baselineStart截取的子路径
		if loopBaseline {
			loopSeg := extractProtectedContractPath(origContractJumpDests, pathContractAddr, baselineStart, "基准循环段")

			// 如果基准不含当前入口PC，使用函数级基准（通常对应bond路径），避免落在debond起点
			if len(functionBaseline) > 0 {
				fuzzEntryPC := uint64(0)
				if len(candidatePath) > 0 {
					fuzzEntryPC = candidatePath[0].PC
				}
				if len(loopSeg) == 0 || (fuzzEntryPC != 0 && !containsPC(loopSeg, fuzzEntryPC)) {
					loopSeg = functionBaseline
					baselineStart = 0
					if currentCount <= 2 {
						log.Printf("[Worker %d]  使用函数级基准路径对齐 (入口PC=%d, len=%d)", workerID, fuzzEntryPC, len(loopSeg))
					}
				}
			}

			if len(loopSeg) > 0 {
				//  函数入口对齐：获取fuzz路径的第一个PC作为函数入口参考点
				var alignedLoopSeg []ContractJumpDest
				if len(candidatePath) > 0 {
					fuzzEntryPC := candidatePath[0].PC
					//  核心修复：在【完整原始路径】中搜索fuzz入口PC，而非仅在loopSeg中搜索
					// 原因：loopSeg从startIndex（debond）开始提取，不包含bond的路径
					// 而原始攻击路径包含：debond_path + 20*(flash_path + bond_path)
					// 所以bond的PC=149只存在于完整路径中，不在debond开始的loopSeg中
					alignIndex := -1
					for i, jd := range origContractJumpDests {
						if strings.EqualFold(jd.Contract, strings.ToLower(pathContractAddr.Hex())) && jd.PC == fuzzEntryPC {
							alignIndex = i
							break
						}
					}
					if alignIndex >= 0 && alignIndex < len(origContractJumpDests) {
						//  修复：从origContractJumpDests的对齐位置开始提取受保护合约的路径
						// 而不是从loopSeg中提取（loopSeg可能不包含目标函数的路径）
						alignedLoopSeg = extractProtectedContractPath(origContractJumpDests, pathContractAddr, alignIndex, "对齐基准")
						if currentCount <= 2 {
							log.Printf("[Worker %d]  函数入口对齐成功: fuzz入口PC=%d, 在完整路径中的索引=%d, 提取后基准长度=%d",
								workerID, fuzzEntryPC, alignIndex, len(alignedLoopSeg))
						}
					} else {
						//  对齐失败，使用滑动窗口法找最佳对齐位置
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
							sim := f.comparator.OverlapContractJumpDests(windowSeg, candidatePath)
							if sim > bestAlignSim {
								bestAlignSim = sim
								bestAlignIdx = offset
							}
						}

						// 使用最佳对齐位置
						alignedLoopSeg = loopSeg[bestAlignIdx:]
						if currentCount <= 2 {
							log.Printf("[Worker %d]  滑动窗口对齐: fuzz入口PC=%d在基准中无精确匹配，使用滑动窗口找到最佳对齐位置=%d (相似度=%.4f)",
								workerID, fuzzEntryPC, bestAlignIdx, bestAlignSim)
							// 打印对齐后的前几个PC
							var alignedPCs []uint64
							for i := 0; i < len(alignedLoopSeg) && i < 5; i++ {
								alignedPCs = append(alignedPCs, alignedLoopSeg[i].PC)
							}
							log.Printf("[Worker %d]  对齐后基准前5个PC=%v, fuzz前5个PC=[%d,%d,...]",
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
					log.Printf("[Worker %d]  使用对齐后的循环体子路径作为基准 (原始len=%d -> 子路径len=%d -> 对齐后len=%d -> 截取len=%d, fuzz路径len=%d)",
						workerID, len(origContractJumpDests), len(loopSeg), len(alignedLoopSeg), targetLen, len(candidatePath))
				}
			} else {
				log.Printf("[Worker %d]   循环体子路径为空，回退使用完整路径 (len=%d)",
					workerID, len(origContractJumpDests))
			}
		}

		// 记录全量尝试（包含低相似度样本）
		f.recordAttempt(similarity, overlapSim)

		// 记录批次最佳路径（每100个组合汇总一次）
		if batchTracker != nil {
			batchTracker.Update(currentCount, similarity, simResult.ContractJumpDests, workerID)
			if currentCount%100 == 0 {
				windowID := currentCount/100 - 1
				if bestSim, bestPath, bestWorker, ok := batchTracker.Snapshot(windowID); ok && len(bestPath) > 0 {
					batchStart := int(windowID*100 + 1)
					batchEnd := int((windowID + 1) * 100)
					log.Printf("[Fuzzer]  批次%d-%d最佳相似度=%.4f (来自Worker %d), JUMPDEST路径: %s",
						batchStart, batchEnd, bestSim, bestWorker, formatPathSnippet(bestPath, 0))
				}
			}
		}

		// 仅在高相似度时打印路径片段，避免日志爆炸；按测试计数采样
		//  修复：打印实际比较的baseline和candidatePath，而非原始的origContractJumpDests
		highSim := f.threshold > 0 && similarity >= f.threshold
		if highSim && (currentCount <= 5 || currentCount%500 == 0) {
			log.Printf("[Worker %d] 路径片段: 基准%s ; Fuzz%s (sim=%.4f)", workerID,
				formatPathSnippet(compareBaseline, 0),
				formatPathSnippet(compareCandidate, 0),
				similarity,
			)
		}

		//  需求1: 记录每个组合的相似度（每100个组合记录一次，避免日志刷屏）
		if currentCount%100 == 0 {
			log.Printf("[Worker %d] 进度: 已测试%d个组合, 当前相似度=%.4f (阈值=%.4f)",
				workerID, currentCount, similarity, f.threshold)
		}

		// 不再使用阈值过滤，记录任意相似度的结果
		logDetails := highSim || currentCount <= 5 || currentCount%500 == 0
		if logDetails {
			log.Printf("[Worker %d]  记录参数: sim=%.4f, selector=%s, params=%s, 窗口len=%d, baselineAlign=%d",
				workerID,
				similarity,
				formatSelectorForLog(newCallData),
				formatParamValuesForLog(combo),
				windowLen,
				baselineAlignIndex,
			)
		}

		// 记录模拟执行概况，便于诊断“高相似度但无违规”的原因
		stateChangeCount := len(simResult.StateChanges)
		if stateChangeCount == 0 {
			if logDetails {
				log.Printf("[Worker %d]  无状态变更详情: selector=%s, params=%s, fuzzPathLen=%d, baselineLen=%d, jumpDests=%d, override(accounts=%d,slots=%d,targetSlots=%d)",
					workerID,
					formatSelectorForLog(newCallData),
					formatParamValuesForLog(combo),
					len(compareCandidate),
					len(compareBaseline),
					len(simResult.ContractJumpDests),
					overrideAccounts, overrideSlots, overrideTargetSlots)
			}
			if logDetails {
				log.Printf("[Worker %d]  无状态变更 sim=%.4f (success=%v, gas=%d)，仍参与最高相似度筛选", workerID, similarity, simResult.Success, simResult.GasUsed)
			}
		} else {
			// 打印前3个有变化的合约地址，避免日志爆炸
			changedAddrs := make([]string, 0, 3)
			for addr := range simResult.StateChanges {
				changedAddrs = append(changedAddrs, addr)
				if len(changedAddrs) >= 3 {
					break
				}
			}
			if logDetails {
				log.Printf("[Worker %d]  状态变更 sim=%.4f, 变更=%d 个 (success=%v, gas=%d, 前3: %v)",
					workerID, similarity, stateChangeCount, simResult.Success, simResult.GasUsed, changedAddrs)
			}
		}

		// 如果启用了不变量检查,先进行不变量验证（可选跳过）
		var violations []interface{}
		if f.enableInvariantCheck && f.invariantEvaluator != nil && !(f.skipInvariantForHighSim && highSim) {
			// 转换状态为ChainState格式
			chainState := ConvertToChainStateFromSimResult(
				simResult,
				simBlockNumber,
				common.Hash{}, // worker中使用零哈希,因为是模拟交易
			)

			// 执行不变量评估
			violations = f.invariantEvaluator.EvaluateTransaction(
				[]common.Address{contractAddr},
				chainState,
			)

			// 若无不变量违规，仍继续记录结果（不再以违规为筛选条件）
			if len(violations) == 0 && logDetails {
				log.Printf("[Worker %d]  未触发不变量违规，继续记录 (sim=%.4f)", workerID, similarity)
			}
		} else if f.skipInvariantForHighSim && highSim {
			log.Printf("[Worker %d] 跳过 高相似度样本跳过不变量评估 (sim=%.4f >= %.4f)", workerID, similarity, f.threshold)
		}

		// 通过路径相似度检查(以及可选的不变量检查),记录结果
		atomic.AddInt32(validCount, 1)

		// 记录达标时间点与最高相似度时间
		elapsed := time.Since(f.stats.StartTime)
		if atomic.LoadInt64(&f.firstHitAt) == 0 {
			atomic.CompareAndSwapInt64(&f.firstHitAt, 0, elapsed.Nanoseconds())
		}
		for {
			oldBits := atomic.LoadUint64(&f.maxSimVal)
			old := math.Float64frombits(oldBits)
			if similarity <= old {
				break
			}
			if atomic.CompareAndSwapUint64(&f.maxSimVal, oldBits, math.Float64bits(similarity)) {
				atomic.StoreInt64(&f.maxSimAt, elapsed.Nanoseconds())
				break
			}
		}

		// 创建参数值列表
		paramValues := f.extractParameterValues(combo, selector, targetMethod)
		ruleParamValues := paramValues
		if f.constraintCollector != nil {
			if rawParams := f.extractRuleParameterValues(newCallData, targetMethod); len(rawParams) > 0 {
				ruleParamValues = rawParams
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

		// 线程安全地添加结果，后续按相似度阈值筛选用于规则生成
		resultMutex.Lock()
		*results = append(*results, result)

		best := *bestSimilarity
		diff := similarity - best
		isNewMax := best < 0 || diff > similarityEpsilon
		isBest := isNewMax || (diff >= -similarityEpsilon && diff <= similarityEpsilon)
		if isNewMax {
			*bestSimilarity = similarity
			if f.sampleRecorder != nil {
				f.sampleRecorder.Reset()
			}
			if f.constraintCollector != nil && len(recordedSelectors) > 0 {
				for sel := range recordedSelectors {
					selBytes, err := hexutil.Decode(sel)
					if err != nil || len(selBytes) < 4 {
						continue
					}
					f.constraintCollector.ResetSamples(contractAddr, selBytes[:4])
				}
			}
			for sel := range recordedSelectors {
				delete(recordedSelectors, sel)
			}
		}

		if isBest {
			f.recordSamples(contractAddr, similarity, observedCalls)
			if targetSelectorHex != "" {
				recordedSelectors[targetSelectorHex] = struct{}{}
			}
			if f.constraintCollector != nil {
				if rule := f.constraintCollector.RecordSample(contractAddr, selector, ruleParamValues, simResult.StateChanges, similarity); rule != nil {
					log.Printf("[Worker %d]  已生成约束规则: %s selector=%s 样本=%d", workerID, contractAddr.Hex(), rule.FunctionSelector, rule.SampleCount)
				}
			}
			// 同步记录连锁调用样本，便于为其他受保护函数生成表达式规则
			if len(observedCalls) > 0 {
				for _, oc := range observedCalls {
					if oc.selector == "" || len(oc.params) == 0 {
						continue
					}
					selKey := strings.ToLower(oc.selector)
					if selKey != "" {
						recordedSelectors[selKey] = struct{}{}
					}
					if f.constraintCollector == nil {
						continue
					}
					if strings.EqualFold(oc.selector, targetSelectorHex) {
						continue
					}
					selBytes, err := hexutil.Decode(oc.selector)
					if err != nil || len(selBytes) < 4 {
						continue
					}
					if rule := f.constraintCollector.RecordSample(contractAddr, selBytes[:4], oc.params, simResult.StateChanges, similarity); rule != nil {
						log.Printf("[Worker %d]  已生成约束规则: %s selector=%s 样本=%d", workerID, contractAddr.Hex(), rule.FunctionSelector, rule.SampleCount)
					}
				}
			}
		}
		resultMutex.Unlock()

		//  检查是否达到目标相似度
		targetSimEnabled := f.targetSimilarity > 0 && f.maxHighSimResults > 0
		if targetSimEnabled && similarity >= f.targetSimilarity {
			currentHighSim := atomic.AddInt32(highSimCount, 1)
			log.Printf("[Worker %d]  Found high-similarity result #%d (sim=%.4f >= %.4f)",
				workerID, currentHighSim, similarity, f.targetSimilarity)

			// 达到目标数量，触发全局停止
			if int(currentHighSim) >= f.maxHighSimResults {
				log.Printf("[Fuzzer]  Found %d high-similarity results (>= %.4f), stopping all workers",
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

// reconstructCallData 使用ABI优先编码动态参数，失败时回退到启发式编码
func (f *CallDataFuzzer) reconstructCallData(selector []byte, params []interface{}, method *abi.Method, workerID int) ([]byte, error) {
	if method != nil {
		normalized := normalizeParamsForABI(params, method)
		if packed, err := method.Inputs.Pack(normalized...); err == nil {
			return append(selector, packed...), nil
		} else {
			log.Printf("[Worker %d]   ABI编码失败，改用启发式编码: %v", workerID, err)
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
	elementType, fixedLen, isArray := parseArrayType(typeStr)

	// 如果目标不是数组类型，且传入了切片/数组，优先取首元素以避免ABI因类型不匹配报错
	if !isArray {
		switch v := val.(type) {
		case []interface{}:
			if len(v) > 0 {
				val = v[0]
			}
		case []common.Address:
			if len(v) > 0 {
				val = v[0]
			}
		case []string:
			if len(v) > 0 {
				val = v[0]
			}
		case [][]byte:
			if len(v) > 0 {
				val = v[0]
			}
		}
	}

	if !isArray {
		switch {
		case typeStr == "address":
			return normalizeAddress(val)
		case strings.HasPrefix(typeStr, "uint"):
			if typeStr == "uint8" {
				if v, ok := normalizeUint8(val); ok {
					return v
				}
			}
			if bi := normalizeBigInt(val); bi != nil {
				return bi
			}
		case strings.HasPrefix(typeStr, "bytes"):
			size := parseFixedBytesSize(typeStr)
			if size > 0 {
				if fixed := normalizeFixedBytesValue(val, size); fixed != nil {
					return fixed
				}
				break
			}
			if b := normalizeBytes(val); b != nil {
				return b
			}
		}
		return val
	}

	baseElementType := stripArrayDimensions(elementType)

	switch {
	case baseElementType == "address":
		if addrs := normalizeAddressSlice(val); addrs != nil {
			return fitAddressSliceLength(addrs, fixedLen)
		}
		// 标量地址包装为单元素数组
		if addr := normalizeAddress(val); (addr != common.Address{}) {
			return fitAddressSliceLength([]common.Address{addr}, fixedLen)
		}
	case baseElementType == "uint8":
		if arr := normalizeUint8Slice(val); arr != nil {
			return fitUint8SliceLength(arr, fixedLen)
		}
		// 标量种子包装为单元素数组
		if n, ok := normalizeUint8(val); ok {
			return fitUint8SliceLength([]uint8{n}, fixedLen)
		}
	case strings.HasPrefix(baseElementType, "uint"):
		if arr := normalizeUintSlice(val); arr != nil {
			return fitBigIntSliceLength(arr, fixedLen)
		}
		// 标量包装为单元素数组
		if bi := normalizeBigInt(val); bi != nil {
			return fitBigIntSliceLength([]*big.Int{bi}, fixedLen)
		}
	case strings.HasPrefix(baseElementType, "bytes"):
		size := parseFixedBytesSize(baseElementType)
		if size > 0 {
			if arr := normalizeFixedBytesArray(val, size, fixedLen); arr != nil {
				return arr
			}
			if fixed := normalizeFixedBytesValue(val, size); fixed != nil {
				return normalizeFixedBytesArray(fixed, size, fixedLen)
			}
			break
		}
		if arr := normalizeBytesSlice(val); arr != nil {
			return fitBytesSliceLength(arr, fixedLen)
		}
		if b := normalizeBytes(val); b != nil {
			return fitBytesSliceLength([][]byte{b}, fixedLen)
		}
	}

	return val
}

func normalizeAddress(val interface{}) common.Address {
	switch v := val.(type) {
	case common.Address:
		return v
	case []interface{}:
		if len(v) > 0 {
			return normalizeAddress(v[0])
		}
		return common.Address{}
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
		//  新增：大整数包装为单元素数组
		if v.Cmp(big.NewInt(255)) <= 0 && v.Sign() >= 0 {
			return []uint8{uint8(v.Uint64())}
		}
		log.Printf("[Normalize]   big.Int %s out of uint8 range, using fallback", v.String())
		return nil
	case string:
		//  新增：字符串处理（可能是hex或数字）
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

func fitAddressSliceLength(addrs []common.Address, length int) []common.Address {
	if length <= 0 {
		return addrs
	}
	if len(addrs) >= length {
		return addrs[:length]
	}
	out := make([]common.Address, length)
	copy(out, addrs)
	for i := len(addrs); i < length; i++ {
		out[i] = common.Address{}
	}
	return out
}

func fitUint8SliceLength(arr []uint8, length int) []uint8 {
	if length <= 0 {
		return arr
	}
	if len(arr) >= length {
		return arr[:length]
	}
	out := make([]uint8, length)
	copy(out, arr)
	return out
}

func fitBigIntSliceLength(arr []*big.Int, length int) []*big.Int {
	if length <= 0 {
		return arr
	}
	if len(arr) >= length {
		return arr[:length]
	}
	out := make([]*big.Int, length)
	copy(out, arr)
	for i := len(arr); i < length; i++ {
		out[i] = big.NewInt(0)
	}
	return out
}

func normalizeBigInt(val interface{}) *big.Int {
	switch v := val.(type) {
	case *big.Int:
		return v
	case []interface{}:
		if len(v) > 0 {
			return normalizeBigInt(v[0])
		}
		return nil
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
	case common.Hash:
		return v.Bytes()
	case []interface{}:
		if len(v) > 0 {
			return normalizeBytes(v[0])
		}
		return nil
	case [32]byte:
		return v[:]
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

func normalizeBytesSlice(val interface{}) [][]byte {
	switch v := val.(type) {
	case [][]byte:
		return v
	case []string:
		out := make([][]byte, 0, len(v))
		for _, s := range v {
			if b := normalizeBytes(s); b != nil {
				out = append(out, b)
			}
		}
		return out
	case []common.Hash:
		out := make([][]byte, 0, len(v))
		for _, h := range v {
			out = append(out, h.Bytes())
		}
		return out
	case []interface{}:
		out := make([][]byte, 0, len(v))
		for _, item := range v {
			if b := normalizeBytes(item); b != nil {
				out = append(out, b)
			}
		}
		return out
	}
	return nil
}

func fitBytesSliceLength(arr [][]byte, length int) [][]byte {
	if length <= 0 {
		return arr
	}
	if len(arr) >= length {
		return arr[:length]
	}
	out := make([][]byte, length)
	copy(out, arr)
	for i := len(arr); i < length; i++ {
		out[i] = []byte{}
	}
	return out
}

func parseFixedBytesSize(typeStr string) int {
	if !strings.HasPrefix(typeStr, "bytes") {
		return 0
	}
	sizeStr := strings.TrimPrefix(typeStr, "bytes")
	if sizeStr == "" {
		return 0
	}
	if size, err := strconv.Atoi(sizeStr); err == nil {
		return size
	}
	return 0
}

func normalizeFixedBytesValue(val interface{}, size int) interface{} {
	if size <= 0 {
		return nil
	}
	data := normalizeBytes(val)
	if data == nil {
		return nil
	}
	fixed := padFixedBytes(data, size)
	return buildFixedBytesValue(fixed, size)
}

func normalizeFixedBytesArray(val interface{}, size int, fixedLen int) interface{} {
	if size <= 0 {
		return nil
	}
	elems := normalizeFixedBytesElements(val, size)
	if fixedLen > 0 {
		if len(elems) >= fixedLen {
			elems = elems[:fixedLen]
		} else {
			for len(elems) < fixedLen {
				elems = append(elems, make([]byte, size))
			}
		}
	} else if elems == nil {
		elems = [][]byte{}
	}
	return buildFixedBytesSlice(elems, size)
}

func normalizeFixedBytesElements(val interface{}, size int) [][]byte {
	switch v := val.(type) {
	case nil:
		return nil
	case []common.Hash:
		if size != 32 {
			return nil
		}
		out := make([][]byte, 0, len(v))
		for _, h := range v {
			out = append(out, padFixedBytes(h.Bytes(), size))
		}
		return out
	case []string:
		out := make([][]byte, 0, len(v))
		for _, s := range v {
			if b := normalizeBytes(s); b != nil {
				out = append(out, padFixedBytes(b, size))
			}
		}
		return out
	case [][]byte:
		out := make([][]byte, 0, len(v))
		for _, b := range v {
			out = append(out, padFixedBytes(b, size))
		}
		return out
	case []interface{}:
		out := make([][]byte, 0, len(v))
		for _, item := range v {
			if b := normalizeBytes(item); b != nil {
				out = append(out, padFixedBytes(b, size))
			}
		}
		if len(out) > 0 {
			return out
		}
	}

	rv := reflect.ValueOf(val)
	if rv.IsValid() && (rv.Kind() == reflect.Slice || rv.Kind() == reflect.Array) {
		elemType := rv.Type().Elem()
		if elemType.Kind() == reflect.Array && elemType.Len() == size && elemType.Elem().Kind() == reflect.Uint8 {
			out := make([][]byte, 0, rv.Len())
			for i := 0; i < rv.Len(); i++ {
				elem := rv.Index(i)
				bytes := make([]byte, size)
				for j := 0; j < size; j++ {
					bytes[j] = byte(elem.Index(j).Uint())
				}
				out = append(out, bytes)
			}
			return out
		}
	}

	if single := normalizeBytes(val); single != nil {
		return [][]byte{padFixedBytes(single, size)}
	}

	return nil
}

func padFixedBytes(data []byte, size int) []byte {
	if size <= 0 {
		return data
	}
	if len(data) == size {
		return append([]byte(nil), data...)
	}
	out := make([]byte, size)
	if len(data) >= size {
		copy(out, data[:size])
		return out
	}
	copy(out, data)
	return out
}

func buildFixedBytesValue(data []byte, size int) interface{} {
	elemType := reflect.ArrayOf(size, reflect.TypeOf(byte(0)))
	arr := reflect.New(elemType).Elem()
	for i := 0; i < size && i < len(data); i++ {
		arr.Index(i).SetUint(uint64(data[i]))
	}
	return arr.Interface()
}

func buildFixedBytesSlice(elems [][]byte, size int) interface{} {
	elemType := reflect.ArrayOf(size, reflect.TypeOf(byte(0)))
	sliceType := reflect.SliceOf(elemType)
	slice := reflect.MakeSlice(sliceType, len(elems), len(elems))
	for i, b := range elems {
		arr := reflect.New(elemType).Elem()
		for j := 0; j < size && j < len(b); j++ {
			arr.Index(j).SetUint(uint64(b[j]))
		}
		slice.Index(i).Set(arr)
	}
	return slice.Interface()
}

// buildSmartUintSeeds 根据原始数值生成小幅震荡的种子组合（锁定拓扑，微扰数值）
// 例如 orig=100 -> {100, 99, 101, 50, 200}
func buildSmartUintSeeds(orig *big.Int) []interface{} {
	if orig == nil || orig.Sign() < 0 {
		return nil
	}

	// 特殊处理 orig=0
	if orig.Sign() == 0 {
		return []interface{}{big.NewInt(0), big.NewInt(1)}
	}

	type ratio struct {
		num int64
		den int64
	}
	ratios := []ratio{
		{1, 1},     // 原值
		{99, 100},  // -1%
		{101, 100}, // +1%
		{1, 2},     // 0.5x
		{2, 1},     // 2x
	}

	seen := make(map[string]bool)
	seeds := make([]interface{}, 0, len(ratios))
	for _, r := range ratios {
		if r.den == 0 {
			continue
		}
		n := new(big.Int).Mul(orig, big.NewInt(r.num))
		n.Div(n, big.NewInt(r.den))
		if n.Sign() < 0 {
			continue
		}
		key := n.String()
		if !seen[key] {
			seen[key] = true
			seeds = append(seeds, n)
		}
	}
	return seeds
}

// simulateExecution 执行单个模拟
func (f *CallDataFuzzer) simulateExecution(ctx context.Context, req *SimulationRequest, workerID int) (*SimulationResult, error) {
	// 创建带超时的context
	simCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	var result *simulator.ReplayResult
	var err error

	if f.localExecution {
		// 本地模式：使用双模式模拟器，避免与RPC竞争
		sim := f.getSimulatorForWorker(workerID)
		if sim == nil {
			return nil, fmt.Errorf("local simulator unavailable")
		}
		result, err = sim.SimulateWithCallDataV2(
			simCtx,
			req.From,
			req.To,
			req.CallData,
			req.Value,
			req.BlockNumber,
			req.StateOverride,
			nil, // 不需要显式mutators，交给拦截器判断
		)
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
			log.Printf("[Worker %d]   无法解码模拟返回数据: %v (raw=%s)", workerID, decodeErr, result.ReturnData)
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

// convertParsedParamsToValues 将解析后的参数转为通用记录格式
func (f *CallDataFuzzer) convertParsedParamsToValues(parsed *ParsedCallData, method *abi.Method) []ParameterValue {
	if parsed == nil {
		return nil
	}
	values := make([]ParameterValue, len(parsed.Parameters))
	for i, p := range parsed.Parameters {
		pType := p.Type
		name := p.Name
		if method != nil && i < len(method.Inputs) {
			pType = method.Inputs[i].Type.String()
			if method.Inputs[i].Name != "" {
				name = method.Inputs[i].Name
			}
		}
		values[i] = ParameterValue{
			Index:   i,
			Type:    pType,
			Name:    name,
			Value:   p.Value,
			IsRange: false,
		}
	}
	return values
}

// decodeParamsForSample 解析实际执行的calldata为样本参数，解析失败时回退已准备的参数
func (f *CallDataFuzzer) decodeParamsForSample(contractAddr common.Address, input []byte, prepared map[string]*PreparedMutation, selector string) ([]ParameterValue, string) {
	fnName := ""
	if parsed, method, err := f.parseCallDataWithABI(contractAddr, input); err == nil && parsed != nil {
		if method != nil {
			fnName = method.Name
		}
		return f.convertParsedParamsToValues(parsed, method), fnName
	}

	if pm, ok := prepared[selector]; ok && pm != nil {
		if pm.FunctionName != "" {
			fnName = pm.FunctionName
		}
		if len(pm.OriginalParams) > 0 {
			return pm.OriginalParams, fnName
		}
		if len(pm.MutatedParams) > 0 {
			return pm.MutatedParams, fnName
		}
	}

	return nil, fnName
}

// extractParameterValues 提取参数值
func (f *CallDataFuzzer) extractParameterValues(combo []interface{}, selector []byte, method *abi.Method) []ParameterValue {
	values := make([]ParameterValue, len(combo))

	for i, val := range combo {
		paramType := f.detectType(val)
		paramName := ""
		normalizedVal := val

		// 优先使用ABI定义的类型/名称，避免数组被识别为unknown
		if method != nil && i < len(method.Inputs) {
			paramType = method.Inputs[i].Type.String()
			paramName = method.Inputs[i].Name
			normalizedVal = normalizeSingleParam(val, paramType)
		}

		values[i] = ParameterValue{
			Index:   i,
			Type:    paramType,
			Name:    paramName,
			Value:   normalizedVal,
			IsRange: false,
		}
	}

	return values
}

// extractRuleParameterValues 将calldata解析为32字节对齐的参数列表，并结合ABI提示修正类型
func (f *CallDataFuzzer) extractRuleParameterValues(callData []byte, method *abi.Method) []ParameterValue {
	if len(callData) < 4 || f.parser == nil {
		return nil
	}

	paramData := callData[4:]
	rawParams := f.parser.parseRawParameters(paramData)
	if len(rawParams) == 0 {
		return nil
	}

	values := make([]ParameterValue, len(rawParams))
	for i, p := range rawParams {
		values[i] = ParameterValue{
			Index:   p.Index,
			Type:    p.Type,
			Name:    p.Name,
			Value:   p.Value,
			IsRange: false,
		}
	}

	if method != nil {
		applyRawParamTypeHints(values, paramData, method, f.parser)
	}

	return values
}

func applyRawParamTypeHints(values []ParameterValue, paramData []byte, method *abi.Method, parser *ABIParser) {
	if method == nil || parser == nil || len(values) == 0 {
		return
	}

	for i := range values {
		values[i].Type = "skip"
	}

	wordCount := len(values)
	headIndex := 0

	for _, input := range method.Inputs {
		if headIndex >= wordCount {
			break
		}

		t := input.Type
		if isDynamicABIType(t) {
			markSkipParam(values, headIndex, "offset")
			if startIdx, ok := offsetToWordIndex(paramData, headIndex, wordCount); ok {
				switch t.T {
				case abi.StringTy, abi.BytesTy:
					annotateDynamicBytes(values, paramData, startIdx, t.String())
				case abi.SliceTy:
					if t.Elem != nil && !isDynamicABIType(*t.Elem) {
						annotateDynamicArray(values, paramData, startIdx, *t.Elem, parser)
					}
				case abi.ArrayTy:
					if t.Elem != nil && !isDynamicABIType(*t.Elem) {
						annotateDynamicArray(values, paramData, startIdx, *t.Elem, parser)
					}
				}
			}
			headIndex += abiTypeWordSize(t)
			continue
		}

		annotateStaticParam(values, paramData, headIndex, t, parser)
		headIndex += abiTypeWordSize(t)
	}
}

func annotateDynamicArray(values []ParameterValue, paramData []byte, startIdx int, elemType abi.Type, parser *ABIParser) {
	wordCount := len(values)
	if startIdx < 0 || startIdx >= wordCount {
		return
	}
	lengthWord := readParamWord(paramData, startIdx)
	length := wordToInt(lengthWord)
	if length == nil || length.BitLen() > 63 {
		return
	}
	n := int(length.Int64())
	if n < 0 {
		return
	}
	markSkipParam(values, startIdx, "length")

	elemSize := abiTypeWordSize(elemType)
	if elemSize <= 0 {
		return
	}

	idx := startIdx + 1
	for i := 0; i < n; i++ {
		if idx >= wordCount {
			break
		}
		if elemType.T == abi.FixedBytesTy {
			word := readParamWord(paramData, idx)
			values[idx].Type = elemType.String() + "_elem"
			if parser != nil && word != nil {
				values[idx].Value = parser.parseValue(elemType.String(), word)
			}
		} else {
			annotateStaticParam(values, paramData, idx, elemType, parser)
		}
		idx += elemSize
	}
}

func annotateDynamicBytes(values []ParameterValue, paramData []byte, startIdx int, payloadType string) {
	wordCount := len(values)
	if startIdx < 0 || startIdx >= wordCount {
		return
	}
	lengthWord := readParamWord(paramData, startIdx)
	length := wordToInt(lengthWord)
	if length == nil || length.BitLen() > 63 {
		return
	}
	n := int(length.Int64())
	if n < 0 {
		return
	}
	markSkipParam(values, startIdx, "length")

	dataWords := (n + 31) / 32
	for i := 0; i < dataWords; i++ {
		idx := startIdx + 1 + i
		if idx >= wordCount {
			break
		}
		word := readParamWord(paramData, idx)
		values[idx].Type = payloadType
		values[idx].Value = append([]byte(nil), word...)
	}
}

func annotateStaticParam(values []ParameterValue, paramData []byte, startIdx int, paramType abi.Type, parser *ABIParser) {
	if startIdx < 0 || startIdx >= len(values) {
		return
	}

	if paramType.T == abi.ArrayTy && paramType.Elem != nil && !isDynamicABIType(*paramType.Elem) {
		elemSize := abiTypeWordSize(*paramType.Elem)
		if elemSize <= 0 {
			return
		}
		for i := 0; i < paramType.Size; i++ {
			childIdx := startIdx + i*elemSize
			if paramType.Elem.T == abi.FixedBytesTy {
				word := readParamWord(paramData, childIdx)
				values[childIdx].Type = paramType.Elem.String() + "_elem"
				if parser != nil && word != nil {
					values[childIdx].Value = parser.parseValue(paramType.Elem.String(), word)
				}
				continue
			}
			annotateStaticParam(values, paramData, childIdx, *paramType.Elem, parser)
		}
		return
	}

	if paramType.T == abi.TupleTy && !isDynamicABIType(paramType) {
		offset := startIdx
		for _, elem := range paramType.TupleElems {
			if elem == nil {
				continue
			}
			annotateStaticParam(values, paramData, offset, *elem, parser)
			offset += abiTypeWordSize(*elem)
		}
		return
	}

	word := readParamWord(paramData, startIdx)
	values[startIdx].Type = paramType.String()
	if parser != nil && word != nil {
		values[startIdx].Value = parser.parseValue(paramType.String(), word)
	}
}

func markSkipParam(values []ParameterValue, index int, skipType string) {
	if index < 0 || index >= len(values) {
		return
	}
	values[index].Type = skipType
}

func offsetToWordIndex(paramData []byte, wordIndex int, wordCount int) (int, bool) {
	word := readParamWord(paramData, wordIndex)
	offset := wordToInt(word)
	if offset == nil || offset.BitLen() > 63 {
		return 0, false
	}
	raw := offset.Int64()
	if raw < 0 || raw%32 != 0 {
		return 0, false
	}
	idx := int(raw / 32)
	if idx < 0 || idx >= wordCount {
		return 0, false
	}
	return idx, true
}

func wordToInt(word []byte) *big.Int {
	if len(word) == 0 {
		return nil
	}
	return new(big.Int).SetBytes(word)
}

func readParamWord(data []byte, index int) []byte {
	start := index * 32
	end := start + 32
	if start < 0 || end > len(data) {
		return nil
	}
	return data[start:end]
}

func isDynamicABIType(t abi.Type) bool {
	switch t.T {
	case abi.StringTy, abi.BytesTy, abi.SliceTy:
		return true
	case abi.ArrayTy:
		if t.Elem == nil {
			return false
		}
		return isDynamicABIType(*t.Elem)
	case abi.TupleTy:
		for _, elem := range t.TupleElems {
			if elem != nil && isDynamicABIType(*elem) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func abiTypeWordSize(t abi.Type) int {
	if isDynamicABIType(t) {
		return 1
	}
	switch t.T {
	case abi.ArrayTy:
		if t.Elem == nil {
			return 1
		}
		return t.Size * abiTypeWordSize(*t.Elem)
	case abi.TupleTy:
		size := 0
		for _, elem := range t.TupleElems {
			if elem == nil {
				continue
			}
			size += abiTypeWordSize(*elem)
		}
		if size == 0 {
			return 1
		}
		return size
	default:
		return 1
	}
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

// containsContractJumpDest 检查路径中是否包含目标合约的JUMPDEST
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
	pathContractAddr common.Address,
	simBlockNumber uint64,
	stateOverride simulator.StateOverride,
	symbolicSeeds []symbolic.SymbolicSeed,
	callTree *CallFrame,
	seedCfg *SeedConfig,
	mutationSeedCfg *SeedConfig,
	loopBaseline bool,
	preparedMutations map[string]*PreparedMutation,
	bestSimilarity *float64,
	recordedSelectors map[string]struct{},
) []FuzzingResult {
	if seedCfg == nil {
		log.Printf("[Adaptive]  Seed config missing, skip adaptive fuzzing")
		return nil
	}
	if seedCfg.AdaptiveConfig == nil {
		log.Printf("[Adaptive]  Adaptive config missing, skip adaptive fuzzing")
		return nil
	}
	seedGen := NewSeedGenerator(seedCfg, f.generator.maxVariations)
	allResults := []FuzzingResult{}

	// 约束范围集成：如果有约束范围配置，合并约束种子
	if seedGen.HasConstraintRanges() {
		if targetMethod != nil {
			seedGen.MergeConstraintSeeds(targetMethod.Name)
			log.Printf("[Adaptive]  Merged constraint seeds for function: %s", targetMethod.Name)
		} else {
			for funcName := range seedCfg.ConstraintRanges {
				seedGen.MergeConstraintSeeds(funcName)
				log.Printf("[Adaptive]  Merged constraint seeds for function: %s", funcName)
			}
		}
		log.Printf("[Adaptive]  Using constraint ranges")
	}

	// Layer 3: 设置符号种子
	if len(symbolicSeeds) > 0 {
		seedGen.SetSymbolicSeeds(symbolicSeeds)
		log.Printf("[Adaptive]  Applied %d symbolic seeds from constraint extraction", len(symbolicSeeds))
	}

	// 第0轮：初始探索（使用 Layer 1 固定范围）
	log.Printf("[Adaptive] ========== Iteration 0: Initial Exploration ==========")
	log.Printf("[Adaptive] Using fixed seed-based ranges")

	initialCombos := seedGen.GenerateSeedBasedCombinations(parsedData.Parameters)
	initialResults := f.executeFuzzing(ctx, initialCombos, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, pathContractAddr, simBlockNumber, stateOverride, callTree, mutationSeedCfg, loopBaseline, preparedMutations, bestSimilarity, recordedSelectors)
	allResults = append(allResults, initialResults...)

	log.Printf("[Adaptive] Iteration 0 completed: %d valid results, total: %d",
		len(initialResults), len(allResults))

	// 初始探索无结果时直接退出，避免无效的空循环
	if len(allResults) == 0 {
		log.Printf("[Adaptive]  初始探索未找到有效结果，停止自适应迭代")
		return allResults
	}
	if len(parsedData.Parameters) == 0 {
		log.Printf("[Adaptive]  无参数函数 %s，跳过自适应迭代以避免重复组合",
			hexutil.Encode(parsedData.Selector))
		return allResults
	}

	// 迭代优化
	for iter := 1; iter <= seedCfg.AdaptiveConfig.MaxIterations; iter++ {
		log.Printf("[Adaptive] ========== Iteration %d: Adaptive Refinement ==========", iter)

		seedGen.currentIteration = iter

		// 1. 分析上一轮反馈
		log.Printf("[Adaptive] Analyzing feedback from %d results...", len(allResults))
		feedback := seedGen.AnalyzeFeedback(allResults, parsedData.Parameters)
		seedGen.feedbackHistory = append(seedGen.feedbackHistory, feedback...)

		// 2. 检查收敛
		if seedGen.HasConverged(feedback) {
			log.Printf("[Adaptive]  检测到收敛 (iteration=%d)，停止自适应迭代", iter)
			break
		}

		// 3. 生成新一轮参数（基于反馈调整）
		log.Printf("[Adaptive] Generating adaptive combinations based on feedback...")
		adaptiveCombos := seedGen.GenerateAdaptiveRound(parsedData.Parameters, feedback)

		// 4. 执行新一轮模糊测试
		log.Printf("[Adaptive] Executing fuzzing with adaptive ranges...")
		iterResults := f.executeFuzzing(ctx, adaptiveCombos, parsedData.Selector, targetMethod, originalPath, targetCall, contractAddr, pathContractAddr, simBlockNumber, stateOverride, callTree, mutationSeedCfg, loopBaseline, preparedMutations, bestSimilarity, recordedSelectors)

		// 5. 累积结果
		allResults = append(allResults, iterResults...)

		log.Printf("[Adaptive] Iteration %d completed: %d new results, total: %d",
			iter, len(iterResults), len(allResults))

		// 如果这一轮没有新的有效结果，认为已饱和，退出
		if len(iterResults) == 0 {
			log.Printf("[Adaptive]  本轮无新增有效结果 (iteration=%d)，停止自适应迭代", iter)
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
	if !f.localExecution || len(f.dualSimulators) == 0 {
		log.Printf("[Fuzzer]   跳过架构初始化：非本地执行模式")
		return nil
	}

	log.Printf("[Fuzzer]  开始初始化新架构组件...")

	f.archComponents = f.archComponents[:0]

	for idx, sim := range f.dualSimulators {
		localExec := sim.GetLocalExecutor()
		if localExec == nil {
			return fmt.Errorf("local executor is nil (index=%d)", idx)
		}

		interceptor := localExec.GetInterceptor()
		if interceptor == nil {
			return fmt.Errorf("interceptor is nil (index=%d)", idx)
		}

		// 1. 创建Registry
		registry := local.NewProtectedRegistry()

		// 2. 创建ParamPoolManager (最多缓存100个池)
		poolManager, err := local.NewParamPoolManager(100)
		if err != nil {
			return fmt.Errorf("failed to create pool manager (index=%d): %w", idx, err)
		}
		if f.generator != nil {
			poolManager.SetParamGenerator(newPoolParamGeneratorAdapter(f.generator))
		}

		// 3. 创建MutationEngine
		engine := local.NewMutationEngine()

		// 4. 注册变异策略（按优先级顺序）

		// 4.1 SeedDrivenStrategy (优先级100)
		var seedConfig *local.SeedConfig
		if f.seedConfig != nil && f.seedConfig.Enabled {
			// 转换fuzzer.SeedConfig为local.SeedConfig
			seedConfig = convertSeedConfigToLocal(f.seedConfig)
		}
		seedStrategy := strategies.NewSeedDrivenStrategy(seedConfig)
		engine.RegisterStrategy(seedStrategy)

		// 4.2 ABIBasedStrategy (优先级50)
		abiStrategy := strategies.NewABIBasedStrategy()
		engine.RegisterStrategy(abiStrategy)

		// 4.3 RangeMutationStrategy (优先级30)
		rangeStrategy := strategies.NewRangeMutationStrategy()
		engine.RegisterStrategy(rangeStrategy)

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

		// 保存组件
		if idx == 0 {
			f.registry = registry
			f.poolManager = poolManager
			f.mutationEngine = engine
		}
		f.archComponents = append(f.archComponents, struct {
			registry       local.ProtectedRegistry
			poolManager    local.ParamPoolManager
			mutationEngine local.MutationEngine
		}{
			registry:       registry,
			poolManager:    poolManager,
			mutationEngine: engine,
		})
	}

	log.Printf("[Fuzzer]  新架构初始化完成，实例数=%d", len(f.archComponents))
	if f.mutationEngine != nil {
		log.Printf("[Fuzzer]  已注册策略: %d个", len(f.mutationEngine.GetStrategies()))
	}

	return nil
}

// newPoolParamGeneratorAdapter 将基础参数生成器适配到本地参数池，保持address参数不被随机化
type poolParamGeneratorAdapter struct {
	base *ParamGenerator
}

func newPoolParamGeneratorAdapter(base *ParamGenerator) local.ParamGenerator {
	return &poolParamGeneratorAdapter{base: base}
}

func (a *poolParamGeneratorAdapter) GenerateForType(paramType abi.Type, seed int) interface{} {
	value := zeroValueForType(paramType)
	if a == nil || a.base == nil {
		return value
	}

	param := Parameter{Type: paramType.String(), Value: value}
	variations := a.base.GenerateVariations(param)
	if len(variations) == 0 {
		return value
	}

	idx := seed % len(variations)
	if idx < 0 {
		idx = 0
	}
	return variations[idx]
}

func zeroValueForType(paramType abi.Type) interface{} {
	switch paramType.T {
	case abi.UintTy, abi.IntTy:
		return big.NewInt(0)
	case abi.BoolTy:
		return false
	case abi.AddressTy:
		return common.Address{}
	case abi.StringTy:
		return ""
	case abi.BytesTy, abi.FixedBytesTy:
		return []byte{}
	default:
		return nil
	}
}

// convertSeedConfigToLocal 将 fuzzer.SeedConfig 转换为 local.SeedConfig（包含约束范围）
func convertSeedConfigToLocal(cfg *SeedConfig) *local.SeedConfig {
	if cfg == nil {
		return nil
	}
	out := &local.SeedConfig{
		Enabled:     cfg.Enabled,
		AttackSeeds: cfg.AttackSeeds,
	}

	// 转换 constraint_ranges（函数名小写）
	if len(cfg.ConstraintRanges) > 0 {
		out.ConstraintRanges = make(map[string]map[string]*local.ConstraintRange)
		for fn, params := range cfg.ConstraintRanges {
			fnLower := strings.ToLower(fn)
			out.ConstraintRanges[fnLower] = make(map[string]*local.ConstraintRange)
			for idx, cr := range params {
				if cr == nil {
					continue
				}
				lcr := &local.ConstraintRange{
					Type:             cr.Type,
					AttackValues:     cr.AttackValues,
					MutationStrategy: cr.MutationStrategy,
					Confidence:       cr.Confidence,
				}
				if cr.Range != nil {
					lcr.Range = &struct {
						Min string `json:"min"`
						Max string `json:"max"`
					}{
						Min: cr.Range.Min,
						Max: cr.Range.Max,
					}
				}
				out.ConstraintRanges[fnLower][idx] = lcr
			}
		}
	}

	// 范围变异配置（可选）
	if cfg.RangeMutationConfig != nil {
		out.RangeMutationConfig = &local.RangeMutationConfig{
			FocusPercentiles:       cfg.RangeMutationConfig.FocusPercentiles,
			BoundaryExploration:    cfg.RangeMutationConfig.BoundaryExploration,
			StepCount:              cfg.RangeMutationConfig.StepCount,
			RandomWithinRangeRatio: cfg.RangeMutationConfig.RandomWithinRangeRatio,
		}
	}

	return out
}

// RegisterProtectedContract 注册受保护合约到registry
// contractAddr: 合约地址
// contractABI: 合约ABI (JSON字符串或*abi.ABI对象)
func (f *CallDataFuzzer) RegisterProtectedContract(
	contractAddr common.Address,
	contractABI interface{},
) error {
	if !f.localExecution || len(f.dualSimulators) == 0 {
		return fmt.Errorf("only supported in local execution mode")
	}

	if f.registry == nil || len(f.archComponents) == 0 {
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
	for idx, comp := range f.archComponents {
		if comp.registry == nil {
			return fmt.Errorf("registry not initialized for executor %d", idx)
		}
		info := &local.ProtectedContractInfo{
			Address:    contractAddr,
			ABI:        parsedABI,
			SeedConfig: seedConfig,
			Metadata:   make(map[string]interface{}),
		}
		if err := comp.registry.RegisterContract(info); err != nil {
			return fmt.Errorf("failed to register contract on executor %d: %w", idx, err)
		}
	}

	log.Printf("[Fuzzer]  已注册受保护合约: %s (方法数=%d)",
		contractAddr.Hex(), len(parsedABI.Methods))

	return nil
}

// InitializeParamPools 为所有已注册的受保护合约预热参数池
func (f *CallDataFuzzer) InitializeParamPools(poolSize int) error {
	if !f.localExecution || len(f.dualSimulators) == 0 {
		return fmt.Errorf("only supported in local execution mode")
	}

	if f.registry == nil || f.poolManager == nil || len(f.archComponents) == 0 {
		return fmt.Errorf("components not initialized, call InitializeArchitecture first")
	}

	log.Printf("[Fuzzer]  开始预热参数池 (poolSize=%d)...", poolSize)

	// 获取所有已注册的合约
	contracts := f.registry.GetAll()
	if len(contracts) == 0 {
		log.Printf("[Fuzzer]   没有已注册的受保护合约，跳过参数池预热")
		return nil
	}

	// 对每个执行器分别预热
	for idx, sim := range f.dualSimulators {
		localExec := sim.GetLocalExecutor()
		if localExec == nil {
			log.Printf("[Fuzzer]   执行器 %d 缺少LocalExecutor，跳过参数池预热", idx)
			continue
		}
		interceptor := localExec.GetInterceptor()
		if interceptor == nil {
			log.Printf("[Fuzzer]   执行器 %d 缺少Interceptor，跳过参数池预热", idx)
			continue
		}

		for _, contract := range contracts {
			err := interceptor.InitializePoolsForContract(contract.Address, poolSize)
			if err != nil {
				log.Printf("[Fuzzer]   执行器 %d 合约 %s 参数池预热失败: %v", idx, contract.Address.Hex(), err)
				continue
			}
			log.Printf("[Fuzzer]  执行器 %d 合约 %s 参数池预热完成", idx, contract.Address.Hex())
		}

		stats := interceptor.GetPoolStats()
		log.Printf("[Fuzzer]  执行器 %d 参数池统计: 总池数=%d, 总参数=%d, 平均池大小=%d, 缓存命中率=%.2f%%",
			idx, stats.TotalPools, stats.TotalParams, stats.AvgPoolSize, stats.CacheHitRate*100)
	}

	return nil
}

// recordAttempt 记录一次组合尝试（包含低相似度样本）
func (f *CallDataFuzzer) recordAttempt(similarity float64, overlap float64) {
	f.attemptMu.Lock()
	defer f.attemptMu.Unlock()

	f.attempts++
	f.simSum += similarity
	if f.attempts == 1 || similarity < f.simMin {
		f.simMin = similarity
	}
	if f.attempts == 1 || similarity > f.simMax {
		f.simMax = similarity
	}
	f.rawSimSum += overlap
	if f.attempts == 1 || overlap < f.rawSimMin {
		f.rawSimMin = overlap
	}
	if f.attempts == 1 || overlap > f.rawSimMax {
		f.rawSimMax = overlap
	}

	// 调试日志：前几次和每100次打印一次
	if f.attempts <= 5 || f.attempts%100 == 0 {
		avg := f.simSum / float64(f.attempts)
		rawAvg := f.rawSimSum / float64(f.attempts)
		log.Printf("[Fuzzer]  尝试#%d 相似度=%.4f (阈值=%.4f) 统计: avg=%.4f min=%.4f max=%.4f, 重叠avg=%.4f min=%.4f max=%.4f",
			f.attempts, similarity, f.threshold, avg, f.simMin, f.simMax, rawAvg, f.rawSimMin, f.rawSimMax)
	}
}

// recordSamples 将本次重放产生的样本按正/负分类记录
func (f *CallDataFuzzer) recordSamples(contractAddr common.Address, similarity float64, observed []observedCall) {
	if f.sampleRecorder == nil || len(observed) == 0 {
		return
	}
	positive := similarity >= f.threshold
	for _, oc := range observed {
		f.sampleRecorder.Record(contractAddr, oc.selector, oc.functionName, oc.params, similarity, oc.mutated, positive)
	}
}

// attachSampleRecords 将样本分类信息写入报告
func (f *CallDataFuzzer) attachSampleRecords(report *AttackParameterReport, contractAddr common.Address, selector []byte, targetMethod *abi.Method) {
	if report == nil || f.sampleRecorder == nil {
		return
	}
	selectorHex := strings.ToLower(hexutil.Encode(selector))
	snapshots := f.sampleRecorder.Snapshot(contractAddr)
	if len(snapshots) == 0 {
		return
	}

	for sel, bucket := range snapshots {
		if bucket == nil {
			continue
		}
		if sel == selectorHex {
			if len(bucket.positive) > 0 {
				report.PositiveSamples = append(report.PositiveSamples, bucket.positive...)
			}
			if len(bucket.negative) > 0 {
				report.NegativeSamples = append(report.NegativeSamples, bucket.negative...)
			}
			if report.FunctionName == "" {
				if bucket.functionName != "" {
					report.FunctionName = bucket.functionName
				} else if targetMethod != nil {
					report.FunctionName = targetMethod.Name
				}
			}
			continue
		}

		if len(bucket.positive) > 0 {
			report.PositiveSamples = append(report.PositiveSamples, bucket.positive...)
		}
		if len(bucket.negative) > 0 {
			report.NegativeSamples = append(report.NegativeSamples, bucket.negative...)
		}
	}
}

// attachPreparedMutations 记录预设的变异参数，便于审计“先准备再重放”的流程
func (f *CallDataFuzzer) attachPreparedMutations(report *AttackParameterReport, prepared map[string]*PreparedMutation) {
	if report == nil || len(prepared) == 0 {
		return
	}
	summaries := make([]PreparedMutationSample, 0, len(prepared))
	for sel, pm := range prepared {
		if pm == nil {
			continue
		}
		summaries = append(summaries, PreparedMutationSample{
			Selector:       sel,
			FunctionName:   pm.FunctionName,
			OriginalParams: toPublicParamValues(pm.OriginalParams),
			PreparedParams: toPublicParamValues(pm.MutatedParams),
		})
	}
	if len(summaries) > 1 {
		sort.Slice(summaries, func(i, j int) bool { return summaries[i].Selector < summaries[j].Selector })
	}
	report.PreparedMutations = summaries
}

// getAttemptStats 返回全量尝试统计
func (f *CallDataFuzzer) getAttemptStats() (attempts int, sum float64, minSim float64, maxSim float64, rawSum float64, rawMin float64, rawMax float64) {
	f.attemptMu.Lock()
	defer f.attemptMu.Unlock()
	return f.attempts, f.simSum, f.simMin, f.simMax, f.rawSimSum, f.rawSimMin, f.rawSimMax
}

// resetAttemptStats 重置尝试统计，避免跨函数污染
func (f *CallDataFuzzer) resetAttemptStats() {
	f.attemptMu.Lock()
	defer f.attemptMu.Unlock()
	f.attempts = 0
	f.simSum = 0
	f.simMin = 0
	f.simMax = 0
	f.rawSimSum = 0
	f.rawSimMin = 0
	f.rawSimMax = 0
}

// 应用约束规则到报告（若收集到足够样本）
func (f *CallDataFuzzer) applyConstraintRule(report *AttackParameterReport, contractAddr common.Address, selector []byte) {
	if report == nil || f.constraintCollector == nil {
		return
	}
	rule := f.constraintCollector.GetRule(contractAddr, selector)
	if rule != nil {
		summaries := convertParamConstraintsToSummaries(rule.ParamConstraints)
		if len(summaries) > 0 {
			report.ValidParameters = summaries
		}
		report.ConstraintRule = rule
	}

	// 附带表达式约束（ratio/linear）
	if expr := f.constraintCollector.GetExpressionRule(contractAddr, selector); expr != nil {
		report.ExpressionRules = append(report.ExpressionRules, *expr)
		if cost := f.constraintCollector.GetExpressionGenCost(contractAddr, selector); cost > 0 {
			report.ExpressionGenMs = cost
		}
	}
}

// convertParamConstraintsToSummaries 将参数约束转成参数摘要
func convertParamConstraintsToSummaries(constraints []ParamConstraint) []ParameterSummary {
	var out []ParameterSummary
	for _, c := range constraints {
		// 地址类型不输出规则
		if isAddressType(c.Type) {
			continue
		}
		if shouldSkipParamType(c.Type) {
			continue
		}
		// 跳过空规则，避免推送空黑名单
		if !c.IsRange && len(c.Values) == 0 {
			continue
		}
		if c.IsRange && strings.TrimSpace(c.RangeMin) == "" && strings.TrimSpace(c.RangeMax) == "" {
			continue
		}
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

// sampleGroup 聚合单个 selector 的样本
type sampleGroup struct {
	functionName string
	pos          []MutationSample
	neg          []MutationSample
}

// buildChainedReportsFromSamples 利用连锁调用样本为其他 target_functions 生成规则报告（不额外fuzz）
func (f *CallDataFuzzer) buildChainedReportsFromSamples(
	baseReport *AttackParameterReport,
	chainedCalls []*CallFrame,
	contractAddr common.Address,
	txHash common.Hash,
	blockNumber uint64,
) []*AttackParameterReport {
	if baseReport == nil || len(chainedCalls) == 0 {
		return nil
	}

	// 按 selector 聚合样本
	groups := make(map[string]*sampleGroup)
	for _, s := range baseReport.PositiveSamples {
		key := strings.ToLower(s.Selector)
		if _, ok := groups[key]; !ok {
			groups[key] = &sampleGroup{}
		}
		groups[key].pos = append(groups[key].pos, s)
		if groups[key].functionName == "" && s.FunctionName != "" {
			groups[key].functionName = s.FunctionName
		}
	}
	for _, s := range baseReport.NegativeSamples {
		key := strings.ToLower(s.Selector)
		if _, ok := groups[key]; !ok {
			groups[key] = &sampleGroup{}
		}
		groups[key].neg = append(groups[key].neg, s)
		if groups[key].functionName == "" && s.FunctionName != "" {
			groups[key].functionName = s.FunctionName
		}
	}

	primarySelector := strings.ToLower(baseReport.FunctionSig)
	seen := make(map[string]bool)
	var out []*AttackParameterReport

	for _, c := range chainedCalls {
		if c == nil || len(c.Input) < 10 {
			continue
		}
		selector := strings.ToLower(c.Input[:10])
		if selector == "" {
			continue
		}
		if strings.EqualFold(selector, primarySelector) {
			continue
		}
		if seen[selector] {
			continue
		}
		seen[selector] = true

		group := groups[selector]
		params := f.deriveParamSummariesFromSamples(group, contractAddr, c)
		if len(params) == 0 {
			continue
		}

		// 优先使用ABI解析到的方法，补全函数名与标准签名
		var decodedMethod *abi.Method
		if _, method, err := f.decodeCallForSamples(contractAddr, c); err == nil {
			decodedMethod = method
		}

		funcName := ""
		if group != nil && group.functionName != "" {
			funcName = group.functionName
		}
		if funcName == "" && decodedMethod != nil {
			funcName = decodedMethod.Name
		}

		totalSamples := 1
		if group != nil {
			totalSamples = len(group.pos) + len(group.neg)
			if totalSamples == 0 {
				totalSamples = 1
			}
		}

		maxSim := baseReport.MaxSimilarity
		if maxSim <= 0 {
			maxSim = 1.0
		}
		avgSim := baseReport.AverageSimilarity
		if avgSim <= 0 {
			avgSim = maxSim
		}

		report := &AttackParameterReport{
			ContractAddress:      contractAddr,
			FunctionSig:          ensureSelectorHex(selector),
			FunctionName:         funcName,
			Timestamp:            time.Now(),
			OriginalTxHash:       txHash,
			BlockNumber:          blockNumber,
			ValidParameters:      params,
			DerivedFromChained:   true,
			TotalCombinations:    totalSamples,
			ValidCombinations:    totalSamples,
			AverageSimilarity:    avgSim,
			MaxSimilarity:        maxSim,
			MinSimilarity:        maxSim,
			RawStatsAvailable:    baseReport.RawStatsAvailable,
			RawAverageSimilarity: baseReport.RawAverageSimilarity,
			RawMaxSimilarity:     baseReport.RawMaxSimilarity,
			RawMinSimilarity:     baseReport.RawMinSimilarity,
			HasInvariantCheck:    baseReport.HasInvariantCheck,
			ViolationCount:       baseReport.ViolationCount,
		}
		if decodedMethod != nil {
			report.FunctionSignature = decodedMethod.Sig
		}

		if group != nil {
			if len(group.pos) > 0 {
				report.PositiveSamples = append(report.PositiveSamples, group.pos...)
			}
			if len(group.neg) > 0 {
				report.NegativeSamples = append(report.NegativeSamples, group.neg...)
			}
		}

		if selBytes, err := hexutil.Decode(selector); err == nil && len(selBytes) >= 4 {
			f.applyConstraintRule(report, contractAddr, selBytes[:4])
		}

		out = append(out, report)
	}

	return out
}

// deriveParamSummariesFromSamples 基于样本和调用帧生成参数摘要（链上规则所需）
func (f *CallDataFuzzer) deriveParamSummariesFromSamples(
	group *sampleGroup,
	contractAddr common.Address,
	call *CallFrame,
) []ParameterSummary {
	type paramAgg struct {
		paramType string
		paramName string
		values    map[string]struct{}
		nums      []*big.Int
	}

	aggs := make(map[int]*paramAgg)
	addValue := func(idx int, typ, name, val string) {
		if idx < 0 {
			return
		}
		if isArrayType(typ) {
			// 跳过数组类型，避免 ParamType 枚举映射错误
			return
		}
		if typ == "" {
			typ = "uint256"
		}
		if val == "" {
			return
		}
		if _, ok := aggs[idx]; !ok {
			aggs[idx] = &paramAgg{
				paramType: typ,
				paramName: name,
				values:    make(map[string]struct{}),
			}
		}
		agg := aggs[idx]
		if agg.paramType == "" {
			agg.paramType = typ
		}
		if agg.paramName == "" {
			agg.paramName = name
		}
		agg.values[val] = struct{}{}
		if n, ok := parseBigInt(val); ok {
			agg.nums = append(agg.nums, n)
		}
	}

	collectFromSamples := func(samples []MutationSample) {
		for _, s := range samples {
			for _, p := range s.Params {
				if p.IsRange {
					if p.RangeMin != "" {
						addValue(p.Index, p.Type, p.Name, p.RangeMin)
					}
					if p.RangeMax != "" {
						addValue(p.Index, p.Type, p.Name, p.RangeMax)
					}
					continue
				}
				addValue(p.Index, p.Type, p.Name, p.Value)
			}
		}
	}

	if group != nil {
		collectFromSamples(group.pos)
		collectFromSamples(group.neg)
	}

	// 回退：若样本缺失，直接解析原始调用参数补全
	if call != nil {
		if parsed, method, err := f.decodeCallForSamples(contractAddr, call); err == nil && parsed != nil {
			for idx, p := range parsed.Parameters {
				typ := p.Type
				name := p.Name
				if method != nil && idx < len(method.Inputs) {
					typ = method.Inputs[idx].Type.String()
					name = method.Inputs[idx].Name
				}
				paramIdx := p.Index
				if paramIdx == 0 {
					paramIdx = idx
				}
				addValue(paramIdx, typ, name, ValueToString(p.Value))
			}
		}
	}

	if len(aggs) == 0 {
		return nil
	}

	summaries := make([]ParameterSummary, 0, len(aggs))
	for idx, agg := range aggs {
		if agg == nil || len(agg.values) == 0 {
			continue
		}
		values := make([]string, 0, len(agg.values))
		for v := range agg.values {
			values = append(values, v)
		}
		sort.Strings(values)

		ps := ParameterSummary{
			ParamIndex:      idx,
			ParamType:       agg.paramType,
			ParamName:       agg.paramName,
			OccurrenceCount: len(values),
		}

		if isNumericTypeStr(agg.paramType) && len(agg.nums) >= 2 {
			minV, maxV := agg.nums[0], agg.nums[0]
			for _, n := range agg.nums[1:] {
				if n.Cmp(minV) < 0 {
					minV = n
				}
				if n.Cmp(maxV) > 0 {
					maxV = n
				}
			}
			ps.IsRange = true
			ps.RangeMin = formatBigInt(minV)
			ps.RangeMax = formatBigInt(maxV)
		} else {
			ps.IsRange = false
			ps.SingleValues = values
		}

		summaries = append(summaries, ps)
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].ParamIndex < summaries[j].ParamIndex
	})
	return summaries
}

// decodeCallForSamples 尝试解析调用帧的参数与方法
func (f *CallDataFuzzer) decodeCallForSamples(contractAddr common.Address, call *CallFrame) (*ParsedCallData, *abi.Method, error) {
	if call == nil || len(call.Input) < 10 {
		return nil, nil, fmt.Errorf("call input empty")
	}
	data, err := hexutil.Decode(call.Input)
	if err != nil {
		return nil, nil, err
	}
	return f.parseCallDataWithABI(contractAddr, data)
}

func ensureSelectorHex(sel string) string {
	if strings.HasPrefix(sel, "0x") {
		return strings.ToLower(sel)
	}
	return "0x" + strings.ToLower(sel)
}

func parseBigInt(val string) (*big.Int, bool) {
	str := strings.TrimSpace(val)
	if str == "" {
		return nil, false
	}
	if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
		if bi, ok := new(big.Int).SetString(str[2:], 16); ok {
			return bi, true
		}
		return nil, false
	}
	if bi, ok := new(big.Int).SetString(str, 10); ok {
		return bi, true
	}
	return nil, false
}

func formatBigInt(n *big.Int) string {
	if n == nil {
		return ""
	}
	return "0x" + n.Text(16)
}

func isNumericTypeStr(t string) bool {
	lt := strings.ToLower(t)
	return strings.HasPrefix(lt, "uint") || strings.HasPrefix(lt, "int") || lt == "uint" || lt == "int"
}
