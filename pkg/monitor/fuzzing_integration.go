package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"autopath/pkg/fuzzer"
	"autopath/pkg/invariants"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// FuzzingDriver 定义 FuzzingIntegration 所需的最小驱动能力
type FuzzingDriver interface {
	// 返回同一交易内针对目标合约的全部函数报告，避免只保留单个selector
	FuzzTransaction(ctx context.Context, txHash common.Hash, contractAddr common.Address, blockNumber uint64, tx *types.Transaction) ([]*fuzzer.AttackParameterReport, error)
	GetStats() *fuzzer.FuzzerStats
}

// FuzzingIntegration 模糊测试集成模块
type FuzzingIntegration struct {
	fuzzer      FuzzingDriver
	config      *FuzzingConfig
	resultCache map[cacheKey][]*fuzzer.AttackParameterReport
	cacheMutex  sync.RWMutex
	outputPath  string
	threshold   float64
	enabled     bool
}

// cacheKey 用于区分同一交易内不同合约的 Fuzz 结果，避免缓存污染
type cacheKey struct {
	Tx   common.Hash
	Addr common.Address
}

// ProtectedContractConfig 受保护合约配置
type ProtectedContractConfig struct {
	Address common.Address `json:"address"`  // 合约地址
	ABIPath string         `json:"abi_path"` // ABI文件路径
	ABIJson string         `json:"abi_json"` // ABI JSON字符串（与ABIPath二选一）
}

// FuzzingConfig Fuzzing配置
type FuzzingConfig struct {
	Enabled                bool                  `json:"enabled"`
	TargetFunctionFallback bool                  `json:"target_function_fallback"`
	Threshold              float64               `json:"threshold"`
	MaxVariations          int                   `json:"max_variations"`
	Workers                int                   `json:"workers"`
	TimeoutSeconds         int                   `json:"timeout_seconds"`
	OutputPath             string                `json:"output_path"`
	AutoTrigger            bool                  `json:"auto_trigger"`
	TriggerContractTypes   []string              `json:"trigger_contract_types"`
	MinSimilarity          float64               `json:"min_similarity"`
	SaveHighSimilarity     bool                  `json:"save_high_similarity"`
	PrintRealtime          bool                  `json:"print_realtime"`
	InvariantCheck         *InvariantCheckConfig `json:"invariant_check"`
	ProjectID              string                `json:"project_id"`
	BaselineStatePath      string                `json:"baseline_state_path"`

	//  Unlimited fuzzing模式配置
	UnlimitedMode     bool    `json:"unlimited_mode"`       // 无限制fuzzing模式
	TargetSimilarity  float64 `json:"target_similarity"`    // 目标相似度阈值
	MaxHighSimResults int     `json:"max_high_sim_results"` // 最大高相似度结果数

	//  Seed-driven fuzzing配置 (使用interface{}避免循环依赖)
	SeedConfig interface{} `json:"seed_config"` // 实际类型为*fuzzer.SeedConfig，但避免导入fuzzer包

	// Entry Call 限制
	EntryCallProtectedOnly bool `json:"entry_call_protected_only"`

	//  本地执行模式配置
	LocalExecution bool `json:"local_execution"` // 使用本地EVM执行（替代RPC调用）

	//  全交易路径记录
	RecordFullTrace bool `json:"record_full_trace"` // 记录全交易路径（不截断到受保护合约）

	//  严格prestate模式（禁止attack_state覆盖，仅允许baseline_state补全）
	StrictPrestate bool `json:"strict_prestate"`
	//  attack_state仅补代码（不写入余额/存储）
	AttackStateCodeOnly bool `json:"attack_state_code_only"`

	// === 新架构配置 ===
	ProtectedContracts []ProtectedContractConfig `json:"protected_contracts"` // 受保护合约列表
	PoolSize           int                       `json:"pool_size"`           // 参数池大小（默认100）
	EnableNewArch      bool                      `json:"enable_new_arch"`     // 是否启用新架构
}

// InvariantCheckConfig 不变量检查配置
type InvariantCheckConfig struct {
	Enabled    bool   `json:"enabled"`
	ProjectID  string `json:"project_id"`
	ConfigPath string `json:"config_path"`
}

// NewFuzzingIntegration 创建模糊测试集成模块
func NewFuzzingIntegration(rpcURL string, config *FuzzingConfig) (*FuzzingIntegration, error) {
	if config == nil {
		config = &FuzzingConfig{
			Enabled:            false,
			Threshold:          0.8,
			MaxVariations:      50,
			Workers:            20,
			TimeoutSeconds:     5,
			OutputPath:         "./fuzzing_results",
			AutoTrigger:        false,
			MinSimilarity:      0.7,
			SaveHighSimilarity: true,
			PrintRealtime:      true,
		}
	}

	// 创建输出目录
	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	// 创建fuzzer配置
	invariantCfg := fuzzer.InvariantCheckConfig{}
	if config.InvariantCheck != nil {
		invariantCfg.Enabled = config.InvariantCheck.Enabled
		invariantCfg.ProjectID = config.InvariantCheck.ProjectID
		invariantCfg.ConfigPath = config.InvariantCheck.ConfigPath
	}

	//  Type assertion to convert interface{} back to *fuzzer.SeedConfig
	var seedCfg *fuzzer.SeedConfig
	if config.SeedConfig != nil {
		if cfg, ok := config.SeedConfig.(*fuzzer.SeedConfig); ok {
			seedCfg = cfg
		}
	}

	fuzzerConfig := &fuzzer.Config{
		RPCURL:                 rpcURL,
		TargetFunctionFallback: config.TargetFunctionFallback,
		Threshold:              config.Threshold,
		MaxVariations:          config.MaxVariations,
		Workers:                config.Workers,
		Timeout:                time.Duration(config.TimeoutSeconds) * time.Second,
		ProjectID:              config.ProjectID,
		BaselineStatePath:      config.BaselineStatePath,
		Output: fuzzer.OutputConfig{
			Format: "json",
			Path:   config.OutputPath,
		},
		InvariantCheck: invariantCfg,

		//  Unlimited fuzzing模式配置
		UnlimitedMode:     config.UnlimitedMode,
		TargetSimilarity:  config.TargetSimilarity,
		MaxHighSimResults: config.MaxHighSimResults,

		//  Seed配置
		SeedConfig: seedCfg,

		// Entry Call 限制
		EntryCallProtectedOnly: config.EntryCallProtectedOnly,

		//  本地执行模式
		LocalExecution: config.LocalExecution,

		//  全交易路径记录
		RecordFullTrace: config.RecordFullTrace,
		//  严格prestate模式与attack_state代码补齐
		StrictPrestate:      config.StrictPrestate,
		AttackStateCodeOnly: config.AttackStateCodeOnly,
	}

	// 创建fuzzer实例
	fuzzerInstance, err := fuzzer.NewCallDataFuzzer(fuzzerConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create fuzzer: %w", err)
	}

	integration := NewFuzzingIntegrationWithDriver(fuzzerInstance, config)

	// === 新架构自动初始化 ===
	if config.LocalExecution && config.EnableNewArch {
		log.Printf("[FuzzingIntegration]  检测到LocalExecution模式且EnableNewArch=true，自动初始化新架构")
		if err := integration.InitializeNewArchitecture(); err != nil {
			return nil, fmt.Errorf("failed to initialize new architecture: %w", err)
		}
	}

	return integration, nil
}

// NewFuzzingIntegrationWithClients 使用现有的RPC和Ethereum客户端创建模糊测试集成模块
// 这个方法允许复用Monitor的连接，避免创建多个独立的RPC连接
func NewFuzzingIntegrationWithClients(rpcClient *rpc.Client, client *ethclient.Client, config *FuzzingConfig) (*FuzzingIntegration, error) {
	if config == nil {
		config = &FuzzingConfig{
			Enabled:            false,
			Threshold:          0.8,
			MaxVariations:      50,
			Workers:            20,
			TimeoutSeconds:     5,
			OutputPath:         "./fuzzing_results",
			AutoTrigger:        false,
			MinSimilarity:      0.7,
			SaveHighSimilarity: true,
			PrintRealtime:      true,
		}
	}

	// 创建输出目录
	if err := os.MkdirAll(config.OutputPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create output directory: %w", err)
	}

	log.Printf("[FuzzingIntegration]  使用共享的RPC连接初始化Fuzzer")

	// 创建fuzzer配置
	invariantCfg := fuzzer.InvariantCheckConfig{}
	if config.InvariantCheck != nil {
		invariantCfg.Enabled = config.InvariantCheck.Enabled
		invariantCfg.ProjectID = config.InvariantCheck.ProjectID
		invariantCfg.ConfigPath = config.InvariantCheck.ConfigPath
	}

	//  Type assertion to convert interface{} back to *fuzzer.SeedConfig
	var seedCfg *fuzzer.SeedConfig
	if config.SeedConfig != nil {
		if cfg, ok := config.SeedConfig.(*fuzzer.SeedConfig); ok {
			seedCfg = cfg
		}
	}

	fuzzerConfig := &fuzzer.Config{
		RPCURL:                 "", // 不使用URL，因为我们传入了客户端
		TargetFunctionFallback: config.TargetFunctionFallback,
		Threshold:              config.Threshold,
		MaxVariations:          config.MaxVariations,
		Workers:                config.Workers,
		Timeout:                time.Duration(config.TimeoutSeconds) * time.Second,
		ProjectID:              config.ProjectID,
		BaselineStatePath:      config.BaselineStatePath,
		Output: fuzzer.OutputConfig{
			Format: "json",
			Path:   config.OutputPath,
		},
		InvariantCheck: invariantCfg,

		//  Unlimited fuzzing模式配置
		UnlimitedMode:     config.UnlimitedMode,
		TargetSimilarity:  config.TargetSimilarity,
		MaxHighSimResults: config.MaxHighSimResults,

		//  Seed配置
		SeedConfig: seedCfg,

		// Entry Call 限制
		EntryCallProtectedOnly: config.EntryCallProtectedOnly,

		//  本地执行模式
		LocalExecution: config.LocalExecution,

		//  全交易路径记录
		RecordFullTrace: config.RecordFullTrace,
		//  严格prestate模式与attack_state代码补齐
		StrictPrestate:      config.StrictPrestate,
		AttackStateCodeOnly: config.AttackStateCodeOnly,
	}

	// 使用现有客户端创建fuzzer实例
	fuzzerInstance, err := fuzzer.NewCallDataFuzzerWithClients(fuzzerConfig, rpcClient, client)
	if err != nil {
		return nil, fmt.Errorf("failed to create fuzzer with clients: %w", err)
	}

	integration := NewFuzzingIntegrationWithDriver(fuzzerInstance, config)

	// === 新架构自动初始化 ===
	if config.LocalExecution && config.EnableNewArch {
		log.Printf("[FuzzingIntegration]  检测到LocalExecution模式且EnableNewArch=true，自动初始化新架构")
		if err := integration.InitializeNewArchitecture(); err != nil {
			return nil, fmt.Errorf("failed to initialize new architecture: %w", err)
		}
	}

	return integration, nil
}

// NewFuzzingIntegrationWithDriver 构造支持自定义 Fuzz 驱动的集成实例（主要用于测试）
func NewFuzzingIntegrationWithDriver(driver FuzzingDriver, config *FuzzingConfig) *FuzzingIntegration {
	if config == nil {
		config = &FuzzingConfig{}
	}

	return &FuzzingIntegration{
		fuzzer:      driver,
		config:      config,
		resultCache: make(map[cacheKey][]*fuzzer.AttackParameterReport),
		outputPath:  config.OutputPath,
		threshold:   config.Threshold,
		enabled:     config.Enabled,
	}
}

// ConfigureInvariantCheck 配置不变量评估器
func (fi *FuzzingIntegration) ConfigureInvariantCheck(evaluator *invariants.Evaluator, cfg *InvariantCheckConfig) {
	if fi == nil {
		return
	}

	if cfg != nil {
		copied := *cfg
		fi.config.InvariantCheck = &copied
	} else {
		fi.config.InvariantCheck = nil
	}

	driver, ok := fi.fuzzer.(interface {
		SetInvariantEvaluator(fuzzer.InvariantEvaluator)
		EnableInvariantCheck(bool)
	})
	if !ok {
		log.Printf("[Fuzzing] 当前驱动不支持不变量检查接口，跳过配置")
		return
	}

	if evaluator == nil || cfg == nil || !cfg.Enabled {
		driver.SetInvariantEvaluator(&fuzzer.EmptyInvariantEvaluator{})
		driver.EnableInvariantCheck(false)
		log.Printf("[Fuzzing] 不变量检查已禁用")
		return
	}

	adapter := &invariantEvaluatorAdapter{evaluator: evaluator}
	driver.SetInvariantEvaluator(adapter)
	driver.EnableInvariantCheck(true)
	log.Printf("[Fuzzing] 不变量检查已启用 (ProjectID=%s)", cfg.ProjectID)
}

// ProcessTransaction 处理交易，触发fuzzing
func (fi *FuzzingIntegration) ProcessTransaction(
	ctx context.Context,
	tx *types.Transaction,
	blockNumber uint64,
	contractAddr common.Address,
	explicitHash common.Hash,
) ([]*FuzzingResult, []*fuzzer.AttackParameterReport, error) {
	if !fi.enabled {
		return nil, nil, nil
	}

	txHash := explicitHash
	if (txHash == common.Hash{}) {
		txHash = tx.Hash()
	}

	k := cacheKey{Tx: txHash, Addr: contractAddr}

	// 检查缓存
	fi.cacheMutex.RLock()
	if cachedReport, exists := fi.resultCache[k]; exists {
		fi.cacheMutex.RUnlock()
		return fi.convertToResults(cachedReport), cachedReport, nil
	}
	fi.cacheMutex.RUnlock()

	// 打印开始信息
	if fi.config.PrintRealtime {
		log.Printf("\n[Fuzzing] 开始分析交易: %s", txHash.Hex())
		log.Printf("[Fuzzing] 目标合约: %s", contractAddr.Hex())
		log.Printf("[Fuzzing] 区块高度: %d", blockNumber)
		log.Printf("[Fuzzing] 相似度阈值: %.2f", fi.threshold)
	}

	// 执行fuzzing，传入完整的交易对象以避免重新查询
	startTime := time.Now()
	reports, err := fi.fuzzer.FuzzTransaction(ctx, txHash, contractAddr, blockNumber, tx)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzzing failed: %w", err)
	}
	duration := time.Since(startTime)

	// 缓存结果（按交易 + 合约维度）
	fi.cacheMutex.Lock()
	fi.resultCache[k] = reports
	fi.cacheMutex.Unlock()

	// 实时打印结果
	if fi.config.PrintRealtime {
		fi.printRealtimeResults(reports, duration)
	}

	// 保存高相似度参数
	if fi.config.SaveHighSimilarity {
		fi.saveHighSimilarityParamsBatch(reports, txHash)
	}

	return fi.convertToResults(reports), reports, nil
}

// printRealtimeResults 实时打印fuzzing结果
func (fi *FuzzingIntegration) printRealtimeResults(reports []*fuzzer.AttackParameterReport, duration time.Duration) {
	displayIdx := 0
	suppressed := 0
	for _, report := range reports {
		if report == nil {
			continue
		}
		if report.DerivedFromChained {
			suppressed++
			continue
		}
		displayIdx++
		fmt.Println("\n" + strings.Repeat("=", 80))
		fmt.Printf("                     Fuzzing 分析结果 #%d\n", displayIdx)
		fmt.Println(strings.Repeat("=", 80))

		avgSim := report.AverageSimilarity
		maxSim := report.MaxSimilarity
		minSim := report.MinSimilarity

		fmt.Printf("\n 统计信息:\n")
		fmt.Printf("   总测试组合数: %d\n", report.TotalCombinations)
		fmt.Printf("   有效组合数: %d\n", report.ValidCombinations)
		fmt.Printf("   平均相似度: %.4f\n", avgSim)
		fmt.Printf("   最高相似度: %.4f\n", maxSim)
		fmt.Printf("   最低相似度: %.4f\n", minSim)
		if report.RawStatsAvailable {
			fmt.Printf("   校正平均相似度: %.4f\n", report.RawAverageSimilarity)
			fmt.Printf("   校正最高相似度: %.4f\n", report.RawMaxSimilarity)
			fmt.Printf("   校正最低相似度: %.4f\n", report.RawMinSimilarity)
		}
		fmt.Printf("   执行时间: %v\n", duration)

		if len(report.ValidParameters) > 0 {
			fmt.Printf("\n 找到 %d 个有效参数组:\n", len(report.ValidParameters))
			fmt.Println(strings.Repeat("-", 60))

			for i, param := range report.ValidParameters {
				if i >= 10 {
					fmt.Printf("\n   ... 还有 %d 个参数未显示 ...\n", len(report.ValidParameters)-10)
					break
				}

				fmt.Printf("\n   参数 #%d (类型: %s):\n", param.ParamIndex, param.ParamType)

				if param.IsRange {
					fmt.Printf("      范围: [%s, %s]\n", param.RangeMin, param.RangeMax)
				} else {
					if len(param.SingleValues) <= 5 {
						fmt.Printf("      值: %v\n", param.SingleValues)
					} else {
						fmt.Printf("      值: %v... (%d个)\n", param.SingleValues[:5], len(param.SingleValues))
					}
				}
				fmt.Printf("      出现次数: %d\n", param.OccurrenceCount)
			}
		}

		// 高相似度路径信息（按保存阈值过滤）
		saveThreshold := fi.config.MinSimilarity
		if fi.config.Threshold > saveThreshold {
			saveThreshold = fi.config.Threshold
		}
		highSimCount := 0
		for _, r := range report.HighSimilarityResults {
			if r.Similarity >= saveThreshold {
				highSimCount++
			}
		}
		if highSimCount > 0 {
			fmt.Printf("\n 高相似度路径 (>= %.2f, 按重叠相似度): %d 个\n", saveThreshold, highSimCount)
		}

		fmt.Println("\n" + strings.Repeat("=", 80))
	}

	if suppressed > 0 {
		fmt.Printf("\n(已省略 %d 个连锁复用的分析结果)\n", suppressed)
	}
}

// saveHighSimilarityParamsBatch 保存高相似度参数
func (fi *FuzzingIntegration) saveHighSimilarityParamsBatch(reports []*fuzzer.AttackParameterReport, txHash common.Hash) {
	// 保存：统计信息 + 参数摘要 + 高相似度结果样本（按保存阈值过滤）
	saveThreshold := fi.config.MinSimilarity
	if fi.config.Threshold > saveThreshold {
		saveThreshold = fi.config.Threshold
	}

	for _, report := range reports {
		if report == nil {
			continue
		}

		var selected []fuzzer.PublicResult
		for _, r := range report.HighSimilarityResults {
			if r.Similarity >= saveThreshold {
				selected = append(selected, r)
			}
		}

		if len(selected) == 0 {
			continue
		}

		timestamp := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("high_sim_%s_%s_%s.json", timestamp, txHash.Hex()[:8], strings.TrimPrefix(report.FunctionSig, "0x"))
		filepath := filepath.Join(fi.outputPath, filename)

		validParams := report.ValidParameters
		if validParams == nil {
			validParams = []fuzzer.ParameterSummary{}
		}

		saveData := struct {
			TxHash          string                    `json:"tx_hash"`
			ContractAddress string                    `json:"contract_address"`
			Timestamp       time.Time                 `json:"timestamp"`
			TotalHighSim    int                       `json:"total_high_similarity"`
			MinSimilarity   float64                   `json:"min_similarity_threshold"`
			ValidParameters []fuzzer.ParameterSummary `json:"valid_parameters"`
			HighSimResults  []fuzzer.PublicResult     `json:"high_similarity_results"`
		}{
			TxHash:          txHash.Hex(),
			ContractAddress: report.ContractAddress.Hex(),
			Timestamp:       time.Now(),
			TotalHighSim:    len(selected),
			MinSimilarity:   saveThreshold,
			ValidParameters: validParams,
			HighSimResults:  selected,
		}

		data, err := json.MarshalIndent(saveData, "", "  ")
		if err != nil {
			log.Printf("[Fuzzing] 保存高相似度参数失败: %v", err)
			continue
		}

		if err := os.WriteFile(filepath, data, 0644); err != nil {
			log.Printf("[Fuzzing] 写入文件失败: %v", err)
			continue
		}

		log.Printf("\n 高相似度参数已保存到: %s", filepath)
	}
}

// SimplifiedResult 简化的结果结构
type SimplifiedResult struct {
	Similarity float64                 `json:"similarity"`
	Parameters []fuzzer.ParameterValue `json:"parameters"`
	GasUsed    uint64                  `json:"gas_used"`
	Success    bool                    `json:"success"`
}

// simplifyResults 简化结果以便保存
func (fi *FuzzingIntegration) simplifyResults(results []fuzzer.FuzzingResult) []SimplifiedResult {
	simplified := make([]SimplifiedResult, 0, len(results))
	for _, r := range results {
		simplified = append(simplified, SimplifiedResult{
			Similarity: r.Similarity,
			Parameters: r.Parameters,
			GasUsed:    r.GasUsed,
			Success:    r.Success,
		})
	}
	return simplified
}

// FuzzingResult 模糊测试结果
type FuzzingResult struct {
	Success           bool
	ValidCombinations int
	TotalCombinations int
	MaxSimilarity     float64
	ValidParameters   []fuzzer.ParameterSummary
}

// convertToResult 转换为简化结果
func (fi *FuzzingIntegration) convertToResult(report *fuzzer.AttackParameterReport) *FuzzingResult {
	if report == nil {
		return nil
	}

	return &FuzzingResult{
		Success:           report.ValidCombinations > 0,
		ValidCombinations: report.ValidCombinations,
		TotalCombinations: report.TotalCombinations,
		MaxSimilarity:     report.MaxSimilarity,
		ValidParameters:   report.ValidParameters,
	}
}

// convertToResults 批量转换，保持与报告顺序一致
func (fi *FuzzingIntegration) convertToResults(reports []*fuzzer.AttackParameterReport) []*FuzzingResult {
	out := make([]*FuzzingResult, 0, len(reports))
	for _, r := range reports {
		out = append(out, fi.convertToResult(r))
	}
	return out
}

// SetEnabled 设置是否启用
func (fi *FuzzingIntegration) SetEnabled(enabled bool) {
	fi.enabled = enabled
}

// IsEnabled 检查是否启用
func (fi *FuzzingIntegration) IsEnabled() bool {
	return fi.enabled
}

// ClearCache 清空缓存
func (fi *FuzzingIntegration) ClearCache() {
	fi.cacheMutex.Lock()
	defer fi.cacheMutex.Unlock()
	fi.resultCache = make(map[cacheKey][]*fuzzer.AttackParameterReport)
}

// GetConfig 获取配置
func (fi *FuzzingIntegration) GetConfig() *FuzzingConfig {
	return fi.config
}

// 使用标准库 strings 包，无需自定义实现。

// invariantEvaluatorAdapter 将 invariants.Evaluator 适配为 fuzzer.InvariantEvaluator
type invariantEvaluatorAdapter struct {
	evaluator *invariants.Evaluator
}

func (a *invariantEvaluatorAdapter) EvaluateTransaction(contracts []common.Address, state interface{}) []interface{} {
	if a == nil || a.evaluator == nil {
		return nil
	}

	chainState, ok := state.(*invariants.ChainState)
	if !ok || chainState == nil {
		return nil
	}

	violations := a.evaluator.EvaluateTransaction(contracts, chainState)
	if len(violations) == 0 {
		return nil
	}

	results := make([]interface{}, len(violations))
	for i := range violations {
		results[i] = violations[i]
	}
	return results
}

// ========== 新架构初始化方法 ==========

// InitializeNewArchitecture 初始化新架构组件（registry、poolManager、mutationEngine）
// 仅在 LocalExecution 且 EnableNewArch 时调用
func (fi *FuzzingIntegration) InitializeNewArchitecture() error {
	if !fi.config.LocalExecution || !fi.config.EnableNewArch {
		log.Printf("[FuzzingIntegration] 跳过新架构初始化 (LocalExecution=%v, EnableNewArch=%v)",
			fi.config.LocalExecution, fi.config.EnableNewArch)
		return nil
	}

	log.Printf("[FuzzingIntegration]  开始初始化新架构...")

	// 类型断言：确保fuzzer实现了InitializeArchitecture方法
	type ArchitectureInitializer interface {
		InitializeArchitecture(poolSize int) error
		RegisterProtectedContract(contractAddr common.Address, contractABI interface{}) error
		InitializeParamPools(poolSize int) error
	}

	fuzzerWithArch, ok := fi.fuzzer.(ArchitectureInitializer)
	if !ok {
		return fmt.Errorf("fuzzer does not implement architecture initialization interface")
	}

	// 1. 初始化架构组件（registry、poolManager、mutationEngine）
	poolSize := fi.config.PoolSize
	if poolSize <= 0 {
		poolSize = 100 // 默认池大小
	}

	if err := fuzzerWithArch.InitializeArchitecture(poolSize); err != nil {
		return fmt.Errorf("failed to initialize architecture: %w", err)
	}
	log.Printf("[FuzzingIntegration]  架构组件初始化完成 (poolSize=%d)", poolSize)

	// 2. 注册所有受保护合约
	if len(fi.config.ProtectedContracts) == 0 {
		log.Printf("[FuzzingIntegration]  未配置受保护合约，跳过注册")
		return nil
	}

	log.Printf("[FuzzingIntegration]  开始注册 %d 个受保护合约...", len(fi.config.ProtectedContracts))
	for i, cfg := range fi.config.ProtectedContracts {
		if err := fi.registerProtectedContract(fuzzerWithArch, cfg); err != nil {
			log.Printf("[FuzzingIntegration]  注册合约 #%d (%s) 失败: %v",
				i+1, cfg.Address.Hex(), err)
			continue
		}
		log.Printf("[FuzzingIntegration]  注册合约 #%d: %s", i+1, cfg.Address.Hex())
	}

	// 3. 预热参数池
	log.Printf("[FuzzingIntegration]  开始预热参数池...")
	if err := fuzzerWithArch.InitializeParamPools(poolSize); err != nil {
		return fmt.Errorf("failed to initialize param pools: %w", err)
	}
	log.Printf("[FuzzingIntegration]  参数池预热完成")

	log.Printf("[FuzzingIntegration]  新架构初始化成功")
	return nil
}

// registerProtectedContract 注册单个受保护合约
func (fi *FuzzingIntegration) registerProtectedContract(
	fuzzerWithArch interface {
		RegisterProtectedContract(contractAddr common.Address, contractABI interface{}) error
	},
	cfg ProtectedContractConfig,
) error {
	// 解析ABI
	var parsedABI *abi.ABI
	var err error

	if cfg.ABIJson != "" {
		// 优先使用JSON字符串
		parsedABI, err = parseABIFromJSON(cfg.ABIJson)
		if err != nil {
			return fmt.Errorf("failed to parse ABI from JSON: %w", err)
		}
	} else if cfg.ABIPath != "" {
		// 回退到文件路径
		parsedABI, err = loadABIFromFile(cfg.ABIPath)
		if err != nil {
			return fmt.Errorf("failed to load ABI from file %s: %w", cfg.ABIPath, err)
		}
	} else {
		return fmt.Errorf("neither ABIJson nor ABIPath provided for contract %s", cfg.Address.Hex())
	}

	// 注册到fuzzer
	return fuzzerWithArch.RegisterProtectedContract(cfg.Address, parsedABI)
}

// parseABIFromJSON 从JSON字符串解析ABI
func parseABIFromJSON(abiJSON string) (*abi.ABI, error) {
	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// loadABIFromFile 从文件加载ABI
func loadABIFromFile(abiPath string) (*abi.ABI, error) {
	file, err := os.Open(abiPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open ABI file: %w", err)
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read ABI file: %w", err)
	}

	return parseABIFromJSON(string(data))
}
