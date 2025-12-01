package fuzzer

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"autopath/pkg/simulator"

	"github.com/ethereum/go-ethereum/common"
)

// Parameter 参数信息
type Parameter struct {
	Index    int         // 参数在calldata中的索引
	Name     string      // 参数名称（如果有ABI）
	Type     string      // Solidity类型 (uint256, address, bool, bytes, etc.)
	Value    interface{} // 参数值
	Size     int         // 对于固定大小类型(bytes32等)
	IsArray  bool        // 是否为数组类型
	ArrayLen int         // 数组长度（对于固定长度数组）
}

// FuzzingResult 模糊测试结果
type FuzzingResult struct {
	CallData            []byte                 // 完整的calldata
	Parameters          []ParameterValue       // 参数值列表
	Similarity          float64                // 与原始路径的相似度
	JumpDests           []uint64               // JUMPDEST序列
	GasUsed             uint64                 // Gas消耗
	Success             bool                   // 执行是否成功
	Error               string                 // 错误信息（如果有）
	InvariantViolations interface{}            // 不变量违规记录 (动态类型,避免循环依赖)
	StateChanges        map[string]StateChange // 状态变更记录
}

// ParameterValue 参数值描述
type ParameterValue struct {
	Index    int         // 参数索引
	Type     string      // 参数类型
	Name     string      // 参数名称
	Value    interface{} // 具体值（单个值）
	IsRange  bool        // 是否为范围
	RangeMin interface{} // 范围最小值
	RangeMax interface{} // 范围最大值
}

// AttackParameterReport 攻击参数报告
type AttackParameterReport struct {
	// 基本信息
	ContractAddress common.Address `json:"contract_address"`
	FunctionSig     string         `json:"function_signature"`
	FunctionName    string         `json:"function_name,omitempty"`
	Timestamp       time.Time      `json:"timestamp"`
	OriginalTxHash  common.Hash    `json:"original_tx_hash"`
	BlockNumber     uint64         `json:"block_number"`

	// 有效参数组合
	ValidParameters []ParameterSummary `json:"valid_parameters"`
	ExpressionRules []ExpressionRule   `json:"expression_rules,omitempty"`

	// 统计信息
	TotalCombinations int     `json:"total_combinations_tested"`
	ValidCombinations int     `json:"valid_combinations_found"`
	AverageSimilarity float64 `json:"average_similarity"`
	MaxSimilarity     float64 `json:"max_similarity"`
	MinSimilarity     float64 `json:"min_similarity"`
	ExecutionTimeMs   int64   `json:"execution_time_ms"`

	// 公开的高相似度结果样本（为便于序列化，参数值已转换为字符串）
	HighSimilarityResults []PublicResult `json:"high_similarity_results,omitempty"`

	// 不变量检查相关（新增）
	HasInvariantCheck bool `json:"has_invariant_check"` // 标识是否经过不变量检查
	ViolationCount    int  `json:"violation_count"`     // 违规次数统计

	// 约束规则（由高相似样本生成）
	ConstraintRule *ConstraintRule `json:"constraint_rule,omitempty"`
}

// ParameterSummary 参数摘要
type ParameterSummary struct {
	ParamIndex int    `json:"param_index"`
	ParamType  string `json:"param_type"`
	ParamName  string `json:"param_name,omitempty"`

	// 对于离散值
	SingleValues []string `json:"single_values,omitempty"`

	// 对于范围值（数值类型）
	IsRange  bool   `json:"is_range"`
	RangeMin string `json:"range_min,omitempty"`
	RangeMax string `json:"range_max,omitempty"`

	// 统计
	OccurrenceCount int `json:"occurrence_count"`
}

// PublicParamValue 可序列化的参数值（将 interface{} 值转为字符串）
type PublicParamValue struct {
	Index    int    `json:"index"`
	Type     string `json:"type"`
	Name     string `json:"name,omitempty"`
	Value    string `json:"value,omitempty"`
	IsRange  bool   `json:"is_range"`
	RangeMin string `json:"range_min,omitempty"`
	RangeMax string `json:"range_max,omitempty"`
}

// PublicResult 可序列化的结果摘要
type PublicResult struct {
	Similarity float64            `json:"similarity"`
	Parameters []PublicParamValue `json:"parameters"`
	GasUsed    uint64             `json:"gas_used"`
	Success    bool               `json:"success"`
}

// ParamConstraint 参数约束
type ParamConstraint struct {
	Index    int      `json:"index"`
	Type     string   `json:"type"`
	IsRange  bool     `json:"is_range"`
	RangeMin string   `json:"range_min,omitempty"`
	RangeMax string   `json:"range_max,omitempty"`
	Values   []string `json:"values,omitempty"` // 离散值
}

// StateConstraint 状态约束（针对受保护合约）
type StateConstraint struct {
	Slot   string   `json:"slot"`
	Values []string `json:"values,omitempty"`
}

// ConstraintRule 由高相似样本生成的拦截规则
type ConstraintRule struct {
	ContractAddress   common.Address    `json:"contract_address"`
	FunctionSelector  string            `json:"function_selector"`
	SampleCount       int               `json:"sample_count"`
	ParamConstraints  []ParamConstraint `json:"param_constraints,omitempty"`
	StateConstraints  []StateConstraint `json:"state_constraints,omitempty"`
	SimilarityTrigger float64           `json:"similarity_trigger"`
	GeneratedAt       time.Time         `json:"generated_at"`
}

// LinearTerm 表示线性不等式中的单个项
type LinearTerm struct {
	Kind       string `json:"kind"`                  // param/state
	ParamIndex int    `json:"param_index,omitempty"` // 当kind=param时有效
	Slot       string `json:"slot,omitempty"`        // 当kind=state时有效
	Coeff      string `json:"coeff"`                 // 系数，十六进制
}

// ExpressionRule 基于样本生成的乘法/线性约束
type ExpressionRule struct {
	Type         string         `json:"type"` // ratio/linear
	Contract     common.Address `json:"contract"`
	Selector     string         `json:"selector"`
	Terms        []LinearTerm   `json:"terms"`          // 左侧线性组合项
	Threshold    string         `json:"threshold"`      // 右侧阈值（十六进制）
	Scale        string         `json:"scale"`          // 精度放大倍数（十六进制）
	Confidence   float64        `json:"confidence"`     // 样本覆盖度
	SampleCount  int            `json:"sample_count"`   // 样本数
	MinMarginHex string         `json:"min_margin_hex"` // 样本中最小剩余（便于调试）
	GeneratedAt  time.Time      `json:"generated_at"`
	Strategy     string         `json:"strategy,omitempty"` // ratio/linear 具体描述
}

// ValueToString 将参数值转为字符串，便于 JSON 输出
func ValueToString(value interface{}) string {
	if value == nil {
		return "null"
	}
	switch v := value.(type) {
	case *big.Int:
		if v.BitLen() > 64 {
			return fmt.Sprintf("0x%s", v.Text(16))
		}
		return v.String()
	case common.Address:
		return v.Hex()
	case bool:
		return fmt.Sprintf("%t", v)
	case []byte:
		if len(v) <= 32 {
			return "0x" + hex.EncodeToString(v)
		}
		return fmt.Sprintf("0x%s... (%d bytes)", hex.EncodeToString(v[:16]), len(v))
	case string:
		if len(v) > 100 {
			return fmt.Sprintf("%s... (%d chars)", v[:100], len(v))
		}
		return v
	case []interface{}:
		return fmt.Sprintf("[%d items]", len(v))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// ToPublicParamValue 转换为可序列化的参数值
func ToPublicParamValue(p ParameterValue) PublicParamValue {
	pp := PublicParamValue{
		Index:   p.Index,
		Type:    p.Type,
		Name:    p.Name,
		IsRange: p.IsRange,
	}
	if p.IsRange {
		pp.RangeMin = ValueToString(p.RangeMin)
		pp.RangeMax = ValueToString(p.RangeMax)
	} else {
		pp.Value = ValueToString(p.Value)
	}
	return pp
}

// ToPublicResults 将内部结果转换为可序列化的结果摘要
func ToPublicResults(results []FuzzingResult) []PublicResult {
	pubs := make([]PublicResult, 0, len(results))
	for _, r := range results {
		pvals := make([]PublicParamValue, 0, len(r.Parameters))
		for _, pv := range r.Parameters {
			pvals = append(pvals, ToPublicParamValue(pv))
		}
		pubs = append(pubs, PublicResult{
			Similarity: r.Similarity,
			Parameters: pvals,
			GasUsed:    r.GasUsed,
			Success:    r.Success,
		})
	}
	return pubs
}

// Config 模糊测试配置
type Config struct {
	// RPC配置
	RPCURL string `yaml:"rpc_url"`

	// 项目标识（用于定位attack_state.json等外部资料）
	ProjectID string `yaml:"project_id"`

	// 相似度阈值
	Threshold float64 `yaml:"jumpdest_similarity_threshold"`

	// 性能配置
	MaxVariations int           `yaml:"max_variations_per_param"`
	Workers       int           `yaml:"concurrent_workers"`
	Timeout       time.Duration `yaml:"timeout_per_simulation"`

	// 参数生成策略
	Strategies StrategyConfig `yaml:"strategies"`

	// 输出配置
	Output OutputConfig `yaml:"output"`

	// 不变量检查配置（新增）
	InvariantCheck InvariantCheckConfig `yaml:"invariant_check"`

	// 种子驱动模糊测试配置（新增）
	SeedConfig *SeedConfig `yaml:"seed_config"`

	// 🆕 无限制fuzzing模式配置
	TargetSimilarity  float64 `yaml:"target_similarity"`    // 目标相似度阈值（如0.95），达到后可停止
	MaxHighSimResults int     `yaml:"max_high_sim_results"` // 找到N个高相似度结果后停止（0=不限制）
	UnlimitedMode     bool    `yaml:"unlimited_mode"`       // 无限制模式：忽略迭代次数限制

	// Entry Call 限制
	EntryCallProtectedOnly bool `yaml:"entry_call_protected_only"` // 仅对受保护合约启用Entry模式

	// 🆕 本地执行模式配置
	LocalExecution bool `yaml:"local_execution"` // 使用本地EVM执行替代RPC调用

	// 🆕 新架构开关（配合本地执行）
	EnableNewArch bool `yaml:"enable_new_arch" json:"enable_new_arch"`
}

// InvariantCheckConfig 不变量检查配置
type InvariantCheckConfig struct {
	Enabled              bool   `yaml:"enabled"`                 // 是否启用
	ProjectID            string `yaml:"project_id"`              // 项目ID
	ConfigPath           string `yaml:"config_path"`             // 不变量配置文件路径
	SkipOnHighSimilarity *bool  `yaml:"skip_on_high_similarity"` // 高相似度样本是否跳过不变量评估（默认true）
}

// StrategyConfig 参数生成策略配置
type StrategyConfig struct {
	Integers  IntegerStrategy `yaml:"integers"`
	Addresses AddressStrategy `yaml:"addresses"`
	Bytes     BytesStrategy   `yaml:"bytes"`
	Arrays    ArrayStrategy   `yaml:"arrays"`
}

// IntegerStrategy 整数生成策略
type IntegerStrategy struct {
	IncludeBoundaries   bool  `yaml:"include_boundaries"`
	IncludePercentages  []int `yaml:"include_percentages"`
	IncludeCommonValues bool  `yaml:"include_common_values"`
	BitFlipping         bool  `yaml:"bit_flipping"`
}

// AddressStrategy 地址生成策略
type AddressStrategy struct {
	IncludePrecompiles bool `yaml:"include_precompiles"`
	IncludeZero        bool `yaml:"include_zero"`
	IncludeRandom      bool `yaml:"include_random"`
	RandomCount        int  `yaml:"random_count"`
}

// BytesStrategy 字节生成策略
type BytesStrategy struct {
	IncludeEmpty    bool `yaml:"include_empty"`
	IncludePatterns bool `yaml:"include_patterns"`
	MaxRandomLength int  `yaml:"max_random_length"`
}

// ArrayStrategy 数组生成策略
type ArrayStrategy struct {
	TestLengths []int `yaml:"test_lengths"`
	MaxElements int   `yaml:"max_elements"`
}

// OutputConfig 输出配置
type OutputConfig struct {
	Format string `yaml:"format"` // json, csv, html
	Path   string `yaml:"path"`
}

// ParsedCallData 解析后的calldata
type ParsedCallData struct {
	Selector   []byte      // 4字节函数选择器
	Parameters []Parameter // 解析出的参数列表
	Raw        []byte      // 原始calldata
}

// SimulationRequest 模拟请求
type SimulationRequest struct {
	From          common.Address
	To            common.Address
	CallData      []byte
	Value         *big.Int
	BlockNumber   uint64
	Timeout       time.Duration
	StateOverride simulator.StateOverride
}

// SimulationResult 模拟结果
type SimulationResult struct {
	Success           bool
	JumpDests         []uint64
	ContractJumpDests []ContractJumpDest
	GasUsed           uint64
	ReturnData        []byte
	Error             error
	StateChanges      map[string]StateChange // 状态变更记录（新增）
}

// StateChange 状态变化
type StateChange struct {
	BalanceBefore  string                   `json:"balance_before"`
	BalanceAfter   string                   `json:"balance_after"`
	StorageChanges map[string]StorageUpdate `json:"storage_changes"`
}

// StorageUpdate 存储槽位的前后状态
type StorageUpdate struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// FuzzerStats 模糊测试统计
type FuzzerStats struct {
	StartTime          time.Time
	EndTime            time.Time
	TotalCombinations  int
	TestedCombinations int
	ValidCombinations  int
	FailedSimulations  int
	AverageSimTime     time.Duration
}

// ========== Layer 2: 自适应范围缩放数据结构 ==========

// AdaptiveRangeConfig 自适应范围配置
type AdaptiveRangeConfig struct {
	Enabled         bool             `yaml:"enabled" json:"enabled"`                   // 是否启用自适应
	MaxIterations   int              `yaml:"max_iterations" json:"max_iterations"`     // 最大迭代轮数(建议3-5)
	ConvergenceRate float64          `yaml:"convergence_rate" json:"convergence_rate"` // 收敛阈值(默认0.02)
	RangeStrategies map[string][]int `yaml:"range_strategies" json:"range_strategies"` // 分层范围策略
	UnlimitedMode   bool             `yaml:"unlimited_mode" json:"unlimited_mode"`     // 🆕 无限制模式：忽略迭代次数限制

	// Layer 2: 高级配置（可选）
	ZoneThreshold      float64 `yaml:"zone_threshold" json:"zone_threshold"`             // 高相似度区域识别阈值(默认0.75)
	ZoneGapPercent     float64 `yaml:"zone_gap_percent" json:"zone_gap_percent"`         // 区域合并间隔百分比(默认0.10)
	ZoneGapAbsolute    int64   `yaml:"zone_gap_absolute" json:"zone_gap_absolute"`       // 区域合并间隔绝对值(默认1000)
	HighSimThreshold   float64 `yaml:"high_sim_threshold" json:"high_sim_threshold"`     // 高相似度策略阈值(默认0.8)
	MediumSimThreshold float64 `yaml:"medium_sim_threshold" json:"medium_sim_threshold"` // 中等相似度策略阈值(默认0.6)
}

// SimilarityFeedback 相似度反馈数据
type SimilarityFeedback struct {
	ParamIndex   int                `json:"param_index"`    // 参数索引
	ValueToSim   map[string]float64 `json:"value_to_sim"`   // 参数值 → 相似度映射(热力图)
	HighSimZones []ValueRange       `json:"high_sim_zones"` // 高相似度区域
	AvgSim       float64            `json:"avg_similarity"` // 平均相似度
}

// ValueRange 值范围
type ValueRange struct {
	Min        *big.Int `json:"min"`         // 范围最小值
	Max        *big.Int `json:"max"`         // 范围最大值
	AvgSim     float64  `json:"avg_sim"`     // 平均相似度
	SampleSize int      `json:"sample_size"` // 样本数量
}
