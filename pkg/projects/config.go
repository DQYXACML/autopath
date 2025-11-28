package projects

// ProjectConfig 定义监控器加载的完整项目配置
type ProjectConfig struct {
	ProjectID        string                 `json:"project_id"`
	Name             string                 `json:"name"`
	ChainID          int                    `json:"chain_id"`
	Contracts        []string               `json:"contracts"`
	Invariants       []interface{}          `json:"invariants"`
	FuzzingConfig    *FuzzingConfigJSON     `json:"fuzzing_config"`
	AlertConfig      map[string]interface{} `json:"alert_config"`
	MonitoringConfig map[string]interface{} `json:"monitoring_config"`
}

// FuzzingConfigJSON 表示 fuzzer 相关的 JSON 配置
type FuzzingConfigJSON struct {
	Enabled              bool                `json:"enabled"`
	Threshold            float64             `json:"threshold"`
	MaxVariations        int                 `json:"max_variations"`
	Workers              int                 `json:"workers"`
	TimeoutSeconds       int                 `json:"timeout_seconds"`
	OutputPath           string              `json:"output_path"`
	AutoTrigger          bool                `json:"auto_trigger"`
	TriggerContractTypes []string            `json:"trigger_contract_types"`
	MinSimilarity        float64             `json:"min_similarity"`
	SaveHighSimilarity   bool                `json:"save_high_similarity"`
	PrintRealtime        bool                `json:"print_realtime"`
	ProjectID            string              `json:"project_id"`
	InvariantCheck       *InvariantCheckJSON `json:"invariant_check"`

	// 🆕 Unlimited fuzzing模式配置
	UnlimitedMode     bool    `json:"unlimited_mode"`       // 无限制fuzzing模式
	TargetSimilarity  float64 `json:"target_similarity"`    // 目标相似度阈值
	MaxHighSimResults int     `json:"max_high_sim_results"` // 最大高相似度结果数

	// 🆕 Seed-driven fuzzing配置
	SeedConfig *SeedConfigJSON `json:"seed_config"` // 种子配置

	// Entry Call 限制
	EntryCallProtectedOnly bool `json:"entry_call_protected_only"`

	// 🆕 本地执行模式
	LocalExecution bool `json:"local_execution"` // 使用本地EVM执行替代RPC调用
}

// InvariantCheckJSON 不变量检查配置
type InvariantCheckJSON struct {
	Enabled    bool   `json:"enabled"`
	ProjectID  string `json:"project_id"`
	ConfigPath string `json:"config_path"`
}

// SeedConfigJSON 种子驱动fuzzing配置（对应fuzzer.SeedConfig）
type SeedConfigJSON struct {
	Enabled             bool                                   `json:"enabled"`
	AttackSeeds         map[string][]interface{}               `json:"attack_seeds"`      // JSON中使用字符串key
	ConstraintRanges    map[string]map[string]*ConstraintRange `json:"constraint_ranges"` // 函数名 → 参数索引 → 约束范围
	AdaptiveConfig      *AdaptiveConfigJSON                    `json:"adaptive_config"`   // Layer 2配置
	RangeConfig         *RangeConfigJSON                       `json:"range_config"`
	Weights             *WeightsConfigJSON                     `json:"weights"`
	RangeMutationConfig *RangeMutationConfigJSON               `json:"range_mutation_config"`
}

// ConstraintRange 约束范围（从constraint_rules_v2.json提取）
type ConstraintRange struct {
	Type            string   `json:"type"`
	SafeThreshold   string   `json:"safe_threshold"`
	DangerThreshold string   `json:"danger_threshold"`
	AttackValues    []string `json:"attack_values"`
	Range           *struct {
		Min string `json:"min"`
		Max string `json:"max"`
	} `json:"range"`
	MutationStrategy string  `json:"mutation_strategy"`
	Confidence       float64 `json:"confidence"`
	ValueExpr        string  `json:"value_expr"`
	StateSlot        string  `json:"state_slot"`
}

// AdaptiveConfigJSON 自适应范围配置
type AdaptiveConfigJSON struct {
	Enabled       bool `json:"enabled"`
	MaxIterations int  `json:"max_iterations"`
	UnlimitedMode bool `json:"unlimited_mode"`
}

// RangeConfigJSON 种子变异范围配置
type RangeConfigJSON struct {
	NumericRangePercent  []int    `json:"numeric_range_percent"`
	AddressMutationTypes []string `json:"address_mutation_types"`
	BoundaryExploration  bool     `json:"boundary_exploration"`
}

// WeightsConfigJSON 种子权重配置
type WeightsConfigJSON struct {
	SeedBased float64 `json:"seed_based"`
	Random    float64 `json:"random"`
	Boundary  float64 `json:"boundary"`
}

// RangeMutationConfigJSON 范围变异配置
type RangeMutationConfigJSON struct {
	FocusPercentiles       []int   `json:"focus_percentiles"`
	BoundaryExploration    bool    `json:"boundary_exploration"`
	StepCount              int     `json:"step_count"`
	RandomWithinRangeRatio float64 `json:"random_within_range_ratio"`
}
