package symbolic

import (
	"math/big"
	"time"
)

// ==================== 配置结构 ====================

// SymbolicConfig 符号执行配置 (Layer 3)
// 所有参数均可配置,无硬编码
type SymbolicConfig struct {
	Enabled        bool              `yaml:"enabled" json:"enabled"`
	Mode           string            `yaml:"mode" json:"mode"`                       // "lightweight", "z3", "hybrid"
	MaxConstraints int               `yaml:"max_constraints" json:"max_constraints"` // 最大约束数量
	SolverTimeout  string            `yaml:"solver_timeout" json:"solver_timeout"`   // 超时时间字符串 "3s"
	Extraction     ExtractionConfig  `yaml:"extraction" json:"extraction"`           // 约束提取配置
	Solver         SolverConfig      `yaml:"solver" json:"solver"`                   // 求解器配置
	Integration    IntegrationConfig `yaml:"integration" json:"integration"`         // 集成配置
}

// ExtractionConfig 约束提取配置
type ExtractionConfig struct {
	MaxTraceDepth int      `yaml:"max_trace_depth" json:"max_trace_depth"` // 最大trace深度
	FocusOpcodes  []string `yaml:"focus_opcodes" json:"focus_opcodes"`     // 关注的操作码
	IgnoreLoops   bool     `yaml:"ignore_loops" json:"ignore_loops"`       // 是否忽略循环
	MaxBranches   int      `yaml:"max_branches" json:"max_branches"`       // 最大分支数
}

// SolverConfig 求解器配置
type SolverConfig struct {
	Strategy     string `yaml:"strategy" json:"strategy"`           // "local", "z3", "hybrid"
	MaxSolutions int    `yaml:"max_solutions" json:"max_solutions"` // 最大解数量
	UseCache     bool   `yaml:"use_cache" json:"use_cache"`         // 是否使用缓存
	CacheSize    int    `yaml:"cache_size" json:"cache_size"`       // 缓存大小
	Parallel     bool   `yaml:"parallel" json:"parallel"`           // 是否并行求解
	Workers      int    `yaml:"workers" json:"workers"`             // 并行工作器数量
}

// IntegrationConfig 与Layer1/2集成配置
type IntegrationConfig struct {
	Priority            string  `yaml:"priority" json:"priority"`                         // "high", "medium", "low"
	MergeWithAdaptive   bool    `yaml:"merge_with_adaptive" json:"merge_with_adaptive"`   // 是否与自适应合并
	ConfidenceThreshold float64 `yaml:"confidence_threshold" json:"confidence_threshold"` // 置信度阈值
	MaxSymbolicSeeds    int     `yaml:"max_symbolic_seeds" json:"max_symbolic_seeds"`     // 最大符号种子数
}

// ==================== 约束类型 ====================

// ConstraintType 约束类型枚举
type ConstraintType int

const (
	ConstraintLT     ConstraintType = iota // 小于 (<)
	ConstraintLE                           // 小于等于 (<=)
	ConstraintGT                           // 大于 (>)
	ConstraintGE                           // 大于等于 (>=)
	ConstraintEQ                           // 等于 (==)
	ConstraintNEQ                          // 不等于 (!=)
	ConstraintRANGE                        // 范围 (min <= x <= max)
	ConstraintMOD                          // 模运算约束
	ConstraintAND                          // 位与约束
	ConstraintOR                           // 位或约束
	ConstraintMASK                         // 掩码约束
)

// String 返回约束类型的字符串表示
func (ct ConstraintType) String() string {
	names := []string{
		"LT", "LE", "GT", "GE", "EQ", "NEQ",
		"RANGE", "MOD", "AND", "OR", "MASK",
	}
	if int(ct) < len(names) {
		return names[ct]
	}
	return "UNKNOWN"
}

// ==================== 约束表示 ====================

// PathConstraint 路径约束
// 表示从EVM trace中提取的单个约束条件
type PathConstraint struct {
	ID             string         `json:"id"`               // 约束唯一标识
	ParamIndex     int            `json:"param_index"`      // 参数索引 (0-based)
	Type           ConstraintType `json:"type"`             // 约束类型
	Value          *big.Int       `json:"value"`            // 约束值 (用于LT/GT/EQ等)
	MinValue       *big.Int       `json:"min_value"`        // 范围最小值 (用于RANGE)
	MaxValue       *big.Int       `json:"max_value"`        // 范围最大值 (用于RANGE)
	Confidence     float64        `json:"confidence"`       // 置信度 [0, 1]
	Source         ConstraintSource `json:"source"`         // 约束来源
	Opcode         string         `json:"opcode"`           // 来源操作码
	TraceIndex     int            `json:"trace_index"`      // trace中的位置
	BranchTaken    bool           `json:"branch_taken"`     // 分支是否被执行
	IsNegated      bool           `json:"is_negated"`       // 是否取反
	DependsOn      []string       `json:"depends_on"`       // 依赖的其他约束ID
}

// ConstraintSource 约束来源
type ConstraintSource int

const (
	SourceJUMPI   ConstraintSource = iota // 条件跳转
	SourceREVERT                          // Revert检查
	SourceASSERT                          // Assert检查
	SourceREQUIRE                         // Require检查
	SourceCALL                            // 外部调用前检查
)

// String 返回约束来源的字符串表示
func (cs ConstraintSource) String() string {
	names := []string{"JUMPI", "REVERT", "ASSERT", "REQUIRE", "CALL"}
	if int(cs) < len(names) {
		return names[cs]
	}
	return "UNKNOWN"
}

// ==================== 求解结果 ====================

// ConstraintSolution 约束求解结果
type ConstraintSolution struct {
	ParamIndex    int           `json:"param_index"`     // 参数索引
	Values        []*big.Int    `json:"values"`          // 求解得到的具体值
	Ranges        []ValueRange  `json:"ranges"`          // 有效范围
	Confidence    float64       `json:"confidence"`      // 综合置信度
	SolverUsed    string        `json:"solver_used"`     // 使用的求解器
	SolveTime     time.Duration `json:"solve_time"`      // 求解耗时
	Constraints   []string      `json:"constraints"`     // 相关约束ID列表
	IsSatisfiable bool          `json:"is_satisfiable"`  // 约束是否可满足
	Error         string        `json:"error,omitempty"` // 错误信息
}

// ValueRange 值范围
type ValueRange struct {
	Min        *big.Int `json:"min"`
	Max        *big.Int `json:"max"`
	Confidence float64  `json:"confidence"`
}

// ==================== 分析结果 ====================

// SymbolicAnalysisResult 符号分析结果
// 包含从单个交易trace中提取的所有信息
type SymbolicAnalysisResult struct {
	TransactionHash string               `json:"transaction_hash"`
	BlockNumber     uint64               `json:"block_number"`
	FunctionSig     string               `json:"function_sig"`
	Constraints     []PathConstraint     `json:"constraints"`      // 提取的所有约束
	Solutions       []ConstraintSolution `json:"solutions"`        // 求解结果
	SymbolicSeeds   []SymbolicSeed       `json:"symbolic_seeds"`   // 生成的符号种子
	CoverageInfo    CoverageInfo         `json:"coverage_info"`    // 覆盖率信息
	AnalysisTime    time.Duration        `json:"analysis_time"`    // 分析耗时
	Error           string               `json:"error,omitempty"`  // 错误信息
}

// SymbolicSeed 符号种子
// 用于传递给Layer 1/2的高优先级种子值
type SymbolicSeed struct {
	ParamIndex  int      `json:"param_index"`
	Value       *big.Int `json:"value"`
	Confidence  float64  `json:"confidence"`  // 置信度
	Priority    int      `json:"priority"`    // 优先级 (越高越优先)
	Reason      string   `json:"reason"`      // 生成原因
	SourceType  string   `json:"source_type"` // "boundary", "solution", "boundary_adjacent"
}

// CoverageInfo 覆盖率信息
type CoverageInfo struct {
	TotalBranches   int     `json:"total_branches"`
	CoveredBranches int     `json:"covered_branches"`
	TotalPaths      int     `json:"total_paths"`
	CoveredPaths    int     `json:"covered_paths"`
	Coverage        float64 `json:"coverage"` // 覆盖率百分比
}

// ==================== EVM Trace 结构 ====================

// EVMTraceStep 单个EVM执行步骤
// 从debug_traceTransaction解析
type EVMTraceStep struct {
	Depth   int      `json:"depth"`
	PC      uint64   `json:"pc"`
	Op      string   `json:"op"`
	Gas     uint64   `json:"gas"`
	GasCost uint64   `json:"gasCost"`
	Stack   []string `json:"stack"`
	Memory  []string `json:"memory,omitempty"`
	Storage map[string]string `json:"storage,omitempty"`
}

// EVMTrace 完整EVM执行trace
type EVMTrace struct {
	Gas         uint64         `json:"gas"`
	ReturnValue string         `json:"returnValue"`
	StructLogs  []EVMTraceStep `json:"structLogs"`
	Failed      bool           `json:"failed"`
}

// ==================== 缓存结构 ====================

// ConstraintCacheEntry 约束缓存条目
type ConstraintCacheEntry struct {
	Key         string               `json:"key"`
	Constraints []PathConstraint     `json:"constraints"`
	Solutions   []ConstraintSolution `json:"solutions"`
	CreatedAt   time.Time            `json:"created_at"`
	HitCount    int                  `json:"hit_count"`
}

// ==================== 默认配置生成器 ====================

// DefaultSymbolicConfig 返回默认配置
// 所有默认值集中在此处,不在使用处硬编码
func DefaultSymbolicConfig() *SymbolicConfig {
	return &SymbolicConfig{
		Enabled:        false,
		Mode:           "lightweight",
		MaxConstraints: 30,
		SolverTimeout:  "3s",
		Extraction: ExtractionConfig{
			MaxTraceDepth: 5000,
			FocusOpcodes:  []string{"JUMPI", "LT", "GT", "EQ", "ISZERO", "SLT", "SGT"},
			IgnoreLoops:   true,
			MaxBranches:   15,
		},
		Solver: SolverConfig{
			Strategy:     "local",
			MaxSolutions: 8,
			UseCache:     true,
			CacheSize:    1000,
			Parallel:     false,
			Workers:      4,
		},
		Integration: IntegrationConfig{
			Priority:            "high",
			MergeWithAdaptive:   true,
			ConfidenceThreshold: 0.5,
			MaxSymbolicSeeds:    20,
		},
	}
}

// MergeWithDefaults 合并用户配置与默认配置
// 用于处理部分配置的情况
func (sc *SymbolicConfig) MergeWithDefaults() {
	defaults := DefaultSymbolicConfig()

	if sc.Mode == "" {
		sc.Mode = defaults.Mode
	}
	if sc.MaxConstraints == 0 {
		sc.MaxConstraints = defaults.MaxConstraints
	}
	if sc.SolverTimeout == "" {
		sc.SolverTimeout = defaults.SolverTimeout
	}

	// Extraction defaults
	if sc.Extraction.MaxTraceDepth == 0 {
		sc.Extraction.MaxTraceDepth = defaults.Extraction.MaxTraceDepth
	}
	if len(sc.Extraction.FocusOpcodes) == 0 {
		sc.Extraction.FocusOpcodes = defaults.Extraction.FocusOpcodes
	}
	if sc.Extraction.MaxBranches == 0 {
		sc.Extraction.MaxBranches = defaults.Extraction.MaxBranches
	}

	// Solver defaults
	if sc.Solver.Strategy == "" {
		sc.Solver.Strategy = defaults.Solver.Strategy
	}
	if sc.Solver.MaxSolutions == 0 {
		sc.Solver.MaxSolutions = defaults.Solver.MaxSolutions
	}
	if sc.Solver.CacheSize == 0 {
		sc.Solver.CacheSize = defaults.Solver.CacheSize
	}
	if sc.Solver.Workers == 0 {
		sc.Solver.Workers = defaults.Solver.Workers
	}

	// Integration defaults
	if sc.Integration.Priority == "" {
		sc.Integration.Priority = defaults.Integration.Priority
	}
	if sc.Integration.ConfidenceThreshold == 0 {
		sc.Integration.ConfidenceThreshold = defaults.Integration.ConfidenceThreshold
	}
	if sc.Integration.MaxSymbolicSeeds == 0 {
		sc.Integration.MaxSymbolicSeeds = defaults.Integration.MaxSymbolicSeeds
	}
}

// GetSolverTimeoutDuration 解析超时时间字符串
func (sc *SymbolicConfig) GetSolverTimeoutDuration() time.Duration {
	d, err := time.ParseDuration(sc.SolverTimeout)
	if err != nil {
		return 3 * time.Second // 默认3秒
	}
	return d
}

// ==================== 辅助函数 ====================

// NewPathConstraint 创建新的路径约束
func NewPathConstraint(paramIndex int, constraintType ConstraintType, value *big.Int) *PathConstraint {
	return &PathConstraint{
		ParamIndex: paramIndex,
		Type:       constraintType,
		Value:      value,
		Confidence: 1.0,
	}
}

// NewRangeConstraint 创建范围约束
func NewRangeConstraint(paramIndex int, min, max *big.Int) *PathConstraint {
	return &PathConstraint{
		ParamIndex: paramIndex,
		Type:       ConstraintRANGE,
		MinValue:   min,
		MaxValue:   max,
		Confidence: 1.0,
	}
}

// Clone 深拷贝约束
func (pc *PathConstraint) Clone() *PathConstraint {
	clone := &PathConstraint{
		ID:          pc.ID,
		ParamIndex:  pc.ParamIndex,
		Type:        pc.Type,
		Confidence:  pc.Confidence,
		Source:      pc.Source,
		Opcode:      pc.Opcode,
		TraceIndex:  pc.TraceIndex,
		BranchTaken: pc.BranchTaken,
		IsNegated:   pc.IsNegated,
	}

	if pc.Value != nil {
		clone.Value = new(big.Int).Set(pc.Value)
	}
	if pc.MinValue != nil {
		clone.MinValue = new(big.Int).Set(pc.MinValue)
	}
	if pc.MaxValue != nil {
		clone.MaxValue = new(big.Int).Set(pc.MaxValue)
	}
	if len(pc.DependsOn) > 0 {
		clone.DependsOn = make([]string, len(pc.DependsOn))
		copy(clone.DependsOn, pc.DependsOn)
	}

	return clone
}

// Negate 返回取反的约束
func (pc *PathConstraint) Negate() *PathConstraint {
	negated := pc.Clone()
	negated.IsNegated = !negated.IsNegated

	// 反转约束类型
	switch pc.Type {
	case ConstraintLT:
		negated.Type = ConstraintGE
	case ConstraintLE:
		negated.Type = ConstraintGT
	case ConstraintGT:
		negated.Type = ConstraintLE
	case ConstraintGE:
		negated.Type = ConstraintLT
	case ConstraintEQ:
		negated.Type = ConstraintNEQ
	case ConstraintNEQ:
		negated.Type = ConstraintEQ
	}

	return negated
}
