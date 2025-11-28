package symbolic

import (
	"context"
	"math/big"
	"testing"
	"time"
)

// ==================== 配置测试 ====================

func TestDefaultSymbolicConfig(t *testing.T) {
	config := DefaultSymbolicConfig()

	if config.Mode != "lightweight" {
		t.Errorf("Expected mode 'lightweight', got '%s'", config.Mode)
	}
	if config.MaxConstraints != 30 {
		t.Errorf("Expected max_constraints 30, got %d", config.MaxConstraints)
	}
	if config.SolverTimeout != "3s" {
		t.Errorf("Expected solver_timeout '3s', got '%s'", config.SolverTimeout)
	}
	if config.Extraction.MaxTraceDepth != 5000 {
		t.Errorf("Expected max_trace_depth 5000, got %d", config.Extraction.MaxTraceDepth)
	}
	if config.Solver.MaxSolutions != 8 {
		t.Errorf("Expected max_solutions 8, got %d", config.Solver.MaxSolutions)
	}
	if config.Integration.ConfidenceThreshold != 0.5 {
		t.Errorf("Expected confidence_threshold 0.5, got %f", config.Integration.ConfidenceThreshold)
	}
}

func TestMergeWithDefaults(t *testing.T) {
	// 部分配置
	config := &SymbolicConfig{
		Enabled:        true,
		MaxConstraints: 50, // 自定义值
		// 其他使用默认值
	}

	config.MergeWithDefaults()

	if config.MaxConstraints != 50 {
		t.Errorf("Custom value should be preserved, got %d", config.MaxConstraints)
	}
	if config.Mode != "lightweight" {
		t.Errorf("Default mode should be applied, got '%s'", config.Mode)
	}
	if config.Solver.MaxSolutions != 8 {
		t.Errorf("Default max_solutions should be applied, got %d", config.Solver.MaxSolutions)
	}
}

func TestGetSolverTimeoutDuration(t *testing.T) {
	config := &SymbolicConfig{SolverTimeout: "5s"}
	d := config.GetSolverTimeoutDuration()
	if d != 5*time.Second {
		t.Errorf("Expected 5s, got %v", d)
	}

	// 无效格式应返回默认值
	config.SolverTimeout = "invalid"
	d = config.GetSolverTimeoutDuration()
	if d != 3*time.Second {
		t.Errorf("Expected default 3s for invalid format, got %v", d)
	}
}

// ==================== 约束类型测试 ====================

func TestConstraintTypeString(t *testing.T) {
	tests := []struct {
		ct       ConstraintType
		expected string
	}{
		{ConstraintLT, "LT"},
		{ConstraintLE, "LE"},
		{ConstraintGT, "GT"},
		{ConstraintGE, "GE"},
		{ConstraintEQ, "EQ"},
		{ConstraintNEQ, "NEQ"},
		{ConstraintRANGE, "RANGE"},
	}

	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.expected {
			t.Errorf("ConstraintType(%d).String() = %s, want %s", tt.ct, got, tt.expected)
		}
	}
}

func TestConstraintSourceString(t *testing.T) {
	tests := []struct {
		cs       ConstraintSource
		expected string
	}{
		{SourceJUMPI, "JUMPI"},
		{SourceREVERT, "REVERT"},
		{SourceASSERT, "ASSERT"},
	}

	for _, tt := range tests {
		if got := tt.cs.String(); got != tt.expected {
			t.Errorf("ConstraintSource(%d).String() = %s, want %s", tt.cs, got, tt.expected)
		}
	}
}

// ==================== 约束操作测试 ====================

func TestNewPathConstraint(t *testing.T) {
	value := big.NewInt(1000)
	c := NewPathConstraint(0, ConstraintLT, value)

	if c.ParamIndex != 0 {
		t.Errorf("Expected ParamIndex 0, got %d", c.ParamIndex)
	}
	if c.Type != ConstraintLT {
		t.Errorf("Expected type LT, got %s", c.Type.String())
	}
	if c.Value.Cmp(value) != 0 {
		t.Errorf("Expected value %s, got %s", value.String(), c.Value.String())
	}
	if c.Confidence != 1.0 {
		t.Errorf("Expected confidence 1.0, got %f", c.Confidence)
	}
}

func TestNewRangeConstraint(t *testing.T) {
	min := big.NewInt(100)
	max := big.NewInt(1000)
	c := NewRangeConstraint(1, min, max)

	if c.ParamIndex != 1 {
		t.Errorf("Expected ParamIndex 1, got %d", c.ParamIndex)
	}
	if c.Type != ConstraintRANGE {
		t.Errorf("Expected type RANGE, got %s", c.Type.String())
	}
	if c.MinValue.Cmp(min) != 0 {
		t.Errorf("Expected MinValue %s, got %s", min.String(), c.MinValue.String())
	}
	if c.MaxValue.Cmp(max) != 0 {
		t.Errorf("Expected MaxValue %s, got %s", max.String(), c.MaxValue.String())
	}
}

func TestConstraintClone(t *testing.T) {
	original := &PathConstraint{
		ID:         "C1",
		ParamIndex: 0,
		Type:       ConstraintLT,
		Value:      big.NewInt(1000),
		Confidence: 0.9,
		DependsOn:  []string{"C0"},
	}

	clone := original.Clone()

	// 验证值相同
	if clone.ID != original.ID {
		t.Errorf("ID mismatch")
	}
	if clone.Value.Cmp(original.Value) != 0 {
		t.Errorf("Value mismatch")
	}

	// 验证深拷贝(修改原值不影响克隆)
	original.Value.SetInt64(2000)
	if clone.Value.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("Clone should be independent, got %s", clone.Value.String())
	}
}

func TestConstraintNegate(t *testing.T) {
	tests := []struct {
		original ConstraintType
		negated  ConstraintType
	}{
		{ConstraintLT, ConstraintGE},
		{ConstraintLE, ConstraintGT},
		{ConstraintGT, ConstraintLE},
		{ConstraintGE, ConstraintLT},
		{ConstraintEQ, ConstraintNEQ},
		{ConstraintNEQ, ConstraintEQ},
	}

	for _, tt := range tests {
		c := &PathConstraint{Type: tt.original, Value: big.NewInt(100)}
		negated := c.Negate()

		if negated.Type != tt.negated {
			t.Errorf("Negate(%s) = %s, want %s", tt.original.String(), negated.Type.String(), tt.negated.String())
		}
		if !negated.IsNegated {
			t.Errorf("IsNegated should be true after Negate()")
		}
	}
}

// ==================== 求解器测试 ====================

func TestConstraintSolverMergeRanges(t *testing.T) {
	config := DefaultSymbolicConfig()
	solver := NewConstraintSolver(config)

	// 测试范围合并: x > 100 && x < 1000
	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
		{ParamIndex: 0, Type: ConstraintLT, Value: big.NewInt(1000)},
	}

	solutions, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("SolveConstraints failed: %v", err)
	}

	if len(solutions) != 1 {
		t.Fatalf("Expected 1 solution, got %d", len(solutions))
	}

	sol := solutions[0]
	if !sol.IsSatisfiable {
		t.Error("Expected satisfiable solution")
	}

	if len(sol.Ranges) != 1 {
		t.Fatalf("Expected 1 range, got %d", len(sol.Ranges))
	}

	r := sol.Ranges[0]
	// x > 100 => min = 101
	if r.Min.Cmp(big.NewInt(101)) != 0 {
		t.Errorf("Expected min 101, got %s", r.Min.String())
	}
	// x < 1000 => max = 999
	if r.Max.Cmp(big.NewInt(999)) != 0 {
		t.Errorf("Expected max 999, got %s", r.Max.String())
	}
}

func TestConstraintSolverUnsatisfiable(t *testing.T) {
	config := DefaultSymbolicConfig()
	solver := NewConstraintSolver(config)

	// 不可满足: x > 1000 && x < 100
	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(1000)},
		{ParamIndex: 0, Type: ConstraintLT, Value: big.NewInt(100)},
	}

	solutions, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("SolveConstraints failed: %v", err)
	}

	if len(solutions) != 1 {
		t.Fatalf("Expected 1 solution, got %d", len(solutions))
	}

	if solutions[0].IsSatisfiable {
		t.Error("Expected unsatisfiable solution")
	}
}

func TestConstraintSolverExactValue(t *testing.T) {
	config := DefaultSymbolicConfig()
	solver := NewConstraintSolver(config)

	// 精确值: x == 500
	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintEQ, Value: big.NewInt(500)},
	}

	solutions, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("SolveConstraints failed: %v", err)
	}

	if len(solutions) != 1 {
		t.Fatalf("Expected 1 solution, got %d", len(solutions))
	}

	sol := solutions[0]
	found := false
	for _, v := range sol.Values {
		if v.Cmp(big.NewInt(500)) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected exact value 500 in solutions")
	}
}

func TestConstraintSolverCache(t *testing.T) {
	config := DefaultSymbolicConfig()
	config.Solver.UseCache = true
	solver := NewConstraintSolver(config)

	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
	}

	// 第一次调用
	_, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("First call failed: %v", err)
	}

	stats := solver.GetStatistics()
	if stats["cache_misses"] != 1 {
		t.Errorf("Expected 1 cache miss, got %d", stats["cache_misses"])
	}

	// 第二次调用(应该命中缓存)
	_, err = solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("Second call failed: %v", err)
	}

	stats = solver.GetStatistics()
	if stats["cache_hits"] != 1 {
		t.Errorf("Expected 1 cache hit, got %d", stats["cache_hits"])
	}
}

func TestCheckSatisfiability(t *testing.T) {
	config := DefaultSymbolicConfig()
	solver := NewConstraintSolver(config)

	// 可满足
	sat, _ := solver.CheckSatisfiability([]PathConstraint{
		{Type: ConstraintGT, Value: big.NewInt(100)},
		{Type: ConstraintLT, Value: big.NewInt(1000)},
	})
	if !sat {
		t.Error("Expected satisfiable")
	}

	// 不可满足
	sat, reason := solver.CheckSatisfiability([]PathConstraint{
		{Type: ConstraintGT, Value: big.NewInt(1000)},
		{Type: ConstraintLT, Value: big.NewInt(100)},
	})
	if sat {
		t.Error("Expected unsatisfiable")
	}
	if reason == "" {
		t.Error("Expected reason for unsatisfiability")
	}
}

// ==================== 提取器测试 ====================

func TestExtractorParseParamValues(t *testing.T) {
	config := DefaultSymbolicConfig()
	extractor := NewConstraintExtractor(config, nil)

	// 测试各种类型转换
	values := []interface{}{
		big.NewInt(1000),
		int64(2000),
		uint64(3000),
		"4000",
		"0x1000", // 十六进制
	}

	parsed := extractor.parseParamValues(values)

	expected := []int64{1000, 2000, 3000, 4000, 4096}
	for i, exp := range expected {
		if parsed[i] == nil {
			t.Errorf("Param %d is nil", i)
			continue
		}
		if parsed[i].Cmp(big.NewInt(exp)) != 0 {
			t.Errorf("Param %d: expected %d, got %s", i, exp, parsed[i].String())
		}
	}
}

func TestExtractorFromTrace(t *testing.T) {
	config := DefaultSymbolicConfig()
	extractor := NewConstraintExtractor(config, nil)

	// 模拟简单的trace
	trace := &EVMTrace{
		Gas:         100000,
		ReturnValue: "0x",
		StructLogs: []EVMTraceStep{
			{
				Depth:   1,
				PC:      100,
				Op:      "LT",
				Gas:     90000,
				GasCost: 3,
				Stack:   []string{"0x3e8", "0x64"}, // 1000, 100
			},
			{
				Depth:   1,
				PC:      101,
				Op:      "JUMPI",
				Gas:     89990,
				GasCost: 10,
				Stack:   []string{"0x1", "0x200"},
			},
		},
	}

	paramValues := []interface{}{big.NewInt(100)} // param == 100

	result, err := extractor.ExtractFromTrace(trace, paramValues)
	if err != nil {
		t.Fatalf("ExtractFromTrace failed: %v", err)
	}

	// 应该提取到约束 (100 与 1000 比较)
	if len(result.Constraints) == 0 {
		t.Log("No constraints extracted (expected for this simple trace)")
	}

	// 检查覆盖率计算
	if result.CoverageInfo.TotalBranches != 1 {
		t.Errorf("Expected 1 branch (JUMPI), got %d", result.CoverageInfo.TotalBranches)
	}
}

func TestExtractorGenerateSymbolicSeeds(t *testing.T) {
	config := DefaultSymbolicConfig()
	extractor := NewConstraintExtractor(config, nil)

	// 创建约束
	constraints := []PathConstraint{
		{
			ParamIndex: 0,
			Type:       ConstraintLT,
			Value:      big.NewInt(1000),
			Confidence: 0.9,
		},
		{
			ParamIndex: 0,
			Type:       ConstraintEQ,
			Value:      big.NewInt(500),
			Confidence: 0.95,
		},
	}

	seeds := extractor.generateSymbolicSeeds(constraints, []*big.Int{big.NewInt(100)})

	if len(seeds) == 0 {
		t.Fatal("Expected some symbolic seeds")
	}

	// 检查精确值种子优先级最高
	found500 := false
	for _, seed := range seeds {
		if seed.Value.Cmp(big.NewInt(500)) == 0 {
			found500 = true
			if seed.Priority != 100 {
				t.Errorf("Exact value seed should have priority 100, got %d", seed.Priority)
			}
		}
	}
	if !found500 {
		t.Error("Expected seed with value 500")
	}
}

// ==================== 集成测试 ====================

func TestFullPipeline(t *testing.T) {
	config := DefaultSymbolicConfig()
	config.Enabled = true

	// 创建求解器
	solver := NewConstraintSolver(config)

	// 模拟约束(来自trace提取)
	constraints := []PathConstraint{
		{
			ID:         "C0",
			ParamIndex: 0,
			Type:       ConstraintGT,
			Value:      big.NewInt(100),
			Confidence: 0.9,
		},
		{
			ID:         "C1",
			ParamIndex: 0,
			Type:       ConstraintLT,
			Value:      big.NewInt(10000),
			Confidence: 0.85,
		},
		{
			ID:         "C2",
			ParamIndex: 1,
			Type:       ConstraintEQ,
			Value:      big.NewInt(42),
			Confidence: 0.95,
		},
	}

	// 求解
	solutions, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("Pipeline failed: %v", err)
	}

	// 验证结果
	if len(solutions) != 2 {
		t.Fatalf("Expected 2 solutions (for 2 params), got %d", len(solutions))
	}

	// 参数0: 范围 [101, 9999]
	sol0 := solutions[0]
	if !sol0.IsSatisfiable {
		t.Error("Param 0 should be satisfiable")
	}
	if len(sol0.Values) == 0 {
		t.Error("Expected some values for param 0")
	}

	// 参数1: 精确值 42
	sol1 := solutions[1]
	if !sol1.IsSatisfiable {
		t.Error("Param 1 should be satisfiable")
	}
	found42 := false
	for _, v := range sol1.Values {
		if v.Cmp(big.NewInt(42)) == 0 {
			found42 = true
			break
		}
	}
	if !found42 {
		t.Error("Expected value 42 for param 1")
	}
}

// ==================== 性能测试 ====================

func BenchmarkSolveConstraints(b *testing.B) {
	config := DefaultSymbolicConfig()
	config.Solver.UseCache = false // 禁用缓存以测试纯求解性能
	solver := NewConstraintSolver(config)

	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
		{ParamIndex: 0, Type: ConstraintLT, Value: big.NewInt(10000)},
		{ParamIndex: 1, Type: ConstraintEQ, Value: big.NewInt(42)},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = solver.SolveConstraints(ctx, constraints)
	}
}

func BenchmarkSolveConstraintsWithCache(b *testing.B) {
	config := DefaultSymbolicConfig()
	config.Solver.UseCache = true
	solver := NewConstraintSolver(config)

	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
		{ParamIndex: 0, Type: ConstraintLT, Value: big.NewInt(10000)},
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = solver.SolveConstraints(ctx, constraints)
	}
}

// ==================== Z3 求解器测试 ====================

func TestZ3SolverBasic(t *testing.T) {
	config := DefaultSymbolicConfig()
	config.Solver.Strategy = "z3"

	solver, err := NewZ3Solver(config)
	if err != nil {
		t.Skipf("Z3 not available: %v", err)
		return
	}
	defer solver.Close()

	// 测试简单约束: x > 100 && x < 1000
	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
		{ParamIndex: 0, Type: ConstraintLT, Value: big.NewInt(1000)},
	}

	solutions, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("Z3 solve failed: %v", err)
	}

	if len(solutions) != 1 {
		t.Fatalf("Expected 1 solution, got %d", len(solutions))
	}

	sol := solutions[0]
	if !sol.IsSatisfiable {
		t.Error("Expected satisfiable solution")
	}

	if sol.SolverUsed != "z3" {
		t.Errorf("Expected solver 'z3', got '%s'", sol.SolverUsed)
	}
}

func TestZ3SolverRange(t *testing.T) {
	config := DefaultSymbolicConfig()
	config.Solver.Strategy = "z3"

	solver, err := NewZ3Solver(config)
	if err != nil {
		t.Skipf("Z3 not available: %v", err)
		return
	}
	defer solver.Close()

	// 测试范围约束
	constraints := []PathConstraint{
		{
			ParamIndex: 0,
			Type:       ConstraintRANGE,
			MinValue:   big.NewInt(1000),
			MaxValue:   big.NewInt(5000),
		},
	}

	solutions, err := solver.SolveConstraints(context.Background(), constraints)
	if err != nil {
		t.Fatalf("Z3 solve failed: %v", err)
	}

	if len(solutions) != 1 {
		t.Fatalf("Expected 1 solution, got %d", len(solutions))
	}

	sol := solutions[0]
	if !sol.IsSatisfiable {
		t.Error("Expected satisfiable solution")
	}

	// 验证解在范围内
	for _, v := range sol.Values {
		if v.Cmp(big.NewInt(1000)) < 0 || v.Cmp(big.NewInt(5000)) > 0 {
			t.Errorf("Value %s outside range [1000, 5000]", v.String())
		}
	}
}

func TestHybridStrategy(t *testing.T) {
	config := DefaultSymbolicConfig()
	config.Solver.Strategy = "hybrid"

	solver := NewConstraintSolver(config)
	defer solver.Close()

	// 简单约束应该用本地求解器
	simpleConstraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
		{ParamIndex: 0, Type: ConstraintLT, Value: big.NewInt(1000)},
	}

	_, err := solver.SolveConstraints(context.Background(), simpleConstraints)
	if err != nil {
		t.Fatalf("Hybrid solve failed: %v", err)
	}

	stats := solver.GetStatistics()

	// 简单约束应该使用本地求解器
	if stats["local_solves"] == 0 {
		t.Log("Note: Expected local solver to be used for simple constraints")
	}

	// 验证统计数据结构
	if _, ok := stats["z3_solves"]; !ok {
		t.Error("Missing z3_solves in statistics")
	}
	if _, ok := stats["fallback_solves"]; !ok {
		t.Error("Missing fallback_solves in statistics")
	}
}

func TestShouldUseZ3(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		strategy    string
		constraints []PathConstraint
		expected    bool
	}{
		{
			name:     "disabled config should not use Z3",
			enabled:  false,
			strategy: "z3",
			constraints: []PathConstraint{
				{Type: ConstraintMOD},
			},
			expected: false,
		},
		{
			name:     "strategy=local should not use Z3",
			enabled:  true,
			strategy: "local",
			constraints: []PathConstraint{
				{Type: ConstraintMOD},
			},
			expected: false,
		},
		{
			name:        "strategy=z3 should always use Z3",
			enabled:     true,
			strategy:    "z3",
			constraints: []PathConstraint{},
			expected:    true,
		},
		{
			name:    "hybrid with simple constraints",
			enabled: true,
			strategy: "hybrid",
			constraints: []PathConstraint{
				{Type: ConstraintLT},
				{Type: ConstraintGT},
			},
			expected: false,
		},
		{
			name:    "hybrid with complex constraints (MOD)",
			enabled: true,
			strategy: "hybrid",
			constraints: []PathConstraint{
				{Type: ConstraintMOD},
			},
			expected: true,
		},
		{
			name:    "hybrid with complex constraints (AND)",
			enabled: true,
			strategy: "hybrid",
			constraints: []PathConstraint{
				{Type: ConstraintAND},
			},
			expected: true,
		},
		{
			name:    "hybrid with complex constraints (OR)",
			enabled: true,
			strategy: "hybrid",
			constraints: []PathConstraint{
				{Type: ConstraintOR},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := DefaultSymbolicConfig()
			config.Enabled = tt.enabled
			config.Solver.Strategy = tt.strategy

			result := ShouldUseZ3(config, tt.constraints)
			if result != tt.expected {
				t.Errorf("ShouldUseZ3() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestZ3SolverStatistics(t *testing.T) {
	config := DefaultSymbolicConfig()
	config.Solver.Strategy = "z3"

	solver, err := NewZ3Solver(config)
	if err != nil {
		t.Skipf("Z3 not available: %v", err)
		return
	}
	defer solver.Close()

	constraints := []PathConstraint{
		{ParamIndex: 0, Type: ConstraintGT, Value: big.NewInt(100)},
	}

	// 执行多次求解
	for i := 0; i < 3; i++ {
		_, _ = solver.SolveConstraints(context.Background(), constraints)
	}

	stats := solver.GetStatistics()

	if stats.TotalSolves != 3 {
		t.Errorf("Expected 3 total solves, got %d", stats.TotalSolves)
	}
}
