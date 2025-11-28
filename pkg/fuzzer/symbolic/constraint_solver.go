package symbolic

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"sync"
	"time"
)

// ConstraintSolver 约束求解器
// 使用本地算法求解简单约束,支持可选的Z3求解器
type ConstraintSolver struct {
	config *SymbolicConfig

	// Z3求解器(可选)
	z3Solver *Z3Solver

	// 缓存
	cache      map[string]*ConstraintCacheEntry
	cacheMutex sync.RWMutex

	// 统计
	cacheHits      int
	cacheMisses    int
	totalSolves    int
	localSolves    int
	z3Solves       int
	fallbackSolves int
}

// NewConstraintSolver 创建约束求解器
func NewConstraintSolver(config *SymbolicConfig) *ConstraintSolver {
	if config == nil {
		config = DefaultSymbolicConfig()
	}
	config.MergeWithDefaults()

	cs := &ConstraintSolver{
		config: config,
		cache:  make(map[string]*ConstraintCacheEntry),
	}

	// 初始化Z3求解器(如果需要)
	if config.Solver.Strategy == "z3" || config.Solver.Strategy == "hybrid" {
		z3Solver, err := NewZ3Solver(config)
		if err != nil {
			log.Printf("[Solver] Warning: Failed to initialize Z3: %v, falling back to local only", err)
		} else {
			cs.z3Solver = z3Solver
			log.Printf("[Solver] Z3 solver initialized (strategy=%s)", config.Solver.Strategy)
		}
	}

	return cs
}

// SolveConstraints 求解约束集合
func (cs *ConstraintSolver) SolveConstraints(
	ctx context.Context,
	constraints []PathConstraint,
) ([]ConstraintSolution, error) {
	startTime := time.Now()

	// 混合策略: 检查是否应使用Z3
	useZ3 := ShouldUseZ3(cs.config, constraints)

	if useZ3 && cs.z3Solver != nil {
		// 使用Z3求解
		log.Printf("[Solver] Using Z3 for %d constraints", len(constraints))
		solutions, err := cs.z3Solver.SolveConstraints(ctx, constraints)
		if err == nil {
			cs.z3Solves++
			return solutions, nil
		}
		// Z3失败,回退到本地求解器
		log.Printf("[Solver] Z3 failed: %v, falling back to local solver", err)
		cs.fallbackSolves++
	}

	// 使用本地求解器
	cs.localSolves++
	return cs.solveWithLocal(ctx, constraints, startTime)
}

// solveWithLocal 使用本地算法求解
func (cs *ConstraintSolver) solveWithLocal(
	ctx context.Context,
	constraints []PathConstraint,
	startTime time.Time,
) ([]ConstraintSolution, error) {
	// 按参数索引分组
	paramConstraints := make(map[int][]PathConstraint)
	for _, c := range constraints {
		paramConstraints[c.ParamIndex] = append(paramConstraints[c.ParamIndex], c)
	}

	solutions := []ConstraintSolution{}
	timeout := cs.config.GetSolverTimeoutDuration()

	// 创建带超时的context
	solveCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// 求解每个参数的约束
	for paramIdx, pConstraints := range paramConstraints {
		select {
		case <-solveCtx.Done():
			log.Printf("[Solver] Timeout reached, solved %d/%d parameters", len(solutions), len(paramConstraints))
			return solutions, solveCtx.Err()
		default:
		}

		solution := cs.solveParamConstraints(paramIdx, pConstraints)
		solution.SolveTime = time.Since(startTime)
		solutions = append(solutions, solution)
	}

	cs.totalSolves++
	return solutions, nil
}

// solveParamConstraints 求解单个参数的约束
func (cs *ConstraintSolver) solveParamConstraints(
	paramIdx int,
	constraints []PathConstraint,
) ConstraintSolution {
	solution := ConstraintSolution{
		ParamIndex:    paramIdx,
		Values:        []*big.Int{},
		Ranges:        []ValueRange{},
		SolverUsed:    "local",
		IsSatisfiable: true,
	}

	// 检查缓存
	cacheKey := cs.generateCacheKey(paramIdx, constraints)
	if cs.config.Solver.UseCache {
		if cached := cs.getFromCache(cacheKey); cached != nil {
			cs.cacheHits++
			return *cached
		}
		cs.cacheMisses++
	}

	// 收集约束ID
	for _, c := range constraints {
		solution.Constraints = append(solution.Constraints, c.ID)
	}

	// 1. 合并范围约束
	mergedRange := cs.mergeRangeConstraints(constraints)

	// 2. 检查可满足性
	if mergedRange != nil && mergedRange.Min.Cmp(mergedRange.Max) > 0 {
		solution.IsSatisfiable = false
		solution.Error = "unsatisfiable: min > max"
		return solution
	}

	// 3. 生成解
	if mergedRange != nil {
		solution.Ranges = append(solution.Ranges, *mergedRange)

		// 生成范围内的值
		values := cs.generateValuesInRange(mergedRange)
		solution.Values = values
	}

	// 4. 处理精确值约束
	exactValues := cs.extractExactValues(constraints)
	for _, v := range exactValues {
		// 检查是否在有效范围内
		if mergedRange == nil || cs.isInRange(v, mergedRange) {
			solution.Values = append(solution.Values, v)
		}
	}

	// 5. 去重并限制数量
	solution.Values = cs.deduplicateValues(solution.Values)
	if len(solution.Values) > cs.config.Solver.MaxSolutions {
		solution.Values = solution.Values[:cs.config.Solver.MaxSolutions]
	}

	// 6. 计算综合置信度
	solution.Confidence = cs.calculateSolutionConfidence(constraints)

	// 缓存结果
	if cs.config.Solver.UseCache {
		cs.saveToCache(cacheKey, &solution)
	}

	return solution
}

// mergeRangeConstraints 合并范围约束
func (cs *ConstraintSolver) mergeRangeConstraints(constraints []PathConstraint) *ValueRange {
	// 初始化为最大范围
	minBound := big.NewInt(0)
	maxBound := new(big.Int).Lsh(big.NewInt(1), 256) // 2^256
	maxBound.Sub(maxBound, big.NewInt(1))

	hasConstraint := false

	for _, c := range constraints {
		switch c.Type {
		case ConstraintLT:
			// x < value => max = min(max, value-1)
			if c.Value != nil {
				upper := new(big.Int).Sub(c.Value, big.NewInt(1))
				if upper.Cmp(maxBound) < 0 {
					maxBound = upper
				}
				hasConstraint = true
			}

		case ConstraintLE:
			// x <= value
			if c.Value != nil && c.Value.Cmp(maxBound) < 0 {
				maxBound = new(big.Int).Set(c.Value)
				hasConstraint = true
			}

		case ConstraintGT:
			// x > value => min = max(min, value+1)
			if c.Value != nil {
				lower := new(big.Int).Add(c.Value, big.NewInt(1))
				if lower.Cmp(minBound) > 0 {
					minBound = lower
				}
				hasConstraint = true
			}

		case ConstraintGE:
			// x >= value
			if c.Value != nil && c.Value.Cmp(minBound) > 0 {
				minBound = new(big.Int).Set(c.Value)
				hasConstraint = true
			}

		case ConstraintRANGE:
			// 显式范围
			if c.MinValue != nil && c.MinValue.Cmp(minBound) > 0 {
				minBound = new(big.Int).Set(c.MinValue)
			}
			if c.MaxValue != nil && c.MaxValue.Cmp(maxBound) < 0 {
				maxBound = new(big.Int).Set(c.MaxValue)
			}
			hasConstraint = true
		}
	}

	if !hasConstraint {
		return nil
	}

	return &ValueRange{
		Min:        minBound,
		Max:        maxBound,
		Confidence: 0.9,
	}
}

// extractExactValues 提取精确值约束
func (cs *ConstraintSolver) extractExactValues(constraints []PathConstraint) []*big.Int {
	values := []*big.Int{}

	for _, c := range constraints {
		if c.Type == ConstraintEQ && c.Value != nil {
			values = append(values, new(big.Int).Set(c.Value))
		}
	}

	return values
}

// generateValuesInRange 在范围内生成值
func (cs *ConstraintSolver) generateValuesInRange(r *ValueRange) []*big.Int {
	values := []*big.Int{}

	// 添加边界值
	values = append(values, new(big.Int).Set(r.Min))
	values = append(values, new(big.Int).Set(r.Max))

	// 计算范围大小
	rangeSize := new(big.Int).Sub(r.Max, r.Min)

	// 如果范围太小,只返回边界
	if rangeSize.Cmp(big.NewInt(2)) <= 0 {
		return values
	}

	// 添加中点
	mid := new(big.Int).Add(r.Min, r.Max)
	mid.Div(mid, big.NewInt(2))
	values = append(values, mid)

	// 添加四分位点
	quarter := new(big.Int).Div(rangeSize, big.NewInt(4))
	if quarter.Sign() > 0 {
		q1 := new(big.Int).Add(r.Min, quarter)
		q3 := new(big.Int).Sub(r.Max, quarter)
		values = append(values, q1, q3)
	}

	// 添加边界附近的值
	if r.Min.Cmp(big.NewInt(0)) > 0 {
		nearMin := new(big.Int).Add(r.Min, big.NewInt(1))
		values = append(values, nearMin)
	}
	nearMax := new(big.Int).Sub(r.Max, big.NewInt(1))
	if nearMax.Cmp(r.Min) > 0 {
		values = append(values, nearMax)
	}

	return values
}

// isInRange 检查值是否在范围内
func (cs *ConstraintSolver) isInRange(value *big.Int, r *ValueRange) bool {
	return value.Cmp(r.Min) >= 0 && value.Cmp(r.Max) <= 0
}

// deduplicateValues 去重
func (cs *ConstraintSolver) deduplicateValues(values []*big.Int) []*big.Int {
	seen := make(map[string]bool)
	unique := []*big.Int{}

	for _, v := range values {
		key := v.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
		}
	}

	return unique
}

// calculateSolutionConfidence 计算解的综合置信度
func (cs *ConstraintSolver) calculateSolutionConfidence(constraints []PathConstraint) float64 {
	if len(constraints) == 0 {
		return 0.0
	}

	totalConfidence := 0.0
	for _, c := range constraints {
		totalConfidence += c.Confidence
	}

	return totalConfidence / float64(len(constraints))
}

// ==================== 缓存管理 ====================

// generateCacheKey 生成缓存键
func (cs *ConstraintSolver) generateCacheKey(paramIdx int, constraints []PathConstraint) string {
	key := fmt.Sprintf("p%d:", paramIdx)
	for _, c := range constraints {
		key += fmt.Sprintf("%s-%s-%v;", c.Type.String(), c.Opcode, c.Value)
	}
	return key
}

// getFromCache 从缓存获取
func (cs *ConstraintSolver) getFromCache(key string) *ConstraintSolution {
	cs.cacheMutex.RLock()
	defer cs.cacheMutex.RUnlock()

	if entry, ok := cs.cache[key]; ok {
		entry.HitCount++
		if len(entry.Solutions) > 0 {
			return &entry.Solutions[0]
		}
	}

	return nil
}

// saveToCache 保存到缓存
func (cs *ConstraintSolver) saveToCache(key string, solution *ConstraintSolution) {
	cs.cacheMutex.Lock()
	defer cs.cacheMutex.Unlock()

	// 检查缓存大小
	if len(cs.cache) >= cs.config.Solver.CacheSize {
		// 简单的LRU: 删除最旧的条目
		var oldestKey string
		var oldestTime time.Time
		for k, v := range cs.cache {
			if oldestKey == "" || v.CreatedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.CreatedAt
			}
		}
		if oldestKey != "" {
			delete(cs.cache, oldestKey)
		}
	}

	cs.cache[key] = &ConstraintCacheEntry{
		Key:       key,
		Solutions: []ConstraintSolution{*solution},
		CreatedAt: time.Now(),
		HitCount:  0,
	}
}

// ClearCache 清空缓存
func (cs *ConstraintSolver) ClearCache() {
	cs.cacheMutex.Lock()
	defer cs.cacheMutex.Unlock()
	cs.cache = make(map[string]*ConstraintCacheEntry)
}

// Close 关闭求解器并释放资源
func (cs *ConstraintSolver) Close() {
	if cs.z3Solver != nil {
		cs.z3Solver.Close()
	}
}

// GetStatistics 获取统计信息
func (cs *ConstraintSolver) GetStatistics() map[string]int {
	return map[string]int{
		"cache_hits":      cs.cacheHits,
		"cache_misses":    cs.cacheMisses,
		"total_solves":    cs.totalSolves,
		"local_solves":    cs.localSolves,
		"z3_solves":       cs.z3Solves,
		"fallback_solves": cs.fallbackSolves,
		"cache_size":      len(cs.cache),
	}
}

// ==================== 高级求解方法 ====================

// SolveWithHeuristics 使用启发式方法求解复杂约束
func (cs *ConstraintSolver) SolveWithHeuristics(
	ctx context.Context,
	constraints []PathConstraint,
	existingSeeds []*big.Int,
) ([]ConstraintSolution, error) {
	// 先使用标准求解
	solutions, err := cs.SolveConstraints(ctx, constraints)
	if err != nil {
		return solutions, err
	}

	// 基于现有种子进行启发式增强
	for i, sol := range solutions {
		if !sol.IsSatisfiable || len(sol.Ranges) == 0 {
			continue
		}

		r := sol.Ranges[0]

		// 查找范围内的现有种子并添加附近值
		for _, seed := range existingSeeds {
			if cs.isInRange(seed, &r) {
				// 添加种子附近的值
				offsets := []int64{-100, -10, -1, 1, 10, 100}
				for _, offset := range offsets {
					nearby := new(big.Int).Add(seed, big.NewInt(offset))
					if cs.isInRange(nearby, &r) {
						solutions[i].Values = append(solutions[i].Values, nearby)
					}
				}
			}
		}

		// 去重
		solutions[i].Values = cs.deduplicateValues(solutions[i].Values)
	}

	return solutions, nil
}

// CheckSatisfiability 检查约束是否可满足
func (cs *ConstraintSolver) CheckSatisfiability(constraints []PathConstraint) (bool, string) {
	mergedRange := cs.mergeRangeConstraints(constraints)

	if mergedRange == nil {
		return true, "no range constraints"
	}

	if mergedRange.Min.Cmp(mergedRange.Max) > 0 {
		return false, fmt.Sprintf("range contradiction: min=%s > max=%s",
			mergedRange.Min.String(), mergedRange.Max.String())
	}

	// 检查精确值约束冲突
	exactValues := cs.extractExactValues(constraints)
	for _, v := range exactValues {
		if !cs.isInRange(v, mergedRange) {
			return false, fmt.Sprintf("exact value %s outside range [%s, %s]",
				v.String(), mergedRange.Min.String(), mergedRange.Max.String())
		}
	}

	// 检查不等式约束
	for _, c := range constraints {
		if c.Type == ConstraintNEQ && c.Value != nil {
			// 如果范围只包含这一个值,则不可满足
			if mergedRange.Min.Cmp(c.Value) == 0 && mergedRange.Max.Cmp(c.Value) == 0 {
				return false, fmt.Sprintf("only value %s is excluded by NEQ", c.Value.String())
			}
		}
	}

	return true, "satisfiable"
}
