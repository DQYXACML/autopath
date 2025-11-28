package symbolic

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// ConstraintExtractor 约束提取器
// 从EVM执行trace中提取参数约束条件
type ConstraintExtractor struct {
	config    *SymbolicConfig
	rpcClient *rpc.Client

	// 操作码到约束类型的映射
	opcodeMapping map[string]ConstraintType

	// 统计信息
	totalExtracted   int
	filteredByDepth  int
	filteredByBranch int
}

// NewConstraintExtractor 创建约束提取器
func NewConstraintExtractor(config *SymbolicConfig, rpcClient *rpc.Client) *ConstraintExtractor {
	// 确保配置有默认值
	if config == nil {
		config = DefaultSymbolicConfig()
	}
	config.MergeWithDefaults()

	// 构建操作码映射
	opcodeMapping := map[string]ConstraintType{
		"LT":     ConstraintLT,
		"GT":     ConstraintGT,
		"SLT":    ConstraintLT, // 有符号小于
		"SGT":    ConstraintGT, // 有符号大于
		"EQ":     ConstraintEQ,
		"ISZERO": ConstraintEQ, // ISZERO(x) == (x == 0)
	}

	return &ConstraintExtractor{
		config:        config,
		rpcClient:     rpcClient,
		opcodeMapping: opcodeMapping,
	}
}

// ExtractFromTransaction 从交易trace中提取约束
func (ce *ConstraintExtractor) ExtractFromTransaction(
	ctx context.Context,
	txHash common.Hash,
	paramValues []interface{},
) (*SymbolicAnalysisResult, error) {
	startTime := time.Now()

	result := &SymbolicAnalysisResult{
		TransactionHash: txHash.Hex(),
		Constraints:     []PathConstraint{},
		Solutions:       []ConstraintSolution{},
		SymbolicSeeds:   []SymbolicSeed{},
	}

	// 1. 获取交易trace
	trace, err := ce.getTransactionTrace(ctx, txHash)
	if err != nil {
		result.Error = fmt.Sprintf("failed to get trace: %v", err)
		return result, err
	}

	log.Printf("[Symbolic] Got trace with %d steps", len(trace.StructLogs))

	// 2. 解析参数值为big.Int
	paramBigInts := ce.parseParamValues(paramValues)

	// 3. 提取约束
	constraints := ce.extractConstraints(trace, paramBigInts)
	result.Constraints = constraints

	// 4. 计算覆盖率信息
	result.CoverageInfo = ce.calculateCoverage(trace)

	// 5. 生成符号种子
	result.SymbolicSeeds = ce.generateSymbolicSeeds(constraints, paramBigInts)

	result.AnalysisTime = time.Since(startTime)

	log.Printf("[Symbolic] Extracted %d constraints, generated %d seeds in %v",
		len(constraints), len(result.SymbolicSeeds), result.AnalysisTime)

	return result, nil
}

// ExtractFromTrace 从已有的trace数据提取约束
// 用于不需要RPC调用的场景
func (ce *ConstraintExtractor) ExtractFromTrace(
	trace *EVMTrace,
	paramValues []interface{},
) (*SymbolicAnalysisResult, error) {
	startTime := time.Now()

	result := &SymbolicAnalysisResult{
		Constraints:   []PathConstraint{},
		Solutions:     []ConstraintSolution{},
		SymbolicSeeds: []SymbolicSeed{},
	}

	// 解析参数值
	paramBigInts := ce.parseParamValues(paramValues)

	// 提取约束
	constraints := ce.extractConstraints(trace, paramBigInts)
	result.Constraints = constraints

	// 计算覆盖率
	result.CoverageInfo = ce.calculateCoverage(trace)

	// 生成符号种子
	result.SymbolicSeeds = ce.generateSymbolicSeeds(constraints, paramBigInts)

	result.AnalysisTime = time.Since(startTime)

	return result, nil
}

// getTransactionTrace 获取交易执行trace
func (ce *ConstraintExtractor) getTransactionTrace(
	ctx context.Context,
	txHash common.Hash,
) (*EVMTrace, error) {
	if ce.rpcClient == nil {
		return nil, fmt.Errorf("RPC client not initialized")
	}

	var result EVMTrace
	err := ce.rpcClient.CallContext(ctx, &result, "debug_traceTransaction", txHash.Hex(), map[string]interface{}{
		"disableStorage": true,
		"disableMemory":  false, // 需要内存来分析参数
		"disableStack":   false, // 需要栈来分析操作数
	})
	if err != nil {
		return nil, fmt.Errorf("debug_traceTransaction failed: %w", err)
	}

	return &result, nil
}

// extractConstraints 从trace中提取约束
func (ce *ConstraintExtractor) extractConstraints(
	trace *EVMTrace,
	paramValues []*big.Int,
) []PathConstraint {
	constraints := []PathConstraint{}
	constraintID := 0

	// 构建要关注的操作码集合
	focusOpcodes := make(map[string]bool)
	for _, op := range ce.config.Extraction.FocusOpcodes {
		focusOpcodes[op] = true
	}

	// 用于跟踪循环
	pcCounts := make(map[uint64]int)
	loopThreshold := 3 // 同一PC执行超过3次视为循环

	// 分析每个trace步骤
	for i, step := range trace.StructLogs {
		// 检查深度限制
		if i >= ce.config.Extraction.MaxTraceDepth {
			ce.filteredByDepth++
			break
		}

		// 检查是否是循环
		if ce.config.Extraction.IgnoreLoops {
			pcCounts[step.PC]++
			if pcCounts[step.PC] > loopThreshold {
				continue // 跳过循环中的重复执行
			}
		}

		// 检查是否是关注的操作码
		if !focusOpcodes[step.Op] {
			continue
		}

		// 提取约束
		extracted := ce.extractFromStep(step, i, paramValues)
		for _, c := range extracted {
			c.ID = fmt.Sprintf("C%d", constraintID)
			constraintID++
			constraints = append(constraints, c)

			// 检查分支限制
			if len(constraints) >= ce.config.Extraction.MaxBranches {
				ce.filteredByBranch++
				return constraints
			}
		}
	}

	ce.totalExtracted = len(constraints)
	return constraints
}

// extractFromStep 从单个trace步骤提取约束
func (ce *ConstraintExtractor) extractFromStep(
	step EVMTraceStep,
	traceIndex int,
	paramValues []*big.Int,
) []PathConstraint {
	constraints := []PathConstraint{}

	// 需要至少2个栈元素进行比较操作
	if len(step.Stack) < 2 {
		return constraints
	}

	// 获取栈顶元素
	stackTop1, ok1 := ce.parseStackValue(step.Stack[len(step.Stack)-1])
	stackTop2, ok2 := ce.parseStackValue(step.Stack[len(step.Stack)-2])
	if !ok1 || !ok2 {
		return constraints
	}

	// 检查栈值是否与参数相关
	for paramIdx, paramVal := range paramValues {
		if paramVal == nil {
			continue
		}

		var constraint *PathConstraint

		switch step.Op {
		case "LT", "SLT":
			// a < b: 检查参数是否是操作数之一
			if stackTop1.Cmp(paramVal) == 0 {
				// param < stackTop2
				constraint = NewPathConstraint(paramIdx, ConstraintLT, stackTop2)
			} else if stackTop2.Cmp(paramVal) == 0 {
				// stackTop1 < param  =>  param > stackTop1
				constraint = NewPathConstraint(paramIdx, ConstraintGT, stackTop1)
			}

		case "GT", "SGT":
			if stackTop1.Cmp(paramVal) == 0 {
				// param > stackTop2
				constraint = NewPathConstraint(paramIdx, ConstraintGT, stackTop2)
			} else if stackTop2.Cmp(paramVal) == 0 {
				// stackTop1 > param  =>  param < stackTop1
				constraint = NewPathConstraint(paramIdx, ConstraintLT, stackTop1)
			}

		case "EQ":
			if stackTop1.Cmp(paramVal) == 0 || stackTop2.Cmp(paramVal) == 0 {
				// 确定另一个操作数
				var otherVal *big.Int
				if stackTop1.Cmp(paramVal) == 0 {
					otherVal = stackTop2
				} else {
					otherVal = stackTop1
				}
				constraint = NewPathConstraint(paramIdx, ConstraintEQ, otherVal)
			}

		case "ISZERO":
			// ISZERO只有一个操作数
			if stackTop1.Cmp(paramVal) == 0 {
				constraint = NewPathConstraint(paramIdx, ConstraintEQ, big.NewInt(0))
			}

		case "JUMPI":
			// JUMPI: [condition, dest] - 分析条件
			// 需要回溯查看条件是如何计算的
			// 这里简化处理,只记录有JUMPI分支
			if ce.isRelatedToParam(step, paramValues) {
				constraint = &PathConstraint{
					ParamIndex: paramIdx,
					Type:       ConstraintEQ, // 占位
					Source:     SourceJUMPI,
					Confidence: 0.5, // 较低置信度,因为关系不明确
				}
			}
		}

		if constraint != nil {
			constraint.Source = SourceJUMPI
			constraint.Opcode = step.Op
			constraint.TraceIndex = traceIndex
			constraint.Confidence = ce.calculateConstraintConfidence(constraint, step)
			constraints = append(constraints, *constraint)
		}
	}

	return constraints
}

// parseParamValues 解析参数值为big.Int
func (ce *ConstraintExtractor) parseParamValues(values []interface{}) []*big.Int {
	result := make([]*big.Int, len(values))

	for i, v := range values {
		switch val := v.(type) {
		case *big.Int:
			result[i] = val
		case int64:
			result[i] = big.NewInt(val)
		case uint64:
			result[i] = new(big.Int).SetUint64(val)
		case string:
			if n, ok := new(big.Int).SetString(val, 0); ok {
				result[i] = n
			}
		case common.Address:
			result[i] = new(big.Int).SetBytes(val.Bytes())
		default:
			// 尝试JSON序列化后解析
			if data, err := json.Marshal(val); err == nil {
				if n, ok := new(big.Int).SetString(string(data), 0); ok {
					result[i] = n
				}
			}
		}
	}

	return result
}

// parseStackValue 解析栈值
func (ce *ConstraintExtractor) parseStackValue(hexStr string) (*big.Int, bool) {
	// 移除0x前缀
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if hexStr == "" {
		return big.NewInt(0), true
	}

	val, ok := new(big.Int).SetString(hexStr, 16)
	return val, ok
}

// isRelatedToParam 检查trace步骤是否与参数相关
func (ce *ConstraintExtractor) isRelatedToParam(step EVMTraceStep, paramValues []*big.Int) bool {
	for _, stackVal := range step.Stack {
		val, ok := ce.parseStackValue(stackVal)
		if !ok {
			continue
		}

		for _, paramVal := range paramValues {
			if paramVal != nil && val.Cmp(paramVal) == 0 {
				return true
			}
		}
	}
	return false
}

// calculateConstraintConfidence 计算约束置信度
func (ce *ConstraintExtractor) calculateConstraintConfidence(
	constraint *PathConstraint,
	step EVMTraceStep,
) float64 {
	confidence := 1.0

	// 基于操作码类型调整
	switch step.Op {
	case "EQ", "ISZERO":
		confidence = 0.95 // 精确匹配,高置信度
	case "LT", "GT":
		confidence = 0.9 // 比较操作
	case "SLT", "SGT":
		confidence = 0.85 // 有符号比较,稍低
	case "JUMPI":
		confidence = 0.7 // 条件跳转,需要更多分析
	}

	// 基于深度调整 (越深置信度越低)
	depthPenalty := float64(step.Depth) * 0.01
	confidence -= depthPenalty
	if confidence < 0.3 {
		confidence = 0.3
	}

	return confidence
}

// calculateCoverage 计算覆盖率信息
func (ce *ConstraintExtractor) calculateCoverage(trace *EVMTrace) CoverageInfo {
	info := CoverageInfo{}

	// 统计唯一PC
	pcSet := make(map[uint64]bool)
	branchSet := make(map[uint64]bool)

	for _, step := range trace.StructLogs {
		pcSet[step.PC] = true
		if step.Op == "JUMPI" {
			branchSet[step.PC] = true
		}
	}

	info.TotalBranches = len(branchSet)
	info.CoveredBranches = len(branchSet) // 所有遇到的分支都算覆盖
	info.TotalPaths = 1                   // 单一路径
	info.CoveredPaths = 1

	if info.TotalBranches > 0 {
		info.Coverage = float64(info.CoveredBranches) / float64(info.TotalBranches) * 100
	} else {
		info.Coverage = 100
	}

	return info
}

// generateSymbolicSeeds 从约束生成符号种子
func (ce *ConstraintExtractor) generateSymbolicSeeds(
	constraints []PathConstraint,
	paramValues []*big.Int,
) []SymbolicSeed {
	seeds := []SymbolicSeed{}

	// 按参数索引分组约束
	paramConstraints := make(map[int][]PathConstraint)
	for _, c := range constraints {
		paramConstraints[c.ParamIndex] = append(paramConstraints[c.ParamIndex], c)
	}

	// 为每个参数生成种子
	for paramIdx, constraints := range paramConstraints {
		paramSeeds := ce.generateSeedsForParam(paramIdx, constraints, paramValues)
		seeds = append(seeds, paramSeeds...)
	}

	// 按优先级排序
	ce.sortSeedsByPriority(seeds)

	// 限制数量
	maxSeeds := ce.config.Integration.MaxSymbolicSeeds
	if len(seeds) > maxSeeds {
		seeds = seeds[:maxSeeds]
	}

	return seeds
}

// generateSeedsForParam 为单个参数生成种子
func (ce *ConstraintExtractor) generateSeedsForParam(
	paramIdx int,
	constraints []PathConstraint,
	paramValues []*big.Int,
) []SymbolicSeed {
	seeds := []SymbolicSeed{}

	for _, c := range constraints {
		if c.Confidence < ce.config.Integration.ConfidenceThreshold {
			continue
		}

		switch c.Type {
		case ConstraintLT:
			// x < value: 生成边界值
			if c.Value != nil {
				// 边界值: value - 1
				boundary := new(big.Int).Sub(c.Value, big.NewInt(1))
				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       boundary,
					Confidence:  c.Confidence * 0.9,
					Priority:    80,
					Reason:      fmt.Sprintf("boundary for %s < %s", "param", c.Value.String()),
					SourceType: "boundary",
				})

				// 跨越边界: value
				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       c.Value,
					Confidence:  c.Confidence * 0.85,
					Priority:    70,
					Reason:      "cross boundary",
					SourceType: "boundary_adjacent",
				})
			}

		case ConstraintGT:
			// x > value
			if c.Value != nil {
				boundary := new(big.Int).Add(c.Value, big.NewInt(1))
				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       boundary,
					Confidence:  c.Confidence * 0.9,
					Priority:    80,
					Reason:      fmt.Sprintf("boundary for %s > %s", "param", c.Value.String()),
					SourceType: "boundary",
				})

				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       c.Value,
					Confidence:  c.Confidence * 0.85,
					Priority:    70,
					Reason:      "cross boundary",
					SourceType: "boundary_adjacent",
				})
			}

		case ConstraintEQ:
			// x == value: 精确值是高优先级种子
			if c.Value != nil {
				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       c.Value,
					Confidence:  c.Confidence,
					Priority:    100, // 最高优先级
					Reason:      "exact match constraint",
					SourceType: "solution",
				})
			}

		case ConstraintRANGE:
			// 范围约束: 生成边界和中点
			if c.MinValue != nil && c.MaxValue != nil {
				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       c.MinValue,
					Confidence:  c.Confidence * 0.9,
					Priority:    85,
					Reason:      "range min",
					SourceType: "boundary",
				})

				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       c.MaxValue,
					Confidence:  c.Confidence * 0.9,
					Priority:    85,
					Reason:      "range max",
					SourceType: "boundary",
				})

				// 中点
				mid := new(big.Int).Add(c.MinValue, c.MaxValue)
				mid.Div(mid, big.NewInt(2))
				seeds = append(seeds, SymbolicSeed{
					ParamIndex:  paramIdx,
					Value:       mid,
					Confidence:  c.Confidence * 0.8,
					Priority:    75,
					Reason:      "range midpoint",
					SourceType: "solution",
				})
			}
		}
	}

	return seeds
}

// sortSeedsByPriority 按优先级排序种子
func (ce *ConstraintExtractor) sortSeedsByPriority(seeds []SymbolicSeed) {
	// 简单冒泡排序 (种子数量通常不大)
	for i := 0; i < len(seeds)-1; i++ {
		for j := 0; j < len(seeds)-i-1; j++ {
			if seeds[j].Priority < seeds[j+1].Priority {
				seeds[j], seeds[j+1] = seeds[j+1], seeds[j]
			}
		}
	}
}

// GetStatistics 获取提取统计信息
func (ce *ConstraintExtractor) GetStatistics() map[string]int {
	return map[string]int{
		"total_extracted":     ce.totalExtracted,
		"filtered_by_depth":   ce.filteredByDepth,
		"filtered_by_branch":  ce.filteredByBranch,
	}
}
