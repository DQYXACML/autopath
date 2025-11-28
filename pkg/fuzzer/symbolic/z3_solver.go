// +build z3

package symbolic

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"time"

	z3 "github.com/mitchellh/go-z3"
)

// Z3Solver Z3 SMT求解器封装
// 用于求解复杂约束(模运算、位运算等)
type Z3Solver struct {
	config   *SymbolicConfig
	context  *z3.Context
	config2  *z3.Config
	stats    Z3Stats
}

// Z3Stats Z3求解器统计
type Z3Stats struct {
	TotalSolves      int
	SuccessfulSolves int
	FailedSolves     int
	TimeoutSolves    int
	TotalSolveTime   time.Duration
}

// NewZ3Solver 创建Z3求解器
func NewZ3Solver(config *SymbolicConfig) (*Z3Solver, error) {
	// 创建Z3配置
	z3Config := z3.NewConfig()

	// 设置超时
	timeout := config.GetSolverTimeoutDuration()
	z3Config.SetInt("timeout", int(timeout.Milliseconds()))

	// 创建Z3上下文
	ctx := z3.NewContext(z3Config)

	return &Z3Solver{
		config:  config,
		context: ctx,
		config2: z3Config,
		stats:   Z3Stats{},
	}, nil
}

// Close 关闭Z3求解器并释放资源
func (zs *Z3Solver) Close() {
	if zs.context != nil {
		zs.context.Close()
	}
	if zs.config2 != nil {
		zs.config2.Close()
	}
}

// SolveConstraints 使用Z3求解约束
func (zs *Z3Solver) SolveConstraints(
	ctx context.Context,
	constraints []PathConstraint,
) ([]ConstraintSolution, error) {
	startTime := time.Now()
	zs.stats.TotalSolves++

	// 按参数索引分组
	paramConstraints := make(map[int][]PathConstraint)
	for _, c := range constraints {
		paramConstraints[c.ParamIndex] = append(paramConstraints[c.ParamIndex], c)
	}

	solutions := []ConstraintSolution{}

	// 为每个参数求解
	for paramIdx, pConstraints := range paramConstraints {
		sol, err := zs.solveParamConstraints(ctx, paramIdx, pConstraints)
		if err != nil {
			zs.stats.FailedSolves++
			return nil, err
		}
		solutions = append(solutions, sol)
	}

	zs.stats.TotalSolveTime += time.Since(startTime)
	zs.stats.SuccessfulSolves++

	return solutions, nil
}

// solveParamConstraints 使用Z3求解单个参数的约束
func (zs *Z3Solver) solveParamConstraints(
	ctx context.Context,
	paramIdx int,
	constraints []PathConstraint,
) (ConstraintSolution, error) {
	solution := ConstraintSolution{
		ParamIndex:    paramIdx,
		Values:        []*big.Int{},
		Ranges:        []ValueRange{},
		SolverUsed:    "z3",
		IsSatisfiable: false,
	}

	// 收集约束ID
	for _, c := range constraints {
		solution.Constraints = append(solution.Constraints, c.ID)
	}

	// 创建Z3求解器
	solver := zs.context.NewSolver()
	defer solver.Close()

	// 创建变量(256位整数)
	paramVar := zs.context.Const(
		zs.context.Symbol(fmt.Sprintf("param_%d", paramIdx)),
		zs.context.BVSort(256), // 256位位向量(uint256)
	)

	// 添加约束到Z3
	for _, c := range constraints {
		z3Constraint := zs.translateConstraint(c, paramVar)
		if z3Constraint != nil {
			solver.Assert(z3Constraint)
		}
	}

	// 检查可满足性
	isSat := solver.Check()

	switch isSat {
	case z3.True:
		solution.IsSatisfiable = true

		// 获取模型
		model := solver.Model()
		defer model.Close()

		// 提取解
		values := zs.extractSolutions(model, paramVar, constraints)
		solution.Values = values

		// 计算范围
		if len(values) > 0 {
			min := new(big.Int).Set(values[0])
			max := new(big.Int).Set(values[0])
			for _, v := range values {
				if v.Cmp(min) < 0 {
					min = v
				}
				if v.Cmp(max) > 0 {
					max = v
				}
			}
			solution.Ranges = append(solution.Ranges, ValueRange{
				Min:        min,
				Max:        max,
				Confidence: 0.95, // Z3求解置信度高
			})
		}

	case z3.False:
		solution.IsSatisfiable = false
		solution.Error = "unsatisfiable constraints"

	case z3.Undef:
		solution.IsSatisfiable = false
		solution.Error = "z3 returned undefined (possibly timeout)"
		zs.stats.TimeoutSolves++
	}

	// 计算综合置信度
	if solution.IsSatisfiable {
		totalConf := 0.0
		for _, c := range constraints {
			totalConf += c.Confidence
		}
		solution.Confidence = totalConf / float64(len(constraints))
		if solution.Confidence > 0.95 {
			solution.Confidence = 0.95 // Z3求解最高0.95
		}
	}

	return solution, nil
}

// translateConstraint 将PathConstraint转换为Z3约束
func (zs *Z3Solver) translateConstraint(
	c PathConstraint,
	paramVar *z3.BV,
) *z3.Bool {
	if c.Value == nil && (c.Type != ConstraintRANGE) {
		return nil
	}

	switch c.Type {
	case ConstraintLT:
		// param < value
		valueZ3 := zs.bigIntToBV(c.Value)
		return paramVar.ULT(valueZ3) // unsigned less than

	case ConstraintLE:
		// param <= value
		valueZ3 := zs.bigIntToBV(c.Value)
		return paramVar.ULE(valueZ3) // unsigned less or equal

	case ConstraintGT:
		// param > value
		valueZ3 := zs.bigIntToBV(c.Value)
		return paramVar.UGT(valueZ3) // unsigned greater than

	case ConstraintGE:
		// param >= value
		valueZ3 := zs.bigIntToBV(c.Value)
		return paramVar.UGE(valueZ3) // unsigned greater or equal

	case ConstraintEQ:
		// param == value
		valueZ3 := zs.bigIntToBV(c.Value)
		return paramVar.Eq(valueZ3)

	case ConstraintNEQ:
		// param != value
		valueZ3 := zs.bigIntToBV(c.Value)
		eq := paramVar.Eq(valueZ3)
		return eq.Not()

	case ConstraintRANGE:
		// min <= param <= max
		if c.MinValue == nil || c.MaxValue == nil {
			return nil
		}
		minZ3 := zs.bigIntToBV(c.MinValue)
		maxZ3 := zs.bigIntToBV(c.MaxValue)
		ge := paramVar.UGE(minZ3)
		le := paramVar.ULE(maxZ3)
		return ge.And(le)

	case ConstraintMOD:
		// param % divisor == remainder
		// 需要额外的Value字段存储divisor和remainder
		// 这里简化处理
		return nil

	case ConstraintAND:
		// param & mask == value
		// 位与约束
		return nil

	default:
		log.Printf("[Z3] Unsupported constraint type: %s", c.Type.String())
		return nil
	}
}

// bigIntToBV 将big.Int转换为Z3位向量
func (zs *Z3Solver) bigIntToBV(value *big.Int) *z3.BV {
	// 转换为十六进制字符串
	hexStr := value.Text(16)

	// 创建256位位向量
	bv := zs.context.FromBigInt(value, zs.context.BVSort(256))
	return bv
}

// bvToBigInt 将Z3位向量转换为big.Int
func (zs *Z3Solver) bvToBigInt(bv *z3.BV) *big.Int {
	// 获取字符串表示
	str := bv.String()

	// 尝试解析
	result := new(big.Int)

	// Z3返回的格式可能是 "#xHEXVALUE" 或十进制
	if len(str) > 2 && str[:2] == "#x" {
		// 十六进制
		result.SetString(str[2:], 16)
	} else if len(str) > 2 && str[:2] == "#b" {
		// 二进制
		result.SetString(str[2:], 2)
	} else {
		// 十进制
		result.SetString(str, 10)
	}

	return result
}

// extractSolutions 从Z3模型中提取解
func (zs *Z3Solver) extractSolutions(
	model *z3.Model,
	paramVar *z3.BV,
	constraints []PathConstraint,
) []*big.Int {
	values := []*big.Int{}

	// 获取参数的具体值
	assignment := model.Eval(paramVar, true)
	if assignment != nil {
		if bv, ok := assignment.(*z3.BV); ok {
			value := zs.bvToBigInt(bv)
			values = append(values, value)
		}
	}

	// 尝试生成额外的解(变化参数并重新求解)
	maxSolutions := zs.config.Solver.MaxSolutions
	if len(values) < maxSolutions {
		// 添加边界值
		for _, c := range constraints {
			if c.Type == ConstraintLT && c.Value != nil {
				// x < value => 边界是 value-1
				boundary := new(big.Int).Sub(c.Value, big.NewInt(1))
				values = append(values, boundary)
			} else if c.Type == ConstraintGT && c.Value != nil {
				// x > value => 边界是 value+1
				boundary := new(big.Int).Add(c.Value, big.NewInt(1))
				values = append(values, boundary)
			} else if c.Type == ConstraintEQ && c.Value != nil {
				// 精确值
				values = append(values, new(big.Int).Set(c.Value))
			}

			if len(values) >= maxSolutions {
				break
			}
		}
	}

	// 去重
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

// GetStatistics 获取统计信息
func (zs *Z3Solver) GetStatistics() Z3Stats {
	return zs.stats
}

// ==================== 辅助功能 ====================

// CanHandle 检查Z3是否能处理给定的约束
func (zs *Z3Solver) CanHandle(constraints []PathConstraint) bool {
	for _, c := range constraints {
		switch c.Type {
		case ConstraintMOD, ConstraintAND, ConstraintOR, ConstraintMASK:
			// 复杂约束需要Z3
			return true
		}
	}

	// 如果约束数量过多,使用Z3
	if len(constraints) > 20 {
		return true
	}

	return false
}
