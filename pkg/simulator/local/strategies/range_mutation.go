// Package strategies 提供参数变异策略实现
package strategies

import (
	"fmt"
	"math/big"

	"autopath/pkg/simulator/local"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// RangeMutationStrategy 范围变异策略
// 基于原始值进行百分比范围变异（±1%, ±5%, ±50%等）
type RangeMutationStrategy struct {
	// rangePercents 变异范围百分比列表
	rangePercents []int
}

// NewRangeMutationStrategy 创建范围变异策略
func NewRangeMutationStrategy() local.MutationStrategy {
	return &RangeMutationStrategy{
		// 默认变异范围：±1%, ±5%, ±10%, ±50%, ±100%
		rangePercents: []int{1, 5, 10, 50, 100},
	}
}

// NewRangeMutationStrategyWithPercents 创建自定义范围的变异策略
func NewRangeMutationStrategyWithPercents(percents []int) local.MutationStrategy {
	return &RangeMutationStrategy{
		rangePercents: percents,
	}
}

// Name 返回策略名称
func (s *RangeMutationStrategy) Name() string {
	return "RangeMutation"
}

// Applicable 判断是否适用于该类型
func (s *RangeMutationStrategy) Applicable(paramType abi.Type) bool {
	// 仅适用于数值类型
	return paramType.T == abi.UintTy || paramType.T == abi.IntTy
}

// Priority 返回策略优先级
func (s *RangeMutationStrategy) Priority() int {
	// 较低优先级，作为补充策略
	return 30
}

// GenerateVariations 生成变异值
func (s *RangeMutationStrategy) GenerateVariations(
	original interface{},
	paramType abi.Type,
	count int,
) ([]interface{}, error) {
	// 仅支持数值类型
	if paramType.T != abi.UintTy && paramType.T != abi.IntTy {
		return nil, fmt.Errorf("range mutation only supports int/uint types, got %s", paramType.String())
	}

	// 转换原始值为big.Int
	originalVal, err := toBigInt(original)
	if err != nil {
		return nil, fmt.Errorf("failed to convert original value: %w", err)
	}

	var variations []interface{}

	// 为每个百分比生成上下两个变异值
	for _, percent := range s.rangePercents {
		// 计算变化量：original * percent / 100
		delta := new(big.Int).Mul(originalVal, big.NewInt(int64(percent)))
		delta.Div(delta, big.NewInt(100))

		// 向上变异：original + delta
		upper := new(big.Int).Add(originalVal, delta)
		variations = append(variations, upper)

		// 向下变异：original - delta
		if paramType.T == abi.UintTy {
			// uint类型，确保不为负
			if delta.Cmp(originalVal) < 0 {
				lower := new(big.Int).Sub(originalVal, delta)
				variations = append(variations, lower)
			} else {
				// delta >= original，下限为0
				variations = append(variations, big.NewInt(0))
			}
		} else {
			// int类型，允许负数
			lower := new(big.Int).Sub(originalVal, delta)
			variations = append(variations, lower)
		}

		if len(variations) >= count {
			return variations[:count], nil
		}
	}

	return variations, nil
}

// toBigInt 将interface{}转换为*big.Int
func toBigInt(value interface{}) (*big.Int, error) {
	switch v := value.(type) {
	case *big.Int:
		return new(big.Int).Set(v), nil
	case int:
		return big.NewInt(int64(v)), nil
	case int64:
		return big.NewInt(v), nil
	case uint64:
		return new(big.Int).SetUint64(v), nil
	case string:
		val, ok := new(big.Int).SetString(v, 0)
		if !ok {
			return nil, fmt.Errorf("failed to parse string %s as big.Int", v)
		}
		return val, nil
	default:
		return nil, fmt.Errorf("unsupported type %T for big.Int conversion", value)
	}
}
