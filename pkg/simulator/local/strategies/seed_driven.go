// Package strategies 提供参数变异策略实现
package strategies

import (
	"fmt"
	"math/big"
	"math/rand"

	"autopath/pkg/simulator/local"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// SeedDrivenStrategy 种子驱动变异策略
// 优先使用预定义的攻击种子值，这些值来自真实攻击案例
type SeedDrivenStrategy struct {
	seedConfig *local.SeedConfig
}

// NewSeedDrivenStrategy 创建种子驱动策略
func NewSeedDrivenStrategy(seedConfig *local.SeedConfig) local.MutationStrategy {
	if seedConfig == nil {
		seedConfig = &local.SeedConfig{
			Enabled:     false,
			AttackSeeds: make(map[int][]interface{}),
		}
	}
	return &SeedDrivenStrategy{
		seedConfig: seedConfig,
	}
}

// Name 返回策略名称
func (s *SeedDrivenStrategy) Name() string {
	return "SeedDriven"
}

// Applicable 判断是否适用于该类型
func (s *SeedDrivenStrategy) Applicable(paramType abi.Type) bool {
	// 种子驱动策略适用于所有类型（如果有配置的种子）
	return s.seedConfig != nil && s.seedConfig.Enabled
}

// Priority 返回策略优先级
func (s *SeedDrivenStrategy) Priority() int {
	// 最高优先级，因为种子来自真实攻击
	return 100
}

// GenerateVariations 生成变异值
func (s *SeedDrivenStrategy) GenerateVariations(
	original interface{},
	paramType abi.Type,
	count int,
) ([]interface{}, error) {
	if !s.seedConfig.Enabled {
		return nil, fmt.Errorf("seed config is not enabled")
	}

	var variations []interface{}

	// 尝试从所有参数索引的种子中查找合适的值
	for _, seeds := range s.seedConfig.AttackSeeds {
		if len(seeds) == 0 {
			continue
		}

		for _, seed := range seeds {
			// 尝试类型转换
			converted, err := s.convertSeedToType(seed, paramType)
			if err == nil {
				variations = append(variations, converted)
				if len(variations) >= count {
					return variations[:count], nil
				}
			}
		}
	}

	// 如果种子数量不足，返回已有的
	if len(variations) > 0 {
		return variations, nil
	}

	return nil, fmt.Errorf("no suitable seeds found for type %s", paramType.String())
}

// convertSeedToType 将种子值转换为目标类型
func (s *SeedDrivenStrategy) convertSeedToType(seed interface{}, targetType abi.Type) (interface{}, error) {
	switch targetType.T {
	case abi.UintTy, abi.IntTy:
		return s.convertToInt(seed, targetType)

	case abi.AddressTy:
		return s.convertToAddress(seed)

	case abi.BoolTy:
		return s.convertToBool(seed)

	case abi.BytesTy, abi.FixedBytesTy:
		return s.convertToBytes(seed)

	case abi.StringTy:
		return s.convertToString(seed)

	default:
		return nil, fmt.Errorf("unsupported type: %s", targetType.String())
	}
}

// convertToInt 转换为整数
func (s *SeedDrivenStrategy) convertToInt(seed interface{}, targetType abi.Type) (interface{}, error) {
	switch v := seed.(type) {
	case int:
		return big.NewInt(int64(v)), nil
	case int64:
		return big.NewInt(v), nil
	case uint64:
		return new(big.Int).SetUint64(v), nil
	case *big.Int:
		return new(big.Int).Set(v), nil
	case string:
		// 尝试解析字符串
		val, ok := new(big.Int).SetString(v, 0)
		if !ok {
			return nil, fmt.Errorf("failed to parse string %s as int", v)
		}
		return val, nil
	default:
		return nil, fmt.Errorf("cannot convert %T to int", seed)
	}
}

// convertToAddress 转换为地址
func (s *SeedDrivenStrategy) convertToAddress(seed interface{}) (interface{}, error) {
	switch v := seed.(type) {
	case common.Address:
		return v, nil
	case string:
		if !common.IsHexAddress(v) {
			return nil, fmt.Errorf("invalid address: %s", v)
		}
		return common.HexToAddress(v), nil
	case []byte:
		if len(v) != 20 {
			return nil, fmt.Errorf("invalid address bytes length: %d", len(v))
		}
		return common.BytesToAddress(v), nil
	default:
		return nil, fmt.Errorf("cannot convert %T to address", seed)
	}
}

// convertToBool 转换为布尔值
func (s *SeedDrivenStrategy) convertToBool(seed interface{}) (interface{}, error) {
	switch v := seed.(type) {
	case bool:
		return v, nil
	case int, int64, uint64:
		// 非零为true
		return v != 0, nil
	case string:
		return v == "true" || v == "1", nil
	default:
		return nil, fmt.Errorf("cannot convert %T to bool", seed)
	}
}

// convertToBytes 转换为字节数组
func (s *SeedDrivenStrategy) convertToBytes(seed interface{}) (interface{}, error) {
	switch v := seed.(type) {
	case []byte:
		return v, nil
	case string:
		// 尝试十六进制解码
		if len(v) >= 2 && v[:2] == "0x" {
			return common.FromHex(v), nil
		}
		return []byte(v), nil
	default:
		return nil, fmt.Errorf("cannot convert %T to bytes", seed)
	}
}

// convertToString 转换为字符串
func (s *SeedDrivenStrategy) convertToString(seed interface{}) (interface{}, error) {
	switch v := seed.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	case int, int64, uint64:
		return fmt.Sprintf("%d", v), nil
	case *big.Int:
		return v.String(), nil
	case common.Address:
		return v.Hex(), nil
	default:
		return fmt.Sprintf("%v", seed), nil
	}
}

// GetRandomSeed 从种子池中随机选择一个
func (s *SeedDrivenStrategy) GetRandomSeed(paramIndex int) interface{} {
	if !s.seedConfig.Enabled {
		return nil
	}

	seeds, exists := s.seedConfig.AttackSeeds[paramIndex]
	if !exists || len(seeds) == 0 {
		return nil
	}

	return seeds[rand.Intn(len(seeds))]
}
