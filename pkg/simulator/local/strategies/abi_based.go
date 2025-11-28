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

// ABIBasedStrategy ABI类型感知变异策略
// 根据ABI参数类型生成针对性的边界值和特殊值
type ABIBasedStrategy struct{}

// NewABIBasedStrategy 创建ABI类型感知策略
func NewABIBasedStrategy() local.MutationStrategy {
	return &ABIBasedStrategy{}
}

// Name 返回策略名称
func (s *ABIBasedStrategy) Name() string {
	return "ABIBased"
}

// Applicable 判断是否适用于该类型
func (s *ABIBasedStrategy) Applicable(paramType abi.Type) bool {
	// 适用于所有基本类型
	return true
}

// Priority 返回策略优先级
func (s *ABIBasedStrategy) Priority() int {
	// 中等优先级，低于种子驱动策略
	return 50
}

// GenerateVariations 生成变异值
func (s *ABIBasedStrategy) GenerateVariations(
	original interface{},
	paramType abi.Type,
	count int,
) ([]interface{}, error) {
	switch paramType.T {
	case abi.UintTy:
		return s.generateUintVariations(paramType, count)
	case abi.IntTy:
		return s.generateIntVariations(paramType, count)
	case abi.AddressTy:
		return s.generateAddressVariations(count)
	case abi.BoolTy:
		return s.generateBoolVariations()
	case abi.BytesTy, abi.FixedBytesTy:
		return s.generateBytesVariations(paramType, count)
	case abi.StringTy:
		return s.generateStringVariations(count)
	default:
		return nil, fmt.Errorf("unsupported type: %s", paramType.String())
	}
}

// generateUintVariations 生成uint类型的变异值
func (s *ABIBasedStrategy) generateUintVariations(paramType abi.Type, count int) ([]interface{}, error) {
	var variations []interface{}

	// 获取类型的最大值
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(paramType.Size))
	maxVal.Sub(maxVal, big.NewInt(1))

	// 边界值和特殊值
	specialValues := []*big.Int{
		big.NewInt(0),                    // 零值
		big.NewInt(1),                    // 最小正数
		big.NewInt(2),                    // 2
		big.NewInt(100),                  // 100
		big.NewInt(1000),                 // 1000
		new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), // 1e18 (DeFi常用)
		new(big.Int).Exp(big.NewInt(10), big.NewInt(6), nil),  // 1e6 (USDC等)
		new(big.Int).Sub(maxVal, big.NewInt(1)),               // max - 1
		maxVal,                                                // 最大值
	}

	for _, val := range specialValues {
		variations = append(variations, new(big.Int).Set(val))
		if len(variations) >= count {
			return variations[:count], nil
		}
	}

	// 如果还需要更多，生成随机值
	for len(variations) < count {
		randVal := new(big.Int).Rand(rand.New(rand.NewSource(rand.Int63())), maxVal)
		variations = append(variations, randVal)
	}

	return variations, nil
}

// generateIntVariations 生成int类型的变异值
func (s *ABIBasedStrategy) generateIntVariations(paramType abi.Type, count int) ([]interface{}, error) {
	var variations []interface{}

	// 获取类型的最大值和最小值
	maxVal := new(big.Int).Lsh(big.NewInt(1), uint(paramType.Size-1))
	maxVal.Sub(maxVal, big.NewInt(1))
	minVal := new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), uint(paramType.Size-1)))

	// 边界值和特殊值
	specialValues := []*big.Int{
		big.NewInt(0),                      // 零值
		big.NewInt(1),                      // 1
		big.NewInt(-1),                     // -1
		new(big.Int).Add(minVal, big.NewInt(1)), // min + 1
		minVal,                             // 最小值
		new(big.Int).Sub(maxVal, big.NewInt(1)), // max - 1
		maxVal,                             // 最大值
	}

	for _, val := range specialValues {
		variations = append(variations, new(big.Int).Set(val))
		if len(variations) >= count {
			return variations[:count], nil
		}
	}

	// 生成随机值
	for len(variations) < count {
		randVal := new(big.Int).Rand(rand.New(rand.NewSource(rand.Int63())), maxVal)
		if rand.Intn(2) == 0 {
			randVal.Neg(randVal)
		}
		variations = append(variations, randVal)
	}

	return variations, nil
}

// generateAddressVariations 生成address类型的变异值
func (s *ABIBasedStrategy) generateAddressVariations(count int) ([]interface{}, error) {
	var variations []interface{}

	// 特殊地址
	specialAddresses := []common.Address{
		common.HexToAddress("0x0000000000000000000000000000000000000000"), // 零地址
		common.HexToAddress("0x0000000000000000000000000000000000000001"), // 预编译合约1
		common.HexToAddress("0x0000000000000000000000000000000000000002"), // 预编译合约2
		common.HexToAddress("0x000000000000000000000000000000000000dEaD"), // 销毁地址
		common.HexToAddress("0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF"), // 全F地址
	}

	for _, addr := range specialAddresses {
		variations = append(variations, addr)
		if len(variations) >= count {
			return variations[:count], nil
		}
	}

	// 生成随机地址
	for len(variations) < count {
		randomAddr := common.BytesToAddress(randBytes(20))
		variations = append(variations, randomAddr)
	}

	return variations, nil
}

// generateBoolVariations 生成bool类型的变异值
func (s *ABIBasedStrategy) generateBoolVariations() ([]interface{}, error) {
	return []interface{}{false, true}, nil
}

// generateBytesVariations 生成bytes类型的变异值
func (s *ABIBasedStrategy) generateBytesVariations(paramType abi.Type, count int) ([]interface{}, error) {
	var variations []interface{}

	// 特殊值
	specialBytes := [][]byte{
		{},                              // 空bytes
		{0x00},                          // 单个零字节
		{0xFF},                          // 单个全1字节
		{0x00, 0x00, 0x00, 0x00},       // 4个零字节
		make([]byte, 32),                // 32个零字节
	}

	for _, b := range specialBytes {
		variations = append(variations, b)
		if len(variations) >= count {
			return variations[:count], nil
		}
	}

	// 生成随机bytes
	for len(variations) < count {
		length := 1 + rand.Intn(64) // 1到64字节
		randomBytes := randBytes(length)
		variations = append(variations, randomBytes)
	}

	return variations, nil
}

// generateStringVariations 生成string类型的变异值
func (s *ABIBasedStrategy) generateStringVariations(count int) ([]interface{}, error) {
	var variations []interface{}

	// 特殊字符串
	specialStrings := []string{
		"",                              // 空字符串
		"0",                             // "0"
		"1",                             // "1"
		"test",                          // 简单字符串
		"0x0000000000000000000000000000000000000000", // 地址格式
		string(make([]byte, 256)),       // 长字符串
	}

	for _, s := range specialStrings {
		variations = append(variations, s)
		if len(variations) >= count {
			return variations[:count], nil
		}
	}

	// 生成随机字符串
	for len(variations) < count {
		length := 1 + rand.Intn(32)
		randomStr := string(randBytes(length))
		variations = append(variations, randomStr)
	}

	return variations, nil
}

// randBytes 生成随机字节数组
func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
