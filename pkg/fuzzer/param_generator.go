package fuzzer

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// ParamGenerator 参数生成器
type ParamGenerator struct {
	maxVariations int
	strategy      *StrategyConfig
}

// NewParamGenerator 创建参数生成器
func NewParamGenerator(maxVariations int) *ParamGenerator {
	return &ParamGenerator{
		maxVariations: maxVariations,
		strategy:      DefaultStrategyConfig(),
	}
}

// NewParamGeneratorWithStrategy 使用策略创建参数生成器
func NewParamGeneratorWithStrategy(maxVariations int, strategy *StrategyConfig) *ParamGenerator {
	return &ParamGenerator{
		maxVariations: maxVariations,
		strategy:      strategy,
	}
}

// DefaultStrategyConfig 默认策略配置
func DefaultStrategyConfig() *StrategyConfig {
	return &StrategyConfig{
		Integers: IntegerStrategy{
			IncludeBoundaries:   true,
			IncludePercentages:  []int{1, 5, 10, 25, 50, 75, 90, 95, 99},
			IncludeCommonValues: true,
			BitFlipping:         true,
		},
		Addresses: AddressStrategy{
			IncludePrecompiles: true,
			IncludeZero:        true,
			IncludeRandom:      true,
			RandomCount:        10,
		},
		Bytes: BytesStrategy{
			IncludeEmpty:    true,
			IncludePatterns: true,
			MaxRandomLength: 1024,
		},
		Arrays: ArrayStrategy{
			TestLengths: []int{0, 1, 2, 10, 100, 1000},
			MaxElements: 1000,
		},
	}
}

// GenerateCombinations 生成参数组合
func (g *ParamGenerator) GenerateCombinations(params []Parameter) <-chan []interface{} {
	ch := make(chan []interface{}, 1000)

	go func() {
		defer close(ch)

		// 策略1: 单参数变异
		g.singleParamMutation(params, ch)

		// 策略2: 双参数组合变异
		if len(params) >= 2 {
			g.doubleParamMutation(params, ch)
		}

		// 策略3: 边界值全组合
		g.boundaryValueCombination(params, ch)

		// 策略4: 随机组合
		g.randomCombination(params, ch)

		// 策略5: 特殊攻击模式
		g.attackPatternCombination(params, ch)
	}()

	return ch
}

// GenerateVariations 为单个参数生成变体
func (g *ParamGenerator) GenerateVariations(param Parameter) []interface{} {
	switch {
	case strings.HasPrefix(param.Type, "uint"):
		return g.generateIntegerVariations(param, false)
	case strings.HasPrefix(param.Type, "int"):
		return g.generateIntegerVariations(param, true)
	case param.Type == "address":
		return g.generateAddressVariations(param)
	case param.Type == "bool":
		return g.generateBoolVariations(param)
	case strings.HasPrefix(param.Type, "bytes"):
		return g.generateBytesVariations(param)
	case param.Type == "string":
		return g.generateStringVariations(param)
	case strings.HasSuffix(param.Type, "[]"):
		return g.generateArrayVariations(param)
	default:
		// 未知类型，返回原值
		return []interface{}{param.Value}
	}
}

// generateIntegerVariations 生成整数变体
func (g *ParamGenerator) generateIntegerVariations(param Parameter, signed bool) []interface{} {
	original, ok := param.Value.(*big.Int)
	if !ok {
		// 尝试转换
		if bytes, ok := param.Value.([]byte); ok {
			original = new(big.Int).SetBytes(bytes)
		} else {
			return []interface{}{param.Value}
		}
	}

	bitSize := g.getBitSize(param.Type)
	variations := make([]interface{}, 0, g.maxVariations)

	// 基础值
	variations = append(variations,
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
	)

	// 原值附近的值
	if original.Sign() > 0 {
		variations = append(variations,
			new(big.Int).Sub(original, big.NewInt(1)),
			original,
			new(big.Int).Add(original, big.NewInt(1)),
			new(big.Int).Div(original, big.NewInt(2)),
			new(big.Int).Mul(original, big.NewInt(2)),
		)
	}

	// 百分比变化
	if g.strategy.Integers.IncludePercentages != nil {
		for _, p := range g.strategy.Integers.IncludePercentages {
			if original.Sign() > 0 {
				delta := new(big.Int).Div(
					new(big.Int).Mul(original, big.NewInt(int64(p))),
					big.NewInt(100),
				)
				variations = append(variations,
					new(big.Int).Add(original, delta),
					new(big.Int).Sub(original, delta),
				)
			}
		}
	}

	// 边界值
	if g.strategy.Integers.IncludeBoundaries {
		maxValue := g.getMaxValue(bitSize, signed)
		minValue := g.getMinValue(bitSize, signed)

		variations = append(variations,
			maxValue,
			new(big.Int).Sub(maxValue, big.NewInt(1)),
			new(big.Int).Div(maxValue, big.NewInt(2)),
			minValue,
			new(big.Int).Add(minValue, big.NewInt(1)),
		)
	}

	// 位翻转
	if g.strategy.Integers.BitFlipping && original.Sign() >= 0 {
		variations = append(variations,
			g.flipBit(original, 0),         // 翻转最低位
			g.flipBit(original, bitSize-1), // 翻转最高位
			g.flipBit(original, bitSize/2), // 翻转中间位
		)
	}

	// 常见攻击值
	if g.strategy.Integers.IncludeCommonValues {
		variations = append(variations,
			big.NewInt(0xDEADBEEF),
			big.NewInt(0x1337),
			big.NewInt(0xCAFEBABE),
			new(big.Int).Exp(big.NewInt(2), big.NewInt(128), nil), // 2^128
			new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil), // 1e18 (1 ETH in wei)
			new(big.Int).Exp(big.NewInt(10), big.NewInt(6), nil),  // 1e6 (USDC/USDT decimals)
		)
	}

	// 过滤无效值并限制数量
	return g.filterIntegerVariations(variations, bitSize, signed)
}

// generateAddressVariations 生成地址变体
func (g *ParamGenerator) generateAddressVariations(param Parameter) []interface{} {
	original, ok := param.Value.(common.Address)
	if !ok {
		// 尝试转换
		if bytes, ok := param.Value.([]byte); ok && len(bytes) >= 20 {
			original = common.BytesToAddress(bytes[len(bytes)-20:])
		}
	}

	pool := g.buildAddressPool(original)
	variations := make([]interface{}, 0, len(pool))

	for _, addr := range pool {
		variations = append(variations, addr)
		if len(variations) >= g.maxVariations {
			break
		}
	}

	return variations
}

// generateBoolVariations 生成布尔值变体
func (g *ParamGenerator) generateBoolVariations(param Parameter) []interface{} {
	return []interface{}{true, false}
}

// generateBytesVariations 生成字节数组变体
func (g *ParamGenerator) generateBytesVariations(param Parameter) []interface{} {
	original, ok := param.Value.([]byte)
	if !ok {
		original = []byte{}
	}

	variations := make([]interface{}, 0)

	// 空字节
	if g.strategy.Bytes.IncludeEmpty {
		variations = append(variations, []byte{})
	}

	// 原值
	if len(original) > 0 {
		variations = append(variations, original)
	}

	// 固定长度的字节数组
	if param.Size > 0 {
		// 全零
		variations = append(variations, bytes.Repeat([]byte{0x00}, param.Size))
		// 全一
		variations = append(variations, bytes.Repeat([]byte{0xFF}, param.Size))
		// 模式字节
		variations = append(variations, bytes.Repeat([]byte{0xAA}, param.Size))
		variations = append(variations, bytes.Repeat([]byte{0x55}, param.Size))
		// 递增序列
		seq := make([]byte, param.Size)
		for i := range seq {
			seq[i] = byte(i % 256)
		}
		variations = append(variations, seq)
	}

	// 动态字节数组
	if param.Size == 0 {
		// 不同长度
		lengths := []int{0, 1, 4, 32, 64, 128, 256}
		for _, length := range lengths {
			if length <= g.strategy.Bytes.MaxRandomLength {
				variations = append(variations, g.generateRandomBytes(length))
			}
		}
	}

	// 基于原值的变体
	if len(original) > 0 {
		// 翻转字节
		flipped := make([]byte, len(original))
		for i := range original {
			flipped[i] = original[len(original)-1-i]
		}
		variations = append(variations, flipped)

		// 修改第一个和最后一个字节
		if len(original) > 0 {
			modified := make([]byte, len(original))
			copy(modified, original)
			modified[0] ^= 0xFF
			variations = append(variations, modified)

			if len(original) > 1 {
				modified2 := make([]byte, len(original))
				copy(modified2, original)
				modified2[len(modified2)-1] ^= 0xFF
				variations = append(variations, modified2)
			}
		}
	}

	// 特殊模式
	if g.strategy.Bytes.IncludePatterns {
		patterns := [][]byte{
			[]byte("\x00\x00\x00\x00"),             // SQL注入尝试
			[]byte("A" + strings.Repeat("A", 100)), // 缓冲区溢出测试
			[]byte{0xDE, 0xAD, 0xBE, 0xEF},         // 经典模式
			[]byte{0xCA, 0xFE, 0xBA, 0xBE},         // Java类文件魔数
		}
		variations = append(variations, g.convertToInterface(patterns)...)
	}

	return variations
}

// generateStringVariations 生成字符串变体
func (g *ParamGenerator) generateStringVariations(param Parameter) []interface{} {
	original, ok := param.Value.(string)
	if !ok {
		if bytes, ok := param.Value.([]byte); ok {
			original = string(bytes)
		} else {
			original = ""
		}
	}

	variations := []interface{}{
		"",                              // 空串
		" ",                             // 空格
		original,                        // 原值
		strings.ToUpper(original),       // 大写
		strings.ToLower(original),       // 小写
		g.reverseString(original),       // 反转
		strings.Repeat("A", 1000),       // 长字符串
		"'; DROP TABLE users; --",       // SQL注入
		"<script>alert('xss')</script>", // XSS
		"../../../etc/passwd",           // 路径遍历
		"%00",                           // 空字节注入
		"\x00\x01\x02\x03",              // 控制字符
		"0x" + strings.Repeat("41", 20), // 假地址
		`{"key":"value"}`,               // JSON
		"!@#$%^&*()_+-=[]{}|;:,.<>?",    // 特殊字符
	}

	return variations
}

// generateArrayVariations 生成数组变体
func (g *ParamGenerator) generateArrayVariations(param Parameter) []interface{} {
	// 获取元素类型
	elementType := strings.TrimSuffix(param.Type, "[]")

	// 创建不同长度的数组
	variations := make([]interface{}, 0)

	// 地址数组禁止随机化：仅保留原始数组
	if elementType == "address" {
		addrPool := g.buildAddressPool(common.Address{})
		base := g.convertAddressArray(param.Value)
		if len(base) == 0 {
			base = g.pickAddressArray(addrPool, 1)
		}

		// 保留原值/基础数组
		variations = append(variations, base)

		// 空数组
		variations = append(variations, []interface{}{})

		// 多种长度的极端数组（包含零地址、广播地址、随机地址）
		lengthOptions := []int{1, 3, 10}
		if g.strategy.Arrays.MaxElements >= 50 {
			lengthOptions = append(lengthOptions, 50)
		}
		for _, ln := range lengthOptions {
			if ln <= g.strategy.Arrays.MaxElements {
				variations = append(variations, g.pickAddressArray(addrPool, ln))
			}
		}

		return variations
	}

	// 空数组
	variations = append(variations, []interface{}{})

	// 不同长度的数组
	for _, length := range g.strategy.Arrays.TestLengths {
		if length <= g.strategy.Arrays.MaxElements {
			arr := g.generateArrayOfLength(elementType, length)
			variations = append(variations, arr)
		}
	}

	// 包含特殊值的数组
	if elementType == "uint256" || strings.HasPrefix(elementType, "uint") {
		// 全零数组
		variations = append(variations, g.generateUniformArray(big.NewInt(0), 10))
		// 全最大值数组
		maxVal := g.getMaxValue(256, false)
		variations = append(variations, g.generateUniformArray(maxVal, 10))
		// 递增序列
		variations = append(variations, g.generateSequentialArray(10))
	}

	return variations
}

// singleParamMutation 单参数变异
func (g *ParamGenerator) singleParamMutation(params []Parameter, ch chan<- []interface{}) {
	for i, param := range params {
		variations := g.GenerateVariations(param)

		// 限制变体数量
		if len(variations) > g.maxVariations {
			variations = variations[:g.maxVariations]
		}

		for _, variation := range variations {
			combo := g.cloneParams(params)
			combo[i] = variation
			ch <- combo
		}
	}
}

// doubleParamMutation 双参数变异
func (g *ParamGenerator) doubleParamMutation(params []Parameter, ch chan<- []interface{}) {
	maxPerParam := 10 // 限制每个参数的变体数量

	for i := 0; i < len(params)-1; i++ {
		for j := i + 1; j < len(params); j++ {
			variations1 := g.GenerateVariations(params[i])
			variations2 := g.GenerateVariations(params[j])

			// 限制组合数量
			limit1 := min(maxPerParam, len(variations1))
			limit2 := min(maxPerParam, len(variations2))

			for k := 0; k < limit1; k++ {
				for l := 0; l < limit2; l++ {
					combo := g.cloneParams(params)
					combo[i] = variations1[k]
					combo[j] = variations2[l]
					ch <- combo
				}
			}
		}
	}
}

// boundaryValueCombination 边界值组合
func (g *ParamGenerator) boundaryValueCombination(params []Parameter, ch chan<- []interface{}) {
	combo := make([]interface{}, len(params))

	for i, param := range params {
		combo[i] = g.getBoundaryValue(param.Type)
	}

	ch <- combo
}

// randomCombination 随机组合
func (g *ParamGenerator) randomCombination(params []Parameter, ch chan<- []interface{}) {
	// 生成10个随机组合
	for i := 0; i < 10; i++ {
		combo := make([]interface{}, len(params))
		for j, param := range params {
			variations := g.GenerateVariations(param)
			if len(variations) > 0 {
				// 随机选择一个变体
				idx := g.randomInt(len(variations))
				combo[j] = variations[idx]
			} else {
				combo[j] = param.Value
			}
		}
		ch <- combo
	}
}

// attackPatternCombination 攻击模式组合
func (g *ParamGenerator) attackPatternCombination(params []Parameter, ch chan<- []interface{}) {
	// 整数溢出攻击模式
	overflowCombo := make([]interface{}, len(params))
	for i, param := range params {
		if strings.HasPrefix(param.Type, "uint") {
			overflowCombo[i] = g.getMaxValue(g.getBitSize(param.Type), false)
		} else {
			overflowCombo[i] = param.Value
		}
	}
	ch <- overflowCombo

	// 下溢攻击模式
	underflowCombo := make([]interface{}, len(params))
	for i, param := range params {
		if strings.HasPrefix(param.Type, "uint") {
			underflowCombo[i] = big.NewInt(0)
		} else {
			underflowCombo[i] = param.Value
		}
	}
	ch <- underflowCombo

	// 重入攻击模式（如果有地址参数）
	for i, param := range params {
		if param.Type == "address" {
			reentrancyCombo := g.cloneParams(params)
			// 使用攻击合约地址
			reentrancyCombo[i] = common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
			ch <- reentrancyCombo
		}
	}
}

// 辅助函数

func (g *ParamGenerator) getBitSize(typeName string) int {
	// 从类型名提取位大小
	typeName = strings.TrimPrefix(typeName, "u")
	typeName = strings.TrimPrefix(typeName, "int")

	var size int
	if _, err := fmt.Sscanf(typeName, "%d", &size); err != nil {
		return 256 // 默认256位
	}
	return size
}

func (g *ParamGenerator) getMaxValue(bitSize int, signed bool) *big.Int {
	if signed {
		// 有符号最大值: 2^(n-1) - 1
		return new(big.Int).Sub(
			new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitSize-1)), nil),
			big.NewInt(1),
		)
	}
	// 无符号最大值: 2^n - 1
	return new(big.Int).Sub(
		new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitSize)), nil),
		big.NewInt(1),
	)
}

func (g *ParamGenerator) getMinValue(bitSize int, signed bool) *big.Int {
	if signed {
		// 有符号最小值: -2^(n-1)
		return new(big.Int).Neg(
			new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bitSize-1)), nil),
		)
	}
	// 无符号最小值: 0
	return big.NewInt(0)
}

func (g *ParamGenerator) flipBit(n *big.Int, bit int) *big.Int {
	result := new(big.Int).Set(n)
	mask := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(bit)), nil)
	return result.Xor(result, mask)
}

func (g *ParamGenerator) generateRandomAddress() common.Address {
	var addr common.Address
	rand.Read(addr[:])
	return addr
}

func (g *ParamGenerator) generateRandomBytes(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func (g *ParamGenerator) reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func (g *ParamGenerator) cloneParams(params []Parameter) []interface{} {
	result := make([]interface{}, len(params))
	for i, param := range params {
		result[i] = param.Value
	}
	return result
}

func (g *ParamGenerator) getBoundaryValue(paramType string) interface{} {
	switch {
	case strings.HasPrefix(paramType, "uint"):
		return g.getMaxValue(g.getBitSize(paramType), false)
	case strings.HasPrefix(paramType, "int"):
		return g.getMaxValue(g.getBitSize(paramType), true)
	case paramType == "address":
		return common.HexToAddress("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
	case paramType == "bool":
		return true
	case strings.HasPrefix(paramType, "bytes"):
		if size := g.getBytesSize(paramType); size > 0 {
			return bytes.Repeat([]byte{0xFF}, size)
		}
		return bytes.Repeat([]byte{0xFF}, 32)
	default:
		return []byte{}
	}
}

func (g *ParamGenerator) getBytesSize(typeName string) int {
	if typeName == "bytes" {
		return 0 // 动态大小
	}
	var size int
	if _, err := fmt.Sscanf(typeName, "bytes%d", &size); err == nil {
		return size
	}
	return 32
}

func (g *ParamGenerator) filterIntegerVariations(variations []interface{}, bitSize int, signed bool) []interface{} {
	filtered := make([]interface{}, 0)
	seen := make(map[string]bool)

	maxValue := g.getMaxValue(bitSize, signed)
	minValue := g.getMinValue(bitSize, signed)

	for _, v := range variations {
		if n, ok := v.(*big.Int); ok {
			// 检查范围
			if n.Cmp(minValue) >= 0 && n.Cmp(maxValue) <= 0 {
				// 去重
				key := n.String()
				if !seen[key] {
					seen[key] = true
					filtered = append(filtered, n)
					if len(filtered) >= g.maxVariations {
						break
					}
				}
			}
		}
	}

	return filtered
}

func (g *ParamGenerator) convertToInterface(items [][]byte) []interface{} {
	result := make([]interface{}, len(items))
	for i, item := range items {
		result[i] = item
	}
	return result
}

func (g *ParamGenerator) generateArrayOfLength(elementType string, length int) []interface{} {
	arr := make([]interface{}, length)

	for i := 0; i < length; i++ {
		switch elementType {
		case "uint256", "uint":
			arr[i] = big.NewInt(int64(i))
		case "address":
			arr[i] = g.generateRandomAddress()
		case "bool":
			arr[i] = i%2 == 0
		default:
			arr[i] = []byte{byte(i)}
		}
	}

	return arr
}

func (g *ParamGenerator) generateUniformArray(value interface{}, length int) []interface{} {
	arr := make([]interface{}, length)
	for i := 0; i < length; i++ {
		arr[i] = value
	}
	return arr
}

func (g *ParamGenerator) generateSequentialArray(length int) []interface{} {
	arr := make([]interface{}, length)
	for i := 0; i < length; i++ {
		arr[i] = big.NewInt(int64(i))
	}
	return arr
}

// buildAddressPool 构造包含原值、极端值、随机值的地址池
func (g *ParamGenerator) buildAddressPool(original common.Address) []common.Address {
	pool := []common.Address{}
	seen := make(map[string]bool)

	add := func(addr common.Address) {
		key := strings.ToLower(addr.Hex())
		if !seen[key] {
			seen[key] = true
			pool = append(pool, addr)
		}
	}

	// 原始值优先
	if (original != common.Address{}) {
		add(original)
	}

	// 零地址 & 广播地址
	add(common.HexToAddress("0x0000000000000000000000000000000000000000"))
	add(common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"))

	// 攻击/占位地址
	add(common.HexToAddress("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))

	// 预编译合约（极低地址）
	if g.strategy.Addresses.IncludePrecompiles {
		for i := 1; i <= 9; i++ {
			add(common.BytesToAddress([]byte{byte(i)}))
		}
	}

	// 随机地址
	if g.strategy.Addresses.IncludeRandom {
		randomCount := g.strategy.Addresses.RandomCount
		if randomCount <= 0 {
			randomCount = 3
		}
		// 限制数量避免过多
		randomCount = min(randomCount, 5)
		for i := 0; i < randomCount; i++ {
			add(g.generateRandomAddress())
		}
	}

	return pool
}

// convertAddressArray 将各种地址数组转换为 []interface{}
func (g *ParamGenerator) convertAddressArray(val interface{}) []interface{} {
	switch v := val.(type) {
	case []interface{}:
		return v
	case []common.Address:
		arr := make([]interface{}, len(v))
		for i, item := range v {
			arr[i] = item
		}
		return arr
	default:
		return []interface{}{}
	}
}

// pickAddressArray 使用地址池构造指定长度的数组（循环取值）
func (g *ParamGenerator) pickAddressArray(pool []common.Address, length int) []interface{} {
	if len(pool) == 0 {
		pool = []common.Address{common.HexToAddress("0x0000000000000000000000000000000000000000")}
	}
	arr := make([]interface{}, length)
	for i := 0; i < length; i++ {
		arr[i] = pool[i%len(pool)]
	}
	return arr
}

func (g *ParamGenerator) randomInt(max int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(max)))
	return int(n.Int64())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
