package fuzzer

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"reflect"
	"sort"
	"strings"

	"autopath/pkg/fuzzer/symbolic"

	"github.com/ethereum/go-ethereum/common"
)

// SeedConfig 种子驱动模糊测试配置
type SeedConfig struct {
	Enabled        bool                     `yaml:"enabled" json:"enabled"`
	AttackSeeds    map[int][]interface{}    `yaml:"attack_seeds" json:"attack_seeds"` // 参数索引 → 攻击参数值列表
	RangeConfig    SeedRangeConfig          `yaml:"range_config" json:"range_config"`
	Weights        SeedWeightConfig         `yaml:"weights" json:"weights"`
	AdaptiveConfig *AdaptiveRangeConfig     `yaml:"adaptive_config" json:"adaptive_config"` // Layer 2: 自适应范围配置
	SymbolicConfig *symbolic.SymbolicConfig `yaml:"symbolic_config" json:"symbolic_config"` // Layer 3: 符号执行配置

	// 约束范围配置（从constraint_rules_v2.json提取）
	ConstraintRanges    map[string]map[string]*ConstraintRange `yaml:"constraint_ranges" json:"constraint_ranges"`         // 函数名 → 参数索引 → 约束范围
	RangeMutationConfig *RangeMutationConfig                   `yaml:"range_mutation_config" json:"range_mutation_config"` // 范围变异配置
}

// ConstraintRange 约束范围（从constraint_rules_v2.json提取的攻击参数范围）
type ConstraintRange struct {
	Type            string   `yaml:"type" json:"type"`                         // 参数类型 (uint256, address, etc.)
	SafeThreshold   string   `yaml:"safe_threshold" json:"safe_threshold"`     // 安全阈值（低于此值安全）
	DangerThreshold string   `yaml:"danger_threshold" json:"danger_threshold"` // 危险阈值（达到此值触发攻击）
	AttackValues    []string `yaml:"attack_values" json:"attack_values"`       // 实际攻击值列表
	Range           *struct {
		Min string `yaml:"min" json:"min"` // 范围下界
		Max string `yaml:"max" json:"max"` // 范围上界
	} `yaml:"range" json:"range"` // 攻击范围
	MutationStrategy string  `yaml:"mutation_strategy" json:"mutation_strategy"` // 变异策略: explore_danger_zone, progressive_approach, boundary_breakthrough
	Confidence       float64 `yaml:"confidence" json:"confidence"`               // 置信度 (0.0-1.0)
	ValueExpr        string  `yaml:"value_expr" json:"value_expr"`               // 原始表达式
	StateSlot        string  `yaml:"state_slot" json:"state_slot"`               // 关联的状态slot
}

// RangeMutationConfig 范围变异配置
type RangeMutationConfig struct {
	FocusPercentiles       []int   `yaml:"focus_percentiles" json:"focus_percentiles"`                 // 聚焦百分位 [50, 75, 90, 95, 99, 100]
	BoundaryExploration    bool    `yaml:"boundary_exploration" json:"boundary_exploration"`           // 是否探索边界
	StepCount              int     `yaml:"step_count" json:"step_count"`                               // 在范围内的采样步数
	RandomWithinRangeRatio float64 `yaml:"random_within_range_ratio" json:"random_within_range_ratio"` // 范围内随机采样比例
}

// SeedRangeConfig 种子变异范围配置
type SeedRangeConfig struct {
	NumericRangePercent  []int    `yaml:"numeric_range_percent" json:"numeric_range_percent"`   // [1, 2, 5, 10, 20, 50, 100]
	AddressMutationTypes []string `yaml:"address_mutation_types" json:"address_mutation_types"` // ["original", "bitflip_1", "bitflip_2", "nearby"]
	BoundaryExploration  bool     `yaml:"boundary_exploration" json:"boundary_exploration"`
}

// SeedWeightConfig 种子变异权重配置
type SeedWeightConfig struct {
	SeedBased float64 `yaml:"seed_based" json:"seed_based"` // 0.7 - 围绕种子值变异
	Random    float64 `yaml:"random" json:"random"`         // 0.2 - 随机探索
	Boundary  float64 `yaml:"boundary" json:"boundary"`     // 0.1 - 边界值测试
}

// SeedGenerator 种子驱动参数生成器
type SeedGenerator struct {
	config        *SeedConfig
	baseGenerator *ParamGenerator // 复用现有的随机生成器
	maxVariations int

	// Layer 2: 自适应范围缩放
	adaptiveConfig   *AdaptiveRangeConfig // 自适应配置
	feedbackHistory  []SimilarityFeedback // 历史反馈数据
	currentIteration int                  // 当前迭代轮次

	// Layer 3: 符号执行种子
	symbolicSeeds map[int][]symbolic.SymbolicSeed // 参数索引 → 符号种子列表
}

// NewSeedGenerator 创建种子驱动生成器
func NewSeedGenerator(config *SeedConfig, maxVariations int) *SeedGenerator {
	// 设置默认权重
	if config.Weights.SeedBased == 0 {
		config.Weights.SeedBased = 0.7
		config.Weights.Random = 0.2
		config.Weights.Boundary = 0.1
	}

	// 设置默认范围
	if len(config.RangeConfig.NumericRangePercent) == 0 {
		config.RangeConfig.NumericRangePercent = []int{1, 2, 5, 10, 20, 50, 100}
	}

	if len(config.RangeConfig.AddressMutationTypes) == 0 {
		// 默认允许更多离谱的地址变异，避免全部落在同一相似度区间
		config.RangeConfig.AddressMutationTypes = []string{"original", "bitflip_1", "bitflip_2", "nearby"}
	}

	// 初始化自适应配置默认值
	if config.AdaptiveConfig != nil && config.AdaptiveConfig.Enabled {
		// 🆕 无限制模式：设置极大的迭代次数
		if config.AdaptiveConfig.UnlimitedMode {
			config.AdaptiveConfig.MaxIterations = 9999
			log.Printf("[SeedGen] 🚀 Unlimited mode enabled, max_iterations set to 9999")
		} else if config.AdaptiveConfig.MaxIterations == 0 {
			config.AdaptiveConfig.MaxIterations = 5 // 默认5轮迭代
		}
		if config.AdaptiveConfig.ConvergenceRate == 0 {
			config.AdaptiveConfig.ConvergenceRate = 0.02 // 默认2%收敛阈值
		}
		if len(config.AdaptiveConfig.RangeStrategies) == 0 {
			// 设置默认的分层范围策略
			config.AdaptiveConfig.RangeStrategies = map[string][]int{
				"high_similarity":   {1, 2, 5},       // 相似度 > 0.8
				"medium_similarity": {5, 10, 20, 50}, // 相似度 0.6-0.8
				"low_similarity":    {50, 100, 200},  // 相似度 < 0.6
			}
		}
		// 设置高级配置默认值
		if config.AdaptiveConfig.ZoneThreshold == 0 {
			config.AdaptiveConfig.ZoneThreshold = 0.75 // 默认高相似度区域阈值
		}
		if config.AdaptiveConfig.ZoneGapPercent == 0 {
			config.AdaptiveConfig.ZoneGapPercent = 0.10 // 默认10%间隔
		}
		if config.AdaptiveConfig.ZoneGapAbsolute == 0 {
			config.AdaptiveConfig.ZoneGapAbsolute = 1000 // 默认1000绝对间隔
		}
		if config.AdaptiveConfig.HighSimThreshold == 0 {
			config.AdaptiveConfig.HighSimThreshold = 0.8 // 默认高相似度阈值
		}
		if config.AdaptiveConfig.MediumSimThreshold == 0 {
			config.AdaptiveConfig.MediumSimThreshold = 0.6 // 默认中等相似度阈值
		}
	}

	return &SeedGenerator{
		config:           config,
		baseGenerator:    NewParamGenerator(maxVariations),
		maxVariations:    maxVariations,
		adaptiveConfig:   config.AdaptiveConfig,
		feedbackHistory:  []SimilarityFeedback{},
		currentIteration: 0,
		symbolicSeeds:    make(map[int][]symbolic.SymbolicSeed),
	}
}

// GenerateSeedBasedCombinations 生成基于种子的参数组合
func (sg *SeedGenerator) GenerateSeedBasedCombinations(params []Parameter) <-chan []interface{} {
	out := make(chan []interface{}, 100)

	go func() {
		defer close(out)

		// 为每个参数生成变异值
		paramVariations := make([][]interface{}, len(params))
		for i, param := range params {
			paramVariations[i] = sg.generateParameterVariations(i, param)
			log.Printf("[SeedGen] Param #%d: Generated %d variations (type=%s)", i, len(paramVariations[i]), param.Type)
		}

		// 生成笛卡尔积组合
		count := 0
		sg.cartesianProduct(paramVariations, []interface{}{}, 0, out, &count)
		log.Printf("[SeedGen] Total combinations generated: %d", count)
	}()

	return out
}

// generateParameterVariations 为单个参数生成变异值
func (sg *SeedGenerator) generateParameterVariations(paramIndex int, param Parameter) []interface{} {
	var variations []interface{}

	// Layer 3: 优先使用符号种子 (最高优先级)
	if sg.HasSymbolicSeeds() {
		symbolicVars := sg.GetSymbolicVariations(paramIndex, param)
		if len(symbolicVars) > 0 {
			log.Printf("[SeedGen] Param #%d: Using %d symbolic seeds (priority)", paramIndex, len(symbolicVars))
			variations = append(variations, symbolicVars...)
		}
	}

	// 检查是否有种子值
	seeds, hasSeed := sg.config.AttackSeeds[paramIndex]
	if !hasSeed || len(seeds) == 0 {
		// 无种子值,回退到基础生成器
		if len(variations) == 0 {
			log.Printf("[SeedGen] No seed for param #%d, using base generator", paramIndex)
			return sg.generateWithBaseGenerator(param)
		}
		// 有符号种子但无攻击种子
		log.Printf("[SeedGen] Param #%d: Only symbolic seeds available", paramIndex)
		return sg.deduplicateVariations(variations)
	}

	log.Printf("[SeedGen] Param #%d has %d seed(s)", paramIndex, len(seeds))

	// 计算各部分的数量
	totalCount := sg.maxVariations
	seedCount := int(float64(totalCount) * sg.config.Weights.SeedBased)
	randomCount := int(float64(totalCount) * sg.config.Weights.Random)
	boundaryCount := int(float64(totalCount) * sg.config.Weights.Boundary)

	// 1. 种子驱动变异 (70%)
	seedVariations := sg.seedDrivenMutation(seeds, param, seedCount)
	variations = append(variations, seedVariations...)

	// 针对地址类型且仅允许original变异：禁止随机和边界，避免生成无代码地址导致必然revert
	if strings.HasPrefix(param.Type, "address") &&
		len(sg.config.RangeConfig.AddressMutationTypes) == 1 &&
		sg.config.RangeConfig.AddressMutationTypes[0] == "original" {
		return sg.deduplicateVariations(variations)
	}

	// 2. 随机探索 (20%)
	randomVariations := sg.randomMutation(param, randomCount)
	variations = append(variations, randomVariations...)

	// 3. 边界值测试 (10%)
	if sg.config.RangeConfig.BoundaryExploration {
		boundaryVariations := sg.boundaryMutation(param, boundaryCount)
		variations = append(variations, boundaryVariations...)
	}

	// 4. 数组类型：不需要特殊处理
	// ✅ 策略：约束种子已经是正确类型，直接在seedDrivenMutation中处理
	// 不再调用generateArraySeedVariations()，避免创建[]interface{}类型

	// 去重
	variations = sg.deduplicateVariations(variations)

	return variations
}

// seedDrivenMutation 围绕种子值生成变异
func (sg *SeedGenerator) seedDrivenMutation(seeds []interface{}, param Parameter, count int) []interface{} {
	var variations []interface{}

	// 始终包含原始种子值
	variations = append(variations, seeds...)

	perSeed := count / len(seeds)
	if perSeed < 1 {
		perSeed = 1
	}

	for _, seed := range seeds {
		// 数组类型：直接使用种子，不包装
		// ✅ 策略：约束种子已经是正确类型（*big.Int, string），让normalizeXXXSlice()去处理
		if strings.HasSuffix(param.Type, "[]") {
			// 直接添加种子值，不调用generateArraySeedVariations()
			variations = append(variations, seed)
			continue
		}

		switch param.Type {
		case "uint256", "uint128", "uint64", "uint32", "uint16", "uint8":
			seedVars := sg.generateNumericSeedVariations(seed, perSeed)
			variations = append(variations, seedVars...)

		case "address":
			seedVars := sg.generateAddressSeedVariations(seed, perSeed)
			variations = append(variations, seedVars...)

		case "bool":
			// bool 只有两个值,直接添加
			variations = append(variations, true, false)

		case "bytes", "bytes32", "bytes4":
			seedVars := sg.generateBytesSeedVariations(seed, perSeed)
			variations = append(variations, seedVars...)

		default:
			log.Printf("[SeedGen] Unsupported type for seed mutation: %s", param.Type)
		}
	}

	return variations
}

// generateArraySeedVariations 为数组类型生成变异（兼容标量种子写法）
func (sg *SeedGenerator) generateArraySeedVariations(seeds []interface{}, param Parameter, count int) []interface{} {
	elementType := strings.TrimSuffix(param.Type, "[]")
	var variations []interface{}

	for _, seed := range seeds {
		if normalized := sg.normalizeArraySeed(seed, elementType); normalized != nil {
			variations = append(variations, normalized)
		}
	}

	// 地址数组提供了种子时，保持原样不做随机/边界变异，避免地址被破坏
	if elementType == "address" && len(variations) > 0 {
		if len(variations) > count && count > 0 {
			return variations[:count]
		}
		return variations
	}

	// 补充基础生成器的数组变体，保证覆盖不同长度/元素
	variations = append(variations, sg.baseGenerator.generateArrayVariations(param)...)

	if len(variations) > count && count > 0 {
		return variations[:count]
	}
	return variations
}

// normalizeArraySeed 将种子转换为 []interface{}，以便后续 ABI 归一化处理
func (sg *SeedGenerator) normalizeArraySeed(seed interface{}, elementType string) []interface{} {
	switch v := seed.(type) {
	case []interface{}:
		return v
	case []byte:
		arr := make([]interface{}, len(v))
		for i, item := range v {
			arr[i] = item
		}
		return arr
	case []int:
		arr := make([]interface{}, len(v))
		for i, item := range v {
			arr[i] = item
		}
		return arr
	case []string:
		arr := make([]interface{}, len(v))
		for i, item := range v {
			arr[i] = item
		}
		return arr
	case string:
		// 如果是 hex 字符串，转换为字节数组再展开
		if strings.HasPrefix(v, "0x") && elementType == "uint8" {
			bytes := common.FromHex(v)
			arr := make([]interface{}, len(bytes))
			for i, item := range bytes {
				arr[i] = item
			}
			return arr
		}
		return []interface{}{v}
	default:
		// 标量：包装成单元素数组，由 normalizeUint8Slice 等函数处理
		return []interface{}{v}
	}
}

// generateNumericSeedVariations 生成数值类型的种子变异
func (sg *SeedGenerator) generateNumericSeedVariations(seed interface{}, count int) []interface{} {
	var variations []interface{}

	// 转换种子为 *big.Int
	var seedValue *big.Int
	switch v := seed.(type) {
	case *big.Int:
		seedValue = new(big.Int).Set(v)
	case int64:
		seedValue = big.NewInt(v)
	case uint64:
		seedValue = new(big.Int).SetUint64(v)
	case string:
		// 尝试解析十六进制或十进制字符串
		val, ok := new(big.Int).SetString(v, 0)
		if !ok {
			log.Printf("[SeedGen] Failed to parse numeric seed: %s", v)
			return variations
		}
		seedValue = val
	default:
		log.Printf("[SeedGen] Unsupported seed type for numeric variation: %T", seed)
		return variations
	}

	// 围绕种子值生成百分比变异
	for _, pct := range sg.config.RangeConfig.NumericRangePercent {
		// 计算偏移量: seed * (pct / 100)
		offset := new(big.Int).Mul(seedValue, big.NewInt(int64(pct)))
		offset.Div(offset, big.NewInt(100))

		// 生成 seed + offset
		upper := new(big.Int).Add(seedValue, offset)
		variations = append(variations, upper)

		// 生成 seed - offset (避免负数)
		if seedValue.Cmp(offset) > 0 {
			lower := new(big.Int).Sub(seedValue, offset)
			variations = append(variations, lower)
		} else {
			// 如果 seed < offset,使用 seed / 2
			half := new(big.Int).Div(seedValue, big.NewInt(2))
			variations = append(variations, half)
		}
	}

	// 添加一些微调值 (±1, ±10, ±100)
	for _, delta := range []int64{1, 10, 100, 1000} {
		upper := new(big.Int).Add(seedValue, big.NewInt(delta))
		variations = append(variations, upper)

		if seedValue.Cmp(big.NewInt(delta)) > 0 {
			lower := new(big.Int).Sub(seedValue, big.NewInt(delta))
			variations = append(variations, lower)
		}
	}

	// 限制数量
	if len(variations) > count {
		variations = variations[:count]
	}

	return variations
}

// generateAddressSeedVariations 生成地址类型的种子变异
func (sg *SeedGenerator) generateAddressSeedVariations(seed interface{}, count int) []interface{} {
	var variations []interface{}

	// 转换种子为 common.Address
	var seedAddr common.Address
	switch v := seed.(type) {
	case common.Address:
		seedAddr = v
	case string:
		// 检查是否是数字字符串（配置错误）
		if !strings.HasPrefix(v, "0x") {
			// 尝试作为数字解析
			if bi, ok := new(big.Int).SetString(v, 10); ok {
				seedAddr = common.BigToAddress(bi)
				log.Printf("[SeedGen] ⚠️  Converting numeric string to address: %s -> %s (config may have type mismatch)", v, seedAddr.Hex())
			} else {
				// 作为普通字符串处理
				seedAddr = common.HexToAddress(v)
			}
		} else {
			seedAddr = common.HexToAddress(v)
		}
	case *big.Int:
		seedAddr = common.BigToAddress(v)
		log.Printf("[SeedGen] ⚠️  Converting *big.Int to address: %s (config may have type mismatch)", seedAddr.Hex())
	case []byte:
		seedAddr = common.BytesToAddress(v)
		log.Printf("[SeedGen] 📝 Converting bytes to address: %s", seedAddr.Hex())
	default:
		log.Printf("[SeedGen] ❌ Unsupported seed type for address variation: %T", seed)
		return variations
	}

	// 始终包含原始地址
	variations = append(variations, seedAddr)

	for _, mutationType := range sg.config.RangeConfig.AddressMutationTypes {
		switch mutationType {
		case "original":
			// 已添加,跳过
			continue

		case "bitflip_1":
			// 翻转单个比特
			for i := 0; i < 5 && len(variations) < count; i++ {
				flipped := sg.flipAddressBit(seedAddr, i)
				variations = append(variations, flipped)
			}

		case "bitflip_2":
			// 翻转两个比特
			for i := 0; i < 3 && len(variations) < count; i++ {
				flipped := sg.flipAddressBit(seedAddr, i)
				flipped = sg.flipAddressBit(flipped, i+8)
				variations = append(variations, flipped)
			}

		case "nearby":
			// 生成附近地址 (±1, ±10, ±100)
			for _, delta := range []int64{1, 10, 100, 1000} {
				if len(variations) >= count {
					break
				}
				addrInt := new(big.Int).SetBytes(seedAddr.Bytes())
				upper := new(big.Int).Add(addrInt, big.NewInt(delta))
				variations = append(variations, common.BytesToAddress(upper.Bytes()))

				if addrInt.Cmp(big.NewInt(delta)) > 0 {
					lower := new(big.Int).Sub(addrInt, big.NewInt(delta))
					variations = append(variations, common.BytesToAddress(lower.Bytes()))
				}
			}

		default:
			log.Printf("[SeedGen] Unknown address mutation type: %s", mutationType)
		}
	}

	// 限制数量
	if len(variations) > count {
		variations = variations[:count]
	}

	return variations
}

// generateBytesSeedVariations 生成字节类型的种子变异
func (sg *SeedGenerator) generateBytesSeedVariations(seed interface{}, count int) []interface{} {
	var variations []interface{}

	// 转换种子为 []byte
	var seedBytes []byte
	switch v := seed.(type) {
	case []byte:
		seedBytes = v
	case string:
		if strings.HasPrefix(v, "0x") || strings.HasPrefix(v, "0X") {
			seedBytes = common.FromHex(v)
		} else {
			// 非hex字符串，直接转为bytes
			seedBytes = []byte(v)
		}
	case *big.Int:
		// ✅ 新增：支持*big.Int转bytes
		seedBytes = v.Bytes()
		log.Printf("[SeedGen] 📝 Converting *big.Int to bytes: 0x%x (length=%d)", seedBytes, len(seedBytes))
	case int, int64, uint64:
		// ✅ 新增：支持整数转bytes
		val64 := reflect.ValueOf(v).Int()
		seedBytes = big.NewInt(val64).Bytes()
		log.Printf("[SeedGen] 📝 Converting integer to bytes: 0x%x", seedBytes)
	default:
		log.Printf("[SeedGen] ❌ Unsupported seed type for bytes variation: %T", seed)
		return variations
	}

	// 始终包含原始值
	variations = append(variations, seedBytes)

	// 如果bytes长度为0，添加一些常见的bytes值
	if len(seedBytes) == 0 {
		variations = append(variations,
			[]byte{},           // 空bytes
			[]byte{0x00},       // 单字节0
			[]byte{0xFF},       // 单字节FF
			[]byte{0x00, 0x00}, // 双字节0
		)
	} else {
		// 翻转单个字节
		for i := 0; i < len(seedBytes) && len(variations) < count; i++ {
			flipped := make([]byte, len(seedBytes))
			copy(flipped, seedBytes)
			flipped[i] ^= 0xFF // 翻转所有比特
			variations = append(variations, flipped)
		}
	}

	// 限制数量
	if len(variations) > count {
		variations = variations[:count]
	}

	return variations
}

// randomMutation 随机探索
func (sg *SeedGenerator) randomMutation(param Parameter, count int) []interface{} {
	// 委托给基础生成器
	baseVariations := sg.generateWithBaseGenerator(param)
	if len(baseVariations) > count {
		return baseVariations[:count]
	}
	return baseVariations
}

// boundaryMutation 边界值测试
func (sg *SeedGenerator) boundaryMutation(param Parameter, count int) []interface{} {
	var variations []interface{}

	switch param.Type {
	case "uint256":
		variations = append(variations,
			big.NewInt(0),
			big.NewInt(1),
			big.NewInt(2),
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)), // 2^256 - 1
		)

	case "uint128":
		variations = append(variations,
			big.NewInt(0),
			new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1)), // 2^128 - 1
		)

	case "address":
		variations = append(variations,
			common.Address{}, // 零地址
			common.HexToAddress("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), // 最大地址
		)

	case "bool":
		variations = append(variations, true, false)

	default:
		// 其他类型暂不支持
	}

	if len(variations) > count {
		return variations[:count]
	}
	return variations
}

// generateWithBaseGenerator 使用基础生成器生成参数
func (sg *SeedGenerator) generateWithBaseGenerator(param Parameter) []interface{} {
	// 复用 ParamGenerator 的逻辑
	switch param.Type {
	case "uint256", "uint128", "uint64", "uint32", "uint16", "uint8":
		return sg.baseGenerator.generateIntegerVariations(param, false) // unsigned
	case "int256", "int128", "int64", "int32", "int16", "int8":
		return sg.baseGenerator.generateIntegerVariations(param, true) // signed
	case "address":
		// 禁止地址随机化，保持原始地址
		return []interface{}{param.Value}
	case "bool":
		return []interface{}{true, false}
	case "bytes", "bytes32", "bytes4":
		return sg.baseGenerator.generateBytesVariations(param)
	default:
		if strings.HasSuffix(param.Type, "[]") {
			// 数组类型，若是地址数组同样保持原值
			if strings.TrimSuffix(param.Type, "[]") == "address" {
				return []interface{}{param.Value}
			}
			return sg.baseGenerator.generateArrayVariations(param)
		}
		log.Printf("[SeedGen] Unsupported parameter type: %s", param.Type)
		return []interface{}{}
	}
}

// deduplicateVariations 去重
func (sg *SeedGenerator) deduplicateVariations(variations []interface{}) []interface{} {
	seen := make(map[string]bool)
	unique := []interface{}{}

	for _, v := range variations {
		key := fmt.Sprintf("%v", v)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
		}
	}

	return unique
}

// cartesianProduct 生成笛卡尔积组合
func (sg *SeedGenerator) cartesianProduct(variations [][]interface{}, current []interface{}, index int, out chan<- []interface{}, count *int) {
	if index == len(variations) {
		// 达到最大变异数限制
		if *count >= sg.maxVariations {
			return
		}

		combination := make([]interface{}, len(current))
		copy(combination, current)
		out <- combination
		*count++
		return
	}

	for _, v := range variations[index] {
		sg.cartesianProduct(variations, append(current, v), index+1, out, count)
		if *count >= sg.maxVariations {
			return
		}
	}
}

// flipAddressBit 翻转地址的指定比特
func (sg *SeedGenerator) flipAddressBit(addr common.Address, bitIndex int) common.Address {
	bytes := addr.Bytes()
	byteIndex := bitIndex / 8
	bitOffset := uint(bitIndex % 8)

	if byteIndex < len(bytes) {
		bytes[byteIndex] ^= (1 << bitOffset)
	}

	return common.BytesToAddress(bytes)
}

// generateRandomBigInt 生成随机大整数
func (sg *SeedGenerator) generateRandomBigInt(max *big.Int) *big.Int {
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return big.NewInt(0)
	}
	return n
}

// ========== Layer 2: 自适应范围缩放方法 ==========

// AnalyzeFeedback 分析模糊测试结果构建相似度热力图
func (sg *SeedGenerator) AnalyzeFeedback(
	results []FuzzingResult,
	params []Parameter,
) []SimilarityFeedback {
	feedback := make([]SimilarityFeedback, len(params))

	for i := range params {
		feedback[i] = SimilarityFeedback{
			ParamIndex:   i,
			ValueToSim:   make(map[string]float64),
			HighSimZones: []ValueRange{},
			AvgSim:       0.0,
		}

		// 收集参数值 → 相似度映射
		totalSim := 0.0
		count := 0
		for _, res := range results {
			if i < len(res.Parameters) {
				valueStr := ValueToString(res.Parameters[i].Value)
				feedback[i].ValueToSim[valueStr] = res.Similarity
				totalSim += res.Similarity
				count++
			}
		}

		// 计算平均相似度
		if count > 0 {
			feedback[i].AvgSim = totalSim / float64(count)
		}

		// 识别高相似度区域（仅对数值类型）
		if sg.isNumericType(params[i].Type) {
			feedback[i].HighSimZones = sg.identifyHighSimZones(
				feedback[i].ValueToSim,
				params[i].Type,
			)
		}

		log.Printf("[Adaptive] Param #%d: avgSim=%.4f, values=%d, highSimZones=%d",
			i, feedback[i].AvgSim, len(feedback[i].ValueToSim), len(feedback[i].HighSimZones))
	}

	return feedback
}

// identifyHighSimZones 识别高相似度区域
func (sg *SeedGenerator) identifyHighSimZones(
	valueToSim map[string]float64,
	paramType string,
) []ValueRange {
	// 使用可配置的高相似度阈值
	zoneThreshold := 0.75 // 默认值
	if sg.adaptiveConfig != nil && sg.adaptiveConfig.ZoneThreshold > 0 {
		zoneThreshold = sg.adaptiveConfig.ZoneThreshold
	}

	// 提取高相似度值
	highSimValues := []*big.Int{}
	simSum := 0.0
	for valStr, sim := range valueToSim {
		if sim > zoneThreshold {
			if val, ok := new(big.Int).SetString(valStr, 0); ok {
				highSimValues = append(highSimValues, val)
				simSum += sim
			}
		}
	}

	if len(highSimValues) == 0 {
		return nil
	}

	// 排序
	sort.Slice(highSimValues, func(i, j int) bool {
		return highSimValues[i].Cmp(highSimValues[j]) < 0
	})

	// 识别连续区域
	zones := []ValueRange{}
	currentZone := ValueRange{
		Min:        new(big.Int).Set(highSimValues[0]),
		Max:        new(big.Int).Set(highSimValues[0]),
		SampleSize: 1,
		AvgSim:     valueToSim[highSimValues[0].String()],
	}

	for i := 1; i < len(highSimValues); i++ {
		// 计算间隔，使用可配置的阈值
		gapPercent := 0.10         // 默认10%
		gapAbsolute := int64(1000) // 默认1000
		if sg.adaptiveConfig != nil {
			if sg.adaptiveConfig.ZoneGapPercent > 0 {
				gapPercent = sg.adaptiveConfig.ZoneGapPercent
			}
			if sg.adaptiveConfig.ZoneGapAbsolute > 0 {
				gapAbsolute = sg.adaptiveConfig.ZoneGapAbsolute
			}
		}

		gap := new(big.Int).Sub(highSimValues[i], currentZone.Max)
		thresholdPercent := new(big.Int).Mul(currentZone.Max, big.NewInt(int64(gapPercent*100)))
		thresholdPercent.Div(thresholdPercent, big.NewInt(100))

		if gap.Cmp(thresholdPercent) <= 0 || gap.Cmp(big.NewInt(gapAbsolute)) <= 0 {
			// 间隔较小，合并到当前区域
			currentZone.Max = new(big.Int).Set(highSimValues[i])
			currentZone.SampleSize++
		} else {
			// 间隔较大，开启新区域
			zones = append(zones, currentZone)
			currentZone = ValueRange{
				Min:        new(big.Int).Set(highSimValues[i]),
				Max:        new(big.Int).Set(highSimValues[i]),
				SampleSize: 1,
				AvgSim:     valueToSim[highSimValues[i].String()],
			}
		}
	}
	zones = append(zones, currentZone) // 添加最后一个区域

	// 计算每个区域的平均相似度
	for i := range zones {
		zones[i].AvgSim = simSum / float64(len(highSimValues))
	}

	return zones
}

// HasConverged 检查是否收敛
func (sg *SeedGenerator) HasConverged(currentFeedback []SimilarityFeedback) bool {
	if sg.currentIteration < 2 || len(sg.feedbackHistory) == 0 {
		return false
	}

	// 获取上一轮反馈
	prevStartIdx := len(sg.feedbackHistory) - len(currentFeedback)
	if prevStartIdx < 0 {
		return false
	}
	prevFeedback := sg.feedbackHistory[prevStartIdx : prevStartIdx+len(currentFeedback)]

	// 计算平均相似度变化
	totalChange := 0.0
	for i, fb := range currentFeedback {
		if i >= len(prevFeedback) {
			break
		}
		change := fb.AvgSim - prevFeedback[i].AvgSim
		if change < 0 {
			change = -change // 取绝对值
		}
		totalChange += change
	}

	avgChange := totalChange / float64(len(currentFeedback))
	converged := avgChange < sg.adaptiveConfig.ConvergenceRate

	log.Printf("[Adaptive] Convergence check: avgChange=%.6f, threshold=%.6f, converged=%v",
		avgChange, sg.adaptiveConfig.ConvergenceRate, converged)

	return converged
}

// GenerateAdaptiveRound 生成自适应轮次的参数组合
func (sg *SeedGenerator) GenerateAdaptiveRound(
	params []Parameter,
	feedback []SimilarityFeedback,
) <-chan []interface{} {
	out := make(chan []interface{}, 100)

	go func() {
		defer close(out)

		// 为每个参数生成自适应变异
		paramVariations := make([][]interface{}, len(params))
		for i, param := range params {
			var fb *SimilarityFeedback
			if i < len(feedback) {
				fb = &feedback[i]
			}
			paramVariations[i] = sg.generateAdaptiveVariations(i, param, fb)
			log.Printf("[Adaptive] Param #%d: Generated %d adaptive variations", i, len(paramVariations[i]))
		}

		// 生成笛卡尔积
		count := 0
		sg.cartesianProduct(paramVariations, []interface{}{}, 0, out, &count)
		log.Printf("[Adaptive] Round %d: Generated %d combinations", sg.currentIteration, count)
	}()

	return out
}

// generateAdaptiveVariations 生成单个参数的自适应变异
func (sg *SeedGenerator) generateAdaptiveVariations(
	paramIndex int,
	param Parameter,
	feedback *SimilarityFeedback,
) []interface{} {
	// 如果没有反馈或非数值类型，使用标准生成
	if feedback == nil || !sg.isNumericType(param.Type) {
		return sg.generateParameterVariations(paramIndex, param)
	}

	var variations []interface{}

	// 策略1：如果有高相似度区域，在这些区域密集采样
	if len(feedback.HighSimZones) > 0 {
		log.Printf("[Adaptive] Param #%d: Found %d high-sim zones, using zone sampling",
			paramIndex, len(feedback.HighSimZones))

		for _, zone := range feedback.HighSimZones {
			zoneVars := sg.generateInZone(zone, sg.maxVariations/len(feedback.HighSimZones))
			variations = append(variations, zoneVars...)
		}
	}

	// 策略2：基于平均相似度选择范围策略
	var rangePercents []int

	// 使用可配置的相似度阈值
	highSimThreshold := 0.8   // 默认值
	mediumSimThreshold := 0.6 // 默认值
	if sg.adaptiveConfig != nil {
		if sg.adaptiveConfig.HighSimThreshold > 0 {
			highSimThreshold = sg.adaptiveConfig.HighSimThreshold
		}
		if sg.adaptiveConfig.MediumSimThreshold > 0 {
			mediumSimThreshold = sg.adaptiveConfig.MediumSimThreshold
		}
	}

	if feedback.AvgSim > highSimThreshold {
		rangePercents = sg.adaptiveConfig.RangeStrategies["high_similarity"] // 细粒度
	} else if feedback.AvgSim > mediumSimThreshold {
		rangePercents = sg.adaptiveConfig.RangeStrategies["medium_similarity"] // 中等粒度
	} else {
		rangePercents = sg.adaptiveConfig.RangeStrategies["low_similarity"] // 粗粒度
	}

	// 从种子生成变异
	seeds, hasSeed := sg.config.AttackSeeds[paramIndex]
	if hasSeed && len(seeds) > 0 {
		for _, seed := range seeds {
			seedVars := sg.generateNumericVariationsWithStrategy(seed, rangePercents)
			variations = append(variations, seedVars...)
		}
	}

	// 去重
	variations = sg.deduplicateVariations(variations)

	// 限制数量
	if len(variations) > sg.maxVariations {
		variations = variations[:sg.maxVariations]
	}

	return variations
}

// generateInZone 在指定区域内生成变异
func (sg *SeedGenerator) generateInZone(zone ValueRange, count int) []interface{} {
	variations := []interface{}{}

	rangeSize := new(big.Int).Sub(zone.Max, zone.Min)
	if rangeSize.Sign() <= 0 {
		// 范围太小，返回边界值
		return []interface{}{zone.Min, zone.Max}
	}

	// 均匀采样
	for i := 0; i < count; i++ {
		step := new(big.Int).Mul(rangeSize, big.NewInt(int64(i)))
		step.Div(step, big.NewInt(int64(count)))
		value := new(big.Int).Add(zone.Min, step)
		variations = append(variations, value)
	}

	// 额外添加边界附近的值
	variations = append(variations, zone.Min, zone.Max)

	// 中点
	mid := new(big.Int).Add(zone.Min, zone.Max)
	mid.Div(mid, big.NewInt(2))
	variations = append(variations, mid)

	return variations
}

// generateNumericVariationsWithStrategy 使用指定策略生成数值变异
func (sg *SeedGenerator) generateNumericVariationsWithStrategy(
	seed interface{},
	rangePercents []int,
) []interface{} {
	// 转换种子为 *big.Int
	var seedValue *big.Int
	switch v := seed.(type) {
	case *big.Int:
		seedValue = new(big.Int).Set(v)
	case int64:
		seedValue = big.NewInt(v)
	case uint64:
		seedValue = new(big.Int).SetUint64(v)
	case string:
		val, ok := new(big.Int).SetString(v, 0)
		if !ok {
			return []interface{}{}
		}
		seedValue = val
	default:
		return []interface{}{}
	}

	var variations []interface{}

	// 应用百分比范围
	for _, pct := range rangePercents {
		offset := new(big.Int).Mul(seedValue, big.NewInt(int64(pct)))
		offset.Div(offset, big.NewInt(100))

		upper := new(big.Int).Add(seedValue, offset)
		variations = append(variations, upper)

		if seedValue.Cmp(offset) > 0 {
			lower := new(big.Int).Sub(seedValue, offset)
			variations = append(variations, lower)
		}
	}

	return variations
}

// isNumericType 检查是否为数值类型
func (sg *SeedGenerator) isNumericType(paramType string) bool {
	numericTypes := []string{"uint256", "uint128", "uint64", "uint32", "uint16", "uint8",
		"int256", "int128", "int64", "int32", "int16", "int8"}
	for _, t := range numericTypes {
		if paramType == t {
			return true
		}
	}
	return false
}

// ========== Layer 3: 符号执行种子集成 ==========

// SetSymbolicSeeds 设置符号执行生成的种子
func (sg *SeedGenerator) SetSymbolicSeeds(seeds []symbolic.SymbolicSeed) {
	// 按参数索引分组
	sg.symbolicSeeds = make(map[int][]symbolic.SymbolicSeed)
	for _, seed := range seeds {
		sg.symbolicSeeds[seed.ParamIndex] = append(sg.symbolicSeeds[seed.ParamIndex], seed)
	}

	// 按优先级排序每个参数的种子
	for paramIdx := range sg.symbolicSeeds {
		seeds := sg.symbolicSeeds[paramIdx]
		// 简单冒泡排序
		for i := 0; i < len(seeds)-1; i++ {
			for j := 0; j < len(seeds)-i-1; j++ {
				if seeds[j].Priority < seeds[j+1].Priority {
					seeds[j], seeds[j+1] = seeds[j+1], seeds[j]
				}
			}
		}
		sg.symbolicSeeds[paramIdx] = seeds
	}

	log.Printf("[SeedGen] Set %d symbolic seeds for %d parameters", len(seeds), len(sg.symbolicSeeds))
}

// GetSymbolicVariations 从符号种子生成变异值
func (sg *SeedGenerator) GetSymbolicVariations(paramIndex int, param Parameter) []interface{} {
	seeds, ok := sg.symbolicSeeds[paramIndex]
	if !ok || len(seeds) == 0 {
		return nil
	}

	variations := []interface{}{}

	// 获取配置的置信度阈值
	confidenceThreshold := 0.5 // 默认值
	if sg.config.SymbolicConfig != nil && sg.config.SymbolicConfig.Integration.ConfidenceThreshold > 0 {
		confidenceThreshold = sg.config.SymbolicConfig.Integration.ConfidenceThreshold
	}

	// 过滤低置信度种子
	for _, seed := range seeds {
		if seed.Confidence < confidenceThreshold {
			continue
		}

		// 添加种子值
		variations = append(variations, seed.Value)

		// 根据种子类型添加额外变异
		if seed.SourceType == "boundary" && sg.isNumericType(param.Type) {
			// 边界种子: 添加邻近值
			offsets := []int64{-1, 1, -10, 10}
			for _, offset := range offsets {
				nearby := new(big.Int).Add(seed.Value, big.NewInt(offset))
				if nearby.Sign() >= 0 { // 避免负数
					variations = append(variations, nearby)
				}
			}
		}
	}

	return variations
}

// HasSymbolicSeeds 检查是否有符号种子
func (sg *SeedGenerator) HasSymbolicSeeds() bool {
	return len(sg.symbolicSeeds) > 0
}

// GetSymbolicSeedCount 获取符号种子数量
func (sg *SeedGenerator) GetSymbolicSeedCount() int {
	count := 0
	for _, seeds := range sg.symbolicSeeds {
		count += len(seeds)
	}
	return count
}

// ========== 约束范围驱动的种子生成 ==========

// HasConstraintRanges 检查是否有约束范围配置
func (sg *SeedGenerator) HasConstraintRanges() bool {
	return sg.config.ConstraintRanges != nil && len(sg.config.ConstraintRanges) > 0
}

// GetConstraintRangeForFunc 获取指定函数的约束范围
func (sg *SeedGenerator) GetConstraintRangeForFunc(funcName string) map[string]*ConstraintRange {
	if sg.config.ConstraintRanges == nil {
		return nil
	}
	return sg.config.ConstraintRanges[funcName]
}

// GenerateConstraintBasedVariations 基于约束范围生成参数变异
// 这个方法用于在已知攻击范围内进行定向变异
func (sg *SeedGenerator) GenerateConstraintBasedVariations(
	funcName string,
	paramIndex int,
	param Parameter,
) []interface{} {
	var variations []interface{}

	// 检查是否有该函数的约束范围
	funcRanges := sg.GetConstraintRangeForFunc(funcName)
	if funcRanges == nil {
		return nil
	}

	// 获取该参数的约束范围
	paramIdxStr := fmt.Sprintf("%d", paramIndex)
	constraintRange, ok := funcRanges[paramIdxStr]
	if !ok || constraintRange == nil {
		return nil
	}

	log.Printf("[ConstraintRange] Generating variations for %s param#%d using strategy: %s",
		funcName, paramIndex, constraintRange.MutationStrategy)

	// 解析阈值
	safeThreshold, _ := new(big.Int).SetString(constraintRange.SafeThreshold, 10)
	dangerThreshold, _ := new(big.Int).SetString(constraintRange.DangerThreshold, 10)

	if safeThreshold == nil || dangerThreshold == nil {
		log.Printf("[ConstraintRange] Failed to parse thresholds for %s param#%d", funcName, paramIndex)
		return nil
	}

	// 1. 添加攻击值
	for _, attackVal := range constraintRange.AttackValues {
		if val, ok := new(big.Int).SetString(attackVal, 10); ok {
			variations = append(variations, val)
		}
	}

	// 2. 根据变异策略生成更多值
	switch constraintRange.MutationStrategy {
	case "explore_danger_zone":
		// 在危险区域内均匀采样
		zoneVars := sg.exploreDangerZone(safeThreshold, dangerThreshold)
		variations = append(variations, zoneVars...)

	case "progressive_approach":
		// 渐进式逼近危险阈值
		progressiveVars := sg.progressiveApproach(safeThreshold, dangerThreshold)
		variations = append(variations, progressiveVars...)

	case "boundary_breakthrough":
		// 边界突破测试
		boundaryVars := sg.boundaryBreakthrough(dangerThreshold)
		variations = append(variations, boundaryVars...)

	default:
		// 默认使用explore_danger_zone
		zoneVars := sg.exploreDangerZone(safeThreshold, dangerThreshold)
		variations = append(variations, zoneVars...)
	}

	// 3. 添加阈值边界值
	variations = append(variations, safeThreshold, dangerThreshold)

	// 去重
	variations = sg.deduplicateVariations(variations)

	log.Printf("[ConstraintRange] Generated %d constraint-based variations for %s param#%d",
		len(variations), funcName, paramIndex)

	return variations
}

// exploreDangerZone 在危险区域内均匀采样
// 策略: 从safe_threshold到danger_threshold按百分位采样
func (sg *SeedGenerator) exploreDangerZone(safeThreshold, dangerThreshold *big.Int) []interface{} {
	var variations []interface{}

	// 计算范围
	rangeSize := new(big.Int).Sub(dangerThreshold, safeThreshold)
	if rangeSize.Sign() <= 0 {
		return variations
	}

	// 获取聚焦百分位
	percentiles := []int{50, 75, 90, 95, 99, 100}
	if sg.config.RangeMutationConfig != nil && len(sg.config.RangeMutationConfig.FocusPercentiles) > 0 {
		percentiles = sg.config.RangeMutationConfig.FocusPercentiles
	}

	// 按百分位采样
	for _, pct := range percentiles {
		offset := new(big.Int).Mul(rangeSize, big.NewInt(int64(pct)))
		offset.Div(offset, big.NewInt(100))
		value := new(big.Int).Add(safeThreshold, offset)
		variations = append(variations, value)
	}

	// 均匀步长采样
	stepCount := 20
	if sg.config.RangeMutationConfig != nil && sg.config.RangeMutationConfig.StepCount > 0 {
		stepCount = sg.config.RangeMutationConfig.StepCount
	}

	step := new(big.Int).Div(rangeSize, big.NewInt(int64(stepCount)))
	if step.Sign() > 0 {
		for i := 0; i <= stepCount; i++ {
			offset := new(big.Int).Mul(step, big.NewInt(int64(i)))
			value := new(big.Int).Add(safeThreshold, offset)
			variations = append(variations, value)
		}
	}

	// 随机采样（如果启用）
	randomRatio := 0.3
	if sg.config.RangeMutationConfig != nil && sg.config.RangeMutationConfig.RandomWithinRangeRatio > 0 {
		randomRatio = sg.config.RangeMutationConfig.RandomWithinRangeRatio
	}

	randomCount := int(float64(len(variations)) * randomRatio)
	for i := 0; i < randomCount; i++ {
		randomOffset := sg.generateRandomBigInt(rangeSize)
		value := new(big.Int).Add(safeThreshold, randomOffset)
		variations = append(variations, value)
	}

	return variations
}

// progressiveApproach 渐进式逼近危险阈值
// 策略: 从safe_threshold开始，逐步增加到danger_threshold
func (sg *SeedGenerator) progressiveApproach(safeThreshold, dangerThreshold *big.Int) []interface{} {
	var variations []interface{}

	rangeSize := new(big.Int).Sub(dangerThreshold, safeThreshold)
	if rangeSize.Sign() <= 0 {
		return variations
	}

	// 分阶段逼近
	phases := []float64{0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0}
	for _, phase := range phases {
		// 计算该阶段的偏移
		phaseOffset := new(big.Int).Mul(rangeSize, big.NewInt(int64(phase*100)))
		phaseOffset.Div(phaseOffset, big.NewInt(100))
		value := new(big.Int).Add(safeThreshold, phaseOffset)
		variations = append(variations, value)

		// 在每个阶段点附近也生成一些变异
		for _, delta := range []int64{-100, -10, -1, 1, 10, 100} {
			nearbyValue := new(big.Int).Add(value, big.NewInt(delta))
			if nearbyValue.Cmp(safeThreshold) >= 0 && nearbyValue.Cmp(dangerThreshold) <= 0 {
				variations = append(variations, nearbyValue)
			}
		}
	}

	return variations
}

// boundaryBreakthrough 边界突破测试
// 策略: 测试danger_threshold及其上方的值
func (sg *SeedGenerator) boundaryBreakthrough(dangerThreshold *big.Int) []interface{} {
	var variations []interface{}

	// 添加危险阈值本身
	variations = append(variations, new(big.Int).Set(dangerThreshold))

	// 测试危险阈值附近的值
	nearbyOffsets := []int64{-100, -10, -1, 1, 10, 100, 1000}
	for _, offset := range nearbyOffsets {
		value := new(big.Int).Add(dangerThreshold, big.NewInt(offset))
		if value.Sign() >= 0 {
			variations = append(variations, value)
		}
	}

	// 测试危险阈值的倍数
	multipliers := []float64{1.01, 1.05, 1.1, 1.5, 2.0}
	for _, mult := range multipliers {
		// value = dangerThreshold * mult
		multInt := new(big.Int).Mul(dangerThreshold, big.NewInt(int64(mult*100)))
		multInt.Div(multInt, big.NewInt(100))
		variations = append(variations, multInt)
	}

	// 如果启用边界探索，测试更极端的值
	if sg.config.RangeMutationConfig != nil && sg.config.RangeMutationConfig.BoundaryExploration {
		// 测试更大的倍数
		extremeMultipliers := []float64{5.0, 10.0, 100.0}
		for _, mult := range extremeMultipliers {
			multInt := new(big.Int).Mul(dangerThreshold, big.NewInt(int64(mult)))
			variations = append(variations, multInt)
		}
	}

	return variations
}

// MergeConstraintSeeds 将约束范围中的攻击值合并到AttackSeeds
// 这样可以利用现有的种子驱动逻辑
// ✅ 修复：根据参数类型正确转换种子值
// ✅ 修复：每次调用时清空AttackSeeds，避免不同函数的种子混淆
func (sg *SeedGenerator) MergeConstraintSeeds(funcName string) {
	funcRanges := sg.GetConstraintRangeForFunc(funcName)
	if funcRanges == nil {
		return
	}
	if sg.config.AttackSeeds == nil {
		sg.config.AttackSeeds = make(map[int][]interface{})
	}

	for paramIdxStr, constraintRange := range funcRanges {
		paramIdx := 0
		fmt.Sscanf(paramIdxStr, "%d", &paramIdx)

		paramType := constraintRange.Type

		// ✅ 根据参数类型转换种子
		switch {
		case paramType == "address" || strings.HasPrefix(paramType, "address"):
			// address类型：保持字符串格式，不转换
			for _, attackVal := range constraintRange.AttackValues {
				if strings.HasPrefix(attackVal, "0x") || strings.HasPrefix(attackVal, "0X") {
					sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], attackVal)
				}
			}
			log.Printf("[ConstraintRange] Added %d address seeds for %s param#%d",
				len(constraintRange.AttackValues), funcName, paramIdx)

		case paramType == "uint8[]" || paramType == "bytes" || strings.HasSuffix(paramType, "[]"):
			// 数组/bytes类型：特殊处理
			// ✅ 策略：保持原始格式（字符串或*big.Int），让normalizeXXXSlice()去处理
			for _, attackVal := range constraintRange.AttackValues {
				// 尝试解析为数字
				if val, ok := new(big.Int).SetString(attackVal, 10); ok {
					// 数字类型：转为*big.Int，normalizeUint8Slice()会包装为单元素数组
					sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], val)
				} else if strings.HasPrefix(attackVal, "0x") {
					// hex字符串：保持原样，normalizeUint8Slice()会转为bytes
					sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], attackVal)
				} else {
					// 其他字符串：保持原样，让归一化逻辑处理
					sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], attackVal)
				}
			}
			log.Printf("[ConstraintRange] Added %d array/bytes seeds for %s param#%d (type=%s)",
				len(constraintRange.AttackValues), funcName, paramIdx, paramType)

		case strings.HasPrefix(paramType, "uint") || strings.HasPrefix(paramType, "int"):
			// 数值类型：转换为*big.Int
			for _, attackVal := range constraintRange.AttackValues {
				if val, ok := new(big.Int).SetString(attackVal, 10); ok {
					sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], val)
				} else if val, ok := new(big.Int).SetString(attackVal, 0); ok {
					// 尝试自动识别进制（支持0x前缀）
					sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], val)
				}
			}
			// 也添加阈值
			if safeThreshold, ok := new(big.Int).SetString(constraintRange.SafeThreshold, 10); ok {
				sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], safeThreshold)
			}
			if dangerThreshold, ok := new(big.Int).SetString(constraintRange.DangerThreshold, 10); ok {
				sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], dangerThreshold)
			}
			log.Printf("[ConstraintRange] Added %d numeric seeds for %s param#%d (type=%s)",
				len(constraintRange.AttackValues)+2, funcName, paramIdx, paramType)

		default:
			// 其他类型：保持原样
			for _, attackVal := range constraintRange.AttackValues {
				sg.config.AttackSeeds[paramIdx] = append(sg.config.AttackSeeds[paramIdx], attackVal)
			}
			log.Printf("[ConstraintRange] Added %d seeds for %s param#%d (type=%s)",
				len(constraintRange.AttackValues), funcName, paramIdx, paramType)
		}
	}

	log.Printf("[ConstraintRange] ✅ Merged constraint seeds for function %s into AttackSeeds", funcName)
}
