// Package local 提供本地EVM执行器实现
package local

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// SeedConfig 种子驱动模糊测试配置（简化版，避免循环导入）
type SeedConfig struct {
	Enabled             bool                                   `json:"enabled"`
	AttackSeeds         map[int][]interface{}                  `json:"attack_seeds"`      // 参数索引 → 攻击参数值列表
	ConstraintRanges    map[string]map[string]*ConstraintRange `json:"constraint_ranges"` // 函数名(小写) → 参数索引字符串 → 范围
	RangeMutationConfig *RangeMutationConfig                   `json:"range_mutation_config"`
}

// ConstraintRange 约束范围（从链下配置提取）
type ConstraintRange struct {
	Type         string   `json:"type"`
	AttackValues []string `json:"attack_values"`
	Range        *struct {
		Min string `json:"min"`
		Max string `json:"max"`
	} `json:"range"`
	MutationStrategy string  `json:"mutation_strategy"`
	Confidence       float64 `json:"confidence"`
}

// RangeMutationConfig 范围变异配置（简化版）
type RangeMutationConfig struct {
	FocusPercentiles       []int   `json:"focus_percentiles"`
	BoundaryExploration    bool    `json:"boundary_exploration"`
	StepCount              int     `json:"step_count"`
	RandomWithinRangeRatio float64 `json:"random_within_range_ratio"`
}

// ParamPoolManager 参数池管理器接口
type ParamPoolManager interface {
	// GeneratePool 为函数预生成参数池
	GeneratePool(
		contract common.Address,
		method *abi.Method,
		seedConfig *SeedConfig,
		poolSize int,
	) error

	// GetPooledParams 从池中获取参数组合
	GetPooledParams(
		contract common.Address,
		selector [4]byte,
	) ([]interface{}, error)

	// InvalidatePool 清空池（重新生成）
	InvalidatePool(contract common.Address, selector [4]byte)

	// GetPoolStats 获取池统计信息
	GetPoolStats() PoolStats

	// SetParamGenerator 设置参数生成器
	SetParamGenerator(generator ParamGenerator)
}

// PoolStats 参数池统计信息
type PoolStats struct {
	TotalPools   int     // 总池数
	TotalParams  int     // 总参数组合数
	CacheHitRate float64 // 缓存命中率
	AvgPoolSize  int     // 平均池大小
}

// ParamGenerator 参数生成器接口
type ParamGenerator interface {
	// GenerateForType 根据类型生成参数值
	GenerateForType(paramType abi.Type, seed int) interface{}
}

// poolKey 参数池的唯一标识
type poolKey struct {
	Contract common.Address
	Selector [4]byte
}

// paramPool 参数池
type paramPool struct {
	params      [][]interface{} // 参数组合列表
	currentIdx  int             // 当前轮询索引
	generatedAt time.Time       // 生成时间
	accessCount int             // 访问次数
}

// paramPoolManager 参数池管理器实现
type paramPoolManager struct {
	mu    sync.RWMutex
	pools map[poolKey]*paramPool

	// LRU缓存最近使用的参数池
	lru *lru.Cache[poolKey, time.Time]

	// 参数生成器
	paramGen ParamGenerator

	// 统计信息
	stats     PoolStats
	cacheHits int
	cacheMiss int
}

// NewParamPoolManager 创建新的参数池管理器
func NewParamPoolManager(maxPools int) (ParamPoolManager, error) {
	cache, err := lru.New[poolKey, time.Time](maxPools)
	if err != nil {
		return nil, fmt.Errorf("failed to create LRU cache: %w", err)
	}

	return &paramPoolManager{
		pools: make(map[poolKey]*paramPool),
		lru:   cache,
	}, nil
}

// SetParamGenerator 设置参数生成器
func (m *paramPoolManager) SetParamGenerator(generator ParamGenerator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.paramGen = generator
}

// GeneratePool 为函数预生成参数池
func (m *paramPoolManager) GeneratePool(
	contract common.Address,
	method *abi.Method,
	seedConfig *SeedConfig,
	poolSize int,
) error {
	if method == nil {
		return fmt.Errorf("method cannot be nil")
	}

	if poolSize <= 0 {
		return fmt.Errorf("pool size must be positive, got %d", poolSize)
	}

	key := poolKey{
		Contract: contract,
		Selector: [4]byte{},
	}
	copy(key.Selector[:], method.ID[:4])

	// 生成参数组合
	var allCombos [][]interface{}
	for i := 0; i < poolSize; i++ {
		combo := make([]interface{}, len(method.Inputs))

		for j, input := range method.Inputs {
			// 优先使用约束范围（按函数名匹配，采用攻击值/范围边界）
			if seedConfig != nil && seedConfig.Enabled {
				if vals := constraintValues(seedConfig, strings.ToLower(method.Name), j, input.Type, poolSize); len(vals) > 0 {
					combo[j] = vals[i%len(vals)]
					continue
				}
			}

			// 退回：使用种子配置
			if seedConfig != nil && seedConfig.Enabled {
				if seeds, hasSeed := seedConfig.AttackSeeds[j]; hasSeed && len(seeds) > 0 {
					// 从种子中轮询选择
					combo[j] = seeds[i%len(seeds)]
					continue
				}
			}

			// 回退到参数生成器
			if m.paramGen != nil {
				combo[j] = m.paramGen.GenerateForType(input.Type, i)
			} else {
				// 最后的fallback：生成默认零值
				combo[j] = m.generateDefaultValue(input.Type)
			}
		}

		allCombos = append(allCombos, combo)
	}

	// 存储到池中
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pools[key] = &paramPool{
		params:      allCombos,
		currentIdx:  0,
		generatedAt: time.Now(),
		accessCount: 0,
	}

	// 更新统计
	m.stats.TotalPools++
	m.stats.TotalParams += len(allCombos)
	if m.stats.TotalPools > 0 {
		m.stats.AvgPoolSize = m.stats.TotalParams / m.stats.TotalPools
	}

	return nil
}

// GetPooledParams 从池中获取参数组合
func (m *paramPoolManager) GetPooledParams(
	contract common.Address,
	selector [4]byte,
) ([]interface{}, error) {
	key := poolKey{
		Contract: contract,
		Selector: selector,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pool, exists := m.pools[key]
	if !exists {
		m.cacheMiss++
		return nil, fmt.Errorf("pool not found for %s:0x%x", contract.Hex(), selector)
	}

	// 缓存命中
	m.cacheHits++

	// 轮询获取参数
	params := pool.params[pool.currentIdx]
	pool.currentIdx = (pool.currentIdx + 1) % len(pool.params)
	pool.accessCount++

	// 更新LRU
	m.lru.Add(key, time.Now())

	// 更新缓存命中率
	totalAccess := m.cacheHits + m.cacheMiss
	if totalAccess > 0 {
		m.stats.CacheHitRate = float64(m.cacheHits) / float64(totalAccess)
	}

	return params, nil
}

// InvalidatePool 清空池
func (m *paramPoolManager) InvalidatePool(contract common.Address, selector [4]byte) {
	key := poolKey{
		Contract: contract,
		Selector: selector,
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if pool, exists := m.pools[key]; exists {
		// 更新统计
		m.stats.TotalParams -= len(pool.params)
		m.stats.TotalPools--
		if m.stats.TotalPools > 0 {
			m.stats.AvgPoolSize = m.stats.TotalParams / m.stats.TotalPools
		} else {
			m.stats.AvgPoolSize = 0
		}
	}

	delete(m.pools, key)
	m.lru.Remove(key)
}

// GetPoolStats 获取池统计信息
func (m *paramPoolManager) GetPoolStats() PoolStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.stats
}

// generateDefaultValue 生成类型的默认零值
func (m *paramPoolManager) generateDefaultValue(paramType abi.Type) interface{} {
	switch paramType.T {
	case abi.UintTy, abi.IntTy:
		return common.Big0
	case abi.BoolTy:
		return false
	case abi.AddressTy:
		return common.Address{}
	case abi.BytesTy, abi.FixedBytesTy:
		return []byte{}
	case abi.StringTy:
		return ""
	case abi.SliceTy, abi.ArrayTy:
		return []interface{}{}
	default:
		return nil
	}
}

// constraintValues 根据配置的约束范围生成值列表
func constraintValues(seed *SeedConfig, funcName string, paramIndex int, paramType abi.Type, poolSize int) []interface{} {
	if seed == nil || seed.ConstraintRanges == nil {
		return nil
	}
	funcRanges, ok := seed.ConstraintRanges[strings.ToLower(funcName)]
	if !ok {
		return nil
	}
	cr, ok := funcRanges[strconv.Itoa(paramIndex)]
	if !ok || cr == nil {
		return nil
	}

	// 1) 攻击值优先
	var out []interface{}
	for _, v := range cr.AttackValues {
		if val := parseConstraintValue(v, paramType); val != nil {
			out = append(out, val)
		}
	}

	// 2) 范围边界/插值
	if cr.Range != nil {
		minVal := parseConstraintValue(cr.Range.Min, paramType)
		maxVal := parseConstraintValue(cr.Range.Max, paramType)
		if minVal != nil {
			out = append(out, minVal)
		}
		if maxVal != nil && !sameValue(minVal, maxVal) {
			out = append(out, maxVal)
		}
		// 简单插值：取中点
		if minVal != nil && maxVal != nil {
			if mid := midpointValue(minVal, maxVal, paramType); mid != nil {
				out = append(out, mid)
			}
		}
	}

	if len(out) == 0 {
		return nil
	}

	// 限制数量，保持与 poolSize 一致的轮询体验
	if len(out) > poolSize {
		return out[:poolSize]
	}
	return out
}

func parseConstraintValue(v string, paramType abi.Type) interface{} {
	switch paramType.T {
	case abi.AddressTy:
		return common.HexToAddress(v)
	case abi.BoolTy:
		return strings.TrimSpace(strings.ToLower(v)) == "true" || v == "1"
	case abi.UintTy, abi.IntTy:
		if strings.HasPrefix(v, "0x") {
			if bi, ok := new(big.Int).SetString(strings.TrimPrefix(v, "0x"), 16); ok {
				return bi
			}
		}
		if bi, ok := new(big.Int).SetString(v, 10); ok {
			return bi
		}
		return nil
	case abi.BytesTy, abi.FixedBytesTy:
		if strings.HasPrefix(v, "0x") {
			return common.FromHex(v)
		}
		return []byte(v)
	case abi.StringTy:
		return v
	default:
		return nil
	}
}

func sameValue(a, b interface{}) bool {
	switch av := a.(type) {
	case *big.Int:
		if bv, ok := b.(*big.Int); ok {
			return av.Cmp(bv) == 0
		}
	case common.Address:
		if bv, ok := b.(common.Address); ok {
			return av == bv
		}
	case []byte:
		if bv, ok := b.([]byte); ok {
			return len(av) == len(bv) && string(av) == string(bv)
		}
	}
	return false
}

func midpointValue(a, b interface{}, paramType abi.Type) interface{} {
	switch av := a.(type) {
	case *big.Int:
		if bv, ok := b.(*big.Int); ok {
			sum := new(big.Int).Add(av, bv)
			return sum.Div(sum, big.NewInt(2))
		}
	case common.Address:
		// 地址不做插值，返回左值
		return av
	}
	return nil
}
