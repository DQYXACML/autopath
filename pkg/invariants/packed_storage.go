// ============================================================================
// 通用Packed Storage检测和解包框架
//
// 支持多种DeFi协议的packed storage自动检测和解包:
// - Uniswap V2: reserve0 + reserve1 + timestamp
// - Uniswap V3: sqrtPriceX96 + tick + 观察数据
// - 未来可扩展: Curve, Balancer等
// ============================================================================

package invariants

import (
	"fmt"
	"log"
	"math/big"
)

// PackedStorageType 打包存储类型
type PackedStorageType string

const (
	UniswapV2Type PackedStorageType = "uniswap_v2"
	UniswapV3Type PackedStorageType = "uniswap_v3"
	UnknownType   PackedStorageType = "unknown"
)

// PackedStorageDetector packed storage检测和解包接口
type PackedStorageDetector interface {
	// Detect 检测是否是该类型的packed storage
	Detect(value *big.Int) bool

	// Unpack 解包存储值
	Unpack(value *big.Int) interface{}

	// CheckChange 检查变化是否超过阈值
	CheckChange(before, after *big.Int, threshold float64) (bool, *ViolationDetail)

	// GetType 返回类型标识
	GetType() PackedStorageType
}

// ============================================================================
// Uniswap V2 检测器
// ============================================================================

// UniswapV2Detector Uniswap V2 packed storage检测器
type UniswapV2Detector struct{}

// UniswapV2Reserves Uniswap V2储备量结构
type UniswapV2Reserves struct {
	Reserve0           *big.Int
	Reserve1           *big.Int
	BlockTimestampLast uint32
}

// Detect 检测是否是Uniswap V2 packed storage
func (d *UniswapV2Detector) Detect(value *big.Int) bool {
	if value == nil || value.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// 启发式规则1: 值 > 2^144 (表示reserve0非零)
	threshold := new(big.Int).Lsh(big.NewInt(1), 144)
	if value.Cmp(threshold) <= 0 {
		return false
	}

	// 启发式规则2: 解包后验证
	reserves := d.unpackReserves(value)
	if reserves == nil {
		return false
	}

	// 两个reserve都应该 > 0
	if reserves.Reserve0.Cmp(big.NewInt(0)) <= 0 ||
	   reserves.Reserve1.Cmp(big.NewInt(0)) <= 0 {
		return false
	}

	// 额外验证: reserve不应该超过2^112 (112位最大值)
	max112 := new(big.Int).Lsh(big.NewInt(1), 112)
	if reserves.Reserve0.Cmp(max112) >= 0 || reserves.Reserve1.Cmp(max112) >= 0 {
		return false
	}

	return true
}

// Unpack 解包Uniswap V2存储值
func (d *UniswapV2Detector) Unpack(value *big.Int) interface{} {
	return d.unpackReserves(value)
}

// unpackReserves 解包Uniswap V2的reserves
// Layout: [reserve0 (112 bits)][reserve1 (112 bits)][blockTimestampLast (32 bits)]
func (d *UniswapV2Detector) unpackReserves(packedValue *big.Int) *UniswapV2Reserves {
	if packedValue == nil {
		return nil
	}

	mask32 := big.NewInt(0xFFFFFFFF)
	mask112 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))

	// 提取blockTimestampLast (最低32位)
	timestamp := new(big.Int).And(packedValue, mask32)

	// 提取reserve1 (中间112位: 位32-143)
	temp := new(big.Int).Rsh(packedValue, 32)
	reserve1 := new(big.Int).And(temp, mask112)

	// 提取reserve0 (最高112位: 位144-255)
	reserve0 := new(big.Int).Rsh(packedValue, 144)

	return &UniswapV2Reserves{
		Reserve0:           reserve0,
		Reserve1:           reserve1,
		BlockTimestampLast: uint32(timestamp.Uint64()),
	}
}

// CheckChange 检查Uniswap V2储备量变化
func (d *UniswapV2Detector) CheckChange(before, after *big.Int, threshold float64) (bool, *ViolationDetail) {
	reservesBefore := d.unpackReserves(before)
	reservesAfter := d.unpackReserves(after)

	if reservesBefore == nil || reservesAfter == nil {
		return true, nil
	}

	log.Printf("   [DEBUG]   Uniswap V2解包成功:")
	log.Printf("   [DEBUG]     Reserve0: %s -> %s", reservesBefore.Reserve0.String(), reservesAfter.Reserve0.String())
	log.Printf("   [DEBUG]     Reserve1: %s -> %s", reservesBefore.Reserve1.String(), reservesAfter.Reserve1.String())
	log.Printf("   [DEBUG]     Timestamp: %d -> %d", reservesBefore.BlockTimestampLast, reservesAfter.BlockTimestampLast)

	// 检查reserve0变化
	if reservesBefore.Reserve0.Cmp(big.NewInt(0)) > 0 {
		changeRate := calculateChangeRate(reservesBefore.Reserve0, reservesAfter.Reserve0)
		log.Printf("   [DEBUG]     Reserve0变化率: %.4f (%.2f%%)", changeRate, changeRate*100)

		if changeRate > threshold {
			return false, &ViolationDetail{
				Message: fmt.Sprintf("Uniswap V2 Reserve0 changed by %.2f%% (threshold: %.2f%%)",
					changeRate*100, threshold*100),
				Metadata: map[string]interface{}{
					"type":         "uniswap_v2",
					"field":        "reserve0",
					"before":       reservesBefore.Reserve0.String(),
					"after":        reservesAfter.Reserve0.String(),
					"change_rate":  changeRate,
					"threshold":    threshold,
					"packed_storage": true,
				},
			}
		}
	}

	// 检查reserve1变化
	if reservesBefore.Reserve1.Cmp(big.NewInt(0)) > 0 {
		changeRate := calculateChangeRate(reservesBefore.Reserve1, reservesAfter.Reserve1)
		log.Printf("   [DEBUG]     Reserve1变化率: %.4f (%.2f%%)", changeRate, changeRate*100)

		if changeRate > threshold {
			return false, &ViolationDetail{
				Message: fmt.Sprintf("Uniswap V2 Reserve1 changed by %.2f%% (threshold: %.2f%%)",
					changeRate*100, threshold*100),
				Metadata: map[string]interface{}{
					"type":         "uniswap_v2",
					"field":        "reserve1",
					"before":       reservesBefore.Reserve1.String(),
					"after":        reservesAfter.Reserve1.String(),
					"change_rate":  changeRate,
					"threshold":    threshold,
					"packed_storage": true,
				},
			}
		}
	}

	return true, nil
}

// GetType 返回类型标识
func (d *UniswapV2Detector) GetType() PackedStorageType {
	return UniswapV2Type
}

// ============================================================================
// Uniswap V3 检测器
// ============================================================================

// UniswapV3Detector Uniswap V3 packed storage检测器
type UniswapV3Detector struct{}

// UniswapV3Slot0 Uniswap V3 slot0结构
type UniswapV3Slot0 struct {
	SqrtPriceX96              *big.Int // uint160
	Tick                      int32    // int24
	ObservationIndex          uint16
	ObservationCardinality    uint16
	ObservationCardinalityNext uint16
	FeeProtocol               uint8
	Unlocked                  bool
}

// Detect 检测是否是Uniswap V3 packed storage
func (d *UniswapV3Detector) Detect(value *big.Int) bool {
	if value == nil || value.Cmp(big.NewInt(0)) == 0 {
		return false
	}

	// 启发式规则: Uniswap V3的slot0特征
	// sqrtPriceX96通常是一个很大的数(160位),但不会超过2^160
	max160 := new(big.Int).Lsh(big.NewInt(1), 160)

	// 提取sqrtPriceX96 (最低160位)
	mask160 := new(big.Int).Sub(max160, big.NewInt(1))
	sqrtPrice := new(big.Int).And(value, mask160)

	// sqrtPriceX96应该 > 0 且 < 2^160
	if sqrtPrice.Cmp(big.NewInt(0)) <= 0 || sqrtPrice.Cmp(max160) >= 0 {
		return false
	}

	// 进一步验证: 检查其他字段是否在合理范围
	slot0 := d.unpackSlot0(value)
	if slot0 == nil {
		return false
	}

	// tick范围: -887272 到 887272
	if slot0.Tick < -887272 || slot0.Tick > 887272 {
		return false
	}

	return true
}

// Unpack 解包Uniswap V3存储值
func (d *UniswapV3Detector) Unpack(value *big.Int) interface{} {
	return d.unpackSlot0(value)
}

// unpackSlot0 解包Uniswap V3的slot0
// Layout:
// [0-159]:   sqrtPriceX96 (160 bits)
// [160-183]: tick (24 bits, signed)
// [184-199]: observationIndex (16 bits)
// [200-215]: observationCardinality (16 bits)
// [216-231]: observationCardinalityNext (16 bits)
// [232-239]: feeProtocol (8 bits)
// [240]:     unlocked (1 bit)
func (d *UniswapV3Detector) unpackSlot0(packedValue *big.Int) *UniswapV3Slot0 {
	if packedValue == nil {
		return nil
	}

	mask160 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 160), big.NewInt(1))
	mask24 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 24), big.NewInt(1))
	mask16 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 16), big.NewInt(1))
	mask8 := big.NewInt(0xFF)
	mask1 := big.NewInt(1)

	// 提取sqrtPriceX96
	sqrtPriceX96 := new(big.Int).And(packedValue, mask160)

	// 提取tick (24位有符号整数)
	temp := new(big.Int).Rsh(packedValue, 160)
	tickBits := new(big.Int).And(temp, mask24)
	tick := int32(tickBits.Int64())
	// 处理符号位
	if tick >= (1 << 23) {
		tick -= (1 << 24)
	}

	// 提取其他字段
	temp = new(big.Int).Rsh(packedValue, 184)
	observationIndex := uint16(new(big.Int).And(temp, mask16).Uint64())

	temp = new(big.Int).Rsh(packedValue, 200)
	observationCardinality := uint16(new(big.Int).And(temp, mask16).Uint64())

	temp = new(big.Int).Rsh(packedValue, 216)
	observationCardinalityNext := uint16(new(big.Int).And(temp, mask16).Uint64())

	temp = new(big.Int).Rsh(packedValue, 232)
	feeProtocol := uint8(new(big.Int).And(temp, mask8).Uint64())

	temp = new(big.Int).Rsh(packedValue, 240)
	unlocked := new(big.Int).And(temp, mask1).Cmp(big.NewInt(1)) == 0

	return &UniswapV3Slot0{
		SqrtPriceX96:              sqrtPriceX96,
		Tick:                      tick,
		ObservationIndex:          observationIndex,
		ObservationCardinality:    observationCardinality,
		ObservationCardinalityNext: observationCardinalityNext,
		FeeProtocol:               feeProtocol,
		Unlocked:                  unlocked,
	}
}

// CheckChange 检查Uniswap V3 slot0变化
func (d *UniswapV3Detector) CheckChange(before, after *big.Int, threshold float64) (bool, *ViolationDetail) {
	slot0Before := d.unpackSlot0(before)
	slot0After := d.unpackSlot0(after)

	if slot0Before == nil || slot0After == nil {
		return true, nil
	}

	log.Printf("   [DEBUG]   Uniswap V3解包成功:")
	log.Printf("   [DEBUG]     SqrtPriceX96: %s -> %s", slot0Before.SqrtPriceX96.String(), slot0After.SqrtPriceX96.String())
	log.Printf("   [DEBUG]     Tick: %d -> %d", slot0Before.Tick, slot0After.Tick)

	// 检查sqrtPriceX96变化
	if slot0Before.SqrtPriceX96.Cmp(big.NewInt(0)) > 0 {
		changeRate := calculateChangeRate(slot0Before.SqrtPriceX96, slot0After.SqrtPriceX96)
		log.Printf("   [DEBUG]     SqrtPriceX96变化率: %.4f (%.2f%%)", changeRate, changeRate*100)

		if changeRate > threshold {
			return false, &ViolationDetail{
				Message: fmt.Sprintf("Uniswap V3 sqrtPriceX96 changed by %.2f%% (threshold: %.2f%%)",
					changeRate*100, threshold*100),
				Metadata: map[string]interface{}{
					"type":         "uniswap_v3",
					"field":        "sqrtPriceX96",
					"before":       slot0Before.SqrtPriceX96.String(),
					"after":        slot0After.SqrtPriceX96.String(),
					"tick_before":  slot0Before.Tick,
					"tick_after":   slot0After.Tick,
					"change_rate":  changeRate,
					"threshold":    threshold,
					"packed_storage": true,
				},
			}
		}
	}

	return true, nil
}

// GetType 返回类型标识
func (d *UniswapV3Detector) GetType() PackedStorageType {
	return UniswapV3Type
}

// ============================================================================
// 通用检测框架
// ============================================================================

var (
	// 注册所有检测器
	// 顺序很重要: 先检查更具体的协议(V3),再检查通用的(V2)
	packedStorageDetectors = []PackedStorageDetector{
		&UniswapV3Detector{}, // V3更具体,先检查
		&UniswapV2Detector{}, // V2较通用,后检查
		// 未来可以添加更多: Curve, Balancer等
	}
)

// DetectPackedStorage 自动检测packed storage类型
func DetectPackedStorage(value *big.Int) (PackedStorageDetector, bool) {
	for _, detector := range packedStorageDetectors {
		if detector.Detect(value) {
			log.Printf("   [DEBUG]    检测到 %s packed storage", detector.GetType())
			return detector, true
		}
	}
	return nil, false
}

// calculateChangeRate 计算变化率
func calculateChangeRate(before, after *big.Int) float64 {
	if before.Cmp(big.NewInt(0)) == 0 {
		return 0
	}

	delta := new(big.Int).Sub(after, before)
	delta.Abs(delta)

	deltaFloat := new(big.Float).SetInt(delta)
	beforeFloat := new(big.Float).SetInt(before)

	ratio := new(big.Float).Quo(deltaFloat, beforeFloat)
	changeRate, _ := ratio.Float64()

	return changeRate
}
