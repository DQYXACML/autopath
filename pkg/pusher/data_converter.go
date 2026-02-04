package pusher

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"autopath/pkg/fuzzer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// DataConverter 数据转换器，负责链下到链上的数据格式转换
type DataConverter struct {
	maxValuesPerParam int
	compressRanges    bool
}

// NewDataConverter 创建数据转换器
func NewDataConverter(maxValues int, compress bool) *DataConverter {
	return &DataConverter{
		maxValuesPerParam: maxValues,
		compressRanges:    compress,
	}
}

// ConvertParameterSummary 转换单个参数摘要
func (dc *DataConverter) ConvertParameterSummary(param fuzzer.ParameterSummary) (*ChainParamSummary, error) {
	summary := &ChainParamSummary{
		ParamIndex:      uint8(param.ParamIndex),
		ParamType:       dc.parseParamType(param.ParamType),
		OccurrenceCount: uint64(param.OccurrenceCount),
	}

	if param.IsRange {
		// 处理范围值
		summary.IsRange = true
		summary.RangeMin = dc.parseValueToBytes32(param.RangeMin, param.ParamType)
		summary.RangeMax = dc.parseValueToBytes32(param.RangeMax, param.ParamType)
	} else {
		// 处理离散值
		summary.SingleValues = dc.parseMultipleValues(param.SingleValues, param.ParamType)

		// 如果值太多，尝试转换为范围
		if dc.compressRanges && len(summary.SingleValues) > 10 {
			if rangeOpt := dc.tryConvertToRange(summary.SingleValues, param.ParamType); rangeOpt != nil {
				summary.IsRange = true
				summary.RangeMin = rangeOpt.Min
				summary.RangeMax = rangeOpt.Max
				summary.SingleValues = nil
			}
		}

		// 限制值的数量
		if len(summary.SingleValues) > dc.maxValuesPerParam {
			summary.SingleValues = summary.SingleValues[:dc.maxValuesPerParam]
		}
	}

	return summary, nil
}

// ChainParamSummary 链上参数摘要格式
type ChainParamSummary struct {
	ParamIndex      uint8
	ParamType       uint8
	SingleValues    [][32]byte
	IsRange         bool
	RangeMin        [32]byte
	RangeMax        [32]byte
	OccurrenceCount uint64
}

// RangeOptimization 范围优化结果
type RangeOptimization struct {
	Min [32]byte
	Max [32]byte
}

// parseParamType 解析参数类型为枚举值
func (dc *DataConverter) parseParamType(paramType string) uint8 {
	typeMap := map[string]uint8{
		"uint256": 0,
		"uint":    0,
		"int256":  1,
		"int":     1,
		"address": 2,
		"bool":    3,
		"bytes32": 4,
		"bytes":   5,
		"string":  6,
	}

	paramType = strings.ToLower(strings.TrimSpace(paramType))

	// 处理数组类型（含固定长度）
	if idx := strings.Index(paramType, "["); idx != -1 && strings.HasSuffix(paramType, "]") {
		// 动态数组按bytes处理（链上会对动态参数进行hash）
		return typeMap["bytes"]
	}

	// 处理固定大小的类型 (uint8, uint16, bytes4等)
	for key := range typeMap {
		if strings.HasPrefix(paramType, key) {
			return typeMap[key]
		}
	}

	if val, ok := typeMap[paramType]; ok {
		return val
	}

	// 默认为uint256
	return 0
}

// parseValueToBytes32 解析单个值为bytes32
func (dc *DataConverter) parseValueToBytes32(value string, paramType string) [32]byte {
	var result [32]byte

	value = strings.TrimSpace(value)
	lowerType := strings.ToLower(strings.TrimSpace(paramType))
	isArray := strings.Contains(lowerType, "[") && strings.HasSuffix(lowerType, "]")
	isDynamic := isArray || lowerType == "bytes" || lowerType == "string"

	// 处理不同类型
	switch dc.parseParamType(paramType) {
	case 2: // ADDRESS
		if addr := dc.parseAddress(value); addr != (common.Address{}) {
			copy(result[12:], addr.Bytes()) // 地址右对齐
		}

	case 3: // BOOL
		if strings.ToLower(value) == "true" || value == "1" {
			result[31] = 1
		}

	case 4: // BYTES32
		if strings.HasPrefix(value, "0x") {
			decoded, _ := hex.DecodeString(strings.TrimPrefix(value, "0x"))
			copy(result[:], decoded)
		}

	case 5, 6: // BYTES, STRING
		if isDynamic {
			if isHexBytes32(value) {
				decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
				if err == nil && len(decoded) == 32 {
					copy(result[:], decoded)
					return result
				}
			}
			if strings.HasPrefix(value, "0x") {
				if decoded, err := hex.DecodeString(strings.TrimPrefix(value, "0x")); err == nil {
					hash := crypto.Keccak256Hash(decoded)
					copy(result[:], hash.Bytes())
					return result
				}
			}
			hash := crypto.Keccak256Hash([]byte(value))
			copy(result[:], hash.Bytes())
			return result
		}
		hash := crypto.Keccak256Hash([]byte(value))
		copy(result[:], hash.Bytes())

	default: // UINT256, INT256
		dc.parseNumber(value, result[:])
	}

	return result
}

func isHexBytes32(value string) bool {
	if !strings.HasPrefix(value, "0x") {
		return false
	}
	return len(value) == 66
}

// parseMultipleValues 解析多个值
func (dc *DataConverter) parseMultipleValues(values []string, paramType string) [][32]byte {
	result := make([][32]byte, 0, len(values))
	seen := make(map[[32]byte]bool)

	for _, val := range values {
		parsed := dc.parseValueToBytes32(val, paramType)
		// 去重
		if !seen[parsed] {
			seen[parsed] = true
			result = append(result, parsed)
		}
	}

	return result
}

// parseAddress 解析地址
func (dc *DataConverter) parseAddress(value string) common.Address {
	if strings.HasPrefix(value, "0x") {
		return common.HexToAddress(value)
	}
	return common.Address{}
}

// parseNumber 解析数字
func (dc *DataConverter) parseNumber(value string, dest []byte) {
	value = strings.TrimSpace(value)

	var n *big.Int
	if strings.HasPrefix(value, "0x") {
		// 十六进制
		n, _ = new(big.Int).SetString(value[2:], 16)
	} else if strings.HasPrefix(value, "-") {
		// 负数
		n, _ = new(big.Int).SetString(value, 10)
	} else {
		// 十进制
		n, _ = new(big.Int).SetString(value, 10)
	}

	if n != nil {
		// 处理负数的二进制补码
		if n.Sign() < 0 {
			// 转换为256位的二进制补码
			modulus := new(big.Int).Lsh(big.NewInt(1), 256)
			n.Add(n, modulus)
		}
		n.FillBytes(dest)
	}
}

// tryConvertToRange 尝试将离散值转换为范围
func (dc *DataConverter) tryConvertToRange(values [][32]byte, paramType string) *RangeOptimization {
	if len(values) < 2 {
		return nil
	}

	// 只对数值类型尝试范围优化
	pType := dc.parseParamType(paramType)
	if pType != 0 && pType != 1 { // 不是uint256或int256
		return nil
	}

	// 转换为big.Int并排序
	nums := make([]*big.Int, 0, len(values))
	for _, val := range values {
		n := new(big.Int).SetBytes(val[:])
		nums = append(nums, n)
	}

	// 找最小和最大值
	min := new(big.Int).Set(nums[0])
	max := new(big.Int).Set(nums[0])

	for _, n := range nums[1:] {
		if n.Cmp(min) < 0 {
			min.Set(n)
		}
		if n.Cmp(max) > 0 {
			max.Set(n)
		}
	}

	// 检查是否值得转换为范围
	// 如果范围内的值占比太低，不转换
	rangeSize := new(big.Int).Sub(max, min)
	if rangeSize.BitLen() > 100 { // 范围太大
		return nil
	}

	// 计算覆盖率
	coverage := float64(len(nums)) / float64(new(big.Int).Add(rangeSize, big.NewInt(1)).Int64())
	if coverage < 0.5 { // 覆盖率低于50%
		return nil
	}

	result := &RangeOptimization{}
	min.FillBytes(result.Min[:])
	max.FillBytes(result.Max[:])

	return result
}

// OptimizeParameters 优化参数集合
func (dc *DataConverter) OptimizeParameters(params []fuzzer.ParameterSummary) []fuzzer.ParameterSummary {
	optimized := make([]fuzzer.ParameterSummary, 0, len(params))

	// 按参数索引分组
	grouped := make(map[int][]fuzzer.ParameterSummary)
	for _, p := range params {
		grouped[p.ParamIndex] = append(grouped[p.ParamIndex], p)
	}

	// 合并相同参数的规则
	for idx, group := range grouped {
		if len(group) == 1 {
			optimized = append(optimized, group[0])
			continue
		}

		// 合并多个规则
		merged := dc.mergeParameterRules(group)
		merged.ParamIndex = idx
		optimized = append(optimized, merged)
	}

	return optimized
}

// mergeParameterRules 合并同一参数的多个规则
func (dc *DataConverter) mergeParameterRules(rules []fuzzer.ParameterSummary) fuzzer.ParameterSummary {
	if len(rules) == 0 {
		return fuzzer.ParameterSummary{}
	}

	merged := rules[0]

	// 如果有多个规则，尝试合并
	for _, rule := range rules[1:] {
		if rule.IsRange && merged.IsRange {
			// 合并范围
			if rule.RangeMin < merged.RangeMin {
				merged.RangeMin = rule.RangeMin
			}
			if rule.RangeMax > merged.RangeMax {
				merged.RangeMax = rule.RangeMax
			}
		} else if !rule.IsRange && !merged.IsRange {
			// 合并离散值
			valueSet := make(map[string]bool)
			for _, v := range merged.SingleValues {
				valueSet[v] = true
			}
			for _, v := range rule.SingleValues {
				valueSet[v] = true
			}

			merged.SingleValues = make([]string, 0, len(valueSet))
			for v := range valueSet {
				merged.SingleValues = append(merged.SingleValues, v)
			}
		} else {
			// 一个是范围，一个是离散值，转换为范围
			merged.IsRange = true
			// 简化处理：使用最宽的范围
		}

		merged.OccurrenceCount += rule.OccurrenceCount
	}

	return merged
}

// ValidateConversion 验证转换结果
func (dc *DataConverter) ValidateConversion(original fuzzer.ParameterSummary, converted *ChainParamSummary) error {
	// 检查参数索引
	if uint8(original.ParamIndex) != converted.ParamIndex {
		return fmt.Errorf("param index mismatch: %d != %d", original.ParamIndex, converted.ParamIndex)
	}

	// 检查类型
	expectedType := dc.parseParamType(original.ParamType)
	if expectedType != converted.ParamType {
		return fmt.Errorf("param type mismatch: expected %d, got %d", expectedType, converted.ParamType)
	}

	// 检查范围标志
	if original.IsRange != converted.IsRange {
		// 允许离散值被优化为范围
		if !original.IsRange && converted.IsRange && dc.compressRanges {
			return nil // 这是允许的优化
		}
		return fmt.Errorf("range flag mismatch")
	}

	return nil
}

// EstimateGasCost 估算链上存储的gas成本
func (dc *DataConverter) EstimateGasCost(summaries []*ChainParamSummary) uint64 {
	var totalGas uint64

	// 基础gas成本
	baseGas := uint64(21000)

	// 每个参数的固定成本
	paramGas := uint64(5000)

	// 存储成本 (SSTORE)
	storageGas := uint64(20000)

	// 动态数组成本
	arrayGas := uint64(2000)

	totalGas = baseGas

	for _, summary := range summaries {
		totalGas += paramGas

		if summary.IsRange {
			// 范围存储成本较低
			totalGas += storageGas * 2 // min和max
		} else {
			// 离散值存储成本
			totalGas += storageGas * uint64(len(summary.SingleValues))
			totalGas += arrayGas * uint64(len(summary.SingleValues))
		}
	}

	// 添加一些缓冲
	totalGas = totalGas * 120 / 100

	return totalGas
}
