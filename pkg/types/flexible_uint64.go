package types

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// FlexibleUint64 是一个可以从多种 JSON 格式解析的 uint64 类型
// 支持的格式:
// - JSON 数字: 100000000
// - 十六进制字符串: "0x5f5e100"
// - 十进制字符串: "100000000"
type FlexibleUint64 struct {
	value uint64
}

// NewFlexibleUint64 创建一个新的 FlexibleUint64
func NewFlexibleUint64(val uint64) FlexibleUint64 {
	return FlexibleUint64{value: val}
}

// Value 返回 uint64 值
func (f FlexibleUint64) Value() uint64 {
	return f.value
}

// UnmarshalJSON 实现 json.Unmarshaler 接口
// 支持解析多种格式的输入
func (f *FlexibleUint64) UnmarshalJSON(data []byte) error {
	// 尝试作为数字解析
	var num json.Number
	if err := json.Unmarshal(data, &num); err == nil {
		val, err := num.Int64()
		if err != nil {
			// 可能是科学计数法或浮点数
			floatVal, err := num.Float64()
			if err != nil {
				return fmt.Errorf("无法解析数字: %v", err)
			}
			f.value = uint64(floatVal)
			return nil
		}
		f.value = uint64(val)
		return nil
	}

	// 尝试作为字符串解析
	var str string
	if err := json.Unmarshal(data, &str); err != nil {
		return fmt.Errorf("既不是数字也不是字符串: %v", err)
	}

	// 空字符串视为 0
	if str == "" || str == "0x" {
		f.value = 0
		return nil
	}

	// 处理十六进制字符串
	if strings.HasPrefix(str, "0x") || strings.HasPrefix(str, "0X") {
		// 去除 0x 前缀
		hexStr := strings.TrimPrefix(strings.ToLower(str), "0x")

		// 使用 big.Int 处理可能超出 uint64 范围的值
		bigInt := new(big.Int)
		_, ok := bigInt.SetString(hexStr, 16)
		if !ok {
			return fmt.Errorf("无效的十六进制字符串: %s", str)
		}

		// 检查是否超出 uint64 范围
		if !bigInt.IsUint64() {
			return fmt.Errorf("十六进制值超出 uint64 范围: %s", str)
		}

		f.value = bigInt.Uint64()
		return nil
	}

	// 处理十进制字符串
	val, err := strconv.ParseUint(str, 10, 64)
	if err != nil {
		return fmt.Errorf("无法解析十进制字符串: %s, 错误: %v", str, err)
	}
	f.value = val
	return nil
}

// MarshalJSON 实现 json.Marshaler 接口
// 序列化为十六进制字符串格式 (与以太坊标准一致)
func (f FlexibleUint64) MarshalJSON() ([]byte, error) {
	hexStr := fmt.Sprintf("\"0x%x\"", f.value)
	return []byte(hexStr), nil
}

// String 返回十六进制字符串表示
func (f FlexibleUint64) String() string {
	return fmt.Sprintf("0x%x", f.value)
}

// Uint64 返回 uint64 值 (Value 的别名，提供更好的可读性)
func (f FlexibleUint64) Uint64() uint64 {
	return f.value
}

// IsZero 检查值是否为 0
func (f FlexibleUint64) IsZero() bool {
	return f.value == 0
}
