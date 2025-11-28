package fuzzer

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ABIParser ABI解析器
type ABIParser struct {
	abis map[common.Address]*abi.ABI // 缓存已加载的ABI
}

// NewABIParser 创建新的ABI解析器
func NewABIParser() *ABIParser {
	return &ABIParser{
		abis: make(map[common.Address]*abi.ABI),
	}
}

// ParseCallData 解析calldata
func (p *ABIParser) ParseCallData(data []byte) (*ParsedCallData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata too short: %d bytes", len(data))
	}

	// 提取函数选择器（前4字节）
	selector := data[:4]

	// 提取参数数据
	paramData := data[4:]

	// 解析参数（不依赖ABI的简单解析）
	params := p.parseRawParameters(paramData)

	return &ParsedCallData{
		Selector:   selector,
		Parameters: params,
		Raw:        data,
	}, nil
}

// ParseCallDataWithABI 使用ABI解析calldata
func (p *ABIParser) ParseCallDataWithABI(data []byte, contractABI *abi.ABI) (*ParsedCallData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("calldata too short: %d bytes", len(data))
	}

	selector := data[:4]
	paramData := data[4:]

	// 查找对应的方法
	method, err := contractABI.MethodById(selector)
	if err != nil {
		// 如果找不到方法，使用原始解析
		return p.ParseCallData(data)
	}

	// 解析参数
	params, err := p.parseMethodParameters(method, paramData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse parameters: %w", err)
	}

	return &ParsedCallData{
		Selector:   selector,
		Parameters: params,
		Raw:        data,
	}, nil
}

// parseRawParameters 解析原始参数（不依赖ABI）
func (p *ABIParser) parseRawParameters(data []byte) []Parameter {
	params := []Parameter{}

	// 基础启发式解析：按32字节分组
	// 这是一个简化实现，实际的动态类型需要更复杂的解析
	for i := 0; i < len(data); i += 32 {
		end := i + 32
		if end > len(data) {
			end = len(data)
		}

		chunk := data[i:end]
		param := Parameter{
			Index: len(params),
			Type:  p.detectParameterType(chunk),
			Value: chunk,
		}

		// 尝试解析为具体类型
		param.Value = p.parseValue(param.Type, chunk)
		params = append(params, param)
	}

	return params
}

// parseMethodParameters 使用方法签名解析参数
func (p *ABIParser) parseMethodParameters(method *abi.Method, data []byte) ([]Parameter, error) {
	// 解包参数
	values, err := method.Inputs.UnpackValues(data)
	if err != nil {
		return nil, err
	}

	params := make([]Parameter, len(values))
	for i, input := range method.Inputs {
		params[i] = Parameter{
			Index: i,
			Name:  input.Name,
			Type:  input.Type.String(),
			Value: values[i],
		}

		// 设置额外属性
		if strings.Contains(input.Type.String(), "[]") {
			params[i].IsArray = true
		}
		if strings.HasPrefix(input.Type.String(), "bytes") {
			if size := strings.TrimPrefix(input.Type.String(), "bytes"); size != "" {
				fmt.Sscanf(size, "%d", &params[i].Size)
			}
		}
	}

	return params, nil
}

// detectParameterType 检测参数类型（启发式）
func (p *ABIParser) detectParameterType(data []byte) string {
	if len(data) != 32 {
		return "bytes"
	}

	// 检查是否可能是地址（前12字节为0）
	isAddress := true
	for i := 0; i < 12; i++ {
		if data[i] != 0 {
			isAddress = false
			break
		}
	}
	if isAddress {
		return "address"
	}

	// 检查是否可能是小整数
	leadingZeros := 0
	for _, b := range data {
		if b == 0 {
			leadingZeros++
		} else {
			break
		}
	}

	if leadingZeros >= 28 {
		// 可能是bool或小整数
		if data[31] == 0 || data[31] == 1 {
			return "bool"
		}
		return "uint256"
	}

	// 默认为uint256
	return "uint256"
}

// parseValue 解析具体值
func (p *ABIParser) parseValue(paramType string, data []byte) interface{} {
	switch paramType {
	case "address":
		if len(data) >= 20 {
			return common.BytesToAddress(data[len(data)-20:])
		}
		return common.Address{}

	case "bool":
		if len(data) > 0 {
			return data[len(data)-1] != 0
		}
		return false

	case "uint256", "int256":
		return new(big.Int).SetBytes(data)

	case "bytes", "bytes32":
		return data

	default:
		// 尝试作为uint256处理
		if strings.HasPrefix(paramType, "uint") || strings.HasPrefix(paramType, "int") {
			return new(big.Int).SetBytes(data)
		}
		return data
	}
}

// ReconstructCallData 重构calldata
func (p *ABIParser) ReconstructCallData(selector []byte, params []interface{}) ([]byte, error) {
	if len(selector) != 4 {
		return nil, fmt.Errorf("invalid selector length: %d", len(selector))
	}

	// 编码参数
	encodedParams, err := p.encodeParameters(params)
	if err != nil {
		return nil, err
	}

	// 组合selector和参数
	result := make([]byte, len(selector)+len(encodedParams))
	copy(result, selector)
	copy(result[4:], encodedParams)

	return result, nil
}

// encodeParameters 编码参数
func (p *ABIParser) encodeParameters(params []interface{}) ([]byte, error) {
	var result []byte

	for _, param := range params {
		encoded, err := p.encodeValue(param)
		if err != nil {
			return nil, err
		}
		result = append(result, encoded...)
	}

	return result, nil
}

// encodeValue 编码单个值
func (p *ABIParser) encodeValue(value interface{}) ([]byte, error) {
	// 创建32字节的缓冲区
	encoded := make([]byte, 32)

	switch v := value.(type) {
	case *big.Int:
		// 大整数编码
		bytes := v.Bytes()
		if len(bytes) > 32 {
			return nil, fmt.Errorf("integer too large: %s", v.String())
		}
		// 右对齐
		copy(encoded[32-len(bytes):], bytes)

	case common.Address:
		// 地址编码
		copy(encoded[12:], v.Bytes())

	case bool:
		// 布尔值编码
		if v {
			encoded[31] = 1
		}

	case []byte:
		// 字节数组编码
		if len(v) <= 32 {
			// 静态字节数组，左对齐
			copy(encoded, v)
		} else {
			// 动态字节数组需要特殊处理
			return p.encodeDynamicBytes(v), nil
		}

	case string:
		// 字符串作为bytes处理
		return p.encodeValue([]byte(v))

	default:
		// 尝试将其他类型转换为字节
		if data, ok := v.([]byte); ok {
			copy(encoded, data)
		} else {
			return nil, fmt.Errorf("unsupported type: %T", v)
		}
	}

	return encoded, nil
}

// encodeDynamicBytes 编码动态字节数组
func (p *ABIParser) encodeDynamicBytes(data []byte) []byte {
	// 动态数据编码：offset + length + data
	// 这是简化版本，完整的ABI编码更复杂
	result := make([]byte, 32)                                                // offset
	result = append(result, p.encodeUint256(big.NewInt(int64(len(data))))...) // length
	result = append(result, data...)                                          // actual data

	// 填充到32字节边界
	padding := (32 - (len(data) % 32)) % 32
	if padding > 0 {
		result = append(result, make([]byte, padding)...)
	}

	return result
}

// encodeUint256 编码uint256
func (p *ABIParser) encodeUint256(n *big.Int) []byte {
	encoded := make([]byte, 32)
	bytes := n.Bytes()
	if len(bytes) > 32 {
		bytes = bytes[len(bytes)-32:]
	}
	copy(encoded[32-len(bytes):], bytes)
	return encoded
}

// GetFunctionSelector 计算函数选择器
func (p *ABIParser) GetFunctionSelector(signature string) []byte {
	hash := crypto.Keccak256Hash([]byte(signature))
	return hash[:4]
}

// ExtractSelector 从calldata提取选择器
func (p *ABIParser) ExtractSelector(calldata []byte) ([]byte, error) {
	if len(calldata) < 4 {
		return nil, fmt.Errorf("calldata too short")
	}
	return calldata[:4], nil
}

// ExtractParameters 从calldata提取参数部分
func (p *ABIParser) ExtractParameters(calldata []byte) []byte {
	if len(calldata) <= 4 {
		return []byte{}
	}
	return calldata[4:]
}

// SetABI 设置合约ABI（可选）
func (p *ABIParser) SetABI(address common.Address, contractABI *abi.ABI) {
	p.abis[address] = contractABI
}

// GetABI 获取合约ABI
func (p *ABIParser) GetABI(address common.Address) (*abi.ABI, bool) {
	abi, exists := p.abis[address]
	return abi, exists
}

// LoadABIForAddress 尝试从本地extracted_contracts中加载指定地址的ABI
func (p *ABIParser) LoadABIForAddress(address common.Address) (*abi.ABI, error) {
	if cached, ok := p.GetABI(address); ok {
		return cached, nil
	}

	baseDir, searchErr := p.locateExtractedRoot()
	if searchErr != nil {
		return nil, fmt.Errorf("未找到ABI根目录: %w", searchErr)
	}

	lowerAddr := strings.ToLower(address.Hex()[2:])
	var matched string
	errStop := errors.New("abi-found")

	walkErr := filepath.WalkDir(baseDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		// 目录名中包含地址且文件名为 abi.json
		if strings.EqualFold(d.Name(), "abi.json") && strings.Contains(strings.ToLower(path), lowerAddr) {
			matched = path
			return errStop
		}
		return nil
	})

	if walkErr != nil && !errors.Is(walkErr, errStop) {
		return nil, walkErr
	}

	if matched == "" {
		return nil, fmt.Errorf("未找到地址 %s 对应的ABI文件", address.Hex())
	}

	file, err := os.Open(matched)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	contractABI, err := abi.JSON(file)
	if err != nil {
		return nil, err
	}

	// 缓存结果，避免重复扫描
	p.SetABI(address, &contractABI)
	return &contractABI, nil
}

// locateExtractedRoot 查找 extracted_contracts 根目录，兼容不同工作目录
func (p *ABIParser) locateExtractedRoot() (string, error) {
	candidates := []string{}

	if wd, err := os.Getwd(); err == nil {
		for depth := 0; depth <= 3; depth++ {
			up := wd
			for i := 0; i < depth; i++ {
				up = filepath.Dir(up)
			}
			candidates = append(candidates, filepath.Join(up, "DeFiHackLabs", "extracted_contracts"))
		}
	}

	candidates = append(candidates, filepath.Join("DeFiHackLabs", "extracted_contracts"))

	for _, cand := range candidates {
		clean := filepath.Clean(cand)
		if st, err := os.Stat(clean); err == nil && st.IsDir() {
			return clean, nil
		}
	}

	var found string
	errStop := errors.New("found-extracted-root")
	_ = filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && strings.EqualFold(d.Name(), "extracted_contracts") {
			found = path
			return errStop
		}
		return nil
	})
	if found != "" {
		return found, nil
	}

	return "", fmt.Errorf("在候选路径中未找到extracted_contracts目录")
}

// SelectorToHex 将选择器转换为十六进制字符串
func SelectorToHex(selector []byte) string {
	return "0x" + hex.EncodeToString(selector)
}
