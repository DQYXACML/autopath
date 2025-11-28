// Package local 提供本地EVM执行器实现
package local

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewProtectedRegistry 测试注册中心创建
func TestNewProtectedRegistry(t *testing.T) {
	registry := NewProtectedRegistry()
	require.NotNil(t, registry)
	assert.Equal(t, 0, registry.Count())
}

// TestRegisterContract 测试合约注册
func TestRegisterContract(t *testing.T) {
	registry := NewProtectedRegistry()

	// 创建简单的ABI
	abiJSON := `[{"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"success","type":"bool"}]}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")
	info := &ProtectedContractInfo{
		Address: addr,
		ABI:     &parsedABI,
		SeedConfig: &SeedConfig{
			Enabled:     true,
			AttackSeeds: make(map[int][]interface{}),
		},
		Metadata: make(map[string]interface{}),
	}

	// 测试注册
	err = registry.RegisterContract(info)
	require.NoError(t, err)
	assert.Equal(t, 1, registry.Count())
	assert.True(t, registry.IsProtected(addr))
}

// TestRegisterContractNilABI 测试注册nil ABI的合约应该失败
func TestRegisterContractNilABI(t *testing.T) {
	registry := NewProtectedRegistry()

	addr := common.HexToAddress("0x2222222222222222222222222222222222222222")
	info := &ProtectedContractInfo{
		Address: addr,
		ABI:     nil, // nil ABI
	}

	err := registry.RegisterContract(info)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ABI cannot be nil")
}

// TestGetContractInfo 测试获取合约信息
func TestGetContractInfo(t *testing.T) {
	registry := NewProtectedRegistry()

	abiJSON := `[{"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"}],"outputs":[]}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	addr := common.HexToAddress("0x3333333333333333333333333333333333333333")
	originalInfo := &ProtectedContractInfo{
		Address: addr,
		ABI:     &parsedABI,
		Metadata: map[string]interface{}{
			"test_key": "test_value",
		},
	}

	err = registry.RegisterContract(originalInfo)
	require.NoError(t, err)

	// 获取合约信息
	retrievedInfo, err := registry.GetContractInfo(addr)
	require.NoError(t, err)
	assert.Equal(t, addr, retrievedInfo.Address)
	assert.NotNil(t, retrievedInfo.ABI)
	assert.Equal(t, "test_value", retrievedInfo.Metadata["test_key"])
}

// TestGetContractInfoNotFound 测试获取不存在的合约
func TestGetContractInfoNotFound(t *testing.T) {
	registry := NewProtectedRegistry()

	addr := common.HexToAddress("0x4444444444444444444444444444444444444444")
	info, err := registry.GetContractInfo(addr)
	assert.Error(t, err)
	assert.Nil(t, info)
	assert.Contains(t, err.Error(), "not found")
}

// TestGetMethod 测试根据选择器获取方法
func TestGetMethod(t *testing.T) {
	registry := NewProtectedRegistry()

	// transfer(address,uint256) 的选择器
	abiJSON := `[
		{"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"success","type":"bool"}]},
		{"name":"approve","type":"function","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"success","type":"bool"}]}
	]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	addr := common.HexToAddress("0x5555555555555555555555555555555555555555")
	info := &ProtectedContractInfo{
		Address: addr,
		ABI:     &parsedABI,
	}

	err = registry.RegisterContract(info)
	require.NoError(t, err)

	// transfer(address,uint256) 的选择器是 0xa9059cbb 的前4字节
	transferMethod := parsedABI.Methods["transfer"]
	selector := [4]byte{}
	copy(selector[:], transferMethod.ID[:4])

	// 获取方法
	method, err := registry.GetMethod(addr, selector)
	require.NoError(t, err)
	assert.Equal(t, "transfer", method.Name)
	assert.Len(t, method.Inputs, 2)
}

// TestGetMethodNotFound 测试获取不存在的方法选择器
func TestGetMethodNotFound(t *testing.T) {
	registry := NewProtectedRegistry()

	abiJSON := `[{"name":"transfer","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	addr := common.HexToAddress("0x6666666666666666666666666666666666666666")
	info := &ProtectedContractInfo{
		Address: addr,
		ABI:     &parsedABI,
	}

	err = registry.RegisterContract(info)
	require.NoError(t, err)

	// 使用一个不存在的选择器
	fakeSelector := [4]byte{0x12, 0x34, 0x56, 0x78}
	method, err := registry.GetMethod(addr, fakeSelector)
	assert.Error(t, err)
	assert.Nil(t, method)
	assert.Contains(t, err.Error(), "method not found")
}

// TestRegisterBatch 测试批量注册
func TestRegisterBatch(t *testing.T) {
	registry := NewProtectedRegistry()

	abiJSON1 := `[{"name":"func1","type":"function","inputs":[],"outputs":[]}]`
	abiJSON2 := `[{"name":"func2","type":"function","inputs":[],"outputs":[]}]`

	parsedABI1, _ := abi.JSON(strings.NewReader(abiJSON1))
	parsedABI2, _ := abi.JSON(strings.NewReader(abiJSON2))

	infos := []*ProtectedContractInfo{
		{
			Address: common.HexToAddress("0x7777777777777777777777777777777777777777"),
			ABI:     &parsedABI1,
		},
		{
			Address: common.HexToAddress("0x8888888888888888888888888888888888888888"),
			ABI:     &parsedABI2,
		},
	}

	err := registry.RegisterBatch(infos)
	require.NoError(t, err)
	assert.Equal(t, 2, registry.Count())
}

// TestRegisterBatchWithError 测试批量注册时部分失败
func TestRegisterBatchWithError(t *testing.T) {
	registry := NewProtectedRegistry()

	abiJSON := `[{"name":"func","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))

	infos := []*ProtectedContractInfo{
		{
			Address: common.HexToAddress("0x9999999999999999999999999999999999999999"),
			ABI:     &parsedABI,
		},
		{
			Address: common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			ABI:     nil, // 这个会失败
		},
	}

	err := registry.RegisterBatch(infos)
	assert.Error(t, err) // 应该返回错误
	assert.Equal(t, 1, registry.Count()) // 但第一个应该注册成功
}

// TestGetAll 测试获取所有合约
func TestGetAll(t *testing.T) {
	registry := NewProtectedRegistry()

	abiJSON := `[{"name":"test","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))

	addr1 := common.HexToAddress("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	addr2 := common.HexToAddress("0xcccccccccccccccccccccccccccccccccccccccc")

	registry.RegisterContract(&ProtectedContractInfo{Address: addr1, ABI: &parsedABI})
	registry.RegisterContract(&ProtectedContractInfo{Address: addr2, ABI: &parsedABI})

	all := registry.GetAll()
	assert.Len(t, all, 2)

	// 验证地址存在（顺序可能不同）
	addrs := make(map[common.Address]bool)
	for _, info := range all {
		addrs[info.Address] = true
	}
	assert.True(t, addrs[addr1])
	assert.True(t, addrs[addr2])
}

// TestIsProtected 测试检查保护状态
func TestIsProtected(t *testing.T) {
	registry := NewProtectedRegistry()

	abiJSON := `[{"name":"test","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))

	protected := common.HexToAddress("0xdddddddddddddddddddddddddddddddddddddddd")
	notProtected := common.HexToAddress("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	registry.RegisterContract(&ProtectedContractInfo{Address: protected, ABI: &parsedABI})

	assert.True(t, registry.IsProtected(protected))
	assert.False(t, registry.IsProtected(notProtected))
}

// TestSelectorCache 测试选择器缓存机制
func TestSelectorCache(t *testing.T) {
	registry := NewProtectedRegistry()

	// 创建包含多个方法的ABI
	abiJSON := `[
		{"name":"transfer","type":"function","inputs":[{"name":"to","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"success","type":"bool"}]},
		{"name":"approve","type":"function","inputs":[{"name":"spender","type":"address"},{"name":"amount","type":"uint256"}],"outputs":[{"name":"success","type":"bool"}]},
		{"name":"balanceOf","type":"function","inputs":[{"name":"account","type":"address"}],"outputs":[{"name":"balance","type":"uint256"}]}
	]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	addr := common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff")
	info := &ProtectedContractInfo{
		Address: addr,
		ABI:     &parsedABI,
	}

	err = registry.RegisterContract(info)
	require.NoError(t, err)

	// 验证所有方法都被缓存
	for methodName, method := range parsedABI.Methods {
		selector := [4]byte{}
		copy(selector[:], method.ID[:4])

		retrieved, err := registry.GetMethod(addr, selector)
		require.NoError(t, err, "Failed to get method: %s", methodName)
		assert.Equal(t, methodName, retrieved.Name)
	}
}
