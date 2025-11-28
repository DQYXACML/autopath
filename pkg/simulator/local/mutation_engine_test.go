// Package local 提供本地EVM执行器实现
package local

import (
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockStrategy 模拟变异策略
type mockStrategy struct {
	name     string
	priority int
}

func (m *mockStrategy) Name() string {
	return m.name
}

func (m *mockStrategy) Applicable(paramType abi.Type) bool {
	// 简单实现：uint和address类型适用
	return paramType.T == abi.UintTy || paramType.T == abi.AddressTy
}

func (m *mockStrategy) GenerateVariations(original interface{}, paramType abi.Type, count int) ([]interface{}, error) {
	variations := make([]interface{}, count)
	for i := 0; i < count; i++ {
		switch paramType.T {
		case abi.UintTy:
			// 生成递增的值
			if orig, ok := original.(*big.Int); ok {
				variations[i] = new(big.Int).Add(orig, big.NewInt(int64(i+1)))
			} else {
				variations[i] = big.NewInt(int64(i))
			}
		case abi.AddressTy:
			// 生成不同的地址
			addr := common.Address{}
			addr[19] = byte(i)
			variations[i] = addr
		default:
			variations[i] = original
		}
	}
	return variations, nil
}

func (m *mockStrategy) Priority() int {
	return m.priority
}

// TestNewMutationEngine 测试引擎创建
func TestNewMutationEngine(t *testing.T) {
	engine := NewMutationEngine()
	require.NotNil(t, engine)

	// 检查初始状态
	strategies := engine.GetStrategies()
	assert.Equal(t, 0, len(strategies))
}

// TestRegisterStrategy 测试策略注册
func TestRegisterStrategy(t *testing.T) {
	engine := NewMutationEngine()

	strategy := &mockStrategy{
		name:     "test-strategy",
		priority: 100,
	}

	engine.RegisterStrategy(strategy)

	strategies := engine.GetStrategies()
	assert.Equal(t, 1, len(strategies))
	assert.Equal(t, "test-strategy", strategies[0].Name())
	assert.Equal(t, 100, strategies[0].Priority())
}

// TestRegisterStrategyNil 测试注册nil策略
func TestRegisterStrategyNil(t *testing.T) {
	engine := NewMutationEngine()

	engine.RegisterStrategy(nil)

	strategies := engine.GetStrategies()
	assert.Equal(t, 0, len(strategies))
}

// TestStrategyPriorityOrdering 测试策略按优先级排序
func TestStrategyPriorityOrdering(t *testing.T) {
	engine := NewMutationEngine()

	// 按非排序顺序添加策略
	strategy1 := &mockStrategy{name: "low", priority: 10}
	strategy2 := &mockStrategy{name: "high", priority: 100}
	strategy3 := &mockStrategy{name: "medium", priority: 50}

	engine.RegisterStrategy(strategy1)
	engine.RegisterStrategy(strategy2)
	engine.RegisterStrategy(strategy3)

	strategies := engine.GetStrategies()
	require.Equal(t, 3, len(strategies))

	// 验证按优先级从高到低排序
	assert.Equal(t, "high", strategies[0].Name())
	assert.Equal(t, 100, strategies[0].Priority())

	assert.Equal(t, "medium", strategies[1].Name())
	assert.Equal(t, 50, strategies[1].Priority())

	assert.Equal(t, "low", strategies[2].Name())
	assert.Equal(t, 10, strategies[2].Priority())
}

// TestGetStrategies 测试获取策略列表
func TestGetStrategies(t *testing.T) {
	engine := NewMutationEngine()

	strategy := &mockStrategy{name: "test", priority: 50}
	engine.RegisterStrategy(strategy)

	// 获取策略列表两次
	strategies1 := engine.GetStrategies()
	strategies2 := engine.GetStrategies()

	// 验证返回的是副本（不同的切片）
	assert.NotSame(t, &strategies1, &strategies2)

	// 但内容相同
	assert.Equal(t, len(strategies1), len(strategies2))
	assert.Equal(t, strategies1[0].Name(), strategies2[0].Name())
}

// TestDecodeCalldata 测试calldata解码
func TestDecodeCalldata(t *testing.T) {
	engine := NewMutationEngine()

	// 创建ABI
	abiJSON := `[{
		"name":"transfer",
		"type":"function",
		"inputs":[
			{"name":"to","type":"address"},
			{"name":"amount","type":"uint256"}
		],
		"outputs":[]
	}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	method := parsedABI.Methods["transfer"]

	// 准备测试参数
	toAddr := common.HexToAddress("0x1234567890123456789012345678901234567890")
	amount := big.NewInt(1000)

	// 编码calldata
	packedParams, err := method.Inputs.Pack(toAddr, amount)
	require.NoError(t, err)

	// 完整calldata = selector + packed params
	calldata := append(method.ID, packedParams...)

	// 解码
	decoded, err := engine.DecodeCalldata(&method, calldata)
	require.NoError(t, err)
	require.Len(t, decoded, 2)

	// 验证解码结果
	assert.Equal(t, toAddr, decoded[0].(common.Address))
	assert.Equal(t, amount, decoded[1].(*big.Int))
}

// TestDecodeCalldataNilMethod 测试nil方法错误处理
func TestDecodeCalldataNilMethod(t *testing.T) {
	engine := NewMutationEngine()

	calldata := []byte{0x00, 0x00, 0x00, 0x00}

	_, err := engine.DecodeCalldata(nil, calldata)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "method cannot be nil")
}

// TestDecodeCalldataShort 测试短calldata错误处理
func TestDecodeCalldataShort(t *testing.T) {
	engine := NewMutationEngine()

	abiJSON := `[{"name":"test","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	method := parsedABI.Methods["test"]

	// 只有2字节的calldata（应该至少4字节selector）
	shortCalldata := []byte{0x00, 0x00}

	_, err := engine.DecodeCalldata(&method, shortCalldata)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "calldata too short")
}

// TestEncodeParams 测试参数编码
func TestEncodeParams(t *testing.T) {
	engine := NewMutationEngine()

	abiJSON := `[{
		"name":"transfer",
		"type":"function",
		"inputs":[
			{"name":"to","type":"address"},
			{"name":"amount","type":"uint256"}
		],
		"outputs":[]
	}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	method := parsedABI.Methods["transfer"]

	// 准备参数
	toAddr := common.HexToAddress("0xabcdef")
	amount := big.NewInt(500)
	params := []interface{}{toAddr, amount}

	// 编码
	encoded, err := engine.EncodeParams(&method, params)
	require.NoError(t, err)
	assert.NotEmpty(t, encoded)

	// 验证：解码后应该得到原始参数
	decoded, err := method.Inputs.Unpack(encoded)
	require.NoError(t, err)
	assert.Equal(t, toAddr, decoded[0].(common.Address))
	assert.Equal(t, amount, decoded[1].(*big.Int))
}

// TestEncodeParamsNilMethod 测试nil方法错误处理
func TestEncodeParamsNilMethod(t *testing.T) {
	engine := NewMutationEngine()

	params := []interface{}{big.NewInt(100)}

	_, err := engine.EncodeParams(nil, params)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "method cannot be nil")
}

// TestMutateCalldata 测试calldata变异
func TestMutateCalldata(t *testing.T) {
	engine := NewMutationEngine()

	abiJSON := `[{
		"name":"test",
		"type":"function",
		"inputs":[{"name":"value","type":"uint256"}],
		"outputs":[]
	}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)

	method := parsedABI.Methods["test"]

	// 原始calldata
	originalParam := big.NewInt(100)
	packedOriginal, _ := method.Inputs.Pack(originalParam)
	originalCalldata := append(method.ID, packedOriginal...)

	// 池化参数（变异后的）
	pooledParams := []interface{}{big.NewInt(200)}

	// 变异
	mutated, err := engine.MutateCalldata(&method, originalCalldata, pooledParams)
	require.NoError(t, err)

	// 验证：selector应该保持不变
	assert.Equal(t, method.ID, mutated[:4])

	// 解码变异后的参数
	decoded, err := method.Inputs.Unpack(mutated[4:])
	require.NoError(t, err)
	assert.Equal(t, big.NewInt(200), decoded[0].(*big.Int))
}

// TestMutateCalldataNilMethod 测试变异时nil方法错误处理
func TestMutateCalldataNilMethod(t *testing.T) {
	engine := NewMutationEngine()

	calldata := []byte{0x00, 0x00, 0x00, 0x00}
	pooledParams := []interface{}{big.NewInt(100)}

	_, err := engine.MutateCalldata(nil, calldata, pooledParams)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "method cannot be nil")
}

// TestMutateCalldataShort 测试变异时短calldata错误处理
func TestMutateCalldataShort(t *testing.T) {
	engine := NewMutationEngine()

	abiJSON := `[{"name":"test","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	method := parsedABI.Methods["test"]

	shortCalldata := []byte{0x00, 0x00}
	pooledParams := []interface{}{}

	_, err := engine.MutateCalldata(&method, shortCalldata, pooledParams)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "calldata too short")
}

// TestUpdateHistory 测试历史记录更新
func TestUpdateHistory(t *testing.T) {
	engine := NewMutationEngine()

	methodSig := "transfer(address,uint256)"

	// 第一次更新
	engine.UpdateHistory(methodSig, 0.8, true)

	history := engine.GetHistory(methodSig)
	require.NotNil(t, history)
	assert.Equal(t, 1, history.TotalAttempts)
	assert.Equal(t, 1, history.SuccessCount)
	assert.Equal(t, 0.8, history.AvgSimilarity)
	assert.Equal(t, 0.8, history.BestSimilarity)

	// 第二次更新
	engine.UpdateHistory(methodSig, 0.6, false)

	history = engine.GetHistory(methodSig)
	assert.Equal(t, 2, history.TotalAttempts)
	assert.Equal(t, 1, history.SuccessCount)
	// 平均相似度 = (0.8 + 0.6) / 2 = 0.7
	assert.Equal(t, 0.7, history.AvgSimilarity)
	// 最佳相似度应该保持0.8
	assert.Equal(t, 0.8, history.BestSimilarity)

	// 第三次更新（更高的相似度）
	engine.UpdateHistory(methodSig, 0.9, true)

	history = engine.GetHistory(methodSig)
	assert.Equal(t, 3, history.TotalAttempts)
	assert.Equal(t, 2, history.SuccessCount)
	// 平均相似度 = (0.8 + 0.6 + 0.9) / 3 ≈ 0.7667
	assert.InDelta(t, 0.7667, history.AvgSimilarity, 0.001)
	// 最佳相似度应该更新为0.9
	assert.Equal(t, 0.9, history.BestSimilarity)
}

// TestGetHistory 测试获取历史记录
func TestGetHistory(t *testing.T) {
	engine := NewMutationEngine()

	methodSig := "test()"

	// 添加一些历史记录
	engine.UpdateHistory(methodSig, 0.5, true)
	engine.UpdateHistory(methodSig, 0.7, true)

	// 获取历史两次
	history1 := engine.GetHistory(methodSig)
	history2 := engine.GetHistory(methodSig)

	// 验证返回的是副本（不同的指针）
	assert.NotSame(t, history1, history2)

	// 但内容相同
	assert.Equal(t, history1.TotalAttempts, history2.TotalAttempts)
	assert.Equal(t, history1.SuccessCount, history2.SuccessCount)
	assert.Equal(t, history1.AvgSimilarity, history2.AvgSimilarity)
	assert.Equal(t, history1.BestSimilarity, history2.BestSimilarity)
}

// TestGetHistoryNotFound 测试获取不存在的历史记录
func TestGetHistoryNotFound(t *testing.T) {
	engine := NewMutationEngine()

	history := engine.GetHistory("nonexistent()")
	assert.Nil(t, history)
}

// TestMultipleMethodsHistory 测试多个方法的历史记录
func TestMultipleMethodsHistory(t *testing.T) {
	engine := NewMutationEngine()

	method1 := "transfer(address,uint256)"
	method2 := "approve(address,uint256)"

	// 为不同方法添加历史
	engine.UpdateHistory(method1, 0.8, true)
	engine.UpdateHistory(method2, 0.6, false)
	engine.UpdateHistory(method1, 0.9, true)

	// 验证method1的历史
	history1 := engine.GetHistory(method1)
	require.NotNil(t, history1)
	assert.Equal(t, 2, history1.TotalAttempts)
	assert.Equal(t, 2, history1.SuccessCount)
	assert.Equal(t, 0.85, history1.AvgSimilarity) // (0.8 + 0.9) / 2
	assert.Equal(t, 0.9, history1.BestSimilarity)

	// 验证method2的历史
	history2 := engine.GetHistory(method2)
	require.NotNil(t, history2)
	assert.Equal(t, 1, history2.TotalAttempts)
	assert.Equal(t, 0, history2.SuccessCount)
	assert.Equal(t, 0.6, history2.AvgSimilarity)
	assert.Equal(t, 0.6, history2.BestSimilarity)
}

// TestConcurrentAccess 测试并发访问安全性
func TestConcurrentAccess(t *testing.T) {
	engine := NewMutationEngine()

	// 准备ABI
	abiJSON := `[{
		"name":"test",
		"type":"function",
		"inputs":[{"name":"value","type":"uint256"}],
		"outputs":[]
	}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)
	method := parsedABI.Methods["test"]

	// 并发访问
	var wg sync.WaitGroup
	numGoroutines := 10
	operationsPerGoroutine := 20

	for i := 0; i < numGoroutines; i++ {\n\t\twg.Add(1)
		go func(id int) {
			defer wg.Done()

			// 注册策略
			strategy := &mockStrategy{
				name:     "strategy-" + string(rune(id)),
				priority: id * 10,
			}
			engine.RegisterStrategy(strategy)

			// 更新历史
			for j := 0; j < operationsPerGoroutine; j++ {
				methodSig := "test()"
				similarity := float64(j) / float64(operationsPerGoroutine)
				engine.UpdateHistory(methodSig, similarity, true)
			}

			// 读取操作
			_ = engine.GetStrategies()
			_ = engine.GetHistory("test()")

			// 编码/解码操作
			params := []interface{}{big.NewInt(int64(id))}
			_, _ = engine.EncodeParams(&method, params)
		}(i)
	}

	wg.Wait()

	// 验证最终状态一致性
	strategies := engine.GetStrategies()
	assert.Equal(t, numGoroutines, len(strategies))

	history := engine.GetHistory("test()")
	require.NotNil(t, history)
	assert.Equal(t, numGoroutines*operationsPerGoroutine, history.TotalAttempts)
}

// TestEncodeDecodeRoundtrip 测试编码解码往返
func TestEncodeDecodeRoundtrip(t *testing.T) {
	engine := NewMutationEngine()

	abiJSON := `[{
		"name":"complex",
		"type":"function",
		"inputs":[
			{"name":"addr","type":"address"},
			{"name":"amount","type":"uint256"},
			{"name":"flag","type":"bool"},
			{"name":"data","type":"bytes"}
		],
		"outputs":[]
	}]`
	parsedABI, err := abi.JSON(strings.NewReader(abiJSON))
	require.NoError(t, err)
	method := parsedABI.Methods["complex"]

	// 原始参数
	originalParams := []interface{}{
		common.HexToAddress("0x1234"),
		big.NewInt(999),
		true,
		[]byte("test data"),
	}

	// 编码
	encoded, err := engine.EncodeParams(&method, originalParams)
	require.NoError(t, err)

	// 构造完整calldata
	calldata := append(method.ID, encoded...)

	// 解码
	decoded, err := engine.DecodeCalldata(&method, calldata)
	require.NoError(t, err)
	require.Len(t, decoded, 4)

	// 验证往返一致性
	assert.Equal(t, originalParams[0].(common.Address), decoded[0].(common.Address))
	assert.Equal(t, originalParams[1].(*big.Int), decoded[1].(*big.Int))
	assert.Equal(t, originalParams[2].(bool), decoded[2].(bool))
	assert.Equal(t, originalParams[3].([]byte), decoded[3].([]byte))
}

// TestEmptyParams 测试空参数处理
func TestEmptyParams(t *testing.T) {
	engine := NewMutationEngine()

	abiJSON := `[{"name":"empty","type":"function","inputs":[],"outputs":[]}]`
	parsedABI, _ := abi.JSON(strings.NewReader(abiJSON))
	method := parsedABI.Methods["empty"]

	// 编码空参数
	encoded, err := engine.EncodeParams(&method, []interface{}{})
	require.NoError(t, err)
	assert.Empty(t, encoded)

	// 解码只有selector的calldata
	calldata := method.ID
	decoded, err := engine.DecodeCalldata(&method, calldata)
	require.NoError(t, err)
	assert.Empty(t, decoded)

	// 变异空参数
	mutated, err := engine.MutateCalldata(&method, calldata, []interface{}{})
	require.NoError(t, err)
	assert.Equal(t, calldata, mutated)
}
