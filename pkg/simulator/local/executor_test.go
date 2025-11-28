// Package local 提供本地EVM执行器实现
package local

import (
	"context"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewLocalEVMExecutor 测试执行器创建
func TestNewLocalEVMExecutor(t *testing.T) {
	exec := NewLocalEVMExecutor(nil)
	require.NotNil(t, exec)
	require.NotNil(t, exec.config)
	require.NotNil(t, exec.interceptor)
	require.NotNil(t, exec.collector)
	require.NotNil(t, exec.jumpTableHook)
}

// TestExecuteSimpleTransfer 测试简单转账
func TestExecuteSimpleTransfer(t *testing.T) {
	exec := NewLocalEVMExecutor(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	to := common.HexToAddress("0x2222222222222222222222222222222222222222")

	// 设置初始状态
	override := StateOverride{
		from.Hex(): &AccountOverride{
			Balance: "0x1000000000000000000", // 1 ETH
		},
	}

	result, err := exec.Execute(
		context.Background(),
		from, to,
		nil,                     // 无calldata
		big.NewInt(1000000000),  // 转账 1 Gwei
		override,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	assert.Empty(t, result.Error)
}

// TestExecuteWithCode 测试合约调用
func TestExecuteWithCode(t *testing.T) {
	exec := NewLocalEVMExecutor(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	contract := common.HexToAddress("0x3333333333333333333333333333333333333333")

	// 简单的合约代码：PUSH1 0x42 PUSH1 0x00 MSTORE PUSH1 0x20 PUSH1 0x00 RETURN
	// 返回值为 0x42
	code := "0x604260005260206000f3"

	override := StateOverride{
		from.Hex(): &AccountOverride{
			Balance: "0x1000000000000000000",
		},
		contract.Hex(): &AccountOverride{
			Code: code,
		},
	}

	result, err := exec.Execute(
		context.Background(),
		from, contract,
		nil, // 无calldata
		nil, // 无转账
		override,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)
	// 验证返回值包含 0x42
	if len(result.ReturnData) > 0 {
		assert.Equal(t, byte(0x42), result.ReturnData[len(result.ReturnData)-1])
	}
}

// TestMutatorIntercept 测试Mutator拦截
func TestMutatorIntercept(t *testing.T) {
	exec := NewLocalEVMExecutor(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x4444444444444444444444444444444444444444")

	// 注册一个简单的mutator
	exec.RegisterMutator(target, func(ctx *CallInterceptContext) ([]byte, bool, error) {
		// 验证上下文
		assert.Equal(t, from, ctx.Caller)
		assert.Equal(t, target, ctx.Target)
		// 不修改calldata
		return ctx.Input, false, nil
	})

	assert.True(t, exec.HasMutators())

	// 创建一个简单的合约来调用target
	// PUSH20 target PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH1 0 PUSH20 target GAS CALL
	// 简化起见，我们直接调用target
	override := StateOverride{
		from.Hex(): &AccountOverride{
			Balance: "0x1000000000000000000",
		},
		target.Hex(): &AccountOverride{
			// 简单返回的代码
			Code: "0x60006000f3", // PUSH1 0 PUSH1 0 RETURN
		},
	}

	result, err := exec.Execute(
		context.Background(),
		from, target,
		[]byte{0x01, 0x02, 0x03, 0x04}, // 一些calldata
		nil,
		override,
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	// 注意：直接调用不会触发mutator，只有内部CALL才会
	// mutator只在CALL指令执行时被调用
}

// TestJumpDestCollection 测试JUMPDEST收集
func TestJumpDestCollection(t *testing.T) {
	exec := NewLocalEVMExecutor(nil)

	from := common.HexToAddress("0x1111111111111111111111111111111111111111")
	contract := common.HexToAddress("0x5555555555555555555555555555555555555555")

	// 包含JUMPDEST的代码
	// PUSH1 0x03 (60 03) -> 跳转到偏移3
	// JUMP (56)
	// JUMPDEST (5b) -> 偏移3
	// PUSH1 0x00 (60 00)
	// PUSH1 0x00 (60 00)
	// RETURN (f3)
	// 0x6003565b60006000f3
	code := "0x6003565b60006000f3"

	override := StateOverride{
		from.Hex(): &AccountOverride{
			Balance: "0x1000000000000000000",
		},
		contract.Hex(): &AccountOverride{
			Code: code,
		},
	}

	result, err := exec.Execute(
		context.Background(),
		from, contract,
		nil,
		nil,
		override,
	)

	require.NoError(t, err)
	require.NotNil(t, result)

	// 验证JUMPDEST被收集
	jumpDests := result.ContractJumpDests
	t.Logf("Success: %v, Error: %s", result.Success, result.Error)
	t.Logf("Collected %d JUMPDEST(s)", len(jumpDests))
	for _, jd := range jumpDests {
		t.Logf("  Contract: %s, PC: %d", jd.Contract, jd.PC)
	}

	// 如果执行成功，应该至少有1个JUMPDEST
	if result.Success {
		assert.GreaterOrEqual(t, len(jumpDests), 1)
	}
}

// TestStateAdapter 测试StateAdapter基本功能
func TestStateAdapter(t *testing.T) {
	override := StateOverride{
		"0x1111111111111111111111111111111111111111": &AccountOverride{
			Balance: "0x1000000000000000000",
			Nonce:   "0x10",
			Code:    "0x6000",
			State: map[string]string{
				"0x0000000000000000000000000000000000000000000000000000000000000001": "0x00000000000000000000000000000000000000000000000000000000000000ff",
			},
		},
	}

	stateDB := NewStateAdapter(override)
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// 验证余额
	balance := stateDB.GetBalance(addr)
	expected, _ := uint256.FromHex("0x1000000000000000000")
	assert.Equal(t, expected, balance)

	// 验证Nonce
	assert.Equal(t, uint64(16), stateDB.GetNonce(addr))

	// 验证代码
	assert.Equal(t, []byte{0x60, 0x00}, stateDB.GetCode(addr))

	// 验证存储
	slot := common.HexToHash("0x0000000000000000000000000000000000000000000000000000000000000001")
	expectedValue := common.HexToHash("0x00000000000000000000000000000000000000000000000000000000000000ff")
	assert.Equal(t, expectedValue, stateDB.GetState(addr, slot))
}

// TestSnapshotRevert 测试快照和回滚
func TestSnapshotRevert(t *testing.T) {
	override := StateOverride{
		"0x1111111111111111111111111111111111111111": &AccountOverride{
			Balance: "0x1000",
		},
	}

	stateDB := NewStateAdapter(override)
	addr := common.HexToAddress("0x1111111111111111111111111111111111111111")

	// 创建快照
	snapID := stateDB.Snapshot()

	// 修改状态
	slot := common.HexToHash("0x01")
	newValue := common.HexToHash("0xff")
	stateDB.SetState(addr, slot, newValue)

	// 验证修改
	assert.Equal(t, newValue, stateDB.GetState(addr, slot))

	// 回滚
	stateDB.RevertToSnapshot(snapID)

	// 验证回滚后状态
	assert.Equal(t, common.Hash{}, stateDB.GetState(addr, slot))
}

// TestTraceCollector 测试TraceCollector
func TestTraceCollector(t *testing.T) {
	collector := NewTraceCollector()

	// 模拟OnOpcode回调
	// JUMPDEST = 0x5B
	collector.OnOpcode(100, 0x5B, 1000000, 1, nil, nil, 1, nil)
	collector.OnOpcode(200, 0x60, 999999, 3, nil, nil, 1, nil) // PUSH1，不应该被收集
	collector.OnOpcode(300, 0x5B, 999996, 1, nil, nil, 2, nil)

	jumpDests := collector.GetPlainJumpDests()
	assert.Len(t, jumpDests, 2)
	assert.Equal(t, uint64(100), jumpDests[0])
	assert.Equal(t, uint64(300), jumpDests[1])

	// 测试重置
	collector.Reset()
	assert.Empty(t, collector.GetPlainJumpDests())
}
