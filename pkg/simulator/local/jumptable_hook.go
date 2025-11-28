// Package local 提供本地EVM执行器实现
package local

import (
	"reflect"
	"sync/atomic"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// HookedJumpTable 包装JumpTable并提供CALL拦截功能
type HookedJumpTable struct {
	interceptor *CallInterceptor
	// depth 跟踪当前调用深度（原子操作）
	depth int32
}

// NewHookedJumpTable 创建HookedJumpTable
func NewHookedJumpTable(interceptor *CallInterceptor) *HookedJumpTable {
	return &HookedJumpTable{
		interceptor: interceptor,
	}
}

// IncrementDepth 增加调用深度
func (h *HookedJumpTable) IncrementDepth() int {
	return int(atomic.AddInt32(&h.depth, 1))
}

// DecrementDepth 减少调用深度
func (h *HookedJumpTable) DecrementDepth() int {
	return int(atomic.AddInt32(&h.depth, -1))
}

// GetDepth 获取当前调用深度
func (h *HookedJumpTable) GetDepth() int {
	return int(atomic.LoadInt32(&h.depth))
}

// ResetDepth 重置调用深度
func (h *HookedJumpTable) ResetDepth() {
	atomic.StoreInt32(&h.depth, 0)
}

// HookEVM 为EVM注入hooked JumpTable
// 这个函数使用reflect+unsafe访问EVM的私有字段
func (h *HookedJumpTable) HookEVM(evm *vm.EVM) error {
	// 获取EVM的table字段
	evmVal := reflect.ValueOf(evm).Elem()
	tableField := evmVal.FieldByName("table")

	if !tableField.IsValid() {
		return ErrTableFieldNotFound
	}

	// 获取原始JumpTable指针
	tablePtr := unsafe.Pointer(tableField.UnsafeAddr())
	originalTable := *(**vm.JumpTable)(tablePtr)

	// 复制并修改JumpTable
	hookedTable := h.copyAndHookJumpTable(originalTable)

	// 注入修改后的table
	*(**vm.JumpTable)(tablePtr) = hookedTable

	return nil
}

// copyAndHookJumpTable 复制JumpTable并hook CALL类操作码
func (h *HookedJumpTable) copyAndHookJumpTable(src *vm.JumpTable) *vm.JumpTable {
	// 复制整个JumpTable - 使用值拷贝
	dest := *src

	// 对每个非nil的operation进行深拷贝
	for i := 0; i < 256; i++ {
		if src[i] != nil {
			// 创建operation的副本
			opCopy := *src[i]
			dest[i] = &opCopy
		}
	}

	// Hook CALL类操作码
	h.hookCallOperation(&dest, OpCALL)
	h.hookCallOperation(&dest, OpCALLCODE)
	h.hookCallOperation(&dest, OpDELEGATECALL)
	h.hookCallOperation(&dest, OpSTATICCALL)

	return &dest
}

// hookCallOperation hook单个CALL类操作码
func (h *HookedJumpTable) hookCallOperation(table *vm.JumpTable, opcode byte) {
	if table[opcode] == nil {
		return
	}

	// 获取原始operation
	op := table[opcode]

	// 获取原始execute函数
	originalExecute := h.getExecuteFunc(op)
	if originalExecute == nil {
		return
	}

	// 创建hooked execute函数
	var hookedExecute ExecutionFunc

	switch opcode {
	case OpCALL:
		hookedExecute = h.createHookedCall(originalExecute)
	case OpCALLCODE:
		hookedExecute = h.createHookedCallCode(originalExecute)
	case OpDELEGATECALL:
		hookedExecute = h.createHookedDelegateCall(originalExecute)
	case OpSTATICCALL:
		hookedExecute = h.createHookedStaticCall(originalExecute)
	default:
		return
	}

	// 设置新的execute函数
	h.setExecuteFunc(op, hookedExecute)
}

// ExecutionFunc 是操作码执行函数的类型签名
type ExecutionFunc func(pc *uint64, evm *vm.EVM, scope *vm.ScopeContext) ([]byte, error)

// getExecuteFunc 获取operation的execute函数
func (h *HookedJumpTable) getExecuteFunc(op interface{}) ExecutionFunc {
	opVal := reflect.ValueOf(op).Elem()
	execField := opVal.FieldByName("execute")
	if !execField.IsValid() {
		return nil
	}

	// 使用unsafe获取私有字段
	execPtr := unsafe.Pointer(execField.UnsafeAddr())
	execFn := *(*ExecutionFunc)(execPtr)
	return execFn
}

// setExecuteFunc 设置operation的execute函数
func (h *HookedJumpTable) setExecuteFunc(op interface{}, exec ExecutionFunc) {
	opVal := reflect.ValueOf(op).Elem()
	execField := opVal.FieldByName("execute")
	if !execField.IsValid() {
		return
	}

	// 使用unsafe设置私有字段
	execPtr := unsafe.Pointer(execField.UnsafeAddr())
	*(*ExecutionFunc)(execPtr) = exec
}

// createHookedCall 创建hooked的CALL执行函数
func (h *HookedJumpTable) createHookedCall(original ExecutionFunc) ExecutionFunc {
	return func(pc *uint64, evm *vm.EVM, scope *vm.ScopeContext) ([]byte, error) {
		// CALL参数布局: gas, addr, value, argsOffset, argsSize, retOffset, retSize
		stack := scope.Stack
		memory := scope.Memory

		// 提取参数（不弹出栈）
		addr := common.Address(stack.Back(1).Bytes20())
		value := stack.Back(2)
		argsOffset := stack.Back(3).Uint64()
		argsSize := stack.Back(4).Uint64()

		// 获取原始calldata
		var input []byte
		if argsSize > 0 {
			input = memory.GetCopy(argsOffset, argsSize)
		}

		// 调用拦截器处理
		caller := scope.Contract.Address()
		depth := h.GetDepth()
		gas := scope.Contract.Gas
		newInput, modified, err := h.interceptor.ProcessCall(
			OpCALL, caller, addr, value, input, gas, depth,
		)
		if err != nil {
			// 拦截器返回错误，使用原始input继续执行
			return original(pc, evm, scope)
		}

		if modified && len(newInput) > 0 {
			// 将修改后的calldata写入memory
			newSize := uint64(len(newInput))
			if newSize > argsSize {
				// 需要扩展memory
				memory.Resize(argsOffset + newSize)
			}
			memory.Set(argsOffset, newSize, newInput)

			// 更新栈上的argsSize
			if newSize != argsSize {
				stack.Back(4).SetUint64(newSize)
			}
		}

		// 增加调用深度
		h.IncrementDepth()
		defer h.DecrementDepth()

		// 调用原始execute
		return original(pc, evm, scope)
	}
}

// createHookedCallCode 创建hooked的CALLCODE执行函数
func (h *HookedJumpTable) createHookedCallCode(original ExecutionFunc) ExecutionFunc {
	return func(pc *uint64, evm *vm.EVM, scope *vm.ScopeContext) ([]byte, error) {
		// CALLCODE参数布局与CALL相同
		stack := scope.Stack
		memory := scope.Memory

		addr := common.Address(stack.Back(1).Bytes20())
		value := stack.Back(2)
		argsOffset := stack.Back(3).Uint64()
		argsSize := stack.Back(4).Uint64()

		var input []byte
		if argsSize > 0 {
			input = memory.GetCopy(argsOffset, argsSize)
		}

		caller := scope.Contract.Address()
		depth := h.GetDepth()
		gas := scope.Contract.Gas
		newInput, modified, err := h.interceptor.ProcessCall(
			OpCALLCODE, caller, addr, value, input, gas, depth,
		)
		if err != nil {
			return original(pc, evm, scope)
		}

		if modified && len(newInput) > 0 {
			newSize := uint64(len(newInput))
			if newSize > argsSize {
				memory.Resize(argsOffset + newSize)
			}
			memory.Set(argsOffset, newSize, newInput)
			if newSize != argsSize {
				stack.Back(4).SetUint64(newSize)
			}
		}

		h.IncrementDepth()
		defer h.DecrementDepth()

		return original(pc, evm, scope)
	}
}

// createHookedDelegateCall 创建hooked的DELEGATECALL执行函数
func (h *HookedJumpTable) createHookedDelegateCall(original ExecutionFunc) ExecutionFunc {
	return func(pc *uint64, evm *vm.EVM, scope *vm.ScopeContext) ([]byte, error) {
		// DELEGATECALL参数布局: gas, addr, argsOffset, argsSize, retOffset, retSize（无value）
		stack := scope.Stack
		memory := scope.Memory

		addr := common.Address(stack.Back(1).Bytes20())
		argsOffset := stack.Back(2).Uint64()
		argsSize := stack.Back(3).Uint64()

		var input []byte
		if argsSize > 0 {
			input = memory.GetCopy(argsOffset, argsSize)
		}

		// DELEGATECALL没有value参数，使用父调用的value
		caller := scope.Contract.Address()
		value := scope.Contract.Value()
		depth := h.GetDepth()
		gas := scope.Contract.Gas
		newInput, modified, err := h.interceptor.ProcessCall(
			OpDELEGATECALL, caller, addr, value, input, gas, depth,
		)
		if err != nil {
			return original(pc, evm, scope)
		}

		if modified && len(newInput) > 0 {
			newSize := uint64(len(newInput))
			if newSize > argsSize {
				memory.Resize(argsOffset + newSize)
			}
			memory.Set(argsOffset, newSize, newInput)
			if newSize != argsSize {
				stack.Back(3).SetUint64(newSize)
			}
		}

		h.IncrementDepth()
		defer h.DecrementDepth()

		return original(pc, evm, scope)
	}
}

// createHookedStaticCall 创建hooked的STATICCALL执行函数
func (h *HookedJumpTable) createHookedStaticCall(original ExecutionFunc) ExecutionFunc {
	return func(pc *uint64, evm *vm.EVM, scope *vm.ScopeContext) ([]byte, error) {
		// STATICCALL参数布局: gas, addr, argsOffset, argsSize, retOffset, retSize（无value）
		stack := scope.Stack
		memory := scope.Memory

		addr := common.Address(stack.Back(1).Bytes20())
		argsOffset := stack.Back(2).Uint64()
		argsSize := stack.Back(3).Uint64()

		var input []byte
		if argsSize > 0 {
			input = memory.GetCopy(argsOffset, argsSize)
		}

		// STATICCALL没有value，使用零值
		caller := scope.Contract.Address()
		depth := h.GetDepth()
		gas := scope.Contract.Gas
		newInput, modified, err := h.interceptor.ProcessCall(
			OpSTATICCALL, caller, addr, uint256.NewInt(0), input, gas, depth,
		)
		if err != nil {
			return original(pc, evm, scope)
		}

		if modified && len(newInput) > 0 {
			newSize := uint64(len(newInput))
			if newSize > argsSize {
				memory.Resize(argsOffset + newSize)
			}
			memory.Set(argsOffset, newSize, newInput)
			if newSize != argsSize {
				stack.Back(3).SetUint64(newSize)
			}
		}

		h.IncrementDepth()
		defer h.DecrementDepth()

		return original(pc, evm, scope)
	}
}
