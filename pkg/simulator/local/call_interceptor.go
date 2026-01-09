// Package local 提供本地EVM执行器实现
package local

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// CallInterceptor 拦截CALL类操作并支持calldata修改
type CallInterceptor struct {
	mu sync.RWMutex

	// === 新架构组件 ===
	// registry 受保护合约注册表
	registry ProtectedRegistry

	// poolManager 参数池管理器
	poolManager ParamPoolManager

	// mutationEngine 参数变异引擎
	mutationEngine MutationEngine

	// === 向后兼容组件 ===
	// mutators 存储地址到回调的映射（保留用于向后兼容）
	mutators map[common.Address]CallMutatorV2

	// stateDB 当前状态数据库
	stateDB vm.StateDB

	// collector JUMPDEST收集器
	collector *TraceCollector

	// pendingOverrides 待应用的calldata覆盖（按调用深度索引）
	pendingOverrides map[int][]byte

	// enabled 是否启用拦截
	enabled bool

	// mutationEnabled 是否允许对受保护合约进行变异（基线重放时关闭）
	mutationEnabled bool

	// firstProtectedHit 记录首个命中的受保护调用
	firstProtectedHit *ProtectedCallHit

	// callStack 记录调用上下文，用于revert诊断
	callStack map[int]*callSnapshot
}

// NewCallInterceptor 创建新的CallInterceptor（向后兼容版本）
func NewCallInterceptor(collector *TraceCollector) *CallInterceptor {
	return &CallInterceptor{
		mutators:         make(map[common.Address]CallMutatorV2),
		pendingOverrides: make(map[int][]byte),
		collector:        collector,
		enabled:          true,
		mutationEnabled:  true,
		callStack:        make(map[int]*callSnapshot),
	}
}

// NewCallInterceptorWithComponents 创建集成新架构组件的CallInterceptor
func NewCallInterceptorWithComponents(
	collector *TraceCollector,
	registry ProtectedRegistry,
	poolManager ParamPoolManager,
	mutationEngine MutationEngine,
) *CallInterceptor {
	return &CallInterceptor{
		registry:         registry,
		poolManager:      poolManager,
		mutationEngine:   mutationEngine,
		mutators:         make(map[common.Address]CallMutatorV2),
		pendingOverrides: make(map[int][]byte),
		collector:        collector,
		enabled:          true,
		mutationEnabled:  true,
		callStack:        make(map[int]*callSnapshot),
	}
}

// SetStateDB 设置状态数据库
func (i *CallInterceptor) SetStateDB(stateDB vm.StateDB) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.stateDB = stateDB
}

// SetEnabled 设置是否启用拦截
func (i *CallInterceptor) SetEnabled(enabled bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.enabled = enabled
}

// SetMutationEnabled 控制是否对受保护合约进行变异（关闭时仅记录不修改）
func (i *CallInterceptor) SetMutationEnabled(enabled bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mutationEnabled = enabled
}

// MutationEnabled 返回当前变异开关状态
func (i *CallInterceptor) MutationEnabled() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.mutationEnabled
}

// ResetProtectedTracking 清空首个受保护调用记录
func (i *CallInterceptor) ResetProtectedTracking() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.firstProtectedHit = nil
}

// ProtectedCallHit 首个受保护调用信息
type ProtectedCallHit struct {
	Caller   common.Address
	Target   common.Address
	Selector string
	Depth    int
}

// GetFirstProtectedHit 返回首个受保护调用记录（若无则nil）
func (i *CallInterceptor) GetFirstProtectedHit() *ProtectedCallHit {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.firstProtectedHit == nil {
		return nil
	}
	cp := *i.firstProtectedHit
	return &cp
}

// RegisterMutator 为指定地址注册CallMutator
func (i *CallInterceptor) RegisterMutator(addr common.Address, mutator CallMutatorV2) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mutators[addr] = mutator
}

// UnregisterMutator 移除指定地址的CallMutator
func (i *CallInterceptor) UnregisterMutator(addr common.Address) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.mutators, addr)
}

// ClearMutators 清除所有注册的mutators
func (i *CallInterceptor) ClearMutators() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.mutators = make(map[common.Address]CallMutatorV2)
}

// HasMutators 检查是否有注册的mutators
func (i *CallInterceptor) HasMutators() bool {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.mutators) > 0 || i.registry != nil
}

// GetMutator 获取指定地址的mutator
func (i *CallInterceptor) GetMutator(addr common.Address) (CallMutatorV2, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	mutator, ok := i.mutators[addr]
	return mutator, ok
}

// EVMTracer 返回用于EVM的tracing.Hooks配置
func (i *CallInterceptor) EVMTracer() *tracing.Hooks {
	return &tracing.Hooks{
		OnEnter:  i.onEnter,
		OnExit:   i.onExit,
		OnOpcode: i.onOpcode,
	}
}

// onEnter 在CALL进入时触发（只读，用于日志记录）
func (i *CallInterceptor) onEnter(depth int, typ byte, from, to common.Address,
	input []byte, gas uint64, value *big.Int) {

	if !i.enabled {
		return
	}

	// 注意：OnEnter是只读的，无法在此修改input
	// 实际的calldata修改在JumpTable Hook中实现
	selector := "0x"
	if len(input) >= 4 {
		selector = "0x" + hex.EncodeToString(input[:4])
	} else if len(input) > 0 {
		selector = "0x" + hex.EncodeToString(input)
	}

	var valueCopy *big.Int
	if value != nil {
		valueCopy = new(big.Int).Set(value)
	}
	i.mu.Lock()
	i.callStack[depth] = &callSnapshot{
		opType:   typ,
		from:     from,
		to:       to,
		selector: selector,
		inputLen: len(input),
		value:    valueCopy,
	}
	i.mu.Unlock()
}

// onExit 在CALL退出时触发
func (i *CallInterceptor) onExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	// 清理该深度的pending override
	i.mu.Lock()
	delete(i.pendingOverrides, depth)
	snapshot := i.callStack[depth]
	delete(i.callStack, depth)
	i.mu.Unlock()

	if !i.enabled {
		return
	}

	if reverted || err != nil {
		revertMsg := decodeRevertMessage(output)
		errMsg := ""
		if err != nil {
			errMsg = err.Error()
		}
		retHex := ""
		if len(output) > 0 {
			retHex = "0x" + hex.EncodeToString(output)
			if len(retHex) > 74 {
				retHex = retHex[:74] + "..."
			}
		}

		opLabel := "UNKNOWN"
		fromStr := ""
		toStr := ""
		selector := ""
		inputLen := 0
		valueStr := ""
		if snapshot != nil {
			opLabel = OpTypeString(snapshot.opType)
			fromStr = snapshot.from.Hex()
			toStr = snapshot.to.Hex()
			selector = snapshot.selector
			inputLen = snapshot.inputLen
			if snapshot.value != nil {
				valueStr = snapshot.value.String()
			}
		}

		log.Printf("[LocalEVM] 调用revert: depth=%d op=%s from=%s to=%s selector=%s inputLen=%d value=%s gasUsed=%d reason=%s return=%s err=%s",
			depth, opLabel, fromStr, toStr, selector, inputLen, valueStr, gasUsed, revertMsg, retHex, errMsg)
	}
}

// onOpcode 在每个操作码执行时触发
func (i *CallInterceptor) onOpcode(pc uint64, op byte, gas, cost uint64,
	scope tracing.OpContext, rData []byte, depth int, err error) {

	// 委托给TraceCollector处理JUMPDEST收集
	if i.collector != nil {
		i.collector.OnOpcode(pc, op, gas, cost, scope, rData, depth, err)
	}
}

// ProcessCall 处理CALL指令，返回修改后的calldata
// 这个方法在hooked JumpTable的execute函数中调用
func (i *CallInterceptor) ProcessCall(
	opType byte,
	caller common.Address,
	target common.Address,
	value *uint256.Int,
	input []byte,
	gas uint64,
	depth int,
) (newInput []byte, modified bool, err error) {

	if !i.enabled {
		return input, false, nil
	}

	// === 新架构路径：检查是否为受保护合约 ===
	if i.registry != nil && i.registry.IsProtected(target) {
		// 记录首个命中的受保护调用
		i.recordFirstProtectedHit(caller, target, input, depth)

		// 基线模式下只记录不变异
		if !i.mutationEnabled {
			return input, false, nil
		}

		// 若显式注册了mutator，则优先使用（便于按selector注入预先准备好的变异值）
		if mutator, ok := i.GetMutator(target); ok {
			ctx := &CallInterceptContext{
				OpType:  OpTypeString(opType),
				Caller:  caller,
				Target:  target,
				Value:   value,
				Input:   input,
				Gas:     gas,
				Depth:   depth,
				StateDB: i.stateDB,
			}
			if newInput, modified, err := mutator(ctx); err != nil {
				return input, false, err
			} else if modified {
				return newInput, true, nil
			}
		}

		return i.processProtectedCall(opType, caller, target, value, input, gas, depth)
	}

	// === 向后兼容路径：使用传统mutators ===
	mutator, ok := i.GetMutator(target)
	if !ok {
		return input, false, nil
	}

	// 构建拦截上下文
	ctx := &CallInterceptContext{
		OpType:  OpTypeString(opType),
		Caller:  caller,
		Target:  target,
		Value:   value,
		Input:   input,
		Gas:     gas,
		Depth:   depth,
		StateDB: i.stateDB,
	}

	// 调用传统mutator
	newInput, modified, err = mutator(ctx)
	if err != nil {
		return input, false, err
	}

	return newInput, modified, nil
}

// processProtectedCall 处理受保护合约的调用（新架构）
func (i *CallInterceptor) processProtectedCall(
	opType byte,
	caller common.Address,
	target common.Address,
	value *uint256.Int,
	input []byte,
	gas uint64,
	depth int,
) (newInput []byte, modified bool, err error) {

	// 检查calldata长度
	if len(input) < 4 {
		// calldata太短，无法提取selector，不变异
		return input, false, nil
	}

	// 提取函数selector（前4字节）
	var selector [4]byte
	copy(selector[:], input[:4])

	// 获取ABI方法定义
	method, err := i.registry.GetMethod(target, selector)
	if err != nil {
		// 找不到方法定义，跳过变异
		return input, false, nil
	}

	// 从参数池获取预生成的参数
	pooledParams, err := i.poolManager.GetPooledParams(target, selector)
	if err != nil {
		// 池中没有参数，跳过变异
		return input, false, nil
	}

	// 使用MutationEngine变异calldata
	if decoded, err := i.mutationEngine.DecodeCalldata(method, input); err == nil {
		for idx := range pooledParams {
			if idx >= len(decoded) {
				break
			}
			if method.Inputs[idx].Type.T == abi.AddressTy {
				pooledParams[idx] = decoded[idx]
			}
		}
	}

	mutatedCalldata, err := i.mutationEngine.MutateCalldata(method, input, pooledParams)
	if err != nil {
		// 变异失败，返回原始calldata
		return input, false, err
	}

	return mutatedCalldata, true, nil
}

// SetPendingOverride 设置待应用的calldata覆盖
func (i *CallInterceptor) SetPendingOverride(depth int, input []byte) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pendingOverrides[depth] = input
}

// GetPendingOverride 获取待应用的calldata覆盖
func (i *CallInterceptor) GetPendingOverride(depth int) ([]byte, bool) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	input, ok := i.pendingOverrides[depth]
	return input, ok
}

// ClearPendingOverride 清除指定深度的覆盖
func (i *CallInterceptor) ClearPendingOverride(depth int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	delete(i.pendingOverrides, depth)
}

// Reset 重置拦截器状态
func (i *CallInterceptor) Reset() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.pendingOverrides = make(map[int][]byte)
	i.firstProtectedHit = nil
	i.callStack = make(map[int]*callSnapshot)
}

// callSnapshot 记录调用关键信息，便于revert诊断
type callSnapshot struct {
	opType   byte
	from     common.Address
	to       common.Address
	selector string
	inputLen int
	value    *big.Int
}

// decodeRevertMessage 从返回数据中解码revert原因
func decodeRevertMessage(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	if msg, err := abi.UnpackRevert(data); err == nil {
		return msg
	}
	return "0x" + hex.EncodeToString(data)
}

// recordFirstProtectedHit 记录首个受保护调用命中
func (i *CallInterceptor) recordFirstProtectedHit(caller, target common.Address, input []byte, depth int) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if i.firstProtectedHit != nil {
		return
	}

	selector := "0x"
	if len(input) >= 4 {
		selector = "0x" + hex.EncodeToString(input[:4])
	}

	i.firstProtectedHit = &ProtectedCallHit{
		Caller:   caller,
		Target:   target,
		Selector: selector,
		Depth:    depth,
	}
}

// === 新架构方法 ===

// InitializePoolsForContract 为指定合约的所有函数预热参数池
// 这个方法应在fuzzing开始前调用，以避免运行时生成参数的开销
func (i *CallInterceptor) InitializePoolsForContract(
	contract common.Address,
	poolSize int,
) error {
	if i.registry == nil || i.poolManager == nil {
		return fmt.Errorf("registry or poolManager not initialized")
	}

	// 获取合约信息
	info, err := i.registry.GetContractInfo(contract)
	if err != nil {
		return fmt.Errorf("failed to get contract info: %w", err)
	}

	// 为合约的每个方法生成参数池
	for _, method := range info.ABI.Methods {
		// 跳过无参数的方法
		if len(method.Inputs) == 0 {
			continue
		}

		// 生成参数池
		err := i.poolManager.GeneratePool(
			contract,
			&method,
			info.SeedConfig,
			poolSize,
		)
		if err != nil {
			// 记录错误但继续处理其他方法
			continue
		}
	}

	return nil
}

// InitializePoolForFunction 为指定合约的特定函数预热参数池
func (i *CallInterceptor) InitializePoolForFunction(
	contract common.Address,
	selector [4]byte,
	poolSize int,
) error {
	if i.registry == nil || i.poolManager == nil {
		return fmt.Errorf("registry or poolManager not initialized")
	}

	// 获取方法定义
	method, err := i.registry.GetMethod(contract, selector)
	if err != nil {
		return fmt.Errorf("failed to get method: %w", err)
	}

	// 获取种子配置
	info, err := i.registry.GetContractInfo(contract)
	if err != nil {
		return fmt.Errorf("failed to get contract info: %w", err)
	}

	// 生成参数池
	err = i.poolManager.GeneratePool(contract, method, info.SeedConfig, poolSize)
	if err != nil {
		return fmt.Errorf("failed to generate pool: %w", err)
	}

	return nil
}

// InvalidatePoolsForContract 清空指定合约的所有参数池
func (i *CallInterceptor) InvalidatePoolsForContract(contract common.Address) error {
	if i.registry == nil || i.poolManager == nil {
		return fmt.Errorf("registry or poolManager not initialized")
	}

	// 获取合约信息
	info, err := i.registry.GetContractInfo(contract)
	if err != nil {
		return fmt.Errorf("failed to get contract info: %w", err)
	}

	// 清空每个方法的参数池
	for _, method := range info.ABI.Methods {
		var selector [4]byte
		copy(selector[:], method.ID[:4])
		i.poolManager.InvalidatePool(contract, selector)
	}

	return nil
}

// GetPoolStats 获取参数池统计信息
func (i *CallInterceptor) GetPoolStats() PoolStats {
	if i.poolManager == nil {
		return PoolStats{}
	}
	return i.poolManager.GetPoolStats()
}

// GetMutationHistory 获取变异历史
func (i *CallInterceptor) GetMutationHistory(methodSig string) *MutationHistory {
	if i.mutationEngine == nil {
		return nil
	}
	return i.mutationEngine.GetHistory(methodSig)
}
