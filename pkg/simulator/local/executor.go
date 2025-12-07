// Package local 提供本地EVM执行器实现
package local

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// LocalEVMExecutor 本地EVM执行器
// 直接使用go-ethereum的vm.EVM运行交易，支持CALL拦截和calldata修改
type LocalEVMExecutor struct {
	// 执行配置
	config *ExecutionConfig

	// 拦截器
	interceptor *CallInterceptor

	// JUMPDEST收集器
	collector *TraceCollector

	// JumpTable Hook
	jumpTableHook *HookedJumpTable

	// 受保护合约（用于控制从何时开始记录路径）
	protectedAddrs []common.Address

	// 是否启用Hook
	enableHook bool
}

// NewLocalEVMExecutor 创建本地EVM执行器
func NewLocalEVMExecutor(config *ExecutionConfig) *LocalEVMExecutor {
	if config == nil {
		config = DefaultExecutionConfig()
	}

	collector := NewTraceCollector()
	interceptor := NewCallInterceptor(collector)
	jumpTableHook := NewHookedJumpTable(interceptor)

	return &LocalEVMExecutor{
		config:        config,
		interceptor:   interceptor,
		collector:     collector,
		jumpTableHook: jumpTableHook,
		enableHook:    true,
	}
}

// SetConfig 设置执行配置
func (e *LocalEVMExecutor) SetConfig(config *ExecutionConfig) {
	e.config = config
}

// GetConfig 获取执行配置
func (e *LocalEVMExecutor) GetConfig() *ExecutionConfig {
	return e.config
}

// SetEnableHook 设置是否启用JumpTable Hook
func (e *LocalEVMExecutor) SetEnableHook(enable bool) {
	e.enableHook = enable
}

// SetMutationEnabled 控制是否对受保护合约进行变异
func (e *LocalEVMExecutor) SetMutationEnabled(enable bool) {
	if e.interceptor != nil {
		e.interceptor.SetMutationEnabled(enable)
	}
}

// SetProtectedAddresses 配置受保护合约列表，用于控制何时开始记录执行路径
func (e *LocalEVMExecutor) SetProtectedAddresses(addrs []common.Address) {
	e.protectedAddrs = addrs
}

// ResetProtectedTracking 重置首个受保护调用记录
func (e *LocalEVMExecutor) ResetProtectedTracking() {
	if e.interceptor != nil {
		e.interceptor.ResetProtectedTracking()
	}
}

// GetFirstProtectedHit 返回首个受保护调用信息
func (e *LocalEVMExecutor) GetFirstProtectedHit() *ProtectedCallHit {
	if e.interceptor == nil {
		return nil
	}
	return e.interceptor.GetFirstProtectedHit()
}

// RegisterMutator 为指定地址注册CallMutator
func (e *LocalEVMExecutor) RegisterMutator(addr common.Address, mutator CallMutatorV2) {
	e.interceptor.RegisterMutator(addr, mutator)
}

// UnregisterMutator 移除指定地址的CallMutator
func (e *LocalEVMExecutor) UnregisterMutator(addr common.Address) {
	e.interceptor.UnregisterMutator(addr)
}

// ClearMutators 清除所有注册的mutators
func (e *LocalEVMExecutor) ClearMutators() {
	e.interceptor.ClearMutators()
}

// HasMutators 检查是否有注册的mutators
func (e *LocalEVMExecutor) HasMutators() bool {
	return e.interceptor.HasMutators()
}

// Execute 执行交易
func (e *LocalEVMExecutor) Execute(
	ctx context.Context,
	from, to common.Address,
	input []byte,
	value *big.Int,
	override StateOverride,
) (*ExecutionResult, error) {
	// 1. 创建StateAdapter
	stateDB := NewStateAdapter(override)

	// 2. 配置拦截器
	e.interceptor.SetStateDB(stateDB)
	e.interceptor.Reset()

	// 3. 重置收集器
	e.collector.ResetWithProtected(e.protectedAddrs)

	// 4. 创建EVM
	blockCtx := e.buildBlockContext()
	txCtx := vm.TxContext{
		Origin:   from,
		GasPrice: big.NewInt(0),
	}

	chainConfig := e.buildChainConfig()
	vmConfig := vm.Config{
		Tracer:    e.interceptor.EVMTracer(),
		ExtraEips: []int{3855}, // 确保启用 PUSH0（EIP-3855）
	}

	evm := vm.NewEVM(blockCtx, stateDB, chainConfig, vmConfig)
	evm.SetTxContext(txCtx)

	// 5. 如果有mutators且启用Hook，注入HookedJumpTable
	if e.enableHook && e.interceptor.HasMutators() {
		if err := e.jumpTableHook.HookEVM(evm); err != nil {
			// Hook失败不影响执行，只是不会修改calldata
			// 可以选择记录日志
		}
	}

	// 6. 准备执行
	// 设置sender的nonce和余额
	if !stateDB.Exist(from) {
		stateDB.CreateAccount(from)
	}
	// 确保sender有足够的余额
	if value != nil && value.Sign() > 0 {
		senderBalance := stateDB.GetBalance(from)
		valueU256, _ := uint256.FromBig(value)
		if senderBalance.Cmp(valueU256) < 0 {
			// 自动设置足够的余额用于测试
			stateDB.AddBalance(from, valueU256, 0)
		}
	}

	// 7. 执行
	var ret []byte
	var leftoverGas uint64
	var execErr error

	if value == nil {
		value = big.NewInt(0)
	}
	valueU256, _ := uint256.FromBig(value)

	// 准备StateDB
	rules := chainConfig.Rules(e.config.BlockNumber, e.config.Random != nil, e.config.Time)
	precompiles := vm.ActivePrecompiledContracts(rules)
	precompileAddrs := make([]common.Address, 0, len(precompiles))
	for addr := range precompiles {
		precompileAddrs = append(precompileAddrs, addr)
	}
	stateDB.Prepare(rules, from, e.config.Coinbase, &to, precompileAddrs, nil)

	ret, leftoverGas, execErr = evm.Call(
		from, to, input, e.config.GasLimit, valueU256,
	)

	// 8. 组装结果
	result := &ExecutionResult{
		Success:           execErr == nil,
		ReturnData:        ret,
		GasUsed:           e.config.GasLimit - leftoverGas,
		ContractJumpDests: e.collector.GetContractJumpDests(),
		StateChanges:      stateDB.GetStateChanges(),
		Logs:              stateDB.GetLogs(),
	}

	if execErr != nil {
		result.Error = execErr.Error()
	}

	return result, nil
}

// ExecuteWithMutators 使用指定的mutators执行交易
func (e *LocalEVMExecutor) ExecuteWithMutators(
	ctx context.Context,
	from, to common.Address,
	input []byte,
	value *big.Int,
	override StateOverride,
	mutators map[common.Address]CallMutatorV2,
) (*ExecutionResult, error) {
	// 清除旧的mutators
	e.ClearMutators()

	// 注册新的mutators
	for addr, mutator := range mutators {
		e.RegisterMutator(addr, mutator)
	}

	// 执行
	return e.Execute(ctx, from, to, input, value, override)
}

// buildBlockContext 构建区块上下文
func (e *LocalEVMExecutor) buildBlockContext() vm.BlockContext {
	return vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     GetHashFn(e.config.BlockNumber),
		Coinbase:    e.config.Coinbase,
		GasLimit:    e.config.GasLimit,
		BlockNumber: e.config.BlockNumber,
		Time:        e.config.Time,
		Difficulty:  e.config.Difficulty,
		BaseFee:     e.config.BaseFee,
		Random:      e.config.Random,
	}
}

// buildChainConfig 构建链配置
func (e *LocalEVMExecutor) buildChainConfig() *params.ChainConfig {
	// 使用Shanghai配置作为基准（支持大部分现代EVM特性）
	shanghaiTime := uint64(0)
	return &params.ChainConfig{
		ChainID:                 e.config.ChainID,
		HomesteadBlock:          big.NewInt(0),
		DAOForkBlock:            nil,
		DAOForkSupport:          false,
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		MuirGlacierBlock:        big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		ArrowGlacierBlock:       big.NewInt(0),
		GrayGlacierBlock:        big.NewInt(0),
		MergeNetsplitBlock:      big.NewInt(0),
		ShanghaiTime:            &shanghaiTime,
		CancunTime:              nil, // 暂不启用Cancun
		TerminalTotalDifficulty: big.NewInt(0),
	}
}

// CanTransfer 检查是否可以转账
func CanTransfer(db vm.StateDB, addr common.Address, amount *uint256.Int) bool {
	return db.GetBalance(addr).Cmp(amount) >= 0
}

// Transfer 执行转账
func Transfer(db vm.StateDB, sender, recipient common.Address, amount *uint256.Int) {
	db.SubBalance(sender, amount, 0)
	db.AddBalance(recipient, amount, 0)
}

// GetHashFn 返回获取区块哈希的函数
func GetHashFn(blockNumber *big.Int) func(n uint64) common.Hash {
	return func(n uint64) common.Hash {
		// 简单实现：返回基于区块号的伪哈希
		// 在测试环境中这通常足够了
		return common.BigToHash(big.NewInt(int64(n)))
	}
}

// GetInterceptor 获取拦截器（用于高级配置）
func (e *LocalEVMExecutor) GetInterceptor() *CallInterceptor {
	return e.interceptor
}

// GetCollector 获取JUMPDEST收集器
func (e *LocalEVMExecutor) GetCollector() *TraceCollector {
	return e.collector
}

// SetInterceptor 设置拦截器（用于新架构集成）
func (e *LocalEVMExecutor) SetInterceptor(interceptor *CallInterceptor) {
	if interceptor != nil {
		e.interceptor = interceptor
		// 更新JumpTable Hook以使用新的interceptor
		e.jumpTableHook = NewHookedJumpTable(interceptor)
	}
}
