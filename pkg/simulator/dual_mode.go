package simulator

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"

	"autopath/pkg/simulator/local"
)

// ExecutionMode 执行模式
type ExecutionMode int

const (
	// ModeRPC 使用RPC执行（默认）
	ModeRPC ExecutionMode = iota
	// ModeLocal 使用本地EVM执行
	ModeLocal
)

// String 返回执行模式的字符串表示
func (m ExecutionMode) String() string {
	switch m {
	case ModeRPC:
		return "RPC"
	case ModeLocal:
		return "Local"
	default:
		return "Unknown"
	}
}

// DualModeSimulator 支持RPC和本地执行的双模式模拟器
type DualModeSimulator struct {
	*EVMSimulator                         // 嵌入原有的EVMSimulator
	localExecutor *local.LocalEVMExecutor // 本地EVM执行器
	mode          ExecutionMode           // 当前执行模式
}

// NewDualModeSimulator 创建双模式模拟器
func NewDualModeSimulator(rpcURL string) (*DualModeSimulator, error) {
	// 创建基础的EVMSimulator
	baseSimulator, err := NewEVMSimulator(rpcURL)
	if err != nil {
		return nil, err
	}

	// 创建本地执行器
	localExec := local.NewLocalEVMExecutor(nil)

	return &DualModeSimulator{
		EVMSimulator:  baseSimulator,
		localExecutor: localExec,
		mode:          ModeRPC, // 默认使用RPC模式
	}, nil
}

// NewDualModeSimulatorWithClients 使用现有的RPC客户端创建双模式模拟器
func NewDualModeSimulatorWithClients(rpcClient *rpc.Client, client *ethclient.Client) *DualModeSimulator {
	baseSimulator := NewEVMSimulatorWithClients(rpcClient, client)
	localExec := local.NewLocalEVMExecutor(nil)

	return &DualModeSimulator{
		EVMSimulator:  baseSimulator,
		localExecutor: localExec,
		mode:          ModeRPC,
	}
}

// SetExecutionMode 设置执行模式
func (s *DualModeSimulator) SetExecutionMode(mode ExecutionMode) {
	s.mode = mode
	fmt.Printf("[DualModeSimulator] 执行模式切换为: %s\n", mode)
}

// GetExecutionMode 获取当前执行模式
func (s *DualModeSimulator) GetExecutionMode() ExecutionMode {
	return s.mode
}

// GetLocalExecutor 获取本地执行器（用于高级配置）
func (s *DualModeSimulator) GetLocalExecutor() *local.LocalEVMExecutor {
	return s.localExecutor
}

// RegisterMutator 为本地执行器注册CallMutator
func (s *DualModeSimulator) RegisterMutator(addr common.Address, mutator local.CallMutatorV2) {
	s.localExecutor.RegisterMutator(addr, mutator)
}

// UnregisterMutator 移除指定地址的CallMutator
func (s *DualModeSimulator) UnregisterMutator(addr common.Address) {
	s.localExecutor.UnregisterMutator(addr)
}

// ClearMutators 清除所有注册的mutators
func (s *DualModeSimulator) ClearMutators() {
	s.localExecutor.ClearMutators()
}

// ReplayTransactionLocal 在本地EVM中基于prestate重放原始交易并返回执行路径
func (s *DualModeSimulator) ReplayTransactionLocal(
	ctx context.Context,
	tx *types.Transaction,
	blockNumber uint64,
	override StateOverride,
	protectedContract common.Address,
) (*ReplayResult, error) {
	if s.localExecutor == nil {
		return nil, fmt.Errorf("local executor not initialized")
	}

	if tx == nil {
		return nil, fmt.Errorf("tx is nil")
	}

	// 仅支持普通调用（不处理合约创建）
	if tx.To() == nil {
		return nil, fmt.Errorf("contract creation tx not supported in local replay")
	}

	from, err := senderFromTx(tx)
	if err != nil {
		return nil, fmt.Errorf("failed to derive sender: %w", err)
	}

	to := *tx.To()
	callData := tx.Data()
	value := tx.Value()

	// 对齐执行配置
	if cfg := s.localExecutor.GetConfig(); cfg != nil {
		c := *cfg
		c.BlockNumber = big.NewInt(int64(blockNumber))
		if gas := tx.Gas(); gas > 0 {
			c.GasLimit = gas
		}
		s.localExecutor.SetConfig(&c)
	}

	// 强制使用本地模式
	s.SetExecutionMode(ModeLocal)

	protected := []common.Address{}
	if protectedContract != (common.Address{}) {
		protected = append(protected, protectedContract)
	}

	return s.executeLocal(ctx, from, to, callData, value, blockNumber, override, nil, protected)
}

// SimulateWithCallDataV2 支持双模式的模拟执行
// 如果设置了mutators，会自动切换到本地模式
func (s *DualModeSimulator) SimulateWithCallDataV2(
	ctx context.Context,
	from, to common.Address,
	callData []byte,
	value *big.Int,
	blockNumber uint64,
	override StateOverride,
	mutators map[common.Address]local.CallMutatorV2,
) (*ReplayResult, error) {
	// 如果有mutators，使用本地执行
	if len(mutators) > 0 || s.mode == ModeLocal {
		return s.executeLocal(ctx, from, to, callData, value, blockNumber, override, mutators, nil)
	}

	// 否则使用RPC执行
	return s.SimulateWithCallData(ctx, from, to, callData, value, blockNumber, override)
}

// executeLocal 使用本地EVM执行
func (s *DualModeSimulator) executeLocal(
	ctx context.Context,
	from, to common.Address,
	callData []byte,
	value *big.Int,
	blockNumber uint64,
	override StateOverride,
	mutators map[common.Address]local.CallMutatorV2,
	protectedAddrs []common.Address,
) (*ReplayResult, error) {
	// 转换StateOverride格式
	localOverride := convertToLocalOverride(override)

	// 计算受保护合约集合（mutators + 显式指定）
	effectiveProtected := mergeProtectedAddrs(mutators, protectedAddrs)

	// 配置块高度，保证与原始攻击交易一致
	if blockNumber > 0 {
		cfg := s.localExecutor.GetConfig()
		if cfg == nil {
			cfg = local.DefaultExecutionConfig()
		}
		cfgCopy := *cfg
		cfgCopy.BlockNumber = big.NewInt(int64(blockNumber))
		s.localExecutor.SetConfig(&cfgCopy)
	}

	// 预先配置受保护合约，命中前不记录路径
	s.localExecutor.SetProtectedAddresses(effectiveProtected)

	// 执行
	var result *local.ExecutionResult
	var err error

	if len(mutators) > 0 {
		result, err = s.localExecutor.ExecuteWithMutators(ctx, from, to, callData, value, localOverride, mutators)
	} else {
		result, err = s.localExecutor.Execute(ctx, from, to, callData, value, localOverride)
	}

	if err != nil {
		return nil, fmt.Errorf("local execution failed: %w", err)
	}

	// 转换结果格式
	return convertToReplayResult(result, effectiveProtected), nil
}

// convertToLocalOverride 转换StateOverride格式
func convertToLocalOverride(override StateOverride) local.StateOverride {
	if override == nil {
		return nil
	}

	localOverride := make(local.StateOverride, len(override))
	for addr, ov := range override {
		if ov == nil {
			continue
		}
		localOverride[addr] = &local.AccountOverride{
			Balance: ov.Balance,
			Nonce:   ov.Nonce,
			Code:    ov.Code,
			State:   ov.State,
		}
	}
	return localOverride
}

// mergeProtectedAddrs 合并显式指定的受保护地址和mutators中的目标地址
func mergeProtectedAddrs(mutators map[common.Address]local.CallMutatorV2, extra []common.Address) []common.Address {
	if len(mutators) == 0 && len(extra) == 0 {
		return nil
	}

	seen := make(map[string]common.Address)
	for _, addr := range extra {
		if addr == (common.Address{}) {
			continue
		}
		seen[strings.ToLower(addr.Hex())] = addr
	}
	for addr := range mutators {
		if addr == (common.Address{}) {
			continue
		}
		seen[strings.ToLower(addr.Hex())] = addr
	}

	merged := make([]common.Address, 0, len(seen))
	for _, addr := range seen {
		merged = append(merged, addr)
	}
	return merged
}

// convertToReplayResult 转换执行结果格式
func convertToReplayResult(result *local.ExecutionResult, protectedAddrs []common.Address) *ReplayResult {
	// 转换ContractJumpDests
	contractJumpDests := make([]ContractJumpDest, len(result.ContractJumpDests))
	for i, jd := range result.ContractJumpDests {
		contractJumpDests[i] = ContractJumpDest{
			Contract: jd.Contract,
			PC:       jd.PC,
		}
	}

	// 提取纯PC序列（向后兼容）
	jumpDests := make([]uint64, len(result.ContractJumpDests))
	for i, jd := range result.ContractJumpDests {
		jumpDests[i] = jd.PC
	}

	// 若提供受保护地址，则从首个命中位置开始记录路径
	protectedStart := 0
	protectedEnd := len(contractJumpDests)
	if idx := findProtectedStartIndex(contractJumpDests, protectedAddrs); idx >= 0 && idx < len(contractJumpDests) {
		if idx > 0 {
			contractJumpDests = contractJumpDests[idx:]
			jumpDests = jumpDests[idx:]
		}
		protectedStart = 0
		protectedEnd = len(contractJumpDests)
	}

	// 转换StateChanges
	stateChanges := make(map[string]StateChange, len(result.StateChanges))
	for addr, sc := range result.StateChanges {
		storageChanges := make(map[string]StorageUpdate, len(sc.StorageChanges))
		for slot, update := range sc.StorageChanges {
			storageChanges[slot] = StorageUpdate{
				Before: update.Before,
				After:  update.After,
			}
		}
		stateChanges[addr] = StateChange{
			BalanceBefore:  sc.BalanceBefore,
			BalanceAfter:   sc.BalanceAfter,
			StorageChanges: storageChanges,
		}
	}

	// 转换Logs
	logs := make([]Log, len(result.Logs))
	for i, lg := range result.Logs {
		topics := make([]common.Hash, len(lg.Topics))
		copy(topics, lg.Topics)
		logs[i] = Log{
			Address: lg.Address,
			Topics:  topics,
			Data:    common.Bytes2Hex(lg.Data),
		}
	}

	return &ReplayResult{
		Success:             result.Success,
		GasUsed:             result.GasUsed,
		ReturnData:          common.Bytes2Hex(result.ReturnData),
		JumpDests:           jumpDests,
		ContractJumpDests:   contractJumpDests,
		ProtectedStartIndex: protectedStart,
		ProtectedEndIndex:   protectedEnd,
		StateChanges:        stateChanges,
		Logs:                logs,
		Error:               result.Error,
	}
}

// findProtectedStartIndex 返回首个匹配受保护地址的路径下标，未命中返回-1
func findProtectedStartIndex(jumps []ContractJumpDest, protectedAddrs []common.Address) int {
	if len(jumps) == 0 || len(protectedAddrs) == 0 {
		return -1
	}

	for i, jd := range jumps {
		for _, addr := range protectedAddrs {
			if strings.EqualFold(jd.Contract, strings.ToLower(addr.Hex())) {
				return i
			}
		}
	}
	return -1
}

// AdaptCallMutator 适配旧版CallMutator到新版CallMutatorV2
// CallMutator 类型已在 hook_executor.go 中定义
func AdaptCallMutator(old CallMutator) local.CallMutatorV2 {
	return func(ctx *local.CallInterceptContext) ([]byte, bool, error) {
		// 构建旧版CallFrame
		frame := &CallFrame{
			Type:  ctx.OpType,
			From:  ctx.Caller.Hex(),
			To:    ctx.Target.Hex(),
			Input: "0x" + common.Bytes2Hex(ctx.Input),
		}
		if ctx.Value != nil {
			frame.Value = fmt.Sprintf("0x%x", ctx.Value.ToBig())
		}

		// 调用旧版mutator
		return old(frame, ctx.Input)
	}
}

// senderFromTx 从交易推导发送者
func senderFromTx(tx *types.Transaction) (common.Address, error) {
	if tx == nil {
		return common.Address{}, fmt.Errorf("tx is nil")
	}

	chainID := tx.ChainId()
	var signer types.Signer
	if chainID != nil {
		signer = types.LatestSignerForChainID(chainID)
	} else {
		signer = types.HomesteadSigner{}
	}

	return types.Sender(signer, tx)
}
