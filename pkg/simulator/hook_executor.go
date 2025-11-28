package simulator

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// CallMutator 在调用发生时可选地替换calldata
// 返回值：新的calldata、是否替换、错误
type CallMutator func(frame *CallFrame, original []byte) ([]byte, bool, error)

// ExecuteWithHooks 按调用树顺序执行整笔交易，每个外部CALL可通过mutator进行参数变异
func (s *EVMSimulator) ExecuteWithHooks(
	ctx context.Context,
	callTree *CallFrame,
	blockNumber uint64,
	baseOverride StateOverride,
	protected map[string]CallMutator, // key: lowercase address
) (*ReplayResult, error) {
	if callTree == nil {
		return nil, fmt.Errorf("callTree is nil")
	}

	// 深拷贝StateOverride，保证每个执行独立
	stateOverride := cloneStateOverride(baseOverride)

	frames := normalizeCallFrames(callTree)

	var aggregatedCJDs []ContractJumpDest
	mergedChanges := make(map[string]StateChange)
	success := true
	var returnData string
	var lastError string
	var totalGasUsed uint64

	for _, frame := range frames {
		callData, err := hexutil.Decode(frame.Input)
		if err != nil {
			return nil, fmt.Errorf("failed to decode call input: %w", err)
		}

		toLower := strings.ToLower(frame.To)
		if mutator, ok := protected[toLower]; ok && mutator != nil {
			if mutated, replaced, err := mutator(frame, callData); err == nil && replaced {
				callData = mutated
			}
		}

		from := common.HexToAddress(frame.From)
		to := common.HexToAddress(frame.To)

		value := big.NewInt(0)
		if frame.Value != "" && frame.Value != "0x0" {
			if v, err := hexutil.DecodeBig(frame.Value); err == nil {
				value = v
			}
		}

		res, simErr := s.SimulateWithCallData(ctx, from, to, callData, value, blockNumber, stateOverride)
		if simErr != nil {
			return nil, fmt.Errorf("hook simulation failed for %s: %w", frame.To, simErr)
		}

		totalGasUsed += res.GasUsed
		if res.ReturnData != "" {
			returnData = res.ReturnData
		}
		if res.Error != "" {
			lastError = res.Error
		}
		if !res.Success {
			success = false
			// 继续合并状态，保持与原逻辑一致
		}

		// 合并路径
		aggregatedCJDs = append(aggregatedCJDs, res.ContractJumpDests...)

		// 合并状态变更到当前override供后续调用使用
		stateOverride = mergeStateChangesToOverride(stateOverride, res.StateChanges)
		// 同时累计结果的状态变更
		for addr, change := range res.StateChanges {
			if existing, ok := mergedChanges[addr]; ok {
				mergedChanges[addr] = mergeStateChange(existing, change)
			} else {
				mergedChanges[addr] = change
			}
		}
	}

	return &ReplayResult{
		Success:           success,
		GasUsed:           totalGasUsed,
		ReturnData:        returnData,
		ContractJumpDests: aggregatedCJDs,
		StateChanges:      mergedChanges,
		Error:             lastError,
	}, nil
}

// mergeStateChangesToOverride 将一次执行的状态变化应用到StateOverride
func mergeStateChangesToOverride(base StateOverride, changes map[string]StateChange) StateOverride {
	if base == nil {
		base = make(StateOverride)
	}

	for addr, change := range changes {
		lowerAddr := strings.ToLower(addr)
		ov, ok := base[lowerAddr]
		if !ok {
			ov = &AccountOverride{}
			base[lowerAddr] = ov
		}

		if change.BalanceAfter != "" {
			ov.Balance = change.BalanceAfter
		}

		if len(change.StorageChanges) > 0 {
			if ov.State == nil {
				ov.State = make(map[string]string)
			}
			for slot, diff := range change.StorageChanges {
				if diff.After != "" {
					ov.State[strings.ToLower(slot)] = diff.After
				}
			}
		}
	}

	return base
}

// mergeStateChange 合并两个状态变化记录
func mergeStateChange(a StateChange, b StateChange) StateChange {
	merged := a
	if b.BalanceAfter != "" {
		merged.BalanceAfter = b.BalanceAfter
	}
	if merged.StorageChanges == nil {
		merged.StorageChanges = make(map[string]StorageUpdate)
	}
	for slot, diff := range b.StorageChanges {
		merged.StorageChanges[slot] = diff
	}
	return merged
}

// cloneStateOverride 深拷贝StateOverride
func cloneStateOverride(src StateOverride) StateOverride {
	if src == nil {
		return nil
	}
	dst := make(StateOverride, len(src))
	for addr, ov := range src {
		if ov == nil {
			continue
		}
		copyOv := &AccountOverride{
			Balance: ov.Balance,
			Nonce:   ov.Nonce,
			Code:    ov.Code,
		}
		if len(ov.State) > 0 {
			copyOv.State = make(map[string]string, len(ov.State))
			for slot, val := range ov.State {
				copyOv.State[slot] = val
			}
		}
		dst[addr] = copyOv
	}
	return dst
}

// normalizeCallFrames 以深度优先顺序展开调用树，缺失的From用父调用的To填充
func normalizeCallFrames(root *CallFrame) []*CallFrame {
	var out []*CallFrame
	var walk func(node *CallFrame, parentTo string)
	walk = func(node *CallFrame, parentTo string) {
		cp := *node
		if cp.From == "" && parentTo != "" {
			cp.From = parentTo
		}
		out = append(out, &cp)
		for i := range node.Calls {
			walk(&node.Calls[i], cp.To)
		}
	}
	walk(root, "")
	return out
}
