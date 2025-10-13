package fuzzer

import (
	"math/big"
	"strings"
	"time"

	"autopath/pkg/invariants"
	"github.com/ethereum/go-ethereum/common"
)

// ConvertToChainState 将模拟结果转换为不变量评估器所需的ChainState格式
func ConvertToChainState(
	stateChanges map[string]StateChange,
	blockNumber uint64,
	txHash common.Hash,
) *invariants.ChainState {
	chainState := &invariants.ChainState{
		BlockNumber: blockNumber,
		TxHash:      txHash,
		Timestamp:   uint64(time.Now().Unix()),
		States:      make(map[common.Address]*invariants.ContractState),
	}

	// 从stateChanges转换
	for addrStr, change := range stateChanges {
		addr := common.HexToAddress(addrStr)

		// 转换存储变更
		storage := make(map[common.Hash]common.Hash)
		for slotStr, update := range change.StorageChanges {
			slotHash := common.HexToHash(slotStr)
			// 使用执行后的值(After)
			afterHash := common.HexToHash(update.After)
			storage[slotHash] = afterHash
		}

		// 转换余额
		balance := big.NewInt(0)
		if change.BalanceAfter != "" && change.BalanceAfter != "0x0" {
			// 移除0x前缀并解析
			balanceStr := strings.TrimPrefix(change.BalanceAfter, "0x")
			if balanceStr != "" {
				balance.SetString(balanceStr, 16)
			}
		}

		chainState.States[addr] = &invariants.ContractState{
			Address: addr,
			Balance: balance,
			Storage: storage,
			Code:    nil, // 不需要完整代码
		}
	}

	return chainState
}

// ConvertToChainStateFromSimResult 从SimulationResult直接转换
func ConvertToChainStateFromSimResult(
	simResult *SimulationResult,
	blockNumber uint64,
	txHash common.Hash,
) *invariants.ChainState {
	if simResult == nil {
		return &invariants.ChainState{
			BlockNumber: blockNumber,
			TxHash:      txHash,
			Timestamp:   uint64(time.Now().Unix()),
			States:      make(map[common.Address]*invariants.ContractState),
		}
	}

	return ConvertToChainState(simResult.StateChanges, blockNumber, txHash)
}

// EnrichChainStateWithContractAddresses 使用合约地址列表补充ChainState
// 对于没有状态变更的合约，也需要添加到States中供不变量评估器查询
func EnrichChainStateWithContractAddresses(
	chainState *invariants.ChainState,
	contractAddrs []common.Address,
) {
	if chainState == nil || chainState.States == nil {
		return
	}

	for _, addr := range contractAddrs {
		if _, exists := chainState.States[addr]; !exists {
			// 添加空状态，表示该合约参与了交易但没有状态变更
			chainState.States[addr] = &invariants.ContractState{
				Address: addr,
				Balance: big.NewInt(0),
				Storage: make(map[common.Hash]common.Hash),
			}
		}
	}
}
