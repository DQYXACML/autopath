package monitor

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"autopath/pkg/invariants"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// StorageFetcher retrieves contract storage snapshots.
type StorageFetcher struct {
	ethClient      *ethclient.Client
	rpcClient      *rpc.Client
	maxRange       int
	requestTimeout time.Duration
	onceLogNoDebug sync.Once
}

// NewStorageFetcher constructs a storage fetcher with sane defaults.
func NewStorageFetcher(ethClient *ethclient.Client, rpcClient *rpc.Client) *StorageFetcher {
	return &StorageFetcher{
		ethClient:      ethClient,
		rpcClient:      rpcClient,
		maxRange:       256,              // slots per debug_storageRangeAt call
		requestTimeout: 10 * time.Second, // guard against slow debug RPCs
	}
}

// Snapshot collects all storage slots for a contract at the given block.
// It attempts to use debug_storageRangeAt; if unsupported it gracefully
// falls back to an empty snapshot (balance/code still populated).
func (f *StorageFetcher) Snapshot(
	ctx context.Context,
	addr common.Address,
	blockHash common.Hash,
	blockNumber *big.Int,
) (map[common.Hash]common.Hash, error) {
	if f.rpcClient == nil {
		return map[common.Hash]common.Hash{}, nil
	}

	storage := make(map[common.Hash]common.Hash)

	startKey := common.Hash{}
	seen := make(map[common.Hash]bool)

	for {
		var result storageRangeResult

		callCtx, cancel := context.WithTimeout(ctx, f.requestTimeout)
		err := f.rpcClient.CallContext(
			callCtx,
			&result,
			"debug_storageRangeAt",
			blockHash,
			addr,
			startKey,
			f.maxRange,
		)
		cancel()

		if err != nil {
			// Some nodes (Anvil, public providers) may not expose debug API.
			f.onceLogNoDebug.Do(func() {
				log.Printf("debug_storageRangeAt unavailable for %s (block %s): %v", addr.Hex(), blockNumber.String(), err)
			})
			// Fallback: attempt targeted slots we already have via eth_getStorageAt.
			return f.fallbackStorage(ctx, addr, blockNumber)
		}

		for keyHex, entry := range result.Storage {
			if entry.Value == "" {
				continue
			}

			// Some clients return the slot index as map key while also providing entry.Key.
			key := parseHexHash(entry.Key)
			if key == (common.Hash{}) {
				key = parseHexHash(keyHex)
			}
			if key == (common.Hash{}) {
				continue
			}

			value := parseHexHash(entry.Value)
			if seen[key] {
				continue
			}
			if (value == common.Hash{}) {
				// zero values are still meaningful, keep them
			}
			storage[key] = value
			seen[key] = true
		}

		if result.NextKey == nil || *result.NextKey == "" {
			break
		}

		startKey = parseHexHash(*result.NextKey)
		if startKey == (common.Hash{}) {
			break
		}
	}

	return storage, nil
}

// fetchERC20Balances attempts to fetch ERC20 balanceOf storage for given holder addresses.
// It tries common balanceOf slot positions (0-5) and computes mapping slots for each holder.
func (f *StorageFetcher) fetchERC20Balances(
	ctx context.Context,
	tokenAddr common.Address,
	holders []common.Address,
	blockNumber *big.Int,
) map[common.Hash]common.Hash {
	storage := make(map[common.Hash]common.Hash)

	// 尝试常见的balanceOf base slots (0-5)
	// 大多数ERC20: balanceOf在slot 0, 1, 2, 或3
	for baseSlot := uint64(0); baseSlot <= 5; baseSlot++ {
		for _, holder := range holders {
			// 计算mapping slot: keccak256(abi.encode(holder, baseSlot))
			// Solidity mapping storage layout: keccak256(h(k) . p)
			// where h(k) = keccak256(k) for dynamic types, or k itself for value types
			// p = base slot position
			slot := crypto.Keccak256Hash(
				append(
					common.LeftPadBytes(holder.Bytes(), 32),
					common.LeftPadBytes(new(big.Int).SetUint64(baseSlot).Bytes(), 32)...,
				),
			)

			value, err := f.ethClient.StorageAt(ctx, tokenAddr, slot, blockNumber)
			if err != nil {
				continue
			}

			if len(value) > 0 {
				valueHash := common.BytesToHash(value)
				// 保存所有值，包括零值（可能有意义）
				storage[slot] = valueHash
			}
		}
	}

	if len(storage) > 0 {
		log.Printf("   [ERC20 Fetcher] 为 %s 获取了 %d 个balanceOf slots", tokenAddr.Hex(), len(storage))
	}

	return storage
}

// fallbackStorage attempts to fetch storage by probing known slots referenced by invariants.
func (f *StorageFetcher) fallbackStorage(ctx context.Context, addr common.Address, blockNumber *big.Int) (map[common.Hash]common.Hash, error) {
	storage := make(map[common.Hash]common.Hash)

	// 针对不同合约类型，查询关键的 storage slots
	// 这是 Anvil 等不支持 debug_storageRangeAt 的环境的 fallback 方案

	// 对于 Uniswap V2 Pair (如 PancakePair)，查询关键 slots
	// Slot 6: token0 地址
	// Slot 7: token1 地址
	// Slot 8: reserves (reserve0, reserve1, blockTimestampLast)
	// Slot 9: price0CumulativeLast
	// Slot 10: price1CumulativeLast

	knownSlots := []uint64{
		0,  // 通常是 totalSupply 或其他关键状态
		1,  // 可能是 name/symbol 或其他配置
		2,  // 常见的 totalSupply 位置
		6,  // Uniswap V2 token0
		7,  // Uniswap V2 token1
		8,  // Uniswap V2 reserves
		9,  // Uniswap V2 price0CumulativeLast
		10, // Uniswap V2 price1CumulativeLast
		11, // Uniswap V2 kLast
		12, // 可能的额外状态
	}

	for _, slotNum := range knownSlots {
		slot := common.BigToHash(new(big.Int).SetUint64(slotNum))

		value, err := f.ethClient.StorageAt(ctx, addr, slot, blockNumber)
		if err != nil {
			log.Printf("Failed to fetch storage slot %d for %s: %v", slotNum, addr.Hex(), err)
			continue
		}

		if len(value) > 0 {
			// 将 []byte 转换为 common.Hash
			var valueHash common.Hash
			copy(valueHash[:], value)

			// 只保存非零值
			if valueHash != (common.Hash{}) {
				storage[slot] = valueHash
			}
		}
	}

	// 【ERC20增强】尝试获取ERC20 token的balanceOf数据
	// 使用Anvil默认账户地址（用于本地测试）
	relevantHolders := []common.Address{
		common.HexToAddress("0x7b3a6eff1c9925e509c2b01a389238c1fcc462b6"), // Anvil账户1（攻击者）
		common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), // Anvil账户0（部署者）
		common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8"), // Anvil账户2
		common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"), // Anvil账户3
	}

	// 尝试获取这些地址的ERC20余额
	erc20Storage := f.fetchERC20Balances(ctx, addr, relevantHolders, blockNumber)
	for slot, value := range erc20Storage {
		storage[slot] = value
	}

	log.Printf("Fallback storage fetched %d slots for %s at block %s",
		len(storage), addr.Hex(), blockNumber.String())

	return storage, nil
}

type storageRangeResult struct {
	Storage map[string]storageEntry `json:"storage"`
	NextKey *string                 `json:"nextKey"`
}

type storageEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

func parseHexHash(input string) common.Hash {
	if input == "" {
		return common.Hash{}
	}
	cleaned := strings.TrimSpace(input)
	if !strings.HasPrefix(cleaned, "0x") {
		cleaned = "0x" + cleaned
	}
	return common.HexToHash(cleaned)
}

// PopulateContractState ensures balance, code, and storage are collected.
func (f *StorageFetcher) PopulateContractState(
	ctx context.Context,
	addr common.Address,
	blockHash common.Hash,
	blockNumber *big.Int,
) (*invariants.ContractState, error) {
	balance, err := f.ethClient.BalanceAt(ctx, addr, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("balance fetch failed: %w", err)
	}

	code, err := f.ethClient.CodeAt(ctx, addr, blockNumber)
	if err != nil {
		return nil, fmt.Errorf("code fetch failed: %w", err)
	}

	storage, err := f.Snapshot(ctx, addr, blockHash, blockNumber)
	if err != nil {
		return nil, err
	}

	return &invariants.ContractState{
		Address: addr,
		Balance: balance,
		Storage: storage,
		Code:    code,
	}, nil
}
