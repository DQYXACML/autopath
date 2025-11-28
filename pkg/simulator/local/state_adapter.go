// Package local 提供本地EVM执行器实现
package local

import (
	"math/big"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/stateless"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie/utils"
	"github.com/holiman/uint256"
)

// StateAdapter 实现 vm.StateDB 接口
// 从 StateOverride 加载初始状态，执行过程中的变更记录在内存中
type StateAdapter struct {
	mu sync.RWMutex

	// 账户状态
	accounts map[common.Address]*AccountState

	// 快照机制
	snapshots  map[int]map[common.Address]*AccountState
	nextSnapID int

	// Access lists (EIP-2929)
	accessedAddresses map[common.Address]struct{}
	accessedSlots     map[common.Address]map[common.Hash]struct{}

	// Transient storage (EIP-1153)
	transientStorage map[common.Address]map[common.Hash]common.Hash

	// 日志
	logs    []*types.Log
	logSize uint

	// 预映像
	preimages map[common.Hash][]byte

	// 状态变更追踪
	stateChanges map[common.Address]map[common.Hash]StorageDiff

	// 已销毁账户
	selfDestructed map[common.Address]struct{}

	// 新创建账户（同一交易中）
	created map[common.Address]struct{}

	// Gas退款
	refund uint64
}

// NewStateAdapter 从 StateOverride 创建 StateAdapter
func NewStateAdapter(override StateOverride) *StateAdapter {
	sa := &StateAdapter{
		accounts:          make(map[common.Address]*AccountState),
		snapshots:         make(map[int]map[common.Address]*AccountState),
		accessedAddresses: make(map[common.Address]struct{}),
		accessedSlots:     make(map[common.Address]map[common.Hash]struct{}),
		transientStorage:  make(map[common.Address]map[common.Hash]common.Hash),
		preimages:         make(map[common.Hash][]byte),
		stateChanges:      make(map[common.Address]map[common.Hash]StorageDiff),
		selfDestructed:    make(map[common.Address]struct{}),
		created:           make(map[common.Address]struct{}),
	}

	// 从 StateOverride 初始化状态
	for addrStr, ov := range override {
		if ov == nil {
			continue
		}
		addr := common.HexToAddress(addrStr)
		account := NewAccountState()

		// 解析余额
		if ov.Balance != "" {
			balance, ok := parseHexOrDecimal(ov.Balance)
			if ok {
				account.Balance = balance
			}
		}

		// 解析Nonce
		if ov.Nonce != "" {
			if strings.HasPrefix(ov.Nonce, "0x") || strings.HasPrefix(ov.Nonce, "0X") {
				nonce, _ := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(ov.Nonce), "0x"), 16, 64)
				account.Nonce = nonce
			} else {
				nonce, _ := strconv.ParseUint(ov.Nonce, 10, 64)
				account.Nonce = nonce
			}
		}

		// 解析Code
		if ov.Code != "" {
			account.Code = common.FromHex(ov.Code)
			if len(account.Code) > 0 {
				account.CodeHash = crypto.Keccak256Hash(account.Code)
			}
		}

		// 解析Storage
		for slotStr, valueStr := range ov.State {
			slot := common.HexToHash(slotStr)
			value := common.HexToHash(valueStr)
			account.Storage[slot] = value
		}

		sa.accounts[addr] = account
	}

	return sa
}

// parseHexOrDecimal 解析十六进制或十进制字符串为big.Int
func parseHexOrDecimal(s string) (*big.Int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return big.NewInt(0), true
	}

	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		val, ok := new(big.Int).SetString(s[2:], 16)
		return val, ok
	}
	val, ok := new(big.Int).SetString(s, 10)
	return val, ok
}

// ============ 账户创建 ============

func (s *StateAdapter) CreateAccount(addr common.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.created[addr] = struct{}{}
	s.accounts[addr] = NewAccountState()
}

func (s *StateAdapter) CreateContract(addr common.Address) {
	s.CreateAccount(addr)
}

// ============ 余额操作 ============

func (s *StateAdapter) GetBalance(addr common.Address) *uint256.Int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[addr]; ok && account.Balance != nil {
		result, _ := uint256.FromBig(account.Balance)
		return result
	}
	return uint256.NewInt(0)
}

func (s *StateAdapter) SubBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.getOrCreateAccount(addr)
	prev, _ := uint256.FromBig(account.Balance)
	account.Balance = new(big.Int).Sub(account.Balance, amount.ToBig())
	return *prev
}

func (s *StateAdapter) AddBalance(addr common.Address, amount *uint256.Int, reason tracing.BalanceChangeReason) uint256.Int {
	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.getOrCreateAccount(addr)
	prev, _ := uint256.FromBig(account.Balance)
	account.Balance = new(big.Int).Add(account.Balance, amount.ToBig())
	return *prev
}

// ============ Nonce操作 ============

func (s *StateAdapter) GetNonce(addr common.Address) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[addr]; ok {
		return account.Nonce
	}
	return 0
}

func (s *StateAdapter) SetNonce(addr common.Address, nonce uint64, reason tracing.NonceChangeReason) {
	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.getOrCreateAccount(addr)
	account.Nonce = nonce
}

// ============ 代码操作 ============

func (s *StateAdapter) GetCode(addr common.Address) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[addr]; ok {
		return account.Code
	}
	return nil
}

func (s *StateAdapter) GetCodeHash(addr common.Address) common.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[addr]; ok {
		if len(account.Code) == 0 {
			// 空代码返回空哈希
			return common.Hash{}
		}
		return account.CodeHash
	}
	return common.Hash{}
}

func (s *StateAdapter) GetCodeSize(addr common.Address) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[addr]; ok {
		return len(account.Code)
	}
	return 0
}

func (s *StateAdapter) SetCode(addr common.Address, code []byte) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.getOrCreateAccount(addr)
	prevCode := account.Code
	account.Code = code
	if len(code) > 0 {
		account.CodeHash = crypto.Keccak256Hash(code)
	} else {
		account.CodeHash = common.Hash{}
	}
	return prevCode
}

// ============ 存储操作 ============

func (s *StateAdapter) GetState(addr common.Address, key common.Hash) common.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if account, ok := s.accounts[addr]; ok {
		if val, ok := account.Storage[key]; ok {
			return val
		}
	}
	return common.Hash{}
}

func (s *StateAdapter) GetStateAndCommittedState(addr common.Address, key common.Hash) (common.Hash, common.Hash) {
	state := s.GetState(addr, key)
	// 在模拟环境中，committed state等同于当前state
	return state, state
}

func (s *StateAdapter) SetState(addr common.Address, key common.Hash, value common.Hash) common.Hash {
	s.mu.Lock()
	defer s.mu.Unlock()

	account := s.getOrCreateAccount(addr)
	oldValue := account.Storage[key]
	account.Storage[key] = value

	// 记录状态变更
	if s.stateChanges[addr] == nil {
		s.stateChanges[addr] = make(map[common.Hash]StorageDiff)
	}
	if _, exists := s.stateChanges[addr][key]; !exists {
		s.stateChanges[addr][key] = StorageDiff{Before: oldValue}
	}
	diff := s.stateChanges[addr][key]
	diff.After = value
	s.stateChanges[addr][key] = diff

	return oldValue
}

func (s *StateAdapter) GetStorageRoot(addr common.Address) common.Hash {
	// 模拟环境不维护真实的storage root
	return common.Hash{}
}

// ============ Transient Storage (EIP-1153) ============

func (s *StateAdapter) GetTransientState(addr common.Address, key common.Hash) common.Hash {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if storage, ok := s.transientStorage[addr]; ok {
		return storage[key]
	}
	return common.Hash{}
}

func (s *StateAdapter) SetTransientState(addr common.Address, key, value common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.transientStorage[addr] == nil {
		s.transientStorage[addr] = make(map[common.Hash]common.Hash)
	}
	s.transientStorage[addr][key] = value
}

// ============ 账户销毁 ============

func (s *StateAdapter) SelfDestruct(addr common.Address) uint256.Int {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.selfDestructed[addr] = struct{}{}

	if account, ok := s.accounts[addr]; ok {
		balance, _ := uint256.FromBig(account.Balance)
		account.Balance = big.NewInt(0)
		return *balance
	}
	return *uint256.NewInt(0)
}

func (s *StateAdapter) HasSelfDestructed(addr common.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.selfDestructed[addr]
	return ok
}

func (s *StateAdapter) SelfDestruct6780(addr common.Address) (uint256.Int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// EIP-6780: 只有在同一交易中创建的账户才能真正销毁
	_, created := s.created[addr]
	if created {
		s.selfDestructed[addr] = struct{}{}
	}

	if account, ok := s.accounts[addr]; ok {
		balance, _ := uint256.FromBig(account.Balance)
		account.Balance = big.NewInt(0)
		return *balance, created
	}
	return *uint256.NewInt(0), created
}

// ============ 账户存在性检查 ============

func (s *StateAdapter) Exist(addr common.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	account, ok := s.accounts[addr]
	if !ok {
		return false
	}
	// 非空账户条件：有余额、有nonce、有code
	return account.Balance.Sign() > 0 || account.Nonce > 0 || len(account.Code) > 0
}

func (s *StateAdapter) Empty(addr common.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	account, ok := s.accounts[addr]
	if !ok {
		return true
	}
	return account.Balance.Sign() == 0 && account.Nonce == 0 && len(account.Code) == 0
}

// ============ Access List (EIP-2929) ============

func (s *StateAdapter) AddressInAccessList(addr common.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.accessedAddresses[addr]
	return ok
}

func (s *StateAdapter) SlotInAccessList(addr common.Address, slot common.Hash) (bool, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, addrOk := s.accessedAddresses[addr]
	if slots, ok := s.accessedSlots[addr]; ok {
		_, slotOk := slots[slot]
		return addrOk, slotOk
	}
	return addrOk, false
}

func (s *StateAdapter) AddAddressToAccessList(addr common.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessedAddresses[addr] = struct{}{}
}

func (s *StateAdapter) AddSlotToAccessList(addr common.Address, slot common.Hash) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.accessedAddresses[addr] = struct{}{}
	if s.accessedSlots[addr] == nil {
		s.accessedSlots[addr] = make(map[common.Hash]struct{})
	}
	s.accessedSlots[addr][slot] = struct{}{}
}

// ============ Gas退款 ============

func (s *StateAdapter) AddRefund(gas uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refund += gas
}

func (s *StateAdapter) SubRefund(gas uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gas > s.refund {
		s.refund = 0
	} else {
		s.refund -= gas
	}
}

func (s *StateAdapter) GetRefund() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.refund
}

// ============ 快照机制 ============

func (s *StateAdapter) Snapshot() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := s.nextSnapID
	s.nextSnapID++

	// 深拷贝当前状态
	snapshot := make(map[common.Address]*AccountState)
	for addr, account := range s.accounts {
		snapshot[addr] = account.Clone()
	}
	s.snapshots[id] = snapshot

	return id
}

func (s *StateAdapter) RevertToSnapshot(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if snapshot, ok := s.snapshots[id]; ok {
		s.accounts = snapshot
		// 删除此ID之后的所有快照
		for snapID := range s.snapshots {
			if snapID >= id {
				delete(s.snapshots, snapID)
			}
		}
	}
}

// ============ 日志 ============

func (s *StateAdapter) AddLog(log *types.Log) {
	s.mu.Lock()
	defer s.mu.Unlock()

	log.Index = s.logSize
	s.logSize++
	s.logs = append(s.logs, log)
}

// GetLogs 返回收集的日志
func (s *StateAdapter) GetLogs() []*types.Log {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.logs
}

// ============ 预映像 ============

func (s *StateAdapter) AddPreimage(hash common.Hash, preimage []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.preimages[hash] = preimage
}

// ============ Prepare ============

func (s *StateAdapter) Prepare(rules params.Rules, sender, coinbase common.Address, dest *common.Address, precompiles []common.Address, txAccesses types.AccessList) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 清除 transient storage
	s.transientStorage = make(map[common.Address]map[common.Hash]common.Hash)

	// 清除 access lists
	s.accessedAddresses = make(map[common.Address]struct{})
	s.accessedSlots = make(map[common.Address]map[common.Hash]struct{})

	// 添加预编译合约到access list
	for _, addr := range precompiles {
		s.accessedAddresses[addr] = struct{}{}
	}

	// 添加sender和coinbase
	s.accessedAddresses[sender] = struct{}{}
	s.accessedAddresses[coinbase] = struct{}{}

	// 添加目标地址
	if dest != nil {
		s.accessedAddresses[*dest] = struct{}{}
	}

	// 添加访问列表
	for _, item := range txAccesses {
		s.accessedAddresses[item.Address] = struct{}{}
		if s.accessedSlots[item.Address] == nil {
			s.accessedSlots[item.Address] = make(map[common.Hash]struct{})
		}
		for _, key := range item.StorageKeys {
			s.accessedSlots[item.Address][key] = struct{}{}
		}
	}
}

// ============ 其他必需方法 ============

func (s *StateAdapter) PointCache() *utils.PointCache {
	return nil // 模拟环境不需要点缓存
}

func (s *StateAdapter) Witness() *stateless.Witness {
	return nil // 模拟环境不需要witness
}

func (s *StateAdapter) AccessEvents() *state.AccessEvents {
	return nil // 模拟环境不需要access events
}

func (s *StateAdapter) Finalise(deleteEmptyObjects bool) {
	// 模拟环境中不需要特殊的finalise操作
}

// ============ 辅助方法 ============

func (s *StateAdapter) getOrCreateAccount(addr common.Address) *AccountState {
	if account, ok := s.accounts[addr]; ok {
		return account
	}
	account := NewAccountState()
	s.accounts[addr] = account
	return account
}

// GetStateChanges 返回所有状态变更（供结果收集使用）
func (s *StateAdapter) GetStateChanges() map[string]StateChange {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make(map[string]StateChange)
	for addr, changes := range s.stateChanges {
		addrStr := strings.ToLower(addr.Hex())
		sc := StateChange{
			StorageChanges: make(map[string]StorageUpdate),
		}

		// 获取余额信息
		if account, ok := s.accounts[addr]; ok {
			sc.BalanceAfter = "0x" + account.Balance.Text(16)
		}

		for slot, diff := range changes {
			sc.StorageChanges[slot.Hex()] = StorageUpdate{
				Before: diff.Before.Hex(),
				After:  diff.After.Hex(),
			}
		}

		result[addrStr] = sc
	}

	return result
}

// GetAccount 返回指定地址的账户状态
func (s *StateAdapter) GetAccount(addr common.Address) *AccountState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.accounts[addr]
}
