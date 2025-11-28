// Package local 提供本地EVM执行器实现，支持CALL指令拦截和calldata修改
package local

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
)

// 错误定义
var (
	// ErrTableFieldNotFound EVM table字段未找到
	ErrTableFieldNotFound = errors.New("EVM table field not found")
	// ErrExecutionFailed 执行失败
	ErrExecutionFailed = errors.New("execution failed")
	// ErrInvalidStateOverride 无效的状态覆盖
	ErrInvalidStateOverride = errors.New("invalid state override")
	// ErrMutatorFailed mutator回调失败
	ErrMutatorFailed = errors.New("mutator callback failed")
)

// ExecutionConfig 执行配置
type ExecutionConfig struct {
	ChainID     *big.Int       // 链ID
	BlockNumber *big.Int       // 区块号
	Time        uint64         // 区块时间戳
	GasLimit    uint64         // Gas限制
	BaseFee     *big.Int       // EIP-1559 基础费用
	Coinbase    common.Address // 矿工地址
	Difficulty  *big.Int       // 难度（PoW）
	Random      *common.Hash   // 随机数（PoS）
}

// DefaultExecutionConfig 返回默认执行配置
func DefaultExecutionConfig() *ExecutionConfig {
	return &ExecutionConfig{
		ChainID:     big.NewInt(1),
		BlockNumber: big.NewInt(1),
		Time:        1000000000,
		GasLimit:    30_000_000,
		BaseFee:     big.NewInt(1000000000), // 1 Gwei
		Coinbase:    common.Address{},
		Difficulty:  big.NewInt(1),
	}
}

// ExecutionResult 执行结果
type ExecutionResult struct {
	Success           bool                          // 执行是否成功
	ReturnData        []byte                        // 返回数据
	GasUsed           uint64                        // 消耗的Gas
	Error             string                        // 错误信息
	ContractJumpDests []ContractJumpDest            // JUMPDEST序列（带合约地址）
	StateChanges      map[string]StateChange        // 状态变更
	Logs              []*types.Log                  // 日志
}

// ContractJumpDest 带合约地址的JUMPDEST
type ContractJumpDest struct {
	Contract string `json:"contract"` // 合约地址
	PC       uint64 `json:"pc"`       // 程序计数器
}

// StateChange 状态变更
type StateChange struct {
	BalanceBefore  string                   `json:"balance_before"`
	BalanceAfter   string                   `json:"balance_after"`
	StorageChanges map[string]StorageUpdate `json:"storage_changes"`
}

// StorageUpdate 存储槽位的前后状态
type StorageUpdate struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// StorageDiff 存储差异（内部使用）
type StorageDiff struct {
	Before common.Hash
	After  common.Hash
}

// AccountState 账户状态
type AccountState struct {
	Balance  *big.Int                        // 余额
	Nonce    uint64                          // Nonce
	Code     []byte                          // 合约代码
	CodeHash common.Hash                     // 代码哈希
	Storage  map[common.Hash]common.Hash     // 存储
}

// NewAccountState 创建新的账户状态
func NewAccountState() *AccountState {
	return &AccountState{
		Balance: big.NewInt(0),
		Storage: make(map[common.Hash]common.Hash),
	}
}

// Clone 深拷贝账户状态
func (a *AccountState) Clone() *AccountState {
	clone := &AccountState{
		Balance:  new(big.Int).Set(a.Balance),
		Nonce:    a.Nonce,
		Code:     append([]byte{}, a.Code...),
		CodeHash: a.CodeHash,
		Storage:  make(map[common.Hash]common.Hash, len(a.Storage)),
	}
	for k, v := range a.Storage {
		clone.Storage[k] = v
	}
	return clone
}

// CallInterceptContext 拦截时的完整上下文
type CallInterceptContext struct {
	OpType  string           // "CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"
	Caller  common.Address   // 调用者地址
	Target  common.Address   // 目标地址
	Value   *uint256.Int     // 转账金额
	Input   []byte           // 原始calldata
	Gas     uint64           // 可用Gas
	Depth   int              // 调用深度

	// 完整上下文
	StateDB vm.StateDB       // 当前状态访问
}

// Selector 返回函数选择器（前4字节）
func (c *CallInterceptContext) Selector() []byte {
	if len(c.Input) >= 4 {
		return c.Input[:4]
	}
	return nil
}

// CallMutatorV2 新版回调接口（支持完整上下文）
// 返回值：新的calldata、是否修改、错误
type CallMutatorV2 func(ctx *CallInterceptContext) (newInput []byte, modified bool, err error)

// StateOverride 状态覆盖配置（与现有类型兼容）
type StateOverride map[string]*AccountOverride

// AccountOverride 账户覆盖配置
type AccountOverride struct {
	Balance string            `json:"balance,omitempty"`
	Nonce   string            `json:"nonce,omitempty"`
	Code    string            `json:"code,omitempty"`
	State   map[string]string `json:"state,omitempty"`
}

// ExecutionMode 执行模式
type ExecutionMode int

const (
	ModeRPC   ExecutionMode = iota // 使用RPC执行（默认）
	ModeLocal                      // 使用本地EVM执行
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

// CALL类操作码常量
const (
	OpCALL         byte = 0xF1
	OpCALLCODE     byte = 0xF2
	OpDELEGATECALL byte = 0xF4
	OpSTATICCALL   byte = 0xFA
	OpCREATE       byte = 0xF0
	OpCREATE2      byte = 0xF5
	OpJUMPDEST     byte = 0x5B
)

// IsCallOp 检查是否是CALL类操作码
func IsCallOp(op byte) bool {
	switch op {
	case OpCALL, OpCALLCODE, OpDELEGATECALL, OpSTATICCALL:
		return true
	default:
		return false
	}
}

// OpTypeString 返回操作码的字符串表示
func OpTypeString(op byte) string {
	switch op {
	case OpCALL:
		return "CALL"
	case OpCALLCODE:
		return "CALLCODE"
	case OpDELEGATECALL:
		return "DELEGATECALL"
	case OpSTATICCALL:
		return "STATICCALL"
	case OpCREATE:
		return "CREATE"
	case OpCREATE2:
		return "CREATE2"
	default:
		return "UNKNOWN"
	}
}
