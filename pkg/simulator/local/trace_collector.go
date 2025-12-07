// Package local 提供本地EVM执行器实现
package local

import (
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
)

// TraceCollector 收集执行路径中的JUMPDEST
type TraceCollector struct {
	mu        sync.Mutex
	jumpDests []ContractJumpDest
	enabled   bool
	protected map[string]bool // 需要从哪个合约开始记录
	recording bool            // 是否已经触发记录
}

// NewTraceCollector 创建新的TraceCollector
func NewTraceCollector() *TraceCollector {
	tc := &TraceCollector{
		jumpDests: make([]ContractJumpDest, 0, 1000), // 预分配空间
		enabled:   true,
	}
	tc.ResetWithProtected(nil)
	return tc
}

// SetEnabled 设置是否启用收集
func (t *TraceCollector) SetEnabled(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = enabled
}

// Reset 重置收集器
func (t *TraceCollector) Reset() {
	t.ResetWithProtected(nil)
}

// ResetWithProtected 重置并配置受保护合约，只有命中后才开始记录
func (t *TraceCollector) ResetWithProtected(addrs []common.Address) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.jumpDests = t.jumpDests[:0]
	if len(addrs) == 0 {
		t.protected = nil
		t.recording = true // 无过滤时立即记录
		return
	}

	t.protected = make(map[string]bool, len(addrs))
	for _, addr := range addrs {
		if addr == (common.Address{}) {
			continue
		}
		t.protected[strings.ToLower(addr.Hex())] = true
	}
	t.recording = false
}

// OnOpcode 实现tracing.Hooks.OnOpcode回调
// 在每个操作码执行时被调用
func (t *TraceCollector) OnOpcode(pc uint64, op byte, gas, cost uint64,
	scope tracing.OpContext, rData []byte, depth int, err error) {

	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// 若配置了受保护合约，则在命中前不记录
	if len(t.protected) > 0 && !t.recording {
		if scope != nil {
			addr := strings.ToLower(scope.Address().Hex())
			if t.protected[addr] {
				t.recording = true
			}
		}
		if !t.recording {
			return
		}
	}

	// 只记录JUMPDEST操作码 (0x5B)
	if op == OpJUMPDEST {
		contractAddr := ""
		if scope != nil {
			contractAddr = scope.Address().Hex()
		}
		t.jumpDests = append(t.jumpDests, ContractJumpDest{
			Contract: contractAddr,
			PC:       pc,
		})
	}
}

// GetContractJumpDests 返回收集的JUMPDEST序列（深拷贝）
func (t *TraceCollector) GetContractJumpDests() []ContractJumpDest {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]ContractJumpDest, len(t.jumpDests))
	copy(result, t.jumpDests)
	return result
}

// GetJumpDestsCount 返回收集的JUMPDEST数量
func (t *TraceCollector) GetJumpDestsCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.jumpDests)
}

// GetPlainJumpDests 返回只包含PC的序列（向后兼容）
func (t *TraceCollector) GetPlainJumpDests() []uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := make([]uint64, len(t.jumpDests))
	for i, jd := range t.jumpDests {
		result[i] = jd.PC
	}
	return result
}
