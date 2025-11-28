// Package local 提供本地EVM执行器实现
package local

import (
	"sync"

	"github.com/ethereum/go-ethereum/core/tracing"
)

// TraceCollector 收集执行路径中的JUMPDEST
type TraceCollector struct {
	mu        sync.Mutex
	jumpDests []ContractJumpDest
	enabled   bool
}

// NewTraceCollector 创建新的TraceCollector
func NewTraceCollector() *TraceCollector {
	return &TraceCollector{
		jumpDests: make([]ContractJumpDest, 0, 1000), // 预分配空间
		enabled:   true,
	}
}

// SetEnabled 设置是否启用收集
func (t *TraceCollector) SetEnabled(enabled bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = enabled
}

// Reset 重置收集器
func (t *TraceCollector) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.jumpDests = t.jumpDests[:0]
}

// OnOpcode 实现tracing.Hooks.OnOpcode回调
// 在每个操作码执行时被调用
func (t *TraceCollector) OnOpcode(pc uint64, op byte, gas, cost uint64,
	scope tracing.OpContext, rData []byte, depth int, err error) {

	if !t.enabled {
		return
	}

	// 只记录JUMPDEST操作码 (0x5B)
	if op == OpJUMPDEST {
		contractAddr := ""
		if scope != nil {
			contractAddr = scope.Address().Hex()
		}
		t.mu.Lock()
		t.jumpDests = append(t.jumpDests, ContractJumpDest{
			Contract: contractAddr,
			PC:       pc,
		})
		t.mu.Unlock()
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
