// Package local 提供本地EVM执行器实现
package local

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/vm"
)

// DelegateContext 记录delegatecall上下文
type DelegateContext struct {
	ProxyAddress       common.Address // 代理合约地址
	ImplementationAddr common.Address // 实现合约地址
	Depth              int            // 调用深度
}

// TraceCollector 收集执行路径中的JUMPDEST
type TraceCollector struct {
	mu        sync.Mutex
	jumpDests []ContractJumpDest
	enabled   bool
	protected map[string]bool // 需要从哪个合约开始记录
	recording bool            // 是否已经触发记录

	// Delegatecall上下文追踪
	delegateStack    []DelegateContext                 // 追踪delegatecall调用链
	stateDB          vm.StateDB                        // 访问状态数据库（读取storage）
	implCache        map[common.Address]common.Address // 代理→实现地址缓存
	lastImplReported map[common.Address]common.Address // 仅在实现地址变化时输出日志
	delegateLogCache map[common.Address]common.Address // 仅在delegatecall实现变化时输出日志
}

// NewTraceCollector 创建新的TraceCollector
func NewTraceCollector() *TraceCollector {
	tc := &TraceCollector{
		jumpDests:        make([]ContractJumpDest, 0, 1000), // 预分配空间
		enabled:          true,
		delegateStack:    make([]DelegateContext, 0, 10), // 预分配delegatecall栈
		implCache:        make(map[common.Address]common.Address),
		lastImplReported: make(map[common.Address]common.Address),
		delegateLogCache: make(map[common.Address]common.Address),
	}
	tc.ResetWithProtected(nil)
	return tc
}

// NewTraceCollectorWithStateDB 创建新的TraceCollector（支持delegatecall追踪）
func NewTraceCollectorWithStateDB(stateDB vm.StateDB) *TraceCollector {
	tc := NewTraceCollector()
	tc.stateDB = stateDB
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
	t.lastImplReported = make(map[common.Address]common.Address)
	t.delegateLogCache = make(map[common.Address]common.Address)
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
			scopeAddr := scope.Address()

			// 检测delegatecall上下文，获取实际执行合约地址
			actualAddr := t.GetCurrentImplementation(scopeAddr)
			contractAddr = actualAddr.Hex()
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

// EIP-1967实现槽位
const EIP1967ImplementationSlot = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"

// PushDelegateContext 进入delegatecall时调用（需持锁调用）
func (t *TraceCollector) PushDelegateContext(proxy, impl common.Address, depth int) {
	t.delegateStack = append(t.delegateStack, DelegateContext{
		ProxyAddress:       proxy,
		ImplementationAddr: impl,
		Depth:              depth,
	})
	// 更新缓存
	t.implCache[proxy] = impl
}

// PopDelegateContext 退出delegatecall时调用（需持锁调用）
func (t *TraceCollector) PopDelegateContext() {
	if len(t.delegateStack) > 0 {
		t.delegateStack = t.delegateStack[:len(t.delegateStack)-1]
	}
}

// GetCurrentImplementation 获取当前执行的实际合约地址
// 如果在delegatecall中，返回实现合约地址；否则返回scope地址
// 注意：此方法假定已持有锁
func (t *TraceCollector) GetCurrentImplementation(scopeAddr common.Address) common.Address {
	shouldLog := func(impl common.Address) bool {
		prev, ok := t.lastImplReported[scopeAddr]
		if ok && prev == impl {
			return false
		}
		t.lastImplReported[scopeAddr] = impl
		return true
	}
	// 如果有delegatecall上下文栈，检查是否匹配
	if len(t.delegateStack) > 0 {
		// 从栈顶向下查找匹配的代理地址
		for i := len(t.delegateStack) - 1; i >= 0; i-- {
			ctx := t.delegateStack[i]
			if strings.EqualFold(ctx.ProxyAddress.Hex(), scopeAddr.Hex()) {
				// 找到匹配的代理，返回实现地址
				if shouldLog(ctx.ImplementationAddr) {
					log.Printf("[TraceCollector] GetCurrentImplementation: 从delegatecall栈匹配到代理 %s -> 实现 %s", scopeAddr.Hex(), ctx.ImplementationAddr.Hex())
				}
				return ctx.ImplementationAddr
			}
		}
	}

	// 否则尝试从缓存中查找
	if impl, ok := t.implCache[scopeAddr]; ok {
		if shouldLog(impl) {
			log.Printf("[TraceCollector] GetCurrentImplementation: 从缓存匹配到代理 %s -> 实现 %s", scopeAddr.Hex(), impl.Hex())
		}
		return impl
	}

	// 默认返回scope地址（非代理合约）
	if shouldLog(scopeAddr) {
		log.Printf("[TraceCollector] GetCurrentImplementation: 返回原始地址 %s", scopeAddr.Hex())
	}
	return scopeAddr
}

// ResolveImplementation 解析EIP-1967代理的实现合约地址
func (t *TraceCollector) ResolveImplementation(proxyAddr common.Address) (common.Address, error) {
	// 先检查缓存
	if impl, ok := t.implCache[proxyAddr]; ok {
		return impl, nil
	}

	if t.stateDB == nil {
		return common.Address{}, errors.New("stateDB not available")
	}

	// 读取EIP-1967实现槽位
	slotHash := common.HexToHash(EIP1967ImplementationSlot)
	implValue := t.stateDB.GetState(proxyAddr, slotHash)
	log.Printf("[TraceCollector] ResolveImplementation: 读取槽位 %s 对于代理 %s, 值=%s", EIP1967ImplementationSlot, proxyAddr.Hex(), implValue.Hex())

	// 提取地址（后20字节）
	implAddr := common.BytesToAddress(implValue.Bytes())
	log.Printf("[TraceCollector] ResolveImplementation: 提取实现地址 %s", implAddr.Hex())

	// 验证实现地址非零
	if implAddr == (common.Address{}) {
		return common.Address{}, fmt.Errorf("proxy %s has zero implementation address", proxyAddr.Hex())
	}

	// 验证实现地址是否有代码
	codeLen := len(t.stateDB.GetCode(implAddr))
	log.Printf("[TraceCollector] ResolveImplementation: 实现地址 %s 代码长度=%d", implAddr.Hex(), codeLen)
	if codeLen == 0 {
		return common.Address{}, fmt.Errorf("implementation %s has no code", implAddr.Hex())
	}

	// 缓存结果
	t.implCache[proxyAddr] = implAddr
	log.Printf("[TraceCollector] ResolveImplementation: ✓ 成功解析并缓存 %s -> %s", proxyAddr.Hex(), implAddr.Hex())

	return implAddr, nil
}

// OnEnter 实现tracing.Hooks.OnEnter回调
// 在进入CALL类操作时被调用
func (t *TraceCollector) OnEnter(depth int, typ byte, from common.Address,
	to common.Address, input []byte, gas uint64, value *big.Int) {

	if !t.enabled {
		return
	}

	// 只处理DELEGATECALL
	if typ != OpDELEGATECALL {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// DELEGATECALL的语义：
	// - from: 代理合约地址（当前执行环境）
	// - to: 实现合约地址（目标代码地址）
	// 无需解析，直接记录映射关系
	if prevImpl, ok := t.delegateLogCache[from]; ok && prevImpl == to {
		t.PushDelegateContext(from, to, depth)
		return
	}
	log.Printf("[TraceCollector] OnEnter DELEGATECALL: 代理=%s -> 实现=%s (depth=%d)", from.Hex(), to.Hex(), depth)
	t.PushDelegateContext(from, to, depth)
	t.delegateLogCache[from] = to
}

// OnExit 实现tracing.Hooks.OnExit回调
// 在退出CALL类操作时被调用
func (t *TraceCollector) OnExit(depth int, output []byte, gasUsed uint64,
	err error, reverted bool) {

	if !t.enabled {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	// 如果深度减少，弹出delegatecall栈
	// 注意：depth是退出后的深度，所以我们需要弹出深度>depth的上下文
	for len(t.delegateStack) > 0 {
		topCtx := t.delegateStack[len(t.delegateStack)-1]
		if topCtx.Depth > depth {
			t.PopDelegateContext()
		} else {
			break
		}
	}
}
