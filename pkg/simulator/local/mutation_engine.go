// Package local 提供本地EVM执行器实现
package local

import (
	"fmt"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// MutationEngine 参数变异引擎接口
type MutationEngine interface {
	// DecodeCalldata 解码calldata
	DecodeCalldata(
		method *abi.Method,
		calldata []byte,
	) ([]interface{}, error)

	// EncodeParams 编码参数
	EncodeParams(
		method *abi.Method,
		args []interface{},
	) ([]byte, error)

	// MutateCalldata 变异calldata（使用参数池）
	MutateCalldata(
		method *abi.Method,
		originalCalldata []byte,
		pooledParams []interface{},
	) ([]byte, error)

	// RegisterStrategy 注册策略
	RegisterStrategy(strategy MutationStrategy)

	// GetStrategies 获取所有已注册的策略
	GetStrategies() []MutationStrategy

	// UpdateHistory 更新变异历史
	UpdateHistory(methodSig string, similarity float64, success bool)

	// GetHistory 获取变异历史
	GetHistory(methodSig string) *MutationHistory
}

// MutationStrategy 变异策略接口
type MutationStrategy interface {
	// Name 策略名称
	Name() string

	// Applicable 判断是否适用于该类型
	Applicable(paramType abi.Type) bool

	// GenerateVariations 生成变异值（批量）
	GenerateVariations(
		original interface{},
		paramType abi.Type,
		count int,
	) ([]interface{}, error)

	// Priority 优先级（用于策略选择）
	Priority() int
}

// MutationHistory 变异历史记录
type MutationHistory struct {
	TotalAttempts int     // 总尝试次数
	SuccessCount  int     // 成功次数（高相似度）
	AvgSimilarity float64 // 平均相似度
	BestSimilarity float64 // 最佳相似度
}

// mutationEngine 变异引擎实现
type mutationEngine struct {
	mu sync.RWMutex

	// strategies 已注册的策略列表（按优先级排序）
	strategies []MutationStrategy

	// history 变异历史：方法签名 → 历史记录
	history map[string]*MutationHistory
}

// NewMutationEngine 创建新的变异引擎
func NewMutationEngine() MutationEngine {
	return &mutationEngine{
		strategies: make([]MutationStrategy, 0),
		history:    make(map[string]*MutationHistory),
	}
}

// DecodeCalldata 解码calldata
func (e *mutationEngine) DecodeCalldata(
	method *abi.Method,
	calldata []byte,
) ([]interface{}, error) {
	if method == nil {
		return nil, fmt.Errorf("method cannot be nil")
	}

	if len(calldata) < 4 {
		return nil, fmt.Errorf("calldata too short: %d bytes", len(calldata))
	}

	// 跳过前4字节的函数选择器
	paramData := calldata[4:]

	// 使用ABI解码参数
	args, err := method.Inputs.Unpack(paramData)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack params: %w", err)
	}

	return args, nil
}

// EncodeParams 编码参数
func (e *mutationEngine) EncodeParams(
	method *abi.Method,
	args []interface{},
) ([]byte, error) {
	if method == nil {
		return nil, fmt.Errorf("method cannot be nil")
	}

	// 使用ABI编码参数
	packed, err := method.Inputs.Pack(args...)
	if err != nil {
		return nil, fmt.Errorf("failed to pack params: %w", err)
	}

	return packed, nil
}

// MutateCalldata 变异calldata（使用参数池中的预生成参数）
func (e *mutationEngine) MutateCalldata(
	method *abi.Method,
	originalCalldata []byte,
	pooledParams []interface{},
) ([]byte, error) {
	if method == nil {
		return nil, fmt.Errorf("method cannot be nil")
	}

	if len(originalCalldata) < 4 {
		return nil, fmt.Errorf("calldata too short: %d bytes", len(originalCalldata))
	}

	// 提取函数选择器（前4字节）
	selector := originalCalldata[:4]

	// 直接使用池中的参数，无需再次变异
	// 编码参数
	packed, err := e.EncodeParams(method, pooledParams)
	if err != nil {
		return nil, err
	}

	// 组合选择器和编码后的参数
	result := make([]byte, 4+len(packed))
	copy(result[:4], selector)
	copy(result[4:], packed)

	return result, nil
}

// RegisterStrategy 注册策略
func (e *mutationEngine) RegisterStrategy(strategy MutationStrategy) {
	if strategy == nil {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.strategies = append(e.strategies, strategy)

	// 按优先级排序（从高到低）
	sort.Slice(e.strategies, func(i, j int) bool {
		return e.strategies[i].Priority() > e.strategies[j].Priority()
	})
}

// GetStrategies 获取所有已注册的策略
func (e *mutationEngine) GetStrategies() []MutationStrategy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 返回副本
	result := make([]MutationStrategy, len(e.strategies))
	copy(result, e.strategies)
	return result
}

// UpdateHistory 更新变异历史
func (e *mutationEngine) UpdateHistory(methodSig string, similarity float64, success bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	history, exists := e.history[methodSig]
	if !exists {
		history = &MutationHistory{}
		e.history[methodSig] = history
	}

	history.TotalAttempts++
	if success {
		history.SuccessCount++
	}

	// 更新平均相似度（累积平均）
	if history.TotalAttempts == 1 {
		history.AvgSimilarity = similarity
	} else {
		history.AvgSimilarity = (history.AvgSimilarity*float64(history.TotalAttempts-1) + similarity) /
			float64(history.TotalAttempts)
	}

	// 更新最佳相似度
	if similarity > history.BestSimilarity {
		history.BestSimilarity = similarity
	}
}

// GetHistory 获取变异历史
func (e *mutationEngine) GetHistory(methodSig string) *MutationHistory {
	e.mu.RLock()
	defer e.mu.RUnlock()

	history, exists := e.history[methodSig]
	if !exists {
		return nil
	}

	// 返回副本
	return &MutationHistory{
		TotalAttempts:  history.TotalAttempts,
		SuccessCount:   history.SuccessCount,
		AvgSimilarity:  history.AvgSimilarity,
		BestSimilarity: history.BestSimilarity,
	}
}
