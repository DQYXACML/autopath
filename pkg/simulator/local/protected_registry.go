// Package local 提供本地EVM执行器实现
package local

import (
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ProtectedRegistry 被保护合约注册中心接口
type ProtectedRegistry interface {
	// RegisterContract 注册被保护合约
	RegisterContract(info *ProtectedContractInfo) error

	// IsProtected 检查是否为被保护合约
	IsProtected(addr common.Address) bool

	// GetContractInfo 获取合约信息（含ABI、种子等）
	GetContractInfo(addr common.Address) (*ProtectedContractInfo, error)

	// GetMethod 根据选择器获取方法
	GetMethod(addr common.Address, selector [4]byte) (*abi.Method, error)

	// RegisterBatch 批量注册
	RegisterBatch(infos []*ProtectedContractInfo) error

	// GetAll 获取所有被保护合约
	GetAll() []*ProtectedContractInfo

	// Count 返回注册的合约数量
	Count() int
}

// ProtectedContractInfo 被保护合约信息
type ProtectedContractInfo struct {
	Address    common.Address         // 合约地址
	ABI        *abi.ABI               // 合约ABI
	SeedConfig *SeedConfig            // 种子配置
	Metadata   map[string]interface{} // 扩展字段
}

// protectedRegistry 被保护合约注册中心实现
type protectedRegistry struct {
	mu sync.RWMutex

	// contracts 存储合约信息：地址 → 合约信息
	contracts map[common.Address]*ProtectedContractInfo

	// selectorCache 选择器缓存：地址 → 选择器 → 方法
	// 用于快速查找方法，避免每次都遍历ABI
	selectorCache map[common.Address]map[[4]byte]*abi.Method
}

// NewProtectedRegistry 创建新的被保护合约注册中心
func NewProtectedRegistry() ProtectedRegistry {
	return &protectedRegistry{
		contracts:     make(map[common.Address]*ProtectedContractInfo),
		selectorCache: make(map[common.Address]map[[4]byte]*abi.Method),
	}
}

// RegisterContract 注册被保护合约
func (r *protectedRegistry) RegisterContract(info *ProtectedContractInfo) error {
	if info == nil {
		return fmt.Errorf("contract info cannot be nil")
	}

	if info.ABI == nil {
		return fmt.Errorf("ABI cannot be nil for contract %s", info.Address.Hex())
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// 存储合约信息
	r.contracts[info.Address] = info

	// 构建选择器缓存
	r.selectorCache[info.Address] = make(map[[4]byte]*abi.Method)
	for name := range info.ABI.Methods {
		method := info.ABI.Methods[name]
		selector := [4]byte{}
		copy(selector[:], method.ID[:4])
		r.selectorCache[info.Address][selector] = &method
	}

	return nil
}

// IsProtected 检查是否为被保护合约
func (r *protectedRegistry) IsProtected(addr common.Address) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.contracts[addr]
	return exists
}

// GetContractInfo 获取合约信息
func (r *protectedRegistry) GetContractInfo(addr common.Address) (*ProtectedContractInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	info, exists := r.contracts[addr]
	if !exists {
		return nil, fmt.Errorf("contract %s not found in registry", addr.Hex())
	}

	return info, nil
}

// GetMethod 根据选择器获取方法
func (r *protectedRegistry) GetMethod(addr common.Address, selector [4]byte) (*abi.Method, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// 检查合约是否存在
	if _, exists := r.contracts[addr]; !exists {
		return nil, fmt.Errorf("contract %s not found in registry", addr.Hex())
	}

	// 从选择器缓存中查找
	if methods, exists := r.selectorCache[addr]; exists {
		if method, ok := methods[selector]; ok {
			return method, nil
		}
	}

	return nil, fmt.Errorf("method not found for selector %x at contract %s",
		selector, addr.Hex())
}

// RegisterBatch 批量注册
func (r *protectedRegistry) RegisterBatch(infos []*ProtectedContractInfo) error {
	if len(infos) == 0 {
		return nil
	}

	// 批量注册，遇到错误继续处理其他合约
	var errors []string
	for _, info := range infos {
		if err := r.RegisterContract(info); err != nil {
			errors = append(errors, err.Error())
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("batch registration failed with %d errors: %v",
			len(errors), errors)
	}

	return nil
}

// GetAll 获取所有被保护合约
func (r *protectedRegistry) GetAll() []*ProtectedContractInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]*ProtectedContractInfo, 0, len(r.contracts))
	for _, info := range r.contracts {
		result = append(result, info)
	}

	return result
}

// Count 返回注册的合约数量
func (r *protectedRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return len(r.contracts)
}
