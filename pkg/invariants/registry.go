package invariants

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// Registry 不变量注册中心
type Registry struct {
	mu                sync.RWMutex
	projects          map[string]*ProjectConfig        // projectID -> config
	contractToProject map[common.Address]string        // contract -> projectID
	invariants        map[string]map[string]*Invariant // projectID -> invariantID -> Invariant
	evaluators        map[string]EvaluatorFunc         // invariantID -> evaluator
}

// NewRegistry 创建新的注册中心
func NewRegistry() *Registry {
	return &Registry{
		projects:          make(map[string]*ProjectConfig),
		contractToProject: make(map[common.Address]string),
		invariants:        make(map[string]map[string]*Invariant),
		evaluators:        make(map[string]EvaluatorFunc),
	}
}

// LoadProjectConfig 从文件加载项目配置
func (r *Registry) LoadProjectConfig(configPath string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config ProjectConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// 注册项目
	r.projects[config.ProjectID] = &config

	// 建立合约到项目的映射
	for _, contractAddr := range config.Contracts {
		addr := common.HexToAddress(contractAddr)
		r.contractToProject[addr] = config.ProjectID
	}

	// 注册不变量
	if r.invariants[config.ProjectID] == nil {
		r.invariants[config.ProjectID] = make(map[string]*Invariant)
	}

	for i := range config.Invariants {
		inv := &config.Invariants[i]
		r.invariants[config.ProjectID][inv.ID] = inv

		// 根据类型分配默认评估器
		if inv.Evaluator == nil {
			inv.Evaluator = r.getDefaultEvaluator(inv.Type, inv.ID)
		}

		// 对于flash_change_prevention类型，使用专门的工厂函数创建评估器
		if inv.Type == FlashChangePreventionInvariant {
			inv.Evaluator = CreateFlashChangePreventionEvaluator(inv)
		}

		// 【修复】从不变量的Contracts字段中注册额外的受保护合约地址
		// 这解决了invariants中硬编码主网地址导致monitor跳过交易的问题

		// 情况1: 顶层 inv.Contracts 字段
		for _, contractAddr := range inv.Contracts {
			addr := common.HexToAddress(contractAddr)
			// 只在该地址尚未注册时才添加，避免覆盖已有的项目映射
			if _, exists := r.contractToProject[addr]; !exists {
				r.contractToProject[addr] = config.ProjectID
			}
		}

		// 情况2: parameters["contracts"] 字段（如 flash_change_prevention 类型）
		if contractsParam, ok := inv.Parameters["contracts"]; ok {
			if contractsSlice, ok := contractsParam.([]interface{}); ok {
				for _, c := range contractsSlice {
					if contractAddr, ok := c.(string); ok {
						addr := common.HexToAddress(contractAddr)
						if _, exists := r.contractToProject[addr]; !exists {
							r.contractToProject[addr] = config.ProjectID
						}
					}
				}
			}
		}
	}

	return nil
}

// RegisterEvaluator 注册不变量评估器
func (r *Registry) RegisterEvaluator(invariantID string, evaluator EvaluatorFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Register the evaluator for future loads
	r.evaluators[invariantID] = evaluator

	// Also update any already-loaded invariants that match this ID
	// so they don't keep using the previous default evaluator.
	for _, invMap := range r.invariants {
		if inv, ok := invMap[invariantID]; ok && inv != nil {
			inv.Evaluator = evaluator
		}
	}
}

// GetProjectByContract 根据合约地址获取项目配置
func (r *Registry) GetProjectByContract(contractAddr common.Address) (*ProjectConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	projectID, exists := r.contractToProject[contractAddr]
	if !exists {
		return nil, false
	}

	project, exists := r.projects[projectID]
	return project, exists
}

// GetProject 获取项目配置
func (r *Registry) GetProject(projectID string) (*ProjectConfig, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	project, exists := r.projects[projectID]
	return project, exists
}

// GetInvariants 获取项目的所有不变量
func (r *Registry) GetInvariants(projectID string) ([]*Invariant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	invMap, exists := r.invariants[projectID]
	if !exists {
		return nil, fmt.Errorf("project %s not found", projectID)
	}

	var result []*Invariant
	for _, inv := range invMap {
		result = append(result, inv)
	}
	return result, nil
}

// IsProtectedContract 检查合约是否受保护
func (r *Registry) IsProtectedContract(addr common.Address) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	_, exists := r.contractToProject[addr]
	return exists
}

// GetAllProtectedContracts 获取所有受保护的合约地址
func (r *Registry) GetAllProtectedContracts() []common.Address {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var addresses []common.Address
	for addr := range r.contractToProject {
		addresses = append(addresses, addr)
	}
	return addresses
}

// getDefaultEvaluator 获取默认评估器
func (r *Registry) getDefaultEvaluator(invType InvariantType, invariantID string) EvaluatorFunc {
	// 先检查是否有注册的评估器
	if evaluator, exists := r.evaluators[invariantID]; exists {
		return evaluator
	}

	// 返回基于类型的默认评估器
	switch invType {
	case RatioInvariant:
		return DefaultRatioEvaluator
	case ThresholdInvariant:
		return DefaultThresholdEvaluator
	case DeltaInvariant:
		return DefaultDeltaEvaluator
	default:
		return func(state *ChainState) (bool, *ViolationDetail) {
			return true, nil // 默认通过
		}
	}
}

// UpdateProjectContracts 覆盖某项目的受保护合约地址集合
func (r *Registry) UpdateProjectContracts(projectID string, contracts []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	project, ok := r.projects[projectID]
	if !ok {
		return fmt.Errorf("project %s not found", projectID)
	}

	// 移除旧映射（仅移除属于该项目的）
	for _, addrStr := range project.Contracts {
		addr := common.HexToAddress(addrStr)
		if pid, exists := r.contractToProject[addr]; exists && pid == projectID {
			delete(r.contractToProject, addr)
		}
	}

	// 设置新 contracts 并创建新映射
	project.Contracts = contracts
	for _, addrStr := range contracts {
		addr := common.HexToAddress(addrStr)
		r.contractToProject[addr] = projectID
	}

	return nil
}

// GetFuzzingTargetContracts 获取配置中定义的Fuzzing目标合约地址
// 这些是明确注入了防火墙代码的合约，应该优先被Fuzz
func (r *Registry) GetFuzzingTargetContracts() []common.Address {
	r.mu.RLock()
	defer r.mu.RUnlock()

	targetContracts := make(map[common.Address]bool)

	for _, project := range r.projects {
		if project.FuzzingConfig != nil && len(project.FuzzingConfig.TargetFunctions) > 0 {
			for _, tf := range project.FuzzingConfig.TargetFunctions {
				if tf.Contract != "" {
					addr := common.HexToAddress(tf.Contract)
					targetContracts[addr] = true
				}
			}
		}
	}

	var result []common.Address
	for addr := range targetContracts {
		result = append(result, addr)
	}
	return result
}

// HasFuzzingTargetFunction 检查合约是否是配置中定义的Fuzzing目标
func (r *Registry) HasFuzzingTargetFunction(addr common.Address) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, project := range r.projects {
		if project.FuzzingConfig != nil {
			for _, tf := range project.FuzzingConfig.TargetFunctions {
				if common.HexToAddress(tf.Contract) == addr {
					return true
				}
			}
		}
	}
	return false
}
