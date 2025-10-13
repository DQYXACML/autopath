package invariants

import (
	"fmt"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Evaluator 不变量评估器
type Evaluator struct {
	registry *Registry
}

// NewEvaluator 创建评估器
func NewEvaluator(registry *Registry) *Evaluator {
	return &Evaluator{
		registry: registry,
	}
}

// EvaluateProject 评估项目的所有不变量
func (e *Evaluator) EvaluateProject(projectID string, state *ChainState) []ViolationResult {
	invariants, err := e.registry.GetInvariants(projectID)
	if err != nil {
		return nil
	}

	log.Printf("\n 开始评估项目 %s 的 %d 个不变量...", projectID, len(invariants))
	log.Printf("   区块高度: %d, 交易: %s", state.BlockNumber, state.TxHash.Hex())

	var violations []ViolationResult
	for i, inv := range invariants {
		log.Printf("\n   [%d/%d] 检查不变量: %s (%s)", i+1, len(invariants), inv.Name, inv.ID)

		passed, detail := inv.Evaluator(state)

		if !passed {
			log.Printf("      检查失败: %s", detail.Message)
			if detail.ActualValue != nil {
				log.Printf("     实际值: %v, 期望值: %v", detail.ActualValue, detail.ExpectedValue)
			}
			violations = append(violations, ViolationResult{
				InvariantID:   inv.ID,
				InvariantName: inv.Name,
				ProjectID:     projectID,
				BlockNumber:   state.BlockNumber,
				Transaction:   state.TxHash,
				Timestamp:     state.Timestamp,
				Details:       detail,
			})
		} else {
			log.Printf("    ✅ 检查通过")
		}
	}

	if len(violations) > 0 {
		log.Printf("\n❌ 评估完成: 发现 %d 个违规", len(violations))
	} else {
		log.Printf("\n✅ 评估完成: 所有不变量检查通过")
	}

	return violations
}

// EvaluateTransaction 评估交易涉及的所有项目
func (e *Evaluator) EvaluateTransaction(contracts []common.Address, state *ChainState) []ViolationResult {
	log.Printf("\n 开始评估交易 %s 的不变量", state.TxHash.Hex())
	log.Printf("   涉及 %d 个合约地址", len(contracts))

	evaluatedProjects := make(map[string]bool)
	var allViolations []ViolationResult
	projectCount := 0

	for _, contract := range contracts {
		project, exists := e.registry.GetProjectByContract(contract)
		if !exists {
			continue
		}

		// 避免重复评估同一项目
		if evaluatedProjects[project.ProjectID] {
			continue
		}
		evaluatedProjects[project.ProjectID] = true
		projectCount++

		log.Printf("\n 评估项目 #%d: %s (合约: %s)", projectCount, project.ProjectID, contract.Hex())

		violations := e.EvaluateProject(project.ProjectID, state)
		allViolations = append(allViolations, violations...)
	}

	if projectCount == 0 {
		log.Printf("\n 没有需要评估的项目")
	} else {
		log.Printf("\n 交易评估汇总: 检查了 %d 个项目，发现 %d 个违规", projectCount, len(allViolations))
	}

	return allViolations
}

// DefaultRatioEvaluator 默认比率评估器
func DefaultRatioEvaluator(state *ChainState) (bool, *ViolationDetail) {
	// 这是一个通用的比率评估器模板
	// 实际实现需要根据具体参数进行定制
	return true, nil
}

// DefaultThresholdEvaluator 默认阈值评估器
func DefaultThresholdEvaluator(state *ChainState) (bool, *ViolationDetail) {
	// 这是一个通用的阈值评估器模板
	return true, nil
}

// DefaultDeltaEvaluator 默认变化率评估器
func DefaultDeltaEvaluator(state *ChainState) (bool, *ViolationDetail) {
	// 这是一个通用的变化率评估器模板
	return true, nil
}

// LodestarPLVGLPRatioEvaluator Lodestar sGLP/plvGLP 比率评估器
func LodestarPLVGLPRatioEvaluator(params LodestarInvariantParams) EvaluatorFunc {
	return func(state *ChainState) (bool, *ViolationDetail) {
		// 获取 depositor 地址的 sGLP 余额
		depositorAddr := common.HexToAddress(params.DepositorAddress)
		sglpAddr := common.HexToAddress(params.SGLPAddress)
		plvglpAddr := common.HexToAddress(params.PlvGLPAddress)

		// 从状态中获取 sGLP 余额（需要读取 balanceOf storage）
		sglpBalance := getERC20Balance(state, sglpAddr, depositorAddr)

		// 获取 plvGLP 总供应量
		plvglpTotalSupply := getERC20TotalSupply(state, plvglpAddr)

		// 避免除零
		if plvglpTotalSupply.Cmp(big.NewInt(0)) == 0 {
			return true, nil
		}

		// 计算比率 (使用大数运算避免精度损失)
		// ratio = sglpBalance * 1e18 / plvglpTotalSupply
		ratio := new(big.Int).Mul(sglpBalance, big.NewInt(1e18))
		ratio.Div(ratio, plvglpTotalSupply)

		// 最大比率 (转换为 big.Int)
		maxRatio := new(big.Int).SetUint64(uint64(params.MaxRatio * 1e18))

		// 检查是否超过阈值
		if ratio.Cmp(maxRatio) > 0 {
			ratioFloat := new(big.Float).SetInt(ratio)
			ratioFloat.Quo(ratioFloat, big.NewFloat(1e18))

			actualRatio, _ := ratioFloat.Float64()

			return false, &ViolationDetail{
				Message:       fmt.Sprintf("sGLP/plvGLP ratio exceeded maximum threshold"),
				ActualValue:   actualRatio,
				ExpectedValue: fmt.Sprintf("<= %.2f", params.MaxRatio),
				Metadata: map[string]interface{}{
					"sglp_balance":        sglpBalance.String(),
					"plvglp_total_supply": plvglpTotalSupply.String(),
					"depositor_address":   params.DepositorAddress,
				},
			}
		}

		return true, nil
	}
}

// getERC20Balance 从状态中获取ERC20余额
func getERC20Balance(state *ChainState, token, holder common.Address) *big.Int {
	tokenState, exists := state.States[token]
	if !exists {
		return big.NewInt(0)
	}

	// ERC20 balanceOf 存储槽计算
	// slot = keccak256(abi.encode(holder, 0)) // 假设 balances 映射在 slot 0
	slot := calculateBalanceSlot(holder, 0)

	if value, exists := tokenState.Storage[slot]; exists {
		return value.Big()
	}

	return big.NewInt(0)
}

// getERC20TotalSupply 从状态中获取ERC20总供应量
func getERC20TotalSupply(state *ChainState, token common.Address) *big.Int {
	tokenState, exists := state.States[token]
	if !exists {
		return big.NewInt(0)
	}

	// ERC20 totalSupply 通常存储在 slot 2
	totalSupplySlot := common.BigToHash(big.NewInt(2))

	if value, exists := tokenState.Storage[totalSupplySlot]; exists {
		return value.Big()
	}

	return big.NewInt(0)
}

// calculateBalanceSlot 计算余额存储槽
func calculateBalanceSlot(holder common.Address, mappingSlot uint64) common.Hash {
	// key = keccak256(abi.encode(holder, mappingSlot))
	holderPadded := common.LeftPadBytes(holder.Bytes(), 32)
	slot := new(big.Int).SetUint64(mappingSlot)
	slotPadded := common.LeftPadBytes(slot.Bytes(), 32)
	data := append(holderPadded, slotPadded...)
	return crypto.Keccak256Hash(data)
}
