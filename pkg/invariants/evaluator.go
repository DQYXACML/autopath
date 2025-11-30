package invariants

import (
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"

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

	// 检测是否为模拟交易
	isSimulated := state.TxHash == (common.Hash{})

	if !isSimulated {
		// 真实交易: 打印详细日志
		log.Printf("\n 开始评估项目 %s 的 %d 个不变量...", projectID, len(invariants))
		log.Printf("   区块高度: %d, 交易: %s", state.BlockNumber, state.TxHash.Hex())
		log.Printf("   当前状态合约数: %d (示例: %s)", len(state.States), sampleContractAddresses(state.States, 6))
		log.Printf("   交易前状态合约数: %d (示例: %s)", len(state.PreviousStates), sampleContractAddresses(state.PreviousStates, 6))
	}

	var violations []ViolationResult
	for _, inv := range invariants {
		passed, detail := inv.Evaluator(state)

		if !passed {
			if !isSimulated {
				// 真实交易: 打印详细违规信息
				log.Printf("   ❌ 不变量触发: %s (%s)", inv.Name, inv.ID)
				if detail != nil {
					log.Printf("      详情: %s", detail.Message)
					if detail.ActualValue != nil {
						log.Printf("      实际值: %v, 期望值: %v", detail.ActualValue, detail.ExpectedValue)
					}
				}
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
		}
	}

	if !isSimulated {
		// 真实交易: 打印评估结果
		if len(violations) > 0 {
			log.Printf("\n❌ 评估完成: 发现 %d 个违规", len(violations))
		} else {
			log.Printf("\n✅ 评估完成: 所有不变量检查通过")
		}
	}

	return violations
}

// EvaluateTransaction 评估交易涉及的所有项目
func (e *Evaluator) EvaluateTransaction(contracts []common.Address, state *ChainState) []ViolationResult {
	// 检测是否为模拟交易(零hash)
	isSimulated := state.TxHash == (common.Hash{})

	if !isSimulated {
		// 真实交易: 打印详细日志
		log.Printf("\n 开始评估交易 %s 的不变量", state.TxHash.Hex())
		log.Printf("   涉及 %d 个合约地址", len(contracts))
	}

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

		if !isSimulated {
			// 真实交易: 打印评估项目
			log.Printf("\n 评估项目 #%d: %s (合约: %s)", projectCount, project.ProjectID, contract.Hex())
		}

		violations := e.EvaluateProject(project.ProjectID, state)
		allViolations = append(allViolations, violations...)
	}

	if !isSimulated {
		// 真实交易: 打印汇总
		if projectCount == 0 {
			log.Printf("\n 没有需要评估的项目")
		} else {
			log.Printf("\n 交易评估汇总: 检查了 %d 个项目，发现 %d 个违规", projectCount, len(allViolations))
		}
	} else if len(allViolations) > 0 {
		// 模拟交易: 只在有违规时打印简洁日志
		log.Printf("[Sim] 不变量违规 | 合约:%d | 违规:%d", len(contracts), len(allViolations))
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

// CreateFlashChangePreventionEvaluator 创建闪电变化预防评估器
// 该评估器监控指定合约的存储槽变化，检测是否超过阈值
func CreateFlashChangePreventionEvaluator(inv *Invariant) EvaluatorFunc {
	return func(state *ChainState) (bool, *ViolationDetail) {
		// 检测是否为模拟交易
		isSimulated := state.TxHash == (common.Hash{})

		// 解析参数
		params, err := parseFlashChangeParams(inv.Parameters)
		if err != nil {
			if !isSimulated {
				log.Printf("   [DEBUG] 解析flash_change_prevention参数失败: %v", err)
			}
			return true, nil // 参数错误时默认通过
		}

		if !isSimulated {
			// 真实交易: 打印详细DEBUG日志
			log.Printf("   [DEBUG] 检查 %d 个合约的闪电变化", len(params.Contracts))
			log.Printf("   [DEBUG] 全局阈值: %.2f, 配置了 %d 个存储槽", params.Threshold, len(params.Slots))
		}

		// 检查是否有配置的合约
		if len(params.Contracts) == 0 {
			if !isSimulated {
				log.Printf("   [DEBUG] 没有配置需要监控的合约")
			}
			return true, nil
		}

		// 检查是否有交易前状态
		hasPreviousStates := state.PreviousStates != nil && len(state.PreviousStates) > 0
		if !isSimulated {
			log.Printf("   [DEBUG] 是否有交易前状态: %v (数量: %d)", hasPreviousStates, len(state.PreviousStates))
		}

		// 遍历所有需要监控的合约
		for _, contractAddrStr := range params.Contracts {
			contractAddr := common.HexToAddress(contractAddrStr)
			if !isSimulated {
				log.Printf("   [DEBUG] 检查合约: %s", contractAddr.Hex())
			}

			// 获取交易后的合约状态
			currentState, currentExists := state.States[contractAddr]
			if !currentExists {
				if !isSimulated {
					log.Printf("   [DEBUG]   跳过：当前状态中没有该合约 (当前State合约数=%d, 示例: %s)", len(state.States), sampleContractAddresses(state.States, 6))
					if hasPreviousStates {
						log.Printf("   [DEBUG]   交易前State合约数=%d, 示例: %s", len(state.PreviousStates), sampleContractAddresses(state.PreviousStates, 6))
					}
				}
				continue // 状态中没有该合约，跳过
			}

			if !isSimulated {
				log.Printf("   [DEBUG]   当前状态存储槽数量: %d (示例: %s)", len(currentState.Storage), sampleSlotHashes(currentState.Storage, 8))
			}

			// 检查该合约的所有配置的存储槽
			for slotName, slotConfig := range params.Slots {
				// 将存储槽索引从十进制字符串转换为big.Int
				slotIndex := new(big.Int)
				if _, ok := slotIndex.SetString(slotConfig.Index, 10); !ok {
					if !isSimulated {
						log.Printf("   [DEBUG]   无效的存储槽索引: %s", slotConfig.Index)
					}
					continue
				}

				slotHash := common.BigToHash(slotIndex)
				if !isSimulated {
					log.Printf("   [DEBUG]   检查存储槽 %s (索引: %s, hash: %s)", slotName, slotConfig.Index, slotHash.Hex())
				}

				// 获取交易后存储槽的值
				afterValue, afterExists := currentState.Storage[slotHash]
				if !afterExists {
					if !isSimulated {
						log.Printf("   [DEBUG]     跳过：当前状态中没有该存储槽，hash=%s", slotHash.Hex())
						log.Printf("   [DEBUG]     当前槽示例: %s", sampleSlotHashes(currentState.Storage, 8))
					}
					// 【Fallback】如果配置的slot不存在，尝试监控所有storage变化
					if hasPreviousStates {
						if !isSimulated {
							log.Printf("   [DEBUG]   [Fallback] 配置的slot不存在，启用全量storage监控...")
						}
						if prevState, prevExists := state.PreviousStates[contractAddr]; prevExists {
							if !isSimulated {
								log.Printf("   [DEBUG]   [Fallback] 找到交易前状态，槽数: %d，交易后槽数: %d",
									len(prevState.Storage), len(currentState.Storage))
								log.Printf("   [DEBUG]   [Fallback] 交易前槽示例: %s", sampleSlotHashes(prevState.Storage, 8))
								log.Printf("   [DEBUG]   [Fallback] 交易后槽示例: %s", sampleSlotHashes(currentState.Storage, 8))
							}

							slotChecked := 0
							slotSkippedNoChange := 0
							slotSkippedNew := 0
							slotSkippedZero := 0

							// 遍历交易后的所有storage slot
							for slot, afterVal := range currentState.Storage {
								slotChecked++
								beforeVal, beforeExists := prevState.Storage[slot]
								if !beforeExists {
									slotSkippedNew++
									continue // 交易前不存在的slot，跳过（可能是新增slot）
								}

								beforeBig := beforeVal.Big()
								afterBig := afterVal.Big()

								// ✅ 修复：对于零值，使用绝对值阈值检测
								if beforeBig.Cmp(big.NewInt(0)) == 0 {
									// 从0变化到非零：检查绝对值是否显著
									// 使用一个合理的绝对值阈值（如 1e18，即1个ETH/Token单位）
									absThreshold := new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)

									if afterBig.Cmp(absThreshold) > 0 {
										// 从0变化到显著的非零值，判定为违规
										if !isSimulated {
											log.Printf("   [DEBUG]   [Fallback] ❌ 检测到违规！slot %s从0变化到%s (>= 1e18阈值)",
												slot.Hex(), afterBig.String())
										}
										return false, &ViolationDetail{
											Message: fmt.Sprintf("Storage slot %s of contract %s changed from 0 to %s (abs threshold: 1e18) [Fallback全量监控-零值检测]",
												slot.Hex(), contractAddr.Hex(), afterBig.String()),
											ActualValue:   afterBig.String(),
											ExpectedValue: "< 1e18 when starting from 0",
										}
									}
									slotSkippedZero++
									continue
								}

								// 检查是否有变化
								if beforeBig.Cmp(afterBig) == 0 {
									slotSkippedNoChange++
									continue // 值没有变化
								}

								// 计算变化率
								delta := new(big.Int).Sub(afterBig, beforeBig)
								delta.Abs(delta)

								deltaFloat := new(big.Float).SetInt(delta)
								beforeFloat := new(big.Float).SetInt(beforeBig)
								ratio := new(big.Float).Quo(deltaFloat, beforeFloat)
								changeRate, _ := ratio.Float64()

								if !isSimulated {
									log.Printf("   [DEBUG]   [Fallback] slot %s: before=%s, after=%s, 变化率=%.4f",
										slot.Hex()[:10], beforeBig.String(), afterBig.String(), changeRate)
								}

								// 使用配置的阈值检查
								threshold := params.Threshold
								if changeRate > threshold {
									if !isSimulated {
										log.Printf("   [DEBUG]   [Fallback] ❌ 检测到违规！slot %s 变化率 %.2f%% > 阈值 %.2f%%",
											slot.Hex(), changeRate*100, threshold*100)
									}
									return false, &ViolationDetail{
										Message: fmt.Sprintf("Storage slot %s of contract %s changed by %.2f%% (threshold: %.2f%%) [Fallback全量监控]",
											slot.Hex(), contractAddr.Hex(), changeRate*100, threshold*100),
										ActualValue:   fmt.Sprintf("%.2f%%", changeRate*100),
										ExpectedValue: fmt.Sprintf("<= %.2f%%", threshold*100),
										Metadata: map[string]interface{}{
											"contract":         contractAddr.Hex(),
											"slot_hash":        slot.Hex(),
											"before_value":     beforeBig.String(),
											"after_value":      afterBig.String(),
											"change_rate":      changeRate,
											"threshold":        threshold,
											"detection_method": "fallback_full_scan",
										},
									}
								}
							}
							if !isSimulated {
								log.Printf("   [DEBUG]   [Fallback] 扫描统计: 检查%d个slot, 跳过%d个(无变化), %d个(新增), %d个(零值)",
									slotChecked, slotSkippedNoChange, slotSkippedNew, slotSkippedZero)
								log.Printf("   [DEBUG]   [Fallback] 全量监控完成，未检测到违规")
							}
						} else {
							if !isSimulated {
								log.Printf("   [DEBUG]   [Fallback] 警告: 交易前状态中没有该合约! 交易前可用合约示例: %s", sampleContractAddresses(state.PreviousStates, 6))
							}
						}
					} else {
						if !isSimulated {
							log.Printf("   [DEBUG]   [Fallback] 警告: 没有交易前状态数据!")
						}
					}
					continue // 继续检查下一个配置的slot
				}

				afterBig := afterValue.Big()
				if !isSimulated {
					log.Printf("   [DEBUG]     交易后值: %s", afterBig.String())
				}

				// 尝试获取交易前的值
				var beforeBig *big.Int
				if state.PreviousStates != nil {
					if prevState, prevExists := state.PreviousStates[contractAddr]; prevExists {
						if !isSimulated {
							log.Printf("   [DEBUG]     找到交易前状态，存储槽数量: %d", len(prevState.Storage))
						}
						if beforeValue, beforeExists := prevState.Storage[slotHash]; beforeExists {
							beforeBig = beforeValue.Big()
							if !isSimulated {
								log.Printf("   [DEBUG]     交易前值: %s", beforeBig.String())
							}
						} else {
							if !isSimulated {
								log.Printf("   [DEBUG]     交易前状态中没有该存储槽，hash=%s", slotHash.Hex())
								log.Printf("   [DEBUG]     交易前槽示例: %s", sampleSlotHashes(prevState.Storage, 8))
							}
						}
					} else {
						if !isSimulated {
							log.Printf("   [DEBUG]     交易前状态中没有该合约，交易前可用合约示例: %s", sampleContractAddresses(state.PreviousStates, 6))
						}
					}
				}

				// 如果有交易前的值，计算变化率
				if beforeBig != nil && beforeBig.Cmp(big.NewInt(0)) != 0 {
					// 获取阈值（优先使用slot配置，否则使用全局阈值）
					threshold := slotConfig.Threshold
					if threshold == 0 {
						threshold = params.Threshold
					}

					if !isSimulated {
						log.Printf("   [DEBUG]     阈值: %.2f (%.2f%%)", threshold, threshold*100)
					}

					// ===== 通用Packed Storage检测 =====
					// 自动检测并处理Uniswap V2/V3等packed storage
					detector, ok := DetectPackedStorage(afterBig)
					if ok {
						if !isSimulated {
							log.Printf("   [DEBUG]   使用 %s 检测器", detector.GetType())
						}

						// 使用对应检测器的CheckChange方法
						passed, violation := detector.CheckChange(beforeBig, afterBig, threshold)

						if !passed {
							if !isSimulated {
								log.Printf("   [DEBUG]     ❌ Packed storage检测到违规！")
							}
							return false, violation
						}

						if !isSimulated {
							log.Printf("   [DEBUG]     ✅ Packed storage变化在阈值内")
						}
						continue // 跳过下面的普通检测逻辑
					}
					// ===== 普通slot检测逻辑 =====

					// 计算变化率: |after - before| / before
					delta := new(big.Int).Sub(afterBig, beforeBig)
					delta.Abs(delta) // 取绝对值

					// 转换为浮点数计算比率
					deltaFloat := new(big.Float).SetInt(delta)
					beforeFloat := new(big.Float).SetInt(beforeBig)

					ratio := new(big.Float).Quo(deltaFloat, beforeFloat)
					changeRate, _ := ratio.Float64()

					if !isSimulated {
						log.Printf("   [DEBUG]     变化率: %.4f (%.2f%%)", changeRate, changeRate*100)
					}

					// 检查是否超过阈值
					if changeRate > threshold {
						if !isSimulated {
							log.Printf("   [DEBUG]     ❌ 检测到违规！变化率 %.2f%% > 阈值 %.2f%%", changeRate*100, threshold*100)
						}
						return false, &ViolationDetail{
							Message: fmt.Sprintf("Storage slot %s of contract %s changed by %.2f%% (threshold: %.2f%%)",
								slotName, contractAddr.Hex(), changeRate*100, threshold*100),
							ActualValue:   fmt.Sprintf("%.2f%%", changeRate*100),
							ExpectedValue: fmt.Sprintf("<= %.2f%%", threshold*100),
							Metadata: map[string]interface{}{
								"contract":     contractAddr.Hex(),
								"slot_name":    slotName,
								"slot_index":   slotConfig.Index,
								"before_value": beforeBig.String(),
								"after_value":  afterBig.String(),
								"change_rate":  changeRate,
								"threshold":    threshold,
								"severity":     slotConfig.Severity,
							},
						}
					} else {
						if !isSimulated {
							log.Printf("   [DEBUG]     ✅ 变化在阈值内")
						}
					}
				} else {
					if !isSimulated {
						log.Printf("   [DEBUG]     没有有效的交易前值用于比较")
					}
					// 没有交易前的值，使用简化检测：检查值是否为0或异常大
					if afterBig.Cmp(big.NewInt(0)) == 0 && beforeBig != nil && beforeBig.Cmp(big.NewInt(0)) > 0 {
						// 值被清零可能表明资金被完全提取
						if !isSimulated {
							log.Printf("   [DEBUG]     ❌ 检测到违规！存储槽被清零")
						}
						return false, &ViolationDetail{
							Message: fmt.Sprintf("Storage slot %s of contract %s was drained to zero",
								slotName, contractAddr.Hex()),
							ActualValue:   "0",
							ExpectedValue: "> 0",
							Metadata: map[string]interface{}{
								"contract":     contractAddr.Hex(),
								"slot_name":    slotName,
								"slot_index":   slotConfig.Index,
								"before_value": beforeBig.String(),
								"after_value":  "0",
								"threshold":    slotConfig.Threshold,
								"severity":     slotConfig.Severity,
							},
						}
					}
				}
			}
		}

		if !isSimulated {
			log.Printf("   [DEBUG] 所有检查通过，未检测到违规")
		}
		return true, nil
	}
}

// parseFlashChangeParams 解析闪电变化预防参数
func parseFlashChangeParams(params map[string]interface{}) (*FlashChangePreventionParams, error) {
	// 使用JSON编码/解码来转换map到结构体
	jsonData, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params failed: %w", err)
	}

	var result FlashChangePreventionParams
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return nil, fmt.Errorf("unmarshal params failed: %w", err)
	}

	return &result, nil
}

// sampleContractAddresses 提供合约地址样本，便于在日志中快速定位缺失原因
func sampleContractAddresses(states map[common.Address]*ContractState, limit int) string {
	if len(states) == 0 {
		return "空"
	}
	if limit <= 0 {
		limit = 5
	}

	entries := make([]string, 0, limit+1)
	count := 0
	for addr := range states {
		entries = append(entries, addr.Hex())
		count++
		if count >= limit {
			break
		}
	}
	if len(states) > limit {
		entries = append(entries, fmt.Sprintf("...+%d", len(states)-limit))
	}
	return strings.Join(entries, ", ")
}

// sampleSlotHashes 提供存储槽哈希样本，辅助排查slot缺失
func sampleSlotHashes(storage map[common.Hash]common.Hash, limit int) string {
	if len(storage) == 0 {
		return "空"
	}
	if limit <= 0 {
		limit = 5
	}

	entries := make([]string, 0, limit+1)
	count := 0
	for slot := range storage {
		hash := slot.Hex()
		if len(hash) > 12 {
			hash = hash[:12] + "..."
		}
		entries = append(entries, hash)
		count++
		if count >= limit {
			break
		}
	}
	if len(storage) > limit {
		entries = append(entries, fmt.Sprintf("...+%d", len(storage)-limit))
	}
	return strings.Join(entries, ", ")
}
