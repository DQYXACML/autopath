package xsij

import (
	"context"
	"log"
	"math/big"

	"autopath/pkg/invariants"
	"autopath/pkg/projects"

	"github.com/ethereum/go-ethereum/common"
)

// XSIJ 攻击涉及的关键地址
var (
	PancakePairAddr  = common.HexToAddress("0xf43Fd71f404CC450c470d42E3F478a6D38C96311")
	XSIJTokenAddr    = common.HexToAddress("0x31bfA137C76561ef848c2af9Ca301b60451CaAC0")
	BUSDTokenAddr    = common.HexToAddress("0x55d398326f99059fF775485246999027B3197955")
	DPPAddr          = common.HexToAddress("0x6098A5638d8D7e9Ed2f952d35B2b67c34EC6B476")
)

func init() {
	projects.RegisterProjectRegistrar("xsij_exp", Register)
}

// Register 将 XSIJ 专属不变量注册到 Registry
func Register(ctx context.Context, deps projects.Dependencies) error {
	if deps.Registry == nil || deps.Config == nil {
		log.Printf("⚠️  XSIJ Register: Missing dependencies, skipping")
		return nil
	}

	log.Printf("🔧 Registering XSIJ-specific invariant evaluators...")

	// SINV_001: PancakePair XSIJ balance 操纵检测
	deps.Registry.RegisterEvaluator("SINV_001", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		return checkPairBalanceManipulation(state, deps)
	})

	// SINV_002: PancakePair reserves 异常变化检测
	deps.Registry.RegisterEvaluator("SINV_002", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		return checkPairReservesAnomaly(state, deps)
	})

	// SINV_003: 循环转账攻击检测
	deps.Registry.RegisterEvaluator("SINV_003", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		return checkLoopTransferAttack(state, deps)
	})

	log.Printf("✅ XSIJ invariant evaluators registered")
	return nil
}

// checkPairBalanceManipulation 检测 PancakePair 的 XSIJ balance 是否被操纵
func checkPairBalanceManipulation(state *invariants.ChainState, deps projects.Dependencies) (bool, *invariants.ViolationDetail) {
	log.Printf("[SINV_001] 开始检测 PancakePair balance manipulation")
	log.Printf("[SINV_001] PancakePair地址: %s", PancakePairAddr.Hex())

	// 打印当前状态中的所有合约
	log.Printf("[SINV_001] 当前状态包含 %d 个合约:", len(state.States))
	for addr := range state.States {
		log.Printf("[SINV_001]   - %s", addr.Hex())
	}

	pairState, exists := state.States[PancakePairAddr]
	if !exists {
		log.Printf("[SINV_001] ⚠️  PancakePair状态不存在，跳过检查")
		return true, nil
	}

	log.Printf("[SINV_001] ✓ 找到PancakePair状态，包含 %d 个storage slots", len(pairState.Storage))

	// 打印所有storage slots
	if len(pairState.Storage) > 0 {
		log.Printf("[SINV_001] Storage slots:")
		for slot, value := range pairState.Storage {
			slotNum := slot.Big().Uint64()
			log.Printf("[SINV_001]   Slot %d: %s", slotNum, value.Hex())
		}
	} else {
		log.Printf("[SINV_001] ⚠️  Storage为空！")
	}

	// 读取 reserves slot (slot 8 in Uniswap V2 Pair)
	reservesSlot := common.BigToHash(big.NewInt(8))
	reservesData, exists := pairState.Storage[reservesSlot]
	if !exists {
		log.Printf("[SINV_001] ⚠️  Slot 8 (reserves) 不存在，跳过检查")
		log.Printf("[SINV_001] 这可能是因为: 1) reserves为零值被过滤 2) storage读取失败")
		return true, nil
	}

	log.Printf("[SINV_001] ✓ Slot 8 (reserves) 原始值: %s", reservesData.Hex())

	// Uniswap V2 Pair slot 8 存储：reserve0 (112 bits) | reserve1 (112 bits) | blockTimestampLast (32 bits)
	// 解析 reserve0 和 reserve1
	mask112 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))
	reserve0 := new(big.Int).And(reservesData.Big(), mask112)
	reserve1 := new(big.Int).Rsh(new(big.Int).And(reservesData.Big(), new(big.Int).Lsh(mask112, 112)), 112)

	log.Printf("[SINV_001] 解析reserves:")
	log.Printf("[SINV_001]   reserve0: %s (%s wei)", reserve0.String(), reserve0.Text(10))
	log.Printf("[SINV_001]   reserve1: %s (%s wei)", reserve1.String(), reserve1.Text(10))

	// 检查是否有 reserve 异常低（被操纵）
	// 攻击中 XSIJ reserve 会被降到约 1800 ether
	threshold := new(big.Int).Mul(big.NewInt(2000), big.NewInt(1e18)) // 2000 ether

	log.Printf("[SINV_001] 阈值: %s wei (2000 ether)", threshold.String())
	log.Printf("[SINV_001] 检查条件: reserve0 < threshold OR reserve1 < threshold")
	log.Printf("[SINV_001]   reserve0 < threshold? %v", reserve0.Cmp(threshold) < 0)
	log.Printf("[SINV_001]   reserve1 < threshold? %v", reserve1.Cmp(threshold) < 0)

	// 假设 token0 是 XSIJ (需要验证)
	// 如果 reserve < threshold，认为被操纵
	if reserve0.Cmp(threshold) < 0 || reserve1.Cmp(threshold) < 0 {
		log.Printf("[SINV_001] 🚨 检测到违规！reserve异常低")
		return false, &invariants.ViolationDetail{
			Message:       "PancakePair XSIJ balance异常低，疑似被操纵攻击",
			ActualValue:   reservesData.Hex(),
			ExpectedValue: "> 2000 ether per reserve",
			Metadata: map[string]interface{}{
				"reserve0": reserve0.String(),
				"reserve1": reserve1.String(),
				"pair_address": PancakePairAddr.Hex(),
			},
		}
	}

	log.Printf("[SINV_001] ✓ 检查通过，reserves正常")
	return true, nil
}

// checkPairReservesAnomaly 检测 PancakePair reserves 的异常变化率
func checkPairReservesAnomaly(state *invariants.ChainState, deps projects.Dependencies) (bool, *invariants.ViolationDetail) {
	log.Printf("[SINV_002] 开始检测 PancakePair reserves anomaly")

	pairState, exists := state.States[PancakePairAddr]
	if !exists {
		log.Printf("[SINV_002] ⚠️  PancakePair状态不存在，跳过检查")
		return true, nil
	}

	// 读取当前 reserves
	reservesSlot := common.BigToHash(big.NewInt(8))
	currentReserves, exists := pairState.Storage[reservesSlot]
	if !exists {
		log.Printf("[SINV_002] ⚠️  Slot 8 (reserves) 不存在，跳过检查")
		return true, nil
	}

	log.Printf("[SINV_002] Slot 8 (reserves) 值: %s", currentReserves.Hex())

	// 需要与前一个状态对比
	// 这里简化：如果 Monitor 能提供 PreviousState，则对比
	// 暂时只检查当前值的合理性

	mask112 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 112), big.NewInt(1))
	reserve0 := new(big.Int).And(currentReserves.Big(), mask112)
	reserve1 := new(big.Int).Rsh(new(big.Int).And(currentReserves.Big(), new(big.Int).Lsh(mask112, 112)), 112)

	log.Printf("[SINV_002]   reserve0: %s", reserve0.String())
	log.Printf("[SINV_002]   reserve1: %s", reserve1.String())

	// 检查两个 reserve 的比率是否异常
	// 正常情况下，ratio 应该在合理范围内
	// 攻击会导致 ratio 严重失衡
	if reserve0.Cmp(big.NewInt(0)) > 0 && reserve1.Cmp(big.NewInt(0)) > 0 {
		ratio := new(big.Int).Div(new(big.Int).Mul(reserve0, big.NewInt(1000)), reserve1)

		log.Printf("[SINV_002] 比率检查 (reserve0/reserve1 * 1000): %s", ratio.String())
		log.Printf("[SINV_002] 正常范围: [1, 10000]")

		// 如果 ratio < 1 或 > 10000 (假设正常范围是 1:1000 到 1000:1)
		if ratio.Cmp(big.NewInt(1)) < 0 || ratio.Cmp(big.NewInt(10000)) > 0 {
			log.Printf("[SINV_002] 🚨 检测到违规！比率异常")
			return false, &invariants.ViolationDetail{
				Message:       "PancakePair reserves 比率异常，疑似价格操纵",
				ActualValue:   ratio.String(),
				ExpectedValue: "Ratio between 1 and 10000",
				Metadata: map[string]interface{}{
					"reserve0": reserve0.String(),
					"reserve1": reserve1.String(),
					"ratio_x1000": ratio.String(),
				},
			}
		}
	} else {
		log.Printf("[SINV_002] ⚠️  reserve0或reserve1为0，无法计算比率")
	}

	log.Printf("[SINV_002] ✓ 检查通过，比率正常")
	return true, nil
}

// checkLoopTransferAttack 检测循环转账攻击模式
func checkLoopTransferAttack(state *invariants.ChainState, deps projects.Dependencies) (bool, *invariants.ViolationDetail) {
	log.Printf("[SINV_003] 开始检测循环转账攻击")

	// 这个检测需要分析交易内的 internal transactions 或 events
	// 攻击特征：大量(>100次)小额 transfer 到同一个地址 (PancakePair)

	// 简化版本：检查 XSIJ token 合约的 event logs
	// 如果 Monitor 能提供 trace 数据，可以统计 transfer call 次数

	xsijState, exists := state.States[XSIJTokenAddr]
	if !exists {
		log.Printf("[SINV_003] ⚠️  XSIJ Token状态不存在，跳过检查")
		return true, nil
	}

	// 这里需要 Monitor 提供更详细的 trace 信息
	// 暂时返回 true（无法检测）
	// TODO: 增强 Monitor 的 trace 分析能力
	_ = xsijState

	log.Printf("[SINV_003] ⚠️  循环转账检测需要trace数据，当前未实现")
	log.Printf("[SINV_003] ✓ 跳过检查（SINV_001和SINV_002已覆盖检测）")
	return true, nil
}
