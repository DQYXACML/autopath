package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"autopath/pkg/simulator"
	"github.com/ethereum/go-ethereum/common"
)

func main() {
	// 命令行参数
	var (
		rpcURL           = flag.String("rpc", "http://localhost:8545", "RPC URL")
		txHash           = flag.String("tx", "", "Transaction hash to simulate")
		blockNumber      = flag.Uint64("block", 0, "Block number for simulation")
		protectedAddress = flag.String("protected", "0x0000000000000000000000000000000000000000", "Protected contract address")
		outputPath       = flag.String("output", "", "Output file path (optional)")
		analyze          = flag.Bool("analyze", false, "Perform path analysis")
		compare          = flag.String("compare", "", "Compare with another transaction hash")
	)
	flag.Parse()

	// 验证参数
	if *txHash == "" {
		log.Fatal("Transaction hash is required (-tx)")
	}

	// 创建模拟器
	sim, err := simulator.NewEVMSimulator(*rpcURL)
	if err != nil {
		log.Fatalf("Failed to create simulator: %v", err)
	}

	ctx := context.Background()
	txHashBytes := common.HexToHash(*txHash)
	protectedAddr := common.HexToAddress(*protectedAddress)

	log.Printf("Simulating transaction: %s", *txHash)
	log.Printf("Protected contract: %s", protectedAddr.Hex())

	// 执行模拟
	result, err := sim.ForkAndReplay(ctx, *blockNumber, txHashBytes, protectedAddr)
	if err != nil {
		log.Fatalf("Simulation failed: %v", err)
	}

	// 打印基本信息
	fmt.Println("\n=== Simulation Result ===")
	fmt.Printf("Success: %v\n", result.Success)
	fmt.Printf("Gas Used: %d\n", result.GasUsed)
	fmt.Printf("Return Data: %s\n", result.ReturnData)
	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
	}

	// 打印JUMPDEST信息
	fmt.Printf("\n=== JUMPDEST Analysis ===\n")
	fmt.Printf("Total JUMPDESTs: %d\n", len(result.JumpDests))
	if len(result.JumpDests) > 0 {
		fmt.Println("JUMPDEST locations:")
		for i, pc := range result.JumpDests {
			if i < 20 { // 只显示前20个
				fmt.Printf("  [%d] PC: 0x%x\n", i, pc)
			}
		}
		if len(result.JumpDests) > 20 {
			fmt.Printf("  ... and %d more\n", len(result.JumpDests)-20)
		}
	}

	// 执行路径分析
	if *analyze {
		analyzer := simulator.NewPathAnalyzer()
		analyzer.StorePath(txHashBytes, result)

		analysis := analyzer.AnalyzePath(result)

		fmt.Println("\n=== Path Analysis ===")
		fmt.Printf("Total Steps: %d\n", analysis.TotalSteps)
		fmt.Printf("Max Depth: %d\n", analysis.MaxDepth)
		fmt.Printf("Total Gas Used: %d\n", analysis.TotalGasUsed)
		fmt.Printf("State Changes: %d\n", analysis.StateChangeCount)
		fmt.Printf("Patterns: %v\n", analysis.Patterns)

		// 显示操作码统计
		fmt.Println("\nTop Opcodes:")
		showTopOpcodes(analysis.UniqueOpcodes, 10)
	}

	// 比较交易
	if *compare != "" {
		compareTxHash := common.HexToHash(*compare)
		log.Printf("Comparing with transaction: %s", *compare)

		compareResult, err := sim.ForkAndReplay(ctx, *blockNumber, compareTxHash, protectedAddr)
		if err != nil {
			log.Printf("Failed to simulate comparison transaction: %v", err)
		} else {
			analyzer := simulator.NewPathAnalyzer()
			analyzer.StorePath(txHashBytes, result)
			analyzer.StorePath(compareTxHash, compareResult)

			similarity := analyzer.ComparePaths(result, compareResult)
			fmt.Printf("\n=== Path Comparison ===\n")
			fmt.Printf("Similarity: %.2f%%\n", similarity*100)

			// 比较关键指标
			fmt.Printf("\nTransaction 1 vs Transaction 2:\n")
			fmt.Printf("  Steps: %d vs %d\n", len(result.ExecutionPath), len(compareResult.ExecutionPath))
			fmt.Printf("  JUMPDESTs: %d vs %d\n", len(result.JumpDests), len(compareResult.JumpDests))
			fmt.Printf("  Gas Used: %d vs %d\n", result.GasUsed, compareResult.GasUsed)
		}
	}

	// 保存结果到文件
	if *outputPath != "" {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			log.Printf("Failed to marshal result: %v", err)
		} else {
			if err := os.WriteFile(*outputPath, data, 0644); err != nil {
				log.Printf("Failed to write output file: %v", err)
			} else {
				log.Printf("Result saved to: %s", *outputPath)
			}
		}
	}

	// 打印状态变化摘要
	if len(result.StateChanges) > 0 {
		fmt.Println("\n=== State Changes ===")
		for addr, change := range result.StateChanges {
			fmt.Printf("Contract %s:\n", addr)
			if change.BalanceAfter != "" && change.BalanceBefore != "" {
				fmt.Printf("  Balance: %s -> %s\n", change.BalanceBefore, change.BalanceAfter)
			}
			if len(change.StorageChanges) > 0 {
				fmt.Printf("  Storage changes: %d slots\n", len(change.StorageChanges))
			}
		}
	}

	// 显示执行路径摘要
	if len(result.ExecutionPath) > 0 {
		fmt.Printf("\n=== Execution Path Summary ===\n")
		fmt.Printf("Total steps: %d\n", len(result.ExecutionPath))

		// 显示前几步和最后几步
		showSteps := 5
		if len(result.ExecutionPath) <= showSteps*2 {
			// 如果总步数较少，显示所有
			for i, step := range result.ExecutionPath {
				fmt.Printf("[%d] PC:%04x Op:%s Gas:%d\n", i, step.PC, step.Op, step.Gas)
			}
		} else {
			// 显示开始的几步
			fmt.Println("First steps:")
			for i := 0; i < showSteps; i++ {
				step := result.ExecutionPath[i]
				fmt.Printf("  [%d] PC:%04x Op:%s Gas:%d\n", i, step.PC, step.Op, step.Gas)
			}

			fmt.Println("  ...")

			// 显示最后的几步
			fmt.Println("Last steps:")
			for i := len(result.ExecutionPath) - showSteps; i < len(result.ExecutionPath); i++ {
				step := result.ExecutionPath[i]
				fmt.Printf("  [%d] PC:%04x Op:%s Gas:%d\n", i, step.PC, step.Op, step.Gas)
			}
		}
	}
}

// showTopOpcodes 显示最常用的操作码
func showTopOpcodes(opcodes map[string]int, limit int) {
	type opCount struct {
		op    string
		count int
	}

	var sorted []opCount
	for op, count := range opcodes {
		sorted = append(sorted, opCount{op, count})
	}

	// 简单排序
	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[j].count > sorted[i].count {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// 显示前N个
	for i := 0; i < limit && i < len(sorted); i++ {
		fmt.Printf("  %s: %d\n", sorted[i].op, sorted[i].count)
	}
}