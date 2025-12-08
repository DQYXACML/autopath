package main

import (
	"autopath/pkg/fuzzer"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"gopkg.in/yaml.v2"
)

// 命令行参数
var (
	txHash       = flag.String("tx", "", "Transaction hash to fuzz (required)")
	contractAddr = flag.String("contract", "", "Contract address (required)")
	blockNum     = flag.Uint64("block", 0, "Block number (required)")
	configPath   = flag.String("config", "./config/fuzzer.yaml", "Configuration file path")
	outputPath   = flag.String("output", "", "Output file path (default: ./fuzzing_reports/<timestamp>_<txhash>.json)")
	threshold    = flag.Float64("threshold", 0.8, "JUMPDEST similarity threshold")
	workers      = flag.Int("workers", 20, "Number of concurrent workers")
	timeout      = flag.Duration("timeout", 5*time.Second, "Timeout per simulation")
	verbose      = flag.Bool("verbose", false, "Enable verbose logging")
	dryRun       = flag.Bool("dry-run", false, "Dry run - only parse and display parameters")
	format       = flag.String("format", "json", "Output format (json, text, csv)")
	rpcURL       = flag.String("rpc", "", "RPC URL (overrides config)")
)

func main() {
	flag.Parse()

	// 设置日志
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	} else {
		log.SetFlags(log.LstdFlags)
	}

	// 验证必需参数
	if *txHash == "" || *contractAddr == "" || *blockNum == 0 {
		fmt.Fprintf(os.Stderr, "Error: Missing required parameters\n\n")
		flag.Usage()
		os.Exit(1)
	}

	// 验证地址格式
	if !common.IsHexAddress(*contractAddr) {
		log.Fatal("Invalid contract address format")
	}

	// 加载配置
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Printf("Warning: Failed to load config file, using defaults: %v", err)
		config = getDefaultConfig()
	}

	// 覆盖配置值（如果命令行参数提供）
	if *rpcURL != "" {
		config.RPCURL = *rpcURL
	}
	if *threshold != 0.8 {
		config.Threshold = *threshold
	}
	if *workers != 20 {
		config.Workers = *workers
	}
	if *timeout != 5*time.Second {
		config.Timeout = *timeout
	}

	// 打印配置信息
	printConfig(config)

	// Dry run模式
	if *dryRun {
		performDryRun(config)
		return
	}

	// 创建模糊测试器
	log.Println("Creating fuzzer...")
	fuzzerInstance, err := fuzzer.NewCallDataFuzzer(config)
	if err != nil {
		log.Fatalf("Failed to create fuzzer: %v", err)
	}

	// 设置信号处理
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nReceived interrupt signal, stopping...")
		cancel()
	}()

	// 执行模糊测试
	log.Printf("Starting fuzzing for transaction: %s", *txHash)
	log.Printf("Target contract: %s", *contractAddr)
	log.Printf("Block number: %d", *blockNum)

	startTime := time.Now()

	reports, err := fuzzerInstance.FuzzTransaction(
		ctx,
		common.HexToHash(*txHash),
		common.HexToAddress(*contractAddr),
		*blockNum,
		nil, // 命令行工具没有预先获取的交易对象，传nil让Fuzzer自行查询
	)

	if err != nil {
		log.Fatalf("Fuzzing failed: %v", err)
	}
	if len(reports) == 0 {
		log.Fatalf("Fuzzing finished but no reports generated")
	}

	duration := time.Since(startTime)

	// 打印统计信息
	printStatistics(reports, duration)

	// 保存报告
	outputFile := *outputPath
	if outputFile == "" {
		outputFile = generateOutputPath(*txHash)
	}

	if err := saveReport(reports, outputFile, *format); err != nil {
		log.Fatalf("Failed to save report: %v", err)
	}

	log.Printf("Report saved to: %s", outputFile)
	log.Printf("Fuzzing completed successfully in %v", duration)
}

// loadConfig 加载配置文件
func loadConfig(path string) (*fuzzer.Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var yamlConfig struct {
		Fuzzer struct {
			Enabled                     bool          `yaml:"enabled"`
			JumpdestSimilarityThreshold float64       `yaml:"jumpdest_similarity_threshold"`
			MaxVariationsPerParam       int           `yaml:"max_variations_per_param"`
			ConcurrentWorkers           int           `yaml:"concurrent_workers"`
			TimeoutPerSimulation        string        `yaml:"timeout_per_simulation"`
			RPCURL                      string        `yaml:"rpc_url"`
			Strategies                  yaml.MapSlice `yaml:"strategies"`
			Output                      struct {
				Format string `yaml:"format"`
				Path   string `yaml:"path"`
			} `yaml:"output"`
		} `yaml:"fuzzer"`
	}

	if err := yaml.Unmarshal(data, &yamlConfig); err != nil {
		return nil, err
	}

	timeout, err := time.ParseDuration(yamlConfig.Fuzzer.TimeoutPerSimulation)
	if err != nil {
		timeout = 5 * time.Second
	}

	config := &fuzzer.Config{
		RPCURL:        yamlConfig.Fuzzer.RPCURL,
		Threshold:     yamlConfig.Fuzzer.JumpdestSimilarityThreshold,
		MaxVariations: yamlConfig.Fuzzer.MaxVariationsPerParam,
		Workers:       yamlConfig.Fuzzer.ConcurrentWorkers,
		Timeout:       timeout,
	}

	// 解析策略配置
	config.Strategies = parseStrategies(yamlConfig.Fuzzer.Strategies)

	// 设置输出配置
	config.Output = fuzzer.OutputConfig{
		Format: yamlConfig.Fuzzer.Output.Format,
		Path:   yamlConfig.Fuzzer.Output.Path,
	}

	return config, nil
}

// parseStrategies 解析策略配置
func parseStrategies(strategies yaml.MapSlice) fuzzer.StrategyConfig {
	// 默认策略
	result := *fuzzer.DefaultStrategyConfig()

	// 这里可以根据需要解析更详细的策略配置
	// 为简化示例，直接返回默认配置
	return result
}

// getDefaultConfig 获取默认配置
func getDefaultConfig() *fuzzer.Config {
	return &fuzzer.Config{
		RPCURL:        "http://localhost:8545",
		Threshold:     0.8,
		MaxVariations: 50,
		Workers:       20,
		Timeout:       5 * time.Second,
		Strategies:    *fuzzer.DefaultStrategyConfig(),
		Output: fuzzer.OutputConfig{
			Format: "json",
			Path:   "./fuzzing_reports/",
		},
	}
}

// printConfig 打印配置信息
func printConfig(config *fuzzer.Config) {
	if !*verbose {
		return
	}

	fmt.Println("\n=== Fuzzer Configuration ===")
	fmt.Printf("RPC URL: %s\n", config.RPCURL)
	fmt.Printf("Similarity Threshold: %.2f\n", config.Threshold)
	fmt.Printf("Max Variations per Param: %d\n", config.MaxVariations)
	fmt.Printf("Concurrent Workers: %d\n", config.Workers)
	fmt.Printf("Timeout per Simulation: %v\n", config.Timeout)
	fmt.Printf("Output Format: %s\n", config.Output.Format)
	fmt.Printf("Output Path: %s\n", config.Output.Path)
	fmt.Println("============================\n")
}

// performDryRun 执行dry run
func performDryRun(config *fuzzer.Config) {
	fmt.Println("\n=== DRY RUN MODE ===")
	fmt.Printf("Would fuzz transaction: %s\n", *txHash)
	fmt.Printf("Target contract: %s\n", *contractAddr)
	fmt.Printf("Block number: %d\n", *blockNum)
	fmt.Printf("Configuration loaded successfully\n")
	fmt.Printf("Would use %d workers with %.2f similarity threshold\n", config.Workers, config.Threshold)
	fmt.Println("====================")
}

// printStatistics 打印统计信息
func printStatistics(reports []*fuzzer.AttackParameterReport, duration time.Duration) {
	fmt.Println("\n=== Fuzzing Results ===")
	if len(reports) == 0 {
		fmt.Println("无报告生成")
		fmt.Println("=======================")
		return
	}

	for idx, report := range reports {
		if report == nil {
			continue
		}
		fmt.Printf("Report #%d - Function (sig=%s)\n", idx+1, report.FunctionSig)
		fmt.Printf("Total Combinations Tested: %d\n", report.TotalCombinations)
		fmt.Printf("Valid Combinations Found: %d\n", report.ValidCombinations)
		fmt.Printf("Average Similarity: %.4f\n", report.AverageSimilarity)
		fmt.Printf("Max Similarity: %.4f\n", report.MaxSimilarity)
		fmt.Printf("Min Similarity: %.4f\n", report.MinSimilarity)
		fmt.Printf("Execution Time: %v\n", duration)

		if len(report.ValidParameters) > 0 {
			fmt.Printf("\n=== Valid Parameters ===\n")
			for _, param := range report.ValidParameters {
				fmt.Printf("Parameter %d (%s):\n", param.ParamIndex, param.ParamType)
				if param.IsRange {
					fmt.Printf("  Range: [%s, %s]\n", param.RangeMin, param.RangeMax)
				} else {
					if len(param.SingleValues) <= 5 {
						fmt.Printf("  Values: %v\n", param.SingleValues)
					} else {
						fmt.Printf("  Values: %v... (%d total)\n", param.SingleValues[:5], len(param.SingleValues))
					}
				}
				fmt.Printf("  Occurrences: %d\n", param.OccurrenceCount)
			}
		}

		if idx < len(reports)-1 {
			fmt.Println("\n-----------------------")
		}
	}
	fmt.Println("=======================")
}

// generateOutputPath 生成输出文件路径
func generateOutputPath(txHash string) string {
	timestamp := time.Now().Format("20060102_150405")
	hash := strings.TrimPrefix(txHash, "0x")
	if len(hash) > 8 {
		hash = hash[:8]
	}

	dir := "./fuzzing_reports"
	if err := os.MkdirAll(dir, 0755); err != nil {
		log.Printf("Warning: Failed to create output directory: %v", err)
		dir = "."
	}

	return filepath.Join(dir, fmt.Sprintf("%s_%s.json", timestamp, hash))
}

// saveReport 保存报告
func saveReport(reports []*fuzzer.AttackParameterReport, path string, format string) error {
	if len(reports) == 0 {
		return fmt.Errorf("no reports to save")
	}

	var data []byte
	var err error

	switch format {
	case "json":
		if len(reports) == 1 {
			data, err = json.MarshalIndent(reports[0], "", "  ")
		} else {
			data, err = json.MarshalIndent(reports, "", "  ")
		}
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

	case "text":
		data = []byte(formatReportsAsText(reports))

	case "csv":
		data = []byte(formatReportsAsCSV(reports))

	default:
		return fmt.Errorf("unsupported format: %s", format)
	}

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 写入文件
	if err := ioutil.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

// formatReportsAsText 格式化报告为文本
func formatReportsAsText(reports []*fuzzer.AttackParameterReport) string {
	var sb strings.Builder
	for idx, report := range reports {
		if report == nil {
			continue
		}

		sb.WriteString("Attack Parameter Fuzzing Report\n")
		sb.WriteString("================================\n\n")

		sb.WriteString(fmt.Sprintf("Report #%d\n", idx+1))
		sb.WriteString(fmt.Sprintf("Contract: %s\n", report.ContractAddress.Hex()))
		sb.WriteString(fmt.Sprintf("Function: %s\n", report.FunctionSig))
		sb.WriteString(fmt.Sprintf("Original TX: %s\n", report.OriginalTxHash.Hex()))
		sb.WriteString(fmt.Sprintf("Block: %d\n", report.BlockNumber))
		sb.WriteString(fmt.Sprintf("Timestamp: %s\n\n", report.Timestamp.Format(time.RFC3339)))

		sb.WriteString("Statistics:\n")
		sb.WriteString(fmt.Sprintf("  Total Tested: %d\n", report.TotalCombinations))
		sb.WriteString(fmt.Sprintf("  Valid Found: %d\n", report.ValidCombinations))
		sb.WriteString(fmt.Sprintf("  Avg Similarity: %.4f\n", report.AverageSimilarity))
		sb.WriteString(fmt.Sprintf("  Max Similarity: %.4f\n", report.MaxSimilarity))
		sb.WriteString(fmt.Sprintf("  Min Similarity: %.4f\n\n", report.MinSimilarity))

		sb.WriteString("Valid Parameters:\n")
		for _, param := range report.ValidParameters {
			sb.WriteString(fmt.Sprintf("\nParameter %d (%s):\n", param.ParamIndex, param.ParamType))
			if param.IsRange {
				sb.WriteString(fmt.Sprintf("  Range: [%s, %s]\n", param.RangeMin, param.RangeMax))
			} else {
				sb.WriteString(fmt.Sprintf("  Values: %v\n", param.SingleValues))
			}
			sb.WriteString(fmt.Sprintf("  Occurrences: %d\n", param.OccurrenceCount))
		}

		if idx < len(reports)-1 {
			sb.WriteString("\n\n")
		}
	}

	return sb.String()
}

// formatReportsAsCSV 格式化报告为CSV
func formatReportsAsCSV(reports []*fuzzer.AttackParameterReport) string {
	var sb strings.Builder

	// CSV头，增加函数selector便于区分
	sb.WriteString("FunctionSig,ParamIndex,ParamType,IsRange,RangeMin,RangeMax,Values,OccurrenceCount\n")

	// 数据行
	for _, report := range reports {
		if report == nil {
			continue
		}
		for _, param := range report.ValidParameters {
			values := ""
			if !param.IsRange {
				values = strings.Join(param.SingleValues, ";")
			}

			sb.WriteString(fmt.Sprintf("%s,%d,%s,%t,%s,%s,%s,%d\n",
				report.FunctionSig,
				param.ParamIndex,
				param.ParamType,
				param.IsRange,
				param.RangeMin,
				param.RangeMax,
				values,
				param.OccurrenceCount,
			))
		}
	}

	return sb.String()
}

// 使用示例
func printUsage() {
	fmt.Println(`
Fuzzer - Attack Parameter Fuzzing Tool

Usage:
  fuzzer -tx <TX_HASH> -contract <CONTRACT_ADDRESS> -block <BLOCK_NUMBER> [options]

Required Arguments:
  -tx string        Transaction hash to fuzz
  -contract string  Contract address
  -block uint       Block number

Optional Arguments:
  -config string    Configuration file path (default: ./config/fuzzer.yaml)
  -output string    Output file path
  -threshold float  JUMPDEST similarity threshold (default: 0.8)
  -workers int      Number of concurrent workers (default: 20)
  -timeout duration Timeout per simulation (default: 5s)
  -format string    Output format: json, text, csv (default: json)
  -rpc string       RPC URL (overrides config)
  -verbose          Enable verbose logging
  -dry-run          Dry run mode

Examples:
  # Basic usage
  fuzzer -tx 0xabc... -contract 0xdef... -block 18000000

  # With custom config
  fuzzer -tx 0xabc... -contract 0xdef... -block 18000000 -config custom.yaml

  # With verbose output and custom threshold
  fuzzer -tx 0xabc... -contract 0xdef... -block 18000000 -verbose -threshold 0.9

  # Export as CSV
  fuzzer -tx 0xabc... -contract 0xdef... -block 18000000 -format csv -output results.csv
`)
}
