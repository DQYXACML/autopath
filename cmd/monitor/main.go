package main

import (
	"context"
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"autopath/pkg/invariants"
	"autopath/pkg/monitor"
	"autopath/pkg/projects"

	_ "autopath/pkg/projects/lodestar"
	_ "autopath/pkg/projects/xsij"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

func main() {
	// 命令行参数
	var (
		rpcURL       = flag.String("rpc", "ws://localhost:8545", "WebSocket RPC URL")
		configPath   = flag.String("config", "pkg/invariants/configs/lodestar.json", "Invariant configuration path")
		webhookURL   = flag.String("webhook", "", "Alert webhook URL")
		broadcastRef = flag.String("broadcast", "", "可选：Foundry broadcast run-latest.json 路径，若提供则覆盖受保护合约地址")
		namesCSV     = flag.String("names", "", "可选：按合约名过滤(逗号分隔)，留空表示使用全部 CREATE 部署")

		// 本地执行模式
		localExecution = flag.Bool("local-execution", false, "使用本地EVM执行模式替代RPC调用（更快但需要更多内存）")

		// Autopatch Oracle 推送相关
		oracleEnabled        = flag.Bool("oracle.enabled", false, "是否启用链上Autopatch推送")
		oracleModule         = flag.String("oracle.module", "", "ParamCheckModule 合约地址")
		oraclePK             = flag.String("oracle.pk", "", "用于推送交易的私钥(0x...)，需被模块授权")
		oracleChainID        = flag.Int64("oracle.chainid", 31337, "链ID")
		oracleThreshold      = flag.Float64("oracle.threshold", 0.8, "推送相似度阈值[0,1]")
		oraclePushCandidates = flag.Bool("oracle.push_candidates", false, "允许低相似度候选规则上链")
		oracleBatch          = flag.Int("oracle.batch", 1, "批量推送大小")
		oracleFlush          = flag.Duration("oracle.flush_interval", 30*time.Second, "定期Flush间隔")
		oracleMaxRules       = flag.Int("oracle.max_rules", 20, "每个函数最多写入的规则数")
		oracleCompress       = flag.Bool("oracle.compress_ranges", true, "是否启用范围压缩")
		oracleMaxValues      = flag.Int("oracle.max_values_per_param", 10, "每个参数最多保留的离散值")

		// 规则导出相关
		ruleExportPath   = flag.String("rule.export_path", "test/Lodestar/scripts/data/firewall-rules.json", "规则导出路径")
		ruleExportEnable = flag.Bool("rule.export_enable", true, "是否启用规则导出")
		ruleExportFormat = flag.String("rule.export_format", "json", "规则导出格式(json/yaml)")

		// 基线状态文件（用于Fork测试场景）
		baselineState = flag.String("baseline-state", "", "预保存的基线状态文件路径（Fork测试优化）")

		// StateOverride控制（用于Fork测试场景）
		disableStateOverride = flag.Bool("disable-state-override", false, "完全禁用StateOverride（适用于Fork测试）")
	)
	flag.Parse()

	// 设置日志
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	log.Printf("Starting Firewall Monitor...")
	log.Printf("RPC: %s", *rpcURL)
	log.Printf("Config: %s", *configPath)

	// 创建不变量注册中心
	registry := invariants.NewRegistry()

	// 加载项目配置
	projectConfig, err := projects.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load project config: %v", err)
	}

	if err := registry.LoadProjectConfig(*configPath); err != nil {
		log.Fatalf("Failed to load project config into registry: %v", err)
	}

	// 若提供 broadcast 文件，则覆盖受保护合约地址为本地部署地址
	if *broadcastRef != "" {
		addrs := parseBroadcastAddresses(*broadcastRef, *namesCSV)
		if len(addrs) == 0 {
			log.Fatalf("未能从 broadcast 解析到任何 CREATE 合约地址: %s", *broadcastRef)
		}
		if err := registry.UpdateProjectContracts(projectConfig.ProjectID, addrs); err != nil {
			log.Fatalf("更新受保护合约失败: %v", err)
		}
		log.Printf("已根据 broadcast 覆盖受保护合约，共 %d 个", len(addrs))
	}

	// 为不变量评估器准备一个本地 ethclient（用于 eth_call）
	rpcCli, err := rpc.Dial(*rpcURL)
	if err != nil {
		log.Fatalf("RPC 连接失败: %v", err)
	}
	ethCli := ethclient.NewClient(rpcCli)
	txTracer := monitor.NewTransactionTracer(rpcCli)

	// 根据项目配置注册定制不变量
	if err := projects.Register(context.Background(), projects.Dependencies{
		Registry:  registry,
		Config:    projectConfig,
		EthClient: ethCli,
		RPCClient: rpcCli,
		Tracer:    txTracer,
	}); err != nil {
		log.Fatalf("Failed to register project-specific evaluators: %v", err)
	}

	// 创建区块链监控器
	bm, err := monitor.NewBlockchainMonitor(*rpcURL, registry)
	if err != nil {
		log.Fatalf("Failed to create monitor: %v", err)
	}

	// 配置告警
	if *webhookURL != "" {
		bm.ConfigureAlerts(*webhookURL, nil)
	}

	// 配置Fuzzing集成
	if projectConfig.FuzzingConfig != nil {
		fuzzingConfig := projects.ConvertFuzzingConfig(projectConfig.FuzzingConfig, projectConfig.ProjectID)
		if fuzzingConfig != nil && *baselineState != "" {
			fuzzingConfig.BaselineStatePath = *baselineState
		}
		// 命令行参数覆盖配置文件设置
		if *localExecution {
			fuzzingConfig.LocalExecution = true
			log.Println("本地EVM执行模式已启用（命令行参数覆盖）")
		}
		if err := bm.ConfigureFuzzing(fuzzingConfig, *rpcURL); err != nil {
			log.Printf("Warning: Failed to configure fuzzing: %v", err)
		} else if fuzzingConfig.Enabled {
			log.Println("Fuzzing integration enabled")
		}
	}

	// 配置基础规则导出
	bm.ConfigureRuleExporter(*ruleExportPath, *ruleExportEnable, *ruleExportFormat)

	// 配置基线状态（如果提供）
	if *baselineState != "" {
		bm.ConfigureBaselineState(*baselineState)
	}

	// 配置 StateOverride 行为（用于Fork测试优化）
	if *disableStateOverride {
		bm.ConfigureStateOverride(false)
		log.Printf("StateOverride disabled (suitable for Fork testing)")
	}

	// 配置 Oracle 推送（Autopatch）
	if *oracleEnabled {
		if *oracleModule == "" || *oraclePK == "" {
			log.Fatalf("Oracle enabled but module or private key not provided")
		}
		oracleCfg := &monitor.OracleConfig{
			Enabled:            true,
			ModuleAddress:      *oracleModule,
			PrivateKey:         *oraclePK,
			RPCURL:             *rpcURL,
			ChainID:            *oracleChainID,
			PushThreshold:      *oracleThreshold,
			BatchSize:          *oracleBatch,
			FlushInterval:      *oracleFlush,
			MaxRulesPerFunc:    *oracleMaxRules,
			CompressRanges:     *oracleCompress,
			MaxValuesPerParam:  *oracleMaxValues,
			AutoPush:           true,
			AllowCandidatePush: *oraclePushCandidates,
			ProjectMapping:     map[string]string{},
			RuleExportPath:     *ruleExportPath,
			EnableRuleExport:   *ruleExportEnable,
			RuleExportFormat:   *ruleExportFormat,
		}
		// 尝试自动构造 ProjectMapping（cToken -> DomainProject）
		type fwOut struct {
			DomainProject string `json:"domainProject"`
		}
		type deployedOut struct {
			LUSDC   string `json:"lUSDC"`
			LplvGLP string `json:"lplvGLP"`
			LETH    string `json:"lETH"`
			LMIM    string `json:"lMIM"`
			LUSDT   string `json:"lUSDT"`
			LFRAX   string `json:"lFRAX"`
			LDAI    string `json:"lDAI"`
			LWBTC   string `json:"lWBTC"`
		}
		// 优先使用 firewall-local.json；若不存在则回退到 firewall-param-only.json
		fwFile := "test/Lodestar/scripts/data/firewall-local.json"
		if _, err := ioutil.ReadFile(fwFile); err != nil {
			if _, err2 := ioutil.ReadFile("test/Lodestar/scripts/data/firewall-param-only.json"); err2 == nil {
				fwFile = "test/Lodestar/scripts/data/firewall-param-only.json"
				log.Printf("使用 fallback 防火墙文件: %s", fwFile)
			}
		}
		if b, err := ioutil.ReadFile(fwFile); err == nil {
			var fw fwOut
			if err := json.Unmarshal(b, &fw); err == nil && fw.DomainProject != "" {
				if b2, err2 := ioutil.ReadFile("test/Lodestar/scripts/data/deployed-local.json"); err2 == nil {
					var d deployedOut
					if err := json.Unmarshal(b2, &d); err == nil {
						domain := strings.ToLower(fw.DomainProject)
						for _, a := range []string{d.LUSDC, d.LplvGLP, d.LETH, d.LMIM, d.LUSDT, d.LFRAX, d.LDAI, d.LWBTC} {
							if a != "" {
								oracleCfg.ProjectMapping[strings.ToLower(a)] = domain
							}
						}
						if len(oracleCfg.ProjectMapping) > 0 {
							log.Printf("Loaded ProjectMapping: %d contracts -> %s", len(oracleCfg.ProjectMapping), fw.DomainProject)
						}
					}
				}
			}
		}
		if err := bm.ConfigureOracle(oracleCfg); err != nil {
			log.Fatalf("Failed to configure oracle: %v", err)
		}
		log.Printf("Oracle integration enabled. Module=%s", *oracleModule)
	}

	// 创建上下文
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动监控
	if err := bm.Start(ctx); err != nil {
		log.Fatalf("Failed to start monitor: %v", err)
	}

	// 等待退出信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Monitor is running. Press Ctrl+C to stop.")

	<-sigChan
	log.Println("Shutting down monitor...")

	// 停止监控
	bm.Stop()
	cancel()

	log.Println("Monitor stopped.")
}

// parseBroadcastAddresses 解析 Foundry broadcast run-latest.json 的 CREATE 合约地址
func parseBroadcastAddresses(path, namesCSV string) []string {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		log.Printf("读取 broadcast 失败: %v", err)
		return nil
	}

	var obj struct {
		Transactions []struct {
			TransactionType string `json:"transactionType"`
			ContractName    string `json:"contractName"`
			ContractAddress string `json:"contractAddress"`
		} `json:"transactions"`
	}
	if err := json.Unmarshal(data, &obj); err != nil {
		log.Printf("解析 broadcast JSON 失败: %v", err)
		return nil
	}

	filter := map[string]struct{}{}
	if namesCSV != "" {
		parts := strings.Split(namesCSV, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				filter[p] = struct{}{}
			}
		}
	}

	var addrs []string
	for _, tx := range obj.Transactions {
		if tx.TransactionType != "CREATE" {
			continue
		}
		if len(filter) > 0 {
			if _, ok := filter[tx.ContractName]; !ok {
				continue
			}
		}
		if tx.ContractAddress != "" {
			addrs = append(addrs, strings.ToLower(tx.ContractAddress))
		}
	}
	return addrs
}
