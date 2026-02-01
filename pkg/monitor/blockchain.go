package monitor

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"sync"
	"time"

	"autopath/pkg/fuzzer"
	"autopath/pkg/invariants"
	"autopath/pkg/simulator"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// BlockchainMonitor 区块链监控器
type BlockchainMonitor struct {
	client         *ethclient.Client
	rpcClient      *rpc.Client
	registry       *invariants.Registry
	evaluator      *invariants.Evaluator
	tracer         *TransactionTracer
	alertManager   *AlertManager
	fuzzing        *FuzzingIntegration // Fuzzing集成
	oracle         *OracleIntegration  // Autopatch Oracle 集成
	storageFetcher *StorageFetcher
	sim            *simulator.EVMSimulator

	blockLag  uint64 // 延迟几个区块以确保最终性
	batchSize uint64 // 批处理大小

	mu        sync.RWMutex
	lastBlock uint64
	running   bool
	stopChan  chan struct{}

	ruleExporter      *RuleExporter
	baselineRuleMutex sync.Mutex
	baselineRecorded  map[string]bool

	// 【新增】预加载的基线状态（用于 Fork 测试场景）
	baselineStateFile  string
	baselineStates     map[common.Address]*invariants.ContractState
	baselineLoaded     bool
	baselineStateMutex sync.RWMutex
	forkBlockNumber    uint64 // Fork 区块号（用于检测是否是新交易）

	// 【新增】StateOverride控制（用于Fork测试优化）
	enableStateOverride bool // 默认true，可通过ConfigureStateOverride(false)禁用
}

type transactionJob struct {
	tx    *types.Transaction
	block *types.Block
	index uint
	hash  common.Hash
}

// NewBlockchainMonitor 创建区块链监控器
func NewBlockchainMonitor(rpcURL string, registry *invariants.Registry) (*BlockchainMonitor, error) {
	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	client := ethclient.NewClient(rpcClient)

	sim := simulator.NewEVMSimulatorWithClients(rpcClient, client)
	sim.SetRPCURL(rpcURL)

	return &BlockchainMonitor{
		client:              client,
		rpcClient:           rpcClient,
		registry:            registry,
		evaluator:           invariants.NewEvaluator(registry),
		tracer:              NewTransactionTracer(rpcClient),
		alertManager:        NewAlertManager(),
		fuzzing:             nil, // 将通过 ConfigureFuzzing 方法设置
		oracle:              nil, // 将通过 ConfigureOracle 方法设置
		storageFetcher:      NewStorageFetcher(client, rpcClient),
		sim:                 sim,
		blockLag:            0,
		batchSize:           10,
		stopChan:            make(chan struct{}),
		baselineRecorded:    make(map[string]bool),
		enableStateOverride: true, // 默认启用StateOverride，可通过ConfigureStateOverride禁用
	}, nil
}

// ConfigureFuzzing 配置模糊测试
func (m *BlockchainMonitor) ConfigureFuzzing(config *FuzzingConfig, rpcURL string) error {
	if config == nil || !config.Enabled {
		log.Println("Fuzzing is disabled")
		return nil
	}

	// 保证本地执行与新架构协同启用
	if config.LocalExecution && !config.EnableNewArch {
		log.Printf("[Monitor] 本地执行已启用但EnableNewArch未开启，自动启用新架构")
		config.EnableNewArch = true
	}
	if config.EnableNewArch && !config.LocalExecution {
		log.Printf("[Monitor] EnableNewArch已启用，自动切换到本地执行模式")
		config.LocalExecution = true
	}

	log.Printf("[Monitor]  配置Fuzzing，复用Monitor的RPC连接")

	// 使用Monitor现有的RPC客户端创建fuzzing集成，避免创建新连接
	fuzzing, err := NewFuzzingIntegrationWithClients(m.rpcClient, m.client, rpcURL, config)
	if err != nil {
		return fmt.Errorf("failed to create fuzzing integration: %w", err)
	}

	// 若本地执行+新架构，初始化注册表与池
	if config.LocalExecution && config.EnableNewArch {
		if err := fuzzing.InitializeNewArchitecture(); err != nil {
			log.Printf("[Monitor]  新架构初始化失败: %v", err)
		}
	}

	// 配置不变量检查适配器（若已启用）
	fuzzing.ConfigureInvariantCheck(m.evaluator, config.InvariantCheck)

	m.fuzzing = fuzzing
	log.Printf("Fuzzing enabled with threshold: %.2f", config.Threshold)
	return nil
}

// ConfigureAlerts 配置告警
func (m *BlockchainMonitor) ConfigureAlerts(webhookURL string, emailRecipients []string) {
	m.alertManager.Configure(webhookURL, emailRecipients)
}

// ConfigureRuleExporter 配置基础规则导出器
func (m *BlockchainMonitor) ConfigureRuleExporter(exportPath string, enable bool, format string) {
	if !enable {
		m.ruleExporter = nil
		return
	}
	m.ruleExporter = NewRuleExporter(exportPath, true, format)
	if m.baselineRecorded == nil {
		m.baselineRecorded = make(map[string]bool)
	}
	log.Printf("Rule exporter enabled. Path: %s", exportPath)
}

// ConfigureBaselineState 配置基线状态文件路径（用于Fork测试场景）
func (m *BlockchainMonitor) ConfigureBaselineState(stateFile string) {
	if stateFile == "" {
		m.baselineStateFile = ""
		log.Println("Baseline state file not configured, will fetch state from RPC")
		return
	}
	m.baselineStateFile = stateFile
	log.Printf("Baseline state configured: %s", stateFile)
}

// ConfigureStateOverride 配置是否启用StateOverride（用于Fork测试优化）
func (m *BlockchainMonitor) ConfigureStateOverride(enable bool) {
	m.enableStateOverride = enable
	if enable {
		log.Println("StateOverride enabled (default behavior)")
	} else {
		log.Println("StateOverride disabled (Fork testing optimization)")
	}
}

// Start 启动监控
func (m *BlockchainMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	// 获取当前区块高度
	latestBlock, err := m.client.BlockNumber(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest block: %w", err)
	}

	m.lastBlock = latestBlock - m.blockLag

	// 订阅新区块
	headers := make(chan *types.Header, 100)
	sub, err := m.client.SubscribeNewHead(ctx, headers)
	if err != nil {
		return fmt.Errorf("failed to subscribe to new blocks: %w", err)
	}

	log.Printf("Started monitoring from block %d", m.lastBlock)
	// 打印当前受保护合约，便于核对是否与本地部署一致
	protected := m.registry.GetAllProtectedContracts()
	if len(protected) == 0 {
		log.Printf("No protected contracts configured. Add addresses to config 'contracts' list.")
	} else {
		log.Printf("Protected contracts (%d):", len(protected))
		for _, addr := range protected {
			log.Printf("  - %s", addr.Hex())
		}
	}

	// 启动 Oracle 集成（若启用）
	if m.oracle != nil && m.oracle.enabled {
		go m.oracle.Start(ctx)
	}

	go func() {
		defer sub.Unsubscribe()

		for {
			select {
			case err := <-sub.Err():
				log.Printf("Subscription error: %v", err)
				m.reconnectAndResume(ctx)
				return

			case header := <-headers:
				// 处理延迟区块
				targetBlock := header.Number.Uint64() - m.blockLag
				if targetBlock > m.lastBlock {
					m.processBlockRange(ctx, m.lastBlock+1, targetBlock)
					m.lastBlock = targetBlock
				}

			case <-m.stopChan:
				log.Println("Stopping monitor")
				return

			case <-ctx.Done():
				log.Println("Context cancelled, stopping monitor")
				return
			}
		}
	}()

	return nil
}

// Stop 停止监控
func (m *BlockchainMonitor) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running {
		close(m.stopChan)
		m.running = false
	}
}

// processBlockRange 处理区块范围
func (m *BlockchainMonitor) processBlockRange(ctx context.Context, from, to uint64) {
	for blockNum := from; blockNum <= to; blockNum++ {
		if err := m.processBlock(ctx, blockNum); err != nil {
			log.Printf("Error processing block %d: %v", blockNum, err)
		}
	}
}

// processBlock 处理单个区块
func (m *BlockchainMonitor) processBlock(ctx context.Context, blockNumber uint64) error {
	block, err := m.client.BlockByNumber(ctx, big.NewInt(int64(blockNumber)))
	if err != nil {
		return fmt.Errorf("failed to get block %d: %w", blockNumber, err)
	}

	log.Printf("Processing block %d with %d transactions", blockNumber, len(block.Transactions()))

	protectedList := m.registry.GetAllProtectedContracts()

	// 【核心修改】优先使用预保存的基线状态
	var preBlockStates map[common.Address]*invariants.ContractState

	// 首次运行且提供了基线状态文件：加载基线状态
	if !m.baselineLoaded && m.baselineStateFile != "" {
		log.Printf("📁 加载预保存的基线状态: %s", m.baselineStateFile)
		preBlockStates = m.loadBaselineState(protectedList)
		if len(preBlockStates) > 0 {
			m.baselineStateMutex.Lock()
			m.baselineStates = preBlockStates
			m.baselineLoaded = true
			m.baselineStateMutex.Unlock()
			log.Printf("✅ 已加载 %d 个合约的基线状态", len(preBlockStates))
		} else {
			log.Printf("⚠️  基线状态加载失败，回退到链上获取")
			preBlockStates = m.capturePreBlockStates(ctx, block, protectedList)
		}
	} else if m.baselineLoaded {
		// 后续区块使用缓存的基线
		m.baselineStateMutex.RLock()
		preBlockStates = m.baselineStates
		m.baselineStateMutex.RUnlock()
		log.Printf("♻️  使用缓存的基线状态（跳过RPC获取）")
	} else {
		// Fallback：运行时获取（兼容非Fork场景）
		log.Printf("⏱️  未提供基线状态文件，从链上获取...")
		preBlockStates = m.capturePreBlockStates(ctx, block, protectedList)
	}

	rollingStates := cloneContractStateMap(preBlockStates)
	for _, addr := range protectedList {
		if _, ok := rollingStates[addr]; !ok {
			rollingStates[addr] = &invariants.ContractState{
				Address: addr,
				Balance: big.NewInt(0),
				Storage: make(map[common.Hash]common.Hash),
			}
		}
	}

	var allViolations []invariants.ViolationResult

	for idx := 0; idx < len(block.Transactions()); idx++ {
		canonicalTx, actualHash, err := m.fetchTransactionInBlock(ctx, block.Hash(), uint(idx))
		if err != nil {
			log.Printf("Failed to fetch transaction %d from block %d: %v", idx, block.NumberU64(), err)
			continue
		}

		job := transactionJob{
			tx:    canonicalTx,
			block: block,
			index: uint(idx),
			hash:  actualHash,
		}

		violations := m.processTransaction(ctx, job, rollingStates, preBlockStates)
		if len(violations) > 0 {
			allViolations = append(allViolations, violations...)
		}
	}

	if len(allViolations) > 0 {
		m.handleViolations(allViolations, block)
	}

	return nil
}

// processTransaction 处理交易
func (m *BlockchainMonitor) processTransaction(ctx context.Context, job transactionJob, rollingStates map[common.Address]*invariants.ContractState, preBlockStates map[common.Address]*invariants.ContractState) []invariants.ViolationResult {
	tx := job.tx
	block := job.block
	txIndex := job.index

	// 优先使用RPC返回的真实哈希；若缺失则退化为本地计算
	rpcTxHash := job.hash
	if (rpcTxHash == common.Hash{}) {
		rpcTxHash = tx.Hash()
	}

	// 第1步：通过receipt获取实际交易哈希
	receipt, err := m.client.TransactionReceipt(ctx, rpcTxHash)
	if err != nil {
		// 如果交易hash仍然无法获取receipt，尝试按索引重新获取一次真实交易
		log.Printf("\n  警告：哈希(%s)无法获取receipt (index=%d, block=%s)", rpcTxHash.Hex(), txIndex, block.Hash().Hex())
		log.Printf("   错误: %v", err)
		log.Printf("    尝试重新获取交易...")

		txFromBlock, actualHash, txErr := m.fetchTransactionInBlock(ctx, block.Hash(), txIndex)
		if txErr == nil {
			tx = txFromBlock
			rpcTxHash = actualHash
			receipt, err = m.client.TransactionReceipt(ctx, actualHash)
			if err == nil {
				log.Printf("    重新获取成功，实际哈希: %s (索引: %d)", actualHash.Hex(), txIndex)
			}
		}

		if err != nil {
			log.Printf("    仍然无法找到匹配的交易 (index=%d)，跳过处理", txIndex)
			return nil
		}
	}

	// 第3步：使用receipt中的实际哈希（最可靠）
	actualTxHash := receipt.TxHash

	// 第4步：比较并记录是否存在哈希不匹配
	if rpcTxHash.Hex() != actualTxHash.Hex() {
		log.Printf("\n      RPC返回的哈希与receipt不一致！")
		log.Printf("   RPC返回的哈希:        %s", rpcTxHash.Hex())
		log.Printf("   receipt中的实际哈希: %s", actualTxHash.Hex())
	}

	if tx.Hash().Hex() != actualTxHash.Hex() {
		log.Printf("\n      交易哈希不匹配检测！")
		log.Printf("   tx.Hash()计算的哈希: %s", tx.Hash().Hex())
		log.Printf("   receipt中的实际哈希: %s", actualTxHash.Hex())
		log.Printf("   将使用实际哈希进行后续操作...")
	}

	// 第5步：使用验证过的实际哈希进行所有后续操作
	txHash := actualTxHash.Hex()
	log.Printf("\n处理交易: %s (区块: %d)", txHash, block.Number().Uint64())

	// 使用实际哈希进行trace
	trace, err := m.tracer.TraceTransaction(actualTxHash)
	if err != nil {
		log.Printf("    Failed to trace transaction: %v", err)
		return nil
	}

	// 检查交易是否revert
	if trace.Error != "" {
		log.Printf("   交易失败/Revert: %s", trace.Error)
		log.Printf("   继续分析失败交易以提取攻击参数...")
	} else {
		log.Printf("    交易成功执行")
	}

	// 查找涉及的受保护合约
	protectedContracts := m.findProtectedContracts(trace)
	log.Printf("   从Trace找到 %d 个受保护合约", len(protectedContracts))

	// 【Backup 1】检查交易的直接To地址
	if tx.To() != nil {
		toAddr := *tx.To()
		if m.registry.IsProtectedContract(toAddr) {
			found := false
			for _, addr := range protectedContracts {
				if addr == toAddr {
					found = true
					break
				}
			}
			if !found {
				log.Printf("   [Backup] 从tx.To找到受保护合约: %s", toAddr.Hex())
				protectedContracts = append(protectedContracts, toAddr)
			}
		}
	}

	if len(protectedContracts) == 0 {
		log.Printf("   没有涉及受保护合约，跳过")
		return nil
	}

	beforeStates := collectContractStates(protectedContracts, rollingStates, preBlockStates)
	afterStates := cloneContractStateMap(rollingStates)

	// ✨ 修复：总是构建prestate（本地EVM fuzzing需要）
	// 将prestate构建从enableStateOverride条件中解耦
	var override simulator.StateOverride
	var ovErr error
	if m.sim != nil {
		override, ovErr = m.sim.BuildStateOverride(ctx, actualTxHash)
		if ovErr != nil {
			log.Printf("     获取prestate失败: %v", ovErr)
			// prestate失败不影响继续执行
		} else if override != nil {
			// 添加日志验证prestate构建成功
			accountCount := len(override)
			slotCount := 0
			for _, acc := range override {
				if acc != nil && acc.State != nil {
					slotCount += len(acc.State)
				}
			}
			log.Printf("✅ Prestate构建成功 (accounts=%d, slots=%d)", accountCount, slotCount)
		} else {
			log.Printf("⚠️  Prestate为空，本地EVM执行可能失败")
		}
	}

	// 根据enableStateOverride决定是否进行RPC重放
	var replayResult *simulator.ReplayResult
	if m.sim != nil && m.enableStateOverride && override != nil {
		// 【优化】检测是否是 Fork 后的新交易
		isForkTransaction := m.forkBlockNumber > 0 && block.Number().Uint64() > m.forkBlockNumber

		if isForkTransaction {
			// 新交易：Anvil 当前状态已正确，无需 StateOverride
			log.Printf("   [Simulator] 检测到 Fork 后的新交易（区块 %d > Fork %d），跳过 StateOverride",
				block.Number().Uint64(), m.forkBlockNumber)

			// 直接使用当前状态重放交易（不需要额外的 StateOverride）
			replay, repErr := m.sim.ReplayTransactionWithOverride(ctx, tx, block.NumberU64(), nil, common.Address{})
			if repErr != nil {
				log.Printf("     回放交易失败: %v", repErr)
			} else {
				replayResult = replay
			}
		} else {
			// 历史交易：使用prestate重放
			replay, repErr := m.sim.ReplayTransactionWithOverride(ctx, tx, block.NumberU64(), override, common.Address{})
			if repErr != nil {
				log.Printf("     回放交易获取状态变更失败: %v", repErr)
			} else {
				replayResult = replay
			}
		}

		// 处理回放结果
		if replayResult != nil {
			totalChanges := len(replayResult.StateChanges)
			protectedChanges := countProtectedChanges(replayResult.StateChanges, m.registry)
			if replayResult.Success {
				log.Printf("    回放完成: success=true, stateChanges=%d (受保护=%d), jumpDests=%d", totalChanges, protectedChanges, len(replayResult.ContractJumpDests))
			} else {
				log.Printf("    回放完成: success=false, stateChanges=%d (受保护=%d), jumpDests=%d, error=%s", totalChanges, protectedChanges, len(replayResult.ContractJumpDests), strings.TrimSpace(replayResult.Error))
				if replayResult.ReturnData != "" && replayResult.ReturnData != "0x" {
					log.Printf("    回放返回数据: %s", replayResult.ReturnData)
				}
			}

			if totalChanges > 0 {
				logged := 0
				for addrStr, change := range replayResult.StateChanges {
					log.Printf("      [StateChange] %s balance %s -> %s, slots=%d", addrStr, change.BalanceBefore, change.BalanceAfter, len(change.StorageChanges))
					logged++
					if logged >= 3 {
						break
					}
				}
			} else {
				log.Printf("      [StateChange] 此次回放未捕获任何状态变更，可能为空操作或预状态缺失")
			}
		}
	}

	if replayResult != nil && replayResult.Success {
		applyStateChangesToProtected(afterStates, replayResult.StateChanges)
		applyStateChangesToProtected(rollingStates, replayResult.StateChanges)
	} else {
		// 【优化】回放失败时的处理
		if m.forkBlockNumber > 0 && block.Number().Uint64() > m.forkBlockNumber {
			// Fork 测试场景：直接使用 rollingStates（已经正确）
			log.Printf("   [ReplayFallback] Fork 测试场景，直接使用 rollingStates")
			afterStates = collectContractStates(protectedContracts, rollingStates)
		} else {
			// 非 Fork 场景：回退到链上实际状态
			log.Printf("   [ReplayFallback] 回放失败，使用链上区块状态作为交易后状态")
			onChainStates := make(map[common.Address]*invariants.ContractState)
			for _, addr := range protectedContracts {
				st, stErr := m.getContractState(ctx, addr, block)
				if stErr != nil {
					log.Printf("       获取区块状态失败 %s: %v", addr.Hex(), stErr)
					continue
				}
				onChainStates[addr] = st
				rollingStates[addr] = copyContractState(st) // 保持滚动状态与链上同步
			}
			afterStates = collectContractStates(protectedContracts, onChainStates, rollingStates)
		}
	}

	chainState := &invariants.ChainState{
		BlockNumber:    block.Number().Uint64(),
		BlockHash:      block.Hash(),
		TxHash:         actualTxHash,
		Timestamp:      block.Time(),
		States:         collectContractStates(protectedContracts, afterStates),
		PreviousStates: beforeStates,
	}

	logProtectedStateDiff(beforeStates, chainState.States, protectedContracts)

	log.Printf("\n 开始不变量检查...")
	violations := m.evaluator.EvaluateTransaction(protectedContracts, chainState)
	if len(violations) > 0 {
		baselineBlock := block.NumberU64()
		if baselineBlock > 0 {
			baselineBlock--
		}
		log.Printf("   [攻击前状态] 来自区块 %d 的基线快照，合约数=%d", baselineBlock, len(beforeStates))
	}

	// 若检测到违规，优先导出精确规则
	if len(violations) > 0 {
		m.exportBaselineRules(tx, trace, protectedContracts)
	}

	// 触发 Fuzzing：
	// 1) 若检测到违规，始终触发
	// 2) 若未检测到违规，但开启了 AutoTrigger，则同样触发
	if m.fuzzing != nil && m.fuzzing.IsEnabled() {
		// 强制开启自动触发，确保每笔交易都会跑Fuzzing（即便未检测到违规）
		shouldAuto := true

		if len(violations) > 0 || shouldAuto {
			if len(violations) > 0 {
				log.Printf("\n 检测到 %d 个不变量违规，触发Fuzzing分析...", len(violations))
				for i, v := range violations {
					log.Printf("   [%d] %s: %s", i+1, v.InvariantName, v.Details.Message)
				}
			} else {
				log.Printf("\n 未发现违规，但已强制开启 AutoTrigger，执行Fuzzing...")
			}

			//  关键修复：等待交易trace数据完全可用
			// WebSocket接收区块通知时，Anvil的trace数据可能还在生成中
			// 根据实际测试，trace生成可能需要5-15秒
			waitTime := 15 * time.Second
			log.Printf("\n 等待%v确保Anvil完成trace数据生成...", waitTime)
			log.Printf(" 原因：WebSocket区块通知早于trace数据就绪（Anvil异步生成）")
			time.Sleep(waitTime)
			log.Printf("  等待完成，开始Fuzzing")

			// 筛选Fuzzing目标：优先选择有target_functions定义的合约（防火墙注入合约）
			fuzzingTargets := m.selectFuzzingTargets(protectedContracts)
			if len(fuzzingTargets) == 0 {
				log.Printf("\n   没有找到可Fuzz的目标合约")
			} else {
				log.Printf("\n 启动Fuzzing分析... (共 %d 个目标合约)", len(fuzzingTargets))
				// 使用交易所在区块的状态进行模拟；状态覆盖已由 prestateTracer/snapshot/attack_state 补齐
				fuzzBlockNumber := block.Number().Uint64()
				log.Printf("    [状态对齐] 使用区块 %d 的状态进行Fuzz模拟", fuzzBlockNumber)
				// 整个Fuzz+推送过程限定在配置超时内，设置下限避免过小导致兜底
				timeoutSeconds := 20
				if m.fuzzing != nil {
					if cfg := m.fuzzing.GetConfig(); cfg != nil && cfg.TimeoutSeconds > 0 {
						timeoutSeconds = cfg.TimeoutSeconds
					}
				}
				if timeoutSeconds < 20 {
					timeoutSeconds = 20
				}
				fuzzCtx, fuzzCancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
				defer fuzzCancel()

				for _, contractAddr := range fuzzingTargets {
					log.Printf("    Fuzzing合约: %s", contractAddr.Hex())
					fuzzResults, reports, err := m.fuzzing.ProcessTransaction(fuzzCtx, tx, fuzzBlockNumber, contractAddr, actualTxHash)
					if err != nil {
						log.Printf("       Fuzzing失败: %v", err)
						continue
					}
					if len(reports) == 0 {
						log.Printf("       未生成任何规则报告")
						continue
					}

					for idx, report := range reports {
						if report == nil {
							continue
						}
						var fuzzResult *FuzzingResult
						if idx < len(fuzzResults) {
							fuzzResult = fuzzResults[idx]
						}

						log.Printf("      ▶ 目标函数: %s", report.FunctionSig)
						if fuzzResult != nil && fuzzResult.Success {
							log.Printf("         有效组合: %d / %d, 最高相似度: %.4f", fuzzResult.ValidCombinations, fuzzResult.TotalCombinations, fuzzResult.MaxSimilarity)
							if len(fuzzResult.ValidParameters) > 0 {
								log.Printf("         提取到 %d 个参数规则", len(fuzzResult.ValidParameters))
							}
						} else {
							log.Printf("         未发现有效参数组合")
						}

						// 若启用 Oracle 推送，提交报告（由Oracle模块决定是否跳过）
						if m.oracle != nil {
							log.Printf("         推送规则到链上...")
							if err := m.oracle.ProcessFuzzingResult(fuzzCtx, report); err != nil {
								log.Printf("          Oracle推送失败: %v", err)
							} else {
								log.Printf("          规则已添加到推送队列")
							}
						}
					}
				}
			}
		} else {
			log.Printf("\n 没有检测到不变量违规，AutoTrigger未启用，不执行Fuzzing")
		}
	}

	log.Printf("\n 交易处理完成")
	log.Printf(strings.Repeat("=", 80))
	return violations
}

func (m *BlockchainMonitor) capturePreBlockStates(ctx context.Context, block *types.Block, contracts []common.Address) map[common.Address]*invariants.ContractState {
	result := make(map[common.Address]*invariants.ContractState)
	if block == nil || len(contracts) == 0 {
		return result
	}

	if block.NumberU64() == 0 {
		return result
	}

	parent := new(big.Int).Sub(block.Number(), big.NewInt(1))
	for _, addr := range contracts {
		state, err := m.getContractStateAtBlock(ctx, addr, parent)
		if err != nil {
			log.Printf("     基线状态获取失败 %s: %v", addr.Hex(), err)
			continue
		}
		result[addr] = state
	}

	return result
}

func cloneContractStateMap(src map[common.Address]*invariants.ContractState) map[common.Address]*invariants.ContractState {
	if len(src) == 0 {
		return map[common.Address]*invariants.ContractState{}
	}
	out := make(map[common.Address]*invariants.ContractState, len(src))
	for addr, state := range src {
		out[addr] = copyContractState(state)
	}
	return out
}

func copyContractState(state *invariants.ContractState) *invariants.ContractState {
	if state == nil {
		return nil
	}
	balance := state.Balance
	if balance == nil {
		balance = big.NewInt(0)
	}
	copyStorage := make(map[common.Hash]common.Hash, len(state.Storage))
	for k, v := range state.Storage {
		copyStorage[k] = v
	}
	return &invariants.ContractState{
		Address: state.Address,
		Balance: new(big.Int).Set(balance),
		Storage: copyStorage,
		Code:    state.Code,
	}
}

func collectContractStates(contracts []common.Address, sources ...map[common.Address]*invariants.ContractState) map[common.Address]*invariants.ContractState {
	result := make(map[common.Address]*invariants.ContractState)
	for _, addr := range contracts {
		for _, src := range sources {
			if src == nil {
				continue
			}
			if st, ok := src[addr]; ok && st != nil {
				result[addr] = copyContractState(st)
				break
			}
		}
		if _, exists := result[addr]; !exists {
			result[addr] = &invariants.ContractState{
				Address: addr,
				Balance: big.NewInt(0),
				Storage: make(map[common.Hash]common.Hash),
			}
		}
	}
	return result
}

func applyStateChangesToProtected(target map[common.Address]*invariants.ContractState, changes map[string]simulator.StateChange) {
	if len(changes) == 0 {
		return
	}
	for addrStr, change := range changes {
		addr := common.HexToAddress(addrStr)
		state, ok := target[addr]
		if !ok || state == nil {
			continue
		}

		if bal := parseHexToBig(change.BalanceAfter); bal != nil {
			state.Balance = bal
		}

		if state.Storage == nil {
			state.Storage = make(map[common.Hash]common.Hash)
		}
		for slot, upd := range change.StorageChanges {
			state.Storage[common.HexToHash(slot)] = common.HexToHash(upd.After)
		}
	}
}

func parseHexToBig(v string) *big.Int {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	lower := strings.TrimPrefix(strings.ToLower(v), "0x")
	if lower == "" {
		return big.NewInt(0)
	}
	bi := new(big.Int)
	if _, ok := bi.SetString(lower, 16); ok {
		return bi
	}
	return nil
}

func countProtectedChanges(changes map[string]simulator.StateChange, registry *invariants.Registry) int {
	if len(changes) == 0 || registry == nil {
		return 0
	}
	protected := 0
	for addrStr := range changes {
		if registry.IsProtectedContract(common.HexToAddress(addrStr)) {
			protected++
		}
	}
	return protected
}

type slotChange struct {
	slot   common.Hash
	before common.Hash
	after  common.Hash
}

func logProtectedStateDiff(before, after map[common.Address]*invariants.ContractState, contracts []common.Address) {
	if len(contracts) == 0 {
		return
	}

	const maxSlotLogs = 3
	for _, addr := range contracts {
		beforeState := before[addr]
		afterState := after[addr]

		beforeBalance := big.NewInt(0)
		if beforeState != nil && beforeState.Balance != nil {
			beforeBalance = new(big.Int).Set(beforeState.Balance)
		}
		afterBalance := big.NewInt(0)
		if afterState != nil && afterState.Balance != nil {
			afterBalance = new(big.Int).Set(afterState.Balance)
		}

		delta := new(big.Int).Sub(afterBalance, beforeBalance)
		beforeSlots := 0
		if beforeState != nil {
			beforeSlots = len(beforeState.Storage)
		}
		afterSlots := 0
		if afterState != nil {
			afterSlots = len(afterState.Storage)
		}

		changes := diffSlots(beforeState, afterState, maxSlotLogs)
		if len(changes) == 0 && delta.Sign() == 0 {
			log.Printf("   [StateDiff] %s 无变化 (slot前=%d, 后=%d)", addr.Hex(), beforeSlots, afterSlots)
			continue
		}

		log.Printf("   [StateDiff] %s balanceΔ=%s, slot变更样本=%d (前=%d, 后=%d)", addr.Hex(), delta.String(), len(changes), beforeSlots, afterSlots)
		for _, c := range changes {
			log.Printf("      slot %s: %s -> %s", c.slot.Hex(), c.before.Hex(), c.after.Hex())
		}
	}
}

func diffSlots(before, after *invariants.ContractState, limit int) []slotChange {
	if limit <= 0 {
		return nil
	}

	result := make([]slotChange, 0, limit)
	seen := make(map[common.Hash]bool)

	if after != nil {
		for slot, afterVal := range after.Storage {
			seen[slot] = true
			var beforeVal common.Hash
			if before != nil {
				beforeVal = before.Storage[slot]
			}
			if afterVal != beforeVal {
				result = append(result, slotChange{slot: slot, before: beforeVal, after: afterVal})
				if len(result) >= limit {
					return result
				}
			}
		}
	}

	if before != nil && len(result) < limit {
		for slot, beforeVal := range before.Storage {
			if seen[slot] {
				continue
			}
			result = append(result, slotChange{slot: slot, before: beforeVal, after: common.Hash{}})
			if len(result) >= limit {
				break
			}
		}
	}

	return result
}

// fetchTransactionInBlock 同时获取交易对象及RPC返回的真实哈希
func (m *BlockchainMonitor) fetchTransactionInBlock(ctx context.Context, blockHash common.Hash, index uint) (*types.Transaction, common.Hash, error) {
	tx, err := m.client.TransactionInBlock(ctx, blockHash, index)
	if err != nil {
		return nil, common.Hash{}, err
	}

	var rpcTx struct {
		Hash common.Hash `json:"hash"`
	}
	paramIndex := hexutil.Uint64(uint64(index))
	if err := m.rpcClient.CallContext(ctx, &rpcTx, "eth_getTransactionByBlockHashAndIndex", blockHash, paramIndex); err != nil {
		return tx, common.Hash{}, err
	}

	if (rpcTx.Hash == common.Hash{}) {
		return tx, tx.Hash(), nil
	}

	return tx, rpcTx.Hash, nil
}

// ConfigureOracle 配置链上推送（Autopatch Oracle）
func (m *BlockchainMonitor) ConfigureOracle(config *OracleConfig) error {
	if config == nil || !config.Enabled {
		m.oracle = nil
		log.Println("Oracle integration disabled")
		return nil
	}

	oi, err := NewOracleIntegration(config)
	if err != nil {
		return fmt.Errorf("failed to create oracle integration: %w", err)
	}
	m.oracle = oi
	log.Printf("Oracle integration enabled. Module: %s", config.ModuleAddress)
	return nil
}

// findProtectedContracts 递归查找受保护的合约
func (m *BlockchainMonitor) findProtectedContracts(trace *CallFrame) []common.Address {
	var contracts []common.Address
	seen := make(map[common.Address]bool)

	m.findProtectedContractsRecursive(trace, &contracts, seen)

	return contracts
}

// findProtectedContractsRecursive 递归查找受保护的合约
func (m *BlockchainMonitor) findProtectedContractsRecursive(frame *CallFrame, contracts *[]common.Address, seen map[common.Address]bool) {
	if frame.To != "" {
		addr := common.HexToAddress(frame.To)
		if !seen[addr] && m.registry.IsProtectedContract(addr) {
			*contracts = append(*contracts, addr)
			seen[addr] = true
			log.Printf("      [Trace]  找到受保护合约: %s", addr.Hex())
		}
	}

	for i := range frame.Calls {
		call := frame.Calls[i]
		m.findProtectedContractsRecursive(&call, contracts, seen)
	}
}

// selectFuzzingTargets 选择Fuzzing目标合约
// 只选择配置中有target_functions定义的合约（防火墙注入合约）
// 如果没有找到，返回空列表以避免对无关合约（如标准token）进行Fuzzing
func (m *BlockchainMonitor) selectFuzzingTargets(protectedContracts []common.Address) []common.Address {
	// 筛选出有target_functions定义的合约
	var priorityTargets []common.Address
	for _, addr := range protectedContracts {
		if m.registry.HasFuzzingTargetFunction(addr) {
			priorityTargets = append(priorityTargets, addr)
		}
	}

	if len(priorityTargets) > 0 {
		log.Printf("    优先选择防火墙注入合约作为Fuzzing目标 (%d个)", len(priorityTargets))
		for _, addr := range priorityTargets {
			log.Printf("      - %s (有target_functions定义)", addr.Hex())
		}
		return priorityTargets
	}

	// 没有明确的target_functions定义，返回空列表（避免对无关合约进行Fuzzing）
	log.Printf("     未找到有target_functions定义的合约，跳过Fuzzing")
	return nil
}

// getChainState 获取链状态
func (m *BlockchainMonitor) getChainState(ctx context.Context, block *types.Block, txHash common.Hash) (*invariants.ChainState, error) {
	state := &invariants.ChainState{
		BlockNumber: block.Number().Uint64(),
		BlockHash:   block.Hash(),
		TxHash:      txHash,
		Timestamp:   block.Time(),
		States:      make(map[common.Address]*invariants.ContractState),
	}

	// 获取所有受保护合约的状态
	contracts := m.registry.GetAllProtectedContracts()
	for _, addr := range contracts {
		contractState, err := m.getContractState(ctx, addr, block)
		if err != nil {
			log.Printf("Failed to get state for contract %s: %v", addr.Hex(), err)
			continue
		}
		state.States[addr] = contractState
	}

	return state, nil
}

// getContractState 获取合约状态
func (m *BlockchainMonitor) getContractState(ctx context.Context, addr common.Address, block *types.Block) (*invariants.ContractState, error) {
	if m.storageFetcher == nil {
		return &invariants.ContractState{
			Address: addr,
			Balance: big.NewInt(0),
			Storage: make(map[common.Hash]common.Hash),
			Code:    []byte{},
		}, nil
	}

	blockHash := block.Hash()
	blockNumber := block.Number()

	state, err := m.storageFetcher.PopulateContractState(ctx, addr, blockHash, blockNumber)
	if err != nil {
		return nil, err
	}

	return state, nil
}

// getContractStateAtBlock 获取指定区块高度的合约状态
func (m *BlockchainMonitor) getContractStateAtBlock(ctx context.Context, addr common.Address, blockNumber *big.Int) (*invariants.ContractState, error) {
	if m.storageFetcher == nil {
		return &invariants.ContractState{
			Address: addr,
			Balance: big.NewInt(0),
			Storage: make(map[common.Hash]common.Hash),
			Code:    []byte{},
		}, nil
	}

	// 使用空hash，storage_fetcher会根据blockNumber查询
	state, err := m.storageFetcher.PopulateContractState(ctx, addr, common.Hash{}, blockNumber)
	if err != nil {
		return nil, err
	}

	return state, nil
}

// exportBaselineRules 将首笔违规交易的参数导出为精确规则
func (m *BlockchainMonitor) exportBaselineRules(tx *types.Transaction, trace *CallFrame, contracts []common.Address) {
	if m.ruleExporter == nil || trace == nil {
		return
	}

	for _, contract := range contracts {
		calls := m.tracer.FindContractCalls(trace, contract.Hex())
		if len(calls) == 0 {
			continue
		}

		input := strings.TrimPrefix(calls[0].Input, "0x")
		if len(input) < 8 {
			continue
		}

		funcSigHex := input[:8]
		var funcSig [4]byte
		if sigBytes, err := hex.DecodeString(funcSigHex); err == nil && len(sigBytes) == 4 {
			copy(funcSig[:], sigBytes)
		} else {
			continue
		}

		key := fmt.Sprintf("%s-%s", strings.ToLower(contract.Hex()), funcSigHex)

		m.baselineRuleMutex.Lock()
		if m.baselineRecorded[key] {
			m.baselineRuleMutex.Unlock()
			continue
		}
		m.baselineRecorded[key] = true
		m.baselineRuleMutex.Unlock()

		paramSummaries := buildParameterSummaries(input[8:])
		if len(paramSummaries) == 0 {
			log.Printf("[BaselineRule] No parameters extracted for %s %s, skipping export", contract.Hex(), funcSigHex)
			continue
		}

		if m.registry != nil && !m.registry.IsTargetFunction(contract, funcSig) {
			log.Printf("[BaselineRule] Skip non-target function rule export: %s %s", contract.Hex(), funcSigHex)
			continue
		}

		if err := m.ruleExporter.ExportRules(contract, funcSig, paramSummaries, 1.0); err != nil {
			log.Printf("[BaselineRule] Failed to export rule for %s %s: %v", contract.Hex(), funcSigHex, err)
		} else {
			log.Printf("[BaselineRule] Exported baseline rule for %s %s", contract.Hex(), funcSigHex)

			// 自动推送基线规则到链上 (如果启用了Oracle)
			if m.oracle != nil {
				report := &fuzzer.AttackParameterReport{
					ContractAddress:   contract,
					FunctionSig:       funcSigHex,
					ValidParameters:   paramSummaries,
					Timestamp:         time.Now(),
					OriginalTxHash:    tx.Hash(),
					TotalCombinations: 1,
					ValidCombinations: 1,
					MaxSimilarity:     1.0,
				}
				ctx := context.Background()
				if err := m.oracle.ProcessFuzzingResult(ctx, report); err != nil {
					log.Printf("[BaselineRule] Oracle推送失败: %v", err)
				} else {
					log.Printf("[BaselineRule]  基线规则已添加到推送队列")
				}
			}
		}
	}
}

// buildParameterSummaries 根据calldata构建参数摘要
func buildParameterSummaries(paramsHex string) []fuzzer.ParameterSummary {
	if len(paramsHex)%64 != 0 {
		// 不对齐的calldata，忽略
		return nil
	}

	count := len(paramsHex) / 64
	summaries := make([]fuzzer.ParameterSummary, 0, count)

	for i := 0; i < count; i++ {
		word := paramsHex[i*64 : (i+1)*64]
		valueHex := "0x" + word

		paramType := inferParamType(word)

		summaries = append(summaries, fuzzer.ParameterSummary{
			ParamIndex:      i,
			ParamType:       paramType,
			SingleValues:    []string{valueHex},
			IsRange:         false,
			OccurrenceCount: 1,
		})
	}

	return summaries
}

// inferParamType 简单推断参数类型
func inferParamType(word string) string {
	lower := strings.ToLower(word)

	if looksLikeAddressWord(lower) {
		return "address"
	}

	// 布尔：前63位为0，最后一位为0或1
	if isBoolWord(lower) {
		return "bool"
	}

	return "uint256"
}

func looksLikeAddressWord(word string) bool {
	if len(word) != 64 {
		return false
	}
	if !strings.HasPrefix(word, strings.Repeat("0", 24)) {
		return false
	}
	body := word[24:]
	if strings.Trim(body, "0") == "" {
		return false
	}
	for _, ch := range body {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func isBoolWord(word string) bool {
	if len(word) != 64 {
		return false
	}
	if !strings.HasPrefix(word, strings.Repeat("0", 63)) {
		return false
	}
	last := word[len(word)-1]
	return last == '0' || last == '1'
}

// handleViolations 处理违规
func (m *BlockchainMonitor) handleViolations(violations []invariants.ViolationResult, block *types.Block) {
	for _, violation := range violations {
		log.Printf(" Invariant violation detected!")
		log.Printf("  Block: %d", violation.BlockNumber)
		log.Printf("  Transaction: %s", violation.Transaction.Hex())
		log.Printf("  Invariant: %s (%s)", violation.InvariantName, violation.InvariantID)
		log.Printf("  Project: %s", violation.ProjectID)

		if violation.Details != nil {
			log.Printf("  Message: %s", violation.Details.Message)
			log.Printf("  Actual: %v", violation.Details.ActualValue)
			log.Printf("  Expected: %v", violation.Details.ExpectedValue)
		}

		// 发送告警
		m.alertManager.SendAlert(violation)
	}
}

// reconnectAndResume 重连并恢复
func (m *BlockchainMonitor) reconnectAndResume(ctx context.Context) {
	log.Println("Attempting to reconnect...")

	backoff := time.Second
	maxBackoff := time.Minute

	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopChan:
			return
		case <-time.After(backoff):
			if err := m.Start(ctx); err == nil {
				log.Println("Reconnected successfully")
				return
			}

			// 指数退避
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// loadBaselineState 从JSON文件加载预保存的基线状态
// 用于Fork测试场景，避免运行时重复获取固定的攻击前状态
func (m *BlockchainMonitor) loadBaselineState(protectedList []common.Address) map[common.Address]*invariants.ContractState {
	// 基线状态JSON结构
	type BaselineContract struct {
		Balance string            `json:"balance"`
		Code    string            `json:"code"`
		Storage map[string]string `json:"storage"`
	}

	type BaselineState struct {
		BlockNumber uint64                      `json:"block_number"`
		Contracts   map[string]BaselineContract `json:"contracts"`
	}

	// 读取文件
	data, err := os.ReadFile(m.baselineStateFile)
	if err != nil {
		log.Printf("❌ 读取基线状态文件失败: %v，回退到链上获取", err)
		return make(map[common.Address]*invariants.ContractState)
	}

	// 解析JSON
	var baseline BaselineState
	if err := json.Unmarshal(data, &baseline); err != nil {
		log.Printf("❌ 解析基线状态文件失败: %v", err)
		return make(map[common.Address]*invariants.ContractState)
	}

	// 转换为ContractState映射
	result := make(map[common.Address]*invariants.ContractState)

	for addrStr, contractData := range baseline.Contracts {
		addr := common.HexToAddress(addrStr)

		// 解析 balance (十六进制字符串 -> big.Int)
		balance := new(big.Int)
		if contractData.Balance != "" && contractData.Balance != "0x" {
			balanceStr := strings.TrimPrefix(contractData.Balance, "0x")
			if balanceStr != "" {
				if _, ok := balance.SetString(balanceStr, 16); !ok {
					log.Printf("⚠️  解析合约 %s 的balance失败: %s", addrStr, contractData.Balance)
					balance = big.NewInt(0)
				}
			}
		}

		// 解析 code (十六进制字符串 -> []byte)
		code := common.FromHex(contractData.Code)

		// 解析 storage (map[string]string -> map[common.Hash]common.Hash)
		storage := make(map[common.Hash]common.Hash)
		for slotStr, valueStr := range contractData.Storage {
			slot := common.HexToHash(slotStr)
			value := common.HexToHash(valueStr)
			storage[slot] = value
		}

		result[addr] = &invariants.ContractState{
			Address: addr,
			Balance: balance,
			Code:    code,
			Storage: storage,
		}
	}

	log.Printf("✅ 成功加载 %d 个合约的基线状态（区块 %d）", len(result), baseline.BlockNumber)

	// 保存 Fork 区块号（用于后续判断是否是新交易）
	m.forkBlockNumber = baseline.BlockNumber

	// 验证是否包含所有受保护合约
	missing := 0
	for _, addr := range protectedList {
		if _, ok := result[addr]; !ok {
			log.Printf("⚠️  基线状态缺少受保护合约: %s", addr.Hex())
			missing++
		}
	}

	if missing > 0 {
		log.Printf("⚠️  共有 %d 个受保护合约缺少基线状态", missing)
	}

	return result
}
