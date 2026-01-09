package monitor

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"autopath/pkg/fuzzer"
	"autopath/pkg/pusher"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// OracleIntegration Oracle推送集成模块
type OracleIntegration struct {
	pusher       *pusher.OraclePusher
	converter    *pusher.DataConverter
	config       *OracleConfig
	enabled      bool
	resultBuffer []*fuzzer.AttackParameterReport
	bufferMutex  sync.Mutex
	pushHistory  map[string]time.Time
	historyMutex sync.RWMutex
	ruleExporter *RuleExporter
}

// OracleConfig Oracle集成配置
type OracleConfig struct {
	Enabled           bool              `json:"enabled"`
	ModuleAddress     string            `json:"module_address"`
	PrivateKey        string            `json:"private_key"`
	RPCURL            string            `json:"rpc_url"`
	ChainID           int64             `json:"chain_id"`
	PushThreshold     float64           `json:"push_threshold"`
	BatchSize         int               `json:"batch_size"`
	FlushInterval     time.Duration     `json:"flush_interval"`
	MaxRulesPerFunc   int               `json:"max_rules_per_func"`
	CompressRanges    bool              `json:"compress_ranges"`
	MaxValuesPerParam int               `json:"max_values_per_param"`
	AutoPush          bool              `json:"auto_push"`
	ProjectMapping    map[string]string `json:"project_mapping"` // contract -> project address

	// 规则导出配置
	RuleExportPath   string `json:"rule_export_path"`
	EnableRuleExport bool   `json:"enable_rule_export"`
	RuleExportFormat string `json:"rule_export_format"` // json, yaml
}

// NewOracleIntegration 创建Oracle集成模块
func NewOracleIntegration(config *OracleConfig) (*OracleIntegration, error) {
	if config == nil || !config.Enabled {
		return &OracleIntegration{enabled: false}, nil
	}

	// 创建推送器配置
	pusherConfig := &pusher.PusherConfig{
		RPCURL:          config.RPCURL,
		ModuleAddress:   config.ModuleAddress,
		PrivateKey:      config.PrivateKey,
		ChainID:         config.ChainID,
		PushThreshold:   config.PushThreshold,
		BatchSize:       config.BatchSize,
		RetryCount:      3,
		RetryDelay:      5 * time.Second,
		MinInterval:     1 * time.Hour,
		GasLimit:        500000,
		MaxRulesPerFunc: config.MaxRulesPerFunc,
	}

	// 创建推送器
	oraclePusher, err := pusher.NewOraclePusher(pusherConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create oracle pusher: %w", err)
	}

	// 创建数据转换器
	converter := pusher.NewDataConverter(
		config.MaxValuesPerParam,
		config.CompressRanges,
	)

	// 创建规则导出器
	ruleExporter := NewRuleExporter(
		config.RuleExportPath,
		config.EnableRuleExport,
		config.RuleExportFormat,
	)

	return &OracleIntegration{
		pusher:       oraclePusher,
		converter:    converter,
		config:       config,
		enabled:      true,
		resultBuffer: make([]*fuzzer.AttackParameterReport, 0),
		pushHistory:  make(map[string]time.Time),
		ruleExporter: ruleExporter,
	}, nil
}

// ProcessFuzzingResult 处理fuzzing结果
func (oi *OracleIntegration) ProcessFuzzingResult(
	ctx context.Context,
	report *fuzzer.AttackParameterReport,
) error {
	if !oi.enabled {
		return nil
	}

	// 规范化并校验函数选择器，防止签名/selector错位
	funcSig, err := oi.normalizeReportSignature(report)
	if err != nil {
		return fmt.Errorf("normalize report signature failed: %w", err)
	}

	// 检查是否满足推送条件
	if !oi.shouldPush(report) {
		log.Printf("[OracleIntegration] Report doesn't meet push criteria, skipping")
		return nil
	}

	// 说明：项目地址与函数签名在分组推送阶段解析，这里无需提前解析

	// 优化参数
	optimizedParams := oi.converter.OptimizeParameters(report.ValidParameters)

	// 更新报告
	report.ValidParameters = optimizedParams

	// 添加到缓冲区
	oi.bufferMutex.Lock()
	oi.resultBuffer = append(oi.resultBuffer, report)
	bufferSize := len(oi.resultBuffer)
	oi.bufferMutex.Unlock()

	// 立即导出表达式规则（链下存档），不依赖批处理
	if oi.ruleExporter != nil && len(report.ExpressionRules) > 0 {
		if err := oi.ruleExporter.ExportExpressionRules(report.ContractAddress, funcSig, report.ExpressionRules); err != nil {
			log.Printf("[OracleIntegration] Export expression rules failed: %v", err)
		}
	}

	log.Printf("[OracleIntegration] Added report to buffer (size: %d)", bufferSize)

	// 如果启用自动推送且缓冲区满，立即推送
	if oi.config.AutoPush && bufferSize >= oi.config.BatchSize {
		return oi.FlushBuffer(ctx)
	}

	return nil
}

// shouldPush 判断是否应该推送
func (oi *OracleIntegration) shouldPush(report *fuzzer.AttackParameterReport) bool {
	// 有表达式规则优先推送；若没有表达式但存在参数范围/离散值，也允许推送
	hasExpr := len(report.ExpressionRules) > 0
	hasParams := len(report.ValidParameters) > 0
	if !hasExpr && !hasParams {
		return false
	}

	// 检查相似度阈值
	if report.MaxSimilarity < oi.config.PushThreshold {
		return false
	}

	// 检查推送历史，避免重复推送
	key := fmt.Sprintf("%s-%s", report.ContractAddress.Hex(), report.FunctionSig)
	oi.historyMutex.RLock()
	lastPush, exists := oi.pushHistory[key]
	oi.historyMutex.RUnlock()

	if exists && time.Since(lastPush) < time.Hour {
		log.Printf("[OracleIntegration] Too soon since last push for %s", key)
		return false
	}

	return true
}

// getProjectAddress 获取项目地址
func (oi *OracleIntegration) getProjectAddress(contractAddr common.Address) (common.Address, error) {
	// 从映射表中查找
	if projectStr, ok := oi.config.ProjectMapping[contractAddr.Hex()]; ok {
		return common.HexToAddress(projectStr), nil
	}

	// 默认使用合约地址作为项目地址
	return contractAddr, nil
}

// parseFunctionSignature 解析函数签名
func (oi *OracleIntegration) parseFunctionSignature(sig string) ([4]byte, error) {
	var result [4]byte

	cleaned := strings.TrimSpace(sig)
	if cleaned == "" {
		return result, fmt.Errorf("empty function signature")
	}

	// 如果包含参数列表，视为完整签名，直接计算selector
	if strings.Contains(cleaned, "(") {
		hash := crypto.Keccak256([]byte(cleaned))
		copy(result[:], hash[:4])
		return result, nil
	}

	// 移除0x前缀
	cleaned = removeHexPrefix(cleaned)

	// 确保是8个字符（4字节）
	if len(cleaned) != 8 {
		return result, fmt.Errorf("invalid function signature length: %s", sig)
	}

	decoded, err := hex.DecodeString(cleaned)
	if err != nil || len(decoded) != 4 {
		return result, fmt.Errorf("failed to decode selector %s: %w", sig, err)
	}
	copy(result[:], decoded[:4])

	return result, nil
}

func formatSelectorHex(sel [4]byte) string {
	return "0x" + hex.EncodeToString(sel[:])
}

// normalizeReportSignature 标准化并校验报告中的selector/签名
func (oi *OracleIntegration) normalizeReportSignature(report *fuzzer.AttackParameterReport) ([4]byte, error) {
	var selector [4]byte
	if report == nil {
		return selector, fmt.Errorf("nil report")
	}

	// 优先使用完整函数签名校验 selector，避免名称与selector错配
	if sig := strings.TrimSpace(report.FunctionSignature); sig != "" {
		parsed, err := oi.parseFunctionSignature(sig)
		if err == nil {
			if repSel, repErr := oi.parseFunctionSignature(report.FunctionSig); repErr == nil && !bytes.Equal(parsed[:], repSel[:]) {
				log.Printf("[OracleIntegration] Selector mismatch, canonical=%s, report=%s，使用canonical纠正",
					formatSelectorHex(parsed), formatSelectorHex(repSel))
			}
			report.FunctionSig = formatSelectorHex(parsed)
			return parsed, nil
		}
		log.Printf("[OracleIntegration] 无法解析完整签名 %s: %v", sig, err)
	}

	// 回退仅使用 selector 字段
	parsed, err := oi.parseFunctionSignature(report.FunctionSig)
	if err != nil {
		return selector, err
	}
	report.FunctionSig = formatSelectorHex(parsed)
	return parsed, nil
}

// FlushBuffer 推送缓冲区中的报告
func (oi *OracleIntegration) FlushBuffer(ctx context.Context) error {
	oi.bufferMutex.Lock()
	reports := oi.resultBuffer
	oi.resultBuffer = make([]*fuzzer.AttackParameterReport, 0)
	oi.bufferMutex.Unlock()

	if len(reports) == 0 {
		return nil
	}

	log.Printf("[OracleIntegration] Flushing %d reports to chain", len(reports))

	// 按项目和函数分组
	grouped := oi.groupReports(reports)

	// 推送每个组
	var errors []error
	for key, group := range grouped {
		if err := oi.pushGroup(ctx, key, group); err != nil {
			log.Printf("[OracleIntegration] Failed to push group %s: %v", key, err)
			errors = append(errors, err)
		} else {
			// 更新推送历史
			oi.historyMutex.Lock()
			oi.pushHistory[key] = time.Now()
			oi.historyMutex.Unlock()
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("push errors: %v", errors)
	}

	return nil
}

// groupReports 分组报告
func (oi *OracleIntegration) groupReports(reports []*fuzzer.AttackParameterReport) map[string][]*fuzzer.AttackParameterReport {
	grouped := make(map[string][]*fuzzer.AttackParameterReport)

	for _, report := range reports {
		projectAddr, _ := oi.getProjectAddress(report.ContractAddress)
		key := fmt.Sprintf("%s-%s", projectAddr.Hex(), report.FunctionSig)
		grouped[key] = append(grouped[key], report)
	}

	return grouped
}

// pushGroup 推送一组报告
func (oi *OracleIntegration) pushGroup(ctx context.Context, key string, reports []*fuzzer.AttackParameterReport) error {
	if len(reports) == 0 {
		return nil
	}

	// 获取最新报告的信息
	latest := reports[len(reports)-1]
	projectAddr, _ := oi.getProjectAddress(latest.ContractAddress)
	funcSig, err := oi.normalizeReportSignature(latest)
	if err != nil {
		return fmt.Errorf("invalid function signature: %w", err)
	}

	// 合并报告中的参数；若包含约束规则则优先使用约束生成的参数摘要
	mergedParams := oi.mergeReportParameters(reports)
	if latest.ConstraintRule != nil && len(latest.ConstraintRule.ParamConstraints) > 0 {
		if summaries := convertParamConstraintsToSummaries(latest.ConstraintRule.ParamConstraints); len(summaries) > 0 {
			mergedParams = summaries
		}
	}

	// 汇总表达式规则：合并所有报告中出现的表达式，避免覆盖丢失
	exprRules := mergeExpressionRules(reports)

	// 调用推送器
	err = oi.pusher.ProcessFuzzingReport(ctx, projectAddr, funcSig, &fuzzer.AttackParameterReport{
		ContractAddress:   latest.ContractAddress,
		FunctionSig:       latest.FunctionSig,
		ValidParameters:   mergedParams,
		MaxSimilarity:     latest.MaxSimilarity,
		TotalCombinations: latest.TotalCombinations,
		ValidCombinations: latest.ValidCombinations,
		ConstraintRule:    latest.ConstraintRule,
		ExpressionRules:   exprRules,
	})

	// 如果推送成功，导出规则到文件
	if err == nil && oi.ruleExporter != nil {
		exportErr := oi.ruleExporter.ExportRules(
			projectAddr,
			funcSig,
			mergedParams,
			latest.MaxSimilarity,
		)
		if exportErr != nil {
			log.Printf("[OracleIntegration] Failed to export rules: %v", exportErr)
			// 不影响主流程，只记录错误
		}
		if len(exprRules) > 0 {
			if exprErr := oi.ruleExporter.ExportExpressionRules(projectAddr, funcSig, exprRules); exprErr != nil {
				log.Printf("[OracleIntegration] Failed to export expression rules: %v", exprErr)
			}
		}
	}

	return err
}

// mergeReportParameters 合并多个报告的参数
func (oi *OracleIntegration) mergeReportParameters(reports []*fuzzer.AttackParameterReport) []fuzzer.ParameterSummary {
	paramMap := make(map[int][]fuzzer.ParameterSummary)

	// 收集所有参数
	for _, report := range reports {
		for _, param := range report.ValidParameters {
			paramMap[param.ParamIndex] = append(paramMap[param.ParamIndex], param)
		}
	}

	// 合并相同索引的参数
	merged := make([]fuzzer.ParameterSummary, 0, len(paramMap))
	for idx, params := range paramMap {
		if len(params) == 1 {
			merged = append(merged, params[0])
		} else {
			// 合并多个参数
			mergedParam := oi.mergeParameters(params)
			mergedParam.ParamIndex = idx
			merged = append(merged, mergedParam)
		}
	}

	return merged
}

// mergeParameters 合并相同参数的多个摘要
func (oi *OracleIntegration) mergeParameters(params []fuzzer.ParameterSummary) fuzzer.ParameterSummary {
	if len(params) == 0 {
		return fuzzer.ParameterSummary{}
	}

	result := params[0]

	// 合并值
	valueSet := make(map[string]bool)
	for _, p := range params {
		if p.IsRange {
			// 如果有范围，扩展范围
			if result.IsRange {
				if p.RangeMin < result.RangeMin {
					result.RangeMin = p.RangeMin
				}
				if p.RangeMax > result.RangeMax {
					result.RangeMax = p.RangeMax
				}
			} else {
				// 转换为范围
				result.IsRange = true
				result.RangeMin = p.RangeMin
				result.RangeMax = p.RangeMax
				result.SingleValues = nil
			}
		} else {
			// 收集所有离散值
			for _, v := range p.SingleValues {
				valueSet[v] = true
			}
		}
		result.OccurrenceCount += p.OccurrenceCount
	}

	// 如果不是范围，更新离散值
	if !result.IsRange && len(valueSet) > 0 {
		result.SingleValues = make([]string, 0, len(valueSet))
		for v := range valueSet {
			result.SingleValues = append(result.SingleValues, v)
		}
	}

	return result
}

// convertParamConstraintsToSummaries 将约束转换为参数摘要，便于链上推送
func convertParamConstraintsToSummaries(constraints []fuzzer.ParamConstraint) []fuzzer.ParameterSummary {
	var out []fuzzer.ParameterSummary
	for _, c := range constraints {
		ps := fuzzer.ParameterSummary{
			ParamIndex:      c.Index,
			ParamType:       c.Type,
			OccurrenceCount: 1,
		}
		if c.IsRange {
			ps.IsRange = true
			ps.RangeMin = c.RangeMin
			ps.RangeMax = c.RangeMax
		} else if len(c.Values) > 0 {
			ps.SingleValues = c.Values
		}
		out = append(out, ps)
	}
	return out
}

// pickLatestExpressionRules 选择最近一次带有表达式约束的报告
func pickLatestExpressionRules(reports []*fuzzer.AttackParameterReport) []fuzzer.ExpressionRule {
	for i := len(reports) - 1; i >= 0; i-- {
		if len(reports[i].ExpressionRules) > 0 {
			// 返回一个拷贝，避免外部修改
			cp := make([]fuzzer.ExpressionRule, len(reports[i].ExpressionRules))
			copy(cp, reports[i].ExpressionRules)
			return cp
		}
	}
	return nil
}

// mergeExpressionRules 汇总所有报告的表达式规则，去重后返回
func mergeExpressionRules(reports []*fuzzer.AttackParameterReport) []fuzzer.ExpressionRule {
	type termKey struct {
		Kind       string
		ParamIndex int
		ParamType  string
		Slot       string
		Coeff      string
	}
	seen := make(map[string]struct{})
	var merged []fuzzer.ExpressionRule

	for _, r := range reports {
		for _, er := range r.ExpressionRules {
			// 为每个规则构造唯一 key 以做去重
			tkeys := make([]termKey, 0, len(er.Terms))
			for _, t := range er.Terms {
				tkeys = append(tkeys, termKey{
					Kind:       strings.ToLower(t.Kind),
					ParamIndex: t.ParamIndex,
					ParamType:  strings.ToLower(t.ParamType),
					Slot:       strings.ToLower(t.Slot),
					Coeff:      strings.ToLower(strings.TrimPrefix(t.Coeff, "0x")),
				})
			}
			b, _ := json.Marshal(tkeys)
			key := er.Type + "|" + strings.ToLower(er.Threshold) + "|" + strings.ToLower(er.Scale) + "|" + string(b)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			// 深拷贝避免外部修改
			cp := er
			if len(er.Terms) > 0 {
				cp.Terms = make([]fuzzer.LinearTerm, len(er.Terms))
				copy(cp.Terms, er.Terms)
			}
			merged = append(merged, cp)
		}
	}
	return merged
}

// Start 启动定期推送任务
func (oi *OracleIntegration) Start(ctx context.Context) {
	if !oi.enabled {
		return
	}

	// 启动推送器的定期任务
	go oi.pusher.Start(ctx, oi.config.FlushInterval)

	// 启动本地的定期刷新任务
	go func() {
		ticker := time.NewTicker(oi.config.FlushInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				// 最后一次刷新
				oi.FlushBuffer(context.Background())
				return
			case <-ticker.C:
				if err := oi.FlushBuffer(ctx); err != nil {
					log.Printf("[OracleIntegration] Failed to flush buffer: %v", err)
				}
			}
		}
	}()

	log.Printf("[OracleIntegration] Started with threshold %.2f, batch size %d",
		oi.config.PushThreshold, oi.config.BatchSize)

	// 启动链上事件监听（AutopatchApplied/AutopatchRule）
	go oi.startRuleEventListener(ctx)
}

// GetStats 获取统计信息
func (oi *OracleIntegration) GetStats() map[string]interface{} {
	oi.bufferMutex.Lock()
	bufferSize := len(oi.resultBuffer)
	oi.bufferMutex.Unlock()

	oi.historyMutex.RLock()
	historySize := len(oi.pushHistory)
	oi.historyMutex.RUnlock()

	pusherStats := map[string]interface{}{}
	if oi.pusher != nil {
		pusherStats = oi.pusher.GetStats()
	}

	return map[string]interface{}{
		"enabled":      oi.enabled,
		"buffer_size":  bufferSize,
		"history_size": historySize,
		"pusher_stats": pusherStats,
		"config":       oi.config,
	}
}

// startRuleEventListener 订阅 ParamCheckModule 的规则更新事件，便于链下确认
func (oi *OracleIntegration) startRuleEventListener(ctx context.Context) {
	if oi.config.ModuleAddress == "" || oi.config.RPCURL == "" {
		return
	}
	// 仅支持 WS / IPC 订阅
	cli, err := ethclient.Dial(oi.config.RPCURL)
	if err != nil {
		log.Printf("[OracleIntegration] RuleEvent listener dial failed: %v", err)
		return
	}
	module := common.HexToAddress(oi.config.ModuleAddress)

	// 构建仅包含事件的最小 ABI，用于解码
	abiJSON := `[
        {"anonymous":false,"inputs":[
            {"indexed":true,"name":"project","type":"address"},
            {"indexed":true,"name":"funcSig","type":"bytes4"},
            {"indexed":false,"name":"ruleCount","type":"uint256"},
            {"indexed":false,"name":"summaryHash","type":"bytes32"}
        ],"name":"AutopatchApplied","type":"event"},
        {"anonymous":false,"inputs":[
            {"indexed":true,"name":"project","type":"address"},
            {"indexed":true,"name":"funcSig","type":"bytes4"},
            {"indexed":false,"name":"ruleIdx","type":"uint8"},
            {"indexed":false,"name":"paramIndex","type":"uint8"},
            {"indexed":false,"name":"paramType","type":"uint8"},
            {"indexed":false,"name":"isRange","type":"bool"},
            {"indexed":false,"name":"rangeMin","type":"bytes32"},
            {"indexed":false,"name":"rangeMax","type":"bytes32"},
            {"indexed":false,"name":"valueCount","type":"uint256"}
        ],"name":"AutopatchRule","type":"event"}
    ]`
	evABI, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		log.Printf("[OracleIntegration] Build event ABI failed: %v", err)
		return
	}

	q := ethereum.FilterQuery{Addresses: []common.Address{module}}
	logsCh := make(chan types.Log, 64)
	sub, err := cli.SubscribeFilterLogs(ctx, q, logsCh)
	if err != nil {
		log.Printf("[OracleIntegration] Subscribe logs failed: %v", err)
		return
	}
	log.Printf("[OracleIntegration] Listening rule events on %s", module.Hex())

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case err := <-sub.Err():
				log.Printf("[OracleIntegration] RuleEvent subscription error: %v", err)
				return
			case lg := <-logsCh:
				// 尝试按两个事件解码
				if lg.Topics != nil && len(lg.Topics) > 0 {
					// AutopatchApplied(project,funcSig,ruleCount,summaryHash)
					if ev, ok := evABI.Events["AutopatchApplied"]; ok && lg.Topics[0] == ev.ID {
						var out struct {
							RuleCount   *big.Int
							SummaryHash [32]byte
						}
						// 索引参数从 Topics 取出
						project := common.HexToAddress(lg.Topics[1].Hex())
						funcSig := lg.Topics[2]
						if err := evABI.UnpackIntoInterface(&out, "AutopatchApplied", lg.Data); err == nil {
							log.Printf("[OracleIntegration] On-chain AutopatchApplied project=%s funcSig=%s rules=%s summary=%s",
								project.Hex(), funcSig.Hex(), out.RuleCount.String(), common.Bytes2Hex(out.SummaryHash[:]))
						} else {
							log.Printf("[OracleIntegration] Decode AutopatchApplied failed: %v", err)
						}
						continue
					}
					if ev, ok := evABI.Events["AutopatchRule"]; ok && lg.Topics[0] == ev.ID {
						var out struct {
							RuleIdx    uint8
							ParamIndex uint8
							ParamType  uint8
							IsRange    bool
							RangeMin   [32]byte
							RangeMax   [32]byte
							ValueCount *big.Int
						}
						project := common.HexToAddress(lg.Topics[1].Hex())
						funcSig := lg.Topics[2]
						if err := evABI.UnpackIntoInterface(&out, "AutopatchRule", lg.Data); err == nil {
							log.Printf("[OracleIntegration] On-chain AutopatchRule project=%s funcSig=%s idx=%d pIdx=%d pType=%d isRange=%v valueN=%s",
								project.Hex(), funcSig.Hex(), out.RuleIdx, out.ParamIndex, out.ParamType, out.IsRange, out.ValueCount.String())
						} else {
							log.Printf("[OracleIntegration] Decode AutopatchRule failed: %v", err)
						}
						continue
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}

// SetEnabled 设置是否启用
func (oi *OracleIntegration) SetEnabled(enabled bool) {
	oi.enabled = enabled
	log.Printf("[OracleIntegration] Enabled: %v", enabled)
}

// removeHexPrefix 移除十六进制前缀
func removeHexPrefix(s string) string {
	if len(s) >= 2 && s[0:2] == "0x" {
		return s[2:]
	}
	return s
}
