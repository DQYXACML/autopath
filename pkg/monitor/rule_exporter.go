package monitor

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"autopath/pkg/fuzzer"
	"github.com/ethereum/go-ethereum/common"
)

// FirewallRuleExport 防火墙规则导出格式（与Solidity脚本兼容）
type FirewallRuleExport struct {
	Project     string          `json:"project"`
	FunctionSig string          `json:"functionSig"`
	Threshold   uint64          `json:"threshold"`
	RuleCount   int             `json:"ruleCount"`
	Parameters  []RuleParameter `json:"parameters"`
	Timestamp   string          `json:"timestamp,omitempty"`
	Source      string          `json:"source,omitempty"`
}

// RuleParameter 单个参数规则
type RuleParameter struct {
	ParamIndex      int      `json:"paramIndex"`
	ParamType       int      `json:"paramType"`
	SingleValues    []string `json:"singleValues"`
	IsRange         bool     `json:"isRange"`
	RangeMin        string   `json:"rangeMin"`
	RangeMax        string   `json:"rangeMax"`
	OccurrenceCount int      `json:"occurrenceCount"`
}

// FirewallRulesCollection 规则集合（避免覆盖问题）
type FirewallRulesCollection struct {
	Rules       []FirewallRuleExport   `json:"rules"`
	Expressions []ExpressionRuleExport `json:"expressions,omitempty"`
	Version     string                 `json:"version"`
	LastUpdate  string                 `json:"lastUpdate"`
}

// RuleExporter 规则导出器
type RuleExporter struct {
	exportPath   string
	enableExport bool
	format       string // json, yaml
	mu           sync.Mutex
	collection   *FirewallRulesCollection
}

// NewRuleExporter 创建规则导出器
func NewRuleExporter(exportPath string, enable bool, format string) *RuleExporter {
	if format == "" {
		format = "json"
	}

	return &RuleExporter{
		exportPath:   exportPath,
		enableExport: enable,
		format:       format,
	}
}

// ensureCollectionInitialized 在当前进程内为导出会话提供全新集合，避免引用历史文件残留
func (re *RuleExporter) ensureCollectionInitialized() {
	if re.collection != nil {
		return
	}
	re.collection = &FirewallRulesCollection{
		Rules:       []FirewallRuleExport{},
		Expressions: []ExpressionRuleExport{},
		Version:     "1.0",
	}
}

// ExpressionRuleExport 表达式规则导出格式
type ExpressionRuleExport struct {
	Contract    string              `json:"contract"`
	FunctionSig string              `json:"functionSig"`
	Type        string              `json:"type"`
	Terms       []fuzzer.LinearTerm `json:"terms"`
	Threshold   string              `json:"threshold"`
	Scale       string              `json:"scale"`
	Confidence  float64             `json:"confidence"`
	SampleCount int                 `json:"sampleCount"`
	MinMargin   string              `json:"minMarginHex"`
	Strategy    string              `json:"strategy,omitempty"`
	GeneratedAt string              `json:"generatedAt,omitempty"`
}

// ExportRules 导出规则到文件（支持合并，避免覆盖）
func (re *RuleExporter) ExportRules(
	project common.Address,
	funcSig [4]byte,
	params []fuzzer.ParameterSummary,
	threshold float64,
) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	if !re.enableExport {
		return nil
	}

	if re.exportPath == "" {
		return fmt.Errorf("export path not configured")
	}

	// 构建新规则
	newRule := re.buildRuleExport(project, funcSig, params, threshold)

	re.ensureCollectionInitialized()
	collection := re.collection

	// 合并或更新规则
	collection = re.mergeRuleIntoCollection(collection, newRule)
	collection.LastUpdate = time.Now().UTC().Format(time.RFC3339)
	re.collection = collection

	// 序列化集合
	data, err := json.MarshalIndent(collection, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal rules collection: %w", err)
	}

	// 确保目录存在
	dir := filepath.Dir(re.exportPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// 原子性写入：先写临时文件，再重命名
	tempFile := re.exportPath + ".tmp"
	if err := ioutil.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, re.exportPath); err != nil {
		// 如果重命名失败，尝试删除临时文件
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	log.Printf("[RuleExporter] Rules exported to: %s", re.exportPath)
	log.Printf("[RuleExporter] Project: %s, Function: %s, Total rules in collection: %d",
		project.Hex(), funcSigToString(funcSig), len(collection.Rules))

	return nil
}

// ExportExpressionRules 导出表达式约束（ratio/linear）到文件
func (re *RuleExporter) ExportExpressionRules(
	project common.Address,
	funcSig [4]byte,
	exprs []fuzzer.ExpressionRule,
) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	if !re.enableExport || len(exprs) == 0 {
		return nil
	}
	if re.exportPath == "" {
		return fmt.Errorf("export path not configured")
	}

	re.ensureCollectionInitialized()
	collection := re.collection

	for _, expr := range exprs {
		export := ExpressionRuleExport{
			Contract:    project.Hex(),
			FunctionSig: funcSigToString(funcSig),
			Type:        expr.Type,
			Terms:       expr.Terms,
			Threshold:   expr.Threshold,
			Scale:       expr.Scale,
			Confidence:  expr.Confidence,
			SampleCount: expr.SampleCount,
			MinMargin:   expr.MinMarginHex,
			Strategy:    expr.Strategy,
		}
		if !expr.GeneratedAt.IsZero() {
			export.GeneratedAt = expr.GeneratedAt.UTC().Format(time.RFC3339)
		}
		collection = re.mergeExpressionIntoCollection(collection, export)
	}
	collection.LastUpdate = time.Now().UTC().Format(time.RFC3339)
	re.collection = collection

	data, err := json.MarshalIndent(collection, "", "    ")
	if err != nil {
		return fmt.Errorf("failed to marshal expressions: %w", err)
	}

	dir := filepath.Dir(re.exportPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	tempFile := re.exportPath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, re.exportPath); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	log.Printf("[RuleExporter] Expression rules exported to: %s", re.exportPath)
	return nil
}

// LoadExistingCollection 加载已有规则集合
func (re *RuleExporter) LoadExistingCollection() (*FirewallRulesCollection, error) {
	if !re.enableExport {
		return nil, fmt.Errorf("exporter not enabled")
	}

	// 检查文件是否存在
	if _, err := os.Stat(re.exportPath); os.IsNotExist(err) {
		// 文件不存在，返回空集合
		return &FirewallRulesCollection{
			Rules:   []FirewallRuleExport{},
			Version: "1.0",
		}, nil
	}

	// 读取文件
	data, err := ioutil.ReadFile(re.exportPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read existing rules: %w", err)
	}

	// 尝试解析为集合格式
	var collection FirewallRulesCollection
	if err := json.Unmarshal(data, &collection); err != nil {
		// 尝试解析为单个规则（向后兼容）
		var singleRule FirewallRuleExport
		if err2 := json.Unmarshal(data, &singleRule); err2 == nil {
			// 转换为集合格式
			return &FirewallRulesCollection{
				Rules:      []FirewallRuleExport{singleRule},
				Version:    "1.0",
				LastUpdate: singleRule.Timestamp,
			}, nil
		}
		return nil, fmt.Errorf("failed to parse existing rules: %w", err)
	}

	return &collection, nil
}

// mergeRuleIntoCollection 将新规则合并到集合中
func (re *RuleExporter) mergeRuleIntoCollection(collection *FirewallRulesCollection, newRule *FirewallRuleExport) *FirewallRulesCollection {
	if collection == nil {
		return &FirewallRulesCollection{
			Rules:      []FirewallRuleExport{*newRule},
			Version:    "1.0",
			LastUpdate: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// 查找是否已存在相同的project+functionSig
	ruleKey := fmt.Sprintf("%s-%s", newRule.Project, newRule.FunctionSig)
	found := false

	for i, existingRule := range collection.Rules {
		existingKey := fmt.Sprintf("%s-%s", existingRule.Project, existingRule.FunctionSig)
		if existingKey == ruleKey {
			// 更新现有规则
			log.Printf("[RuleExporter] Updating existing rule for %s", ruleKey)
			collection.Rules[i] = re.mergeRules(&existingRule, newRule)
			found = true
			break
		}
	}

	if !found {
		// 添加新规则
		log.Printf("[RuleExporter] Adding new rule for %s", ruleKey)
		collection.Rules = append(collection.Rules, *newRule)
	}

	return collection
}

func (re *RuleExporter) mergeExpressionIntoCollection(collection *FirewallRulesCollection, newExpr ExpressionRuleExport) *FirewallRulesCollection {
	if collection == nil {
		return &FirewallRulesCollection{
			Expressions: []ExpressionRuleExport{newExpr},
			Version:     "1.0",
			LastUpdate:  time.Now().UTC().Format(time.RFC3339),
		}
	}

	key := fmt.Sprintf("%s-%s-%s", newExpr.Contract, newExpr.FunctionSig, newExpr.Type)
	for i, ex := range collection.Expressions {
		if fmt.Sprintf("%s-%s-%s", ex.Contract, ex.FunctionSig, ex.Type) == key {
			collection.Expressions[i] = newExpr
			return collection
		}
	}
	collection.Expressions = append(collection.Expressions, newExpr)
	return collection
}

// mergeRules 合并两个规则（智能合并参数）
func (re *RuleExporter) mergeRules(existing *FirewallRuleExport, newRule *FirewallRuleExport) FirewallRuleExport {
	// 基本信息使用新规则
	merged := *newRule

	// 合并参数（如果需要更复杂的合并逻辑）
	paramMap := make(map[int]RuleParameter)

	// 先添加现有参数
	for _, param := range existing.Parameters {
		paramMap[param.ParamIndex] = param
	}

	// 用新参数覆盖或合并
	for _, newParam := range newRule.Parameters {
		if existingParam, exists := paramMap[newParam.ParamIndex]; exists {
			// 合并参数范围
			mergedParam := re.mergeParameters(&existingParam, &newParam)
			paramMap[newParam.ParamIndex] = mergedParam
		} else {
			paramMap[newParam.ParamIndex] = newParam
		}
	}

	// 转换回数组
	merged.Parameters = []RuleParameter{}
	for _, param := range paramMap {
		merged.Parameters = append(merged.Parameters, param)
	}
	merged.RuleCount = len(merged.Parameters)

	return merged
}

// mergeParameters 合并两个参数规则
func (re *RuleExporter) mergeParameters(existing *RuleParameter, newParam *RuleParameter) RuleParameter {
	merged := *newParam

	// 如果都是范围，取并集
	if existing.IsRange && newParam.IsRange {
		// 扩展范围
		if existing.RangeMin < merged.RangeMin {
			merged.RangeMin = existing.RangeMin
		}
		if existing.RangeMax > merged.RangeMax {
			merged.RangeMax = existing.RangeMax
		}
		log.Printf("[RuleExporter] Merged range for param %d: [%s, %s]",
			merged.ParamIndex, merged.RangeMin, merged.RangeMax)
	} else if !existing.IsRange && !newParam.IsRange {
		// 如果都是离散值，合并去重
		valueSet := make(map[string]bool)
		for _, v := range existing.SingleValues {
			valueSet[v] = true
		}
		for _, v := range newParam.SingleValues {
			valueSet[v] = true
		}

		merged.SingleValues = []string{}
		for v := range valueSet {
			merged.SingleValues = append(merged.SingleValues, v)
		}
		log.Printf("[RuleExporter] Merged %d discrete values for param %d",
			len(merged.SingleValues), merged.ParamIndex)
	}

	// 更新出现次数
	merged.OccurrenceCount = existing.OccurrenceCount + newParam.OccurrenceCount

	return merged
}

// buildRuleExport 构建规则导出结构
func (re *RuleExporter) buildRuleExport(
	project common.Address,
	funcSig [4]byte,
	params []fuzzer.ParameterSummary,
	threshold float64,
) *FirewallRuleExport {
	rule := &FirewallRuleExport{
		Project:     project.Hex(),
		FunctionSig: funcSigToString(funcSig),
		Threshold:   uint64(threshold * 1e18), // 转换为wei
		RuleCount:   len(params),
		Parameters:  make([]RuleParameter, 0, len(params)),
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Source:      "autopath_monitor",
	}

	// 转换参数
	for _, p := range params {
		ruleParam := RuleParameter{
			ParamIndex:      p.ParamIndex,
			ParamType:       re.convertParamType(p.ParamType),
			IsRange:         p.IsRange,
			OccurrenceCount: p.OccurrenceCount,
		}

		if p.IsRange {
			// 范围值：确保为bytes32格式（64位十六进制）
			ruleParam.RangeMin = re.formatAsBytes32(p.RangeMin)
			ruleParam.RangeMax = re.formatAsBytes32(p.RangeMax)
			ruleParam.SingleValues = []string{} // 空数组
		} else {
			// 离散值：转换所有值
			ruleParam.SingleValues = make([]string, 0, len(p.SingleValues))
			for _, val := range p.SingleValues {
				ruleParam.SingleValues = append(ruleParam.SingleValues, re.formatAsBytes32(val))
			}
		}

		rule.Parameters = append(rule.Parameters, ruleParam)
	}

	return rule
}

// convertParamType 转换参数类型为枚举值
func (re *RuleExporter) convertParamType(paramType string) int {
	// 根据ParamCheckModule.sol中的ParamType枚举
	switch strings.ToLower(paramType) {
	case "uint256", "uint":
		return 0 // UINT256
	case "int256", "int":
		return 1 // INT256
	case "address":
		return 2 // ADDRESS
	case "bool":
		return 3 // BOOL
	case "bytes32":
		return 4 // BYTES32
	case "bytes":
		return 5 // BYTES
	case "string":
		return 6 // STRING
	default:
		return 0 // 默认为UINT256
	}
}

// formatAsBytes32 格式化值为bytes32格式（0x开头，64位十六进制）
func (re *RuleExporter) formatAsBytes32(value string) string {
	// 移除0x前缀
	value = strings.TrimPrefix(value, "0x")

	// 如果是纯数字字符串，解析为大整数并转换
	if !strings.Contains(value, "x") && !strings.Contains(value, "X") {
		// 尝试解析为十进制数
		// 这里简化处理，假设已经是十六进制格式
	}

	// 确保是64位十六进制（32字节）
	if len(value) > 64 {
		value = value[:64]
	} else if len(value) < 64 {
		// 左侧补0
		value = strings.Repeat("0", 64-len(value)) + value
	}

	return "0x" + value
}

// funcSigToString 将函数签名转换为字符串
func funcSigToString(sig [4]byte) string {
	return "0x" + hex.EncodeToString(sig[:])
}

// LoadExistingRules 加载已有规则（向后兼容）
func (re *RuleExporter) LoadExistingRules() (*FirewallRuleExport, error) {
	collection, err := re.LoadExistingCollection()
	if err != nil {
		return nil, err
	}

	if len(collection.Rules) > 0 {
		// 返回第一个规则（向后兼容）
		return &collection.Rules[0], nil
	}

	return nil, nil
}
