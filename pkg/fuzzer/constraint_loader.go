package fuzzer

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"path/filepath"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ConstraintRulesV2 从 constraint_rules_v2.json 加载的约束规则
type ConstraintRulesV2 struct {
	Protocol           string                          `json:"protocol"`
	YearMonth          string                          `json:"year_month"`
	VulnerableContract ContractInfo                    `json:"vulnerable_contract"`
	Constraints        []FunctionConstraint            `json:"constraints"`
	constraintsByFunc  map[string][]FunctionConstraint // 支持每个选择器对应多个约束
}

// ContractInfo 合约信息
type ContractInfo struct {
	Address string `json:"address"`
	Name    string `json:"name"`
}

// FunctionConstraint 函数约束
type FunctionConstraint struct {
	Function      string             `json:"function"`
	Signature     string             `json:"signature"`
	AttackPattern string             `json:"attack_pattern"`
	Constraint    ConstraintDetail   `json:"constraint"`
	Analysis      ConstraintAnalysis `json:"analysis"`
}

// ConstraintDetail 约束详情
type ConstraintDetail struct {
	Type            string                  `json:"type"`
	Expression      string                  `json:"expression"`
	Semantics       string                  `json:"semantics"`
	AttackValues    []interface{}           `json:"attack_values,omitempty"`
	Variables       map[string]VariableInfo `json:"variables"`
	DangerCondition string                  `json:"danger_condition,omitempty"`
	SafeCondition   string                  `json:"safe_condition,omitempty"`
	ThresholdValue  interface{}             `json:"threshold_value,omitempty"`
	Range           *RangeInfo              `json:"range,omitempty"`
}

// VariableInfo 变量信息
type VariableInfo struct {
	Source       string      `json:"source"` // "function_parameter" or "storage"
	Index        int         `json:"index,omitempty"`
	Type         string      `json:"type"`
	ValueExpr    string      `json:"value_expr,omitempty"`
	SemanticName string      `json:"semantic_name,omitempty"`
	BeforeValue  interface{} `json:"before_value,omitempty"`
	AfterValue   interface{} `json:"after_value,omitempty"`
}

// RangeInfo 范围信息
type RangeInfo struct {
	Min interface{} `json:"min"`
	Max interface{} `json:"max"`
}

// ConstraintAnalysis 约束分析
type ConstraintAnalysis struct {
	StateValue            interface{} `json:"state_value,omitempty"`
	Threshold             interface{} `json:"threshold,omitempty"`
	Coefficient           interface{} `json:"coefficient,omitempty"`
	AttackIntensity       interface{} `json:"attack_intensity,omitempty"`
	Reasoning             string      `json:"reasoning,omitempty"`
	CorrelationType       string      `json:"correlation_type,omitempty"`
	CorrelationConfidence float64     `json:"correlation_confidence,omitempty"`
	Ratio                 interface{} `json:"ratio,omitempty"`
	ChangeDirection       string      `json:"change_direction,omitempty"`
}

// LoadConstraintRules 从文件加载约束规则
func LoadConstraintRules(basePath, protocol string) (*ConstraintRulesV2, error) {
	// 构建文件路径
	filePath := filepath.Join(basePath, "DeFiHackLabs", "extracted_contracts", "2024-01", protocol, "constraint_rules_v2.json")

	log.Printf("[ConstraintLoader] Loading rules from: %s", filePath)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read constraint rules: %w", err)
	}

	var rules ConstraintRulesV2
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, fmt.Errorf("failed to parse constraint rules: %w", err)
	}

	// 构建索引
	rules.constraintsByFunc = make(map[string][]FunctionConstraint)
	for _, c := range rules.Constraints {
		// 使用函数名和签名都作为键
		if c.Function != "" {
			rules.constraintsByFunc[strings.ToLower(c.Function)] = append(rules.constraintsByFunc[strings.ToLower(c.Function)], c)
		}
		if c.Signature != "" {
			sigLower := strings.ToLower(c.Signature)
			rules.constraintsByFunc[sigLower] = append(rules.constraintsByFunc[sigLower], c)

			// 如果 signature 包含完整的参数列表(包含括号),计算其选择器
			if strings.Contains(c.Signature, "(") && strings.Contains(c.Signature, ")") {
				// 计算函数选择器: keccak256(signature)的前4字节
				hash := crypto.Keccak256Hash([]byte(c.Signature))
				selector := "0x" + hex.EncodeToString(hash[:4])
				rules.constraintsByFunc[selector] = append(rules.constraintsByFunc[selector], c)
				log.Printf("[ConstraintLoader] Indexed constraint by selector: %s -> %s", selector, c.Function)
			}
		}
	}

	log.Printf("[ConstraintLoader] Loaded %d constraints for %s", len(rules.Constraints), protocol)
	return &rules, nil
}

// GetConstraintForFunction 获取函数的约束（可能存在多条）
func (r *ConstraintRulesV2) GetConstraintForFunction(funcName string) []FunctionConstraint {
	if r == nil || r.constraintsByFunc == nil {
		return nil
	}

	key := strings.ToLower(funcName)
	if c, ok := r.constraintsByFunc[key]; ok {
		return c
	}
	return nil
}

// ExtractParameterConstraint 从约束中提取参数约束信息
func ExtractParameterConstraint(constraint *FunctionConstraint, paramIndex int) *ParamConstraintInfo {
	if constraint == nil {
		return nil
	}

	// 查找参数相关的变量
	for _, varInfo := range constraint.Constraint.Variables {
		if varInfo.Source == "function_parameter" && varInfo.Index == paramIndex {
			return &ParamConstraintInfo{
				ParamIndex:      paramIndex,
				ParamType:       varInfo.Type,
				SafeThreshold:   extractThresholdValue(constraint.Constraint.SafeCondition, constraint.Constraint.ThresholdValue),
				DangerThreshold: extractThresholdValue(constraint.Constraint.DangerCondition, constraint.Analysis.Threshold),
				AttackValues:    constraint.Constraint.AttackValues,
				ConstraintType:  constraint.Constraint.Type,
				IsSafeUpper:     strings.Contains(strings.ToLower(constraint.Constraint.SafeCondition), "<=") || strings.Contains(strings.ToLower(constraint.Constraint.SafeCondition), "<"),
			}
		}
	}

	return nil
}

// ParamConstraintInfo 参数约束信息
type ParamConstraintInfo struct {
	ParamIndex      int
	ParamType       string
	SafeThreshold   *big.Int      // 安全阈值（小于此值安全）
	DangerThreshold *big.Int      // 危险阈值（大于等于此值危险）
	AttackValues    []interface{} // 实际攻击值
	ConstraintType  string        // 约束类型
	IsSafeUpper     bool          // 安全条件是否为上界（true: amount <= safe, false: amount >= safe）
}

// extractThresholdValue 从条件表达式或阈值中提取数值
func extractThresholdValue(condition string, threshold interface{}) *big.Int {
	// 优先从 condition 中提取数值
	if condition != "" {
		// 提取形如 "amount <= 2867543696806566690816" 中的数值
		parts := strings.Fields(condition)
		for _, part := range parts {
			if val, ok := parseConstraintBigInt(part); ok {
				return val
			}
		}
	}

	// 回退到 threshold 字段
	if threshold != nil {
		if val, ok := parseConstraintBigInt(threshold); ok {
			return val
		}
	}

	return nil
}

// parseConstraintBigInt 尝试将各种类型转换为 big.Int（用于约束规则）
func parseConstraintBigInt(value interface{}) (*big.Int, bool) {
	switch v := value.(type) {
	case string:
		// 移除可能的引号和空格
		v = strings.Trim(v, `"' `)
		// 尝试十六进制
		if strings.HasPrefix(v, "0x") {
			if n, ok := new(big.Int).SetString(v[2:], 16); ok {
				return n, true
			}
		}
		// 尝试十进制
		if n, ok := new(big.Int).SetString(v, 10); ok {
			return n, true
		}
	case float64:
		return big.NewInt(int64(v)), true
	case int64:
		return big.NewInt(v), true
	case int:
		return big.NewInt(int64(v)), true
	case *big.Int:
		return v, true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return big.NewInt(i), true
		}
	}
	return nil, false
}

// LoadConstraintRulesByContractAddr 根据合约地址加载约束规则
func LoadConstraintRulesByContractAddr(basePath string, contractAddr common.Address) (*ConstraintRulesV2, error) {
	// 尝试从已知的协议列表中查找
	protocolDirs := []string{
		"BarleyFinance_exp",
		"CitadelFinance_exp",
		"MIMSpell2_exp",
		"WiseLending02_exp",
		"WiseLending03_exp",
		"OrbitChain_exp",
		"PeapodsFinance_exp",
		"XSIJ_exp",
		"SocketGateway_exp",
		"Gamma_exp",
		"MIC_exp",
		"LQDX_alert_exp",
		"Bmizapper_exp",
	}

	addrLower := strings.ToLower(contractAddr.Hex())

	for _, protocol := range protocolDirs {
		rules, err := LoadConstraintRules(basePath, protocol)
		if err != nil {
			continue
		}

		// 检查地址是否匹配
		if strings.ToLower(rules.VulnerableContract.Address) == addrLower {
			return rules, nil
		}
	}

	return nil, fmt.Errorf("no constraint rules found for contract %s", contractAddr.Hex())
}
