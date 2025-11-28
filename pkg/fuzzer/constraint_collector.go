package fuzzer

import (
	"encoding/hex"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// constraintSample 保存单次高相似模拟的参数与状态
type constraintSample struct {
	params []ParameterValue
	state  map[string]StateChange
	sim    float64
}

// ConstraintCollector 收集高相似样本并生成约束规则
type ConstraintCollector struct {
	mu        sync.Mutex
	samples   map[string][]constraintSample // key: contract-selector
	rules     map[string]*ConstraintRule
	threshold int
}

// NewConstraintCollector 创建约束收集器
func NewConstraintCollector(threshold int) *ConstraintCollector {
	if threshold <= 0 {
		threshold = 10
	}
	return &ConstraintCollector{
		samples:   make(map[string][]constraintSample),
		rules:     make(map[string]*ConstraintRule),
		threshold: threshold,
	}
}

// RecordSample 记录一次高相似模拟结果，满足阈值时生成规则
func (cc *ConstraintCollector) RecordSample(
	contract common.Address,
	selector []byte,
	params []ParameterValue,
	state map[string]StateChange,
	similarity float64,
) *ConstraintRule {
	if cc == nil {
		return nil
	}
	key := cc.ruleKey(contract, selector)

	cc.mu.Lock()
	defer cc.mu.Unlock()

	cc.samples[key] = append(cc.samples[key], constraintSample{
		params: params,
		state:  state,
		sim:    similarity,
	})

	if len(cc.samples[key]) < cc.threshold {
		return nil
	}

	// 已生成过规则直接返回
	if rule, ok := cc.rules[key]; ok {
		return rule
	}

	rule := cc.buildRule(contract, selector, cc.samples[key])
	cc.rules[key] = rule
	return rule
}

// GetRule 获取已生成的规则
func (cc *ConstraintCollector) GetRule(contract common.Address, selector []byte) *ConstraintRule {
	if cc == nil {
		return nil
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.rules[cc.ruleKey(contract, selector)]
}

func (cc *ConstraintCollector) ruleKey(contract common.Address, selector []byte) string {
	return strings.ToLower(contract.Hex()) + "-" + hex.EncodeToString(selector)
}

func (cc *ConstraintCollector) buildRule(contract common.Address, selector []byte, samples []constraintSample) *ConstraintRule {
	paramRanges := aggregateParamConstraints(samples)
	stateConstraints := aggregateStateConstraints(contract, samples)

	return &ConstraintRule{
		ContractAddress:   contract,
		FunctionSelector:  "0x" + hex.EncodeToString(selector),
		SampleCount:       len(samples),
		ParamConstraints:  paramRanges,
		StateConstraints:  stateConstraints,
		SimilarityTrigger: averageSimilarity(samples),
		GeneratedAt:       time.Now(),
	}
}

func averageSimilarity(samples []constraintSample) float64 {
	if len(samples) == 0 {
		return 0
	}
	var sum float64
	for _, s := range samples {
		sum += s.sim
	}
	return sum / float64(len(samples))
}

func aggregateParamConstraints(samples []constraintSample) []ParamConstraint {
	if len(samples) == 0 {
		return nil
	}

	// 使用第一条样本的参数长度为基准
	paramCount := len(samples[0].params)
	constraints := make([]ParamConstraint, paramCount)

	for i := 0; i < paramCount; i++ {
		constraints[i].Index = samples[0].params[i].Index
		constraints[i].Type = samples[0].params[i].Type
	}

	for i := 0; i < paramCount; i++ {
		pc := &constraints[i]
		isNumeric := strings.HasPrefix(pc.Type, "uint") || strings.HasPrefix(pc.Type, "int")

		var minVal, maxVal *big.Int
		valueSet := make(map[string]struct{})

		for _, s := range samples {
			if i >= len(s.params) {
				continue
			}
			val := s.params[i].Value
			if isNumeric {
				if bi := normalizeBigIntValue(val); bi != nil {
					if minVal == nil || bi.Cmp(minVal) < 0 {
						minVal = new(big.Int).Set(bi)
					}
					if maxVal == nil || bi.Cmp(maxVal) > 0 {
						maxVal = new(big.Int).Set(bi)
					}
				}
			} else {
				valueSet[ValueToString(val)] = struct{}{}
			}
		}

		if isNumeric && minVal != nil && maxVal != nil {
			pc.IsRange = true
			pc.RangeMin = "0x" + minVal.Text(16)
			pc.RangeMax = "0x" + maxVal.Text(16)
		} else {
			pc.Values = dedupMapKeys(valueSet)
		}
	}

	return constraints
}

func aggregateStateConstraints(contract common.Address, samples []constraintSample) []StateConstraint {
	slotValues := make(map[string]map[string]struct{})
	target := strings.ToLower(contract.Hex())

	for _, s := range samples {
		for addr, change := range s.state {
			if strings.ToLower(addr) != target {
				continue
			}
			for slot, diff := range change.StorageChanges {
				if diff.After == "" {
					continue
				}
				if slotValues[slot] == nil {
					slotValues[slot] = make(map[string]struct{})
				}
				slotValues[slot][diff.After] = struct{}{}
			}
		}
	}

	var constraints []StateConstraint
	for slot, vals := range slotValues {
		constraints = append(constraints, StateConstraint{
			Slot:   slot,
			Values: dedupMapKeys(vals),
		})
	}
	return constraints
}

func dedupMapKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// normalizeBigIntValue 将各种输入转为*big.Int
func normalizeBigIntValue(val interface{}) *big.Int {
	switch v := val.(type) {
	case *big.Int:
		return v
	case int:
		return big.NewInt(int64(v))
	case int64:
		return big.NewInt(v)
	case uint64:
		return new(big.Int).SetUint64(v)
	case string:
		base := 10
		s := v
		if strings.HasPrefix(v, "0x") {
			base = 16
			s = strings.TrimPrefix(v, "0x")
		}
		if bi, ok := new(big.Int).SetString(s, base); ok {
			return bi
		}
	}
	return nil
}
