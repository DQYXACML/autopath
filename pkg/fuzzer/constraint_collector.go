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
	exprs     map[string]*ExpressionRule
}

// NewConstraintCollector 创建约束收集器
func NewConstraintCollector(threshold int) *ConstraintCollector {
	if threshold <= 0 {
		threshold = 10
	}
	return &ConstraintCollector{
		samples:   make(map[string][]constraintSample),
		rules:     make(map[string]*ConstraintRule),
		exprs:     make(map[string]*ExpressionRule),
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

	// 同步生成表达式规则（ratio/linear）
	if expr := cc.buildExpressionRule(contract, selector, cc.samples[key]); expr != nil {
		cc.exprs[key] = expr
	}

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

// GetExpressionRule 获取基于样本的表达式约束
func (cc *ConstraintCollector) GetExpressionRule(contract common.Address, selector []byte) *ExpressionRule {
	if cc == nil {
		return nil
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.exprs[cc.ruleKey(contract, selector)]
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

// buildExpressionRule 基于样本生成 ratio 或 linear 约束
func (cc *ConstraintCollector) buildExpressionRule(contract common.Address, selector []byte, samples []constraintSample) *ExpressionRule {
	if len(samples) == 0 {
		return nil
	}

	selectorHex := "0x" + hex.EncodeToString(selector)
	now := time.Now()
	scale := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(18), nil) // 1e18

	// 先尝试 ratio 规则（单参数/单槽位）
	if ratioRule := buildRatioRule(contract, selectorHex, samples, scale); ratioRule != nil {
		ratioRule.GeneratedAt = now
		return ratioRule
	}

	// 回退线性规则（简单稀疏超平面）
	if linRule := buildLinearRule(contract, selectorHex, samples, scale); linRule != nil {
		linRule.GeneratedAt = now
		return linRule
	}

	return nil
}

// buildRatioRule 生成乘法比率阈值：p*SCALE >= k*s
func buildRatioRule(contract common.Address, selector string, samples []constraintSample, scale *big.Int) *ExpressionRule {
	type candidate struct {
		paramIdx int
		slot     string
		rMin     *big.Rat
	}

	var best candidate
	best.rMin = nil

	// 预取参数/状态数值
	paramVals := extractNumericParams(samples)
	stateVals := extractNumericState(samples, contract)

	for pIdx, vals := range paramVals {
		for slot, svals := range stateVals {
			minRat := minRatio(vals, svals)
			if minRat == nil {
				continue
			}
			// 留一点安全余量 90%
			minRat.Mul(minRat, big.NewRat(9, 10))
			if best.rMin == nil || minRat.Cmp(best.rMin) < 0 {
				best = candidate{paramIdx: pIdx, slot: slot, rMin: minRat}
			}
		}
	}

	if best.rMin == nil {
		return nil
	}

	// k = rMin，转为 big.Int 精度 scale
	k := new(big.Rat).Mul(best.rMin, new(big.Rat).SetInt(scale))
	kInt := new(big.Int).Div(k.Num(), k.Denom())
	if kInt.Sign() == 0 {
		return nil
	}

	paramCoeff := new(big.Int).Set(scale) // p * SCALE
	stateCoeff := new(big.Int).Neg(kInt)  // -k * s
	minMargin := calcMinMarginRatio(paramVals[best.paramIdx], stateVals[best.slot], paramCoeff, stateCoeff)

	return &ExpressionRule{
		Type:     "ratio",
		Contract: contract,
		Selector: selector,
		Terms: []LinearTerm{
			{Kind: "param", ParamIndex: best.paramIdx, Coeff: "0x" + paramCoeff.Text(16)},
			{Kind: "state", Slot: best.slot, Coeff: "0x" + stateCoeff.Text(16)},
		},
		Threshold:    "0x0",
		Scale:        "0x" + scale.Text(16),
		Confidence:   float64(len(samples)) / float64(len(samples)), // 全部样本
		SampleCount:  len(samples),
		MinMarginHex: "0x" + minMargin.Text(16),
		Strategy:     "ratio_param_over_state",
	}
}

// buildLinearRule 生成稀疏线性不等式：∑ w_i * x_i >= T
func buildLinearRule(contract common.Address, selector string, samples []constraintSample, scale *big.Int) *ExpressionRule {
	if len(samples) == 0 {
		return nil
	}

	paramVals := extractNumericParams(samples)
	stateVals := extractNumericState(samples, contract)

	// 构造权重：对每个特征取均值的倒数，避免全零
	type feat struct {
		kind       string
		paramIndex int
		slot       string
		avg        *big.Int
	}

	var feats []feat
	for idx, vals := range paramVals {
		if avg := averageInt(vals); avg != nil && avg.Sign() != 0 {
			feats = append(feats, feat{kind: "param", paramIndex: idx, avg: avg})
		}
	}
	for slot, vals := range stateVals {
		if avg := averageInt(vals); avg != nil && avg.Sign() != 0 {
			feats = append(feats, feat{kind: "state", slot: slot, avg: avg})
		}
	}

	if len(feats) == 0 {
		return nil
	}

	// 稀疏：最多取前 6 个
	if len(feats) > 6 {
		feats = feats[:6]
	}

	terms := make([]LinearTerm, 0, len(feats))
	for _, f := range feats {
		coeff := new(big.Int).Div(scale, f.avg) // 1/avg 乘 scale
		if coeff.Sign() == 0 {
			coeff = big.NewInt(1)
		}
		term := LinearTerm{Kind: f.kind, Coeff: "0x" + coeff.Text(16)}
		if f.kind == "param" {
			term.ParamIndex = f.paramIndex
		} else {
			term.Slot = f.slot
		}
		terms = append(terms, term)
	}

	// 计算所有样本的最小 margin
	minMargin := big.NewInt(0)
	minMargin.SetInt64(1 << 62) // 大数
	for _, s := range samples {
		sum := big.NewInt(0)
		sum.SetInt64(0)
		for _, t := range terms {
			coeff := hexToInt(t.Coeff)
			var val *big.Int
			if t.Kind == "param" {
				val = pickParamValue(s.params, t.ParamIndex)
			} else {
				val = pickStateValue(s.state, t.Slot)
			}
			if val == nil {
				val = big.NewInt(0)
			}
			sum.Add(sum, new(big.Int).Mul(coeff, val))
		}
		if sum.Cmp(minMargin) < 0 {
			minMargin = sum
		}
	}

	// 阈值取 90% 的最小值，保证样本通过
	threshold := new(big.Int).Mul(minMargin, big.NewInt(9))
	threshold = threshold.Div(threshold, big.NewInt(10))

	return &ExpressionRule{
		Type:         "linear",
		Contract:     contract,
		Selector:     selector,
		Terms:        terms,
		Threshold:    "0x" + threshold.Text(16),
		Scale:        "0x" + scale.Text(16),
		Confidence:   1.0,
		SampleCount:  len(samples),
		MinMarginHex: "0x" + minMargin.Text(16),
		Strategy:     "sparse_hyperplane",
	}
}

// 辅助函数：提取数值型参数
func extractNumericParams(samples []constraintSample) map[int][]*big.Int {
	out := make(map[int][]*big.Int)
	for _, s := range samples {
		for _, p := range s.params {
			if val := normalizeToBigInt(p.Value); val != nil {
				out[p.Index] = append(out[p.Index], val)
			}
		}
	}
	return out
}

// 辅助函数：提取目标合约数值型状态槽
func extractNumericState(samples []constraintSample, contract common.Address) map[string][]*big.Int {
	out := make(map[string][]*big.Int)
	target := strings.ToLower(contract.Hex())
	for _, s := range samples {
		for addr, change := range s.state {
			if strings.ToLower(addr) != target {
				continue
			}
			for slot, diff := range change.StorageChanges {
				if val := normalizeHexToBigInt(diff.After); val != nil {
					out[slot] = append(out[slot], val)
				}
			}
		}
	}
	return out
}

func normalizeToBigInt(v interface{}) *big.Int {
	switch val := v.(type) {
	case *big.Int:
		return new(big.Int).Set(val)
	case int:
		return big.NewInt(int64(val))
	case int64:
		return big.NewInt(val)
	case uint64:
		return new(big.Int).SetUint64(val)
	case string:
		if strings.HasPrefix(val, "0x") {
			if bi, ok := new(big.Int).SetString(strings.TrimPrefix(val, "0x"), 16); ok {
				return bi
			}
		} else if bi, ok := new(big.Int).SetString(val, 10); ok {
			return bi
		}
	case []byte:
		return new(big.Int).SetBytes(val)
	}
	return nil
}

func normalizeHexToBigInt(hexStr string) *big.Int {
	if hexStr == "" {
		return nil
	}
	body := strings.TrimPrefix(strings.ToLower(hexStr), "0x")
	if body == "" {
		return big.NewInt(0)
	}
	if bi, ok := new(big.Int).SetString(body, 16); ok {
		return bi
	}
	return nil
}

func minRatio(numerators, denominators []*big.Int) *big.Rat {
	if len(numerators) == 0 || len(denominators) == 0 {
		return nil
	}
	min := big.NewRat(0, 1)
	min.SetInt64(0)
	first := true
	for _, n := range numerators {
		for _, d := range denominators {
			if d.Sign() == 0 {
				continue
			}
			r := new(big.Rat).SetFrac(n, d)
			if first || r.Cmp(min) < 0 {
				min = r
				first = false
			}
		}
	}
	if first {
		return nil
	}
	return min
}

func averageInt(vals []*big.Int) *big.Int {
	if len(vals) == 0 {
		return nil
	}
	sum := big.NewInt(0)
	for _, v := range vals {
		sum.Add(sum, v)
	}
	return sum.Div(sum, big.NewInt(int64(len(vals))))
}

func calcMinMarginRatio(params []*big.Int, states []*big.Int, paramCoeff, stateCoeff *big.Int) *big.Int {
	min := big.NewInt(0)
	min.SetInt64(1 << 62)
	for _, p := range params {
		for _, s := range states {
			lhs := new(big.Int).Mul(paramCoeff, p)
			lhs.Add(lhs, new(big.Int).Mul(stateCoeff, s))
			if lhs.Cmp(min) < 0 {
				min = lhs
			}
		}
	}
	return min
}

func hexToInt(hexStr string) *big.Int {
	body := strings.TrimPrefix(strings.ToLower(hexStr), "0x")
	if body == "" {
		return big.NewInt(0)
	}
	bi := new(big.Int)
	if _, ok := bi.SetString(body, 16); ok {
		return bi
	}
	return big.NewInt(0)
}

func pickParamValue(params []ParameterValue, idx int) *big.Int {
	for _, p := range params {
		if p.Index == idx {
			return normalizeToBigInt(p.Value)
		}
	}
	return nil
}

func pickStateValue(state map[string]StateChange, slot string) *big.Int {
	for addr := range state {
		// 这里 state 已按合约过滤
		if diff, ok := state[addr]; ok {
			if upd, ok2 := diff.StorageChanges[slot]; ok2 {
				return normalizeHexToBigInt(upd.After)
			}
		}
	}
	return nil
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
