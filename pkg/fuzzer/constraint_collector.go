package fuzzer

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sort"
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
	mu              sync.Mutex
	samples         map[string][]constraintSample // key: contract-selector
	rules           map[string]*ConstraintRule
	threshold       int
	exprs           map[string]*ExpressionRule
	exprCost        map[string]int64 // 表达式生成耗时(ms)
	lastGenSample   map[string]int   // 记录每个key上次生成规则时的样本数，便于滑动窗口再生成
	constraintRules *ConstraintRulesV2
	selectorToFunc  map[string]string
	selectorToSig   map[string]string
	basePath        string
	projectID       string
}

// NewConstraintCollector 创建约束收集器
func NewConstraintCollector(threshold int) *ConstraintCollector {
	return NewConstraintCollectorWithBasePath(threshold, "")
}

// NewConstraintCollectorWithBasePath 创建带基础路径的约束收集器（用于加载constraint_rules_v2.json）
func NewConstraintCollectorWithBasePath(threshold int, basePath string) *ConstraintCollector {
	if threshold <= 0 {
		threshold = 10
	}
	return &ConstraintCollector{
		samples:       make(map[string][]constraintSample),
		rules:         make(map[string]*ConstraintRule),
		exprs:         make(map[string]*ExpressionRule),
		exprCost:      make(map[string]int64),
		threshold:     threshold,
		lastGenSample: make(map[string]int),
		basePath:      basePath,
	}
}

// NewConstraintCollectorWithProject 创建带基础路径和项目ID的约束收集器
func NewConstraintCollectorWithProject(threshold int, basePath, projectID string) *ConstraintCollector {
	cc := NewConstraintCollectorWithBasePath(threshold, basePath)
	cc.projectID = projectID
	cc.loadTargetFunctionMap()
	return cc
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

	// 尝试加载约束规则（首次调用时）
	if cc.constraintRules == nil && cc.basePath != "" {
		if cc.projectID != "" {
			if rules, err := LoadConstraintRules(cc.basePath, cc.projectID); err == nil {
				if strings.EqualFold(rules.VulnerableContract.Address, contract.Hex()) {
					cc.constraintRules = rules
					log.Printf("[ConstraintCollector] Loaded constraint rules for contract %s", contract.Hex())
				} else {
					log.Printf("[ConstraintCollector] 项目 %s 约束不匹配合约 %s，回退按地址查找", cc.projectID, contract.Hex())
				}
			}
		}
		if cc.constraintRules == nil {
			if rules, err := LoadConstraintRulesByContractAddr(cc.basePath, contract); err == nil {
				cc.constraintRules = rules
				log.Printf("[ConstraintCollector] Loaded constraint rules for contract %s", contract.Hex())
			}
		}
	}

	cc.samples[key] = append(cc.samples[key], constraintSample{
		params: params,
		state:  state,
		sim:    similarity,
	})

	if len(cc.samples[key]) < cc.threshold {
		return nil
	}

	// 生成或更新规则：达到阈值后每次都基于最新窗口重建，保证规则随样本滑动刷新
	rule := cc.buildRule(contract, selector, cc.samples[key])
	cc.rules[key] = rule
	cc.lastGenSample[key] = len(cc.samples[key])

	// 同步生成表达式规则（ratio/linear）
	start := time.Now()
	if expr := cc.buildExpressionRule(contract, selector, cc.samples[key]); expr != nil {
		cc.exprs[key] = expr
		cc.exprCost[key] = time.Since(start).Milliseconds()
	}

	// 保留滑动窗口：只保留最近 threshold 条样本，避免缓存无限增长
	if len(cc.samples[key]) > cc.threshold {
		cc.samples[key] = cc.samples[key][len(cc.samples[key])-cc.threshold:]
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

// GetExpressionGenCost 获取表达式生成耗时(ms)
func (cc *ConstraintCollector) GetExpressionGenCost(contract common.Address, selector []byte) int64 {
	if cc == nil {
		return 0
	}
	cc.mu.Lock()
	defer cc.mu.Unlock()
	return cc.exprCost[cc.ruleKey(contract, selector)]
}

func (cc *ConstraintCollector) ruleKey(contract common.Address, selector []byte) string {
	return strings.ToLower(contract.Hex()) + "-" + hex.EncodeToString(selector)
}

func (cc *ConstraintCollector) buildRule(contract common.Address, selector []byte, samples []constraintSample) *ConstraintRule {
	// 构造函数签名用于查找约束
	selectorHex := "0x" + hex.EncodeToString(selector)
	var funcConstraints []FunctionConstraint
	if cc.constraintRules != nil {
		funcConstraints = cc.lookupConstraints(selectorHex)
	}

	paramRanges := cc.aggregateParamConstraintsWithRules(samples, funcConstraints)
	stateConstraints := aggregateStateConstraints(contract, samples)

	return &ConstraintRule{
		ContractAddress:   contract,
		FunctionSelector:  selectorHex,
		SampleCount:       len(samples),
		ParamConstraints:  paramRanges,
		StateConstraints:  stateConstraints,
		SimilarityTrigger: averageSimilarity(samples),
		GeneratedAt:       time.Now(),
	}
}

type targetFunctionConfig struct {
	ProjectID     string `json:"project_id"`
	FuzzingConfig *struct {
		TargetFunctions []struct {
			Signature string `json:"signature"`
			Function  string `json:"function"`
		} `json:"target_functions"`
	} `json:"fuzzing_config"`
}

func (cc *ConstraintCollector) loadTargetFunctionMap() {
	if cc.basePath == "" || cc.projectID == "" {
		return
	}

	configDirs := []string{
		filepath.Join(cc.basePath, "autopath", "pkg", "invariants", "configs"),
		filepath.Join(cc.basePath, "pkg", "invariants", "configs"),
	}

	selectorToFunc := make(map[string]string)
	selectorToSig := make(map[string]string)

	for _, dir := range configDirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, path := range matches {
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			var cfg targetFunctionConfig
			if err := json.Unmarshal(data, &cfg); err != nil {
				continue
			}
			if !strings.EqualFold(cfg.ProjectID, cc.projectID) || cfg.FuzzingConfig == nil {
				continue
			}
			for _, tf := range cfg.FuzzingConfig.TargetFunctions {
				selector, err := signatureToSelector(tf.Signature)
				if err != nil || selector == "" {
					continue
				}
				selKey := strings.ToLower(selector)
				if tf.Function != "" {
					selectorToFunc[selKey] = tf.Function
				}
				if tf.Signature != "" {
					selectorToSig[selKey] = tf.Signature
				}
			}
		}
	}

	cc.selectorToFunc = selectorToFunc
	cc.selectorToSig = selectorToSig
}

func (cc *ConstraintCollector) lookupConstraints(selectorHex string) []FunctionConstraint {
	if cc.constraintRules == nil {
		return nil
	}

	if funcConstraints := cc.constraintRules.GetConstraintForFunction(selectorHex); len(funcConstraints) > 0 {
		log.Printf("[ConstraintCollector] Found %d constraint(s) for selector %s", len(funcConstraints), selectorHex)
		return funcConstraints
	}

	selectorKey := strings.ToLower(selectorHex)
	if sig := cc.selectorToSig[selectorKey]; sig != "" {
		if funcConstraints := cc.constraintRules.GetConstraintForFunction(sig); len(funcConstraints) > 0 {
			log.Printf("[ConstraintCollector] Found %d constraint(s) for signature %s", len(funcConstraints), sig)
			return funcConstraints
		}
	}

	if name := cc.selectorToFunc[selectorKey]; name != "" {
		if funcConstraints := cc.constraintRules.GetConstraintForFunction(name); len(funcConstraints) > 0 {
			log.Printf("[ConstraintCollector] Found %d constraint(s) for function %s", len(funcConstraints), name)
			return funcConstraints
		}
	}

	return nil
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
		margin   *big.Int
	}

	var best candidate
	best.rMin = nil

	// 预取参数/状态数值
	paramVals := extractNumericParams(samples)
	stateVals := extractNumericState(samples, contract)
	paramTypes := collectParamTypes(samples)

	for pIdx, vals := range paramVals {
		for slot, svals := range stateVals {
			minRat := minRatio(vals, svals)
			if minRat == nil {
				continue
			}
			// 留一点安全余量 90%（5-10%安全边际）
			minRat = new(big.Rat).Mul(minRat, big.NewRat(9, 10))

			// k = rMin，转为 big.Int 精度 scale
			kScaled := ratToInt(new(big.Rat).Mul(minRat, new(big.Rat).SetInt(scale)))
			if kScaled == nil || kScaled.Sign() == 0 {
				continue
			}

			paramCoeff := new(big.Int).Set(scale) // p * SCALE
			stateCoeff := new(big.Int).Neg(kScaled)
			minMargin := calcMinMarginRatio(vals, svals, paramCoeff, stateCoeff)
			if minMargin == nil {
				continue
			}

			if best.rMin == nil || minRat.Cmp(best.rMin) < 0 || (minRat.Cmp(best.rMin) == 0 && minMargin.Cmp(best.margin) > 0) {
				best = candidate{paramIdx: pIdx, slot: slot, rMin: minRat, margin: minMargin}
			}
		}
	}

	if best.rMin == nil {
		return nil
	}

	kInt := ratToInt(new(big.Rat).Mul(best.rMin, new(big.Rat).SetInt(scale)))
	if kInt == nil || kInt.Sign() == 0 {
		return nil
	}

	// 反转系数符号，使表达式变为拦截条件
	// 原表达式：p*SCALE - k*s >= 0（攻击满足，会通过❌）
	// 新表达式：-p*SCALE + k*s >= 0（攻击不满足，会被拦截✓）
	// 即：p*SCALE <= k*s，拦截 p >= k*s/SCALE 的攻击参数
	paramCoeff := new(big.Int).Neg(scale) // -p * SCALE
	stateCoeff := new(big.Int).Set(kInt)  // +k * s
	minMargin := calcMinMarginRatio(paramVals[best.paramIdx], stateVals[best.slot], paramCoeff, stateCoeff)

	return &ExpressionRule{
		Type:     "ratio",
		Contract: contract,
		Selector: selector,
		Terms: []LinearTerm{
			{
				Kind:       "param",
				ParamIndex: best.paramIdx,
				ParamType:  paramTypes[best.paramIdx],
				Coeff:      formatSignedHex(paramCoeff),
			},
			{Kind: "state", Slot: best.slot, Coeff: formatSignedHex(stateCoeff)},
		},
		Threshold:    formatSignedHex(big.NewInt(0)),
		Scale:        formatUnsignedHex(scale),
		Confidence:   1.0, // 正样本全部覆盖
		SampleCount:  len(samples),
		MinMarginHex: formatSignedHex(minMargin),
		Strategy:     "ratio_param_over_state",
	}
}

// buildLinearRule 生成稀疏线性不等式：∑ w_i * x_i >= T
func buildLinearRule(contract common.Address, selector string, samples []constraintSample, scale *big.Int) *ExpressionRule {
	if len(samples) == 0 {
		return nil
	}

	featureOrder, maxAbs := collectFeatureOrder(samples, contract)
	if len(featureOrder) == 0 {
		return nil
	}

	// 构造特征向量（原始数值）
	vectors := buildFeatureVectors(samples, featureOrder)
	paramTypes := collectParamTypes(samples)

	// 归一化并计算中心方向（近似 one-class 线性分隔）
	centroid := make([]*big.Rat, len(featureOrder))
	for i := range centroid {
		centroid[i] = new(big.Rat)
	}
	for _, vec := range vectors {
		for i, v := range vec {
			norm := normalizeWithMax(v, maxAbs[i])
			centroid[i].Add(centroid[i], norm)
		}
	}
	countRat := new(big.Rat).SetInt64(int64(len(vectors)))
	for i := range centroid {
		centroid[i].Quo(centroid[i], countRat)
	}

	// 计算最小间隔（所有正样本均需满足）
	minDot := (*big.Rat)(nil)
	for _, vec := range vectors {
		dot := new(big.Rat)
		for i, v := range vec {
			dot.Add(dot, new(big.Rat).Mul(centroid[i], normalizeWithMax(v, maxAbs[i])))
		}
		if minDot == nil || dot.Cmp(minDot) < 0 {
			minDot = dot
		}
	}
	if minDot == nil || minDot.Sign() <= 0 {
		return nil
	}

	// 设置阈值为最小间隔的90%（安全余量）
	thresholdRat := new(big.Rat).Mul(minDot, big.NewRat(9, 10))
	if thresholdRat.Sign() <= 0 {
		return nil
	}

	// 反转质心方向和阈值，使攻击样本被拦截
	// 原：攻击样本 ∑w_i*x_i >= T，会通过❌
	// 新：攻击样本 ∑(-w_i)*x_i < -T，会被拦截✓
	// 链上检查：lhs >= threshold 时通过，所以需要让攻击样本不满足这个条件
	for i := range centroid {
		centroid[i].Neg(centroid[i]) // 反转质心方向
	}
	thresholdRat.Neg(thresholdRat) // 反转阈值

	terms := make([]LinearTerm, 0, len(featureOrder))
	coeffInts := make([]*big.Int, len(featureOrder))
	scaleRat := new(big.Rat).SetInt(scale)
	for i, feat := range featureOrder {
		// coeff = centroid_i / maxAbs_i * scale
		coeffRat := new(big.Rat).Set(centroid[i])
		coeffRat.Quo(coeffRat, new(big.Rat).SetInt(maxAbs[i]))
		coeffRat.Mul(coeffRat, scaleRat)
		coeffInt := ratToInt(coeffRat)
		if coeffInt == nil {
			coeffInt = big.NewInt(0)
		}
		coeffInts[i] = coeffInt

		term := LinearTerm{Kind: feat.kind, Coeff: formatSignedHex(coeffInt)}
		if feat.kind == "param" {
			term.ParamIndex = feat.paramIndex
			term.ParamType = paramTypes[feat.paramIndex]
		} else {
			term.Slot = feat.slot
		}
		terms = append(terms, term)
	}

	thresholdInt := ratToInt(new(big.Rat).Mul(thresholdRat, scaleRat))
	if thresholdInt == nil || thresholdInt.Sign() == 0 {
		return nil
	}

	minMargin := calcMinMarginLinear(vectors, coeffInts, thresholdInt)

	return &ExpressionRule{
		Type:         "linear",
		Contract:     contract,
		Selector:     selector,
		Terms:        terms,
		Threshold:    formatSignedHex(thresholdInt),
		Scale:        formatUnsignedHex(scale),
		Confidence:   1.0,
		SampleCount:  len(samples),
		MinMarginHex: formatSignedHex(minMargin),
		Strategy:     "sparse_hyperplane_origin_margin",
	}
}

// 辅助函数：提取数值型参数
func extractNumericParams(samples []constraintSample) map[int][]*big.Int {
	out := make(map[int][]*big.Int)
	for _, s := range samples {
		for _, p := range s.params {
			// 地址类型不参与表达式/数值规则
			if isAddressType(p.Type) {
				continue
			}
			if val := normalizeToBigInt(p.Value); val != nil {
				out[p.Index] = append(out[p.Index], val)
			}
		}
	}
	return out
}

// collectParamTypes 收集每个参数索引对应的类型字符串
func collectParamTypes(samples []constraintSample) map[int]string {
	out := make(map[int]string)
	for _, s := range samples {
		for _, p := range s.params {
			if _, ok := out[p.Index]; ok {
				continue
			}
			out[p.Index] = p.Type
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
			// 地址类型不参与数值特征
			if isAddressType(p.Type) {
				return nil
			}
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

// aggregateParamConstraintsWithRules 使用约束规则生成参数约束
func (cc *ConstraintCollector) aggregateParamConstraintsWithRules(samples []constraintSample, funcConstraints []FunctionConstraint) []ParamConstraint {
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
		// 地址类型不生成规则，直接跳过
		if isAddressType(pc.Type) {
			continue
		}
		isNumeric := strings.HasPrefix(pc.Type, "uint") || strings.HasPrefix(pc.Type, "int")

		var minVal, maxVal *big.Int
		numericValues := make(map[string]struct{})
		valueSet := make(map[string]struct{})

		// 收集观察到的参数值
		for _, s := range samples {
			if i >= len(s.params) {
				continue
			}
			val := s.params[i].Value
			if isNumeric {
				if bi := normalizeBigIntValue(val); bi != nil {
					numericValues[bi.String()] = struct{}{}
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
			// 查找参数的约束规则
			paramConstraint := pickParamConstraint(funcConstraints, i)
			if len(numericValues) <= 1 && (paramConstraint == nil || paramConstraint.ConstraintType == "discrete_numeric") {
				log.Printf("[ConstraintCollector] 跳过单值数值规则: param#%d value=%s", i, minVal.String())
				continue
			}

			// 默认使用攻击样本范围作为黑名单区间
			rangeMinHex := "0x" + minVal.Text(16)
			rangeMaxHex := "0x" + maxVal.Text(16)

			// 如果存在安全阈值，转换为“拦截 unsafe 区间”的范围
			if paramConstraint != nil && paramConstraint.SafeThreshold != nil {
				thresholdHex := "0x" + paramConstraint.SafeThreshold.Text(16)
				if paramConstraint.IsSafeUpper {
					// 拦截 >= safe_threshold 的高危数值
					rangeMinHex = thresholdHex
					if strings.HasPrefix(pc.Type, "uint") {
						maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
						rangeMaxHex = "0x" + maxUint256.Text(16)
					} else {
						rangeMaxHex = "0x" + maxVal.Text(16)
						log.Printf("[ConstraintCollector] Warning: 使用观察到的最大值作为上界（非uint类型 %s）", pc.Type)
					}
					log.Printf("[ConstraintCollector] 应用上界拦截: param#%d unsafe >= %s", i, thresholdHex)
				} else {
					// 拦截 <= safe_threshold 的低危数值
					rangeMinHex = "0x0"
					rangeMaxHex = thresholdHex
					log.Printf("[ConstraintCollector] 应用下界拦截: param#%d unsafe <= %s", i, thresholdHex)
				}
			} else {
				log.Printf("[ConstraintCollector] 使用攻击样本范围作为黑名单: param#%d [%s, %s]", i, minVal.String(), maxVal.String())
			}

			pc.IsRange = true
			pc.RangeMin = rangeMinHex
			pc.RangeMax = rangeMaxHex
		} else {
			pc.Values = dedupMapKeys(valueSet)
		}
	}

	return constraints
}

// pickParamConstraint 从多条函数约束中挑选对指定参数最严格的阈值
func pickParamConstraint(funcConstraints []FunctionConstraint, paramIndex int) *ParamConstraintInfo {
	var chosen *ParamConstraintInfo
	for i := range funcConstraints {
		pc := ExtractParameterConstraint(&funcConstraints[i], paramIndex)
		if pc == nil {
			continue
		}
		if chosen == nil {
			chosen = pc
			continue
		}
		// 优先保留更严格的安全阈值：上界取较小，下界取较大
		if pc.SafeThreshold != nil && chosen.SafeThreshold != nil {
			if pc.IsSafeUpper == chosen.IsSafeUpper {
				if pc.IsSafeUpper && pc.SafeThreshold.Cmp(chosen.SafeThreshold) < 0 {
					chosen = pc
				} else if !pc.IsSafeUpper && pc.SafeThreshold.Cmp(chosen.SafeThreshold) > 0 {
					chosen = pc
				}
			}
			continue
		}
		if chosen.SafeThreshold == nil && pc.SafeThreshold != nil {
			chosen = pc
		}
	}
	return chosen
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
		// 地址类型不生成规则，直接跳过
		if isAddressType(pc.Type) {
			continue
		}
		isNumeric := strings.HasPrefix(pc.Type, "uint") || strings.HasPrefix(pc.Type, "int")

		var minVal, maxVal *big.Int
		numericValues := make(map[string]struct{})
		valueSet := make(map[string]struct{})

		for _, s := range samples {
			if i >= len(s.params) {
				continue
			}
			val := s.params[i].Value
			if isNumeric {
				if bi := normalizeBigIntValue(val); bi != nil {
					numericValues[bi.String()] = struct{}{}
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
			if len(numericValues) <= 1 {
				log.Printf("[ConstraintCollector] 跳过单值数值规则: param#%d value=%s", i, minVal.String())
				continue
			}
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

// featureDesc 描述用于线性不等式的特征（参数或状态槽）
type featureDesc struct {
	kind       string
	paramIndex int
	slot       string
}

// collectFeatureOrder 获取稳定的特征顺序及每个特征的最大绝对值（用于归一化）
func collectFeatureOrder(samples []constraintSample, contract common.Address) ([]featureDesc, []*big.Int) {
	paramVals := extractNumericParams(samples)
	stateVals := extractNumericState(samples, contract)

	var featureOrder []featureDesc
	var maxAbs []*big.Int

	paramIdx := make([]int, 0, len(paramVals))
	for idx := range paramVals {
		paramIdx = append(paramIdx, idx)
	}
	sort.Ints(paramIdx)
	for _, idx := range paramIdx {
		featureOrder = append(featureOrder, featureDesc{kind: "param", paramIndex: idx})
		maxAbs = append(maxAbs, maxAbsValue(paramVals[idx]))
	}

	stateSlots := make([]string, 0, len(stateVals))
	for slot := range stateVals {
		stateSlots = append(stateSlots, slot)
	}
	sort.Strings(stateSlots)
	for _, slot := range stateSlots {
		featureOrder = append(featureOrder, featureDesc{kind: "state", slot: slot})
		maxAbs = append(maxAbs, maxAbsValue(stateVals[slot]))
	}

	return featureOrder, maxAbs
}

// buildFeatureVectors 根据特征顺序生成样本向量
func buildFeatureVectors(samples []constraintSample, order []featureDesc) [][]*big.Int {
	vectors := make([][]*big.Int, 0, len(samples))
	for _, s := range samples {
		vec := make([]*big.Int, len(order))
		for i, feat := range order {
			if feat.kind == "param" {
				vec[i] = pickParamValue(s.params, feat.paramIndex)
			} else {
				vec[i] = pickStateValue(s.state, feat.slot)
			}
			if vec[i] == nil {
				vec[i] = big.NewInt(0)
			}
		}
		vectors = append(vectors, vec)
	}
	return vectors
}

// maxAbsValue 计算一组数值的最大绝对值，最小为1以避免除零
func maxAbsValue(vals []*big.Int) *big.Int {
	maxV := big.NewInt(1)
	for _, v := range vals {
		if v == nil {
			continue
		}
		if abs := new(big.Int).Abs(v); abs.Cmp(maxV) > 0 {
			maxV = abs
		}
	}
	return maxV
}

// normalizeWithMax 将值按最大绝对值归一化为[-1,1]区间，返回有理数
func normalizeWithMax(val *big.Int, maxAbs *big.Int) *big.Rat {
	if maxAbs == nil || maxAbs.Sign() == 0 {
		return new(big.Rat)
	}
	return new(big.Rat).SetFrac(val, maxAbs)
}

// ratToInt 将有理数下取整为big.Int
func ratToInt(r *big.Rat) *big.Int {
	if r == nil {
		return nil
	}
	return new(big.Int).Div(r.Num(), r.Denom())
}

// calcMinMarginLinear 计算线性不等式的最小裕度：sum(coeff_i * x_i) - threshold
func calcMinMarginLinear(vectors [][]*big.Int, coeffs []*big.Int, threshold *big.Int) *big.Int {
	if len(vectors) == 0 {
		return big.NewInt(0)
	}
	minMargin := (*big.Int)(nil)
	for _, vec := range vectors {
		sum := big.NewInt(0)
		for i, v := range vec {
			coeff := big.NewInt(0)
			if i < len(coeffs) && coeffs[i] != nil {
				coeff = coeffs[i]
			}
			sum.Add(sum, new(big.Int).Mul(coeff, v))
		}
		margin := new(big.Int).Sub(sum, threshold)
		if minMargin == nil || margin.Cmp(minMargin) < 0 {
			minMargin = margin
		}
	}
	if minMargin == nil {
		return big.NewInt(0)
	}
	return minMargin
}

func formatSignedHex(value *big.Int) string {
	if value == nil {
		return "0x0"
	}
	if value.Sign() < 0 {
		abs := new(big.Int).Abs(value)
		return "-0x" + abs.Text(16)
	}
	return "0x" + value.Text(16)
}

func formatUnsignedHex(value *big.Int) string {
	if value == nil {
		return "0x0"
	}
	if value.Sign() < 0 {
		abs := new(big.Int).Abs(value)
		return "0x" + abs.Text(16)
	}
	return "0x" + value.Text(16)
}
