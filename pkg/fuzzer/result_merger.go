package fuzzer

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// ResultMerger 结果合并器
type ResultMerger struct {
	// 配置参数
	mergeStrategy MergeStrategy
	// 约束规则
	constraintRules *ConstraintRulesV2
	// 基础路径（用于加载约束规则）
	basePath string
}

// MergeStrategy 合并策略
type MergeStrategy int

const (
	// MergeByRange 按范围合并（数值类型）
	MergeByRange MergeStrategy = iota
	// MergeByValue 按值合并（离散值）
	MergeByValue
	// MergeAuto 自动选择合并策略
	MergeAuto
)

// NewResultMerger 创建结果合并器
func NewResultMerger() *ResultMerger {
	return &ResultMerger{
		mergeStrategy: MergeAuto,
		basePath:      "/home/dqy/Firewall/FirewallOnchain",
	}
}

// NewResultMergerWithBasePath 创建带基础路径的结果合并器
func NewResultMergerWithBasePath(basePath string) *ResultMerger {
	return &ResultMerger{
		mergeStrategy: MergeAuto,
		basePath:      basePath,
	}
}

// NewResultMergerWithStrategy 使用指定策略创建结果合并器
func NewResultMergerWithStrategy(strategy MergeStrategy) *ResultMerger {
	return &ResultMerger{
		mergeStrategy: strategy,
	}
}

// MergeResults 合并模糊测试结果
func (m *ResultMerger) MergeResults(
	results []FuzzingResult,
	contractAddr common.Address,
	selector []byte,
	txHash common.Hash,
	blockNumber uint64,
	startTime time.Time,
) *AttackParameterReport {
	if len(results) == 0 {
		return &AttackParameterReport{
			ContractAddress:   contractAddr,
			FunctionSig:       hex.EncodeToString(selector),
			Timestamp:         startTime,
			OriginalTxHash:    txHash,
			BlockNumber:       blockNumber,
			TotalCombinations: 0,
			ValidCombinations: 0,
			HasInvariantCheck: false,
			ViolationCount:    0,
		}
	}

	// 尝试加载约束规则（如果还没加载）
	if m.constraintRules == nil && m.basePath != "" {
		rules, err := LoadConstraintRulesByContractAddr(m.basePath, contractAddr)
		if err == nil {
			m.constraintRules = rules
			log.Printf("[ResultMerger] Loaded constraint rules for contract %s", contractAddr.Hex())
		} else {
			log.Printf("[ResultMerger] No constraint rules found for contract %s: %v", contractAddr.Hex(), err)
		}
	}

	// 按参数索引分组
	paramGroups := m.groupByParameter(results)

	// 提取函数名（用于查找约束）
	funcName := m.extractFunctionName(results)

	// 为每个参数生成摘要（使用约束规则）
	validParams := m.extractParameterSummariesWithConstraints(paramGroups, funcName)

	// 计算统计信息
	stats := m.calculateStatistics(results)

	// 统计不变量检查相关信息
	hasInvariantCheck := false
	violationCount := 0
	for _, result := range results {
		if result.InvariantViolations != nil {
			hasInvariantCheck = true
			// 计算违规数量（interface{}切片）
			if violations, ok := result.InvariantViolations.([]interface{}); ok {
				violationCount += len(violations)
			}
		}
	}

	return &AttackParameterReport{
		ContractAddress:   contractAddr,
		FunctionSig:       "0x" + hex.EncodeToString(selector),
		Timestamp:         startTime,
		OriginalTxHash:    txHash,
		BlockNumber:       blockNumber,
		ValidParameters:   validParams,
		TotalCombinations: stats.totalTested,
		ValidCombinations: len(results),
		AverageSimilarity: stats.avgSimilarity,
		MaxSimilarity:     stats.maxSimilarity,
		MinSimilarity:     stats.minSimilarity,
		ExecutionTimeMs:   int64(time.Since(startTime).Milliseconds()),
		HasInvariantCheck: hasInvariantCheck, // 标记是否经过不变量检查
		ViolationCount:    violationCount,    // 违规总数
	}
}

// groupByParameter 按参数索引分组结果
func (m *ResultMerger) groupByParameter(results []FuzzingResult) map[int][]ParameterValue {
	groups := make(map[int][]ParameterValue)

	for _, result := range results {
		for _, param := range result.Parameters {
			groups[param.Index] = append(groups[param.Index], param)
		}
	}

	return groups
}

// extractParameterSummaries 提取参数摘要
func (m *ResultMerger) extractParameterSummaries(groups map[int][]ParameterValue) []ParameterSummary {
	summaries := []ParameterSummary{}

	// 按索引排序处理
	indices := make([]int, 0, len(groups))
	for idx := range groups {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	for _, idx := range indices {
		values := groups[idx]
		if len(values) == 0 {
			continue
		}

		// 获取参数类型和名称（从第一个值）
		paramType := values[0].Type
		paramName := values[0].Name

		// 地址类型不参与最终规则/表达式推送，避免硬编码地址
		if isAddressType(paramType) {
			continue
		}

		summary := ParameterSummary{
			ParamIndex:      idx,
			ParamType:       paramType,
			ParamName:       paramName,
			OccurrenceCount: len(values),
		}

		// 根据类型决定合并策略
		if m.shouldMergeAsRange(paramType, values) {
			// 合并为范围
			rangeMin, rangeMax := m.findRange(values)
			summary.IsRange = true
			summary.RangeMin = m.valueToString(rangeMin)
			summary.RangeMax = m.valueToString(rangeMax)
		} else {
			// 记录离散值
			summary.IsRange = false
			summary.SingleValues = m.extractUniqueValues(values)
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// shouldMergeAsRange 判断是否应该合并为范围
func (m *ResultMerger) shouldMergeAsRange(paramType string, values []ParameterValue) bool {
	// 强制策略
	if m.mergeStrategy == MergeByRange {
		return m.isNumericType(paramType)
	}
	if m.mergeStrategy == MergeByValue {
		return false
	}

	// 自动策略
	if !m.isNumericType(paramType) {
		return false
	}

	// 如果数值类型的不同值太多（>10），使用范围
	uniqueCount := len(m.extractUniqueValues(values))
	return uniqueCount > 10
}

// isNumericType 判断是否为数值类型
func (m *ResultMerger) isNumericType(paramType string) bool {
	return strings.HasPrefix(paramType, "uint") ||
		strings.HasPrefix(paramType, "int") ||
		paramType == "uint" ||
		paramType == "int"
}

// isAddressType 判断是否为地址类型（含数组）
func isAddressType(paramType string) bool {
	lower := strings.ToLower(paramType)
	return strings.HasPrefix(lower, "address")
}

// findRange 查找数值范围
func (m *ResultMerger) findRange(values []ParameterValue) (interface{}, interface{}) {
	if len(values) == 0 {
		return nil, nil
	}

	// 尝试处理范围值
	var minVal, maxVal *big.Int

	for _, v := range values {
		// 如果已经是范围，使用范围值
		if v.IsRange {
			if min, ok := v.RangeMin.(*big.Int); ok {
				if minVal == nil || min.Cmp(minVal) < 0 {
					minVal = new(big.Int).Set(min)
				}
			}
			if max, ok := v.RangeMax.(*big.Int); ok {
				if maxVal == nil || max.Cmp(maxVal) > 0 {
					maxVal = new(big.Int).Set(max)
				}
			}
		} else {
			// 单个值
			if val, ok := m.toBigInt(v.Value); ok {
				if minVal == nil || val.Cmp(minVal) < 0 {
					minVal = new(big.Int).Set(val)
				}
				if maxVal == nil || val.Cmp(maxVal) > 0 {
					maxVal = new(big.Int).Set(val)
				}
			}
		}
	}

	if minVal == nil || maxVal == nil {
		// 非数值类型，返回第一个和最后一个值
		return values[0].Value, values[len(values)-1].Value
	}

	return minVal, maxVal
}

// toBigInt 尝试将值转换为big.Int
func (m *ResultMerger) toBigInt(value interface{}) (*big.Int, bool) {
	switch v := value.(type) {
	case *big.Int:
		return v, true
	case int64:
		return big.NewInt(v), true
	case uint64:
		return new(big.Int).SetUint64(v), true
	case []byte:
		if len(v) <= 32 {
			return new(big.Int).SetBytes(v), true
		}
	case string:
		// 尝试解析十六进制字符串
		if strings.HasPrefix(v, "0x") {
			if n, ok := new(big.Int).SetString(v[2:], 16); ok {
				return n, true
			}
		}
		// 尝试解析十进制字符串
		if n, ok := new(big.Int).SetString(v, 10); ok {
			return n, true
		}
	}
	return nil, false
}

// extractUniqueValues 提取唯一值
func (m *ResultMerger) extractUniqueValues(values []ParameterValue) []string {
	seen := make(map[string]bool)
	unique := []string{}

	for _, v := range values {
		var strVal string
		if v.IsRange {
			// 范围值特殊处理
			strVal = fmt.Sprintf("[%s, %s]",
				m.valueToString(v.RangeMin),
				m.valueToString(v.RangeMax))
		} else {
			strVal = m.valueToString(v.Value)
		}

		if !seen[strVal] {
			seen[strVal] = true
			unique = append(unique, strVal)
		}
	}

	// 排序以保证稳定输出
	sort.Strings(unique)

	// 限制数量，避免报告过大
	if len(unique) > 100 {
		unique = unique[:100]
		unique = append(unique, "... (truncated)")
	}

	return unique
}

// valueToString 将值转换为字符串
func (m *ResultMerger) valueToString(value interface{}) string {
	if value == nil {
		return "null"
	}

	switch v := value.(type) {
	case *big.Int:
		// 对于大整数，如果很大则使用科学计数法
		if v.BitLen() > 64 {
			return fmt.Sprintf("0x%s", v.Text(16))
		}
		return v.String()

	case common.Address:
		return v.Hex()

	case bool:
		return fmt.Sprintf("%t", v)

	case []byte:
		if len(v) <= 32 {
			return "0x" + hex.EncodeToString(v)
		}
		return fmt.Sprintf("0x%s... (%d bytes)", hex.EncodeToString(v[:16]), len(v))

	case string:
		if len(v) > 100 {
			return fmt.Sprintf("%s... (%d chars)", v[:100], len(v))
		}
		return v

	case []interface{}:
		// 数组类型
		return fmt.Sprintf("[%d items]", len(v))

	default:
		return fmt.Sprintf("%v", v)
	}
}

// calculateStatistics 计算统计信息
func (m *ResultMerger) calculateStatistics(results []FuzzingResult) struct {
	totalTested   int
	avgSimilarity float64
	maxSimilarity float64
	minSimilarity float64
} {
	if len(results) == 0 {
		return struct {
			totalTested   int
			avgSimilarity float64
			maxSimilarity float64
			minSimilarity float64
		}{}
	}

	var sum float64
	maxSim := 0.0
	minSim := 1.0

	for _, result := range results {
		sum += result.Similarity
		if result.Similarity > maxSim {
			maxSim = result.Similarity
		}
		if result.Similarity < minSim {
			minSim = result.Similarity
		}
	}

	return struct {
		totalTested   int
		avgSimilarity float64
		maxSimilarity float64
		minSimilarity float64
	}{
		totalTested:   len(results),
		avgSimilarity: sum / float64(len(results)),
		maxSimilarity: maxSim,
		minSimilarity: minSim,
	}
}

// MergeMultipleReports 合并多个报告
func (m *ResultMerger) MergeMultipleReports(reports []*AttackParameterReport) *AttackParameterReport {
	if len(reports) == 0 {
		return nil
	}
	if len(reports) == 1 {
		return reports[0]
	}

	// 使用第一个报告作为基础
	merged := &AttackParameterReport{
		ContractAddress:   reports[0].ContractAddress,
		FunctionSig:       reports[0].FunctionSig,
		FunctionName:      reports[0].FunctionName,
		FunctionSignature: reports[0].FunctionSignature,
		Timestamp:         reports[0].Timestamp,
		OriginalTxHash:    reports[0].OriginalTxHash,
		BlockNumber:       reports[0].BlockNumber,
	}

	// 合并参数
	paramMap := make(map[int][]ParameterSummary)
	totalCombinations := 0
	validCombinations := 0
	var similarities []float64

	for _, report := range reports {
		totalCombinations += report.TotalCombinations
		validCombinations += report.ValidCombinations

		if report.AverageSimilarity > 0 {
			similarities = append(similarities, report.AverageSimilarity)
		}

		for _, param := range report.ValidParameters {
			paramMap[param.ParamIndex] = append(paramMap[param.ParamIndex], param)
		}
	}

	// 合并每个参数的信息
	var mergedParams []ParameterSummary
	for idx, params := range paramMap {
		if len(params) == 0 {
			continue
		}

		mergedParam := params[0]
		mergedParam.ParamIndex = idx

		// 合并所有出现的值
		allValues := []string{}
		for _, p := range params {
			if p.IsRange {
				allValues = append(allValues,
					fmt.Sprintf("[%s, %s]", p.RangeMin, p.RangeMax))
			} else {
				allValues = append(allValues, p.SingleValues...)
			}
			mergedParam.OccurrenceCount += p.OccurrenceCount
		}

		// 去重
		mergedParam.SingleValues = m.deduplicateStrings(allValues)

		mergedParams = append(mergedParams, mergedParam)
	}

	// 按索引排序
	sort.Slice(mergedParams, func(i, j int) bool {
		return mergedParams[i].ParamIndex < mergedParams[j].ParamIndex
	})

	merged.ValidParameters = mergedParams
	merged.TotalCombinations = totalCombinations
	merged.ValidCombinations = validCombinations

	// 计算平均相似度
	if len(similarities) > 0 {
		sum := 0.0
		for _, s := range similarities {
			sum += s
		}
		merged.AverageSimilarity = sum / float64(len(similarities))
		merged.MaxSimilarity = m.maxFloat64(similarities)
		merged.MinSimilarity = m.minFloat64(similarities)
	}

	return merged
}

// deduplicateStrings 字符串去重
func (m *ResultMerger) deduplicateStrings(strs []string) []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}

	sort.Strings(result)
	return result
}

// maxFloat64 找最大值
func (m *ResultMerger) maxFloat64(nums []float64) float64 {
	if len(nums) == 0 {
		return 0
	}
	max := nums[0]
	for _, n := range nums[1:] {
		if n > max {
			max = n
		}
	}
	return max
}

// minFloat64 找最小值
func (m *ResultMerger) minFloat64(nums []float64) float64 {
	if len(nums) == 0 {
		return 0
	}
	min := nums[0]
	for _, n := range nums[1:] {
		if n < min {
			min = n
		}
	}
	return min
}

// AnalyzeParameterDistribution 分析参数分布
func (m *ResultMerger) AnalyzeParameterDistribution(results []FuzzingResult) map[int]*ParameterDistribution {
	distributions := make(map[int]*ParameterDistribution)

	// 按参数索引收集值
	paramValues := make(map[int][]interface{})
	for _, result := range results {
		for _, param := range result.Parameters {
			paramValues[param.Index] = append(paramValues[param.Index], param.Value)
		}
	}

	// 分析每个参数的分布
	for idx, values := range paramValues {
		dist := m.analyzeDistribution(values)
		distributions[idx] = dist
	}

	return distributions
}

// ParameterDistribution 参数分布信息
type ParameterDistribution struct {
	TotalValues  int            // 总值数量
	UniqueValues int            // 唯一值数量
	ValueCounts  map[string]int // 值出现次数
	NumericStats *NumericStats  // 数值统计（如果是数值类型）
	MostCommon   []string       // 最常见的值
	Distribution string         // 分布类型描述
}

// NumericStats 数值统计
type NumericStats struct {
	Min    *big.Int
	Max    *big.Int
	Mean   *big.Float
	Median *big.Int
	StdDev *big.Float
}

// analyzeDistribution 分析单个参数的分布
func (m *ResultMerger) analyzeDistribution(values []interface{}) *ParameterDistribution {
	dist := &ParameterDistribution{
		TotalValues: len(values),
		ValueCounts: make(map[string]int),
	}

	// 统计值出现次数
	for _, v := range values {
		strVal := m.valueToString(v)
		dist.ValueCounts[strVal]++
	}

	dist.UniqueValues = len(dist.ValueCounts)

	// 找出最常见的值
	type valueCount struct {
		value string
		count int
	}
	var counts []valueCount
	for val, cnt := range dist.ValueCounts {
		counts = append(counts, valueCount{val, cnt})
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].count > counts[j].count
	})

	// 取前10个最常见的值
	for i := 0; i < len(counts) && i < 10; i++ {
		dist.MostCommon = append(dist.MostCommon, counts[i].value)
	}

	// 尝试计算数值统计
	numericValues := m.extractNumericValues(values)
	if len(numericValues) > 0 {
		dist.NumericStats = m.calculateNumericStats(numericValues)
		dist.Distribution = m.detectDistributionType(numericValues)
	}

	return dist
}

// extractNumericValues 提取数值
func (m *ResultMerger) extractNumericValues(values []interface{}) []*big.Int {
	var nums []*big.Int
	for _, v := range values {
		if n, ok := m.toBigInt(v); ok {
			nums = append(nums, n)
		}
	}
	return nums
}

// calculateNumericStats 计算数值统计
func (m *ResultMerger) calculateNumericStats(values []*big.Int) *NumericStats {
	if len(values) == 0 {
		return nil
	}

	stats := &NumericStats{}

	// 排序
	sorted := make([]*big.Int, len(values))
	for i, v := range values {
		sorted[i] = new(big.Int).Set(v)
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Cmp(sorted[j]) < 0
	})

	// Min/Max
	stats.Min = sorted[0]
	stats.Max = sorted[len(sorted)-1]

	// Median
	if len(sorted)%2 == 0 {
		mid1 := sorted[len(sorted)/2-1]
		mid2 := sorted[len(sorted)/2]
		stats.Median = new(big.Int).Div(
			new(big.Int).Add(mid1, mid2),
			big.NewInt(2),
		)
	} else {
		stats.Median = sorted[len(sorted)/2]
	}

	// Mean
	sum := new(big.Int)
	for _, v := range values {
		sum.Add(sum, v)
	}
	mean := new(big.Float).SetInt(sum)
	mean.Quo(mean, big.NewFloat(float64(len(values))))
	stats.Mean = mean

	// Standard Deviation
	variance := new(big.Float)
	for _, v := range values {
		diff := new(big.Float).SetInt(v)
		diff.Sub(diff, mean)
		diff.Mul(diff, diff)
		variance.Add(variance, diff)
	}
	variance.Quo(variance, big.NewFloat(float64(len(values))))
	stats.StdDev = new(big.Float).Sqrt(variance)

	return stats
}

// detectDistributionType 检测分布类型
func (m *ResultMerger) detectDistributionType(values []*big.Int) string {
	if len(values) < 10 {
		return "insufficient data"
	}

	// 简单的分布检测
	// 检查是否均匀分布
	if m.isUniformDistribution(values) {
		return "uniform"
	}

	// 检查是否集中在某些值
	uniqueCount := len(m.getUniqueValues(values))
	if float64(uniqueCount)/float64(len(values)) < 0.1 {
		return "concentrated"
	}

	// 检查是否在边界值
	if m.isBoundaryConcentrated(values) {
		return "boundary-concentrated"
	}

	return "mixed"
}

// isUniformDistribution 检查是否均匀分布
func (m *ResultMerger) isUniformDistribution(values []*big.Int) bool {
	if len(values) < 2 {
		return false
	}

	// 计算值之间的间隔
	sorted := make([]*big.Int, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Cmp(sorted[j]) < 0
	})

	// 检查间隔是否相对一致
	intervals := make([]*big.Int, len(sorted)-1)
	for i := 0; i < len(sorted)-1; i++ {
		intervals[i] = new(big.Int).Sub(sorted[i+1], sorted[i])
	}

	// 计算间隔的方差
	meanInterval := new(big.Int)
	for _, interval := range intervals {
		meanInterval.Add(meanInterval, interval)
	}
	meanInterval.Div(meanInterval, big.NewInt(int64(len(intervals))))

	variance := new(big.Int)
	for _, interval := range intervals {
		diff := new(big.Int).Sub(interval, meanInterval)
		diff.Mul(diff, diff)
		variance.Add(variance, diff)
	}

	// 如果方差很小，认为是均匀分布
	threshold := new(big.Int).Mul(meanInterval, meanInterval)
	threshold.Div(threshold, big.NewInt(10)) // 10%的阈值

	return variance.Cmp(threshold) < 0
}

// isBoundaryConcentrated 检查是否集中在边界值
func (m *ResultMerger) isBoundaryConcentrated(values []*big.Int) bool {
	if len(values) == 0 {
		return false
	}

	// 找出最大值（假设是边界）
	maxValue := new(big.Int)
	for _, v := range values {
		if v.Cmp(maxValue) > 0 {
			maxValue = v
		}
	}

	// 统计接近0和接近最大值的数量
	nearZero := 0
	nearMax := 0
	threshold := new(big.Int).Div(maxValue, big.NewInt(100)) // 1%阈值

	for _, v := range values {
		if v.Cmp(threshold) <= 0 {
			nearZero++
		}
		diff := new(big.Int).Sub(maxValue, v)
		if diff.Cmp(threshold) <= 0 {
			nearMax++
		}
	}

	// 如果超过50%的值在边界附近，认为是边界集中
	boundaryCount := nearZero + nearMax
	return float64(boundaryCount)/float64(len(values)) > 0.5
}

// getUniqueValues 获取唯一值
func (m *ResultMerger) getUniqueValues(values []*big.Int) []*big.Int {
	seen := make(map[string]bool)
	unique := []*big.Int{}

	for _, v := range values {
		key := v.String()
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
		}
	}

	return unique
}

// extractFunctionName 从结果中提取函数名
func (m *ResultMerger) extractFunctionName(results []FuzzingResult) string {
	if len(results) == 0 {
		return ""
	}

	// 从CallData中提取函数selector（前4字节）
	for _, result := range results {
		if len(result.CallData) >= 4 {
			selector := fmt.Sprintf("0x%x", result.CallData[0:4])
			return selector
		}
	}

	return ""
}

// extractParameterSummariesWithConstraints 使用约束规则提取参数摘要
func (m *ResultMerger) extractParameterSummariesWithConstraints(groups map[int][]ParameterValue, funcSelector string) []ParameterSummary {
	summaries := []ParameterSummary{}

	// 按索引排序处理
	indices := make([]int, 0, len(groups))
	for idx := range groups {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	for _, idx := range indices {
		values := groups[idx]
		if len(values) == 0 {
			continue
		}

		// 获取参数类型和名称（从第一个值）
		paramType := values[0].Type
		paramName := values[0].Name

		// 地址类型不参与最终规则/表达式推送，避免硬编码地址
		if isAddressType(paramType) {
			continue
		}

		summary := ParameterSummary{
			ParamIndex:      idx,
			ParamType:       paramType,
			ParamName:       paramName,
			OccurrenceCount: len(values),
		}

		// 尝试为这个参数索引查找约束（传入函数selector用于匹配）
		var paramConstraint *ParamConstraintInfo
		if m.constraintRules != nil {
			paramConstraint = m.findConstraintForParameter(idx, paramName, funcSelector)
		}

		// 根据类型决定合并策略
		if m.shouldMergeAsRange(paramType, values) {
			// 合并为范围
			rangeMin, rangeMax := m.findRangeWithConstraint(values, paramConstraint)
			summary.IsRange = true
			summary.RangeMin = m.valueToString(rangeMin)
			summary.RangeMax = m.valueToString(rangeMax)

			// 输出约束信息
			if paramConstraint != nil && paramConstraint.SafeThreshold != nil {
				log.Printf("[ResultMerger] Param #%d (%s): Applied constraint - SafeMax=%s, ObservedMax=%s, FinalMax=%s",
					idx,
					paramName,
					paramConstraint.SafeThreshold.String(),
					m.valueToString(rangeMax),
					summary.RangeMax,
				)
			}
		} else {
			// 记录离散值
			summary.IsRange = false
			summary.SingleValues = m.extractUniqueValues(values)
		}

		summaries = append(summaries, summary)
	}

	return summaries
}

// findConstraintForParameter 为参数索引查找约束
func (m *ResultMerger) findConstraintForParameter(paramIndex int, paramName string, funcSelector string) *ParamConstraintInfo {
	if m.constraintRules == nil {
		return nil
	}

	// 从selector计算期望的函数名
	// 注意：这里假设约束规则中的function字段与selector对应的函数名一致
	// 例如 selector 0xee9c79da 对应 function "debond"

	// 遍历所有约束，查找匹配的参数
	for _, constraint := range m.constraintRules.Constraints {
		// 尝试提取参数约束
		paramConstraint := ExtractParameterConstraint(&constraint, paramIndex)
		if paramConstraint == nil {
			continue // 这个约束不包含当前参数
		}

		// 如果提供了selector，检查是否属于同一个函数
		if funcSelector != "" {
			// 计算约束对应的selector
			var constraintSelector string
			if constraint.Signature != "" {
				// 从完整签名计算selector
				constraintSelector = calculateSelector(constraint.Signature)
			}

			// 检查是否匹配
			if constraintSelector == "" || strings.EqualFold(constraintSelector, funcSelector) {
				// Selector匹配或无法计算selector（使用函数名匹配）
				log.Printf("[ResultMerger] ✓ Found constraint for param #%d in function %s (selector: %s)",
					paramIndex, constraint.Function, funcSelector)
				return paramConstraint
			}
		} else {
			// 没有selector，返回第一个匹配的
			log.Printf("[ResultMerger] Found constraint for param #%d in function %s (no selector)", paramIndex, constraint.Function)
			return paramConstraint
		}
	}

	log.Printf("[ResultMerger] ✗ No constraint found for param #%d with selector %s", paramIndex, funcSelector)
	return nil
}

// calculateSelector 从函数签名计算selector
func calculateSelector(signature string) string {
	// 移除空格
	sig := strings.TrimSpace(signature)

	// 如果是简化签名如"debond(...)"，无法计算selector
	if strings.Contains(sig, "...") {
		return ""
	}

	// 计算keccak256并取前4字节
	hash := crypto.Keccak256([]byte(sig))
	selector := fmt.Sprintf("0x%x", hash[:4])
	return selector
}

// findRangeWithConstraint 查找数值范围（使用约束规则）
func (m *ResultMerger) findRangeWithConstraint(values []ParameterValue, constraint *ParamConstraintInfo) (interface{}, interface{}) {
	if len(values) == 0 {
		return nil, nil
	}

	// 首先找出观察到的范围
	observedMin, observedMax := m.findRange(values)

	// 如果没有约束，不返回范围（避免生成错误的"允许范围"）
	// 离散值会自动使用Blacklist规则
	if constraint == nil || constraint.SafeThreshold == nil {
		log.Printf("[ResultMerger] No constraint for parameter, skipping range (will use blacklist for discrete values)")
		return nil, nil
	}

	// 应用约束规则
	// 对于安全上界约束（amount <= safe_threshold），将 rangeMax 设置为 safe_threshold
	// 对于安全下界约束（amount >= safe_threshold），将 rangeMin 设置为 safe_threshold

	minVal, _ := m.toBigInt(observedMin)
	maxVal, ok := m.toBigInt(observedMax)

	if !ok || maxVal == nil {
		// 非数值类型，返回观察到的范围
		return observedMin, observedMax
	}

	// 判断约束类型
	if constraint.IsSafeUpper {
		// 安全条件是上界（amount <= threshold）
		// 规则应该允许 [0, safe_threshold]
		// 而不是只允许 [observed_min, observed_max]（攻击参数范围）

		log.Printf("[ResultMerger] Applying upper bound constraint: observed [%s, %s] -> allowed [0, %s]",
			minVal.String(),
			maxVal.String(),
			constraint.SafeThreshold.String(),
		)

		// 返回 [0, safe_threshold]
		return big.NewInt(0), constraint.SafeThreshold
	} else {
		// 安全条件是下界（amount >= threshold）
		// 规则应该允许 [safe_threshold, ∞]，使用类型最大值作为上界
		maxUint256 := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))

		log.Printf("[ResultMerger] Applying lower bound constraint: observed [%s, %s] -> allowed [%s, max]",
			minVal.String(),
			maxVal.String(),
			constraint.SafeThreshold.String(),
		)

		return constraint.SafeThreshold, maxUint256
	}
}
