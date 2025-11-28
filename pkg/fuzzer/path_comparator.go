package fuzzer

import (
	"fmt"
	"math"
	"strings"
)

// PathComparator 路径比较器
type PathComparator struct {
	// 可配置的参数
	minSimilarity float64 // 最小相似度阈值
}

// NewPathComparator 创建路径比较器
func NewPathComparator() *PathComparator {
	return &PathComparator{
		minSimilarity: 0.0, // 默认不设置最小阈值
	}
}

// NewPathComparatorWithThreshold 创建带阈值的路径比较器
func NewPathComparatorWithThreshold(minSimilarity float64) *PathComparator {
	return &PathComparator{
		minSimilarity: minSimilarity,
	}
}

// CompareJumpDests 比较两个JUMPDEST序列的相似度
// 使用最长公共子序列(LCS)算法计算相似度
// 返回值范围: 0.0 (完全不同) 到 1.0 (完全相同)
func (p *PathComparator) CompareJumpDests(original, variant []uint64) float64 {
	// 处理空序列情况
	if len(original) == 0 && len(variant) == 0 {
		return 1.0 // 两个空序列视为相同
	}
	if len(original) == 0 || len(variant) == 0 {
		return 0.0 // 一个为空，另一个不为空，视为完全不同
	}

	// 计算最长公共子序列长度
	lcsLength := p.longestCommonSubsequence(original, variant)

	// 使用Dice系数计算相似度: 2 * LCS / (len1 + len2)
	similarity := (2.0 * float64(lcsLength)) / float64(len(original)+len(variant))

	// 如果设置了最小阈值，低于阈值的返回0
	if p.minSimilarity > 0 && similarity < p.minSimilarity {
		return 0.0
	}

	return similarity
}

// longestCommonSubsequence 计算最长公共子序列长度
// 使用动态规划算法，时间复杂度O(m*n)，空间复杂度O(m*n)
func (p *PathComparator) longestCommonSubsequence(seq1, seq2 []uint64) int {
	m, n := len(seq1), len(seq2)

	// 创建DP表
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	// 填充DP表
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if seq1[i-1] == seq2[j-1] {
				// 当前元素相同，LCS长度+1
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				// 当前元素不同，取左边或上边的最大值
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	return dp[m][n]
}

// CompareJumpDestsWithDetails 比较JUMPDEST序列并返回详细信息
func (p *PathComparator) CompareJumpDestsWithDetails(original, variant []uint64) *PathComparisonResult {
	similarity := p.CompareJumpDests(original, variant)
	lcsLength := p.longestCommonSubsequence(original, variant)

	// 计算其他指标
	commonElements := p.findCommonElements(original, variant)
	uniqueInOriginal := p.findUniqueElements(original, variant)
	uniqueInVariant := p.findUniqueElements(variant, original)

	return &PathComparisonResult{
		Similarity:       similarity,
		LCSLength:        lcsLength,
		OriginalLength:   len(original),
		VariantLength:    len(variant),
		CommonElements:   commonElements,
		UniqueInOriginal: uniqueInOriginal,
		UniqueInVariant:  uniqueInVariant,
		IsMatch:          similarity >= 0.8, // 默认阈值0.8
	}
}

// PathComparisonResult 路径比较结果
type PathComparisonResult struct {
	Similarity       float64  // 相似度分数
	LCSLength        int      // 最长公共子序列长度
	OriginalLength   int      // 原始序列长度
	VariantLength    int      // 变体序列长度
	CommonElements   []uint64 // 共同元素
	UniqueInOriginal []uint64 // 原始序列独有元素
	UniqueInVariant  []uint64 // 变体序列独有元素
	IsMatch          bool     // 是否匹配（超过阈值）
}

// findCommonElements 查找共同元素
func (p *PathComparator) findCommonElements(seq1, seq2 []uint64) []uint64 {
	set2 := make(map[uint64]bool)
	for _, v := range seq2 {
		set2[v] = true
	}

	common := []uint64{}
	seen := make(map[uint64]bool)
	for _, v := range seq1 {
		if set2[v] && !seen[v] {
			common = append(common, v)
			seen[v] = true
		}
	}

	return common
}

// findUniqueElements 查找seq1中独有的元素（不在seq2中）
func (p *PathComparator) findUniqueElements(seq1, seq2 []uint64) []uint64 {
	set2 := make(map[uint64]bool)
	for _, v := range seq2 {
		set2[v] = true
	}

	unique := []uint64{}
	seen := make(map[uint64]bool)
	for _, v := range seq1 {
		if !set2[v] && !seen[v] {
			unique = append(unique, v)
			seen[v] = true
		}
	}

	return unique
}

// BatchCompare 批量比较多个序列与原始序列的相似度
func (p *PathComparator) BatchCompare(original []uint64, variants [][]uint64) []float64 {
	results := make([]float64, len(variants))
	for i, variant := range variants {
		results[i] = p.CompareJumpDests(original, variant)
	}
	return results
}

// FilterBySimilarity 过滤出相似度高于阈值的序列
func (p *PathComparator) FilterBySimilarity(original []uint64, variants [][]uint64, threshold float64) []int {
	indices := []int{}
	for i, variant := range variants {
		similarity := p.CompareJumpDests(original, variant)
		if similarity >= threshold {
			indices = append(indices, i)
		}
	}
	return indices
}

// 优化版本：使用空间优化的LCS算法
// 当序列很长时，可以使用这个版本节省内存

// longestCommonSubsequenceOptimized 空间优化版LCS
// 空间复杂度从O(m*n)降低到O(min(m,n))
func (p *PathComparator) longestCommonSubsequenceOptimized(seq1, seq2 []uint64) int {
	// 确保seq1是较短的序列，以优化空间使用
	if len(seq1) > len(seq2) {
		seq1, seq2 = seq2, seq1
	}

	m, n := len(seq1), len(seq2)

	// 只需要两行来计算DP
	prev := make([]int, m+1)
	curr := make([]int, m+1)

	for j := 1; j <= n; j++ {
		for i := 1; i <= m; i++ {
			if seq1[i-1] == seq2[j-1] {
				curr[i] = prev[i-1] + 1
			} else {
				curr[i] = max(curr[i-1], prev[i])
			}
		}
		// 交换prev和curr
		prev, curr = curr, prev
	}

	return prev[m]
}

// 额外的相似度算法（可选）

// jaccardSimilarity 计算Jaccard相似度
// Jaccard系数 = |A ∩ B| / |A ∪ B|
func (p *PathComparator) jaccardSimilarity(seq1, seq2 []uint64) float64 {
	if len(seq1) == 0 && len(seq2) == 0 {
		return 1.0
	}

	set1 := make(map[uint64]bool)
	set2 := make(map[uint64]bool)

	for _, v := range seq1 {
		set1[v] = true
	}
	for _, v := range seq2 {
		set2[v] = true
	}

	// 计算交集
	intersection := 0
	for v := range set1 {
		if set2[v] {
			intersection++
		}
	}

	// 计算并集
	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// editDistance 计算编辑距离（Levenshtein距离）
// 返回将seq1转换为seq2所需的最少操作数
func (p *PathComparator) editDistance(seq1, seq2 []uint64) int {
	m, n := len(seq1), len(seq2)

	// 创建DP表
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	// 初始化边界
	for i := 0; i <= m; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = j
	}

	// 填充DP表
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if seq1[i-1] == seq2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = 1 + min3(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
			}
		}
	}

	return dp[m][n]
}

// editDistanceSimilarity 基于编辑距离的相似度
// 相似度 = 1 - (编辑距离 / 最大可能距离)
func (p *PathComparator) editDistanceSimilarity(seq1, seq2 []uint64) float64 {
	if len(seq1) == 0 && len(seq2) == 0 {
		return 1.0
	}

	distance := p.editDistance(seq1, seq2)
	maxDistance := max(len(seq1), len(seq2))

	return 1.0 - float64(distance)/float64(maxDistance)
}

// cosineSimilarity 计算余弦相似度
// 将序列视为向量，计算向量间的余弦相似度
func (p *PathComparator) cosineSimilarity(seq1, seq2 []uint64) float64 {
	// 创建频率向量
	freq1 := make(map[uint64]int)
	freq2 := make(map[uint64]int)

	for _, v := range seq1 {
		freq1[v]++
	}
	for _, v := range seq2 {
		freq2[v]++
	}

	// 获取所有唯一元素
	allElements := make(map[uint64]bool)
	for v := range freq1 {
		allElements[v] = true
	}
	for v := range freq2 {
		allElements[v] = true
	}

	// 计算点积和范数
	var dotProduct, norm1, norm2 float64
	for v := range allElements {
		f1 := float64(freq1[v])
		f2 := float64(freq2[v])
		dotProduct += f1 * f2
		norm1 += f1 * f1
		norm2 += f2 * f2
	}

	if norm1 == 0 || norm2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(norm1) * math.Sqrt(norm2))
}

// CompareContractJumpDests 比较带合约地址的 JUMPDEST 序列
// 从受保护合约开始的索引截取后比较
// 🔧 修复：当LCS相似度较低时，自动切换到Jaccard相似度（适用于循环场景）
func (p *PathComparator) CompareContractJumpDests(
	original, variant []ContractJumpDest,
	startIndex int,
) float64 {
	// 从 startIndex 开始截取原始序列
	var origSlice []ContractJumpDest
	if startIndex >= 0 && startIndex < len(original) {
		origSlice = original[startIndex:]
	} else if startIndex < 0 {
		// 如果 startIndex 为 -1（未找到受保护合约），使用整个序列
		origSlice = original
	} else {
		// startIndex 超出范围
		origSlice = []ContractJumpDest{}
	}

	varSlice := variant // 变异后的从头开始就是受保护合约

	if len(origSlice) == 0 && len(varSlice) == 0 {
		return 1.0
	}
	if len(origSlice) == 0 || len(varSlice) == 0 {
		return 0.0
	}

	// LCS 算法，比较时同时匹配 contract + pc
	lcsLength := p.lcsContractJumpDests(origSlice, varSlice)

	// Dice 系数
	diceSimilarity := (2.0 * float64(lcsLength)) / float64(len(origSlice)+len(varSlice))

	// 🔧 循环场景优化：当Dice相似度较低时，尝试使用Jaccard相似度
	// Jaccard忽略顺序，只关注是否访问了相同的JUMPDEST
	// 这对于循环攻击很有用，因为单次调用的PC序列与多次循环的PC序列顺序不同
	if diceSimilarity < 0.3 {
		jaccardSim := p.jaccardContractJumpDests(origSlice, varSlice)
		if jaccardSim > diceSimilarity {
			return jaccardSim
		}
	}

	return diceSimilarity
}

// jaccardContractJumpDests 计算ContractJumpDest的Jaccard相似度（忽略顺序）
// Jaccard = |A ∩ B| / |A ∪ B|
func (p *PathComparator) jaccardContractJumpDests(seq1, seq2 []ContractJumpDest) float64 {
	if len(seq1) == 0 && len(seq2) == 0 {
		return 1.0
	}

	// 使用 contract:pc 作为key
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, jd := range seq1 {
		key := fmt.Sprintf("%s:%d", strings.ToLower(jd.Contract), jd.PC)
		set1[key] = true
	}
	for _, jd := range seq2 {
		key := fmt.Sprintf("%s:%d", strings.ToLower(jd.Contract), jd.PC)
		set2[key] = true
	}

	// 计算交集
	intersection := 0
	for k := range set1 {
		if set2[k] {
			intersection++
		}
	}

	// 计算并集
	union := len(set1) + len(set2) - intersection

	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union)
}

// lcsContractJumpDests LCS 算法 for ContractJumpDest
func (p *PathComparator) lcsContractJumpDests(seq1, seq2 []ContractJumpDest) int {
	m, n := len(seq1), len(seq2)

	// 创建 DP 表
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	// 填充 DP 表
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			// 同时匹配合约地址和 PC
			if strings.ToLower(seq1[i-1].Contract) == strings.ToLower(seq2[j-1].Contract) &&
				seq1[i-1].PC == seq2[j-1].PC {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	return dp[m][n]
}

// 辅助函数

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}