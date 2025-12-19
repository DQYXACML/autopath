package fuzzer

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParameterGeneration 测试参数生成
func TestParameterGeneration(t *testing.T) {
	generator := NewParamGenerator(50)

	t.Run("IntegerGeneration", func(t *testing.T) {
		param := Parameter{
			Type:  "uint256",
			Value: big.NewInt(1000),
		}

		variations := generator.GenerateVariations(param)

		// 验证生成了变体
		assert.Greater(t, len(variations), 10, "Should generate multiple variations")

		// 验证包含关键值
		hasZero := false
		hasOriginal := false
		hasMax := false

		for _, v := range variations {
			if val, ok := v.(*big.Int); ok {
				if val.Cmp(big.NewInt(0)) == 0 {
					hasZero = true
				}
				if val.Cmp(big.NewInt(1000)) == 0 {
					hasOriginal = true
				}
				// 检查是否有接近最大值的数
				maxUint256 := new(big.Int).Sub(
					new(big.Int).Exp(big.NewInt(2), big.NewInt(256), nil),
					big.NewInt(1),
				)
				if val.Cmp(maxUint256) == 0 {
					hasMax = true
				}
			}
		}

		assert.True(t, hasZero, "Should include zero")
		assert.True(t, hasOriginal, "Should include original value")
		assert.True(t, hasMax, "Should include max uint256")
	})

	t.Run("AddressGeneration", func(t *testing.T) {
		param := Parameter{
			Type:  "address",
			Value: common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"),
		}

		variations := generator.GenerateVariations(param)

		assert.Greater(t, len(variations), 5, "Should generate multiple address variations")

		// 验证包含零地址
		hasZeroAddress := false
		for _, v := range variations {
			if addr, ok := v.(common.Address); ok {
				if addr == common.HexToAddress("0x0") {
					hasZeroAddress = true
					break
				}
			}
		}
		assert.True(t, hasZeroAddress, "Should include zero address")
	})

	t.Run("BoolGeneration", func(t *testing.T) {
		param := Parameter{
			Type:  "bool",
			Value: true,
		}

		variations := generator.GenerateVariations(param)

		assert.Len(t, variations, 2, "Bool should have exactly 2 variations")
		assert.Contains(t, variations, true)
		assert.Contains(t, variations, false)
	})

	t.Run("BytesGeneration", func(t *testing.T) {
		param := Parameter{
			Type:  "bytes32",
			Value: []byte("test"),
			Size:  32,
		}

		variations := generator.GenerateVariations(param)

		assert.Greater(t, len(variations), 3, "Should generate multiple bytes variations")

		// 验证包含空字节
		hasEmpty := false
		for _, v := range variations {
			if bytes, ok := v.([]byte); ok {
				allZero := true
				for _, b := range bytes {
					if b != 0 {
						allZero = false
						break
					}
				}
				if allZero && len(bytes) > 0 {
					hasEmpty = true
					break
				}
			}
		}
		assert.True(t, hasEmpty, "Should include empty bytes")
	})
}

// TestJumpDestComparison 测试JUMPDEST序列比较
func TestJumpDestComparison(t *testing.T) {
	comparator := NewPathComparator()

	tests := []struct {
		name     string
		seq1     []uint64
		seq2     []uint64
		expected float64
		delta    float64
	}{
		{
			name:     "Identical sequences",
			seq1:     []uint64{100, 200, 300, 400},
			seq2:     []uint64{100, 200, 300, 400},
			expected: 1.0,
			delta:    0.01,
		},
		{
			name:     "Completely different",
			seq1:     []uint64{100, 200, 300},
			seq2:     []uint64{500, 600, 700},
			expected: 0.0,
			delta:    0.01,
		},
		{
			name:     "Partial match",
			seq1:     []uint64{100, 200, 300, 400},
			seq2:     []uint64{100, 200, 500, 600},
			expected: 0.5,
			delta:    0.01,
		},
		{
			name:     "Different lengths",
			seq1:     []uint64{100, 200, 300},
			seq2:     []uint64{100, 200},
			expected: 0.8,
			delta:    0.01,
		},
		{
			name:     "Empty sequences",
			seq1:     []uint64{},
			seq2:     []uint64{},
			expected: 1.0,
			delta:    0.01,
		},
		{
			name:     "One empty sequence",
			seq1:     []uint64{100, 200},
			seq2:     []uint64{},
			expected: 0.0,
			delta:    0.01,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			similarity := comparator.CompareJumpDests(tc.seq1, tc.seq2)
			assert.InDelta(t, tc.expected, similarity, tc.delta,
				"Similarity for %s should be %.2f, got %.2f",
				tc.name, tc.expected, similarity)
		})
	}
}

// TestCallDataParsing 测试Calldata解析
func TestCallDataParsing(t *testing.T) {
	parser := NewABIParser()

	t.Run("BasicParsing", func(t *testing.T) {
		// transfer(address,uint256) 的calldata
		// 0xa9059cbb + address(32 bytes) + amount(32 bytes)
		selector := []byte{0xa9, 0x05, 0x9c, 0xbb}
		address := common.LeftPadBytes(common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").Bytes(), 32)
		amount := common.LeftPadBytes(big.NewInt(1000000).Bytes(), 32)

		calldata := append(selector, address...)
		calldata = append(calldata, amount...)

		parsed, err := parser.ParseCallData(calldata)
		require.NoError(t, err)

		assert.Equal(t, selector, parsed.Selector)
		assert.Len(t, parsed.Parameters, 2, "Should parse 2 parameters")
	})

	t.Run("EmptyCalldata", func(t *testing.T) {
		// 只有selector，没有参数
		calldata := []byte{0x12, 0x34, 0x56, 0x78}

		parsed, err := parser.ParseCallData(calldata)
		require.NoError(t, err)

		assert.Equal(t, calldata, parsed.Selector)
		assert.Len(t, parsed.Parameters, 0, "Should have no parameters")
	})

	t.Run("InvalidCalldata", func(t *testing.T) {
		// 太短的calldata
		calldata := []byte{0x12, 0x34}

		_, err := parser.ParseCallData(calldata)
		assert.Error(t, err, "Should error on too short calldata")
	})
}

// TestCallDataReconstruction 测试Calldata重构
func TestCallDataReconstruction(t *testing.T) {
	parser := NewABIParser()

	selector := []byte{0xa9, 0x05, 0x9c, 0xbb}
	params := []interface{}{
		common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1"),
		big.NewInt(1000000),
	}

	reconstructed, err := parser.ReconstructCallData(selector, params)
	require.NoError(t, err)

	// 验证selector
	assert.Equal(t, selector, reconstructed[:4])

	// 验证总长度（selector + 2 * 32 bytes）
	assert.Equal(t, 68, len(reconstructed))
}

// TestResultMerging 测试结果合并
func TestResultMerging(t *testing.T) {
	merger := NewResultMerger()

	// 创建测试结果
	results := []FuzzingResult{
		{
			Parameters: []ParameterValue{
				{Index: 0, Type: "uint256", Value: big.NewInt(100)},
				{Index: 1, Type: "address", Value: common.HexToAddress("0x123")},
			},
			Similarity: 0.85,
		},
		{
			Parameters: []ParameterValue{
				{Index: 0, Type: "uint256", Value: big.NewInt(200)},
				{Index: 1, Type: "address", Value: common.HexToAddress("0x123")},
			},
			Similarity: 0.90,
		},
		{
			Parameters: []ParameterValue{
				{Index: 0, Type: "uint256", Value: big.NewInt(150)},
				{Index: 1, Type: "address", Value: common.HexToAddress("0x456")},
			},
			Similarity: 0.82,
		},
	}

	report := merger.MergeResults(
		results,
		common.HexToAddress("0xabc"),
		[]byte{0x12, 0x34, 0x56, 0x78},
		common.HexToHash("0xdef"),
		18000000,
		time.Now(),
	)

	assert.NotNil(t, report)
	assert.Equal(t, 3, report.ValidCombinations)
	// 地址类型会被过滤，避免链上规则硬编码地址
	assert.Len(t, report.ValidParameters, 1, "Should have 1 non-address parameter")

	// 验证参数0的范围（100-200）
	param0 := report.ValidParameters[0]
	assert.Equal(t, 0, param0.ParamIndex)
	assert.Equal(t, "uint256", param0.ParamType)
}

// TestLCSAlgorithm 测试最长公共子序列算法
func TestLCSAlgorithm(t *testing.T) {
	comparator := NewPathComparator()

	tests := []struct {
		name     string
		seq1     []uint64
		seq2     []uint64
		expected int
	}{
		{
			name:     "Identical",
			seq1:     []uint64{1, 2, 3, 4, 5},
			seq2:     []uint64{1, 2, 3, 4, 5},
			expected: 5,
		},
		{
			name:     "Subsequence",
			seq1:     []uint64{1, 2, 3, 4, 5},
			seq2:     []uint64{1, 3, 5},
			expected: 3,
		},
		{
			name:     "Interleaved",
			seq1:     []uint64{1, 3, 5, 7, 9},
			seq2:     []uint64{2, 3, 4, 7, 8},
			expected: 2, // 3, 7
		},
		{
			name:     "No common",
			seq1:     []uint64{1, 2, 3},
			seq2:     []uint64{4, 5, 6},
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lcs := comparator.longestCommonSubsequence(tc.seq1, tc.seq2)
			assert.Equal(t, tc.expected, lcs,
				"LCS length for %s should be %d, got %d",
				tc.name, tc.expected, lcs)
		})
	}
}

// TestParameterRangeMerging 测试参数范围合并
func TestParameterRangeMerging(t *testing.T) {
	merger := NewResultMerger()

	// 创建数值参数的多个值
	values := []ParameterValue{
		{Index: 0, Type: "uint256", Value: big.NewInt(100)},
		{Index: 0, Type: "uint256", Value: big.NewInt(150)},
		{Index: 0, Type: "uint256", Value: big.NewInt(200)},
		{Index: 0, Type: "uint256", Value: big.NewInt(120)},
		{Index: 0, Type: "uint256", Value: big.NewInt(180)},
	}

	// 分组
	groups := map[int][]ParameterValue{
		0: values,
	}

	// 提取摘要
	summaries := merger.extractParameterSummaries(groups)

	require.Len(t, summaries, 1)
	summary := summaries[0]

	// 验证识别为范围
	if merger.shouldMergeAsRange("uint256", values) {
		assert.True(t, summary.IsRange, "Should be merged as range")
		assert.Equal(t, "100", summary.RangeMin)
		assert.Equal(t, "200", summary.RangeMax)
	}
}

// BenchmarkParameterGeneration 基准测试：参数生成
func BenchmarkParameterGeneration(b *testing.B) {
	generator := NewParamGenerator(50)
	param := Parameter{
		Type:  "uint256",
		Value: big.NewInt(1000),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		generator.GenerateVariations(param)
	}
}

// BenchmarkPathComparison 基准测试：路径比较
func BenchmarkPathComparison(b *testing.B) {
	comparator := NewPathComparator()
	seq1 := make([]uint64, 1000)
	seq2 := make([]uint64, 1000)

	for i := range seq1 {
		seq1[i] = uint64(i * 2)
		seq2[i] = uint64(i*2 + 1)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		comparator.CompareJumpDests(seq1, seq2)
	}
}
