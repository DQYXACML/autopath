package pusher

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
	"time"

	"autopath/pkg/fuzzer"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDataConverter 测试数据转换器
func TestDataConverter(t *testing.T) {
	converter := NewDataConverter(10, true)

	t.Run("ConvertParameterType", func(t *testing.T) {
		tests := []struct {
			input    string
			expected uint8
		}{
			{"uint256", 0},
			{"int256", 1},
			{"address", 2},
			{"bool", 3},
			{"bytes32", 4},
			{"bytes", 5},
			{"string", 6},
			{"uint", 0},
			{"int", 1},
		}

		for _, test := range tests {
			result := converter.parseParamType(test.input)
			assert.Equal(t, test.expected, result, "Failed for type: %s", test.input)
		}
	})

	t.Run("ParseValueToBytes32", func(t *testing.T) {
		// 测试数值解析
		valueBytes := converter.parseValueToBytes32("1000", "uint256")
		expected := new(big.Int).SetInt64(1000)
		result := new(big.Int).SetBytes(valueBytes[:])
		assert.Equal(t, expected.String(), result.String())

		// 测试地址解析
		addr := "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"
		addrBytes := converter.parseValueToBytes32(addr, "address")
		expectedAddr := common.HexToAddress(addr)
		var resultAddr common.Address
		copy(resultAddr[:], addrBytes[12:])
		assert.Equal(t, expectedAddr, resultAddr)

		// 测试布尔值解析
		trueBytes := converter.parseValueToBytes32("true", "bool")
		assert.Equal(t, byte(1), trueBytes[31])

		falseBytes := converter.parseValueToBytes32("false", "bool")
		assert.Equal(t, byte(0), falseBytes[31])
	})

	t.Run("ConvertParameterSummary", func(t *testing.T) {
		// 测试范围参数
		rangeParam := fuzzer.ParameterSummary{
			ParamIndex:      0,
			ParamType:       "uint256",
			IsRange:         true,
			RangeMin:        "100",
			RangeMax:        "1000",
			OccurrenceCount: 10,
		}

		converted, err := converter.ConvertParameterSummary(rangeParam)
		require.NoError(t, err)
		assert.Equal(t, uint8(0), converted.ParamIndex)
		assert.Equal(t, uint8(0), converted.ParamType) // uint256
		assert.True(t, converted.IsRange)
		assert.Equal(t, uint64(10), converted.OccurrenceCount)

		// 测试离散值参数
		discreteParam := fuzzer.ParameterSummary{
			ParamIndex:      1,
			ParamType:       "address",
			SingleValues:    []string{"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"},
			OccurrenceCount: 5,
		}

		converted2, err := converter.ConvertParameterSummary(discreteParam)
		require.NoError(t, err)
		assert.Equal(t, uint8(1), converted2.ParamIndex)
		assert.Equal(t, uint8(2), converted2.ParamType) // address
		assert.False(t, converted2.IsRange)
		assert.Len(t, converted2.SingleValues, 1)
	})

	t.Run("RangeOptimization", func(t *testing.T) {
		// 测试范围优化
		values := [][32]byte{}
		for i := 100; i <= 110; i++ {
			var val [32]byte
			big.NewInt(int64(i)).FillBytes(val[:])
			values = append(values, val)
		}

		rangeOpt := converter.tryConvertToRange(values, "uint256")
		assert.NotNil(t, rangeOpt)

		minVal := new(big.Int).SetBytes(rangeOpt.Min[:])
		maxVal := new(big.Int).SetBytes(rangeOpt.Max[:])
		assert.Equal(t, int64(100), minVal.Int64())
		assert.Equal(t, int64(110), maxVal.Int64())
	})
}

// TestOraclePusher 测试Oracle推送器
func TestOraclePusher(t *testing.T) {
	t.Skip("Requires Ethereum node connection")

	config := &PusherConfig{
		RPCURL:          "http://localhost:8545",
		ModuleAddress:   "0x0000000000000000000000000000000000000001",
		PrivateKey:      "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
		ChainID:         1337,
		PushThreshold:   0.8,
		BatchSize:       5,
		RetryCount:      3,
		RetryDelay:      time.Second,
		MinInterval:     time.Hour,
		MaxRulesPerFunc: 20,
	}

	pusher, err := NewOraclePusher(config)
	require.NoError(t, err)
	assert.NotNil(t, pusher)

	t.Run("ProcessFuzzingReport", func(t *testing.T) {
		ctx := context.Background()

		report := &fuzzer.AttackParameterReport{
			ContractAddress: common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"),
			FunctionSig:     "0xa9059cbb",
			ValidParameters: []fuzzer.ParameterSummary{
				{
					ParamIndex:      0,
					ParamType:       "address",
					SingleValues:    []string{"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"},
					OccurrenceCount: 10,
				},
				{
					ParamIndex:      1,
					ParamType:       "uint256",
					IsRange:         true,
					RangeMin:        "1000000000000000000",
					RangeMax:        "10000000000000000000",
					OccurrenceCount: 20,
				},
			},
			MaxSimilarity:     0.95,
			TotalCombinations: 100,
			ValidCombinations: 30,
		}

		err := pusher.ProcessFuzzingReport(ctx,
			common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"),
			[4]byte{0xa9, 0x05, 0x9c, 0xbb},
			report,
		)
		assert.NoError(t, err)
	})

	t.Run("FlushPending", func(t *testing.T) {
		ctx := context.Background()

		// 添加多个报告到待处理队列
		for i := 0; i < 3; i++ {
			report := &fuzzer.AttackParameterReport{
				ContractAddress:   common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"),
				FunctionSig:       fmt.Sprintf("0xa9059cb%d", i),
				MaxSimilarity:     0.85,
				ValidCombinations: 10,
			}

			pusher.pendingReports = append(pusher.pendingReports, &PushRequest{
				Project:     common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7"),
				FunctionSig: [4]byte{0xa9, 0x05, 0x9c, byte(0xb0 + i)},
				Report:      report,
				Threshold:   0.8,
				Timestamp:   time.Now(),
			})
		}

		err := pusher.FlushPending(ctx)
		// 由于没有真实的链接，会失败，但应该处理了队列
		assert.Error(t, err) // 预期失败因为没有真实的以太坊节点
		assert.Len(t, pusher.pendingReports, 3) // 应该重新加入队列（重试）
	})

	t.Run("GetStats", func(t *testing.T) {
		stats := pusher.GetStats()
		assert.NotNil(t, stats)
		assert.Contains(t, stats, "pending_count")
		assert.Contains(t, stats, "last_push_times")
		assert.Contains(t, stats, "config")
	})
}

// TestIntegration 集成测试
func TestIntegration(t *testing.T) {
	t.Run("EndToEndFlow", func(t *testing.T) {
		// 创建模拟的fuzzing报告
		report := &fuzzer.AttackParameterReport{
			ContractAddress: common.HexToAddress("0x1234567890123456789012345678901234567890"),
			FunctionSig:     "0xabcdef12",
			Timestamp:       time.Now(),
			OriginalTxHash:  common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"),
			BlockNumber:     12345,
			ValidParameters: []fuzzer.ParameterSummary{
				{
					ParamIndex:   0,
					ParamType:    "uint256",
					IsRange:      true,
					RangeMin:     "1000",
					RangeMax:     "10000",
					OccurrenceCount: 50,
				},
				{
					ParamIndex:   1,
					ParamType:    "address",
					SingleValues: []string{
						"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb7",
						"0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
					},
					OccurrenceCount: 30,
				},
			},
			TotalCombinations: 200,
			ValidCombinations: 80,
			AverageSimilarity: 0.85,
			MaxSimilarity:     0.95,
			MinSimilarity:     0.75,
		}

		// 序列化为JSON
		data, err := json.MarshalIndent(report, "", "  ")
		require.NoError(t, err)

		// 打印结果
		fmt.Printf("Fuzzing Report JSON:\n%s\n", string(data))

		// 创建数据转换器
		converter := NewDataConverter(10, true)

		// 转换参数
		for _, param := range report.ValidParameters {
			converted, err := converter.ConvertParameterSummary(param)
			require.NoError(t, err)

			fmt.Printf("\nConverted Parameter %d:\n", param.ParamIndex)
			fmt.Printf("  Type: %d (from %s)\n", converted.ParamType, param.ParamType)
			fmt.Printf("  IsRange: %v\n", converted.IsRange)
			if converted.IsRange {
				minVal := new(big.Int).SetBytes(converted.RangeMin[:])
				maxVal := new(big.Int).SetBytes(converted.RangeMax[:])
				fmt.Printf("  Range: [%s, %s]\n", minVal.String(), maxVal.String())
			} else {
				fmt.Printf("  Values: %d items\n", len(converted.SingleValues))
			}
		}

		// 验证转换
		assert.Len(t, report.ValidParameters, 2)
	})
}

// BenchmarkDataConversion 性能测试
func BenchmarkDataConversion(b *testing.B) {
	converter := NewDataConverter(100, true)

	// 创建大量参数
	params := make([]fuzzer.ParameterSummary, 100)
	for i := range params {
		params[i] = fuzzer.ParameterSummary{
			ParamIndex:   i,
			ParamType:    "uint256",
			SingleValues: []string{"1000", "2000", "3000", "4000", "5000"},
			OccurrenceCount: 10,
		}
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		for _, param := range params {
			_, _ = converter.ConvertParameterSummary(param)
		}
	}
}

// TestGasEstimation 测试gas估算
func TestGasEstimation(t *testing.T) {
	converter := NewDataConverter(10, false)

	summaries := []*ChainParamSummary{
		{
			ParamIndex:   0,
			ParamType:    0,
			IsRange:      true,
			RangeMin:     [32]byte{},
			RangeMax:     [32]byte{},
		},
		{
			ParamIndex:   1,
			ParamType:    2,
			SingleValues: make([][32]byte, 10),
		},
	}

	gas := converter.EstimateGasCost(summaries)
	assert.Greater(t, gas, uint64(21000)) // 应该大于基础gas
	assert.Less(t, gas, uint64(1000000))  // 应该小于1M gas

	fmt.Printf("Estimated gas for %d summaries: %d\n", len(summaries), gas)
}