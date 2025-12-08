package integration

import (
	"context"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"autopath/pkg/fuzzer"
	"autopath/pkg/invariants"
	"autopath/pkg/monitor"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
)

func TestInvariantViolationTriggersFuzzing(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	contractAddr := common.HexToAddress("0x00000000000000000000000000000000000000a0")
	slotKey := common.HexToHash("0x01")

	cfg := invariants.ProjectConfig{
		ProjectID: "demo",
		Name:      "Demo",
		ChainID:   1,
		Contracts: []string{contractAddr.Hex()},
		Invariants: []invariants.Invariant{
			{
				ID:   "demo-break",
				Name: "Slot must be non-zero",
				Type: invariants.CustomInvariant,
			},
		},
	}

	configBytes, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}

	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, configBytes, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	registry := invariants.NewRegistry()
	if err := registry.LoadProjectConfig(configPath); err != nil {
		t.Fatalf("load config: %v", err)
	}

	registry.RegisterEvaluator("demo-break", func(state *invariants.ChainState) (bool, *invariants.ViolationDetail) {
		contractState := state.States[contractAddr]
		if contractState == nil {
			return true, nil
		}

		if val, ok := contractState.Storage[slotKey]; !ok || val == (common.Hash{}) {
			return false, &invariants.ViolationDetail{
				Message:       "protected slot is zero",
				ActualValue:   "0x0",
				ExpectedValue: "non-zero",
			}
		}
		return true, nil
	})

	evaluator := invariants.NewEvaluator(registry)

	chainState := &invariants.ChainState{
		BlockNumber: 88,
		BlockHash:   common.HexToHash("0xabc"),
		TxHash:      common.HexToHash("0xdef"),
		Timestamp:   123456,
		States: map[common.Address]*invariants.ContractState{
			contractAddr: {
				Address: contractAddr,
				Balance: big.NewInt(0),
				Storage: map[common.Hash]common.Hash{
					slotKey: {},
				},
			},
		},
	}

	violations := evaluator.EvaluateTransaction([]common.Address{contractAddr}, chainState)
	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}

	if violations[0].Details == nil || violations[0].Details.Message != "protected slot is zero" {
		t.Fatalf("unexpected violation detail: %+v", violations[0].Details)
	}

	fakeDriver := &stubFuzzDriver{
		report: &fuzzer.AttackParameterReport{
			ContractAddress:   contractAddr,
			FunctionSig:       "0x12345678",
			ValidCombinations: 1,
			TotalCombinations: 1,
			AverageSimilarity: 0.9,
			MaxSimilarity:     0.95,
			MinSimilarity:     0.9,
			ValidParameters: []fuzzer.ParameterSummary{
				{ParamIndex: 0, ParamType: "uint256", SingleValues: []string{"42"}, OccurrenceCount: 1},
			},
			HighSimilarityResults: []fuzzer.PublicResult{
				{Similarity: 0.95, Success: true},
			},
		},
		stats: &fuzzer.FuzzerStats{
			TestedCombinations: 1,
			ValidCombinations:  1,
		},
	}

	fuzzDir := filepath.Join(tmpDir, "fuzz")
	if err := os.MkdirAll(fuzzDir, 0o755); err != nil {
		t.Fatalf("mkdir fuzz dir: %v", err)
	}

	fuzzConfig := &monitor.FuzzingConfig{
		Enabled:            true,
		Threshold:          0.8,
		MaxVariations:      1,
		Workers:            1,
		TimeoutSeconds:     1,
		OutputPath:         fuzzDir,
		AutoTrigger:        false,
		MinSimilarity:      0.7,
		SaveHighSimilarity: false,
		PrintRealtime:      false,
	}

	integration := monitor.NewFuzzingIntegrationWithDriver(fakeDriver, fuzzConfig)

	tx := types.NewTransaction(0, contractAddr, big.NewInt(0), 21_000, big.NewInt(1), []byte{0x12, 0x34, 0x56, 0x78})

	ctx := context.Background()
	results, reports, err := integration.ProcessTransaction(ctx, tx, chainState.BlockNumber, contractAddr, tx.Hash())
	if err != nil {
		t.Fatalf("process transaction: %v", err)
	}

	if fakeDriver.calls != 1 {
		t.Fatalf("expected fuzz driver to be called once, got %d", fakeDriver.calls)
	}

	if len(results) != 1 || results[0] == nil || !results[0].Success || results[0].ValidCombinations != 1 {
		t.Fatalf("unexpected fuzzing result: %+v", results)
	}

	if len(reports) != 1 || reports[0] == nil || reports[0].ValidCombinations != 1 || reports[0].TotalCombinations != fakeDriver.stats.TestedCombinations {
		t.Fatalf("unexpected report: %+v", reports)
	}

	cached, cachedReports, err := integration.ProcessTransaction(ctx, tx, chainState.BlockNumber, contractAddr, tx.Hash())
	if err != nil {
		t.Fatalf("process transaction (cached): %v", err)
	}
	if fakeDriver.calls != 1 {
		t.Fatalf("expected cached path to avoid driver, calls=%d", fakeDriver.calls)
	}
	if len(cached) != 1 || cached[0] == nil || !cached[0].Success {
		t.Fatalf("cached result mismatch: %+v", cached)
	}
	if len(cachedReports) != 1 || cachedReports[0] == nil {
		t.Fatalf("cached reports mismatch: %+v", cachedReports)
	}
}

type stubFuzzDriver struct {
	report *fuzzer.AttackParameterReport
	stats  *fuzzer.FuzzerStats
	calls  int
}

func (s *stubFuzzDriver) FuzzTransaction(ctx context.Context, txHash common.Hash, contractAddr common.Address, blockNumber uint64, tx *types.Transaction) ([]*fuzzer.AttackParameterReport, error) {
	s.calls++
	return []*fuzzer.AttackParameterReport{s.report}, nil
}

func (s *stubFuzzDriver) GetStats() *fuzzer.FuzzerStats {
	return s.stats
}
