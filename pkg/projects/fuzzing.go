package projects

import (
	"autopath/pkg/fuzzer"
	"autopath/pkg/monitor"
	"math/big"
	"strconv"
)

// ConvertFuzzingConfig 将 JSON 配置转为内部结构
// projectID 作为默认项目标识，用于定位 attack_state 等外部资料
func ConvertFuzzingConfig(jsonConfig *FuzzingConfigJSON, projectID string) *monitor.FuzzingConfig {
	if jsonConfig == nil {
		return nil
	}

	var invariantCfg *monitor.InvariantCheckConfig
	if jsonConfig.InvariantCheck != nil {
		invariantCfg = &monitor.InvariantCheckConfig{
			Enabled:    jsonConfig.InvariantCheck.Enabled,
			ProjectID:  jsonConfig.InvariantCheck.ProjectID,
			ConfigPath: jsonConfig.InvariantCheck.ConfigPath,
		}
	}

	// 🆕 转换SeedConfig
	var seedCfg *fuzzer.SeedConfig
	if jsonConfig.SeedConfig != nil {
		seedCfg = convertSeedConfig(jsonConfig.SeedConfig)
	}

	projectIdentifier := projectID
	if projectIdentifier == "" && jsonConfig.ProjectID != "" {
		projectIdentifier = jsonConfig.ProjectID
	}
	if projectIdentifier == "" && jsonConfig.InvariantCheck != nil {
		projectIdentifier = jsonConfig.InvariantCheck.ProjectID
	}

	return &monitor.FuzzingConfig{
		Enabled:              jsonConfig.Enabled,
		Threshold:            jsonConfig.Threshold,
		MaxVariations:        jsonConfig.MaxVariations,
		Workers:              jsonConfig.Workers,
		TimeoutSeconds:       jsonConfig.TimeoutSeconds,
		OutputPath:           jsonConfig.OutputPath,
		AutoTrigger:          jsonConfig.AutoTrigger,
		TriggerContractTypes: jsonConfig.TriggerContractTypes,
		MinSimilarity:        jsonConfig.MinSimilarity,
		SaveHighSimilarity:   jsonConfig.SaveHighSimilarity,
		PrintRealtime:        jsonConfig.PrintRealtime,
		InvariantCheck:       invariantCfg,

		// 🆕 Unlimited fuzzing配置
		UnlimitedMode:     jsonConfig.UnlimitedMode,
		TargetSimilarity:  jsonConfig.TargetSimilarity,
		MaxHighSimResults: jsonConfig.MaxHighSimResults,

		// 🆕 Seed配置
		SeedConfig: seedCfg,

		// Entry Call 限制
		EntryCallProtectedOnly: jsonConfig.EntryCallProtectedOnly,

		// 🆕 本地执行模式
		LocalExecution: jsonConfig.LocalExecution,

		// 项目标识
		ProjectID: projectIdentifier,
	}
}

// convertSeedConfig 将JSON的SeedConfig转换为fuzzer.SeedConfig
func convertSeedConfig(jsonSeedCfg *SeedConfigJSON) *fuzzer.SeedConfig {
	if jsonSeedCfg == nil {
		return nil
	}

	cfg := &fuzzer.SeedConfig{
		Enabled: jsonSeedCfg.Enabled,
	}

	// 转换AttackSeeds（从map[string][]interface{}转为map[int][]interface{}）
	if jsonSeedCfg.AttackSeeds != nil {
		cfg.AttackSeeds = make(map[int][]interface{})
		for keyStr, values := range jsonSeedCfg.AttackSeeds {
			if idx, err := strconv.Atoi(keyStr); err == nil {
				// 转换string值为*big.Int（如果是数字字符串）
				var convertedValues []interface{}
				for _, val := range values {
					if strVal, ok := val.(string); ok {
						if bigVal, ok := new(big.Int).SetString(strVal, 10); ok {
							convertedValues = append(convertedValues, bigVal)
							continue
						}
					}
					convertedValues = append(convertedValues, val)
				}
				cfg.AttackSeeds[idx] = convertedValues
			}
		}
	}

	// 转换ConstraintRanges
	if jsonSeedCfg.ConstraintRanges != nil {
		cfg.ConstraintRanges = make(map[string]map[string]*fuzzer.ConstraintRange)
		for funcName, paramRanges := range jsonSeedCfg.ConstraintRanges {
			cfg.ConstraintRanges[funcName] = make(map[string]*fuzzer.ConstraintRange)
			for paramIdx, constraintRange := range paramRanges {
				cfg.ConstraintRanges[funcName][paramIdx] = &fuzzer.ConstraintRange{
					Type:             constraintRange.Type,
					SafeThreshold:    constraintRange.SafeThreshold,
					DangerThreshold:  constraintRange.DangerThreshold,
					AttackValues:     constraintRange.AttackValues,
					MutationStrategy: constraintRange.MutationStrategy,
					Confidence:       constraintRange.Confidence,
					ValueExpr:        constraintRange.ValueExpr,
					StateSlot:        constraintRange.StateSlot,
				}
				// 转换Range字段
				if constraintRange.Range != nil {
					cfg.ConstraintRanges[funcName][paramIdx].Range = &struct {
						Min string `yaml:"min" json:"min"`
						Max string `yaml:"max" json:"max"`
					}{
						Min: constraintRange.Range.Min,
						Max: constraintRange.Range.Max,
					}
				}
			}
		}
	}

	// 转换AdaptiveConfig
	if jsonSeedCfg.AdaptiveConfig != nil {
		cfg.AdaptiveConfig = &fuzzer.AdaptiveRangeConfig{
			Enabled:       jsonSeedCfg.AdaptiveConfig.Enabled,
			MaxIterations: jsonSeedCfg.AdaptiveConfig.MaxIterations,
			UnlimitedMode: jsonSeedCfg.AdaptiveConfig.UnlimitedMode,
		}
	}

	// 转换RangeConfig
	if jsonSeedCfg.RangeConfig != nil {
		cfg.RangeConfig = fuzzer.SeedRangeConfig{
			NumericRangePercent:  jsonSeedCfg.RangeConfig.NumericRangePercent,
			AddressMutationTypes: jsonSeedCfg.RangeConfig.AddressMutationTypes,
			BoundaryExploration:  jsonSeedCfg.RangeConfig.BoundaryExploration,
		}
	}

	// 转换Weights
	if jsonSeedCfg.Weights != nil {
		cfg.Weights = fuzzer.SeedWeightConfig{
			SeedBased: jsonSeedCfg.Weights.SeedBased,
			Random:    jsonSeedCfg.Weights.Random,
			Boundary:  jsonSeedCfg.Weights.Boundary,
		}
	}

	// 转换RangeMutationConfig
	if jsonSeedCfg.RangeMutationConfig != nil {
		cfg.RangeMutationConfig = &fuzzer.RangeMutationConfig{
			FocusPercentiles:       jsonSeedCfg.RangeMutationConfig.FocusPercentiles,
			BoundaryExploration:    jsonSeedCfg.RangeMutationConfig.BoundaryExploration,
			StepCount:              jsonSeedCfg.RangeMutationConfig.StepCount,
			RandomWithinRangeRatio: jsonSeedCfg.RangeMutationConfig.RandomWithinRangeRatio,
		}
	}

	return cfg
}
