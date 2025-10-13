package projects

import "autopath/pkg/monitor"

// ConvertFuzzingConfig 将 JSON 配置转为内部结构
func ConvertFuzzingConfig(jsonConfig *FuzzingConfigJSON) *monitor.FuzzingConfig {
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
	}
}
