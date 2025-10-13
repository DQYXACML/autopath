package projects

// ProjectConfig 定义监控器加载的完整项目配置
type ProjectConfig struct {
	ProjectID        string                 `json:"project_id"`
	Name             string                 `json:"name"`
	ChainID          int                    `json:"chain_id"`
	Contracts        []string               `json:"contracts"`
	Invariants       []interface{}          `json:"invariants"`
	FuzzingConfig    *FuzzingConfigJSON     `json:"fuzzing_config"`
	AlertConfig      map[string]interface{} `json:"alert_config"`
	MonitoringConfig map[string]interface{} `json:"monitoring_config"`
}

// FuzzingConfigJSON 表示 fuzzer 相关的 JSON 配置
type FuzzingConfigJSON struct {
	Enabled              bool                `json:"enabled"`
	Threshold            float64             `json:"threshold"`
	MaxVariations        int                 `json:"max_variations"`
	Workers              int                 `json:"workers"`
	TimeoutSeconds       int                 `json:"timeout_seconds"`
	OutputPath           string              `json:"output_path"`
	AutoTrigger          bool                `json:"auto_trigger"`
	TriggerContractTypes []string            `json:"trigger_contract_types"`
	MinSimilarity        float64             `json:"min_similarity"`
	SaveHighSimilarity   bool                `json:"save_high_similarity"`
	PrintRealtime        bool                `json:"print_realtime"`
	InvariantCheck       *InvariantCheckJSON `json:"invariant_check"`
}

// InvariantCheckJSON 不变量检查配置
type InvariantCheckJSON struct {
	Enabled    bool   `json:"enabled"`
	ProjectID  string `json:"project_id"`
	ConfigPath string `json:"config_path"`
}
