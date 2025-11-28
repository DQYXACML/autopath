package invariants

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// InvariantType 不变量类型
type InvariantType string

const (
	RatioInvariant                 InvariantType = "ratio"                   // 比率型不变量
	ThresholdInvariant             InvariantType = "threshold"               // 阈值型不变量
	DeltaInvariant                 InvariantType = "delta"                   // 变化率型不变量
	CustomInvariant                InvariantType = "custom"                  // 自定义型不变量
	FlashChangePreventionInvariant InvariantType = "flash_change_prevention" // 闪电变化预防型不变量
)

// Invariant 不变量定义
type Invariant struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Type        InvariantType          `json:"type"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Contracts   []string               `json:"contracts"` // 相关合约地址
	Evaluator   EvaluatorFunc          `json:"-"`         // 评估函数
}

// EvaluatorFunc 不变量评估函数类型
type EvaluatorFunc func(state *ChainState) (bool, *ViolationDetail)

// ChainState 链状态快照
type ChainState struct {
	BlockNumber    uint64
	BlockHash      common.Hash
	TxHash         common.Hash
	Timestamp      uint64
	States         map[common.Address]*ContractState // 合约交易后状态映射
	PreviousStates map[common.Address]*ContractState // 合约交易前状态映射（可选）
}

// ContractState 合约状态
type ContractState struct {
	Address common.Address
	Balance *big.Int
	Storage map[common.Hash]common.Hash
	Code    []byte
}

// ProjectConfig 项目配置
type ProjectConfig struct {
	ProjectID     string         `json:"project_id"`
	Name          string         `json:"name"`
	ChainID       uint64         `json:"chain_id"`
	Contracts     []string       `json:"contracts"`  // 被保护合约地址
	Invariants    []Invariant    `json:"invariants"` // 不变量列表
	AlertConfig   *AlertConfig   `json:"alert_config"`
	FuzzingConfig *FuzzingConfig `json:"fuzzing_config"` // Fuzzing配置
}

// FuzzingConfig Fuzzing配置
type FuzzingConfig struct {
	Enabled                bool             `json:"enabled"`
	TargetFunctions        []TargetFunction `json:"target_functions"` // 目标函数列表
	Threshold              float64          `json:"threshold"`
	MaxVariations          int              `json:"max_variations"`
	Workers                int              `json:"workers"`
	TimeoutSeconds         int              `json:"timeout_seconds"`
	AutoTrigger            bool             `json:"auto_trigger"`
	MinSimilarity          float64          `json:"min_similarity"`
	PrintRealtime          bool             `json:"print_realtime"`
	OutputPath             string           `json:"output_path"`
	EntryCallProtectedOnly bool             `json:"entry_call_protected_only"`
}

// TargetFunction 目标函数定义
type TargetFunction struct {
	Contract  string `json:"contract"`  // 合约地址
	Function  string `json:"function"`  // 函数名
	Signature string `json:"signature"` // 函数签名
}

// AlertConfig 告警配置
type AlertConfig struct {
	Enabled         bool     `json:"enabled"`
	WebhookURL      string   `json:"webhook_url"`
	EmailRecipients []string `json:"email_recipients"`
	Severity        string   `json:"severity"` // low, medium, high, critical
}

// ViolationResult 违反结果
type ViolationResult struct {
	InvariantID   string           `json:"invariant_id"`
	InvariantName string           `json:"invariant_name"`
	ProjectID     string           `json:"project_id"`
	BlockNumber   uint64           `json:"block_number"`
	Transaction   common.Hash      `json:"transaction"`
	Timestamp     uint64           `json:"timestamp"`
	Details       *ViolationDetail `json:"details"`
}

// ViolationDetail 违反详情
type ViolationDetail struct {
	Message       string                 `json:"message"`
	ActualValue   interface{}            `json:"actual_value"`
	ExpectedValue interface{}            `json:"expected_value"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// LodestarInvariantParams Lodestar特定不变量参数
type LodestarInvariantParams struct {
	MaxRatio         float64 `json:"max_ratio"`
	DepositorAddress string  `json:"depositor_address"`
	SGLPAddress      string  `json:"sglp_address"`
	PlvGLPAddress    string  `json:"plvglp_address"`
	OracleAddress    string  `json:"oracle_address"`
}

// ParibusInvariantParams Paribus特定不变量参数
type ParibusInvariantParams struct {
	MaxUtilization     float64 `json:"max_utilization"`
	MarketAddress      string  `json:"market_address"`
	ComptrollerAddress string  `json:"comptroller_address"`
}

// SlotConfig 存储槽配置
type SlotConfig struct {
	Index     string  `json:"index"`     // 存储槽索引（十进制字符串）
	Severity  string  `json:"severity"`  // 严重性级别
	Threshold float64 `json:"threshold"` // 变化阈值（倍数）
}

// FlashChangePreventionParams 闪电变化预防型不变量参数
type FlashChangePreventionParams struct {
	Threshold float64               `json:"threshold"` // 全局默认阈值
	Contracts []string              `json:"contracts"` // 要监控的合约地址
	Slots     map[string]SlotConfig `json:"slots"`     // 存储槽配置 slot_name -> config
	Formula   string                `json:"formula"`   // 公式描述（仅用于文档）
}
