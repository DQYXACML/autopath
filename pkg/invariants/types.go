package invariants

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// InvariantType 不变量类型
type InvariantType string

const (
	RatioInvariant     InvariantType = "ratio"     // 比率型不变量
	ThresholdInvariant InvariantType = "threshold" // 阈值型不变量
	DeltaInvariant     InvariantType = "delta"     // 变化率型不变量
	CustomInvariant    InvariantType = "custom"    // 自定义型不变量
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
	BlockNumber uint64
	BlockHash   common.Hash
	TxHash      common.Hash
	Timestamp   uint64
	States      map[common.Address]*ContractState // 合约状态映射
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
	ProjectID   string       `json:"project_id"`
	Name        string       `json:"name"`
	ChainID     uint64       `json:"chain_id"`
	Contracts   []string     `json:"contracts"`  // 被保护合约地址
	Invariants  []Invariant  `json:"invariants"` // 不变量列表
	AlertConfig *AlertConfig `json:"alert_config"`
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
