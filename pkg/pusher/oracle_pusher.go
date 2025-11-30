package pusher

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"autopath/pkg/fuzzer"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

// OraclePusher 负责将链下分析结果推送到链上ParamCheckModule
type OraclePusher struct {
	client         *ethclient.Client
	auth           *bind.TransactOpts
	moduleAddress  common.Address
	config         *PusherConfig
	lastPushTime   map[string]time.Time // project+funcSig -> lastPush
	mutex          sync.RWMutex
	pendingReports []*PushRequest
	moduleABI      abi.ABI
	bound          *bind.BoundContract
}

// PusherConfig Oracle推送配置
type PusherConfig struct {
	// 链接配置
	RPCURL        string `json:"rpc_url"`
	ModuleAddress string `json:"module_address"`
	PrivateKey    string `json:"private_key"`
	ChainID       int64  `json:"chain_id"`

	// 推送策略
	PushThreshold float64       `json:"push_threshold"`     // 相似度阈值
	BatchSize     int           `json:"batch_size"`         // 批量推送大小
	RetryCount    int           `json:"retry_count"`        // 重试次数
	RetryDelay    time.Duration `json:"retry_delay"`        // 重试延迟
	MinInterval   time.Duration `json:"min_interval_hours"` // 最小推送间隔

	// Gas配置
	GasLimit    uint64   `json:"gas_limit"`
	MaxGasPrice *big.Int `json:"max_gas_price"`

	// 安全配置
	EnableSignature bool `json:"enable_signature"`
	MaxRulesPerFunc int  `json:"max_rules_per_function"`
}

// PushRequest 推送请求
type PushRequest struct {
	Project     common.Address
	FunctionSig [4]byte
	Report      *fuzzer.AttackParameterReport
	Threshold   float64
	Timestamp   time.Time
	RetryCount  int
}

// ParamSummary 链上参数摘要结构（与合约对应）
// SingleValues 字段在链上会被解释为黑名单拦截值集合
type ParamSummary struct {
	ParamIndex      uint8
	ParamType       uint8 // 转换为枚举值
	SingleValues    [][32]byte
	IsRange         bool
	RangeMin        [32]byte
	RangeMax        [32]byte
	OccurrenceCount *big.Int
}

// ExpressionTerm 链上表达式项
type ExpressionTerm struct {
	Kind       uint8
	ParamIndex uint8
	Slot       [32]byte
	Coeff      *big.Int
}

// ExpressionRule 链上表达式规则
type ExpressionRule struct {
	RuleType  string
	Terms     []ExpressionTerm
	Threshold *big.Int
	Scale     *big.Int
}

// NewOraclePusher 创建新的Oracle推送器
func NewOraclePusher(config *PusherConfig) (*OraclePusher, error) {
	// 连接到以太坊节点
	client, err := ethclient.Dial(config.RPCURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to ethereum: %w", err)
	}

	// 解析私钥
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(config.PrivateKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// 创建交易授权
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(config.ChainID))
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %w", err)
	}

	// 设置gas配置
	if config.GasLimit > 0 {
		auth.GasLimit = config.GasLimit
	}
	if config.MaxGasPrice != nil {
		auth.GasPrice = config.MaxGasPrice
	}

	// 解析模块地址
	moduleAddr := common.HexToAddress(config.ModuleAddress)

	// 解析ABI
	moduleABI, err := abi.JSON(strings.NewReader(ParamCheckModuleABI))
	if err != nil {
		return nil, fmt.Errorf("failed to parse module ABI: %w", err)
	}

	// 绑定合约
	bound := bind.NewBoundContract(moduleAddr, moduleABI, client, client, client)

	return &OraclePusher{
		client:        client,
		auth:          auth,
		moduleAddress: moduleAddr,
		config:        config,
		lastPushTime:  make(map[string]time.Time),
		moduleABI:     moduleABI,
		bound:         bound,
	}, nil
}

// ProcessFuzzingReport 处理fuzzing报告并决定是否推送
func (p *OraclePusher) ProcessFuzzingReport(
	ctx context.Context,
	project common.Address,
	funcSig [4]byte,
	report *fuzzer.AttackParameterReport,
) error {
	// 新增: 检查是否经过不变量验证
	if report.HasInvariantCheck {
		// 如果启用了不变量检查,则只推送有违规的报告
		if report.ViolationCount == 0 {
			log.Printf("[OraclePusher] Report has invariant check but no violations, skipping push")
			return nil
		}
		log.Printf("[OraclePusher] Report passed invariant check with %d violations, proceeding", report.ViolationCount)
	} else {
		// 未启用不变量检查,输出警告但继续推送
		log.Printf("[OraclePusher] Warning: Report lacks invariant check, proceeding with caution")
	}

	// 检查相似度阈值
	if report.MaxSimilarity < p.config.PushThreshold {
		log.Printf("[OraclePusher] Similarity %.2f below threshold %.2f, skipping",
			report.MaxSimilarity, p.config.PushThreshold)
		return nil
	}

	// 检查推送频率限制
	key := fmt.Sprintf("%s-%x", project.Hex(), funcSig)
	p.mutex.RLock()
	lastPush, exists := p.lastPushTime[key]
	p.mutex.RUnlock()

	if exists && time.Since(lastPush) < p.config.MinInterval {
		log.Printf("[OraclePusher] Too frequent push for %s, last push: %v", key, lastPush)
		return nil
	}

	// 创建推送请求
	request := &PushRequest{
		Project:     project,
		FunctionSig: funcSig,
		Report:      report,
		Threshold:   p.config.PushThreshold,
		Timestamp:   time.Now(),
	}

	// 添加到待推送队列
	p.mutex.Lock()
	p.pendingReports = append(p.pendingReports, request)
	p.mutex.Unlock()

	// 先尝试推送表达式规则（链上存档）
	if len(report.ExpressionRules) > 0 {
		if err := p.pushExpressionRules(ctx, project, funcSig, report.ExpressionRules); err != nil {
			log.Printf("[OraclePusher] Push expression rules failed: %v", err)
		}
	}

	// 如果达到批量大小，执行推送
	if len(p.pendingReports) >= p.config.BatchSize {
		return p.FlushPending(ctx)
	}

	return nil
}

// FlushPending 推送所有待处理的报告
func (p *OraclePusher) FlushPending(ctx context.Context) error {
	p.mutex.Lock()
	requests := p.pendingReports
	p.pendingReports = nil
	p.mutex.Unlock()

	if len(requests) == 0 {
		return nil
	}

	log.Printf("[OraclePusher] Flushing %d pending reports", len(requests))

	// 按项目和函数分组
	grouped := p.groupRequests(requests)

	// 推送每个组
	var lastErr error
	for key, reqs := range grouped {
		if err := p.pushGroup(ctx, key, reqs); err != nil {
			log.Printf("[OraclePusher] Failed to push group %s: %v", key, err)
			lastErr = err
			// 失败的请求重新加入队列
			for _, req := range reqs {
				req.RetryCount++
				if req.RetryCount < p.config.RetryCount {
					p.mutex.Lock()
					p.pendingReports = append(p.pendingReports, req)
					p.mutex.Unlock()
				}
			}
		}
	}

	return lastErr
}

// groupRequests 按项目和函数分组请求
func (p *OraclePusher) groupRequests(requests []*PushRequest) map[string][]*PushRequest {
	grouped := make(map[string][]*PushRequest)
	for _, req := range requests {
		key := fmt.Sprintf("%s-%x", req.Project.Hex(), req.FunctionSig)
		grouped[key] = append(grouped[key], req)
	}
	return grouped
}

// pushGroup 推送一组相同项目和函数的报告
func (p *OraclePusher) pushGroup(ctx context.Context, key string, requests []*PushRequest) error {
	if len(requests) == 0 {
		return nil
	}

	// 使用最新的报告
	latest := requests[len(requests)-1]

	// 转换参数摘要为链上格式
	summaries, err := p.convertToChainFormat(latest.Report.ValidParameters)
	if err != nil {
		return fmt.Errorf("failed to convert parameters: %w", err)
	}

	// 限制规则数量
	if len(summaries) > p.config.MaxRulesPerFunc {
		summaries = summaries[:p.config.MaxRulesPerFunc]
	}

	// 发送交易（直接通过绑定合约调用）
	// 说明：GasPrice/GasLimit 若未指定，将由 bind 库自动建议与估算
	tx, err := p.bound.Transact(
		p.auth,
		"updateFromAutopatch",
		latest.Project,
		latest.FunctionSig,
		summaries,
		big.NewInt(int64(latest.Threshold*1000000)),
	)
	if err != nil {
		return fmt.Errorf("failed to send transaction: %w", err)
	}

	log.Printf("[OraclePusher] Pushed update for %s, tx: %s", key, tx.Hash().Hex())

	// 更新最后推送时间
	p.mutex.Lock()
	p.lastPushTime[key] = time.Now()
	p.mutex.Unlock()

	return nil
}

// convertToChainFormat 转换参数为链上格式
func (p *OraclePusher) convertToChainFormat(params []fuzzer.ParameterSummary) ([]ParamSummary, error) {
	summaries := make([]ParamSummary, 0, len(params))

	for _, param := range params {
		summary := ParamSummary{
			ParamIndex:      uint8(param.ParamIndex),
			ParamType:       p.convertParamType(param.ParamType),
			OccurrenceCount: big.NewInt(int64(param.OccurrenceCount)),
		}

		if param.IsRange {
			// 范围值
			summary.IsRange = true
			summary.RangeMin = p.stringToBytes32(param.RangeMin)
			summary.RangeMax = p.stringToBytes32(param.RangeMax)
		} else {
			// 离散值（链上作为黑名单处理）
			summary.IsRange = false
			for _, val := range param.SingleValues {
				summary.SingleValues = append(summary.SingleValues, p.stringToBytes32(val))
			}
		}

		summaries = append(summaries, summary)
	}

	return summaries, nil
}

// convertParamType 转换参数类型为枚举值
func (p *OraclePusher) convertParamType(paramType string) uint8 {
	// 根据Solidity中的ParamType枚举定义
	switch strings.ToLower(paramType) {
	case "uint256", "uint":
		return 0 // UINT256
	case "int256", "int":
		return 1 // INT256
	case "address":
		return 2 // ADDRESS
	case "bool":
		return 3 // BOOL
	case "bytes32":
		return 4 // BYTES32
	case "bytes":
		return 5 // BYTES
	case "string":
		return 6 // STRING
	default:
		return 0 // 默认为UINT256
	}
}

// stringToBytes32 转换字符串值为bytes32
func (p *OraclePusher) stringToBytes32(val string) [32]byte {
	var result [32]byte

	// 处理十六进制字符串
	if strings.HasPrefix(val, "0x") {
		val = strings.TrimPrefix(val, "0x")
		if len(val) > 64 {
			val = val[:64]
		}
		// 从右边填充，确保数值正确
		padded := fmt.Sprintf("%064s", val)
		fmt.Sscanf(padded, "%x", &result)
	} else {
		// 尝试作为十进制数处理
		if n, ok := new(big.Int).SetString(val, 10); ok {
			n.FillBytes(result[:])
		} else {
			// 作为字符串处理，左对齐
			copy(result[:], []byte(val))
		}
	}

	return result
}

// pushExpressionRules 推送表达式规则（ratio/linear）
func (p *OraclePusher) pushExpressionRules(
	ctx context.Context,
	project common.Address,
	funcSig [4]byte,
	exprs []fuzzer.ExpressionRule,
) error {
	chainRules := make([]ExpressionRule, 0, len(exprs))
	for _, expr := range exprs {
		cr := ExpressionRule{
			RuleType:  expr.Type,
			Threshold: parseBigIntHex(expr.Threshold),
			Scale:     parseBigIntHex(expr.Scale),
		}
		for _, t := range expr.Terms {
			term := ExpressionTerm{
				Coeff: parseBigIntHex(t.Coeff),
			}
			if strings.EqualFold(t.Kind, "param") {
				term.Kind = 0
				if t.ParamIndex > 255 {
					term.ParamIndex = 255
				} else {
					term.ParamIndex = uint8(t.ParamIndex)
				}
			} else {
				term.Kind = 1
				if len(t.Slot) > 2 {
					copy(term.Slot[:], common.FromHex(t.Slot))
				}
			}
			cr.Terms = append(cr.Terms, term)
		}
		chainRules = append(chainRules, cr)
	}
	if len(chainRules) == 0 {
		return nil
	}

	tx, err := p.bound.Transact(p.auth, "updateExpressionRules", project, funcSig, chainRules)
	if err != nil {
		return fmt.Errorf("failed to push expression rules: %w", err)
	}
	log.Printf("[OraclePusher] Pushed expression rules tx=%s", tx.Hash().Hex())
	return nil
}

func parseBigIntHex(hexStr string) *big.Int {
	if hexStr == "" {
		return big.NewInt(0)
	}
	hs := strings.ToLower(strings.TrimSpace(hexStr))
	sign := int64(1)
	if strings.HasPrefix(hs, "-0x") {
		sign = -1
		hs = strings.TrimPrefix(hs, "-0x")
	} else if strings.HasPrefix(hs, "0x") {
		hs = strings.TrimPrefix(hs, "0x")
	}
	bi := new(big.Int)
	if _, ok := bi.SetString(hs, 16); ok {
		if sign < 0 {
			bi.Neg(bi)
		}
		return bi
	}
	return big.NewInt(0)
}

// sendTransaction 已弃用：改为使用绑定合约的 Transact 发送
// 保留接口以兼容旧代码路径（不再被调用）
func (p *OraclePusher) sendTransaction(ctx context.Context, data []byte) (common.Hash, error) {
	return common.Hash{}, fmt.Errorf("sendTransaction deprecated: use bound.Transact instead")
}

// Start 启动定期推送任务
func (p *OraclePusher) Start(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// 推送剩余的报告
			p.FlushPending(context.Background())
			return
		case <-ticker.C:
			// 定期推送待处理的报告
			if err := p.FlushPending(ctx); err != nil {
				log.Printf("[OraclePusher] Failed to flush pending: %v", err)
			}
		}
	}
}

// GetStats 获取推送统计信息
func (p *OraclePusher) GetStats() map[string]interface{} {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	return map[string]interface{}{
		"pending_count":   len(p.pendingReports),
		"last_push_times": p.lastPushTime,
		"config":          p.config,
	}
}

// ParamCheckModuleABI 合约ABI（简化版，实际需要从合约生成）
const ParamCheckModuleABI = `[
	{
		"inputs": [
			{
				"name": "project",
				"type": "address"
			},
			{
				"name": "funcSig",
				"type": "bytes4"
			},
			{
				"components": [
					{"name": "paramIndex", "type": "uint8"},
					{"name": "paramType", "type": "uint8"},
					{"name": "singleValues", "type": "bytes32[]"},
					{"name": "isRange", "type": "bool"},
					{"name": "rangeMin", "type": "bytes32"},
					{"name": "rangeMax", "type": "bytes32"},
					{"name": "occurrenceCount", "type": "uint256"}
				],
				"name": "summaries",
				"type": "tuple[]"
			},
			{
				"name": "threshold",
				"type": "uint256"
			}
		],
		"name": "updateFromAutopatch",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{"name": "project", "type": "address"},
			{"name": "funcSig", "type": "bytes4"},
			{
				"components": [
					{"name": "ruleType", "type": "string"},
					{"components": [
						{"name": "kind", "type": "uint8"},
						{"name": "paramIndex", "type": "uint8"},
						{"name": "slot", "type": "bytes32"},
						{"name": "coeff", "type": "int256"}
					], "name": "terms", "type": "tuple[]"},
					{"name": "threshold", "type": "int256"},
					{"name": "scale", "type": "uint256"}
				],
				"name": "rules",
				"type": "tuple[]"
			}
		],
		"name": "updateExpressionRules",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`
