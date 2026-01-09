package monitor

import (
	"encoding/json"
	"fmt"
	"strings"

	"autopath/pkg/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rpc"
)

// CallFrame 调用帧结构
type CallFrame struct {
	Type     string              `json:"type"`     // CALL, DELEGATECALL, STATICCALL, CREATE, CREATE2
	From     string              `json:"from"`     // 调用者地址
	To       string              `json:"to"`       // 目标地址
	Value    string              `json:"value"`    // 转账金额
	Gas      types.FlexibleUint64 `json:"gas"`      // Gas限制 (支持多种格式)
	GasUsed  types.FlexibleUint64 `json:"gasUsed"`  // 实际使用的Gas (支持多种格式)
	Input    string              `json:"input"`    // 输入数据
	Output   string              `json:"output"`   // 输出数据
	Error    string              `json:"error"`    // 错误信息
	Calls    []CallFrame         `json:"calls"`    // 子调用
}

// TransactionTracer 交易追踪器
type TransactionTracer struct {
	rpcClient *rpc.Client
}

// NewTransactionTracer 创建交易追踪器
func NewTransactionTracer(rpcClient *rpc.Client) *TransactionTracer {
	return &TransactionTracer{
		rpcClient: rpcClient,
	}
}

// TraceTransaction 追踪交易
func (t *TransactionTracer) TraceTransaction(txHash common.Hash) (*CallFrame, error) {
	var result CallFrame

	// 使用 debug_traceTransaction 与 callTracer
	err := t.rpcClient.Call(&result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": "callTracer",
		"tracerConfig": map[string]interface{}{
			"onlyTopCall": false, // 获取所有内部调用
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to trace transaction %s: %w", txHash.Hex(), err)
	}

	return &result, nil
}

// TraceTransactionWithCustomTracer 使用自定义追踪器追踪交易
func (t *TransactionTracer) TraceTransactionWithCustomTracer(txHash common.Hash, tracerCode string) (json.RawMessage, error) {
	var result json.RawMessage

	err := t.rpcClient.Call(&result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": tracerCode,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to trace transaction with custom tracer: %w", err)
	}

	return result, nil
}

// TraceBlock 追踪整个区块
func (t *TransactionTracer) TraceBlock(blockNumber uint64) ([]*CallFrame, error) {
	var results []json.RawMessage

	err := t.rpcClient.Call(&results, "debug_traceBlockByNumber", fmt.Sprintf("0x%x", blockNumber), map[string]interface{}{
		"tracer": "callTracer",
		"tracerConfig": map[string]interface{}{
			"onlyTopCall": false,
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to trace block %d: %w", blockNumber, err)
	}

	// 解析结果
	var traces []*CallFrame
	for _, result := range results {
		var trace CallFrame
		if err := json.Unmarshal(result, &trace); err != nil {
			continue
		}
		traces = append(traces, &trace)
	}

	return traces, nil
}

// FindContractCalls 查找特定合约的调用
func (t *TransactionTracer) FindContractCalls(frame *CallFrame, targetAddress string) []*CallFrame {
	var results []*CallFrame
	targetAddress = strings.ToLower(targetAddress)

	t.findContractCallsRecursive(frame, targetAddress, &results)

	return results
}

// findContractCallsRecursive 递归查找合约调用
func (t *TransactionTracer) findContractCallsRecursive(frame *CallFrame, targetAddress string, results *[]*CallFrame) {
	if strings.ToLower(frame.To) == targetAddress {
		*results = append(*results, frame)
	}

	for i := range frame.Calls {
		t.findContractCallsRecursive(&frame.Calls[i], targetAddress, results)
	}
}

// AnalyzeCallPath 分析调用路径
func (t *TransactionTracer) AnalyzeCallPath(frame *CallFrame) []CallPath {
	var paths []CallPath
	currentPath := []string{}
	t.analyzeCallPathRecursive(frame, currentPath, &paths)
	return paths
}

// CallPath 调用路径
type CallPath struct {
	Path  []string // 地址路径
	Depth int      // 调用深度
	Type  string   // 最终调用类型
}

// analyzeCallPathRecursive 递归分析调用路径
func (t *TransactionTracer) analyzeCallPathRecursive(frame *CallFrame, currentPath []string, paths *[]CallPath) {
	// 添加当前地址到路径
	newPath := append(currentPath, frame.To)

	// 如果没有子调用，这是一个完整路径
	if len(frame.Calls) == 0 {
		*paths = append(*paths, CallPath{
			Path:  newPath,
			Depth: len(newPath),
			Type:  frame.Type,
		})
		return
	}

	// 递归处理子调用
	for i := range frame.Calls {
		t.analyzeCallPathRecursive(&frame.Calls[i], newPath, paths)
	}
}

// GetStorageChanges 获取存储变化（需要使用特殊的tracer）
func (t *TransactionTracer) GetStorageChanges(txHash common.Hash) (map[common.Address]map[common.Hash]StorageChange, error) {
	// 使用预状态追踪器
	tracerCode := `{
		data: {},
		fault: function(log) {},
		step: function(log) {
			if(log.op.toString() == "SSTORE") {
				var addr = toHex(log.contract.getAddress());
				var key = toHex(log.stack.peek(0).toString(16));
				var val = toHex(log.stack.peek(1).toString(16));
				if(!this.data[addr]) this.data[addr] = {};
				this.data[addr][key] = val;
			}
		},
		result: function() { return this.data; }
	}`

	result, err := t.TraceTransactionWithCustomTracer(txHash, tracerCode)
	if err != nil {
		return nil, err
	}

	// 解析结果
	var storageChanges map[string]map[string]string
	if err := json.Unmarshal(result, &storageChanges); err != nil {
		return nil, err
	}

	// 转换格式
	changes := make(map[common.Address]map[common.Hash]StorageChange)
	for addr, slots := range storageChanges {
		address := common.HexToAddress(addr)
		changes[address] = make(map[common.Hash]StorageChange)
		for slot, value := range slots {
			changes[address][common.HexToHash(slot)] = StorageChange{
				Slot:  common.HexToHash(slot),
				Value: common.HexToHash(value),
			}
		}
	}

	return changes, nil
}

// StorageChange 存储变化
type StorageChange struct {
	Slot  common.Hash
	Value common.Hash
}

// ExtractFunctionSignature 从输入数据提取函数签名
func ExtractFunctionSignature(input string) string {
	if len(input) < 10 {
		return ""
	}
	return input[:10] // 前4字节（0x + 8个十六进制字符）
}

// CallStatistics 调用统计
type CallStatistics struct {
	TotalCalls       int
	SuccessfulCalls  int
	FailedCalls      int
	TotalGasUsed     uint64
	UniqueAddresses  map[string]bool
	FunctionSignatures map[string]int
}

// GetCallStatistics 获取调用统计
func (t *TransactionTracer) GetCallStatistics(frame *CallFrame) *CallStatistics {
	stats := &CallStatistics{
		UniqueAddresses:    make(map[string]bool),
		FunctionSignatures: make(map[string]int),
	}

	t.collectStatistics(frame, stats)

	return stats
}

// collectStatistics 递归收集统计信息
func (t *TransactionTracer) collectStatistics(frame *CallFrame, stats *CallStatistics) {
	stats.TotalCalls++

	if frame.Error == "" {
		stats.SuccessfulCalls++
	} else {
		stats.FailedCalls++
	}

	// 统计Gas使用 - 直接使用 FlexibleUint64 的 Value() 方法
	stats.TotalGasUsed += frame.GasUsed.Value()

	// 记录唯一地址
	if frame.To != "" {
		stats.UniqueAddresses[strings.ToLower(frame.To)] = true
	}

	// 统计函数签名
	if sig := ExtractFunctionSignature(frame.Input); sig != "" {
		stats.FunctionSignatures[sig]++
	}

	// 递归处理子调用
	for i := range frame.Calls {
		t.collectStatistics(&frame.Calls[i], stats)
	}
}

// parseHexUint64 解析十六进制字符串为uint64
func parseHexUint64(hex string) (uint64, error) {
	hex = strings.TrimPrefix(hex, "0x")
	var result uint64
	_, err := fmt.Sscanf(hex, "%x", &result)
	return result, err
}