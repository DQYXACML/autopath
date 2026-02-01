package simulator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"

	apptypes "autopath/pkg/types"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// EVMSimulator EVM模拟器（简化版本）
type EVMSimulator struct {
	client    *ethclient.Client
	rpcClient *rpc.Client
	rpcURL    string
}

// NewEVMSimulator 创建EVM模拟器
func NewEVMSimulator(rpcURL string) (*EVMSimulator, error) {
	rpcClient, err := rpc.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	client := ethclient.NewClient(rpcClient)

	return &EVMSimulator{
		client:    client,
		rpcClient: rpcClient,
		rpcURL:    rpcURL,
	}, nil
}

// NewEVMSimulatorWithClients 使用现有的RPC客户端创建EVM模拟器
// 这个方法允许复用现有的连接，避免创建多个独立的RPC连接
func NewEVMSimulatorWithClients(rpcClient *rpc.Client, client *ethclient.Client) *EVMSimulator {
	fmt.Printf("[Simulator]  使用共享的RPC客户端创建模拟器（避免创建新连接）\n")
	return &EVMSimulator{
		client:    client,
		rpcClient: rpcClient,
		rpcURL:    "",
	}
}

func (s *EVMSimulator) SetRPCURL(url string) {
	s.rpcURL = url
}

// buildReplayTracerCode 生成重放交易的 JS tracer 代码
func buildReplayTracerCode(protectedAddr string, recordAll bool) string {
	return fmt.Sprintf(`{
		data: {
			jumpDests: [],
			contractJumpDests: [],
			callTargets: [],
			callEdges: [],
			protectedCallTargets: [],
			protectedContract: "%s",
			recordingStarted: false,
			recordAll: %t,
			protectedStartIndex: -1,
			protectedEndIndex: -1,
			// executionPath: [],  // 注释掉：记录15万+步骤会导致内存/性能问题
			stateChanges: {},
			logs: [],
			gasUsed: 0,
			success: true,
			returnData: "",
			debugInfo: {
				totalSteps: 0,
				protectedSteps: 0,
				jumpDestCount: 0,
				firstProtectedContract: "",
				recordingTrigger: ""
			}
		},
		formatHex: function(value) {
			var hex;
			if (typeof value === "bigint") {
				hex = "0x" + value.toString(16);
			} else {
				hex = toHex(value);
			}
			if (hex === "0x") {
				return "0x0";
			}
			var body = hex.slice(2);
			if (body.length === 0) {
				return "0x0";
			}
			if (body.length %% 2 === 1) {
				body = "0" + body;
			}
			return "0x" + body.toLowerCase();
		},
		formatAddress: function(value) {
			var body = this.formatHex(value).slice(2);
			while (body.length < 40) {
				body = "0" + body;
			}
			if (body.length > 40) {
				body = body.slice(body.length - 40);
			}
			return "0x" + body.toLowerCase();
		},
		formatWord: function(value) {
			var body = this.formatHex(value).slice(2);
			while (body.length < 64) {
				body = "0" + body;
			}
			if (body.length > 64) {
				body = body.slice(body.length - 64);
			}
			return "0x" + body;
		},
		fault: function(log, db) {
			this.data.success = false;
			this.data.error = log.getError();
		},
			step: function(log, db) {
				var currentContract = toHex(log.contract.getAddress());
				var currentLower = currentContract.toLowerCase();
				var opName = log.op.toString();

				this.data.debugInfo.totalSteps++;

				if (opName === "CALL" || opName === "DELEGATECALL" || opName === "STATICCALL" || opName === "CALLCODE") {
					var targetAddr = this.formatAddress(log.stack.peek(1));
					this.data.callTargets.push(targetAddr);
					this.data.callEdges.push({
						caller: currentLower,
						target: targetAddr,
						op: opName,
						depth: log.getDepth()
					});
					if (this.data.protectedContract !== "" && currentLower === this.data.protectedContract) {
						this.data.protectedCallTargets.push(targetAddr);
					}
				}

				if (this.data.recordAll && this.data.protectedStartIndex === -1) {
					this.data.protectedStartIndex = 0;
				}

			if (!this.data.recordAll && this.data.protectedContract !== "" && currentLower === this.data.protectedContract) {
				if (!this.data.recordingStarted) {
					this.data.recordingStarted = true;
					this.data.debugInfo.recordingTrigger = "matched_protected_contract";
					this.data.debugInfo.firstProtectedContract = currentContract;
					if (this.data.protectedStartIndex === -1) {
						this.data.protectedStartIndex = this.data.contractJumpDests.length;
					}
				}
			}

			var shouldRecord = this.data.recordAll || this.data.recordingStarted;
			if (!shouldRecord) {
				return;
			}

			this.data.debugInfo.protectedSteps++;

			if (opName === "JUMPDEST") {
				this.data.debugInfo.jumpDestCount++;
				this.data.jumpDests.push(log.getPC());
				this.data.contractJumpDests.push({
					contract: currentContract,
					pc: log.getPC()
				});
			}

			// 记录状态变化
			if (opName === "SSTORE") {
				var addrKey = currentLower;
				if (!this.data.stateChanges[addrKey]) {
					var balance = this.formatHex(db.getBalance(log.contract.getAddress()));
					this.data.stateChanges[addrKey] = {
						address: currentContract,
						balanceBefore: balance,
						balanceAfter: balance,
						storageChanges: {}
					};
				}
				var state = this.data.stateChanges[addrKey];
				var slotKey = this.formatWord(log.stack.peek(0));
				var newValue = this.formatWord(log.stack.peek(1));
				var previousValue = db.getState(log.contract.getAddress(), log.stack.peek(0));
				var formattedPrev = previousValue ? this.formatWord(previousValue) : "0x0";
				state.storageChanges[slotKey] = {
					before: formattedPrev,
					after: newValue
				};
				state.balanceAfter = this.formatHex(db.getBalance(log.contract.getAddress()));
			}

			if (opName === "SSTORE") {
				var addrKey = currentLower;
				if (!this.data.stateChanges[addrKey]) {
					var balance = this.formatHex(db.getBalance(log.contract.getAddress()));
					this.data.stateChanges[addrKey] = {
						address: currentContract,
						balanceBefore: balance,
						balanceAfter: balance,
						storageChanges: {}
					};
				}
				var state = this.data.stateChanges[addrKey];
				var slotKey = this.formatWord(log.stack.peek(0));
				var newValue = this.formatWord(log.stack.peek(1));
				var previousValue = db.getState(log.contract.getAddress(), log.stack.peek(0));
				var formattedPrev = previousValue ? this.formatWord(previousValue) : "0x0";
				state.storageChanges[slotKey] = {
					before: formattedPrev,
					after: newValue
				};
				state.balanceAfter = this.formatHex(db.getBalance(log.contract.getAddress()));
			}

			},
		result: function(ctx, db) {
			this.data.gasUsed = ctx.gasUsed;
			if (ctx.type === "REVERT") {
				this.data.success = false;
			}
			this.data.returnData = toHex(ctx.output);

			if (this.data.recordingStarted && this.data.protectedEndIndex === -1) {
				this.data.protectedEndIndex = this.data.contractJumpDests.length;
			}

			if (this.data.protectedEndIndex === -1) {
				this.data.protectedEndIndex = this.data.contractJumpDests.length;
			}
			if (this.data.recordAll && this.data.protectedStartIndex === -1) {
				this.data.protectedStartIndex = 0;
			}

			this.data.logs = [];
			var logs = ctx.logs || [];
			for (var i = 0; i < logs.length; i++) {
				var entry = logs[i];
				var topics = [];
				if (entry.topics) {
					for (var j = 0; j < entry.topics.length; j++) {
						var topicValue = entry.topics[j];
						if (typeof topicValue === "string") {
							topics.push(topicValue.toLowerCase());
						} else {
							topics.push(this.formatWord(topicValue));
						}
					}
				}
				var logData = entry.data;
				if (typeof logData === "string") {
					logData = logData.toLowerCase();
				} else {
					logData = this.formatHex(logData);
				}
				var addressValue = entry.address;
				if (typeof addressValue !== "string") {
					addressValue = toHex(addressValue);
				}
				this.data.logs.push({
					address: addressValue.toLowerCase(),
					topics: topics,
					data: logData
				});
			}

			return this.data;
		}
	}`, protectedAddr, recordAll)
}

// parseReplayResult 将 tracer 原始输出解码为 ReplayResult
func parseReplayResult(raw json.RawMessage) (*ReplayResult, error) {
	var decoded struct {
		Success             bool               `json:"success"`
		GasUsed             uint64             `json:"gasUsed"`
		ReturnData          string             `json:"returnData"`
		Error               string             `json:"error,omitempty"`
		JumpDests           []uint64           `json:"jumpDests"`
		ContractJumpDests   []ContractJumpDest `json:"contractJumpDests"`
		CallTargets         []string           `json:"callTargets"`
		CallEdges           []CallEdge         `json:"callEdges"`
		ProtectedStartIndex int                `json:"protectedStartIndex"`
		ProtectedEndIndex   int                `json:"protectedEndIndex"`
		ExecutionPath       []PathStep         `json:"executionPath"`
		StateChanges        map[string]struct {
			BalanceBefore  string `json:"balanceBefore"`
			BalanceAfter   string `json:"balanceAfter"`
			StorageChanges map[string]struct {
				Before string `json:"before"`
				After  string `json:"after"`
			} `json:"storageChanges"`
		} `json:"stateChanges"`
		Logs      []Log `json:"logs"`
		DebugInfo struct {
			TotalSteps             int    `json:"totalSteps"`
			ProtectedSteps         int    `json:"protectedSteps"`
			JumpDestCount          int    `json:"jumpDestCount"`
			FirstProtectedContract string `json:"firstProtectedContract"`
			RecordingTrigger       string `json:"recordingTrigger"`
		} `json:"debugInfo"`
	}

	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trace result: %w", err)
	}

	fmt.Printf("[DEBUG tracer result] totalSteps=%d, protectedSteps=%d, jumpDestCount=%d, trigger=%s, firstContract=%s\n",
		decoded.DebugInfo.TotalSteps, decoded.DebugInfo.ProtectedSteps, decoded.DebugInfo.JumpDestCount,
		decoded.DebugInfo.RecordingTrigger, decoded.DebugInfo.FirstProtectedContract)
	fmt.Printf("[DEBUG tracer result] raw.JumpDests length=%d, raw.ContractJumpDests length=%d\n",
		len(decoded.JumpDests), len(decoded.ContractJumpDests))
	fmt.Printf("[DEBUG tracer result] callEdges=%d, callTargets=%d\n",
		len(decoded.CallEdges), len(decoded.CallTargets))

	contractJumpDests := decoded.ContractJumpDests

	// 组装状态变更
	stateChanges := make(map[string]StateChange, len(decoded.StateChanges))
	for addr, change := range decoded.StateChanges {
		updates := make(map[string]StorageUpdate, len(change.StorageChanges))
		for slot, diff := range change.StorageChanges {
			updates[slot] = StorageUpdate{
				Before: diff.Before,
				After:  diff.After,
			}
		}
		stateChanges[addr] = StateChange{
			BalanceBefore:  change.BalanceBefore,
			BalanceAfter:   change.BalanceAfter,
			StorageChanges: updates,
		}
	}

	replay := &ReplayResult{
		Success:             decoded.Success,
		GasUsed:             decoded.GasUsed,
		ReturnData:          decoded.ReturnData,
		JumpDests:           decoded.JumpDests,
		ContractJumpDests:   contractJumpDests,
		CallTargets:         decoded.CallTargets,
		CallEdges:           decoded.CallEdges,
		ProtectedStartIndex: decoded.ProtectedStartIndex,
		ProtectedEndIndex:   decoded.ProtectedEndIndex,
		ExecutionPath:       decoded.ExecutionPath,
		StateChanges:        stateChanges,
		Logs:                decoded.Logs,
		Error:               decoded.Error,
	}
	return replay, nil
}

func normalizeStackAddress(word string) string {
	w := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(word)), "0x")
	if w == "" {
		return ""
	}
	if len(w) > 40 {
		w = w[len(w)-40:]
	}
	if len(w) < 40 {
		w = strings.Repeat("0", 40-len(w)) + w
	}
	return "0x" + w
}

func wsURLToHTTP(url string) string {
	switch {
	case strings.HasPrefix(url, "ws://"):
		return "http://" + strings.TrimPrefix(url, "ws://")
	case strings.HasPrefix(url, "wss://"):
		return "https://" + strings.TrimPrefix(url, "wss://")
	default:
		return url
	}
}

func callTargetFromStack(op string, stack []string) string {
	if len(stack) == 0 {
		return ""
	}
	var idx int
	switch op {
	case "CALL", "CALLCODE":
		idx = len(stack) - 6
	case "DELEGATECALL", "STATICCALL":
		idx = len(stack) - 5
	default:
		return ""
	}
	if idx < 0 || idx >= len(stack) {
		return ""
	}
	return normalizeStackAddress(stack[idx])
}

func isCallOp(op string) bool {
	switch op {
	case "CALL", "CALLCODE", "DELEGATECALL", "STATICCALL":
		return true
	default:
		return false
	}
}

func resolveProtectedIndices(path []ContractJumpDest, target common.Address) (int, int) {
	if target == (common.Address{}) {
		if len(path) == 0 {
			return -1, -1
		}
		return 0, len(path)
	}
	targetLower := strings.ToLower(target.Hex())
	start := -1
	end := -1
	for i, jd := range path {
		if strings.EqualFold(jd.Contract, targetLower) {
			if start == -1 {
				start = i
			}
			end = i + 1
		}
	}
	return start, end
}

func buildPathFromGethTrace(steps []gethTraceStep, rootAddr common.Address) ([]uint64, []ContractJumpDest, []string, []CallEdge) {
	root := strings.ToLower(rootAddr.Hex())
	addrByDepth := make(map[int]string)
	pendingByDepth := make(map[int]string)
	prevDepth := -1

	var jumpDests []uint64
	var contractJumpDests []ContractJumpDest
	var callTargets []string
	var callEdges []CallEdge

	for _, step := range steps {
		depth := step.Depth
		if prevDepth == -1 {
			if root != "" {
				addrByDepth[depth] = root
			}
		} else {
			if depth > prevDepth {
				if pending, ok := pendingByDepth[prevDepth]; ok && pending != "" {
					addrByDepth[depth] = pending
				} else if addrByDepth[prevDepth] != "" {
					addrByDepth[depth] = addrByDepth[prevDepth]
				}
			} else if depth < prevDepth {
				for d := prevDepth; d > depth; d-- {
					delete(addrByDepth, d)
					delete(pendingByDepth, d)
				}
				if _, ok := addrByDepth[depth]; !ok && root != "" {
					addrByDepth[depth] = root
				}
			} else if _, ok := addrByDepth[depth]; !ok && root != "" {
				addrByDepth[depth] = root
			}
		}
		prevDepth = depth

		currentAddr := addrByDepth[depth]
		if currentAddr == "" {
			currentAddr = root
		}

		if step.Op == "JUMPDEST" {
			jumpDests = append(jumpDests, step.PC)
			contractJumpDests = append(contractJumpDests, ContractJumpDest{
				Contract: currentAddr,
				PC:       step.PC,
			})
		}

		if isCallOp(step.Op) {
			target := callTargetFromStack(step.Op, step.Stack)
			if target != "" {
				pendingByDepth[depth] = target
				callTargets = append(callTargets, target)
				callEdges = append(callEdges, CallEdge{
					Caller: currentAddr,
					Target: target,
					Op:     step.Op,
					Depth:  depth,
				})
			}
		}
	}

	return jumpDests, contractJumpDests, callTargets, callEdges
}

// ContractJumpDest 合约维度的 JUMPDEST
type ContractJumpDest struct {
	Contract string `json:"contract"` // 合约地址
	PC       uint64 `json:"pc"`       // 程序计数器
}

// CallEdge 记录调用边（caller -> target）
type CallEdge struct {
	Caller string `json:"caller"`
	Target string `json:"target"`
	Op     string `json:"op"`
	Depth  int    `json:"depth"`
}

// CallFrame callTracer 的调用帧
type CallFrame struct {
	Type    string                  `json:"type"`
	From    string                  `json:"from"`
	To      string                  `json:"to"`
	Value   string                  `json:"value"`
	Gas     apptypes.FlexibleUint64 `json:"gas"`
	GasUsed apptypes.FlexibleUint64 `json:"gasUsed"`
	Input   string                  `json:"input"`
	Output  string                  `json:"output"`
	Error   string                  `json:"error"`
	Calls   []CallFrame             `json:"calls"`
}

// ReplayResult 重放结果
type ReplayResult struct {
	Success             bool                   `json:"success"`
	GasUsed             uint64                 `json:"gas_used"`
	ReturnData          string                 `json:"return_data"`
	Logs                []Log                  `json:"logs"`
	StateChanges        map[string]StateChange `json:"state_changes"`
	JumpDests           []uint64               `json:"jump_dests"`            // 保留向后兼容
	ContractJumpDests   []ContractJumpDest     `json:"contract_jump_dests"`   // 新增：带合约地址的路径
	CallTargets         []string               `json:"call_targets"`          // 新增：CALL目标地址序列
	CallEdges           []CallEdge             `json:"call_edges"`            // 新增：CALL调用边
	ProtectedStartIndex int                    `json:"protected_start_index"` // 新增：受保护合约开始索引
	ProtectedEndIndex   int                    `json:"protected_end_index"`   // 新增：受保护合约结束索引
	ExecutionPath       []PathStep             `json:"execution_path"`
	Error               string                 `json:"error,omitempty"`
}

// Log 日志
type Log struct {
	Address common.Address `json:"address"`
	Topics  []common.Hash  `json:"topics"`
	Data    string         `json:"data"`
}

// StorageUpdate 存储槽位的前后状态
type StorageUpdate struct {
	Before string `json:"before"`
	After  string `json:"after"`
}

// StateChange 状态变化
type StateChange struct {
	BalanceBefore  string                   `json:"balance_before"`
	BalanceAfter   string                   `json:"balance_after"`
	StorageChanges map[string]StorageUpdate `json:"storage_changes"`
}

// PathStep 执行路径步骤
type PathStep struct {
	PC       uint64         `json:"pc"`       // 程序计数器
	Op       string         `json:"op"`       // 操作码
	Gas      uint64         `json:"gas"`      // 剩余Gas
	GasCost  uint64         `json:"gas_cost"` // Gas消耗
	Depth    int            `json:"depth"`    // 调用深度
	Stack    []string       `json:"stack"`    // 栈内容（简化）
	Memory   string         `json:"memory"`   // 内存内容（简化）
	Contract common.Address `json:"contract"` // 当前合约地址
}

type gethTraceStep struct {
	Depth   int      `json:"depth"`
	PC      uint64   `json:"pc"`
	Op      string   `json:"op"`
	Gas     uint64   `json:"gas"`
	GasCost uint64   `json:"gasCost"`
	Stack   []string `json:"stack"`
	Memory  []string `json:"memory,omitempty"`
}

type gethTraceResult struct {
	Gas         uint64          `json:"gas"`
	ReturnValue string          `json:"returnValue"`
	StructLogs  []gethTraceStep `json:"structLogs"`
	Failed      bool            `json:"failed"`
}

// ForkAndReplay Fork状态并重放交易
func (s *EVMSimulator) ForkAndReplay(ctx context.Context, blockNumber uint64, txHash common.Hash, protectedContract common.Address) (*ReplayResult, error) {
	// 优先使用 geth-style debug_traceTransaction(structLogs)
	if res, err := s.traceTransactionWithGethTracer(ctx, txHash, protectedContract); err == nil {
		fmt.Printf("[DEBUG ForkAndReplay] geth tracer 成功! JumpDests=%d, ContractJumpDests=%d, ProtectedStart=%d\n",
			len(res.JumpDests), len(res.ContractJumpDests), res.ProtectedStartIndex)
		return res, nil
	} else {
		fmt.Printf("[DEBUG ForkAndReplay] geth tracer 失败: %v\n", err)
	}

	// 回退到 JS tracer
	result, err := s.traceTransactionWithCustomTracer(txHash, protectedContract)
	if err != nil {
		fmt.Printf("[DEBUG ForkAndReplay] traceTransactionWithCustomTracer失败: %v\n", err)
		// 兼容不支持JS Tracer的节点（如某些 anvil 版本）
		if strings.Contains(err.Error(), "unsupported tracer type") || strings.Contains(err.Error(), "unsupported tracer") {
			fmt.Printf("[DEBUG ForkAndReplay] 触发callTracer fallback!\n")
			// 回退到 callTracer，并使用伪 JumpDests 表示调用序列
			return s.traceTransactionWithCallTracer(txHash)
		}
		return nil, fmt.Errorf("failed to trace transaction: %w", err)
	}

	fmt.Printf("[DEBUG ForkAndReplay] 成功! JumpDests=%d, ContractJumpDests=%d, ProtectedStart=%d\n",
		len(result.JumpDests), len(result.ContractJumpDests), result.ProtectedStartIndex)
	return result, nil
}

func (s *EVMSimulator) resolveTraceRootAddress(ctx context.Context, txHash common.Hash) (common.Address, error) {
	if s.client == nil {
		return common.Address{}, fmt.Errorf("eth client not initialized")
	}
	if tx, _, err := s.client.TransactionByHash(ctx, txHash); err == nil && tx != nil {
		if to := tx.To(); to != nil {
			return *to, nil
		}
	}
	if receipt, err := s.client.TransactionReceipt(ctx, txHash); err == nil && receipt != nil {
		if receipt.ContractAddress != (common.Address{}) {
			return receipt.ContractAddress, nil
		}
	}
	return common.Address{}, fmt.Errorf("failed to resolve root address for trace")
}

func (s *EVMSimulator) traceTransactionWithGethTracer(ctx context.Context, txHash common.Hash, protectedContract common.Address) (*ReplayResult, error) {
	rootAddr, err := s.resolveTraceRootAddress(ctx, txHash)
	if err != nil {
		return nil, err
	}

	traceParams := map[string]interface{}{
		"disableStorage": true,
		"disableMemory":  true,
		"disableStack":   false,
	}

	// 若主RPC为ws/wss，优先使用HTTP执行trace以避免大响应触发读限制
	if httpURL := wsURLToHTTP(s.rpcURL); httpURL != "" && httpURL != s.rpcURL {
		if httpClient, dialErr := rpc.Dial(httpURL); dialErr == nil {
			defer httpClient.Close()
			var httpTrace gethTraceResult
			if httpErr := httpClient.CallContext(ctx, &httpTrace, "debug_traceTransaction", txHash, traceParams); httpErr == nil {
				if len(httpTrace.StructLogs) == 0 {
					return nil, fmt.Errorf("geth trace returned empty structLogs")
				}
				jumpDests, contractJumpDests, callTargets, callEdges := buildPathFromGethTrace(httpTrace.StructLogs, rootAddr)
				startIdx, endIdx := resolveProtectedIndices(contractJumpDests, protectedContract)
				return &ReplayResult{
					Success:             !httpTrace.Failed,
					GasUsed:             httpTrace.Gas,
					ReturnData:          httpTrace.ReturnValue,
					JumpDests:           jumpDests,
					ContractJumpDests:   contractJumpDests,
					CallTargets:         callTargets,
					CallEdges:           callEdges,
					ProtectedStartIndex: startIdx,
					ProtectedEndIndex:   endIdx,
				}, nil
			}
		}
	}

	var trace gethTraceResult
	err = s.rpcClient.CallContext(ctx, &trace, "debug_traceTransaction", txHash, traceParams)
	if err != nil {
		if strings.Contains(err.Error(), "read limit exceeded") && s.rpcURL != "" {
			httpURL := wsURLToHTTP(s.rpcURL)
			if httpURL != "" && httpURL != s.rpcURL {
				if httpClient, dialErr := rpc.Dial(httpURL); dialErr == nil {
					defer httpClient.Close()
					var httpTrace gethTraceResult
					if httpErr := httpClient.CallContext(ctx, &httpTrace, "debug_traceTransaction", txHash, traceParams); httpErr == nil {
						trace = httpTrace
						err = nil
					} else {
						err = httpErr
					}
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("geth trace failed: %w", err)
		}
	}
	if len(trace.StructLogs) == 0 {
		return nil, fmt.Errorf("geth trace returned empty structLogs")
	}

	jumpDests, contractJumpDests, callTargets, callEdges := buildPathFromGethTrace(trace.StructLogs, rootAddr)
	startIdx, endIdx := resolveProtectedIndices(contractJumpDests, protectedContract)

	return &ReplayResult{
		Success:             !trace.Failed,
		GasUsed:             trace.Gas,
		ReturnData:          trace.ReturnValue,
		JumpDests:           jumpDests,
		ContractJumpDests:   contractJumpDests,
		CallTargets:         callTargets,
		CallEdges:           callEdges,
		ProtectedStartIndex: startIdx,
		ProtectedEndIndex:   endIdx,
	}, nil
}

// traceTransactionWithCustomTracer 使用自定义追踪器追踪交易
func (s *EVMSimulator) traceTransactionWithCustomTracer(txHash common.Hash, protectedContract common.Address) (*ReplayResult, error) {
	recordAll := protectedContract == (common.Address{})
	protectedAddr := ""
	if !recordAll {
		protectedAddr = strings.ToLower(protectedContract.Hex())
	}

	fmt.Printf("[DEBUG tracer] recordAll=%v, protectedAddr=%s\n", recordAll, protectedAddr)

	tracerCode := buildReplayTracerCode(protectedAddr, recordAll)

	var result json.RawMessage

	//  诊断日志：记录RPC调用详情
	fmt.Printf("[DEBUG Trace] 即将调用debug_traceTransaction:\n")
	fmt.Printf("  - txHash: %s\n", txHash.Hex())
	fmt.Printf("  - protectedContract: %s\n", protectedAddr)
	fmt.Printf("  - recordAll: %v\n", recordAll)
	fmt.Printf("  - RPC Client类型: %T\n", s.rpcClient)

	startTime := time.Now()
	err := s.rpcClient.Call(&result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": tracerCode,
		// Ensure deep call frames are traced (some Anvil builds default to top-level only)
		"tracerConfig": map[string]interface{}{
			"onlyTopCall": false,
		},
	})
	elapsed := time.Since(startTime)

	fmt.Printf("[DEBUG Trace] debug_traceTransaction完成:\n")
	fmt.Printf("  - 耗时: %v\n", elapsed)
	fmt.Printf("  - 错误: %v\n", err)
	if err == nil {
		fmt.Printf("  - 结果长度: %d bytes\n", len(result))
	}

	if err != nil {
		return nil, err
	}

	// 输出原始JSON用于调试
	fmt.Printf("[DEBUG tracer raw JSON] %s\n", string(result)[:min(500, len(result))])

	return parseReplayResult(result)
}

// ReplayTransactionWithOverride 使用 prestate 覆盖离线重放原始交易
func (s *EVMSimulator) ReplayTransactionWithOverride(
	ctx context.Context,
	tx *types.Transaction,
	blockNumber uint64,
	override StateOverride,
	protectedContract common.Address,
) (*ReplayResult, error) {
	msg, err := buildCallMessageFromTx(tx)
	if err != nil {
		return nil, err
	}

	recordAll := protectedContract == (common.Address{})
	protectedAddr := ""
	if !recordAll {
		protectedAddr = strings.ToLower(protectedContract.Hex())
	}

	tracerCode := buildReplayTracerCode(protectedAddr, recordAll)

	options := map[string]interface{}{
		"tracer": tracerCode,
		// Ensure deep call frames are traced (some Anvil builds default to top-level only)
		"tracerConfig": map[string]interface{}{
			"onlyTopCall": false,
		},
	}

	params := []interface{}{
		msg,
		fmt.Sprintf("0x%x", blockNumber),
		options,
	}

	isStateOverrideErr := func(err error) bool {
		if err == nil {
			return false
		}
		errStr := err.Error()
		return strings.Contains(errStr, "stateOverrides") ||
			strings.Contains(errStr, "unexpected EOF") ||
			strings.Contains(errStr, "invalid length") ||
			strings.Contains(errStr, "did not match any variant of untagged enum EthRpcCall")
	}

	var result json.RawMessage

	// 优先尝试Anvil格式（stateOverrides放在options里）
	if override != nil && len(override) > 0 {
		options["stateOverrides"] = override
		err = s.rpcClient.CallContext(ctx, &result, "debug_traceCall", params...)

		// Anvil格式失败时尝试Geth格式（override作为第四参数）
		if err != nil && isStateOverrideErr(err) {
			delete(options, "stateOverrides")
			params = []interface{}{
				msg,
				fmt.Sprintf("0x%x", blockNumber),
				options,
				override,
			}
			err = s.rpcClient.CallContext(ctx, &result, "debug_traceCall", params...)
		}
	} else {
		err = s.rpcClient.CallContext(ctx, &result, "debug_traceCall", params...)
	}

	// 节点不支持stateOverrides时，回退到链上注入
	if err != nil && override != nil && len(override) > 0 && isStateOverrideErr(err) {
		setAccounts, setSlots := s.applyOverrideOnChain(ctx, override)
		log.Printf("[Simulator]  已将 stateOverride 注入本地区块链 (accounts=%d, slots=%d)", setAccounts, setSlots)

		paramsFallback := []interface{}{
			msg,
			fmt.Sprintf("0x%x", blockNumber),
			map[string]interface{}{"tracer": tracerCode},
		}
		var retryRaw json.RawMessage
		if retryErr := s.rpcClient.CallContext(ctx, &retryRaw, "debug_traceCall", paramsFallback...); retryErr == nil {
			result = retryRaw
			err = nil
		} else {
			err = retryErr
		}
	}

	if err != nil {
		return nil, fmt.Errorf("failed to trace call with override: %w", err)
	}

	fmt.Printf("[DEBUG tracer raw JSON] %s\n", string(result)[:min(500, len(result))])
	return parseReplayResult(result)
}

// TraceCallTreeWithOverride 使用 callTracer 在 prestate 上重放交易，获取完整调用树
func (s *EVMSimulator) TraceCallTreeWithOverride(
	ctx context.Context,
	tx *types.Transaction,
	blockNumber uint64,
	override StateOverride,
) (*CallFrame, error) {
	msg, err := buildCallMessageFromTx(tx)
	if err != nil {
		return nil, err
	}

	options := map[string]interface{}{
		"tracer": "callTracer",
		"tracerConfig": map[string]interface{}{
			"onlyTopCall": false,
		},
	}

	// 智能检测节点类型：先尝试 Anvil 格式（stateOverride in options）
	var params []interface{}
	if override != nil && len(override) > 0 {
		options["stateOverrides"] = override // Anvil 格式
		params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options}
	} else {
		params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options}
	}

	var raw json.RawMessage
	callErr := s.rpcClient.CallContext(ctx, &raw, "debug_traceCall", params...)

	// 如果 Anvil 格式失败，尝试 Geth 格式（stateOverride 作为第4参数）
	if callErr != nil && override != nil && len(override) > 0 {
		errStr := callErr.Error()
		if strings.Contains(errStr, "did not match any variant of untagged enum EthRpcCall") ||
			strings.Contains(errStr, "stateOverrides") ||
			strings.Contains(errStr, "unexpected EOF") ||
			strings.Contains(errStr, "invalid length") {

			log.Printf("[Simulator] Anvil格式失败,尝试Geth格式 (err=%v)", callErr)

			// 移除 options 中的 stateOverrides，作为第4参数传递
			delete(options, "stateOverrides")
			params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options, override}

			if retryErr := s.rpcClient.CallContext(ctx, &raw, "debug_traceCall", params...); retryErr == nil {
				callErr = nil
				log.Printf("[Simulator] ✅ Geth格式成功")
			} else {
				// Geth格式也失败，执行本地状态注入
				log.Printf("[Simulator] Geth格式也失败,注入链上状态 (err=%v)", retryErr)
				setAccounts, setSlots := s.applyOverrideOnChain(ctx, override)
				log.Printf("[Simulator] 已注入 (accounts=%d, slots=%d)", setAccounts, setSlots)

				// 移除 stateOverride 重试
				params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options}
				callErr = s.rpcClient.CallContext(ctx, &raw, "debug_traceCall", params...)
			}
		}
	}

	if callErr != nil {
		return nil, fmt.Errorf("failed to trace call tree: %w", callErr)
	}

	var frame CallFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil, fmt.Errorf("failed to unmarshal callTracer frame: %w", err)
	}
	return &frame, nil
}

// buildCallMessageFromTx 将已上链交易转换为 debug_traceCall 所需的消息结构
func buildCallMessageFromTx(tx *types.Transaction) (map[string]interface{}, error) {
	msg := map[string]interface{}{
		"data": hexutil.Encode(tx.Data()),
		"gas":  fmt.Sprintf("0x%x", tx.Gas()),
	}

	if tx.To() != nil {
		msg["to"] = tx.To().Hex()
	}

	if tx.Value() != nil && tx.Value().Sign() > 0 {
		msg["value"] = fmt.Sprintf("0x%x", tx.Value())
	}

	chainID := tx.ChainId()
	var signer types.Signer
	if chainID != nil {
		signer = types.LatestSignerForChainID(chainID)
	} else {
		signer = types.HomesteadSigner{}
	}

	from, err := types.Sender(signer, tx)
	if err != nil {
		return nil, fmt.Errorf("failed to derive sender from tx: %w", err)
	}
	msg["from"] = from.Hex()

	// 为避免余额检查失败，使用零 gas 价格模拟执行
	msg["gasPrice"] = "0x0"
	if tx.Type() == types.DynamicFeeTxType {
		msg["maxFeePerGas"] = "0x0"
		msg["maxPriorityFeePerGas"] = "0x0"
	}

	return msg, nil
}

// SimulateTransaction 模拟交易执行
func (s *EVMSimulator) SimulateTransaction(ctx context.Context, from common.Address, to common.Address, data []byte, value *big.Int, blockNumber uint64) (*SimulateResult, error) {
	// 构建调用参数
	msg := map[string]interface{}{
		"from": from,
		"to":   to,
		"data": common.Bytes2Hex(data),
	}

	if value != nil {
		msg["value"] = fmt.Sprintf("0x%x", value)
	}

	// 使用 eth_call 模拟执行
	var result string
	err := s.rpcClient.Call(&result, "eth_call", msg, fmt.Sprintf("0x%x", blockNumber))

	if err != nil {
		return nil, err
	}

	return &SimulateResult{
		Success:    err == nil,
		ReturnData: result,
	}, nil
}

// SimulateResult 模拟结果
type SimulateResult struct {
	Success    bool   `json:"success"`
	ReturnData string `json:"return_data"`
	Error      string `json:"error,omitempty"`
}

// PathAnalyzer 路径分析器
type PathAnalyzer struct {
	paths map[common.Hash]*ReplayResult // 交易哈希 -> 执行结果
}

// NewPathAnalyzer 创建路径分析器
func NewPathAnalyzer() *PathAnalyzer {
	return &PathAnalyzer{
		paths: make(map[common.Hash]*ReplayResult),
	}
}

// StorePath 存储路径
func (a *PathAnalyzer) StorePath(txHash common.Hash, result *ReplayResult) {
	a.paths[txHash] = result
}

// GetPath 获取路径
func (a *PathAnalyzer) GetPath(txHash common.Hash) (*ReplayResult, bool) {
	result, exists := a.paths[txHash]
	return result, exists
}

// AnalyzePath 分析路径特征
func (a *PathAnalyzer) AnalyzePath(result *ReplayResult) *PathAnalysis {
	analysis := &PathAnalysis{
		TotalSteps:       len(result.ExecutionPath),
		UniqueOpcodes:    make(map[string]int),
		MaxDepth:         0,
		TotalGasUsed:     result.GasUsed,
		JumpDestCount:    len(result.JumpDests),
		StateChangeCount: len(result.StateChanges),
	}

	for _, step := range result.ExecutionPath {
		analysis.UniqueOpcodes[step.Op]++

		if step.Depth > analysis.MaxDepth {
			analysis.MaxDepth = step.Depth
		}
	}

	// 识别常见模式
	analysis.Patterns = a.identifyPatterns(result.ExecutionPath)

	return analysis
}

// PathAnalysis 路径分析结果
type PathAnalysis struct {
	TotalSteps       int            `json:"total_steps"`
	UniqueOpcodes    map[string]int `json:"unique_opcodes"`
	MaxDepth         int            `json:"max_depth"`
	TotalGasUsed     uint64         `json:"total_gas_used"`
	JumpDestCount    int            `json:"jump_dest_count"`
	StateChangeCount int            `json:"state_change_count"`
	Patterns         []string       `json:"patterns"`
}

// identifyPatterns 识别执行模式
func (a *PathAnalyzer) identifyPatterns(path []PathStep) []string {
	var patterns []string

	// 检查是否有循环模式
	if a.hasLoopPattern(path) {
		patterns = append(patterns, "LOOP_DETECTED")
	}

	// 检查是否有递归调用
	if a.hasRecursivePattern(path) {
		patterns = append(patterns, "RECURSIVE_CALL")
	}

	// 检查是否有大量存储操作
	sstoreCount := 0
	for _, step := range path {
		if step.Op == "SSTORE" {
			sstoreCount++
		}
	}
	if sstoreCount > 10 {
		patterns = append(patterns, "HEAVY_STORAGE_OPS")
	}

	// 检查是否有外部调用
	for _, step := range path {
		if step.Op == "CALL" || step.Op == "DELEGATECALL" || step.Op == "STATICCALL" {
			patterns = append(patterns, "EXTERNAL_CALLS")
			break
		}
	}

	return patterns
}

// hasLoopPattern 检测循环模式
func (a *PathAnalyzer) hasLoopPattern(path []PathStep) bool {
	// 简化的循环检测：查找重复的PC序列
	if len(path) < 10 {
		return false
	}

	pcSequence := make([]uint64, 0)
	for _, step := range path {
		if step.Op == "JUMPDEST" {
			pcSequence = append(pcSequence, step.PC)
		}
	}

	// 查找重复序列
	for i := 0; i < len(pcSequence)/2; i++ {
		for j := i + 1; j < len(pcSequence); j++ {
			if pcSequence[i] == pcSequence[j] {
				// 发现重复的JUMPDEST
				return true
			}
		}
	}

	return false
}

// hasRecursivePattern 检测递归模式
func (a *PathAnalyzer) hasRecursivePattern(path []PathStep) bool {
	maxDepth := 0
	for _, step := range path {
		if step.Depth > maxDepth {
			maxDepth = step.Depth
		}
	}
	return maxDepth > 3 // 深度超过3可能是递归
}

// ComparePaths 比较两个执行结果的JUMPDEST序列相似度（基于LCS）
func (a *PathAnalyzer) ComparePaths(r1, r2 *ReplayResult) float64 {
	if r1 == nil || r2 == nil {
		return 0.0
	}
	seq1 := r1.JumpDests
	seq2 := r2.JumpDests
	if len(seq1) == 0 && len(seq2) == 0 {
		return 1.0
	}
	if len(seq1) == 0 || len(seq2) == 0 {
		return 0.0
	}
	lcs := lcsLength(seq1, seq2)
	return (2.0 * float64(lcs)) / float64(len(seq1)+len(seq2))
}

// lcsLength 计算两个uint64序列的最长公共子序列长度
func lcsLength(aSeq, bSeq []uint64) int {
	m, n := len(aSeq), len(bSeq)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if aSeq[i-1] == bSeq[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				if dp[i-1][j] >= dp[i][j-1] {
					dp[i][j] = dp[i-1][j]
				} else {
					dp[i][j] = dp[i][j-1]
				}
			}
		}
	}
	return dp[m][n]
}

// GetRpcClient 获取RPC客户端
func (s *EVMSimulator) GetRpcClient() *rpc.Client {
	return s.rpcClient
}

// applyOverrideOnChain 尝试将 stateOverride 直接写入本地节点（如Anvil），用于不支持stateOverride参数的节点
func (s *EVMSimulator) applyOverrideOnChain(ctx context.Context, override StateOverride) (int, int) {
	if override == nil || len(override) == 0 {
		return 0, 0
	}
	setAccounts := 0
	setSlots := 0

	normalizeWord := func(val string) string {
		raw := strings.TrimSpace(val)
		if !strings.HasPrefix(raw, "0x") && !strings.HasPrefix(raw, "0X") {
			raw = strings.TrimLeft(raw, "0")
			if raw == "" {
				raw = "0"
			}
			raw = "0x" + raw
		}
		body := strings.TrimPrefix(strings.ToLower(raw), "0x")
		body = strings.TrimLeft(body, "0")
		if body == "" {
			body = "0"
		}
		if len(body) < 64 {
			body = strings.Repeat("0", 64-len(body)) + body
		} else if len(body) > 64 {
			body = body[len(body)-64:]
		}
		return "0x" + body
	}

	for addr, ov := range override {
		if ov == nil {
			continue
		}
		lowerAddr := strings.ToLower(addr)
		setAccounts++

		if ov.Balance != "" {
			_ = s.rpcClient.CallContext(ctx, nil, "anvil_setBalance", lowerAddr, ov.Balance)
		}
		if ov.Nonce != "" {
			_ = s.rpcClient.CallContext(ctx, nil, "anvil_setNonce", lowerAddr, ov.Nonce)
		}
		if len(ov.State) > 0 {
			for slot, val := range ov.State {
				slotHex := normalizeWord(slot)
				valHex := normalizeWord(val)
				if callErr := s.rpcClient.CallContext(ctx, nil, "anvil_setStorageAt", lowerAddr, slotHex, valHex); callErr == nil {
					setSlots++
				} else {
					log.Printf("[Simulator]  写入storage失败 addr=%s slot=%s err=%v", lowerAddr, slotHex, callErr)
				}
			}
		}
	}
	return setAccounts, setSlots
}

// SimulateWithCallData 使用自定义calldata模拟交易执行
// 这个方法专门为模糊测试设计，返回带合约地址的JUMPDEST序列
func (s *EVMSimulator) SimulateWithCallData(
	ctx context.Context,
	from common.Address,
	to common.Address,
	callData []byte,
	value *big.Int,
	blockNumber uint64,
	override StateOverride,
) (*ReplayResult, error) {
	// 使用自定义tracer记录带合约地址的JUMPDEST
	tracerCode := `{
		data: {
			jumpDests: [],
			contractJumpDests: [],
			gasUsed: 0,
			success: true,
			returnData: "",
			stateChanges: {}
		},
		formatHex: function(value) {
			var hex = toHex(value);
			if (hex === "0x") {
				return "0x0";
			}
			var body = hex.slice(2);
			if (body.length === 0) {
				return "0x0";
			}
			if (body.length % 2 === 1) {
				body = "0" + body;
			}
			return "0x" + body.toLowerCase();
		},
		formatWord: function(value) {
			var body = this.formatHex(value).slice(2);
			while (body.length < 64) {
				body = "0" + body;
			}
			if (body.length > 64) {
				body = body.slice(body.length - 64);
			}
			return "0x" + body;
		},
		fault: function(log, db) {
			this.data.success = false;
			if (log.getError) {
				this.data.error = log.getError();
			}
		},
		step: function(log, db) {
			var currentContract = toHex(log.contract.getAddress());

			// 记录JUMPDEST操作码
			if (log.op.toString() === "JUMPDEST") {
				// 旧格式（向后兼容）
				this.data.jumpDests.push(log.getPC());

				// 新格式：带合约地址
				var jumpDest = {
					contract: currentContract,
					pc: log.getPC()
				};
				this.data.contractJumpDests.push(jumpDest);
			}

			// 记录状态变化
			if (log.op.toString() === "SSTORE") {
				var addrKey = currentContract.toLowerCase();
				if (!this.data.stateChanges[addrKey]) {
					var balance = this.formatHex(db.getBalance(log.contract.getAddress()));
					this.data.stateChanges[addrKey] = {
						address: currentContract,
						balanceBefore: balance,
						balanceAfter: balance,
						storageChanges: {}
					};
				}
				var state = this.data.stateChanges[addrKey];
				var slotKey = this.formatWord(log.stack.peek(0));
				var newValue = this.formatWord(log.stack.peek(1));
				var previousValue = db.getState(log.contract.getAddress(), log.stack.peek(0));
				var formattedPrev = previousValue ? this.formatWord(previousValue) : "0x0";
				state.storageChanges[slotKey] = {
					before: formattedPrev,
					after: newValue
				};
				state.balanceAfter = this.formatHex(db.getBalance(log.contract.getAddress()));
			}

			//  新增：捕获 CALL 操作的 ETH 转账
			var opName = log.op.toString();
			if (opName === "CALL" || opName === "CALLCODE") {
				var callValue = log.stack.peek(2);
				if (callValue) {
					var valueHex = toHex(callValue);
					if (valueHex && valueHex !== "0x0" && valueHex !== "0x") {
						var fromAddr = currentContract.toLowerCase();

						// 记录发送方余额变更
						if (!this.data.stateChanges[fromAddr]) {
							this.data.stateChanges[fromAddr] = {
								address: currentContract,
								balanceBefore: this.formatHex(db.getBalance(log.contract.getAddress())),
								balanceAfter: "0x0",
								storageChanges: {}
							};
						}
					}
				}
			}
		},
		result: function(ctx, db) {
			this.data.gasUsed = ctx.gasUsed;
			if (ctx.type === "REVERT") {
				this.data.success = false;
				this.data.returnData = toHex(ctx.output);
			} else {
				this.data.returnData = toHex(ctx.output);
			}

			// 收尾：填充 balanceAfter
			for (var addrKey in this.data.stateChanges) {
				var entry = this.data.stateChanges[addrKey];
				var addr = toAddress(entry.address);
				entry.balanceAfter = this.formatHex(db.getBalance(addr));
			}
			return this.data;
		}
	}`

	// 构建调用消息
	msg := map[string]interface{}{
		"from": from.Hex(),
		"to":   to.Hex(),
		"data": "0x" + common.Bytes2Hex(callData),
	}

	if value != nil && value.Sign() > 0 {
		msg["value"] = fmt.Sprintf("0x%x", value)
	}

	// 使用debug_traceCall执行模拟
	options := map[string]interface{}{"tracer": tracerCode}

	// 智能检测节点类型：先尝试 Anvil 格式（stateOverride in options）
	var params []interface{}
	if override != nil && len(override) > 0 {
		options["stateOverrides"] = override // Anvil 格式
		params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options}
	} else {
		params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options}
	}

	var result json.RawMessage
	err := s.rpcClient.CallContext(ctx, &result, "debug_traceCall", params...)

	// 如果 Anvil 格式失败，尝试 Geth 格式（stateOverride 作为第4参数）
	if err != nil && override != nil && len(override) > 0 {
		errStr := err.Error()
		// 某些节点可能仍然不识别 stateOverrides，回退为无覆盖调用，并尝试写链
		if strings.Contains(errStr, "did not match any variant of untagged enum EthRpcCall") ||
			strings.Contains(errStr, "unexpected EOF") ||
			strings.Contains(errStr, "invalid length") ||
			strings.Contains(errStr, "stateOverrides") {

			log.Printf("[Simulator] Anvil格式失败,尝试Geth格式 (override账户数=%d, err=%v)", len(override), err)

			// 移除 options 中的 stateOverrides，作为第4参数传递
			delete(options, "stateOverrides")
			params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), options, override}

			var retryResult json.RawMessage
			if retryErr := s.rpcClient.CallContext(ctx, &retryResult, "debug_traceCall", params...); retryErr == nil {
				result = retryResult
				err = nil
				log.Printf("[Simulator] ✅ Geth格式成功")
			} else {
				// Geth格式也失败，执行本地状态注入
				log.Printf("[Simulator] Geth格式也失败,注入链上状态 (err=%v)", retryErr)
				setAccounts, setSlots := s.applyOverrideOnChain(ctx, override)
				log.Printf("[Simulator] 已注入 (accounts=%d, slots=%d)", setAccounts, setSlots)

				// 移除 stateOverride 重试
				params = []interface{}{msg, fmt.Sprintf("0x%x", blockNumber), map[string]interface{}{"tracer": tracerCode}}
				err = s.rpcClient.CallContext(ctx, &result, "debug_traceCall", params...)
			}
		}
	}

	if err != nil {
		// 回退到 callTracer（无指令级JUMPDEST，但可用调用序列近似比较）
		if strings.Contains(err.Error(), "unsupported tracer type") || strings.Contains(err.Error(), "unsupported tracer") {
			return s.simulateWithCallTracer(ctx, from, to, callData, value, blockNumber, override)
		}
		return nil, fmt.Errorf("failed to trace call: %w", err)
	}

	// 解析结果
	var traceResult struct {
		JumpDests         []uint64           `json:"jumpDests"`
		ContractJumpDests []ContractJumpDest `json:"contractJumpDests"`
		GasUsed           uint64             `json:"gasUsed"`
		Success           bool               `json:"success"`
		ReturnData        string             `json:"returnData"`
		StateChanges      map[string]struct {
			BalanceBefore  string `json:"balanceBefore"`
			BalanceAfter   string `json:"balanceAfter"`
			StorageChanges map[string]struct {
				Before string `json:"before"`
				After  string `json:"after"`
			} `json:"storageChanges"`
		} `json:"stateChanges"`
		Error string `json:"error,omitempty"`
	}

	if err := json.Unmarshal(result, &traceResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal trace result: %w", err)
	}

	stateChanges := make(map[string]StateChange, len(traceResult.StateChanges))
	for addr, change := range traceResult.StateChanges {
		updates := make(map[string]StorageUpdate, len(change.StorageChanges))
		for slot, diff := range change.StorageChanges {
			updates[slot] = StorageUpdate{
				Before: diff.Before,
				After:  diff.After,
			}
		}
		stateChanges[addr] = StateChange{
			BalanceBefore:  change.BalanceBefore,
			BalanceAfter:   change.BalanceAfter,
			StorageChanges: updates,
		}
	}

	// 转换为ReplayResult
	// 直接调用受保护合约，从头开始就是受保护合约，所以 ProtectedStartIndex = 0
	replayResult := &ReplayResult{
		Success:             traceResult.Success,
		GasUsed:             traceResult.GasUsed,
		ReturnData:          traceResult.ReturnData,
		JumpDests:           traceResult.JumpDests,
		ContractJumpDests:   traceResult.ContractJumpDests,
		ProtectedStartIndex: 0, // 直接调用受保护合约，从头开始
		StateChanges:        stateChanges,
		Error:               traceResult.Error,
	}

	return replayResult, nil
}

// --- 回退：使用 callTracer 提取调用序列并转换为伪 JumpDests ---

type callTracerFrame = CallFrame

// traceTransactionWithCallTracer 使用内置 callTracer 追踪已上链交易
func (s *EVMSimulator) traceTransactionWithCallTracer(txHash common.Hash) (*ReplayResult, error) {
	var raw json.RawMessage
	err := s.rpcClient.Call(&raw, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer":       "callTracer",
		"tracerConfig": map[string]interface{}{"onlyTopCall": false},
	})
	if err != nil {
		return nil, fmt.Errorf("callTracer fallback failed: %w", err)
	}
	var frame callTracerFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil, fmt.Errorf("failed to unmarshal callTracer frame: %w", err)
	}
	addrs := normalizeCallAddresses(flattenCallAddresses(frame))
	pseudo := addressesToPseudoJumpDests(addrs)
	contractJumpDests := addressesToContractJumpDests(addrs, pseudo)
	return &ReplayResult{
		Success:             true,
		GasUsed:             0,
		ReturnData:          "",
		JumpDests:           pseudo,
		ContractJumpDests:   contractJumpDests,
		CallTargets:         addrs,
		ExecutionPath:       nil,
		ProtectedStartIndex: 0,
		Error:               "",
	}, nil
}

// simulateWithCallTracer 使用内置 callTracer 追踪 eth_call 模拟
func (s *EVMSimulator) simulateWithCallTracer(
	ctx context.Context,
	from common.Address,
	to common.Address,
	callData []byte,
	value *big.Int,
	blockNumber uint64,
	override StateOverride,
) (*ReplayResult, error) {
	msg := map[string]interface{}{
		"from": from.Hex(),
		"to":   to.Hex(),
		"data": "0x" + common.Bytes2Hex(callData),
	}
	if value != nil && value.Sign() > 0 {
		msg["value"] = fmt.Sprintf("0x%x", value)
	}

	params := []interface{}{
		msg,
		fmt.Sprintf("0x%x", blockNumber),
		map[string]interface{}{"tracer": "callTracer", "tracerConfig": map[string]interface{}{"onlyTopCall": false}},
	}
	if override != nil && len(override) > 0 {
		params = append(params, override)
	}

	var raw json.RawMessage
	err := s.rpcClient.CallContext(ctx, &raw, "debug_traceCall", params...)
	if err != nil {
		return nil, fmt.Errorf("callTracer fallback failed: %w", err)
	}
	var frame callTracerFrame
	if err := json.Unmarshal(raw, &frame); err != nil {
		return nil, fmt.Errorf("failed to unmarshal callTracer frame: %w", err)
	}
	addrs := normalizeCallAddresses(flattenCallAddresses(frame))
	pseudo := addressesToPseudoJumpDests(addrs)
	contractJumpDests := addressesToContractJumpDests(addrs, pseudo)
	return &ReplayResult{
		Success:             true,
		GasUsed:             0,
		ReturnData:          "",
		JumpDests:           pseudo,
		ContractJumpDests:   contractJumpDests,
		CallTargets:         addrs,
		ProtectedStartIndex: 0,
		Error:               "",
	}, nil
}

func flattenCallAddresses(frame callTracerFrame) []string {
	var res []string
	var dfs func(f callTracerFrame)
	dfs = func(f callTracerFrame) {
		if f.To != "" {
			res = append(res, strings.ToLower(f.To))
		}
		for _, c := range f.Calls {
			dfs(c)
		}
	}
	dfs(frame)
	return res
}

func normalizeCallAddresses(addrs []string) []string {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		out = append(out, strings.ToLower(addr))
	}
	return out
}

func addressesToContractJumpDests(addrs []string, pseudo []uint64) []ContractJumpDest {
	if len(addrs) == 0 {
		return nil
	}
	out := make([]ContractJumpDest, 0, len(addrs))
	for i, addr := range addrs {
		pc := uint64(0)
		if i < len(pseudo) {
			pc = pseudo[i]
		}
		out = append(out, ContractJumpDest{
			Contract: addr,
			PC:       pc,
		})
	}
	return out
}

func addressesToPseudoJumpDests(addrs []string) []uint64 {
	out := make([]uint64, 0, len(addrs))
	for _, a := range addrs {
		// 使用地址后8字节生成伪指令位置（稳定且可比较）
		if len(a) >= 2+16 { // 0x + 16 hex chars => 8 bytes
			tail := a[len(a)-16:]
			// 解析为 uint64
			var v uint64
			fmt.Sscanf(tail, "%016x", &v)
			out = append(out, v)
		} else {
			out = append(out, 0)
		}
	}
	return out
}

// SimulateTransactionWithParams 使用指定参数模拟交易
func (s *EVMSimulator) SimulateTransactionWithParams(
	ctx context.Context,
	req *SimulateRequest,
) (*SimulateResult, error) {
	// 使用 eth_call 进行基本模拟
	msg := map[string]interface{}{
		"from": req.From.Hex(),
		"to":   req.To.Hex(),
		"data": "0x" + common.Bytes2Hex(req.Data),
	}

	if req.Value != nil {
		msg["value"] = fmt.Sprintf("0x%x", req.Value)
	}

	var result string
	err := s.rpcClient.CallContext(ctx, &result, "eth_call", msg, fmt.Sprintf("0x%x", req.BlockNumber))

	if err != nil {
		// 检查是否为revert错误
		if err.Error() == "execution reverted" {
			return &SimulateResult{
				Success:    false,
				ReturnData: result,
				Error:      "execution reverted",
			}, nil
		}
		return nil, err
	}

	return &SimulateResult{
		Success:    true,
		ReturnData: result,
	}, nil
}

// SimulateRequest 模拟请求参数
type SimulateRequest struct {
	From        common.Address
	To          common.Address
	Data        []byte
	Value       *big.Int
	BlockNumber uint64
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
