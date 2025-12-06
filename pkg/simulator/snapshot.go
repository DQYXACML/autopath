package simulator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// isZeroHex 判断十六进制字符串是否表示0（兼容0x、0x0、0x00等形式）
func isZeroHex(v string) bool {
	if v == "" {
		return true
	}
	l := strings.ToLower(strings.TrimPrefix(v, "0x"))
	if l == "" {
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] != '0' {
			return false
		}
	}
	return true
}

// CallSnapshot 记录某次CALL时的完整状态快照
type CallSnapshot struct {
	Depth         int               `json:"depth"`         // 调用深度
	Caller        common.Address    `json:"caller"`        // 调用者地址
	Callee        common.Address    `json:"callee"`        // 被调用者地址
	CallerBalance string            `json:"callerBalance"` // 调用者余额
	CallerStorage map[string]string `json:"callerStorage"` // 调用者storage状态
	CalleeBalance string            `json:"calleeBalance"` // 被调用者余额
	CalleeStorage map[string]string `json:"calleeStorage"` // 被调用者storage状态
	Input         string            `json:"input"`         // 调用数据
	Value         string            `json:"value"`         // 转账金额
	JumpDestIndex int               `json:"jumpDestIndex"` // 此时的JUMPDEST计数
	Selector      string            `json:"selector"`      // 函数选择器
}

// SnapshotTracerResult 增强版tracer返回的结果
type SnapshotTracerResult struct {
	JumpDests         []uint64           `json:"jumpDests"`
	ContractJumpDests []ContractJumpDest `json:"contractJumpDests"`
	CallSnapshots     []CallSnapshot     `json:"callSnapshots"`
	Success           bool               `json:"success"`
	GasUsed           uint64             `json:"gasUsed"`
	ReturnData        string             `json:"returnData"`
	Error             string             `json:"error,omitempty"`
}

// ExtractSnapshotForProtectedCall 从trace中提取调用受保护合约时的状态快照
// callIndex: 第几次调用受保护合约（0开始，用于循环攻击场景）
func (s *EVMSimulator) ExtractSnapshotForProtectedCall(
	ctx context.Context,
	txHash common.Hash,
	protectedContract common.Address,
	callIndex int,
) (*CallSnapshot, error) {
	protectedAddr := strings.ToLower(protectedContract.Hex())

	log.Printf("[Snapshot] 提取状态快照: txHash=%s, protectedContract=%s, callIndex=%d",
		txHash.Hex(), protectedAddr, callIndex)

	// 使用增强版tracer重放交易，记录每次CALL时的状态
	tracerCode := fmt.Sprintf(`{
		data: {
			jumpDests: [],
			contractJumpDests: [],
			callSnapshots: [],
			protectedContract: "%s",
			callStack: [],
			gasUsed: 0,
			success: true,
			returnData: "",
			currentStorageCache: {},
			debugCalls: [],
			stepCount: 0,
			callOpcodeCount: 0
		},
		formatHex: function(value) {
			//  修复: 处理bigint类型 (Anvil的stack.peek返回bigint)
			var hex;
			if (typeof value === 'bigint') {
				hex = "0x" + value.toString(16);
			} else {
				hex = toHex(value);
			}
			if (hex === "0x") return "0x0";
			var body = hex.slice(2);
			if (body.length === 0) return "0x0";
			if (body.length %% 2 === 1) body = "0" + body;
			return "0x" + body.toLowerCase();
		},
		formatAddress: function(value) {
			//  修复: 处理bigint类型 (Anvil的stack.peek返回bigint)
			var hex;
			if (typeof value === 'bigint') {
				hex = "0x" + value.toString(16);
			} else {
				hex = toHex(value);
			}
			var body = hex.slice(2).toLowerCase();
			while (body.length < 40) body = "0" + body;
			if (body.length > 40) body = body.slice(body.length - 40);
			return "0x" + body;
		},
		formatWord: function(value) {
			var body = this.formatHex(value).slice(2);
			while (body.length < 64) body = "0" + body;
			if (body.length > 64) body = body.slice(body.length - 64);
			return "0x" + body;
		},
		getStorageSlots: function(db, addr, slots) {
			var result = {};
			for (var i = 0; i < slots.length; i++) {
				var slot = slots[i];
				var value = db.getState(addr, slot);
				result[this.formatWord(slot)] = this.formatWord(value);
			}
			return result;
		},
		fault: function(log, db) {
			this.data.success = false;
			if (log.getError) this.data.error = log.getError();
		},
		step: function(log, db) {
			this.data.stepCount++;
			var currentContract = toHex(log.contract.getAddress());
			var currentLower = currentContract.toLowerCase();
			var opName = log.op.toString();

			// 记录JUMPDEST
			if (opName === "JUMPDEST") {
				this.data.jumpDests.push(log.getPC());
				this.data.contractJumpDests.push({
					contract: currentContract,
					pc: log.getPC()
				});
			}

			// 记录SSTORE以跟踪storage变化
			if (opName === "SSTORE") {
				var slot = this.formatWord(log.stack.peek(0));
				var value = this.formatWord(log.stack.peek(1));
				if (!this.data.currentStorageCache[currentLower]) {
					this.data.currentStorageCache[currentLower] = {};
				}
				this.data.currentStorageCache[currentLower][slot] = value;
			}

			// 在CALL类指令时记录状态快照
			if (opName === "CALL" || opName === "DELEGATECALL" || opName === "STATICCALL" || opName === "CALLCODE") {
				this.data.callOpcodeCount++;
				var targetAddr;
				var callValue = "0x0";
				var inputOffset, inputSize;

				if (opName === "CALL" || opName === "CALLCODE") {
					// CALL: gas, addr, value, argsOffset, argsSize, retOffset, retSize
					targetAddr = this.formatAddress(log.stack.peek(1));
					callValue = this.formatHex(log.stack.peek(2));
					inputOffset = parseInt(this.formatHex(log.stack.peek(3)), 16);
					inputSize = parseInt(this.formatHex(log.stack.peek(4)), 16);
				} else {
					// DELEGATECALL/STATICCALL: gas, addr, argsOffset, argsSize, retOffset, retSize
					targetAddr = this.formatAddress(log.stack.peek(1));
					inputOffset = parseInt(this.formatHex(log.stack.peek(2)), 16);
					inputSize = parseInt(this.formatHex(log.stack.peek(3)), 16);
				}

				var targetLower = targetAddr.toLowerCase();

				// 记录所有CALL用于调试（只记录前20个）
				if (this.data.debugCalls.length < 20) {
					this.data.debugCalls.push({
						op: opName,
						target: targetLower,
						protected: this.data.protectedContract,
						match: targetLower === this.data.protectedContract
					});
				}

				// 检查是否是调用受保护合约
				if (targetLower === this.data.protectedContract) {
					var callerAddr = log.contract.getAddress();
					var callerBalance = this.formatHex(db.getBalance(callerAddr));

					// 获取调用数据的前4字节作为selector
					var selector = "0x00000000";
					if (inputSize >= 4) {
						var mem = log.memory.slice(inputOffset, inputOffset + 4);
						if (mem && mem.length >= 4) {
							selector = toHex(mem);
						}
					}

					// 获取caller当前的storage状态（从缓存+链上状态合并）
					var callerStorage = {};
					var callerLower = toHex(callerAddr).toLowerCase();
					if (this.data.currentStorageCache[callerLower]) {
						for (var slot in this.data.currentStorageCache[callerLower]) {
							callerStorage[slot] = this.data.currentStorageCache[callerLower][slot];
						}
					}

					// 记录被调用合约的storage状态
					var calleeStorage = {};
					if (this.data.currentStorageCache[targetLower]) {
						for (var slot in this.data.currentStorageCache[targetLower]) {
							calleeStorage[slot] = this.data.currentStorageCache[targetLower][slot];
						}
					}

					var snapshot = {
						depth: log.getDepth(),
						caller: toHex(callerAddr),
						callee: targetAddr,
						callerBalance: callerBalance,
						callerStorage: callerStorage,
						calleeBalance: this.formatHex(db.getBalance(toAddress(targetAddr))),
						calleeStorage: calleeStorage,
						input: selector,
						value: callValue,
						jumpDestIndex: this.data.jumpDests.length,
						selector: selector
					};

					this.data.callSnapshots.push(snapshot);
				}
			}
		},
		enter: function(callFrame) {
			var from = toHex(callFrame.getFrom());
			var to = toHex(callFrame.getTo());
			var toLower = to.toLowerCase();
			var fromLower = from.toLowerCase();

			this.data.callStack.push({
				from: from,
				to: to
			});

			//  关键修复：在enter回调中捕获对受保护合约的调用
			// enter回调会在每次子调用发生时被触发，包括嵌套的子调用
			if (this.data.debugCalls.length < 50) {
				this.data.debugCalls.push({
					op: "ENTER",
					target: toLower,
					protected: this.data.protectedContract,
					match: toLower === this.data.protectedContract,
					from: fromLower
				});
			}

			// 如果调用目标是受保护合约，记录快照
			if (toLower === this.data.protectedContract) {
				var value = "0x0";
				//  修复: callFrame.getValue() 返回bigint, 需要特殊处理
				try {
					var rawValue = callFrame.getValue();
					if (rawValue !== undefined && rawValue !== null) {
						if (typeof rawValue === 'bigint') {
							value = "0x" + rawValue.toString(16);
						} else if (typeof rawValue === 'number') {
							value = "0x" + rawValue.toString(16);
						} else {
							value = toHex(rawValue);
						}
					}
				} catch(ve) {
					value = "0x0";
				}

				var input = "0x";
				if (callFrame.getInput) {
					input = toHex(callFrame.getInput());
				}
				var selector = "0x00000000";
				if (input.length >= 10) {
					selector = input.slice(0, 10);
				}

				// 获取caller的storage状态
				var callerStorage = {};
				if (this.data.currentStorageCache[fromLower]) {
					for (var slot in this.data.currentStorageCache[fromLower]) {
						callerStorage[slot] = this.data.currentStorageCache[fromLower][slot];
					}
				}

				var calleeStorage = {};
				if (this.data.currentStorageCache[toLower]) {
					for (var slot in this.data.currentStorageCache[toLower]) {
						calleeStorage[slot] = this.data.currentStorageCache[toLower][slot];
					}
				}

				var snapshot = {
					depth: this.data.callStack.length,
					caller: from,
					callee: to,
					callerBalance: "0x0", // enter回调中无法获取db
					callerStorage: callerStorage,
					calleeBalance: "0x0",
					calleeStorage: calleeStorage,
					input: selector,
					value: value,
					jumpDestIndex: this.data.jumpDests.length,
					selector: selector
				};

				this.data.callSnapshots.push(snapshot);
			}
		},
		exit: function(result) {
			this.data.callStack.pop();
		},
		result: function(ctx, db) {
			this.data.gasUsed = ctx.gasUsed;
			if (ctx.type === "REVERT") {
				this.data.success = false;
			}
			this.data.returnData = toHex(ctx.output);
			return this.data;
		}
	}`, protectedAddr)

	var result json.RawMessage
	err := s.rpcClient.CallContext(ctx, &result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": tracerCode,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to trace transaction for snapshot: %w", err)
	}

	// 首先解析调试信息
	var debugResult struct {
		DebugCalls []struct {
			Op        string `json:"op"`
			Target    string `json:"target"`
			Protected string `json:"protected"`
			Match     bool   `json:"match"`
		} `json:"debugCalls"`
		StepCount       int `json:"stepCount"`
		CallOpcodeCount int `json:"callOpcodeCount"`
	}
	if err := json.Unmarshal(result, &debugResult); err == nil {
		log.Printf("[Snapshot] 调试: stepCount=%d, callOpcodeCount=%d, debugCalls=%d",
			debugResult.StepCount, debugResult.CallOpcodeCount, len(debugResult.DebugCalls))
		if debugResult.StepCount == 0 {
			log.Printf("[Snapshot] 调试:   step函数未被调用！tracer可能有语法错误")
		}
		if debugResult.CallOpcodeCount == 0 && debugResult.StepCount > 0 {
			log.Printf("[Snapshot] 调试:   没有发现CALL/STATICCALL/DELEGATECALL指令")
		}
		if len(debugResult.DebugCalls) == 0 && debugResult.CallOpcodeCount > 0 {
			log.Printf("[Snapshot] 调试:   发现了%d个CALL指令但没有记录debugCalls", debugResult.CallOpcodeCount)
			// 打印原始JSON的前1500字符用于调试
			rawStr := string(result)
			if len(rawStr) > 1500 {
				rawStr = rawStr[:1500]
			}
			log.Printf("[Snapshot] 调试: 原始JSON前1500字符: %s", rawStr)
		}
		for i, call := range debugResult.DebugCalls {
			log.Printf("[Snapshot]   [%d] %s -> %s (protected=%s, match=%v)",
				i, call.Op, call.Target, call.Protected, call.Match)
		}
	}

	// 解析结果
	var traceResult SnapshotTracerResult
	if err := json.Unmarshal(result, &traceResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal snapshot trace result: %w", err)
	}

	log.Printf("[Snapshot] 找到 %d 次调用受保护合约", len(traceResult.CallSnapshots))

	if len(traceResult.CallSnapshots) == 0 {
		return nil, fmt.Errorf("no calls to protected contract found in transaction")
	}

	// 选择指定索引的调用
	if callIndex >= len(traceResult.CallSnapshots) {
		log.Printf("[Snapshot]  callIndex=%d 超出范围，使用最后一次调用 (index=%d)",
			callIndex, len(traceResult.CallSnapshots)-1)
		callIndex = len(traceResult.CallSnapshots) - 1
	}

	snapshot := &traceResult.CallSnapshots[callIndex]
	log.Printf("[Snapshot]  已提取调用时状态快照 (caller=%s, balance=%s, selector=%s, jumpDestIndex=%d)",
		snapshot.Caller.Hex(), snapshot.CallerBalance, snapshot.Selector, snapshot.JumpDestIndex)

	return snapshot, nil
}

// BuildStateOverrideFromSnapshot 将状态快照合并到现有的StateOverride
// 确保调用者（攻击合约）有正确的余额和storage状态
func BuildStateOverrideFromSnapshot(
	baseOverride StateOverride,
	snapshot *CallSnapshot,
) StateOverride {
	if baseOverride == nil {
		baseOverride = make(StateOverride)
	}

	if snapshot == nil {
		return baseOverride
	}

	callerAddr := strings.ToLower(snapshot.Caller.Hex())

	// 获取或创建caller的override
	callerOverride := baseOverride[callerAddr]
	if callerOverride == nil {
		callerOverride = &AccountOverride{}
		baseOverride[callerAddr] = callerOverride
	}

	// 注入调用者余额
	if !isZeroHex(snapshot.CallerBalance) {
		callerOverride.Balance = snapshot.CallerBalance
		log.Printf("[Snapshot]  注入caller余额: %s = %s", callerAddr, snapshot.CallerBalance)
	}

	// 注入调用者storage状态
	if len(snapshot.CallerStorage) > 0 {
		if callerOverride.State == nil {
			callerOverride.State = make(map[string]string)
		}
		for slot, value := range snapshot.CallerStorage {
			callerOverride.State[slot] = value
		}
		log.Printf("[Snapshot]  注入caller storage: %d slots", len(snapshot.CallerStorage))
	}

	// 同步被调用合约的余额与存储，确保目标合约状态与调用时刻一致
	calleeAddr := strings.ToLower(snapshot.Callee.Hex())
	if calleeAddr != "" && calleeAddr != "0x0000000000000000000000000000000000000000" {
		calleeOverride := baseOverride[calleeAddr]
		if calleeOverride == nil {
			calleeOverride = &AccountOverride{}
			baseOverride[calleeAddr] = calleeOverride
		}

		if !isZeroHex(snapshot.CalleeBalance) {
			calleeOverride.Balance = snapshot.CalleeBalance
			log.Printf("[Snapshot]  注入callee余额: %s = %s", calleeAddr, snapshot.CalleeBalance)
		}

		if len(snapshot.CalleeStorage) > 0 {
			if calleeOverride.State == nil {
				calleeOverride.State = make(map[string]string)
			}
			for slot, value := range snapshot.CalleeStorage {
				calleeOverride.State[slot] = value
			}
			log.Printf("[Snapshot]  注入callee storage: %d slots", len(snapshot.CalleeStorage))
		}
	}

	return baseOverride
}

// ExtractAllCallSnapshots 提取交易中所有调用受保护合约的快照
// 用于循环攻击场景的分析
func (s *EVMSimulator) ExtractAllCallSnapshots(
	ctx context.Context,
	txHash common.Hash,
	protectedContract common.Address,
) ([]*CallSnapshot, error) {
	// 先提取第一个快照（会执行完整的trace）
	// 这里我们重新实现一个返回所有快照的版本

	protectedAddr := strings.ToLower(protectedContract.Hex())

	tracerCode := fmt.Sprintf(`{
		data: {
			callSnapshots: [],
			protectedContract: "%s",
			currentStorageCache: {}
		},
		formatHex: function(value) {
			//  修复: 处理bigint类型 (Anvil的stack.peek返回bigint)
			var hex;
			if (typeof value === 'bigint') {
				hex = "0x" + value.toString(16);
			} else {
				hex = toHex(value);
			}
			if (hex === "0x") return "0x0";
			var body = hex.slice(2);
			if (body.length === 0) return "0x0";
			if (body.length %% 2 === 1) body = "0" + body;
			return "0x" + body.toLowerCase();
		},
		formatAddress: function(value) {
			//  修复: 处理bigint类型 (Anvil的stack.peek返回bigint)
			var hex;
			if (typeof value === 'bigint') {
				hex = "0x" + value.toString(16);
			} else {
				hex = toHex(value);
			}
			var body = hex.slice(2).toLowerCase();
			while (body.length < 40) body = "0" + body;
			if (body.length > 40) body = body.slice(body.length - 40);
			return "0x" + body;
		},
		formatWord: function(value) {
			var body = this.formatHex(value).slice(2);
			while (body.length < 64) body = "0" + body;
			if (body.length > 64) body = body.slice(body.length - 64);
			return "0x" + body;
		},
		fault: function(log, db) {},
		step: function(log, db) {
			var currentContract = toHex(log.contract.getAddress());
			var currentLower = currentContract.toLowerCase();
			var opName = log.op.toString();

			if (opName === "SSTORE") {
				var slot = this.formatWord(log.stack.peek(0));
				var value = this.formatWord(log.stack.peek(1));
				if (!this.data.currentStorageCache[currentLower]) {
					this.data.currentStorageCache[currentLower] = {};
				}
				this.data.currentStorageCache[currentLower][slot] = value;
			}

			if (opName === "CALL" || opName === "DELEGATECALL" || opName === "STATICCALL" || opName === "CALLCODE") {
				var targetAddr;
				var callValue = "0x0";
				var inputOffset = 0;
				var inputSize = 0;

				if (opName === "CALL" || opName === "CALLCODE") {
					targetAddr = this.formatAddress(log.stack.peek(1));
					callValue = this.formatHex(log.stack.peek(2));
					inputOffset = parseInt(this.formatHex(log.stack.peek(3)), 16);
					inputSize = parseInt(this.formatHex(log.stack.peek(4)), 16);
				} else {
					targetAddr = this.formatAddress(log.stack.peek(1));
					inputOffset = parseInt(this.formatHex(log.stack.peek(2)), 16);
					inputSize = parseInt(this.formatHex(log.stack.peek(3)), 16);
				}

				var targetLower = targetAddr.toLowerCase();

				if (targetLower === this.data.protectedContract) {
					var callerAddr = log.contract.getAddress();
					var callerBalance = this.formatHex(db.getBalance(callerAddr));
					var callerStorage = {};
					var callerLower = toHex(callerAddr).toLowerCase();

					if (this.data.currentStorageCache[callerLower]) {
						for (var slot in this.data.currentStorageCache[callerLower]) {
							callerStorage[slot] = this.data.currentStorageCache[callerLower][slot];
						}
					}

					// 尝试解析selector
					var selector = "0x00000000";
					if (inputSize >= 4) {
						var mem = log.memory.slice(inputOffset, inputOffset + 4);
						if (mem && mem.length >= 4) {
							selector = toHex(mem);
						}
					}

					var calleeStorage = {};
					if (this.data.currentStorageCache[targetLower]) {
						for (var slot in this.data.currentStorageCache[targetLower]) {
							calleeStorage[slot] = this.data.currentStorageCache[targetLower][slot];
						}
					}

					var snapshot = {
						depth: log.getDepth(),
						caller: toHex(callerAddr),
						callee: targetAddr,
						callerBalance: callerBalance,
						callerStorage: callerStorage,
						calleeBalance: this.formatHex(db.getBalance(toAddress(targetAddr))),
						calleeStorage: calleeStorage,
						value: callValue,
						selector: selector,
						input: selector
					};

					this.data.callSnapshots.push(snapshot);
				}
			}
		},
		enter: function(callFrame) {
			var from = toHex(callFrame.getFrom());
			var to = toHex(callFrame.getTo());
			var toLower = to.toLowerCase();
			var fromLower = from.toLowerCase();

			// 如果调用目标是受保护合约，记录快照
			if (toLower === this.data.protectedContract) {
				var value = "0x0";
				//  修复: callFrame.getValue() 返回bigint, 需要特殊处理
				try {
					var rawValue = callFrame.getValue();
					if (rawValue !== undefined && rawValue !== null) {
						if (typeof rawValue === 'bigint') {
							value = "0x" + rawValue.toString(16);
						} else if (typeof rawValue === 'number') {
							value = "0x" + rawValue.toString(16);
						} else {
							value = toHex(rawValue);
						}
					}
				} catch(ve) {
					value = "0x0";
				}

				var input = "0x";
				if (callFrame.getInput) {
					input = toHex(callFrame.getInput());
				}
				var selector = "0x00000000";
				if (input.length >= 10) {
					selector = input.slice(0, 10);
				}

				var calleeStorage = {};
				if (this.data.currentStorageCache[toLower]) {
					for (var slot in this.data.currentStorageCache[toLower]) {
						calleeStorage[slot] = this.data.currentStorageCache[toLower][slot];
					}
				}

				// 获取caller的storage状态
				var callerStorage = {};
				if (this.data.currentStorageCache[fromLower]) {
					for (var slot in this.data.currentStorageCache[fromLower]) {
						callerStorage[slot] = this.data.currentStorageCache[fromLower][slot];
					}
				}

				var snapshot = {
					depth: 0, // enter回调中无法获取深度
					caller: from,
					callee: to,
					callerBalance: "0x0", // enter回调中无法获取db
					callerStorage: callerStorage,
					value: value,
					calleeBalance: "0x0",
					calleeStorage: calleeStorage,
					selector: selector,
					input: selector
				};

				this.data.callSnapshots.push(snapshot);
			}
		},
		exit: function(result) {},
		result: function(ctx, db) {
			return this.data;
		}
	}`, protectedAddr)

	var result json.RawMessage
	err := s.rpcClient.CallContext(ctx, &result, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": tracerCode,
	})

	if err != nil {
		return nil, fmt.Errorf("failed to trace transaction for all snapshots: %w", err)
	}

	var traceResult struct {
		CallSnapshots []CallSnapshot `json:"callSnapshots"`
	}
	if err := json.Unmarshal(result, &traceResult); err != nil {
		return nil, fmt.Errorf("failed to unmarshal all snapshots result: %w", err)
	}

	snapshots := make([]*CallSnapshot, len(traceResult.CallSnapshots))
	for i := range traceResult.CallSnapshots {
		snapshots[i] = &traceResult.CallSnapshots[i]
	}

	log.Printf("[Snapshot] 提取到 %d 个调用快照", len(snapshots))
	return snapshots, nil
}
