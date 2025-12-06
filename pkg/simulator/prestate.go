package simulator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// AccountOverride 表示 state override 中单个账户的覆盖信息
type AccountOverride struct {
	Balance string            `json:"balance,omitempty"`
	Nonce   string            `json:"nonce,omitempty"`
	Code    string            `json:"code,omitempty"`
	State   map[string]string `json:"state,omitempty"`
}

// StateOverride 表示调用 debug_traceCall 时的状态覆盖
type StateOverride map[string]*AccountOverride

// BuildStateOverride 基于 prestateTracer 输出构造执行前的状态覆盖
func (s *EVMSimulator) BuildStateOverride(ctx context.Context, txHash common.Hash) (StateOverride, error) {
	var raw json.RawMessage
	if err := s.rpcClient.CallContext(ctx, &raw, "debug_traceTransaction", txHash, map[string]interface{}{
		"tracer": "prestateTracer",
	}); err != nil {
		return nil, fmt.Errorf("failed to get prestate via tracer: %w", err)
	}

	type prestateAccount struct {
		Balance string            `json:"balance"`
		Nonce   json.RawMessage   `json:"nonce"`
		Code    string            `json:"code"`
		State   map[string]string `json:"storage"`
	}

	var prestate map[string]prestateAccount
	if err := json.Unmarshal(raw, &prestate); err != nil {
		return nil, fmt.Errorf("failed to unmarshal prestate: %w", err)
	}

	overrides := make(StateOverride, len(prestate))
	for addr, account := range prestate {
		override := &AccountOverride{}

		if account.Balance != "" {
			override.Balance = normalizeNumericString(account.Balance)
		}

		if len(account.Nonce) > 0 {
			nonceHex, err := parseNonceHex(account.Nonce)
			if err != nil {
				return nil, fmt.Errorf("failed to parse nonce for %s: %w", addr, err)
			}
			override.Nonce = nonceHex
		}

		if account.Code != "" {
			override.Code = strings.ToLower(account.Code)
		}

		if len(account.State) > 0 {
			state := make(map[string]string, len(account.State))
			for slot, value := range account.State {
				state[strings.ToLower(slot)] = normalizeNumericString(value)
			}
			override.State = state
		}

		// 仅在存在有效字段时记录，否则跳过该账户
		if override.Balance != "" || override.Nonce != "" || override.Code != "" || len(override.State) > 0 {
			overrides[strings.ToLower(addr)] = override
		}
	}

	//  补充本地已部署合约的代码
	// 处理场景：攻击合约通过 anvil_setCode 注入但 prestateTracer 未包含
	for addr, override := range overrides {
		if override.Code == "" || override.Code == "0x" {
			// 查询本地节点上的合约代码
			var localCode string
			if err := s.rpcClient.CallContext(ctx, &localCode, "eth_getCode", addr, "latest"); err == nil {
				if localCode != "" && localCode != "0x" && len(localCode) > 2 {
					override.Code = strings.ToLower(localCode)
					log.Printf("[StateOverride]  从本地节点补充合约代码: %s (size=%d bytes)",
						addr, (len(localCode)-2)/2)
				}
			}
		}
	}

	if len(overrides) > 0 {
		accountWithCode := 0
		totalSlots := 0
		for _, ov := range overrides {
			if ov == nil {
				continue
			}
			if ov.Code != "" && ov.Code != "0x" {
				accountWithCode++
			}
			totalSlots += len(ov.State)
		}
		log.Printf("[StateOverride]  构造完成 (accounts=%d, slots=%d, withCode=%d)", len(overrides), totalSlots, accountWithCode)
	}

	return overrides, nil
}

func parseNonceHex(raw json.RawMessage) (string, error) {
	data := bytes.TrimSpace(raw)
	if len(data) == 0 {
		return "0x0", nil
	}

	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return "", err
		}
		return normalizeNumericString(s), nil
	}

	var num uint64
	if err := json.Unmarshal(data, &num); err == nil {
		return fmt.Sprintf("0x%x", num), nil
	}

	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		return normalizeNumericString(s), nil
	}

	return "", fmt.Errorf("unsupported nonce format: %s", string(data))
}

func normalizeNumericString(value string) string {
	if value == "" {
		return "0x0"
	}

	lowered := strings.ToLower(value)
	if strings.HasPrefix(lowered, "0x") {
		if lowered == "0x" {
			return "0x0"
		}
		return lowered
	}

	num := new(big.Int)
	if _, ok := num.SetString(value, 10); ok {
		return fmt.Sprintf("0x%x", num)
	}

	// 既不是十六进制也不是十进制，直接返回原始值（保持向后兼容）
	return value
}
