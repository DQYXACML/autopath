package local

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// LazyStateProvider 用于按需从RPC拉齐缺失状态
type LazyStateProvider interface {
	GetBalance(addr common.Address) (*big.Int, error)
	GetNonce(addr common.Address) (uint64, error)
	GetCode(addr common.Address) ([]byte, error)
	GetStorage(addr common.Address, slot common.Hash) (common.Hash, error)
}

// RPCStateProvider 通过RPC读取链上状态
type RPCStateProvider struct {
	rpcClient     *rpc.Client
	blockNumberFn func() *big.Int
}

// NewRPCStateProvider 创建RPC状态提供者
func NewRPCStateProvider(rpcClient *rpc.Client, blockNumberFn func() *big.Int) *RPCStateProvider {
	return &RPCStateProvider{
		rpcClient:     rpcClient,
		blockNumberFn: blockNumberFn,
	}
}

func (p *RPCStateProvider) blockParam() string {
	if p == nil {
		return "latest"
	}
	if p.blockNumberFn == nil {
		return "latest"
	}
	bn := p.blockNumberFn()
	if bn == nil {
		return "latest"
	}
	return hexutil.EncodeBig(bn)
}

func (p *RPCStateProvider) GetBalance(addr common.Address) (*big.Int, error) {
	if p == nil || p.rpcClient == nil {
		return nil, fmt.Errorf("rpc client not configured")
	}
	var result string
	if err := p.rpcClient.CallContext(context.Background(), &result, "eth_getBalance", addr.Hex(), p.blockParam()); err != nil {
		return nil, err
	}
	return decodeQuantityToBig(result)
}

func (p *RPCStateProvider) GetNonce(addr common.Address) (uint64, error) {
	if p == nil || p.rpcClient == nil {
		return 0, fmt.Errorf("rpc client not configured")
	}
	var result string
	if err := p.rpcClient.CallContext(context.Background(), &result, "eth_getTransactionCount", addr.Hex(), p.blockParam()); err != nil {
		return 0, err
	}
	return decodeQuantityToUint64(result)
}

func (p *RPCStateProvider) GetCode(addr common.Address) ([]byte, error) {
	if p == nil || p.rpcClient == nil {
		return nil, fmt.Errorf("rpc client not configured")
	}
	var result string
	if err := p.rpcClient.CallContext(context.Background(), &result, "eth_getCode", addr.Hex(), p.blockParam()); err != nil {
		return nil, err
	}
	if result == "" || result == "0x" {
		return nil, nil
	}
	return common.FromHex(result), nil
}

func (p *RPCStateProvider) GetStorage(addr common.Address, slot common.Hash) (common.Hash, error) {
	if p == nil || p.rpcClient == nil {
		return common.Hash{}, fmt.Errorf("rpc client not configured")
	}
	var result string
	if err := p.rpcClient.CallContext(context.Background(), &result, "eth_getStorageAt", addr.Hex(), slot.Hex(), p.blockParam()); err != nil {
		return common.Hash{}, err
	}
	if result == "" {
		return common.Hash{}, nil
	}
	return common.HexToHash(result), nil
}

func decodeQuantityToBig(value string) (*big.Int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" || raw == "0x" {
		return big.NewInt(0), nil
	}
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		return hexutil.DecodeBig(raw)
	}
	bn, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		log.Printf("[LazyState] 解析余额失败: %s", value)
		return big.NewInt(0), nil
	}
	return bn, nil
}

func decodeQuantityToUint64(value string) (uint64, error) {
	raw := strings.TrimSpace(value)
	if raw == "" || raw == "0x" {
		return 0, nil
	}
	if strings.HasPrefix(raw, "0x") || strings.HasPrefix(raw, "0X") {
		return hexutil.DecodeUint64(raw)
	}
	bn, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		log.Printf("[LazyState] 解析nonce失败: %s", value)
		return 0, nil
	}
	return bn.Uint64(), nil
}
