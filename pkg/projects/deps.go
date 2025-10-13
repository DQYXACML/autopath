package projects

import (
	"context"

	"autopath/pkg/invariants"
	"autopath/pkg/monitor"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
)

// Dependencies 聚合项目注册器所需的外部依赖
type Dependencies struct {
	Registry  *invariants.Registry
	Config    *ProjectConfig
	EthClient *ethclient.Client
	RPCClient *rpc.Client
	Tracer    *monitor.TransactionTracer
}

// RegisterOptions 允许针对实验传入额外的上下文
type RegisterOptions struct {
	Context context.Context
}
