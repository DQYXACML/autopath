package fuzzer

import (
	"github.com/ethereum/go-ethereum/common"
)

// InvariantEvaluator 不变量评估器接口（避免循环依赖）
type InvariantEvaluator interface {
	// EvaluateTransaction 评估交易涉及的所有项目
	EvaluateTransaction(contracts []common.Address, state interface{}) []interface{}
}

// EmptyInvariantEvaluator 空实现，当不启用不变量检查时使用
type EmptyInvariantEvaluator struct{}

func (e *EmptyInvariantEvaluator) EvaluateTransaction(contracts []common.Address, state interface{}) []interface{} {
	return nil
}
