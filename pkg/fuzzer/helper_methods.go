package fuzzer

// SetInvariantEvaluator 设置不变量评估器
// 外部可以通过此方法注入实际的invariants.Evaluator实现
func (f *CallDataFuzzer) SetInvariantEvaluator(evaluator InvariantEvaluator) {
	f.invariantEvaluator = evaluator
}

// EnableInvariantCheck 启用不变量检查
func (f *CallDataFuzzer) EnableInvariantCheck(enable bool) {
	f.enableInvariantCheck = enable
}

// IsInvariantCheckEnabled 检查是否启用了不变量检查
func (f *CallDataFuzzer) IsInvariantCheckEnabled() bool {
	return f.enableInvariantCheck
}
