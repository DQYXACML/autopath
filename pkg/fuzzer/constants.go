package fuzzer

const (
	similarityEpsilon          = 1e-6
	ruleGenMinSimilarity       = 0.6
	exprFallbackMinSimilarity  = 0.1
	exprFallbackMinSampleCount = 2

	// overlap召回通道：用于识别“核心路径命中但长度膨胀”的样本。
	// 这类样本仅用于链下候选规则导出，不直接进入链上推送。
	overlapRecallMinSimilarity = 0.95
	overlapCandidateMinAvgSim  = 0.90

	// 规则优先级分层阈值（按adjusted相似度）。
	rulePriorityHighSimilarity = 0.80
	rulePriorityMidSimilarity  = 0.60
)
