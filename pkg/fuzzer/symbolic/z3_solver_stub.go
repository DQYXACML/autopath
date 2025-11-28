// +build !z3

package symbolic

import (
	"context"
	"errors"
	"time"
)

// Z3Solver Z3 SMT求解器封装(stub版本 - Z3未启用)
type Z3Solver struct {
	config *SymbolicConfig
	stats  Z3Stats
}

// Z3Stats Z3求解器统计
type Z3Stats struct {
	TotalSolves      int
	SuccessfulSolves int
	FailedSolves     int
	TimeoutSolves    int
	TotalSolveTime   time.Duration
}

// NewZ3Solver 创建Z3求解器(stub - 返回错误)
func NewZ3Solver(config *SymbolicConfig) (*Z3Solver, error) {
	return nil, errors.New("Z3 solver not available - rebuild with '-tags z3' to enable")
}

// Close 关闭Z3求解器(stub)
func (zs *Z3Solver) Close() {
	// No-op
}

// SolveConstraints 使用Z3求解约束(stub - 返回错误)
func (zs *Z3Solver) SolveConstraints(
	ctx context.Context,
	constraints []PathConstraint,
) ([]ConstraintSolution, error) {
	return nil, errors.New("Z3 solver not available")
}

// GetStatistics 获取统计信息(stub)
func (zs *Z3Solver) GetStatistics() Z3Stats {
	return Z3Stats{}
}

// CanHandle 检查Z3是否能处理给定的约束(stub)
func (zs *Z3Solver) CanHandle(constraints []PathConstraint) bool {
	return false
}

// ShouldUseZ3 根据配置和约束特征判断是否应使用Z3
func ShouldUseZ3(config *SymbolicConfig, constraints []PathConstraint) bool {
	if config == nil || !config.Enabled {
		return false
	}

	mode := config.Solver.Strategy
	if mode == "local" {
		return false
	}
	if mode == "z3" {
		return true
	}
	if mode == "hybrid" {
		// hybrid模式: 检查约束复杂度
		for _, c := range constraints {
			if c.Type == ConstraintMOD || c.Type == ConstraintAND ||
				c.Type == ConstraintOR || c.Type == ConstraintMASK {
				return true
			}
		}
		// 简单约束用本地求解器
		return false
	}

	return false
}
