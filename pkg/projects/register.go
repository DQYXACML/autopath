package projects

import (
	"context"
	"log"
	"strings"
)

// Registrar 定义项目注册函数签名
type Registrar func(context.Context, Dependencies) error

var (
	projectRegistrars = map[string]Registrar{}
)

// RegisterProjectRegistrar 注册项目对应的评估器构建函数
func RegisterProjectRegistrar(projectID string, registrar Registrar) {
	key := strings.ToLower(projectID)
	if key == "" || registrar == nil {
		return
	}
	projectRegistrars[key] = registrar
}

// Register 根据配置的 ProjectID 调用对应注册器
func Register(ctx context.Context, deps Dependencies) error {
	if deps.Config == nil {
		return nil
	}
	key := strings.ToLower(deps.Config.ProjectID)
	if key == "" {
		log.Printf("Project config missing ProjectID, skip project-specific registrars")
		return nil
	}
	registrar, ok := projectRegistrars[key]
	if !ok {
		alias := key
		for {
			idx := strings.LastIndex(alias, "-")
			if idx <= 0 {
				break
			}
			alias = alias[:idx]
			if reg, aliasOk := projectRegistrars[alias]; aliasOk {
				log.Printf("No project-specific registrar for %s, fallback to alias %s", deps.Config.ProjectID, alias)
				registrar = reg
				ok = true
				break
			}
		}
	}
	if !ok {
		log.Printf("No project-specific registrar found for %s, skip additional evaluators", deps.Config.ProjectID)
		return nil
	}
	return registrar(ctx, deps)
}
