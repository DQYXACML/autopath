# Autopath - 链下监控系统

Autopath 是一个用于监控区块链不变量并检测潜在攻击的链下监控系统。

## 功能特性

### 1. 不变量管理
- 支持多种类型的不变量（比率型、阈值型、变化率型、自定义型）
- 灵活的项目配置管理
- 可扩展的评估器架构

### 2. 链下监控
- 实时区块监控
- 交易追踪（使用 CallTracer）
- 深度优先搜索识别受保护合约
- 并发处理提高性能

### 3. 模拟执行
- Fork 历史状态
- 重放攻击交易
- 记录 JUMPDEST 执行路径
- 路径分析和比较

### 4. 告警系统
- Webhook 通知
- 邮件告警
- 告警限流
- 历史记录

## 项目结构

```
autopath/
├── cmd/                    # 程序入口
│   ├── monitor/           # 监控服务
│   └── simulator/         # 模拟器工具
├── pkg/                   # 核心包
│   ├── invariants/        # 不变量管理
│   ├── monitor/           # 监控模块
│   └── simulator/         # 模拟执行
├── config/                # 配置文件
└── test/                  # 测试文件
```

## 快速开始

### 安装依赖

```bash
cd autopath
go mod init autopath
go get -u github.com/ethereum/go-ethereum
```

### 运行监控服务

```bash
# 使用默认配置
go run cmd/monitor/main.go

# 指定配置文件和 RPC
go run cmd/monitor/main.go \
  -rpc ws://localhost:8545 \
  -config pkg/invariants/configs/lodestar.json \
  -webhook https://your-webhook.com/alerts
```

### 运行交易模拟

```bash
# 模拟单个交易
go run cmd/simulator/main.go \
  -tx 0x... \
  -block 123456 \
  -analyze

# 比较两个交易
go run cmd/simulator/main.go \
  -tx 0xabc... \
  -compare 0xdef... \
  -block 123456
```

### 链上自动推送（Autopatch Oracle）

1) 合约侧授权：将用于推送的 EOA 地址授权为 Autopatch Oracle。

- 部署/配置脚本已内置授权流程（可通过环境变量传入推送地址）：
  - `scripts/Deploy_Lodestar_Firewall.s.sol` 会读取 `AUTOPATCH_ORACLE` 并调用 `ParamCheckModule.setAutopatchOracle(oracle, true)`。

2) 启用链下推送并指定 ParamCheckModule 地址与私钥：

```bash
go run cmd/monitor/main.go \
  -rpc ws://127.0.0.1:8545 \
  -config pkg/invariants/configs/lodestar.json \
  -oracle.enabled \
  -oracle.module 0xYourParamCheckModuleAddress \
  -oracle.pk $PRIVATE_KEY \
  -oracle.chainid 31337 \
  -oracle.threshold 0.8 \
  -oracle.batch 1 \
  -oracle.flush_interval 30s \
  -oracle.max_rules 20
```

- 推送逻辑：Fuzzing 发现满足阈值的有效参数后，自动调用 `ParamCheckModule.updateFromAutopatch(project, funcSig, summaries, threshold)` 写入规则。
- 说明：当前链上 `detect` 仅支持静态参数类型（uint256/int256/address/bool/bytes32）。动态类型（bytes/string/数组）仍按照偏移字读取，尚未在链上解码。


## 配置说明

### Lodestar 不变量配置

位于 `pkg/invariants/configs/lodestar.json`：

1. **sGLP/plvGLP 比率监控**
   - 检测价格操纵攻击
   - 阈值: 1.5

2. **预言机价格变化检测**
   - 监控价格突变
   - 阈值: 20%

3. **市场利用率监控**
   - 防止异常借贷
   - 阈值: 95%

4. **借款集中度风险**
   - 监控大户行为
   - 单一借款人限制: 30%

5. **递归借贷检测**
   - 识别攻击模式
   - 最大递归深度: 5

## API 说明

### 监控器 API

```go
// 创建监控器
monitor, err := monitor.NewBlockchainMonitor(rpcURL, registry)

// 启动监控
err := monitor.Start(ctx)

// 停止监控
monitor.Stop()
```

### 模拟器 API

```go
// 创建模拟器
sim, err := simulator.NewEVMSimulator(rpcURL)

// 重放交易
result, err := sim.ForkAndReplay(ctx, blockNumber, txHash)

// 分析路径
analyzer := simulator.NewPathAnalyzer()
analysis := analyzer.AnalyzePath(result)
```

## 开发指南

### 添加新的不变量

1. 在配置文件中定义不变量：
```json
{
  "id": "my-invariant",
  "name": "My Custom Invariant",
  "type": "custom",
  "parameters": {...}
}
```

2. 注册评估器：
```go
registry.RegisterEvaluator("my-invariant", func(state *ChainState) (bool, *ViolationDetail) {
    // 实现检查逻辑
    return true, nil
})
```

### 扩展监控功能

1. 实现新的追踪器
2. 添加状态读取器
3. 扩展告警渠道

## 测试

```bash
# 运行所有测试
go test ./...

# 运行特定包测试
go test ./pkg/invariants

# 运行基准测试
go test -bench=. ./pkg/monitor
```

## 性能优化

- 使用并发处理交易
- 批量获取区块数据
- 缓存常用状态
- 限流告警通知

## 注意事项

1. 确保 RPC 节点支持 `debug_traceTransaction`
2. 监控大量合约时注意资源消耗
3. 设置合理的告警限流避免过多通知
4. 定期清理历史数据

## License

MIT
