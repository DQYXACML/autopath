# 种子驱动模糊测试使用指南

## 概述

种子驱动模糊测试 (Seed-Driven Fuzzing) 是 Layer 1 的核心功能,通过使用已知的攻击参数作为种子,在其附近生成变异值,极大提升了模糊测试的效率和准确性。

## 核心优势

### 对比传统方法

**传统随机模糊测试**:
- 测试组合数: 120
- 有效结果: 0-2 个
- 耗时: 2-5秒
- 问题: 盲目测试,效率低下

**种子驱动模糊测试**:
- 测试组合数: 300
- 有效结果: 预计 10-30 个
- 耗时: 5-10秒
- 优势: 聚焦攻击参数附近,精准高效

### 变异策略

种子驱动生成器采用三层加权策略:

1. **种子驱动变异 (70%)**:
   - 数值类型: 生成 ±1%, ±2%, ±5%, ±10%, ±20%, ±50%, ±100% 的变异
   - 地址类型: bitflip (翻转1-2个比特)、nearby (±1, ±10, ±100, ±1000)
   - 字节类型: 字节级翻转

2. **随机探索 (20%)**:
   - 使用基础随机生成器探索其他可能性

3. **边界值测试 (10%)**:
   - 0, 1, 2, MAX 等边界值

## 配置方法

### 1. 准备种子数据

从攻击交易中提取关键参数值。例如 MIC 攻击:
- 参数0 (amount): `1000000000000000000` (1 ETH)
- 参数1 (address): `0x5FC8d32690cc91D4c39d9d3abcBD16989F875707`

### 2. 配置 JSON 文件

在不变量配置文件中添加 `seed_config` 部分:

```json
{
  "fuzzing_config": {
    "enabled": true,
    "threshold": 0.7,
    "max_variations": 300,
    "workers": 8,
    "seed_config": {
      "enabled": true,
      "attack_seeds": {
        "0": ["1000000000000000000"],
        "1": ["0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"]
      },
      "range_config": {
        "numeric_range_percent": [1, 2, 5, 10, 20, 50, 100],
        "address_mutation_types": ["original", "bitflip_1", "bitflip_2", "nearby"],
        "boundary_exploration": true
      },
      "weights": {
        "seed_based": 0.7,
        "random": 0.2,
        "boundary": 0.1
      }
    }
  }
}
```

### 3. 参数说明

#### attack_seeds
- 键: 参数索引 (从0开始)
- 值: 该参数的攻击值列表

支持多种数据类型:
```json
{
  "0": [1000000000000000000],           // 数值
  "1": ["0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"],  // 地址
  "2": [true],                           // 布尔
  "3": ["0xabcdef..."]                   // 字节
}
```

#### numeric_range_percent
数值类型的变异百分比列表。例如 `[1, 5, 10]` 表示:
- 种子值 1000 → 生成 1010 (1000 + 1%), 990 (1000 - 1%)
- 种子值 1000 → 生成 1050 (1000 + 5%), 950 (1000 - 5%)
- 种子值 1000 → 生成 1100 (1000 + 10%), 900 (1000 - 10%)

#### address_mutation_types
地址类型的变异方式:
- `original`: 保留原始地址
- `bitflip_1`: 翻转单个比特
- `bitflip_2`: 翻转两个比特
- `nearby`: 生成附近地址 (±1, ±10, ±100, ±1000)

#### weights
各策略的权重配置:
- `seed_based`: 种子驱动变异占比 (推荐 0.7)
- `random`: 随机探索占比 (推荐 0.2)
- `boundary`: 边界值测试占比 (推荐 0.1)

## 使用示例

### 场景1: MIC Token 攻击复现

1. **准备配置文件** (`pkg/invariants/configs/mic_seed.json`):

```json
{
  "fuzzing_config": {
    "seed_config": {
      "enabled": true,
      "attack_seeds": {
        "0": ["1000000000000000000"],
        "1": ["0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"]
      }
    }
  }
}
```

2. **启动 Monitor**:

```bash
cd autopath
./monitor -rpc ws://localhost:8545 \
  -config pkg/invariants/configs/mic_seed.json \
  -webhook http://localhost:9000/alerts \
  -oracle.enabled \
  -oracle.module 0x<ParamCheckModule地址> \
  -oracle.pk 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

3. **执行攻击测试**:

```bash
export PRIVATE_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
forge script test/MIC/scripts/ExploitLocal.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast -vvvv
```

4. **观察 Fuzzing 结果**:

Monitor 日志会显示:
```
[Fuzzer] Using seed-driven generation with 2 attack seeds
[SeedGen] Param #0: Generated 45 variations (type=uint256)
[SeedGen] Param #1: Generated 28 variations (type=address)
[SeedGen] Total combinations generated: 300
[Fuzzer] Found 15 valid combinations
```

### 场景2: 无种子数据的回退

如果某个参数没有种子数据,系统会自动回退到随机生成:

```json
{
  "attack_seeds": {
    "0": ["1000000000000000000"]
    // 参数1 没有种子,会使用随机生成
  }
}
```

日志输出:
```
[SeedGen] Param #0 has 1 seed(s)
[SeedGen] No seed for param #1, using base generator
```

### 场景3: 禁用种子驱动

如果需要回退到传统随机模糊测试:

```json
{
  "seed_config": {
    "enabled": false
  }
}
```

或完全移除 `seed_config` 配置。

## 变异示例

### 数值参数变异

**种子值**: `1000000000000000000` (1 ETH)

**生成的变异值** (部分):
```
1010000000000000000  (1000000000000000000 + 1%)
 990000000000000000  (1000000000000000000 - 1%)
1050000000000000000  (1000000000000000000 + 5%)
 950000000000000000  (1000000000000000000 - 5%)
1100000000000000000  (1000000000000000000 + 10%)
 900000000000000000  (1000000000000000000 - 10%)
1500000000000000000  (1000000000000000000 + 50%)
 500000000000000000  (1000000000000000000 - 50%)
2000000000000000000  (1000000000000000000 + 100%)
1000000000000000001  (1000000000000000000 + 1)
 999999999999999999  (1000000000000000000 - 1)
1000000000000000010  (1000000000000000000 + 10)
```

### 地址参数变异

**种子值**: `0x5FC8d32690cc91D4c39d9d3abcBD16989F875707`

**生成的变异值** (部分):
```
0x5FC8d32690cc91D4c39d9d3abcBD16989F875707  (original)
0x5FC8d32690cc91D4c39d9d3abcBD16989F875706  (bitflip 比特0)
0x5FC8d32690cc91D4c39d9d3abcBD16989F875705  (bitflip 比特1)
0x5FC8d32690cc91D4c39d9d3abcBD16989F875708  (nearby +1)
0x5FC8d32690cc91D4c39d9d3abcBD16989F875711  (nearby +10)
0x5FC8d32690cc91D4c39d9d3abcBD16989F8756A7  (nearby +100)
```

## 性能调优

### 阈值调整

根据需求调整相似度阈值:

```json
{
  "threshold": 0.7,        // 主阈值 (fuzzing 过滤)
  "min_similarity": 0.65   // 保存阈值 (结果输出)
}
```

**推荐配置**:
- 严格模式: `threshold: 0.8, min_similarity: 0.75`
- 平衡模式: `threshold: 0.7, min_similarity: 0.65`
- 宽松模式: `threshold: 0.6, min_similarity: 0.55`

### 变异数量调整

根据参数复杂度调整最大变异数:

```json
{
  "max_variations": 300  // 推荐 200-500
}
```

**选择指南**:
- 简单攻击 (1-2个参数): 200
- 中等复杂度 (3-4个参数): 300
- 高复杂度 (5+个参数): 500

### 权重微调

根据攻击特征调整策略权重:

```json
{
  "weights": {
    "seed_based": 0.8,  // 如果攻击参数非常关键
    "random": 0.15,     // 减少随机探索
    "boundary": 0.05    // 减少边界测试
  }
}
```

## 日志解读

### 成功示例

```
[Fuzzer] Using seed-driven generation with 2 attack seeds
[SeedGen] Param #0: Generated 45 variations (type=uint256)
[SeedGen] Param #1: Generated 28 variations (type=address)
[SeedGen] Total combinations generated: 300
[Fuzzer] Tested 300 combinations, found 15 valid
[Fuzzer] Found valid combination #1 with similarity 0.8234 (violations: 1)
[Fuzzer] Found valid combination #2 with similarity 0.8156 (violations: 1)
...
高相似度参数已保存到: ./fuzzing_results/mic/high_sim_20250117_143052_0xa1b2c3d4.json
```

### 问题诊断

**问题1: 无有效结果**
```
[SeedGen] Total combinations generated: 300
[Fuzzer] Tested 300 combinations, found 0 valid
```

**可能原因**:
- 阈值过高 → 降低 `threshold` 到 0.6
- 不变量过严 → 检查不变量配置
- 种子值不准确 → 验证攻击参数是否正确

**问题2: 种子未生效**
```
[Fuzzer] Using default random generation
```

**可能原因**:
- `seed_config.enabled` 未设置为 `true`
- `attack_seeds` 为空或格式错误
- 配置文件路径错误

## 最佳实践

### 1. 种子数据收集

从真实攻击交易中提取参数:

```bash
# 使用 cast 工具解析交易
cast tx 0x<攻击交易哈希> --rpc-url <RPC_URL>

# 解析 calldata
cast 4byte-decode <calldata>
```

### 2. 渐进式调优

从严格配置开始,逐步放宽:

```
第1轮: threshold=0.8, max_variations=200
  ↓ 如果结果过少
第2轮: threshold=0.7, max_variations=300
  ↓ 如果仍然不足
第3轮: threshold=0.65, max_variations=500
```

### 3. 多种子策略

如果攻击有多个变种,提供多个种子:

```json
{
  "attack_seeds": {
    "0": [
      "1000000000000000000",
      "2000000000000000000",
      "5000000000000000000"
    ]
  }
}
```

### 4. 验证结果

查看保存的高相似度参数文件:

```bash
cat ./fuzzing_results/mic/high_sim_*.json | jq '.high_similarity_results[0]'
```

确认参数范围符合预期。

## 故障排除

### 编译错误

如果遇到编译错误:

```bash
cd autopath
go mod tidy
go build -o monitor ./cmd/monitor
```

### 配置文件格式错误

验证 JSON 格式:

```bash
cat pkg/invariants/configs/mic_seed.json | jq .
```

### Monitor 连接失败

检查 Anvil 是否运行:

```bash
curl -X POST -H "Content-Type: application/json" \
  --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
  http://localhost:8545
```

## 下一步: Layer 2-5

Layer 1 种子驱动模糊测试已就绪。后续优化方向:

- **Layer 2**: 自适应范围缩放 - 根据相似度动态调整变异范围
- **Layer 3**: 符号执行 - 使用符号执行引导参数生成
- **Layer 4**: 梯度引导 - 利用相似度梯度优化参数搜索
- **Layer 5**: 混合模式 - 结合符号和具体执行

当前 Layer 1 已能满足大部分场景需求,建议先验证效果后再决定是否实施后续层级。
