# 配置生成器更新说明 - Layer 1/2 支持

## 概述

已更新 `template_generator.py` 以支持生成包含 Layer 1 (种子驱动) 和 Layer 2 (自适应范围缩放) 的模糊测试配置。

## 重要说明

### 当前生成器生成的配置

**默认配置** (由 `python3 scripts/tools/firewall_integration_cli.py batch` 生成):
- ✅ 包含基础 `fuzzing_config`
- ✅ 包含 `seed_config` 结构（但 `enabled: false`）
- ❌ **不包含** `adaptive_config`（Layer 2）
- 📝 `attack_seeds` 为空，需要手动填充

### 手动配置文件

项目中的以下配置文件是**手动创建**的示例，**不是**由脚本生成：

1. **autopath/pkg/invariants/configs/mic_seed.json**
   - Layer 1 种子驱动配置示例
   - 包含已填充的 `attack_seeds`
   - 未包含 `adaptive_config`

2. **autopath/pkg/invariants/configs/mic_adaptive.json**
   - Layer 2 自适应配置示例
   - 包含完整的 `seed_config` 和 `adaptive_config`
   - 包含所有高级配置参数

## 生成器架构

### template_generator.py 的两个配置生成函数

```python
class TemplateGenerator:

    def _generate_fuzzing_config(self, target_functions, protocol_name_lower):
        """
        生成 Layer 1 基础配置
        - fuzzing基础参数
        - seed_config结构（enabled: false）
        - attack_seeds为空（需手动填充）
        """

    def _generate_fuzzing_config_with_adaptive(self, target_functions, protocol_name_lower):
        """
        生成 Layer 2 完整配置
        - 继承 Layer 1 所有配置
        - 启用 seed_config
        - 添加 adaptive_config
        - 包含所有高级参数
        """
```

## 如何启用 Layer 1/2 配置

### 方法1: 使用生成的基础配置 + 手动启用

```bash
# 1. 生成基础配置
python3 scripts/tools/firewall_integration_cli.py batch

# 2. 手动编辑生成的配置文件
vi autopath/pkg/invariants/configs/mic.json
```

**修改步骤**:

```json
{
  "fuzzing_config": {
    "seed_config": {
      "enabled": true,  // 改为 true
      "attack_seeds": {
        // 从攻击交易中提取参数值
        "0": ["1000000000000000000"],
        "1": ["0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"]
      }
    }
  }
}
```

### 方法2: 使用专用函数生成 Layer 2 配置（未实现）

**建议的未来实现**:

```bash
# 生成包含 Layer 2 的配置
python3 scripts/tools/firewall_integration_cli.py batch --enable-adaptive
```

这需要修改 `firewall_integration_cli.py` 添加 `--enable-adaptive` 选项。

### 方法3: 直接复制示例配置

```bash
# 复制 Layer 1 示例
cp autopath/pkg/invariants/configs/mic_seed.json \
   autopath/pkg/invariants/configs/<protocol>_seed.json

# 或复制 Layer 2 示例
cp autopath/pkg/invariants/configs/mic_adaptive.json \
   autopath/pkg/invariants/configs/<protocol>_adaptive.json

# 然后手动修改协议名称和攻击种子
```

## 从攻击交易提取种子值

### 使用 cast 工具

```bash
# 1. 获取攻击交易
export ATTACK_TX="0x<attack_tx_hash>"
export RPC_URL="https://eth-mainnet.g.alchemy.com/v2/<key>"

# 2. 查看交易详情
cast tx $ATTACK_TX --rpc-url $RPC_URL

# 3. 解码 calldata
cast 4byte-decode <calldata>

# 4. 提取参数值
cast abi-decode "functionName(uint256,address)" <calldata>
```

### 示例：MIC 攻击

```bash
# 攻击交易中调用了 swap(uint256 amount, address to)
# 提取的参数:
# - amount: 1000000000000000000 (1 ETH)
# - to: 0x5FC8d32690cc91D4c39d9d3abcBD16989F875707

# 填入配置:
"attack_seeds": {
  "0": ["1000000000000000000"],
  "1": ["0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"]
}
```

## 配置文件层级

### Layer 0: 基础配置（随机模糊测试）

```json
{
  "fuzzing_config": {
    "enabled": true,
    "threshold": 0.7,
    "max_variations": 300,
    "workers": 8
    // 无 seed_config
  }
}
```

**特点**: 完全随机生成参数，效率最低

### Layer 1: 种子驱动配置

```json
{
  "fuzzing_config": {
    "enabled": true,
    "seed_config": {
      "enabled": true,
      "attack_seeds": {
        "0": ["1000000000000000000"],
        "1": ["0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"]
      },
      "range_config": {
        "numeric_range_percent": [1, 2, 5, 10, 20, 50, 100]
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

**特点**: 围绕已知攻击参数变异，效率提升 7-10x

### Layer 2: 自适应配置

```json
{
  "fuzzing_config": {
    "enabled": true,
    "seed_config": {
      "enabled": true,
      "attack_seeds": { ... },
      "adaptive_config": {
        "enabled": true,
        "max_iterations": 5,
        "convergence_rate": 0.02,
        "range_strategies": {
          "high_similarity": [1, 2, 5],
          "medium_similarity": [5, 10, 20, 50],
          "low_similarity": [50, 100, 200]
        }
      }
    }
  }
}
```

**特点**: 多轮迭代 + 动态范围调整，效率提升 4-5x（相对 Layer 1）

## 生成器代码修改总结

### template_generator.py

**修改内容**:
- ✅ `_generate_fuzzing_config()`: 添加 `seed_config` 结构
- ✅ 新增 `_generate_fuzzing_config_with_adaptive()`: Layer 2 配置生成
- ✅ 更新默认阈值: `threshold: 0.7`, `max_variations: 300`

**行数**: +55 行

### 建议的后续改进

1. **firewall_integration_cli.py**: 添加 `--enable-seed` 和 `--enable-adaptive` 选项
2. **攻击参数自动提取**: 从 attack-state.json 自动提取种子值
3. **配置验证**: 检查 attack_seeds 是否与函数参数匹配

## 使用建议

### 对于新协议

1. **第一步**: 使用脚本生成基础配置
   ```bash
   python3 scripts/tools/firewall_integration_cli.py batch \
     --scan DeFiHackLabs/extracted_contracts
   ```

2. **第二步**: 从攻击交易提取参数（使用 cast 或查看 attack-state.json）

3. **第三步**: 手动启用并配置 `seed_config`
   - 修改 `enabled: true`
   - 填充 `attack_seeds`

4. **第四步** (可选): 如需 Layer 2，添加 `adaptive_config`
   - 复制 `mic_adaptive.json` 中的 `adaptive_config` 部分
   - 根据攻击特征调整阈值

### 对于 Layer 2 测试

**推荐配置文件**:
- 使用 `mic_adaptive.json` 作为模板
- 修改 `project_id`, `contracts`, `attack_seeds`
- 保持默认的 `adaptive_config` 参数

**测试流程**:
```bash
# 1. 准备配置（修改 attack_seeds）
vi autopath/pkg/invariants/configs/<protocol>_adaptive.json

# 2. 启动 Monitor
./monitor -rpc ws://localhost:8545 \
  -config pkg/invariants/configs/<protocol>_adaptive.json \
  ...

# 3. 执行攻击，观察日志
tail -f logs/monitor_<protocol>.log | grep -E "(Iteration|Adaptive|converged)"
```

## 配置文件关系图

```
firewall_integration_cli.py batch
    ↓
生成基础配置 (<protocol>.json)
    ├─ fuzzing_config (基础)
    └─ seed_config (结构, enabled=false)

手动修改
    ↓
Layer 1 配置 (<protocol>_seed.json)
    ├─ fuzzing_config
    └─ seed_config (enabled=true, 已填充 attack_seeds)

手动添加
    ↓
Layer 2 配置 (<protocol>_adaptive.json)
    ├─ fuzzing_config
    └─ seed_config
        ├─ enabled=true
        ├─ attack_seeds (已填充)
        └─ adaptive_config (完整配置)
```

## 总结

**当前状态**:
- ✅ 生成器已支持生成 Layer 1 配置结构
- ✅ 提供了 `_generate_fuzzing_config_with_adaptive()` 用于未来集成
- ⚠️ `attack_seeds` 仍需手动从攻击交易中提取
- ⚠️ `adaptive_config` 需要手动添加（或复制示例）

**建议使用方式**:
1. 对于大多数场景：使用生成的基础配置 + 手动添加种子
2. 对于深度分析：复制 `mic_adaptive.json` 并修改
3. 等待未来 CLI 支持自动生成 Layer 2 配置

**重要**: `mic_seed.json` 和 `mic_adaptive.json` 是手动创建的**示例文件**，供参考和复制使用。
