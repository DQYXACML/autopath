#!/bin/bash
# 自动生成的Monitor启动脚本 - PeapodsFinance
#
# 使用方法:
#   ./start_monitor_peapodsfinance.sh
#
# 环境变量（可选）:
#   PRIVATE_KEY - Oracle推送使用的私钥（默认: Anvil账户0）
#

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 获取项目根目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 协议配置
PROTOCOL="peapodsfinance"
PROTOCOL_NAME="PeapodsFinance"
DEPLOYMENT_FILE="$PROJECT_ROOT/test/PeapodsFinance_exp/scripts/data/deployment.json"
TEMPLATE_FILE="config/templates/peapodsfinance_dynamic.json.tmpl"
CONFIG_FILE="pkg/invariants/configs/peapodsfinance-dynamic.json"
RULE_EXPORT_PATH="../test/PeapodsFinance_exp/scripts/data/firewall-rules.json"
RPC_URL="ws://localhost:8545"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}启动Monitor - ${PROTOCOL_NAME}${NC}"
echo -e "${BLUE}========================================${NC}"

# 检查部署文件是否存在
if [ ! -f "$DEPLOYMENT_FILE" ]; then
    echo -e "${RED}错误: 部署文件不存在${NC}"
    echo -e "${RED}路径: $DEPLOYMENT_FILE${NC}"
    echo ""
    echo "请先运行部署脚本："
    echo "  forge script test/PeapodsFinance_exp/scripts/DeployContracts.s.sol \\"
    echo "    --tc DeployPeapodsFinanceContracts \\"
    echo "    --rpc-url http://127.0.0.1:8545 \\"
    echo "    --broadcast -vvv"
    exit 1
fi

# 检查monitor_dynamic.sh是否存在
if [ ! -f "$SCRIPT_DIR/monitor_dynamic.sh" ]; then
    echo -e "${RED}错误: monitor_dynamic.sh 不存在${NC}"
    echo -e "${RED}路径: $SCRIPT_DIR/monitor_dynamic.sh${NC}"
    exit 1
fi

# 提取Oracle参数
echo -e "${YELLOW}正在从部署文件提取参数...${NC}"

# 检查jq是否安装
if ! command -v jq &> /dev/null; then
    echo -e "${RED}错误: 需要安装jq工具来解析JSON${NC}"
    echo "安装命令: sudo apt-get install jq"
    exit 1
fi

# 提取ParamCheckModule地址
PMC=$(jq -r '.paramCheckModule // empty' "$DEPLOYMENT_FILE")
if [ -z "$PMC" ]; then
    echo -e "${RED}错误: 无法从部署文件提取paramCheckModule地址${NC}"
    exit 1
fi
echo -e "${GREEN}  ParamCheckModule: $PMC${NC}"

# 提取DomainProject地址（可选）
DOMAIN=$(jq -r '.domainProject // empty' "$DEPLOYMENT_FILE")
if [ -n "$DOMAIN" ]; then
    echo -e "${GREEN}  DomainProject: $DOMAIN${NC}"
fi

# 提取主合约地址（用于日志显示）
COMPTROLLER=$(jq -r '.comptroller // .mainContract // empty' "$DEPLOYMENT_FILE")
if [ -n "$COMPTROLLER" ]; then
    echo -e "${GREEN}  主合约: $COMPTROLLER${NC}"
fi

# 构建monitor_dynamic.sh参数
echo ""
echo -e "${YELLOW}正在启动Monitor...${NC}"

cd "$SCRIPT_DIR"

# 构建命令参数
MONITOR_ARGS=(
    --project "$PROTOCOL"
    --deploy "$DEPLOYMENT_FILE"
    --template "$TEMPLATE_FILE"
    --config "$CONFIG_FILE"
    --rpc "$RPC_URL"
    --var "param_check_module=$PMC"
)

# 添加可选参数
if [ -n "$DOMAIN" ]; then
    MONITOR_ARGS+=(--var "domain_project=$DOMAIN")
fi

MONITOR_ARGS+=(--var "rule_export_path=$RULE_EXPORT_PATH")

# 显示完整命令（用于调试）
echo -e "${BLUE}执行命令:${NC}"
echo "./monitor_dynamic.sh \\"
for arg in "${MONITOR_ARGS[@]}"; do
    echo "  $arg \\"
done
echo ""

# 执行monitor_dynamic.sh
exec ./monitor_dynamic.sh "${MONITOR_ARGS[@]}"
