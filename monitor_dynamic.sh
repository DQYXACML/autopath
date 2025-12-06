#!/bin/bash

# 通用动态监控脚本 - 支持通过模板和部署文件生成配置并启动监控器

set -euo pipefail

usage() {
    cat <<EOF
用法: $0 [--project NAME] [--deploy PATH] [--template PATH] [--config PATH] [--rpc URL]
          [--var key=value] [--no-build]

选项说明：
  --project NAME     项目标识（默认：lodestar）
  --deploy PATH      部署信息 JSON 文件路径
  --template PATH    配置模板路径（string.Template 语法）
  --config PATH      输出配置文件路径
  --rpc URL          WebSocket RPC 地址（默认：ws://localhost:8545）
  --var key=value    传递给模板的额外变量，可重复使用
  --no-build         跳过 monitor 编译
  -h, --help         查看帮助
EOF
}

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

if ! command -v jq >/dev/null 2>&1; then
    echo -e "${RED}缺少 jq，请先安装 jq 工具以解析配置${NC}"
    exit 1
fi

PROJECT_RAW="lodestar"
DEPLOY_PATH=""
TEMPLATE_PATH=""
CONFIG_PATH=""
RPC_URL="ws://localhost:8545"
BUILD_BINARY=1
EXTRA_VARS=()
# 本地执行开关（默认开启，保证Fuzz走本地EVM+Hook）
USE_LOCAL_EXECUTION="${USE_LOCAL_EXECUTION:-true}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --project)
            PROJECT_RAW="$2"
            shift 2
            ;;
        --deploy)
            DEPLOY_PATH="$2"
            shift 2
            ;;
        --template)
            TEMPLATE_PATH="$2"
            shift 2
            ;;
        --config)
            CONFIG_PATH="$2"
            shift 2
            ;;
        --rpc)
            RPC_URL="$2"
            shift 2
            ;;
        --var)
            EXTRA_VARS+=("$2")
            shift 2
            ;;
        --no-build)
            BUILD_BINARY=0
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "未知参数: $1"
            usage
            exit 1
            ;;
    esac
done

PROJECT_KEY=$(echo "$PROJECT_RAW" | tr 'A-Z' 'a-z')
PID_FILE="monitor_dynamic_${PROJECT_KEY}.pid"
LOG_FILE="monitor_dynamic_${PROJECT_KEY}.log"

if [ -z "$CONFIG_PATH" ]; then
    CONFIG_PATH="pkg/invariants/configs/${PROJECT_KEY}-dynamic.json"
fi

case "$PROJECT_KEY" in
    lodestar)
        if [ -z "$DEPLOY_PATH" ]; then
            DEPLOY_PATH="../test/Lodestar/scripts/data/deployed-local.json"
        fi
        if [ -z "$TEMPLATE_PATH" ]; then
            TEMPLATE_PATH="config/templates/lodestar_dynamic.json.tmpl"
        fi
        ;;
    *)
        if [ -z "$DEPLOY_PATH" ]; then
            GUESS_DEPLOY="../test/${PROJECT_RAW}/scripts/data/deployed-local.json"
            if [ -f "$GUESS_DEPLOY" ]; then
                DEPLOY_PATH="$GUESS_DEPLOY"
            fi
        fi
        if [ -z "$TEMPLATE_PATH" ]; then
            GUESS_TEMPLATE="config/templates/${PROJECT_KEY}_dynamic.json.tmpl"
            if [ -f "$GUESS_TEMPLATE" ]; then
                TEMPLATE_PATH="$GUESS_TEMPLATE"
            fi
        fi
        ;;
esac

echo "========================================="
echo "动态监控项目：$PROJECT_RAW"
echo "========================================="

echo -e "${YELLOW}[1/3] 生成动态配置文件...${NC}"
GEN_ARGS=(python3 generate_config.py --project "$PROJECT_KEY" --output "$CONFIG_PATH")
GEN_ARGS+=(--var "config_path=$CONFIG_PATH")
if [ -n "$DEPLOY_PATH" ]; then
    GEN_ARGS+=(--deploy "$DEPLOY_PATH")
fi
if [ -n "$TEMPLATE_PATH" ]; then
    GEN_ARGS+=(--template "$TEMPLATE_PATH")
fi
for kv in "${EXTRA_VARS[@]}"; do
    GEN_ARGS+=(--var "$kv")
done

"${GEN_ARGS[@]}" || {
    echo -e "${RED}生成配置失败，请检查模板和部署文件${NC}"
    exit 1
}

# 提示不变量检查配置状态
INV_ENABLED=$(jq -r '.fuzzing_config.invariant_check.enabled // false' "$CONFIG_PATH" 2>/dev/null || echo "false")
if [ "$INV_ENABLED" = "true" ]; then
    INV_PROJECT=$(jq -r '.fuzzing_config.invariant_check.project_id // "unknown"' "$CONFIG_PATH" 2>/dev/null || echo "unknown")
    echo -e "${GREEN}已启用相似路径不变量检查 (ProjectID: ${INV_PROJECT})${NC}"
else
    echo -e "${YELLOW}提示：当前配置未启用不变量检查，可在 fuzzing_config.invariant_check 中开启${NC}"
fi

if [ "$BUILD_BINARY" -eq 1 ]; then
    echo -e "${YELLOW}[2/3] 编译监控器...${NC}"
    go build -o monitor ./cmd/monitor
else
    echo -e "${YELLOW}[2/3] 跳过编译（--no-build）${NC}"
fi

echo -e "${YELLOW}[3/3] 启动监控器...${NC}"

kill_and_wait() {
    local pid="$1"; local name="$2"; local timeout=10
    if kill -TERM "$pid" 2>/dev/null; then
        for _ in $(seq 1 $timeout); do
            if ! ps -p "$pid" >/dev/null 2>&1; then
                echo -e "${GREEN} 已终止 ${name} (PID: ${pid})${NC}"
                return 0
            fi
            sleep 1
        done
        echo -e "${YELLOW}! 进程未在 ${timeout}s 内退出，发送 KILL${NC}"
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

stop_existing_monitor() {
    echo -e "${YELLOW}尝试终止已有的 monitor 进程...${NC}"

    if [ -f "$PID_FILE" ]; then
        OLD_PID=$(cat "$PID_FILE" 2>/dev/null || echo "")
        if [ -n "$OLD_PID" ] && ps -p "$OLD_PID" >/dev/null 2>&1; then
            CMDLINE=$(ps -o command= -p "$OLD_PID" 2>/dev/null || echo "")
            if echo "$CMDLINE" | grep -q "monitor"; then
                echo "- 发现历史 PID: $OLD_PID ($CMDLINE)"
                kill_and_wait "$OLD_PID" "monitor"
            fi
        fi
        rm -f "$PID_FILE" 2>/dev/null || true
    fi

    MATCH_PATTERN="-config $CONFIG_PATH"
    PIDS=$(pgrep -f "monitor .*${MATCH_PATTERN}" || true)
    if [ -n "$PIDS" ]; then
        echo "- 按配置文件匹配到 PIDs: $PIDS"
        for p in $PIDS; do
            kill_and_wait "$p" "monitor"
        done
    fi
}

MONITOR_CMD="./monitor -rpc ${RPC_URL} -config ${CONFIG_PATH}"

# 启用本地执行模式（默认开启，可通过USE_LOCAL_EXECUTION控制）
if [ "${USE_LOCAL_EXECUTION}" = "true" ]; then
    MONITOR_CMD="$MONITOR_CMD -local-execution"
    echo -e "${YELLOW}启用本地EVM执行模式 (USE_LOCAL_EXECUTION=true)${NC}"
else
    echo -e "${YELLOW}未启用本地EVM执行模式 (USE_LOCAL_EXECUTION=${USE_LOCAL_EXECUTION})${NC}"
fi

PMC=""
DOMAIN=""
RULE_EXPORT_PATH=""
if [ "$PROJECT_KEY" = "lodestar" ]; then
    if [ -f "../test/Lodestar/scripts/data/firewall-local.json" ]; then
        PMC=$(jq -r '.paramCheckModule' ../test/Lodestar/scripts/data/firewall-local.json 2>/dev/null || echo "")
        DOMAIN=$(jq -r '.domainProject' ../test/Lodestar/scripts/data/firewall-local.json 2>/dev/null || echo "")
    elif [ -f "../test/Lodestar/scripts/data/firewall-param-only.json" ]; then
        PMC=$(jq -r '.paramCheckModule' ../test/Lodestar/scripts/data/firewall-param-only.json 2>/dev/null || echo "")
        DOMAIN=$(jq -r '.domainProject' ../test/Lodestar/scripts/data/firewall-param-only.json 2>/dev/null || echo "")
    fi

    if [ -n "$PMC" ] && [ "$PMC" != "null" ]; then
        echo -e "${BLUE}检测到防火墙配置，启用Oracle集成和规则导出${NC}"
        PRIVATE_KEY=${PRIVATE_KEY:-"0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"}
        RULE_EXPORT_PATH="../test/Lodestar/scripts/data/firewall-rules.json"
        MONITOR_CMD="$MONITOR_CMD -oracle.enabled -oracle.module $PMC -oracle.pk $PRIVATE_KEY -oracle.chainid 31337 -oracle.threshold 0.8 -oracle.batch 1 -oracle.flush_interval 15s -oracle.max_rules 20 -rule.export_path $RULE_EXPORT_PATH -rule.export_enable"
        echo -e "${GREEN}规则将自动导出到: $RULE_EXPORT_PATH${NC}"
    fi
fi

echo -e "${GREEN}启动命令：${NC}"
echo "$MONITOR_CMD"
echo ""

stop_existing_monitor

$MONITOR_CMD > "$LOG_FILE" 2>&1 &
MONITOR_PID=$!
echo "$MONITOR_PID" > "$PID_FILE" 2>/dev/null || true

echo "监控器 PID: $MONITOR_PID"
sleep 5

if ! ps -p $MONITOR_PID > /dev/null; then
    echo -e "${RED}监控器启动失败!${NC}"
    echo "日志内容："
    cat "$LOG_FILE"
    exit 1
fi

echo -e "${GREEN} 监控器已成功启动${NC}"
echo ""
echo "========================================="
echo "监控器配置："
echo "  - 项目: $PROJECT_RAW"
echo "  - 配置文件: $CONFIG_PATH"
echo "  - 日志文件: $LOG_FILE"
if [ "$PROJECT_KEY" = "lodestar" ] && [ -n "$PMC" ] && [ "$PMC" != "null" ]; then
    echo "  - Oracle模块: $PMC"
    echo "  - Domain项目: $DOMAIN"
    echo "  - 规则导出: $RULE_EXPORT_PATH"
fi
echo ""
echo "查看日志："
echo "  tail -f $LOG_FILE"
echo "========================================="

echo ""
echo -e "${YELLOW}监控器初始日志：${NC}"
head -20 "$LOG_FILE" || true
