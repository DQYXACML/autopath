#!/usr/bin/env bash

set -euo pipefail

# Read ParamCheckModule rules using Foundry cast
# Requirements: cast, jq

usage() {
  echo "Usage:"
  echo "  read_rules.sh -m <ParamCheckModule> -p <Project> -f <func>";
  echo ""
  echo "Options:"
  echo "  -r, --rpc <url>          RPC URL (default: \$RPC_URL or http://127.0.0.1:8545)"
  echo "  -m, --module <address>   ParamCheckModule address (0x...)"
  echo "  -p, --project <address>  Project/Domain address (0x...)"
  echo "  -f, --func <sig|selector> Function signature (e.g. transfer(address,uint256)) or selector (e.g. 0xa9059cbb)"
  echo "  -i, --index <n>          Read a single rule by index (calls getRule)"
  echo "      --raw                Output raw JSON only"
  echo "  -h, --help               Show this help"
  echo ""
  echo "Examples:"
  echo "  RPC_URL=http://127.0.0.1:8545 ./read_rules.sh -m 0xPMC -p 0xPROJECT -f 0xc5ebeaec"
  echo ""
  echo "  ./read_rules.sh -m 0xPMC -p 0xPROJECT -f transfer(address,uint256)"
}

die() { echo "[read_rules] $*" >&2; exit 1; }

need_bin() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

need_bin cast
need_bin jq

RPC_URL_DEFAULT="${RPC_URL:-http://127.0.0.1:8545}"
RPC_URL="$RPC_URL_DEFAULT"
PMC=""
PROJECT=""
FUNC_IN=""
RULE_INDEX=""
RAW=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r|--rpc) RPC_URL="$2"; shift 2;;
    -m|--module) PMC="$2"; shift 2;;
    -p|--project) PROJECT="$2"; shift 2;;
    -f|--func) FUNC_IN="$2"; shift 2;;
    -i|--index) RULE_INDEX="$2"; shift 2;;
    --raw) RAW=true; shift;;
    -h|--help) usage; exit 0;;
    *) die "unknown argument: $1";;
  esac
done

[[ -n "$PMC" ]] || die "--module is required"
[[ -n "$PROJECT" ]] || die "--project is required"
[[ -n "$FUNC_IN" ]] || die "--func is required"

# Normalize function selector
if [[ "$FUNC_IN" =~ ^0x[0-9a-fA-F]{8}$ ]]; then
  FUNC_SEL="$FUNC_IN"
else
  FUNC_SEL=$(cast sig "$FUNC_IN") || die "failed to compute selector for: $FUNC_IN"
fi

if [[ "$RAW" == true ]]; then
  if [[ -n "$RULE_INDEX" ]]; then
    cast call "$PMC" \
      "getRule(address,bytes4,uint8)((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool))" \
      "$PROJECT" "$FUNC_SEL" "$RULE_INDEX" \
      --rpc-url "$RPC_URL" --json
  else
    cast call "$PMC" \
      "getFunctionConfig(address,bytes4)((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],bool,uint256,address,bool)" \
      "$PROJECT" "$FUNC_SEL" \
      --rpc-url "$RPC_URL" --json
  fi
  exit 0
fi

echo "== ParamCheckModule Rules =="
echo "- RPC       : $RPC_URL"
echo "- Module    : $PMC"
echo "- Project   : $PROJECT"
echo "- Func      : $FUNC_IN ($FUNC_SEL)"

if [[ -n "$RULE_INDEX" ]]; then
  echo "- Reading single rule index: $RULE_INDEX"
  JSON=$(cast call "$PMC" \
    "getRule(address,bytes4,uint8)((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool))" \
    "$PROJECT" "$FUNC_SEL" "$RULE_INDEX" \
    --rpc-url "$RPC_URL" --json)

  # Pretty print single rule
  echo "$JSON" | jq -r '
    def ptype(n): if n==0 then "UINT256" elif n==1 then "INT256" elif n==2 then "ADDRESS" elif n==3 then "BOOL" elif n==4 then "BYTES32" elif n==5 then "BYTES" else "STRING" end;
    def rtype(n): if n==0 then "NONE" elif n==1 then "WHITELIST" elif n==2 then "BLACKLIST" elif n==3 then "RANGE" elif n==4 then "PATTERN" else "COMBINED" end;
    def toaddr(x): ("0x" + ((x|ltrimstr("0x"))[-40:]));
    . as $r |
    "paramIndex : \($r[0])\n" +
    "paramType  : \($r[1]) (" + ptype($r[1]) + ")\n" +
    "ruleType   : \($r[2]) (" + rtype($r[2]) + ")\n" +
    "enabled    : \($r[9])\n" +
    ("allowed    : \(($r[3]|length)) values" + (if $r[1]==2 and ($r[3]|length)>0 then ": " + ($r[3]|map(toaddr(.))|join(", ")) else "" end) + "\n") +
    (if $r[2]==3 then "range     : min=\($r[5]) max=\($r[6])\n" else "" end)
  '
  exit 0
fi

# Read full function config
CONF_JSON=$(cast call "$PMC" \
  "getFunctionConfig(address,bytes4)((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool)[],bool,uint256,address,bool)" \
  "$PROJECT" "$FUNC_SEL" \
  --rpc-url "$RPC_URL" --json)

LEN=$(echo "$CONF_JSON" | jq '.[0] | length')
REQ=$(echo "$CONF_JSON" | jq -r '.[1]')
LAST=$(echo "$CONF_JSON" | jq -r '.[2]')
UPD=$(echo "$CONF_JSON" | jq -r '.[3]')
CFG=$(echo "$CONF_JSON" | jq -r '.[4]')

HUMAN_TS="n/a"
if [[ "$LAST" != "0" ]]; then
  if date -d @1 >/dev/null 2>&1; then
    HUMAN_TS=$(date -d "@$LAST" "+%F %T")
  else
    HUMAN_TS=$(date -r "$LAST" "+%F %T" 2>/dev/null || echo "n/a")
  fi
fi

echo "- configured : $CFG"
echo "- lastUpdate : $LAST ($HUMAN_TS)"
echo "- updater    : $UPD"
echo "- requireAll : $REQ"
echo "- rules      : $LEN"

if [[ "$LEN" -eq 0 ]]; then
  exit 0
fi

echo ""
echo "-- Rules --"
for ((i=0; i<LEN; i++)); do
  RJSON=$(cast call "$PMC" \
    "getRule(address,bytes4,uint8)((uint8,uint8,uint8,bytes32[],bytes32[],bytes32,bytes32,bytes,bool))" \
    "$PROJECT" "$FUNC_SEL" "$i" \
    --rpc-url "$RPC_URL" --json)

  echo "# Rule $i"
  echo "$RJSON" | jq -r '
    def ptype(n): if n==0 then "UINT256" elif n==1 then "INT256" elif n==2 then "ADDRESS" elif n==3 then "BOOL" elif n==4 then "BYTES32" elif n==5 then "BYTES" else "STRING" end;
    def rtype(n): if n==0 then "NONE" elif n==1 then "WHITELIST" elif n==2 then "BLACKLIST" elif n==3 then "RANGE" elif n==4 then "PATTERN" else "COMBINED" end;
    def toaddr(x): ("0x" + ((x|ltrimstr("0x"))[-40:]));
    . as $r |
    "paramIndex : \($r[0])\n" +
    "paramType  : \($r[1]) (" + ptype($r[1]) + ")\n" +
    "ruleType   : \($r[2]) (" + rtype($r[2]) + ")\n" +
    "enabled    : \($r[9])\n" +
    ("allowed    : \(($r[3]|length)) values" + (if $r[1]==2 and ($r[3]|length)>0 then ": " + ($r[3]|map(toaddr(.))|join(", ")) else "" end) + "\n") +
    (if $r[2]==3 then "range     : min=\($r[5]) max=\($r[6])\n" else "" end)
  '
  echo ""
done

