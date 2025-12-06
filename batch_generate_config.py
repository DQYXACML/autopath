#!/usr/bin/env python3
"""
批量生成 Monitor 配置文件

基于 autopath/generate_config.py，按照月份或协议列表批量执行，
自动匹配模板、部署信息与输出路径。

示例：
    python3 batch_generate_config.py --filter 2024-01 --dry-run
    python3 batch_generate_config.py --filter 2024-01
    python3 batch_generate_config.py --protocols AAVE_Repay_Adapter,BarleyFinance_exp
"""

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set


PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCRIPT_DIR = Path(__file__).resolve().parent
GENERATE_CONFIG = SCRIPT_DIR / "generate_config.py"
EXTRACTED_ROOT = PROJECT_ROOT / "DeFiHackLabs" / "extracted_contracts"
GENERATED_ROOT = PROJECT_ROOT / "generated"
TEMPLATE_FALLBACK_ROOT = SCRIPT_DIR / "config" / "templates"
OUTPUT_ROOT = SCRIPT_DIR / "pkg" / "invariants" / "configs"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="批量调用 generate_config.py 生成 Monitor 配置"
    )
    parser.add_argument(
        "--filter",
        action="append",
        default=[],
        help="按年月过滤（格式：YYYY-MM，可重复）",
    )
    parser.add_argument(
        "--protocols",
        action="append",
        help="指定协议列表，逗号分隔或重复使用该参数",
    )
    parser.add_argument(
        "--var",
        action="append",
        default=[],
        help="传递给 generate_config.py 的附加变量，格式 key=value，可重复",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="若目标 JSON 已存在，仍强制重新生成",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="仅打印将要执行的命令，不实际生成文件",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="静默模式，仅输出结果摘要",
    )
    return parser.parse_args()


def collect_protocols(filters: Sequence[str]) -> List[str]:
    if not EXTRACTED_ROOT.exists():
        raise FileNotFoundError(f"未找到目录：{EXTRACTED_ROOT}")

    normalized_filters: Set[str] = set()
    for item in filters:
        item = item.strip()
        if not item:
            continue
        if len(item) != 7 or item[4] != "-":
            raise ValueError(f"--filter 参数格式应为 YYYY-MM，收到：{item}")
        normalized_filters.add(item)

    protocols: List[str] = []
    year_month_dirs = sorted(
        d for d in EXTRACTED_ROOT.iterdir() if d.is_dir()
    )

    for month_dir in year_month_dirs:
        if normalized_filters and month_dir.name not in normalized_filters:
            continue

        for protocol_dir in sorted(month_dir.iterdir()):
            if not protocol_dir.is_dir():
                continue
            protocols.append(protocol_dir.name)

    return protocols


def parse_protocols(protocol_args: Optional[Sequence[str]]) -> List[str]:
    if not protocol_args:
        return []

    seen: Set[str] = set()
    result: List[str] = []
    for entry in protocol_args:
        if not entry:
            continue
        parts = [p.strip() for p in entry.split(",") if p.strip()]
        for name in parts:
            if name not in seen:
                seen.add(name)
                result.append(name)
    return result


def protocol_to_key(protocol: str) -> str:
    key = protocol.strip().lower().replace(" ", "_")
    if key.endswith("_exp"):
        key = key[:-4]
    return key


def build_command(
    project: str,
    template_path: Path,
    deploy_path: Path,
    output_path: Path,
    extra_vars: Iterable[str],
) -> List[str]:
    cmd = [
        sys.executable,
        str(GENERATE_CONFIG),
        "--project",
        project,
        "--template",
        str(template_path),
        "--output",
        str(output_path),
    ]

    if deploy_path:
        cmd.extend(["--deploy", str(deploy_path)])

    for kv in extra_vars:
        cmd.extend(["--var", kv])

    return cmd


def main() -> int:
    args = parse_args()

    protocol_list = parse_protocols(args.protocols)
    if not protocol_list:
        protocol_list = collect_protocols(args.filter)

    if not protocol_list:
        print("  未找到任何协议，请检查过滤条件")
        return 1

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    success = 0
    skipped = 0
    failed = 0

    for protocol in protocol_list:
        project_key = protocol_to_key(protocol)
        template_path = GENERATED_ROOT / protocol / f"{project_key}_dynamic.json.tmpl"
        if not template_path.exists():
            fallback_path = TEMPLATE_FALLBACK_ROOT / f"{project_key}_dynamic.json.tmpl"
            if fallback_path.exists():
                template_path = fallback_path
        deploy_path = (
            PROJECT_ROOT
            / "test"
            / protocol
            / "scripts"
            / "data"
            / "deployment.json"
        )
        output_path = OUTPUT_ROOT / f"{project_key}.json"

        if not template_path.exists():
            if not args.quiet:
                print(f" 跳过 {protocol}：未找到模板 {template_path}")
            failed += 1
            continue

        if output_path.exists() and not args.force:
            if not args.quiet:
                print(f"  已存在，跳过 {output_path}")
            skipped += 1
            continue

        cmd = build_command(
            project=project_key,
            template_path=template_path,
            deploy_path=deploy_path,
            output_path=output_path,
            extra_vars=args.var,
        )

        if args.dry_run:
            if not args.quiet:
                print("DRY-RUN:", " ".join(cmd))
            success += 1
            continue

        if not args.quiet:
            print("  生成配置:", " ".join(cmd))

        result = subprocess.run(cmd, cwd=PROJECT_ROOT)
        if result.returncode == 0:
            success += 1
        else:
            failed += 1

    summary = (
        f"完成：成功 {success} 个"
        f"{', 跳过 ' + str(skipped) + ' 个' if skipped else ''}"
        f"{', 失败 ' + str(failed) + ' 个' if failed else ''}"
    )
    print(summary)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
