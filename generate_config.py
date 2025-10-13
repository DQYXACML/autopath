#!/usr/bin/env python3
"""
动态生成监控配置文件

默认支持 Lodestar 项目（保留原有行为），同时提供通用模板机制，便于导入新的实验项目。
用法示例：
    python3 generate_config.py --project lodestar
    python3 generate_config.py --project foo --template config/templates/foo.json.tmpl \\
        --deploy ../test/Foo/scripts/data/deployed-local.json --output pkg/invariants/configs/foo.json
"""

import argparse
import json
import os
from pathlib import Path
from string import Template
from typing import Any, Dict

DEFAULT_PROJECTS: Dict[str, Dict[str, Any]] = {
    "lodestar": {
        "deploy": "../test/Lodestar/scripts/data/deployed-local.json",
        "template": "config/templates/lodestar_dynamic.json.tmpl",
        "output": "pkg/invariants/configs/lodestar-dynamic.json",
        "vars": {
            "project_id": "lodestar-local-dynamic",
            "project_name": "Lodestar Protocol (Local Dynamic)",
        },
    }
}


def parse_kv(pairs):
    result = {}
    for item in pairs:
        if "=" not in item:
            raise ValueError(f"无效参数格式: {item}，应为 key=value")
        key, value = item.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def load_json_if_exists(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r") as f:
        return json.load(f)


def cleanup_config(value: Any) -> Any:
    if isinstance(value, list):
        cleaned = [cleanup_config(item) for item in value]
        return [item for item in cleaned if not (isinstance(item, str) and item == "")]
    if isinstance(value, dict):
        return {k: cleanup_config(v) for k, v in value.items()}
    return value


def generate_from_template(template_path: str, mapping: Dict[str, Any]) -> Dict[str, Any]:
    template_text = Path(template_path).read_text()
    string_mapping = {k: ("" if v is None else str(v)) for k, v in mapping.items()}
    rendered = Template(template_text).safe_substitute(string_mapping)
    if "${" in rendered:
        raise ValueError("模板渲染后仍存在未替换的占位符，请检查输入变量是否完整")
    data = json.loads(rendered)
    return cleanup_config(data)


def ensure_parent_dir(path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def main():
    parser = argparse.ArgumentParser(description="根据部署信息生成监控配置文件")
    parser.add_argument("--project", default="lodestar", help="项目标识（默认：lodestar）")
    parser.add_argument("--deploy", help="部署信息 JSON 文件路径")
    parser.add_argument("--template", help="配置模板文件（string.Template 语法）")
    parser.add_argument("--output", help="输出配置文件路径")
    parser.add_argument(
        "--var",
        action="append",
        default=[],
        help="附加变量，格式 key=value，可重复使用",
    )

    args = parser.parse_args()
    project = args.project.lower()
    defaults = DEFAULT_PROJECTS.get(project, {})

    deploy_path = args.deploy or defaults.get("deploy")
    template_path = args.template or defaults.get("template")
    output_path = args.output or defaults.get("output") or f"pkg/invariants/configs/{project}-dynamic.json"

    if not template_path:
        parser.error(f"项目 {project} 缺少模板文件，请通过 --template 指定")

    mapping: Dict[str, Any] = {}
    if deploy_path:
        deploy_path = os.path.normpath(deploy_path)
        if not os.path.exists(deploy_path):
            print(f"⚠️  未找到部署文件 {deploy_path}，缺失字段将使用空字符串")
        else:
            mapping.update(load_json_if_exists(deploy_path))

    mapping.update(defaults.get("vars", {}))
    mapping.update(parse_kv(args.var))
    mapping.setdefault("project_id", f"{project}-dynamic")
    mapping.setdefault("project_name", f"{project.title()} Project (Dynamic)")
    mapping.setdefault("config_path", output_path)

    config = generate_from_template(template_path, mapping)
    ensure_parent_dir(output_path)
    with open(output_path, "w") as f:
        json.dump(config, f, indent=2)

    contract_count = len(config.get("contracts", []))
    print(f"✅ 已生成动态配置文件: {output_path}")
    print(f"   合约数量: {contract_count}")
    if contract_count and config.get("contracts"):
        preview = config["contracts"][:min(5, contract_count)]
        print("   部分合约地址预览:")
        for addr in preview:
            print(f"     - {addr}")


if __name__ == "__main__":
    main()
