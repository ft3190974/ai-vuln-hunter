#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Schema 契约自校验脚本。
做两件事：
  1. 校验每个 *.schema.json 本身是合法 JSON 且符合 Draft 2020-12
  2. 用每个 schema 自带的 examples 校验 schema 定义是否自洽
     （如果 schema 的 examples 都通不过自己的校验，说明 schema 设计有 bug）

依赖：pip install jsonschema referencing
用法：python validate_schemas.py
"""
import json
import sys
from pathlib import Path

try:
    import jsonschema
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource
except ImportError:
    print("缺少依赖，请运行: pip install jsonschema referencing")
    sys.exit(2)

SCHEMA_DIR = Path(__file__).parent
PASS = "\033[32m✓\033[0m"
FAIL = "\033[31m✗\033[0m"

# ANSI 颜色在某些 Windows 终端不显示，提供降级
if sys.platform.startswith("win"):
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        PASS, FAIL = "[OK]", "[X]"


def load_all_schemas():
    """加载所有 schema 文件，建立 $id -> schema 的注册表，支持 $ref 跨文件解析。"""
    schemas = {}
    for f in SCHEMA_DIR.glob("*.schema.json"):
        with open(f, encoding="utf-8") as fh:
            data = json.load(fh)
        schemas[data["$id"]] = data
        print(f"  加载 {f.name}  ($id={data['$id']})")
    return schemas


def build_registry(schemas):
    """构建 referencing Registry，让 $ref 能跨文件解析。"""
    resources = []
    for sid, schema in schemas.items():
        resources.append((sid, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def extract_examples(schema):
    """提取 schema 根级的 examples（单个对象或数组）。"""
    ex = schema.get("examples")
    if ex is None:
        return []
    if isinstance(ex, list):
        return ex
    return [ex]


def main():
    print("=" * 60)
    print("AI Vuln Hunter - Schema 契约自校验")
    print("=" * 60)

    # 1. 加载所有 schema
    print("\n[1/3] 加载 schema 文件...")
    schemas = load_all_schemas()
    registry = build_registry(schemas)
    print(f"  共加载 {len(schemas)} 个 schema\n")

    errors_total = 0

    # 2. 校验每个 schema 是合法的 Draft 2020-12
    print("[2/3] 校验 schema 合法性（Draft 2020-12）...")
    for sid, schema in schemas.items():
        name = Path(sid).stem.replace(".schema", "")
        try:
            Draft202012Validator.check_schema(schema)
            print(f"  {PASS} {name}.schema.json")
        except jsonschema.exceptions.SchemaError as e:
            errors_total += 1
            print(f"  {FAIL} {name}.schema.json")
            print(f"       {e.message}")
    print()

    # 3. 用每个 schema 的 examples 校验自身定义
    print("[3/3] 用 examples 反向校验 schema 定义...")
    for sid, schema in schemas.items():
        name = Path(sid).stem.replace(".schema", "")
        examples = extract_examples(schema)
        if not examples:
            print(f"  -- {name}.schema.json (无 examples，跳过)")
            continue
        validator = Draft202012Validator(schema, registry=registry)
        for i, ex in enumerate(examples, 1):
            errs = sorted(validator.iter_errors(ex), key=lambda x: list(x.path))
            if errs:
                errors_total += 1
                print(f"  {FAIL} {name}.schema.json  example #{i} 校验失败：")
                for e in errs[:3]:
                    loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
                    print(f"       [{loc}] {e.message}")
            else:
                print(f"  {PASS} {name}.schema.json  example #{i} 通过")

    # 总结
    print("\n" + "=" * 60)
    if errors_total == 0:
        print(f"结果：{PASS} 全部通过，0 错误")
        print(f"已校验 {len(schemas)} 个 schema 文件，所有 examples 自洽。")
        sys.exit(0)
    else:
        print(f"结果：{FAIL} 发现 {errors_total} 个错误，请修复")
        sys.exit(1)


if __name__ == "__main__":
    main()
