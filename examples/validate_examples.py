#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""校验 examples/ 下的示例文件是否符合对应 schema。"""
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).parent.parent / "schemas"
EXAMPLES = Path(__file__).parent

# 示例文件 -> 对应 schema 的 $id
MAPPING = {
    "ruanan-sast-sample-output.json": "sast-output.schema.json",
}

schemas = {}
for f in SCHEMA_DIR.glob("*.schema.json"):
    d = json.loads(f.read_text(encoding="utf-8"))
    schemas[d["$id"]] = d
registry = Registry().with_resources(
    [(k, Resource.from_contents(v)) for k, v in schemas.items()]
)

fail = 0
for ex_file, schema_file in MAPPING.items():
    ex_path = EXAMPLES / ex_file
    if not ex_path.exists():
        print(f"  [X] 示例文件不存在: {ex_file}")
        fail += 1
        continue
    ex = json.loads(ex_path.read_text(encoding="utf-8"))
    sid = f"https://ai-vuln-hunter/schemas/{schema_file}"
    validator = Draft202012Validator(schemas[sid], registry=registry)
    errs = sorted(validator.iter_errors(ex), key=lambda x: list(x.path))
    if errs:
        fail += 1
        print(f"  [X] {ex_file} 不符合 {schema_file}:")
        for e in errs[:5]:
            loc = "/".join(str(p) for p in e.absolute_path) or "(root)"
            print(f"       [{loc}] {e.message}")
    else:
        print(f"  [OK] {ex_file} 通过 {schema_file} 校验")

sys.exit(0 if fail == 0 else 1)
