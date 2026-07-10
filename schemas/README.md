# AI 漏洞挖掘应用 — Schema 契约基线

本目录是 AI 漏洞挖掘应用的**契约单点真相（single source of truth）**。
所有工具接入层、数据流、Agent 之间的数据交换，都以这里的 JSON Schema 为准。

> 配套设计文档：`桌面/AI漏洞挖掘应用设计方案V2.docx`（第 3、4 章对应本目录）

---

## 1. 文件清单

```
schemas/
├── common.schema.json         # 共享类型（Severity/VulnCategory/Location/FlowPoint 等）
├── code-snippet.schema.json   # 代码片段模型（LLM 判定与修复的核心输入）
├── finding.schema.json        # ★ 核心漏洞对象（系统内部唯一数据结构）
├── tool-adapter.schema.json   # 工具适配器能力声明（注册与路由）
├── scan-request.schema.json   # 统一扫描请求
├── sca-output.schema.json     # SCA 工具归一化输出（软安 SCA / Trivy）
├── sast-output.schema.json    # SAST 工具归一化输出（软安 SAST / Semgrep / CodeQL）
├── bat-output.schema.json     # BAT 工具归一化输出（软安 BAT / Ghidra）
├── rule.schema.json           # 判定规则 DSL（结构化 + LLM prompt 两种形态）
├── validate_schemas.py        # Schema 自校验脚本
└── README.md                  # 本文件

examples/
├── ruanan-sast-sample-output.json   # 软安 SAST 真实结构示例
└── validate_examples.py             # 示例文件校验脚本
```

---

## 2. 数据流（数据如何流动）

```
                 ┌─────────────────────────────────────┐
                 │      scan-request.schema.json        │  ← Agent 提交扫描任务
                 └──────────────────┬──────────────────┘
                                    ▼
   ┌─────────────┬─────────────┬─────────────┐
   │             │             │             │
   ▼             ▼             ▼             ▼
 sca-output  sast-output   bat-output   （其他工具）
   │             │             │
   └─────────────┴─────────────┘
                 │
                 ▼  归一化器（Normalizer）
   ┌─────────────────────────────────────┐
   │       finding.schema.json           │  ★ 系统内部唯一漏洞对象
   └──────────────────┬──────────────────┘
                      ▼
              多 Agent 层（判定/验证/修复/学习）
                      │
                      ▼
              rule.schema.json（判定规则约束）

  code-snippet.schema.json  被 finding / sast-output 等引用
  tool-adapter.schema.json  用于工具注册，声明 capabilities
```

---

## 3. 核心设计决策

| 决策 | 说明 |
|---|---|
| **统一 Finding 对象** | 多工具命中同一漏洞点时合并为一条 Finding，`sources` 数组记录每个来源。避免告警洪水。 |
| **代码片段必带** | SAST 输出强制携带 `snippet`，这是 LLM 深度判定与修复的必需输入（用户要求）。 |
| **可达性四级** | Finding 的 `reachability.level` 0-4 对应方案第八章的四级分层（包/函数/语义/动态）。 |
| **规则双形态** | `rule.type` 支持 `structured`（确定性，零幻觉）和 `llm_prompt`（半结构化，约束 LLM）。 |
| **编译降级** | SAST 输出的 `buildStatus.downgradedTo` 记录降级后的实际工具（方案第十章）。 |
| **分类归一** | `VulnCategory` 枚举统一所有工具的类别（sqli/cmdi/authz/business_logic 等），新增类别需同步 finding 与 rule。 |

---

## 4. 校验

### 4.1 校验 schema 自身 + examples 自洽

```bash
pip install jsonschema referencing
cd schemas
python validate_schemas.py
```

输出示例：
```
[1/3] 加载 schema 文件...  共加载 9 个 schema
[2/3] 校验 schema 合法性（Draft 2020-12）...  9/9 通过
[3/3] 用 examples 反向校验 schema 定义...  8/8 通过
结果：全部通过，0 错误
```

### 4.2 校验示例文件

```bash
cd examples
python validate_examples.py
```

---

## 5. 如何接入新工具（给工具开发团队）

接入一个新工具只需 3 步：

### 步骤 1：注册适配器

按 `tool-adapter.schema.json` 填一份能力声明，例如软安 SAST：

```json
{
  "toolId": "ruanan-sast",
  "toolName": "软安 SAST 静兮",
  "toolType": "SAST",
  "capabilities": {
    "languages": ["java", "c", "cpp", "python", "go"],
    "inputType": "source",
    "needBuild": true,
    "output": ["findings", "data_flow"]
  }
}
```

### 步骤 2：实现输出契约

按工具类型选择对应 schema，输出符合契约的 JSON：
- SCA 工具 → `sca-output.schema.json`（含 SBOM + 脆弱函数清单）
- SAST 工具 → `sast-output.schema.json`（**必须含 snippet 代码片段**）
- BAT 工具 → `bat-output.schema.json`（含反汇编片段 + 暴露面）

### 步骤 3：自校验

```python
import json
from jsonschema import Draft202012Validator
schema = json.load(open("schemas/sast-output.schema.json", encoding="utf-8"))
your_output = json.load(open("your-tool-output.json", encoding="utf-8"))
Draft202012Validator(schema).validate(your_output)  # 不抛异常即合规
```

---

## 6. 与 MCP 的映射

每个 schema 可直接映射为 MCP（Model Context Protocol）的 tool schema：

| Schema | MCP Tool Name（建议） | 用途 |
|---|---|---|
| `scan-request` | `vuln_hunter_scan` | 提交扫描任务 |
| `sca-output` | `ruanan_sca_results` | SCA 结果回调 |
| `sast-output` | `ruanan_sast_results` | SAST 结果回调 |
| `bat-output` | `ruanan_bat_results` | BAT 结果回调 |
| `finding` | `vuln_hunter_query_findings` | 查询归一化漏洞 |
| `rule` | `vuln_hunter_manage_rules` | 管理判定规则 |

`tool-adapter.schema.json` 的 `endpoints` 字段直接填写 MCP tool name。

---

## 7. 代码生成

基于本套 schema 可自动生成各语言的类型定义，避免手写：

```bash
# TypeScript 类型
npx json-schema-to-typescript schemas/finding.schema.json -o types/finding.ts

# Python dataclass（pydantic）
datamodel-codegen --input schemas/finding.schema.json --input-file-type jsonschema \
  --output models/finding.py

# Java POJO
jsonschema2pojo -s schemas/ -t src/main/java/
```

---

## 8. 版本管理

- Schema 遵循 **JSON Schema Draft 2020-12**
- 字段新增：向后兼容，不需要升级主版本
- 字段删除/重命名/语义变更：必须升级 `$id` 版本号并迁移数据
- 每次修改需同步更新 `examples/` 并通过 `validate_schemas.py` + `validate_examples.py`
