# Migrations — 数据库迁移

版本化的数据库 schema 管理。每个迁移是一个 `NNN_name.sql` 文件，按数字顺序执行。

## 用法

```bash
# 跑全部未应用的迁移
DATABASE_URL=postgres://user:pass@localhost:5432/ai_vuln_hunter \
  node migrations/migrate.js

# 只看不执行（dry-run）
DATABASE_URL=... node migrations/migrate.js --dry-run
```

## 查看已应用版本

```sql
SELECT * FROM schema_migrations ORDER BY version;
```

## 新增迁移

1. 复制 `_template.sql` → `002_your_change.sql`（数字递增）
2. 在 BEGIN/COMMIT 之间写 DDL（ALTER TABLE / CREATE INDEX 等）
3. 末尾 `INSERT INTO schema_migrations (version, name) VALUES (2, 'your_change')`
4. 提交代码，部署时跑 `node migrate.js`

## 当前迁移

| 版本 | 文件 | 内容 |
|---|---|---|
| 1 | 001_initial.sql | 初始 schema：findings/false_positives/rules/users + 索引 + 触发器 |

## 索引设计说明

- **B-tree 索引**：status/category/severity/created_at（高频过滤字段）
- **部分索引**：`idx_findings_open` 仅索引 candidate/confirmed（"待办"查询加速）
- **JSONB GIN**：`idx_findings_data_gin` / `idx_rules_data_gin`（加速 data 字段的 `->>`/`@>` 查询）
- **触发器**：`touch_updated_at()` 自动维护 updated_at（findings/rules）
