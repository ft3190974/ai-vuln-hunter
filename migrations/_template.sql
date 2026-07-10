-- migrations/_template.sql — 后续迁移模板
--
-- 复制此文件，改名为 002_xxx.sql、003_xxx.sql ...（数字递增，决定执行顺序）。
-- 必须在末尾 INSERT schema_migrations 记录版本。

BEGIN;

-- 在此写 ALTER TABLE / CREATE INDEX 等 DDL
-- 示例：
-- ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee VARCHAR(60);
-- CREATE INDEX IF NOT EXISTS idx_findings_assignee ON findings(assignee);

-- 记录版本（把 2 改成你的版本号，对应文件名前缀）
INSERT INTO schema_migrations (version, name) VALUES (2, 'template_example')
  ON CONFLICT (version) DO NOTHING;

COMMIT;
