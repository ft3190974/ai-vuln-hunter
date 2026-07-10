-- migrations/001_initial.sql — 初始 schema（v1）
--
-- 对应 schema 版本 1。包含：
--   - findings / false_positives / rules / users 四张核心表
--   - JSONB GIN 索引（加速 data 字段查询）
--   - B-tree 索引（状态/类别/严重度等高频过滤字段）
--   - updated_at 触发器（自动维护更新时间）
--   - schema_migrations 版本追踪表
--
-- 幂等：所有语句带 IF NOT EXISTS，可重复执行。
-- 用法：psql -d yourdb -f migrations/001_initial.sql

BEGIN;

-- ── 版本追踪表 ──
CREATE TABLE IF NOT EXISTS schema_migrations (
  version     INTEGER PRIMARY KEY,
  name        VARCHAR(200) NOT NULL,
  applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── findings：核心漏洞对象，整体 JSONB + 冗余索引列 ──
CREATE TABLE IF NOT EXISTS findings (
  finding_id   VARCHAR(40) PRIMARY KEY,
  data         JSONB NOT NULL,
  status       VARCHAR(20) NOT NULL DEFAULT 'candidate',
  category     VARCHAR(40),
  severity     VARCHAR(20),
  confidence   NUMERIC(3,2),
  is_zero_day  BOOLEAN NOT NULL DEFAULT false,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- B-tree 索引：高频过滤字段
CREATE INDEX IF NOT EXISTS idx_findings_status     ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_category   ON findings(category);
CREATE INDEX IF NOT EXISTS idx_findings_severity   ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);
-- 部分索引：仅未处理的（候选/已确认），加速"待办"查询
CREATE INDEX IF NOT EXISTS idx_findings_open ON findings(finding_id) WHERE status IN ('candidate', 'confirmed');
-- JSONB GIN 索引：加速 data 字段的 ->> 提取与 @> 包含查询
CREATE INDEX IF NOT EXISTS idx_findings_data_gin ON findings USING gin(data);

-- ── false_positives：误报库 ──
CREATE TABLE IF NOT EXISTS false_positives (
  id          SERIAL PRIMARY KEY,
  category    VARCHAR(40) NOT NULL,
  pattern     TEXT NOT NULL,
  action      VARCHAR(20) NOT NULL DEFAULT 'drop',
  reason      TEXT,
  source      VARCHAR(40) NOT NULL DEFAULT 'manual',
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_fp_category ON false_positives(category);

-- ── rules：判定规则 ──
CREATE TABLE IF NOT EXISTS rules (
  rule_id    VARCHAR(60) PRIMARY KEY,
  data       JSONB NOT NULL,
  enabled    BOOLEAN NOT NULL DEFAULT true,
  version    VARCHAR(20) NOT NULL DEFAULT '1.0.0',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled);
CREATE INDEX IF NOT EXISTS idx_rules_data_gin ON rules USING gin(data);

-- ── users：JWT 认证用户 ──
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(60) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          VARCHAR(20) NOT NULL DEFAULT 'member',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── updated_at 触发器（findings / rules 自动维护）──
CREATE OR REPLACE FUNCTION touch_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_findings_updated ON findings;
CREATE TRIGGER trg_findings_updated BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

DROP TRIGGER IF EXISTS trg_rules_updated ON rules;
CREATE TRIGGER trg_rules_updated BEFORE UPDATE ON rules
  FOR EACH ROW EXECUTE FUNCTION touch_updated_at();

-- ── 记录版本 ──
INSERT INTO schema_migrations (version, name) VALUES (1, 'initial')
  ON CONFLICT (version) DO NOTHING;

COMMIT;
