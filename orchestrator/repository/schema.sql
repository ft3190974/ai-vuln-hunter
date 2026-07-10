-- repository/schema.sql
--
-- ⚠️ 已迁移到版本化管理，请用：
--   DATABASE_URL=... node migrations/migrate.js
--
-- 实际 schema 定义见：migrations/001_initial.sql
-- 包含：findings/false_positives/rules/users 四张表
--       + B-tree/部分/GIN 索引
--       + updated_at 触发器
--       + schema_migrations 版本追踪表
--
-- 此文件保留为兼容入口（旧文档可能引用），实际内容已迁移。

\i ../migrations/001_initial.sql
