-- Rollback: remove tenant_id from sessions.
-- SQLite does not support DROP COLUMN before 3.35, so we recreate the table.
DROP INDEX IF EXISTS idx_sessions_tenant;
DROP INDEX IF EXISTS idx_sessions_tenant_updated;
ALTER TABLE sessions DROP COLUMN tenant_id;
