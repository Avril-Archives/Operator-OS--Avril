-- Add tenant_id to sessions for multi-tenant isolation.
-- Existing sessions get an empty tenant_id (single-tenant / self-hosted default).

ALTER TABLE sessions ADD COLUMN tenant_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_updated ON sessions(tenant_id, updated_at);
