-- 012_create_usage_events: token usage metering
CREATE TABLE IF NOT EXISTS usage_events (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    model           TEXT NOT NULL,
    provider        TEXT NOT NULL DEFAULT '',
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    total_tokens    INTEGER NOT NULL DEFAULT 0,
    session_key     TEXT DEFAULT '',
    agent_id        TEXT DEFAULT '',
    duration_ms     INTEGER DEFAULT 0,
    estimated_cost  REAL DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_usage_user_id    ON usage_events(user_id);
CREATE INDEX IF NOT EXISTS idx_usage_user_time  ON usage_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_usage_user_model ON usage_events(user_id, model);
CREATE INDEX IF NOT EXISTS idx_usage_created    ON usage_events(created_at);
