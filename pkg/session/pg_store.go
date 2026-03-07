package session

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/standardws/operator/pkg/providers"
)

// PGStore implements SessionStore (and EvictableStore) backed by PostgreSQL.
// All writes are immediate (write-through); Save is a no-op.
type PGStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewPGStore creates a PostgreSQL-backed session store using the provided *sql.DB.
// It initialises the schema (sessions + messages tables) if not present.
func NewPGStore(db *sql.DB) (*PGStore, error) {
	if db == nil {
		return nil, fmt.Errorf("pg session store: db is nil")
	}
	if err := initPGSchema(db); err != nil {
		return nil, fmt.Errorf("pg session store: init schema: %w", err)
	}
	return &PGStore{db: db}, nil
}

func initPGSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    key         TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_updated ON sessions(tenant_id, updated_at);

CREATE TABLE IF NOT EXISTS messages (
    id           BIGSERIAL PRIMARY KEY,
    session_key  TEXT NOT NULL REFERENCES sessions(key) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT NOT NULL DEFAULT '[]',
    tool_call_id TEXT NOT NULL DEFAULT '',
    reasoning    TEXT NOT NULL DEFAULT '',
    media        TEXT NOT NULL DEFAULT '[]',
    extra        TEXT NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_key);
`
	_, err := db.Exec(schema)
	return err
}

// GetOrCreate returns the session for the given key, creating it if needed.
func (s *PGStore) GetOrCreate(key string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO sessions (key, created_at, updated_at) VALUES ($1, $2, $3)
		 ON CONFLICT(key) DO NOTHING`,
		key, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert session %q: %w", key, err)
	}

	return s.loadSession(key)
}

func (s *PGStore) loadSession(key string) (*Session, error) {
	var summary string
	var created, updated time.Time
	err := s.db.QueryRow(
		`SELECT summary, created_at, updated_at FROM sessions WHERE key = $1`, key,
	).Scan(&summary, &created, &updated)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session %q not found", key)
	}
	if err != nil {
		return nil, fmt.Errorf("query session %q: %w", key, err)
	}

	messages, err := s.loadMessages(key)
	if err != nil {
		return nil, err
	}

	return &Session{
		Key:      key,
		Messages: messages,
		Summary:  summary,
		Created:  created,
		Updated:  updated,
	}, nil
}

func (s *PGStore) loadMessages(key string) ([]providers.Message, error) {
	rows, err := s.db.Query(
		`SELECT role, content, tool_calls, tool_call_id, reasoning, media
		 FROM messages WHERE session_key = $1 ORDER BY id ASC`, key,
	)
	if err != nil {
		return nil, fmt.Errorf("query messages for %q: %w", key, err)
	}
	defer rows.Close()

	var messages []providers.Message
	for rows.Next() {
		var (
			role, content, toolCallsJSON, toolCallID, reasoning, mediaJSON string
		)
		if err := rows.Scan(&role, &content, &toolCallsJSON, &toolCallID, &reasoning, &mediaJSON); err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}

		msg := providers.Message{
			Role:             role,
			Content:          content,
			ToolCallID:       toolCallID,
			ReasoningContent: reasoning,
		}

		if toolCallsJSON != "" && toolCallsJSON != "[]" {
			if err := json.Unmarshal([]byte(toolCallsJSON), &msg.ToolCalls); err != nil {
				return nil, fmt.Errorf("unmarshal tool_calls: %w", err)
			}
		}

		if mediaJSON != "" && mediaJSON != "[]" {
			if err := json.Unmarshal([]byte(mediaJSON), &msg.Media); err != nil {
				return nil, fmt.Errorf("unmarshal media: %w", err)
			}
		}

		messages = append(messages, msg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate messages: %w", err)
	}

	if messages == nil {
		messages = []providers.Message{}
	}
	return messages, nil
}

// AddMessage appends a message to the session's history.
func (s *PGStore) AddMessage(key string, msg providers.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO sessions (key, created_at, updated_at) VALUES ($1, $2, $3)
		 ON CONFLICT(key) DO UPDATE SET updated_at = $4`,
		key, now, now, now,
	)
	if err != nil {
		return fmt.Errorf("ensure session %q: %w", key, err)
	}

	toolCallsJSON, err := json.Marshal(msg.ToolCalls)
	if err != nil {
		toolCallsJSON = []byte("[]")
	}
	if msg.ToolCalls == nil {
		toolCallsJSON = []byte("[]")
	}

	mediaJSON, err := json.Marshal(msg.Media)
	if err != nil {
		mediaJSON = []byte("[]")
	}
	if msg.Media == nil {
		mediaJSON = []byte("[]")
	}

	_, err = s.db.Exec(
		`INSERT INTO messages (session_key, role, content, tool_calls, tool_call_id, reasoning, media)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		key, msg.Role, msg.Content, string(toolCallsJSON), msg.ToolCallID, msg.ReasoningContent, string(mediaJSON),
	)
	if err != nil {
		return fmt.Errorf("insert message for %q: %w", key, err)
	}

	return nil
}

// GetHistory returns a copy of all messages for the session.
func (s *PGStore) GetHistory(key string) ([]providers.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadMessages(key)
}

// GetSummary returns the conversation summary for the session.
func (s *PGStore) GetSummary(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var summary string
	err := s.db.QueryRow(`SELECT summary FROM sessions WHERE key = $1`, key).Scan(&summary)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get summary for %q: %w", key, err)
	}
	return summary, nil
}

// SetSummary updates the conversation summary.
func (s *PGStore) SetSummary(key string, summary string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	res, err := s.db.Exec(
		`UPDATE sessions SET summary = $1, updated_at = $2 WHERE key = $3`,
		summary, now, key,
	)
	if err != nil {
		return fmt.Errorf("set summary for %q: %w", key, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("session %q not found", key)
	}
	return nil
}

// SetHistory replaces the entire message history for the session.
func (s *PGStore) SetHistory(key string, messages []providers.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM messages WHERE session_key = $1`, key); err != nil {
		return fmt.Errorf("delete messages for %q: %w", key, err)
	}

	for _, msg := range messages {
		toolCallsJSON, _ := json.Marshal(msg.ToolCalls)
		if msg.ToolCalls == nil {
			toolCallsJSON = []byte("[]")
		}
		mediaJSON, _ := json.Marshal(msg.Media)
		if msg.Media == nil {
			mediaJSON = []byte("[]")
		}

		if _, err := tx.Exec(
			`INSERT INTO messages (session_key, role, content, tool_calls, tool_call_id, reasoning, media)
			 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			key, msg.Role, msg.Content, string(toolCallsJSON), msg.ToolCallID, msg.ReasoningContent, string(mediaJSON),
		); err != nil {
			return fmt.Errorf("insert message: %w", err)
		}
	}

	now := time.Now()
	if _, err := tx.Exec(`UPDATE sessions SET updated_at = $1 WHERE key = $2`, now, key); err != nil {
		return fmt.Errorf("update session timestamp: %w", err)
	}

	return tx.Commit()
}

// TruncateHistory removes all but the last keepLast messages.
func (s *PGStore) TruncateHistory(key string, keepLast int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if keepLast <= 0 {
		_, err := s.db.Exec(`DELETE FROM messages WHERE session_key = $1`, key)
		if err != nil {
			return fmt.Errorf("truncate all messages for %q: %w", key, err)
		}
		return nil
	}

	_, err := s.db.Exec(
		`DELETE FROM messages WHERE session_key = $1 AND id NOT IN (
			SELECT id FROM messages WHERE session_key = $1 ORDER BY id DESC LIMIT $2
		)`,
		key, keepLast,
	)
	if err != nil {
		return fmt.Errorf("truncate messages for %q: %w", key, err)
	}
	return nil
}

// Save is a no-op for PGStore since all writes are immediate.
func (s *PGStore) Save(_ string) error {
	return nil
}

// SessionCount returns the total number of sessions.
func (s *PGStore) SessionCount() (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}
	return count, nil
}

// DeleteSession removes a session and all its messages.
func (s *PGStore) DeleteSession(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`DELETE FROM sessions WHERE key = $1`, key)
	if err != nil {
		return fmt.Errorf("delete session %q: %w", key, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("session %q not found", key)
	}
	return nil
}

// EvictExpired deletes sessions whose updated_at is older than ttl from now.
func (s *PGStore) EvictExpired(ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-ttl)
	res, err := s.db.Exec(`DELETE FROM sessions WHERE updated_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("evict expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EvictLRU deletes the least-recently-updated sessions until the total count
// is at or below maxSessions.
func (s *PGStore) EvictLRU(maxSessions int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxSessions <= 0 {
		return 0, nil
	}

	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}

	if count <= int64(maxSessions) {
		return 0, nil
	}

	excess := count - int64(maxSessions)
	res, err := s.db.Exec(
		`DELETE FROM sessions WHERE key IN (
			SELECT key FROM sessions ORDER BY updated_at ASC LIMIT $1
		)`, excess,
	)
	if err != nil {
		return 0, fmt.Errorf("evict LRU sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Close is a no-op — the caller owns the *sql.DB and is responsible for closing it.
func (s *PGStore) Close() error {
	return nil
}
