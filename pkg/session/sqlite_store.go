package session

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/standardws/operator/pkg/providers"
)

// SQLiteStore implements SessionStore backed by a SQLite database.
// All writes are immediate (write-through); Save is a no-op.
type SQLiteStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewSQLiteStore opens (or creates) a SQLite database at dbPath and
// initialises the sessions/messages schema.
func NewSQLiteStore(dbPath string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// Limit connections to 1 writer to avoid SQLITE_BUSY in WAL mode.
	db.SetMaxOpenConns(4)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}

	return &SQLiteStore{db: db}, nil
}

func initSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS sessions (
    key         TEXT PRIMARY KEY,
    tenant_id   TEXT NOT NULL DEFAULT '',
    summary     TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now')),
    updated_at  TEXT NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_sessions_tenant ON sessions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_updated ON sessions(tenant_id, updated_at);

CREATE TABLE IF NOT EXISTS messages (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key  TEXT NOT NULL REFERENCES sessions(key) ON DELETE CASCADE,
    role         TEXT NOT NULL,
    content      TEXT NOT NULL DEFAULT '',
    tool_calls   TEXT NOT NULL DEFAULT '[]',
    tool_call_id TEXT NOT NULL DEFAULT '',
    reasoning    TEXT NOT NULL DEFAULT '',
    media        TEXT NOT NULL DEFAULT '[]',
    extra        TEXT NOT NULL DEFAULT '{}',
    created_at   TEXT NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%fZ','now'))
);

CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_key);
`
	_, err := db.Exec(schema)
	return err
}

// GetOrCreate returns the session for the given key, creating it if needed.
func (s *SQLiteStore) GetOrCreate(key string) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()

	// Upsert session row.
	_, err := s.db.Exec(
		`INSERT INTO sessions (key, created_at, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO NOTHING`,
		key, now.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano),
	)
	if err != nil {
		return nil, fmt.Errorf("upsert session %q: %w", key, err)
	}

	return s.loadSession(key)
}

// loadSession reads a session and its messages from the database.
// Caller must hold at least a read lock.
func (s *SQLiteStore) loadSession(key string) (*Session, error) {
	var summary, createdStr, updatedStr string
	err := s.db.QueryRow(
		`SELECT summary, created_at, updated_at FROM sessions WHERE key = ?`, key,
	).Scan(&summary, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session %q not found", key)
	}
	if err != nil {
		return nil, fmt.Errorf("query session %q: %w", key, err)
	}

	created, _ := time.Parse(time.RFC3339Nano, createdStr)
	updated, _ := time.Parse(time.RFC3339Nano, updatedStr)

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

func (s *SQLiteStore) loadMessages(key string) ([]providers.Message, error) {
	rows, err := s.db.Query(
		`SELECT role, content, tool_calls, tool_call_id, reasoning, media
		 FROM messages WHERE session_key = ? ORDER BY id ASC`, key,
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
func (s *SQLiteStore) AddMessage(key string, msg providers.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Ensure session exists.
	now := time.Now().Format(time.RFC3339Nano)
	_, err := s.db.Exec(
		`INSERT INTO sessions (key, created_at, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET updated_at = ?`,
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
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		key, msg.Role, msg.Content, string(toolCallsJSON), msg.ToolCallID, msg.ReasoningContent, string(mediaJSON),
	)
	if err != nil {
		return fmt.Errorf("insert message for %q: %w", key, err)
	}

	return nil
}

// GetHistory returns a copy of all messages for the session.
func (s *SQLiteStore) GetHistory(key string) ([]providers.Message, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadMessages(key)
}

// GetSummary returns the conversation summary for the session.
func (s *SQLiteStore) GetSummary(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var summary string
	err := s.db.QueryRow(`SELECT summary FROM sessions WHERE key = ?`, key).Scan(&summary)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get summary for %q: %w", key, err)
	}
	return summary, nil
}

// SetSummary updates the conversation summary.
func (s *SQLiteStore) SetSummary(key string, summary string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Format(time.RFC3339Nano)
	res, err := s.db.Exec(
		`UPDATE sessions SET summary = ?, updated_at = ? WHERE key = ?`,
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
func (s *SQLiteStore) SetHistory(key string, messages []providers.Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete existing messages.
	if _, err := tx.Exec(`DELETE FROM messages WHERE session_key = ?`, key); err != nil {
		return fmt.Errorf("delete messages for %q: %w", key, err)
	}

	// Insert new messages.
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
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			key, msg.Role, msg.Content, string(toolCallsJSON), msg.ToolCallID, msg.ReasoningContent, string(mediaJSON),
		); err != nil {
			return fmt.Errorf("insert message: %w", err)
		}
	}

	now := time.Now().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, now, key); err != nil {
		return fmt.Errorf("update session timestamp: %w", err)
	}

	return tx.Commit()
}

// TruncateHistory removes all but the last keepLast messages.
func (s *SQLiteStore) TruncateHistory(key string, keepLast int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if keepLast <= 0 {
		_, err := s.db.Exec(`DELETE FROM messages WHERE session_key = ?`, key)
		if err != nil {
			return fmt.Errorf("truncate all messages for %q: %w", key, err)
		}
		return nil
	}

	// Delete all but the last N messages.
	_, err := s.db.Exec(
		`DELETE FROM messages WHERE session_key = ? AND id NOT IN (
			SELECT id FROM messages WHERE session_key = ? ORDER BY id DESC LIMIT ?
		)`,
		key, key, keepLast,
	)
	if err != nil {
		return fmt.Errorf("truncate messages for %q: %w", key, err)
	}
	return nil
}

// Save is a no-op for SQLiteStore since all writes are immediate.
func (s *SQLiteStore) Save(_ string) error {
	return nil
}

// SessionCount returns the total number of sessions.
func (s *SQLiteStore) SessionCount() (int64, error) {
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
func (s *SQLiteStore) DeleteSession(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Messages are deleted via ON DELETE CASCADE.
	res, err := s.db.Exec(`DELETE FROM sessions WHERE key = ?`, key)
	if err != nil {
		return fmt.Errorf("delete session %q: %w", key, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("session %q not found", key)
	}
	return nil
}

// EvictExpired deletes sessions whose updated_at is older than ttl from now.
// Returns the number of sessions evicted.
func (s *SQLiteStore) EvictExpired(ttl time.Duration) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-ttl).Format(time.RFC3339Nano)

	// Delete messages first (in case foreign keys aren't cascading in all modes),
	// then sessions.
	res, err := s.db.Exec(
		`DELETE FROM sessions WHERE updated_at < ?`, cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("evict expired sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EvictLRU deletes the least-recently-updated sessions until the total count
// is at or below maxSessions. Returns the number of sessions evicted.
func (s *SQLiteStore) EvictLRU(maxSessions int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if maxSessions <= 0 {
		return 0, nil
	}

	// Count current sessions.
	var count int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sessions: %w", err)
	}

	if count <= int64(maxSessions) {
		return 0, nil
	}

	// Delete oldest sessions beyond the limit.
	excess := count - int64(maxSessions)
	res, err := s.db.Exec(
		`DELETE FROM sessions WHERE key IN (
			SELECT key FROM sessions ORDER BY updated_at ASC LIMIT ?
		)`, excess,
	)
	if err != nil {
		return 0, fmt.Errorf("evict LRU sessions: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Close closes the underlying database connection.
func (s *SQLiteStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}
