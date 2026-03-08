package session

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/providers"
)

// Tenant context key type.
type tenantContextKey struct{}

// WithTenantID returns a new context carrying the given tenant ID.
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// TenantIDFromContext extracts the tenant ID from a context. Returns "" if unset.
func TenantIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(tenantContextKey{}).(string); ok {
		return v
	}
	return ""
}

// TenantStore implements SessionStore with tenant-level isolation.
// All operations are scoped to a single tenant_id, ensuring that
// different tenants cannot read or write each other's sessions.
type TenantStore struct {
	db       *sql.DB
	tenantID string
	mu       sync.RWMutex
}

// NewTenantStore creates a tenant-scoped session store backed by an existing
// SQLite database. The database must already have the sessions/messages tables
// with a tenant_id column (migration 005).
func NewTenantStore(db *sql.DB, tenantID string) (*TenantStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID must not be empty")
	}
	return &TenantStore{db: db, tenantID: tenantID}, nil
}

// TenantID returns the tenant ID this store is scoped to.
func (t *TenantStore) TenantID() string {
	return t.tenantID
}

// GetOrCreate returns the session for the given key within this tenant,
// creating it if it doesn't exist.
func (t *TenantStore) GetOrCreate(key string) (*Session, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Format(time.RFC3339Nano)

	_, err := t.db.Exec(
		`INSERT INTO sessions (key, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO NOTHING`,
		t.scopedKey(key), t.tenantID, now, now,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert session %q for tenant %q: %w", key, t.tenantID, err)
	}

	return t.loadSession(key)
}

// scopedKey produces a unique session key scoped to this tenant.
// Format: "tenant:<tenantID>:<originalKey>"
func (t *TenantStore) scopedKey(key string) string {
	return "tenant:" + t.tenantID + ":" + key
}

// loadSession reads a session and its messages from the database, scoped to this tenant.
func (t *TenantStore) loadSession(key string) (*Session, error) {
	sk := t.scopedKey(key)

	var summary, createdStr, updatedStr string
	err := t.db.QueryRow(
		`SELECT summary, created_at, updated_at FROM sessions WHERE key = ? AND tenant_id = ?`,
		sk, t.tenantID,
	).Scan(&summary, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session %q not found for tenant %q", key, t.tenantID)
	}
	if err != nil {
		return nil, fmt.Errorf("query session %q for tenant %q: %w", key, t.tenantID, err)
	}

	created, _ := time.Parse(time.RFC3339Nano, createdStr)
	updated, _ := time.Parse(time.RFC3339Nano, updatedStr)

	messages, err := t.loadMessages(sk)
	if err != nil {
		return nil, err
	}

	return &Session{
		Key:      key, // Return original (unscoped) key to callers
		Messages: messages,
		Summary:  summary,
		Created:  created,
		Updated:  updated,
	}, nil
}

func (t *TenantStore) loadMessages(scopedKey string) ([]providers.Message, error) {
	rows, err := t.db.Query(
		`SELECT role, content, tool_calls, tool_call_id, reasoning, media
		 FROM messages WHERE session_key = ? ORDER BY id ASC`, scopedKey,
	)
	if err != nil {
		return nil, fmt.Errorf("query messages for %q: %w", scopedKey, err)
	}
	defer rows.Close()

	var messages []providers.Message
	for rows.Next() {
		var role, content, toolCallsJSON, toolCallID, reasoning, mediaJSON string
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

// AddMessage appends a message to the session's history within this tenant.
func (t *TenantStore) AddMessage(key string, msg providers.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	sk := t.scopedKey(key)
	now := time.Now().Format(time.RFC3339Nano)

	_, err := t.db.Exec(
		`INSERT INTO sessions (key, tenant_id, created_at, updated_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET updated_at = ?`,
		sk, t.tenantID, now, now, now,
	)
	if err != nil {
		return fmt.Errorf("ensure session %q for tenant %q: %w", key, t.tenantID, err)
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

	_, err = t.db.Exec(
		`INSERT INTO messages (session_key, role, content, tool_calls, tool_call_id, reasoning, media)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		sk, msg.Role, msg.Content, string(toolCallsJSON), msg.ToolCallID, msg.ReasoningContent, string(mediaJSON),
	)
	if err != nil {
		return fmt.Errorf("insert message for %q: %w", key, err)
	}

	return nil
}

// GetHistory returns all messages for the session within this tenant.
func (t *TenantStore) GetHistory(key string) ([]providers.Message, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.loadMessages(t.scopedKey(key))
}

// GetSummary returns the conversation summary for the session within this tenant.
func (t *TenantStore) GetSummary(key string) (string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var summary string
	err := t.db.QueryRow(
		`SELECT summary FROM sessions WHERE key = ? AND tenant_id = ?`,
		t.scopedKey(key), t.tenantID,
	).Scan(&summary)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get summary for %q: %w", key, err)
	}
	return summary, nil
}

// SetSummary updates the conversation summary within this tenant.
func (t *TenantStore) SetSummary(key string, summary string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().Format(time.RFC3339Nano)
	res, err := t.db.Exec(
		`UPDATE sessions SET summary = ?, updated_at = ? WHERE key = ? AND tenant_id = ?`,
		summary, now, t.scopedKey(key), t.tenantID,
	)
	if err != nil {
		return fmt.Errorf("set summary for %q: %w", key, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("session %q not found for tenant %q", key, t.tenantID)
	}
	return nil
}

// SetHistory replaces the entire message history within this tenant.
func (t *TenantStore) SetHistory(key string, messages []providers.Message) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	sk := t.scopedKey(key)

	tx, err := t.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify session belongs to this tenant.
	var count int
	err = tx.QueryRow(`SELECT COUNT(*) FROM sessions WHERE key = ? AND tenant_id = ?`, sk, t.tenantID).Scan(&count)
	if err != nil {
		return fmt.Errorf("check session ownership: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("session %q not found for tenant %q", key, t.tenantID)
	}

	if _, err := tx.Exec(`DELETE FROM messages WHERE session_key = ?`, sk); err != nil {
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
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			sk, msg.Role, msg.Content, string(toolCallsJSON), msg.ToolCallID, msg.ReasoningContent, string(mediaJSON),
		); err != nil {
			return fmt.Errorf("insert message: %w", err)
		}
	}

	now := time.Now().Format(time.RFC3339Nano)
	if _, err := tx.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, now, sk); err != nil {
		return fmt.Errorf("update session timestamp: %w", err)
	}

	return tx.Commit()
}

// TruncateHistory removes all but the last keepLast messages within this tenant.
func (t *TenantStore) TruncateHistory(key string, keepLast int) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	sk := t.scopedKey(key)

	// Verify session belongs to this tenant.
	var count int
	err := t.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE key = ? AND tenant_id = ?`, sk, t.tenantID).Scan(&count)
	if err != nil {
		return fmt.Errorf("check session ownership: %w", err)
	}
	if count == 0 {
		return fmt.Errorf("session %q not found for tenant %q", key, t.tenantID)
	}

	if keepLast <= 0 {
		_, err := t.db.Exec(`DELETE FROM messages WHERE session_key = ?`, sk)
		if err != nil {
			return fmt.Errorf("truncate all messages for %q: %w", key, err)
		}
		return nil
	}

	_, err = t.db.Exec(
		`DELETE FROM messages WHERE session_key = ? AND id NOT IN (
			SELECT id FROM messages WHERE session_key = ? ORDER BY id DESC LIMIT ?
		)`,
		sk, sk, keepLast,
	)
	if err != nil {
		return fmt.Errorf("truncate messages for %q: %w", key, err)
	}
	return nil
}

// Save is a no-op for TenantStore since all writes are immediate.
func (t *TenantStore) Save(_ string) error {
	return nil
}

// Close is a no-op for TenantStore; the shared DB is managed externally.
// Callers who own the *sql.DB are responsible for closing it.
func (t *TenantStore) Close() error {
	return nil
}

// SessionCount returns the number of sessions for this tenant.
func (t *TenantStore) SessionCount() (int64, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var count int64
	err := t.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE tenant_id = ?`, t.tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count sessions for tenant %q: %w", t.tenantID, err)
	}
	return count, nil
}

// DeleteSession removes a session and all its messages within this tenant.
func (t *TenantStore) DeleteSession(key string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	sk := t.scopedKey(key)
	res, err := t.db.Exec(`DELETE FROM sessions WHERE key = ? AND tenant_id = ?`, sk, t.tenantID)
	if err != nil {
		return fmt.Errorf("delete session %q for tenant %q: %w", key, t.tenantID, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("session %q not found for tenant %q", key, t.tenantID)
	}
	return nil
}

// EvictExpired deletes sessions older than ttl for this tenant only.
func (t *TenantStore) EvictExpired(ttl time.Duration) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := time.Now().Add(-ttl).Format(time.RFC3339Nano)
	res, err := t.db.Exec(
		`DELETE FROM sessions WHERE tenant_id = ? AND updated_at < ?`,
		t.tenantID, cutoff,
	)
	if err != nil {
		return 0, fmt.Errorf("evict expired sessions for tenant %q: %w", t.tenantID, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// EvictLRU removes least-recently-updated sessions until the tenant's count
// is at or below maxSessions.
func (t *TenantStore) EvictLRU(maxSessions int) (int64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if maxSessions <= 0 {
		return 0, nil
	}

	var count int64
	if err := t.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE tenant_id = ?`, t.tenantID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count sessions for tenant %q: %w", t.tenantID, err)
	}

	if count <= int64(maxSessions) {
		return 0, nil
	}

	excess := count - int64(maxSessions)
	res, err := t.db.Exec(
		`DELETE FROM sessions WHERE key IN (
			SELECT key FROM sessions WHERE tenant_id = ? ORDER BY updated_at ASC LIMIT ?
		)`, t.tenantID, excess,
	)
	if err != nil {
		return 0, fmt.Errorf("evict LRU sessions for tenant %q: %w", t.tenantID, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ListSessions returns all session keys for this tenant.
func (t *TenantStore) ListSessions() ([]string, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rows, err := t.db.Query(
		`SELECT key FROM sessions WHERE tenant_id = ? ORDER BY updated_at DESC`,
		t.tenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("list sessions for tenant %q: %w", t.tenantID, err)
	}
	defer rows.Close()

	var keys []string
	prefix := "tenant:" + t.tenantID + ":"
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("scan session key: %w", err)
		}
		// Strip the scoped prefix to return original keys.
		if len(key) > len(prefix) {
			key = key[len(prefix):]
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate sessions: %w", err)
	}
	return keys, nil
}

// TenantStoreFactory creates tenant-scoped session stores from a shared database.
type TenantStoreFactory struct {
	db *sql.DB
}

// NewTenantStoreFactory creates a factory for tenant-scoped session stores.
// The database must have the sessions table with tenant_id column (migration 005).
func NewTenantStoreFactory(db *sql.DB) (*TenantStoreFactory, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}
	return &TenantStoreFactory{db: db}, nil
}

// ForTenant returns a SessionStore scoped to the given tenant.
func (f *TenantStoreFactory) ForTenant(tenantID string) (SessionStore, error) {
	return NewTenantStore(f.db, tenantID)
}

// Close closes the underlying database connection.
func (f *TenantStoreFactory) Close() error {
	return f.db.Close()
}
