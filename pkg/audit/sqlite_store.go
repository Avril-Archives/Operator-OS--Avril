package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLiteAuditStore implements AuditStore using SQLite.
type SQLiteAuditStore struct {
	db *sql.DB
}

// NewSQLiteAuditStore creates a new SQLite-backed audit store.
// It creates the audit_log table if it doesn't exist.
func NewSQLiteAuditStore(db *sql.DB) (*SQLiteAuditStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}

	if err := initAuditSchema(db); err != nil {
		return nil, fmt.Errorf("init audit schema: %w", err)
	}

	return &SQLiteAuditStore{db: db}, nil
}

func initAuditSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id          TEXT PRIMARY KEY,
			timestamp   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			user_id     TEXT NOT NULL DEFAULT '',
			actor       TEXT NOT NULL DEFAULT '',
			action      TEXT NOT NULL,
			resource    TEXT NOT NULL DEFAULT '',
			resource_id TEXT NOT NULL DEFAULT '',
			detail      TEXT NOT NULL DEFAULT '{}',
			ip_address  TEXT NOT NULL DEFAULT '',
			user_agent  TEXT NOT NULL DEFAULT '',
			status      TEXT NOT NULL DEFAULT 'success',
			error_msg   TEXT NOT NULL DEFAULT ''
		);
		CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
		CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
		CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
		CREATE INDEX IF NOT EXISTS idx_audit_log_resource ON audit_log(resource, resource_id);
	`)
	return err
}

// Log records an audit event.
func (s *SQLiteAuditStore) Log(ctx context.Context, event *Event) error {
	if event == nil {
		return fmt.Errorf("event must not be nil")
	}
	if event.Action == "" {
		return fmt.Errorf("event action must not be empty")
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (id, timestamp, user_id, actor, action, resource, resource_id, detail, ip_address, user_agent, status, error_msg)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		event.ID,
		event.Timestamp.UTC().Format(time.RFC3339Nano),
		event.UserID,
		event.Actor,
		event.Action,
		event.Resource,
		event.ResourceID,
		event.DetailJSON(),
		event.IPAddress,
		event.UserAgent,
		event.Status,
		event.ErrorMsg,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}
	return nil
}

// Query retrieves audit events matching the given filter.
func (s *SQLiteAuditStore) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	query, args := buildQuery("SELECT id, timestamp, user_id, actor, action, resource, resource_id, detail, ip_address, user_agent, status, error_msg FROM audit_log", filter)

	// Add ordering
	query += " ORDER BY timestamp DESC"

	// Add pagination
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	query += fmt.Sprintf(" LIMIT %d", limit)
	if filter.Offset > 0 {
		query += fmt.Sprintf(" OFFSET %d", filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit events: %w", err)
	}

	return events, nil
}

// Count returns the number of events matching the given filter.
func (s *SQLiteAuditStore) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	query, args := buildQuery("SELECT COUNT(*) FROM audit_log", filter)

	var count int64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit events: %w", err)
	}
	return count, nil
}

// DeleteBefore removes audit events older than the given timestamp.
func (s *SQLiteAuditStore) DeleteBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE timestamp < ?`, before.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("delete old audit events: %w", err)
	}
	return result.RowsAffected()
}

// Close is a no-op — the database connection is managed externally.
func (s *SQLiteAuditStore) Close() error {
	return nil
}

// buildQuery constructs a WHERE clause from a QueryFilter.
func buildQuery(base string, filter QueryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if filter.UserID != "" {
		conditions = append(conditions, "user_id = ?")
		args = append(args, filter.UserID)
	}
	if filter.Action != "" {
		// Support prefix matching for action categories (e.g., "auth." matches all auth actions)
		if strings.HasSuffix(filter.Action, ".") {
			conditions = append(conditions, "action LIKE ?")
			args = append(args, filter.Action+"%")
		} else {
			conditions = append(conditions, "action = ?")
			args = append(args, filter.Action)
		}
	}
	if filter.Resource != "" {
		conditions = append(conditions, "resource = ?")
		args = append(args, filter.Resource)
	}
	if filter.ResourceID != "" {
		conditions = append(conditions, "resource_id = ?")
		args = append(args, filter.ResourceID)
	}
	if filter.Status != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, filter.Status)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.Since.UTC().Format(time.RFC3339Nano))
	}
	if !filter.Until.IsZero() {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.Until.UTC().Format(time.RFC3339Nano))
	}

	if len(conditions) > 0 {
		base += " WHERE " + strings.Join(conditions, " AND ")
	}

	return base, args
}

// scanEvent scans a row into an Event.
func scanEvent(rows *sql.Rows) (*Event, error) {
	var (
		e         Event
		ts        string
		detailStr string
	)

	if err := rows.Scan(
		&e.ID, &ts, &e.UserID, &e.Actor, &e.Action,
		&e.Resource, &e.ResourceID, &detailStr,
		&e.IPAddress, &e.UserAgent, &e.Status, &e.ErrorMsg,
	); err != nil {
		return nil, fmt.Errorf("scan audit event: %w", err)
	}

	if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
		e.Timestamp = t
	}

	if detailStr != "" && detailStr != "{}" {
		e.Detail = make(map[string]string)
		_ = json.Unmarshal([]byte(detailStr), &e.Detail)
	}

	return &e, nil
}
