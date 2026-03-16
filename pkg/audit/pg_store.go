package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// PGAuditStore implements AuditStore using PostgreSQL.
type PGAuditStore struct {
	db *sql.DB
}

// NewPGAuditStore creates a new PostgreSQL-backed audit store.
// It creates the audit_log table if it doesn't exist.
func NewPGAuditStore(db *sql.DB) (*PGAuditStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}

	if err := initPGAuditSchema(db); err != nil {
		return nil, fmt.Errorf("init pg audit schema: %w", err)
	}

	return &PGAuditStore{db: db}, nil
}

func initPGAuditSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS audit_log (
			id          TEXT PRIMARY KEY,
			timestamp   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
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
func (s *PGAuditStore) Log(ctx context.Context, event *Event) error {
	if event == nil {
		return fmt.Errorf("event must not be nil")
	}
	if event.Action == "" {
		return fmt.Errorf("event action must not be empty")
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (id, timestamp, user_id, actor, action, resource, resource_id, detail, ip_address, user_agent, status, error_msg)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`,
		event.ID,
		event.Timestamp.UTC(),
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
func (s *PGAuditStore) Query(ctx context.Context, filter QueryFilter) ([]*Event, error) {
	query, args := buildPGQuery("SELECT id, timestamp, user_id, actor, action, resource, resource_id, detail, ip_address, user_agent, status, error_msg FROM audit_log", filter)

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
	argIdx := len(args) + 1
	query += fmt.Sprintf(" LIMIT $%d", argIdx)
	args = append(args, limit)
	if filter.Offset > 0 {
		argIdx++
		query += fmt.Sprintf(" OFFSET $%d", argIdx)
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		e, err := scanPGEvent(rows)
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
func (s *PGAuditStore) Count(ctx context.Context, filter QueryFilter) (int64, error) {
	query, args := buildPGQuery("SELECT COUNT(*) FROM audit_log", filter)

	var count int64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, fmt.Errorf("count audit events: %w", err)
	}
	return count, nil
}

// DeleteBefore removes audit events older than the given timestamp.
func (s *PGAuditStore) DeleteBefore(ctx context.Context, before time.Time) (int64, error) {
	result, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE timestamp < $1`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete old audit events: %w", err)
	}
	return result.RowsAffected()
}

// Close is a no-op — the database connection is managed externally.
func (s *PGAuditStore) Close() error {
	return nil
}

// buildPGQuery constructs a WHERE clause from a QueryFilter with PostgreSQL
// numbered placeholders ($1, $2, ...).
func buildPGQuery(base string, filter QueryFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	argIdx := 0

	if filter.UserID != "" {
		argIdx++
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, filter.UserID)
	}
	if filter.Action != "" {
		argIdx++
		if strings.HasSuffix(filter.Action, ".") {
			conditions = append(conditions, fmt.Sprintf("action LIKE $%d", argIdx))
			args = append(args, filter.Action+"%")
		} else {
			conditions = append(conditions, fmt.Sprintf("action = $%d", argIdx))
			args = append(args, filter.Action)
		}
	}
	if filter.Resource != "" {
		argIdx++
		conditions = append(conditions, fmt.Sprintf("resource = $%d", argIdx))
		args = append(args, filter.Resource)
	}
	if filter.ResourceID != "" {
		argIdx++
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIdx))
		args = append(args, filter.ResourceID)
	}
	if filter.Status != "" {
		argIdx++
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status)
	}
	if !filter.Since.IsZero() {
		argIdx++
		conditions = append(conditions, fmt.Sprintf("timestamp >= $%d", argIdx))
		args = append(args, filter.Since.UTC())
	}
	if !filter.Until.IsZero() {
		argIdx++
		conditions = append(conditions, fmt.Sprintf("timestamp <= $%d", argIdx))
		args = append(args, filter.Until.UTC())
	}

	if len(conditions) > 0 {
		base += " WHERE " + strings.Join(conditions, " AND ")
	}

	return base, args
}

// scanPGEvent scans a row into an Event (PostgreSQL variant — timestamps are native).
func scanPGEvent(rows *sql.Rows) (*Event, error) {
	var (
		e         Event
		detailStr string
	)

	if err := rows.Scan(
		&e.ID, &e.Timestamp, &e.UserID, &e.Actor, &e.Action,
		&e.Resource, &e.ResourceID, &detailStr,
		&e.IPAddress, &e.UserAgent, &e.Status, &e.ErrorMsg,
	); err != nil {
		return nil, fmt.Errorf("scan audit event: %w", err)
	}

	if detailStr != "" && detailStr != "{}" {
		e.Detail = make(map[string]string)
		_ = json.Unmarshal([]byte(detailStr), &e.Detail)
	}

	return &e, nil
}
