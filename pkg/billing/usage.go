package billing

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// UsageEvent records a single LLM token consumption event.
type UsageEvent struct {
	ID            string    `json:"id"`
	UserID        string    `json:"user_id"`
	Model         string    `json:"model"`
	Provider      string    `json:"provider"`
	InputTokens   int64     `json:"input_tokens"`
	OutputTokens  int64     `json:"output_tokens"`
	TotalTokens   int64     `json:"total_tokens"`
	SessionKey    string    `json:"session_key,omitempty"`
	AgentID       string    `json:"agent_id,omitempty"`
	DurationMs    int64     `json:"duration_ms,omitempty"`
	EstimatedCost float64   `json:"estimated_cost,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// UsageSummary aggregates token usage for a user over a time period.
type UsageSummary struct {
	UserID        string  `json:"user_id"`
	TotalInput    int64   `json:"total_input_tokens"`
	TotalOutput   int64   `json:"total_output_tokens"`
	TotalTokens   int64   `json:"total_tokens"`
	TotalRequests int64   `json:"total_requests"`
	TotalCost     float64 `json:"total_cost"`
}

// ModelUsage aggregates usage per model.
type ModelUsage struct {
	Model         string  `json:"model"`
	Provider      string  `json:"provider"`
	InputTokens   int64   `json:"input_tokens"`
	OutputTokens  int64   `json:"output_tokens"`
	TotalTokens   int64   `json:"total_tokens"`
	RequestCount  int64   `json:"request_count"`
	EstimatedCost float64 `json:"estimated_cost"`
}

// DailyUsage aggregates usage per day.
type DailyUsage struct {
	Date          string `json:"date"` // YYYY-MM-DD
	InputTokens   int64  `json:"input_tokens"`
	OutputTokens  int64  `json:"output_tokens"`
	TotalTokens   int64  `json:"total_tokens"`
	RequestCount  int64  `json:"request_count"`
}

// UsageQuery defines filters for querying usage events.
type UsageQuery struct {
	UserID string
	Model  string
	Since  time.Time
	Until  time.Time
	Limit  int
	Offset int
}

// UsageStore abstracts usage event persistence and querying.
type UsageStore interface {
	// Record inserts a usage event.
	Record(event *UsageEvent) error
	// GetSummary returns aggregate usage for a user in the given time range.
	GetSummary(userID string, since, until time.Time) (*UsageSummary, error)
	// GetByModel returns per-model usage breakdown for a user in the given time range.
	GetByModel(userID string, since, until time.Time) ([]*ModelUsage, error)
	// GetDaily returns daily usage for a user in the given time range.
	GetDaily(userID string, since, until time.Time) ([]*DailyUsage, error)
	// GetCurrentPeriodUsage returns the total tokens used in the current billing period.
	GetCurrentPeriodUsage(userID string, periodStart time.Time) (int64, error)
	// GetCurrentPeriodMessages returns total LLM requests in the current billing period.
	GetCurrentPeriodMessages(userID string, periodStart time.Time) (int64, error)
	// ListEvents returns usage events matching the query.
	ListEvents(query UsageQuery) ([]*UsageEvent, error)
	// DeleteBefore removes usage events older than the given timestamp.
	DeleteBefore(before time.Time) (int64, error)
	// Close releases resources.
	Close() error
}

// ---------- SQLite implementation ----------

const createUsageEventsSQL = `
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
`

// SQLiteUsageStore implements UsageStore backed by SQLite.
type SQLiteUsageStore struct {
	mu sync.RWMutex
	db *sql.DB
}

// NewSQLiteUsageStore creates a SQLiteUsageStore and ensures the table exists.
func NewSQLiteUsageStore(db *sql.DB) (*SQLiteUsageStore, error) {
	if db == nil {
		return nil, fmt.Errorf("billing: db is nil")
	}
	if _, err := db.Exec(createUsageEventsSQL); err != nil {
		return nil, fmt.Errorf("billing: create usage_events table: %w", err)
	}
	return &SQLiteUsageStore{db: db}, nil
}

func (s *SQLiteUsageStore) Record(event *UsageEvent) error {
	if event == nil {
		return fmt.Errorf("billing: usage event is nil")
	}
	if event.ID == "" {
		return fmt.Errorf("billing: usage event ID is empty")
	}
	if event.UserID == "" {
		return fmt.Errorf("billing: usage event user_id is empty")
	}
	if event.Model == "" {
		return fmt.Errorf("billing: usage event model is empty")
	}

	// Auto-compute total if not set.
	if event.TotalTokens == 0 && (event.InputTokens > 0 || event.OutputTokens > 0) {
		event.TotalTokens = event.InputTokens + event.OutputTokens
	}

	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO usage_events (
			id, user_id, model, provider, input_tokens, output_tokens, total_tokens,
			session_key, agent_id, duration_ms, estimated_cost, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.UserID, event.Model, event.Provider,
		event.InputTokens, event.OutputTokens, event.TotalTokens,
		event.SessionKey, event.AgentID, event.DurationMs,
		event.EstimatedCost, event.CreatedAt.UTC(),
	)
	if err != nil {
		if isDuplicateErr(err) {
			return ErrDuplicateID
		}
		return fmt.Errorf("billing: insert usage event: %w", err)
	}
	return nil
}

func (s *SQLiteUsageStore) GetSummary(userID string, since, until time.Time) (*UsageSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	row := s.db.QueryRow(`
		SELECT
			COALESCE(SUM(input_tokens), 0),
			COALESCE(SUM(output_tokens), 0),
			COALESCE(SUM(total_tokens), 0),
			COUNT(*),
			COALESCE(SUM(estimated_cost), 0)
		FROM usage_events
		WHERE user_id = ? AND created_at >= ? AND created_at < ?`,
		userID, since.UTC(), until.UTC(),
	)

	summary := &UsageSummary{UserID: userID}
	err := row.Scan(
		&summary.TotalInput,
		&summary.TotalOutput,
		&summary.TotalTokens,
		&summary.TotalRequests,
		&summary.TotalCost,
	)
	if err != nil {
		return nil, fmt.Errorf("billing: get usage summary: %w", err)
	}
	return summary, nil
}

func (s *SQLiteUsageStore) GetByModel(userID string, since, until time.Time) ([]*ModelUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT
			model, provider,
			SUM(input_tokens), SUM(output_tokens), SUM(total_tokens),
			COUNT(*),
			SUM(estimated_cost)
		FROM usage_events
		WHERE user_id = ? AND created_at >= ? AND created_at < ?
		GROUP BY model, provider
		ORDER BY SUM(total_tokens) DESC`,
		userID, since.UTC(), until.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("billing: get usage by model: %w", err)
	}
	defer rows.Close()

	var out []*ModelUsage
	for rows.Next() {
		mu := &ModelUsage{}
		if err := rows.Scan(
			&mu.Model, &mu.Provider,
			&mu.InputTokens, &mu.OutputTokens, &mu.TotalTokens,
			&mu.RequestCount, &mu.EstimatedCost,
		); err != nil {
			return nil, fmt.Errorf("billing: scan model usage: %w", err)
		}
		out = append(out, mu)
	}
	return out, rows.Err()
}

func (s *SQLiteUsageStore) GetDaily(userID string, since, until time.Time) ([]*DailyUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT
			SUBSTR(created_at, 1, 10) as day,
			COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0), COALESCE(SUM(total_tokens), 0),
			COUNT(*)
		FROM usage_events
		WHERE user_id = ? AND created_at >= ? AND created_at < ?
		GROUP BY SUBSTR(created_at, 1, 10)
		ORDER BY day ASC`,
		userID, since.UTC(), until.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("billing: get daily usage: %w", err)
	}
	defer rows.Close()

	var out []*DailyUsage
	for rows.Next() {
		du := &DailyUsage{}
		if err := rows.Scan(&du.Date, &du.InputTokens, &du.OutputTokens, &du.TotalTokens, &du.RequestCount); err != nil {
			return nil, fmt.Errorf("billing: scan daily usage: %w", err)
		}
		out = append(out, du)
	}
	return out, rows.Err()
}

func (s *SQLiteUsageStore) GetCurrentPeriodUsage(userID string, periodStart time.Time) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var total int64
	err := s.db.QueryRow(`
		SELECT COALESCE(SUM(total_tokens), 0) FROM usage_events
		WHERE user_id = ? AND created_at >= ?`,
		userID, periodStart.UTC(),
	).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("billing: get period usage: %w", err)
	}
	return total, nil
}

func (s *SQLiteUsageStore) GetCurrentPeriodMessages(userID string, periodStart time.Time) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM usage_events
		WHERE user_id = ? AND created_at >= ?`,
		userID, periodStart.UTC(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("billing: get period messages: %w", err)
	}
	return count, nil
}

func (s *SQLiteUsageStore) ListEvents(query UsageQuery) ([]*UsageEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	where := "WHERE 1=1"
	args := make([]any, 0)

	if query.UserID != "" {
		where += " AND user_id = ?"
		args = append(args, query.UserID)
	}
	if query.Model != "" {
		where += " AND model = ?"
		args = append(args, query.Model)
	}
	if !query.Since.IsZero() {
		where += " AND created_at >= ?"
		args = append(args, query.Since.UTC())
	}
	if !query.Until.IsZero() {
		where += " AND created_at < ?"
		args = append(args, query.Until.UTC())
	}

	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}

	q := fmt.Sprintf(`
		SELECT id, user_id, model, provider, input_tokens, output_tokens, total_tokens,
		       session_key, agent_id, duration_ms, estimated_cost, created_at
		FROM usage_events %s
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?`, where)
	args = append(args, limit, query.Offset)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("billing: list usage events: %w", err)
	}
	defer rows.Close()

	var out []*UsageEvent
	for rows.Next() {
		ev := &UsageEvent{}
		if err := rows.Scan(
			&ev.ID, &ev.UserID, &ev.Model, &ev.Provider,
			&ev.InputTokens, &ev.OutputTokens, &ev.TotalTokens,
			&ev.SessionKey, &ev.AgentID, &ev.DurationMs,
			&ev.EstimatedCost, &ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("billing: scan usage event: %w", err)
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

func (s *SQLiteUsageStore) DeleteBefore(before time.Time) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`DELETE FROM usage_events WHERE created_at < ?`, before.UTC())
	if err != nil {
		return 0, fmt.Errorf("billing: delete usage events: %w", err)
	}
	return res.RowsAffected()
}

func (s *SQLiteUsageStore) Close() error { return nil }
