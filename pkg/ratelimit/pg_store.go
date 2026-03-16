package ratelimit

import (
	"database/sql"
	"fmt"
	"time"
)

// PGRateLimitStore implements RateLimitStore using PostgreSQL.
type PGRateLimitStore struct {
	db *sql.DB
}

// NewPGRateLimitStore creates a new PostgreSQL-backed rate limit store.
// It creates the rate_limits table if it doesn't exist.
func NewPGRateLimitStore(db *sql.DB) (*PGRateLimitStore, error) {
	if db == nil {
		return nil, fmt.Errorf("db must not be nil")
	}

	if err := initPGRateLimitSchema(db); err != nil {
		return nil, fmt.Errorf("init pg rate limit schema: %w", err)
	}

	return &PGRateLimitStore{db: db}, nil
}

func initPGRateLimitSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS rate_limits (
			user_id    TEXT PRIMARY KEY,
			tier       TEXT NOT NULL DEFAULT 'free',
			tokens     DOUBLE PRECISION NOT NULL DEFAULT 0,
			last_time  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			day_count  INTEGER NOT NULL DEFAULT 0,
			day_start  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

// SaveBucket persists a user's bucket state.
func (s *PGRateLimitStore) SaveBucket(userID string, tier PlanTier, state BucketState) error {
	_, err := s.db.Exec(`
		INSERT INTO rate_limits (user_id, tier, tokens, last_time, day_count, day_start, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT(user_id) DO UPDATE SET
			tier = EXCLUDED.tier,
			tokens = EXCLUDED.tokens,
			last_time = EXCLUDED.last_time,
			day_count = EXCLUDED.day_count,
			day_start = EXCLUDED.day_start,
			updated_at = NOW()
	`, userID, string(tier), state.Tokens, state.LastTime.UTC(),
		state.DayCount, state.DayStart.UTC())
	if err != nil {
		return fmt.Errorf("save rate limit bucket: %w", err)
	}
	return nil
}

// LoadBucket retrieves a user's saved bucket state.
func (s *PGRateLimitStore) LoadBucket(userID string) (PlanTier, BucketState, error) {
	var (
		tierStr  string
		tokens   float64
		lastTime time.Time
		dayCount int64
		dayStart time.Time
	)

	err := s.db.QueryRow(`
		SELECT tier, tokens, last_time, day_count, day_start
		FROM rate_limits WHERE user_id = $1
	`, userID).Scan(&tierStr, &tokens, &lastTime, &dayCount, &dayStart)
	if err == sql.ErrNoRows {
		return "", BucketState{}, ErrNotFound
	}
	if err != nil {
		return "", BucketState{}, fmt.Errorf("load rate limit bucket: %w", err)
	}

	return PlanTier(tierStr), BucketState{
		Tokens:   tokens,
		LastTime: lastTime,
		DayCount: dayCount,
		DayStart: dayStart,
	}, nil
}

// DeleteBucket removes a user's saved bucket state.
func (s *PGRateLimitStore) DeleteBucket(userID string) error {
	_, err := s.db.Exec(`DELETE FROM rate_limits WHERE user_id = $1`, userID)
	if err != nil {
		return fmt.Errorf("delete rate limit bucket: %w", err)
	}
	return nil
}

// Close is a no-op — the database connection is managed externally.
func (s *PGRateLimitStore) Close() error {
	return nil
}
