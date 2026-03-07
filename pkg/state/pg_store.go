package state

import (
	"database/sql"
	"fmt"
	"sync"
	"time"
)

// PGStateStore implements StateStore backed by PostgreSQL.
// All writes are immediate (write-through).
type PGStateStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewPGStateStore creates a PostgreSQL-backed state store using the provided *sql.DB.
// It initialises the schema (state table) if not present.
func NewPGStateStore(db *sql.DB) (*PGStateStore, error) {
	if db == nil {
		return nil, fmt.Errorf("pg state store: db is nil")
	}
	if err := initPGStateSchema(db); err != nil {
		return nil, fmt.Errorf("pg state store: init schema: %w", err)
	}
	return &PGStateStore{db: db}, nil
}

func initPGStateSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL DEFAULT '',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
	_, err := db.Exec(schema)
	return err
}

// Get retrieves the value for the given key. Returns "" if not found.
func (s *PGStateStore) Get(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var value string
	err := s.db.QueryRow(`SELECT value FROM state WHERE key = $1`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get state %q: %w", key, err)
	}
	return value, nil
}

// Set stores a key-value pair with the current timestamp.
func (s *PGStateStore) Set(key string, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	_, err := s.db.Exec(
		`INSERT INTO state (key, value, updated_at) VALUES ($1, $2, $3)
		 ON CONFLICT(key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`,
		key, value, now,
	)
	if err != nil {
		return fmt.Errorf("set state %q: %w", key, err)
	}
	return nil
}

// GetTimestamp returns the last update time for the given key.
// Returns zero time if the key has never been set.
func (s *PGStateStore) GetTimestamp(key string) (time.Time, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var updated time.Time
	err := s.db.QueryRow(`SELECT updated_at FROM state WHERE key = $1`, key).Scan(&updated)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, fmt.Errorf("get timestamp %q: %w", key, err)
	}
	return updated, nil
}

// Close is a no-op — the caller owns the *sql.DB and is responsible for closing it.
func (s *PGStateStore) Close() error {
	return nil
}
