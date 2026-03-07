// Package pgstore provides PostgreSQL database helpers for SaaS mode.
// It uses pgx/v5 via the database/sql stdlib interface for consistency
// with the existing SQLite stores.
package pgstore

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Config holds PostgreSQL connection configuration.
type Config struct {
	// DSN is the PostgreSQL connection string (e.g. "postgres://user:pass@host:5432/dbname?sslmode=require").
	DSN string

	// MaxOpenConns is the maximum number of open connections (default 25).
	MaxOpenConns int

	// MaxIdleConns is the maximum number of idle connections (default 10).
	MaxIdleConns int

	// ConnMaxLifetime is the maximum amount of time a connection may be reused (default 5m).
	ConnMaxLifetime time.Duration

	// ConnMaxIdleTime is the maximum amount of time a connection may be idle (default 1m).
	ConnMaxIdleTime time.Duration
}

// DefaultConfig returns a Config with sensible pool defaults.
func DefaultConfig(dsn string) Config {
	return Config{
		DSN:             dsn,
		MaxOpenConns:    25,
		MaxIdleConns:    10,
		ConnMaxLifetime: 5 * time.Minute,
		ConnMaxIdleTime: 1 * time.Minute,
	}
}

// Open opens a PostgreSQL connection pool using the pgx stdlib driver
// and applies pool configuration.
func Open(cfg Config) (*sql.DB, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("pgstore: DSN is required")
	}

	db, err := sql.Open("pgx", cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("pgstore: open: %w", err)
	}

	if cfg.MaxOpenConns > 0 {
		db.SetMaxOpenConns(cfg.MaxOpenConns)
	}
	if cfg.MaxIdleConns > 0 {
		db.SetMaxIdleConns(cfg.MaxIdleConns)
	}
	if cfg.ConnMaxLifetime > 0 {
		db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
	}
	if cfg.ConnMaxIdleTime > 0 {
		db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)
	}

	// Verify connectivity.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgstore: ping: %w", err)
	}

	return db, nil
}
