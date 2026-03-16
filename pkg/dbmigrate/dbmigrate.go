// Package dbmigrate provides an embedded SQL migration framework for SQLite.
//
// Migrations are Go-embedded SQL files that run in version order on startup.
// A schema_migrations table tracks which versions have been applied. Each
// migration runs in a transaction, and the framework guarantees idempotent
// execution: already-applied migrations are skipped.
//
// Usage:
//
//	//go:embed migrations/*.sql
//	var migrations embed.FS
//
//	migrator, _ := dbmigrate.New(db, migrations, "migrations")
//	applied, err := migrator.Up()
package dbmigrate

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Migrations contains the built-in SQL migration files for the Operator OS
// database schema.
//
//go:embed migrations/*.sql
var Migrations embed.FS

// MigrationsDir is the directory within the embedded FS containing migrations.
const MigrationsDir = "migrations"

// AutoMigrate is a convenience function that creates a Migrator from the
// built-in embedded migrations and applies all pending ones. Returns the
// number of migrations applied. This is the typical entry point at startup.
func AutoMigrate(db *sql.DB) (int, error) {
	m, err := New(db, Migrations, MigrationsDir)
	if err != nil {
		return 0, err
	}
	return m.Up()
}

// Migration represents a single versioned migration.
type Migration struct {
	Version int
	Name    string // e.g. "001_create_sessions.sql"
	SQL     string
}

// AppliedMigration records a migration that has been executed.
type AppliedMigration struct {
	Version   int
	Name      string
	AppliedAt time.Time
}

// Migrator manages database migrations for a single *sql.DB.
type Migrator struct {
	db         *sql.DB
	migrations []Migration
}

// New creates a Migrator by reading embedded SQL files from fsys under dir.
//
// File names must start with a numeric version prefix (e.g. "001_", "2_").
// Files are sorted by version number and executed in that order. Non-.sql
// files and files without a numeric prefix are silently ignored.
func New(db *sql.DB, fsys fs.FS, dir string) (*Migrator, error) {
	if db == nil {
		return nil, fmt.Errorf("dbmigrate: db is nil")
	}

	migrations, err := loadMigrations(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("dbmigrate: load migrations: %w", err)
	}

	return &Migrator{db: db, migrations: migrations}, nil
}

// NewFromList creates a Migrator from an explicit list of migrations.
// This is useful when migrations are constructed programmatically rather
// than from embedded files.
func NewFromList(db *sql.DB, migrations []Migration) (*Migrator, error) {
	if db == nil {
		return nil, fmt.Errorf("dbmigrate: db is nil")
	}

	// Sort by version.
	sorted := make([]Migration, len(migrations))
	copy(sorted, migrations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Version < sorted[j].Version
	})

	// Check for duplicate versions.
	seen := make(map[int]bool)
	for _, m := range sorted {
		if seen[m.Version] {
			return nil, fmt.Errorf("dbmigrate: duplicate migration version %d", m.Version)
		}
		seen[m.Version] = true
	}

	return &Migrator{db: db, migrations: sorted}, nil
}

// Up runs all pending migrations in version order. Returns the number of
// migrations applied. Each migration runs in its own transaction.
func (m *Migrator) Up() (int, error) {
	if err := m.ensureTable(); err != nil {
		return 0, err
	}

	applied, err := m.Applied()
	if err != nil {
		return 0, err
	}

	appliedSet := make(map[int]bool, len(applied))
	for _, a := range applied {
		appliedSet[a.Version] = true
	}

	count := 0
	for _, mig := range m.migrations {
		if appliedSet[mig.Version] {
			continue
		}
		if err := m.apply(mig); err != nil {
			return count, fmt.Errorf("dbmigrate: migration %d (%s) failed: %w", mig.Version, mig.Name, err)
		}
		count++
	}

	return count, nil
}

// Applied returns all previously executed migrations, ordered by version.
func (m *Migrator) Applied() ([]AppliedMigration, error) {
	if err := m.ensureTable(); err != nil {
		return nil, err
	}

	rows, err := m.db.Query(
		`SELECT version, name, applied_at FROM schema_migrations ORDER BY version ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("dbmigrate: query applied migrations: %w", err)
	}
	defer rows.Close()

	var result []AppliedMigration
	for rows.Next() {
		var a AppliedMigration
		var ts string
		if err := rows.Scan(&a.Version, &a.Name, &ts); err != nil {
			return nil, fmt.Errorf("dbmigrate: scan migration row: %w", err)
		}
		a.AppliedAt, _ = time.Parse(time.RFC3339Nano, ts)
		result = append(result, a)
	}
	return result, rows.Err()
}

// Pending returns migrations that have not yet been applied.
func (m *Migrator) Pending() ([]Migration, error) {
	applied, err := m.Applied()
	if err != nil {
		return nil, err
	}

	appliedSet := make(map[int]bool, len(applied))
	for _, a := range applied {
		appliedSet[a.Version] = true
	}

	var pending []Migration
	for _, mig := range m.migrations {
		if !appliedSet[mig.Version] {
			pending = append(pending, mig)
		}
	}
	return pending, nil
}

// Version returns the latest applied migration version, or 0 if none.
func (m *Migrator) Version() (int, error) {
	if err := m.ensureTable(); err != nil {
		return 0, err
	}

	var v sql.NullInt64
	err := m.db.QueryRow(
		`SELECT MAX(version) FROM schema_migrations`,
	).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("dbmigrate: query version: %w", err)
	}
	if !v.Valid {
		return 0, nil
	}
	return int(v.Int64), nil
}

// ensureTable creates the schema_migrations tracking table if it doesn't exist.
func (m *Migrator) ensureTable() error {
	_, err := m.db.Exec(`
CREATE TABLE IF NOT EXISTS schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
)`)
	if err != nil {
		return fmt.Errorf("dbmigrate: create schema_migrations table: %w", err)
	}
	return nil
}

// apply runs a single migration inside a transaction and records it.
func (m *Migrator) apply(mig Migration) error {
	tx, err := m.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Execute the migration SQL.
	if _, err := tx.Exec(mig.SQL); err != nil {
		return fmt.Errorf("exec sql: %w", err)
	}

	// Record the migration.
	now := time.Now().Format(time.RFC3339Nano)
	if _, err := tx.Exec(
		`INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		mig.Version, mig.Name, now,
	); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}

	return tx.Commit()
}

// loadMigrations reads .sql files from fsys under dir and parses them into
// sorted Migration values.
func loadMigrations(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", dir, err)
	}

	var migrations []Migration
	seen := make(map[int]bool)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".sql") {
			continue
		}
		// Skip down-migration files (*.down.sql).
		if strings.HasSuffix(name, ".down.sql") {
			continue
		}

		version, err := parseVersion(name)
		if err != nil {
			continue // silently skip non-versioned files
		}

		if seen[version] {
			return nil, fmt.Errorf("duplicate migration version %d: %s", version, name)
		}
		seen[version] = true

		content, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		migrations = append(migrations, Migration{
			Version: version,
			Name:    name,
			SQL:     string(content),
		})
	}

	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Version < migrations[j].Version
	})

	return migrations, nil
}

// parseVersion extracts the leading numeric prefix from a filename.
// E.g. "001_create_sessions.sql" → 1, "42_add_index.sql" → 42.
func parseVersion(name string) (int, error) {
	// Strip extension.
	base := strings.TrimSuffix(name, ".sql")

	// Find first underscore or end of string.
	idx := strings.Index(base, "_")
	numStr := base
	if idx > 0 {
		numStr = base[:idx]
	}

	v, err := strconv.Atoi(numStr)
	if err != nil {
		return 0, fmt.Errorf("parse version from %q: %w", name, err)
	}
	return v, nil
}
