package dbmigrate

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// DownMigration represents a versioned rollback migration.
type DownMigration struct {
	Version int
	Name    string // e.g. "001_create_sessions.down.sql"
	SQL     string
}

// DownMigrator manages down (rollback) migrations. It requires a separate set
// of *.down.sql files that undo the corresponding up migrations.
type DownMigrator struct {
	m    *Migrator
	down []DownMigration
}

// NewDownMigrator creates a DownMigrator by pairing an existing Migrator with
// down-migration SQL files loaded from fsys under dir.
//
// Down files must follow the naming convention: NNN_description.down.sql
// where NNN matches the version of the corresponding up migration.
func NewDownMigrator(m *Migrator, fsys fs.FS, dir string) (*DownMigrator, error) {
	if m == nil {
		return nil, fmt.Errorf("dbmigrate: migrator is nil")
	}

	downs, err := loadDownMigrations(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("dbmigrate: load down migrations: %w", err)
	}

	return &DownMigrator{m: m, down: downs}, nil
}

// Down rolls back the most recent migration. Returns the version that was
// rolled back, or 0 if there is nothing to roll back.
func (dm *DownMigrator) Down() (int, error) {
	if err := dm.m.ensureTable(); err != nil {
		return 0, err
	}

	current, err := dm.m.Version()
	if err != nil {
		return 0, err
	}
	if current == 0 {
		return 0, nil // nothing to roll back
	}

	return dm.rollback(current)
}

// DownTo rolls back all migrations down to (but not including) the target
// version. For example, DownTo(3) rolls back all migrations with version > 3.
// DownTo(0) rolls back everything.
func (dm *DownMigrator) DownTo(target int) (int, error) {
	if target < 0 {
		return 0, fmt.Errorf("dbmigrate: target version must be >= 0")
	}

	if err := dm.m.ensureTable(); err != nil {
		return 0, err
	}

	count := 0
	for {
		current, err := dm.m.Version()
		if err != nil {
			return count, err
		}
		if current <= target {
			break
		}

		if _, err := dm.rollback(current); err != nil {
			return count, err
		}
		count++
	}

	return count, nil
}

// rollback executes the down migration for the given version in a transaction.
func (dm *DownMigrator) rollback(version int) (int, error) {
	down := dm.findDown(version)
	if down == nil {
		return 0, fmt.Errorf("dbmigrate: no down migration for version %d", version)
	}

	tx, err := dm.m.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("dbmigrate: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Execute the rollback SQL.
	if _, err := tx.Exec(down.SQL); err != nil {
		return 0, fmt.Errorf("dbmigrate: rollback version %d: %w", version, err)
	}

	// Remove the migration record.
	if _, err := tx.Exec(
		`DELETE FROM schema_migrations WHERE version = ?`, version,
	); err != nil {
		return 0, fmt.Errorf("dbmigrate: remove migration record %d: %w", version, err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("dbmigrate: commit rollback %d: %w", version, err)
	}

	return version, nil
}

// findDown locates the down migration for a given version.
func (dm *DownMigrator) findDown(version int) *DownMigration {
	for i := range dm.down {
		if dm.down[i].Version == version {
			return &dm.down[i]
		}
	}
	return nil
}

// loadDownMigrations reads *.down.sql files from fsys under dir.
func loadDownMigrations(fsys fs.FS, dir string) ([]DownMigration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %q: %w", dir, err)
	}

	var downs []DownMigration
	seen := make(map[int]bool)

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".down.sql") {
			continue
		}

		// Parse version from "NNN_description.down.sql"
		base := strings.TrimSuffix(name, ".down.sql")
		version, err := parseVersion(base + ".sql") // reuse existing parser
		if err != nil {
			continue
		}

		if seen[version] {
			return nil, fmt.Errorf("duplicate down migration version %d: %s", version, name)
		}
		seen[version] = true

		content, err := fs.ReadFile(fsys, path.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		downs = append(downs, DownMigration{
			Version: version,
			Name:    name,
			SQL:     string(content),
		})
	}

	sort.Slice(downs, func(i, j int) bool {
		return downs[i].Version < downs[j].Version
	})

	return downs, nil
}
