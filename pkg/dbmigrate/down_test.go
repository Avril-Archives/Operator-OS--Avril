package dbmigrate

import (
	"io/fs"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testDownFS() fs.FS {
	return fstest.MapFS{
		"m/001_create_users.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL);`),
		},
		"m/002_create_posts.sql": &fstest.MapFile{
			Data: []byte(`CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id), body TEXT);`),
		},
		"m/001_create_users.down.sql": &fstest.MapFile{
			Data: []byte(`DROP TABLE IF EXISTS users;`),
		},
		"m/002_create_posts.down.sql": &fstest.MapFile{
			Data: []byte(`DROP TABLE IF EXISTS posts;`),
		},
	}
}

func TestDown_RollsBackLatest(t *testing.T) {
	db := openTestDB(t)
	fsys := testDownFS()

	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	// Apply all up migrations.
	n, err := m.Up()
	require.NoError(t, err)
	assert.Equal(t, 2, n)

	// Create down migrator.
	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	// Roll back the latest (v2).
	rolled, err := dm.Down()
	require.NoError(t, err)
	assert.Equal(t, 2, rolled)

	// Version should now be 1.
	v, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 1, v)

	// posts table should be gone, users should still exist.
	_, err = db.Exec(`INSERT INTO users (name) VALUES ('alice')`)
	assert.NoError(t, err)
	_, err = db.Exec(`INSERT INTO posts (body) VALUES ('hello')`)
	assert.Error(t, err) // table does not exist
}

func TestDown_NothingToRollback(t *testing.T) {
	db := openTestDB(t)
	fsys := testDownFS()

	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	// No migrations applied — should return 0.
	rolled, err := dm.Down()
	require.NoError(t, err)
	assert.Equal(t, 0, rolled)
}

func TestDownTo_RollsBackToTarget(t *testing.T) {
	db := openTestDB(t)
	fsys := testDownFS()

	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	_, err = m.Up()
	require.NoError(t, err)

	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	// Roll back to version 0 (everything).
	count, err := dm.DownTo(0)
	require.NoError(t, err)
	assert.Equal(t, 2, count)

	v, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 0, v)
}

func TestDownTo_PartialRollback(t *testing.T) {
	db := openTestDB(t)
	fsys := testDownFS()

	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	_, err = m.Up()
	require.NoError(t, err)

	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	// Roll back to version 1 (only v2 rolled back).
	count, err := dm.DownTo(1)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	v, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 1, v)
}

func TestDown_MissingDownMigration(t *testing.T) {
	// Only up migrations, no down files.
	fsys := testFS()

	db := openTestDB(t)
	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	_, err = m.Up()
	require.NoError(t, err)

	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	// Should error because no down migration exists.
	_, err = dm.Down()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no down migration")
}

func TestDown_ReapplyAfterRollback(t *testing.T) {
	db := openTestDB(t)
	fsys := testDownFS()

	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	// Apply all.
	_, err = m.Up()
	require.NoError(t, err)

	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	// Roll back v2.
	_, err = dm.Down()
	require.NoError(t, err)

	// Re-apply — should apply v2 again.
	n, err := m.Up()
	require.NoError(t, err)
	assert.Equal(t, 1, n)

	v, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, 2, v)
}

func TestNewDownMigrator_NilMigrator(t *testing.T) {
	_, err := NewDownMigrator(nil, testFS(), "m")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "migrator is nil")
}

func TestDownTo_NegativeTarget(t *testing.T) {
	db := openTestDB(t)
	fsys := testDownFS()

	m, err := New(db, fsys, "m")
	require.NoError(t, err)

	dm, err := NewDownMigrator(m, fsys, "m")
	require.NoError(t, err)

	_, err = dm.DownTo(-1)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "target version must be >= 0")
}

func TestLoadDownMigrations_SkipsUpFiles(t *testing.T) {
	fsys := testDownFS()
	downs, err := loadDownMigrations(fsys, "m")
	require.NoError(t, err)
	assert.Len(t, downs, 2)
	assert.Equal(t, 1, downs[0].Version)
	assert.Equal(t, 2, downs[1].Version)
}
