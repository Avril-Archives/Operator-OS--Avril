package state

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testPGDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("OPERATOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OPERATOR_TEST_PG_DSN not set — skipping PostgreSQL integration test")
	}

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)

	db.Exec("DROP TABLE IF EXISTS state CASCADE")

	t.Cleanup(func() {
		db.Exec("DROP TABLE IF EXISTS state CASCADE")
		db.Close()
	})

	return db
}

func TestPGStateStoreNilDB(t *testing.T) {
	_, err := NewPGStateStore(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db is nil")
}

func TestPGStateStoreInterfaceCompliance(t *testing.T) {
	var _ StateStore = (*PGStateStore)(nil)
}

func TestPGStateStoreGetSet(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStateStore(db)
	require.NoError(t, err)

	// Get non-existent returns empty.
	val, err := store.Get("missing")
	require.NoError(t, err)
	assert.Empty(t, val)

	// Set + Get.
	err = store.Set("key1", "value1")
	require.NoError(t, err)

	val, err = store.Get("key1")
	require.NoError(t, err)
	assert.Equal(t, "value1", val)
}

func TestPGStateStoreUpsert(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStateStore(db)
	require.NoError(t, err)

	err = store.Set("key1", "value1")
	require.NoError(t, err)

	err = store.Set("key1", "value2")
	require.NoError(t, err)

	val, err := store.Get("key1")
	require.NoError(t, err)
	assert.Equal(t, "value2", val)
}

func TestPGStateStoreTimestamp(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStateStore(db)
	require.NoError(t, err)

	// Zero time for missing key.
	ts, err := store.GetTimestamp("missing")
	require.NoError(t, err)
	assert.True(t, ts.IsZero())

	before := time.Now().Add(-time.Second)
	err = store.Set("ts-key", "val")
	require.NoError(t, err)
	after := time.Now().Add(time.Second)

	ts, err = store.GetTimestamp("ts-key")
	require.NoError(t, err)
	assert.True(t, ts.After(before), "timestamp should be after before")
	assert.True(t, ts.Before(after), "timestamp should be before after")
}

func TestPGStateStoreClose(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStateStore(db)
	require.NoError(t, err)

	// Close is a no-op.
	err = store.Close()
	assert.NoError(t, err)
}

func TestPGStateStoreMultipleKeys(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStateStore(db)
	require.NoError(t, err)

	err = store.Set("a", "1")
	require.NoError(t, err)
	err = store.Set("b", "2")
	require.NoError(t, err)
	err = store.Set("c", "3")
	require.NoError(t, err)

	v, err := store.Get("a")
	require.NoError(t, err)
	assert.Equal(t, "1", v)

	v, err = store.Get("b")
	require.NoError(t, err)
	assert.Equal(t, "2", v)

	v, err = store.Get("c")
	require.NoError(t, err)
	assert.Equal(t, "3", v)
}
