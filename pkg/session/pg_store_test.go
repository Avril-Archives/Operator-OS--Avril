package session

import (
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/standardws/operator/pkg/providers"
)

// testPGDB returns a *sql.DB connected to a test PostgreSQL instance,
// or skips the test if OPERATOR_TEST_PG_DSN is not set.
func testPGDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("OPERATOR_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("OPERATOR_TEST_PG_DSN not set — skipping PostgreSQL integration test")
	}

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)

	// Clean up tables for a fresh test.
	db.Exec("DROP TABLE IF EXISTS messages CASCADE")
	db.Exec("DROP TABLE IF EXISTS sessions CASCADE")

	t.Cleanup(func() {
		db.Exec("DROP TABLE IF EXISTS messages CASCADE")
		db.Exec("DROP TABLE IF EXISTS sessions CASCADE")
		db.Close()
	})

	return db
}

func TestPGStoreNilDB(t *testing.T) {
	_, err := NewPGStore(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db is nil")
}

// TestPGStoreInterfaceCompliance verifies PGStore satisfies both interfaces at compile time.
func TestPGStoreInterfaceCompliance(t *testing.T) {
	var _ SessionStore = (*PGStore)(nil)
	var _ EvictableStore = (*PGStore)(nil)
}

func TestPGStoreGetOrCreate(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	sess, err := store.GetOrCreate("test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", sess.Key)
	assert.Empty(t, sess.Messages)
	assert.Empty(t, sess.Summary)
	assert.False(t, sess.Created.IsZero())

	// Second call should return same session.
	sess2, err := store.GetOrCreate("test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", sess2.Key)
}

func TestPGStoreAddAndGetHistory(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	msg := providers.Message{Role: "user", Content: "hello"}
	err = store.AddMessage("k1", msg)
	require.NoError(t, err)

	history, err := store.GetHistory("k1")
	require.NoError(t, err)
	require.Len(t, history, 1)
	assert.Equal(t, "user", history[0].Role)
	assert.Equal(t, "hello", history[0].Content)
}

func TestPGStoreAddMessageWithToolCalls(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	msg := providers.Message{
		Role:    "assistant",
		Content: "result",
		ToolCalls: []providers.ToolCall{
			{ID: "tc1", Function: &providers.FunctionCall{Name: "test", Arguments: `{"a":1}`}},
		},
	}
	err = store.AddMessage("k1", msg)
	require.NoError(t, err)

	history, err := store.GetHistory("k1")
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Len(t, history[0].ToolCalls, 1)
	assert.Equal(t, "tc1", history[0].ToolCalls[0].ID)
}

func TestPGStoreSummary(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	_, err = store.GetOrCreate("s1")
	require.NoError(t, err)

	err = store.SetSummary("s1", "conversation about testing")
	require.NoError(t, err)

	summary, err := store.GetSummary("s1")
	require.NoError(t, err)
	assert.Equal(t, "conversation about testing", summary)
}

func TestPGStoreSummaryNotFound(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	summary, err := store.GetSummary("nonexistent")
	require.NoError(t, err)
	assert.Empty(t, summary)
}

func TestPGStoreSetSummaryNotFound(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	err = store.SetSummary("nonexistent", "nope")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPGStoreSetHistory(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	_, err = store.GetOrCreate("h1")
	require.NoError(t, err)

	err = store.AddMessage("h1", providers.Message{Role: "user", Content: "old"})
	require.NoError(t, err)

	newMessages := []providers.Message{
		{Role: "user", Content: "new1"},
		{Role: "assistant", Content: "new2"},
	}
	err = store.SetHistory("h1", newMessages)
	require.NoError(t, err)

	history, err := store.GetHistory("h1")
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, "new1", history[0].Content)
	assert.Equal(t, "new2", history[1].Content)
}

func TestPGStoreTruncateHistory(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		err = store.AddMessage("tr1", providers.Message{Role: "user", Content: "msg"})
		require.NoError(t, err)
	}

	err = store.TruncateHistory("tr1", 2)
	require.NoError(t, err)

	history, err := store.GetHistory("tr1")
	require.NoError(t, err)
	assert.Len(t, history, 2)
}

func TestPGStoreTruncateAll(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	err = store.AddMessage("tr2", providers.Message{Role: "user", Content: "msg"})
	require.NoError(t, err)

	err = store.TruncateHistory("tr2", 0)
	require.NoError(t, err)

	history, err := store.GetHistory("tr2")
	require.NoError(t, err)
	assert.Empty(t, history)
}

func TestPGStoreSave(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	// Save is a no-op.
	err = store.Save("anything")
	assert.NoError(t, err)
}

func TestPGStoreSessionCount(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	count, err := store.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	_, err = store.GetOrCreate("c1")
	require.NoError(t, err)
	_, err = store.GetOrCreate("c2")
	require.NoError(t, err)

	count, err = store.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestPGStoreDeleteSession(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	_, err = store.GetOrCreate("del1")
	require.NoError(t, err)

	err = store.DeleteSession("del1")
	require.NoError(t, err)

	count, err := store.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestPGStoreDeleteSessionNotFound(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	err = store.DeleteSession("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestPGStoreEvictExpired(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	// Create sessions with old timestamps.
	_, err = store.GetOrCreate("old1")
	require.NoError(t, err)
	_, err = store.GetOrCreate("old2")
	require.NoError(t, err)

	// Manually backdate sessions.
	old := time.Now().Add(-48 * time.Hour)
	_, err = db.Exec(`UPDATE sessions SET updated_at = $1 WHERE key IN ('old1', 'old2')`, old)
	require.NoError(t, err)

	_, err = store.GetOrCreate("new1")
	require.NoError(t, err)

	evicted, err := store.EvictExpired(24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(2), evicted)

	count, err := store.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)
}

func TestPGStoreEvictLRU(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		_, err = store.GetOrCreate(string(rune('a' + i)))
		require.NoError(t, err)
	}

	evicted, err := store.EvictLRU(3)
	require.NoError(t, err)
	assert.Equal(t, int64(2), evicted)

	count, err := store.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestPGStoreEvictLRUZero(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	evicted, err := store.EvictLRU(0)
	require.NoError(t, err)
	assert.Equal(t, int64(0), evicted)
}

func TestPGStoreClose(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	// Close is a no-op for PGStore.
	err = store.Close()
	assert.NoError(t, err)
}

func TestPGStoreEmptyHistory(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	// GetHistory for unknown key returns empty (not error).
	history, err := store.GetHistory("unknown")
	require.NoError(t, err)
	assert.Empty(t, history)
}

func TestPGStoreMessageWithMedia(t *testing.T) {
	db := testPGDB(t)
	store, err := NewPGStore(db)
	require.NoError(t, err)

	msg := providers.Message{
		Role:    "user",
		Content: "check this",
		Media:   []string{"data:image/png;base64,abc123"},
	}
	err = store.AddMessage("media1", msg)
	require.NoError(t, err)

	history, err := store.GetHistory("media1")
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Len(t, history[0].Media, 1)
	assert.Equal(t, "data:image/png;base64,abc123", history[0].Media[0])
}
