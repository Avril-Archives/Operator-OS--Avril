package session

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/operatoronline/Operator-OS/pkg/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openTestDB creates an in-memory SQLite database with the full schema
// (including tenant_id).
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(on)")
	require.NoError(t, err)
	require.NoError(t, initSchema(db))
	t.Cleanup(func() { db.Close() })
	return db
}

// --- Context helpers ---

func TestWithTenantID(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", TenantIDFromContext(ctx))

	ctx = WithTenantID(ctx, "tenant-abc")
	assert.Equal(t, "tenant-abc", TenantIDFromContext(ctx))
}

func TestTenantIDFromContextEmpty(t *testing.T) {
	assert.Equal(t, "", TenantIDFromContext(context.Background()))
}

// --- NewTenantStore validation ---

func TestNewTenantStoreNilDB(t *testing.T) {
	_, err := NewTenantStore(nil, "t1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}

func TestNewTenantStoreEmptyTenant(t *testing.T) {
	db := openTestDB(t)
	_, err := NewTenantStore(db, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant ID must not be empty")
}

// --- Tenant isolation ---

func TestTenantIsolation(t *testing.T) {
	db := openTestDB(t)

	storeA, err := NewTenantStore(db, "tenant-a")
	require.NoError(t, err)

	storeB, err := NewTenantStore(db, "tenant-b")
	require.NoError(t, err)

	// Create sessions with the same key in different tenants.
	_, err = storeA.GetOrCreate("chat:123")
	require.NoError(t, err)

	_, err = storeB.GetOrCreate("chat:123")
	require.NoError(t, err)

	// Add messages to each.
	require.NoError(t, storeA.AddMessage("chat:123", providers.Message{Role: "user", Content: "hello from A"}))
	require.NoError(t, storeB.AddMessage("chat:123", providers.Message{Role: "user", Content: "hello from B"}))

	// Each tenant sees only its own messages.
	histA, err := storeA.GetHistory("chat:123")
	require.NoError(t, err)
	require.Len(t, histA, 1)
	assert.Equal(t, "hello from A", histA[0].Content)

	histB, err := storeB.GetHistory("chat:123")
	require.NoError(t, err)
	require.Len(t, histB, 1)
	assert.Equal(t, "hello from B", histB[0].Content)
}

func TestTenantCannotAccessOtherTenantSession(t *testing.T) {
	db := openTestDB(t)

	storeA, _ := NewTenantStore(db, "tenant-a")
	storeB, _ := NewTenantStore(db, "tenant-b")

	_, err := storeA.GetOrCreate("private-session")
	require.NoError(t, err)
	require.NoError(t, storeA.SetSummary("private-session", "secret summary"))

	// Tenant B should get empty summary (session doesn't exist for them).
	summary, err := storeB.GetSummary("private-session")
	require.NoError(t, err)
	assert.Equal(t, "", summary)

	// Tenant B cannot set summary on tenant A's session.
	err = storeB.SetSummary("private-session", "hacked!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- GetOrCreate ---

func TestTenantGetOrCreate(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	sess, err := store.GetOrCreate("s1")
	require.NoError(t, err)
	assert.Equal(t, "s1", sess.Key) // Returns unscoped key
	assert.Empty(t, sess.Messages)

	// Second call returns same session.
	sess2, err := store.GetOrCreate("s1")
	require.NoError(t, err)
	assert.Equal(t, sess.Key, sess2.Key)
}

// --- AddMessage and GetHistory ---

func TestTenantAddMessageGetHistory(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, err := store.GetOrCreate("s1")
	require.NoError(t, err)

	msgs := []providers.Message{
		{Role: "user", Content: "hi"},
		{Role: "assistant", Content: "hello"},
		{Role: "user", Content: "how are you?"},
	}
	for _, m := range msgs {
		require.NoError(t, store.AddMessage("s1", m))
	}

	history, err := store.GetHistory("s1")
	require.NoError(t, err)
	require.Len(t, history, 3)
	assert.Equal(t, "hi", history[0].Content)
	assert.Equal(t, "hello", history[1].Content)
	assert.Equal(t, "how are you?", history[2].Content)
}

// --- Summary ---

func TestTenantSummary(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, err := store.GetOrCreate("s1")
	require.NoError(t, err)

	require.NoError(t, store.SetSummary("s1", "conversation about Go"))

	summary, err := store.GetSummary("s1")
	require.NoError(t, err)
	assert.Equal(t, "conversation about Go", summary)
}

// --- SetHistory ---

func TestTenantSetHistory(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, err := store.GetOrCreate("s1")
	require.NoError(t, err)

	require.NoError(t, store.AddMessage("s1", providers.Message{Role: "user", Content: "original"}))

	newHistory := []providers.Message{
		{Role: "user", Content: "replaced1"},
		{Role: "assistant", Content: "replaced2"},
	}
	require.NoError(t, store.SetHistory("s1", newHistory))

	history, err := store.GetHistory("s1")
	require.NoError(t, err)
	require.Len(t, history, 2)
	assert.Equal(t, "replaced1", history[0].Content)
	assert.Equal(t, "replaced2", history[1].Content)
}

func TestTenantSetHistoryNonexistent(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	err := store.SetHistory("nonexistent", []providers.Message{{Role: "user", Content: "x"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- TruncateHistory ---

func TestTenantTruncateHistory(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, err := store.GetOrCreate("s1")
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		require.NoError(t, store.AddMessage("s1", providers.Message{Role: "user", Content: "msg"}))
	}

	require.NoError(t, store.TruncateHistory("s1", 2))

	history, err := store.GetHistory("s1")
	require.NoError(t, err)
	assert.Len(t, history, 2)
}

func TestTenantTruncateHistoryAll(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, err := store.GetOrCreate("s1")
	require.NoError(t, err)
	require.NoError(t, store.AddMessage("s1", providers.Message{Role: "user", Content: "msg"}))
	require.NoError(t, store.TruncateHistory("s1", 0))

	history, err := store.GetHistory("s1")
	require.NoError(t, err)
	assert.Empty(t, history)
}

func TestTenantTruncateHistoryNonexistent(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	err := store.TruncateHistory("nonexistent", 5)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// --- SessionCount ---

func TestTenantSessionCount(t *testing.T) {
	db := openTestDB(t)
	storeA, _ := NewTenantStore(db, "tenant-a")
	storeB, _ := NewTenantStore(db, "tenant-b")

	_, _ = storeA.GetOrCreate("s1")
	_, _ = storeA.GetOrCreate("s2")
	_, _ = storeB.GetOrCreate("s1")

	countA, err := storeA.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(2), countA)

	countB, err := storeB.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(1), countB)
}

// --- DeleteSession ---

func TestTenantDeleteSession(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, err := store.GetOrCreate("s1")
	require.NoError(t, err)

	require.NoError(t, store.DeleteSession("s1"))

	count, err := store.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestTenantDeleteSessionCrossTenant(t *testing.T) {
	db := openTestDB(t)
	storeA, _ := NewTenantStore(db, "tenant-a")
	storeB, _ := NewTenantStore(db, "tenant-b")

	_, _ = storeA.GetOrCreate("s1")

	// Tenant B cannot delete tenant A's session.
	err := storeB.DeleteSession("s1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Tenant A's session still exists.
	countA, _ := storeA.SessionCount()
	assert.Equal(t, int64(1), countA)
}

// --- EvictExpired ---

func TestTenantEvictExpired(t *testing.T) {
	db := openTestDB(t)
	storeA, _ := NewTenantStore(db, "tenant-a")
	storeB, _ := NewTenantStore(db, "tenant-b")

	// Create sessions.
	_, _ = storeA.GetOrCreate("old-a")
	_, _ = storeA.GetOrCreate("new-a")
	_, _ = storeB.GetOrCreate("old-b")

	// Backdate "old" sessions.
	oldTime := time.Now().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	_, _ = db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, oldTime, "tenant:tenant-a:old-a")
	_, _ = db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, oldTime, "tenant:tenant-b:old-b")

	// Evict expired for tenant A only (24h TTL).
	evicted, err := storeA.EvictExpired(24 * time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(1), evicted)

	// Tenant A's new session survives.
	countA, _ := storeA.SessionCount()
	assert.Equal(t, int64(1), countA)

	// Tenant B's session is untouched.
	countB, _ := storeB.SessionCount()
	assert.Equal(t, int64(1), countB)
}

// --- EvictLRU ---

func TestTenantEvictLRU(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	for i := 0; i < 5; i++ {
		_, _ = store.GetOrCreate(fmt.Sprintf("s%d", i))
	}

	evicted, err := store.EvictLRU(3)
	require.NoError(t, err)
	assert.Equal(t, int64(2), evicted)

	count, _ := store.SessionCount()
	assert.Equal(t, int64(3), count)
}

func TestTenantEvictLRUCrossTenantSafety(t *testing.T) {
	db := openTestDB(t)
	storeA, _ := NewTenantStore(db, "tenant-a")
	storeB, _ := NewTenantStore(db, "tenant-b")

	// 3 sessions for A, 2 for B.
	for i := 0; i < 3; i++ {
		_, _ = storeA.GetOrCreate(fmt.Sprintf("a-%d", i))
	}
	for i := 0; i < 2; i++ {
		_, _ = storeB.GetOrCreate(fmt.Sprintf("b-%d", i))
	}

	// Evict LRU for tenant A to max 1.
	evicted, err := storeA.EvictLRU(1)
	require.NoError(t, err)
	assert.Equal(t, int64(2), evicted)

	countA, _ := storeA.SessionCount()
	assert.Equal(t, int64(1), countA)

	// Tenant B untouched.
	countB, _ := storeB.SessionCount()
	assert.Equal(t, int64(2), countB)
}

// --- ListSessions ---

func TestTenantListSessions(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, _ = store.GetOrCreate("chat:101")
	_, _ = store.GetOrCreate("chat:102")

	keys, err := store.ListSessions()
	require.NoError(t, err)
	require.Len(t, keys, 2)

	// Keys should be unscoped.
	assert.Contains(t, keys, "chat:101")
	assert.Contains(t, keys, "chat:102")
}

func TestTenantListSessionsIsolation(t *testing.T) {
	db := openTestDB(t)
	storeA, _ := NewTenantStore(db, "tenant-a")
	storeB, _ := NewTenantStore(db, "tenant-b")

	_, _ = storeA.GetOrCreate("s1")
	_, _ = storeB.GetOrCreate("s2")

	keysA, _ := storeA.ListSessions()
	assert.Equal(t, []string{"s1"}, keysA)

	keysB, _ := storeB.ListSessions()
	assert.Equal(t, []string{"s2"}, keysB)
}

// --- TenantStoreFactory ---

func TestTenantStoreFactory(t *testing.T) {
	db := openTestDB(t)

	factory, err := NewTenantStoreFactory(db)
	require.NoError(t, err)

	storeA, err := factory.ForTenant("alpha")
	require.NoError(t, err)

	storeB, err := factory.ForTenant("beta")
	require.NoError(t, err)

	_, _ = storeA.GetOrCreate("s1")
	_, _ = storeB.GetOrCreate("s1")

	require.NoError(t, storeA.AddMessage("s1", providers.Message{Role: "user", Content: "from alpha"}))
	require.NoError(t, storeB.AddMessage("s1", providers.Message{Role: "user", Content: "from beta"}))

	hA, _ := storeA.GetHistory("s1")
	hB, _ := storeB.GetHistory("s1")

	require.Len(t, hA, 1)
	require.Len(t, hB, 1)
	assert.Equal(t, "from alpha", hA[0].Content)
	assert.Equal(t, "from beta", hB[0].Content)
}

func TestTenantStoreFactoryNilDB(t *testing.T) {
	_, err := NewTenantStoreFactory(nil)
	require.Error(t, err)
}

// --- Save / Close ---

func TestTenantSaveNoOp(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")
	assert.NoError(t, store.Save("any-key"))
}

func TestTenantCloseNoOp(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")
	assert.NoError(t, store.Close())
}

// --- TenantID accessor ---

func TestTenantStoreReportsTenantID(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "my-tenant")
	assert.Equal(t, "my-tenant", store.TenantID())
}

// --- Tool calls / media round-trip ---

func TestTenantMessageToolCallsRoundTrip(t *testing.T) {
	db := openTestDB(t)
	store, _ := NewTenantStore(db, "t1")

	_, _ = store.GetOrCreate("s1")

	msg := providers.Message{
		Role:    "assistant",
		Content: "",
		ToolCalls: []providers.ToolCall{
			{
				ID:       "call_1",
				Type:     "function",
				Function: &providers.FunctionCall{Name: "search", Arguments: `{"q":"test"}`},
			},
		},
	}
	require.NoError(t, store.AddMessage("s1", msg))

	history, err := store.GetHistory("s1")
	require.NoError(t, err)
	require.Len(t, history, 1)
	require.Len(t, history[0].ToolCalls, 1)
	assert.Equal(t, "call_1", history[0].ToolCalls[0].ID)
	assert.Equal(t, "search", history[0].ToolCalls[0].Function.Name)
}
