package session

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/standardws/operator/pkg/providers"
)

func newTestEvictableStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "eviction_test.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// seedSessions creates n sessions and adds a message to each.
func seedSessions(t *testing.T, store *SQLiteStore, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("session:%d", i)
		_, err := store.GetOrCreate(key)
		if err != nil {
			t.Fatalf("GetOrCreate(%q): %v", key, err)
		}
		if err := store.AddMessage(key, providers.Message{Role: "user", Content: fmt.Sprintf("msg %d", i)}); err != nil {
			t.Fatalf("AddMessage: %v", err)
		}
	}
}

func TestSQLiteStore_SessionCount(t *testing.T) {
	store := newTestEvictableStore(t)

	count, err := store.SessionCount()
	if err != nil {
		t.Fatalf("SessionCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 sessions, got %d", count)
	}

	seedSessions(t, store, 5)

	count, err = store.SessionCount()
	if err != nil {
		t.Fatalf("SessionCount: %v", err)
	}
	if count != 5 {
		t.Errorf("expected 5 sessions, got %d", count)
	}
}

func TestSQLiteStore_DeleteSession(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 3)

	// Delete one session.
	if err := store.DeleteSession("session:1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	count, _ := store.SessionCount()
	if count != 2 {
		t.Errorf("expected 2 sessions after delete, got %d", count)
	}

	// Verify messages are also gone.
	history, err := store.GetHistory("session:1")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected 0 messages for deleted session, got %d", len(history))
	}

	// Delete non-existent session should return error.
	err = store.DeleteSession("nonexistent")
	if err == nil {
		t.Error("expected error for non-existent session")
	}
}

func TestSQLiteStore_EvictExpired(t *testing.T) {
	store := newTestEvictableStore(t)

	// Create sessions and manually set updated_at in the past.
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("ttl:%d", i)
		_, _ = store.GetOrCreate(key)
		_ = store.AddMessage(key, providers.Message{Role: "user", Content: "test"})
	}

	// Make 3 sessions look old by updating their updated_at to 25 hours ago.
	past := time.Now().Add(-25 * time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("ttl:%d", i)
		store.mu.Lock()
		_, err := store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, past, key)
		store.mu.Unlock()
		if err != nil {
			t.Fatalf("set old timestamp: %v", err)
		}
	}

	// Evict with 24h TTL — should remove the 3 old sessions.
	n, err := store.EvictExpired(24 * time.Hour)
	if err != nil {
		t.Fatalf("EvictExpired: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 evicted, got %d", n)
	}

	count, _ := store.SessionCount()
	if count != 2 {
		t.Errorf("expected 2 remaining sessions, got %d", count)
	}

	// Verify remaining sessions still have their data.
	for i := 3; i < 5; i++ {
		key := fmt.Sprintf("ttl:%d", i)
		history, err := store.GetHistory(key)
		if err != nil {
			t.Fatalf("GetHistory(%q): %v", key, err)
		}
		if len(history) != 1 {
			t.Errorf("expected 1 message for %q, got %d", key, len(history))
		}
	}
}

func TestSQLiteStore_EvictExpired_NoExpired(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 3)

	// All sessions are fresh — nothing should be evicted.
	n, err := store.EvictExpired(24 * time.Hour)
	if err != nil {
		t.Fatalf("EvictExpired: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 evicted, got %d", n)
	}
}

func TestSQLiteStore_EvictLRU(t *testing.T) {
	store := newTestEvictableStore(t)

	// Create 10 sessions with staggered updated_at timestamps.
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("lru:%d", i)
		_, _ = store.GetOrCreate(key)
		_ = store.AddMessage(key, providers.Message{Role: "user", Content: fmt.Sprintf("msg %d", i)})

		// Set updated_at to i hours ago (lru:0 is oldest, lru:9 is newest).
		ts := time.Now().Add(-time.Duration(10-i) * time.Hour).Format(time.RFC3339Nano)
		store.mu.Lock()
		_, _ = store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, ts, key)
		store.mu.Unlock()
	}

	// Set max to 7 — should evict 3 oldest (lru:0, lru:1, lru:2).
	n, err := store.EvictLRU(7)
	if err != nil {
		t.Fatalf("EvictLRU: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 evicted, got %d", n)
	}

	count, _ := store.SessionCount()
	if count != 7 {
		t.Errorf("expected 7 remaining sessions, got %d", count)
	}

	// Verify oldest are gone.
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("lru:%d", i)
		history, _ := store.GetHistory(key)
		if len(history) != 0 {
			t.Errorf("expected session %q to be evicted, but has %d messages", key, len(history))
		}
	}

	// Verify newest are kept.
	for i := 3; i < 10; i++ {
		key := fmt.Sprintf("lru:%d", i)
		history, _ := store.GetHistory(key)
		if len(history) != 1 {
			t.Errorf("expected session %q to be kept with 1 message, got %d", key, len(history))
		}
	}
}

func TestSQLiteStore_EvictLRU_UnderLimit(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 3)

	// Under limit — nothing should be evicted.
	n, err := store.EvictLRU(10)
	if err != nil {
		t.Fatalf("EvictLRU: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 evicted, got %d", n)
	}
}

func TestSQLiteStore_EvictLRU_ZeroMax(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 3)

	// Zero max — should do nothing.
	n, err := store.EvictLRU(0)
	if err != nil {
		t.Fatalf("EvictLRU: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 evicted, got %d", n)
	}
}

func TestEvictor_RunOnce(t *testing.T) {
	store := newTestEvictableStore(t)

	// Create 5 sessions, make 2 expire.
	for i := 0; i < 5; i++ {
		key := fmt.Sprintf("evictor:%d", i)
		_, _ = store.GetOrCreate(key)
		_ = store.AddMessage(key, providers.Message{Role: "user", Content: "test"})
	}

	past := time.Now().Add(-2 * time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 2; i++ {
		key := fmt.Sprintf("evictor:%d", i)
		store.mu.Lock()
		_, _ = store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, past, key)
		store.mu.Unlock()
	}

	config := EvictorConfig{
		TTL:         1 * time.Hour,
		MaxSessions: 100, // won't trigger LRU
		Interval:    1 * time.Minute,
	}
	evictor := NewEvictor(store, config)

	n, err := evictor.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 evicted, got %d", n)
	}

	count, _ := store.SessionCount()
	if count != 3 {
		t.Errorf("expected 3 remaining, got %d", count)
	}
}

func TestEvictor_RunOnce_TTLAndLRU(t *testing.T) {
	store := newTestEvictableStore(t)

	// Create 8 sessions with staggered times.
	for i := 0; i < 8; i++ {
		key := fmt.Sprintf("combo:%d", i)
		_, _ = store.GetOrCreate(key)
		_ = store.AddMessage(key, providers.Message{Role: "user", Content: "test"})
	}

	// Make 2 sessions expired (3 hours old with 2h TTL).
	past := time.Now().Add(-3 * time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 2; i++ {
		key := fmt.Sprintf("combo:%d", i)
		store.mu.Lock()
		_, _ = store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, past, key)
		store.mu.Unlock()
	}

	// After TTL eviction: 6 remain. MaxSessions=4 should evict 2 more by LRU.
	// Set distinct timestamps for the remaining 6 so LRU is deterministic.
	for i := 2; i < 8; i++ {
		ts := time.Now().Add(-time.Duration(8-i) * time.Minute).Format(time.RFC3339Nano)
		key := fmt.Sprintf("combo:%d", i)
		store.mu.Lock()
		_, _ = store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, ts, key)
		store.mu.Unlock()
	}

	config := EvictorConfig{
		TTL:         2 * time.Hour,
		MaxSessions: 4,
		Interval:    1 * time.Minute,
	}
	evictor := NewEvictor(store, config)

	n, err := evictor.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	// 2 TTL + 2 LRU = 4
	if n != 4 {
		t.Errorf("expected 4 evicted, got %d", n)
	}

	count, _ := store.SessionCount()
	if count != 4 {
		t.Errorf("expected 4 remaining, got %d", count)
	}
}

func TestEvictor_RunOnce_NoTTL(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 5)

	config := EvictorConfig{
		TTL:         0, // disabled
		MaxSessions: 3,
		Interval:    1 * time.Minute,
	}
	evictor := NewEvictor(store, config)

	// Set staggered timestamps for deterministic LRU.
	for i := 0; i < 5; i++ {
		ts := time.Now().Add(-time.Duration(5-i) * time.Minute).Format(time.RFC3339Nano)
		key := fmt.Sprintf("session:%d", i)
		store.mu.Lock()
		_, _ = store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, ts, key)
		store.mu.Unlock()
	}

	n, err := evictor.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 2 {
		t.Errorf("expected 2 evicted by LRU, got %d", n)
	}
}

func TestEvictor_RunOnce_NoLRU(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 3)

	// Make all sessions old.
	past := time.Now().Add(-48 * time.Hour).Format(time.RFC3339Nano)
	for i := 0; i < 3; i++ {
		key := fmt.Sprintf("session:%d", i)
		store.mu.Lock()
		_, _ = store.db.Exec(`UPDATE sessions SET updated_at = ? WHERE key = ?`, past, key)
		store.mu.Unlock()
	}

	config := EvictorConfig{
		TTL:         24 * time.Hour,
		MaxSessions: 0, // disabled
		Interval:    1 * time.Minute,
	}
	evictor := NewEvictor(store, config)

	n, err := evictor.RunOnce()
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if n != 3 {
		t.Errorf("expected 3 evicted by TTL, got %d", n)
	}
}

func TestEvictor_StartStop(t *testing.T) {
	store := newTestEvictableStore(t)
	seedSessions(t, store, 2)

	config := EvictorConfig{
		TTL:         24 * time.Hour,
		MaxSessions: 100,
		Interval:    50 * time.Millisecond, // fast for testing
	}
	evictor := NewEvictor(store, config)

	evictor.Start()

	// Let it tick a few times.
	time.Sleep(200 * time.Millisecond)

	// Stop should not hang.
	evictor.Stop()

	// Double stop is safe.
	evictor.Stop()
}

func TestEvictor_DefaultConfig(t *testing.T) {
	config := DefaultEvictorConfig()

	if config.TTL != 24*time.Hour {
		t.Errorf("expected TTL 24h, got %v", config.TTL)
	}
	if config.MaxSessions != 10000 {
		t.Errorf("expected MaxSessions 10000, got %d", config.MaxSessions)
	}
	if config.Interval != 5*time.Minute {
		t.Errorf("expected Interval 5m, got %v", config.Interval)
	}
}

func TestEvictor_DefaultInterval(t *testing.T) {
	store := newTestEvictableStore(t)
	config := EvictorConfig{
		TTL:         1 * time.Hour,
		MaxSessions: 100,
		Interval:    0, // should default to 5 minutes
	}
	evictor := NewEvictor(store, config)
	if evictor.config.Interval != 5*time.Minute {
		t.Errorf("expected default interval 5m, got %v", evictor.config.Interval)
	}
}

// TestSQLiteStore_ImplementsEvictableStore verifies at compile time that
// SQLiteStore implements the EvictableStore interface.
var _ EvictableStore = (*SQLiteStore)(nil)
