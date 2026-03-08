package session

import (
	"path/filepath"
	"testing"

	"github.com/operatoronline/Operator-OS/pkg/providers"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestSQLiteStore_GetOrCreate(t *testing.T) {
	store := newTestStore(t)

	sess, err := store.GetOrCreate("test-key")
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}
	if sess.Key != "test-key" {
		t.Errorf("expected key %q, got %q", "test-key", sess.Key)
	}
	if len(sess.Messages) != 0 {
		t.Errorf("expected 0 messages, got %d", len(sess.Messages))
	}

	// Second call should return same session (idempotent).
	sess2, err := store.GetOrCreate("test-key")
	if err != nil {
		t.Fatalf("GetOrCreate (2nd): %v", err)
	}
	if sess2.Key != "test-key" {
		t.Errorf("expected key %q on second call, got %q", "test-key", sess2.Key)
	}
}

func TestSQLiteStore_AddMessageAndGetHistory(t *testing.T) {
	store := newTestStore(t)

	key := "chat:123"
	_, err := store.GetOrCreate(key)
	if err != nil {
		t.Fatalf("GetOrCreate: %v", err)
	}

	// Add several messages.
	msgs := []providers.Message{
		{Role: "user", Content: "hello"},
		{Role: "assistant", Content: "hi there"},
		{Role: "user", Content: "how are you?"},
	}
	for _, msg := range msgs {
		if err := store.AddMessage(key, msg); err != nil {
			t.Fatalf("AddMessage: %v", err)
		}
	}

	history, err := store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(history))
	}
	if history[0].Role != "user" || history[0].Content != "hello" {
		t.Errorf("unexpected first message: %+v", history[0])
	}
	if history[2].Content != "how are you?" {
		t.Errorf("unexpected third message: %+v", history[2])
	}
}

func TestSQLiteStore_AddMessage_AutoCreatesSession(t *testing.T) {
	store := newTestStore(t)

	// AddMessage should auto-create the session if it doesn't exist.
	key := "auto:999"
	err := store.AddMessage(key, providers.Message{Role: "user", Content: "auto-created"})
	if err != nil {
		t.Fatalf("AddMessage: %v", err)
	}

	history, err := store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 message, got %d", len(history))
	}
}

func TestSQLiteStore_ToolCalls(t *testing.T) {
	store := newTestStore(t)

	key := "tools:1"
	_, _ = store.GetOrCreate(key)

	msg := providers.Message{
		Role:    "assistant",
		Content: "",
		ToolCalls: []providers.ToolCall{
			{
				ID:   "call_1",
				Type: "function",
				Function: &providers.FunctionCall{
					Name:      "read_file",
					Arguments: `{"path": "/tmp/test.txt"}`,
				},
			},
		},
	}
	if err := store.AddMessage(key, msg); err != nil {
		t.Fatalf("AddMessage with tool calls: %v", err)
	}

	// Add tool result.
	toolResult := providers.Message{
		Role:       "tool",
		Content:    "file contents here",
		ToolCallID: "call_1",
	}
	if err := store.AddMessage(key, toolResult); err != nil {
		t.Fatalf("AddMessage tool result: %v", err)
	}

	history, err := store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(history))
	}
	if len(history[0].ToolCalls) != 1 {
		t.Fatalf("expected 1 tool call, got %d", len(history[0].ToolCalls))
	}
	if history[0].ToolCalls[0].ID != "call_1" {
		t.Errorf("expected tool call ID %q, got %q", "call_1", history[0].ToolCalls[0].ID)
	}
	if history[1].ToolCallID != "call_1" {
		t.Errorf("expected tool_call_id %q, got %q", "call_1", history[1].ToolCallID)
	}
}

func TestSQLiteStore_Summary(t *testing.T) {
	store := newTestStore(t)

	key := "summary:1"
	_, _ = store.GetOrCreate(key)

	// Initially empty.
	summary, err := store.GetSummary(key)
	if err != nil {
		t.Fatalf("GetSummary: %v", err)
	}
	if summary != "" {
		t.Errorf("expected empty summary, got %q", summary)
	}

	// Set summary.
	if err := store.SetSummary(key, "User discussed Go testing."); err != nil {
		t.Fatalf("SetSummary: %v", err)
	}

	summary, err = store.GetSummary(key)
	if err != nil {
		t.Fatalf("GetSummary after set: %v", err)
	}
	if summary != "User discussed Go testing." {
		t.Errorf("expected summary %q, got %q", "User discussed Go testing.", summary)
	}

	// Non-existent session returns empty.
	s, err := store.GetSummary("nonexistent")
	if err != nil {
		t.Fatalf("GetSummary nonexistent: %v", err)
	}
	if s != "" {
		t.Errorf("expected empty for nonexistent, got %q", s)
	}
}

func TestSQLiteStore_SetHistory(t *testing.T) {
	store := newTestStore(t)

	key := "sethistory:1"
	_, _ = store.GetOrCreate(key)

	// Add initial messages.
	_ = store.AddMessage(key, providers.Message{Role: "user", Content: "msg1"})
	_ = store.AddMessage(key, providers.Message{Role: "assistant", Content: "msg2"})
	_ = store.AddMessage(key, providers.Message{Role: "user", Content: "msg3"})

	// Replace with new history.
	newHistory := []providers.Message{
		{Role: "user", Content: "replaced1"},
		{Role: "assistant", Content: "replaced2"},
	}
	if err := store.SetHistory(key, newHistory); err != nil {
		t.Fatalf("SetHistory: %v", err)
	}

	history, err := store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(history))
	}
	if history[0].Content != "replaced1" {
		t.Errorf("expected %q, got %q", "replaced1", history[0].Content)
	}
}

func TestSQLiteStore_TruncateHistory(t *testing.T) {
	store := newTestStore(t)

	key := "truncate:1"
	_, _ = store.GetOrCreate(key)

	for i := 0; i < 10; i++ {
		_ = store.AddMessage(key, providers.Message{Role: "user", Content: "msg"})
	}

	// Keep last 3.
	if err := store.TruncateHistory(key, 3); err != nil {
		t.Fatalf("TruncateHistory: %v", err)
	}

	history, err := store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 3 {
		t.Errorf("expected 3 messages after truncate, got %d", len(history))
	}

	// Truncate all.
	if err := store.TruncateHistory(key, 0); err != nil {
		t.Fatalf("TruncateHistory(0): %v", err)
	}
	history, err = store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory after truncate all: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected 0 messages, got %d", len(history))
	}
}

func TestSQLiteStore_SaveIsNoOp(t *testing.T) {
	store := newTestStore(t)
	if err := store.Save("any-key"); err != nil {
		t.Errorf("Save should be no-op, got error: %v", err)
	}
}

func TestSQLiteStore_GetHistory_NonExistent(t *testing.T) {
	store := newTestStore(t)

	history, err := store.GetHistory("nonexistent")
	if err != nil {
		t.Fatalf("GetHistory on nonexistent: %v", err)
	}
	if len(history) != 0 {
		t.Errorf("expected empty history, got %d messages", len(history))
	}
}

func TestSQLiteStore_MediaField(t *testing.T) {
	store := newTestStore(t)

	key := "media:1"
	_, _ = store.GetOrCreate(key)

	msg := providers.Message{
		Role:    "user",
		Content: "check this image",
		Media:   []string{"https://example.com/img.png", "/tmp/photo.jpg"},
	}
	if err := store.AddMessage(key, msg); err != nil {
		t.Fatalf("AddMessage with media: %v", err)
	}

	history, err := store.GetHistory(key)
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("expected 1 message, got %d", len(history))
	}
	if len(history[0].Media) != 2 {
		t.Errorf("expected 2 media items, got %d", len(history[0].Media))
	}
	if history[0].Media[0] != "https://example.com/img.png" {
		t.Errorf("unexpected media[0]: %s", history[0].Media[0])
	}
}

func TestSQLiteStore_Persistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "persist.db")

	// Write data with first store instance.
	store1, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	_, _ = store1.GetOrCreate("persist-key")
	_ = store1.AddMessage("persist-key", providers.Message{Role: "user", Content: "remember me"})
	_ = store1.SetSummary("persist-key", "test summary")
	store1.Close()

	// Re-open and verify data survived.
	store2, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore (reopen): %v", err)
	}
	defer store2.Close()

	history, err := store2.GetHistory("persist-key")
	if err != nil {
		t.Fatalf("GetHistory: %v", err)
	}
	if len(history) != 1 || history[0].Content != "remember me" {
		t.Errorf("data did not persist: %+v", history)
	}

	summary, _ := store2.GetSummary("persist-key")
	if summary != "test summary" {
		t.Errorf("summary did not persist: %q", summary)
	}
}

// TestSessionManager_WithSQLiteStore verifies that SessionManager delegates to the store.
func TestSessionManager_WithSQLiteStore(t *testing.T) {
	store := newTestStore(t)
	sm := NewSessionManagerWithStore(store)

	key := "telegram:99999"

	// GetOrCreate
	sess := sm.GetOrCreate(key)
	if sess.Key != key {
		t.Errorf("expected key %q, got %q", key, sess.Key)
	}

	// AddMessage
	sm.AddMessage(key, "user", "hello from manager")
	sm.AddFullMessage(key, providers.Message{Role: "assistant", Content: "hi back"})

	// GetHistory
	history := sm.GetHistory(key)
	if len(history) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(history))
	}
	if history[0].Content != "hello from manager" {
		t.Errorf("unexpected content: %q", history[0].Content)
	}

	// Summary
	sm.SetSummary(key, "test convo")
	if got := sm.GetSummary(key); got != "test convo" {
		t.Errorf("expected summary %q, got %q", "test convo", got)
	}

	// SetHistory
	sm.SetHistory(key, []providers.Message{{Role: "user", Content: "replaced"}})
	history = sm.GetHistory(key)
	if len(history) != 1 || history[0].Content != "replaced" {
		t.Errorf("SetHistory failed: %+v", history)
	}

	// TruncateHistory
	sm.AddMessage(key, "user", "extra1")
	sm.AddMessage(key, "user", "extra2")
	sm.TruncateHistory(key, 1)
	history = sm.GetHistory(key)
	if len(history) != 1 {
		t.Errorf("expected 1 message after truncate, got %d", len(history))
	}

	// Save (no-op)
	if err := sm.Save(key); err != nil {
		t.Errorf("Save: %v", err)
	}

	// Close
	if err := sm.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
