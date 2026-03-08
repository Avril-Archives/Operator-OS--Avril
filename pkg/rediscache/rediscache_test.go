package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/operatoronline/Operator-OS/pkg/providers"
	"github.com/operatoronline/Operator-OS/pkg/session"
)

// --- fake Redis client (in-memory, no real Redis needed) ---

type fakeRedis struct {
	mu   sync.RWMutex
	data map[string]string
	ttls map[string]time.Duration
}

func newFakeRedis() *fakeRedis {
	return &fakeRedis{
		data: make(map[string]string),
		ttls: make(map[string]time.Duration),
	}
}

func (f *fakeRedis) Get(_ context.Context, key string) *redis.StringCmd {
	f.mu.RLock()
	defer f.mu.RUnlock()
	val, ok := f.data[key]
	cmd := redis.NewStringCmd(context.Background())
	if !ok {
		cmd.SetErr(redis.Nil)
		return cmd
	}
	cmd.SetVal(val)
	return cmd
}

func (f *fakeRedis) Set(_ context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch v := value.(type) {
	case string:
		f.data[key] = v
	case []byte:
		f.data[key] = string(v)
	default:
		f.data[key] = fmt.Sprintf("%v", v)
	}
	f.ttls[key] = ttl
	cmd := redis.NewStatusCmd(context.Background())
	cmd.SetVal("OK")
	return cmd
}

func (f *fakeRedis) Del(_ context.Context, keys ...string) *redis.IntCmd {
	f.mu.Lock()
	defer f.mu.Unlock()
	var count int64
	for _, key := range keys {
		if _, ok := f.data[key]; ok {
			delete(f.data, key)
			delete(f.ttls, key)
			count++
		}
	}
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetVal(count)
	return cmd
}

func (f *fakeRedis) Ping(_ context.Context) *redis.StatusCmd {
	cmd := redis.NewStatusCmd(context.Background())
	cmd.SetVal("PONG")
	return cmd
}

func (f *fakeRedis) DBSize(_ context.Context) *redis.IntCmd {
	f.mu.RLock()
	defer f.mu.RUnlock()
	cmd := redis.NewIntCmd(context.Background())
	cmd.SetVal(int64(len(f.data)))
	return cmd
}

func (f *fakeRedis) keyCount() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.data)
}

func (f *fakeRedis) hasKey(key string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	_, ok := f.data[key]
	return ok
}

func (f *fakeRedis) getTTL(key string) time.Duration {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.ttls[key]
}

// compile-time check that fakeRedis implements RedisClient.
var _ RedisClient = (*fakeRedis)(nil)

// --- fake backing store ---

type fakeBackingStore struct {
	mu       sync.Mutex
	sessions map[string]*session.Session
	errors   map[string]error
}

func newFakeBackingStore() *fakeBackingStore {
	return &fakeBackingStore{
		sessions: make(map[string]*session.Session),
		errors:   make(map[string]error),
	}
}

func (f *fakeBackingStore) GetOrCreate(key string) (*session.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["GetOrCreate"]; ok {
		return nil, err
	}
	sess, ok := f.sessions[key]
	if !ok {
		sess = &session.Session{
			Key:      key,
			Messages: []providers.Message{},
			Created:  time.Now(),
			Updated:  time.Now(),
		}
		f.sessions[key] = sess
	}
	return sess, nil
}

func (f *fakeBackingStore) AddMessage(key string, msg providers.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["AddMessage"]; ok {
		return err
	}
	sess, ok := f.sessions[key]
	if !ok {
		sess = &session.Session{
			Key:      key,
			Messages: []providers.Message{},
			Created:  time.Now(),
		}
		f.sessions[key] = sess
	}
	sess.Messages = append(sess.Messages, msg)
	sess.Updated = time.Now()
	return nil
}

func (f *fakeBackingStore) GetHistory(key string) ([]providers.Message, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["GetHistory"]; ok {
		return nil, err
	}
	sess, ok := f.sessions[key]
	if !ok {
		return []providers.Message{}, nil
	}
	msgs := make([]providers.Message, len(sess.Messages))
	copy(msgs, sess.Messages)
	return msgs, nil
}

func (f *fakeBackingStore) GetSummary(key string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["GetSummary"]; ok {
		return "", err
	}
	sess, ok := f.sessions[key]
	if !ok {
		return "", nil
	}
	return sess.Summary, nil
}

func (f *fakeBackingStore) SetSummary(key string, summary string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["SetSummary"]; ok {
		return err
	}
	sess, ok := f.sessions[key]
	if !ok {
		return fmt.Errorf("session %q not found", key)
	}
	sess.Summary = summary
	return nil
}

func (f *fakeBackingStore) SetHistory(key string, messages []providers.Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["SetHistory"]; ok {
		return err
	}
	sess, ok := f.sessions[key]
	if !ok {
		return fmt.Errorf("session %q not found", key)
	}
	sess.Messages = messages
	return nil
}

func (f *fakeBackingStore) TruncateHistory(key string, keepLast int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errors["TruncateHistory"]; ok {
		return err
	}
	sess, ok := f.sessions[key]
	if !ok {
		return nil
	}
	if keepLast <= 0 {
		sess.Messages = []providers.Message{}
		return nil
	}
	if len(sess.Messages) > keepLast {
		sess.Messages = sess.Messages[len(sess.Messages)-keepLast:]
	}
	return nil
}

func (f *fakeBackingStore) Save(_ string) error {
	if err, ok := f.errors["Save"]; ok {
		return err
	}
	return nil
}

func (f *fakeBackingStore) Close() error {
	if err, ok := f.errors["Close"]; ok {
		return err
	}
	return nil
}

// evictable methods for testing EvictableStore delegation
func (f *fakeBackingStore) SessionCount() (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.sessions)), nil
}

func (f *fakeBackingStore) DeleteSession(key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[key]; !ok {
		return fmt.Errorf("session %q not found", key)
	}
	delete(f.sessions, key)
	return nil
}

func (f *fakeBackingStore) EvictExpired(_ time.Duration) (int64, error) {
	return 0, nil
}

func (f *fakeBackingStore) EvictLRU(_ int) (int64, error) {
	return 0, nil
}

// --- tests ---

func TestNew_NilClient(t *testing.T) {
	_, err := New(nil, newFakeBackingStore(), DefaultConfig())
	assert.ErrorIs(t, err, ErrNilClient)
}

func TestNew_NilBackingStore(t *testing.T) {
	fr := newFakeRedis()
	_, err := New(fr, nil, DefaultConfig())
	assert.ErrorIs(t, err, ErrNilBackingStore)
}

func TestNew_Success(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, err := New(fr, bs, DefaultConfig())
	require.NoError(t, err)
	assert.NotNil(t, rc)
}

func TestNew_DefaultsApplied(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, err := New(fr, bs, Config{}) // zero config
	require.NoError(t, err)
	assert.Equal(t, "sess:", rc.config.KeyPrefix)
	assert.Equal(t, 30*time.Minute, rc.config.TTL)
}

func TestNew_CustomConfig(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	cfg := Config{
		KeyPrefix: "test:",
		TTL:       5 * time.Minute,
	}
	rc, err := New(fr, bs, cfg)
	require.NoError(t, err)
	assert.Equal(t, "test:", rc.config.KeyPrefix)
	assert.Equal(t, 5*time.Minute, rc.config.TTL)
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	assert.Equal(t, "sess:", cfg.KeyPrefix)
	assert.Equal(t, 30*time.Minute, cfg.TTL)
	assert.Nil(t, cfg.Ctx)
}

func TestGetOrCreate_CacheMiss_PopulatesCache(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	sess, err := rc.GetOrCreate("test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", sess.Key)
	assert.Empty(t, sess.Messages)

	// Cache should now be populated.
	assert.True(t, fr.hasKey("sess:test-key"))
}

func TestGetOrCreate_CacheHit(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// First call populates cache.
	_, err := rc.GetOrCreate("test-key")
	require.NoError(t, err)

	// Modify backing store directly to verify we read from cache.
	bs.mu.Lock()
	bs.sessions["test-key"].Summary = "modified in backing"
	bs.mu.Unlock()

	// Second call should hit cache (no backing store summary).
	sess, err := rc.GetOrCreate("test-key")
	require.NoError(t, err)
	assert.Equal(t, "", sess.Summary) // cache has original empty summary
}

func TestGetOrCreate_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["GetOrCreate"] = errors.New("db error")
	rc, _ := New(fr, bs, DefaultConfig())

	_, err := rc.GetOrCreate("test-key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db error")
}

func TestAddMessage_WritesThrough(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Create session first.
	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("sess:test-key"))

	// Add message — should invalidate cache.
	msg := providers.Message{Role: "user", Content: "hello"}
	err := rc.AddMessage("test-key", msg)
	require.NoError(t, err)

	// Cache should be invalidated.
	assert.False(t, fr.hasKey("sess:test-key"))

	// Backing store should have the message.
	bs.mu.Lock()
	assert.Len(t, bs.sessions["test-key"].Messages, 1)
	assert.Equal(t, "hello", bs.sessions["test-key"].Messages[0].Content)
	bs.mu.Unlock()
}

func TestAddMessage_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["AddMessage"] = errors.New("write failed")
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.AddMessage("test-key", providers.Message{Role: "user", Content: "hello"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write failed")
}

func TestGetHistory_CacheHit(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Set up backing store with messages.
	bs.mu.Lock()
	bs.sessions["test-key"] = &session.Session{
		Key: "test-key",
		Messages: []providers.Message{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "hi there"},
		},
		Created: time.Now(),
		Updated: time.Now(),
	}
	bs.mu.Unlock()

	// First GetOrCreate populates cache with messages.
	_, _ = rc.GetOrCreate("test-key")

	// GetHistory should hit cache.
	msgs, err := rc.GetHistory("test-key")
	require.NoError(t, err)
	assert.Len(t, msgs, 2)
	assert.Equal(t, "hello", msgs[0].Content)
	assert.Equal(t, "hi there", msgs[1].Content)
}

func TestGetHistory_CacheMiss(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Set up backing store with messages but don't populate cache.
	bs.mu.Lock()
	bs.sessions["test-key"] = &session.Session{
		Key: "test-key",
		Messages: []providers.Message{
			{Role: "user", Content: "hello"},
		},
		Created: time.Now(),
		Updated: time.Now(),
	}
	bs.mu.Unlock()

	msgs, err := rc.GetHistory("test-key")
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
	assert.Equal(t, "hello", msgs[0].Content)
}

func TestGetHistory_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["GetHistory"] = errors.New("read failed")
	rc, _ := New(fr, bs, DefaultConfig())

	_, err := rc.GetHistory("test-key")
	assert.Error(t, err)
}

func TestGetSummary_CacheHit(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	bs.mu.Lock()
	bs.sessions["test-key"] = &session.Session{
		Key:     "test-key",
		Summary: "a conversation about Go",
		Created: time.Now(),
		Updated: time.Now(),
	}
	bs.mu.Unlock()

	// Populate cache.
	_, _ = rc.GetOrCreate("test-key")

	summary, err := rc.GetSummary("test-key")
	require.NoError(t, err)
	assert.Equal(t, "a conversation about Go", summary)
}

func TestGetSummary_CacheMiss(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	bs.mu.Lock()
	bs.sessions["test-key"] = &session.Session{
		Key:     "test-key",
		Summary: "cached summary",
		Created: time.Now(),
		Updated: time.Now(),
	}
	bs.mu.Unlock()

	summary, err := rc.GetSummary("test-key")
	require.NoError(t, err)
	assert.Equal(t, "cached summary", summary)
}

func TestSetSummary_InvalidatesCache(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Create and cache session.
	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("sess:test-key"))

	err := rc.SetSummary("test-key", "new summary")
	require.NoError(t, err)
	assert.False(t, fr.hasKey("sess:test-key"))
}

func TestSetSummary_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["SetSummary"] = errors.New("write failed")
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.SetSummary("test-key", "new summary")
	assert.Error(t, err)
}

func TestSetHistory_InvalidatesCache(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("sess:test-key"))

	msgs := []providers.Message{{Role: "user", Content: "replaced"}}
	err := rc.SetHistory("test-key", msgs)
	require.NoError(t, err)
	assert.False(t, fr.hasKey("sess:test-key"))
}

func TestSetHistory_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["SetHistory"] = errors.New("write failed")
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.SetHistory("test-key", nil)
	assert.Error(t, err)
}

func TestTruncateHistory_InvalidatesCache(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("sess:test-key"))

	err := rc.TruncateHistory("test-key", 5)
	require.NoError(t, err)
	assert.False(t, fr.hasKey("sess:test-key"))
}

func TestTruncateHistory_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["TruncateHistory"] = errors.New("truncate failed")
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.TruncateHistory("test-key", 5)
	assert.Error(t, err)
}

func TestSave_DelegatesToBacking(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.Save("test-key")
	assert.NoError(t, err)
}

func TestClose_DelegatesToBacking(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.Close()
	assert.NoError(t, err)
}

func TestClose_BackingStoreError(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	bs.errors["Close"] = errors.New("close failed")
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.Close()
	assert.Error(t, err)
}

func TestSessionCount_DelegatesToEvictableBacking(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	bs.mu.Lock()
	bs.sessions["a"] = &session.Session{Key: "a"}
	bs.sessions["b"] = &session.Session{Key: "b"}
	bs.mu.Unlock()

	count, err := rc.SessionCount()
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)
}

func TestDeleteSession_RemovesFromBothStores(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Create and cache session.
	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("sess:test-key"))

	err := rc.DeleteSession("test-key")
	require.NoError(t, err)
	assert.False(t, fr.hasKey("sess:test-key"))

	bs.mu.Lock()
	_, exists := bs.sessions["test-key"]
	bs.mu.Unlock()
	assert.False(t, exists)
}

func TestDeleteSession_NotFound(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.DeleteSession("nonexistent")
	assert.Error(t, err)
}

func TestEvictExpired_DelegatesToBacking(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	n, err := rc.EvictExpired(time.Hour)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

func TestEvictLRU_DelegatesToBacking(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	n, err := rc.EvictLRU(100)
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

// Test with a non-evictable backing store
type nonEvictableStore struct {
	fakeBackingStore
}

// Remove evictable methods to test fallback.
func (s *nonEvictableStore) SessionCount() (int64, error) { panic("should not be called") }
func (s *nonEvictableStore) DeleteSession(key string) error { panic("should not be called") }
func (s *nonEvictableStore) EvictExpired(ttl time.Duration) (int64, error) { panic("should not be called") }
func (s *nonEvictableStore) EvictLRU(maxSessions int) (int64, error) { panic("should not be called") }

// minimalBackingStore only implements SessionStore, not EvictableStore.
type minimalBackingStore struct{}

func (m *minimalBackingStore) GetOrCreate(key string) (*session.Session, error) {
	return &session.Session{Key: key, Messages: []providers.Message{}, Created: time.Now(), Updated: time.Now()}, nil
}
func (m *minimalBackingStore) AddMessage(string, providers.Message) error { return nil }
func (m *minimalBackingStore) GetHistory(string) ([]providers.Message, error) { return nil, nil }
func (m *minimalBackingStore) GetSummary(string) (string, error) { return "", nil }
func (m *minimalBackingStore) SetSummary(string, string) error { return nil }
func (m *minimalBackingStore) SetHistory(string, []providers.Message) error { return nil }
func (m *minimalBackingStore) TruncateHistory(string, int) error { return nil }
func (m *minimalBackingStore) Save(string) error { return nil }
func (m *minimalBackingStore) Close() error { return nil }

func TestSessionCount_NonEvictableBackingStore(t *testing.T) {
	fr := newFakeRedis()
	rc, _ := New(fr, &minimalBackingStore{}, DefaultConfig())
	_, err := rc.SessionCount()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support SessionCount")
}

func TestDeleteSession_NonEvictableBackingStore(t *testing.T) {
	fr := newFakeRedis()
	rc, _ := New(fr, &minimalBackingStore{}, DefaultConfig())
	err := rc.DeleteSession("key")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not support DeleteSession")
}

func TestEvictExpired_NonEvictableBackingStore(t *testing.T) {
	fr := newFakeRedis()
	rc, _ := New(fr, &minimalBackingStore{}, DefaultConfig())
	_, err := rc.EvictExpired(time.Hour)
	assert.Error(t, err)
}

func TestEvictLRU_NonEvictableBackingStore(t *testing.T) {
	fr := newFakeRedis()
	rc, _ := New(fr, &minimalBackingStore{}, DefaultConfig())
	_, err := rc.EvictLRU(100)
	assert.Error(t, err)
}

func TestPing(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	err := rc.Ping()
	assert.NoError(t, err)
}

func TestStats(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Add some entries.
	_, _ = rc.GetOrCreate("key1")
	_, _ = rc.GetOrCreate("key2")

	stats, err := rc.Stats()
	require.NoError(t, err)
	assert.Equal(t, int64(2), stats.KeyCount)
	assert.Equal(t, "sess:", stats.KeyPrefix)
	assert.Equal(t, 30*time.Minute, stats.TTL)
}

func TestInvalidate(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("sess:test-key"))

	rc.Invalidate("test-key")
	assert.False(t, fr.hasKey("sess:test-key"))
}

func TestRedisKey_CustomPrefix(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	cfg := Config{KeyPrefix: "custom:", TTL: time.Minute}
	rc, _ := New(fr, bs, cfg)

	_, _ = rc.GetOrCreate("test-key")
	assert.True(t, fr.hasKey("custom:test-key"))
	assert.False(t, fr.hasKey("sess:test-key"))
}

func TestCachedSession_RoundTrip(t *testing.T) {
	cs := cachedSession{
		Key:     "test",
		Summary: "a summary",
		Messages: []cachedMessage{
			{Role: "user", Content: "hello"},
			{Role: "assistant", Content: "hi", ToolCalls: []providers.ToolCall{
				{ID: "tc1", Function: &providers.FunctionCall{Name: "test_tool", Arguments: `{"a":"b"}`}},
			}},
			{Role: "tool", ToolCallID: "tc1", Content: "result"},
		},
		Created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Updated: time.Date(2026, 1, 1, 1, 0, 0, 0, time.UTC),
	}

	data, err := json.Marshal(cs)
	require.NoError(t, err)

	var decoded cachedSession
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, cs.Key, decoded.Key)
	assert.Equal(t, cs.Summary, decoded.Summary)
	assert.Len(t, decoded.Messages, 3)
	assert.Equal(t, "user", decoded.Messages[0].Role)
	assert.Equal(t, "hello", decoded.Messages[0].Content)
	assert.Len(t, decoded.Messages[1].ToolCalls, 1)
	assert.Equal(t, "tc1", decoded.Messages[1].ToolCalls[0].ID)
	assert.Equal(t, "tc1", decoded.Messages[2].ToolCallID)
}

func TestCachedMessageConversion(t *testing.T) {
	msgs := []providers.Message{
		{Role: "user", Content: "hello", Media: []string{"data:image/png;base64,abc123"}},
		{Role: "assistant", Content: "hi", ToolCalls: []providers.ToolCall{{ID: "tc1"}}},
		{Role: "tool", ToolCallID: "tc1", Content: "result"},
		{Role: "assistant", ReasoningContent: "thinking..."},
	}

	cached := toCachedMessages(msgs)
	assert.Len(t, cached, 4)
	assert.Equal(t, "user", cached[0].Role)
	assert.Len(t, cached[0].Media, 1)

	roundTripped := fromCachedMessages(cached)
	assert.Len(t, roundTripped, 4)
	assert.Equal(t, "hello", roundTripped[0].Content)
	assert.Len(t, roundTripped[0].Media, 1)
	assert.Equal(t, "data:image/png;base64,abc123", roundTripped[0].Media[0])
	assert.Len(t, roundTripped[1].ToolCalls, 1)
	assert.Equal(t, "tc1", roundTripped[2].ToolCallID)
	assert.Equal(t, "thinking...", roundTripped[3].ReasoningContent)
}

func TestCorruptCacheEntry_TreatedAsMiss(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Inject corrupt data directly.
	fr.mu.Lock()
	fr.data["sess:test-key"] = "{{invalid json"
	fr.mu.Unlock()

	sess, err := rc.GetOrCreate("test-key")
	require.NoError(t, err)
	assert.Equal(t, "test-key", sess.Key)

	// Corrupt entry should have been cleaned up.
	// New valid entry should be cached.
	assert.True(t, fr.hasKey("sess:test-key"))
}

func TestCustomContext(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	ctx := context.WithValue(context.Background(), "test", "value")
	cfg := Config{
		KeyPrefix: "sess:",
		TTL:       time.Minute,
		Ctx:       ctx,
	}
	rc, _ := New(fr, bs, cfg)

	// Should use custom context (no error = context works).
	_, err := rc.GetOrCreate("test-key")
	assert.NoError(t, err)
}

func TestCacheTTL_Applied(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	cfg := Config{
		KeyPrefix: "sess:",
		TTL:       10 * time.Minute,
	}
	rc, _ := New(fr, bs, cfg)

	_, _ = rc.GetOrCreate("test-key")

	ttl := fr.getTTL("sess:test-key")
	assert.Equal(t, 10*time.Minute, ttl)
}

func TestMultiSession_Isolation(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// Create two sessions.
	sess1, _ := rc.GetOrCreate("session-1")
	sess2, _ := rc.GetOrCreate("session-2")

	assert.Equal(t, "session-1", sess1.Key)
	assert.Equal(t, "session-2", sess2.Key)
	assert.True(t, fr.hasKey("sess:session-1"))
	assert.True(t, fr.hasKey("sess:session-2"))

	// Delete one, other should remain.
	rc.Invalidate("session-1")
	assert.False(t, fr.hasKey("sess:session-1"))
	assert.True(t, fr.hasKey("sess:session-2"))
}

func TestParseRedisURL_Valid(t *testing.T) {
	// ParseURL validates format but doesn't connect, so this is safe.
	client, err := ParseRedisURL("redis://localhost:6379/0")
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestParseRedisURL_Empty(t *testing.T) {
	_, err := ParseRedisURL("")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "URL is required")
}

func TestParseRedisURL_Invalid(t *testing.T) {
	_, err := ParseRedisURL("not-a-url")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "parse URL")
}

func TestParseRedisURL_TLS(t *testing.T) {
	client, err := ParseRedisURL("rediss://user:pass@redis.example.com:6380/1")
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestInterfaceCompliance(t *testing.T) {
	// Compile-time check that RedisCache implements SessionStore.
	var _ session.SessionStore = (*RedisCache)(nil)
}

func TestEvictableStoreCompliance(t *testing.T) {
	// Compile-time check that RedisCache implements EvictableStore.
	var _ session.EvictableStore = (*RedisCache)(nil)
}

func TestCacheNilSession(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// cacheSession with nil should not panic.
	rc.cacheSession(nil)
	assert.Equal(t, 0, fr.keyCount())
}

func TestFullFlow_CreateAddReadInvalidate(t *testing.T) {
	fr := newFakeRedis()
	bs := newFakeBackingStore()
	rc, _ := New(fr, bs, DefaultConfig())

	// 1. Create session.
	sess, err := rc.GetOrCreate("flow-test")
	require.NoError(t, err)
	assert.Empty(t, sess.Messages)
	assert.True(t, fr.hasKey("sess:flow-test"))

	// 2. Add messages (invalidates cache).
	err = rc.AddMessage("flow-test", providers.Message{Role: "user", Content: "hello"})
	require.NoError(t, err)
	assert.False(t, fr.hasKey("sess:flow-test"))

	err = rc.AddMessage("flow-test", providers.Message{Role: "assistant", Content: "hi"})
	require.NoError(t, err)

	// 3. Read history (cache miss, reads from backing, populates cache async).
	msgs, err := rc.GetHistory("flow-test")
	require.NoError(t, err)
	assert.Len(t, msgs, 2)

	// 4. Set summary (invalidates cache).
	err = rc.SetSummary("flow-test", "greeting exchange")
	require.NoError(t, err)

	// 5. Read summary from backing.
	summary, err := rc.GetSummary("flow-test")
	require.NoError(t, err)
	assert.Equal(t, "greeting exchange", summary)

	// 6. Truncate history.
	err = rc.TruncateHistory("flow-test", 1)
	require.NoError(t, err)

	msgs, err = rc.GetHistory("flow-test")
	require.NoError(t, err)
	assert.Len(t, msgs, 1)
	assert.Equal(t, "hi", msgs[0].Content)

	// 7. Delete session.
	err = rc.DeleteSession("flow-test")
	require.NoError(t, err)
	assert.False(t, fr.hasKey("sess:flow-test"))
}
