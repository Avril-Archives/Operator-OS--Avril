// Package rediscache provides a Redis-based caching layer for session data.
// It implements the session.SessionStore interface as a read-through/write-through
// cache that wraps a persistent backing store (SQLite or PostgreSQL).
//
// In SaaS mode, this sits between the SessionManager and the database store
// to reduce latency for hot sessions. Cache misses fall through to the backing
// store automatically.
package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/operatoronline/Operator-OS/pkg/providers"
	"github.com/operatoronline/Operator-OS/pkg/session"
)

// RedisClient is the minimal Redis interface required by RedisCache.
// Both *redis.Client and *redis.ClusterClient satisfy this interface.
type RedisClient interface {
	Get(ctx context.Context, key string) *redis.StringCmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Del(ctx context.Context, keys ...string) *redis.IntCmd
	Ping(ctx context.Context) *redis.StatusCmd
	DBSize(ctx context.Context) *redis.IntCmd
}

// ErrNilClient is returned when a nil Redis client is provided.
var ErrNilClient = errors.New("rediscache: redis client is nil")

// ErrNilBackingStore is returned when a nil backing store is provided.
var ErrNilBackingStore = errors.New("rediscache: backing store is nil")

// Config holds configuration for the Redis session cache.
type Config struct {
	// KeyPrefix is prepended to all Redis keys (default "sess:").
	KeyPrefix string

	// TTL is how long cached sessions live in Redis (default 30m).
	// After expiry, the next read falls through to the backing store.
	TTL time.Duration

	// Ctx is the base context for Redis operations.
	// If nil, context.Background() is used.
	Ctx context.Context
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		KeyPrefix: "sess:",
		TTL:       30 * time.Minute,
	}
}

// cachedSession is the JSON-serialised representation of a session in Redis.
type cachedSession struct {
	Key      string              `json:"key"`
	Summary  string              `json:"summary"`
	Messages []cachedMessage     `json:"messages"`
	Created  time.Time           `json:"created"`
	Updated  time.Time           `json:"updated"`
}

// cachedMessage is a compact JSON representation of a providers.Message for caching.
type cachedMessage struct {
	Role             string              `json:"r"`
	Content          string              `json:"c,omitempty"`
	ToolCalls        []providers.ToolCall `json:"tc,omitempty"`
	ToolCallID       string              `json:"ti,omitempty"`
	ReasoningContent string              `json:"rc,omitempty"`
	Media            []string            `json:"m,omitempty"`
}

func toCachedMessages(msgs []providers.Message) []cachedMessage {
	out := make([]cachedMessage, len(msgs))
	for i, m := range msgs {
		out[i] = cachedMessage{
			Role:             m.Role,
			Content:          m.Content,
			ToolCalls:        m.ToolCalls,
			ToolCallID:       m.ToolCallID,
			ReasoningContent: m.ReasoningContent,
			Media:            m.Media,
		}
	}
	return out
}

func fromCachedMessages(cms []cachedMessage) []providers.Message {
	out := make([]providers.Message, len(cms))
	for i, cm := range cms {
		out[i] = providers.Message{
			Role:             cm.Role,
			Content:          cm.Content,
			ToolCalls:        cm.ToolCalls,
			ToolCallID:       cm.ToolCallID,
			ReasoningContent: cm.ReasoningContent,
			Media:            cm.Media,
		}
	}
	return out
}

// RedisCache wraps a backing SessionStore with a Redis caching layer.
// It implements session.SessionStore and session.EvictableStore (delegating
// eviction methods to the backing store if it supports them).
type RedisCache struct {
	client  RedisClient
	backing session.SessionStore
	config  Config
}

// New creates a RedisCache that caches session data in Redis and delegates
// persistence to the backing store.
func New(client RedisClient, backing session.SessionStore, config Config) (*RedisCache, error) {
	if client == nil {
		return nil, ErrNilClient
	}
	if backing == nil {
		return nil, ErrNilBackingStore
	}

	if config.KeyPrefix == "" {
		config.KeyPrefix = "sess:"
	}
	if config.TTL <= 0 {
		config.TTL = 30 * time.Minute
	}

	return &RedisCache{
		client:  client,
		backing: backing,
		config:  config,
	}, nil
}

func (rc *RedisCache) ctx() context.Context {
	if rc.config.Ctx != nil {
		return rc.config.Ctx
	}
	return context.Background()
}

func (rc *RedisCache) redisKey(sessionKey string) string {
	return rc.config.KeyPrefix + sessionKey
}

// GetOrCreate returns the session for the given key.
// It first checks Redis, then falls through to the backing store on miss.
func (rc *RedisCache) GetOrCreate(key string) (*session.Session, error) {
	// Try cache first.
	if sess, err := rc.getFromCache(key); err == nil && sess != nil {
		return sess, nil
	}

	// Cache miss — delegate to backing store.
	sess, err := rc.backing.GetOrCreate(key)
	if err != nil {
		return nil, err
	}

	// Populate cache asynchronously (best-effort).
	rc.cacheSession(sess)

	return sess, nil
}

// AddMessage appends a message to both the backing store and invalidates the cache.
// Write-through: the backing store is the source of truth.
func (rc *RedisCache) AddMessage(key string, msg providers.Message) error {
	if err := rc.backing.AddMessage(key, msg); err != nil {
		return err
	}

	// Invalidate cache so the next read gets fresh data.
	rc.invalidate(key)
	return nil
}

// GetHistory returns message history, checking cache first.
func (rc *RedisCache) GetHistory(key string) ([]providers.Message, error) {
	// Try cache first.
	if sess, err := rc.getFromCache(key); err == nil && sess != nil {
		msgs := make([]providers.Message, len(sess.Messages))
		copy(msgs, sess.Messages)
		return msgs, nil
	}

	// Cache miss — backing store.
	msgs, err := rc.backing.GetHistory(key)
	if err != nil {
		return nil, err
	}

	// Best-effort: load full session into cache for future reads.
	go func() {
		if sess, err := rc.backing.GetOrCreate(key); err == nil {
			rc.cacheSession(sess)
		}
	}()

	return msgs, nil
}

// GetSummary returns the conversation summary, checking cache first.
func (rc *RedisCache) GetSummary(key string) (string, error) {
	// Try cache first.
	if sess, err := rc.getFromCache(key); err == nil && sess != nil {
		return sess.Summary, nil
	}

	// Cache miss — backing store.
	return rc.backing.GetSummary(key)
}

// SetSummary updates the summary in the backing store and invalidates the cache.
func (rc *RedisCache) SetSummary(key string, summary string) error {
	if err := rc.backing.SetSummary(key, summary); err != nil {
		return err
	}
	rc.invalidate(key)
	return nil
}

// SetHistory replaces message history in the backing store and invalidates the cache.
func (rc *RedisCache) SetHistory(key string, messages []providers.Message) error {
	if err := rc.backing.SetHistory(key, messages); err != nil {
		return err
	}
	rc.invalidate(key)
	return nil
}

// TruncateHistory truncates history in the backing store and invalidates the cache.
func (rc *RedisCache) TruncateHistory(key string, keepLast int) error {
	if err := rc.backing.TruncateHistory(key, keepLast); err != nil {
		return err
	}
	rc.invalidate(key)
	return nil
}

// Save delegates to the backing store.
func (rc *RedisCache) Save(key string) error {
	return rc.backing.Save(key)
}

// Close closes the backing store. Redis client lifecycle is managed by the caller.
func (rc *RedisCache) Close() error {
	return rc.backing.Close()
}

// SessionCount delegates to the backing store (not cached — admin operation).
func (rc *RedisCache) SessionCount() (int64, error) {
	if es, ok := rc.backing.(session.EvictableStore); ok {
		return es.SessionCount()
	}
	return 0, fmt.Errorf("backing store does not support SessionCount")
}

// DeleteSession deletes from both the backing store and cache.
func (rc *RedisCache) DeleteSession(key string) error {
	if es, ok := rc.backing.(session.EvictableStore); ok {
		if err := es.DeleteSession(key); err != nil {
			return err
		}
		rc.invalidate(key)
		return nil
	}
	return fmt.Errorf("backing store does not support DeleteSession")
}

// EvictExpired delegates to the backing store.
// Does not clear individual cache entries (they expire naturally via TTL).
func (rc *RedisCache) EvictExpired(ttl time.Duration) (int64, error) {
	if es, ok := rc.backing.(session.EvictableStore); ok {
		return es.EvictExpired(ttl)
	}
	return 0, fmt.Errorf("backing store does not support EvictExpired")
}

// EvictLRU delegates to the backing store.
func (rc *RedisCache) EvictLRU(maxSessions int) (int64, error) {
	if es, ok := rc.backing.(session.EvictableStore); ok {
		return es.EvictLRU(maxSessions)
	}
	return 0, fmt.Errorf("backing store does not support EvictLRU")
}

// Ping checks Redis connectivity.
func (rc *RedisCache) Ping() error {
	return rc.client.Ping(rc.ctx()).Err()
}

// Invalidate removes a session from the cache.
func (rc *RedisCache) Invalidate(key string) {
	rc.invalidate(key)
}

// Stats returns cache statistics.
func (rc *RedisCache) Stats() (*CacheStats, error) {
	ctx := rc.ctx()
	dbSize := rc.client.DBSize(ctx)
	if dbSize.Err() != nil {
		return nil, fmt.Errorf("redis DBSize: %w", dbSize.Err())
	}
	return &CacheStats{
		KeyCount:  dbSize.Val(),
		KeyPrefix: rc.config.KeyPrefix,
		TTL:       rc.config.TTL,
	}, nil
}

// CacheStats contains basic cache statistics.
type CacheStats struct {
	KeyCount  int64         `json:"key_count"`
	KeyPrefix string        `json:"key_prefix"`
	TTL       time.Duration `json:"ttl"`
}

// --- internal helpers ---

func (rc *RedisCache) getFromCache(key string) (*session.Session, error) {
	ctx := rc.ctx()
	data, err := rc.client.Get(ctx, rc.redisKey(key)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil // cache miss
		}
		return nil, fmt.Errorf("redis get %q: %w", key, err)
	}

	var cs cachedSession
	if err := json.Unmarshal(data, &cs); err != nil {
		// Corrupt cache entry — delete and treat as miss.
		rc.invalidate(key)
		return nil, nil
	}

	return &session.Session{
		Key:      cs.Key,
		Summary:  cs.Summary,
		Messages: fromCachedMessages(cs.Messages),
		Created:  cs.Created,
		Updated:  cs.Updated,
	}, nil
}

func (rc *RedisCache) cacheSession(sess *session.Session) {
	if sess == nil {
		return
	}

	cs := cachedSession{
		Key:      sess.Key,
		Summary:  sess.Summary,
		Messages: toCachedMessages(sess.Messages),
		Created:  sess.Created,
		Updated:  sess.Updated,
	}

	data, err := json.Marshal(cs)
	if err != nil {
		return // best-effort
	}

	ctx := rc.ctx()
	rc.client.Set(ctx, rc.redisKey(sess.Key), data, rc.config.TTL)
}

func (rc *RedisCache) invalidate(key string) {
	rc.client.Del(rc.ctx(), rc.redisKey(key))
}

// ParseRedisURL creates a Redis client from a URL string.
// Supports redis:// and rediss:// (TLS) schemes.
func ParseRedisURL(url string) (*redis.Client, error) {
	if url == "" {
		return nil, fmt.Errorf("rediscache: URL is required")
	}

	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("rediscache: parse URL: %w", err)
	}

	return redis.NewClient(opts), nil
}
