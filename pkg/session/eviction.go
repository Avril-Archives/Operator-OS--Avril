package session

import (
	"fmt"
	"sync"
	"time"

	"github.com/standardws/operator/pkg/logger"
)

// EvictableStore extends SessionStore with methods needed for TTL and LRU eviction.
// Stores that support eviction should implement this interface.
type EvictableStore interface {
	SessionStore

	// SessionCount returns the total number of sessions.
	SessionCount() (int64, error)

	// DeleteSession removes a session and all its messages.
	DeleteSession(key string) error

	// EvictExpired deletes sessions whose updated_at is older than the given TTL.
	// Returns the number of sessions evicted.
	EvictExpired(ttl time.Duration) (int64, error)

	// EvictLRU deletes the least-recently-updated sessions until the total count
	// is at or below maxSessions. Returns the number of sessions evicted.
	EvictLRU(maxSessions int) (int64, error)
}

// EvictorConfig holds the configuration for the session Evictor.
type EvictorConfig struct {
	// TTL is the maximum time a session can be inactive before eviction.
	// Zero means no TTL-based eviction.
	TTL time.Duration

	// MaxSessions is the maximum number of sessions allowed.
	// When exceeded, the least-recently-used sessions are evicted.
	// Zero means no LRU-based eviction.
	MaxSessions int

	// Interval is how often the evictor runs its sweep.
	// Defaults to 5 minutes if zero.
	Interval time.Duration
}

// DefaultEvictorConfig returns a config with sensible defaults:
// 24h TTL, 10000 max sessions, 5-minute sweep interval.
func DefaultEvictorConfig() EvictorConfig {
	return EvictorConfig{
		TTL:         24 * time.Hour,
		MaxSessions: 10000,
		Interval:    5 * time.Minute,
	}
}

// Evictor runs periodic session eviction based on TTL and LRU policies.
type Evictor struct {
	store  EvictableStore
	config EvictorConfig
	stopCh chan struct{}
	done   chan struct{}
	once   sync.Once
}

// NewEvictor creates a new Evictor for the given store.
// Call Start() to begin periodic eviction.
func NewEvictor(store EvictableStore, config EvictorConfig) *Evictor {
	if config.Interval <= 0 {
		config.Interval = 5 * time.Minute
	}
	return &Evictor{
		store:  store,
		config: config,
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
}

// Start begins the periodic eviction loop in a background goroutine.
func (e *Evictor) Start() {
	go e.loop()
}

// Stop signals the evictor to stop and waits for it to finish.
func (e *Evictor) Stop() {
	e.once.Do(func() {
		close(e.stopCh)
	})
	<-e.done
}

// RunOnce performs a single eviction sweep. Safe to call manually.
// Returns total sessions evicted (TTL + LRU).
func (e *Evictor) RunOnce() (int64, error) {
	var total int64

	// TTL eviction first.
	if e.config.TTL > 0 {
		n, err := e.store.EvictExpired(e.config.TTL)
		if err != nil {
			return total, fmt.Errorf("evict expired: %w", err)
		}
		total += n
		if n > 0 {
			logger.InfoCF("session.evictor", fmt.Sprintf("Evicted %d expired sessions (TTL: %s)", n, e.config.TTL), nil)
		}
	}

	// LRU eviction second.
	if e.config.MaxSessions > 0 {
		n, err := e.store.EvictLRU(e.config.MaxSessions)
		if err != nil {
			return total, fmt.Errorf("evict LRU: %w", err)
		}
		total += n
		if n > 0 {
			logger.InfoCF("session.evictor", fmt.Sprintf("Evicted %d sessions by LRU (max: %d)", n, e.config.MaxSessions), nil)
		}
	}

	return total, nil
}

func (e *Evictor) loop() {
	defer close(e.done)

	ticker := time.NewTicker(e.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			if _, err := e.RunOnce(); err != nil {
				logger.ErrorF(fmt.Sprintf("[session.evictor] Eviction sweep failed: %v", err), nil)
			}
		}
	}
}
