package users

import (
	"sync"
	"time"
)

// TokenBlacklist provides in-memory JWT revocation by tracking blacklisted JTI values.
// Entries auto-expire after their TTL to prevent unbounded memory growth.
type TokenBlacklist struct {
	mu      sync.RWMutex
	entries map[string]time.Time // jti → expiry time
	done    chan struct{}
}

// NewTokenBlacklist creates a new blacklist with a background sweeper.
func NewTokenBlacklist() *TokenBlacklist {
	bl := &TokenBlacklist{
		entries: make(map[string]time.Time),
		done:    make(chan struct{}),
	}
	go bl.sweep()
	return bl
}

// Revoke adds a token's JTI to the blacklist. The entry is kept until expiresAt,
// after which the token would be rejected by normal expiry checks anyway.
func (bl *TokenBlacklist) Revoke(jti string, expiresAt time.Time) {
	bl.mu.Lock()
	bl.entries[jti] = expiresAt
	bl.mu.Unlock()
}

// IsRevoked checks if a JTI has been blacklisted.
func (bl *TokenBlacklist) IsRevoked(jti string) bool {
	bl.mu.RLock()
	_, revoked := bl.entries[jti]
	bl.mu.RUnlock()
	return revoked
}

// RevokeUser revokes both access and refresh tokens for a given JTI base.
// Convention: access JTI is "<base>-access", refresh is "<base>-refresh".
func (bl *TokenBlacklist) RevokeUser(jtiBase string, accessExpiry, refreshExpiry time.Time) {
	bl.mu.Lock()
	bl.entries[jtiBase+"-access"] = accessExpiry
	bl.entries[jtiBase+"-refresh"] = refreshExpiry
	bl.mu.Unlock()
}

// Stop halts the background sweeper.
func (bl *TokenBlacklist) Stop() {
	close(bl.done)
}

// Size returns the number of active blacklist entries.
func (bl *TokenBlacklist) Size() int {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	return len(bl.entries)
}

func (bl *TokenBlacklist) sweep() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-bl.done:
			return
		case now := <-ticker.C:
			bl.mu.Lock()
			for jti, exp := range bl.entries {
				if now.After(exp) {
					delete(bl.entries, jti)
				}
			}
			bl.mu.Unlock()
		}
	}
}
