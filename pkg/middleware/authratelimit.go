package middleware

import (
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

// AuthRateLimitConfig configures IP-based rate limiting for auth endpoints.
type AuthRateLimitConfig struct {
	// MaxAttempts is the maximum number of attempts allowed per window.
	MaxAttempts int
	// Window is the time window for tracking attempts.
	Window time.Duration
	// CleanupInterval controls how often expired entries are swept.
	CleanupInterval time.Duration
}

// DefaultAuthRateLimitConfig returns sensible defaults: 10 attempts per 15 minutes.
func DefaultAuthRateLimitConfig() AuthRateLimitConfig {
	return AuthRateLimitConfig{
		MaxAttempts:     10,
		Window:          15 * time.Minute,
		CleanupInterval: 5 * time.Minute,
	}
}

type ipEntry struct {
	count    int
	windowAt time.Time
}

// AuthRateLimiter provides IP-based rate limiting for unauthenticated endpoints
// like login, registration, and password reset.
type AuthRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*ipEntry
	cfg     AuthRateLimitConfig
	done    chan struct{}
}

// NewAuthRateLimiter creates and starts an IP-based rate limiter.
func NewAuthRateLimiter(cfg AuthRateLimitConfig) *AuthRateLimiter {
	rl := &AuthRateLimiter{
		entries: make(map[string]*ipEntry),
		cfg:     cfg,
		done:    make(chan struct{}),
	}
	go rl.cleanup()
	return rl
}

// Stop halts the background cleanup goroutine.
func (rl *AuthRateLimiter) Stop() {
	close(rl.done)
}

// Middleware returns HTTP middleware that rate-limits requests by client IP.
func (rl *AuthRateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Too many requests. Please try again later.",
				"code":  "rate_limited",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *AuthRateLimiter) allow(ip string) bool {
	now := time.Now()
	rl.mu.Lock()
	defer rl.mu.Unlock()

	entry, ok := rl.entries[ip]
	if !ok {
		rl.entries[ip] = &ipEntry{count: 1, windowAt: now}
		return true
	}

	// Window expired — reset.
	if now.Sub(entry.windowAt) >= rl.cfg.Window {
		entry.count = 1
		entry.windowAt = now
		return true
	}

	entry.count++
	return entry.count <= rl.cfg.MaxAttempts
}

func (rl *AuthRateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cfg.CleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-rl.done:
			return
		case now := <-ticker.C:
			rl.mu.Lock()
			for ip, entry := range rl.entries {
				if now.Sub(entry.windowAt) >= rl.cfg.Window {
					delete(rl.entries, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// clientIP extracts the client IP, preferring X-Forwarded-For when behind a proxy.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first (client) IP from the chain.
		if idx := net.ParseIP(xff); idx != nil {
			return xff
		}
		// X-Forwarded-For might contain "client, proxy1, proxy2"
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				ip := xff[:i]
				if net.ParseIP(ip) != nil {
					return ip
				}
				break
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
