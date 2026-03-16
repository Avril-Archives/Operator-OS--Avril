package middleware

import (
	"net/http"
	"strings"
)

// CORSConfig holds CORS middleware configuration.
type CORSConfig struct {
	// AllowedOrigins is a list of origins allowed to make cross-origin requests.
	// Use ["*"] to allow all origins (not recommended for production).
	AllowedOrigins []string
	// AllowedMethods is a list of HTTP methods allowed for cross-origin requests.
	AllowedMethods []string
	// AllowedHeaders is a list of headers allowed in cross-origin requests.
	AllowedHeaders []string
	// AllowCredentials indicates whether cookies/auth headers are allowed.
	AllowCredentials bool
	// MaxAge is the maximum time (in seconds) that preflight results can be cached.
	MaxAge string
}

// DefaultCORSConfig returns a production-safe CORS configuration that allows
// only the local Vite dev server and common API headers.
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins:   []string{"http://localhost:5173", "http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Correlation-ID"},
		AllowCredentials: true,
		MaxAge:           "86400",
	}
}

// CORS returns middleware that adds Cross-Origin Resource Sharing headers.
// It handles preflight OPTIONS requests and sets appropriate response headers.
func CORS(cfg CORSConfig) func(http.Handler) http.Handler {
	allowAll := len(cfg.AllowedOrigins) == 1 && cfg.AllowedOrigins[0] == "*"
	originSet := make(map[string]bool, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		originSet[o] = true
	}

	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			// Check if the origin is allowed.
			allowed := allowAll || originSet[origin]
			if !allowed {
				next.ServeHTTP(w, r)
				return
			}

			// Set CORS headers.
			if allowAll {
				w.Header().Set("Access-Control-Allow-Origin", "*")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Vary", "Origin")
			}

			if cfg.AllowCredentials && !allowAll {
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight.
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", methods)
				w.Header().Set("Access-Control-Allow-Headers", headers)
				if cfg.MaxAge != "" {
					w.Header().Set("Access-Control-Max-Age", cfg.MaxAge)
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
