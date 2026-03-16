// Package middleware provides shared HTTP middleware for request validation,
// body size limits, and content-type enforcement.
package middleware

import (
	"net/http"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
)

// DefaultMaxBodySize is the default maximum request body size (1 MB).
const DefaultMaxBodySize int64 = 1 << 20

// BodySizeLimit returns middleware that limits request body size.
// If maxBytes is 0, DefaultMaxBodySize is used.
func BodySizeLimit(maxBytes int64) func(http.Handler) http.Handler {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBodySize
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireJSON returns middleware that enforces Content-Type: application/json
// on POST, PUT, and PATCH requests that have a body. GET, DELETE, HEAD, and
// OPTIONS requests are passed through without checks.
func RequireJSON(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch:
			if r.ContentLength != 0 {
				ct := r.Header.Get("Content-Type")
				if ct != "application/json" && ct != "application/json; charset=utf-8" {
					apiutil.WriteError(w, http.StatusUnsupportedMediaType,
						"unsupported_media_type",
						"Content-Type must be application/json")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// RecoverPanic returns middleware that recovers from panics in handlers
// and returns a 500 Internal Server Error response.
func RecoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				apiutil.WriteError(w, http.StatusInternalServerError,
					"internal_error",
					"An unexpected error occurred")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
