package logger

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"
)

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.written += int64(n)
	return n, err
}

// Unwrap returns the underlying ResponseWriter for compatibility with
// http.ResponseController and other unwrap-aware code.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// RequestLogging returns an HTTP middleware that logs every request with
// structured fields: method, path, status, duration, user_id (if present),
// remote_addr, and a correlation ID injected into the request context.
func RequestLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate correlation ID and inject into context.
		cid := generateCorrelationID()
		ctx := WithCorrelationID(r.Context(), cid)
		r = r.WithContext(ctx)

		// Set correlation ID response header.
		w.Header().Set("X-Correlation-ID", cid)

		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		fields := map[string]any{
			"method":      r.Method,
			"path":        r.URL.Path,
			"status":      rw.statusCode,
			"duration_ms": duration.Milliseconds(),
			"remote_addr": r.RemoteAddr,
			"bytes":       rw.written,
		}

		if userAgent := r.Header.Get("User-Agent"); userAgent != "" {
			fields["user_agent"] = userAgent
		}

		// Log level based on status code.
		switch {
		case rw.statusCode >= 500:
			logMessageCtx(ctx, ERROR, "http", "Request completed", fields)
		case rw.statusCode >= 400:
			logMessageCtx(ctx, WARN, "http", "Request completed", fields)
		default:
			logMessageCtx(ctx, INFO, "http", "Request completed", fields)
		}
	})
}

// generateCorrelationID creates a short random hex ID.
func generateCorrelationID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b)
}
