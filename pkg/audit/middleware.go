package audit

import (
	"net"
	"net/http"
	"strings"
)

// Middleware returns an HTTP middleware that logs audit events for requests.
// It extracts the user ID from context (set by auth middleware) and captures
// request metadata (IP, user agent).
type Middleware struct {
	logger    *Logger
	getUserID func(r *http.Request) string
}

// NewMiddleware creates audit middleware with a Logger and a function to extract
// user ID from request context.
func NewMiddleware(logger *Logger, getUserIDFn func(r *http.Request) string) *Middleware {
	return &Middleware{
		logger:    logger,
		getUserID: getUserIDFn,
	}
}

// WrapHandler wraps an http.Handler to log audit events.
// The action and resource are specified by the caller.
func (m *Middleware) WrapHandler(action, resource string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Capture response status via wrapper
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		// Log the event after the handler completes
		event := NewEvent(action).
			WithResource(resource, "").
			WithIPAddress(extractIP(r)).
			WithUserAgent(r.UserAgent())

		if m.getUserID != nil {
			event.WithUser(m.getUserID(r))
		}

		if rw.statusCode >= 400 {
			event.WithFailure(http.StatusText(rw.statusCode))
		}

		m.logger.Log(r.Context(), event)
	})
}

// responseWriter wraps http.ResponseWriter to capture the status code.
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	written    bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.written {
		rw.statusCode = code
		rw.written = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.written {
		rw.written = true
	}
	return rw.ResponseWriter.Write(b)
}

// extractIP returns the client's IP address from the request.
func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}

	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
