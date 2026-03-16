package logger

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestLogging(t *testing.T) {
	handler := RequestLogging(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify correlation ID is in context
		cid := CorrelationID(r.Context())
		if cid == "" {
			t.Error("expected correlation ID in context")
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))

	req := httptest.NewRequest("GET", "/api/v1/test", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	cid := rec.Header().Get("X-Correlation-ID")
	if cid == "" {
		t.Error("expected X-Correlation-ID header")
	}
	if len(cid) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 char correlation ID, got %d", len(cid))
	}
}

func TestResponseWriterCapturesStatus(t *testing.T) {
	handler := RequestLogging(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))

	req := httptest.NewRequest("GET", "/missing", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}
}
