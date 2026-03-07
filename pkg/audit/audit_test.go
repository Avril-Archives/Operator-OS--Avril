package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// --- Event tests ---

func TestNewEvent(t *testing.T) {
	e := NewEvent(ActionLogin)
	assert.NotEmpty(t, e.ID)
	assert.Equal(t, ActionLogin, e.Action)
	assert.Equal(t, StatusSuccess, e.Status)
	assert.NotNil(t, e.Detail)
	assert.WithinDuration(t, time.Now().UTC(), e.Timestamp, 2*time.Second)
}

func TestEventBuilders(t *testing.T) {
	e := NewEvent(ActionToolExecuted).
		WithUser("user-1").
		WithActor("admin@example.com").
		WithResource(ResourceTool, "shell").
		WithDetail("command", "ls -la").
		WithDetail("exit_code", "0").
		WithIPAddress("192.168.1.100").
		WithUserAgent("Mozilla/5.0")

	assert.Equal(t, "user-1", e.UserID)
	assert.Equal(t, "admin@example.com", e.Actor)
	assert.Equal(t, ResourceTool, e.Resource)
	assert.Equal(t, "shell", e.ResourceID)
	assert.Equal(t, "ls -la", e.Detail["command"])
	assert.Equal(t, "0", e.Detail["exit_code"])
	assert.Equal(t, "192.168.1.100", e.IPAddress)
	assert.Equal(t, "Mozilla/5.0", e.UserAgent)
	assert.Equal(t, StatusSuccess, e.Status)
}

func TestEventWithFailure(t *testing.T) {
	e := NewEvent(ActionLoginFailed).
		WithUser("user-1").
		WithFailure("invalid credentials")

	assert.Equal(t, StatusFailure, e.Status)
	assert.Equal(t, "invalid credentials", e.ErrorMsg)
}

func TestEventDetailJSON(t *testing.T) {
	t.Run("empty detail", func(t *testing.T) {
		e := NewEvent(ActionLogin)
		e.Detail = nil
		assert.Equal(t, "{}", e.DetailJSON())
	})

	t.Run("with detail", func(t *testing.T) {
		e := NewEvent(ActionLogin).WithDetail("method", "password")
		j := e.DetailJSON()
		var m map[string]string
		require.NoError(t, json.Unmarshal([]byte(j), &m))
		assert.Equal(t, "password", m["method"])
	})

	t.Run("empty map", func(t *testing.T) {
		e := NewEvent(ActionLogin)
		e.Detail = map[string]string{}
		assert.Equal(t, "{}", e.DetailJSON())
	})
}

func TestEventWithTimestamp(t *testing.T) {
	ts := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	e := NewEvent(ActionLogin).WithTimestamp(ts)
	assert.Equal(t, ts, e.Timestamp)
}

// --- SQLiteAuditStore tests ---

func TestNewSQLiteAuditStore(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	assert.NotNil(t, store)
}

func TestNewSQLiteAuditStore_NilDB(t *testing.T) {
	_, err := NewSQLiteAuditStore(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "db must not be nil")
}

func TestLog_Success(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	e := NewEvent(ActionLogin).
		WithUser("user-1").
		WithActor("test@example.com").
		WithIPAddress("10.0.0.1")

	err = store.Log(context.Background(), e)
	require.NoError(t, err)

	// Verify it was stored
	events, err := store.Query(context.Background(), QueryFilter{UserID: "user-1"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, ActionLogin, events[0].Action)
	assert.Equal(t, "test@example.com", events[0].Actor)
	assert.Equal(t, "10.0.0.1", events[0].IPAddress)
}

func TestLog_NilEvent(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	err = store.Log(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event must not be nil")
}

func TestLog_EmptyAction(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	e := NewEvent("")
	e.Action = ""
	err = store.Log(context.Background(), e)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event action must not be empty")
}

func TestLog_WithDetail(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	e := NewEvent(ActionToolExecuted).
		WithUser("user-1").
		WithResource(ResourceTool, "shell").
		WithDetail("command", "echo hello").
		WithDetail("duration_ms", "42")

	err = store.Log(context.Background(), e)
	require.NoError(t, err)

	events, err := store.Query(context.Background(), QueryFilter{UserID: "user-1"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "echo hello", events[0].Detail["command"])
	assert.Equal(t, "42", events[0].Detail["duration_ms"])
}

func TestQuery_ByAction(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	// Insert different actions
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLoginFailed).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionToolExecuted).WithUser("u1")))

	events, err := store.Query(ctx, QueryFilter{Action: ActionLogin})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, ActionLogin, events[0].Action)
}

func TestQuery_ByActionPrefix(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLoginFailed).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionRegister).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionToolExecuted).WithUser("u1")))

	// "auth." prefix should match login, login_failed, register
	events, err := store.Query(ctx, QueryFilter{Action: "auth."})
	require.NoError(t, err)
	assert.Len(t, events, 3)
}

func TestQuery_ByResource(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionAgentCreated).WithResource(ResourceAgent, "agent-1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionToolExecuted).WithResource(ResourceTool, "shell")))

	events, err := store.Query(ctx, QueryFilter{Resource: ResourceAgent})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "agent-1", events[0].ResourceID)
}

func TestQuery_ByStatus(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin)))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLoginFailed).WithFailure("bad password")))

	events, err := store.Query(ctx, QueryFilter{Status: StatusFailure})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "bad password", events[0].ErrorMsg)
}

func TestQuery_TimeRange(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	t1 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC)
	t3 := time.Date(2025, 12, 31, 12, 0, 0, 0, time.UTC)

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t1)))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t2)))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t3)))

	events, err := store.Query(ctx, QueryFilter{
		Since: time.Date(2025, 3, 1, 0, 0, 0, 0, time.UTC),
		Until: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC),
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, t2, events[0].Timestamp)
}

func TestQuery_Pagination(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	// Insert 10 events with distinct timestamps
	for i := 0; i < 10; i++ {
		ts := time.Date(2025, 1, 1, i, 0, 0, 0, time.UTC)
		require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(ts).WithDetail("idx", fmt.Sprintf("%d", i))))
	}

	// Get first 3 (most recent first)
	events, err := store.Query(ctx, QueryFilter{Limit: 3})
	require.NoError(t, err)
	require.Len(t, events, 3)
	assert.Equal(t, "9", events[0].Detail["idx"])

	// Get next 3
	events, err = store.Query(ctx, QueryFilter{Limit: 3, Offset: 3})
	require.NoError(t, err)
	require.Len(t, events, 3)
	assert.Equal(t, "6", events[0].Detail["idx"])
}

func TestQuery_DefaultLimit(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	// Insert 5 events
	for i := 0; i < 5; i++ {
		require.NoError(t, store.Log(ctx, NewEvent(ActionLogin)))
	}

	events, err := store.Query(ctx, QueryFilter{})
	require.NoError(t, err)
	assert.Len(t, events, 5) // default limit is 100, all 5 returned
}

func TestQuery_MaxLimit(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	// Limit should be capped at 1000
	events, err := store.Query(context.Background(), QueryFilter{Limit: 5000})
	require.NoError(t, err)
	assert.Empty(t, events) // no events, but no error
}

func TestQuery_EmptyResult(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	events, err := store.Query(context.Background(), QueryFilter{UserID: "nonexistent"})
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestCount(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u2")))

	count, err := store.Count(ctx, QueryFilter{UserID: "u1"})
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	total, err := store.Count(ctx, QueryFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(3), total)
}

func TestDeleteBefore(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t1)))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t2)))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t3)))

	deleted, err := store.DeleteBefore(ctx, time.Date(2025, 7, 1, 0, 0, 0, 0, time.UTC))
	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	remaining, err := store.Count(ctx, QueryFilter{})
	require.NoError(t, err)
	assert.Equal(t, int64(1), remaining)
}

func TestCombinedFilters(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLoginFailed).WithUser("u1").WithFailure("bad creds")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u2")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionToolExecuted).WithUser("u1")))

	events, err := store.Query(ctx, QueryFilter{
		UserID: "u1",
		Action: ActionLoginFailed,
		Status: StatusFailure,
	})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "bad creds", events[0].ErrorMsg)
}

func TestPersistence(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1").WithDetail("key", "val")))

	// Reopen store on same DB
	store2, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	events, err := store2.Query(ctx, QueryFilter{UserID: "u1"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "val", events[0].Detail["key"])
}

// --- Logger tests ---

func TestLogger_Log(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	logger := NewLogger(store)
	logger.Log(context.Background(), NewEvent(ActionLogin).WithUser("u1"))

	events, err := store.Query(context.Background(), QueryFilter{UserID: "u1"})
	require.NoError(t, err)
	assert.Len(t, events, 1)
}

func TestLogger_OnError(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	var capturedErr error
	logger := NewLogger(store).OnError(func(err error) {
		capturedErr = err
	})

	// Log nil event to trigger an error
	logger.Log(context.Background(), nil)
	assert.Error(t, capturedErr)
	assert.Contains(t, capturedErr.Error(), "audit log")
}

func TestLogger_SilentError(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	// No error handler — should not panic
	logger := NewLogger(store)
	logger.Log(context.Background(), nil) // no panic
}

// --- API tests ---

func TestAPI_ListEvents(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionToolExecuted).WithUser("u1")))

	api := NewAPI(store)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/audit/events?user_id=u1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, float64(2), resp["count"])
}

func TestAPI_ListEvents_WithFilters(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLoginFailed).WithUser("u1")))

	api := NewAPI(store)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/audit/events?action=auth.login&limit=10", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, float64(1), resp["count"])
}

func TestAPI_ListEvents_Empty(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	api := NewAPI(store)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/audit/events", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	events := resp["events"].([]interface{})
	assert.Len(t, events, 0)
}

func TestAPI_CountEvents(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithUser("u2")))

	api := NewAPI(store)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/audit/events/count?user_id=u1", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, float64(2), resp["count"])
}

func TestAPI_TimeFilter(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC))))

	api := NewAPI(store)
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("GET", "/api/v1/audit/events?since=2025-03-01T00:00:00Z", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, float64(1), resp["count"])
}

// --- Middleware tests ---

func TestMiddleware_WrapHandler(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	logger := NewLogger(store)
	mw := NewMiddleware(logger, func(r *http.Request) string {
		return "test-user"
	})

	handler := mw.WrapHandler(ActionLogin, ResourceUser, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("User-Agent", "TestAgent/1.0")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	events, err := store.Query(context.Background(), QueryFilter{UserID: "test-user"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, ActionLogin, events[0].Action)
	assert.Equal(t, "TestAgent/1.0", events[0].UserAgent)
	assert.Equal(t, StatusSuccess, events[0].Status)
}

func TestMiddleware_FailureCapture(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	logger := NewLogger(store)
	mw := NewMiddleware(logger, nil)

	handler := mw.WrapHandler(ActionLogin, ResourceUser, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	events, err := store.Query(context.Background(), QueryFilter{})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, StatusFailure, events[0].Status)
}

func TestMiddleware_XForwardedFor(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	logger := NewLogger(store)
	mw := NewMiddleware(logger, nil)

	handler := mw.WrapHandler(ActionLogin, ResourceUser, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 70.41.3.18")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	events, err := store.Query(context.Background(), QueryFilter{})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "203.0.113.50", events[0].IPAddress)
}

func TestMiddleware_XRealIP(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)

	logger := NewLogger(store)
	mw := NewMiddleware(logger, nil)

	handler := mw.WrapHandler(ActionLogin, ResourceUser, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "/login", nil)
	req.Header.Set("X-Real-IP", "198.51.100.23")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	events, err := store.Query(context.Background(), QueryFilter{})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "198.51.100.23", events[0].IPAddress)
}

// --- ExtractIP tests ---

func TestExtractIP_RemoteAddr(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	assert.Equal(t, "192.168.1.1", extractIP(req))
}

func TestExtractIP_RemoteAddrNoPort(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.1"
	assert.Equal(t, "192.168.1.1", extractIP(req))
}

// --- Close test ---

func TestSQLiteAuditStore_Close(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	assert.NoError(t, store.Close())
}

// --- Query by resource ID ---

func TestQuery_ByResourceID(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	require.NoError(t, store.Log(ctx, NewEvent(ActionAgentCreated).WithResource(ResourceAgent, "agent-1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionAgentUpdated).WithResource(ResourceAgent, "agent-2")))

	events, err := store.Query(ctx, QueryFilter{ResourceID: "agent-1"})
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, ActionAgentCreated, events[0].Action)
}

// --- Ordering test ---

func TestQuery_OrderByTimestampDesc(t *testing.T) {
	db := openTestDB(t)
	store, err := NewSQLiteAuditStore(db)
	require.NoError(t, err)
	ctx := context.Background()

	t1 := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)

	// Insert in non-chronological order
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t2).WithDetail("idx", "2")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t1).WithDetail("idx", "1")))
	require.NoError(t, store.Log(ctx, NewEvent(ActionLogin).WithTimestamp(t3).WithDetail("idx", "3")))

	events, err := store.Query(ctx, QueryFilter{})
	require.NoError(t, err)
	require.Len(t, events, 3)
	assert.Equal(t, "3", events[0].Detail["idx"]) // most recent first
	assert.Equal(t, "2", events[1].Detail["idx"])
	assert.Equal(t, "1", events[2].Detail["idx"])
}
