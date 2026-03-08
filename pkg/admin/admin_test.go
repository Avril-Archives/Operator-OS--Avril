package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/audit"
	"github.com/operatoronline/Operator-OS/pkg/users"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Test helpers ---

// setupTestAPI creates a test admin API with a fresh SQLite user store and audit store.
func setupTestAPI(t *testing.T) (*API, *users.SQLiteUserStore, *testAuditStore) {
	t.Helper()
	dbPath := t.TempDir() + "/test.db"
	store, err := users.NewSQLiteUserStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	auditSt := &testAuditStore{}
	api := NewAPI(store, auditSt)
	return api, store, auditSt
}

// createTestUser creates a user with the given email, status, and role.
func createTestUser(t *testing.T, store users.UserStore, email, status, role string) *users.User {
	t.Helper()
	hash, err := users.HashPassword("password123")
	require.NoError(t, err)
	u := &users.User{
		Email:        email,
		PasswordHash: hash,
		Status:       status,
		Role:         role,
	}
	require.NoError(t, store.Create(u))
	return u
}

// withAdminContext adds a user ID to the request context (simulating auth middleware).
func withAdminContext(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), users.ContextKeyUserID(), userID)
	return r.WithContext(ctx)
}

// testAuditStore is a minimal in-memory audit store for testing.
type testAuditStore struct {
	events []*audit.Event
}

func (s *testAuditStore) Log(_ context.Context, event *audit.Event) error {
	s.events = append(s.events, event)
	return nil
}

func (s *testAuditStore) Query(_ context.Context, filter audit.QueryFilter) ([]*audit.Event, error) {
	if filter.Limit == 0 {
		filter.Limit = 100
	}
	var result []*audit.Event
	for _, e := range s.events {
		if filter.UserID != "" && e.UserID != filter.UserID {
			continue
		}
		if filter.Action != "" && e.Action != filter.Action {
			continue
		}
		result = append(result, e)
	}
	if filter.Offset >= len(result) {
		return []*audit.Event{}, nil
	}
	end := filter.Offset + filter.Limit
	if end > len(result) {
		end = len(result)
	}
	return result[filter.Offset:end], nil
}

func (s *testAuditStore) Count(_ context.Context, filter audit.QueryFilter) (int64, error) {
	events, _ := s.Query(context.Background(), filter)
	return int64(len(events)), nil
}

func (s *testAuditStore) DeleteBefore(_ context.Context, before time.Time) (int64, error) {
	var kept []*audit.Event
	var deleted int64
	for _, e := range s.events {
		if e.Timestamp.Before(before) {
			deleted++
		} else {
			kept = append(kept, e)
		}
	}
	s.events = kept
	return deleted, nil
}

// --- Admin Middleware Tests ---

func TestAdminMiddleware_AdminAllowed(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	_ = api
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mw := AdminMiddleware(store)
	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminMiddleware_RegularUserDenied(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	_ = api
	user := createTestUser(t, store, "user@test.com", users.StatusActive, users.RoleUser)

	mw := AdminMiddleware(store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	r = withAdminContext(r, user.ID)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAdminMiddleware_NoAuth(t *testing.T) {
	_, store, _ := setupTestAPI(t)

	mw := AdminMiddleware(store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAdminMiddleware_UserNotFound(t *testing.T) {
	_, store, _ := setupTestAPI(t)

	mw := AdminMiddleware(store)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	r := httptest.NewRequest("GET", "/test", nil)
	r = withAdminContext(r, "nonexistent-id")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- List Users Tests ---

func TestListUsers_Success(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	createTestUser(t, store, "a@test.com", users.StatusActive, users.RoleUser)
	createTestUser(t, store, "b@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(3), resp.Total)
	assert.Equal(t, 3, len(resp.Users))
}

func TestListUsers_WithStatusFilter(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	createTestUser(t, store, "active@test.com", users.StatusActive, users.RoleUser)
	createTestUser(t, store, "suspended@test.com", users.StatusSuspended, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users?status=suspended", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total)
	assert.Equal(t, "suspended@test.com", resp.Users[0].Email)
}

func TestListUsers_WithRoleFilter(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	createTestUser(t, store, "user@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users?role=admin", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(1), resp.Total)
	assert.Equal(t, "admin@test.com", resp.Users[0].Email)
}

func TestListUsers_Pagination(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	for i := 0; i < 5; i++ {
		createTestUser(t, store, "user"+string(rune('a'+i))+"@test.com", users.StatusActive, users.RoleUser)
	}
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users?limit=2&offset=1", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(6), resp.Total) // 5 + admin
	assert.Equal(t, 2, len(resp.Users))
	assert.Equal(t, 2, resp.Limit)
	assert.Equal(t, 1, resp.Offset)
}

// --- Get User Tests ---

func TestGetUser_Success(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users/"+user.ID, nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, user.ID, resp.ID)
	assert.Equal(t, "target@test.com", resp.Email)
	assert.Equal(t, users.RoleUser, resp.Role)
}

func TestGetUser_NotFound(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users/nonexistent", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Update User Tests ---

func TestUpdateUser_Success(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	newName := "Updated Name"
	body, _ := json.Marshal(UpdateUserRequest{DisplayName: &newName})
	r := httptest.NewRequest("PUT", "/api/v1/admin/users/"+user.ID, bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Updated Name", resp.DisplayName)
	assert.Len(t, auditSt.events, 1)
}

func TestUpdateUser_InvalidRole(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	badRole := "superadmin"
	body, _ := json.Marshal(UpdateUserRequest{Role: &badRole})
	r := httptest.NewRequest("PUT", "/api/v1/admin/users/"+user.ID, bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdateUser_SelfDemotion(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	userRole := users.RoleUser
	body, _ := json.Marshal(UpdateUserRequest{Role: &userRole})
	r := httptest.NewRequest("PUT", "/api/v1/admin/users/"+admin.ID, bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestUpdateUser_NotFound(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	name := "test"
	body, _ := json.Marshal(UpdateUserRequest{DisplayName: &name})
	r := httptest.NewRequest("PUT", "/api/v1/admin/users/nonexistent", bytes.NewReader(body))
	r = withAdminContext(r, "admin-id")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestUpdateUser_InvalidJSON(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("PUT", "/api/v1/admin/users/"+user.ID, bytes.NewReader([]byte("invalid")))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Delete User Tests ---

func TestDeleteUser_Success(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("DELETE", "/api/v1/admin/users/"+user.ID, nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Len(t, auditSt.events, 1)
	assert.Equal(t, audit.ActionUserDeleted, auditSt.events[0].Action)
}

func TestDeleteUser_SelfDeletion(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("DELETE", "/api/v1/admin/users/"+admin.ID, nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestDeleteUser_NotFound(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("DELETE", "/api/v1/admin/users/nonexistent", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Suspend/Activate Tests ---

func TestSuspendUser_Success(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("POST", "/api/v1/admin/users/"+user.ID+"/suspend", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, users.StatusSuspended, resp.Status)
	assert.Len(t, auditSt.events, 1)
	assert.Equal(t, audit.ActionUserSuspended, auditSt.events[0].Action)
}

func TestSuspendUser_SelfSuspend(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("POST", "/api/v1/admin/users/"+admin.ID+"/suspend", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestSuspendUser_NotFound(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("POST", "/api/v1/admin/users/nonexistent/suspend", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestActivateUser_Success(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusSuspended, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("POST", "/api/v1/admin/users/"+user.ID+"/activate", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, users.StatusActive, resp.Status)
	assert.Len(t, auditSt.events, 1)
	assert.Equal(t, audit.ActionUserActivated, auditSt.events[0].Action)
}

func TestActivateUser_NotFound(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("POST", "/api/v1/admin/users/nonexistent/activate", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Set Role Tests ---

func TestSetRole_Success(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	body, _ := json.Marshal(SetRoleRequest{Role: users.RoleAdmin})
	r := httptest.NewRequest("POST", "/api/v1/admin/users/"+user.ID+"/role", bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, users.RoleAdmin, resp.Role)
	assert.Len(t, auditSt.events, 1)
}

func TestSetRole_InvalidRole(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	user := createTestUser(t, store, "target@test.com", users.StatusActive, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	body, _ := json.Marshal(SetRoleRequest{Role: "superadmin"})
	r := httptest.NewRequest("POST", "/api/v1/admin/users/"+user.ID+"/role", bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSetRole_SelfDemotion(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	body, _ := json.Marshal(SetRoleRequest{Role: users.RoleUser})
	r := httptest.NewRequest("POST", "/api/v1/admin/users/"+admin.ID+"/role", bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestSetRole_NotFound(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	body, _ := json.Marshal(SetRoleRequest{Role: users.RoleAdmin})
	r := httptest.NewRequest("POST", "/api/v1/admin/users/nonexistent/role", bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestSetRole_InvalidJSON(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("POST", "/api/v1/admin/users/some-id/role", bytes.NewReader([]byte("{")))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Stats Tests ---

func TestStats_Success(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	createTestUser(t, store, "active1@test.com", users.StatusActive, users.RoleUser)
	createTestUser(t, store, "active2@test.com", users.StatusActive, users.RoleUser)
	createTestUser(t, store, "pending@test.com", users.StatusPendingVerification, users.RoleUser)
	createTestUser(t, store, "suspended@test.com", users.StatusSuspended, users.RoleUser)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/stats", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp StatsResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(5), resp.Users.Total)
	assert.Equal(t, int64(3), resp.Users.Active) // 2 active + admin
	assert.Equal(t, int64(1), resp.Users.PendingVerification)
	assert.Equal(t, int64(1), resp.Users.Suspended)
	assert.NotEmpty(t, resp.RetrievedAt)
}

// --- Audit Events Tests ---

func TestAuditEvents_Success(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	// Add some audit events.
	auditSt.events = append(auditSt.events,
		audit.NewEvent(audit.ActionLogin).WithUser("user-1"),
		audit.NewEvent(audit.ActionRegister).WithUser("user-2"),
	)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/audit", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	events := resp["events"].([]interface{})
	assert.Equal(t, 2, len(events))
}

func TestAuditEvents_WithFilter(t *testing.T) {
	api, store, auditSt := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	auditSt.events = append(auditSt.events,
		audit.NewEvent(audit.ActionLogin).WithUser("user-1"),
		audit.NewEvent(audit.ActionRegister).WithUser("user-2"),
	)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/audit?user_id=user-1", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	events := resp["events"].([]interface{})
	assert.Equal(t, 1, len(events))
}

func TestAuditEvents_NoStore(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	store, err := users.NewSQLiteUserStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	api := NewAPI(store, nil)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/audit", nil)
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Helper: passthrough middleware ---

func passthrough(next http.Handler) http.Handler {
	return next
}

// --- User role default test ---

func TestUserRoleDefault(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	store, err := users.NewSQLiteUserStore(dbPath)
	require.NoError(t, err)
	defer store.Close()

	hash, _ := users.HashPassword("password123")
	u := &users.User{
		Email:        "test@test.com",
		PasswordHash: hash,
		Status:       users.StatusActive,
	}
	require.NoError(t, store.Create(u))

	fetched, err := store.GetByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, users.RoleUser, fetched.Role)
}

func TestUpdateUser_SelfSuspend(t *testing.T) {
	api, store, _ := setupTestAPI(t)
	admin := createTestUser(t, store, "admin@test.com", users.StatusActive, users.RoleAdmin)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	suspended := users.StatusSuspended
	body, _ := json.Marshal(UpdateUserRequest{Status: &suspended})
	r := httptest.NewRequest("PUT", "/api/v1/admin/users/"+admin.ID, bytes.NewReader(body))
	r = withAdminContext(r, admin.ID)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestListUsers_Empty(t *testing.T) {
	api, _, _ := setupTestAPI(t)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux, passthrough, passthrough)

	r := httptest.NewRequest("GET", "/api/v1/admin/users", nil)
	r = withAdminContext(r, "some-admin")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp AdminUserListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(0), resp.Total)
}
