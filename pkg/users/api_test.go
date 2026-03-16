package users

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAPI(t *testing.T) (*API, *SQLiteUserStore) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_api.db")
	store, err := NewSQLiteUserStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	api := NewAPI(store)
	return api, store
}

func doRegister(t *testing.T, api *API, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestRegister_Success(t *testing.T) {
	api, store := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:       "user@example.com",
		Password:    "Secure@Pass1",
		DisplayName: "Test User",
	})

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp RegisterResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, "user@example.com", resp.Email)
	assert.Equal(t, "Test User", resp.DisplayName)
	assert.Equal(t, StatusPendingVerification, resp.Status)
	assert.False(t, resp.EmailVerified)

	// Verify user exists in store.
	user, err := store.GetByEmail("user@example.com")
	require.NoError(t, err)
	assert.Equal(t, resp.ID, user.ID)

	// Verify password was hashed (not stored plaintext).
	assert.NotEqual(t, "Secure@Pass1", user.PasswordHash)
	assert.NoError(t, CheckPassword(user.PasswordHash, "Secure@Pass1"))
}

func TestRegister_DuplicateEmail(t *testing.T) {
	api, _ := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:    "dupe@example.com",
		Password: "Secure@Pass1",
	})
	assert.Equal(t, http.StatusCreated, w.Code)

	w = doRegister(t, api, RegisterRequest{
		Email:    "dupe@example.com",
		Password: "Different@Pass1",
	})
	assert.Equal(t, http.StatusConflict, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "email_exists", resp.Code)
}

func TestRegister_MissingEmail(t *testing.T) {
	api, _ := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Password: "Secure@Pass1",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "missing_email", resp.Code)
}

func TestRegister_InvalidEmail(t *testing.T) {
	api, _ := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:    "not-an-email",
		Password: "Secure@Pass1",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_email", resp.Code)
}

func TestRegister_WeakPassword(t *testing.T) {
	api, _ := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:    "weak@example.com",
		Password: "short",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "weak_password", resp.Code)
}

func TestRegister_InvalidJSON(t *testing.T) {
	api, _ := newTestAPI(t)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_json", resp.Code)
}

func TestRegister_EmailCaseNormalization(t *testing.T) {
	api, store := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:    "User@EXAMPLE.COM",
		Password: "Secure@Pass1",
	})
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp RegisterResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user@example.com", resp.Email)

	// Should be findable by lowercase.
	user, err := store.GetByEmail("user@example.com")
	require.NoError(t, err)
	assert.Equal(t, resp.ID, user.ID)
}

func TestRegister_EmptyPassword(t *testing.T) {
	api, _ := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:    "empty@example.com",
		Password: "",
	})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_WhitespaceEmail(t *testing.T) {
	api, _ := newTestAPI(t)

	w := doRegister(t, api, RegisterRequest{
		Email:    "  trimmed@example.com  ",
		Password: "Secure@Pass1",
	})
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp RegisterResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "trimmed@example.com", resp.Email)
}
