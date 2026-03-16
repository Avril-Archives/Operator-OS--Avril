package users

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAPIWithAuth(t *testing.T) (*API, *SQLiteUserStore, *TokenService) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test_login.db")
	store, err := NewSQLiteUserStore(dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { store.Close() })

	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	api := NewAPIWithAuth(store, ts)
	return api, store, ts
}

func registerUser(t *testing.T, api *API, email, password string) {
	t.Helper()
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	body, _ := json.Marshal(RegisterRequest{Email: email, Password: password})
	req := httptest.NewRequest("POST", "/api/v1/auth/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
}

func doLogin(t *testing.T, api *API, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func doRefresh(t *testing.T, api *API, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// --- Login tests ---

func TestLogin_Success(t *testing.T) {
	api, _, ts := newTestAPIWithAuth(t)
	registerUser(t, api, "login@example.com", "Secure@Pass1")

	w := doLogin(t, api, LoginRequest{
		Email:    "login@example.com",
		Password: "Secure@Pass1",
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp LoginResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, int64(0))
	assert.Equal(t, "login@example.com", resp.User.Email)
	assert.Equal(t, StatusPendingVerification, resp.User.Status)

	// Verify the access token is valid.
	claims, err := ts.ValidateAccessToken(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "login@example.com", claims.Email)
}

func TestLogin_WrongPassword(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "wrong@example.com", "Secure@Pass1")

	w := doLogin(t, api, LoginRequest{
		Email:    "wrong@example.com",
		Password: "Wrong@Pass1",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_credentials", resp.Code)
}

func TestLogin_NonexistentUser(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)

	w := doLogin(t, api, LoginRequest{
		Email:    "nobody@example.com",
		Password: "Some@Pass1",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// Same error as wrong password to prevent email enumeration.
	assert.Equal(t, "invalid_credentials", resp.Code)
}

func TestLogin_MissingEmail(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)

	w := doLogin(t, api, LoginRequest{
		Password: "Secure@Pass1",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "missing_email", resp.Code)
}

func TestLogin_MissingPassword(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "nopw@example.com", "Secure@Pass1")

	w := doLogin(t, api, LoginRequest{
		Email: "nopw@example.com",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "missing_password", resp.Code)
}

func TestLogin_InvalidJSON(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestLogin_CaseInsensitiveEmail(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "CaSe@Example.COM", "Secure@Pass1")

	w := doLogin(t, api, LoginRequest{
		Email:    "case@example.com",
		Password: "Secure@Pass1",
	})

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogin_SuspendedAccount(t *testing.T) {
	api, store, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "suspended@example.com", "Secure@Pass1")

	// Suspend the user.
	user, err := store.GetByEmail("suspended@example.com")
	require.NoError(t, err)
	user.Status = StatusSuspended
	require.NoError(t, store.Update(user))

	w := doLogin(t, api, LoginRequest{
		Email:    "suspended@example.com",
		Password: "Secure@Pass1",
	})

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "account_suspended", resp.Code)
}

func TestLogin_DeletedAccount(t *testing.T) {
	api, store, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "deleted@example.com", "Secure@Pass1")

	// Mark user as deleted.
	user, err := store.GetByEmail("deleted@example.com")
	require.NoError(t, err)
	user.Status = StatusDeleted
	require.NoError(t, store.Update(user))

	w := doLogin(t, api, LoginRequest{
		Email:    "deleted@example.com",
		Password: "Secure@Pass1",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// Same as invalid credentials to prevent enumeration.
	assert.Equal(t, "invalid_credentials", resp.Code)
}

func TestLogin_NoTokenServiceConfigured(t *testing.T) {
	api, _ := newTestAPI(t) // No token service

	w := doLogin(t, api, LoginRequest{
		Email:    "test@example.com",
		Password: "Secure@Pass1",
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "auth_not_configured", resp.Code)
}

// --- Refresh tests ---

func TestRefresh_Success(t *testing.T) {
	api, _, ts := newTestAPIWithAuth(t)
	registerUser(t, api, "refresh@example.com", "Secure@Pass1")

	// Login first.
	loginResp := doLogin(t, api, LoginRequest{
		Email:    "refresh@example.com",
		Password: "Secure@Pass1",
	})
	require.Equal(t, http.StatusOK, loginResp.Code)

	var login LoginResponse
	require.NoError(t, json.Unmarshal(loginResp.Body.Bytes(), &login))

	// Refresh.
	w := doRefresh(t, api, RefreshRequest{
		RefreshToken: login.RefreshToken,
	})

	assert.Equal(t, http.StatusOK, w.Code)

	var resp RefreshResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.Greater(t, resp.ExpiresIn, int64(0))

	// New access token should be valid.
	claims, err := ts.ValidateAccessToken(resp.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "refresh@example.com", claims.Email)
}

func TestRefresh_InvalidToken(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)

	w := doRefresh(t, api, RefreshRequest{
		RefreshToken: "invalid-refresh-token",
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_token", resp.Code)
}

func TestRefresh_AccessTokenRejected(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "noaccess@example.com", "Secure@Pass1")

	loginResp := doLogin(t, api, LoginRequest{
		Email:    "noaccess@example.com",
		Password: "Secure@Pass1",
	})
	require.Equal(t, http.StatusOK, loginResp.Code)

	var login LoginResponse
	require.NoError(t, json.Unmarshal(loginResp.Body.Bytes(), &login))

	// Try to refresh with access token (should fail).
	w := doRefresh(t, api, RefreshRequest{
		RefreshToken: login.AccessToken,
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_MissingToken(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)

	w := doRefresh(t, api, RefreshRequest{})
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp apiutil.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "missing_token", resp.Code)
}

func TestRefresh_SuspendedUser(t *testing.T) {
	api, store, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "suspend-refresh@example.com", "Secure@Pass1")

	// Login while active.
	loginResp := doLogin(t, api, LoginRequest{
		Email:    "suspend-refresh@example.com",
		Password: "Secure@Pass1",
	})
	require.Equal(t, http.StatusOK, loginResp.Code)

	var login LoginResponse
	require.NoError(t, json.Unmarshal(loginResp.Body.Bytes(), &login))

	// Suspend user after login.
	user, err := store.GetByEmail("suspend-refresh@example.com")
	require.NoError(t, err)
	user.Status = StatusSuspended
	require.NoError(t, store.Update(user))

	// Try to refresh.
	w := doRefresh(t, api, RefreshRequest{
		RefreshToken: login.RefreshToken,
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRefresh_DeletedUser(t *testing.T) {
	api, store, _ := newTestAPIWithAuth(t)
	registerUser(t, api, "delete-refresh@example.com", "Secure@Pass1")

	loginResp := doLogin(t, api, LoginRequest{
		Email:    "delete-refresh@example.com",
		Password: "Secure@Pass1",
	})
	require.Equal(t, http.StatusOK, loginResp.Code)

	var login LoginResponse
	require.NoError(t, json.Unmarshal(loginResp.Body.Bytes(), &login))

	// Delete user from store.
	user, err := store.GetByEmail("delete-refresh@example.com")
	require.NoError(t, err)
	require.NoError(t, store.Delete(user.ID))

	// Try to refresh.
	w := doRefresh(t, api, RefreshRequest{
		RefreshToken: login.RefreshToken,
	})

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRefresh_InvalidJSON(t *testing.T) {
	api, _, _ := newTestAPIWithAuth(t)

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	req := httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRefresh_NoTokenServiceConfigured(t *testing.T) {
	api, _ := newTestAPI(t) // No token service

	w := doRefresh(t, api, RefreshRequest{
		RefreshToken: "some-token",
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Full flow: register → login → access protected → refresh → access again ---

func TestFullAuthFlow(t *testing.T) {
	api, _, ts := newTestAPIWithAuth(t)

	// 1. Register.
	registerUser(t, api, "flow@example.com", "Secure@Pass1")

	// 2. Login.
	loginW := doLogin(t, api, LoginRequest{
		Email:    "flow@example.com",
		Password: "Secure@Pass1",
	})
	require.Equal(t, http.StatusOK, loginW.Code)

	var login LoginResponse
	require.NoError(t, json.Unmarshal(loginW.Body.Bytes(), &login))

	// 3. Use access token on a protected endpoint (via middleware).
	protectedHandler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid := UserIDFromContext(r.Context())
		w.Write([]byte(uid))
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+login.AccessToken)
	rec := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, login.User.ID, rec.Body.String())

	// 4. Refresh tokens.
	refreshW := doRefresh(t, api, RefreshRequest{
		RefreshToken: login.RefreshToken,
	})
	require.Equal(t, http.StatusOK, refreshW.Code)

	var refresh RefreshResponse
	require.NoError(t, json.Unmarshal(refreshW.Body.Bytes(), &refresh))

	// 5. Use new access token.
	req2 := httptest.NewRequest("GET", "/protected", nil)
	req2.Header.Set("Authorization", "Bearer "+refresh.AccessToken)
	rec2 := httptest.NewRecorder()
	protectedHandler.ServeHTTP(rec2, req2)
	assert.Equal(t, http.StatusOK, rec2.Code)
	assert.Equal(t, login.User.ID, rec2.Body.String())
}
