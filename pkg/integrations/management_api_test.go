package integrations

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/standardws/operator/pkg/oauth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"database/sql"

	_ "modernc.org/sqlite"
)

// mgmtAuthedRequest creates an authenticated request with body.
func mgmtAuthedRequest(method, url string, body any) *http.Request {
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, url, &b)
	r = r.WithContext(WithUserID(r.Context(), "user-1"))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// mgmtUnauthRequest creates an unauthenticated request with optional body.
func mgmtUnauthRequest(method, url string, body any) *http.Request {
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, url, &b)
	r.Header.Set("Content-Type", "application/json")
	return r
}

// --- test helpers ---

func setupManagementTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE user_integrations (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			integration_id TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'pending',
			config TEXT DEFAULT '{}',
			scopes TEXT DEFAULT '[]',
			error_message TEXT DEFAULT '',
			last_used_at TEXT,
			created_at TEXT NOT NULL,
			updated_at TEXT NOT NULL,
			UNIQUE(user_id, integration_id)
		);
		CREATE INDEX idx_ui_user ON user_integrations(user_id);
		CREATE INDEX idx_ui_status ON user_integrations(user_id, status);
	`)
	require.NoError(t, err)
	return db
}

func setupVaultTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	_, err = db.Exec(`
		CREATE TABLE credential_vault (
			id              TEXT PRIMARY KEY,
			user_id         TEXT NOT NULL,
			provider_id     TEXT NOT NULL,
			encrypted_data  BLOB NOT NULL,
			encrypted       INTEGER NOT NULL DEFAULT 1,
			label           TEXT NOT NULL DEFAULT '',
			status          TEXT NOT NULL DEFAULT 'active',
			scopes          TEXT NOT NULL DEFAULT '',
			expires_at      TEXT NOT NULL DEFAULT '',
			created_at      TEXT NOT NULL DEFAULT '',
			updated_at      TEXT NOT NULL DEFAULT '',
			UNIQUE(user_id, provider_id)
		);
		CREATE INDEX idx_cv_user ON credential_vault(user_id);
		CREATE INDEX idx_cv_provider ON credential_vault(provider_id);
		CREATE INDEX idx_cv_user_status ON credential_vault(user_id, status);
	`)
	require.NoError(t, err)
	return db
}

func testRegistry() *IntegrationRegistry {
	r := NewIntegrationRegistry()
	_ = r.Register(&Integration{
		ID:          "google-gmail",
		Name:        "Gmail",
		Category:    "email",
		Description: "Google Gmail integration",
		AuthType:    "oauth2",
		OAuth: &OAuthConfig{
			AuthorizationURL: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenURL:         "https://oauth2.googleapis.com/token",
			Scopes:           []string{"https://www.googleapis.com/auth/gmail.readonly"},
		},
		Tools:  []ToolManifest{{Name: "gmail_list", Description: "List emails"}},
		Status: "active",
	})
	_ = r.Register(&Integration{
		ID:          "weather-api",
		Name:        "Weather API",
		Category:    "data",
		Description: "Weather data API",
		AuthType:    "api_key",
		APIKeyConfig: &APIKeyConfig{
			Header: "X-API-Key",
		},
		Tools:  []ToolManifest{{Name: "weather_get", Description: "Get weather"}},
		Status: "active",
	})
	_ = r.Register(&Integration{
		ID:          "public-data",
		Name:        "Public Data",
		Category:    "data",
		Description: "Public data source",
		AuthType:    "none",
		Tools:       []ToolManifest{{Name: "public_get", Description: "Get data"}},
		Status:      "active",
	})
	return r
}

// --- mock OAuth service ---

type mockOAuthStateStore struct{}

func (m *mockOAuthStateStore) Create(state *oauth.OAuthState) error  { return nil }
func (m *mockOAuthStateStore) GetByState(s string) (*oauth.OAuthState, error) {
	return nil, nil
}
func (m *mockOAuthStateStore) MarkUsed(id string) error        { return nil }
func (m *mockOAuthStateStore) DeleteExpired() (int64, error)    { return 0, nil }
func (m *mockOAuthStateStore) Close() error                     { return nil }

func setupTestOAuthService(t *testing.T) *oauth.Service {
	t.Helper()
	reg := oauth.NewProviderRegistry()
	_ = reg.Register(&oauth.Provider{
		ID:           "google-gmail",
		Name:         "Gmail",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURL:  "http://localhost/callback",
		Scopes:       []string{"email"},
	})
	svc, err := oauth.NewService(oauth.ServiceConfig{
		Registry:   reg,
		StateStore: &mockOAuthStateStore{},
	})
	require.NoError(t, err)
	return svc
}

// --- tests ---

func TestManagementAPI_NewManagementAPI(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
	})
	assert.NotNil(t, api)
	assert.NotNil(t, api.registry)
}

func TestManagementAPI_RegisterRoutes(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
	})
	mux := http.NewServeMux()
	api.RegisterRoutes(mux)
	// Verify routes are registered by making requests.
	w := httptest.NewRecorder()
	r := mgmtUnauthRequest(http.MethodGet, "/api/v1/manage/integrations/status", nil)
	mux.ServeHTTP(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestManagementAPI_Connect_Unauthorized(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtUnauthRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "google-gmail",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestManagementAPI_Connect_NoStore(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "google-gmail",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestManagementAPI_Connect_MissingIntegrationID(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_Connect_NotFound(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "nonexistent",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestManagementAPI_Connect_AlreadyConnected(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	// Pre-create an active integration.
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "public-data",
		Status:        UserIntegrationActive,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "public-data",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestManagementAPI_Connect_OAuth_NoService(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "google-gmail",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestManagementAPI_Connect_OAuth_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	oauthSvc := setupTestOAuthService(t)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry:     testRegistry(),
		Store:        store,
		OAuthService: oauthSvc,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]any{
		"integration_id": "google-gmail",
		"scopes":         []string{"email", "profile"},
		"redirect_after": "http://localhost/done",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConnectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "google-gmail", resp.IntegrationID)
	assert.Equal(t, UserIntegrationPending, resp.Status)
	assert.NotEmpty(t, resp.AuthURL)
	assert.Contains(t, resp.AuthURL, "accounts.google.com")

	// Verify user integration record was created.
	ui, err := store.Get("user-1", "google-gmail")
	require.NoError(t, err)
	assert.Equal(t, UserIntegrationPending, ui.Status)
}

func TestManagementAPI_Connect_OAuth_Reconnect_Existing(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	oauthSvc := setupTestOAuthService(t)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry:     testRegistry(),
		Store:        store,
		OAuthService: oauthSvc,
	})

	// Pre-create a failed integration.
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationFailed,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "google-gmail",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify status was updated to pending.
	ui, err := store.Get("user-1", "google-gmail")
	require.NoError(t, err)
	assert.Equal(t, UserIntegrationPending, ui.Status)
}

func TestManagementAPI_Connect_APIKey_MissingKey(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "weather-api",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_Connect_APIKey_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	vaultDB := setupVaultTestDB(t)
	defer vaultDB.Close()
	vault, err := oauth.NewSQLiteVaultStore(vaultDB, "")
	require.NoError(t, err)

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
		Vault:    vault,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "weather-api",
		"api_key":        "sk-test-key-123",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConnectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "weather-api", resp.IntegrationID)
	assert.Equal(t, UserIntegrationActive, resp.Status)
	assert.Equal(t, "API key stored successfully", resp.Message)

	// Verify vault has the credential.
	cred, err := vault.Get("user-1", "weather-api")
	require.NoError(t, err)
	assert.Equal(t, "sk-test-key-123", cred.AccessToken)
}

func TestManagementAPI_Connect_APIKey_NoVault(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "weather-api",
		"api_key":        "sk-test-key",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	// Still creates the record.
	ui, err := store.Get("user-1", "weather-api")
	require.NoError(t, err)
	assert.Equal(t, UserIntegrationActive, ui.Status)
}

func TestManagementAPI_Connect_NoAuth_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/connect", map[string]string{
		"integration_id": "public-data",
	})
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConnectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, UserIntegrationActive, resp.Status)
	assert.Equal(t, "Integration connected", resp.Message)
}

func TestManagementAPI_Connect_MethodNotAllowed(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{Registry: testRegistry()})
	w := httptest.NewRecorder()
	r := mgmtUnauthRequest(http.MethodGet, "/api/v1/manage/integrations/connect", nil)
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestManagementAPI_Connect_InvalidJSON(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/manage/integrations/connect", bytes.NewBufferString("not json"))
	r = r.WithContext(WithUserID(r.Context(), "user-1"))
	api.handleConnect(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Disconnect tests ---

func TestManagementAPI_Disconnect_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	vaultDB := setupVaultTestDB(t)
	defer vaultDB.Close()
	vault, _ := oauth.NewSQLiteVaultStore(vaultDB, "")

	// Pre-create connected integration.
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	})
	_ = vault.Store(&oauth.VaultCredential{
		UserID:      "user-1",
		ProviderID:  "google-gmail",
		AccessToken: "access-token",
		Status:      oauth.CredentialStatusActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
		Vault:    vault,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/disconnect", map[string]string{
		"integration_id": "google-gmail",
	})
	api.handleDisconnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, true, resp["disconnected"])

	// Verify user integration is deleted.
	_, err := store.Get("user-1", "google-gmail")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Verify vault credential is deleted.
	cred, err := vault.Get("user-1", "google-gmail")
	assert.NoError(t, err)
	assert.Nil(t, cred)
}

func TestManagementAPI_Disconnect_NotFound(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/disconnect", map[string]string{
		"integration_id": "nonexistent",
	})
	api.handleDisconnect(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestManagementAPI_Disconnect_Unauthorized(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtUnauthRequest(http.MethodPost, "/api/v1/manage/integrations/disconnect", map[string]string{
		"integration_id": "google-gmail",
	})
	api.handleDisconnect(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestManagementAPI_Disconnect_MissingID(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/disconnect", map[string]string{})
	api.handleDisconnect(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_Disconnect_MethodNotAllowed(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{Registry: testRegistry()})
	w := httptest.NewRecorder()
	r := mgmtUnauthRequest(http.MethodGet, "/api/v1/manage/integrations/disconnect", nil)
	api.handleDisconnect(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// --- Status tests ---

func TestManagementAPI_ListStatus_Empty(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/status", nil)
	api.handleListStatus(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(0), resp["count"])
}

func TestManagementAPI_ListStatus_WithIntegrations(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	vaultDB := setupVaultTestDB(t)
	defer vaultDB.Close()
	vault, _ := oauth.NewSQLiteVaultStore(vaultDB, "")

	// Create two integrations.
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	})
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "public-data",
		Status:        UserIntegrationActive,
	})
	// Add vault credential for gmail.
	_ = vault.Store(&oauth.VaultCredential{
		UserID:      "user-1",
		ProviderID:  "google-gmail",
		AccessToken: "token",
		Status:      oauth.CredentialStatusActive,
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
		Vault:    vault,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/status", nil)
	api.handleListStatus(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(2), resp["count"])

	integrations := resp["integrations"].([]any)
	gmailStatus := integrations[0].(map[string]any)
	assert.Equal(t, "google-gmail", gmailStatus["integration_id"])
	assert.Equal(t, "Gmail", gmailStatus["integration_name"])
	assert.Equal(t, "email", gmailStatus["category"])
	assert.NotNil(t, gmailStatus["token_status"])
}

func TestManagementAPI_ListStatus_Unauthorized(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{Registry: testRegistry()})
	w := httptest.NewRecorder()
	r := mgmtUnauthRequest(http.MethodGet, "/api/v1/manage/integrations/status", nil)
	api.handleListStatus(w, r)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestManagementAPI_ListStatus_WithFilter(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	})
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "public-data",
		Status:        UserIntegrationDisabled,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/status?status=active", nil)
	api.handleListStatus(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(1), resp["count"])
}

// --- Single status tests ---

func TestManagementAPI_SingleStatus_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
		Scopes:        []string{"email"},
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/google-gmail/status", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp IntegrationStatus
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, "google-gmail", resp.IntegrationID)
	assert.Equal(t, "Gmail", resp.IntegrationName)
	assert.Equal(t, UserIntegrationActive, resp.Status)
}

func TestManagementAPI_SingleStatus_NotFound(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/nonexistent/status", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Enable tests ---

func TestManagementAPI_Enable_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationDisabled,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/enable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	ui, _ := store.Get("user-1", "google-gmail")
	assert.Equal(t, UserIntegrationActive, ui.Status)
}

func TestManagementAPI_Enable_AlreadyActive(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/enable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestManagementAPI_Enable_InvalidState(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationFailed,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/enable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_Enable_NotFound(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/nonexistent/enable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Disable tests ---

func TestManagementAPI_Disable_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/disable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	ui, _ := store.Get("user-1", "google-gmail")
	assert.Equal(t, UserIntegrationDisabled, ui.Status)
}

func TestManagementAPI_Disable_AlreadyDisabled(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationDisabled,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/disable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestManagementAPI_Disable_InvalidState(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationPending,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/disable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Reconnect tests ---

func TestManagementAPI_Reconnect_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	oauthSvc := setupTestOAuthService(t)

	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationFailed,
		Scopes:        []string{"email"},
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry:     testRegistry(),
		Store:        store,
		OAuthService: oauthSvc,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/reconnect", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ConnectResponse
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, UserIntegrationPending, resp.Status)
	assert.NotEmpty(t, resp.AuthURL)
}

func TestManagementAPI_Reconnect_NotOAuth(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "weather-api",
		Status:        UserIntegrationFailed,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/weather-api/reconnect", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_Reconnect_NotFound(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/nonexistent/reconnect", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestManagementAPI_Reconnect_NoOAuthService(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationFailed,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/google-gmail/reconnect", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// --- Config update tests ---

func TestManagementAPI_UpdateConfig_Success(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "weather-api",
		Status:        UserIntegrationActive,
		Config:        map[string]string{"city": "NYC"},
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPut, "/api/v1/manage/integrations/weather-api/config", map[string]any{
		"config": map[string]string{"city": "LA", "units": "imperial"},
	})
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	ui, _ := store.Get("user-1", "weather-api")
	assert.Equal(t, "LA", ui.Config["city"])
	assert.Equal(t, "imperial", ui.Config["units"])
}

func TestManagementAPI_UpdateConfig_NotFound(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPut, "/api/v1/manage/integrations/nonexistent/config", map[string]any{
		"config": map[string]string{"key": "val"},
	})
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestManagementAPI_UpdateConfig_MissingConfig(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "weather-api",
		Status:        UserIntegrationActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPut, "/api/v1/manage/integrations/weather-api/config", map[string]any{})
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_UpdateConfig_InvalidJSON(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "weather-api",
		Status:        UserIntegrationActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "/api/v1/manage/integrations/weather-api/config", bytes.NewBufferString("not json"))
	r = r.WithContext(WithUserID(r.Context(), "user-1"))
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Action routing tests ---

func TestManagementAPI_UnknownAction(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/some-id/unknown", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestManagementAPI_InvalidPath(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestManagementAPI_WrongMethod_Status(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/some-id/status", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestManagementAPI_WrongMethod_Enable(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/some-id/enable", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestManagementAPI_WrongMethod_Config(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/some-id/config", nil)
	api.handleIntegrationAction(w, r)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// --- Multi-user isolation ---

func TestManagementAPI_MultiUserIsolation(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)

	// User-1 connects an integration.
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	})
	// User-2 connects a different one.
	_ = store.Create(&UserIntegration{
		UserID:        "user-2",
		IntegrationID: "public-data",
		Status:        UserIntegrationActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	// User-1 should only see their integrations.
	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/status", nil)
	api.handleListStatus(w, r)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	assert.Equal(t, float64(1), resp["count"])

	// User-1 should not be able to see user-2's integration status.
	w2 := httptest.NewRecorder()
	r2 := mgmtAuthedRequest(http.MethodGet, "/api/v1/manage/integrations/public-data/status", nil)
	api.handleIntegrationAction(w2, r2)
	assert.Equal(t, http.StatusNotFound, w2.Code)
}

// --- Token status enrichment tests ---

func TestManagementAPI_BuildStatus_WithTokenStatus(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	vaultDB := setupVaultTestDB(t)
	defer vaultDB.Close()
	vault, _ := oauth.NewSQLiteVaultStore(vaultDB, "")

	expiry := time.Now().Add(30 * time.Minute)
	_ = vault.Store(&oauth.VaultCredential{
		UserID:       "user-1",
		ProviderID:   "google-gmail",
		AccessToken:  "access-token",
		RefreshToken: "refresh-token",
		Status:       oauth.CredentialStatusActive,
		ExpiresAt:    expiry,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
		Vault:    vault,
	})

	ui := &UserIntegration{
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	}
	status := api.buildIntegrationStatus("user-1", ui)

	assert.NotNil(t, status.TokenStatus)
	assert.True(t, status.TokenStatus.HasAccessToken)
	assert.True(t, status.TokenStatus.HasRefreshToken)
	assert.False(t, status.TokenStatus.IsExpired)
	assert.Equal(t, "active", status.TokenStatus.TokenStatus)
	assert.NotNil(t, status.TokenStatus.ExpiresAt)
}

func TestManagementAPI_BuildStatus_ExpiredToken(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	vaultDB := setupVaultTestDB(t)
	defer vaultDB.Close()
	vault, _ := oauth.NewSQLiteVaultStore(vaultDB, "")

	_ = vault.Store(&oauth.VaultCredential{
		UserID:      "user-1",
		ProviderID:  "google-gmail",
		AccessToken: "expired-token",
		Status:      oauth.CredentialStatusActive,
		ExpiresAt:   time.Now().Add(-1 * time.Hour),
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
		Vault:    vault,
	})

	ui := &UserIntegration{
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	}
	status := api.buildIntegrationStatus("user-1", ui)

	assert.NotNil(t, status.TokenStatus)
	assert.True(t, status.TokenStatus.IsExpired)
	assert.True(t, status.TokenStatus.NeedsRefresh)
}

func TestManagementAPI_BuildStatus_NoVault(t *testing.T) {
	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
	})

	ui := &UserIntegration{
		IntegrationID: "google-gmail",
		Status:        UserIntegrationActive,
	}
	status := api.buildIntegrationStatus("user-1", ui)

	assert.Nil(t, status.TokenStatus)
	assert.Equal(t, "Gmail", status.IntegrationName)
}

// --- Disconnect without vault ---

func TestManagementAPI_Disconnect_NoVault(t *testing.T) {
	db := setupManagementTestDB(t)
	defer db.Close()
	store, _ := NewSQLiteUserIntegrationStore(db)
	_ = store.Create(&UserIntegration{
		UserID:        "user-1",
		IntegrationID: "public-data",
		Status:        UserIntegrationActive,
	})

	api := NewManagementAPI(ManagementAPIConfig{
		Registry: testRegistry(),
		Store:    store,
	})

	w := httptest.NewRecorder()
	r := mgmtAuthedRequest(http.MethodPost, "/api/v1/manage/integrations/disconnect", map[string]string{
		"integration_id": "public-data",
	})
	api.handleDisconnect(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Context helpers ---

func TestManagementAPI_WithUserID_Context(t *testing.T) {
	ctx := WithUserID(context.Background(), "test-user")
	assert.Equal(t, "test-user", userIDFromContext(ctx))
}
