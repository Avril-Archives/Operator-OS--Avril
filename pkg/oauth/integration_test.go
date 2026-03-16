package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

// --- Google OAuth Integration Tests ---

func registerGoogleProvider(t *testing.T, reg *ProviderRegistry, tokenURL string) {
	t.Helper()
	require.NoError(t, reg.Register(&Provider{
		ID:           "google",
		Name:         "Google",
		AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     tokenURL,
		ClientID:     "google-client-id.apps.googleusercontent.com",
		ClientSecret: "google-client-secret",
		RedirectURL:  "https://app.example.com/api/v1/oauth/callback",
		Scopes:       []string{"openid", "email", "profile"},
		UsePKCE:      true,
		ExtraAuthParams: map[string]string{
			"access_type": "offline",
			"prompt":      "consent",
		},
	}))
}

func TestIntegration_GoogleOAuth_FullFlow(t *testing.T) {
	// Mock Google token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.NoError(t, r.ParseForm())

		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.NotEmpty(t, r.FormValue("code"))
		assert.Equal(t, "google-client-id.apps.googleusercontent.com", r.FormValue("client_id"))
		assert.Equal(t, "google-client-secret", r.FormValue("client_secret"))
		assert.NotEmpty(t, r.FormValue("code_verifier")) // PKCE

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "ya29.google-access-token",
			"refresh_token": "1//google-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
			"scope":         "openid email profile",
			"id_token":      "eyJhbGciOiJSUzI1NiJ9.fake-id-token",
		})
	}))
	defer tokenServer.Close()

	db := testDB(t)
	store, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	reg := NewProviderRegistry()
	svc, err := NewService(ServiceConfig{
		Registry:   reg,
		StateStore: store,
	})
	require.NoError(t, err)
	api, err := NewAPI(svc)
	require.NoError(t, err)

	registerGoogleProvider(t, reg, tokenServer.URL+"/token")

	// 1. Start authorization flow.
	result, err := svc.StartFlow("user-google-1", "google", nil, "/dashboard")
	require.NoError(t, err)

	// Verify Google-specific auth params.
	assert.Contains(t, result.AuthURL, "access_type=offline")
	assert.Contains(t, result.AuthURL, "prompt=consent")
	assert.Contains(t, result.AuthURL, "code_challenge=")
	assert.Contains(t, result.AuthURL, "code_challenge_method=S256")
	assert.Contains(t, result.AuthURL, "scope=")

	// 2. Simulate callback via API handler.
	callbackReq := httptest.NewRequest("GET", "/api/v1/oauth/callback?state="+result.State+"&code=4/google-auth-code", nil)
	callbackW := httptest.NewRecorder()
	api.handleCallback(callbackW, callbackReq)

	assert.Equal(t, http.StatusOK, callbackW.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(callbackW.Body).Decode(&resp))
	assert.Equal(t, "ya29.google-access-token", resp["access_token"])
	assert.Equal(t, "1//google-refresh-token", resp["refresh_token"])
	assert.Equal(t, "google", resp["provider"])
	assert.Equal(t, "user-google-1", resp["user_id"])
}

// --- GitHub OAuth Integration Tests ---

func registerGitHubProvider(t *testing.T, reg *ProviderRegistry, tokenURL string) {
	t.Helper()
	require.NoError(t, reg.Register(&Provider{
		ID:           "github",
		Name:         "GitHub",
		AuthURL:      "https://github.com/login/oauth/authorize",
		TokenURL:     tokenURL,
		ClientID:     "github-client-id",
		ClientSecret: "github-client-secret",
		RedirectURL:  "https://app.example.com/api/v1/oauth/callback",
		Scopes:       []string{"user:email", "read:org"},
		UsePKCE:      false, // GitHub doesn't support PKCE
	}))
}

func TestIntegration_GitHubOAuth_FullFlow(t *testing.T) {
	// Mock GitHub token endpoint (returns JSON when Accept header is set).
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "POST", r.Method)
		require.NoError(t, r.ParseForm())

		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.NotEmpty(t, r.FormValue("code"))
		assert.Equal(t, "github-client-id", r.FormValue("client_id"))
		assert.Equal(t, "github-client-secret", r.FormValue("client_secret"))
		// GitHub doesn't use PKCE, so no code_verifier.
		assert.Empty(t, r.FormValue("code_verifier"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_github-access-token",
			"token_type":   "bearer",
			"scope":        "user:email,read:org",
		})
	}))
	defer tokenServer.Close()

	db := testDB(t)
	store, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	reg := NewProviderRegistry()
	svc, err := NewService(ServiceConfig{
		Registry:   reg,
		StateStore: store,
	})
	require.NoError(t, err)
	api, err := NewAPI(svc)
	require.NoError(t, err)

	registerGitHubProvider(t, reg, tokenServer.URL+"/token")

	// 1. Start flow — no PKCE.
	result, err := svc.StartFlow("user-github-1", "github", nil, "/settings")
	require.NoError(t, err)

	assert.NotContains(t, result.AuthURL, "code_challenge")
	assert.Contains(t, result.AuthURL, "client_id=github-client-id")

	// 2. Callback.
	callbackReq := httptest.NewRequest("GET", "/api/v1/oauth/callback?state="+result.State+"&code=gh-auth-code-123", nil)
	callbackW := httptest.NewRecorder()
	api.handleCallback(callbackW, callbackReq)

	assert.Equal(t, http.StatusOK, callbackW.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(callbackW.Body).Decode(&resp))
	assert.Equal(t, "gho_github-access-token", resp["access_token"])
	assert.Equal(t, "github", resp["provider"])
	assert.Equal(t, "user-github-1", resp["user_id"])
}

// TestIntegration_OAuth_TokenRefresh_GoogleRotation tests Google's token rotation.
func TestIntegration_OAuth_TokenRefresh_GoogleRotation(t *testing.T) {
	callCount := 0
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "refresh_token", r.FormValue("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "ya29.new-access-token",
			"refresh_token": "1//new-refresh-token", // Google rotates refresh tokens
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	defer refreshServer.Close()

	db := testDB(t)
	store, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	reg := NewProviderRegistry()
	svc, err := NewService(ServiceConfig{
		Registry:   reg,
		StateStore: store,
	})
	require.NoError(t, err)

	registerGoogleProvider(t, reg, refreshServer.URL+"/token")

	tokenResp, err := svc.RefreshToken("google", "1//old-refresh-token")
	require.NoError(t, err)
	assert.Equal(t, "ya29.new-access-token", tokenResp.AccessToken)
	assert.Equal(t, "1//new-refresh-token", tokenResp.RefreshToken)
	assert.Equal(t, 1, callCount)
}

// TestIntegration_OAuth_TokenRefresh_GitHubNoRotation tests GitHub's non-rotating tokens.
func TestIntegration_OAuth_TokenRefresh_GitHubNoRotation(t *testing.T) {
	refreshServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// GitHub doesn't rotate refresh tokens — no refresh_token in response.
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "gho_new-access-token",
			"token_type":   "bearer",
		})
	}))
	defer refreshServer.Close()

	db := testDB(t)
	store, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	reg := NewProviderRegistry()
	svc, err := NewService(ServiceConfig{
		Registry:   reg,
		StateStore: store,
	})
	require.NoError(t, err)

	registerGitHubProvider(t, reg, refreshServer.URL+"/token")

	tokenResp, err := svc.RefreshToken("github", "ghr_original-refresh")
	require.NoError(t, err)
	assert.Equal(t, "gho_new-access-token", tokenResp.AccessToken)
	// Original refresh token should be preserved since provider didn't send new one.
	assert.Equal(t, "ghr_original-refresh", tokenResp.RefreshToken)
}

// TestIntegration_OAuth_MultiProviderIsolation verifies users can connect to
// multiple providers simultaneously without state leakage.
func TestIntegration_OAuth_MultiProviderIsolation(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-" + r.FormValue("client_id"),
			"token_type":   "Bearer",
		})
	}))
	defer tokenServer.Close()

	db := testDB(t)
	store, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	reg := NewProviderRegistry()
	svc, err := NewService(ServiceConfig{
		Registry:   reg,
		StateStore: store,
	})
	require.NoError(t, err)

	registerGoogleProvider(t, reg, tokenServer.URL+"/token")
	registerGitHubProvider(t, reg, tokenServer.URL+"/token")

	// Same user starts flows with both providers.
	googleResult, err := svc.StartFlow("user-multi", "google", nil, "")
	require.NoError(t, err)

	githubResult, err := svc.StartFlow("user-multi", "github", nil, "")
	require.NoError(t, err)

	// States must be different.
	assert.NotEqual(t, googleResult.State, githubResult.State)

	// Complete Google callback.
	googleToken, err := svc.HandleCallback(googleResult.State, "google-code")
	require.NoError(t, err)
	assert.Equal(t, "google", googleToken.ProviderID)

	// Complete GitHub callback.
	githubToken, err := svc.HandleCallback(githubResult.State, "github-code")
	require.NoError(t, err)
	assert.Equal(t, "github", githubToken.ProviderID)

	// Both should reference the same user.
	assert.Equal(t, "user-multi", googleToken.UserID)
	assert.Equal(t, "user-multi", githubToken.UserID)
}

// TestIntegration_OAuth_AuthorizeEndpoint_WithAuth exercises the HTTP authorize
// endpoint with authenticated user context.
func TestIntegration_OAuth_AuthorizeEndpoint_WithAuth(t *testing.T) {
	db := testDB(t)
	store, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	reg := NewProviderRegistry()
	svc, err := NewService(ServiceConfig{
		Registry:   reg,
		StateStore: store,
	})
	require.NoError(t, err)
	api, err := NewAPI(svc)
	require.NoError(t, err)

	registerGoogleProvider(t, reg, "https://accounts.google.com/token")

	// Authorize with user context.
	body := `{"provider":"google","scopes":["drive.readonly"],"redirect_after":"/files"}`
	req := httptest.NewRequest("POST", "/api/v1/oauth/authorize", strings.NewReader(body))
	req = withUser(req, "user-auth-test")
	w := httptest.NewRecorder()
	api.handleAuthorize(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Contains(t, resp["auth_url"], "accounts.google.com")
	assert.NotEmpty(t, resp["state"])
	assert.Equal(t, "google", resp["provider"])
}

// TestIntegration_OAuth_ProviderError_AccessDenied tests handling of provider-side
// access denial (user clicks "Cancel" on consent screen).
func TestIntegration_OAuth_ProviderError_AccessDenied(t *testing.T) {
	api, _ := testAPI(t)

	req := httptest.NewRequest("GET",
		"/api/v1/oauth/callback?error=access_denied&error_description=The+user+denied+access",
		nil)
	w := httptest.NewRecorder()
	api.handleCallback(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]any
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "provider_error", resp["code"])
	assert.Contains(t, resp["error"].(string), "denied access")
}
