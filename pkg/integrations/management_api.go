package integrations

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/oauth"
)

// ManagementAPI provides full integration lifecycle management endpoints.
// It orchestrates the integration registry, user integration store, OAuth service,
// credential vault, and token refresh manager to provide connect, disconnect,
// status, enable, disable, and reconnect operations.
type ManagementAPI struct {
	registry       *IntegrationRegistry
	store          UserIntegrationStore
	oauthService   *oauth.Service
	vault          oauth.VaultStore
	refreshManager *oauth.TokenRefreshManager
}

// ManagementAPIConfig holds dependencies for the management API.
type ManagementAPIConfig struct {
	Registry       *IntegrationRegistry
	Store          UserIntegrationStore
	OAuthService   *oauth.Service
	Vault          oauth.VaultStore
	RefreshManager *oauth.TokenRefreshManager
}

// NewManagementAPI creates a new integration management API handler.
func NewManagementAPI(cfg ManagementAPIConfig) *ManagementAPI {
	return &ManagementAPI{
		registry:       cfg.Registry,
		store:          cfg.Store,
		oauthService:   cfg.OAuthService,
		vault:          cfg.Vault,
		refreshManager: cfg.RefreshManager,
	}
}

// RegisterRoutes registers the management API routes on the given mux.
func (m *ManagementAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/manage/integrations/connect", m.handleConnect)
	mux.HandleFunc("/api/v1/manage/integrations/disconnect", m.handleDisconnect)
	mux.HandleFunc("/api/v1/manage/integrations/status", m.handleListStatus)
	mux.HandleFunc("/api/v1/manage/integrations/", m.handleIntegrationAction)
}

// IntegrationStatus represents the full status of a user's integration.
type IntegrationStatus struct {
	IntegrationID   string             `json:"integration_id"`
	IntegrationName string             `json:"integration_name"`
	Category        string             `json:"category"`
	AuthType        string             `json:"auth_type"`
	Status          string             `json:"status"`
	TokenStatus     *TokenStatus       `json:"token_status,omitempty"`
	RefreshStatus   *oauth.RefreshStatus `json:"refresh_status,omitempty"`
	Config          map[string]string  `json:"config,omitempty"`
	Scopes          []string           `json:"scopes,omitempty"`
	ErrorMessage    string             `json:"error_message,omitempty"`
	LastUsedAt      *time.Time         `json:"last_used_at,omitempty"`
	ConnectedAt     time.Time          `json:"connected_at"`
}

// TokenStatus represents OAuth token health.
type TokenStatus struct {
	HasAccessToken  bool       `json:"has_access_token"`
	HasRefreshToken bool       `json:"has_refresh_token"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	IsExpired       bool       `json:"is_expired"`
	NeedsRefresh    bool       `json:"needs_refresh"`
	TokenStatus     string     `json:"token_status"` // active, expired, revoked
}

// ConnectRequest represents a request to connect an integration.
type ConnectRequest struct {
	IntegrationID string            `json:"integration_id"`
	Config        map[string]string `json:"config,omitempty"`
	Scopes        []string          `json:"scopes,omitempty"`
	RedirectAfter string            `json:"redirect_after,omitempty"`
	// For API key integrations:
	APIKey string `json:"api_key,omitempty"`
}

// ConnectResponse represents the result of a connect request.
type ConnectResponse struct {
	IntegrationID string `json:"integration_id"`
	Status        string `json:"status"`
	// OAuth flow — redirect to this URL:
	AuthURL string `json:"auth_url,omitempty"`
	// API key — immediately active:
	Message string `json:"message,omitempty"`
}

// handleConnect starts the connection flow for an integration.
// POST /api/v1/manage/integrations/connect
func (m *ManagementAPI) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "POST only"))
		return
	}
	userID := userIDFromRequest(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("unauthorized", "Authentication required"))
		return
	}
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("not_configured", "Integration store not configured"))
		return
	}

	var req ConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid_json", "Invalid request body"))
		return
	}
	if req.IntegrationID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("missing_integration_id", "integration_id is required"))
		return
	}

	// Check if integration exists in the registry.
	integ := m.registry.Get(req.IntegrationID)
	if integ == nil {
		writeJSON(w, http.StatusNotFound, errorResp("integration_not_found", "Integration not found in registry"))
		return
	}

	// Check if already connected.
	existing, _ := m.store.Get(userID, req.IntegrationID)
	if existing != nil && (existing.Status == UserIntegrationActive || existing.Status == UserIntegrationPending) {
		writeJSON(w, http.StatusConflict, errorResp("already_connected", "Integration is already connected"))
		return
	}

	switch integ.AuthType {
	case "oauth2":
		m.connectOAuth(w, userID, integ, req, existing)
	case "api_key":
		m.connectAPIKey(w, userID, integ, req, existing)
	case "none":
		m.connectNoAuth(w, userID, integ, req, existing)
	default:
		writeJSON(w, http.StatusBadRequest, errorResp("unsupported_auth", "Unsupported auth type: "+integ.AuthType))
	}
}

func (m *ManagementAPI) connectOAuth(w http.ResponseWriter, userID string, integ *Integration, req ConnectRequest, existing *UserIntegration) {
	if m.oauthService == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("oauth_not_configured", "OAuth service not configured"))
		return
	}

	// Create or reuse user integration record.
	if existing == nil {
		ui := &UserIntegration{
			UserID:        userID,
			IntegrationID: integ.ID,
			Status:        UserIntegrationPending,
			Config:        req.Config,
			Scopes:        req.Scopes,
		}
		if err := m.store.Create(ui); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to create integration record"))
			return
		}
	} else {
		// Reactivate a previously disconnected integration.
		if err := m.store.UpdateStatus(userID, integ.ID, UserIntegrationPending, ""); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to update integration status"))
			return
		}
	}

	// Start the OAuth flow.
	result, err := m.oauthService.StartFlow(userID, integ.ID, req.Scopes, req.RedirectAfter)
	if err != nil {
		// Mark as failed.
		_ = m.store.UpdateStatus(userID, integ.ID, UserIntegrationFailed, err.Error())
		writeJSON(w, http.StatusBadGateway, errorResp("oauth_error", "Failed to start OAuth flow: "+err.Error()))
		return
	}

	writeJSON(w, http.StatusOK, ConnectResponse{
		IntegrationID: integ.ID,
		Status:        UserIntegrationPending,
		AuthURL:       result.AuthURL,
	})
}

func (m *ManagementAPI) connectAPIKey(w http.ResponseWriter, userID string, integ *Integration, req ConnectRequest, existing *UserIntegration) {
	if req.APIKey == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("missing_api_key", "api_key is required for API key integrations"))
		return
	}

	// Store the API key in the vault if available.
	if m.vault != nil {
		cred := &oauth.VaultCredential{
			UserID:      userID,
			ProviderID:  integ.ID,
			AccessToken: req.APIKey,
			TokenType:   "api_key",
			Label:       integ.Name,
			Status:      oauth.CredentialStatusActive,
		}
		if err := m.vault.Store(cred); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to store API key"))
			return
		}
	}

	// Create or update the user integration record.
	if existing == nil {
		ui := &UserIntegration{
			UserID:        userID,
			IntegrationID: integ.ID,
			Status:        UserIntegrationActive,
			Config:        req.Config,
			Scopes:        req.Scopes,
		}
		if err := m.store.Create(ui); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to create integration record"))
			return
		}
	} else {
		if err := m.store.UpdateStatus(userID, integ.ID, UserIntegrationActive, ""); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to update integration status"))
			return
		}
	}

	writeJSON(w, http.StatusOK, ConnectResponse{
		IntegrationID: integ.ID,
		Status:        UserIntegrationActive,
		Message:       "API key stored successfully",
	})
}

func (m *ManagementAPI) connectNoAuth(w http.ResponseWriter, userID string, integ *Integration, req ConnectRequest, existing *UserIntegration) {
	if existing == nil {
		ui := &UserIntegration{
			UserID:        userID,
			IntegrationID: integ.ID,
			Status:        UserIntegrationActive,
			Config:        req.Config,
		}
		if err := m.store.Create(ui); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to create integration record"))
			return
		}
	} else {
		if err := m.store.UpdateStatus(userID, integ.ID, UserIntegrationActive, ""); err != nil {
			writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to update integration status"))
			return
		}
	}

	writeJSON(w, http.StatusOK, ConnectResponse{
		IntegrationID: integ.ID,
		Status:        UserIntegrationActive,
		Message:       "Integration connected",
	})
}

// handleDisconnect disconnects an integration, revoking tokens and cleaning up.
// POST /api/v1/manage/integrations/disconnect
func (m *ManagementAPI) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "POST only"))
		return
	}
	userID := userIDFromRequest(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("unauthorized", "Authentication required"))
		return
	}
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("not_configured", "Integration store not configured"))
		return
	}

	var req struct {
		IntegrationID string `json:"integration_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid_json", "Invalid request body"))
		return
	}
	if req.IntegrationID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("missing_integration_id", "integration_id is required"))
		return
	}

	// Check that the user integration exists.
	_, err := m.store.Get(userID, req.IntegrationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, errorResp("not_found", "Integration not connected"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	// Revoke tokens in the vault.
	if m.vault != nil {
		_ = m.vault.Revoke(userID, req.IntegrationID)
	}

	// Reset refresh retries.
	if m.refreshManager != nil {
		m.refreshManager.ResetRetries(userID, req.IntegrationID)
	}

	// Delete the user integration record.
	if err := m.store.Delete(userID, req.IntegrationID); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to delete integration"))
		return
	}

	// Clean up vault credential.
	if m.vault != nil {
		_ = m.vault.Delete(userID, req.IntegrationID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"integration_id": req.IntegrationID,
		"disconnected":   true,
	})
}

// handleListStatus returns the status of all user integrations with token health info.
// GET /api/v1/manage/integrations/status
func (m *ManagementAPI) handleListStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "GET only"))
		return
	}
	userID := userIDFromRequest(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("unauthorized", "Authentication required"))
		return
	}
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("not_configured", "Integration store not configured"))
		return
	}

	statusFilter := r.URL.Query().Get("status")
	userIntegrations, err := m.store.ListByUser(userID, statusFilter)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	statuses := make([]IntegrationStatus, 0, len(userIntegrations))
	for _, ui := range userIntegrations {
		status := m.buildIntegrationStatus(userID, ui)
		statuses = append(statuses, status)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"integrations": statuses,
		"count":        len(statuses),
	})
}

// handleIntegrationAction routes per-integration actions.
// GET  /api/v1/manage/integrations/{id}/status
// POST /api/v1/manage/integrations/{id}/enable
// POST /api/v1/manage/integrations/{id}/disable
// POST /api/v1/manage/integrations/{id}/reconnect
// PUT  /api/v1/manage/integrations/{id}/config
func (m *ManagementAPI) handleIntegrationAction(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromRequest(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("unauthorized", "Authentication required"))
		return
	}
	if m.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("not_configured", "Integration store not configured"))
		return
	}

	// Parse: /api/v1/manage/integrations/{id}/{action}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/manage/integrations/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid_path", "Expected /api/v1/manage/integrations/{id}/{action}"))
		return
	}
	integrationID := parts[0]
	action := parts[1]

	switch action {
	case "status":
		if r.Method != http.MethodGet {
			writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "GET only"))
			return
		}
		m.handleSingleStatus(w, userID, integrationID)
	case "enable":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "POST only"))
			return
		}
		m.handleEnable(w, userID, integrationID)
	case "disable":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "POST only"))
			return
		}
		m.handleDisable(w, userID, integrationID)
	case "reconnect":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "POST only"))
			return
		}
		m.handleReconnect(w, r, userID, integrationID)
	case "config":
		if r.Method != http.MethodPut {
			writeJSON(w, http.StatusMethodNotAllowed, errorResp("method_not_allowed", "PUT only"))
			return
		}
		m.handleUpdateConfig(w, r, userID, integrationID)
	default:
		writeJSON(w, http.StatusNotFound, errorResp("unknown_action", "Unknown action: "+action))
	}
}

// handleSingleStatus returns the status of a single user integration.
func (m *ManagementAPI) handleSingleStatus(w http.ResponseWriter, userID, integrationID string) {
	ui, err := m.store.Get(userID, integrationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, errorResp("not_found", "Integration not connected"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	status := m.buildIntegrationStatus(userID, ui)
	writeJSON(w, http.StatusOK, status)
}

// handleEnable re-enables a disabled integration.
func (m *ManagementAPI) handleEnable(w http.ResponseWriter, userID, integrationID string) {
	ui, err := m.store.Get(userID, integrationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, errorResp("not_found", "Integration not connected"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	if ui.Status == UserIntegrationActive {
		writeJSON(w, http.StatusConflict, errorResp("already_active", "Integration is already active"))
		return
	}
	if ui.Status != UserIntegrationDisabled {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid_state", "Can only enable disabled integrations, current status: "+ui.Status))
		return
	}

	if err := m.store.UpdateStatus(userID, integrationID, UserIntegrationActive, ""); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to enable integration"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"integration_id": integrationID,
		"status":         UserIntegrationActive,
		"message":        "Integration enabled",
	})
}

// handleDisable disables an integration without disconnecting (preserves tokens).
func (m *ManagementAPI) handleDisable(w http.ResponseWriter, userID, integrationID string) {
	ui, err := m.store.Get(userID, integrationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, errorResp("not_found", "Integration not connected"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	if ui.Status == UserIntegrationDisabled {
		writeJSON(w, http.StatusConflict, errorResp("already_disabled", "Integration is already disabled"))
		return
	}
	if ui.Status != UserIntegrationActive {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid_state", "Can only disable active integrations, current status: "+ui.Status))
		return
	}

	if err := m.store.UpdateStatus(userID, integrationID, UserIntegrationDisabled, ""); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to disable integration"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"integration_id": integrationID,
		"status":         UserIntegrationDisabled,
		"message":        "Integration disabled",
	})
}

// handleReconnect re-initiates the OAuth flow for a failed or revoked integration.
func (m *ManagementAPI) handleReconnect(w http.ResponseWriter, r *http.Request, userID, integrationID string) {
	ui, err := m.store.Get(userID, integrationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, errorResp("not_found", "Integration not connected"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	integ := m.registry.Get(integrationID)
	if integ == nil {
		writeJSON(w, http.StatusNotFound, errorResp("integration_not_found", "Integration not found in registry"))
		return
	}

	if integ.AuthType != "oauth2" {
		writeJSON(w, http.StatusBadRequest, errorResp("not_oauth", "Reconnect is only available for OAuth integrations"))
		return
	}

	if m.oauthService == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorResp("oauth_not_configured", "OAuth service not configured"))
		return
	}

	// Parse optional body for redirect and scopes.
	var req struct {
		Scopes        []string `json:"scopes,omitempty"`
		RedirectAfter string   `json:"redirect_after,omitempty"`
	}
	// Ignore decode errors — body is optional.
	_ = json.NewDecoder(r.Body).Decode(&req)

	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = ui.Scopes
	}

	// Reset status to pending.
	if err := m.store.UpdateStatus(userID, integrationID, UserIntegrationPending, ""); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to update status"))
		return
	}

	// Reset refresh retries.
	if m.refreshManager != nil {
		m.refreshManager.ResetRetries(userID, integrationID)
	}

	// Start new OAuth flow.
	result, flowErr := m.oauthService.StartFlow(userID, integrationID, scopes, req.RedirectAfter)
	if flowErr != nil {
		_ = m.store.UpdateStatus(userID, integrationID, UserIntegrationFailed, flowErr.Error())
		writeJSON(w, http.StatusBadGateway, errorResp("oauth_error", "Failed to start OAuth flow: "+flowErr.Error()))
		return
	}

	writeJSON(w, http.StatusOK, ConnectResponse{
		IntegrationID: integrationID,
		Status:        UserIntegrationPending,
		AuthURL:       result.AuthURL,
	})
}

// handleUpdateConfig updates the configuration for a user integration.
func (m *ManagementAPI) handleUpdateConfig(w http.ResponseWriter, r *http.Request, userID, integrationID string) {
	ui, err := m.store.Get(userID, integrationID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeJSON(w, http.StatusNotFound, errorResp("not_found", "Integration not connected"))
			return
		}
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", err.Error()))
		return
	}

	var req struct {
		Config map[string]string `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid_json", "Invalid request body"))
		return
	}
	if req.Config == nil {
		writeJSON(w, http.StatusBadRequest, errorResp("missing_config", "config is required"))
		return
	}

	// Merge config.
	if ui.Config == nil {
		ui.Config = make(map[string]string)
	}
	for k, v := range req.Config {
		ui.Config[k] = v
	}

	if err := m.store.Update(ui); err != nil {
		writeJSON(w, http.StatusInternalServerError, errorResp("internal", "Failed to update config"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"integration_id": integrationID,
		"config":         ui.Config,
		"message":        "Configuration updated",
	})
}

// buildIntegrationStatus builds a full status view for a user integration.
func (m *ManagementAPI) buildIntegrationStatus(userID string, ui *UserIntegration) IntegrationStatus {
	status := IntegrationStatus{
		IntegrationID: ui.IntegrationID,
		Status:        ui.Status,
		Config:        ui.Config,
		Scopes:        ui.Scopes,
		ErrorMessage:  ui.ErrorMessage,
		LastUsedAt:    ui.LastUsedAt,
		ConnectedAt:   ui.CreatedAt,
	}

	// Enrich with registry info.
	if integ := m.registry.Get(ui.IntegrationID); integ != nil {
		status.IntegrationName = integ.Name
		status.Category = integ.Category
		status.AuthType = integ.AuthType
	}

	// Enrich with token status from vault.
	if m.vault != nil {
		cred, err := m.vault.Get(userID, ui.IntegrationID)
		if err == nil && cred != nil {
			ts := &TokenStatus{
				HasAccessToken:  cred.AccessToken != "",
				HasRefreshToken: cred.RefreshToken != "",
				TokenStatus:     cred.Status,
				IsExpired:       cred.IsExpired(),
				NeedsRefresh:    cred.NeedsRefresh(),
			}
			if !cred.ExpiresAt.IsZero() {
				ts.ExpiresAt = &cred.ExpiresAt
			}
			status.TokenStatus = ts
		}
	}

	// Enrich with refresh status.
	if m.refreshManager != nil {
		rs := m.refreshManager.GetRefreshStatus(userID, ui.IntegrationID)
		if rs != nil {
			status.RefreshStatus = rs
		}
	}

	return status
}
