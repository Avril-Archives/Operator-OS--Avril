package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
	"github.com/operatoronline/Operator-OS/pkg/users"
)

// API provides HTTP handlers for OAuth 2.0 flows.
type API struct {
	service *Service
}

// NewAPI creates a new OAuth API handler.
func NewAPI(service *Service) (*API, error) {
	if service == nil {
		return nil, fmt.Errorf("service is required")
	}
	return &API{service: service}, nil
}

// RegisterRoutes registers OAuth API routes on the given mux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/oauth/providers", a.handleListProviders)
	mux.HandleFunc("POST /api/v1/oauth/authorize", a.handleAuthorize)
	mux.HandleFunc("GET /api/v1/oauth/callback", a.handleCallback)
	mux.HandleFunc("POST /api/v1/oauth/refresh", a.handleRefresh)
}

// handleListProviders returns available OAuth providers.
func (a *API) handleListProviders(w http.ResponseWriter, r *http.Request) {
	providers := a.service.GetRegistry().List()

	type providerInfo struct {
		ID     string   `json:"id"`
		Name   string   `json:"name"`
		Scopes []string `json:"scopes"`
	}

	result := make([]providerInfo, 0, len(providers))
	for _, p := range providers {
		result = append(result, providerInfo{
			ID:     p.ID,
			Name:   p.Name,
			Scopes: p.Scopes,
		})
	}

	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"providers": result})
}

// handleAuthorize initiates an OAuth flow for the authenticated user.
func (a *API) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	userID := users.UserIDFromContext(r.Context())
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req struct {
		Provider      string   `json:"provider"`
		Scopes        []string `json:"scopes"`
		RedirectAfter string   `json:"redirect_after"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.Provider == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_provider", "Provider is required")
		return
	}

	result, err := a.service.StartFlow(userID, req.Provider, req.Scopes, req.RedirectAfter)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			apiutil.WriteError(w, http.StatusNotFound, "provider_not_found", fmt.Sprintf("Provider %q is not configured", req.Provider))
			return
		}
		apiutil.WriteError(w, http.StatusInternalServerError, "flow_start_failed", err.Error())
		return
	}

	apiutil.WriteJSON(w, http.StatusOK, result)
}

// handleCallback processes the OAuth provider callback.
func (a *API) handleCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errParam := r.URL.Query().Get("error")

	if errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		if errDesc == "" {
			errDesc = errParam
		}
		apiutil.WriteError(w, http.StatusBadRequest, "provider_error", errDesc)
		return
	}

	if state == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_state", "State parameter is required")
		return
	}

	if code == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_code", "Code parameter is required")
		return
	}

	tokenResp, err := a.service.HandleCallback(state, code)
	if err != nil {
		status := http.StatusInternalServerError
		errorCode := "callback_failed"
		if strings.Contains(err.Error(), "invalid or unknown") ||
			strings.Contains(err.Error(), "expired") ||
			strings.Contains(err.Error(), "already used") {
			status = http.StatusBadRequest
			errorCode = "invalid_state"
		}
		apiutil.WriteError(w, status, errorCode, err.Error())
		return
	}

	// Return tokens (in production, you'd store these in the vault
	// and redirect the user, but the API layer handles that).
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  tokenResp.AccessToken,
		"refresh_token": tokenResp.RefreshToken,
		"token_type":    tokenResp.TokenType,
		"expires_in":    tokenResp.ExpiresIn,
		"scope":         tokenResp.Scope,
		"provider":      tokenResp.ProviderID,
		"user_id":       tokenResp.UserID,
	})
}

// handleRefresh exchanges a refresh token for a new access token.
func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	userID := users.UserIDFromContext(r.Context())
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	var req struct {
		Provider     string `json:"provider"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.Provider == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_provider", "Provider is required")
		return
	}
	if req.RefreshToken == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_refresh_token", "Refresh token is required")
		return
	}

	tokenResp, err := a.service.RefreshToken(req.Provider, req.RefreshToken)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			apiutil.WriteError(w, http.StatusNotFound, "provider_not_found", err.Error())
			return
		}
		apiutil.WriteError(w, http.StatusBadGateway, "refresh_failed", err.Error())
		return
	}

	tokenResp.UserID = userID

	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"access_token":  tokenResp.AccessToken,
		"refresh_token": tokenResp.RefreshToken,
		"token_type":    tokenResp.TokenType,
		"expires_in":    tokenResp.ExpiresIn,
		"scope":         tokenResp.Scope,
		"provider":      tokenResp.ProviderID,
	})
}
