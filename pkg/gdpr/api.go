package gdpr

import (
	"encoding/json"
	"net/http"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
)

// userIDFromContext extracts the user ID from the request context.
// It checks for the key used by the auth middleware.
func userIDFromContext(r *http.Request) string {
	if v := r.Context().Value(contextKeyUserID); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// contextKeyType is a private type to avoid context key collisions.
type contextKeyType string

const contextKeyUserID contextKeyType = "user_id"

// API provides HTTP handlers for GDPR compliance endpoints.
type API struct {
	service *Service
}

// NewAPI creates a new GDPR API handler.
func NewAPI(service *Service) *API {
	return &API{service: service}
}

// RegisterRoutes registers GDPR API endpoints on the given mux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/gdpr/export", a.handleExport)
	mux.HandleFunc("/api/v1/gdpr/erase", a.handleErase)
	mux.HandleFunc("/api/v1/gdpr/requests", a.handleRequests)
	mux.HandleFunc("/api/v1/gdpr/requests/", a.handleRequestByID)
	mux.HandleFunc("/api/v1/gdpr/retention", a.handleRetention)
}

// handleExport initiates a data export for the authenticated user.
func (a *API) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiutil.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	if a.service == nil {
		apiutil.WriteError(w, http.StatusServiceUnavailable, "not_configured", "GDPR service not configured")
		return
	}
	userID := userIDFromContext(r)
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	export, err := a.service.ExportUserData(r.Context(), userID, userID)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	apiutil.WriteJSON(w, http.StatusOK, export)
}

// handleErase initiates data erasure for the authenticated user.
func (a *API) handleErase(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		apiutil.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	if a.service == nil {
		apiutil.WriteError(w, http.StatusServiceUnavailable, "not_configured", "GDPR service not configured")
		return
	}
	userID := userIDFromContext(r)
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	// Parse optional confirmation
	var body struct {
		Confirm bool `json:"confirm"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	if !body.Confirm {
		apiutil.WriteError(w, http.StatusBadRequest, "confirmation_required", "Set confirm=true to proceed with data erasure. This action is irreversible.")
		return
	}

	report, err := a.service.EraseUserData(r.Context(), userID, userID)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}

	apiutil.WriteJSON(w, http.StatusOK, report)
}

// handleRequests lists the user's DSRs.
func (a *API) handleRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiutil.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	if a.service == nil {
		apiutil.WriteError(w, http.StatusServiceUnavailable, "not_configured", "GDPR service not configured")
		return
	}
	userID := userIDFromContext(r)
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	requests, err := a.service.ListUserRequests(userID)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if requests == nil {
		requests = []*DataSubjectRequest{}
	}

	apiutil.WriteJSON(w, http.StatusOK, map[string]interface{}{
		"requests": requests,
		"count":    len(requests),
	})
}

// handleRequestByID returns or cancels a specific DSR.
func (a *API) handleRequestByID(w http.ResponseWriter, r *http.Request) {
	if a.service == nil {
		apiutil.WriteError(w, http.StatusServiceUnavailable, "not_configured", "GDPR service not configured")
		return
	}
	userID := userIDFromContext(r)
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	// Extract ID from path: /api/v1/gdpr/requests/{id}
	id := r.URL.Path[len("/api/v1/gdpr/requests/"):]
	if id == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_id", "Request ID is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		req, err := a.service.GetRequest(id)
		if err != nil {
			if err == ErrRequestNotFound {
				apiutil.WriteError(w, http.StatusNotFound, "not_found", "Request not found")
				return
			}
			apiutil.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		// Ensure user can only see their own requests
		if req.UserID != userID {
			apiutil.WriteError(w, http.StatusNotFound, "not_found", "Request not found")
			return
		}
		apiutil.WriteJSON(w, http.StatusOK, req)

	case http.MethodDelete:
		// Cancel a pending request
		req, err := a.service.GetRequest(id)
		if err != nil {
			if err == ErrRequestNotFound {
				apiutil.WriteError(w, http.StatusNotFound, "not_found", "Request not found")
				return
			}
			apiutil.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		if req.UserID != userID {
			apiutil.WriteError(w, http.StatusNotFound, "not_found", "Request not found")
			return
		}
		if err := a.service.CancelRequest(id); err != nil {
			if err == ErrAlreadyProcessed {
				apiutil.WriteError(w, http.StatusConflict, "already_processed", "Request already processed")
				return
			}
			apiutil.WriteError(w, http.StatusInternalServerError, "internal", err.Error())
			return
		}
		apiutil.WriteJSON(w, http.StatusOK, map[string]string{"status": "canceled"})

	default:
		apiutil.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

// handleRetention returns the current retention policy.
func (a *API) handleRetention(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		apiutil.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
		return
	}
	if a.service == nil {
		apiutil.WriteError(w, http.StatusServiceUnavailable, "not_configured", "GDPR service not configured")
		return
	}
	userID := userIDFromContext(r)
	if userID == "" {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
		return
	}

	type retentionResponse struct {
		AuditLogDays    int `json:"audit_log_days"`
		UsageDataDays   int `json:"usage_data_days"`
		SessionDays     int `json:"session_days"`
		DeletedUserDays int `json:"deleted_user_days"`
	}

	resp := retentionResponse{
		AuditLogDays:    int(a.service.retention.AuditLogRetention.Hours() / 24),
		UsageDataDays:   int(a.service.retention.UsageDataRetention.Hours() / 24),
		SessionDays:     int(a.service.retention.SessionRetention.Hours() / 24),
		DeletedUserDays: int(a.service.retention.DeletedUserRetention.Hours() / 24),
	}

	apiutil.WriteJSON(w, http.StatusOK, resp)
}
