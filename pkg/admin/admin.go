// Package admin provides administrative API endpoints for Operator OS.
//
// It includes user management (list, get, update status/role, delete),
// platform statistics, and configuration queries. All endpoints require
// admin role authentication via AdminMiddleware.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/audit"
	"github.com/operatoronline/Operator-OS/pkg/users"
)

// API provides HTTP handlers for admin management endpoints.
type API struct {
	userStore  users.UserStore
	auditStore audit.AuditStore
}

// NewAPI creates a new admin API with the required stores.
func NewAPI(userStore users.UserStore, auditStore audit.AuditStore) *API {
	return &API{
		userStore:  userStore,
		auditStore: auditStore,
	}
}

// AdminMiddleware returns an HTTP middleware that checks the authenticated
// user has the admin role. Must be used after AuthMiddleware.
func AdminMiddleware(userStore users.UserStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := users.UserIDFromContext(r.Context())
			if userID == "" {
				writeError(w, http.StatusUnauthorized, "unauthorized", "Authentication required")
				return
			}

			user, err := userStore.GetByID(userID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "unauthorized", "User not found")
				return
			}

			if user.Role != users.RoleAdmin {
				writeError(w, http.StatusForbidden, "forbidden", "Admin access required")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RegisterRoutes registers admin API endpoints on the given ServeMux.
// Both authMiddleware (JWT) and adminMiddleware (role check) are applied.
func (a *API) RegisterRoutes(mux *http.ServeMux, authMiddleware, adminMiddleware func(http.Handler) http.Handler) {
	wrap := func(fn http.HandlerFunc) http.Handler {
		return authMiddleware(adminMiddleware(fn))
	}

	// User management
	mux.Handle("GET /api/v1/admin/users", wrap(a.handleListUsers))
	mux.Handle("GET /api/v1/admin/users/{id}", wrap(a.handleGetUser))
	mux.Handle("PUT /api/v1/admin/users/{id}", wrap(a.handleUpdateUser))
	mux.Handle("DELETE /api/v1/admin/users/{id}", wrap(a.handleDeleteUser))
	mux.Handle("POST /api/v1/admin/users/{id}/suspend", wrap(a.handleSuspendUser))
	mux.Handle("POST /api/v1/admin/users/{id}/activate", wrap(a.handleActivateUser))
	mux.Handle("POST /api/v1/admin/users/{id}/role", wrap(a.handleSetRole))

	// Platform stats
	mux.Handle("GET /api/v1/admin/stats", wrap(a.handleStats))

	// Audit log access (admin-scoped)
	mux.Handle("GET /api/v1/admin/audit", wrap(a.handleAuditEvents))
}

// --- Request/Response Types ---

// AdminUserResponse is the JSON representation of a user for admin endpoints.
// Unlike the public registration response, it includes role and all fields.
type AdminUserResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name"`
	Role          string `json:"role"`
	Status        string `json:"status"`
	EmailVerified bool   `json:"email_verified"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
}

// AdminUserListResponse wraps a paginated list of users.
type AdminUserListResponse struct {
	Users  []*AdminUserResponse `json:"users"`
	Total  int64                `json:"total"`
	Limit  int                  `json:"limit"`
	Offset int                  `json:"offset"`
}

// UpdateUserRequest is the JSON body for admin user updates.
type UpdateUserRequest struct {
	DisplayName *string `json:"display_name,omitempty"`
	Role        *string `json:"role,omitempty"`
	Status      *string `json:"status,omitempty"`
}

// SetRoleRequest is the JSON body for setting a user's role.
type SetRoleRequest struct {
	Role string `json:"role"`
}

// StatsResponse contains platform-level statistics.
type StatsResponse struct {
	Users       UserStats  `json:"users"`
	RetrievedAt string     `json:"retrieved_at"`
}

// UserStats holds user-related platform statistics.
type UserStats struct {
	Total             int64 `json:"total"`
	Active            int64 `json:"active"`
	PendingVerification int64 `json:"pending_verification"`
	Suspended         int64 `json:"suspended"`
}

// ErrorResponse is a standard error JSON response.
type ErrorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// --- Handlers ---

func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	limit, offset := parsePagination(r)

	allUsers, err := a.userStore.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to list users")
		return
	}

	total := int64(len(allUsers))

	// Apply status filter if provided.
	statusFilter := r.URL.Query().Get("status")
	roleFilter := r.URL.Query().Get("role")
	if statusFilter != "" || roleFilter != "" {
		filtered := make([]*users.User, 0)
		for _, u := range allUsers {
			if statusFilter != "" && u.Status != statusFilter {
				continue
			}
			if roleFilter != "" && u.Role != roleFilter {
				continue
			}
			filtered = append(filtered, u)
		}
		allUsers = filtered
		total = int64(len(allUsers))
	}

	// Apply pagination.
	start := offset
	if start > int(total) {
		start = int(total)
	}
	end := start + limit
	if end > int(total) {
		end = int(total)
	}
	page := allUsers[start:end]

	resp := AdminUserListResponse{
		Users:  make([]*AdminUserResponse, len(page)),
		Total:  total,
		Limit:  limit,
		Offset: offset,
	}
	for i, u := range page {
		resp.Users[i] = userToAdminResponse(u)
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleGetUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")

	user, err := a.userStore.GetByID(userID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to retrieve user")
		return
	}

	writeJSON(w, http.StatusOK, userToAdminResponse(user))
}

func (a *API) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	adminID := users.UserIDFromContext(r.Context())

	user, err := a.userStore.GetByID(targetID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to retrieve user")
		return
	}

	var req UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.DisplayName != nil {
		user.DisplayName = strings.TrimSpace(*req.DisplayName)
	}
	if req.Role != nil {
		role := *req.Role
		if role != users.RoleUser && role != users.RoleAdmin {
			writeError(w, http.StatusBadRequest, "invalid_role", "Role must be 'user' or 'admin'")
			return
		}
		// Prevent admin from removing their own admin role.
		if targetID == adminID && role != users.RoleAdmin {
			writeError(w, http.StatusConflict, "self_demotion", "Cannot remove your own admin role")
			return
		}
		user.Role = role
	}
	if req.Status != nil {
		status := *req.Status
		if !isValidStatus(status) {
			writeError(w, http.StatusBadRequest, "invalid_status", "Invalid user status")
			return
		}
		// Prevent admin from suspending/deleting themselves.
		if targetID == adminID && (status == users.StatusSuspended || status == users.StatusDeleted) {
			writeError(w, http.StatusConflict, "self_action", "Cannot suspend or delete your own account via admin API")
			return
		}
		user.Status = status
	}

	if err := a.userStore.Update(user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to update user")
		return
	}

	a.logAuditEvent(r.Context(), adminID, audit.ActionConfigUpdated, audit.ResourceUser, targetID, nil)

	writeJSON(w, http.StatusOK, userToAdminResponse(user))
}

func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	adminID := users.UserIDFromContext(r.Context())

	// Prevent self-deletion.
	if targetID == adminID {
		writeError(w, http.StatusConflict, "self_deletion", "Cannot delete your own account via admin API")
		return
	}

	if err := a.userStore.Delete(targetID); err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to delete user")
		return
	}

	a.logAuditEvent(r.Context(), adminID, audit.ActionUserDeleted, audit.ResourceUser, targetID, nil)

	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleSuspendUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	adminID := users.UserIDFromContext(r.Context())

	if targetID == adminID {
		writeError(w, http.StatusConflict, "self_action", "Cannot suspend your own account")
		return
	}

	user, err := a.userStore.GetByID(targetID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to retrieve user")
		return
	}

	user.Status = users.StatusSuspended
	if err := a.userStore.Update(user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to suspend user")
		return
	}

	a.logAuditEvent(r.Context(), adminID, audit.ActionUserSuspended, audit.ResourceUser, targetID, nil)

	writeJSON(w, http.StatusOK, userToAdminResponse(user))
}

func (a *API) handleActivateUser(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	adminID := users.UserIDFromContext(r.Context())

	user, err := a.userStore.GetByID(targetID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to retrieve user")
		return
	}

	user.Status = users.StatusActive
	if err := a.userStore.Update(user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to activate user")
		return
	}

	a.logAuditEvent(r.Context(), adminID, audit.ActionUserActivated, audit.ResourceUser, targetID, nil)

	writeJSON(w, http.StatusOK, userToAdminResponse(user))
}

func (a *API) handleSetRole(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("id")
	adminID := users.UserIDFromContext(r.Context())

	var req SetRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.Role != users.RoleUser && req.Role != users.RoleAdmin {
		writeError(w, http.StatusBadRequest, "invalid_role", "Role must be 'user' or 'admin'")
		return
	}

	// Prevent self-demotion.
	if targetID == adminID && req.Role != users.RoleAdmin {
		writeError(w, http.StatusConflict, "self_demotion", "Cannot remove your own admin role")
		return
	}

	user, err := a.userStore.GetByID(targetID)
	if err != nil {
		if errors.Is(err, users.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "User not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to retrieve user")
		return
	}

	user.Role = req.Role
	if err := a.userStore.Update(user); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to update role")
		return
	}

	a.logAuditEvent(r.Context(), adminID, audit.ActionConfigUpdated, audit.ResourceUser, targetID,
		map[string]string{"role": req.Role})

	writeJSON(w, http.StatusOK, userToAdminResponse(user))
}

func (a *API) handleStats(w http.ResponseWriter, r *http.Request) {
	total, err := a.userStore.Count()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to get user count")
		return
	}

	allUsers, err := a.userStore.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to list users")
		return
	}

	var active, pending, suspended int64
	for _, u := range allUsers {
		switch u.Status {
		case users.StatusActive:
			active++
		case users.StatusPendingVerification:
			pending++
		case users.StatusSuspended:
			suspended++
		}
	}

	resp := StatsResponse{
		Users: UserStats{
			Total:               total,
			Active:              active,
			PendingVerification: pending,
			Suspended:           suspended,
		},
		RetrievedAt: time.Now().UTC().Format(time.RFC3339),
	}

	writeJSON(w, http.StatusOK, resp)
}

func (a *API) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if a.auditStore == nil {
		writeError(w, http.StatusInternalServerError, "audit_not_configured", "Audit logging is not configured")
		return
	}

	filter := parseAuditFilter(r)

	events, err := a.auditStore.Query(r.Context(), filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to query audit events")
		return
	}

	if events == nil {
		events = []*audit.Event{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"events": events,
		"count":  len(events),
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// --- Helpers ---

func (a *API) logAuditEvent(ctx context.Context, actorID, action, resource, resourceID string, detail map[string]string) {
	if a.auditStore == nil {
		return
	}
	evt := audit.NewEvent(action).
		WithUser(resourceID).
		WithActor(actorID).
		WithResource(resource, resourceID)
	if detail != nil {
		for k, v := range detail {
			evt = evt.WithDetail(k, v)
		}
	}
	_ = a.auditStore.Log(ctx, evt)
}

func userToAdminResponse(u *users.User) *AdminUserResponse {
	role := u.Role
	if role == "" {
		role = users.RoleUser
	}
	return &AdminUserResponse{
		ID:            u.ID,
		Email:         u.Email,
		DisplayName:   u.DisplayName,
		Role:          role,
		Status:        u.Status,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt.Format(time.RFC3339),
		UpdatedAt:     u.UpdatedAt.Format(time.RFC3339),
	}
}

func parsePagination(r *http.Request) (limit, offset int) {
	limit = 50
	offset = 0

	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
			if limit > 1000 {
				limit = 1000
			}
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

func parseAuditFilter(r *http.Request) audit.QueryFilter {
	q := r.URL.Query()
	filter := audit.QueryFilter{
		UserID:     q.Get("user_id"),
		Action:     q.Get("action"),
		Resource:   q.Get("resource"),
		ResourceID: q.Get("resource_id"),
		Status:     q.Get("status"),
	}

	if since := q.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			filter.Since = t
		}
	}
	if until := q.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			filter.Until = t
		}
	}
	if limit := q.Get("limit"); limit != "" {
		if n, err := strconv.Atoi(limit); err == nil && n > 0 {
			filter.Limit = n
		}
	}
	if offset := q.Get("offset"); offset != "" {
		if n, err := strconv.Atoi(offset); err == nil && n >= 0 {
			filter.Offset = n
		}
	}
	return filter
}

func isValidStatus(s string) bool {
	switch s {
	case users.StatusActive, users.StatusPendingVerification,
		users.StatusSuspended, users.StatusDeleted:
		return true
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: message,
		Code:  code,
	})
}
