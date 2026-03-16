package audit

import (
	"net/http"
	"strconv"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
)

// API provides HTTP handlers for querying audit logs.
type API struct {
	store AuditStore
}

// NewAPI creates a new audit API with the given store.
func NewAPI(store AuditStore) *API {
	return &API{store: store}
}

// RegisterRoutes registers audit log endpoints on the given ServeMux.
// These routes should be behind admin authentication middleware.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/audit/events", a.handleListEvents)
	mux.HandleFunc("GET /api/v1/audit/events/count", a.handleCountEvents)
}

// handleListEvents returns audit events matching optional query parameters.
// Query params: user_id, action, resource, resource_id, status, since, until, limit, offset
func (a *API) handleListEvents(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)

	events, err := a.store.Query(r.Context(), filter)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "failed to query audit events")
		return
	}

	if events == nil {
		events = []*Event{}
	}

	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
		"limit":  filter.Limit,
		"offset": filter.Offset,
	})
}

// handleCountEvents returns the count of audit events matching optional query parameters.
func (a *API) handleCountEvents(w http.ResponseWriter, r *http.Request) {
	filter := parseFilter(r)

	count, err := a.store.Count(r.Context(), filter)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "failed to count audit events")
		return
	}

	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"count": count,
	})
}

// parseFilter extracts query filter parameters from the request.
func parseFilter(r *http.Request) QueryFilter {
	q := r.URL.Query()
	filter := QueryFilter{
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

