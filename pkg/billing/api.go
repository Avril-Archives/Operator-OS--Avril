package billing

import (
	"net/http"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
)

// API provides HTTP handlers for billing plan endpoints.
type API struct {
	catalogue *Catalogue
	store     SubscriptionStore
}

// NewAPI creates a billing API with the given catalogue.
// store may be nil if subscription management is not yet enabled.
func NewAPI(catalogue *Catalogue, store SubscriptionStore) *API {
	return &API{catalogue: catalogue, store: store}
}

// RegisterRoutes registers billing routes on the given mux.
// All routes are under /api/v1/billing/.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/billing/plans", a.handleListPlans)
	mux.HandleFunc("GET /api/v1/billing/plans/{id}", a.handleGetPlan)
}

// handleListPlans returns all active plans.
func (a *API) handleListPlans(w http.ResponseWriter, r *http.Request) {
	plans := a.catalogue.ListActive()
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"plans": plans,
		"count": len(plans),
	})
}

// handleGetPlan returns a single plan by ID.
func (a *API) handleGetPlan(w http.ResponseWriter, r *http.Request) {
	id := PlanID(r.PathValue("id"))
	plan := a.catalogue.Get(id)
	if plan == nil {
		apiutil.WriteError(w, http.StatusNotFound, "not_found", "plan not found")
		return
	}
	apiutil.WriteJSON(w, http.StatusOK, plan)
}

// writeJSON is a package-level convenience wrapper for apiutil.WriteJSON.
// Used by usage_api.go, plan_change.go, webhook.go, overage.go.
func writeJSON(w http.ResponseWriter, status int, v any) {
	apiutil.WriteJSON(w, status, v)
}
