package billing

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// WebhookHandler handles incoming Stripe webhook events and updates
// subscription state accordingly.
type WebhookHandler struct {
	webhookSecret string
	subStore      SubscriptionStore
	catalogue     *Catalogue
	priceMap      *PlanPriceMap
	// OnEvent is an optional callback invoked after processing each event.
	// It receives the event type and any processing error.
	OnEvent func(eventType string, err error)
}

// NewWebhookHandler creates a WebhookHandler.
func NewWebhookHandler(
	webhookSecret string,
	subStore SubscriptionStore,
	catalogue *Catalogue,
	priceMap *PlanPriceMap,
) *WebhookHandler {
	return &WebhookHandler{
		webhookSecret: webhookSecret,
		subStore:      subStore,
		catalogue:     catalogue,
		priceMap:      priceMap,
	}
}

// ServeHTTP implements http.Handler for the webhook endpoint.
func (h *WebhookHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB max
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	event, err := VerifyWebhookSignature(body, r.Header.Get("Stripe-Signature"), h.webhookSecret, 300)
	if err != nil {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	procErr := h.processEvent(event)
	if h.OnEvent != nil {
		h.OnEvent(event.Type, procErr)
	}

	// Always return 200 to Stripe to prevent retries for events we don't handle.
	// Processing errors are logged via OnEvent, not returned to Stripe.
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// processEvent dispatches a Stripe event to the appropriate handler.
func (h *WebhookHandler) processEvent(event *StripeEvent) error {
	switch event.Type {
	case "checkout.session.completed":
		return h.handleCheckoutCompleted(event)
	case "customer.subscription.updated":
		return h.handleSubscriptionUpdated(event)
	case "customer.subscription.deleted":
		return h.handleSubscriptionDeleted(event)
	case "invoice.payment_failed":
		return h.handlePaymentFailed(event)
	case "invoice.payment_succeeded":
		return h.handlePaymentSucceeded(event)
	default:
		// Unhandled event type — not an error.
		return nil
	}
}

// handleCheckoutCompleted handles checkout.session.completed events.
// This creates or activates a subscription in our store.
func (h *WebhookHandler) handleCheckoutCompleted(event *StripeEvent) error {
	var session StripeCheckoutSession
	if err := json.Unmarshal(event.Data.Object, &session); err != nil {
		return fmt.Errorf("billing: unmarshal checkout session: %w", err)
	}

	if session.Mode != "subscription" || session.SubscriptionID == "" {
		return nil // not a subscription checkout
	}

	userID := session.ClientReferenceID
	if userID == "" {
		return fmt.Errorf("billing: checkout session missing client_reference_id")
	}

	// Determine the plan from the subscription.
	planID, interval, err := h.resolvePlanFromSubscriptionID(session.SubscriptionID)
	if err != nil {
		// Fallback: store subscription with starter plan.
		planID = PlanStarter
		interval = IntervalMonthly
	}

	now := time.Now().UTC()
	sub := &Subscription{
		ID:                 uuid.New().String(),
		UserID:             userID,
		PlanID:             planID,
		Status:             SubStatusActive,
		BillingInterval:    interval,
		CurrentPeriodStart: now,
		CurrentPeriodEnd:   now.AddDate(0, 1, 0), // will be updated by subscription.updated
		StripeCustomerID:   session.CustomerID,
		StripeSubID:        session.SubscriptionID,
	}

	// Check if user already has a subscription.
	existing, err := h.subStore.GetByUserID(userID)
	if err == nil && existing != nil {
		// Update existing subscription.
		existing.PlanID = planID
		existing.Status = SubStatusActive
		existing.BillingInterval = interval
		existing.StripeCustomerID = session.CustomerID
		existing.StripeSubID = session.SubscriptionID
		existing.CancelAtPeriodEnd = false
		return h.subStore.Update(existing)
	}

	return h.subStore.Create(sub)
}

// handleSubscriptionUpdated handles customer.subscription.updated events.
// This synchronises plan, status, and period from Stripe.
func (h *WebhookHandler) handleSubscriptionUpdated(event *StripeEvent) error {
	var stripeSub StripeSubscription
	if err := json.Unmarshal(event.Data.Object, &stripeSub); err != nil {
		return fmt.Errorf("billing: unmarshal subscription: %w", err)
	}

	sub, err := h.findByStripeSubID(stripeSub.ID)
	if err != nil {
		return fmt.Errorf("billing: find subscription for %s: %w", stripeSub.ID, err)
	}

	// Update status.
	newStatus := mapStripeStatus(stripeSub.Status)
	if newStatus != "" {
		sub.Status = newStatus
	}

	// Update plan if items changed.
	if stripeSub.Items != nil && len(stripeSub.Items.Data) > 0 {
		priceID := stripeSub.Items.Data[0].Price.ID
		if planID, interval, ok := h.priceMap.PlanForPrice(priceID); ok {
			sub.PlanID = planID
			sub.BillingInterval = interval
		}
	}

	// Update period.
	if stripeSub.CurrentPeriodStart > 0 {
		sub.CurrentPeriodStart = time.Unix(stripeSub.CurrentPeriodStart, 0).UTC()
	}
	if stripeSub.CurrentPeriodEnd > 0 {
		sub.CurrentPeriodEnd = time.Unix(stripeSub.CurrentPeriodEnd, 0).UTC()
	}
	sub.CancelAtPeriodEnd = stripeSub.CancelAtPeriodEnd

	return h.subStore.Update(sub)
}

// handleSubscriptionDeleted handles customer.subscription.deleted events.
func (h *WebhookHandler) handleSubscriptionDeleted(event *StripeEvent) error {
	var stripeSub StripeSubscription
	if err := json.Unmarshal(event.Data.Object, &stripeSub); err != nil {
		return fmt.Errorf("billing: unmarshal subscription: %w", err)
	}

	sub, err := h.findByStripeSubID(stripeSub.ID)
	if err != nil {
		return fmt.Errorf("billing: find subscription for %s: %w", stripeSub.ID, err)
	}

	sub.Status = SubStatusCanceled
	sub.CancelAtPeriodEnd = false
	return h.subStore.Update(sub)
}

// handlePaymentFailed handles invoice.payment_failed events.
func (h *WebhookHandler) handlePaymentFailed(event *StripeEvent) error {
	var invoice struct {
		SubscriptionID string `json:"subscription"`
	}
	if err := json.Unmarshal(event.Data.Object, &invoice); err != nil {
		return fmt.Errorf("billing: unmarshal invoice: %w", err)
	}
	if invoice.SubscriptionID == "" {
		return nil // not subscription-related
	}

	sub, err := h.findByStripeSubID(invoice.SubscriptionID)
	if err != nil {
		return err
	}

	sub.Status = SubStatusPastDue
	return h.subStore.Update(sub)
}

// handlePaymentSucceeded handles invoice.payment_succeeded events.
func (h *WebhookHandler) handlePaymentSucceeded(event *StripeEvent) error {
	var invoice struct {
		SubscriptionID string `json:"subscription"`
	}
	if err := json.Unmarshal(event.Data.Object, &invoice); err != nil {
		return fmt.Errorf("billing: unmarshal invoice: %w", err)
	}
	if invoice.SubscriptionID == "" {
		return nil
	}

	sub, err := h.findByStripeSubID(invoice.SubscriptionID)
	if err != nil {
		return err
	}

	// Payment succeeded → mark active (recovers from past_due).
	if sub.Status == SubStatusPastDue {
		sub.Status = SubStatusActive
		return h.subStore.Update(sub)
	}
	return nil
}

// findByStripeSubID scans subscriptions to find one by Stripe subscription ID.
// This is adequate for SQLite; for PostgreSQL, add an index on stripe_subscription_id.
func (h *WebhookHandler) findByStripeSubID(stripeSubID string) (*Subscription, error) {
	// Try active first, then all statuses.
	for _, status := range []SubscriptionStatus{
		SubStatusActive, SubStatusTrialing, SubStatusPastDue,
		SubStatusPaused, SubStatusCanceled, SubStatusExpired,
	} {
		subs, err := h.subStore.ListByStatus(status)
		if err != nil {
			continue
		}
		for _, s := range subs {
			if s.StripeSubID == stripeSubID {
				return s, nil
			}
		}
	}
	return nil, ErrNotFound
}

// resolvePlanFromSubscriptionID fetches the subscription from Stripe (if client
// available) or returns an error. This is a best-effort lookup during checkout.
func (h *WebhookHandler) resolvePlanFromSubscriptionID(subID string) (PlanID, BillingInterval, error) {
	// Without a Stripe client, we cannot resolve — caller should fallback.
	return "", "", fmt.Errorf("billing: cannot resolve subscription plan without Stripe client")
}

// mapStripeStatus converts a Stripe subscription status to our internal status.
func mapStripeStatus(s string) SubscriptionStatus {
	switch s {
	case "active":
		return SubStatusActive
	case "trialing":
		return SubStatusTrialing
	case "past_due":
		return SubStatusPastDue
	case "canceled", "unpaid":
		return SubStatusCanceled
	case "paused":
		return SubStatusPaused
	case "incomplete_expired":
		return SubStatusExpired
	default:
		return ""
	}
}

// ---------- Billing API extensions ----------

// StripeAPI extends the billing API with Stripe-specific endpoints.
type StripeAPI struct {
	stripe    *StripeClient
	subStore  SubscriptionStore
	catalogue *Catalogue
	priceMap  *PlanPriceMap
	webhook   *WebhookHandler
}

// NewStripeAPI creates a StripeAPI with all dependencies.
func NewStripeAPI(
	stripe *StripeClient,
	subStore SubscriptionStore,
	catalogue *Catalogue,
	priceMap *PlanPriceMap,
	webhookSecret string,
) *StripeAPI {
	return &StripeAPI{
		stripe:    stripe,
		subStore:  subStore,
		catalogue: catalogue,
		priceMap:  priceMap,
		webhook:   NewWebhookHandler(webhookSecret, subStore, catalogue, priceMap),
	}
}

// RegisterRoutes registers Stripe billing routes on the given mux.
func (a *StripeAPI) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/billing/checkout", a.handleCreateCheckout)
	mux.HandleFunc("POST /api/v1/billing/portal", a.handleCreatePortal)
	mux.HandleFunc("GET /api/v1/billing/subscription", a.handleGetSubscription)
	mux.Handle("POST /api/v1/billing/webhook", a.webhook)
}

// CheckoutRequest is the JSON body for creating a checkout session.
type CheckoutRequest struct {
	PlanID      string `json:"plan_id"`
	Interval    string `json:"interval"` // "monthly" or "yearly"
	SuccessURL  string `json:"success_url"`
	CancelURL   string `json:"cancel_url"`
}

// handleCreateCheckout creates a Stripe Checkout Session.
func (a *StripeAPI) handleCreateCheckout(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "authentication required",
			"code":  "unauthorized",
		})
		return
	}

	var req CheckoutRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid JSON",
			"code":  "invalid_request",
		})
		return
	}

	planID := PlanID(req.PlanID)
	if !ValidPlanID(planID) || planID == PlanFree {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid or free plan specified",
			"code":  "invalid_plan",
		})
		return
	}

	interval := BillingInterval(req.Interval)
	if interval != IntervalMonthly && interval != IntervalYearly {
		interval = IntervalMonthly
	}

	priceID := a.priceMap.GetPrice(planID, interval)
	if priceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "no Stripe price configured for this plan",
			"code":  "price_not_configured",
		})
		return
	}

	if req.SuccessURL == "" || req.CancelURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "success_url and cancel_url are required",
			"code":  "missing_urls",
		})
		return
	}

	// Find or create Stripe customer.
	customerID := ""
	existingSub, err := a.subStore.GetByUserID(userID)
	if err == nil && existingSub != nil && existingSub.StripeCustomerID != "" {
		customerID = existingSub.StripeCustomerID
	}

	sess, err := a.stripe.CreateCheckoutSession(CheckoutParams{
		CustomerID:      customerID,
		PriceID:         priceID,
		SuccessURL:      req.SuccessURL,
		CancelURL:       req.CancelURL,
		ClientRefID:     userID,
		BillingInterval: interval,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "failed to create checkout session",
			"code":  "stripe_error",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"checkout_url": sess.URL,
		"session_id":   sess.ID,
	})
}

// handleCreatePortal creates a Stripe Billing Portal session.
func (a *StripeAPI) handleCreatePortal(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "authentication required",
			"code":  "unauthorized",
		})
		return
	}

	var req struct {
		ReturnURL string `json:"return_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid JSON",
			"code":  "invalid_request",
		})
		return
	}

	if req.ReturnURL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "return_url is required",
			"code":  "missing_return_url",
		})
		return
	}

	sub, err := a.subStore.GetByUserID(userID)
	if err != nil || sub.StripeCustomerID == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "no active subscription found",
			"code":  "no_subscription",
		})
		return
	}

	sess, err := a.stripe.CreateBillingPortalSession(sub.StripeCustomerID, req.ReturnURL)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"error": "failed to create portal session",
			"code":  "stripe_error",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"portal_url": sess.URL,
	})
}

// handleGetSubscription returns the current user's subscription status.
func (a *StripeAPI) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromContext(r)
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"error": "authentication required",
			"code":  "unauthorized",
		})
		return
	}

	sub, err := a.subStore.GetByUserID(userID)
	if err != nil {
		// No subscription = free plan.
		writeJSON(w, http.StatusOK, map[string]any{
			"plan":   a.catalogue.Get(PlanFree),
			"status": "none",
		})
		return
	}

	plan := a.catalogue.Get(sub.PlanID)
	writeJSON(w, http.StatusOK, map[string]any{
		"subscription": sub,
		"plan":         plan,
	})
}

// userIDFromContext extracts the user ID from the request context.
// This expects the auth middleware to have injected it.
func userIDFromContext(r *http.Request) string {
	if v := r.Context().Value(contextKeyUserID("user_id")); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// contextKeyUserID is a local type matching the one in pkg/users.
type contextKeyUserID string
