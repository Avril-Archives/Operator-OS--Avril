package billing

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"
)

// newTestDB creates an in-memory SQLite database with subscription store.
func newTestDB(t *testing.T) SubscriptionStore {
	t.Helper()
	db := openTestDB(t)
	store, err := NewSQLiteSubscriptionStore(db)
	require.NoError(t, err)
	return store
}

func makeWebhookRequest(t *testing.T, secret string, event StripeEvent) (*http.Request, []byte) {
	t.Helper()
	body, err := json.Marshal(event)
	require.NoError(t, err)

	ts := time.Now().Unix()
	signed := fmt.Sprintf("%d.%s", ts, string(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := hex.EncodeToString(mac.Sum(nil))
	header := fmt.Sprintf("t=%d,v1=%s", ts, sig)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/webhook", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", header)
	return req, body
}

func TestWebhookHandler_InvalidSignature(t *testing.T) {
	store := newTestDB(t)
	h := NewWebhookHandler("whsec_correct", store, NewCatalogue(nil), DefaultPlanPriceMap())

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Stripe-Signature", "t=123,v1=wrongsig")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebhookHandler_MethodNotAllowed(t *testing.T) {
	store := newTestDB(t)
	h := NewWebhookHandler("whsec_test", store, NewCatalogue(nil), DefaultPlanPriceMap())

	req := httptest.NewRequest(http.MethodGet, "/webhook", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestWebhookHandler_CheckoutCompleted(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"
	priceMap := DefaultPlanPriceMap()
	priceMap.SetPrice(PlanStarter, IntervalMonthly, "price_starter_monthly")
	h := NewWebhookHandler(secret, store, NewCatalogue(nil), priceMap)

	var processedType string
	h.OnEvent = func(eventType string, err error) {
		processedType = eventType
		assert.NoError(t, err)
	}

	session := StripeCheckoutSession{
		ID:                "cs_123",
		Mode:              "subscription",
		SubscriptionID:    "sub_stripe_1",
		CustomerID:        "cus_abc",
		ClientReferenceID: "user-42",
	}
	sessionJSON, _ := json.Marshal(session)

	event := StripeEvent{
		ID:   "evt_checkout",
		Type: "checkout.session.completed",
		Data: StripeEventData{Object: sessionJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "checkout.session.completed", processedType)

	// Verify subscription was created.
	sub, err := store.GetByUserID("user-42")
	require.NoError(t, err)
	assert.Equal(t, PlanStarter, sub.PlanID) // fallback plan
	assert.Equal(t, SubStatusActive, sub.Status)
	assert.Equal(t, "cus_abc", sub.StripeCustomerID)
	assert.Equal(t, "sub_stripe_1", sub.StripeSubID)
}

func TestWebhookHandler_CheckoutCompleted_ExistingSubscription(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"

	// Create existing subscription.
	existing := &Subscription{
		ID:               "old-sub-1",
		UserID:           "user-42",
		PlanID:           PlanFree,
		Status:           SubStatusActive,
		BillingInterval:  IntervalNone,
		StripeCustomerID: "cus_old",
	}
	require.NoError(t, store.Create(existing))

	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	session := StripeCheckoutSession{
		ID:                "cs_upgrade",
		Mode:              "subscription",
		SubscriptionID:    "sub_new",
		CustomerID:        "cus_new",
		ClientReferenceID: "user-42",
	}
	sessionJSON, _ := json.Marshal(session)
	event := StripeEvent{
		ID:   "evt_upgrade",
		Type: "checkout.session.completed",
		Data: StripeEventData{Object: sessionJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify existing subscription was updated, not duplicated.
	sub, err := store.GetByUserID("user-42")
	require.NoError(t, err)
	assert.Equal(t, "old-sub-1", sub.ID) // same ID
	assert.Equal(t, "sub_new", sub.StripeSubID)
	assert.Equal(t, "cus_new", sub.StripeCustomerID)
}

func TestWebhookHandler_CheckoutCompleted_NonSubscription(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"
	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	session := StripeCheckoutSession{
		ID:   "cs_onetime",
		Mode: "payment", // not subscription
	}
	sessionJSON, _ := json.Marshal(session)
	event := StripeEvent{
		ID:   "evt_onetime",
		Type: "checkout.session.completed",
		Data: StripeEventData{Object: sessionJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// No subscription created.
	_, err := store.GetByUserID("user-42")
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestWebhookHandler_SubscriptionUpdated(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"
	priceMap := DefaultPlanPriceMap()
	priceMap.SetPrice(PlanPro, IntervalMonthly, "price_pro_monthly")

	// Create a subscription to be updated.
	require.NoError(t, store.Create(&Subscription{
		ID:              "sub-1",
		UserID:          "user-42",
		PlanID:          PlanStarter,
		Status:          SubStatusActive,
		BillingInterval: IntervalMonthly,
		StripeSubID:     "sub_stripe_1",
	}))

	h := NewWebhookHandler(secret, store, NewCatalogue(nil), priceMap)

	periodStart := time.Now().Unix()
	periodEnd := time.Now().Add(30 * 24 * time.Hour).Unix()
	stripeSub := StripeSubscription{
		ID:                 "sub_stripe_1",
		Status:             "active",
		CurrentPeriodStart: periodStart,
		CurrentPeriodEnd:   periodEnd,
		CancelAtPeriodEnd:  true,
		Items: &StripeSubscriptionItems{
			Data: []StripeSubscriptionItem{
				{Price: StripePrice{ID: "price_pro_monthly"}},
			},
		},
	}
	subJSON, _ := json.Marshal(stripeSub)
	event := StripeEvent{
		ID:   "evt_updated",
		Type: "customer.subscription.updated",
		Data: StripeEventData{Object: subJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Verify updates.
	sub, err := store.GetByID("sub-1")
	require.NoError(t, err)
	assert.Equal(t, PlanPro, sub.PlanID)        // upgraded
	assert.True(t, sub.CancelAtPeriodEnd)         // set to cancel
	assert.Equal(t, SubStatusActive, sub.Status)
	assert.Equal(t, time.Unix(periodStart, 0).UTC(), sub.CurrentPeriodStart)
}

func TestWebhookHandler_SubscriptionDeleted(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"

	require.NoError(t, store.Create(&Subscription{
		ID:          "sub-1",
		UserID:      "user-42",
		PlanID:      PlanPro,
		Status:      SubStatusActive,
		StripeSubID: "sub_stripe_del",
	}))

	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	stripeSub := StripeSubscription{ID: "sub_stripe_del"}
	subJSON, _ := json.Marshal(stripeSub)
	event := StripeEvent{
		ID:   "evt_deleted",
		Type: "customer.subscription.deleted",
		Data: StripeEventData{Object: subJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	sub, err := store.GetByID("sub-1")
	require.NoError(t, err)
	assert.Equal(t, SubStatusCanceled, sub.Status)
}

func TestWebhookHandler_PaymentFailed(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"

	require.NoError(t, store.Create(&Subscription{
		ID:          "sub-1",
		UserID:      "user-42",
		PlanID:      PlanStarter,
		Status:      SubStatusActive,
		StripeSubID: "sub_stripe_pf",
	}))

	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	invoice := map[string]string{"subscription": "sub_stripe_pf"}
	invoiceJSON, _ := json.Marshal(invoice)
	event := StripeEvent{
		ID:   "evt_pf",
		Type: "invoice.payment_failed",
		Data: StripeEventData{Object: invoiceJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	sub, err := store.GetByID("sub-1")
	require.NoError(t, err)
	assert.Equal(t, SubStatusPastDue, sub.Status)
}

func TestWebhookHandler_PaymentSucceeded_RecoveryFromPastDue(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"

	require.NoError(t, store.Create(&Subscription{
		ID:          "sub-1",
		UserID:      "user-42",
		PlanID:      PlanStarter,
		Status:      SubStatusPastDue,
		StripeSubID: "sub_stripe_ps",
	}))

	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	invoice := map[string]string{"subscription": "sub_stripe_ps"}
	invoiceJSON, _ := json.Marshal(invoice)
	event := StripeEvent{
		ID:   "evt_ps",
		Type: "invoice.payment_succeeded",
		Data: StripeEventData{Object: invoiceJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	sub, err := store.GetByID("sub-1")
	require.NoError(t, err)
	assert.Equal(t, SubStatusActive, sub.Status) // recovered
}

func TestWebhookHandler_PaymentSucceeded_AlreadyActive(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"

	require.NoError(t, store.Create(&Subscription{
		ID:          "sub-1",
		UserID:      "user-42",
		PlanID:      PlanStarter,
		Status:      SubStatusActive,
		StripeSubID: "sub_stripe_aa",
	}))

	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	invoice := map[string]string{"subscription": "sub_stripe_aa"}
	invoiceJSON, _ := json.Marshal(invoice)
	event := StripeEvent{
		ID:   "evt_aa",
		Type: "invoice.payment_succeeded",
		Data: StripeEventData{Object: invoiceJSON},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Status unchanged.
	sub, _ := store.GetByID("sub-1")
	assert.Equal(t, SubStatusActive, sub.Status)
}

func TestWebhookHandler_PaymentFailed_NoSubscription(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"
	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	// invoice without subscription field
	invoice := map[string]string{}
	invoiceJSON, _ := json.Marshal(invoice)
	event := StripeEvent{
		ID:   "evt_noinv",
		Type: "invoice.payment_failed",
		Data: StripeEventData{Object: invoiceJSON},
	}

	var onEventErr error
	h.OnEvent = func(_ string, err error) { onEventErr = err }

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NoError(t, onEventErr) // no subscription field = skip
}

func TestWebhookHandler_UnknownEvent(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"
	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	event := StripeEvent{
		ID:   "evt_unknown",
		Type: "charge.succeeded",
		Data: StripeEventData{Object: json.RawMessage(`{}`)},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code) // always 200
}

func TestWebhookHandler_OnEventCallback(t *testing.T) {
	store := newTestDB(t)
	secret := "whsec_test"
	h := NewWebhookHandler(secret, store, NewCatalogue(nil), DefaultPlanPriceMap())

	var called bool
	h.OnEvent = func(eventType string, err error) {
		called = true
		assert.Equal(t, "test.event", eventType)
	}

	event := StripeEvent{
		ID:   "evt_cb",
		Type: "test.event",
		Data: StripeEventData{Object: json.RawMessage(`{}`)},
	}

	req, _ := makeWebhookRequest(t, secret, event)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	assert.True(t, called)
}

// ---------- StripeAPI endpoint tests ----------

func TestStripeAPI_CreateCheckout_Unauthorized(t *testing.T) {
	store := newTestDB(t)
	priceMap := DefaultPlanPriceMap()
	priceMap.SetPrice(PlanStarter, IntervalMonthly, "price_starter")

	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
		priceMap:  priceMap,
	}

	body := `{"plan_id":"starter","success_url":"https://ok","cancel_url":"https://cancel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	api.handleCreateCheckout(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStripeAPI_CreateCheckout_InvalidPlan(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
		priceMap:  DefaultPlanPriceMap(),
	}

	body := `{"plan_id":"nonexistent","success_url":"https://ok","cancel_url":"https://cancel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader([]byte(body)))
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	api.handleCreateCheckout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStripeAPI_CreateCheckout_FreePlan(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
		priceMap:  DefaultPlanPriceMap(),
	}

	body := `{"plan_id":"free","success_url":"https://ok","cancel_url":"https://cancel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader([]byte(body)))
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	api.handleCreateCheckout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStripeAPI_CreateCheckout_NoPriceConfigured(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
		priceMap:  DefaultPlanPriceMap(), // empty
	}

	body := `{"plan_id":"starter","success_url":"https://ok","cancel_url":"https://cancel"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader([]byte(body)))
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	api.handleCreateCheckout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "price_not_configured")
}

func TestStripeAPI_CreateCheckout_MissingURLs(t *testing.T) {
	store := newTestDB(t)
	priceMap := DefaultPlanPriceMap()
	priceMap.SetPrice(PlanStarter, IntervalMonthly, "price_starter")
	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
		priceMap:  priceMap,
	}

	body := `{"plan_id":"starter"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader([]byte(body)))
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	api.handleCreateCheckout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "missing_urls")
}

func TestStripeAPI_CreateCheckout_InvalidJSON(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
		priceMap:  DefaultPlanPriceMap(),
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/checkout", bytes.NewReader([]byte(`{bad`)))
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	api.handleCreateCheckout(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStripeAPI_CreatePortal_Unauthorized(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{subStore: store, catalogue: NewCatalogue(nil)}

	body := `{"return_url":"https://example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/portal", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	api.handleCreatePortal(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStripeAPI_CreatePortal_NoSubscription(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{subStore: store, catalogue: NewCatalogue(nil)}

	body := `{"return_url":"https://example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/portal", bytes.NewReader([]byte(body)))
	req = addUserContext(req, "user-no-sub")
	w := httptest.NewRecorder()
	api.handleCreatePortal(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestStripeAPI_CreatePortal_MissingReturnURL(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{subStore: store, catalogue: NewCatalogue(nil)}

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/billing/portal", bytes.NewReader([]byte(body)))
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	api.handleCreatePortal(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestStripeAPI_GetSubscription_NoSub(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/subscription", nil)
	req = addUserContext(req, "user-no-sub")
	w := httptest.NewRecorder()
	api.handleGetSubscription(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]json.RawMessage
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, string(resp["status"]), "none")
}

func TestStripeAPI_GetSubscription_WithSub(t *testing.T) {
	store := newTestDB(t)
	require.NoError(t, store.Create(&Subscription{
		ID:     "sub-1",
		UserID: "user-42",
		PlanID: PlanPro,
		Status: SubStatusActive,
	}))

	api := &StripeAPI{
		subStore:  store,
		catalogue: NewCatalogue(nil),
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/subscription", nil)
	req = addUserContext(req, "user-42")
	w := httptest.NewRecorder()
	api.handleGetSubscription(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "Pro")
}

func TestStripeAPI_GetSubscription_Unauthorized(t *testing.T) {
	store := newTestDB(t)
	api := &StripeAPI{subStore: store, catalogue: NewCatalogue(nil)}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/subscription", nil)
	w := httptest.NewRecorder()
	api.handleGetSubscription(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestStripeAPI_RegisterRoutes(t *testing.T) {
	store := newTestDB(t)
	priceMap := DefaultPlanPriceMap()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123"})
	api := NewStripeAPI(c, store, NewCatalogue(nil), priceMap, "whsec_test")

	mux := http.NewServeMux()
	api.RegisterRoutes(mux)

	// Verify routes are registered by making requests.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/billing/subscription", nil)
	req = addUserContext(req, "user-1")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code) // free plan default
}

// ---------- Helpers ----------

func addUserContext(req *http.Request, userID string) *http.Request {
	ctx := context.WithValue(req.Context(), contextKeyUserID("user_id"), userID)
	return req.WithContext(ctx)
}
