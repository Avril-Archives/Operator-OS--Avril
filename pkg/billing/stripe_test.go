package billing

import (
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
)

// ---------- StripeClient tests ----------

func TestNewStripeClient_EmptyKey(t *testing.T) {
	_, err := NewStripeClient(StripeConfig{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "secret key is required")
}

func TestNewStripeClient_Success(t *testing.T) {
	c, err := NewStripeClient(StripeConfig{SecretKey: "sk_test_123"})
	require.NoError(t, err)
	assert.Equal(t, "https://api.stripe.com", c.baseURL)
}

func TestNewStripeClient_CustomBaseURL(t *testing.T) {
	c, err := NewStripeClient(StripeConfig{
		SecretKey: "sk_test_123",
		BaseURL:   "http://localhost:12111/",
	})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:12111", c.baseURL) // trailing slash stripped
}

func TestStripeClient_CreateCustomer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/customers", r.URL.Path)
		assert.Equal(t, http.MethodPost, r.Method)

		// Check auth.
		user, _, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.Equal(t, "sk_test_123", user)

		// Check form params.
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "test@example.com", r.FormValue("email"))
		assert.Equal(t, "user-42", r.FormValue("metadata[user_id]"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeCustomer{ID: "cus_abc", Email: "test@example.com"})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	cust, err := c.CreateCustomer("test@example.com", "user-42")
	require.NoError(t, err)
	assert.Equal(t, "cus_abc", cust.ID)
	assert.Equal(t, "test@example.com", cust.Email)
}

func TestStripeClient_GetCustomer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/customers/cus_abc", r.URL.Path)
		assert.Equal(t, http.MethodGet, r.Method)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeCustomer{ID: "cus_abc", Email: "test@example.com"})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	cust, err := c.GetCustomer("cus_abc")
	require.NoError(t, err)
	assert.Equal(t, "cus_abc", cust.ID)
}

func TestStripeClient_CreateCheckoutSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/checkout/sessions", r.URL.Path)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "subscription", r.FormValue("mode"))
		assert.Equal(t, "price_123", r.FormValue("line_items[0][price]"))
		assert.Equal(t, "1", r.FormValue("line_items[0][quantity]"))
		assert.Equal(t, "https://example.com/success", r.FormValue("success_url"))
		assert.Equal(t, "cus_abc", r.FormValue("customer"))
		assert.Equal(t, "user-42", r.FormValue("client_reference_id"))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeCheckoutSession{
			ID:  "cs_123",
			URL: "https://checkout.stripe.com/cs_123",
		})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	sess, err := c.CreateCheckoutSession(CheckoutParams{
		CustomerID:  "cus_abc",
		PriceID:     "price_123",
		SuccessURL:  "https://example.com/success",
		CancelURL:   "https://example.com/cancel",
		ClientRefID: "user-42",
	})
	require.NoError(t, err)
	assert.Equal(t, "cs_123", sess.ID)
	assert.Contains(t, sess.URL, "checkout.stripe.com")
}

func TestStripeClient_CreateCheckoutSession_WithTrial(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "14", r.FormValue("subscription_data[trial_period_days]"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeCheckoutSession{ID: "cs_trial"})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	sess, err := c.CreateCheckoutSession(CheckoutParams{
		PriceID:    "price_123",
		SuccessURL: "https://example.com/success",
		CancelURL:  "https://example.com/cancel",
		TrialDays:  14,
	})
	require.NoError(t, err)
	assert.Equal(t, "cs_trial", sess.ID)
}

func TestStripeClient_GetSubscription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/subscriptions/sub_123", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeSubscription{
			ID:         "sub_123",
			CustomerID: "cus_abc",
			Status:     "active",
		})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	sub, err := c.GetSubscription("sub_123")
	require.NoError(t, err)
	assert.Equal(t, "sub_123", sub.ID)
	assert.Equal(t, "active", sub.Status)
}

func TestStripeClient_CancelSubscription(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "true", r.FormValue("cancel_at_period_end"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeSubscription{
			ID:                "sub_123",
			CancelAtPeriodEnd: true,
		})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	sub, err := c.CancelSubscription("sub_123")
	require.NoError(t, err)
	assert.True(t, sub.CancelAtPeriodEnd)
}

func TestStripeClient_CancelSubscriptionImmediately(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/v1/subscriptions/sub_123", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	err := c.CancelSubscriptionImmediately("sub_123")
	require.NoError(t, err)
}

func TestStripeClient_CreateBillingPortalSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/billing_portal/sessions", r.URL.Path)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "cus_abc", r.FormValue("customer"))
		assert.Equal(t, "https://example.com/account", r.FormValue("return_url"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeBillingPortalSession{
			ID:  "bps_123",
			URL: "https://billing.stripe.com/bps_123",
		})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	sess, err := c.CreateBillingPortalSession("cus_abc", "https://example.com/account")
	require.NoError(t, err)
	assert.Equal(t, "bps_123", sess.ID)
	assert.Contains(t, sess.URL, "billing.stripe.com")
}

func TestStripeClient_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"type":    "invalid_request_error",
				"code":    "parameter_missing",
				"message": "Missing required param: email.",
			},
		})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	_, err := c.CreateCustomer("", "user-1")
	require.Error(t, err)
	var stripeErr *StripeError
	require.ErrorAs(t, err, &stripeErr)
	assert.Equal(t, "parameter_missing", stripeErr.Code)
}

func TestStripeClient_StripeVersionHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2024-12-18.acacia", r.Header.Get("Stripe-Version"))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(StripeCustomer{ID: "cus_x"})
	}))
	defer srv.Close()

	c, _ := NewStripeClient(StripeConfig{SecretKey: "sk_test_123", BaseURL: srv.URL})
	_, _ = c.GetCustomer("cus_x")
}

// ---------- Webhook signature verification tests ----------

func signPayload(payload string, secret string, ts int64) string {
	signed := fmt.Sprintf("%d.%s", ts, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("t=%d,v1=%s", ts, sig)
}

func TestVerifyWebhookSignature_Valid(t *testing.T) {
	secret := "whsec_test123"
	payload := `{"id":"evt_1","type":"test","data":{"object":{}}}`
	ts := time.Now().Unix()
	sig := signPayload(payload, secret, ts)

	event, err := VerifyWebhookSignature([]byte(payload), sig, secret, 300)
	require.NoError(t, err)
	assert.Equal(t, "evt_1", event.ID)
	assert.Equal(t, "test", event.Type)
}

func TestVerifyWebhookSignature_MissingHeader(t *testing.T) {
	_, err := VerifyWebhookSignature([]byte("{}"), "", "secret", 300)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing Stripe-Signature")
}

func TestVerifyWebhookSignature_InvalidFormat(t *testing.T) {
	_, err := VerifyWebhookSignature([]byte("{}"), "invalid", "secret", 300)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid Stripe-Signature format")
}

func TestVerifyWebhookSignature_WrongSecret(t *testing.T) {
	payload := `{"id":"evt_1","type":"test","data":{"object":{}}}`
	ts := time.Now().Unix()
	sig := signPayload(payload, "wrong_secret", ts)

	_, err := VerifyWebhookSignature([]byte(payload), sig, "correct_secret", 300)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestVerifyWebhookSignature_Expired(t *testing.T) {
	secret := "whsec_test123"
	payload := `{"id":"evt_1","type":"test","data":{"object":{}}}`
	ts := time.Now().Add(-10 * time.Minute).Unix() // 10 minutes old
	sig := signPayload(payload, secret, ts)

	_, err := VerifyWebhookSignature([]byte(payload), sig, secret, 300)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "timestamp too old")
}

func TestVerifyWebhookSignature_NoTolerance(t *testing.T) {
	secret := "whsec_test123"
	payload := `{"id":"evt_1","type":"test","data":{"object":{}}}`
	ts := time.Now().Add(-1 * time.Hour).Unix()
	sig := signPayload(payload, secret, ts)

	// tolerance=0 means no check.
	event, err := VerifyWebhookSignature([]byte(payload), sig, secret, 0)
	require.NoError(t, err)
	assert.Equal(t, "evt_1", event.ID)
}

func TestVerifyWebhookSignature_MultipleV1(t *testing.T) {
	secret := "whsec_test123"
	payload := `{"id":"evt_1","type":"test","data":{"object":{}}}`
	ts := time.Now().Unix()

	// First sig is wrong, second is correct.
	signed := fmt.Sprintf("%d.%s", ts, payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	correctSig := hex.EncodeToString(mac.Sum(nil))

	header := fmt.Sprintf("t=%d,v1=deadbeef,v1=%s", ts, correctSig)

	event, err := VerifyWebhookSignature([]byte(payload), header, secret, 300)
	require.NoError(t, err)
	assert.Equal(t, "evt_1", event.ID)
}

func TestVerifyWebhookSignature_BadTimestamp(t *testing.T) {
	_, err := VerifyWebhookSignature([]byte("{}"), "t=notanumber,v1=abc", "secret", 300)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid timestamp")
}

// ---------- PlanPriceMap tests ----------

func TestPlanPriceMap_SetAndGet(t *testing.T) {
	m := DefaultPlanPriceMap()
	m.SetPrice(PlanStarter, IntervalMonthly, "price_starter_monthly")
	m.SetPrice(PlanStarter, IntervalYearly, "price_starter_yearly")
	m.SetPrice(PlanPro, IntervalMonthly, "price_pro_monthly")

	assert.Equal(t, "price_starter_monthly", m.GetPrice(PlanStarter, IntervalMonthly))
	assert.Equal(t, "price_starter_yearly", m.GetPrice(PlanStarter, IntervalYearly))
	assert.Equal(t, "price_pro_monthly", m.GetPrice(PlanPro, IntervalMonthly))
	assert.Equal(t, "", m.GetPrice(PlanFree, IntervalMonthly))
	assert.Equal(t, "", m.GetPrice(PlanPro, IntervalNone))
}

func TestPlanPriceMap_PlanForPrice(t *testing.T) {
	m := DefaultPlanPriceMap()
	m.SetPrice(PlanStarter, IntervalMonthly, "price_starter_monthly")
	m.SetPrice(PlanPro, IntervalYearly, "price_pro_yearly")

	plan, interval, ok := m.PlanForPrice("price_starter_monthly")
	assert.True(t, ok)
	assert.Equal(t, PlanStarter, plan)
	assert.Equal(t, IntervalMonthly, interval)

	plan, interval, ok = m.PlanForPrice("price_pro_yearly")
	assert.True(t, ok)
	assert.Equal(t, PlanPro, plan)
	assert.Equal(t, IntervalYearly, interval)

	_, _, ok = m.PlanForPrice("price_unknown")
	assert.False(t, ok)
}

// ---------- mapStripeStatus tests ----------

func TestMapStripeStatus(t *testing.T) {
	tests := []struct {
		input    string
		expected SubscriptionStatus
	}{
		{"active", SubStatusActive},
		{"trialing", SubStatusTrialing},
		{"past_due", SubStatusPastDue},
		{"canceled", SubStatusCanceled},
		{"unpaid", SubStatusCanceled},
		{"paused", SubStatusPaused},
		{"incomplete_expired", SubStatusExpired},
		{"unknown", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, mapStripeStatus(tt.input))
		})
	}
}

// ---------- StripeError tests ----------

func TestStripeError_ErrorString(t *testing.T) {
	e := &StripeError{
		Type:    "invalid_request_error",
		Code:    "missing_param",
		Message: "Missing required param: email.",
	}
	assert.Contains(t, e.Error(), "Missing required param")
	assert.Contains(t, e.Error(), "missing_param")
}
