package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// StripeConfig holds the configuration for Stripe integration.
type StripeConfig struct {
	// SecretKey is the Stripe secret API key (sk_test_... or sk_live_...).
	SecretKey string
	// WebhookSecret is the Stripe webhook signing secret (whsec_...).
	WebhookSecret string
	// BaseURL overrides the Stripe API base URL (for testing). Default: https://api.stripe.com
	BaseURL string
}

// StripeClient provides methods for interacting with the Stripe REST API.
// It uses net/http directly — no external SDK dependency.
type StripeClient struct {
	secretKey  string
	baseURL    string
	httpClient *http.Client
}

// NewStripeClient creates a StripeClient from the given config.
func NewStripeClient(cfg StripeConfig) (*StripeClient, error) {
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("billing: stripe secret key is required")
	}
	base := cfg.BaseURL
	if base == "" {
		base = "https://api.stripe.com"
	}
	return &StripeClient{
		secretKey: cfg.SecretKey,
		baseURL:   strings.TrimRight(base, "/"),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// ---------- Stripe API Types ----------

// StripeCustomer represents a Stripe Customer object (subset).
type StripeCustomer struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// StripeCheckoutSession represents a Stripe Checkout Session (subset).
type StripeCheckoutSession struct {
	ID                 string `json:"id"`
	URL                string `json:"url"`
	CustomerID         string `json:"customer"`
	SubscriptionID     string `json:"subscription"`
	PaymentStatus      string `json:"payment_status"`
	Mode               string `json:"mode"`
	ClientReferenceID  string `json:"client_reference_id"`
}

// StripeSubscription represents a Stripe Subscription (subset).
type StripeSubscription struct {
	ID                 string                `json:"id"`
	CustomerID         string                `json:"customer"`
	Status             string                `json:"status"`
	CurrentPeriodStart int64                 `json:"current_period_start"`
	CurrentPeriodEnd   int64                 `json:"current_period_end"`
	CancelAtPeriodEnd  bool                  `json:"cancel_at_period_end"`
	Items              *StripeSubscriptionItems `json:"items,omitempty"`
}

// StripeSubscriptionItems wraps the items list.
type StripeSubscriptionItems struct {
	Data []StripeSubscriptionItem `json:"data"`
}

// StripeSubscriptionItem represents a single item in a subscription.
type StripeSubscriptionItem struct {
	ID    string      `json:"id"`
	Price StripePrice `json:"price"`
}

// StripePrice represents a Stripe Price (subset).
type StripePrice struct {
	ID       string `json:"id"`
	Product  string `json:"product"`
	Interval string `json:"interval,omitempty"`
}

// StripeBillingPortalSession represents a Stripe Billing Portal Session (subset).
type StripeBillingPortalSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// StripeEvent represents a Stripe webhook event.
type StripeEvent struct {
	ID      string          `json:"id"`
	Type    string          `json:"type"`
	Created int64           `json:"created"`
	Data    StripeEventData `json:"data"`
}

// StripeEventData wraps the event payload.
type StripeEventData struct {
	Object json.RawMessage `json:"object"`
}

// StripeError represents a Stripe API error response.
type StripeError struct {
	Type    string `json:"type"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *StripeError) Error() string {
	return fmt.Sprintf("stripe: %s: %s (%s)", e.Type, e.Message, e.Code)
}

// ---------- Customer ----------

// CreateCustomer creates a Stripe customer for the given user.
func (c *StripeClient) CreateCustomer(email, userID string) (*StripeCustomer, error) {
	params := url.Values{}
	params.Set("email", email)
	params.Set("metadata[user_id]", userID)

	var cust StripeCustomer
	if err := c.post("/v1/customers", params, &cust); err != nil {
		return nil, fmt.Errorf("billing: create customer: %w", err)
	}
	return &cust, nil
}

// GetCustomer retrieves a Stripe customer by ID.
func (c *StripeClient) GetCustomer(customerID string) (*StripeCustomer, error) {
	var cust StripeCustomer
	if err := c.get("/v1/customers/"+customerID, &cust); err != nil {
		return nil, fmt.Errorf("billing: get customer: %w", err)
	}
	return &cust, nil
}

// ---------- Checkout Sessions ----------

// CheckoutParams configures a checkout session.
type CheckoutParams struct {
	CustomerID      string
	PriceID         string
	SuccessURL      string
	CancelURL       string
	ClientRefID     string // maps back to our user ID
	BillingInterval BillingInterval
	TrialDays       int
}

// CreateCheckoutSession creates a Stripe Checkout Session for subscription billing.
func (c *StripeClient) CreateCheckoutSession(p CheckoutParams) (*StripeCheckoutSession, error) {
	params := url.Values{}
	params.Set("mode", "subscription")
	params.Set("success_url", p.SuccessURL)
	params.Set("cancel_url", p.CancelURL)
	params.Set("line_items[0][price]", p.PriceID)
	params.Set("line_items[0][quantity]", "1")

	if p.CustomerID != "" {
		params.Set("customer", p.CustomerID)
	}
	if p.ClientRefID != "" {
		params.Set("client_reference_id", p.ClientRefID)
	}
	if p.TrialDays > 0 {
		params.Set("subscription_data[trial_period_days]", strconv.Itoa(p.TrialDays))
	}

	var sess StripeCheckoutSession
	if err := c.post("/v1/checkout/sessions", params, &sess); err != nil {
		return nil, fmt.Errorf("billing: create checkout session: %w", err)
	}
	return &sess, nil
}

// ---------- Subscriptions ----------

// GetSubscription retrieves a Stripe subscription by ID.
func (c *StripeClient) GetSubscription(subID string) (*StripeSubscription, error) {
	var sub StripeSubscription
	if err := c.get("/v1/subscriptions/"+subID, &sub); err != nil {
		return nil, fmt.Errorf("billing: get subscription: %w", err)
	}
	return &sub, nil
}

// CancelSubscription cancels a Stripe subscription at period end.
func (c *StripeClient) CancelSubscription(subID string) (*StripeSubscription, error) {
	params := url.Values{}
	params.Set("cancel_at_period_end", "true")

	var sub StripeSubscription
	if err := c.post("/v1/subscriptions/"+subID, params, &sub); err != nil {
		return nil, fmt.Errorf("billing: cancel subscription: %w", err)
	}
	return &sub, nil
}

// CancelSubscriptionImmediately cancels a Stripe subscription immediately.
func (c *StripeClient) CancelSubscriptionImmediately(subID string) error {
	if err := c.del("/v1/subscriptions/" + subID); err != nil {
		return fmt.Errorf("billing: delete subscription: %w", err)
	}
	return nil
}

// ---------- Billing Portal ----------

// CreateBillingPortalSession creates a Stripe Billing Portal session so a
// customer can manage their subscription.
func (c *StripeClient) CreateBillingPortalSession(customerID, returnURL string) (*StripeBillingPortalSession, error) {
	params := url.Values{}
	params.Set("customer", customerID)
	params.Set("return_url", returnURL)

	var sess StripeBillingPortalSession
	if err := c.post("/v1/billing_portal/sessions", params, &sess); err != nil {
		return nil, fmt.Errorf("billing: create portal session: %w", err)
	}
	return &sess, nil
}

// ---------- HTTP helpers ----------

func (c *StripeClient) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, out)
}

func (c *StripeClient) post(path string, params url.Values, out any) error {
	body := strings.NewReader(params.Encode())
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req, out)
}

func (c *StripeClient) del(path string) error {
	req, err := http.NewRequest(http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	return c.do(req, nil)
}

func (c *StripeClient) do(req *http.Request, out any) error {
	req.SetBasicAuth(c.secretKey, "")
	req.Header.Set("Stripe-Version", "2024-12-18.acacia")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("stripe request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("stripe: read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		var apiErr struct {
			Error StripeError `json:"error"`
		}
		if json.Unmarshal(respBody, &apiErr) == nil && apiErr.Error.Message != "" {
			return &apiErr.Error
		}
		return fmt.Errorf("stripe: HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("stripe: decode response: %w", err)
		}
	}
	return nil
}

// ---------- Webhook signature verification ----------

// VerifyWebhookSignature verifies a Stripe webhook signature.
// tolerance is the max age of the event in seconds (recommended: 300).
func VerifyWebhookSignature(payload []byte, sigHeader, secret string, tolerance int64) (*StripeEvent, error) {
	if sigHeader == "" {
		return nil, fmt.Errorf("billing: missing Stripe-Signature header")
	}

	// Parse the signature header: t=TIMESTAMP,v1=SIG[,v1=SIG...]
	parts := strings.Split(sigHeader, ",")
	var timestamp string
	var signatures []string
	for _, part := range parts {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}

	if timestamp == "" || len(signatures) == 0 {
		return nil, fmt.Errorf("billing: invalid Stripe-Signature format")
	}

	// Check timestamp tolerance.
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("billing: invalid timestamp in signature: %w", err)
	}
	if tolerance > 0 {
		age := time.Now().Unix() - ts
		if age < 0 {
			age = -age
		}
		if age > tolerance {
			return nil, fmt.Errorf("billing: webhook timestamp too old (%ds)", age)
		}
	}

	// Compute expected signature: HMAC-SHA256(timestamp + "." + payload).
	signed := fmt.Sprintf("%s.%s", timestamp, string(payload))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed))
	expected := hex.EncodeToString(mac.Sum(nil))

	// Check if any v1 signature matches.
	matched := false
	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, fmt.Errorf("billing: webhook signature mismatch")
	}

	// Decode the event.
	var event StripeEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("billing: decode webhook event: %w", err)
	}
	return &event, nil
}

// ---------- Plan → Stripe Price ID mapping ----------

// PlanPriceMap maps plan IDs to Stripe price IDs for each billing interval.
type PlanPriceMap struct {
	Monthly map[PlanID]string
	Yearly  map[PlanID]string
}

// DefaultPlanPriceMap returns an empty map; operators must configure price IDs
// via environment variables or configuration.
func DefaultPlanPriceMap() *PlanPriceMap {
	return &PlanPriceMap{
		Monthly: make(map[PlanID]string),
		Yearly:  make(map[PlanID]string),
	}
}

// SetPrice sets the Stripe price ID for a plan at the given interval.
func (m *PlanPriceMap) SetPrice(plan PlanID, interval BillingInterval, priceID string) {
	switch interval {
	case IntervalMonthly:
		m.Monthly[plan] = priceID
	case IntervalYearly:
		m.Yearly[plan] = priceID
	}
}

// GetPrice returns the Stripe price ID for a plan and interval, or empty string.
func (m *PlanPriceMap) GetPrice(plan PlanID, interval BillingInterval) string {
	switch interval {
	case IntervalMonthly:
		return m.Monthly[plan]
	case IntervalYearly:
		return m.Yearly[plan]
	}
	return ""
}

// PlanForPrice looks up which plan ID + interval corresponds to a Stripe price ID.
// Returns false if not found.
func (m *PlanPriceMap) PlanForPrice(priceID string) (PlanID, BillingInterval, bool) {
	for plan, pid := range m.Monthly {
		if pid == priceID {
			return plan, IntervalMonthly, true
		}
	}
	for plan, pid := range m.Yearly {
		if pid == priceID {
			return plan, IntervalYearly, true
		}
	}
	return "", "", false
}
