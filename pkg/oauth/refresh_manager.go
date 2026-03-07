package oauth

import (
	"fmt"
	"log"
	"sync"
	"time"
)

// RefreshConfig configures the token refresh manager.
type RefreshConfig struct {
	// CheckInterval is how often the manager checks for expiring tokens.
	// Default: 5 minutes.
	CheckInterval time.Duration

	// RefreshBefore is how long before expiry to trigger a refresh.
	// Default: 5 minutes (same as NeedsRefresh on VaultCredential).
	RefreshBefore time.Duration

	// MaxRetries is the maximum number of consecutive refresh attempts
	// for a single credential before giving up. Default: 3.
	MaxRetries int

	// RetryDelay is the initial delay between retry attempts.
	// Doubles on each retry (exponential backoff). Default: 30 seconds.
	RetryDelay time.Duration

	// OnRefresh is called after each successful refresh. Optional.
	OnRefresh func(userID, providerID string)

	// OnError is called on refresh failure. Optional.
	OnError func(userID, providerID string, err error)
}

// DefaultRefreshConfig returns sensible defaults for the refresh manager.
func DefaultRefreshConfig() RefreshConfig {
	return RefreshConfig{
		CheckInterval: 5 * time.Minute,
		RefreshBefore: 5 * time.Minute,
		MaxRetries:    3,
		RetryDelay:    30 * time.Second,
	}
}

// refreshState tracks retry state for a single credential.
type refreshState struct {
	retries   int
	lastError error
	nextRetry time.Time
}

// TokenRefreshManager automatically refreshes OAuth tokens before they expire.
// It prevents concurrent refreshes for the same credential using a singleflight
// pattern (per user+provider lock).
type TokenRefreshManager struct {
	vault   VaultStore
	service *Service
	config  RefreshConfig

	mu       sync.Mutex
	inflight map[string]*sync.Mutex // key: userID:providerID
	retries  map[string]*refreshState

	stopCh chan struct{}
	done   chan struct{}
	closed bool
}

// NewTokenRefreshManager creates a new token refresh manager.
func NewTokenRefreshManager(vault VaultStore, service *Service, config RefreshConfig) (*TokenRefreshManager, error) {
	if vault == nil {
		return nil, fmt.Errorf("vault store is required")
	}
	if service == nil {
		return nil, fmt.Errorf("oauth service is required")
	}

	if config.CheckInterval <= 0 {
		config.CheckInterval = DefaultRefreshConfig().CheckInterval
	}
	if config.RefreshBefore <= 0 {
		config.RefreshBefore = DefaultRefreshConfig().RefreshBefore
	}
	if config.MaxRetries <= 0 {
		config.MaxRetries = DefaultRefreshConfig().MaxRetries
	}
	if config.RetryDelay <= 0 {
		config.RetryDelay = DefaultRefreshConfig().RetryDelay
	}

	return &TokenRefreshManager{
		vault:    vault,
		service:  service,
		config:   config,
		inflight: make(map[string]*sync.Mutex),
		retries:  make(map[string]*refreshState),
		stopCh:   make(chan struct{}),
		done:     make(chan struct{}),
	}, nil
}

// Start begins the background refresh loop. Call Stop() to shut down.
func (m *TokenRefreshManager) Start() {
	go m.loop()
}

// Stop gracefully shuts down the refresh manager.
func (m *TokenRefreshManager) Stop() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	m.mu.Unlock()
	close(m.stopCh)
	<-m.done
}

// loop is the main background loop.
func (m *TokenRefreshManager) loop() {
	defer close(m.done)

	// Run an initial check immediately.
	m.checkAll()

	ticker := time.NewTicker(m.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.checkAll()
		}
	}
}

// checkAll scans all active credentials and refreshes those nearing expiry.
func (m *TokenRefreshManager) checkAll() {
	// List all active credentials from the vault. We need to check each user.
	// The vault doesn't have a "list all" method, so we use ListByUser.
	// Since we don't have a user listing here, we query active credentials
	// that are nearing expiry directly from the vault if it supports it.
	// For now, use the sweep approach via the SweepableVault interface.
	sweepable, ok := m.vault.(SweepableVault)
	if !ok {
		return
	}

	threshold := time.Now().UTC().Add(m.config.RefreshBefore)
	creds, err := sweepable.ListExpiring(threshold)
	if err != nil {
		log.Printf("token refresh: error listing expiring credentials: %v", err)
		return
	}

	for _, cred := range creds {
		m.maybeRefresh(cred)
	}
}

// maybeRefresh checks retry state and initiates a refresh if appropriate.
func (m *TokenRefreshManager) maybeRefresh(cred *VaultCredential) {
	key := credKey(cred.UserID, cred.ProviderID)

	m.mu.Lock()
	state := m.retries[key]
	if state != nil {
		if state.retries >= m.config.MaxRetries {
			m.mu.Unlock()
			return // exhausted retries
		}
		if time.Now().Before(state.nextRetry) {
			m.mu.Unlock()
			return // waiting for retry backoff
		}
	}
	m.mu.Unlock()

	// Run refresh asynchronously with singleflight protection.
	go m.refreshCredential(cred)
}

// RefreshCredential manually triggers a refresh for a specific credential.
// It is safe to call concurrently; only one refresh per credential runs at a time.
// Returns the refreshed credential, or an error if the refresh failed.
func (m *TokenRefreshManager) RefreshCredential(userID, providerID string) (*VaultCredential, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}
	if providerID == "" {
		return nil, fmt.Errorf("provider ID is required")
	}

	cred, err := m.vault.Get(userID, providerID)
	if err != nil {
		return nil, fmt.Errorf("getting credential: %w", err)
	}
	if cred == nil {
		return nil, fmt.Errorf("credential not found for %s/%s", userID, providerID)
	}
	if cred.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available for %s/%s", userID, providerID)
	}

	return m.doRefresh(cred)
}

// EnsureFresh checks if a credential needs refreshing and refreshes it if necessary.
// Returns the current (possibly refreshed) credential.
func (m *TokenRefreshManager) EnsureFresh(userID, providerID string) (*VaultCredential, error) {
	if userID == "" {
		return nil, fmt.Errorf("user ID is required")
	}
	if providerID == "" {
		return nil, fmt.Errorf("provider ID is required")
	}

	cred, err := m.vault.Get(userID, providerID)
	if err != nil {
		return nil, fmt.Errorf("getting credential: %w", err)
	}
	if cred == nil {
		return nil, fmt.Errorf("credential not found for %s/%s", userID, providerID)
	}

	if !cred.NeedsRefresh() {
		return cred, nil
	}

	if cred.RefreshToken == "" {
		return nil, fmt.Errorf("token expired and no refresh token available for %s/%s", userID, providerID)
	}

	return m.doRefresh(cred)
}

// GetRefreshStatus returns the retry state for a credential, or nil if none.
func (m *TokenRefreshManager) GetRefreshStatus(userID, providerID string) *RefreshStatus {
	key := credKey(userID, providerID)

	m.mu.Lock()
	defer m.mu.Unlock()

	state := m.retries[key]
	if state == nil {
		return nil
	}

	return &RefreshStatus{
		UserID:       userID,
		ProviderID:   providerID,
		Retries:      state.retries,
		MaxRetries:   m.config.MaxRetries,
		LastError:    errorString(state.lastError),
		NextRetryAt:  state.nextRetry,
		Exhausted:    state.retries >= m.config.MaxRetries,
	}
}

// ResetRetries clears retry state for a credential, allowing new refresh attempts.
func (m *TokenRefreshManager) ResetRetries(userID, providerID string) {
	key := credKey(userID, providerID)
	m.mu.Lock()
	delete(m.retries, key)
	m.mu.Unlock()
}

// RefreshStatus provides information about a credential's refresh state.
type RefreshStatus struct {
	UserID      string    `json:"user_id"`
	ProviderID  string    `json:"provider_id"`
	Retries     int       `json:"retries"`
	MaxRetries  int       `json:"max_retries"`
	LastError   string    `json:"last_error,omitempty"`
	NextRetryAt time.Time `json:"next_retry_at,omitempty"`
	Exhausted   bool      `json:"exhausted"`
}

// refreshCredential is the internal async refresh handler called from the background loop.
func (m *TokenRefreshManager) refreshCredential(cred *VaultCredential) {
	_, err := m.doRefresh(cred)
	if err != nil {
		key := credKey(cred.UserID, cred.ProviderID)
		m.mu.Lock()
		state := m.retries[key]
		if state == nil {
			state = &refreshState{}
			m.retries[key] = state
		}
		state.retries++
		state.lastError = err
		// Exponential backoff: retryDelay * 2^(retries-1)
		backoff := m.config.RetryDelay * (1 << (state.retries - 1))
		state.nextRetry = time.Now().Add(backoff)
		m.mu.Unlock()

		if m.config.OnError != nil {
			m.config.OnError(cred.UserID, cred.ProviderID, err)
		}
		log.Printf("token refresh: failed for %s/%s (attempt %d/%d): %v",
			cred.UserID, cred.ProviderID, state.retries, m.config.MaxRetries, err)
	}
}

// doRefresh performs the actual token refresh with singleflight protection.
func (m *TokenRefreshManager) doRefresh(cred *VaultCredential) (*VaultCredential, error) {
	key := credKey(cred.UserID, cred.ProviderID)

	// Get or create per-credential mutex (singleflight).
	mu := m.getCredMutex(key)
	mu.Lock()
	defer mu.Unlock()

	// Re-read from vault in case another goroutine already refreshed.
	current, err := m.vault.Get(cred.UserID, cred.ProviderID)
	if err != nil {
		return nil, fmt.Errorf("re-reading credential: %w", err)
	}
	if current == nil {
		return nil, fmt.Errorf("credential deleted during refresh")
	}

	// If the credential was refreshed by another goroutine, return it.
	if !current.NeedsRefresh() {
		// Clear retry state on success.
		m.mu.Lock()
		delete(m.retries, key)
		m.mu.Unlock()
		return current, nil
	}

	if current.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Perform the refresh via the OAuth service.
	tokenResp, err := m.service.RefreshToken(cred.ProviderID, current.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("oauth refresh failed: %w", err)
	}

	// Update the credential in the vault.
	current.AccessToken = tokenResp.AccessToken
	if tokenResp.RefreshToken != "" {
		current.RefreshToken = tokenResp.RefreshToken
	}
	if tokenResp.TokenType != "" {
		current.TokenType = tokenResp.TokenType
	}
	if tokenResp.IDToken != "" {
		current.IDToken = tokenResp.IDToken
	}
	if tokenResp.Scope != "" {
		current.Scopes = tokenResp.Scope
	}
	if !tokenResp.ExpiresAt.IsZero() {
		current.ExpiresAt = tokenResp.ExpiresAt
	}
	current.Status = CredentialStatusActive

	if err := m.vault.Store(current); err != nil {
		return nil, fmt.Errorf("storing refreshed credential: %w", err)
	}

	// Clear retry state on success.
	m.mu.Lock()
	delete(m.retries, key)
	m.mu.Unlock()

	if m.config.OnRefresh != nil {
		m.config.OnRefresh(cred.UserID, cred.ProviderID)
	}

	return current, nil
}

// getCredMutex returns a per-credential mutex for singleflight protection.
func (m *TokenRefreshManager) getCredMutex(key string) *sync.Mutex {
	m.mu.Lock()
	defer m.mu.Unlock()

	mu, ok := m.inflight[key]
	if !ok {
		mu = &sync.Mutex{}
		m.inflight[key] = mu
	}
	return mu
}

// credKey generates a unique key for a user+provider pair.
func credKey(userID, providerID string) string {
	return userID + ":" + providerID
}

// errorString safely converts an error to string.
func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// SweepableVault extends VaultStore with the ability to list credentials nearing expiry.
// SQLiteVaultStore implements this for the background sweep.
type SweepableVault interface {
	VaultStore
	// ListExpiring returns active credentials that expire before the given threshold.
	ListExpiring(before time.Time) ([]*VaultCredential, error)
}
