package oauth

import (
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- helpers ---

func setupRefreshDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	require.NoError(t, err)
	db.SetMaxOpenConns(1) // serialize access for in-memory DB
	_, err = db.Exec(`PRAGMA journal_mode=WAL`)
	require.NoError(t, err)
	// Create tables needed for vault and oauth states.
	_, err = db.Exec(`
		CREATE TABLE credential_vault (
			id           TEXT PRIMARY KEY,
			user_id      TEXT NOT NULL,
			provider_id  TEXT NOT NULL,
			encrypted_data BLOB NOT NULL,
			encrypted    INTEGER DEFAULT 0,
			label        TEXT DEFAULT '',
			status       TEXT DEFAULT 'active',
			scopes       TEXT DEFAULT '',
			expires_at   TEXT DEFAULT '',
			created_at   TEXT NOT NULL,
			updated_at   TEXT NOT NULL,
			UNIQUE(user_id, provider_id)
		);
		CREATE TABLE oauth_states (
			id            TEXT PRIMARY KEY,
			user_id       TEXT NOT NULL,
			provider_id   TEXT NOT NULL,
			state         TEXT NOT NULL UNIQUE,
			code_verifier TEXT DEFAULT '',
			redirect_uri  TEXT DEFAULT '',
			scopes        TEXT DEFAULT '',
			created_at    TEXT NOT NULL,
			expires_at    TEXT NOT NULL,
			used          INTEGER DEFAULT 0
		);
	`)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

func testProvider() *Provider {
	return &Provider{
		ID:          "test-provider",
		Name:        "Test Provider",
		AuthURL:     "https://test.example.com/auth",
		TokenURL:    "https://test.example.com/token",
		ClientID:    "test-client-id",
		RedirectURL: "https://app.example.com/callback",
		UsePKCE:     true,
	}
}

func setupRefreshManager(t *testing.T, db *sql.DB, config RefreshConfig) (*TokenRefreshManager, *SQLiteVaultStore) {
	t.Helper()
	vault, err := NewSQLiteVaultStore(db, "")
	require.NoError(t, err)

	registry := NewProviderRegistry()
	require.NoError(t, registry.Register(testProvider()))

	stateStore, err := NewSQLiteStateStore(db)
	require.NoError(t, err)

	service, err := NewService(ServiceConfig{
		Registry:   registry,
		StateStore: stateStore,
	})
	require.NoError(t, err)

	mgr, err := NewTokenRefreshManager(vault, service, config)
	require.NoError(t, err)

	return mgr, vault
}

func storeCredential(t *testing.T, vault *SQLiteVaultStore, userID, providerID, accessToken, refreshToken string, expiresAt time.Time) {
	t.Helper()
	err := vault.Store(&VaultCredential{
		UserID:       userID,
		ProviderID:   providerID,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Status:       CredentialStatusActive,
		ExpiresAt:    expiresAt,
	})
	require.NoError(t, err)
}

// --- constructor tests ---

func TestNewTokenRefreshManager_NilVault(t *testing.T) {
	_, err := NewTokenRefreshManager(nil, &Service{}, DefaultRefreshConfig())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "vault store is required")
}

func TestNewTokenRefreshManager_NilService(t *testing.T) {
	db := setupRefreshDB(t)
	vault, _ := NewSQLiteVaultStore(db, "")
	_, err := NewTokenRefreshManager(vault, nil, DefaultRefreshConfig())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "oauth service is required")
}

func TestNewTokenRefreshManager_DefaultConfig(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, RefreshConfig{})

	assert.Equal(t, 5*time.Minute, mgr.config.CheckInterval)
	assert.Equal(t, 5*time.Minute, mgr.config.RefreshBefore)
	assert.Equal(t, 3, mgr.config.MaxRetries)
	assert.Equal(t, 30*time.Second, mgr.config.RetryDelay)
}

func TestNewTokenRefreshManager_CustomConfig(t *testing.T) {
	db := setupRefreshDB(t)
	cfg := RefreshConfig{
		CheckInterval: 10 * time.Minute,
		RefreshBefore: 15 * time.Minute,
		MaxRetries:    5,
		RetryDelay:    1 * time.Minute,
	}
	mgr, _ := setupRefreshManager(t, db, cfg)

	assert.Equal(t, 10*time.Minute, mgr.config.CheckInterval)
	assert.Equal(t, 15*time.Minute, mgr.config.RefreshBefore)
	assert.Equal(t, 5, mgr.config.MaxRetries)
	assert.Equal(t, 1*time.Minute, mgr.config.RetryDelay)
}

func TestDefaultRefreshConfig(t *testing.T) {
	cfg := DefaultRefreshConfig()
	assert.Equal(t, 5*time.Minute, cfg.CheckInterval)
	assert.Equal(t, 5*time.Minute, cfg.RefreshBefore)
	assert.Equal(t, 3, cfg.MaxRetries)
	assert.Equal(t, 30*time.Second, cfg.RetryDelay)
}

// --- start/stop ---

func TestTokenRefreshManager_StartStop(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, RefreshConfig{
		CheckInterval: 1 * time.Hour, // long interval so it doesn't fire
	})

	mgr.Start()
	time.Sleep(50 * time.Millisecond)
	mgr.Stop()

	// Double stop should be safe.
	mgr.Stop()
}

// --- EnsureFresh ---

func TestEnsureFresh_EmptyUserID(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	_, err := mgr.EnsureFresh("", "provider")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestEnsureFresh_EmptyProviderID(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	_, err := mgr.EnsureFresh("user1", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider ID is required")
}

func TestEnsureFresh_NotFound(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	_, err := mgr.EnsureFresh("user1", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
}

func TestEnsureFresh_NotExpiring(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Token expires in 1 hour — no refresh needed.
	storeCredential(t, vault, "user1", "test-provider", "access-token", "refresh-token",
		time.Now().UTC().Add(1*time.Hour))

	cred, err := mgr.EnsureFresh("user1", "test-provider")
	require.NoError(t, err)
	assert.Equal(t, "access-token", cred.AccessToken)
}

func TestEnsureFresh_NoRefreshToken(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Token expires in 2 minutes — needs refresh, but no refresh token.
	storeCredential(t, vault, "user1", "test-provider", "access-token", "",
		time.Now().UTC().Add(2*time.Minute))

	_, err := mgr.EnsureFresh("user1", "test-provider")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no refresh token available")
}

func TestEnsureFresh_NoExpiry(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Token with no expiry — should be considered fresh.
	storeCredential(t, vault, "user1", "test-provider", "access-token", "refresh-token",
		time.Time{})

	cred, err := mgr.EnsureFresh("user1", "test-provider")
	require.NoError(t, err)
	assert.Equal(t, "access-token", cred.AccessToken)
}

// --- RefreshCredential ---

func TestRefreshCredential_EmptyUserID(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	_, err := mgr.RefreshCredential("", "provider")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "user ID is required")
}

func TestRefreshCredential_EmptyProviderID(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	_, err := mgr.RefreshCredential("user1", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "provider ID is required")
}

func TestRefreshCredential_NotFound(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	_, err := mgr.RefreshCredential("user1", "nonexistent")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential not found")
}

func TestRefreshCredential_NoRefreshToken(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	storeCredential(t, vault, "user1", "test-provider", "access-token", "",
		time.Now().UTC().Add(2*time.Minute))

	_, err := mgr.RefreshCredential("user1", "test-provider")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no refresh token available")
}

// --- GetRefreshStatus / ResetRetries ---

func TestGetRefreshStatus_None(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	status := mgr.GetRefreshStatus("user1", "test-provider")
	assert.Nil(t, status)
}

func TestGetRefreshStatus_WithRetries(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Simulate retry state.
	key := credKey("user1", "test-provider")
	mgr.mu.Lock()
	mgr.retries[key] = &refreshState{
		retries:   2,
		lastError: fmt.Errorf("connection refused"),
		nextRetry: time.Now().Add(1 * time.Minute),
	}
	mgr.mu.Unlock()

	status := mgr.GetRefreshStatus("user1", "test-provider")
	require.NotNil(t, status)
	assert.Equal(t, "user1", status.UserID)
	assert.Equal(t, "test-provider", status.ProviderID)
	assert.Equal(t, 2, status.Retries)
	assert.Equal(t, 3, status.MaxRetries)
	assert.Equal(t, "connection refused", status.LastError)
	assert.False(t, status.Exhausted)
}

func TestGetRefreshStatus_Exhausted(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	key := credKey("user1", "test-provider")
	mgr.mu.Lock()
	mgr.retries[key] = &refreshState{
		retries:   3,
		lastError: fmt.Errorf("token revoked"),
	}
	mgr.mu.Unlock()

	status := mgr.GetRefreshStatus("user1", "test-provider")
	require.NotNil(t, status)
	assert.True(t, status.Exhausted)
}

func TestResetRetries(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	key := credKey("user1", "test-provider")
	mgr.mu.Lock()
	mgr.retries[key] = &refreshState{retries: 3}
	mgr.mu.Unlock()

	mgr.ResetRetries("user1", "test-provider")

	status := mgr.GetRefreshStatus("user1", "test-provider")
	assert.Nil(t, status)
}

// --- SweepableVault (ListExpiring) ---

func TestSQLiteVaultStore_ListExpiring_Empty(t *testing.T) {
	db := setupRefreshDB(t)
	vault, err := NewSQLiteVaultStore(db, "")
	require.NoError(t, err)

	creds, err := vault.ListExpiring(time.Now().UTC().Add(1 * time.Hour))
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestSQLiteVaultStore_ListExpiring_FindsExpiring(t *testing.T) {
	db := setupRefreshDB(t)
	vault, err := NewSQLiteVaultStore(db, "")
	require.NoError(t, err)

	// Store a credential expiring in 3 minutes.
	storeCredential(t, vault, "user1", "provider1", "token1", "refresh1",
		time.Now().UTC().Add(3*time.Minute))

	// Store a credential expiring in 1 hour (should not be returned with 10min threshold).
	storeCredential(t, vault, "user2", "provider2", "token2", "refresh2",
		time.Now().UTC().Add(1*time.Hour))

	// Store a credential with no expiry (should not be returned).
	storeCredential(t, vault, "user3", "provider3", "token3", "refresh3",
		time.Time{})

	threshold := time.Now().UTC().Add(10 * time.Minute)
	creds, err := vault.ListExpiring(threshold)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "user1", creds[0].UserID)
	assert.Equal(t, "provider1", creds[0].ProviderID)
}

func TestSQLiteVaultStore_ListExpiring_SkipsNonActive(t *testing.T) {
	db := setupRefreshDB(t)
	vault, err := NewSQLiteVaultStore(db, "")
	require.NoError(t, err)

	// Store an active credential expiring soon.
	storeCredential(t, vault, "user1", "provider1", "token1", "refresh1",
		time.Now().UTC().Add(3*time.Minute))

	// Store a revoked credential expiring soon.
	err = vault.Store(&VaultCredential{
		UserID:       "user2",
		ProviderID:   "provider2",
		AccessToken:  "token2",
		RefreshToken: "refresh2",
		Status:       CredentialStatusRevoked,
		ExpiresAt:    time.Now().UTC().Add(3 * time.Minute),
	})
	require.NoError(t, err)

	threshold := time.Now().UTC().Add(10 * time.Minute)
	creds, err := vault.ListExpiring(threshold)
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "user1", creds[0].UserID)
}

func TestSQLiteVaultStore_ListExpiring_MultipleSorted(t *testing.T) {
	db := setupRefreshDB(t)
	vault, err := NewSQLiteVaultStore(db, "")
	require.NoError(t, err)

	// Store credentials with different expiry times.
	storeCredential(t, vault, "user2", "providerB", "token2", "refresh2",
		time.Now().UTC().Add(8*time.Minute))
	storeCredential(t, vault, "user1", "providerA", "token1", "refresh1",
		time.Now().UTC().Add(3*time.Minute))

	threshold := time.Now().UTC().Add(10 * time.Minute)
	creds, err := vault.ListExpiring(threshold)
	require.NoError(t, err)
	require.Len(t, creds, 2)
	// Sorted by expires_at ASC.
	assert.Equal(t, "user1", creds[0].UserID)
	assert.Equal(t, "user2", creds[1].UserID)
}

// --- SweepableVault interface compliance ---

func TestSQLiteVaultStore_ImplementsSweepableVault(t *testing.T) {
	db := setupRefreshDB(t)
	vault, err := NewSQLiteVaultStore(db, "")
	require.NoError(t, err)

	var _ SweepableVault = vault // compile-time check
}

// --- maybeRefresh retry logic ---

func TestMaybeRefresh_RespectsMaxRetries(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	key := credKey("user1", "test-provider")
	mgr.mu.Lock()
	mgr.retries[key] = &refreshState{retries: 3} // exhausted
	mgr.mu.Unlock()

	cred := &VaultCredential{
		UserID:     "user1",
		ProviderID: "test-provider",
	}
	// Should return immediately without attempting refresh.
	mgr.maybeRefresh(cred)
	// If it tried to refresh, it would fail (no refresh token) and increment retries.
	time.Sleep(50 * time.Millisecond)

	mgr.mu.Lock()
	assert.Equal(t, 3, mgr.retries[key].retries) // unchanged
	mgr.mu.Unlock()
}

func TestMaybeRefresh_RespectsBackoff(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	key := credKey("user1", "test-provider")
	mgr.mu.Lock()
	mgr.retries[key] = &refreshState{
		retries:   1,
		nextRetry: time.Now().Add(1 * time.Hour), // far in the future
	}
	mgr.mu.Unlock()

	cred := &VaultCredential{
		UserID:     "user1",
		ProviderID: "test-provider",
	}
	mgr.maybeRefresh(cred)
	time.Sleep(50 * time.Millisecond)

	mgr.mu.Lock()
	assert.Equal(t, 1, mgr.retries[key].retries) // unchanged — backoff not reached
	mgr.mu.Unlock()
}

// --- Concurrent refresh prevention ---

func TestConcurrentRefresh_SingleFlight(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Store credential that does NOT need refresh (so doRefresh's re-read sees it fresh).
	storeCredential(t, vault, "user1", "test-provider", "access-token", "refresh-token",
		time.Now().UTC().Add(1*time.Hour))

	var wg sync.WaitGroup
	results := make(chan *VaultCredential, 5)
	errs := make(chan error, 5)

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cred, err := mgr.EnsureFresh("user1", "test-provider")
			if err != nil {
				errs <- err
			} else {
				results <- cred
			}
		}()
	}

	wg.Wait()
	close(results)
	close(errs)

	// All should succeed (token not expiring, so no actual refresh needed).
	for err := range errs {
		t.Errorf("unexpected error: %v", err)
	}
	count := 0
	for cred := range results {
		assert.Equal(t, "access-token", cred.AccessToken)
		count++
	}
	assert.Equal(t, 5, count)
}

// --- OnRefresh / OnError callbacks ---

func TestRefreshConfig_OnErrorCallback(t *testing.T) {
	db := setupRefreshDB(t)

	var callbackCount int32
	cfg := DefaultRefreshConfig()
	cfg.OnError = func(userID, providerID string, err error) {
		atomic.AddInt32(&callbackCount, 1)
	}

	mgr, vault := setupRefreshManager(t, db, cfg)

	// Store credential that needs refresh but has a refresh token that will fail
	// (no real OAuth server).
	storeCredential(t, vault, "user1", "test-provider", "expired-token", "bad-refresh-token",
		time.Now().UTC().Add(-1*time.Minute))

	// Trigger a background refresh.
	mgr.refreshCredential(&VaultCredential{
		UserID:       "user1",
		ProviderID:   "test-provider",
		RefreshToken: "bad-refresh-token",
	})

	time.Sleep(100 * time.Millisecond)

	assert.GreaterOrEqual(t, atomic.LoadInt32(&callbackCount), int32(1))

	// Should have retry state.
	status := mgr.GetRefreshStatus("user1", "test-provider")
	require.NotNil(t, status)
	assert.Equal(t, 1, status.Retries)
	assert.NotEmpty(t, status.LastError)
}

// --- credKey ---

func TestCredKey(t *testing.T) {
	assert.Equal(t, "user1:provider1", credKey("user1", "provider1"))
	assert.Equal(t, "abc:xyz", credKey("abc", "xyz"))
}

// --- errorString ---

func TestErrorString(t *testing.T) {
	assert.Equal(t, "", errorString(nil))
	assert.Equal(t, "test error", errorString(fmt.Errorf("test error")))
}

// --- checkAll with non-sweepable vault ---

type mockNonSweepableVault struct {
	VaultStore
}

func TestCheckAll_NonSweepableVault(t *testing.T) {
	// Create a manager with a vault that doesn't implement SweepableVault.
	db := setupRefreshDB(t)
	registry := NewProviderRegistry()
	registry.Register(testProvider())
	stateStore, _ := NewSQLiteStateStore(db)
	service, _ := NewService(ServiceConfig{
		Registry:   registry,
		StateStore: stateStore,
	})

	mgr, err := NewTokenRefreshManager(&mockNonSweepableVault{}, service, DefaultRefreshConfig())
	require.NoError(t, err)

	// Should not panic; just returns silently.
	mgr.checkAll()
}

// --- Multi-user isolation ---

func TestRefreshStatus_MultiUser(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Set retry state for user1.
	mgr.mu.Lock()
	mgr.retries[credKey("user1", "providerA")] = &refreshState{retries: 2}
	mgr.retries[credKey("user2", "providerA")] = &refreshState{retries: 1}
	mgr.mu.Unlock()

	s1 := mgr.GetRefreshStatus("user1", "providerA")
	s2 := mgr.GetRefreshStatus("user2", "providerA")

	require.NotNil(t, s1)
	require.NotNil(t, s2)
	assert.Equal(t, 2, s1.Retries)
	assert.Equal(t, 1, s2.Retries)

	// Reset only user1.
	mgr.ResetRetries("user1", "providerA")
	assert.Nil(t, mgr.GetRefreshStatus("user1", "providerA"))
	assert.NotNil(t, mgr.GetRefreshStatus("user2", "providerA"))
}

// --- Exponential backoff ---

func TestRefreshCredential_ExponentialBackoff(t *testing.T) {
	db := setupRefreshDB(t)
	cfg := RefreshConfig{
		RetryDelay: 1 * time.Second,
	}
	mgr, vault := setupRefreshManager(t, db, cfg)

	// Store credential that needs refresh.
	storeCredential(t, vault, "user1", "test-provider", "expired", "bad-refresh",
		time.Now().UTC().Add(-1*time.Minute))

	cred := &VaultCredential{
		UserID:       "user1",
		ProviderID:   "test-provider",
		RefreshToken: "bad-refresh",
	}

	// First failure.
	mgr.refreshCredential(cred)
	time.Sleep(50 * time.Millisecond)

	mgr.mu.Lock()
	state := mgr.retries[credKey("user1", "test-provider")]
	require.NotNil(t, state)
	assert.Equal(t, 1, state.retries)
	firstRetryTime := state.nextRetry
	mgr.mu.Unlock()

	// The next retry should be ~1s from now (1s * 2^0).
	assert.WithinDuration(t, time.Now().Add(1*time.Second), firstRetryTime, 500*time.Millisecond)

	// Update state to allow second retry.
	mgr.mu.Lock()
	mgr.retries[credKey("user1", "test-provider")].nextRetry = time.Now().Add(-1 * time.Second)
	mgr.mu.Unlock()

	// Second failure.
	mgr.refreshCredential(cred)
	time.Sleep(50 * time.Millisecond)

	mgr.mu.Lock()
	state = mgr.retries[credKey("user1", "test-provider")]
	assert.Equal(t, 2, state.retries)
	secondRetryTime := state.nextRetry
	mgr.mu.Unlock()

	// Second retry should be ~2s from now (1s * 2^1).
	assert.WithinDuration(t, time.Now().Add(2*time.Second), secondRetryTime, 500*time.Millisecond)
}

// --- doRefresh re-reads from vault ---

func TestDoRefresh_ReReadsFromVault(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Store credential that does NOT need refresh.
	storeCredential(t, vault, "user1", "test-provider", "already-fresh", "refresh-token",
		time.Now().UTC().Add(1*time.Hour))

	// Call doRefresh with a stale credential copy.
	staleCred := &VaultCredential{
		UserID:       "user1",
		ProviderID:   "test-provider",
		AccessToken:  "old-token",
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().UTC().Add(-1 * time.Minute),
	}

	result, err := mgr.doRefresh(staleCred)
	require.NoError(t, err)
	// Should return the fresh version from vault, not the stale one.
	assert.Equal(t, "already-fresh", result.AccessToken)
}

// --- doRefresh deleted credential ---

func TestDoRefresh_DeletedCredential(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, vault := setupRefreshManager(t, db, DefaultRefreshConfig())

	// Store and then delete.
	storeCredential(t, vault, "user1", "test-provider", "token", "refresh",
		time.Now().UTC().Add(2*time.Minute))
	vault.Delete("user1", "test-provider")

	cred := &VaultCredential{
		UserID:       "user1",
		ProviderID:   "test-provider",
		RefreshToken: "refresh",
	}

	_, err := mgr.doRefresh(cred)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "credential deleted during refresh")
}

// --- getCredMutex ---

func TestGetCredMutex_ReturnsSameForSameKey(t *testing.T) {
	db := setupRefreshDB(t)
	mgr, _ := setupRefreshManager(t, db, DefaultRefreshConfig())

	mu1 := mgr.getCredMutex("user1:provider1")
	mu2 := mgr.getCredMutex("user1:provider1")
	mu3 := mgr.getCredMutex("user2:provider1")

	assert.Same(t, mu1, mu2) // same mutex for same key
	assert.NotSame(t, mu1, mu3) // different mutex for different key
}
