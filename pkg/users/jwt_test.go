package users

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testSigningKey() []byte {
	return []byte("test-secret-key-for-unit-tests-32bytes!")
}

func testUser() *User {
	return &User{
		ID:    "user-123",
		Email: "test@example.com",
	}
}

// --- TokenService creation ---

func TestNewTokenService_Valid(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)
	assert.NotNil(t, ts)
}

func TestNewTokenService_EmptyKey(t *testing.T) {
	ts, err := NewTokenService([]byte{})
	assert.ErrorIs(t, err, ErrMissingSigningKey)
	assert.Nil(t, ts)
}

func TestNewTokenService_NilKey(t *testing.T) {
	ts, err := NewTokenService(nil)
	assert.ErrorIs(t, err, ErrMissingSigningKey)
	assert.Nil(t, ts)
}

func TestNewTokenService_WithOptions(t *testing.T) {
	ts, err := NewTokenService(testSigningKey(),
		WithAccessTokenTTL(5*time.Minute),
		WithRefreshTokenTTL(24*time.Hour),
		WithIssuer("test-issuer"),
	)
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, ts.accessTokenTTL)
	assert.Equal(t, 24*time.Hour, ts.refreshTokenTTL)
	assert.Equal(t, "test-issuer", ts.issuer)
}

// --- Token issuance ---

func TestIssueTokenPair_Success(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	assert.NotEmpty(t, pair.AccessToken)
	assert.NotEmpty(t, pair.RefreshToken)
	assert.Equal(t, "Bearer", pair.TokenType)
	assert.Equal(t, int64(DefaultAccessTokenTTL.Seconds()), pair.ExpiresIn)
	assert.NotEqual(t, pair.AccessToken, pair.RefreshToken)
}

// --- Token validation ---

func TestValidateToken_AccessToken(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	claims, err := ts.ValidateToken(pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, "test@example.com", claims.Email)
	assert.Equal(t, TokenTypeAccess, claims.TokenType)
	assert.Equal(t, "operator-os", claims.Issuer)
}

func TestValidateToken_RefreshToken(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	claims, err := ts.ValidateToken(pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, TokenTypeRefresh, claims.TokenType)
}

func TestValidateToken_InvalidString(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	_, err = ts.ValidateToken("not-a-valid-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_WrongKey(t *testing.T) {
	ts1, _ := NewTokenService([]byte("key-one-for-signing-tokens-xxxxx"))
	ts2, _ := NewTokenService([]byte("key-two-different-from-one-xxxxx"))

	pair, err := ts1.IssueTokenPair(testUser())
	require.NoError(t, err)

	_, err = ts2.ValidateToken(pair.AccessToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateToken_Expired(t *testing.T) {
	ts, err := NewTokenService(testSigningKey(), WithAccessTokenTTL(-1*time.Second))
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	_, err = ts.ValidateAccessToken(pair.AccessToken)
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestValidateAccessToken_RejectsRefresh(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	_, err = ts.ValidateAccessToken(pair.RefreshToken)
	assert.ErrorIs(t, err, ErrInvalidTokenType)
}

func TestValidateRefreshToken_RejectsAccess(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	_, err = ts.ValidateRefreshToken(pair.AccessToken)
	assert.ErrorIs(t, err, ErrInvalidTokenType)
}

func TestValidateAccessToken_Success(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	claims, err := ts.ValidateAccessToken(pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, TokenTypeAccess, claims.TokenType)
}

func TestValidateRefreshToken_Success(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	claims, err := ts.ValidateRefreshToken(pair.RefreshToken)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, TokenTypeRefresh, claims.TokenType)
}

// --- Token claims ---

func TestTokenClaims_SubjectMatchesUserID(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	claims, err := ts.ValidateToken(pair.AccessToken)
	require.NoError(t, err)
	assert.Equal(t, claims.UserID, claims.Subject)
}

func TestTokenClaims_UniqueJTI(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair1, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)
	pair2, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	claims1, _ := ts.ValidateToken(pair1.AccessToken)
	claims2, _ := ts.ValidateToken(pair2.AccessToken)
	assert.NotEqual(t, claims1.ID, claims2.ID)
}

// --- Middleware ---

func TestAuthMiddleware_ValidToken(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	var capturedUserID, capturedEmail string
	handler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUserID = UserIDFromContext(r.Context())
		capturedEmail = EmailFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "user-123", capturedUserID)
	assert.Equal(t, "test@example.com", capturedEmail)
}

func TestAuthMiddleware_MissingToken(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	handler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	handler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_RefreshTokenRejected(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	handler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called with refresh token")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pair.RefreshToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_MalformedAuthHeader(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	handler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "NotBearer sometoken")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// --- Context helpers ---

func TestContextHelpers_NoValues(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, "", UserIDFromContext(ctx))
	assert.Equal(t, "", EmailFromContext(ctx))
	assert.Nil(t, ClaimsFromContext(ctx))
}

func TestClaimsFromContext_Roundtrip(t *testing.T) {
	ts, err := NewTokenService(testSigningKey())
	require.NoError(t, err)

	pair, err := ts.IssueTokenPair(testUser())
	require.NoError(t, err)

	var capturedClaims *TokenClaims
	handler := AuthMiddleware(ts)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	require.NotNil(t, capturedClaims)
	assert.Equal(t, "user-123", capturedClaims.UserID)
	assert.Equal(t, "test@example.com", capturedClaims.Email)
	assert.Equal(t, TokenTypeAccess, capturedClaims.TokenType)
}
