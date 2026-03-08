package users

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Token type constants used in the "type" claim.
const (
	TokenTypeAccess  = "access"
	TokenTypeRefresh = "refresh"
)

// Default token lifetimes.
const (
	DefaultAccessTokenTTL  = 15 * time.Minute
	DefaultRefreshTokenTTL = 7 * 24 * time.Hour
)

// JWT-related errors.
var (
	ErrInvalidToken      = errors.New("invalid or expired token")
	ErrInvalidTokenType  = errors.New("invalid token type")
	ErrMissingSigningKey = errors.New("JWT signing key is required")
)

// TokenClaims extends jwt.RegisteredClaims with Operator OS–specific fields.
type TokenClaims struct {
	jwt.RegisteredClaims
	UserID    string `json:"uid"`
	Email     string `json:"email"`
	TokenType string `json:"type"`
}

// TokenPair holds an access token and a refresh token.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"` // seconds until access token expires
}

// TokenService issues and validates JWTs.
type TokenService struct {
	signingKey      []byte
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
	issuer          string
}

// TokenServiceOption configures a TokenService.
type TokenServiceOption func(*TokenService)

// WithAccessTokenTTL overrides the default access token lifetime.
func WithAccessTokenTTL(d time.Duration) TokenServiceOption {
	return func(ts *TokenService) { ts.accessTokenTTL = d }
}

// WithRefreshTokenTTL overrides the default refresh token lifetime.
func WithRefreshTokenTTL(d time.Duration) TokenServiceOption {
	return func(ts *TokenService) { ts.refreshTokenTTL = d }
}

// WithIssuer sets the "iss" claim.
func WithIssuer(iss string) TokenServiceOption {
	return func(ts *TokenService) { ts.issuer = iss }
}

// NewTokenService creates a TokenService. signingKey must be non-empty.
func NewTokenService(signingKey []byte, opts ...TokenServiceOption) (*TokenService, error) {
	if len(signingKey) == 0 {
		return nil, ErrMissingSigningKey
	}
	ts := &TokenService{
		signingKey:      signingKey,
		accessTokenTTL:  DefaultAccessTokenTTL,
		refreshTokenTTL: DefaultRefreshTokenTTL,
		issuer:          "operator-os.standardcompute",
	}
	for _, opt := range opts {
		opt(ts)
	}
	return ts, nil
}

// IssueTokenPair generates a new access + refresh token pair for the given user.
func (ts *TokenService) IssueTokenPair(user *User) (*TokenPair, error) {
	now := time.Now()
	jti, err := generateJTI()
	if err != nil {
		return nil, fmt.Errorf("generate jti: %w", err)
	}

	accessToken, err := ts.createToken(user, TokenTypeAccess, now, ts.accessTokenTTL, jti+"-access")
	if err != nil {
		return nil, fmt.Errorf("create access token: %w", err)
	}

	refreshToken, err := ts.createToken(user, TokenTypeRefresh, now, ts.refreshTokenTTL, jti+"-refresh")
	if err != nil {
		return nil, fmt.Errorf("create refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(ts.accessTokenTTL.Seconds()),
	}, nil
}

// ValidateToken parses and validates a JWT string. Returns claims if valid.
func (ts *TokenService) ValidateToken(tokenStr string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &TokenClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return ts.signingKey, nil
	})
	if err != nil {
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ValidateAccessToken validates a token and ensures it is an access token.
func (ts *TokenService) ValidateAccessToken(tokenStr string) (*TokenClaims, error) {
	claims, err := ts.ValidateToken(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeAccess {
		return nil, ErrInvalidTokenType
	}
	return claims, nil
}

// ValidateRefreshToken validates a token and ensures it is a refresh token.
func (ts *TokenService) ValidateRefreshToken(tokenStr string) (*TokenClaims, error) {
	claims, err := ts.ValidateToken(tokenStr)
	if err != nil {
		return nil, err
	}
	if claims.TokenType != TokenTypeRefresh {
		return nil, ErrInvalidTokenType
	}
	return claims, nil
}

func (ts *TokenService) createToken(user *User, tokenType string, now time.Time, ttl time.Duration, jti string) (string, error) {
	claims := TokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   user.ID,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			Issuer:    ts.issuer,
			ID:        jti,
		},
		UserID:    user.ID,
		Email:     user.Email,
		TokenType: tokenType,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(ts.signingKey)
}

func generateJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
