package users

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"

	"github.com/operatoronline/Operator-OS/pkg/apiutil"
)

// API provides HTTP handlers for user management endpoints.
type API struct {
	store             UserStore
	tokenService      *TokenService
	verificationStore VerificationStore
}

// NewAPI creates a new API with the given UserStore.
func NewAPI(store UserStore) *API {
	return &API{store: store}
}

// NewAPIWithAuth creates a new API with a UserStore and TokenService for
// authenticated endpoints (login, refresh, token-protected routes).
func NewAPIWithAuth(store UserStore, ts *TokenService) *API {
	return &API{store: store, tokenService: ts}
}

// NewAPIFull creates a new API with all services: UserStore, TokenService,
// and VerificationStore for email verification endpoints.
func NewAPIFull(store UserStore, ts *TokenService, vs VerificationStore) *API {
	return &API{store: store, tokenService: ts, verificationStore: vs}
}

// RegisterRoutes registers user management endpoints on the given ServeMux.
// An optional rate-limiting middleware can be provided to protect auth endpoints
// against brute-force attacks (applied to login, register, and resend-verification).
func (a *API) RegisterRoutes(mux *http.ServeMux, rateLimitMiddleware ...func(http.Handler) http.Handler) {
	wrap := func(h http.HandlerFunc) http.Handler {
		var handler http.Handler = h
		for i := len(rateLimitMiddleware) - 1; i >= 0; i-- {
			handler = rateLimitMiddleware[i](handler)
		}
		return handler
	}
	mux.Handle("POST /api/v1/auth/register", wrap(a.handleRegister))
	mux.Handle("POST /api/v1/auth/login", wrap(a.handleLogin))
	mux.Handle("POST /api/v1/auth/refresh", http.HandlerFunc(a.handleRefresh))
	mux.Handle("POST /api/v1/auth/verify-email", http.HandlerFunc(a.handleVerifyEmail))
	mux.Handle("POST /api/v1/auth/resend-verification", wrap(a.handleResendVerification))
	mux.Handle("POST /api/v1/auth/logout", http.HandlerFunc(a.handleLogout))
}

// RegisterRequest is the JSON body for user registration.
type RegisterRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
}

// RegisterResponse is the JSON response after successful registration.
type RegisterResponse struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	DisplayName   string `json:"display_name,omitempty"`
	Status        string `json:"status"`
	EmailVerified bool   `json:"email_verified"`
}

// LoginRequest is the JSON body for user login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginResponse is the JSON response after successful login.
type LoginResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	TokenType    string           `json:"token_type"`
	ExpiresIn    int64            `json:"expires_in"`
	User         RegisterResponse `json:"user"`
}

// RefreshRequest is the JSON body for token refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// RefreshResponse is the JSON response after successful token refresh.
type RefreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// VerifyEmailRequest is the JSON body for email verification.
type VerifyEmailRequest struct {
	Token string `json:"token"`
}

// VerifyEmailResponse is the JSON response after successful verification.
type VerifyEmailResponse struct {
	Message       string `json:"message"`
	EmailVerified bool   `json:"email_verified"`
	Status        string `json:"status"`
}

// ResendVerificationRequest is the JSON body for resending verification.
type ResendVerificationRequest struct {
	Email string `json:"email"`
}

// ResendVerificationResponse is the JSON response after resending verification.
type ResendVerificationResponse struct {
	Message string `json:"message"`
}


func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	// Validate email.
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_email", "Email is required")
		return
	}
	if err := validateEmail(req.Email); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_email", err.Error())
		return
	}

	// Validate password.
	if err := ValidatePassword(req.Password); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}

	// Hash password.
	hash, err := HashPassword(req.Password)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to process password")
		return
	}

	user := &User{
		Email:        strings.ToLower(req.Email),
		PasswordHash: hash,
		DisplayName:  strings.TrimSpace(req.DisplayName),
		Status:       StatusPendingVerification,
	}

	if err := a.store.Create(user); err != nil {
		if errors.Is(err, ErrEmailExists) {
			apiutil.WriteError(w, http.StatusConflict, "email_exists", "An account with this email already exists")
			return
		}
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to create account")
		return
	}

	resp := RegisterResponse{
		ID:            user.ID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		Status:        user.Status,
		EmailVerified: user.EmailVerified,
	}

	apiutil.WriteJSON(w, http.StatusCreated, resp)
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.tokenService == nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "auth_not_configured", "Authentication is not configured")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	// Validate input.
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_email", "Email is required")
		return
	}
	if req.Password == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_password", "Password is required")
		return
	}

	// Look up user by email.
	user, err := a.store.GetByEmail(strings.ToLower(req.Email))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Deliberately vague error to prevent email enumeration.
			apiutil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
			return
		}
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Authentication failed")
		return
	}

	// Check account status.
	if user.Status == StatusSuspended {
		apiutil.WriteError(w, http.StatusForbidden, "account_suspended", "Account has been suspended")
		return
	}
	if user.Status == StatusDeleted {
		apiutil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		return
	}

	// Verify password.
	if err := CheckPassword(user.PasswordHash, req.Password); err != nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		return
	}

	// Issue tokens.
	pair, err := a.tokenService.IssueTokenPair(user)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to generate tokens")
		return
	}

	resp := LoginResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
		User: RegisterResponse{
			ID:            user.ID,
			Email:         user.Email,
			DisplayName:   user.DisplayName,
			Status:        user.Status,
			EmailVerified: user.EmailVerified,
		},
	}

	apiutil.WriteJSON(w, http.StatusOK, resp)
}

func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if a.tokenService == nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "auth_not_configured", "Authentication is not configured")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_token", "Refresh token is required")
		return
	}

	// Validate the refresh token.
	claims, err := a.tokenService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired refresh token")
		return
	}

	// Look up the user to ensure they still exist and are active.
	user, err := a.store.GetByID(claims.UserID)
	if err != nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "invalid_token", "User no longer exists")
		return
	}
	if user.Status == StatusSuspended || user.Status == StatusDeleted {
		apiutil.WriteError(w, http.StatusForbidden, "account_suspended", "Account is no longer active")
		return
	}

	// Issue new token pair.
	pair, err := a.tokenService.IssueTokenPair(user)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to generate tokens")
		return
	}

	resp := RefreshResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}

	apiutil.WriteJSON(w, http.StatusOK, resp)
}

func (a *API) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if a.verificationStore == nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "verification_not_configured", "Email verification is not configured")
		return
	}

	var req VerifyEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	req.Token = sanitizeToken(req.Token)
	if req.Token == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_token", "Verification token is required")
		return
	}

	if err := VerifyEmail(req.Token, a.verificationStore, a.store); err != nil {
		switch {
		case errors.Is(err, ErrTokenNotFound):
			apiutil.WriteError(w, http.StatusNotFound, "token_not_found", "Verification token not found")
		case errors.Is(err, ErrTokenExpired):
			apiutil.WriteError(w, http.StatusGone, "token_expired", "Verification token has expired")
		case errors.Is(err, ErrTokenUsed):
			apiutil.WriteError(w, http.StatusConflict, "token_used", "Verification token has already been used")
		case errors.Is(err, ErrAlreadyVerified):
			apiutil.WriteError(w, http.StatusConflict, "already_verified", "Email is already verified")
		default:
			apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Verification failed")
		}
		return
	}

	resp := VerifyEmailResponse{
		Message:       "Email verified successfully",
		EmailVerified: true,
		Status:        StatusActive,
	}

	apiutil.WriteJSON(w, http.StatusOK, resp)
}

func (a *API) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	if a.verificationStore == nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "verification_not_configured", "Email verification is not configured")
		return
	}

	var req ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		apiutil.WriteError(w, http.StatusBadRequest, "missing_email", "Email is required")
		return
	}

	// Look up user by email. Use vague error for non-existent users to prevent enumeration.
	user, err := a.store.GetByEmail(strings.ToLower(req.Email))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Return success even if user doesn't exist (anti-enumeration).
			resp := ResendVerificationResponse{Message: "If an account with that email exists, a verification email has been sent"}
			apiutil.WriteJSON(w, http.StatusOK, resp)
			return
		}
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to process request")
		return
	}

	_, err = ResendVerification(user.ID, a.verificationStore, a.store, DefaultResendCooldown)
	if err != nil {
		switch {
		case errors.Is(err, ErrAlreadyVerified):
			apiutil.WriteError(w, http.StatusConflict, "already_verified", "Email is already verified")
		case errors.Is(err, ErrTooManyTokens):
			apiutil.WriteError(w, http.StatusTooManyRequests, "too_many_requests", "Please wait before requesting another verification email")
		default:
			apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to send verification")
		}
		return
	}

	// In production, this would trigger an email send.
	// The token is returned in the response only for development/testing.
	resp := ResendVerificationResponse{
		Message: "If an account with that email exists, a verification email has been sent",
	}

	apiutil.WriteJSON(w, http.StatusOK, resp)
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if a.tokenService == nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "auth_not_configured", "Authentication is not configured")
		return
	}

	// Extract and revoke the access token from the Authorization header.
	tokenStr := extractBearerToken(r)
	if tokenStr != "" {
		claims, err := a.tokenService.ValidateToken(tokenStr)
		if err == nil {
			a.tokenService.RevokeToken(claims)
		}
	}

	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"message": "Logged out successfully"})
}

// validateEmail checks basic email format using net/mail.
func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}
	return nil
}


// ── User Profile Endpoints ──

// RegisterProfileRoutes registers authenticated user profile endpoints.
func (a *API) RegisterProfileRoutes(mux *http.ServeMux, authMiddleware func(http.Handler) http.Handler) {
	wrap := func(h http.HandlerFunc) http.Handler { return authMiddleware(h) }
	mux.Handle("GET /api/v1/user/profile", wrap(a.handleGetProfile))
	mux.Handle("PUT /api/v1/user/profile", wrap(a.handleUpdateProfile))
	mux.Handle("POST /api/v1/user/change-password", wrap(a.handleChangePassword))
	mux.Handle("GET /api/v1/user/notifications", wrap(a.handleGetNotifications))
	mux.Handle("PUT /api/v1/user/notifications", wrap(a.handleUpdateNotifications))
	mux.Handle("GET /api/v1/user/api-keys", wrap(a.handleListAPIKeys))
	mux.Handle("POST /api/v1/user/api-keys", wrap(a.handleCreateAPIKey))
	mux.Handle("DELETE /api/v1/user/api-keys/{id}", wrap(a.handleDeleteAPIKey))
}

func (a *API) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Missing auth")
		return
	}
	user, err := a.store.GetByID(claims.UserID)
	if err != nil {
		apiutil.WriteError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"id":             user.ID,
		"email":          user.Email,
		"display_name":   user.DisplayName,
		"role":           user.Role,
		"email_verified": user.EmailVerified,
		"created_at":     user.CreatedAt,
	})
}

func (a *API) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Missing auth")
		return
	}
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "bad_request", "Invalid JSON")
		return
	}
	user, err := a.store.GetByID(claims.UserID)
	if err != nil {
		apiutil.WriteError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	user.DisplayName = req.DisplayName
	if err := a.store.Update(user); err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to update profile")
		return
	}
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *API) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	claims := ClaimsFromContext(r.Context())
	if claims == nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "unauthorized", "Missing auth")
		return
	}
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "bad_request", "Invalid JSON")
		return
	}
	user, err := a.store.GetByID(claims.UserID)
	if err != nil {
		apiutil.WriteError(w, http.StatusNotFound, "not_found", "User not found")
		return
	}
	if CheckPassword(user.PasswordHash, req.CurrentPassword) != nil {
		apiutil.WriteError(w, http.StatusUnauthorized, "invalid_password", "Current password is incorrect")
		return
	}
	if err := ValidatePassword(req.NewPassword); err != nil {
		apiutil.WriteError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}
	hash, err := HashPassword(req.NewPassword)
	if err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to hash password")
		return
	}
	user.PasswordHash = hash
	if err := a.store.Update(user); err != nil {
		apiutil.WriteError(w, http.StatusInternalServerError, "internal", "Failed to update password")
		return
	}
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

// Stub endpoints — notifications and API keys
func (a *API) handleGetNotifications(w http.ResponseWriter, _ *http.Request) {
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{
		"email_notifications": true,
		"push_notifications":  false,
		"weekly_digest":       false,
	})
}

func (a *API) handleUpdateNotifications(w http.ResponseWriter, _ *http.Request) {
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *API) handleListAPIKeys(w http.ResponseWriter, _ *http.Request) {
	apiutil.WriteJSON(w, http.StatusOK, []any{})
}

func (a *API) handleCreateAPIKey(w http.ResponseWriter, _ *http.Request) {
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"id": "stub", "key": "op-stub-not-implemented"})
}

func (a *API) handleDeleteAPIKey(w http.ResponseWriter, _ *http.Request) {
	apiutil.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}
