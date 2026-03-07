package users

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
)

// API provides HTTP handlers for user management endpoints.
type API struct {
	store        UserStore
	tokenService *TokenService
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

// RegisterRoutes registers user management endpoints on the given ServeMux.
func (a *API) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/register", a.handleRegister)
	mux.HandleFunc("POST /api/v1/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/refresh", a.handleRefresh)
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

// ErrorResponse is a standard error JSON response.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

func (a *API) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	// Validate email.
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "missing_email", "Email is required")
		return
	}
	if err := validateEmail(req.Email); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_email", err.Error())
		return
	}

	// Validate password.
	if err := ValidatePassword(req.Password); err != nil {
		writeError(w, http.StatusBadRequest, "weak_password", err.Error())
		return
	}

	// Hash password.
	hash, err := HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to process password")
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
			writeError(w, http.StatusConflict, "email_exists", "An account with this email already exists")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Failed to create account")
		return
	}

	resp := RegisterResponse{
		ID:            user.ID,
		Email:         user.Email,
		DisplayName:   user.DisplayName,
		Status:        user.Status,
		EmailVerified: user.EmailVerified,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	if a.tokenService == nil {
		writeError(w, http.StatusInternalServerError, "auth_not_configured", "Authentication is not configured")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	// Validate input.
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "missing_email", "Email is required")
		return
	}
	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "missing_password", "Password is required")
		return
	}

	// Look up user by email.
	user, err := a.store.GetByEmail(strings.ToLower(req.Email))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Deliberately vague error to prevent email enumeration.
			writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "Authentication failed")
		return
	}

	// Check account status.
	if user.Status == StatusSuspended {
		writeError(w, http.StatusForbidden, "account_suspended", "Account has been suspended")
		return
	}
	if user.Status == StatusDeleted {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		return
	}

	// Verify password.
	if err := CheckPassword(user.PasswordHash, req.Password); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Invalid email or password")
		return
	}

	// Issue tokens.
	pair, err := a.tokenService.IssueTokenPair(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to generate tokens")
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if a.tokenService == nil {
		writeError(w, http.StatusInternalServerError, "auth_not_configured", "Authentication is not configured")
		return
	}

	var req RefreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "missing_token", "Refresh token is required")
		return
	}

	// Validate the refresh token.
	claims, err := a.tokenService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "Invalid or expired refresh token")
		return
	}

	// Look up the user to ensure they still exist and are active.
	user, err := a.store.GetByID(claims.UserID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", "User no longer exists")
		return
	}
	if user.Status == StatusSuspended || user.Status == StatusDeleted {
		writeError(w, http.StatusForbidden, "account_suspended", "Account is no longer active")
		return
	}

	// Issue new token pair.
	pair, err := a.tokenService.IssueTokenPair(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "Failed to generate tokens")
		return
	}

	resp := RefreshResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    pair.TokenType,
		ExpiresIn:    pair.ExpiresIn,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// validateEmail checks basic email format using net/mail.
func validateEmail(email string) error {
	_, err := mail.ParseAddress(email)
	if err != nil {
		return ErrInvalidEmail
	}
	return nil
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: message,
		Code:  code,
	})
}
