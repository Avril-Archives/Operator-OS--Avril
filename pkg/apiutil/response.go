// Package apiutil provides shared HTTP API response helpers for consistent
// error formatting across all REST endpoints.
package apiutil

import (
	"encoding/json"
	"net/http"
)

// ErrorResponse is the standard error response format for all API endpoints.
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// WriteError sends a JSON error response with the given status code, error code, and message.
func WriteError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error: message,
		Code:  code,
	})
}

// WriteJSON sends a JSON response with the given status code and value.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
