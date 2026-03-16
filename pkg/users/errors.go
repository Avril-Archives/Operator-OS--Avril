package users

import "errors"

var (
	// ErrNotFound is returned when a user lookup finds no matching record.
	ErrNotFound = errors.New("user not found")
	// ErrEmailExists is returned when attempting to create a user with a
	// duplicate email address.
	ErrEmailExists = errors.New("email already registered")
	// ErrInvalidEmail is returned when the email format is invalid.
	ErrInvalidEmail = errors.New("invalid email address")
	// ErrWeakPassword is returned when the password does not meet minimum
	// strength requirements.
	ErrWeakPassword = errors.New("password must be at least 8 characters and include uppercase, lowercase, digit, and special character")
)
