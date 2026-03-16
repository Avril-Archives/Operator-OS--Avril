package users

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("Test@Pass1")
	require.NoError(t, err)
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, "Test@Pass1", hash)
	// bcrypt hashes start with $2a$ or $2b$.
	assert.Contains(t, hash, "$2a$")
}

func TestCheckPassword_Match(t *testing.T) {
	hash, err := HashPassword("Correct@Pass1")
	require.NoError(t, err)
	assert.NoError(t, CheckPassword(hash, "Correct@Pass1"))
}

func TestCheckPassword_Mismatch(t *testing.T) {
	hash, err := HashPassword("Correct@Pass1")
	require.NoError(t, err)
	assert.Error(t, CheckPassword(hash, "Wrong@Pass1"))
}

func TestValidatePassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{"valid complex", "Abcdef1!", false},
		{"valid long complex", "MyP@ssw0rd123", false},
		{"too short", "Ab1!xyz", true},
		{"empty", "", true},
		{"one char", "a", true},
		{"no uppercase", "abcdef1!", true},
		{"no lowercase", "ABCDEF1!", true},
		{"no digit", "Abcdefg!", true},
		{"no special", "Abcdefg1", true},
		{"only lowercase long", "abcdefghij", true},
		{"only digits", "12345678", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassword(tt.password)
			if tt.wantErr {
				assert.ErrorIs(t, err, ErrWeakPassword)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
