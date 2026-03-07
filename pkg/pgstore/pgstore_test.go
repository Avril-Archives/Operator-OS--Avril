package pgstore

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig("postgres://localhost:5432/test")
	assert.Equal(t, "postgres://localhost:5432/test", cfg.DSN)
	assert.Equal(t, 25, cfg.MaxOpenConns)
	assert.Equal(t, 10, cfg.MaxIdleConns)
	assert.NotZero(t, cfg.ConnMaxLifetime)
	assert.NotZero(t, cfg.ConnMaxIdleTime)
}

func TestOpenEmptyDSN(t *testing.T) {
	_, err := Open(Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DSN is required")
}

func TestOpenInvalidDSN(t *testing.T) {
	// Attempting to connect to a non-existent server should fail at ping.
	_, err := Open(Config{DSN: "postgres://nonexistent:5432/test?connect_timeout=1"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pgstore:")
}
