package worker

import (
	"time"
)

// Config configures a stateless worker instance.
type Config struct {
	// ID uniquely identifies this worker instance. Used for NATS consumer
	// prefixing and distributed tracing. Required.
	ID string

	// Concurrency is the number of messages to process in parallel.
	// Default: 1 (sequential processing).
	Concurrency int

	// ShutdownTimeout is how long to wait for in-flight messages to complete
	// during graceful shutdown. Default: 30s.
	ShutdownTimeout time.Duration

	// MaxRetries is the maximum number of times to retry a failed message
	// before sending it to the dead letter queue. Default: 3.
	MaxRetries int

	// ProcessTimeout is the maximum time allowed for processing a single
	// message (including LLM calls and tool execution). Default: 5m.
	ProcessTimeout time.Duration

	// HeartbeatInterval is how often the worker reports health status.
	// Default: 30s. Set to 0 to disable.
	HeartbeatInterval time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig(id string) Config {
	return Config{
		ID:                id,
		Concurrency:       1,
		ShutdownTimeout:   30 * time.Second,
		MaxRetries:        3,
		ProcessTimeout:    5 * time.Minute,
		HeartbeatInterval: 30 * time.Second,
	}
}

// validate checks that required fields are set and applies defaults.
func (c *Config) validate() {
	if c.Concurrency < 1 {
		c.Concurrency = 1
	}
	if c.ShutdownTimeout <= 0 {
		c.ShutdownTimeout = 30 * time.Second
	}
	if c.MaxRetries < 0 {
		c.MaxRetries = 0
	}
	if c.ProcessTimeout <= 0 {
		c.ProcessTimeout = 5 * time.Minute
	}
}
