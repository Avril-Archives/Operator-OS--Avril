package health

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SQLiteCheck returns a checker function for a SQLite database.
func SQLiteCheck(db *sql.DB) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		if db == nil {
			return CheckResult{Status: StatusUnhealthy, Message: "database is nil"}
		}

		if err := db.PingContext(ctx); err != nil {
			return CheckResult{Status: StatusUnhealthy, Message: fmt.Sprintf("ping failed: %v", err)}
		}

		// Check WAL mode (recommended for concurrent access).
		var mode string
		err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode)
		if err != nil {
			return CheckResult{
				Status:  StatusDegraded,
				Message: fmt.Sprintf("cannot read journal_mode: %v", err),
			}
		}

		details := map[string]any{
			"journal_mode": mode,
		}

		// Get page count for size estimation.
		var pageCount, pageSize int64
		if err := db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pageCount); err == nil {
			if err := db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); err == nil {
				details["size_bytes"] = pageCount * pageSize
			}
		}

		return CheckResult{Status: StatusHealthy, Message: "ok", Details: details}
	}
}

// PostgreSQLCheck returns a checker function for a PostgreSQL database.
func PostgreSQLCheck(db *sql.DB) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		if db == nil {
			return CheckResult{Status: StatusUnhealthy, Message: "database is nil"}
		}

		if err := db.PingContext(ctx); err != nil {
			return CheckResult{Status: StatusUnhealthy, Message: fmt.Sprintf("ping failed: %v", err)}
		}

		details := map[string]any{}

		// Connection pool stats.
		stats := db.Stats()
		details["open_connections"] = stats.OpenConnections
		details["in_use"] = stats.InUse
		details["idle"] = stats.Idle
		details["max_open"] = stats.MaxOpenConnections

		// Check if approaching connection limit.
		if stats.MaxOpenConnections > 0 {
			usage := float64(stats.InUse) / float64(stats.MaxOpenConnections)
			if usage > 0.9 {
				return CheckResult{
					Status:  StatusDegraded,
					Message: fmt.Sprintf("connection pool %.0f%% utilized", usage*100),
					Details: details,
				}
			}
		}

		// Server version.
		var version string
		if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&version); err == nil {
			details["version"] = version
		}

		return CheckResult{Status: StatusHealthy, Message: "ok", Details: details}
	}
}

// Pinger is implemented by types that support Ping() for health checks (e.g., Redis).
type Pinger interface {
	Ping() error
}

// PingerCheck returns a checker function for any Pinger implementation.
func PingerCheck(name string, p Pinger) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		if p == nil {
			return CheckResult{Status: StatusUnhealthy, Message: fmt.Sprintf("%s client is nil", name)}
		}

		if err := p.Ping(); err != nil {
			return CheckResult{Status: StatusUnhealthy, Message: fmt.Sprintf("ping failed: %v", err)}
		}

		return CheckResult{Status: StatusHealthy, Message: "ok"}
	}
}

// NATSChecker is satisfied by types that expose a NATS connection for health checks.
type NATSChecker interface {
	// IsConnected returns true if the NATS connection is active.
	IsConnected() bool
}

// NATSCheck returns a checker function for a NATS connection.
func NATSCheck(nc NATSChecker) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		if nc == nil {
			return CheckResult{Status: StatusUnhealthy, Message: "NATS client is nil"}
		}

		if !nc.IsConnected() {
			return CheckResult{Status: StatusUnhealthy, Message: "NATS disconnected"}
		}

		return CheckResult{Status: StatusHealthy, Message: "ok"}
	}
}

// CustomCheck creates a simple checker from a function that returns (ok, message).
// This is a convenience wrapper for simple pass/fail checks.
func CustomCheck(fn func() (bool, string)) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		ok, msg := fn()
		if ok {
			return CheckResult{Status: StatusHealthy, Message: msg}
		}
		return CheckResult{Status: StatusUnhealthy, Message: msg}
	}
}

// CompositeCheck creates a checker that runs multiple sub-checks and aggregates results.
func CompositeCheck(checks map[string]CheckerFunc) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		details := map[string]any{}
		overall := StatusHealthy

		for name, check := range checks {
			result := check(ctx)
			details[name] = map[string]any{
				"status":  string(result.Status),
				"message": result.Message,
			}

			switch result.Status {
			case StatusUnhealthy, StatusUnknown:
				overall = StatusUnhealthy
			case StatusDegraded:
				if overall == StatusHealthy {
					overall = StatusDegraded
				}
			}
		}

		msg := "all sub-checks passed"
		if overall != StatusHealthy {
			msg = "one or more sub-checks failed"
		}

		return CheckResult{Status: overall, Message: msg, Details: details}
	}
}

// ChannelStatusChecker is satisfied by messaging channels that expose IsRunning().
type ChannelStatusChecker interface {
	IsRunning() bool
}

// ChannelCheck returns a checker function for a messaging channel.
// It reports healthy if the channel is running, unhealthy otherwise.
func ChannelCheck(name string, ch ChannelStatusChecker) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		if ch == nil {
			return CheckResult{Status: StatusUnhealthy, Message: fmt.Sprintf("%s channel is nil", name)}
		}
		if !ch.IsRunning() {
			return CheckResult{Status: StatusUnhealthy, Message: fmt.Sprintf("%s channel is not running", name)}
		}
		return CheckResult{Status: StatusHealthy, Message: "ok", Details: map[string]any{"channel": name}}
	}
}

// TimeoutCheck wraps a checker function with a specific timeout.
// The check returns unhealthy if it doesn't complete within the given duration.
func TimeoutCheck(timeout time.Duration, fn CheckerFunc) CheckerFunc {
	return func(ctx context.Context) CheckResult {
		childCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()

		resultCh := make(chan CheckResult, 1)
		go func() {
			resultCh <- fn(childCtx)
		}()

		select {
		case result := <-resultCh:
			return result
		case <-childCtx.Done():
			return CheckResult{
				Status:  StatusUnhealthy,
				Message: fmt.Sprintf("check timed out after %s", timeout),
			}
		}
	}
}
