// Package audit provides structured audit logging for security-relevant events.
//
// Audit events track authentication attempts, tool executions, configuration
// changes, and administrative actions. Each event includes the actor, action,
// resource, and contextual metadata (IP, user agent, etc.).
package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// Action constants define the types of auditable events.
const (
	// Authentication actions
	ActionLogin              = "auth.login"
	ActionLoginFailed        = "auth.login_failed"
	ActionLogout             = "auth.logout"
	ActionRegister           = "auth.register"
	ActionTokenRefresh       = "auth.token_refresh"
	ActionEmailVerified      = "auth.email_verified"
	ActionPasswordChanged    = "auth.password_changed"

	// Agent actions
	ActionAgentCreated       = "agent.created"
	ActionAgentUpdated       = "agent.updated"
	ActionAgentDeleted       = "agent.deleted"
	ActionAgentDefaultSet    = "agent.default_set"

	// Tool execution actions
	ActionToolExecuted       = "tool.executed"
	ActionToolFailed         = "tool.failed"

	// Configuration actions
	ActionConfigUpdated      = "config.updated"
	ActionPlanChanged        = "config.plan_changed"

	// Admin actions
	ActionUserSuspended      = "admin.user_suspended"
	ActionUserActivated      = "admin.user_activated"
	ActionUserDeleted        = "admin.user_deleted"
)

// Status constants for event outcomes.
const (
	StatusSuccess = "success"
	StatusFailure = "failure"
)

// Resource constants identify the type of resource affected.
const (
	ResourceUser    = "user"
	ResourceAgent   = "agent"
	ResourceTool    = "tool"
	ResourceConfig  = "config"
	ResourceSession = "session"
)

// Event represents a single audit log entry.
type Event struct {
	ID         string            `json:"id"`
	Timestamp  time.Time         `json:"timestamp"`
	UserID     string            `json:"user_id,omitempty"`
	Actor      string            `json:"actor,omitempty"`
	Action     string            `json:"action"`
	Resource   string            `json:"resource,omitempty"`
	ResourceID string            `json:"resource_id,omitempty"`
	Detail     map[string]string `json:"detail,omitempty"`
	IPAddress  string            `json:"ip_address,omitempty"`
	UserAgent  string            `json:"user_agent,omitempty"`
	Status     string            `json:"status"`
	ErrorMsg   string            `json:"error_msg,omitempty"`
}

// NewEvent creates a new audit event with a generated ID and current timestamp.
func NewEvent(action string) *Event {
	return &Event{
		ID:        generateID(),
		Timestamp: time.Now().UTC(),
		Action:    action,
		Status:    StatusSuccess,
		Detail:    make(map[string]string),
	}
}

// WithUser sets the user ID on the event.
func (e *Event) WithUser(userID string) *Event {
	e.UserID = userID
	return e
}

// WithActor sets the actor (email or system identifier) on the event.
func (e *Event) WithActor(actor string) *Event {
	e.Actor = actor
	return e
}

// WithResource sets the resource type and ID on the event.
func (e *Event) WithResource(resource, resourceID string) *Event {
	e.Resource = resource
	e.ResourceID = resourceID
	return e
}

// WithDetail adds a key-value pair to the event's detail map.
func (e *Event) WithDetail(key, value string) *Event {
	if e.Detail == nil {
		e.Detail = make(map[string]string)
	}
	e.Detail[key] = value
	return e
}

// WithIPAddress sets the source IP on the event.
func (e *Event) WithIPAddress(ip string) *Event {
	e.IPAddress = ip
	return e
}

// WithUserAgent sets the user agent on the event.
func (e *Event) WithUserAgent(ua string) *Event {
	e.UserAgent = ua
	return e
}

// WithFailure marks the event as failed with an error message.
func (e *Event) WithFailure(errMsg string) *Event {
	e.Status = StatusFailure
	e.ErrorMsg = errMsg
	return e
}

// WithTimestamp overrides the event timestamp (useful for testing).
func (e *Event) WithTimestamp(t time.Time) *Event {
	e.Timestamp = t
	return e
}

// DetailJSON returns the detail map as a JSON string.
func (e *Event) DetailJSON() string {
	if len(e.Detail) == 0 {
		return "{}"
	}
	b, err := json.Marshal(e.Detail)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// QueryFilter specifies criteria for querying audit events.
type QueryFilter struct {
	UserID     string    `json:"user_id,omitempty"`
	Action     string    `json:"action,omitempty"`
	Resource   string    `json:"resource,omitempty"`
	ResourceID string    `json:"resource_id,omitempty"`
	Status     string    `json:"status,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	Until      time.Time `json:"until,omitempty"`
	Limit      int       `json:"limit,omitempty"`
	Offset     int       `json:"offset,omitempty"`
}

// AuditStore defines the interface for persisting and querying audit events.
type AuditStore interface {
	// Log records an audit event.
	Log(ctx context.Context, event *Event) error

	// Query retrieves audit events matching the given filter.
	Query(ctx context.Context, filter QueryFilter) ([]*Event, error)

	// Count returns the number of events matching the given filter.
	Count(ctx context.Context, filter QueryFilter) (int64, error)

	// DeleteBefore removes audit events older than the given timestamp.
	DeleteBefore(ctx context.Context, before time.Time) (int64, error)
}

// Logger provides a convenient interface for logging audit events.
// It wraps an AuditStore and handles errors via an optional error handler.
type Logger struct {
	store   AuditStore
	onError func(error)
}

// NewLogger creates a new audit Logger wrapping the given store.
func NewLogger(store AuditStore) *Logger {
	return &Logger{store: store}
}

// OnError sets an error handler for failed audit log attempts.
// If not set, errors are silently ignored to avoid disrupting the main flow.
func (l *Logger) OnError(fn func(error)) *Logger {
	l.onError = fn
	return l
}

// Log records an audit event, calling the error handler on failure.
func (l *Logger) Log(ctx context.Context, event *Event) {
	if err := l.store.Log(ctx, event); err != nil {
		if l.onError != nil {
			l.onError(fmt.Errorf("audit log: %w", err))
		}
	}
}

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("audit-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
