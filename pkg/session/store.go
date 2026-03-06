package session

import "github.com/standardws/operator/pkg/providers"

// SessionStore abstracts the persistence layer for session data.
// Implementations must be safe for concurrent use.
type SessionStore interface {
	// GetOrCreate returns the session for the given key, creating it if it doesn't exist.
	GetOrCreate(key string) (*Session, error)

	// AddMessage appends a message to the session's history.
	AddMessage(key string, msg providers.Message) error

	// GetHistory returns a copy of all messages for the session.
	GetHistory(key string) ([]providers.Message, error)

	// GetSummary returns the conversation summary for the session.
	GetSummary(key string) (string, error)

	// SetSummary updates the conversation summary for the session.
	SetSummary(key string, summary string) error

	// SetHistory replaces the entire message history for the session.
	SetHistory(key string, messages []providers.Message) error

	// TruncateHistory removes all but the last keepLast messages.
	TruncateHistory(key string, keepLast int) error

	// Save persists the session data. For stores that write-through (like SQLite),
	// this may be a no-op.
	Save(key string) error

	// Close releases any resources held by the store.
	Close() error
}
