package auth

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// PGCredentialStore implements CredentialStore backed by PostgreSQL
// with AES-256-GCM encryption for credential data.
//
// If no encryption key is provided, credentials are stored in base64 encoding
// (not plaintext) with a loud warning.
type PGCredentialStore struct {
	db         *sql.DB
	passphrase string
	mu         sync.RWMutex
}

// NewPGCredentialStore creates a PostgreSQL-backed credential store using the
// provided *sql.DB. If encryptionKey is empty, credentials are stored without
// encryption (a warning is logged).
func NewPGCredentialStore(db *sql.DB, encryptionKey string) (*PGCredentialStore, error) {
	if db == nil {
		return nil, fmt.Errorf("pg credential store: db is nil")
	}
	if err := initPGCredentialSchema(db); err != nil {
		return nil, fmt.Errorf("pg credential store: init schema: %w", err)
	}

	if encryptionKey == "" {
		log.Println("WARNING: OPERATOR_ENCRYPTION_KEY not set. Credentials will be stored without encryption. " +
			"Set OPERATOR_ENCRYPTION_KEY environment variable for at-rest encryption.")
	}

	return &PGCredentialStore{
		db:         db,
		passphrase: encryptionKey,
	}, nil
}

func initPGCredentialSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS credentials (
    provider        TEXT PRIMARY KEY,
    encrypted_data  BYTEA NOT NULL,
    encrypted       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
`
	_, err := db.Exec(schema)
	return err
}

// Get returns the credential for the given provider, or nil if not found.
func (s *PGCredentialStore) Get(provider string) (*AuthCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var data []byte
	var encrypted bool
	err := s.db.QueryRow(
		`SELECT encrypted_data, encrypted FROM credentials WHERE provider = $1`, provider,
	).Scan(&data, &encrypted)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("query credential %q: %w", provider, err)
	}

	plaintext, err := s.decrypt(data, encrypted)
	if err != nil {
		return nil, fmt.Errorf("decrypt credential %q: %w", provider, err)
	}

	var cred AuthCredential
	if err := json.Unmarshal(plaintext, &cred); err != nil {
		return nil, fmt.Errorf("unmarshal credential %q: %w", provider, err)
	}
	return &cred, nil
}

// Set stores (or updates) the credential for the given provider.
func (s *PGCredentialStore) Set(provider string, cred *AuthCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	plaintext, err := json.Marshal(cred)
	if err != nil {
		return fmt.Errorf("marshal credential: %w", err)
	}

	data, isEncrypted, err := s.encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt credential: %w", err)
	}

	now := time.Now()
	_, err = s.db.Exec(
		`INSERT INTO credentials (provider, encrypted_data, encrypted, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT(provider) DO UPDATE SET
		     encrypted_data = EXCLUDED.encrypted_data,
		     encrypted = EXCLUDED.encrypted,
		     updated_at = EXCLUDED.updated_at`,
		provider, data, isEncrypted, now, now,
	)
	if err != nil {
		return fmt.Errorf("upsert credential %q: %w", provider, err)
	}
	return nil
}

// Delete removes the credential for the given provider.
func (s *PGCredentialStore) Delete(provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM credentials WHERE provider = $1`, provider)
	if err != nil {
		return fmt.Errorf("delete credential %q: %w", provider, err)
	}
	return nil
}

// DeleteAll removes all stored credentials.
func (s *PGCredentialStore) DeleteAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM credentials`)
	if err != nil {
		return fmt.Errorf("delete all credentials: %w", err)
	}
	return nil
}

// List returns all stored credentials keyed by provider name.
func (s *PGCredentialStore) List() (map[string]*AuthCredential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`SELECT provider, encrypted_data, encrypted FROM credentials`)
	if err != nil {
		return nil, fmt.Errorf("query credentials: %w", err)
	}
	defer rows.Close()

	result := make(map[string]*AuthCredential)
	for rows.Next() {
		var provider string
		var data []byte
		var encrypted bool
		if err := rows.Scan(&provider, &data, &encrypted); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}

		plaintext, err := s.decrypt(data, encrypted)
		if err != nil {
			return nil, fmt.Errorf("decrypt credential %q: %w", provider, err)
		}

		var cred AuthCredential
		if err := json.Unmarshal(plaintext, &cred); err != nil {
			return nil, fmt.Errorf("unmarshal credential %q: %w", provider, err)
		}
		result[provider] = &cred
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate credentials: %w", err)
	}

	return result, nil
}

// Close is a no-op — the caller owns the *sql.DB and is responsible for closing it.
func (s *PGCredentialStore) Close() error {
	return nil
}

func (s *PGCredentialStore) encrypt(plaintext []byte) ([]byte, bool, error) {
	if s.passphrase == "" {
		encoded := make([]byte, base64.StdEncoding.EncodedLen(len(plaintext)))
		base64.StdEncoding.Encode(encoded, plaintext)
		return encoded, false, nil
	}

	encrypted, err := encryptAESGCM(plaintext, s.passphrase)
	if err != nil {
		return nil, false, err
	}
	return encrypted, true, nil
}

func (s *PGCredentialStore) decrypt(data []byte, encrypted bool) ([]byte, error) {
	if !encrypted {
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
		n, err := base64.StdEncoding.Decode(decoded, data)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return decoded[:n], nil
	}

	if s.passphrase == "" {
		return nil, fmt.Errorf("credential is encrypted but no encryption key is configured (set OPERATOR_ENCRYPTION_KEY)")
	}

	return decryptAESGCM(data, s.passphrase)
}
