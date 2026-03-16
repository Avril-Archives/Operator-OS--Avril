package agents

import (
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// PGUserAgentStore implements UserAgentStore backed by PostgreSQL.
type PGUserAgentStore struct {
	db *sql.DB
	mu sync.RWMutex
}

// NewPGUserAgentStore creates a PostgreSQL-backed agent store using the provided *sql.DB.
// It initialises the schema (user_agents table) if not present.
func NewPGUserAgentStore(db *sql.DB) (*PGUserAgentStore, error) {
	if db == nil {
		return nil, fmt.Errorf("pg agent store: db is nil")
	}
	if err := initPGUserAgentsSchema(db); err != nil {
		return nil, fmt.Errorf("pg agent store: init schema: %w", err)
	}
	return &PGUserAgentStore{db: db}, nil
}

func initPGUserAgentsSchema(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS user_agents (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    name            TEXT NOT NULL,
    description     TEXT NOT NULL DEFAULT '',
    system_prompt   TEXT NOT NULL DEFAULT '',
    model           TEXT NOT NULL DEFAULT '',
    model_fallbacks TEXT NOT NULL DEFAULT '[]',
    tools           TEXT NOT NULL DEFAULT '[]',
    skills          TEXT NOT NULL DEFAULT '[]',
    max_tokens      INTEGER NOT NULL DEFAULT 0,
    temperature     DOUBLE PRECISION DEFAULT NULL,
    max_iterations  INTEGER NOT NULL DEFAULT 0,
    is_default      BOOLEAN NOT NULL DEFAULT FALSE,
    status          TEXT NOT NULL DEFAULT 'active',
    allowed_integrations TEXT NOT NULL DEFAULT '[]',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_agents_user_id ON user_agents(user_id);
CREATE INDEX IF NOT EXISTS idx_user_agents_user_default ON user_agents(user_id, is_default);
DO $$ BEGIN
    CREATE UNIQUE INDEX idx_user_agents_user_name ON user_agents(user_id, name);
EXCEPTION WHEN duplicate_table THEN NULL;
END $$;
`
	_, err := db.Exec(schema)
	return err
}

// Create inserts a new agent. Generates a UUID if agent.ID is empty.
func (s *PGUserAgentStore) Create(agent *UserAgent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}

	now := time.Now()
	agent.CreatedAt = now
	agent.UpdatedAt = now

	if agent.Status == "" {
		agent.Status = AgentStatusActive
	}

	fallbacksJSON := marshalStringSlice(agent.ModelFallbacks)
	toolsJSON := marshalStringSlice(agent.Tools)
	skillsJSON := marshalStringSlice(agent.Skills)
	integrationsJSON := marshalIntegrationScopes(agent.AllowedIntegrations)

	var tempVal sql.NullFloat64
	if agent.Temperature != nil {
		tempVal = sql.NullFloat64{Float64: *agent.Temperature, Valid: true}
	}

	_, err := s.db.Exec(
		`INSERT INTO user_agents (id, user_id, name, description, system_prompt, model,
		 model_fallbacks, tools, skills, max_tokens, temperature, max_iterations,
		 is_default, status, allowed_integrations, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		agent.ID,
		agent.UserID,
		agent.Name,
		agent.Description,
		agent.SystemPrompt,
		agent.Model,
		fallbacksJSON,
		toolsJSON,
		skillsJSON,
		agent.MaxTokens,
		tempVal,
		agent.MaxIterations,
		agent.IsDefault,
		agent.Status,
		integrationsJSON,
		now,
		now,
	)
	if err != nil {
		if isPGUniqueViolation(err) {
			return ErrNameExists
		}
		return fmt.Errorf("insert agent: %w", err)
	}

	return nil
}

// GetByID returns the agent with the given ID.
func (s *PGUserAgentStore) GetByID(id string) (*UserAgent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.getBy("id", "$1", id)
}

func (s *PGUserAgentStore) getBy(column, placeholder, value string) (*UserAgent, error) {
	query := fmt.Sprintf(
		`SELECT id, user_id, name, description, system_prompt, model,
		 model_fallbacks, tools, skills, max_tokens, temperature, max_iterations,
		 is_default, status, allowed_integrations, created_at, updated_at
		 FROM user_agents WHERE %s = %s`, column, placeholder,
	)

	var a UserAgent
	var fallbacksJSON, toolsJSON, skillsJSON string
	var integrationsJSON sql.NullString
	var tempVal sql.NullFloat64

	err := s.db.QueryRow(query, value).Scan(
		&a.ID, &a.UserID, &a.Name, &a.Description, &a.SystemPrompt, &a.Model,
		&fallbacksJSON, &toolsJSON, &skillsJSON,
		&a.MaxTokens, &tempVal, &a.MaxIterations,
		&a.IsDefault, &a.Status, &integrationsJSON, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query agent by %s: %w", column, err)
	}

	a.ModelFallbacks = unmarshalStringSlice(fallbacksJSON)
	a.Tools = unmarshalStringSlice(toolsJSON)
	a.Skills = unmarshalStringSlice(skillsJSON)
	if integrationsJSON.Valid {
		a.AllowedIntegrations = unmarshalIntegrationScopes(integrationsJSON.String)
	}
	if tempVal.Valid {
		a.Temperature = &tempVal.Float64
	}

	return &a, nil
}

// Update saves changes to an existing agent.
func (s *PGUserAgentStore) Update(agent *UserAgent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent.UpdatedAt = time.Now()

	fallbacksJSON := marshalStringSlice(agent.ModelFallbacks)
	toolsJSON := marshalStringSlice(agent.Tools)
	skillsJSON := marshalStringSlice(agent.Skills)
	integrationsJSON := marshalIntegrationScopes(agent.AllowedIntegrations)

	var tempVal sql.NullFloat64
	if agent.Temperature != nil {
		tempVal = sql.NullFloat64{Float64: *agent.Temperature, Valid: true}
	}

	res, err := s.db.Exec(
		`UPDATE user_agents SET name = $1, description = $2, system_prompt = $3, model = $4,
		 model_fallbacks = $5, tools = $6, skills = $7, max_tokens = $8, temperature = $9,
		 max_iterations = $10, is_default = $11, status = $12, allowed_integrations = $13, updated_at = $14
		 WHERE id = $15`,
		agent.Name,
		agent.Description,
		agent.SystemPrompt,
		agent.Model,
		fallbacksJSON,
		toolsJSON,
		skillsJSON,
		agent.MaxTokens,
		tempVal,
		agent.MaxIterations,
		agent.IsDefault,
		agent.Status,
		integrationsJSON,
		agent.UpdatedAt,
		agent.ID,
	)
	if err != nil {
		if isPGUniqueViolation(err) {
			return ErrNameExists
		}
		return fmt.Errorf("update agent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// Delete removes an agent by ID.
func (s *PGUserAgentStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	res, err := s.db.Exec(`DELETE FROM user_agents WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete agent: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAgentNotFound
	}
	return nil
}

// ListByUser returns all agents for a user, ordered by created_at ascending.
func (s *PGUserAgentStore) ListByUser(userID string) ([]*UserAgent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		`SELECT id, user_id, name, description, system_prompt, model,
		 model_fallbacks, tools, skills, max_tokens, temperature, max_iterations,
		 is_default, status, allowed_integrations, created_at, updated_at
		 FROM user_agents WHERE user_id = $1 ORDER BY created_at ASC`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()

	var agents []*UserAgent
	for rows.Next() {
		a, err := scanPGAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agents: %w", err)
	}

	if agents == nil {
		agents = []*UserAgent{}
	}
	return agents, nil
}

// CountByUser returns the number of agents a user has.
func (s *PGUserAgentStore) CountByUser(userID string) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM user_agents WHERE user_id = $1`, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count agents: %w", err)
	}
	return count, nil
}

// GetDefault returns the user's default agent.
func (s *PGUserAgentStore) GetDefault(userID string) (*UserAgent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var a UserAgent
	var fallbacksJSON, toolsJSON, skillsJSON string
	var integrationsJSON sql.NullString
	var tempVal sql.NullFloat64

	err := s.db.QueryRow(
		`SELECT id, user_id, name, description, system_prompt, model,
		 model_fallbacks, tools, skills, max_tokens, temperature, max_iterations,
		 is_default, status, allowed_integrations, created_at, updated_at
		 FROM user_agents WHERE user_id = $1 AND is_default = TRUE`, userID,
	).Scan(
		&a.ID, &a.UserID, &a.Name, &a.Description, &a.SystemPrompt, &a.Model,
		&fallbacksJSON, &toolsJSON, &skillsJSON,
		&a.MaxTokens, &tempVal, &a.MaxIterations,
		&a.IsDefault, &a.Status, &integrationsJSON, &a.CreatedAt, &a.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("query default agent: %w", err)
	}

	a.ModelFallbacks = unmarshalStringSlice(fallbacksJSON)
	a.Tools = unmarshalStringSlice(toolsJSON)
	a.Skills = unmarshalStringSlice(skillsJSON)
	if integrationsJSON.Valid {
		a.AllowedIntegrations = unmarshalIntegrationScopes(integrationsJSON.String)
	}
	if tempVal.Valid {
		a.Temperature = &tempVal.Float64
	}

	return &a, nil
}

// SetDefault marks one agent as default and clears the flag on all others
// for the same user. Both operations run in a transaction.
func (s *PGUserAgentStore) SetDefault(userID, agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Verify agent exists and belongs to user.
	var ownerID string
	err = tx.QueryRow(`SELECT user_id FROM user_agents WHERE id = $1`, agentID).Scan(&ownerID)
	if err == sql.ErrNoRows {
		return ErrAgentNotFound
	}
	if err != nil {
		return fmt.Errorf("check agent owner: %w", err)
	}
	if ownerID != userID {
		return ErrAgentNotFound
	}

	// Clear all defaults for this user.
	if _, err := tx.Exec(`UPDATE user_agents SET is_default = FALSE WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("clear defaults: %w", err)
	}

	// Set the new default.
	if _, err := tx.Exec(`UPDATE user_agents SET is_default = TRUE WHERE id = $1`, agentID); err != nil {
		return fmt.Errorf("set default: %w", err)
	}

	return tx.Commit()
}

// Close is a no-op — the caller owns the *sql.DB and is responsible for closing it.
func (s *PGUserAgentStore) Close() error {
	return nil
}

// scanPGAgent scans a single row into a UserAgent (PostgreSQL variant).
func scanPGAgent(rows *sql.Rows) (*UserAgent, error) {
	var a UserAgent
	var fallbacksJSON, toolsJSON, skillsJSON string
	var integrationsJSON sql.NullString
	var tempVal sql.NullFloat64

	if err := rows.Scan(
		&a.ID, &a.UserID, &a.Name, &a.Description, &a.SystemPrompt, &a.Model,
		&fallbacksJSON, &toolsJSON, &skillsJSON,
		&a.MaxTokens, &tempVal, &a.MaxIterations,
		&a.IsDefault, &a.Status, &integrationsJSON, &a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan agent: %w", err)
	}

	a.ModelFallbacks = unmarshalStringSlice(fallbacksJSON)
	a.Tools = unmarshalStringSlice(toolsJSON)
	a.Skills = unmarshalStringSlice(skillsJSON)
	if integrationsJSON.Valid {
		a.AllowedIntegrations = unmarshalIntegrationScopes(integrationsJSON.String)
	}
	if tempVal.Valid {
		a.Temperature = &tempVal.Float64
	}

	return &a, nil
}

// isPGUniqueViolation checks if a PostgreSQL error is a unique constraint violation.
func isPGUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "duplicate key value violates unique constraint") ||
		strings.Contains(err.Error(), "UNIQUE constraint failed")
}
