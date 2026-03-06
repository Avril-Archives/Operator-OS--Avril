# CLAUDE.md — Operator OS Production Readiness

You are an autonomous coding agent working on **Operator OS**, an ultra-lightweight AI agent framework written in Go. Your mission is to make this platform production-ready for both self-hosted and managed SaaS deployment.

---

## Project Context

- **Repository:** `/tmp/Operator-OS` (or wherever this repo is cloned)
- **Language:** Go 1.25, CGO disabled (`CGO_ENABLED=0`)
- **Build:** `make build` → binary in `build/operator`
- **Test:** `make test` (or `go test ./...`)
- **Lint:** `golangci-lint run`
- **Current state:** Excellent single-user tool. NOT production-ready for multi-tenant SaaS.

### Key Documents
- `STATUS.md` — **READ THIS FIRST.** Current phase, tasks, progress. Update after every work session.
- `docs/assessment/Production-Readiness-Assessment.md` — Full technical assessment, architecture, gaps, roadmap.
- `docs/assessment/User-Onboarding-and-Service-Integration.md` — Product design for onboarding and integrations.

---

## How to Work

### Every Session

1. **Read `STATUS.md`** — find the current phase and the next TODO task
2. **Pick ONE task** — the highest-priority TODO in the current phase
3. **Implement it** — write code, tests, and update docs
4. **Run tests** — `make test` must pass. No regressions.
5. **Update `STATUS.md`** — mark task as ✅ Done, add notes, update phase progress percentage
6. **Commit** — descriptive commit message referencing the task ID (e.g., `F1: Replace JSON sessions with SQLite`)
7. **If the phase is complete** — update phase status to ✅ Done, move to next phase

### Task Completion Criteria

A task is done when:
- Code is written and compiles (`make build`)
- Tests pass (`make test`) with no regressions
- New code has tests (≥80% coverage for new packages)
- `STATUS.md` is updated
- Changes are committed

### When Stuck

- If a task is blocked by a missing dependency or design decision, **note it in STATUS.md** and move to the next task
- If tests fail and you can't fix them in 15 minutes, **revert and note the issue**
- If the scope of a task is larger than expected, **break it into subtasks** in STATUS.md
- Never break existing functionality. The existing test suite is your guardrail.

---

## Architecture Rules

### Package Structure

```
pkg/
├── agent/       # Agent loop, context builder, memory, registry
├── auth/        # OAuth, PKCE, credential store
├── bus/         # Message bus (currently in-memory channels)
├── channels/    # Messaging channels (Telegram, Discord, Slack, etc.)
├── config/      # Configuration loading and defaults
├── constants/   # Shared constants
├── cron/        # Cron scheduler
├── devices/     # Hardware device monitoring
├── fileutil/    # File utilities (atomic write)
├── health/      # Health check HTTP server
├── heartbeat/   # Heartbeat service
├── identity/    # Agent identity
├── logger/      # Logging (to be replaced with zerolog)
├── mcp/         # MCP server manager
├── media/       # Media file store
├── migrate/     # Config migration
├── providers/   # LLM providers (OpenAI, Anthropic, Gemini, etc.)
├── routing/     # Agent routing (7-level cascade)
├── session/     # Session manager
├── skills/      # Skill loader and registry
├── state/       # Persistent state manager
├── tools/       # Tool implementations (shell, FS, web, MCP, etc.)
├── utils/       # Shared utilities
└── voice/       # Voice transcription
```

### Design Principles

1. **Interface-first:** When replacing a component (e.g., JSON → SQLite), define an interface first, implement it, then swap. The existing API surface should not change.

2. **Incremental migration:** Never rewrite. Always wrap, extend, then swap. The existing test suite must pass at every commit.

3. **Single binary:** Operator OS ships as one binary. No external database required for self-hosted mode. SQLite is embedded. PostgreSQL is optional for SaaS mode.

4. **Build tags for deployment modes:**
   ```go
   // Self-hosted: SQLite, in-process bus, local encryption
   // SaaS: PostgreSQL, NATS, Vault/KMS
   ```

5. **Zero external dependencies for self-hosted:** The binary must remain self-contained. Database (SQLite) is already a pure Go dependency.

### Coding Standards

- **Go conventions:** Follow standard Go style. Run `golangci-lint`.
- **Error handling:** Always wrap errors with context: `fmt.Errorf("thing failed: %w", err)`
- **Logging:** Use the project's logger package (or zerolog after migration). Always include structured fields.
- **Concurrency:** Use `sync.Mutex` / `sync.RWMutex` appropriately. The bus package shows good patterns.
- **Testing:** Table-driven tests. Use `testify/assert` and `testify/require` (already a dependency).
- **File operations:** Use `fileutil.WriteFileAtomic` for any persistent writes.
- **Commit messages:** `TASK_ID: Short description` (e.g., `F1: Implement SQLite session store`)

---

## Phase 1 Implementation Guide

Phase 1 is the foundation. These are the specific implementation paths:

### F1: SQLite Session Store

**Goal:** Replace `pkg/session/manager.go` (JSON files) with SQLite.

```go
// pkg/session/store.go — New interface
type SessionStore interface {
    GetOrCreate(key string) (*Session, error)
    AddMessage(key string, msg providers.Message) error
    GetHistory(key string) ([]providers.Message, error)
    GetSummary(key string) (string, error)
    SetSummary(key string, summary string) error
    SetHistory(key string, messages []providers.Message) error
    TruncateHistory(key string, keepLast int) error
    Save(key string) error
}
```

Schema:
```sql
CREATE TABLE sessions (
    key         TEXT PRIMARY KEY,
    summary     TEXT DEFAULT '',
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE messages (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_key TEXT NOT NULL REFERENCES sessions(key),
    role        TEXT NOT NULL,
    content     TEXT DEFAULT '',
    tool_calls  TEXT DEFAULT '[]',      -- JSON array of tool calls
    tool_call_id TEXT DEFAULT '',
    reasoning   TEXT DEFAULT '',
    extra       TEXT DEFAULT '{}',      -- JSON for extensibility
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_messages_session ON messages(session_key);
```

Implementation path:
1. Create `pkg/session/sqlite_store.go`
2. Implement `SessionStore` interface
3. Create `pkg/session/sqlite_store_test.go`
4. Update `SessionManager` to use `SessionStore` interface
5. Add migration from JSON → SQLite (one-time)
6. Verify all existing session tests pass

### F2: SQLite State Store

**Goal:** Replace `pkg/state/state.go` (JSON file) with SQLite.

Use the same SQLite database as sessions. Add a `state` table:
```sql
CREATE TABLE state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### F3: Encrypted Auth Store

**Goal:** Replace `pkg/auth/store.go` (plaintext JSON) with encrypted SQLite.

```sql
CREATE TABLE credentials (
    provider        TEXT PRIMARY KEY,
    encrypted_data  BLOB NOT NULL,
    iv              BLOB NOT NULL,
    key_version     INTEGER DEFAULT 1,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

Encryption:
- Use `crypto/aes` + `crypto/cipher` (GCM mode)
- Key derived from `OPERATOR_ENCRYPTION_KEY` env var using Argon2id
- Fallback: if no encryption key set, warn loudly and store in base64 (not plaintext)

### F4: Structured Logging

**Goal:** Replace `pkg/logger/logger.go` with `zerolog`.

- `rs/zerolog` is already a transitive dependency
- Preserve the public API surface: `logger.InfoCF(component, message, fields)`
- Add `request_id` / `correlation_id` field propagated via context
- JSON output format for production, console format for development
- Log level configurable via env var `OPERATOR_LOG_LEVEL`

### F5: OpenTelemetry Metrics

**Goal:** Add Prometheus metrics endpoint.

Key metrics:
```go
// LLM
llm_request_duration_seconds     (histogram, labels: provider, model, status)
llm_tokens_total                 (counter, labels: provider, model, direction=in|out)
llm_errors_total                 (counter, labels: provider, model, error_type)

// Sessions
sessions_active                  (gauge)
sessions_messages_total          (counter)

// Bus
bus_messages_total               (counter, labels: direction=inbound|outbound)
bus_queue_depth                  (gauge, labels: direction)

// Tools
tool_execution_duration_seconds  (histogram, labels: tool_name, status)
tool_executions_total            (counter, labels: tool_name, status)

// Health
operator_uptime_seconds          (gauge)
operator_info                    (gauge, labels: version, go_version)
```

Register on the health server mux at `/metrics`.

---

## Important Patterns in the Codebase

### Message Flow
```
Channel → bus.PublishInbound → AgentLoop.Run() consumes →
  processMessage → routing → runAgentLoop →
    buildMessages → LLM call → tool execution loop →
      bus.PublishOutbound → Channel sends response
```

### Provider Fallback
The `providers.FallbackChain` handles provider failures:
- `FallbackCandidate` list built from model config
- `CooldownTracker` tracks recently-failed providers
- Error classifier (`error_classifier.go`) categorizes failures for retry decisions

### Tool Execution
Tools implement `tools.Tool` interface. Registered in `tools.ToolRegistry`.
Results return `ToolResult` with `ForLLM` (goes back to model) and `ForUser` (sent to user).

### Session Summarization
When history exceeds threshold (20 messages or 75% of context window):
- Oldest messages summarized via LLM call
- Summary stored, old messages truncated
- Emergency compression drops 50% on context window errors

---

## What NOT to Change

- **Do not change the CLI interface** (`operator gateway`, `operator agent`, etc.)
- **Do not change the config file format** — only add new fields with defaults
- **Do not remove any existing channel implementations**
- **Do not change the workspace file structure** for existing self-hosted users
- **Do not add required external services** for self-hosted mode (SQLite only)
- **Do not break the <10MB RAM promise** for self-hosted single-user mode

---

## Testing

```bash
# Run all tests
make test

# Run specific package tests
go test ./pkg/session/... -v
go test ./pkg/state/... -v
go test ./pkg/auth/... -v

# Run with race detection
go test -race ./...

# Run with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

---

## Commit Convention

```
TASK_ID: Short description

Longer description if needed.

- Bullet points for specific changes
- Reference related tasks if applicable
```

Examples:
```
F1: Implement SQLite session store

Replace JSON file-based session storage with SQLite using modernc.org/sqlite.
Introduces SessionStore interface for pluggable backends.

- Add pkg/session/store.go (interface)
- Add pkg/session/sqlite_store.go (implementation)
- Add pkg/session/sqlite_store_test.go
- Update SessionManager to use SessionStore
- Migrate existing JSON sessions on first run
```
