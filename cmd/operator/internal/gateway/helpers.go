package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"database/sql"

	_ "modernc.org/sqlite"

	"github.com/operatoronline/Operator-OS/cmd/operator/internal"
	"github.com/operatoronline/Operator-OS/pkg/admin"
	"github.com/operatoronline/Operator-OS/pkg/agent"
	"github.com/operatoronline/Operator-OS/pkg/agents"
	"github.com/operatoronline/Operator-OS/pkg/audit"
	"github.com/operatoronline/Operator-OS/pkg/billing"
	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/channels"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/dingtalk"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/discord"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/feishu"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/line"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/maixcam"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/onebot"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/operator"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/qq"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/slack"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/telegram"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/wecom"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/whatsapp"
	_ "github.com/operatoronline/Operator-OS/pkg/channels/whatsapp_native"
	"github.com/operatoronline/Operator-OS/pkg/config"
	"github.com/operatoronline/Operator-OS/pkg/cron"
	"github.com/operatoronline/Operator-OS/pkg/devices"
	"github.com/operatoronline/Operator-OS/pkg/health"
	"github.com/operatoronline/Operator-OS/pkg/heartbeat"
	"github.com/operatoronline/Operator-OS/pkg/logger"
	"github.com/operatoronline/Operator-OS/pkg/media"
	"github.com/operatoronline/Operator-OS/pkg/metrics"
	"github.com/operatoronline/Operator-OS/pkg/providers"
	"github.com/operatoronline/Operator-OS/pkg/ratelimit"
	"github.com/operatoronline/Operator-OS/pkg/secaudit"
	"github.com/operatoronline/Operator-OS/pkg/state"
	"github.com/operatoronline/Operator-OS/pkg/tools"
	"github.com/operatoronline/Operator-OS/pkg/users"
)

func gatewayCmd(debug bool) error {
	if debug {
		logger.SetLevel(logger.DEBUG)
		fmt.Println("🔍 Debug mode enabled")
	}

	cfg, err := internal.LoadConfig()
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	// Validate config schema before proceeding.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("config validation error: %w", err)
	}

	provider, modelID, err := providers.CreateProvider(cfg)
	if err != nil {
		return fmt.Errorf("error creating provider: %w", err)
	}

	// Use the resolved model ID from provider creation
	if modelID != "" {
		cfg.Agents.Defaults.ModelName = modelID
	}

	msgBus := bus.NewMessageBus()
	agentLoop := agent.NewAgentLoop(cfg, msgBus, provider)

	// Print agent startup info
	fmt.Println("\n📦 Agent Status:")
	startupInfo := agentLoop.GetStartupInfo()
	toolsInfo := startupInfo["tools"].(map[string]any)
	skillsInfo := startupInfo["skills"].(map[string]any)
	fmt.Printf("  • Tools: %d loaded\n", toolsInfo["count"])
	fmt.Printf("  • Skills: %d/%d available\n",
		skillsInfo["available"],
		skillsInfo["total"])

	// Log to file as well
	logger.InfoCF("agent", "Agent initialized",
		map[string]any{
			"tools_count":      toolsInfo["count"],
			"skills_total":     skillsInfo["total"],
			"skills_available": skillsInfo["available"],
		})

	// Setup cron tool and service
	execTimeout := time.Duration(cfg.Tools.Cron.ExecTimeoutMinutes) * time.Minute
	cronService := setupCronTool(
		agentLoop,
		msgBus,
		cfg.WorkspacePath(),
		cfg.Agents.Defaults.RestrictToWorkspace,
		execTimeout,
		cfg,
	)

	heartbeatService := heartbeat.NewHeartbeatService(
		cfg.WorkspacePath(),
		cfg.Heartbeat.Interval,
		cfg.Heartbeat.Enabled,
	)
	heartbeatService.SetBus(msgBus)
	heartbeatService.SetHandler(func(prompt, channel, chatID string) *tools.ToolResult {
		// Use cli:direct as fallback if no valid channel
		if channel == "" || chatID == "" {
			channel, chatID = "cli", "direct"
		}
		// Use ProcessHeartbeat - no session history, each heartbeat is independent
		var response string
		response, err = agentLoop.ProcessHeartbeat(context.Background(), prompt, channel, chatID)
		if err != nil {
			return tools.ErrorResult(fmt.Sprintf("Heartbeat error: %v", err))
		}
		if response == "HEARTBEAT_OK" {
			return tools.SilentResult("Heartbeat OK")
		}
		// For heartbeat, always return silent - the subagent result will be
		// sent to user via processSystemMessage when the async task completes
		return tools.SilentResult(response)
	})

	// Create media store for file lifecycle management with TTL cleanup
	mediaStore := media.NewFileMediaStoreWithCleanup(media.MediaCleanerConfig{
		Enabled:  cfg.Tools.MediaCleanup.Enabled,
		MaxAge:   time.Duration(cfg.Tools.MediaCleanup.MaxAge) * time.Minute,
		Interval: time.Duration(cfg.Tools.MediaCleanup.Interval) * time.Minute,
	})
	mediaStore.Start()

	channelManager, err := channels.NewManager(cfg, msgBus, mediaStore)
	if err != nil {
		mediaStore.Stop()
		return fmt.Errorf("error creating channel manager: %w", err)
	}

	// Inject channel manager and media store into agent loop
	agentLoop.SetChannelManager(channelManager)
	agentLoop.SetMediaStore(mediaStore)

	enabledChannels := channelManager.GetEnabledChannels()
	if len(enabledChannels) > 0 {
		fmt.Printf("✓ Channels enabled: %s\n", enabledChannels)
	} else {
		fmt.Println("⚠ Warning: No channels enabled")
	}

	fmt.Printf("✓ Gateway started on %s:%d\n", cfg.Gateway.Host, cfg.Gateway.Port)
	fmt.Println("Press Ctrl+C to stop")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := cronService.Start(); err != nil {
		fmt.Printf("Error starting cron service: %v\n", err)
	}
	fmt.Println("✓ Cron service started")

	if err := heartbeatService.Start(); err != nil {
		fmt.Printf("Error starting heartbeat service: %v\n", err)
	}
	fmt.Println("✓ Heartbeat service started")

	stateManager := state.NewManager(cfg.WorkspacePath())
	deviceService := devices.NewService(devices.Config{
		Enabled:    cfg.Devices.Enabled,
		MonitorUSB: cfg.Devices.MonitorUSB,
	}, stateManager)
	deviceService.SetBus(msgBus)
	if err := deviceService.Start(ctx); err != nil {
		fmt.Printf("Error starting device service: %v\n", err)
	} else if cfg.Devices.Enabled {
		fmt.Println("✓ Device event service started")
	}

	// Initialize Prometheus metrics and setup shared HTTP server
	metrics.Init(internal.GetVersion())
	healthServer := health.NewServer(cfg.Gateway.Host, cfg.Gateway.Port)
	addr := fmt.Sprintf("%s:%d", cfg.Gateway.Host, cfg.Gateway.Port)
	channelManager.SetupHTTPServer(addr, healthServer)

	// ── Wire up User Management & Admin APIs ──
	dbPath := filepath.Join(cfg.WorkspacePath(), "data", "operator.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	userStore, err := users.NewSQLiteUserStore(dbPath)
	if err != nil {
		return fmt.Errorf("init user store: %w", err)
	}

	// JWT signing key — use env or generate a stable key from config path
	jwtKey := os.Getenv("OPERATOR_JWT_SECRET")
	if jwtKey == "" {
		jwtKey = "operator-os-default-jwt-signing-key-change-me"
	}
	tokenService, err := users.NewTokenService([]byte(jwtKey))
	if err != nil {
		return fmt.Errorf("init token service: %w", err)
	}

	userAPI := users.NewAPIWithAuth(userStore, tokenService)
	authMiddleware := users.AuthMiddleware(tokenService)
	adminMiddleware := admin.AdminMiddleware(userStore)

	// Open shared DB for audit store
	auditDB, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(wal)&_pragma=busy_timeout(5000)")
	if err != nil {
		return fmt.Errorf("open audit db: %w", err)
	}
	auditStore, err := audit.NewSQLiteAuditStore(auditDB)
	if err != nil {
		auditDB.Close()
		return fmt.Errorf("init audit store: %w", err)
	}

	adminAPI := admin.NewAPI(userStore, auditStore)

	// Register health check components now that DB is available
	healthChecker := health.NewChecker()
	healthChecker.Register(health.ComponentConfig{
		Name: "database",
		Type: health.TypeDatabase,
		CheckFunc: func(ctx context.Context) health.CheckResult {
			if err := auditDB.PingContext(ctx); err != nil {
				return health.CheckResult{Status: health.StatusUnhealthy, Message: err.Error()}
			}
			return health.CheckResult{Status: health.StatusHealthy, Message: "sqlite ok"}
		},
		Critical: true,
	})
	healthChecker.Register(health.ComponentConfig{
		Name: "provider",
		Type: health.TypeExternal,
		CheckFunc: func(_ context.Context) health.CheckResult {
			if provider == nil {
				return health.CheckResult{Status: health.StatusUnhealthy, Message: "no provider configured"}
			}
			return health.CheckResult{Status: health.StatusHealthy, Message: fmt.Sprintf("model: %s", modelID)}
		},
		Critical: true,
	})
	healthServer.SetChecker(healthChecker)

	// ── Agents API ──
	agentStore, err := agents.NewSQLiteUserAgentStore(dbPath)
	if err != nil {
		return fmt.Errorf("init agent store: %w", err)
	}
	agentAPI := agents.NewAPI(agentStore)

	// ── Audit API ──
	auditAPI := audit.NewAPI(auditStore)

	// ── Billing APIs (stub stores for now — no Stripe configured) ──
	catalogue := billing.NewCatalogue(billing.DefaultPlans())
	billingPlanAPI := billing.NewAPI(catalogue, &stubSubStore{})
	billingUsageAPI := billing.NewUsageAPI(&stubUsageStore{}, &stubSubStore{}, catalogue)

	// ── Rate Limiter ──
	limiter := ratelimit.NewLimiter(nil) // nil → uses DefaultTierConfigs()

	// ── Security Audit ──
	secAuditor := secaudit.NewAuditor()

	// Register routes on the shared mux
	apiMux := channelManager.Mux()
	if apiMux != nil {
		// Auth
		userAPI.RegisterRoutes(apiMux)
		userAPI.RegisterProfileRoutes(apiMux, authMiddleware)
		// Admin
		adminAPI.RegisterRoutes(apiMux, authMiddleware, adminMiddleware)
		// Agents
		agentAPI.RegisterRoutes(apiMux, authMiddleware)
		// Audit
		auditAPI.RegisterRoutes(apiMux)
		// Billing
		billingPlanAPI.RegisterRoutes(apiMux)
		billingUsageAPI.RegisterRoutes(apiMux)
		// Rate limit
		ratelimit.RegisterRoutes(apiMux, limiter)
		// Security audit
		secaudit.RegisterRoutes(apiMux, secAuditor)
		// Sessions stub
		registerSessionStubs(apiMux, authMiddleware)

		// WebSocket bridge — wire /api/v1/ws to the Operator channel with JWT auth
		if opCh, ok := channelManager.GetChannel("operator"); ok {
			type jwtValidator interface {
				SetTokenValidator(func(string) (string, bool))
			}
			if operatorCh, ok := opCh.(jwtValidator); ok {
				operatorCh.SetTokenValidator(func(tok string) (string, bool) {
					claims, err := tokenService.ValidateAccessToken(tok)
					if err != nil {
						return "", false
					}
					return claims.UserID, true
				})
			}
			apiMux.Handle("/api/v1/ws", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Rewrite path so the Operator channel's ServeHTTP sees /ws
				r.URL.Path = "/operator/ws"
				opCh.(http.Handler).ServeHTTP(w, r)
			}))
		}

		fmt.Println("✓ All API routes registered (auth, profile, agents, billing, audit, sessions, ws)")
	}

	if err := channelManager.StartAll(ctx); err != nil {
		fmt.Printf("Error starting channels: %v\n", err)
		return err
	}

	// Mark the system as ready now that all routes are registered and channels started
	healthServer.SetReady(true)

	fmt.Printf("✓ Health endpoints available at http://%s:%d/health, /ready, and /metrics\n", cfg.Gateway.Host, cfg.Gateway.Port)

	go agentLoop.Run(ctx)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	sig := <-sigChan

	logger.InfoCF("gateway", "Shutdown signal received", map[string]any{"signal": sig.String()})
	fmt.Println("\nShutting down...")
	if cp, ok := provider.(providers.StatefulProvider); ok {
		cp.Close()
	}
	cancel()
	msgBus.Close()

	// Use a fresh context with timeout for graceful shutdown,
	// since the original ctx is already canceled.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	// Mark system as not ready before shutting down services.
	healthServer.SetReady(false)

	channelManager.StopAll(shutdownCtx)
	deviceService.Stop()
	heartbeatService.Stop()
	cronService.Stop()
	mediaStore.Stop()
	agentLoop.Stop()
	auditDB.Close()

	logger.InfoC("gateway", "Gateway stopped")
	fmt.Println("✓ Gateway stopped")

	return nil
}

func setupCronTool(
	agentLoop *agent.AgentLoop,
	msgBus *bus.MessageBus,
	workspace string,
	restrict bool,
	execTimeout time.Duration,
	cfg *config.Config,
) *cron.CronService {
	cronStorePath := filepath.Join(workspace, "cron", "jobs.json")

	// Create cron service
	cronService := cron.NewCronService(cronStorePath, nil)

	// Create and register CronTool
	cronTool, err := tools.NewCronTool(cronService, agentLoop, msgBus, workspace, restrict, execTimeout, cfg)
	if err != nil {
		log.Fatalf("Critical error during CronTool initialization: %v", err)
	}

	agentLoop.RegisterTool(cronTool)

	// Set the onJob handler
	cronService.SetOnJob(func(job *cron.CronJob) (string, error) {
		result := cronTool.ExecuteJob(context.Background(), job)
		return result, nil
	})

	return cronService
}

// ── Stub implementations for billing stores (no Stripe configured yet) ──

type stubSubStore struct{}

func (s *stubSubStore) Create(_ *billing.Subscription) error { return nil }
func (s *stubSubStore) GetByID(_ string) (*billing.Subscription, error) {
	return &billing.Subscription{Status: billing.SubStatusActive, PlanID: billing.PlanFree}, nil
}
func (s *stubSubStore) GetByUserID(_ string) (*billing.Subscription, error) {
	return &billing.Subscription{Status: billing.SubStatusActive, PlanID: billing.PlanFree}, nil
}
func (s *stubSubStore) Update(_ *billing.Subscription) error                              { return nil }
func (s *stubSubStore) ListByStatus(_ billing.SubscriptionStatus) ([]*billing.Subscription, error) { return nil, nil }
func (s *stubSubStore) Close() error                                                       { return nil }

type stubUsageStore struct{}

func (s *stubUsageStore) Record(_ *billing.UsageEvent) error { return nil }
func (s *stubUsageStore) GetSummary(_ string, _, _ time.Time) (*billing.UsageSummary, error) {
	return &billing.UsageSummary{}, nil
}
func (s *stubUsageStore) GetByModel(_ string, _, _ time.Time) ([]*billing.ModelUsage, error) {
	return nil, nil
}
func (s *stubUsageStore) GetDaily(_ string, _, _ time.Time) ([]*billing.DailyUsage, error) {
	return nil, nil
}
func (s *stubUsageStore) GetCurrentPeriodUsage(_ string, _ time.Time) (int64, error)    { return 0, nil }
func (s *stubUsageStore) GetCurrentPeriodMessages(_ string, _ time.Time) (int64, error) { return 0, nil }
func (s *stubUsageStore) ListEvents(_ billing.UsageQuery) ([]*billing.UsageEvent, error) { return nil, nil }
func (s *stubUsageStore) DeleteBefore(_ time.Time) (int64, error)                        { return 0, nil }
func (s *stubUsageStore) Close() error                                                    { return nil }

// ── Session stubs (chat sessions — not yet backed by real store) ──

func registerSessionStubs(mux *http.ServeMux, authMiddleware func(http.Handler) http.Handler) {
	wrap := func(h http.HandlerFunc) http.Handler { return authMiddleware(h) }
	mux.Handle("GET /api/v1/sessions", wrap(handleListSessions))
	mux.Handle("POST /api/v1/sessions", wrap(handleCreateSession))
	mux.Handle("GET /api/v1/sessions/{id}", wrap(handleGetSession))
	mux.Handle("PUT /api/v1/sessions/{id}", wrap(handleUpdateSession))
	mux.Handle("DELETE /api/v1/sessions/{id}", wrap(handleDeleteSession))
	mux.Handle("GET /api/v1/sessions/{id}/messages", wrap(handleGetMessages))
}

func jsonResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func handleListSessions(w http.ResponseWriter, _ *http.Request) {
	jsonResp(w, http.StatusOK, []any{})
}

func handleCreateSession(w http.ResponseWriter, _ *http.Request) {
	jsonResp(w, http.StatusCreated, map[string]any{
		"id":         "session-1",
		"title":      "New conversation",
		"created_at": time.Now(),
	})
}

func handleGetSession(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, map[string]any{
		"id":         r.PathValue("id"),
		"title":      "Conversation",
		"created_at": time.Now(),
	})
}

func handleUpdateSession(w http.ResponseWriter, _ *http.Request) {
	jsonResp(w, http.StatusOK, map[string]any{"status": "ok"})
}

func handleDeleteSession(w http.ResponseWriter, _ *http.Request) {
	jsonResp(w, http.StatusOK, map[string]any{"status": "ok"})
}

func handleGetMessages(w http.ResponseWriter, _ *http.Request) {
	jsonResp(w, http.StatusOK, map[string]any{
		"messages":   []any{},
		"total":      0,
		"page":       1,
		"per_page":   50,
		"has_more":   false,
	})
}
