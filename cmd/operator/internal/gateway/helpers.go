package gateway

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"database/sql"

	_ "modernc.org/sqlite"

	"github.com/standardws/operator/cmd/operator/internal"
	"github.com/standardws/operator/pkg/admin"
	"github.com/standardws/operator/pkg/agent"
	"github.com/standardws/operator/pkg/audit"
	"github.com/standardws/operator/pkg/bus"
	"github.com/standardws/operator/pkg/channels"
	_ "github.com/standardws/operator/pkg/channels/dingtalk"
	_ "github.com/standardws/operator/pkg/channels/discord"
	_ "github.com/standardws/operator/pkg/channels/feishu"
	_ "github.com/standardws/operator/pkg/channels/line"
	_ "github.com/standardws/operator/pkg/channels/maixcam"
	_ "github.com/standardws/operator/pkg/channels/onebot"
	_ "github.com/standardws/operator/pkg/channels/pico"
	_ "github.com/standardws/operator/pkg/channels/qq"
	_ "github.com/standardws/operator/pkg/channels/slack"
	_ "github.com/standardws/operator/pkg/channels/telegram"
	_ "github.com/standardws/operator/pkg/channels/wecom"
	_ "github.com/standardws/operator/pkg/channels/whatsapp"
	_ "github.com/standardws/operator/pkg/channels/whatsapp_native"
	"github.com/standardws/operator/pkg/config"
	"github.com/standardws/operator/pkg/cron"
	"github.com/standardws/operator/pkg/devices"
	"github.com/standardws/operator/pkg/health"
	"github.com/standardws/operator/pkg/heartbeat"
	"github.com/standardws/operator/pkg/logger"
	"github.com/standardws/operator/pkg/media"
	"github.com/standardws/operator/pkg/metrics"
	"github.com/standardws/operator/pkg/providers"
	"github.com/standardws/operator/pkg/state"
	"github.com/standardws/operator/pkg/tools"
	"github.com/standardws/operator/pkg/users"
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

	// Register routes on the shared mux
	apiMux := channelManager.Mux()
	if apiMux != nil {
		userAPI.RegisterRoutes(apiMux)
		adminAPI.RegisterRoutes(apiMux, authMiddleware, adminMiddleware)
		fmt.Println("✓ User management & admin APIs registered")
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
	signal.Notify(sigChan, os.Interrupt)
	<-sigChan

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

	channelManager.StopAll(shutdownCtx)
	deviceService.Stop()
	heartbeatService.Stop()
	cronService.Stop()
	mediaStore.Stop()
	agentLoop.Stop()
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
