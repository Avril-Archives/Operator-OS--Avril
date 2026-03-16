package config

import (
	"strings"
	"testing"
)

func TestValidate_DefaultConfigPasses(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should pass validation: %v", err)
	}
}

func TestValidate_InvalidPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gateway.Port = 99999
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for invalid port")
	}
	if !strings.Contains(err.Error(), "gateway.port") {
		t.Errorf("expected port error, got: %v", err)
	}
}

func TestValidate_InvalidTemperature(t *testing.T) {
	cfg := DefaultConfig()
	temp := 3.0
	cfg.Agents.Defaults.Temperature = &temp
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for temperature > 2.0")
	}
	if !strings.Contains(err.Error(), "temperature") {
		t.Errorf("expected temperature error, got: %v", err)
	}
}

func TestValidate_TelegramEnabledWithoutToken(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Channels.Telegram.Enabled = true
	cfg.Channels.Telegram.Token = ""
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for telegram without token")
	}
	if !strings.Contains(err.Error(), "telegram.token") {
		t.Errorf("expected telegram token error, got: %v", err)
	}
}

func TestValidate_HeartbeatIntervalTooLow(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Heartbeat.Enabled = true
	cfg.Heartbeat.Interval = 2
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for low heartbeat interval")
	}
	if !strings.Contains(err.Error(), "heartbeat.interval") {
		t.Errorf("expected heartbeat interval error, got: %v", err)
	}
}

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Gateway.Port = -1
	temp := -0.5
	cfg.Agents.Defaults.Temperature = &temp
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected errors")
	}
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(ve.Errors) < 2 {
		t.Errorf("expected at least 2 errors, got %d", len(ve.Errors))
	}
}

func TestValidate_MCPServerWithoutCommand(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Tools.MCP.Enabled = true
	cfg.Tools.MCP.Servers = map[string]MCPServerConfig{
		"test": {Enabled: true, Command: "", URL: ""},
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for MCP server without command or URL")
	}
	if !strings.Contains(err.Error(), "tools.mcp.servers[test]") {
		t.Errorf("expected MCP server error, got: %v", err)
	}
}
