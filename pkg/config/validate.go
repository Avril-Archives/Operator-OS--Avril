package config

import (
	"fmt"
	"strings"
)

// ValidationError collects multiple validation issues.
type ValidationError struct {
	Errors []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("config validation failed:\n  - %s", strings.Join(e.Errors, "\n  - "))
}

func (e *ValidationError) add(msg string) {
	e.Errors = append(e.Errors, msg)
}

func (e *ValidationError) hasErrors() bool {
	return len(e.Errors) > 0
}

// Validate performs comprehensive validation of the Config at startup.
// It checks required fields, value ranges, and cross-field consistency.
func (c *Config) Validate() error {
	ve := &ValidationError{}

	// Gateway
	if c.Gateway.Port < 0 || c.Gateway.Port > 65535 {
		ve.add(fmt.Sprintf("gateway.port must be 0-65535, got %d", c.Gateway.Port))
	}

	// Agent defaults
	if c.Agents.Defaults.MaxTokens < 0 {
		ve.add(fmt.Sprintf("agents.defaults.max_tokens must be non-negative, got %d", c.Agents.Defaults.MaxTokens))
	}
	if c.Agents.Defaults.MaxToolIterations < 0 {
		ve.add(fmt.Sprintf("agents.defaults.max_tool_iterations must be non-negative, got %d", c.Agents.Defaults.MaxToolIterations))
	}
	if c.Agents.Defaults.Temperature != nil {
		t := *c.Agents.Defaults.Temperature
		if t < 0.0 || t > 2.0 {
			ve.add(fmt.Sprintf("agents.defaults.temperature must be 0.0-2.0, got %.2f", t))
		}
	}

	// Model list
	for i, m := range c.ModelList {
		if m.ModelName == "" {
			ve.add(fmt.Sprintf("model_list[%d].model_name is required", i))
		}
		if m.Model == "" {
			ve.add(fmt.Sprintf("model_list[%d].model is required", i))
		}
		if m.RPM < 0 {
			ve.add(fmt.Sprintf("model_list[%d].rpm must be non-negative", i))
		}
	}

	// Heartbeat
	if c.Heartbeat.Enabled && c.Heartbeat.Interval < 5 {
		ve.add(fmt.Sprintf("heartbeat.interval must be >= 5 minutes when enabled, got %d", c.Heartbeat.Interval))
	}

	// Channels — validate enabled channels have required credentials
	if c.Channels.Telegram.Enabled && c.Channels.Telegram.Token == "" {
		ve.add("channels.telegram.token is required when telegram is enabled")
	}
	if c.Channels.Discord.Enabled && c.Channels.Discord.Token == "" {
		ve.add("channels.discord.token is required when discord is enabled")
	}
	if c.Channels.Slack.Enabled && c.Channels.Slack.BotToken == "" {
		ve.add("channels.slack.bot_token is required when slack is enabled")
	}
	if c.Channels.Feishu.Enabled && (c.Channels.Feishu.AppID == "" || c.Channels.Feishu.AppSecret == "") {
		ve.add("channels.feishu.app_id and app_secret are required when feishu is enabled")
	}
	if c.Channels.DingTalk.Enabled && (c.Channels.DingTalk.ClientID == "" || c.Channels.DingTalk.ClientSecret == "") {
		ve.add("channels.dingtalk.client_id and client_secret are required when dingtalk is enabled")
	}
	if c.Channels.LINE.Enabled && (c.Channels.LINE.ChannelSecret == "" || c.Channels.LINE.ChannelAccessToken == "") {
		ve.add("channels.line.channel_secret and channel_access_token are required when line is enabled")
	}

	// MCP servers
	if c.Tools.MCP.Enabled {
		for name, srv := range c.Tools.MCP.Servers {
			if !srv.Enabled {
				continue
			}
			if srv.Command == "" && srv.URL == "" {
				ve.add(fmt.Sprintf("tools.mcp.servers[%s] requires either command or url", name))
			}
		}
	}

	if ve.hasErrors() {
		return ve
	}
	return nil
}
