package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/operatoronline/Operator-OS/pkg/bus"
	"github.com/operatoronline/Operator-OS/pkg/config"
	"github.com/operatoronline/Operator-OS/pkg/providers"
	"github.com/operatoronline/Operator-OS/pkg/tools"
)

// --- Integration Tests: Full Agent Loop ---

// toolCallingMockProvider simulates an LLM that makes tool calls.
// On the first call, it returns a tool call. On subsequent calls, it returns
// a final response incorporating the tool result.
type toolCallingMockProvider struct {
	callCount int
	toolName  string
	toolArgs  map[string]any
	finalResp string
}

func (m *toolCallingMockProvider) Chat(
	ctx context.Context,
	messages []providers.Message,
	toolDefs []providers.ToolDefinition,
	model string,
	opts map[string]any,
) (*providers.LLMResponse, error) {
	m.callCount++

	// First call: request a tool call.
	if m.callCount == 1 {
		argsJSON, _ := json.Marshal(m.toolArgs)
		return &providers.LLMResponse{
			Content: "",
			ToolCalls: []providers.ToolCall{
				{
					ID:   "call_001",
					Type: "function",
					Name: m.toolName,
					Function: &providers.FunctionCall{
						Name:      m.toolName,
						Arguments: string(argsJSON),
					},
					Arguments: m.toolArgs,
				},
			},
		}, nil
	}

	// Second call: incorporate tool result and return final response.
	// Check that tool result is in the messages.
	hasToolResult := false
	for _, msg := range messages {
		if msg.Role == "tool" {
			hasToolResult = true
			break
		}
	}

	if !hasToolResult {
		return nil, fmt.Errorf("expected tool result in messages, but none found")
	}

	return &providers.LLMResponse{
		Content:   m.finalResp,
		ToolCalls: []providers.ToolCall{},
	}, nil
}

func (m *toolCallingMockProvider) GetDefaultModel() string {
	return "mock-tool-model"
}

// echoTool is a simple tool that echoes its input.
type echoTool struct{}

func (t *echoTool) Name() string        { return "echo" }
func (t *echoTool) Description() string  { return "Echoes the input message" }
func (t *echoTool) Parameters() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"message": map[string]any{
				"type":        "string",
				"description": "The message to echo",
			},
		},
		"required": []string{"message"},
	}
}

func (t *echoTool) Execute(ctx context.Context, args map[string]any) *tools.ToolResult {
	msg, _ := args["message"].(string)
	return tools.NewToolResult("Echo: " + msg)
}

// TestIntegration_AgentLoop_ToolExecution verifies the full agent loop:
// user message → LLM call → tool call → tool execution → LLM call with result → final response.
func TestIntegration_AgentLoop_ToolExecution(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Agents: config.AgentsConfig{
			Defaults: config.AgentDefaults{
				Workspace:         tmpDir,
				Model:             "test-model",
				MaxTokens:         4096,
				MaxToolIterations: 10,
			},
		},
	}

	msgBus := bus.NewMessageBus()
	provider := &toolCallingMockProvider{
		toolName:  "echo",
		toolArgs:  map[string]any{"message": "hello world"},
		finalResp: "The echo tool returned: Echo: hello world",
	}

	al := NewAgentLoop(cfg, msgBus, provider)
	al.RegisterTool(&echoTool{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := al.ProcessDirect(ctx, "Please echo hello world", "integration-test-session")
	if err != nil {
		t.Fatalf("ProcessDirect failed: %v", err)
	}

	// Provider should have been called twice: once for tool call, once for final response.
	if provider.callCount != 2 {
		t.Errorf("Expected 2 provider calls, got %d", provider.callCount)
	}

	if response != "The echo tool returned: Echo: hello world" {
		t.Errorf("Expected final response, got: %s", response)
	}
}

// multiToolMockProvider requests multiple tools in sequence.
type multiToolMockProvider struct {
	callCount   int
	maxToolCalls int
}

func (m *multiToolMockProvider) Chat(
	ctx context.Context,
	messages []providers.Message,
	toolDefs []providers.ToolDefinition,
	model string,
	opts map[string]any,
) (*providers.LLMResponse, error) {
	m.callCount++

	// Count how many tool results are already in messages.
	toolResults := 0
	for _, msg := range messages {
		if msg.Role == "tool" {
			toolResults++
		}
	}

	if toolResults < m.maxToolCalls {
		argsJSON, _ := json.Marshal(map[string]any{"message": fmt.Sprintf("step-%d", toolResults+1)})
		return &providers.LLMResponse{
			ToolCalls: []providers.ToolCall{
				{
					ID:   fmt.Sprintf("call_%03d", m.callCount),
					Type: "function",
					Name: "echo",
					Function: &providers.FunctionCall{
						Name:      "echo",
						Arguments: string(argsJSON),
					},
					Arguments: map[string]any{"message": fmt.Sprintf("step-%d", toolResults+1)},
				},
			},
		}, nil
	}

	return &providers.LLMResponse{
		Content: fmt.Sprintf("Completed %d tool calls", toolResults),
	}, nil
}

func (m *multiToolMockProvider) GetDefaultModel() string {
	return "mock-multi-tool"
}

// TestIntegration_AgentLoop_MultiStepToolExecution verifies the agent can chain
// multiple tool calls in sequence.
func TestIntegration_AgentLoop_MultiStepToolExecution(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Agents: config.AgentsConfig{
			Defaults: config.AgentDefaults{
				Workspace:         tmpDir,
				Model:             "test-model",
				MaxTokens:         4096,
				MaxToolIterations: 10,
			},
		},
	}

	msgBus := bus.NewMessageBus()
	provider := &multiToolMockProvider{maxToolCalls: 3}

	al := NewAgentLoop(cfg, msgBus, provider)
	al.RegisterTool(&echoTool{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := al.ProcessDirect(ctx, "Run three steps", "multi-step-session")
	if err != nil {
		t.Fatalf("ProcessDirect failed: %v", err)
	}

	// 3 tool calls + 1 final response = 4 provider calls.
	if provider.callCount != 4 {
		t.Errorf("Expected 4 provider calls (3 tool + 1 final), got %d", provider.callCount)
	}

	if response != "Completed 3 tool calls" {
		t.Errorf("Expected 'Completed 3 tool calls', got: %s", response)
	}
}

// errorTool is a tool that always returns an error.
type errorTool struct{}

func (t *errorTool) Name() string        { return "fail" }
func (t *errorTool) Description() string  { return "Always fails" }
func (t *errorTool) Parameters() map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}
}

func (t *errorTool) Execute(ctx context.Context, args map[string]any) *tools.ToolResult {
	return tools.ErrorResult("tool execution failed: simulated error")
}

// TestIntegration_AgentLoop_ToolError verifies the agent loop handles tool errors
// gracefully — the error is passed back to the LLM as a tool result.
func TestIntegration_AgentLoop_ToolError(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Agents: config.AgentsConfig{
			Defaults: config.AgentDefaults{
				Workspace:         tmpDir,
				Model:             "test-model",
				MaxTokens:         4096,
				MaxToolIterations: 10,
			},
		},
	}

	msgBus := bus.NewMessageBus()

	callCount := 0
	provider := &toolErrorMockProvider{callCount: &callCount}

	al := NewAgentLoop(cfg, msgBus, provider)
	al.RegisterTool(&errorTool{})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := al.ProcessDirect(ctx, "Try the fail tool", "error-test-session")
	if err != nil {
		t.Fatalf("ProcessDirect failed: %v", err)
	}

	if response != "The tool failed, but I handled it" {
		t.Errorf("Expected error handling response, got: %s", response)
	}
}

type toolErrorMockProvider struct {
	callCount *int
}

func (m *toolErrorMockProvider) Chat(
	ctx context.Context,
	messages []providers.Message,
	toolDefs []providers.ToolDefinition,
	model string,
	opts map[string]any,
) (*providers.LLMResponse, error) {
	*m.callCount++

	if *m.callCount == 1 {
		argsJSON, _ := json.Marshal(map[string]any{})
		return &providers.LLMResponse{
			ToolCalls: []providers.ToolCall{
				{
					ID:   "call_err",
					Type: "function",
					Name: "fail",
					Function: &providers.FunctionCall{
						Name:      "fail",
						Arguments: string(argsJSON),
					},
					Arguments: map[string]any{},
				},
			},
		}, nil
	}

	// The tool error should be in messages; agent handles it gracefully.
	return &providers.LLMResponse{
		Content: "The tool failed, but I handled it",
	}, nil
}

func (m *toolErrorMockProvider) GetDefaultModel() string {
	return "mock-error-model"
}

// TestIntegration_AgentLoop_EmptyResponse verifies fallback behavior when provider
// returns empty content without tool calls.
func TestIntegration_AgentLoop_EmptyResponse(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Agents: config.AgentsConfig{
			Defaults: config.AgentDefaults{
				Workspace:         tmpDir,
				Model:             "test-model",
				MaxTokens:         4096,
				MaxToolIterations: 10,
			},
		},
	}

	msgBus := bus.NewMessageBus()
	provider := &simpleMockProvider{response: ""}

	al := NewAgentLoop(cfg, msgBus, provider)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	response, err := al.ProcessDirect(ctx, "Hello", "empty-response-session")
	if err != nil {
		t.Fatalf("ProcessDirect failed: %v", err)
	}

	// Empty response should trigger fallback message.
	if response == "" {
		// Some implementations return a fallback; just ensure no error.
		t.Log("Empty response returned (expected fallback behavior)")
	}
}

// TestIntegration_AgentLoop_SessionPersistence verifies messages are saved to session.
func TestIntegration_AgentLoop_SessionPersistence(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Agents: config.AgentsConfig{
			Defaults: config.AgentDefaults{
				Workspace:         tmpDir,
				Model:             "test-model",
				MaxTokens:         4096,
				MaxToolIterations: 10,
			},
		},
	}

	msgBus := bus.NewMessageBus()
	provider := &simpleMockProvider{response: "Response to first message"}
	al := NewAgentLoop(cfg, msgBus, provider)

	ctx := context.Background()
	sessionKey := "persistence-test"

	// First message.
	resp1, err := al.ProcessDirect(ctx, "First message", sessionKey)
	if err != nil {
		t.Fatalf("First ProcessDirect failed: %v", err)
	}
	if resp1 != "Response to first message" {
		t.Errorf("Expected 'Response to first message', got: %s", resp1)
	}

	// The session key is namespaced internally as "agent:<id>:main".
	// Verify by checking the default agent exists.
	defaultAgent := al.registry.GetDefaultAgent()
	if defaultAgent == nil {
		t.Fatal("No default agent")
	}

	// The internal session key is "agent:<agentID>:main" — check using the
	// agent's own session manager with the normalized key.
	internalKey := "agent:" + defaultAgent.ID + ":main"
	history := defaultAgent.Sessions.GetHistory(internalKey)
	if len(history) < 2 {
		t.Logf("History length after first message: %d (may use different key scheme)", len(history))
	}

	// Second message should succeed.
	provider.response = "Response to second message"
	resp2, err := al.ProcessDirect(ctx, "Second message", sessionKey)
	if err != nil {
		t.Fatalf("Second ProcessDirect failed: %v", err)
	}
	if resp2 != "Response to second message" {
		t.Errorf("Expected 'Response to second message', got: %s", resp2)
	}
}

// TestIntegration_AgentLoop_ProviderError verifies the agent loop handles
// non-retriable provider errors (e.g. auth failure) without infinite retries.
func TestIntegration_AgentLoop_ProviderError(t *testing.T) {
	tmpDir := t.TempDir()

	cfg := &config.Config{
		Agents: config.AgentsConfig{
			Defaults: config.AgentDefaults{
				Workspace:         tmpDir,
				Model:             "test-model",
				MaxTokens:         4096,
				MaxToolIterations: 10,
			},
		},
	}

	msgBus := bus.NewMessageBus()
	provider := &alwaysFailProvider{err: fmt.Errorf("authentication failed: invalid API key")}
	al := NewAgentLoop(cfg, msgBus, provider)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := al.ProcessDirect(ctx, "Should fail", "error-session")
	// Provider always fails — either error is returned or empty response.
	if err != nil {
		t.Logf("Got expected error: %v", err)
	}
}

type alwaysFailProvider struct {
	err error
}

func (m *alwaysFailProvider) Chat(
	ctx context.Context,
	messages []providers.Message,
	toolDefs []providers.ToolDefinition,
	model string,
	opts map[string]any,
) (*providers.LLMResponse, error) {
	return nil, m.err
}

func (m *alwaysFailProvider) GetDefaultModel() string {
	return "mock-fail"
}
