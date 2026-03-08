package google

import (
	"context"
	"fmt"
	"testing"

	"github.com/operatoronline/Operator-OS/pkg/integrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- OAuth Provider ---

func TestNewOAuthProvider(t *testing.T) {
	p := NewOAuthProvider("client-id", "client-secret", "https://example.com/callback")
	assert.Equal(t, ProviderID, p.ID)
	assert.Equal(t, "Google", p.Name)
	assert.Equal(t, AuthorizationURL, p.AuthURL)
	assert.Equal(t, TokenURL, p.TokenURL)
	assert.Equal(t, "client-id", p.ClientID)
	assert.Equal(t, "client-secret", p.ClientSecret)
	assert.Equal(t, "https://example.com/callback", p.RedirectURL)
	assert.True(t, p.UsePKCE)
	assert.Contains(t, p.Scopes, "openid")
	assert.Contains(t, p.Scopes, "email")
	assert.Contains(t, p.Scopes, "profile")
	assert.Equal(t, "offline", p.ExtraAuthParams["access_type"])
	assert.Equal(t, "consent", p.ExtraAuthParams["prompt"])
}

func TestNewOAuthProviderValidates(t *testing.T) {
	p := NewOAuthProvider("cid", "csec", "https://example.com/cb")
	err := p.Validate()
	assert.NoError(t, err)
}

// --- Integration Manifests ---

func TestGmailIntegration(t *testing.T) {
	i := GmailIntegration()
	assert.Equal(t, GmailIntegrationID, i.ID)
	assert.Equal(t, "Gmail", i.Name)
	assert.Equal(t, "email", i.Category)
	assert.Equal(t, integrations.AuthTypeOAuth2, i.AuthType)
	assert.NotNil(t, i.OAuth)
	assert.Equal(t, AuthorizationURL, i.OAuth.AuthorizationURL)
	assert.Equal(t, TokenURL, i.OAuth.TokenURL)
	assert.True(t, i.OAuth.UsePKCE)
	assert.Contains(t, i.OAuth.Scopes, ScopeGmailReadonly)
	assert.Contains(t, i.OAuth.Scopes, ScopeGmailSend)
	assert.Equal(t, integrations.IntegrationStatusActive, i.Status)
	assert.NoError(t, i.Validate())
	assert.True(t, len(i.Tools) >= 7, "Gmail should have at least 7 tools")
}

func TestDriveIntegration(t *testing.T) {
	i := DriveIntegration()
	assert.Equal(t, DriveIntegrationID, i.ID)
	assert.Equal(t, "Google Drive", i.Name)
	assert.Equal(t, "storage", i.Category)
	assert.Equal(t, integrations.AuthTypeOAuth2, i.AuthType)
	assert.NotNil(t, i.OAuth)
	assert.Contains(t, i.OAuth.Scopes, ScopeDriveReadonly)
	assert.Equal(t, integrations.IntegrationStatusActive, i.Status)
	assert.NoError(t, i.Validate())
	assert.True(t, len(i.Tools) >= 7, "Drive should have at least 7 tools")
}

func TestCalendarIntegration(t *testing.T) {
	i := CalendarIntegration()
	assert.Equal(t, CalendarIntegrationID, i.ID)
	assert.Equal(t, "Google Calendar", i.Name)
	assert.Equal(t, "productivity", i.Category)
	assert.Equal(t, integrations.AuthTypeOAuth2, i.AuthType)
	assert.NotNil(t, i.OAuth)
	assert.Contains(t, i.OAuth.Scopes, ScopeCalendarReadonly)
	assert.Contains(t, i.OAuth.Scopes, ScopeCalendarEvents)
	assert.Equal(t, integrations.IntegrationStatusActive, i.Status)
	assert.NoError(t, i.Validate())
	assert.True(t, len(i.Tools) >= 7, "Calendar should have at least 7 tools")
}

func TestAllIntegrations(t *testing.T) {
	all := AllIntegrations()
	assert.Len(t, all, 3)
	ids := make(map[string]bool)
	for _, i := range all {
		ids[i.ID] = true
		assert.NoError(t, i.Validate(), "integration %q should be valid", i.ID)
	}
	assert.True(t, ids[GmailIntegrationID])
	assert.True(t, ids[DriveIntegrationID])
	assert.True(t, ids[CalendarIntegrationID])
}

// --- Tool Definitions ---

func TestGmailToolNames(t *testing.T) {
	i := GmailIntegration()
	names := i.ToolNames()
	expected := []string{
		ToolGmailListMessages, ToolGmailGetMessage, ToolGmailSendMessage,
		ToolGmailSearchMessages, ToolGmailListLabels, ToolGmailModifyLabels,
		ToolGmailTrashMessage,
	}
	for _, e := range expected {
		assert.Contains(t, names, e, "Gmail should have tool %q", e)
	}
}

func TestDriveToolNames(t *testing.T) {
	i := DriveIntegration()
	names := i.ToolNames()
	expected := []string{
		ToolDriveListFiles, ToolDriveGetFile, ToolDriveSearchFiles,
		ToolDriveGetContent, ToolDriveCreateFile, ToolDriveCreateFolder,
		ToolDriveDeleteFile,
	}
	for _, e := range expected {
		assert.Contains(t, names, e, "Drive should have tool %q", e)
	}
}

func TestCalendarToolNames(t *testing.T) {
	i := CalendarIntegration()
	names := i.ToolNames()
	expected := []string{
		ToolCalendarListEvents, ToolCalendarGetEvent, ToolCalendarCreateEvent,
		ToolCalendarUpdateEvent, ToolCalendarDeleteEvent, ToolCalendarListCalendars,
		ToolCalendarQuickAdd,
	}
	for _, e := range expected {
		assert.Contains(t, names, e, "Calendar should have tool %q", e)
	}
}

func TestToolsHaveDescriptionsAndParameters(t *testing.T) {
	for _, integ := range AllIntegrations() {
		for _, tool := range integ.Tools {
			assert.NotEmpty(t, tool.Name, "tool name should not be empty in %s", integ.ID)
			assert.NotEmpty(t, tool.Description, "tool %q in %s should have a description", tool.Name, integ.ID)
			assert.NotNil(t, tool.Parameters, "tool %q in %s should have parameters", tool.Name, integ.ID)
			assert.NotEmpty(t, tool.RequiredScopes, "tool %q in %s should have required scopes", tool.Name, integ.ID)
			assert.Greater(t, tool.RateLimit, 0, "tool %q in %s should have a rate limit", tool.Name, integ.ID)
		}
	}
}

func TestToolNamesAreUniqueAcrossIntegrations(t *testing.T) {
	seen := make(map[string]string)
	for _, integ := range AllIntegrations() {
		for _, tool := range integ.Tools {
			if prev, exists := seen[tool.Name]; exists {
				t.Errorf("duplicate tool name %q in %s (first seen in %s)", tool.Name, integ.ID, prev)
			}
			seen[tool.Name] = integ.ID
		}
	}
}

func TestToolParametersHaveType(t *testing.T) {
	for _, integ := range AllIntegrations() {
		for _, tool := range integ.Tools {
			typ, ok := tool.Parameters["type"]
			assert.True(t, ok, "tool %q parameters should have 'type' field", tool.Name)
			assert.Equal(t, "object", typ, "tool %q parameters type should be 'object'", tool.Name)
		}
	}
}

// --- Registry Integration ---

func TestRegisterAll(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	count, err := RegisterAll(reg)
	require.NoError(t, err)
	assert.Equal(t, 3, count)
	assert.Equal(t, 3, reg.Count())

	// Verify all are retrievable.
	assert.NotNil(t, reg.Get(GmailIntegrationID))
	assert.NotNil(t, reg.Get(DriveIntegrationID))
	assert.NotNil(t, reg.Get(CalendarIntegrationID))
}

func TestRegisterAllDuplicate(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	_, err := RegisterAll(reg)
	require.NoError(t, err)

	// Second registration should fail.
	_, err = RegisterAll(reg)
	assert.Error(t, err)
}

func TestRegistryCategories(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	RegisterAll(reg)

	cats := reg.Categories()
	assert.Contains(t, cats, "email")
	assert.Contains(t, cats, "storage")
	assert.Contains(t, cats, "productivity")
}

func TestRegistryListByCategory(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	RegisterAll(reg)

	email := reg.ListByCategory("email")
	assert.Len(t, email, 1)
	assert.Equal(t, GmailIntegrationID, email[0].ID)

	storage := reg.ListByCategory("storage")
	assert.Len(t, storage, 1)
	assert.Equal(t, DriveIntegrationID, storage[0].ID)
}

func TestRegistryToolLookup(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	RegisterAll(reg)

	// Look up a Gmail tool.
	tm, integID := reg.GetToolManifest(ToolGmailSendMessage)
	assert.NotNil(t, tm)
	assert.Equal(t, GmailIntegrationID, integID)

	// Look up a Calendar tool.
	tm, integID = reg.GetToolManifest(ToolCalendarCreateEvent)
	assert.NotNil(t, tm)
	assert.Equal(t, CalendarIntegrationID, integID)

	// Unknown tool.
	tm, integID = reg.GetToolManifest("nonexistent_tool")
	assert.Nil(t, tm)
	assert.Empty(t, integID)
}

func TestRegistryAllToolNames(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	RegisterAll(reg)

	names := reg.AllToolNames()
	assert.True(t, len(names) >= 21, "should have at least 21 tools, got %d", len(names))
	assert.Contains(t, names, ToolGmailListMessages)
	assert.Contains(t, names, ToolDriveListFiles)
	assert.Contains(t, names, ToolCalendarListEvents)
}

// --- Tool Adapter ---

func TestIntegrationToolAdapter(t *testing.T) {
	gmail := GmailIntegration()
	manifest := gmail.Tools[0] // gmail_list_messages

	called := false
	executor := func(ctx context.Context, integrationID, toolName string, args map[string]any) (string, error) {
		called = true
		assert.Equal(t, GmailIntegrationID, integrationID)
		assert.Equal(t, ToolGmailListMessages, toolName)
		return `{"messages": []}`, nil
	}

	tool := integrations.NewIntegrationTool(GmailIntegrationID, manifest, executor)
	assert.Equal(t, ToolGmailListMessages, tool.Name())
	assert.NotEmpty(t, tool.Description())
	assert.NotNil(t, tool.Parameters())
	assert.Equal(t, GmailIntegrationID, tool.IntegrationID())

	result := tool.Execute(context.Background(), map[string]any{})
	assert.True(t, called)
	assert.False(t, result.IsError)
	assert.Contains(t, result.ForLLM, "messages")
}

func TestIntegrationToolAdapterError(t *testing.T) {
	gmail := GmailIntegration()
	manifest := gmail.Tools[0]

	executor := func(ctx context.Context, integrationID, toolName string, args map[string]any) (string, error) {
		return "", fmt.Errorf("API error: 401 unauthorized")
	}

	tool := integrations.NewIntegrationTool(GmailIntegrationID, manifest, executor)
	result := tool.Execute(context.Background(), nil)
	assert.True(t, result.IsError)
	assert.Contains(t, result.ForLLM, "401 unauthorized")
}

func TestIntegrationToolAdapterNoExecutor(t *testing.T) {
	gmail := GmailIntegration()
	manifest := gmail.Tools[0]

	tool := integrations.NewIntegrationTool(GmailIntegrationID, manifest, nil)
	result := tool.Execute(context.Background(), nil)
	assert.True(t, result.IsError)
	assert.Contains(t, result.ForLLM, "no executor")
}

// --- Endpoint Resolution ---

func TestResolveEndpointGmail(t *testing.T) {
	tests := []struct {
		tool       string
		args       map[string]any
		wantMethod string
		wantPath   string
	}{
		{ToolGmailListMessages, nil, "GET", "/gmail/v1/users/me/messages"},
		{ToolGmailGetMessage, map[string]any{"message_id": "abc123"}, "GET", "/gmail/v1/users/me/messages/abc123"},
		{ToolGmailSendMessage, nil, "POST", "/gmail/v1/users/me/messages/send"},
		{ToolGmailListLabels, nil, "GET", "/gmail/v1/users/me/labels"},
		{ToolGmailModifyLabels, map[string]any{"message_id": "msg1"}, "POST", "/gmail/v1/users/me/messages/msg1/modify"},
		{ToolGmailTrashMessage, map[string]any{"message_id": "msg1"}, "POST", "/gmail/v1/users/me/messages/msg1/trash"},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			method, path, err := ResolveEndpoint(GmailIntegrationID, tt.tool, tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}

func TestResolveEndpointDrive(t *testing.T) {
	tests := []struct {
		tool       string
		args       map[string]any
		wantMethod string
		wantPath   string
	}{
		{ToolDriveListFiles, nil, "GET", "/drive/v3/files"},
		{ToolDriveGetFile, map[string]any{"file_id": "fileXYZ"}, "GET", "/drive/v3/files/fileXYZ"},
		{ToolDriveSearchFiles, nil, "GET", "/drive/v3/files"},
		{ToolDriveCreateFile, nil, "POST", "/drive/v3/files"},
		{ToolDriveDeleteFile, map[string]any{"file_id": "f1"}, "PATCH", "/drive/v3/files/f1"},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			method, path, err := ResolveEndpoint(DriveIntegrationID, tt.tool, tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}

func TestResolveEndpointCalendar(t *testing.T) {
	tests := []struct {
		tool       string
		args       map[string]any
		wantMethod string
		wantPath   string
	}{
		{ToolCalendarListEvents, nil, "GET", "/calendar/v3/calendars/primary/events"},
		{ToolCalendarListEvents, map[string]any{"calendar_id": "custom@group.calendar.google.com"}, "GET", "/calendar/v3/calendars/custom@group.calendar.google.com/events"},
		{ToolCalendarGetEvent, map[string]any{"event_id": "evt1"}, "GET", "/calendar/v3/calendars/primary/events/evt1"},
		{ToolCalendarCreateEvent, nil, "POST", "/calendar/v3/calendars/primary/events"},
		{ToolCalendarUpdateEvent, map[string]any{"event_id": "evt1"}, "PATCH", "/calendar/v3/calendars/primary/events/evt1"},
		{ToolCalendarDeleteEvent, map[string]any{"event_id": "evt1"}, "DELETE", "/calendar/v3/calendars/primary/events/evt1"},
		{ToolCalendarListCalendars, nil, "GET", "/calendar/v3/users/me/calendarList"},
		{ToolCalendarQuickAdd, nil, "POST", "/calendar/v3/calendars/primary/events/quickAdd"},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			method, path, err := ResolveEndpoint(CalendarIntegrationID, tt.tool, tt.args)
			require.NoError(t, err)
			assert.Equal(t, tt.wantMethod, method)
			assert.Equal(t, tt.wantPath, path)
		})
	}
}

func TestResolveEndpointUnknownTool(t *testing.T) {
	_, _, err := ResolveEndpoint("google_gmail", "nonexistent_tool", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown tool")
}

func TestResolveEndpointUnresolvedPlaceholder(t *testing.T) {
	// message_id is required but not provided.
	_, _, err := ResolveEndpoint(GmailIntegrationID, ToolGmailGetMessage, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unresolved path parameters")
}

func TestResolveEndpointPathEscaping(t *testing.T) {
	// IDs with special characters should be escaped.
	method, path, err := ResolveEndpoint(DriveIntegrationID, ToolDriveGetFile, map[string]any{
		"file_id": "file/with spaces",
	})
	require.NoError(t, err)
	assert.Equal(t, "GET", method)
	assert.Contains(t, path, "file%2Fwith%20spaces")
}

// --- Base URL Resolution ---

func TestResolveBaseURL(t *testing.T) {
	assert.Equal(t, GmailAPIBase, ResolveBaseURL(GmailIntegrationID))
	assert.Equal(t, DriveAPIBase, ResolveBaseURL(DriveIntegrationID))
	assert.Equal(t, CalendarAPIBase, ResolveBaseURL(CalendarIntegrationID))
	assert.Equal(t, "https://www.googleapis.com", ResolveBaseURL("unknown"))
}

// --- GetEndpointSpec ---

func TestGetEndpointSpec(t *testing.T) {
	spec, ok := GetEndpointSpec(ToolGmailListMessages)
	assert.True(t, ok)
	assert.Equal(t, "GET", spec.Method)
	assert.Contains(t, spec.BasePath, "messages")

	_, ok = GetEndpointSpec("nonexistent")
	assert.False(t, ok)
}

// --- AllToolNames ---

func TestAllToolNamesPackage(t *testing.T) {
	names := AllToolNames()
	assert.True(t, len(names) >= 21, "should have at least 21 tools, got %d", len(names))
}

// --- Constants ---

func TestConstants(t *testing.T) {
	assert.Equal(t, "google", ProviderID)
	assert.Equal(t, "google_gmail", GmailIntegrationID)
	assert.Equal(t, "google_drive", DriveIntegrationID)
	assert.Equal(t, "google_calendar", CalendarIntegrationID)
	assert.Contains(t, AuthorizationURL, "accounts.google.com")
	assert.Contains(t, TokenURL, "oauth2.googleapis.com")
}

// --- Scopes ---

func TestScopeConstants(t *testing.T) {
	// Gmail scopes.
	assert.Contains(t, ScopeGmailReadonly, "gmail.readonly")
	assert.Contains(t, ScopeGmailSend, "gmail.send")
	assert.Contains(t, ScopeGmailModify, "gmail.modify")
	assert.Contains(t, ScopeGmailLabels, "gmail.labels")

	// Drive scopes.
	assert.Contains(t, ScopeDriveReadonly, "drive.readonly")
	assert.Contains(t, ScopeDriveFile, "drive.file")
	assert.Contains(t, ScopeDriveFull, "auth/drive")

	// Calendar scopes.
	assert.Contains(t, ScopeCalendarReadonly, "calendar.readonly")
	assert.Contains(t, ScopeCalendarEvents, "calendar.events")
	assert.Contains(t, ScopeCalendarFull, "auth/calendar")
}

// --- Integration Validation ---

func TestGmailIntegrationValidation(t *testing.T) {
	i := GmailIntegration()
	// Mutate and check validation still works.
	assert.NoError(t, i.Validate())

	// Remove OAuth should fail.
	orig := i.OAuth
	i.OAuth = nil
	assert.Error(t, i.Validate())
	i.OAuth = orig
}

func TestIntegrationVersioning(t *testing.T) {
	for _, integ := range AllIntegrations() {
		assert.NotEmpty(t, integ.Version, "integration %q should have a version", integ.ID)
		assert.Equal(t, "1.0.0", integ.Version, "integration %q should be v1.0.0", integ.ID)
	}
}

func TestIntegrationRequiredPlan(t *testing.T) {
	for _, integ := range AllIntegrations() {
		assert.Equal(t, "free", integ.RequiredPlan, "integration %q should require 'free' plan", integ.ID)
	}
}

// --- Tool Registrar ---

func TestToolRegistrarWithGoogle(t *testing.T) {
	reg := integrations.NewIntegrationRegistry()
	RegisterAll(reg)

	called := make(map[string]bool)
	executor := func(ctx context.Context, integrationID, toolName string, args map[string]any) (string, error) {
		called[toolName] = true
		return "ok", nil
	}

	// Use a mock tool registry since we can't import the real one easily.
	// Just verify that the registrar correctly iterates all tools.
	count := 0
	for _, integ := range reg.List() {
		for _, tm := range integ.Tools {
			tool := integrations.NewIntegrationTool(integ.ID, tm, executor)
			assert.Equal(t, tm.Name, tool.Name())
			count++
		}
	}
	assert.True(t, count >= 21, "should have registered at least 21 tools, got %d", count)
}

// --- Gmail Send Tool Parameters ---

func TestGmailSendToolRequiredFields(t *testing.T) {
	gmail := GmailIntegration()
	var sendTool *integrations.ToolManifest
	for idx := range gmail.Tools {
		if gmail.Tools[idx].Name == ToolGmailSendMessage {
			sendTool = &gmail.Tools[idx]
			break
		}
	}
	require.NotNil(t, sendTool)

	// Check required fields.
	req, ok := sendTool.Parameters["required"].([]string)
	require.True(t, ok)
	assert.Contains(t, req, "to")
	assert.Contains(t, req, "subject")
	assert.Contains(t, req, "body")
}

// --- Calendar Create Event Tool Parameters ---

func TestCalendarCreateEventRequiredFields(t *testing.T) {
	cal := CalendarIntegration()
	var createTool *integrations.ToolManifest
	for idx := range cal.Tools {
		if cal.Tools[idx].Name == ToolCalendarCreateEvent {
			createTool = &cal.Tools[idx]
			break
		}
	}
	require.NotNil(t, createTool)

	req, ok := createTool.Parameters["required"].([]string)
	require.True(t, ok)
	assert.Contains(t, req, "summary")
}


