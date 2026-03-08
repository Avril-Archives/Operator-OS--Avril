package google

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/operatoronline/Operator-OS/pkg/integrations"
)

// EndpointSpec describes an HTTP endpoint for a tool.
type EndpointSpec struct {
	Method   string
	BasePath string // Path template, may contain {param} placeholders.
}

// gmailEndpoints maps Gmail tool names to their API endpoints.
var gmailEndpoints = map[string]EndpointSpec{
	ToolGmailListMessages:   {Method: http.MethodGet, BasePath: "/gmail/v1/users/me/messages"},
	ToolGmailGetMessage:     {Method: http.MethodGet, BasePath: "/gmail/v1/users/me/messages/{message_id}"},
	ToolGmailSendMessage:    {Method: http.MethodPost, BasePath: "/gmail/v1/users/me/messages/send"},
	ToolGmailSearchMessages: {Method: http.MethodGet, BasePath: "/gmail/v1/users/me/messages"},
	ToolGmailListLabels:     {Method: http.MethodGet, BasePath: "/gmail/v1/users/me/labels"},
	ToolGmailModifyLabels:   {Method: http.MethodPost, BasePath: "/gmail/v1/users/me/messages/{message_id}/modify"},
	ToolGmailTrashMessage:   {Method: http.MethodPost, BasePath: "/gmail/v1/users/me/messages/{message_id}/trash"},
}

// driveEndpoints maps Drive tool names to their API endpoints.
var driveEndpoints = map[string]EndpointSpec{
	ToolDriveListFiles:    {Method: http.MethodGet, BasePath: "/drive/v3/files"},
	ToolDriveGetFile:      {Method: http.MethodGet, BasePath: "/drive/v3/files/{file_id}"},
	ToolDriveSearchFiles:  {Method: http.MethodGet, BasePath: "/drive/v3/files"},
	ToolDriveGetContent:   {Method: http.MethodGet, BasePath: "/drive/v3/files/{file_id}"},
	ToolDriveCreateFile:   {Method: http.MethodPost, BasePath: "/drive/v3/files"},
	ToolDriveCreateFolder: {Method: http.MethodPost, BasePath: "/drive/v3/files"},
	ToolDriveDeleteFile:   {Method: http.MethodPatch, BasePath: "/drive/v3/files/{file_id}"},
}

// calendarEndpoints maps Calendar tool names to their API endpoints.
var calendarEndpoints = map[string]EndpointSpec{
	ToolCalendarListEvents:    {Method: http.MethodGet, BasePath: "/calendar/v3/calendars/{calendar_id}/events"},
	ToolCalendarGetEvent:      {Method: http.MethodGet, BasePath: "/calendar/v3/calendars/{calendar_id}/events/{event_id}"},
	ToolCalendarCreateEvent:   {Method: http.MethodPost, BasePath: "/calendar/v3/calendars/{calendar_id}/events"},
	ToolCalendarUpdateEvent:   {Method: http.MethodPatch, BasePath: "/calendar/v3/calendars/{calendar_id}/events/{event_id}"},
	ToolCalendarDeleteEvent:   {Method: http.MethodDelete, BasePath: "/calendar/v3/calendars/{calendar_id}/events/{event_id}"},
	ToolCalendarListCalendars: {Method: http.MethodGet, BasePath: "/calendar/v3/users/me/calendarList"},
	ToolCalendarQuickAdd:      {Method: http.MethodPost, BasePath: "/calendar/v3/calendars/{calendar_id}/events/quickAdd"},
}

// allEndpoints is a combined map of all Google endpoints.
var allEndpoints map[string]EndpointSpec

func init() {
	allEndpoints = make(map[string]EndpointSpec)
	for k, v := range gmailEndpoints {
		allEndpoints[k] = v
	}
	for k, v := range driveEndpoints {
		allEndpoints[k] = v
	}
	for k, v := range calendarEndpoints {
		allEndpoints[k] = v
	}
}

// ResolveEndpoint returns the HTTP method and path for a Google tool,
// substituting any {param} placeholders from the args map.
// Calendar endpoints default calendar_id to "primary" when not provided.
func ResolveEndpoint(integrationID, toolName string, args map[string]any) (method, path string, err error) {
	spec, ok := allEndpoints[toolName]
	if !ok {
		return "", "", fmt.Errorf("unknown tool %q for integration %q", toolName, integrationID)
	}

	p := spec.BasePath

	// Default calendar_id to "primary" for calendar tools.
	if strings.Contains(p, "{calendar_id}") {
		calID := "primary"
		if v, ok := args["calendar_id"].(string); ok && v != "" {
			calID = v
		}
		p = strings.ReplaceAll(p, "{calendar_id}", url.PathEscape(calID))
	}

	// Replace other path parameters from args.
	for key, val := range args {
		placeholder := "{" + key + "}"
		if strings.Contains(p, placeholder) {
			if s, ok := val.(string); ok {
				p = strings.ReplaceAll(p, placeholder, url.PathEscape(s))
			}
		}
	}

	// Check for unreplaced placeholders.
	if strings.Contains(p, "{") {
		return "", "", fmt.Errorf("unresolved path parameters in %q for tool %q", p, toolName)
	}

	return spec.Method, p, nil
}

// ResolveBaseURL returns the appropriate Google API base URL for an integration.
func ResolveBaseURL(integrationID string) string {
	switch integrationID {
	case GmailIntegrationID:
		return GmailAPIBase
	case DriveIntegrationID:
		return DriveAPIBase
	case CalendarIntegrationID:
		return CalendarAPIBase
	default:
		return "https://www.googleapis.com"
	}
}

// NewGoogleEndpointResolver returns an EndpointResolver compatible with
// integrations.HTTPToolExecutorConfig.
func NewGoogleEndpointResolver() func(integrationID, toolName string) (string, string, error) {
	return func(integrationID, toolName string, ) (string, string, error) {
		return ResolveEndpoint(integrationID, toolName, nil)
	}
}

// NewGoogleBaseURLResolver returns a BaseURLResolver compatible with
// integrations.HTTPToolExecutorConfig.
func NewGoogleBaseURLResolver() func(integrationID string) string {
	return ResolveBaseURL
}

// NewGoogleHTTPExecutor creates an IntegrationToolExecutor for Google APIs
// using the generic HTTP executor from the integrations package.
func NewGoogleHTTPExecutor(tokenResolver func(ctx context.Context, userID, integrationID string) (string, error)) integrations.IntegrationToolExecutor {
	return integrations.NewHTTPToolExecutor(integrations.HTTPToolExecutorConfig{
		BaseURLResolver: ResolveBaseURL,
		TokenResolver:   tokenResolver,
		EndpointResolver: func(integrationID, toolName string) (string, string, error) {
			spec, ok := allEndpoints[toolName]
			if !ok {
				return "", "", fmt.Errorf("unknown Google tool: %s", toolName)
			}
			// Replace calendar_id default for calendar tools.
			path := spec.BasePath
			if strings.Contains(path, "{calendar_id}") {
				path = strings.ReplaceAll(path, "{calendar_id}", "primary")
			}
			return spec.Method, path, nil
		},
	})
}

// GetEndpointSpec returns the endpoint specification for a tool name.
// Returns false if the tool is not a Google tool.
func GetEndpointSpec(toolName string) (EndpointSpec, bool) {
	spec, ok := allEndpoints[toolName]
	return spec, ok
}

// AllToolNames returns the names of all Google tools across all integrations.
func AllToolNames() []string {
	names := make([]string, 0, len(allEndpoints))
	for name := range allEndpoints {
		names = append(names, name)
	}
	return names
}
