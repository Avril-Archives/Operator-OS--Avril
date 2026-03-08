package google

import "github.com/operatoronline/Operator-OS/pkg/integrations"

// Calendar tool names.
const (
	ToolCalendarListEvents  = "calendar_list_events"
	ToolCalendarGetEvent    = "calendar_get_event"
	ToolCalendarCreateEvent = "calendar_create_event"
	ToolCalendarUpdateEvent = "calendar_update_event"
	ToolCalendarDeleteEvent = "calendar_delete_event"
	ToolCalendarListCalendars = "calendar_list_calendars"
	ToolCalendarQuickAdd    = "calendar_quick_add"
)

func calendarTools() []integrations.ToolManifest {
	return []integrations.ToolManifest{
		{
			Name:        ToolCalendarListEvents,
			Description: "List upcoming events from a Google Calendar. Returns event titles, times, locations, and attendees.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calendar_id": map[string]any{
						"type":        "string",
						"description": "Calendar ID (use 'primary' for the user's main calendar). Default: primary.",
					},
					"time_min": map[string]any{
						"type":        "string",
						"description": "Lower bound for event start time (RFC3339, e.g. '2025-01-01T00:00:00Z'). Default: now.",
					},
					"time_max": map[string]any{
						"type":        "string",
						"description": "Upper bound for event start time (RFC3339). Default: 7 days from now.",
					},
					"max_results": map[string]any{
						"type":        "integer",
						"description": "Maximum number of events (1-250). Default: 10.",
					},
					"order_by": map[string]any{
						"type":        "string",
						"enum":        []string{"startTime", "updated"},
						"description": "Sort order. Default: startTime.",
					},
					"single_events": map[string]any{
						"type":        "boolean",
						"description": "Whether to expand recurring events into instances. Default: true.",
					},
					"query": map[string]any{
						"type":        "string",
						"description": "Free text search terms to find events that match.",
					},
				},
			},
			RequiredScopes: []string{ScopeCalendarReadonly},
			RateLimit:      30,
		},
		{
			Name:        ToolCalendarGetEvent,
			Description: "Get details of a specific calendar event by its ID. Returns full event information including description, attendees, reminders, and conferencing.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calendar_id": map[string]any{
						"type":        "string",
						"description": "Calendar ID. Default: primary.",
					},
					"event_id": map[string]any{
						"type":        "string",
						"description": "The event ID to retrieve.",
					},
				},
				"required": []string{"event_id"},
			},
			RequiredScopes: []string{ScopeCalendarReadonly},
			RateLimit:      30,
		},
		{
			Name:        ToolCalendarCreateEvent,
			Description: "Create a new event on Google Calendar. Supports setting time, location, description, attendees, and reminders.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calendar_id": map[string]any{
						"type":        "string",
						"description": "Calendar ID. Default: primary.",
					},
					"summary": map[string]any{
						"type":        "string",
						"description": "Event title.",
					},
					"description": map[string]any{
						"type":        "string",
						"description": "Event description or notes.",
					},
					"location": map[string]any{
						"type":        "string",
						"description": "Event location (address or place name).",
					},
					"start_time": map[string]any{
						"type":        "string",
						"description": "Event start time in RFC3339 format (e.g. '2025-03-15T10:00:00-05:00').",
					},
					"end_time": map[string]any{
						"type":        "string",
						"description": "Event end time in RFC3339 format.",
					},
					"start_date": map[string]any{
						"type":        "string",
						"description": "For all-day events: start date (YYYY-MM-DD).",
					},
					"end_date": map[string]any{
						"type":        "string",
						"description": "For all-day events: end date (YYYY-MM-DD, exclusive).",
					},
					"attendees": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Email addresses of attendees to invite.",
					},
					"timezone": map[string]any{
						"type":        "string",
						"description": "IANA timezone (e.g. 'America/New_York'). Default: user's calendar timezone.",
					},
					"reminders": map[string]any{
						"type":        "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"method":  map[string]any{"type": "string", "enum": []string{"email", "popup"}},
								"minutes": map[string]any{"type": "integer"},
							},
						},
						"description": "Custom reminders. Each has a method (email/popup) and minutes before event.",
					},
					"recurrence": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Recurrence rules in RRULE format (e.g. 'RRULE:FREQ=WEEKLY;BYDAY=MO,WE,FR').",
					},
				},
				"required": []string{"summary"},
			},
			RequiredScopes: []string{ScopeCalendarEvents},
			RateLimit:      10,
		},
		{
			Name:        ToolCalendarUpdateEvent,
			Description: "Update an existing calendar event. Only specified fields are modified; unspecified fields remain unchanged.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calendar_id": map[string]any{
						"type":        "string",
						"description": "Calendar ID. Default: primary.",
					},
					"event_id": map[string]any{
						"type":        "string",
						"description": "The event ID to update.",
					},
					"summary": map[string]any{
						"type":        "string",
						"description": "Updated event title.",
					},
					"description": map[string]any{
						"type":        "string",
						"description": "Updated event description.",
					},
					"location": map[string]any{
						"type":        "string",
						"description": "Updated event location.",
					},
					"start_time": map[string]any{
						"type":        "string",
						"description": "Updated start time (RFC3339).",
					},
					"end_time": map[string]any{
						"type":        "string",
						"description": "Updated end time (RFC3339).",
					},
				},
				"required": []string{"event_id"},
			},
			RequiredScopes: []string{ScopeCalendarEvents},
			RateLimit:      10,
		},
		{
			Name:        ToolCalendarDeleteEvent,
			Description: "Delete a calendar event. The event is permanently removed.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calendar_id": map[string]any{
						"type":        "string",
						"description": "Calendar ID. Default: primary.",
					},
					"event_id": map[string]any{
						"type":        "string",
						"description": "The event ID to delete.",
					},
				},
				"required": []string{"event_id"},
			},
			RequiredScopes: []string{ScopeCalendarEvents},
			RateLimit:      10,
		},
		{
			Name:        ToolCalendarListCalendars,
			Description: "List all calendars accessible to the user. Returns calendar names, IDs, and access roles.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			RequiredScopes: []string{ScopeCalendarReadonly},
			RateLimit:      10,
		},
		{
			Name:        ToolCalendarQuickAdd,
			Description: "Create an event using natural language. Google Calendar parses the text to determine event details (e.g. 'Lunch with Sarah at noon tomorrow at The Coffee Shop').",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"calendar_id": map[string]any{
						"type":        "string",
						"description": "Calendar ID. Default: primary.",
					},
					"text": map[string]any{
						"type":        "string",
						"description": "Natural language event description (e.g. 'Meeting with team at 3pm on Friday').",
					},
				},
				"required": []string{"text"},
			},
			RequiredScopes: []string{ScopeCalendarEvents},
			RateLimit:      10,
		},
	}
}
