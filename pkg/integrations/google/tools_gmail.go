package google

import "github.com/operatoronline/Operator-OS/pkg/integrations"

// Gmail tool names.
const (
	ToolGmailListMessages   = "gmail_list_messages"
	ToolGmailGetMessage     = "gmail_get_message"
	ToolGmailSendMessage    = "gmail_send_message"
	ToolGmailSearchMessages = "gmail_search_messages"
	ToolGmailListLabels     = "gmail_list_labels"
	ToolGmailModifyLabels   = "gmail_modify_labels"
	ToolGmailTrashMessage   = "gmail_trash_message"
)

func gmailTools() []integrations.ToolManifest {
	return []integrations.ToolManifest{
		{
			Name:        ToolGmailListMessages,
			Description: "List recent email messages from the user's Gmail inbox. Returns message IDs, subjects, and snippets.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"max_results": map[string]any{
						"type":        "integer",
						"description": "Maximum number of messages to return (1-100). Default: 10.",
					},
					"label_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Filter by label IDs (e.g. INBOX, UNREAD, STARRED).",
					},
					"page_token": map[string]any{
						"type":        "string",
						"description": "Token for fetching the next page of results.",
					},
				},
			},
			RequiredScopes: []string{ScopeGmailReadonly},
			RateLimit:      30,
		},
		{
			Name:        ToolGmailGetMessage,
			Description: "Get the full content of a specific email message by its ID. Returns headers, body (plain text), and attachment metadata.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"message_id": map[string]any{
						"type":        "string",
						"description": "The Gmail message ID to retrieve.",
					},
					"format": map[string]any{
						"type":        "string",
						"enum":        []string{"full", "metadata", "minimal"},
						"description": "Response format. 'full' includes body, 'metadata' includes headers only, 'minimal' includes IDs only. Default: full.",
					},
				},
				"required": []string{"message_id"},
			},
			RequiredScopes: []string{ScopeGmailReadonly},
			RateLimit:      30,
		},
		{
			Name:        ToolGmailSendMessage,
			Description: "Send an email message. Supports plain text and HTML body, CC, BCC.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"to": map[string]any{
						"type":        "string",
						"description": "Recipient email address.",
					},
					"subject": map[string]any{
						"type":        "string",
						"description": "Email subject line.",
					},
					"body": map[string]any{
						"type":        "string",
						"description": "Email body content (plain text).",
					},
					"html_body": map[string]any{
						"type":        "string",
						"description": "Email body content (HTML). If provided, takes precedence over body.",
					},
					"cc": map[string]any{
						"type":        "string",
						"description": "CC recipient email address.",
					},
					"bcc": map[string]any{
						"type":        "string",
						"description": "BCC recipient email address.",
					},
					"reply_to_message_id": map[string]any{
						"type":        "string",
						"description": "If replying, the message ID of the original email.",
					},
					"thread_id": map[string]any{
						"type":        "string",
						"description": "Thread ID to add this message to (for replies).",
					},
				},
				"required": []string{"to", "subject", "body"},
			},
			RequiredScopes: []string{ScopeGmailSend},
			RateLimit:      10,
		},
		{
			Name:        ToolGmailSearchMessages,
			Description: "Search Gmail messages using Gmail search syntax (same as the Gmail search bar). Returns matching message IDs and snippets.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Gmail search query (e.g. 'from:user@example.com', 'is:unread', 'subject:invoice', 'newer_than:7d').",
					},
					"max_results": map[string]any{
						"type":        "integer",
						"description": "Maximum number of results (1-100). Default: 10.",
					},
				},
				"required": []string{"query"},
			},
			RequiredScopes: []string{ScopeGmailReadonly},
			RateLimit:      20,
		},
		{
			Name:        ToolGmailListLabels,
			Description: "List all Gmail labels (folders and categories) for the user's account.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			},
			RequiredScopes: []string{ScopeGmailLabels},
			RateLimit:      10,
		},
		{
			Name:        ToolGmailModifyLabels,
			Description: "Add or remove labels from a message. Use this to mark as read/unread, star/unstar, archive, or apply custom labels.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"message_id": map[string]any{
						"type":        "string",
						"description": "The Gmail message ID to modify.",
					},
					"add_label_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Label IDs to add (e.g. STARRED, UNREAD, or custom label IDs).",
					},
					"remove_label_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Label IDs to remove (e.g. UNREAD to mark as read, INBOX to archive).",
					},
				},
				"required": []string{"message_id"},
			},
			RequiredScopes: []string{ScopeGmailModify},
			RateLimit:      20,
		},
		{
			Name:        ToolGmailTrashMessage,
			Description: "Move an email message to the trash. The message can be recovered within 30 days.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"message_id": map[string]any{
						"type":        "string",
						"description": "The Gmail message ID to trash.",
					},
				},
				"required": []string{"message_id"},
			},
			RequiredScopes: []string{ScopeGmailModify},
			RateLimit:      10,
		},
	}
}
