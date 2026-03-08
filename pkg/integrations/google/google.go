// Package google provides Google Workspace integration manifests and tool executors
// for Gmail, Google Drive, and Google Calendar.
package google

import (
	"github.com/operatoronline/Operator-OS/pkg/integrations"
	"github.com/operatoronline/Operator-OS/pkg/oauth"
)

// Provider IDs.
const (
	ProviderID = "google"
)

// Integration IDs.
const (
	GmailIntegrationID    = "google_gmail"
	DriveIntegrationID    = "google_drive"
	CalendarIntegrationID = "google_calendar"
)

// Google OAuth endpoints.
const (
	AuthorizationURL = "https://accounts.google.com/o/oauth2/v2/auth"
	TokenURL         = "https://oauth2.googleapis.com/token"
)

// Google API base URLs.
const (
	GmailAPIBase    = "https://gmail.googleapis.com"
	DriveAPIBase    = "https://www.googleapis.com"
	CalendarAPIBase = "https://www.googleapis.com"
)

// Gmail scopes.
const (
	ScopeGmailReadonly = "https://www.googleapis.com/auth/gmail.readonly"
	ScopeGmailSend     = "https://www.googleapis.com/auth/gmail.send"
	ScopeGmailModify   = "https://www.googleapis.com/auth/gmail.modify"
	ScopeGmailLabels   = "https://www.googleapis.com/auth/gmail.labels"
)

// Drive scopes.
const (
	ScopeDriveReadonly = "https://www.googleapis.com/auth/drive.readonly"
	ScopeDriveFile     = "https://www.googleapis.com/auth/drive.file"
	ScopeDriveFull     = "https://www.googleapis.com/auth/drive"
)

// Calendar scopes.
const (
	ScopeCalendarReadonly = "https://www.googleapis.com/auth/calendar.readonly"
	ScopeCalendarEvents   = "https://www.googleapis.com/auth/calendar.events"
	ScopeCalendarFull     = "https://www.googleapis.com/auth/calendar"
)

// NewOAuthProvider returns a Google OAuth 2.0 provider configuration.
// clientID, clientSecret, and redirectURL must be provided by the caller
// (from environment or config).
func NewOAuthProvider(clientID, clientSecret, redirectURL string) *oauth.Provider {
	return &oauth.Provider{
		ID:           ProviderID,
		Name:         "Google",
		AuthURL:      AuthorizationURL,
		TokenURL:     TokenURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		UsePKCE:      true,
		Scopes: []string{
			"openid",
			"email",
			"profile",
		},
		ExtraAuthParams: map[string]string{
			"access_type": "offline",
			"prompt":      "consent",
		},
	}
}

// GmailIntegration returns the Gmail integration manifest.
func GmailIntegration() *integrations.Integration {
	return &integrations.Integration{
		ID:          GmailIntegrationID,
		Name:        "Gmail",
		Icon:        "gmail",
		Category:    "email",
		Description: "Read, send, and manage emails via Gmail API.",
		AuthType:    integrations.AuthTypeOAuth2,
		OAuth: &integrations.OAuthConfig{
			AuthorizationURL: AuthorizationURL,
			TokenURL:         TokenURL,
			Scopes:           []string{ScopeGmailReadonly, ScopeGmailSend, ScopeGmailModify, ScopeGmailLabels},
			UsePKCE:          true,
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
		RequiredPlan: "free",
		Tools:        gmailTools(),
		Status:       integrations.IntegrationStatusActive,
		Version:      "1.0.0",
	}
}

// DriveIntegration returns the Google Drive integration manifest.
func DriveIntegration() *integrations.Integration {
	return &integrations.Integration{
		ID:          DriveIntegrationID,
		Name:        "Google Drive",
		Icon:        "drive",
		Category:    "storage",
		Description: "Search, read, and manage files in Google Drive.",
		AuthType:    integrations.AuthTypeOAuth2,
		OAuth: &integrations.OAuthConfig{
			AuthorizationURL: AuthorizationURL,
			TokenURL:         TokenURL,
			Scopes:           []string{ScopeDriveReadonly, ScopeDriveFile},
			UsePKCE:          true,
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
		RequiredPlan: "free",
		Tools:        driveTools(),
		Status:       integrations.IntegrationStatusActive,
		Version:      "1.0.0",
	}
}

// CalendarIntegration returns the Google Calendar integration manifest.
func CalendarIntegration() *integrations.Integration {
	return &integrations.Integration{
		ID:          CalendarIntegrationID,
		Name:        "Google Calendar",
		Icon:        "calendar",
		Category:    "productivity",
		Description: "View, create, and manage calendar events.",
		AuthType:    integrations.AuthTypeOAuth2,
		OAuth: &integrations.OAuthConfig{
			AuthorizationURL: AuthorizationURL,
			TokenURL:         TokenURL,
			Scopes:           []string{ScopeCalendarReadonly, ScopeCalendarEvents},
			UsePKCE:          true,
			ExtraAuthParams: map[string]string{
				"access_type": "offline",
				"prompt":      "consent",
			},
		},
		RequiredPlan: "free",
		Tools:        calendarTools(),
		Status:       integrations.IntegrationStatusActive,
		Version:      "1.0.0",
	}
}

// AllIntegrations returns all Google integration manifests.
func AllIntegrations() []*integrations.Integration {
	return []*integrations.Integration{
		GmailIntegration(),
		DriveIntegration(),
		CalendarIntegration(),
	}
}

// RegisterAll registers all Google integrations into the registry.
// Returns the number of integrations registered, or the first error.
func RegisterAll(registry *integrations.IntegrationRegistry) (int, error) {
	count := 0
	for _, integ := range AllIntegrations() {
		if err := registry.Register(integ); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}
