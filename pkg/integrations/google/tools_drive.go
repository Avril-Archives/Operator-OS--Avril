package google

import "github.com/operatoronline/Operator-OS/pkg/integrations"

// Drive tool names.
const (
	ToolDriveListFiles    = "drive_list_files"
	ToolDriveGetFile      = "drive_get_file"
	ToolDriveSearchFiles  = "drive_search_files"
	ToolDriveGetContent   = "drive_get_content"
	ToolDriveCreateFile   = "drive_create_file"
	ToolDriveCreateFolder = "drive_create_folder"
	ToolDriveDeleteFile   = "drive_delete_file"
)

func driveTools() []integrations.ToolManifest {
	return []integrations.ToolManifest{
		{
			Name:        ToolDriveListFiles,
			Description: "List files and folders in Google Drive. Returns file names, IDs, MIME types, and modification dates.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"page_size": map[string]any{
						"type":        "integer",
						"description": "Maximum number of files to return (1-100). Default: 10.",
					},
					"folder_id": map[string]any{
						"type":        "string",
						"description": "ID of the folder to list. Use 'root' for the root folder. Default: root.",
					},
					"order_by": map[string]any{
						"type":        "string",
						"description": "Sort order. Options: 'modifiedTime desc', 'name', 'createdTime desc'. Default: 'modifiedTime desc'.",
					},
					"page_token": map[string]any{
						"type":        "string",
						"description": "Token for fetching the next page of results.",
					},
				},
			},
			RequiredScopes: []string{ScopeDriveReadonly},
			RateLimit:      30,
		},
		{
			Name:        ToolDriveGetFile,
			Description: "Get metadata for a specific file or folder by its ID. Returns name, size, MIME type, owners, permissions, and sharing status.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file_id": map[string]any{
						"type":        "string",
						"description": "The Google Drive file ID.",
					},
				},
				"required": []string{"file_id"},
			},
			RequiredScopes: []string{ScopeDriveReadonly},
			RateLimit:      30,
		},
		{
			Name:        ToolDriveSearchFiles,
			Description: "Search for files in Google Drive using Drive query syntax. Returns matching file IDs, names, and types.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Drive search query (e.g. \"name contains 'report'\", \"mimeType='application/pdf'\", \"modifiedTime > '2024-01-01'\").",
					},
					"page_size": map[string]any{
						"type":        "integer",
						"description": "Maximum number of results (1-100). Default: 10.",
					},
				},
				"required": []string{"query"},
			},
			RequiredScopes: []string{ScopeDriveReadonly},
			RateLimit:      20,
		},
		{
			Name:        ToolDriveGetContent,
			Description: "Download and return the text content of a file. Works with Google Docs (exported as plain text), text files, and other text-based formats. Not suitable for binary files.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file_id": map[string]any{
						"type":        "string",
						"description": "The Google Drive file ID.",
					},
					"mime_type": map[string]any{
						"type":        "string",
						"description": "Export MIME type for Google Docs (e.g. 'text/plain', 'text/csv'). Default: 'text/plain'.",
					},
					"max_size": map[string]any{
						"type":        "integer",
						"description": "Maximum content size in bytes to return (to prevent loading huge files). Default: 100000.",
					},
				},
				"required": []string{"file_id"},
			},
			RequiredScopes: []string{ScopeDriveReadonly},
			RateLimit:      20,
		},
		{
			Name:        ToolDriveCreateFile,
			Description: "Create a new file in Google Drive with text content. Supports plain text, Google Docs, and other text-based formats.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "File name (e.g. 'meeting-notes.txt', 'report.md').",
					},
					"content": map[string]any{
						"type":        "string",
						"description": "Text content of the file.",
					},
					"mime_type": map[string]any{
						"type":        "string",
						"description": "MIME type (e.g. 'text/plain', 'application/vnd.google-apps.document'). Default: 'text/plain'.",
					},
					"folder_id": map[string]any{
						"type":        "string",
						"description": "Parent folder ID. Default: root.",
					},
				},
				"required": []string{"name", "content"},
			},
			RequiredScopes: []string{ScopeDriveFile},
			RateLimit:      10,
		},
		{
			Name:        ToolDriveCreateFolder,
			Description: "Create a new folder in Google Drive.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{
						"type":        "string",
						"description": "Folder name.",
					},
					"parent_id": map[string]any{
						"type":        "string",
						"description": "Parent folder ID. Default: root.",
					},
				},
				"required": []string{"name"},
			},
			RequiredScopes: []string{ScopeDriveFile},
			RateLimit:      10,
		},
		{
			Name:        ToolDriveDeleteFile,
			Description: "Move a file or folder to the trash in Google Drive. Can be recovered from trash within 30 days.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"file_id": map[string]any{
						"type":        "string",
						"description": "The Google Drive file ID to trash.",
					},
				},
				"required": []string{"file_id"},
			},
			RequiredScopes: []string{ScopeDriveFile},
			RateLimit:      10,
		},
	}
}
