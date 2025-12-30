package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the rclone tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"source": schema.StringWithDesc("Local file or directory path to exfiltrate"),
		"destination": schema.StringWithDesc("Remote path in format 'remote:path'"),
		"provider": schema.JSON{
			Type:        "string",
			Description: "Cloud storage provider",
			Enum:        []any{"s3", "gcs", "azure", "dropbox", "gdrive"},
		},
		"config": schema.Object(map[string]schema.JSON{
			// S3 specific config
			"access_key_id": schema.StringWithDesc("AWS access key ID (for s3)"),
			"secret_access_key": schema.StringWithDesc("AWS secret access key (for s3)"),
			"region": schema.StringWithDesc("AWS region (for s3)"),
			"endpoint": schema.StringWithDesc("S3-compatible endpoint URL (for s3)"),

			// GCS specific config
			"service_account_credentials": schema.StringWithDesc("GCS service account JSON (for gcs)"),
			"project_number": schema.StringWithDesc("GCP project number (for gcs)"),

			// Azure specific config
			"account": schema.StringWithDesc("Azure storage account name (for azure)"),
			"key": schema.StringWithDesc("Azure storage account key (for azure)"),

			// Dropbox specific config
			"dropbox_token": schema.StringWithDesc("Dropbox access token (for dropbox)"),

			// Google Drive specific config
			"client_id": schema.StringWithDesc("OAuth client ID (for gdrive)"),
			"client_secret": schema.StringWithDesc("OAuth client secret (for gdrive)"),
			"gdrive_token": schema.StringWithDesc("OAuth token JSON (for gdrive)"),
		}),
	}, "source", "destination", "provider", "config")
}

// OutputSchema defines the output schema for the rclone tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"transferred": schema.JSON{
			Type:        "integer",
			Description: "Number of bytes transferred",
		},
		"files_count": schema.JSON{
			Type:        "integer",
			Description: "Number of files transferred",
		},
		"transfer_rate": schema.StringWithDesc("Average transfer rate (e.g., '1.5 MBytes/s')"),
		"destination_url": schema.StringWithDesc("Full destination URL/path"),
	})
}
