package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for gobuster tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"url": schema.StringWithDesc("Target URL for directory/file brute-forcing (required)"),
		"wordlist": schema.JSON{
			Type:        "string",
			Description: "Path to wordlist file (optional, defaults to common.txt)",
			Default:     "/usr/share/wordlists/dirb/common.txt",
		},
		"mode": schema.JSON{
			Type:        "string",
			Description: "Scan mode: dir, dns, vhost, fuzz, s3, gcs, tftp",
			Enum:        []any{"dir", "dns", "vhost", "fuzz", "s3", "gcs", "tftp"},
			Default:     "dir",
		},
		"extensions": schema.JSON{
			Type:        "array",
			Description: "File extensions to search for (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"threads": schema.JSON{
			Type:        "integer",
			Description: "Number of concurrent threads (optional)",
			Default:     10,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"status_codes": schema.JSON{
			Type:        "string",
			Description: "Positive status codes to match (optional)",
			Default:     "200,204,301,302,307,401,403",
		},
	}, "url") // url is required
}

// OutputSchema returns the JSON schema for gobuster tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"url": schema.String(),
		"results": schema.Array(schema.Object(map[string]schema.JSON{
			"path":        schema.String(),
			"status_code": schema.Int(),
			"size":        schema.Int(),
		})),
		"total_found":  schema.Int(),
		"scan_time_ms": schema.Int(),
	})
}
