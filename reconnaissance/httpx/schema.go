package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for httpx tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"targets": schema.JSON{
			Type:        "array",
			Description: "List of URLs or hosts to probe (required)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"follow_redirects": schema.JSON{
			Type:        "boolean",
			Description: "Follow HTTP redirects (optional)",
			Default:     true,
		},
		"status_code": schema.JSON{
			Type:        "boolean",
			Description: "Display status code (optional)",
			Default:     true,
		},
		"title": schema.JSON{
			Type:        "boolean",
			Description: "Display page title (optional)",
			Default:     true,
		},
		"tech_detect": schema.JSON{
			Type:        "boolean",
			Description: "Detect technologies (optional)",
			Default:     false,
		},
	}, "targets") // targets is required
}

// OutputSchema returns the JSON schema for httpx tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"results": schema.Array(schema.Object(map[string]schema.JSON{
			"url":          schema.String(),
			"status_code":  schema.Int(),
			"title":        schema.String(),
			"content_type": schema.String(),
			"technologies": schema.Array(schema.String()),
		})),
		"total_probed":  schema.Int(),
		"alive_count":   schema.Int(),
		"scan_time_ms":  schema.Int(),
	})
}
