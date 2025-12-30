package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for nuclei tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("Target URL or host to scan (required)"),
		"templates": schema.JSON{
			Type:        "array",
			Description: "Specific template IDs to use (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"severity": schema.JSON{
			Type:        "array",
			Description: "Filter templates by severity (info, low, medium, high, critical)",
			Items:       &schema.JSON{Type: "string"},
		},
		"tags": schema.JSON{
			Type:        "array",
			Description: "Filter templates by tags (optional)",
			Items:       &schema.JSON{Type: "string"},
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"rate_limit": schema.JSON{
			Type:        "integer",
			Description: "Maximum requests per second (optional)",
			Default:     150,
		},
	}, "target") // target is required
}

// OutputSchema returns the JSON schema for nuclei tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.String(),
		"findings": schema.Array(schema.Object(map[string]schema.JSON{
			"template_id":   schema.String(),
			"template_name": schema.String(),
			"severity":      schema.String(),
			"type":          schema.String(),
			"matched_at":    schema.String(),
			"extracted":     schema.Array(schema.String()),
		})),
		"total_findings": schema.Int(),
		"scan_time_ms":   schema.Int(),
	})
}
