package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the recon-ng tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"workspace": schema.StringWithDesc("Workspace name for recon-ng session"),
		"module":    schema.StringWithDesc("Module path to execute (e.g., recon/domains-hosts/bing_domain_web)"),
		"options": schema.JSON{
			Type:        "object",
			Description: "Module-specific options as key-value pairs",
		},
		"source_domain": schema.StringWithDesc("Source domain for reconnaissance (optional)"),
	}, "workspace", "module") // workspace and module are required
}

// OutputSchema defines the output schema for the recon-ng tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"module": schema.StringWithDesc("Module that was executed"),
		"results": schema.JSON{
			Type:        "array",
			Description: "Module-specific results as array of objects",
			Items: &schema.JSON{
				Type: "object",
			},
		},
		"result_count": schema.JSON{
			Type:        "integer",
			Description: "Number of results returned",
		},
		"execution_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Execution duration in milliseconds",
		},
	})
}
