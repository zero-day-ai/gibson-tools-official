package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for slowhttptest
func InputSchema() schema.JSON {
	attackTypeSchema := schema.String()
	attackTypeSchema.Enum = []any{"slowloris", "slowread", "slowpost", "range"}
	attackTypeSchema.Description = "Type of slow HTTP attack to perform"

	return schema.Object(map[string]schema.JSON{
		"target":      schema.StringWithDesc("Target URL (e.g., http://example.com)"),
		"attack_type": attackTypeSchema,
		"connections": schema.Int(),
		"duration":    schema.Int(),
		"rate":        schema.Int(),
	}, "target", "attack_type")
}

// OutputSchema defines the output structure for slowhttptest results
func OutputSchema() schema.JSON {
	statusSchema := schema.String()
	statusSchema.Enum = []any{"available", "unavailable", "degraded"}

	return schema.Object(map[string]schema.JSON{
		"target_status":           statusSchema,
		"connections_established": schema.Int(),
		"test_duration_seconds":   schema.Int(),
		"response_times_ms": schema.Object(map[string]schema.JSON{
			"initial": schema.Int(),
			"final":   schema.Int(),
		}),
	})
}
