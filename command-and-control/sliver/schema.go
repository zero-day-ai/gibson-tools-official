package main

import "github.com/zero-day-ai/sdk/schema"

// WithDesc adds a description to a JSON schema
func WithDesc(j schema.JSON, desc string) schema.JSON {
	j.Description = desc
	return j
}

// InputSchema defines the input schema for the sliver tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"action": WithDesc(
			schema.Enum("generate", "sessions", "beacons", "use", "shell"),
			"Action to perform: generate implant, list sessions/beacons, or execute command",
		),
		"implant_config": WithDesc(
			schema.Object(map[string]schema.JSON{
				"os": WithDesc(
					schema.Enum("windows", "linux", "darwin"),
					"Target operating system",
				),
				"arch": WithDesc(
					schema.Enum("amd64", "386", "arm64"),
					"Target architecture",
				),
				"format": WithDesc(
					schema.Enum("exe", "shared", "service", "shellcode"),
					"Output format",
				),
				"c2_endpoints": WithDesc(
					schema.Array(schema.String()),
					"C2 server endpoints (e.g., https://192.168.1.100:443)",
				),
			}),
			"Implant generation configuration (required for 'generate' action)",
		),
		"session_id": schema.StringWithDesc("Session ID for 'use' or 'shell' actions"),
		"command":    schema.StringWithDesc("Command to execute (required for 'shell' action)"),
	}, "action") // action is required
}

// OutputSchema defines the output schema for the sliver tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": WithDesc(
			schema.Bool(),
			"Whether the action completed successfully",
		),
		"sessions": WithDesc(
			schema.Array(schema.Object(map[string]schema.JSON{
				"id":        schema.StringWithDesc("Session ID"),
				"name":      schema.StringWithDesc("Session name"),
				"hostname":  schema.StringWithDesc("Target hostname"),
				"username":  schema.StringWithDesc("Username running the implant"),
				"os":        schema.StringWithDesc("Operating system"),
				"transport": schema.StringWithDesc("Transport protocol (mtls, wg, http, https, dns)"),
			})),
			"List of active sessions",
		),
		"beacons": WithDesc(
			schema.Array(schema.Object(map[string]schema.JSON{
				"id":        schema.StringWithDesc("Beacon ID"),
				"name":      schema.StringWithDesc("Beacon name"),
				"hostname":  schema.StringWithDesc("Target hostname"),
				"username":  schema.StringWithDesc("Username running the implant"),
				"os":        schema.StringWithDesc("Operating system"),
				"transport": schema.StringWithDesc("Transport protocol"),
				"interval":  schema.StringWithDesc("Beacon interval"),
				"jitter":    schema.StringWithDesc("Beacon jitter"),
			})),
			"List of active beacons",
		),
		"output":             schema.StringWithDesc("Command output or generation result"),
		"implant_path":       schema.StringWithDesc("Path to generated implant file"),
		"execution_time_ms":  WithDesc(schema.Int(), "Execution time in milliseconds"),
	})
}
