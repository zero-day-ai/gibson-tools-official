package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the winpeas tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target_shell": schema.StringWithDesc("Command execution interface (required)"),
		"checks": schema.JSON{
			Type:        "array",
			Items:       &schema.JSON{Type: "string"},
			Description: "Specific checks to run (optional)",
		},
		"quiet": schema.JSON{
			Type:        "boolean",
			Description: "Reduce output verbosity (optional)",
		},
	}, "target_shell") // target_shell is required
}

// OutputSchema defines the output schema for the winpeas tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"system_info": schema.JSON{
			Type:        "object",
			Properties:  map[string]schema.JSON{},
			Description: "System information",
		},
		"users": schema.JSON{
			Type: "array",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"username": schema.StringWithDesc("Username"),
					"groups": schema.JSON{
						Type:        "array",
						Items:       &schema.JSON{Type: "string"},
						Description: "User groups",
					},
					"privileges": schema.JSON{
						Type:        "array",
						Items:       &schema.JSON{Type: "string"},
						Description: "User privileges",
					},
				},
			},
			Description: "User accounts and privileges",
		},
		"services": schema.JSON{
			Type: "array",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"name": schema.StringWithDesc("Service name"),
					"path": schema.StringWithDesc("Service binary path"),
					"vulnerable": schema.JSON{
						Type:        "boolean",
						Description: "Whether service is vulnerable",
					},
					"reason": schema.StringWithDesc("Vulnerability reason"),
				},
			},
			Description: "Windows services",
		},
		"scheduled_tasks": schema.JSON{
			Type: "array",
			Items: &schema.JSON{
				Type:       "object",
				Properties: map[string]schema.JSON{},
			},
			Description: "Scheduled tasks",
		},
		"unquoted_paths": schema.JSON{
			Type:        "array",
			Items:       &schema.JSON{Type: "string"},
			Description: "Unquoted service paths",
		},
		"registry_autoruns": schema.JSON{
			Type: "array",
			Items: &schema.JSON{
				Type:       "object",
				Properties: map[string]schema.JSON{},
			},
			Description: "Registry autorun entries",
		},
		"possible_exploits": schema.JSON{
			Type: "array",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"name":        schema.StringWithDesc("Exploit name"),
					"cve":         schema.StringWithDesc("CVE identifier"),
					"description": schema.StringWithDesc("Exploit description"),
				},
			},
			Description: "Possible privilege escalation exploits",
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Scan duration in milliseconds",
		},
	})
}
