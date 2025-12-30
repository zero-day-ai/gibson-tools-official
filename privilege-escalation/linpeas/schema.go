package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the linpeas tool.
// The tool executes linpeas.sh on a target system via a shell interface.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target_shell": schema.JSON{
			Type:        "string",
			Description: "Command execution interface for the target system (e.g., 'ssh user@host', session ID, or shell command prefix)",
		},
		"checks": schema.JSON{
			Type:        "array",
			Description: "Specific checks to run (optional)",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"intensity": schema.JSON{
			Type:        "string",
			Description: "Scan intensity level",
			Enum:        []any{"quick", "normal", "thorough"},
			Default:     "normal",
		},
	}, "target_shell")
}

// OutputSchema defines the output schema for the linpeas tool.
// Returns structured privilege escalation findings.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"system_info": schema.JSON{
			Type:        "object",
			Description: "Basic system information",
			Properties: map[string]schema.JSON{
				"hostname":     schema.String(),
				"kernel":       schema.String(),
				"distribution": schema.String(),
				"arch":         schema.String(),
			},
		},
		"users": schema.JSON{
			Type:        "array",
			Description: "User account information",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"username": schema.String(),
					"groups": schema.Array(schema.String()),
					"sudo_privileges": schema.Array(schema.String()),
				},
			},
		},
		"suid_binaries": schema.JSON{
			Type:        "array",
			Description: "SUID binaries found on the system",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"writable_paths": schema.JSON{
			Type:        "array",
			Description: "Writable directories and files",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"cron_jobs": schema.JSON{
			Type:        "array",
			Description: "Cron jobs that may be exploitable",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"user":    schema.String(),
					"command": schema.String(),
					"path":    schema.String(),
				},
			},
		},
		"capabilities": schema.JSON{
			Type:        "array",
			Description: "Files with interesting capabilities",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"file":       schema.String(),
					"capability": schema.String(),
				},
			},
		},
		"interesting_files": schema.JSON{
			Type:        "array",
			Description: "Files that may contain sensitive information",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"possible_exploits": schema.JSON{
			Type:        "array",
			Description: "Potential privilege escalation vectors",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"name":        schema.String(),
					"description": schema.String(),
					"confidence":  schema.String(),
				},
			},
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Total scan time in milliseconds",
		},
	})
}
