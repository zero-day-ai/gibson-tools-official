package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the Impacket suite tool.
// Supports multiple execution methods: psexec, wmiexec, smbexec, atexec, dcomexec.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"tool": schema.JSON{
			Type:        "string",
			Description: "Impacket tool to use",
			Enum:        []any{"psexec", "wmiexec", "smbexec", "atexec", "dcomexec"},
		},
		"target": schema.StringWithDesc("Target host (IP or hostname)"),
		"domain": schema.StringWithDesc("Domain name (optional)"),
		"username": schema.StringWithDesc("Username for authentication"),
		"password": schema.StringWithDesc("Password for authentication (optional if hash is provided)"),
		"hash": schema.StringWithDesc("NTLM hash for pass-the-hash authentication (optional if password is provided)"),
		"command": schema.StringWithDesc("Command to execute on the target"),
	}, "tool", "target", "username", "command")
}

// OutputSchema defines the output schema for the Impacket suite tool.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": schema.JSON{
			Type:        "boolean",
			Description: "Whether the command executed successfully",
		},
		"tool": schema.StringWithDesc("Impacket tool that was used"),
		"output": schema.StringWithDesc("Command output from the target"),
		"error": schema.StringWithDesc("Error message if execution failed"),
		"execution_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Time taken to execute the command in milliseconds",
		},
	})
}
