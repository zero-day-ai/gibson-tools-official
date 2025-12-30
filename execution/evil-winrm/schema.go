package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the evil-winrm tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("Target host (IP or hostname)"),
		"username": schema.StringWithDesc("Username for authentication"),
		"password": schema.StringWithDesc("Password for authentication (optional if using hash)"),
		"hash": schema.StringWithDesc("NTLM hash for pass-the-hash authentication (optional if using password)"),
		"command": schema.StringWithDesc("Single command to execute (optional)"),
		"script": schema.StringWithDesc("PowerShell script path to execute (optional)"),
		"port": schema.JSON{
			Type:        "integer",
			Description: "WinRM port (default: 5985)",
			Default:     5985,
		},
	}, "target", "username") // target and username are required
}

// OutputSchema defines the output schema for the evil-winrm tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": schema.JSON{
			Type:        "boolean",
			Description: "Whether the command executed successfully",
		},
		"output": schema.StringWithDesc("Command output"),
		"error": schema.StringWithDesc("Error message if execution failed"),
		"execution_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Execution duration in milliseconds",
		},
	})
}
