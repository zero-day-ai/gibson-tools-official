package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the xfreerdp tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target":   withDesc(schema.String(), "Target host (IP or hostname) for RDP connection (required)"),
		"username": withDesc(schema.String(), "Username for authentication (required)"),
		"password": withDesc(schema.String(), "Password for authentication (optional, use with password or hash)"),
		"hash":     withDesc(schema.String(), "NTLM hash for pass-the-hash authentication (optional, format: LM:NT)"),
		"domain":   withDesc(schema.String(), "Domain for authentication (optional)"),
		"port":     withDesc(schema.Int(), "RDP port (optional, default: 3389)"),
		"command":  withDesc(schema.String(), "RemoteApp command to execute (optional, for RemoteApp sessions)"),
	}, "target", "username") // target and username are required
}

// OutputSchema defines the output schema for the xfreerdp tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"connected":  withDesc(schema.Bool(), "Whether the RDP connection was successful"),
		"session_id": withDesc(schema.String(), "Session identifier (process ID)"),
		"error":      withDesc(schema.String(), "Error message if connection failed"),
	})
}

// withDesc adds a description to a JSON schema
func withDesc(j schema.JSON, desc string) schema.JSON {
	j.Description = desc
	return j
}
