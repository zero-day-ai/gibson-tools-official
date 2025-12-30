package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the metasploit tool
func InputSchema() schema.JSON {
	options := schema.Object(map[string]schema.JSON{})
	options.Description = "Module options as key-value pairs (e.g., RHOSTS, RPORT, LHOST, LPORT)"

	payloadOptions := schema.Object(map[string]schema.JSON{})
	payloadOptions.Description = "Payload options as key-value pairs (optional)"

	return schema.Object(map[string]schema.JSON{
		"module":          schema.StringWithDesc("Exploit or auxiliary module path (e.g., exploit/windows/smb/ms17_010_eternalblue)"),
		"options":         options,
		"payload":         schema.StringWithDesc("Payload module path (optional, e.g., windows/meterpreter/reverse_tcp)"),
		"payload_options": payloadOptions,
	}, "module", "options") // module and options are required
}

// OutputSchema defines the output schema for the metasploit tool
func OutputSchema() schema.JSON {
	successField := schema.Bool()
	successField.Description = "Whether the module executed successfully"

	sessionID := schema.Int()
	sessionID.Description = "Session ID"

	sessionArray := schema.Array(
		schema.Object(map[string]schema.JSON{
			"id":           sessionID,
			"type":         schema.StringWithDesc("Session type (e.g., meterpreter, shell)"),
			"info":         schema.StringWithDesc("Session information"),
			"tunnel_local": schema.StringWithDesc("Local tunnel endpoint"),
			"tunnel_peer":  schema.StringWithDesc("Remote tunnel endpoint"),
		}),
	)
	sessionArray.Description = "List of sessions created by the module"

	execTime := schema.Int()
	execTime.Description = "Execution time in milliseconds"

	return schema.Object(map[string]schema.JSON{
		"success":           successField,
		"module":            schema.StringWithDesc("The module that was executed"),
		"sessions":          sessionArray,
		"output":            schema.StringWithDesc("Console output from the module execution"),
		"execution_time_ms": execTime,
	})
}
