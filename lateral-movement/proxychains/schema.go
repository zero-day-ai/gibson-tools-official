package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input structure for the proxychains tool.
// It accepts a list of proxies to chain together and a command to execute through them.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"proxies": schema.Array(schema.Object(map[string]schema.JSON{
			"type": schema.Enum("socks4", "socks5", "http"),
			"host": schema.String(),
			"port": schema.Int(),
		}, "type", "host", "port")),
		"command": schema.StringWithDesc("Command to execute through the proxy chain"),
	}, "proxies", "command")
}

// OutputSchema defines the output structure for the proxychains tool.
// It returns the success status, command output, and any errors.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": schema.Bool(),
		"output":  schema.String(),
		"error":   schema.String(),
	})
}
