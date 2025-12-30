package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for the chisel tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"mode": schema.JSON{
			Type:        "string",
			Description: "Operation mode: server or client",
			Enum:        []any{"server", "client"},
		},
		"server_addr": schema.JSON{
			Type:        "string",
			Description: "Server address (required for client mode, format: host:port)",
		},
		"local_port": schema.JSON{
			Type:        "integer",
			Description: "Local port to bind (for server mode) or local port for tunnel",
		},
		"remote": schema.JSON{
			Type:        "string",
			Description: "Remote endpoint mapping (format: remote_host:remote_port or R:local_port:remote_host:remote_port)",
		},
		"reverse": schema.JSON{
			Type:        "boolean",
			Description: "Enable reverse tunnel (client listens, server connects)",
			Default:     false,
		},
	}, "mode", "local_port", "remote")
}

// OutputSchema defines the output structure for the chisel tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": schema.JSON{
			Type:        "boolean",
			Description: "Whether the tunnel was established successfully",
		},
		"tunnel_id": schema.JSON{
			Type:        "string",
			Description: "Unique identifier for this tunnel session",
		},
		"local_endpoint": schema.JSON{
			Type:        "string",
			Description: "Local endpoint address (host:port)",
		},
		"remote_endpoint": schema.JSON{
			Type:        "string",
			Description: "Remote endpoint address (host:port)",
		},
		"status": schema.JSON{
			Type:        "string",
			Description: "Current tunnel status (connecting, connected, failed, closed)",
		},
	})
}
