package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the hydra tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target":  schema.StringWithDesc("Target host (IP or hostname)"),
		"service": schema.StringWithDesc("Protocol/service to attack (ssh, ftp, http-post, etc.)"),
		"port": schema.JSON{
			Type:        "integer",
			Description: "Target port (optional, uses service default if not specified)",
		},
		"username": schema.StringWithDesc("Single username to test (optional)"),
		"username_file": schema.StringWithDesc("Path to username wordlist file (optional)"),
		"password": schema.StringWithDesc("Single password to test (optional)"),
		"password_file": schema.StringWithDesc("Path to password wordlist file (optional)"),
		"threads": schema.JSON{
			Type:        "integer",
			Description: "Number of parallel tasks (optional, default: 16)",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Timeout in seconds per attempt (optional, default: 30)",
		},
		"http_path": schema.StringWithDesc("HTTP path for HTTP services (optional, e.g., /login.php)"),
		"http_form": schema.StringWithDesc("HTTP form parameters (optional, e.g., user=^USER^&pass=^PASS^)"),
	}, "target", "service") // target and service are required
}

// OutputSchema defines the output schema for the hydra tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"success": schema.JSON{
			Type:        "boolean",
			Description: "Whether any credentials were found",
		},
		"credentials": schema.JSON{
			Type: "array",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"host":     schema.StringWithDesc("Target host"),
					"port":     schema.Int(),
					"service":  schema.StringWithDesc("Service/protocol"),
					"username": schema.StringWithDesc("Valid username"),
					"password": schema.StringWithDesc("Valid password"),
				},
			},
			Description: "List of found credentials",
		},
		"attempts": schema.JSON{
			Type:        "integer",
			Description: "Total number of authentication attempts",
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Scan duration in milliseconds",
		},
	})
}
