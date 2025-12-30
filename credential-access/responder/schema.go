package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for Responder
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"interface": schema.StringWithDesc("Network interface to listen on (required)"),
		"analyze_mode": schema.JSON{
			Type:        "boolean",
			Description: "Enable analyze mode (passive mode, no poisoning)",
			Default:     false,
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Capture duration in seconds",
			Default:     60,
		},
		"protocols": schema.JSON{
			Type:        "array",
			Description: "Specific protocols to poison (e.g., LLMNR, NBT-NS, MDNS)",
			Items: &schema.JSON{
				Type: "string",
			},
		},
	}, "interface")
}

// OutputSchema defines the output structure for Responder results
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"captured_hashes": schema.Array(schema.Object(map[string]schema.JSON{
			"protocol": schema.JSON{
				Type:        "string",
				Description: "Protocol used (HTTP, SMB, LDAP, etc.)",
			},
			"client_ip": schema.JSON{
				Type:        "string",
				Description: "IP address of the client",
			},
			"username": schema.JSON{
				Type:        "string",
				Description: "Captured username",
			},
			"domain": schema.JSON{
				Type:        "string",
				Description: "Domain or workgroup",
			},
			"hash": schema.JSON{
				Type:        "string",
				Description: "Captured hash value",
			},
			"hash_type": schema.JSON{
				Type:        "string",
				Description: "Hash type (NTLMv1, NTLMv2, etc.)",
			},
		})),
		"capture_time_seconds": schema.JSON{
			Type:        "integer",
			Description: "Total capture duration in seconds",
		},
	})
}
