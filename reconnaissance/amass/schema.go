package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema returns the JSON schema for amass tool input.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain for enumeration (required)"),
		"mode": schema.JSON{
			Type:        "string",
			Description: "Enumeration mode: passive or active",
			Enum:        []any{"passive", "active"},
			Default:     "passive",
		},
		"timeout": schema.JSON{
			Type:        "integer",
			Description: "Execution timeout in seconds (optional)",
		},
		"max_depth": schema.JSON{
			Type:        "integer",
			Description: "DNS recursion depth (optional)",
		},
		"include_whois": schema.JSON{
			Type:        "boolean",
			Description: "Include WHOIS information (optional)",
		},
		"include_asn": schema.JSON{
			Type:        "boolean",
			Description: "Include ASN information (optional)",
		},
	}, "domain") // domain is required
}

// OutputSchema returns the JSON schema for amass tool output.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.String(),
		"subdomains": schema.Array(schema.String()),
		"ip_addresses": schema.Array(schema.String()),
		"asn_info": schema.Array(schema.Object(map[string]schema.JSON{
			"asn":         schema.Int(),
			"description": schema.String(),
			"country":     schema.String(),
		})),
		"dns_records": schema.Array(schema.Object(map[string]schema.JSON{
			"name":  schema.String(),
			"type":  schema.String(),
			"value": schema.String(),
		})),
		"whois": schema.Object(map[string]schema.JSON{}), // Generic object for WHOIS data
		"scan_time_ms": schema.Int(),
	})
}
