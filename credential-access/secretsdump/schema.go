package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for secretsdump
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("Target host (IP, hostname, or domain)"),
		"domain": schema.StringWithDesc("Domain name (optional)"),
		"username": schema.StringWithDesc("Username for authentication"),
		"password": schema.StringWithDesc("Password for authentication (optional)"),
		"hash": schema.StringWithDesc("NTLM hash for pass-the-hash authentication (optional)"),
		"method": schema.JSON{
			Type:        "string",
			Description: "Extraction method (sam, lsa, ntds) - optional, will try all if not specified",
			Enum:        []any{"sam", "lsa", "ntds"},
		},
	}, "target", "username") // Required fields
}

// OutputSchema defines the output structure for secretsdump
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain_users": schema.Array(schema.Object(map[string]schema.JSON{
			"username": schema.String(),
			"rid":      schema.Int(),
			"lm_hash":  schema.String(),
			"nt_hash":  schema.String(),
		})),
		"machine_accounts": schema.Array(schema.Object(map[string]schema.JSON{
			"username": schema.String(),
			"lm_hash":  schema.String(),
			"nt_hash":  schema.String(),
		})),
		"cached_credentials": schema.Array(schema.Object(map[string]schema.JSON{
			"username": schema.String(),
			"hash":     schema.String(),
		})),
		"dpapi_keys": schema.Array(schema.Object(map[string]schema.JSON{
			"username": schema.String(),
			"key":      schema.String(),
		})),
	})
}
