package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for bloodhound-python
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target Active Directory domain"),
		"username": schema.StringWithDesc("Username for authentication"),
		"password": schema.StringWithDesc("Password for authentication (optional if using hash)"),
		"hash": schema.StringWithDesc("NTLM hash for authentication (optional if using password)"),
		"dc_ip": schema.StringWithDesc("Domain Controller IP address (optional)"),
		"collection_method": schema.JSON{
			Type:        "string",
			Description: "Data collection method",
			Enum:        []any{"all", "group", "localadmin", "session", "trusts", "default"},
			Default:     "default",
		},
	}, "domain", "username")
}

// OutputSchema defines the output structure for bloodhound results
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"users":              schema.Int(),
		"groups":             schema.Int(),
		"computers":          schema.Int(),
		"domains":            schema.Int(),
		"gpos":               schema.Int(),
		"ous":                schema.Int(),
		"output_files":       schema.Array(schema.String()),
		"collection_time_ms": schema.Int(),
	})
}
