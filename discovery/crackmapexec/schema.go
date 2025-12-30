package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for crackmapexec/netexec
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"target": schema.StringWithDesc("IP, range, or domain to scan"),
		"protocol": schema.Object(map[string]schema.JSON{
			"type": schema.String(),
			"enum": schema.Enum("smb", "winrm", "ldap", "mssql", "ssh"),
		}),
		"username": schema.StringWithDesc("username for authentication (optional)"),
		"password": schema.StringWithDesc("password for authentication (optional)"),
		"hash":     schema.StringWithDesc("NTLM hash for pass-the-hash (optional)"),
		"module":   schema.StringWithDesc("specific module to run (optional)"),
		"options":  schema.Object(map[string]schema.JSON{}),
	}, "target", "protocol")
}

// OutputSchema defines the output structure for crackmapexec/netexec results
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"hosts": schema.Array(schema.Object(map[string]schema.JSON{
			"ip":       schema.String(),
			"hostname": schema.String(),
			"domain":   schema.String(),
			"os":       schema.String(),
			"signing":  schema.Bool(),
			"smbv1":    schema.Bool(),
		})),
		"users": schema.Array(schema.Object(map[string]schema.JSON{
			"username": schema.String(),
			"domain":   schema.String(),
			"admin":    schema.Bool(),
		})),
		"shares": schema.Array(schema.Object(map[string]schema.JSON{
			"name":        schema.String(),
			"permissions": schema.String(),
		})),
		"module_output": schema.Object(map[string]schema.JSON{}),
	})
}
