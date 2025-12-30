package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the john tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"hash_file": schema.JSON{
			Type:        "string",
			Description: "Path to file containing password hashes",
		},
		"format": schema.JSON{
			Type:        "string",
			Description: "Hash format (optional, auto-detected if not specified)",
		},
		"wordlist": schema.JSON{
			Type:        "string",
			Description: "Path to wordlist file for dictionary attack (optional)",
		},
		"rules": schema.JSON{
			Type:        "string",
			Description: "Rules to apply to wordlist (optional)",
		},
		"incremental": schema.JSON{
			Type:        "boolean",
			Description: "Use incremental mode (brute-force) (optional)",
		},
	}, "hash_file") // hash_file is required
}

// OutputSchema defines the output schema for the john tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"cracked": schema.JSON{
			Type:        "array",
			Description: "List of cracked credentials",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"hash": schema.JSON{
						Type:        "string",
						Description: "Original hash",
					},
					"plaintext": schema.JSON{
						Type:        "string",
						Description: "Cracked password",
					},
					"format": schema.JSON{
						Type:        "string",
						Description: "Hash format",
					},
				},
			},
		},
		"total_hashes": schema.JSON{
			Type:        "integer",
			Description: "Total number of hashes in the file",
		},
		"cracked_count": schema.JSON{
			Type:        "integer",
			Description: "Number of successfully cracked hashes",
		},
	})
}
