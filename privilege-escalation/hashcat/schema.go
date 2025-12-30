package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the hashcat tool.
// Supports dictionary, brute-force, and hybrid attack modes.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"hash_file": schema.JSON{
			Type:        "string",
			Description: "Path to file containing hashes (one per line, or hash:salt format)",
		},
		"hash_type": schema.JSON{
			Type:        "integer",
			Description: "Hashcat mode number (e.g., 0=MD5, 1000=NTLM, 1800=sha512crypt, 3200=bcrypt)",
		},
		"attack_mode": schema.JSON{
			Type:        "string",
			Description: "Attack mode to use",
			Enum:        []any{"dictionary", "bruteforce", "hybrid"},
		},
		"wordlist": schema.JSON{
			Type:        "string",
			Description: "Path to wordlist file (required for dictionary and hybrid attacks)",
		},
		"rules": schema.JSON{
			Type:        "string",
			Description: "Path to rule file for dictionary attacks (optional)",
		},
		"mask": schema.JSON{
			Type:        "string",
			Description: "Mask for brute-force attacks (e.g., '?l?l?l?l?d?d?d?d' for 4 lowercase + 4 digits)",
		},
		"increment": schema.JSON{
			Type:        "boolean",
			Description: "Enable incremental mode for brute-force (start with shorter masks)",
			Default:     false,
		},
		"workload": schema.JSON{
			Type:        "integer",
			Description: "Workload profile (1=low, 2=default, 3=high, 4=nightmare)",
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(4),
			Default:     2,
		},
		"session_name": schema.JSON{
			Type:        "string",
			Description: "Session name for resumable attacks (optional)",
		},
		"max_runtime": schema.JSON{
			Type:        "integer",
			Description: "Maximum runtime in seconds (optional)",
		},
	}, "hash_file", "hash_type", "attack_mode")
}

// OutputSchema defines the output schema for the hashcat tool.
// Returns cracked hash:password pairs and statistics.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"cracked": schema.JSON{
			Type:        "array",
			Description: "List of cracked hash:password pairs",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"hash": schema.JSON{
						Type:        "string",
						Description: "Original hash value",
					},
					"plaintext": schema.JSON{
						Type:        "string",
						Description: "Cracked plaintext password",
					},
				},
			},
		},
		"total_hashes": schema.JSON{
			Type:        "integer",
			Description: "Total number of hashes in input file",
		},
		"cracked_count": schema.JSON{
			Type:        "integer",
			Description: "Number of hashes successfully cracked",
		},
		"exhausted": schema.JSON{
			Type:        "boolean",
			Description: "Whether the attack exhausted all possibilities",
		},
		"speed": schema.JSON{
			Type:        "string",
			Description: "Average cracking speed (e.g., '1.2 GH/s')",
		},
		"runtime_seconds": schema.JSON{
			Type:        "integer",
			Description: "Total runtime in seconds",
		},
		"gpu_info": schema.JSON{
			Type:        "string",
			Description: "GPU information (if available)",
		},
	})
}

// ptrFloat64 is a helper to create a float64 pointer for schema constraints
func ptrFloat64(v float64) *float64 {
	return &v
}
