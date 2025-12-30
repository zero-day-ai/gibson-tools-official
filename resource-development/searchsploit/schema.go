package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input parameters for searchsploit tool.
// Based on FR-2.1 requirements.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"query": schema.StringWithDesc("Search terms for finding exploits"),
		"exact": schema.JSON{
			Type:        "boolean",
			Description: "Perform exact match search",
		},
		"cve": schema.StringWithDesc("CVE ID to search for (e.g., CVE-2021-1234)"),
		"type": schema.JSON{
			Type:        "string",
			Description: "Filter by type",
			Enum:        []any{"exploits", "shellcodes", "papers"},
		},
		"platform": schema.StringWithDesc("Target platform filter (e.g., linux, windows, osx)"),
	}, "query") // query is required
}

// OutputSchema defines the output structure for searchsploit tool.
// Based on FR-2.1 requirements.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"results": schema.Array(schema.Object(map[string]schema.JSON{
			"id":       schema.StringWithDesc("Exploit database ID"),
			"title":    schema.StringWithDesc("Exploit title/description"),
			"path":     schema.StringWithDesc("Path to exploit file in exploit-db"),
			"type":     schema.StringWithDesc("Type of exploit (exploit, shellcode, paper)"),
			"platform": schema.StringWithDesc("Target platform"),
			"date":     schema.StringWithDesc("Publication date"),
			"author":   schema.StringWithDesc("Exploit author"),
			"verified": schema.JSON{
				Type:        "boolean",
				Description: "Whether the exploit has been verified",
			},
		})),
		"total_results": schema.JSON{
			Type:        "integer",
			Description: "Total number of results found",
		},
	})
}
