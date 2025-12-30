package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input structure for theHarvester tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain to harvest information from (required)"),
		"sources": schema.JSON{
			Type:        "array",
			Description: "Search engines and data sources to query (optional)",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"limit": schema.JSON{
			Type:        "integer",
			Description: "Maximum results per source (optional, default: 500)",
			Default:     500,
		},
		"start": schema.JSON{
			Type:        "integer",
			Description: "Pagination start offset (optional, default: 0)",
			Default:     0,
		},
	}, "domain") // domain is required
}

// OutputSchema defines the output structure for theHarvester tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"domain": schema.StringWithDesc("Target domain that was scanned"),
		"emails": schema.JSON{
			Type:        "array",
			Description: "Discovered email addresses",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"hosts": schema.JSON{
			Type:        "array",
			Description: "Discovered hostnames and subdomains",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"ips": schema.JSON{
			Type:        "array",
			Description: "Discovered IP addresses",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"interesting_urls": schema.JSON{
			Type:        "array",
			Description: "Interesting URLs found during reconnaissance",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"people": schema.JSON{
			Type:        "array",
			Description: "Names and people associated with the domain",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"sources_queried": schema.JSON{
			Type:        "array",
			Description: "List of sources that were queried",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Total scan time in milliseconds",
		},
	})
}
