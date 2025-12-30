package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the Shodan tool
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"query": schema.JSON{
			Type:        "string",
			Description: "Shodan search query (e.g., 'apache', 'port:22', 'country:US')",
		},
		"api_key": schema.JSON{
			Type:        "string",
			Description: "Shodan API key (required for searches)",
		},
		"limit": schema.JSON{
			Type:        "integer",
			Description: "Maximum number of results to return (default: 100)",
			Default:     100,
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(1000),
		},
		"facets": schema.JSON{
			Type:        "array",
			Description: "Facets to include in results (e.g., 'country', 'org', 'port')",
			Items: &schema.JSON{
				Type: "string",
			},
		},
	}, "query", "api_key") // query and api_key are required
}

// OutputSchema defines the output schema for the Shodan tool
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"total": schema.JSON{
			Type:        "integer",
			Description: "Total number of results available",
		},
		"results": schema.JSON{
			Type:        "array",
			Description: "Array of search results",
			Items: &schema.JSON{
				Type: "object",
				Properties: map[string]schema.JSON{
					"ip": schema.JSON{
						Type:        "string",
						Description: "IP address",
					},
					"port": schema.JSON{
						Type:        "integer",
						Description: "Port number",
					},
					"org": schema.JSON{
						Type:        "string",
						Description: "Organization name",
					},
					"isp": schema.JSON{
						Type:        "string",
						Description: "Internet Service Provider",
					},
					"os": schema.JSON{
						Type:        "string",
						Description: "Operating system",
					},
					"product": schema.JSON{
						Type:        "string",
						Description: "Product/service name",
					},
					"version": schema.JSON{
						Type:        "string",
						Description: "Product version",
					},
					"banner": schema.JSON{
						Type:        "string",
						Description: "Service banner",
					},
					"vulns": schema.JSON{
						Type:        "array",
						Description: "List of CVE IDs for known vulnerabilities",
						Items: &schema.JSON{
							Type: "string",
						},
					},
					"location": schema.JSON{
						Type:        "object",
						Description: "Geographic location information",
						Properties: map[string]schema.JSON{
							"country_code": schema.JSON{Type: "string"},
							"country_name": schema.JSON{Type: "string"},
							"city":         schema.JSON{Type: "string"},
							"latitude":     schema.JSON{Type: "number"},
							"longitude":    schema.JSON{Type: "number"},
						},
					},
				},
			},
		},
		"facets": schema.JSON{
			Type:        "object",
			Description: "Aggregated facet data",
		},
		"query_credits_used": schema.JSON{
			Type:        "integer",
			Description: "Number of query credits consumed",
		},
	})
}

// ptrFloat64 is a helper to create a pointer to a float64 value
func ptrFloat64(f float64) *float64 {
	return &f
}
