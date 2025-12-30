package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the sqlmap tool.
// Based on FR-3.1 requirements.
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"url": schema.JSON{
			Type:        "string",
			Description: "Target URL with parameter to test for SQL injection",
		},
		"data": schema.JSON{
			Type:        "string",
			Description: "POST data string (e.g., 'param1=value1&param2=value2')",
		},
		"cookie": schema.JSON{
			Type:        "string",
			Description: "HTTP Cookie header value",
		},
		"method": schema.JSON{
			Type:        "string",
			Description: "HTTP method to use",
			Enum:        []any{"GET", "POST"},
		},
		"param": schema.JSON{
			Type:        "string",
			Description: "Specific parameter to test (testable parameter)",
		},
		"dbms": schema.JSON{
			Type:        "string",
			Description: "Force back-end DBMS to provided value (e.g., MySQL, PostgreSQL, MSSQL)",
		},
		"level": schema.JSON{
			Type:        "integer",
			Description: "Level of tests to perform (1-5, default 1)",
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(5),
			Default:     1,
		},
		"risk": schema.JSON{
			Type:        "integer",
			Description: "Risk of tests to perform (1-3, default 1)",
			Minimum:     ptrFloat64(1),
			Maximum:     ptrFloat64(3),
			Default:     1,
		},
		"technique": schema.JSON{
			Type:        "string",
			Description: "SQL injection techniques to use (e.g., 'B' for Boolean-based, 'E' for Error-based, 'U' for UNION-based)",
		},
		"batch": schema.JSON{
			Type:        "boolean",
			Description: "Never ask for user input, use default behavior (always true for non-interactive mode)",
			Default:     true,
		},
		"dump": schema.JSON{
			Type:        "boolean",
			Description: "Dump DBMS database table entries",
			Default:     false,
		},
		"dbs": schema.JSON{
			Type:        "boolean",
			Description: "Enumerate DBMS databases",
			Default:     false,
		},
	}, "url") // url is required
}

// OutputSchema defines the output schema for the sqlmap tool.
// Based on FR-3.1 requirements.
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"vulnerable": schema.JSON{
			Type:        "boolean",
			Description: "Whether SQL injection vulnerability was found",
		},
		"injection_point": schema.JSON{
			Type:        "object",
			Description: "Details about the injection point if vulnerability found",
			Properties: map[string]schema.JSON{
				"parameter": schema.JSON{
					Type:        "string",
					Description: "The vulnerable parameter name",
				},
				"type": schema.JSON{
					Type:        "string",
					Description: "Type of SQL injection (e.g., boolean-based blind, error-based)",
				},
				"payload": schema.JSON{
					Type:        "string",
					Description: "Example payload that worked",
				},
			},
		},
		"dbms": schema.JSON{
			Type:        "string",
			Description: "Detected database management system",
		},
		"databases": schema.JSON{
			Type:        "array",
			Description: "List of enumerated databases (if --dbs was used)",
			Items: &schema.JSON{
				Type: "string",
			},
		},
		"current_user": schema.JSON{
			Type:        "string",
			Description: "Current database user",
		},
		"current_db": schema.JSON{
			Type:        "string",
			Description: "Current database name",
		},
		"is_dba": schema.JSON{
			Type:        "boolean",
			Description: "Whether current user has DBA privileges",
		},
		"data_extracted": schema.JSON{
			Type:        "object",
			Description: "Data extracted from database (if --dump was used)",
		},
		"scan_time_ms": schema.JSON{
			Type:        "integer",
			Description: "Total scan time in milliseconds",
		},
	})
}

// ptrFloat64 is a helper to create a pointer to a float64 value.
func ptrFloat64(f float64) *float64 {
	return &f
}
