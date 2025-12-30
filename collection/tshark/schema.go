package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the expected input structure for tshark packet capture.
// Based on FR-11.1 from requirements.md
func InputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"interface": schema.StringWithDesc("Network interface to capture from (required)"),
		"filter":    schema.StringWithDesc("BPF filter expression (optional)"),
		"duration": schema.JSON{
			Type:        "integer",
			Description: "Capture duration in seconds (optional)",
		},
		"packet_count": schema.JSON{
			Type:        "integer",
			Description: "Maximum number of packets to capture (optional)",
		},
		"output_file": schema.StringWithDesc("Custom output file path (optional, defaults to temp file)"),
	}, "interface") // interface is required
}

// OutputSchema defines the output structure for tshark packet capture.
// Based on FR-11.1 from requirements.md
func OutputSchema() schema.JSON {
	return schema.Object(map[string]schema.JSON{
		"packets_captured": schema.JSON{
			Type:        "integer",
			Description: "Number of packets captured",
		},
		"output_file": schema.StringWithDesc("Path to the capture file (pcap format)"),
		"protocols_detected": schema.JSON{
			Type:        "array",
			Items:       &schema.JSON{Type: "string"},
			Description: "List of unique protocols detected in the capture",
		},
		"capture_time_seconds": schema.JSON{
			Type:        "integer",
			Description: "Actual time taken for the capture in seconds",
		},
	})
}
