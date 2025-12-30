package main

import "github.com/zero-day-ai/sdk/schema"

// InputSchema defines the input schema for the msfvenom tool
func InputSchema() schema.JSON {
	lportSchema := schema.Int()
	lportSchema.Description = "Listener port (optional)"

	iterationsSchema := schema.Int()
	iterationsSchema.Description = "Number of encoding iterations (optional)"

	return schema.Object(map[string]schema.JSON{
		"payload":    schema.StringWithDesc("Payload module path (e.g., windows/meterpreter/reverse_tcp)"),
		"format":     schema.StringWithDesc("Output format (exe, dll, elf, ps1, jar, war, etc.)"),
		"lhost":      schema.StringWithDesc("Listener host (optional)"),
		"lport":      lportSchema,
		"encoder":    schema.StringWithDesc("Encoder module (optional, e.g., x86/shikata_ga_nai)"),
		"iterations": iterationsSchema,
		"platform":   schema.StringWithDesc("Target platform (optional, e.g., windows, linux, osx)"),
		"arch":       schema.StringWithDesc("Target architecture (optional, e.g., x86, x64, x86_64)"),
	}, "payload", "format") // payload and format are required
}

// OutputSchema defines the output schema for the msfvenom tool
func OutputSchema() schema.JSON {
	sizeSchema := schema.Int()
	sizeSchema.Description = "Size of generated payload in bytes"

	return schema.Object(map[string]schema.JSON{
		"payload_path": schema.StringWithDesc("Absolute path to generated payload file"),
		"payload_size": sizeSchema,
		"format":       schema.StringWithDesc("Output format used"),
		"encoder":      schema.StringWithDesc("Encoder used (if any)"),
		"md5":          schema.StringWithDesc("MD5 hash of the payload"),
		"sha256":       schema.StringWithDesc("SHA256 hash of the payload"),
	})
}
