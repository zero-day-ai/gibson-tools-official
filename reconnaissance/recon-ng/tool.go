package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "recon-ng"
	ToolVersion     = "1.0.0"
	ToolDescription = "OSINT Framework for modular reconnaissance using recon-ng"
	BinaryName      = "recon-ng"
)

// ToolImpl implements the tool execution logic
type ToolImpl struct{}

// NewTool creates a new recon-ng tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"osint",
			"TA0043",
			"T1589", // Gather Victim Identity Information
			"T1590", // Gather Victim Network Information
			"T1591", // Gather Victim Org Information
			"T1592", // Gather Victim Host Information
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs the recon-ng tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract required inputs
	workspace, _ := input["workspace"].(string)
	module, _ := input["module"].(string)

	if workspace == "" {
		return nil, fmt.Errorf("workspace is required")
	}
	if module == "" {
		return nil, fmt.Errorf("module is required")
	}

	// Extract optional inputs
	options, _ := input["options"].(map[string]any)
	sourceDomain, _ := input["source_domain"].(string)

	// Create a temporary directory for workspace and output
	tmpDir, err := os.MkdirTemp("", "recon-ng-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Build recon-ng commands as a resource file
	rcFile := filepath.Join(tmpDir, "recon.rc")
	commands := []string{
		fmt.Sprintf("workspaces create %s", workspace),
		fmt.Sprintf("workspaces select %s", workspace),
	}

	// Add source domain if provided
	if sourceDomain != "" {
		commands = append(commands, fmt.Sprintf("db insert domains domain=%s", sourceDomain))
	}

	// Add module options
	if options != nil {
		for key, value := range options {
			commands = append(commands, fmt.Sprintf("options set %s %v", key, value))
		}
	}

	// Load and run the module
	commands = append(commands,
		fmt.Sprintf("modules load %s", module),
		"run",
		"show",
		"exit",
	)

	// Write commands to resource file
	rcContent := strings.Join(commands, "\n")
	if err := os.WriteFile(rcFile, []byte(rcContent), 0600); err != nil {
		return nil, fmt.Errorf("failed to write resource file: %w", err)
	}

	// Execute recon-ng with resource file
	cmd := exec.CommandContext(ctx, BinaryName,
		"-w", workspace,
		"--no-version",
		"-r", rcFile,
	)

	// Set HOME to temp directory to isolate workspace
	cmd.Env = append(os.Environ(), fmt.Sprintf("HOME=%s", tmpDir))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("recon-ng execution failed: %w\nOutput: %s", err, string(output))
	}

	// Parse the output
	results, resultCount := parseReconNGOutput(string(output), module)

	executionTime := time.Since(startTime)

	return map[string]any{
		"module":            module,
		"results":           results,
		"result_count":      resultCount,
		"execution_time_ms": executionTime.Milliseconds(),
	}, nil
}

// parseReconNGOutput parses the recon-ng output and extracts results
func parseReconNGOutput(output string, module string) ([]map[string]any, int) {
	results := []map[string]any{}
	lines := strings.Split(output, "\n")

	// Look for table output or JSON output
	inTable := false
	tableHeaders := []string{}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Try to parse as JSON first (if module outputs JSON)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			var jsonResult map[string]any
			if err := json.Unmarshal([]byte(trimmed), &jsonResult); err == nil {
				results = append(results, jsonResult)
				continue
			}
		}

		// Parse table format
		if strings.Contains(trimmed, "---") && len(trimmed) > 10 {
			inTable = true
			continue
		}

		if inTable && strings.Contains(trimmed, "|") {
			fields := strings.Split(trimmed, "|")
			cleanFields := []string{}
			for _, f := range fields {
				clean := strings.TrimSpace(f)
				if clean != "" {
					cleanFields = append(cleanFields, clean)
				}
			}

			if len(tableHeaders) == 0 {
				tableHeaders = cleanFields
			} else if len(cleanFields) == len(tableHeaders) {
				// Create result map from headers and values
				result := make(map[string]any)
				for i, header := range tableHeaders {
					result[header] = cleanFields[i]
				}
				results = append(results, result)
			}
		}

		// End of table
		if inTable && trimmed == "" {
			inTable = false
		}
	}

	// If no structured results found, create a simple result with raw output snippets
	if len(results) == 0 {
		// Look for specific result patterns in output
		for _, line := range lines {
			if strings.Contains(line, "added") || strings.Contains(line, "found") {
				results = append(results, map[string]any{
					"message": strings.TrimSpace(line),
				})
			}
		}
	}

	return results, len(results)
}

// Health checks if the recon-ng binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if recon-ng binary exists
	_, err := exec.LookPath(BinaryName)
	if err != nil {
		return types.NewUnhealthyStatus(fmt.Sprintf("%s binary not found in PATH", BinaryName), nil)
	}

	return types.NewHealthyStatus(fmt.Sprintf("%s is available", BinaryName))
}
