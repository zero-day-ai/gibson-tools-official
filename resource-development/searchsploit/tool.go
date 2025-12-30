package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "searchsploit"
	ToolVersion     = "1.0.0"
	ToolDescription = "Search the Exploit Database for exploits, shellcodes, and security papers matching CVEs or keywords"
	BinaryName      = "searchsploit"
)

// ToolImpl implements the searchsploit tool.
type ToolImpl struct{}

// NewTool creates and configures a new searchsploit tool.
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"resource-development",
			"exploit-research",
			"T1587.004", // Develop Capabilities: Exploits
			"T1588.005", // Obtain Capabilities: Exploits
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks.
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs searchsploit with the provided parameters.
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	query := getString(input, "query", "")
	exact := getBool(input, "exact", false)
	cve := getString(input, "cve", "")
	typeFilter := getString(input, "type", "")
	platform := getString(input, "platform", "")

	// Build searchsploit command arguments
	args := []string{"-j"} // JSON output

	// Add search query or CVE
	if cve != "" {
		args = append(args, "--cve", cve)
	} else if query != "" {
		if exact {
			args = append(args, "--exact")
		}
		args = append(args, query)
	} else {
		return nil, fmt.Errorf("either 'query' or 'cve' must be provided")
	}

	// Add type filter
	if typeFilter != "" {
		switch typeFilter {
		case "exploits":
			args = append(args, "--exclude=shellcodes,papers")
		case "shellcodes":
			args = append(args, "--exclude=exploits,papers")
		case "papers":
			args = append(args, "--exclude=exploits,shellcodes")
		}
	}

	// Add platform filter
	if platform != "" {
		args = append(args, "--platform", platform)
	}

	// Execute searchsploit
	cmd := exec.CommandContext(ctx, BinaryName, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// searchsploit returns non-zero exit code when no results found
		// Check if output contains valid JSON
		if len(output) == 0 {
			return nil, fmt.Errorf("searchsploit execution failed: %w", err)
		}
	}

	// Parse JSON output
	var searchsploitOutput struct {
		ResultsExploits []struct {
			ID       string   `json:"id"`
			Title    string   `json:"title"`
			Path     string   `json:"path"`
			Type     string   `json:"type"`
			Platform string   `json:"platform"`
			Date     string   `json:"date_published"`
			Author   string   `json:"author"`
			Verified bool     `json:"verified"`
			Codes    []string `json:"codes"`
		} `json:"RESULTS_EXPLOIT"`
		ResultsShellcode []struct {
			ID       string   `json:"id"`
			Title    string   `json:"title"`
			Path     string   `json:"path"`
			Type     string   `json:"type"`
			Platform string   `json:"platform"`
			Date     string   `json:"date_published"`
			Author   string   `json:"author"`
			Verified bool     `json:"verified"`
			Codes    []string `json:"codes"`
		} `json:"RESULTS_SHELLCODE"`
	}

	if err := json.Unmarshal(output, &searchsploitOutput); err != nil {
		return nil, fmt.Errorf("failed to parse searchsploit JSON output: %w (output: %s)", err, string(output))
	}

	// Combine results from exploits and shellcodes
	var results []map[string]any

	// Process exploit results
	for _, exploit := range searchsploitOutput.ResultsExploits {
		results = append(results, map[string]any{
			"id":       exploit.ID,
			"title":    exploit.Title,
			"path":     exploit.Path,
			"type":     determineType(exploit.Type, exploit.Path),
			"platform": exploit.Platform,
			"date":     exploit.Date,
			"author":   exploit.Author,
			"verified": exploit.Verified,
		})
	}

	// Process shellcode results
	for _, shellcode := range searchsploitOutput.ResultsShellcode {
		results = append(results, map[string]any{
			"id":       shellcode.ID,
			"title":    shellcode.Title,
			"path":     shellcode.Path,
			"type":     determineType(shellcode.Type, shellcode.Path),
			"platform": shellcode.Platform,
			"date":     shellcode.Date,
			"author":   shellcode.Author,
			"verified": shellcode.Verified,
		})
	}

	// Return structured output
	return map[string]any{
		"results":       results,
		"total_results": len(results),
	}, nil
}

// Health checks if searchsploit is available and exploit-db exists.
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if searchsploit binary exists
	_, err := exec.LookPath(BinaryName)
	if err != nil {
		return types.NewUnhealthyStatus(
			"searchsploit binary not found in PATH",
			map[string]any{"error": err.Error()},
		)
	}

	// Check if exploit-db database exists
	// searchsploit typically stores the database at /usr/share/exploitdb
	exploitDBPaths := []string{
		"/usr/share/exploitdb",
		"/opt/exploitdb",
		filepath.Join(os.Getenv("HOME"), ".local/share/exploitdb"),
	}

	dbFound := false
	var checkedPaths []string
	for _, path := range exploitDBPaths {
		checkedPaths = append(checkedPaths, path)
		if _, err := os.Stat(path); err == nil {
			dbFound = true
			break
		}
	}

	if !dbFound {
		return types.NewUnhealthyStatus(
			"exploit-db database not found",
			map[string]any{
				"checked_paths": checkedPaths,
				"hint":          "Install exploit-db: apt-get install exploitdb or git clone https://gitlab.com/exploit-database/exploitdb.git",
			},
		)
	}

	return types.NewHealthyStatus("searchsploit is operational and exploit-db is available")
}

// Helper functions

// getString safely extracts a string value from input map.
func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultVal
}

// getBool safely extracts a boolean value from input map.
func getBool(input map[string]any, key string, defaultVal bool) bool {
	if val, ok := input[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return defaultVal
}

// determineType determines the type of result based on path or type field.
func determineType(typeField, path string) string {
	if typeField != "" && typeField != "exploit" {
		return typeField
	}

	pathLower := strings.ToLower(path)
	if strings.Contains(pathLower, "shellcode") {
		return "shellcode"
	}
	if strings.Contains(pathLower, "paper") || strings.Contains(pathLower, "pdf") {
		return "paper"
	}
	return "exploit"
}
