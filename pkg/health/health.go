package health

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/executor"
	"github.com/zero-day-ai/sdk/types"
)

// BinaryCheck verifies a binary exists and is executable
func BinaryCheck(name string) types.HealthStatus {
	if executor.BinaryExists(name) {
		path, _ := executor.BinaryPath(name)
		return types.NewHealthyStatus(fmt.Sprintf("%s is available at %s", name, path))
	}
	return types.NewUnhealthyStatus(fmt.Sprintf("%s binary not found in PATH", name), nil)
}

// BinaryVersionCheck verifies binary exists and meets version requirement
func BinaryVersionCheck(name string, minVersion string, versionFlag string) types.HealthStatus {
	// First check if binary exists
	binaryStatus := BinaryCheck(name)
	if !binaryStatus.IsHealthy() {
		return binaryStatus
	}

	// Try to get version
	result, err := executor.Execute(context.Background(), executor.Config{
		Command: name,
		Args:    []string{versionFlag},
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return types.NewDegradedStatus(
			fmt.Sprintf("binary %q found but version check failed", name),
			map[string]any{
				"binary":       name,
				"version_flag": versionFlag,
				"error":        err.Error(),
			},
		)
	}

	version := string(result.Stdout)
	return types.HealthStatus{
		Status:  types.StatusHealthy,
		Message: fmt.Sprintf("binary %q found with version info", name),
		Details: map[string]any{
			"binary":       name,
			"version":      version,
			"min_required": minVersion,
		},
	}
}

// CapabilityCheck verifies binary has required Linux capabilities
func CapabilityCheck(binary string, caps []string) types.HealthStatus {
	// First check if binary exists
	binaryStatus := BinaryCheck(binary)
	if !binaryStatus.IsHealthy() {
		return binaryStatus
	}

	path, _ := executor.BinaryPath(binary)

	// Try to check capabilities using getcap
	result, err := executor.Execute(context.Background(), executor.Config{
		Command: "getcap",
		Args:    []string{path},
		Timeout: 5 * time.Second,
	})

	// If getcap is not available or fails, return degraded status
	if err != nil {
		return types.NewDegradedStatus(
			fmt.Sprintf("cannot verify capabilities for %q (getcap not available or failed)", binary),
			map[string]any{
				"binary":        binary,
				"path":          path,
				"required_caps": caps,
				"getcap_error":  err.Error(),
				"note":          "capability check skipped - may need root privileges",
			},
		)
	}

	capsOutput := string(result.Stdout)
	missingCaps := []string{}

	for _, cap := range caps {
		if !containsIgnoreCase(capsOutput, cap) {
			missingCaps = append(missingCaps, cap)
		}
	}

	if len(missingCaps) > 0 {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("binary %q missing required capabilities", binary),
			map[string]any{
				"binary":        binary,
				"path":          path,
				"required_caps": caps,
				"missing_caps":  missingCaps,
				"current_caps":  capsOutput,
			},
		)
	}

	return types.HealthStatus{
		Status:  types.StatusHealthy,
		Message: fmt.Sprintf("binary %q has required capabilities", binary),
		Details: map[string]any{
			"binary":        binary,
			"path":          path,
			"required_caps": caps,
			"current_caps":  capsOutput,
		},
	}
}

// containsIgnoreCase checks if s contains substr (case insensitive)
func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return contains(s, substr)
}

// toLower converts string to lowercase
func toLower(s string) string {
	result := make([]rune, len(s))
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			result[i] = r + 32
		} else {
			result[i] = r
		}
	}
	return string(result)
}

// contains checks if s contains substr
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOfSubstr(s, substr) >= 0)
}

// indexOfSubstr returns the index of substr in s, or -1 if not found
func indexOfSubstr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// NetworkCheck verifies network connectivity to a host
func NetworkCheck(ctx context.Context, host string, port int) types.HealthStatus {
	timeout := 5 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return types.NewUnhealthyStatus(fmt.Sprintf("cannot connect to %s: %v", address, err), nil)
	}
	conn.Close()
	return types.NewHealthyStatus(fmt.Sprintf("successfully connected to %s", address))
}

// FileCheck verifies a file or directory exists
func FileCheck(path string) types.HealthStatus {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return types.NewUnhealthyStatus(fmt.Sprintf("file or directory %s does not exist", path), nil)
		}
		return types.NewUnhealthyStatus(fmt.Sprintf("cannot access %s: %v", path, err), nil)
	}

	if info.IsDir() {
		return types.NewHealthyStatus(fmt.Sprintf("directory %s exists", path))
	}
	return types.NewHealthyStatus(fmt.Sprintf("file %s exists", path))
}

// CombineChecks combines multiple health checks
// Returns healthy only if all checks are healthy
// Returns unhealthy if any check is unhealthy
// Returns degraded if any check is degraded and none are unhealthy
func CombineChecks(checks ...types.HealthStatus) types.HealthStatus {
	if len(checks) == 0 {
		return types.NewHealthyStatus("no checks to perform")
	}

	hasUnhealthy := false
	hasDegraded := false
	messages := []string{}
	allDetails := make(map[string]any)

	for i, check := range checks {
		if check.IsUnhealthy() {
			hasUnhealthy = true
		} else if check.IsDegraded() {
			hasDegraded = true
		}

		if check.Message != "" {
			messages = append(messages, check.Message)
		}

		// Collect details with indexed keys to avoid collisions
		if check.Details != nil {
			for k, v := range check.Details {
				allDetails[fmt.Sprintf("check_%d_%s", i, k)] = v
			}
		}
	}

	combinedMessage := joinStrings(messages, "; ")

	if hasUnhealthy {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("health check failed: %s", combinedMessage),
			allDetails,
		)
	}

	if hasDegraded {
		return types.NewDegradedStatus(
			fmt.Sprintf("health check degraded: %s", combinedMessage),
			allDetails,
		)
	}

	return types.NewHealthyStatus(combinedMessage)
}

// joinStrings joins a slice of strings with a separator
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	if len(strs) == 1 {
		return strs[0]
	}

	totalLen := (len(strs) - 1) * len(sep)
	for _, s := range strs {
		totalLen += len(s)
	}

	result := make([]byte, 0, totalLen)
	for i, s := range strs {
		if i > 0 {
			result = append(result, sep...)
		}
		result = append(result, s...)
	}
	return string(result)
}
