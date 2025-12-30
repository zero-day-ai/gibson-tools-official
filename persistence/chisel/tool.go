package main

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "chisel"
	ToolVersion     = "1.0.0"
	ToolDescription = "Creates encrypted HTTP tunnels for maintaining persistent access through firewalls"
	BinaryName      = "chisel"
)

// ChiselTool implements the chisel tunneling tool
type ChiselTool struct{}

// NewTool creates a new configured chisel tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"persistence",
			"tunneling",
			"networking",
			"T1572", // Protocol Tunneling
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ChiselTool{}).Execute)

	t, _ := tool.New(cfg)
	return &toolWithHealth{Tool: t, impl: &ChiselTool{}}
}

// toolWithHealth wraps the tool to add custom health checks
type toolWithHealth struct {
	tool.Tool
	impl *ChiselTool
}

func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}

// Execute runs the chisel tool with the provided input
func (t *ChiselTool) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract input parameters
	mode := getString(input, "mode", "")
	localPort := getInt(input, "local_port", 0)
	remote := getString(input, "remote", "")
	reverse := getBool(input, "reverse", false)

	// Build chisel command based on mode
	var args []string
	var localEndpoint, remoteEndpoint string

	switch mode {
	case "server":
		// Server mode: chisel server --port <local_port> [--reverse]
		args = append(args, "server", "--port", strconv.Itoa(localPort))
		if reverse {
			args = append(args, "--reverse")
		}
		localEndpoint = fmt.Sprintf("0.0.0.0:%d", localPort)
		remoteEndpoint = remote

	case "client":
		// Client mode: chisel client <server_addr> <remote_mapping>
		serverAddr := getString(input, "server_addr", "")
		if serverAddr == "" {
			return nil, fmt.Errorf("server_addr is required for client mode")
		}

		args = append(args, "client", serverAddr)

		// Format remote mapping
		// If reverse is true, format is R:local_port:remote_host:remote_port
		// Otherwise, it's local_port:remote_host:remote_port
		if reverse {
			args = append(args, fmt.Sprintf("R:%s", remote))
		} else {
			args = append(args, remote)
		}

		localEndpoint = fmt.Sprintf("localhost:%d", localPort)
		remoteEndpoint = remote

	default:
		return nil, fmt.Errorf("invalid mode: %s (must be 'server' or 'client')", mode)
	}

	// Check if chisel binary exists
	chiselPath, err := exec.LookPath(BinaryName)
	if err != nil {
		return nil, fmt.Errorf("chisel binary not found in PATH: %w", err)
	}

	// Create command
	cmd := exec.CommandContext(ctx, chiselPath, args...)

	// Start the chisel process in the background
	// Note: For persistent tunnels, we start the process and check if it's running
	if err := cmd.Start(); err != nil {
		return map[string]any{
			"success":         false,
			"tunnel_id":       "",
			"local_endpoint":  localEndpoint,
			"remote_endpoint": remoteEndpoint,
			"status":          "failed",
		}, fmt.Errorf("failed to start chisel: %w", err)
	}

	// Give the process a moment to start and establish the tunnel
	time.Sleep(500 * time.Millisecond)

	// Check if process is still running (basic health check)
	processRunning := true
	if cmd.Process != nil {
		// Try to send signal 0 to check if process exists
		if err := cmd.Process.Signal(nil); err != nil {
			processRunning = false
		}
	}

	status := "connecting"
	if processRunning {
		status = "connected"
	} else {
		status = "failed"
	}

	// Generate tunnel ID from process PID
	tunnelID := ""
	if cmd.Process != nil {
		tunnelID = fmt.Sprintf("chisel-%d", cmd.Process.Pid)
	}

	return map[string]any{
		"success":         processRunning,
		"tunnel_id":       tunnelID,
		"local_endpoint":  localEndpoint,
		"remote_endpoint": remoteEndpoint,
		"status":          status,
	}, nil
}

// Health checks if the chisel binary is available
func (t *ChiselTool) Health(ctx context.Context) types.HealthStatus {
	// Check if chisel binary exists in PATH
	_, err := exec.LookPath(BinaryName)
	if err != nil {
		return types.NewUnhealthyStatus(fmt.Sprintf("chisel binary not found in PATH: %v", err), nil)
	}

	// Verify chisel version (optional - just check it runs)
	cmd := exec.CommandContext(ctx, BinaryName, "--version")
	if err := cmd.Run(); err != nil {
		return types.NewUnhealthyStatus(fmt.Sprintf("chisel binary exists but cannot execute: %v", err), nil)
	}

	return types.NewHealthyStatus("chisel binary is available and operational")
}

// Helper functions for safe input extraction

func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key]; ok {
		if strVal, ok := val.(string); ok {
			return strVal
		}
	}
	return defaultVal
}

func getInt(input map[string]any, key string, defaultVal int) int {
	if val, ok := input[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case float64:
			return int(v)
		case string:
			if intVal, err := strconv.Atoi(v); err == nil {
				return intVal
			}
		}
	}
	return defaultVal
}

func getBool(input map[string]any, key string, defaultVal bool) bool {
	if val, ok := input[key]; ok {
		if boolVal, ok := val.(bool); ok {
			return boolVal
		}
	}
	return defaultVal
}

// getStringSlice safely extracts a string slice from input map
func getStringSlice(input map[string]any, key string) []string {
	if val, ok := input[key]; ok {
		if slice, ok := val.([]any); ok {
			result := make([]string, 0, len(slice))
			for _, item := range slice {
				if str, ok := item.(string); ok {
					result = append(result, str)
				}
			}
			return result
		}
		if slice, ok := val.([]string); ok {
			return slice
		}
	}
	return []string{}
}
