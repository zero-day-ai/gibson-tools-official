package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "proxychains"
	ToolVersion     = "1.0.0"
	ToolDescription = "Route traffic through proxy chains using proxychains-ng"
	BinaryName      = "proxychains4"
)

// ToolImpl implements the proxychains tool logic.
type ToolImpl struct{}

// NewTool creates a new proxychains tool instance.
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"lateral-movement",
			"proxy",
			"T1090", // MITRE ATT&CK: Proxy
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

// Execute runs a command through a proxy chain.
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	// Extract proxies from input
	proxiesRaw, ok := input["proxies"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid proxies format")
	}

	var proxies []map[string]interface{}
	for _, p := range proxiesRaw {
		proxyMap, ok := p.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid proxy format")
		}
		proxies = append(proxies, proxyMap)
	}

	// Extract command
	command, ok := input["command"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid command format")
	}

	// Create temporary config file
	configPath, err := t.createProxychainsConfig(proxies)
	if err != nil {
		return map[string]any{
			"success": false,
			"output":  "",
			"error":   fmt.Sprintf("failed to create config: %v", err),
		}, nil
	}
	defer os.Remove(configPath)

	// Execute command through proxychains
	output, execErr := t.executeCommand(ctx, configPath, command)

	if execErr != nil {
		return map[string]any{
			"success": false,
			"output":  output,
			"error":   execErr.Error(),
		}, nil
	}

	return map[string]any{
		"success": true,
		"output":  output,
		"error":   "",
	}, nil
}

// createProxychainsConfig generates a temporary proxychains configuration file.
func (t *ToolImpl) createProxychainsConfig(proxies []map[string]interface{}) (string, error) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "proxychains-*")
	if err != nil {
		return "", err
	}

	configPath := filepath.Join(tempDir, "proxychains.conf")

	// Build config content
	var configBuilder strings.Builder
	configBuilder.WriteString("# Proxychains configuration\n")
	configBuilder.WriteString("strict_chain\n")
	configBuilder.WriteString("proxy_dns\n")
	configBuilder.WriteString("tcp_read_time_out 15000\n")
	configBuilder.WriteString("tcp_connect_time_out 8000\n")
	configBuilder.WriteString("\n[ProxyList]\n")

	// Add each proxy to config
	for _, proxy := range proxies {
		proxyType, _ := proxy["type"].(string)
		host, _ := proxy["host"].(string)

		// Handle port as either float64 or int
		var port int
		switch v := proxy["port"].(type) {
		case float64:
			port = int(v)
		case int:
			port = v
		default:
			return "", fmt.Errorf("invalid port type: %T", proxy["port"])
		}

		configBuilder.WriteString(fmt.Sprintf("%s %s %d\n", proxyType, host, port))
	}

	// Write config file
	err = os.WriteFile(configPath, []byte(configBuilder.String()), 0600)
	if err != nil {
		os.RemoveAll(tempDir)
		return "", err
	}

	return configPath, nil
}

// executeCommand runs the command through proxychains using the specified config.
func (t *ToolImpl) executeCommand(ctx context.Context, configPath, command string) (string, error) {
	// Parse the command into executable and args
	cmdParts := strings.Fields(command)
	if len(cmdParts) == 0 {
		return "", fmt.Errorf("empty command")
	}

	// Build proxychains command
	args := []string{"-f", configPath}
	args = append(args, cmdParts...)

	cmd := exec.CommandContext(ctx, BinaryName, args...)

	// Capture combined output
	output, err := cmd.CombinedOutput()

	return string(output), err
}

// Health checks if proxychains binary is available.
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if proxychains4 binary exists
	_, err := exec.LookPath(BinaryName)
	if err != nil {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("binary %s not found in PATH", BinaryName),
			map[string]any{
				"binary": BinaryName,
				"error":  err.Error(),
			},
		)
	}

	return types.NewHealthyStatus(fmt.Sprintf("%s is available", BinaryName))
}
