package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "tshark"
	ToolVersion     = "1.0.0"
	ToolDescription = "Packet capture tool using tshark for network sniffing and protocol analysis"
	BinaryName      = "tshark"
)

// ToolImpl implements the tshark packet capture tool
type ToolImpl struct{}

// NewTool creates and configures the tshark tool
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"collection",       // Phase
			"network",          // Category
			"packet-capture",   // Specific
			"T1040",            // Network Sniffing
			"TA0009",           // Collection phase
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

// Execute runs tshark to capture network packets
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	iface := getString(input, "interface", "")
	if iface == "" {
		return nil, fmt.Errorf("interface parameter is required")
	}

	filter := getString(input, "filter", "")
	duration := getInt(input, "duration", 0)
	packetCount := getInt(input, "packet_count", 0)
	outputFile := getString(input, "output_file", "")

	// Create output file if not specified
	if outputFile == "" {
		tempDir := os.TempDir()
		tempFile, err := os.CreateTemp(tempDir, "tshark-capture-*.pcap")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp capture file: %w", err)
		}
		outputFile = tempFile.Name()
		tempFile.Close()
	}

	// Build tshark command arguments
	args := []string{
		"-i", iface,      // Interface
		"-w", outputFile, // Write to file
		"-q",             // Quiet mode (no packet output to stdout)
	}

	// Add BPF filter if specified
	if filter != "" {
		args = append(args, "-f", filter)
	}

	// Add duration limit if specified
	if duration > 0 {
		args = append(args, "-a", fmt.Sprintf("duration:%d", duration))
	}

	// Add packet count limit if specified
	if packetCount > 0 {
		args = append(args, "-c", strconv.Itoa(packetCount))
	}

	// Create command with context for timeout support
	cmd := exec.CommandContext(ctx, BinaryName, args...)

	// Capture stderr for any error messages
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// Execute tshark
	if err := cmd.Run(); err != nil {
		// Check if context was canceled
		if ctx.Err() != nil {
			return nil, fmt.Errorf("capture canceled: %w", ctx.Err())
		}
		return nil, fmt.Errorf("tshark execution failed: %w, stderr: %s", err, stderr.String())
	}

	// Calculate capture time
	captureTime := int(time.Since(startTime).Seconds())

	// Count packets and detect protocols
	packetsCaptured, protocols, err := analyzeCapture(outputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to analyze capture: %w", err)
	}

	// Build output
	output := map[string]any{
		"packets_captured":      packetsCaptured,
		"output_file":           outputFile,
		"protocols_detected":    protocols,
		"capture_time_seconds":  captureTime,
	}

	return output, nil
}

// analyzeCapture reads the pcap file and extracts packet count and protocol information
func analyzeCapture(pcapFile string) (int, []string, error) {
	// Use tshark to read the capture and get statistics
	cmd := exec.Command(BinaryName,
		"-r", pcapFile,     // Read from file
		"-T", "fields",     // Output fields
		"-e", "frame.protocols", // Extract protocol stack
		"-E", "separator=,",
	)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return 0, nil, fmt.Errorf("failed to analyze capture file: %w", err)
	}

	// Parse output to count packets and extract unique protocols
	protocolSet := make(map[string]bool)
	packetCount := 0

	scanner := bufio.NewScanner(&stdout)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		packetCount++

		// Extract protocols from the protocol stack
		// Protocol stack is colon-separated, e.g., "eth:ethertype:ip:tcp:http"
		protocols := strings.Split(line, ":")
		for _, proto := range protocols {
			proto = strings.TrimSpace(proto)
			if proto != "" {
				protocolSet[proto] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, nil, fmt.Errorf("error reading tshark output: %w", err)
	}

	// Convert protocol set to sorted slice
	protocols := make([]string, 0, len(protocolSet))
	for proto := range protocolSet {
		protocols = append(protocols, proto)
	}

	return packetCount, protocols, nil
}

// Health checks if tshark binary is available and has proper permissions
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	// Check if tshark binary exists
	path, err := exec.LookPath(BinaryName)
	if err != nil {
		return types.NewUnhealthyStatus(
			fmt.Sprintf("tshark binary not found in PATH: %v", err),
			map[string]any{"binary": BinaryName},
		)
	}

	// Verify tshark can list interfaces (requires appropriate permissions)
	cmd := exec.CommandContext(ctx, BinaryName, "-D")
	if err := cmd.Run(); err != nil {
		return types.NewDegradedStatus(
			fmt.Sprintf("tshark found but cannot list interfaces (may need elevated privileges): %v", err),
			map[string]any{
				"binary": path,
				"hint":   "tshark may require root/sudo or CAP_NET_RAW capability",
			},
		)
	}

	return types.NewHealthyStatus(fmt.Sprintf("tshark is available at %s", path))
}

// Helper functions for safe type extraction from input map

func getString(input map[string]any, key string, defaultVal string) string {
	if val, ok := input[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return defaultVal
}

func getInt(input map[string]any, key string, defaultVal int) int {
	if val, ok := input[key]; ok {
		switch v := val.(type) {
		case int:
			return v
		case int64:
			return int(v)
		case float64:
			return int(v)
		case string:
			if i, err := strconv.Atoi(v); err == nil {
				return i
			}
		}
	}
	return defaultVal
}
