package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/zero-day-ai/gibson-tools-official/pkg/common"
	"github.com/zero-day-ai/gibson-tools-official/pkg/executor"
	"github.com/zero-day-ai/gibson-tools-official/pkg/health"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

const (
	ToolName        = "subfinder"
	ToolVersion     = "1.0.0"
	ToolDescription = "Fast passive subdomain enumeration tool using multiple online sources"
	BinaryName      = "subfinder"
)

// ToolImpl implements the subfinder tool
type ToolImpl struct{}

// NewTool creates a new subfinder tool instance
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"reconnaissance",
			"subdomain",
			"osint",
			"T1595", // Active Scanning
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

// Execute runs the subfinder tool with the provided input
func (t *ToolImpl) Execute(ctx context.Context, input map[string]any) (map[string]any, error) {
	startTime := time.Now()

	// Extract input parameters
	domain := common.GetString(input, "domain", "")
	if domain == "" {
		return nil, fmt.Errorf("domain is required")
	}

	timeout := common.GetTimeout(input, "timeout", common.DefaultTimeout())
	silent := common.GetBool(input, "silent", false)
	recursive := common.GetBool(input, "recursive", false)
	all := common.GetBool(input, "all", true)

	// Build subfinder command arguments
	args := buildArgs(domain, silent, recursive, all)

	// Execute subfinder command
	result, err := executor.Execute(ctx, executor.Config{
		Command: BinaryName,
		Args:    args,
		Timeout: timeout,
	})

	if err != nil {
		return nil, common.NewToolError(ToolName, "execute", common.ErrCodeExecutionFailed, err.Error()).WithCause(err)
	}

	// Parse subfinder output
	output, err := parseOutput(result.Stdout, domain)
	if err != nil {
		return nil, common.NewToolError(ToolName, "parse", common.ErrCodeParseError, err.Error()).WithCause(err)
	}

	// Add scan time
	output["scan_time_ms"] = int(time.Since(startTime).Milliseconds())

	return output, nil
}

// Health checks if the subfinder binary is available
func (t *ToolImpl) Health(ctx context.Context) types.HealthStatus {
	return health.BinaryCheck(BinaryName)
}

// buildArgs constructs the command-line arguments for subfinder
func buildArgs(domain string, silent, recursive, all bool) []string {
	args := []string{"-d", domain}

	if silent {
		args = append(args, "-silent")
	}

	if recursive {
		args = append(args, "-recursive")
	}

	if all {
		args = append(args, "-all")
	}

	return args
}

// parseOutput parses the output from subfinder
func parseOutput(data []byte, domain string) (map[string]any, error) {
	lines := strings.Split(string(data), "\n")

	subdomains := []string{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			subdomains = append(subdomains, line)
		}
	}

	return map[string]any{
		"domain":     domain,
		"subdomains": subdomains,
		"count":      len(subdomains),
	}, nil
}
