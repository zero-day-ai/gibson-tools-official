package main

import (
	"context"
	"log"

	"github.com/zero-day-ai/sdk/serve"
	"github.com/zero-day-ai/sdk/tool"
	"github.com/zero-day-ai/sdk/types"
)

func main() {
	t := NewTool()
	if err := serve.Tool(t); err != nil {
		log.Fatal(err)
	}
}

// NewTool creates a new linpeas tool instance.
func NewTool() tool.Tool {
	cfg := tool.NewConfig().
		SetName(ToolName).
		SetVersion(ToolVersion).
		SetDescription(ToolDescription).
		SetTags([]string{
			"privilege-escalation",
			"enumeration",
			"linux",
			"T1548", // Abuse Elevation Control Mechanism
		}).
		SetInputSchema(InputSchema()).
		SetOutputSchema(OutputSchema()).
		SetExecuteFunc((&ToolImpl{}).Execute)

	t, err := tool.New(cfg)
	if err != nil {
		log.Fatalf("failed to create tool: %v", err)
	}

	return &toolWithHealth{Tool: t, impl: &ToolImpl{}}
}

// toolWithHealth wraps the tool to add custom health checks.
type toolWithHealth struct {
	tool.Tool
	impl *ToolImpl
}

// Health implements the Health check for the tool.
func (t *toolWithHealth) Health(ctx context.Context) types.HealthStatus {
	return t.impl.Health(ctx)
}
