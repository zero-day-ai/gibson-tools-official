# Gibson Tool Development Guide

## Overview

Gibson tools are security-focused utilities that execute specific operations (scanning, enumeration, exploitation, etc.) and return structured results. Tools use Protocol Buffers for type-safe input/output and contribute to graph-based knowledge representation through the DiscoveryResult system.

## Tool Interface

Every tool must implement the `Tool` interface:

```go
type Tool interface {
    // Identity
    Name() string
    Version() string
    Description() string
    Category() string

    // Execution
    Execute(ctx context.Context, input proto.Message) (proto.Message, error)

    // Proto definitions
    InputMessageType() string
    OutputMessageType() string

    // Lifecycle
    Initialize(ctx context.Context, cfg ToolConfig) error
    Shutdown(ctx context.Context) error
    Health(ctx context.Context) types.HealthStatus
}
```

## Proto Architecture

Each tool owns its proto definitions in a `proto/` subdirectory. This is the **self-contained proto architecture**.

### Creating New Tool Protos

1. Create `proto/{tool}.proto` with package `gibson.tools.{tool}`
2. Import `graphrag.proto` for DiscoveryResult (field 100)
3. Run `make proto` to generate to `gen/`
4. Import local `gen/` package in tool.go

### Critical: Field 100

All tool responses MUST use SDK's DiscoveryResult for field 100:

```protobuf
syntax = "proto3";

package gibson.tools.nmap;

import "graphrag.proto";

option go_package = "github.com/zero-day-ai/tools/network/nmap/gen";

message NmapRequest {
  string target = 1;
  string ports = 2;
  repeated string flags = 3;
}

message NmapResponse {
  // Tool-specific fields 1-99
  repeated Host hosts = 1;
  string raw_output = 2;
  int32 exit_code = 3;

  // REQUIRED: Field 100 for graph population
  gibson.graphrag.DiscoveryResult discovery = 100;
}

message Host {
  string address = 1;
  repeated Port ports = 2;
  string hostname = 3;
}

message Port {
  int32 number = 1;
  string protocol = 2;
  string state = 3;
  string service = 4;
}
```

**Why Field 100?**
- Provides consistent graph knowledge representation
- Enables automatic entity/relationship extraction
- Supports mission-wide knowledge correlation
- Required by the SDK's graph processing pipeline

### Package Naming

| Type | Package Pattern | Example |
|------|-----------------|---------|
| Tool protos | `gibson.tools.{tool_name}` | `gibson.tools.nmap` |
| Category shared | `gibson.tools.{category}` | `gibson.tools.kubernetes` |
| SDK framework | `gibson.graphrag`, `gibson.common` | Core SDK types |

**Important**: Use the FULL package name, not just `gibson.tools`.

### InputMessageType() Convention

The `InputMessageType()` method must return the FULL proto message name including package:

```go
// CORRECT:
func (t *NmapTool) InputMessageType() string {
    return "gibson.tools.nmap.NmapRequest"  // Includes package name
}

func (t *NmapTool) OutputMessageType() string {
    return "gibson.tools.nmap.NmapResponse"
}

// WRONG:
func (t *NmapTool) InputMessageType() string {
    return "NmapRequest"  // Missing package - won't resolve in GlobalTypes
}
```

**Why?** The Gibson runtime uses these names to:
1. Resolve types in the global proto registry
2. Enable dynamic proto message creation
3. Support agent-to-tool proto marshaling
4. Validate input/output type compatibility

### Import Patterns

```go
// Import local generated protos
import "github.com/zero-day-ai/tools/{category}/{tool}/gen"

// Import SDK types (for DiscoveryResult)
import "github.com/zero-day-ai/sdk/api/gen/graphragpb"

// Import category shared types (if needed)
import "github.com/zero-day-ai/tools/{category}/common/gen"
```

**Example tool.go imports:**

```go
package main

import (
    "context"

    // Local proto types
    pb "github.com/zero-day-ai/tools/network/nmap/gen"

    // SDK types for DiscoveryResult
    "github.com/zero-day-ai/sdk/api/gen/graphragpb"

    // SDK tool framework
    "github.com/zero-day-ai/sdk/tool"
    "github.com/zero-day-ai/sdk/serve"

    "google.golang.org/protobuf/proto"
)
```

### Proto Generation

From tool directory:
```bash
make proto        # Generate proto code
make proto-clean  # Clean and regenerate
```

From tools root:
```bash
make proto        # Generate for ALL tools
```

**Build order:**
1. SDK protos (graphrag.proto) must be built first
2. Category common protos (if any)
3. Tool-specific protos

The Makefile handles this automatically via dependencies.

### Common Mistakes to Avoid

| Mistake | Impact | Fix |
|---------|--------|-----|
| Wrong package name (`gibson.tools` instead of `gibson.tools.nmap`) | Type resolution fails | Use full package: `gibson.tools.{tool}` |
| Missing field 100 | Graph population breaks | Add `gibson.graphrag.DiscoveryResult discovery = 100;` |
| Wrong import path | Circular dependencies | Import from local `gen/`, not SDK `toolspb/` |
| Short type name in InputMessageType() | Runtime type lookup fails | Use full name: `gibson.tools.{tool}.{Message}` |
| Importing SDK tool protos | Circular dependency | Tools should NEVER import SDK's toolspb package |

## Complete Tool Example

```go
package main

import (
    "context"
    "os/exec"

    pb "github.com/zero-day-ai/tools/network/nmap/gen"
    "github.com/zero-day-ai/sdk/api/gen/graphragpb"
    "github.com/zero-day-ai/sdk/tool"
    "github.com/zero-day-ai/sdk/serve"
    "google.golang.org/protobuf/proto"
)

type NmapTool struct {
    config NmapConfig
}

func (t *NmapTool) Name() string        { return "nmap" }
func (t *NmapTool) Version() string     { return "1.0.0" }
func (t *NmapTool) Description() string { return "Network port scanner" }
func (t *NmapTool) Category() string    { return "network" }

func (t *NmapTool) InputMessageType() string {
    return "gibson.tools.nmap.NmapRequest"
}

func (t *NmapTool) OutputMessageType() string {
    return "gibson.tools.nmap.NmapResponse"
}

func (t *NmapTool) Execute(ctx context.Context, input proto.Message) (proto.Message, error) {
    req := input.(*pb.NmapRequest)

    // Build nmap command
    args := append([]string{req.Target}, req.Flags...)
    if req.Ports != "" {
        args = append(args, "-p", req.Ports)
    }

    // Execute nmap
    cmd := exec.CommandContext(ctx, "nmap", args...)
    output, err := cmd.CombinedOutput()
    if err != nil {
        return nil, err
    }

    // Parse output (simplified)
    hosts := parseNmapOutput(output)

    // Build DiscoveryResult for graph population
    discovery := &graphragpb.DiscoveryResult{
        Entities: []*graphragpb.Entity{},
        Relationships: []*graphragpb.Relationship{},
    }

    for _, host := range hosts {
        // Create host entity
        hostEntity := &graphragpb.Entity{
            Type: "host",
            Name: host.Address,
            Properties: map[string]string{
                "address":  host.Address,
                "hostname": host.Hostname,
            },
        }
        discovery.Entities = append(discovery.Entities, hostEntity)

        // Create port entities and relationships
        for _, port := range host.Ports {
            portEntity := &graphragpb.Entity{
                Type: "port",
                Name: fmt.Sprintf("%s:%d", host.Address, port.Number),
                Properties: map[string]string{
                    "number":   fmt.Sprintf("%d", port.Number),
                    "protocol": port.Protocol,
                    "state":    port.State,
                    "service":  port.Service,
                },
            }
            discovery.Entities = append(discovery.Entities, portEntity)

            // Host -> Port relationship
            rel := &graphragpb.Relationship{
                Source: host.Address,
                Target: portEntity.Name,
                Type:   "has_port",
            }
            discovery.Relationships = append(discovery.Relationships, rel)
        }
    }

    // Return response with discovery results
    return &pb.NmapResponse{
        Hosts:      hosts,
        RawOutput:  string(output),
        ExitCode:   0,
        Discovery:  discovery,  // Field 100
    }, nil
}

func (t *NmapTool) Initialize(ctx context.Context, cfg tool.ToolConfig) error {
    // Verify nmap is installed
    if _, err := exec.LookPath("nmap"); err != nil {
        return fmt.Errorf("nmap not found in PATH: %w", err)
    }
    return nil
}

func (t *NmapTool) Shutdown(ctx context.Context) error {
    return nil
}

func (t *NmapTool) Health(ctx context.Context) types.HealthStatus {
    // Check if nmap is accessible
    if _, err := exec.LookPath("nmap"); err != nil {
        return types.HealthStatus{
            Status:  types.HealthStatusUnhealthy,
            Message: "nmap binary not found",
        }
    }
    return types.HealthStatus{Status: types.HealthStatusHealthy}
}

func main() {
    tool := &NmapTool{}
    serve.Tool(tool, serve.WithPort(50051))
}
```

## Tool Configuration

### component.yaml

```yaml
name: nmap
version: 1.0.0
type: tool
category: network
description: Network port scanner using nmap

input_type: gibson.tools.nmap.NmapRequest
output_type: gibson.tools.nmap.NmapResponse

dependencies:
  binaries:
    - name: nmap
      version: ">=7.80"
      optional: false

config_options:
  - name: timeout
    type: duration
    description: Default scan timeout
    default: 5m
  - name: max_retries
    type: int
    description: Maximum scan retries on failure
    default: 3
```

## Existing Tools

### Network Category

**nmap** - Network port scanner
- Location: `opensource/tools/network/nmap/`
- Input: NmapRequest (target, ports, flags)
- Output: NmapResponse (hosts, ports, services)

**subfinder** - Subdomain enumeration
- Location: `opensource/tools/network/subfinder/`
- Input: SubfinderRequest (domain, sources)
- Output: SubfinderResponse (subdomains)

### Web Category

**httpx** - HTTP probe and analysis
- Location: `opensource/tools/web/httpx/`
- Input: HttpxRequest (urls, options)
- Output: HttpxResponse (results, technologies)

**nuclei** - Vulnerability scanner
- Location: `opensource/tools/web/nuclei/`
- Input: NucleiRequest (targets, templates)
- Output: NucleiResponse (findings, matches)

### Kubernetes Category

**kubectl** - Kubernetes cluster operations
- Location: `opensource/tools/kubernetes/kubectl/`
- Uses: `kubernetes/common/gen` for shared types

## Development Workflow

### Create New Tool

```bash
# 1. Create tool directory
mkdir -p opensource/tools/{category}/{tool}/proto

# 2. Create proto definition
cat > opensource/tools/{category}/{tool}/proto/{tool}.proto <<EOF
syntax = "proto3";
package gibson.tools.{tool};
import "graphrag.proto";
option go_package = "github.com/zero-day-ai/tools/{category}/{tool}/gen";

message {Tool}Request {
  string target = 1;
}

message {Tool}Response {
  string result = 1;
  gibson.graphrag.DiscoveryResult discovery = 100;
}
EOF

# 3. Create Makefile
cat > opensource/tools/{category}/{tool}/Makefile <<EOF
include ../../../proto.mk
EOF

# 4. Generate protos
cd opensource/tools/{category}/{tool}
make proto

# 5. Implement tool.go
# See complete example above
```

### Build and Test

```bash
# Generate protos
make proto

# Build tool
make build

# Run tests
make test
make test-coverage

# Run locally
./{tool}
```

### Debug

```bash
# Enable debug logging
export GIBSON_LOG_LEVEL=debug

# Test with grpcurl
grpcurl -plaintext -d '{...}' localhost:50051 gibson.tools.{tool}.{Tool}Service/{Method}
```

## Best Practices

### Proto Design

1. **Use field 100 for DiscoveryResult** - Always include graph data
2. **Full package names** - `gibson.tools.{tool}`, not `gibson.tools`
3. **Semantic versioning** - Version protos carefully to avoid breaking changes
4. **Descriptive field names** - Use clear, consistent naming conventions
5. **Avoid nested complexity** - Flatten structures where possible

### Tool Implementation

1. **Validate input** - Check required fields before execution
2. **Handle timeouts** - Respect context cancellation
3. **Return structured errors** - Use proto error types when applicable
4. **Populate discovery results** - Extract entities and relationships
5. **Log appropriately** - Use structured logging with context
6. **Check dependencies** - Verify external binaries in Initialize()
7. **Graceful shutdown** - Clean up resources in Shutdown()

### Graph Population

1. **Entity types** - Use consistent entity type naming (host, port, domain, service)
2. **Entity names** - Use unique, deterministic identifiers
3. **Relationships** - Model real-world connections (has_port, runs_service, depends_on)
4. **Properties** - Add relevant metadata for filtering and analysis
5. **Confidence scores** - Include confidence when applicable

### Testing

1. **Unit tests** - Test proto parsing and tool logic separately
2. **Integration tests** - Test full execution with real/mock binaries
3. **Proto validation** - Verify field 100 is populated correctly
4. **Error cases** - Test timeout, invalid input, missing dependencies
5. **Mock external tools** - Use test fixtures for reproducible tests

## Migration Guide

### From Old toolspb to Self-Contained Protos

1. **Create local proto/**: Move tool proto from SDK to tool directory
2. **Update package**: Change from `gibson.tools` to `gibson.tools.{tool}`
3. **Add field 100**: Include DiscoveryResult in response message
4. **Update imports**: Change from SDK toolspb to local gen package
5. **Fix InputMessageType()**: Use full package name
6. **Run make proto**: Generate new proto code
7. **Update tests**: Update import paths and type assertions

**Example migration:**

```diff
// Before (old SDK toolspb)
-import "github.com/zero-day-ai/sdk/api/gen/toolspb"
+import pb "github.com/zero-day-ai/tools/network/nmap/gen"
+import "github.com/zero-day-ai/sdk/api/gen/graphragpb"

 func (t *NmapTool) InputMessageType() string {
-    return "NmapRequest"
+    return "gibson.tools.nmap.NmapRequest"
 }

 func (t *NmapTool) Execute(ctx context.Context, input proto.Message) (proto.Message, error) {
-    req := input.(*toolspb.NmapRequest)
+    req := input.(*pb.NmapRequest)

     // ... execution logic ...

-    return &toolspb.NmapResponse{
+    return &pb.NmapResponse{
         Hosts: hosts,
+        Discovery: discovery,  // NEW: Field 100
     }, nil
 }
```

## Resources

- **SDK Documentation**: `github.com/zero-day-ai/sdk/docs/`
- **Proto Best Practices**: `github.com/zero-day-ai/sdk/docs/proto-guide.md`
- **Example Tools**: `opensource/tools/network/nmap/`
- **Protocol Buffers Guide**: https://protobuf.dev/
- **gRPC Go Tutorial**: https://grpc.io/docs/languages/go/
