# Gibson Tools

This directory contains Gibson's modular security tools that integrate with the Gibson framework.

## Overview

Gibson tools are standalone security tools that can run as workers or servers, integrating with the Gibson daemon through a standardized protocol buffer interface. Each tool performs specific security functions like network discovery, vulnerability scanning, or Kubernetes security auditing.

## Proto Architecture

### Design Philosophy

Gibson follows a **self-contained proto architecture** where tools own their domain-specific proto definitions while the SDK owns only framework-level types. This design enables:

- **Independent tool development**: Add new tools without SDK changes
- **Clear ownership boundaries**: Domain types stay with tools, framework types in SDK
- **Flexible versioning**: Tools can evolve their schemas independently
- **Community contributions**: External developers can create tools without SDK access

### What SDK Owns vs What Tools Own

| Owner | Types | Purpose |
|-------|-------|---------|
| **SDK** | `gibson.graphrag.DiscoveryResult` | Field 100 for graph population |
| **SDK** | `gibson.common.Error` | Structured error responses |
| **SDK** | `gibson.common.HealthStatus` | Tool health reporting |
| **Tools** | Request/Response messages | Tool-specific I/O |
| **Tools** | Domain types (e.g., `KubeContext`) | Shared within category |

### Directory Structure

Each tool with protos follows this structure:

```
tools/{category}/{tool-name}/
├── proto/
│   └── {tool}.proto          # Tool's proto definitions
├── gen/
│   └── {tool}.pb.go          # Generated Go code (do not edit)
├── tool.go                   # Tool implementation
├── Makefile                  # Includes proto.mk
└── cmd/
    ├── server/main.go
    └── worker/main.go
```

For category-shared types:

```
tools/{category}/common/
├── proto/
│   └── {category}.proto      # Shared domain types
├── gen/
│   └── {category}.pb.go      # Generated code
└── Makefile
```

### Creating a New Tool with Protos

1. **Create directory structure**:
   ```bash
   mkdir -p tools/{category}/{tool-name}/proto
   mkdir -p tools/{category}/{tool-name}/gen
   mkdir -p tools/{category}/{tool-name}/cmd/server
   mkdir -p tools/{category}/{tool-name}/cmd/worker
   ```

2. **Create proto file** at `proto/{tool}.proto`:
   ```protobuf
   syntax = "proto3";
   package gibson.tools.{tool_name};
   option go_package = "github.com/zero-day-ai/tools/{category}/{tool-name}/gen";

   import "graphrag.proto";

   message {Tool}Request {
     // Your input fields (1-99)
   }

   message {Tool}Response {
     // Your output fields (1-99)

     // Field 100 MUST be DiscoveryResult for graph population
     gibson.graphrag.DiscoveryResult discovery = 100;
   }
   ```

3. **Create Makefile**:
   ```makefile
   include ../../proto.mk

   .PHONY: all build test

   all: proto build

   build:
       go build ./...

   test:
       go test ./...
   ```

4. **Generate proto code**:
   ```bash
   make proto
   ```

5. **Implement tool** using local `gen/` imports:
   ```go
   import (
       "github.com/zero-day-ai/tools/{category}/{tool-name}/gen"
       "github.com/zero-day-ai/sdk/api/gen/graphragpb"
   )

   func (t *ToolImpl) InputMessageType() string {
       return "gibson.tools.{tool_name}.{Tool}Request"
   }
   ```

### Sharing Types Between Tools

For types shared across tools in a category (e.g., `KubeContext` for Kubernetes tools):

1. **Create shared proto** at `tools/{category}/common/proto/{category}.proto`:
   ```protobuf
   syntax = "proto3";
   package gibson.tools.{category};
   option go_package = "github.com/zero-day-ai/tools/{category}/common/gen";

   message SharedType {
     // Shared fields
   }
   ```

2. **Import in tool protos**:
   ```protobuf
   import "{category}.proto";

   message MyToolRequest {
     gibson.tools.{category}.SharedType context = 1;
   }
   ```

3. **Update tool Makefile** to include common proto path (handled by proto.mk).

### Migration from SDK Protos

To migrate an existing tool from SDK protos to self-contained protos:

1. **Copy proto file**:
   ```bash
   cp sdk/api/proto/tools/{tool}.proto tools/{category}/{tool}/proto/
   ```

2. **Update package name**:
   ```diff
   -package gibson.tools;
   +package gibson.tools.{tool};
   ```

3. **Update go_package**:
   ```diff
   -option go_package = "github.com/zero-day-ai/sdk/api/gen/toolspb";
   +option go_package = "github.com/zero-day-ai/tools/{category}/{tool}/gen";
   ```

4. **Create Makefile** and generate:
   ```bash
   make proto
   ```

5. **Update tool.go imports**:
   ```diff
   -import "github.com/zero-day-ai/sdk/api/gen/toolspb"
   +import "github.com/zero-day-ai/tools/{category}/{tool}/gen"
   ```

6. **Update InputMessageType()**:
   ```diff
   -return "gibson.tools.{Tool}Request"
   +return "gibson.tools.{tool}.{Tool}Request"
   ```

7. **Mark SDK proto deprecated** (if it existed there).

### Proto Package Naming Convention

| Location | Package | Example |
|----------|---------|---------|
| SDK graphrag | `gibson.graphrag` | `DiscoveryResult` |
| SDK common | `gibson.common` | `Error`, `HealthStatus` |
| Category shared | `gibson.tools.{category}` | `gibson.tools.kubernetes` |
| Tool specific | `gibson.tools.{tool}` | `gibson.tools.nmap` |

### Field 100 Convention

**All tool responses MUST include field 100 for DiscoveryResult**:

```protobuf
import "graphrag.proto";

message MyToolResponse {
  // Tool-specific fields use 1-99
  string result = 1;
  int32 count = 2;

  // Field 100 is RESERVED for discovery results
  gibson.graphrag.DiscoveryResult discovery = 100;
}
```

This enables the Gibson framework to automatically populate the GraphRAG knowledge graph.

## Available Tools

### Discovery Category

Tools for network and infrastructure discovery:

- **nmap**: Network discovery and port scanning
- **httpx**: HTTP service enumeration and fingerprinting
- **nuclei**: Vulnerability scanning with templates
- **wappalyzer**: Web technology detection

### Kubernetes Category

Tools for Kubernetes security auditing and analysis:

- Additional Kubernetes tools coming soon

## Building Tools

### Build All Tools

```bash
make all
```

### Build Specific Tool

```bash
cd {category}/{tool-name}
make build
```

### Generate Proto Files

Generate protos for all tools:

```bash
make proto
```

Generate for specific tool:

```bash
cd {category}/{tool-name}
make proto
```

### Clean Generated Files

```bash
make proto-clean
```

## Running Tools

### As a Worker

```bash
cd {category}/{tool-name}
./cmd/worker/worker
```

### As a Server

```bash
cd {category}/{tool-name}
./cmd/server/server
```

## Testing

### Run All Tests

```bash
make test
```

### Run Specific Tool Tests

```bash
cd {category}/{tool-name}
make test
```

## Contributing

When contributing new tools:

1. Follow the proto architecture guidelines above
2. Place tools in appropriate category directories
3. Include comprehensive tests
4. Document tool-specific configuration
5. Ensure field 100 (DiscoveryResult) is properly populated
6. Follow Go best practices and Gibson coding standards

## License

See LICENSE file in this directory for licensing information.
