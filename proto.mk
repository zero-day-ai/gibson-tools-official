# Proto generation for Gibson tools
# Include in tool Makefiles: include ../../proto.mk
#
# This provides standardized proto generation for self-contained tools.
# Tools define their protos in proto/ and generate code to gen/
#
# Usage:
#   1. Create proto/*.proto files
#   2. Include this file: include ../../proto.mk
#   3. Run: make proto
#
# Proto imports are resolved from:
#   - proto/ (tool's own protos)
#   - SDK's proto directory (for graphrag.proto, common.proto)
#   - ../../common/proto (for category shared protos, if exists)

PROTOC ?= protoc
PROTO_DIR := proto
GEN_DIR := gen

# Find SDK proto directory via go module
SDK_PROTO := $(shell go list -m -f '{{.Dir}}' github.com/zero-day-ai/sdk 2>/dev/null)/api/proto
ifeq ($(SDK_PROTO),/api/proto)
    SDK_PROTO := $(shell pwd)/../../opensource/sdk/api/proto
endif

# Check for category common protos
COMMON_PROTO_DIR := $(wildcard ../../common/proto)

.PHONY: proto proto-clean proto-check

# Generate Go code from proto files
proto: $(GEN_DIR)
	@echo "Generating protos for $(notdir $(CURDIR))..."
	$(PROTOC) \
		--proto_path=$(PROTO_DIR) \
		--proto_path=$(SDK_PROTO) \
		$(if $(COMMON_PROTO_DIR),--proto_path=$(COMMON_PROTO_DIR),) \
		--go_out=$(GEN_DIR) \
		--go_opt=paths=source_relative \
		$(wildcard $(PROTO_DIR)/*.proto)

$(GEN_DIR):
	mkdir -p $(GEN_DIR)

# Clean generated proto files
proto-clean:
	rm -rf $(GEN_DIR)

# Check proto files exist
proto-check:
	@if [ ! -d "$(PROTO_DIR)" ]; then \
		echo "Error: proto/ directory not found"; \
		exit 1; \
	fi
	@if [ -z "$$(ls -A $(PROTO_DIR)/*.proto 2>/dev/null)" ]; then \
		echo "Error: No .proto files found in $(PROTO_DIR)/"; \
		exit 1; \
	fi
