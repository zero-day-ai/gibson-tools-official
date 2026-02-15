# Kubernetes common proto generation
# These are shared types used by all Kubernetes tools

PROTOC ?= protoc
PROTO_DIR := proto
GEN_DIR := gen

# Find SDK proto directory
SDK_PROTO := $(shell go list -m -f '{{.Dir}}' github.com/zero-day-ai/sdk 2>/dev/null)/api/proto
ifeq ($(SDK_PROTO),/api/proto)
    SDK_PROTO := $(shell pwd)/../../../opensource/sdk/api/proto
endif

.PHONY: proto proto-clean

proto: $(GEN_DIR)
	@echo "Generating Kubernetes common protos..."
	$(PROTOC) \
		--proto_path=$(PROTO_DIR) \
		--proto_path=$(SDK_PROTO) \
		--go_out=$(GEN_DIR) \
		--go_opt=paths=source_relative \
		$(wildcard $(PROTO_DIR)/*.proto)

$(GEN_DIR):
	mkdir -p $(GEN_DIR)

proto-clean:
	rm -rf $(GEN_DIR)
