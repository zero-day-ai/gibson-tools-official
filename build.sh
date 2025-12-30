#!/bin/bash
# build.sh - Build script for Gibson Tools ecosystem
# This script builds all security tools organized by MITRE ATT&CK phases

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BIN_DIR="bin"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_TAGS=""
VERBOSE=0

# Dependency paths - can be overridden by environment
SDK_PATH="${SDK_PATH:-}"
GIBSON_PATH="${GIBSON_PATH:-}"

# Tool directories organized by MITRE ATT&CK phase
TOOLS=(
    # Reconnaissance Tools (TA0043)
    "reconnaissance/subfinder"
    "reconnaissance/httpx"
    "reconnaissance/amass"
    "reconnaissance/theharvester"
    "reconnaissance/nuclei"
    "reconnaissance/playwright"
    "reconnaissance/recon-ng"
    "reconnaissance/shodan"
    "reconnaissance/spiderfoot"

    # Resource Development Tools (TA0042)
    "resource-development/searchsploit"

    # Initial Access Tools (TA0001)
    "initial-access/sqlmap"
    "initial-access/gobuster"
    "initial-access/hydra"
    "initial-access/metasploit"

    # Execution Tools (TA0002)
    "execution/evil-winrm"
    "execution/impacket"

    # Persistence Tools (TA0003)
    "persistence/chisel"

    # Privilege Escalation Tools (TA0004)
    "privilege-escalation/linpeas"
    "privilege-escalation/winpeas"
    "privilege-escalation/john"
    "privilege-escalation/hashcat"

    # Defense Evasion Tools (TA0005)
    "defense-evasion/msfvenom"

    # Credential Access Tools (TA0006)
    "credential-access/secretsdump"
    "credential-access/responder"

    # Discovery Tools (TA0007)
    "discovery/nmap"
    "discovery/bloodhound"
    "discovery/crackmapexec"

    # Lateral Movement Tools (TA0008)
    "lateral-movement/proxychains"
    "lateral-movement/xfreerdp"

    # Collection Tools (TA0009)
    "collection/tshark"

    # Command and Control Tools (TA0011)
    "command-and-control/sliver"

    # Exfiltration Tools (TA0010)
    "exfiltration/rclone"

    # Impact Tools (TA0040)
    "impact/slowhttptest"
)

# Usage information
usage() {
    cat <<EOF
Usage: $0 [OPTIONS] [COMMAND]

Commands:
    all             Build all tools (default)
    clean           Remove all build artifacts
    test            Run all unit tests
    integration     Run integration tests
    help            Show this help message

Options:
    -v, --verbose   Verbose output
    -t, --tags      Build tags (comma-separated)
    -h, --help      Show this help message

Examples:
    $0                  # Build all tools
    $0 all              # Build all tools
    $0 clean            # Clean build artifacts
    $0 test             # Run unit tests
    $0 -v all           # Build with verbose output
    $0 -t integration   # Build with integration tag

EOF
}

# Print colored message
print_msg() {
    local color=$1
    local msg=$2
    echo -e "${color}${msg}${NC}"
}

# Print section header
print_section() {
    echo
    print_msg "$BLUE" "===================================================================="
    print_msg "$BLUE" "$1"
    print_msg "$BLUE" "===================================================================="
}

# Print success message
print_success() {
    print_msg "$GREEN" "[✓] $1"
}

# Print error message
print_error() {
    print_msg "$RED" "[✗] $1"
}

# Print warning message
print_warning() {
    print_msg "$YELLOW" "[!] $1"
}

# Print info message
print_info() {
    print_msg "$BLUE" "[i] $1"
}

# Create bin directory
setup_directories() {
    print_section "Setting up directories"

    if [ ! -d "$BIN_DIR" ]; then
        mkdir -p "$BIN_DIR"
        print_success "Created $BIN_DIR directory"
    else
        print_info "$BIN_DIR directory already exists"
    fi
}

# Setup Go workspace for building tools
# This handles both local development (relative paths) and Docker builds (absolute paths)
setup_workspace() {
    print_section "Setting up Go workspace"

    # Auto-detect SDK and Gibson paths if not set
    if [ -z "$SDK_PATH" ]; then
        # Check common locations
        if [ -d "/src/sdk" ]; then
            SDK_PATH="/src/sdk"
        elif [ -d "$SCRIPT_DIR/../../../sdk" ]; then
            SDK_PATH="$(cd "$SCRIPT_DIR/../../../sdk" && pwd)"
        else
            print_warning "SDK_PATH not set and not found in standard locations"
            print_info "Set SDK_PATH environment variable or clone SDK to /src/sdk or ../../../sdk"
            return 1
        fi
    fi

    if [ -z "$GIBSON_PATH" ]; then
        # Check common locations
        if [ -d "/src/gibson" ]; then
            GIBSON_PATH="/src/gibson"
        elif [ -d "$SCRIPT_DIR/../../../gibson" ]; then
            GIBSON_PATH="$(cd "$SCRIPT_DIR/../../../gibson" && pwd)"
        else
            print_warning "GIBSON_PATH not set and not found in standard locations"
            print_info "Set GIBSON_PATH environment variable or clone Gibson to /src/gibson or ../../../gibson"
            return 1
        fi
    fi

    # Export paths for use in build_tool
    export SDK_PATH
    export GIBSON_PATH

    print_info "Using SDK from: $SDK_PATH"
    print_info "Using Gibson from: $GIBSON_PATH"

    # Update pkg go.mod first (shared dependency)
    if [ -d "$SCRIPT_DIR/pkg" ] && [ -f "$SCRIPT_DIR/pkg/go.mod" ]; then
        print_info "Setting up pkg module..."
        local pkgmod="$SCRIPT_DIR/pkg/go.mod"

        # Remove old replace directives
        sed -i '/github.com\/zero-day-ai\/sdk.*=>/d' "$pkgmod"
        sed -i '/github.com\/zero-day-ai\/gibson[[:space:]]*=>/d' "$pkgmod"

        # Add new replace directives
        echo "" >> "$pkgmod"
        echo "replace github.com/zero-day-ai/sdk => $SDK_PATH" >> "$pkgmod"
        echo "replace github.com/zero-day-ai/gibson => $GIBSON_PATH" >> "$pkgmod"

        (cd "$SCRIPT_DIR/pkg" && GOWORK=off go mod tidy 2>/dev/null) || true
    fi

    print_success "Go workspace configured"
    return 0
}

# Build a single tool
# Returns: 0 = success, 1 = failed, 2 = skipped
build_tool() {
    local tool_path=$1
    local tool_name=$(basename "$tool_path")
    local output_binary="$BIN_DIR/$tool_name"

    if [ ! -d "$tool_path" ]; then
        print_warning "Tool directory $tool_path does not exist, skipping"
        return 2
    fi

    if [ ! -f "$tool_path/main.go" ]; then
        print_warning "No main.go found in $tool_path, skipping"
        return 2
    fi

    print_info "Building $tool_name..."

    # Update go.mod in this tool directory with correct paths
    if [ -f "$tool_path/go.mod" ]; then
        local modfile="$tool_path/go.mod"
        local pkg_rel=$(realpath --relative-to="$tool_path" "$SCRIPT_DIR/pkg" 2>/dev/null || echo "../../pkg")

        # Remove old replace directives
        sed -i '/github.com\/zero-day-ai\/sdk.*=>/d' "$modfile"
        sed -i '/github.com\/zero-day-ai\/gibson[[:space:]]*=>/d' "$modfile"
        sed -i '/github.com\/zero-day-ai\/gibson-tools-official\/pkg.*=>/d' "$modfile"
        sed -i '/^replace ($/{N;/^replace (\n)$/d}' "$modfile"

        # Add new replace directives
        echo "" >> "$modfile"
        echo "replace github.com/zero-day-ai/sdk => $SDK_PATH" >> "$modfile"
        echo "replace github.com/zero-day-ai/gibson => $GIBSON_PATH" >> "$modfile"
        if [ -d "$SCRIPT_DIR/pkg" ]; then
            echo "replace github.com/zero-day-ai/gibson-tools-official/pkg => $pkg_rel" >> "$modfile"
        fi

        # Run go mod tidy to update go.sum
        if [ "$VERBOSE" -eq 1 ]; then
            print_info "Running go mod tidy for $tool_name..."
        fi
        (cd "$tool_path" && GOWORK=off go mod tidy 2>/dev/null) || true
    fi

    # Build command - disable go.work to avoid conflicts
    local build_cmd="GOWORK=off go build -o ../../$output_binary"

    if [ -n "$BUILD_TAGS" ]; then
        build_cmd="$build_cmd -tags=$BUILD_TAGS"
    fi

    build_cmd="$build_cmd ."

    # Change to tool directory and build
    if [ "$VERBOSE" -eq 1 ]; then
        print_info "Executing: cd $tool_path && $build_cmd"
    fi

    if (cd "$tool_path" && eval $build_cmd); then
        if [ -f "$output_binary" ]; then
            local size=$(du -h "$output_binary" | cut -f1)
            print_success "Built $tool_name ($size)"
        else
            print_success "Built $tool_name"
        fi
        return 0
    else
        print_error "Failed to build $tool_name"
        return 1
    fi
}

# Build all tools
build_all() {
    print_section "Building all Gibson Tools"

    # Setup workspace first (configure SDK/Gibson paths)
    if ! setup_workspace; then
        print_error "Failed to setup Go workspace. Ensure SDK and Gibson are available."
        return 1
    fi

    setup_directories

    local success_count=0
    local fail_count=0
    local skip_count=0
    local total=${#TOOLS[@]}

    for tool in "${TOOLS[@]}"; do
        # Capture return code (0=success, 1=failed, 2=skipped)
        local result=0
        build_tool "$tool" || result=$?
        case $result in
            0)
                ((++success_count)) || true
                ;;
            1)
                ((++fail_count)) || true
                ;;
            2)
                ((++skip_count)) || true
                ;;
        esac
    done

    print_section "Build Summary"
    print_info "Total tools: $total"
    print_success "Successfully built: $success_count"

    if [ $skip_count -gt 0 ]; then
        print_warning "Skipped: $skip_count"
    fi

    if [ $fail_count -gt 0 ]; then
        print_error "Failed: $fail_count"
        return 1
    fi

    print_success "All tools built successfully!"
    return 0
}

# Clean build artifacts
clean_all() {
    print_section "Cleaning build artifacts"

    if [ -d "$BIN_DIR" ]; then
        rm -rf "$BIN_DIR"
        print_success "Removed $BIN_DIR directory"
    else
        print_info "No $BIN_DIR directory to clean"
    fi

    # Clean any go build cache
    print_info "Cleaning Go build cache..."
    go clean -cache 2>/dev/null || true

    print_success "Clean complete"
}

# Run unit tests
run_tests() {
    print_section "Running unit tests"

    print_info "Running tests for all modules..."

    if [ "$VERBOSE" -eq 1 ]; then
        go test -v ./...
    else
        go test ./...
    fi

    if [ $? -eq 0 ]; then
        print_success "All tests passed"
        return 0
    else
        print_error "Some tests failed"
        return 1
    fi
}

# Run integration tests
run_integration_tests() {
    print_section "Running integration tests"

    print_info "Running integration tests (requires binaries installed)..."

    if [ "$VERBOSE" -eq 1 ]; then
        go test -v -tags=integration ./...
    else
        go test -tags=integration ./...
    fi

    if [ $? -eq 0 ]; then
        print_success "All integration tests passed"
        return 0
    else
        print_error "Some integration tests failed"
        return 1
    fi
}

# Main function
main() {
    local command="all"

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -t|--tags)
                BUILD_TAGS="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            all|clean|test|integration|help)
                command="$1"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Change to script directory
    cd "$SCRIPT_DIR"

    # Execute command
    case $command in
        all)
            build_all
            ;;
        clean)
            clean_all
            ;;
        test)
            run_tests
            ;;
        integration)
            run_integration_tests
            ;;
        help)
            usage
            ;;
        *)
            print_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
