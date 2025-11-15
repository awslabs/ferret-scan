#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# System-wide installation script for Ferret Scan
# Supports multiple installation methods for internal company deployment

set -e

# Configuration
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-~/.ferret-scan}"
BINARY_NAME="ferret-scan"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_permissions() {
    if [ "$EUID" -ne 0 ] && [ ! -w "$INSTALL_DIR" ]; then
        print_error "Installation requires sudo privileges or write access to $INSTALL_DIR"
        echo "Run with: sudo $0"
        exit 1
    fi
}

install_from_source() {
    print_info "Installing from source..."

    # Check if we're in the ferret-scan directory
    if [ ! -f "Makefile" ] || [ ! -f "go.mod" ]; then
        print_error "Not in ferret-scan source directory"
        print_info "Please run this script from the ferret-scan project root"
        exit 1
    fi

    # Build the binary
    print_info "Building ferret-scan..."
    if ! make build; then
        print_error "Build failed"
        exit 1
    fi

    # Install binary
    print_info "Installing binary to $INSTALL_DIR..."
    cp bin/ferret-scan "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    print_success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
}

install_from_binary() {
    local binary_path="$1"

    if [ ! -f "$binary_path" ]; then
        print_error "Binary not found: $binary_path"
        exit 1
    fi

    print_info "Installing binary from $binary_path..."
    cp "$binary_path" "$INSTALL_DIR/$BINARY_NAME"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    print_success "Binary installed to $INSTALL_DIR/$BINARY_NAME"
}

install_config_files() {
    print_info "Installing configuration files..."

    # Expand tilde to actual home directory
    local expanded_config_dir="${CONFIG_DIR/#\~/$HOME}"

    # Create config directory
    mkdir -p "$expanded_config_dir"

    # Install the example config as the default config (ready to use)
    if [ -f "examples/ferret.yaml" ]; then
        cp examples/ferret.yaml "$expanded_config_dir/config.yaml"
        print_success "Default config installed to $expanded_config_dir/config.yaml (from examples/ferret.yaml)"

        # Also keep a copy as example for reference
        cp examples/ferret.yaml "$expanded_config_dir/ferret.example.yaml"
        print_success "Example config installed to $expanded_config_dir/ferret.example.yaml"
    elif [ -f "config.yaml" ]; then
        # Fallback to basic config.yaml if examples/ferret.yaml doesn't exist
        cp config.yaml "$expanded_config_dir/config.yaml"
        print_success "Default config installed to $expanded_config_dir/config.yaml"
    else
        print_warning "No configuration files found to install"
    fi
}

setup_pre_commit_integration() {
    print_info "Setting up pre-commit integration..."

    # Make scripts executable
    if [ -d "scripts" ]; then
        chmod +x scripts/*.sh
        print_success "Pre-commit scripts made executable"
    fi

    # Note: Pre-commit wrapper scripts have been removed in favor of direct integration
    # Users should now use ferret-scan directly in their pre-commit configuration
    print_info "Pre-commit wrapper scripts have been deprecated - use direct integration instead"

    # Provide guidance for direct integration
    echo ""
    print_info "For direct pre-commit integration, add to your .pre-commit-config.yaml:"
    echo "  repos:"
    echo "    - repo: local"
    echo "      hooks:"
    echo "        - id: ferret-scan"
    echo "          name: Ferret Scan"
    echo "          entry: ferret-scan --pre-commit-mode"
    echo "          language: system"
    echo "          files: \\.(txt|md|py|go|js|ts|java|cpp|c|h)$"
    echo ""
    print_info "Or use the Python package:"
    echo "  repos:"
    echo "    - repo: https://github.com/your-org/ferret-scan"
    echo "      rev: v1.0.0"
    echo "      hooks:"
    echo "        - id: ferret-scan"
}

verify_installation() {
    print_info "Verifying installation..."

    if command -v ferret-scan >/dev/null 2>&1; then
        local version
        version=$(ferret-scan --version 2>/dev/null || echo "unknown")
        print_success "ferret-scan is available in PATH (version: $version)"
    else
        print_warning "ferret-scan not found in PATH"
        print_info "You may need to add $INSTALL_DIR to your PATH"
        print_info "Add this to your ~/.bashrc or ~/.zshrc:"
        echo "export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

show_usage() {
    echo "Usage: $0 [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  source              Install from source (default)"
    echo "  binary <path>       Install from existing binary"
    echo "  uninstall          Remove ferret-scan installation"
    echo ""
    echo "Options:"
    echo "  --install-dir DIR   Installation directory (default: /usr/local/bin)"
    echo "  --config-dir DIR    Configuration directory (default: ~/.ferret-scan)"
    echo "  --no-config         Skip configuration file installation"
    echo "  --no-precommit      Skip pre-commit integration setup"
    echo "  --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  sudo $0                                    # Install from source"
    echo "  sudo $0 binary ./ferret-scan              # Install from binary"
    echo "  sudo $0 --install-dir /opt/bin source     # Custom install directory"
}

uninstall() {
    print_info "Uninstalling ferret-scan..."

    # Remove binary
    if [ -f "$INSTALL_DIR/$BINARY_NAME" ]; then
        rm "$INSTALL_DIR/$BINARY_NAME"
        print_success "Removed $INSTALL_DIR/$BINARY_NAME"
    else
        print_warning "Binary not found: $INSTALL_DIR/$BINARY_NAME"
    fi

    # Remove pre-commit wrapper
    if [ -f "$INSTALL_DIR/ferret-scan-precommit" ]; then
        rm "$INSTALL_DIR/ferret-scan-precommit"
        print_success "Removed $INSTALL_DIR/ferret-scan-precommit"
    else
        print_warning "Pre-commit wrapper not found: $INSTALL_DIR/ferret-scan-precommit"
    fi

    # Ask about config directory
    local expanded_config_dir="${CONFIG_DIR/#\~/$HOME}"
    if [ -d "$expanded_config_dir" ]; then
        echo ""
        print_info "Configuration directory found: $expanded_config_dir"
        echo "Contents:"
        ls -la "$expanded_config_dir" 2>/dev/null || echo "  (empty or inaccessible)"
        echo ""
        echo -n "Remove configuration directory $expanded_config_dir? [y/N]: "
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            rm -rf "$expanded_config_dir"
            print_success "Removed $expanded_config_dir"
        else
            print_info "Configuration directory preserved"
        fi
    else
        print_info "No configuration directory found at $expanded_config_dir"
    fi

    # Check for project-level pre-commit hooks
    if [ -f ".git/hooks/pre-commit" ]; then
        echo ""
        print_info "Found Git pre-commit hook in current directory"
        echo -n "Remove pre-commit hook from current project? [y/N]: "
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            rm -f ".git/hooks/pre-commit"
            print_success "Removed .git/hooks/pre-commit"
        fi
    fi

    # Provide cleanup instructions
    echo ""
    print_info "Manual cleanup (if needed):"
    echo "• Remove from PATH if manually added"
    echo "• Run 'pre-commit uninstall' in projects using pre-commit framework"
    echo "• Remove project-specific .ferret-scan.yaml files"
    echo "• Remove project-specific .ferret-scan-suppressions.yaml files"

    print_success "Uninstallation complete"
}

# Parse command line arguments
INSTALL_CONFIG=true
INSTALL_PRECOMMIT=true
COMMAND="source"

while [[ $# -gt 0 ]]; do
    case $1 in
        --install-dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --config-dir)
            CONFIG_DIR="$2"
            shift 2
            ;;
        --no-config)
            INSTALL_CONFIG=false
            shift
            ;;
        --no-precommit)
            INSTALL_PRECOMMIT=false
            shift
            ;;
        --help)
            show_usage
            exit 0
            ;;
        source|binary|uninstall)
            COMMAND="$1"
            shift
            ;;
        *)
            if [ "$COMMAND" = "binary" ] && [ -z "$BINARY_PATH" ]; then
                BINARY_PATH="$1"
                shift
            else
                print_error "Unknown option: $1"
                show_usage
                exit 1
            fi
            ;;
    esac
done

# Main installation logic
echo "🚀 Ferret Scan System Installation"
echo "=================================="
echo "Install directory: $INSTALL_DIR"
echo "Config directory: ${CONFIG_DIR/#\~/$HOME}"
echo "Command: $COMMAND"
echo ""

case "$COMMAND" in
    source)
        check_permissions
        install_from_source
        ;;
    binary)
        if [ -z "$BINARY_PATH" ]; then
            print_error "Binary path required for 'binary' command"
            show_usage
            exit 1
        fi
        check_permissions
        install_from_binary "$BINARY_PATH"
        ;;
    uninstall)
        check_permissions
        uninstall
        exit 0
        ;;
esac

# Install additional components
if [ "$INSTALL_CONFIG" = true ]; then
    install_config_files
fi

if [ "$INSTALL_PRECOMMIT" = true ]; then
    setup_pre_commit_integration
fi

verify_installation

echo ""
print_success "Installation complete!"
echo ""
print_info "Next steps:"
echo "1. Test installation: ferret-scan --version"
echo "2. Set up pre-commit: cd your-repo && scripts/setup-pre-commit.sh"
echo "3. Configure user settings: vim ~/.ferret-scan/config.yaml"
echo ""
print_info "Documentation: https://your-internal-docs/ferret-scan"
