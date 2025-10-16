#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to set up the development environment for Ferret Scanner

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go first."
    exit 1
fi

# Install required Go tools
echo "Installing required Go tools..."
go install golang.org/x/lint/golint@latest

# Check if GOPATH/bin is in PATH
GOPATH=$(go env GOPATH)
if [[ ":$PATH:" != *":$GOPATH/bin:"* ]]; then
    echo "Adding $GOPATH/bin to PATH in your shell configuration..."

    # Determine shell configuration file
    SHELL_CONFIG=""
    if [ -n "$ZSH_VERSION" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [ -n "$BASH_VERSION" ] || [ "$(basename "$SHELL")" = "bash" ]; then
        if [ "$(uname)" = "Darwin" ]; then
            SHELL_CONFIG="$HOME/.bash_profile"
        else
            SHELL_CONFIG="$HOME/.bashrc"
        fi
    fi

    if [ -n "$SHELL_CONFIG" ]; then
        echo "" >> "$SHELL_CONFIG"
        echo "# Add Go bin directory to PATH" >> "$SHELL_CONFIG"
        echo "export PATH=\$PATH:\$(go env GOPATH)/bin" >> "$SHELL_CONFIG"
        echo "Added Go bin directory to $SHELL_CONFIG"
        echo "Please run 'source $SHELL_CONFIG' or restart your terminal to apply changes."
    else
        echo "Could not determine shell configuration file."
        echo "Please manually add the following line to your shell configuration:"
        echo "export PATH=\$PATH:$GOPATH/bin"
    fi
else
    echo "Go bin directory is already in your PATH."
fi

# Install other dependencies
echo "Installing other dependencies..."
go mod tidy

echo ""
echo "Development environment setup complete!"
echo "You may need to restart your terminal or run 'source ~/.zshrc' (or your shell config file) to apply PATH changes."
echo ""
echo "To verify installation, run:"
echo "  command -v golint  # Should show the path to golint"
echo ""
echo "To run the linter directly:"
echo "  $GOPATH/bin/golint ./..."
