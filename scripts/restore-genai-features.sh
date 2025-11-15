#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# GenAI Features Restoration Script
# This script automatically restores all GenAI features by uncommenting GENAI_DISABLED code

set -e

echo "========================================"
echo "GenAI Features Restoration Script"
echo "========================================"
echo "This script will restore all disabled GenAI features."
echo ""

# Confirmation prompt
read -p "Are you sure you want to restore GenAI features? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Restoration cancelled."
    exit 0
fi

echo "Starting GenAI features restoration..."
echo ""

# Track restoration progress
RESTORED_FILES=0
TOTAL_CHANGES=0

# Function to restore GenAI code in a file
restore_genai_in_file() {
    local file="$1"
    local description="$2"

    if [ ! -f "$file" ]; then
        echo "⚠️  SKIP: $file (file not found)"
        return
    fi

    echo -n "Restoring $description ($file)... "

    # Count changes before restoration
    local changes_before=$(grep -c "GENAI_DISABLED" "$file" 2>/dev/null || echo "0")

    if [ "$changes_before" -eq 0 ]; then
        echo "✅ SKIP (no GenAI code to restore)"
        return
    fi

    # Create backup
    cp "$file" "$file.backup.$(date +%Y%m%d_%H%M%S)"

    # Restore Go code comments
    sed -i.tmp 's|// GENAI_DISABLED: ||g' "$file"

    # Restore HTML/XML comments
    sed -i.tmp 's|<!-- GENAI_DISABLED: \(.*\) -->|\1|g' "$file"

    # Restore YAML/Shell comments
    sed -i.tmp 's|# GENAI_DISABLED: ||g' "$file"

    # Remove temporary file
    rm -f "$file.tmp"

    # Count changes after restoration
    local changes_after=$(grep -c "GENAI_DISABLED" "$file" 2>/dev/null || echo "0")
    local restored_count=$((changes_before - changes_after))

    if [ "$restored_count" -gt 0 ]; then
        echo "✅ RESTORED ($restored_count changes)"
        RESTORED_FILES=$((RESTORED_FILES + 1))
        TOTAL_CHANGES=$((TOTAL_CHANGES + restored_count))
    else
        echo "⚠️  NO CHANGES"
    fi
}

echo "Restoring CLI interface..."
restore_genai_in_file "cmd/main.go" "CLI flags and functionality"

echo ""
echo "Restoring web interface..."
restore_genai_in_file "cmd/web/main.go" "Web backend GenAI processing"
restore_genai_in_file "cmd/web/template.html" "Web UI GenAI elements"

echo ""
echo "Restoring configuration system..."
restore_genai_in_file "internal/config/config.go" "GenAI configuration options"

echo ""
echo "Restoring router components..."
restore_genai_in_file "internal/router/file_router.go" "GenAI preprocessor routing"
restore_genai_in_file "internal/router/context.go" "GenAI context handling"
restore_genai_in_file "internal/router/integration.go" "GenAI integration logic"

echo ""
echo "Restoring scanner components..."
restore_genai_in_file "internal/scanner/scanner.go" "GenAI validator integration"

echo ""
echo "Restoring help system..."
restore_genai_in_file "internal/help/help.go" "GenAI help documentation"

echo ""
echo "Restoring parallel processing..."
restore_genai_in_file "internal/parallel/worker_pool.go" "GenAI parallel processing"

echo ""
echo "Restoring documentation and examples..."
restore_genai_in_file "README.md" "GenAI documentation"
restore_genai_in_file "examples/ferret.yaml" "GenAI configuration examples"
restore_genai_in_file "examples/genai_example.sh" "GenAI usage examples"

echo ""
echo "========================================"
echo "GenAI Restoration Complete"
echo "========================================"
echo "Files restored: $RESTORED_FILES"
echo "Total changes: $TOTAL_CHANGES"
echo ""

if [ $TOTAL_CHANGES -gt 0 ]; then
    echo "✅ GenAI features have been successfully restored!"
    echo ""
    echo "Next steps:"
    echo "1. Test the restored functionality:"
    echo "   go build -o ferret-scan cmd/main.go"
    echo "   ./ferret-scan --help | grep genai"
    echo ""
    echo "2. Verify GenAI flags are available:"
    echo "   ./ferret-scan --enable-genai --help"
    echo ""
    echo "3. Test GenAI functionality with AWS credentials configured"
    echo ""
    echo "4. Update tests to verify GenAI features work correctly"
    echo ""
    echo "Backup files created with timestamp for safety."
else
    echo "⚠️  No GenAI code found to restore."
    echo "GenAI features may already be enabled or the codebase structure has changed."
fi
