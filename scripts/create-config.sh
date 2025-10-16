#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to create a default configuration file for Ferret Scan

CONFIG_DIR="$HOME/.config/ferret"
CONFIG_FILE="$CONFIG_DIR/config.yaml"

# Create config directory if it doesn't exist
mkdir -p "$CONFIG_DIR"

# Check if config file already exists
if [ -f "$CONFIG_FILE" ]; then
  echo "Configuration file already exists at $CONFIG_FILE"
  echo "To overwrite, delete the file first or specify a different location."
  exit 1
fi

# Create the configuration file
cat > "$CONFIG_FILE" << 'EOF'
# Ferret Scanner Configuration File
# This file defines default settings and profiles for different scanning scenarios

# Default settings applied when no profile is specified
defaults:
  format: text                # Output format: text or json
  confidence_levels: all      # Confidence levels to display: high, medium, low, or combinations
  checks: all                 # Specific checks to run: CREDIT_CARD, EMAIL, INTELLECTUAL_PROPERTY, IP_ADDRESS, METADATA, PASSPORT, PERSON_NAME, PHONE, SECRETS, SOCIAL_MEDIA, SSN, or combinations
  verbose: false              # Display detailed information for each finding
  no_color: false             # Disable colored output
  recursive: false            # Recursively scan directories

# Profiles for different scanning scenarios
profiles:
  # Quick scan profile - only high confidence matches, minimal output
  quick:
    format: text
    confidence_levels: high
    checks: all
    verbose: false
    no_color: false
    recursive: false
    description: "Quick scan with only high confidence matches"

  # Thorough scan profile - all confidence levels, verbose output, recursive scanning
  thorough:
    format: text
    confidence_levels: all
    checks: all
    verbose: true
    no_color: false
    recursive: true
    description: "Thorough scan with all confidence levels and recursive scanning"

  # CI/CD pipeline profile - JSON output for integration with CI/CD systems
  ci:
    format: json
    confidence_levels: high,medium
    checks: all
    verbose: true
    no_color: true
    recursive: true
    description: "CI/CD pipeline profile with JSON output"
EOF

chmod 600 "$CONFIG_FILE"

echo "Configuration file created at $CONFIG_FILE"
echo "You can now use it with: ferret-scan --file <path> --profile quick"
echo "Or list available profiles with: ferret-scan --list-profiles"
