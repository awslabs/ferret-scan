#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Setup team-wide Ferret Scan configuration

set -e

echo "🏢 Setting up team-wide Ferret Scan configuration..."

# Function to create a team config file
create_team_config() {
    local config_type=$1
    local config_file=".ferret-scan.yaml"
    
    case $config_type in
        "startup")
            cat > "$config_file" << 'EOF'
# Ferret Scan Team Configuration - Startup/Development Team
# Balanced security with developer productivity focus

defaults:
  format: text
  confidence_levels: high,medium
  checks: CREDIT_CARD,SECRETS,SSN,EMAIL,PHONE
  verbose: false
  recursive: true
  quiet: false

# Suppressions configuration
suppressions:
  file: ".ferret-scan-suppressions.yaml"
  generate_on_scan: false

profiles:
  # Pre-commit profile - fast and focused
  precommit:
    format: text
    confidence_levels: high
    checks: CREDIT_CARD,SECRETS,SSN
    verbose: false
    quiet: true
    description: "Fast pre-commit scan focusing on critical data"
  
  # CI/CD profile - comprehensive scanning
  ci:
    format: junit
    confidence_levels: high,medium
    checks: all
    verbose: true
    no_color: true
    recursive: true
    quiet: true
    description: "Comprehensive CI/CD pipeline scan"
  
  # Security audit profile - thorough analysis
  security:
    format: json
    confidence_levels: all
    checks: all
    verbose: true
    recursive: true
    show_match: true
    description: "Thorough security audit scan"
EOF
            ;;
        "enterprise")
            cat > "$config_file" << 'EOF'
# Ferret Scan Team Configuration - Enterprise/Security-Focused
# High security standards with comprehensive detection

defaults:
  format: text
  confidence_levels: high,medium,low
  checks: all
  verbose: true
  recursive: true
  quiet: false

# Enhanced security settings
suppressions:
  file: ".ferret-scan-suppressions.yaml"
  generate_on_scan: false

# Validator configurations for enterprise
validators:
  intellectual_property:
    internal_urls:
      - "http[s]?:\\/\\/.*\\.internal\\.company\\.com"
      - "http[s]?:\\/\\/.*\\.corp\\.company\\.com"
      - "http[s]?:\\/\\/intranet\\.company\\.com"
      - "http[s]?:\\/\\/wiki\\.company\\.com"
      # Add your company's internal URL patterns here

profiles:
  # Strict pre-commit - blocks on medium confidence
  precommit:
    format: text
    confidence_levels: high,medium
    checks: all
    verbose: true
    quiet: true
    description: "Strict pre-commit security scan"
  
  # Enterprise CI/CD - comprehensive with audit trail
  ci:
    format: junit
    confidence_levels: all
    checks: all
    verbose: true
    no_color: true
    recursive: true
    quiet: true
    show_suppressed: true
    description: "Enterprise CI/CD scan with full audit trail"
  
  # Compliance audit - maximum detection
  compliance:
    format: json
    confidence_levels: all
    checks: all
    verbose: true
    recursive: true
    show_match: true
    show_suppressed: true
    description: "Compliance audit with maximum detection"
EOF
            ;;
        "financial")
            cat > "$config_file" << 'EOF'
# Ferret Scan Team Configuration - Financial Services
# Specialized for financial industry compliance requirements

defaults:
  format: text
  confidence_levels: high,medium
  checks: CREDIT_CARD,SSN,EMAIL,PHONE,SECRETS,PASSPORT
  verbose: true
  recursive: true
  quiet: false

# Financial services specific settings
suppressions:
  file: ".ferret-scan-suppressions.yaml"
  generate_on_scan: false

profiles:
  # PCI DSS compliance focused
  pci-compliance:
    format: json
    confidence_levels: all
    checks: CREDIT_CARD,SECRETS
    verbose: true
    recursive: true
    show_match: false  # Don't show actual card numbers in logs
    description: "PCI DSS compliance scan for credit card data"
  
  # SOX compliance focused
  sox-compliance:
    format: json
    confidence_levels: high,medium
    checks: all
    verbose: true
    recursive: true
    description: "SOX compliance comprehensive scan"
  
  # Pre-commit for financial code
  precommit:
    format: text
    confidence_levels: high
    checks: CREDIT_CARD,SSN,SECRETS
    verbose: false
    quiet: true
    description: "Financial services pre-commit scan"
EOF
            ;;
    esac
    
    echo "✅ Created $config_file for $config_type team"
}

# Function to show team type options
show_team_options() {
    echo ""
    echo "📋 Choose your team type:"
    echo ""
    echo "1. STARTUP      - Balanced security for development teams"
    echo "2. ENTERPRISE   - High security standards for large organizations"
    echo "3. FINANCIAL    - Specialized for financial services compliance"
    echo "4. CUSTOM       - I'll create my own configuration"
    echo ""
}

# Get team type
if [ $# -eq 0 ]; then
    show_team_options
    read -p "Choose team type (1-4): " choice
else
    choice=$1
fi

case $choice in
    1|startup|STARTUP)
        create_team_config "startup"
        ;;
    2|enterprise|ENTERPRISE)
        create_team_config "enterprise"
        ;;
    3|financial|FINANCIAL)
        create_team_config "financial"
        ;;
    4|custom|CUSTOM)
        echo "📝 Creating basic template..."
        cp config.yaml .ferret-scan.yaml
        echo "✅ Created .ferret-scan.yaml template"
        echo "📖 Edit .ferret-scan.yaml to customize for your team"
        ;;
    *)
        echo "❌ Invalid choice. Please run again and choose 1-4."
        exit 1
        ;;
esac

# Create suppressions file if it doesn't exist
if [ ! -f ".ferret-scan-suppressions.yaml" ]; then
    cat > .ferret-scan-suppressions.yaml << 'EOF'
# Ferret Scan Suppressions
# This file contains rules to suppress false positives
# Generated rules will be added here automatically

version: "1.0"
suppressions: []
EOF
    echo "✅ Created .ferret-scan-suppressions.yaml"
fi

# Update .gitignore if needed
if [ -f ".gitignore" ]; then
    if ! grep -q ".ferret-scan-suppressions.yaml" .gitignore; then
        echo "" >> .gitignore
        echo "# Ferret Scan suppressions (team-specific)" >> .gitignore
        echo ".ferret-scan-suppressions.yaml" >> .gitignore
        echo "✅ Added suppressions file to .gitignore"
    fi
fi

echo ""
echo "🎉 Team configuration setup complete!"
echo ""
echo "📁 Files created:"
echo "   • .ferret-scan.yaml (team configuration)"
echo "   • .ferret-scan-suppressions.yaml (suppressions)"
echo ""
echo "🔧 Next steps:"
echo "   1. Commit .ferret-scan.yaml to share with your team"
echo "   2. Keep .ferret-scan-suppressions.yaml local (in .gitignore)"
echo "   3. Run: ./scripts/setup-pre-commit.sh"
echo "   4. Test with: ferret-scan --file . --profile precommit"
echo ""
echo "📖 Available profiles in your config:"
if [ -f ".ferret-scan.yaml" ]; then
    echo "$(grep -A1 "^  [a-z-]*:$" .ferret-scan.yaml | grep -v "^--$" | sed 's/^  /   • /')"
fi