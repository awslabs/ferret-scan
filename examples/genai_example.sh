#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# GENAI_DISABLED: Ferret Scan GenAI Example Script
# GENAI_DISABLED: This script demonstrates how to use Amazon Textract OCR with Ferret Scan

# GENAI_DISABLED: echo "Ferret Scan GenAI (Amazon Textract OCR) Example"
# GENAI_DISABLED: echo "=============================================="
# GENAI_DISABLED: echo ""

# Check if ferret-scan binary exists
if [ ! -f "../bin/ferret-scan" ]; then
    echo "Error: ferret-scan binary not found. Please build the project first:"
    echo "  make build"
    exit 1
fi

echo "GenAI Features Currently Disabled"
echo "================================="
echo "GenAI features (Amazon Textract, Transcribe, and Comprehend) are currently"
echo "disabled in this version of Ferret Scan. All GenAI-related functionality"
echo "has been temporarily commented out."
echo ""
echo "For standard document scanning without GenAI, use:"
echo "  ../bin/ferret-scan --file document.pdf"
echo ""
echo "Available non-GenAI features include:"
echo "• Credit card detection"
echo "• SSN detection"
echo "• Email detection"
echo "• Phone number detection"
echo "• IP address detection"
echo "• Passport detection"
echo "• Secrets detection"
echo "• Metadata extraction"
echo ""

# GENAI_DISABLED: Check if AWS credentials are configured
# GENAI_DISABLED: echo "Checking AWS credentials..."
# GENAI_DISABLED: if ! aws sts get-caller-identity >/dev/null 2>&1; then
# GENAI_DISABLED:     echo "Warning: AWS credentials not found or invalid."
# GENAI_DISABLED:     echo "Please configure AWS credentials before using GenAI mode:"
# GENAI_DISABLED:     echo "  aws configure"
# GENAI_DISABLED:     echo ""
# GENAI_DISABLED:     echo "Or set environment variables:"
# GENAI_DISABLED:     echo "  export AWS_ACCESS_KEY_ID=\"your-access-key\""
# GENAI_DISABLED:     echo "  export AWS_SECRET_ACCESS_KEY=\"your-secret-key\""
# GENAI_DISABLED:     echo "  export AWS_DEFAULT_REGION=\"us-east-1\""
# GENAI_DISABLED:     echo ""
# GENAI_DISABLED:     echo "Continuing with examples (will fail without credentials)..."
# GENAI_DISABLED:     echo ""
# GENAI_DISABLED: fi

# GENAI_DISABLED: echo "GenAI Mode Examples:"
# GENAI_DISABLED: echo "==================="
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "1. Basic GenAI usage (scanned PDF):"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file scanned-document.pdf --enable-genai"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "2. Process image with OCR:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file screenshot.png --enable-genai"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "3. Specify AWS region:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file image.jpg --enable-genai --textract-region us-west-2"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "4. GenAI with JSON output:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file document.pdf --enable-genai --format json"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "5. GenAI with debug information:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file image.png --enable-genai --debug"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "6. GenAI with specific checks:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file scanned.pdf --enable-genai --checks CREDIT_CARD,SSN"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "7. Batch processing with GenAI:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file *.pdf --enable-genai --recursive"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "8. AI-powered PII detection with Comprehend:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file document.txt --enable-genai --checks COMPREHEND_PII"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "9. Using GenAI profile from config:"
# GENAI_DISABLED: echo "   ../bin/ferret-scan --file document.pdf --config ferret.yaml --profile genai"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "Important Notes:"
# GENAI_DISABLED: echo "==============="
# GENAI_DISABLED: echo "⚠️  GenAI mode sends files/text to AWS services (Textract, Comprehend)"
# GENAI_DISABLED: echo "⚠️  AWS charges apply (Textract: ~\$0.0015/page, Comprehend: ~\$0.0001/100chars)"
# GENAI_DISABLED: echo "⚠️  Requires internet connection and AWS credentials"
# GENAI_DISABLED: echo "⚠️  Textract formats: PDF, PNG, JPEG, TIFF"
# GENAI_DISABLED: echo "⚠️  Comprehend: Any text content"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "Prerequisites:"
# GENAI_DISABLED: echo "============="
# GENAI_DISABLED: echo "1. AWS account with billing enabled"
# GENAI_DISABLED: echo "2. AWS credentials configured (aws configure)"
# GENAI_DISABLED: echo "3. IAM permissions: textract:DetectDocumentText, comprehend:DetectPiiEntities"
# GENAI_DISABLED: echo "4. Supported AWS region (us-east-1, us-west-2, etc.)"
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "Cost Estimation:"
# GENAI_DISABLED: echo "==============="
# GENAI_DISABLED: echo "• Single image: ~\$0.0015"
# GENAI_DISABLED: echo "• 10-page PDF: ~\$0.015"
# GENAI_DISABLED: echo "• 100 images: ~\$0.15"
# GENAI_DISABLED: echo ""
# GENAI_DISABLED: echo "Use --debug flag to see cost estimates before processing."
# GENAI_DISABLED: echo ""

# GENAI_DISABLED: echo "For more information, see:"
# GENAI_DISABLED: echo "• Main documentation: ../README.md"
# GENAI_DISABLED: echo "• GenAI guide: ../docs/genai_integration.md"
# GENAI_DISABLED: echo "• AWS Textract pricing: https://aws.amazon.com/textract/pricing/"
