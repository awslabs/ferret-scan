#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Enhanced Architecture Compatibility Test Runner
# This script runs comprehensive compatibility tests to verify the enhanced architecture
# maintains backward compatibility and produces consistent results.

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_DIR="${TEST_DIR}/tmp/compatibility-tests"
LOG_FILE="${TEMP_DIR}/compatibility-test.log"

# Create temp directory
mkdir -p "${TEMP_DIR}"

echo -e "${BLUE}Enhanced Architecture Compatibility Test Suite${NC}"
echo "=============================================="
echo "Test directory: ${TEST_DIR}"
echo "Temp directory: ${TEMP_DIR}"
echo "Log file: ${LOG_FILE}"
echo ""

# Function to log messages
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "${LOG_FILE}"
}

# Function to run test with error handling
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -e "${BLUE}Running: ${test_name}${NC}"
    log "Starting test: ${test_name}"
    
    if eval "${test_command}" >> "${LOG_FILE}" 2>&1; then
        echo -e "${GREEN}✓ PASSED: ${test_name}${NC}"
        log "PASSED: ${test_name}"
        return 0
    else
        echo -e "${RED}✗ FAILED: ${test_name}${NC}"
        log "FAILED: ${test_name}"
        return 1
    fi
}

# Initialize test results
TOTAL_TESTS=0
PASSED_TESTS=0
FAILED_TESTS=0

# Test 1: Backward Compatibility Tests
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Backward Compatibility Tests" "cd '${TEST_DIR}' && go test ./tests/integration/backward_compatibility_test.go -v"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 2: Architecture Compatibility Tests
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Architecture Compatibility Tests" "cd '${TEST_DIR}' && go test ./tests/integration/architecture_compatibility_test.go -v"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 3: CLI Compatibility Tests
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "CLI Compatibility Tests" "cd '${TEST_DIR}' && go test ./tests/integration/cli_compatibility_test.go -v"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 4: Content Router Unit Tests
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Content Router Unit Tests" "cd '${TEST_DIR}' && go test ./tests/unit/router/content_router_test.go -v"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 5: Enhanced Validator Bridge Tests
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Enhanced Validator Bridge Tests" "cd '${TEST_DIR}' && go test ./internal/validators/dual_path_bridge_test.go -v"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 6: Build Verification
TOTAL_TESTS=$((TOTAL_TESTS + 1))
if run_test "Build Verification" "cd '${TEST_DIR}' && go build -o '${TEMP_DIR}/ferret-scan-test' cmd/main.go"; then
    PASSED_TESTS=$((PASSED_TESTS + 1))
else
    FAILED_TESTS=$((FAILED_TESTS + 1))
fi

echo ""

# Test 7: Basic Functionality Test
if [ -f "${TEMP_DIR}/ferret-scan-test" ]; then
    # Create test file
    echo "Test document with credit card 4532-1234-5678-9012 and email test@example.com" > "${TEMP_DIR}/test-input.txt"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if run_test "Basic Functionality Test" "'${TEMP_DIR}/ferret-scan-test' --file '${TEMP_DIR}/test-input.txt' --format json --confidence high"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
    
    # Test 8: Preprocess-Only Mode
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if run_test "Preprocess-Only Mode Test" "'${TEMP_DIR}/ferret-scan-test' --file '${TEMP_DIR}/test-input.txt' --preprocess-only"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
    
    # Test 9: Configuration Compatibility
    # Create test config
    cat > "${TEMP_DIR}/test-config.yaml" << EOF
defaults:
  format: "json"
  confidence_levels: "high"
  verbose: true
EOF
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    if run_test "Configuration Compatibility Test" "'${TEMP_DIR}/ferret-scan-test' --config '${TEMP_DIR}/test-config.yaml' --file '${TEMP_DIR}/test-input.txt'"; then
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
fi

# Performance Test (optional, only if binary was built successfully)
if [ -f "${TEMP_DIR}/ferret-scan-test" ]; then
    # Create larger test file for performance testing
    for i in {1..100}; do
        echo "Line $i: Credit card 4532-1234-5678-9012 and email test$i@example.com"
    done > "${TEMP_DIR}/large-test-input.txt"
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -e "${BLUE}Running: Performance Test${NC}"
    log "Starting performance test"
    
    start_time=$(date +%s)
    if "${TEMP_DIR}/ferret-scan-test" --file "${TEMP_DIR}/large-test-input.txt" --format json --confidence high >> "${LOG_FILE}" 2>&1; then
        end_time=$(date +%s)
        duration=$((end_time - start_time))
        
        if [ $duration -le 10 ]; then
            echo -e "${GREEN}✓ PASSED: Performance Test (${duration}s)${NC}"
            log "PASSED: Performance Test (${duration}s)"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo -e "${YELLOW}⚠ WARNING: Performance Test took ${duration}s (expected ≤10s)${NC}"
            log "WARNING: Performance Test took ${duration}s"
            PASSED_TESTS=$((PASSED_TESTS + 1))
        fi
    else
        echo -e "${RED}✗ FAILED: Performance Test${NC}"
        log "FAILED: Performance Test"
        FAILED_TESTS=$((FAILED_TESTS + 1))
    fi
    
    echo ""
fi

# Summary
echo "=============================================="
echo -e "${BLUE}Test Summary${NC}"
echo "=============================================="
echo "Total tests: ${TOTAL_TESTS}"
echo -e "Passed: ${GREEN}${PASSED_TESTS}${NC}"
echo -e "Failed: ${RED}${FAILED_TESTS}${NC}"

if [ ${FAILED_TESTS} -eq 0 ]; then
    echo ""
    echo -e "${GREEN}🎉 All compatibility tests passed!${NC}"
    echo -e "${GREEN}The enhanced architecture is ready for deployment.${NC}"
    log "All compatibility tests passed successfully"
    exit 0
else
    echo ""
    echo -e "${RED}❌ ${FAILED_TESTS} test(s) failed.${NC}"
    echo -e "${RED}Please review the failures before deployment.${NC}"
    echo ""
    echo "Check the log file for details: ${LOG_FILE}"
    log "${FAILED_TESTS} test(s) failed"
    exit 1
fi