#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Ferret Scan Test Runner Script
# This script provides a convenient way to run different types of tests
# Compatible with GitLab CI/CD and local development

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TEST_TYPE="all"
VERBOSE=false
COVERAGE=false
RACE=false
DEBUG=false

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -t, --type TYPE     Test type: all, unit, integration, aws (default: all)"
    echo "  -v, --verbose       Enable verbose output"
    echo "  -c, --coverage      Generate coverage report"
    echo "  -r, --race          Enable race detection"
    echo "  -d, --debug         Enable debug logging"
    echo "  -h, --help          Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                          # Run all tests"
    echo "  $0 -t unit -v              # Run unit tests with verbose output"
    echo "  $0 -t integration -c       # Run integration tests with coverage"
    echo "  $0 -t aws -d               # Run AWS tests with debug logging"
    echo "  $0 -r -c                   # Run all tests with race detection and coverage"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--coverage)
            COVERAGE=true
            shift
            ;;
        -r|--race)
            RACE=true
            shift
            ;;
        -d|--debug)
            DEBUG=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate test type
case $TEST_TYPE in
    all|unit|integration|aws)
        ;;
    *)
        print_error "Invalid test type: $TEST_TYPE"
        print_error "Valid types: all, unit, integration, aws"
        exit 1
        ;;
esac

# Setup environment
print_status "Setting up test environment..."

# Enable test mode for AWS mocking
export FERRET_TEST_MODE=true

# Enable debug logging if requested
if [ "$DEBUG" = true ]; then
    export FERRET_DEBUG=1
    print_status "Debug logging enabled"
fi

# Mock AWS credentials for testing
export AWS_ACCESS_KEY_ID=test-access-key
export AWS_SECRET_ACCESS_KEY=test-secret-key
export AWS_REGION=us-east-1

# Build test flags
TEST_FLAGS=""
if [ "$VERBOSE" = true ]; then
    TEST_FLAGS="$TEST_FLAGS -v"
fi

if [ "$RACE" = true ]; then
    TEST_FLAGS="$TEST_FLAGS -race"
    print_status "Race detection enabled"
fi

if [ "$COVERAGE" = true ]; then
    TEST_FLAGS="$TEST_FLAGS -coverprofile=coverage.out"
    print_status "Coverage reporting enabled"
fi

# Function to run tests
run_tests() {
    local test_path=$1
    local test_name=$2

    print_status "Running $test_name tests..."

    if go test $TEST_FLAGS $test_path; then
        print_success "$test_name tests passed"
        return 0
    else
        print_error "$test_name tests failed"
        return 1
    fi
}

# Main test execution
print_status "Starting Ferret Scan test suite..."
print_status "Test type: $TEST_TYPE"

FAILED_TESTS=0

case $TEST_TYPE in
    "unit")
        run_tests "./tests/unit/..." "Unit" || FAILED_TESTS=$((FAILED_TESTS + 1))
        ;;
    "integration")
        run_tests "./tests/integration/..." "Integration" || FAILED_TESTS=$((FAILED_TESTS + 1))
        ;;
    "aws")
        run_tests "./tests/integration/aws_integration_test.go" "AWS Integration" || FAILED_TESTS=$((FAILED_TESTS + 1))
        ;;
    "all")
        run_tests "./tests/unit/..." "Unit" || FAILED_TESTS=$((FAILED_TESTS + 1))
        run_tests "./tests/integration/..." "Integration" || FAILED_TESTS=$((FAILED_TESTS + 1))
        ;;
esac

# Generate coverage report if requested
if [ "$COVERAGE" = true ] && [ -f coverage.out ]; then
    print_status "Generating coverage report..."
    go tool cover -html=coverage.out -o coverage.html

    # Calculate coverage percentage
    COVERAGE_PERCENT=$(go tool cover -func=coverage.out | grep total | awk '{print $3}')
    print_status "Total coverage: $COVERAGE_PERCENT"

    if command -v open >/dev/null 2>&1; then
        print_status "Opening coverage report in browser..."
        open coverage.html
    elif command -v xdg-open >/dev/null 2>&1; then
        print_status "Opening coverage report in browser..."
        xdg-open coverage.html
    else
        print_status "Coverage report saved to coverage.html"
    fi
fi

# Clean up environment
unset FERRET_TEST_MODE
unset FERRET_DEBUG
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_REGION

# Final status
if [ $FAILED_TESTS -eq 0 ]; then
    print_success "All tests completed successfully!"
    exit 0
else
    print_error "$FAILED_TESTS test suite(s) failed"
    exit 1
fi
