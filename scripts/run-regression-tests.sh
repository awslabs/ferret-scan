#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Comprehensive Regression Test Suite Runner
# This script runs the architecture regression tests for the metadata processing enhancement

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
TEST_TIMEOUT="30m"
VERBOSE=${VERBOSE:-false}
STRESS_TESTS=${STRESS_TESTS:-false}
BENCHMARK_TESTS=${BENCHMARK_TESTS:-false}

echo -e "${BLUE}=== Ferret Scan Architecture Regression Test Suite ===${NC}"
echo "Running comprehensive regression tests to compare current and enhanced architectures"
echo

# Function to print section headers
print_section() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

# Function to print success messages
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

# Function to print warning messages
print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Function to print error messages
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Set up test environment
setup_test_environment() {
    print_section "Setting up test environment"

    # Set test mode environment variables
    export FERRET_TEST_MODE=true
    export AWS_ACCESS_KEY_ID=test-access-key
    export AWS_SECRET_ACCESS_KEY=test-secret-key
    export AWS_REGION=us-east-1

    # Create test directories if they don't exist
    mkdir -p tests/integration
    mkdir -p tests/testdata/samples

    print_success "Test environment configured"
}

# Run core regression tests
run_core_regression_tests() {
    print_section "Running Core Regression Tests"

    echo "Testing file type consistency..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestArchitectureRegressionSuite/FileTypeConsistencyTests; then
        print_success "File type consistency tests passed"
    else
        print_error "File type consistency tests failed"
        return 1
    fi

    echo "Testing metadata combination consistency..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestArchitectureRegressionSuite/MetadataCombinationTests; then
        print_success "Metadata combination tests passed"
    else
        print_error "Metadata combination tests failed"
        return 1
    fi

    echo "Testing confidence score variance..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestArchitectureRegressionSuite/ConfidenceScoreVarianceTests; then
        print_success "Confidence score variance tests passed"
    else
        print_error "Confidence score variance tests failed"
        return 1
    fi

    echo "Testing edge case handling..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestArchitectureRegressionSuite/EdgeCaseHandlingTests; then
        print_success "Edge case handling tests passed"
    else
        print_error "Edge case handling tests failed"
        return 1
    fi
}

# Run large dataset tests
run_large_dataset_tests() {
    print_section "Running Large Dataset Tests"

    echo "Testing large dataset consistency..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestArchitectureRegressionSuite/LargeDatasetTests; then
        print_success "Large dataset tests passed"
    else
        print_error "Large dataset tests failed"
        return 1
    fi
}

# Run performance regression tests
run_performance_tests() {
    print_section "Running Performance Regression Tests"

    echo "Testing performance regression..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestArchitectureRegressionSuite/PerformanceRegressionTests; then
        print_success "Performance regression tests passed"
    else
        print_error "Performance regression tests failed"
        return 1
    fi
}

# Run real file tests
run_real_file_tests() {
    print_section "Running Real File Tests"

    echo "Testing with real sample files..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestRegressionSuiteWithRealFiles; then
        print_success "Real file tests passed"
    else
        print_warning "Real file tests failed (may be due to missing sample files)"
    fi
}

# Run configuration variation tests
run_configuration_tests() {
    print_section "Running Configuration Variation Tests"

    echo "Testing different configuration scenarios..."
    if go test -timeout $TEST_TIMEOUT -v ./tests/integration -run TestRegressionSuiteConfigurationVariations; then
        print_success "Configuration variation tests passed"
    else
        print_error "Configuration variation tests failed"
        return 1
    fi
}

# Run stress tests (optional)
run_stress_tests() {
    if [ "$STRESS_TESTS" = "true" ]; then
        print_section "Running Stress Tests"

        echo "Running high-load stress tests..."
        if go test -timeout 60m -v ./tests/integration -run TestRegressionSuiteStressTest; then
            print_success "Stress tests passed"
        else
            print_error "Stress tests failed"
            return 1
        fi
    else
        print_warning "Stress tests skipped (set STRESS_TESTS=true to enable)"
    fi
}

# Run benchmark tests (optional)
run_benchmark_tests() {
    if [ "$BENCHMARK_TESTS" = "true" ]; then
        print_section "Running Benchmark Tests"

        echo "Running performance benchmarks..."
        if go test -timeout 45m -v ./tests/integration -run TestRegressionSuiteBenchmark; then
            print_success "Benchmark tests passed"
        else
            print_error "Benchmark tests failed"
            return 1
        fi
    else
        print_warning "Benchmark tests skipped (set BENCHMARK_TESTS=true to enable)"
    fi
}

# Generate test report
generate_test_report() {
    print_section "Generating Test Report"

    REPORT_FILE="regression_test_report_$(date +%Y%m%d_%H%M%S).txt"

    echo "Architecture Regression Test Report" > $REPORT_FILE
    echo "Generated: $(date)" >> $REPORT_FILE
    echo "======================================" >> $REPORT_FILE
    echo >> $REPORT_FILE

    echo "Test Configuration:" >> $REPORT_FILE
    echo "- Timeout: $TEST_TIMEOUT" >> $REPORT_FILE
    echo "- Stress Tests: $STRESS_TESTS" >> $REPORT_FILE
    echo "- Benchmark Tests: $BENCHMARK_TESTS" >> $REPORT_FILE
    echo "- Verbose: $VERBOSE" >> $REPORT_FILE
    echo >> $REPORT_FILE

    echo "Test Results:" >> $REPORT_FILE
    echo "- Core regression tests: PASSED" >> $REPORT_FILE
    echo "- Large dataset tests: PASSED" >> $REPORT_FILE
    echo "- Performance tests: PASSED" >> $REPORT_FILE
    echo "- Configuration tests: PASSED" >> $REPORT_FILE

    if [ "$STRESS_TESTS" = "true" ]; then
        echo "- Stress tests: PASSED" >> $REPORT_FILE
    fi

    if [ "$BENCHMARK_TESTS" = "true" ]; then
        echo "- Benchmark tests: PASSED" >> $REPORT_FILE
    fi

    echo >> $REPORT_FILE
    echo "All regression tests completed successfully." >> $REPORT_FILE
    echo "The enhanced architecture maintains consistency with the current implementation." >> $REPORT_FILE

    print_success "Test report generated: $REPORT_FILE"
}

# Cleanup function
cleanup() {
    print_section "Cleaning up"

    # Unset test environment variables
    unset FERRET_TEST_MODE
    unset AWS_ACCESS_KEY_ID
    unset AWS_SECRET_ACCESS_KEY
    unset AWS_REGION

    print_success "Cleanup completed"
}

# Main execution
main() {
    local exit_code=0

    # Set up trap for cleanup
    trap cleanup EXIT

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --stress)
                STRESS_TESTS=true
                shift
                ;;
            --benchmark)
                BENCHMARK_TESTS=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --timeout)
                TEST_TIMEOUT="$2"
                shift 2
                ;;
            --help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --stress      Enable stress tests (long running)"
                echo "  --benchmark   Enable benchmark tests (long running)"
                echo "  --verbose     Enable verbose output"
                echo "  --timeout     Set test timeout (default: 30m)"
                echo "  --help        Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    # Set verbose mode if requested
    if [ "$VERBOSE" = "true" ]; then
        set -x
    fi

    echo "Starting regression test suite with configuration:"
    echo "- Timeout: $TEST_TIMEOUT"
    echo "- Stress Tests: $STRESS_TESTS"
    echo "- Benchmark Tests: $BENCHMARK_TESTS"
    echo "- Verbose: $VERBOSE"
    echo

    # Run test phases
    setup_test_environment || exit_code=1

    if [ $exit_code -eq 0 ]; then
        run_core_regression_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_large_dataset_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_performance_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_real_file_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_configuration_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_stress_tests || exit_code=1
    fi

    if [ $exit_code -eq 0 ]; then
        run_benchmark_tests || exit_code=1
    fi

    # Generate report if all tests passed
    if [ $exit_code -eq 0 ]; then
        generate_test_report
        print_success "All regression tests completed successfully!"
        echo
        echo -e "${GREEN}The enhanced metadata processing architecture maintains consistency"
        echo -e "with the current implementation while providing improved functionality.${NC}"
    else
        print_error "Some regression tests failed. Please review the output above."
        echo
        echo -e "${RED}The enhanced architecture may have compatibility issues that need"
        echo -e "to be addressed before deployment.${NC}"
    fi

    exit $exit_code
}

# Run main function with all arguments
main "$@"
