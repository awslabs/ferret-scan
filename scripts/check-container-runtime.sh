#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to check available container runtimes

echo "Checking for container runtimes..."

DOCKER_AVAILABLE=false
FINCH_AVAILABLE=false

if command -v docker >/dev/null 2>&1; then
    DOCKER_AVAILABLE=true
    echo "✓ Docker found: $(docker --version)"
    
    # Test if Docker daemon is running
    if docker info >/dev/null 2>&1; then
        echo "  ✓ Docker daemon is running"
    else
        echo "  ✗ Docker daemon is not running"
    fi
else
    echo "✗ Docker not found"
fi

if command -v finch >/dev/null 2>&1; then
    FINCH_AVAILABLE=true
    echo "✓ Finch found: $(finch --version)"
    
    # Test if Finch is working
    if finch info >/dev/null 2>&1; then
        echo "  ✓ Finch is working"
    else
        echo "  ✗ Finch is not working properly"
    fi
else
    echo "✗ Finch not found"
fi

if [ "$DOCKER_AVAILABLE" = false ] && [ "$FINCH_AVAILABLE" = false ]; then
    echo ""
    echo "No container runtime found. Install one of:"
    echo "  Docker: https://docs.docker.com/get-docker/"
    echo "  Finch: https://github.com/runfinch/finch"
    exit 1
fi

echo ""
echo "Container runtime check completed successfully!"