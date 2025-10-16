#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Helper script to run containers with either Docker or Finch
# Usage: ./scripts/container-run.sh [container-args] image [command]

# Detect available container runtime
CONTAINER_CMD=""
if command -v docker >/dev/null 2>&1; then
    CONTAINER_CMD="docker"
elif command -v finch >/dev/null 2>&1; then
    CONTAINER_CMD="finch"
else
    echo "Error: Neither Docker nor Finch found. Please install one of them:"
    echo "  Docker: https://docs.docker.com/get-docker/"
    echo "  Finch: https://github.com/runfinch/finch"
    exit 1
fi

# Run the container with all passed arguments
exec $CONTAINER_CMD run "$@"