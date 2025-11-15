#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Script to update version in Go source file
# Used by semantic-release to inject version information

set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <version>"
    exit 1
fi

VERSION="$1"
VERSION_FILE="internal/version/version.go"

echo "Updating version to $VERSION in $VERSION_FILE"

# Update the version in the Go file
sed -i.bak "s/Version = \".*\"/Version = \"$VERSION\"/" "$VERSION_FILE"

# Remove backup file
rm -f "$VERSION_FILE.bak"

echo "Version updated successfully"
