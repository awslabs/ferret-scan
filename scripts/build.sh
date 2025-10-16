#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0



# Build script for Go-Metadata extractors

echo "Building Go-Metadata extractors..."

# Create build directory
mkdir -p build

# Build metadata extractors
echo "Building metadata extractors..."
cd meta-extractors

echo "  Building meta-extract-exif..."
go build -ldflags="-s -w" -o ../build/meta-extract-exif meta-extract-exif.go

echo "  Building meta-extract-pdf..."
go build -ldflags="-s -w" -o ../build/meta-extract-pdf meta-extract-pdf.go

echo "  Building meta-extract-office..."
go build -ldflags="-s -w" -o ../build/meta-extract-office meta-extract-office.go

cd ..

# Build text extractors
echo "Building text extractors..."
cd text-extractors

echo "  Building text-extract-pdf..."
go build -ldflags="-s -w" -o ../build/text-extract-pdf text-extract-pdf.go

echo "  Building text-extract-office..."
go build -ldflags="-s -w" -o ../build/text-extract-office text-extract-office.go

cd ..

echo "Build complete! Executables are in the 'build' directory:"
ls -la build/

echo ""
echo "Usage examples:"
echo "  ./build/meta-extract-exif image.jpg"
echo "  ./build/meta-extract-pdf document.pdf"
echo "  ./build/meta-extract-office document.docx"
echo "  ./build/text-extract-pdf document.pdf"
echo "  ./build/text-extract-office document.docx"
