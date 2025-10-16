// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"fmt"
	"io"
	"strings"
	"sync"
)

// Embedded compressed name database files
//
//go:embed data/first_names.txt.gz
var firstNamesDataGZ []byte

//go:embed data/last_names.txt.gz
var lastNamesDataGZ []byte

// NameDatabases holds the parsed name data for O(1) lookups
type NameDatabases struct {
	FirstNames map[string]bool // Lowercase name → exists
	LastNames  map[string]bool // Lowercase name → exists
}

var (
	// Global instance for lazy loading
	nameDatabases *NameDatabases
	loadOnce      sync.Once
	loadError     error
)

// LoadNameDatabases loads and decompresses the embedded name databases
// Uses sync.Once to ensure thread-safe lazy loading
func LoadNameDatabases() (*NameDatabases, error) {
	loadOnce.Do(func() {
		nameDatabases, loadError = loadEmbeddedDatabases()
	})
	return nameDatabases, loadError
}

// loadEmbeddedDatabases performs the actual loading and decompression
func loadEmbeddedDatabases() (*NameDatabases, error) {
	db := &NameDatabases{
		FirstNames: make(map[string]bool, 5200), // Optimized for actual ~5242 first names
		LastNames:  make(map[string]bool, 2200), // Optimized for actual ~2127 last names
	}

	// Load first names
	if err := loadNamesIntoMap(firstNamesDataGZ, db.FirstNames); err != nil {
		return nil, fmt.Errorf("failed to load first names: %w", err)
	}

	// Load last names
	if err := loadNamesIntoMap(lastNamesDataGZ, db.LastNames); err != nil {
		return nil, fmt.Errorf("failed to load last names: %w", err)
	}

	return db, nil
}

// loadNamesIntoMap decompresses and loads names into a boolean map
func loadNamesIntoMap(compressedData []byte, nameMap map[string]bool) error {
	// Decompress the data
	reader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	// Read and parse line by line
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		name := strings.TrimSpace(scanner.Text())
		if name != "" {
			// Validate name (basic sanitization)
			if isValidName(name) {
				nameMap[strings.ToLower(name)] = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading decompressed data: %w", err)
	}

	return nil
}

// isValidName performs basic validation on name data
func isValidName(name string) bool {
	// Check length constraints
	if len(name) < 2 || len(name) > 30 {
		return false
	}

	// Check for valid characters (letters, hyphens, apostrophes, spaces)
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			r == '-' || r == '\'' || r == ' ' || r == '.') {
			return false
		}
	}

	return true
}

// GetEmbeddedDataStats returns statistics about the embedded data
func GetEmbeddedDataStats() map[string]interface{} {
	return map[string]interface{}{
		"first_names_compressed_size": len(firstNamesDataGZ),
		"last_names_compressed_size":  len(lastNamesDataGZ),
		"total_compressed_size":       len(firstNamesDataGZ) + len(lastNamesDataGZ),
	}
}

// DecompressData is a utility function for testing decompression
func DecompressData(compressedData []byte) (string, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressedData))
	if err != nil {
		return "", fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return "", fmt.Errorf("failed to decompress data: %w", err)
	}

	return buf.String(), nil
}
