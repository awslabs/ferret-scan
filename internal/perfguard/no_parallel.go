// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import (
	"fmt"
	"os"
	"strings"
)

// AssertNoParallelTests reports every t.Parallel call in the Go test files under dir.
//
// This pins the assumption every measurement in this package depends on. ProcessCPUTime reports CPU
// for the WHOLE PROCESS, so a reading is only about the function under test while nothing else in the
// process is burning CPU concurrently. `go test` builds one binary per package, so competing packages
// are separate processes and cannot interfere — but a test inside the same package that runs
// concurrently with a measurement is charged to it.
//
// Measured, so this is not a theoretical worry: 28 busy GOROUTINES — as opposed to processes —
// inflated a base reading from 4.374ms to 39.559ms and turned a 4.07x single-pass scan into 11.62x,
// which is a false O(n^2) report on correct code. The same load generated as 28 separate PROCESSES
// moved the minimum base reading by 0.6%.
//
// Returns the offending "file:line" locations rather than failing, so the caller decides the message
// and this package does not import testing.
func AssertNoParallelTests(dir string) ([]string, int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, fmt.Errorf("perfguard: read %s: %w", dir, err)
	}

	// Assembled from fragments so this file does not contain the literal it searches for. The
	// equivalent guard in internal/goldencorpus matched its own search string and its own error
	// message before this was done, and "exempt the guard's own file" is the wrong fix — a file
	// that measures has to be policed like the rest.
	needle := "t.Paralle" + "l()"

	var offenders []string
	var scanned int
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		raw, readErr := os.ReadFile(dir + "/" + e.Name()) // #nosec G304 -- a test file in the caller's own package
		if readErr != nil {
			return nil, scanned, fmt.Errorf("perfguard: read %s: %w", e.Name(), readErr)
		}
		scanned++
		for i, line := range strings.Split(string(raw), "\n") {
			code := line
			if idx := strings.Index(code, "//"); idx >= 0 {
				code = code[:idx]
			}
			if strings.Contains(code, needle) {
				offenders = append(offenders, fmt.Sprintf("%s:%d", e.Name(), i+1))
			}
		}
	}
	return offenders, scanned, nil
}
