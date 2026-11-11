// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
)

// writeConfigValueWarnings prints one "Warning: config value <path>: <problem> — <effect>" line per
// configured value the run's validators could not use (#903), or nothing when there is none. lines are
// core.ConfigWarnings' (or core.ScanResult.ConfigWarnings'), which carry no prefix.
//
// One function for both input paths, so --file and --stdin print the same bytes for the same config. It
// is a disclosure, not progress output: the callers gate it only where stderr is the findings document.
func writeConfigValueWarnings(w io.Writer, lines []string) {
	for _, line := range lines {
		fmt.Fprintf(w, "Warning: %s\n", line)
	}
}
