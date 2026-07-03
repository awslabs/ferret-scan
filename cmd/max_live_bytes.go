// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"strconv"
	"strings"
)

// parseByteSize converts a human byte-size string into a byte count for the
// --max-live-bytes flag. It accepts a bare integer (bytes) or an integer with a
// unit suffix B, KB, MB, or GB (case-insensitive, binary multiples: 1KB = 1024).
// An empty string returns 0 (the disabled sentinel — no live-bytes cap). A
// malformed or non-positive value is an error so the flag fails fast rather than
// silently disabling the cap the operator asked for.
func parseByteSize(spec string) (int64, error) {
	s := strings.TrimSpace(spec)
	if s == "" {
		return 0, nil
	}

	upper := strings.ToUpper(s)
	var mult int64 = 1
	// Order matters: check the two-letter units before the bare "B".
	switch {
	case strings.HasSuffix(upper, "GB"):
		mult, upper = 1024*1024*1024, strings.TrimSuffix(upper, "GB")
	case strings.HasSuffix(upper, "MB"):
		mult, upper = 1024*1024, strings.TrimSuffix(upper, "MB")
	case strings.HasSuffix(upper, "KB"):
		mult, upper = 1024, strings.TrimSuffix(upper, "KB")
	case strings.HasSuffix(upper, "B"):
		mult, upper = 1, strings.TrimSuffix(upper, "B")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(upper), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid --max-live-bytes value %q: expected a number optionally suffixed with B, KB, MB, or GB", spec)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid --max-live-bytes value %q: must be positive", spec)
	}
	// Guard against overflow when applying the multiplier.
	if n > (1<<62)/mult {
		return 0, fmt.Errorf("invalid --max-live-bytes value %q: too large", spec)
	}
	return n * mult, nil
}
