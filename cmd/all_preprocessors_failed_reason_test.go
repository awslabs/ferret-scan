// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// The router's typed "all preprocessors failed" error reads, once the path is stripped, as no
// reason at all (#1022). humanizeReason must still return "" for it, because collectUnscanned
// then asks describeUnparseable to look at the bytes; that is what keeps the report's per-file
// detail ("zip signature present but ...") byte-identical to the text-matching version.
func TestAllPreprocessorsFailedReasonStillStripsToBytesDescription(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.docx")
	if err := os.WriteFile(p, []byte("PK\x03\x04 garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	reason := fmt.Errorf("%w: %s", router.ErrAllPreprocessorsFailed, p).Error()
	if want := "all preprocessors failed for file: " + p; reason != want {
		t.Fatalf("reason text %q, want %q", reason, want)
	}
	if got := humanizeReason(p, reason); got != "" {
		t.Fatalf("humanizeReason = %q, want empty so the bytes are described", got)
	}
	if got, want := classifyReason(reason), causeUnparseable; got != want {
		t.Fatalf("classifyReason = %v, want %v", got, want)
	}
	if got, want := describeUnparseable(p), "zip signature present but the archive could not be opened (truncated or corrupt)"; got != want {
		t.Fatalf("describeUnparseable = %q, want %q", got, want)
	}
}
