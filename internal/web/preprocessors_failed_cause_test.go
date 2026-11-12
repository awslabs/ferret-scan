// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/coverage"
)

// TestAllPreprocessorsFailedCarriesCannotParse is #924's producer half. A file the router accepts and
// every preprocessor then fails on comes back from the router as "all preprocessors failed for file",
// and the worker pool stated no cause for it, so /scan disclosed it with cause "" (12 of the 639 public
// corpus files on main 3aa380e) while the CLI recovered "cannot parse" from the prose. The cause is now
// set where the failure happens, so both surfaces read it from the same field.
//
// The fixture is an OLE2 compound-file signature followed by zeros: a .doc by type and by magic, which
// no preprocessor can open.
func TestAllPreprocessorsFailedCarriesCannotParse(t *testing.T) {
	h := parityServer(t)
	doc := append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, make([]byte, 504)...)
	resp, _ := sessionScan(t, h, nil, "broken.doc", doc, nil)

	if len(resp.NotExamined) != 1 {
		t.Fatalf("want one not-examined record for broken.doc, got %+v", resp.NotExamined)
	}
	ne := resp.NotExamined[0]
	if !strings.Contains(ne.Detail, "preprocessors failed") {
		t.Fatalf("the fixture no longer reaches the router's all-preprocessors-failed exit (detail %q); pick another", ne.Detail)
	}
	if ne.Cause != coverage.CauseUnparseable.String() {
		t.Errorf("cause = %q, want %q: the UI cannot classify a record with no cause, and the CLI prints %q for the same file",
			ne.Cause, coverage.CauseUnparseable.String(), coverage.CauseUnparseable.String())
	}
}
