// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/pkg/scan"
)

// MaxLiveBytes caps the extracted content held in memory at once. core.ScanConfig
// has carried the field since the limiter was added and the CLI has exposed
// --max-live-bytes just as long, but pkg/scan never forwarded it — so the one
// consumer that most needs a memory envelope, an external caller on a
// memory-constrained host, was the only one unable to set it.
//
// What these tests can and cannot prove, stated plainly: the limiter THROTTLES
// concurrent extraction rather than rejecting oversized input, and a single-file
// scan has nothing to contend with. So a budget cannot be observed through
// findings, and asserting on timing would be a flake. What is worth locking is that
// the option is honoured rather than silently dropped: a scan under a tiny budget
// must still return the same findings as an unlimited one, because a memory cap is
// a scheduling constraint and must never change what is detected. A dropped cap
// and a working cap look identical on findings — that is exactly why the field went
// unforwarded unnoticed — so the wiring is additionally proven by the compile-time
// reference below.

func writeFixture(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return p
}

const fixtureBody = "Employee SSN 449-87-4100 on file.\n" +
	"Card 4532-0151-1283-0366 expires soon.\n" +
	"Contact ops@example.com for details.\n"

// A memory budget must not change WHICH findings are produced. If a tiny cap
// silently dropped content, the same file would report fewer findings — a cap that
// costs detection is a cleartext leak dressed as resource management.
func TestMaxLiveBytesDoesNotChangeFindings(t *testing.T) {
	path := writeFixture(t, "notes.txt", fixtureBody)
	checks := []string{"SSN", "CREDIT_CARD", "EMAIL"}

	unlimited, err := scan.ScanFile(context.Background(), path, scan.FileOptions{Checks: checks})
	if err != nil {
		t.Fatalf("unlimited scan: %v", err)
	}
	if len(unlimited.Findings) == 0 {
		t.Fatal("the unlimited baseline found nothing, so every comparison below would " +
			"be vacuous")
	}

	for _, budget := range []int64{1, 64, 1024, 1 << 20} {
		capped, err := scan.ScanFile(context.Background(), path, scan.FileOptions{
			Checks:       checks,
			MaxLiveBytes: budget,
		})
		if err != nil {
			t.Fatalf("MaxLiveBytes=%d: %v", budget, err)
		}
		if len(capped.Findings) != len(unlimited.Findings) {
			t.Errorf("MaxLiveBytes=%d produced %d findings, unlimited produced %d — a "+
				"memory cap is a scheduling constraint and must never change what is "+
				"detected", budget, len(capped.Findings), len(unlimited.Findings))
		}
	}
}

// A budget smaller than the file must still admit it. The limiter's documented rule
// is that an oversized single item runs alone once the pool is otherwise empty, so
// it can never deadlock — without that, a 1-byte budget would hang forever rather
// than scan.
func TestMaxLiveBytesSmallerThanFileStillCompletes(t *testing.T) {
	big := strings.Repeat("filler line with no sensitive content at all\n", 2000) +
		"Employee SSN 449-87-4100 on file.\n"
	path := writeFixture(t, "big.txt", big)

	res, err := scan.ScanFile(context.Background(), path, scan.FileOptions{
		Checks:       []string{"SSN"},
		MaxLiveBytes: 1, // far below the file size
	})
	if err != nil {
		t.Fatalf("a budget below the file size must not fail the scan: %v", err)
	}
	found := false
	for _, f := range res.Findings {
		if strings.Contains(f.Text, "449-87-4100") {
			found = true
		}
	}
	if !found {
		t.Error("the SSN was not found under a 1-byte budget — an oversized item must be " +
			"admitted alone rather than dropped, or the cap silently costs detection")
	}
}

// Zero and negative budgets mean unlimited, matching the CLI without the flag. A
// caller that leaves the field at its zero value must get the default behaviour.
func TestMaxLiveBytesZeroMeansUnlimited(t *testing.T) {
	path := writeFixture(t, "notes.txt", fixtureBody)
	checks := []string{"SSN", "CREDIT_CARD", "EMAIL"}

	base, err := scan.ScanFile(context.Background(), path, scan.FileOptions{Checks: checks})
	if err != nil {
		t.Fatal(err)
	}
	for _, budget := range []int64{0, -1} {
		got, err := scan.ScanFile(context.Background(), path, scan.FileOptions{
			Checks:       checks,
			MaxLiveBytes: budget,
		})
		if err != nil {
			t.Fatalf("MaxLiveBytes=%d: %v", budget, err)
		}
		if len(got.Findings) != len(base.Findings) {
			t.Errorf("MaxLiveBytes=%d gave %d findings, the unset default gave %d — "+
				"zero and negative must both mean unlimited", budget, len(got.Findings), len(base.Findings))
		}
	}
}

// The field must exist on the public options struct with the documented type. This
// is the assertion that would have failed before the change: a caller could not
// express a memory budget at all, and no findings-based test can show that.
func TestMaxLiveBytesIsPubliclySettable(t *testing.T) {
	var opts scan.FileOptions
	opts.MaxLiveBytes = 8 << 20
	if opts.MaxLiveBytes != 8<<20 {
		t.Fatalf("FileOptions.MaxLiveBytes did not round-trip: got %d", opts.MaxLiveBytes)
	}
}

// The option must be FORWARDED to the engine, and this is the only test here that
// can tell.
//
// Verified by deleting the forwarding line: every findings-based test above still
// passed. That is not a weakness in those tests, it is the shape of the defect —
// the limiter throttles concurrent extraction rather than rejecting input, so a
// dropped budget and an honoured budget produce identical findings on any single
// file. A silently ignored option is precisely how this field came to sit unused on
// core.ScanConfig while the CLI exposed it.
//
// With no exported counter on the limiter there is nothing observable to assert, so
// this reads the source. A structural check is a poor substitute for a behavioural
// one and is written as narrowly as possible: it asserts only that the field is
// passed through in the same construction the other options use. If the engine ever
// exposes an accept/wait counter, replace this with a real observation.
func TestMaxLiveBytesIsForwardedToTheEngine(t *testing.T) {
	src, err := os.ReadFile("scan.go")
	if err != nil {
		t.Fatalf("reading scan.go: %v", err)
	}
	text := string(src)

	// Locate the ScanFile body so a match elsewhere in the file cannot satisfy this.
	start := strings.Index(text, "func ScanFile(")
	if start < 0 {
		t.Fatal("could not find func ScanFile in scan.go; this guard needs updating")
	}
	body := text[start:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}

	if !strings.Contains(body, "MaxLiveBytes:") {
		t.Error("ScanFile does not pass MaxLiveBytes into core.ScanConfig, so a caller " +
			"that sets it gets an unlimited scan and no error. Every findings-based test " +
			"in this file passes in that state — that is why this check reads the source.")
	}
	if !strings.Contains(body, "opts.MaxLiveBytes") {
		t.Error("ScanFile references MaxLiveBytes but not opts.MaxLiveBytes: the caller's " +
			"value is not what reaches the engine")
	}
}
