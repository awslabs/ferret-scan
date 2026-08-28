// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// The product-token rule was measured on real files before it was written, and these tests
// keep that grounding in the suite rather than leaving it in a PR description.
//
// It matters here specifically because a hand-written fixture already misled me twice on
// this change:
//
//   - A synthetic CSV header "sourceIPAddress" does not match the keyword search
//     (whole-word, and "ip" inside "sourceipaddress" is not a word), while the real
//     CloudTrail export writes "Source IP address" with spaces. The synthetic passed where
//     the real file would have failed.
//   - An assertion that a URL-authority address reports HIGH failed on a real CUPS help
//     page, because "in a URL" has never implied HIGH. See the second test.
//
// Both walks share one bounded pass over the filesystem: the roots below are large, and an
// unbounded walk per test took 160s.

// productTokenQuad finds "Name/N.N.N.N" — a product token whose version is four parts.
var productTokenQuad = regexp.MustCompile(`(?:^|[^\w.])([A-Za-z][A-Za-z0-9_.+-]*)/((?:\d{1,3}\.){3}\d{1,3})(?:[^\d.]|$)`)

// urlAuthorityQuad finds "scheme://N.N.N.N" — the shape a naive "preceded by a slash" rule
// would misclassify.
var urlAuthorityQuad = regexp.MustCompile(`[a-z][a-z0-9+.-]*://((?:\d{1,3}\.){3}\d{1,3})`)

// publicRoots are directories whose contents ship with the OS or with installed
// applications, so a file found under them can be named in a test.
var publicRoots = []string{
	"/usr/share",
	"/System/Library",
	"/Applications",
}

// realHit is one occurrence found in a real file.
type realHit struct {
	path, product, quad, line string
}

const (
	// wantPerShape is how many examples of each shape are enough. The rule is uniform, so
	// a handful of real files establishes it; the population statistics are in the PR.
	wantPerShape = 4
	// perRootBudget bounds the walk PER ROOT rather than overall. A single overall budget
	// was spent inside the first root, so the walk never reached the one holding the
	// product-token examples and the test skipped — which proves nothing. Without any
	// budget the walk took 160s.
	perRootBudget = 4000
)

// textishExt reports whether a file is worth reading as text. Numeric extensions are
// included because man pages (.1, .3, .5, .8) are a rich source of both shapes — the CUPS
// and Xcode SDK examples that shaped this rule are man pages and HTML help.
func textishExt(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	switch ext {
	case ".js", ".json", ".txt", ".log", ".plist", ".html", ".md", ".conf", ".xml", ".pem":
		return true
	}
	if len(ext) == 2 && ext[0] == '.' && ext[1] >= '0' && ext[1] <= '9' {
		return true // man page section
	}
	return false
}

var (
	realScanOnce sync.Once
	productHits  []realHit
	urlHits      []realHit
)

// scanRealFiles makes one bounded pass over publicRoots collecting both shapes.
func scanRealFiles() {
	for _, root := range publicRoots {
		if len(productHits) >= wantPerShape && len(urlHits) >= wantPerShape {
			return
		}
		examined := 0
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil //nolint:nilerr // an unreadable subtree is not this test's concern
			}
			if examined >= perRootBudget ||
				(len(productHits) >= wantPerShape && len(urlHits) >= wantPerShape) {
				return filepath.SkipAll
			}
			if d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			if !textishExt(p) {
				return nil
			}
			info, statErr := d.Info()
			if statErr != nil || info.Size() > 512*1024 {
				return nil
			}
			b, readErr := os.ReadFile(p) //nolint:gosec // walking public OS directories only
			if readErr != nil {
				return nil
			}
			examined++
			content := string(b)
			v := NewValidator()

			if len(productHits) < wantPerShape {
				for _, m := range productTokenQuad.FindAllStringSubmatch(content, -1) {
					// Only a value the validator would actually report is informative; a
					// private or reserved quad is dropped for an unrelated reason.
					if !allOctetsInRange(m[2]) || !v.isSensitiveIP(m[2]) {
						continue
					}
					productHits = append(productHits, realHit{
						path: p, product: m[1], quad: m[2], line: lineAround(content, m[2]),
					})
					break
				}
			}
			if len(urlHits) < wantPerShape {
				for _, m := range urlAuthorityQuad.FindAllStringSubmatch(content, -1) {
					if !allOctetsInRange(m[1]) || !v.isSensitiveIP(m[1]) {
						continue
					}
					urlHits = append(urlHits, realHit{
						path: p, quad: m[1], line: lineAround(content, m[1]),
					})
					break
				}
			}
			return nil
		})
	}
}

func realFileHits(t *testing.T) ([]realHit, []realHit) {
	t.Helper()
	if testing.Short() {
		t.Skip("-short: skipping the filesystem walk for real fixtures")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skipf("real-fixture roots are unix paths; GOOS=%s", runtime.GOOS)
	}
	realScanOnce.Do(scanRealFiles)
	return productHits, urlHits
}

// TestRealFilesCarryingAProductVersionReportItBelowHigh finds real files containing a
// four-part product version and asserts the value is reported below HIGH.
//
// Skipped rather than failed when nothing is found: the point is to exercise real bytes
// where they exist, not to require a particular host layout.
func TestRealFilesCarryingAProductVersionReportItBelowHigh(t *testing.T) {
	hits, _ := realFileHits(t)
	if len(hits) == 0 {
		t.Skip("no public file within the walk budget carries a reportable four-part product version")
	}

	for _, h := range hits {
		t.Run(h.product+"_"+h.quad, func(t *testing.T) {
			got := confidenceOf(t, h.line, h.quad)
			if got < 0 {
				t.Fatalf("%s in %s was not reported at all; this rule demotes rather than drops",
					h.quad, h.path)
			}
			if got >= 90 {
				t.Errorf("%s reported at %v (HIGH) from real file %s\n  line: %q\n"+
					"A four-part product version must not compete with a real address for "+
					"attention (#513).", h.quad, got, h.path, truncate(h.line, 120))
			}
		})
	}
	t.Logf("exercised %d real public files carrying a reportable product version", len(hits))
}

// TestRealFilesCarryingAUrlAuthorityAddressAreNotTreatedAsVersions is the recall half, on
// real bytes: a rule keyed on a preceding '/' alone would classify every address in a URL
// as a version.
//
// It asserts the RULE's answer rather than the reported confidence, and that distinction
// was learned from this exact case. An earlier version asserted HIGH and failed on
// /usr/share/doc/cups/help/admin.html, which documents "ipp://11.22.33.44/ipp/print" on a
// line carrying no IP keyword at all. The validator's own ambiguity cap holds that value
// at 75 and always has; the parent reported HIGH 95 only because the document-level
// adjustment lifted it, which is the very promotion this change removes. So "in a URL" has
// never implied HIGH, and asserting it would have been asserting the defect.
func TestRealFilesCarryingAUrlAuthorityAddressAreNotTreatedAsVersions(t *testing.T) {
	_, hits := realFileHits(t)
	if len(hits) == 0 {
		t.Skip("no public file within the walk budget carries a reportable URL-authority address")
	}

	for _, h := range hits {
		t.Run(h.quad, func(t *testing.T) {
			idx := strings.Index(h.line, h.quad)
			if idx < 0 {
				t.Fatalf("%s not found on the line extracted for it", h.quad)
			}
			// Non-vacuity: the character before really is a '/', so this is the case a
			// naive "preceded by a slash" rule would have caught.
			if idx == 0 || h.line[idx-1] != '/' {
				t.Skipf("%s is not preceded by '/' on this line, so it does not exercise the "+
					"discrimination", h.quad)
			}
			if isProductVersionAt(h.line, idx) {
				t.Errorf("%s from real file %s was classified as a product version\n  line: %q\n"+
					"It is a URL authority: the '//' before it is what distinguishes it from "+
					"\"Chrome/138.0.0.0\", and the rule requires a LETTER before the slash for "+
					"exactly this reason.", h.quad, h.path, truncate(h.line, 120))
			}
			// And it must still be reported: the rule contributes nothing here, so whatever
			// the pre-existing scoring decides, the finding exists.
			if got := confidenceOf(t, h.line, h.quad); got < 0 {
				t.Errorf("%s from %s was not reported at all", h.quad, h.path)
			}
		})
	}
	t.Logf("exercised %d real public files carrying a URL-authority address", len(hits))
}

func allOctetsInRange(quad string) bool {
	for _, part := range strings.Split(quad, ".") {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// lineAround returns the single line of content holding value, so the validator sees the
// same line the real file has rather than a whole minified bundle as one line.
func lineAround(content, value string) string {
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, value) {
			return line
		}
	}
	return value
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
