// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package ipaddress

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
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
// unbounded walk per test took 160s. A pass bounded only by the number of files it READ then
// took 377-600s on the ubuntu-24.04 runner under -race and timed the package out (#810), so
// it is now bounded in entries visited and in wall-clock time as well; see the constants.

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
	// perRootEntries bounds the walk PER ROOT rather than overall. A single overall budget
	// was spent inside the first root, so the walk never reached the one holding the
	// product-token examples and the test skipped — which proves nothing. Without any
	// budget the walk took 160s.
	//
	// It counts EVERY entry visited: directories, other extensions and oversized files as
	// well as the files read. It used to count only files read (4,000), so how long a root
	// took depended on how much of it was text, and directories and skipped files were
	// walked without bound (#810). 50,000 entries is about what those 4,000 reads reached
	// on a Linux host: 47,915 of the 52,629 entries in its /usr/share.
	perRootEntries = 50000
	// maxFileBytes skips larger files unread; it was 512 KiB. Man pages and HTML help, the
	// sources this rule was built on, are small: the /usr/share/doc/git pages the walk
	// finds on the Linux host it was measured on are 51 KB and 75 KB.
	maxFileBytes = 128 << 10
	// walkTimeBudget bounds the whole pass in wall-clock time, so a slow disk or the race
	// detector costs coverage instead of the package's 10-minute timeout. When it runs out
	// the pass stops, and a test that found nothing skips saying how far the pass got.
	// Each root gets an equal share of the time left; see scanRealFiles. 60 s is half the
	// 120 s #810 gives the whole package, which leaves the rest for its other tests: 8 s
	// under -race on a Linux host, and 14.6-18.9 s on windows-latest, which skips the walk,
	// in the last three main runs.
	walkTimeBudget = 60 * time.Second
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

// rootWalk records how far the pass got in one root, so a skip or a pass can say so.
type rootWalk struct {
	root          string
	entries, read int
	bytes         int64
	elapsed       time.Duration
	stop          string
}

var (
	realScanOnce sync.Once
	productHits  []realHit
	urlHits      []realHit
	realWalk     []rootWalk
	realWalkTime time.Duration
)

func haveEnoughRealHits() bool {
	return len(productHits) >= wantPerShape && len(urlHits) >= wantPerShape
}

// scanRealFiles makes one bounded pass over publicRoots collecting both shapes.
func scanRealFiles() {
	start := time.Now()
	defer func() { realWalkTime = time.Since(start) }()
	deadline := start.Add(walkTimeBudget)
	// One validator for the whole pass: isSensitiveIP only reads it, and one per file
	// compiled its patterns again for every file read (93 µs each on a Linux host, 430 µs
	// under -race).
	v := NewValidator()

	var roots []string
	for _, r := range publicRoots {
		if info, err := os.Stat(r); err == nil && info.IsDir() {
			roots = append(roots, r)
		}
	}
	for i, root := range roots {
		if haveEnoughRealHits() {
			return
		}
		w := rootWalk{root: root, stop: "walked it all"}
		rootStart := time.Now()
		// An equal share of the time left, so one large root cannot spend all of it: the
		// reason the entry budget is per root, applied to time. A root that finishes early
		// leaves the rest of its share to the roots after it.
		rootDeadline := rootStart.Add(deadline.Sub(rootStart) / time.Duration(len(roots)-i))
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			switch {
			case haveEnoughRealHits():
				w.stop = "stopped with enough examples"
				return filepath.SkipAll
			case w.entries >= perRootEntries:
				w.stop = "stopped at the entry budget"
				return filepath.SkipAll
			case !time.Now().Before(rootDeadline):
				w.stop = "stopped at the time budget"
				return filepath.SkipAll
			}
			w.entries++
			if err != nil {
				return nil //nolint:nilerr // an unreadable subtree is not this test's concern
			}
			if d.IsDir() || !d.Type().IsRegular() || !textishExt(p) {
				return nil
			}
			info, statErr := d.Info()
			if statErr != nil || info.Size() > maxFileBytes {
				return nil
			}
			b, readErr := os.ReadFile(p) //nolint:gosec // walking public OS directories only
			if readErr != nil {
				return nil
			}
			w.read++
			w.bytes += int64(len(b))
			collectRealHits(v, p, string(b))
			return nil
		})
		w.elapsed = time.Since(rootStart)
		realWalk = append(realWalk, w)
	}
}

// collectRealHits records the first reportable occurrence of each shape still wanted.
//
// Each regex runs only on a file where quadAfter finds the literal it requires. The two
// whole-content FindAllStringSubmatch passes were the walk's main cost, 1.4 µs a byte under
// -race (47.5 s for 32.7 MiB of /usr/share on a Linux host), and almost no file holds
// either shape: in a census of 10,974 text files from six trees the gate let the product
// regex run on 22 and the URL regex on 10, and turned away no file either regex matches.
func collectRealHits(v *Validator, p, content string) {
	if len(productHits) < wantPerShape && quadAfter(content, "/") {
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
	if len(urlHits) < wantPerShape && quadAfter(content, "://") {
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
}

// quadAfter reports whether sep occurs in s immediately followed by N.N.N.N (one to three
// digits a part). Both shape regexes require exactly that — productTokenQuad a '/' before
// its quad, urlAuthorityQuad "://" — so a file it rejects cannot match, and skipping the
// regex there changes no hit. Digits and '.' are disjoint, so reading digits greedily is
// exact for (?:\d{1,3}\.){3}\d{1,3}.
func quadAfter(s, sep string) bool {
	for {
		i := strings.Index(s, sep)
		if i < 0 {
			return false
		}
		s = s[i+len(sep):]
		if quadPrefix(s) {
			return true
		}
	}
}

// quadPrefix reports whether s starts with N.N.N.N, one to three digits a part.
func quadPrefix(s string) bool {
	i := 0
	for part := 0; part < 4; part++ {
		start := i
		for i < len(s) && i-start < 3 && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == start {
			return false
		}
		if part < 3 {
			if i >= len(s) || s[i] != '.' {
				return false
			}
			i++
		}
	}
	return true
}

// realWalkSummary says how far the pass got, for a skip or a pass to log: when the walk's
// cost drifts again, the job log shows where (#810).
func realWalkSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "walk took %v", realWalkTime.Round(time.Millisecond))
	for _, w := range realWalk {
		fmt.Fprintf(&b, "; %s: %d entries, %d files read (%.1f MiB) in %v, %s",
			w.root, w.entries, w.read, float64(w.bytes)/(1<<20),
			w.elapsed.Round(time.Millisecond), w.stop)
	}
	return b.String()
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
		t.Skipf("no public file within the walk budget carries a reportable four-part product "+
			"version; %s", realWalkSummary())
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
	t.Logf("exercised %d real public files carrying a reportable product version; %s",
		len(hits), realWalkSummary())
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
		t.Skipf("no public file within the walk budget carries a reportable URL-authority "+
			"address; %s", realWalkSummary())
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
	t.Logf("exercised %d real public files carrying a URL-authority address; %s",
		len(hits), realWalkSummary())
}

// TestTheWalkPrefilterNeverSkipsAFileEitherShapeMatches holds quadAfter to its contract: a
// file the gate turns away is one neither regex could match. A gate that rejected a real
// match would not fail anything; the walk would find nothing and the tests above would
// skip, which proves nothing. The mustGate rows show it filters at all.
func TestTheWalkPrefilterNeverSkipsAFileEitherShapeMatches(t *testing.T) {
	mustPass := []string{
		"agent=git/1.8.3.1", // the /usr/share/doc/git pages
		"Mozilla/5.0 (X11) Chrome/138.0.0.0 Safari/537.36", // a User-Agent
		"Framework.framework/Versions/153.1.100.18",
		"ipp://11.22.33.44/ipp/print", // the CUPS help page
		"http://11.22.33.44:8080/status",
		"x/1.2.3.4", // the quad ends the input
	}
	for _, s := range mustPass {
		p, u := productTokenQuad.MatchString(s), urlAuthorityQuad.MatchString(s)
		if !p && !u {
			t.Fatalf("%q matches neither shape, so it tests nothing here", s)
		}
		if p && !quadAfter(s, "/") {
			t.Errorf("quadAfter(%q, \"/\") is false, but productTokenQuad matches it", s)
		}
		if u && !quadAfter(s, "://") {
			t.Errorf("quadAfter(%q, \"://\") is false, but urlAuthorityQuad matches it", s)
		}
	}
	mustGate := []string{
		`<html xmlns="http://www.w3.org/1999/xhtml">`,
		"released 10/12/2025",
		"route 192.168.1.0/24 via 10.0.0.1",
		"see https://example.com/v1/1.2.3/notes",
		"a/1234.5.6.7",
	}
	for _, s := range mustGate {
		if productTokenQuad.MatchString(s) || urlAuthorityQuad.MatchString(s) {
			t.Fatalf("%q matches a shape, so it cannot show the gate filtering", s)
		}
		if quadAfter(s, "/") || quadAfter(s, "://") {
			t.Errorf("quadAfter accepts %q, which holds no separator followed by N.N.N.N", s)
		}
	}
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
