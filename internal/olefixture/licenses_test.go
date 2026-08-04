// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package olefixture

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Every module in go.mod must appear in THIRD-PARTY-LICENSES.
//
// This exists because adding a dependency and forgetting its license entry is
// invisible: nothing builds differently, no test fails, and the omission surfaces
// only in a compliance review. It happened with the two OLE libraries this package
// exists to support — both were added to go.mod, shipped in the binary, and absent
// from the license file.
//
// The check lives here rather than in a dedicated package because this is the
// package the OLE dependencies were added FOR, and a leaf package with no
// ferret-scan imports is a safe home for a repository-level assertion.
func TestEveryDependencyHasALicenseEntry(t *testing.T) {
	root := repoRoot(t)

	mods := modulesFromGoMod(t, filepath.Join(root, "go.mod"))
	if len(mods) == 0 {
		t.Fatal("no modules parsed from go.mod; this check would pass vacuously")
	}

	licenses, err := os.ReadFile(filepath.Join(root, "THIRD-PARTY-LICENSES"))
	if err != nil {
		t.Fatalf("reading THIRD-PARTY-LICENSES: %v", err)
	}
	text := string(licenses)

	var missing []string
	for _, m := range mods {
		if !strings.Contains(text, m) {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		t.Errorf("THIRD-PARTY-LICENSES has no entry for %d dependency/dependencies:\n  %s\n"+
			"A dependency shipped without its license recorded is a compliance gap, and "+
			"nothing else in the build will ever complain about it.",
			len(missing), strings.Join(missing, "\n  "))
	}
}

// The stated total must match the number of entries actually present, or the
// summary silently drifts from the body — which is how the previous count came to
// claim 24 dependencies whose license distribution summed to 27.
func TestLicenseSummaryMatchesEntries(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "THIRD-PARTY-LICENSES"))
	if err != nil {
		t.Fatalf("reading THIRD-PARTY-LICENSES: %v", err)
	}
	text := string(data)

	// Count "License: " lines, one per entry, rather than the numbered headings:
	// several license BODIES contain numbered clause lists, so a heading pattern
	// keyed on digits alone would miscount.
	entries := strings.Count(text, "\nLicense: ")

	m := regexp.MustCompile(`Total Dependencies: (\d+)`).FindStringSubmatch(text)
	if m == nil {
		t.Fatal("no \"Total Dependencies: N\" line found in the summary")
	}
	var stated int
	if _, err := fmtSscan(m[1], &stated); err != nil {
		t.Fatalf("parsing the stated total %q: %v", m[1], err)
	}
	if stated != entries {
		t.Errorf("the summary states %d dependencies but the file contains %d entries; "+
			"a stale total makes the whole summary untrustworthy", stated, entries)
	}

	// The per-license distribution must also add up to the total.
	sum := 0
	for _, line := range strings.Split(text, "\n") {
		lm := regexp.MustCompile(`^- .*: (\d+) packages?$`).FindStringSubmatch(strings.TrimSpace(line))
		if lm != nil {
			var n int
			if _, err := fmtSscan(lm[1], &n); err == nil {
				sum += n
			}
		}
	}
	if sum != stated {
		t.Errorf("the license distribution sums to %d but the stated total is %d", sum, stated)
	}
}

// repoRoot walks up from the package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the module root (no go.mod found walking up)")
	return ""
}

// modulesFromGoMod returns every required module path, direct and indirect. The
// version is deliberately NOT compared: a version bump should not fail this test,
// only a missing module should.
func modulesFromGoMod(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- a fixed path inside the repo
	if err != nil {
		t.Fatalf("opening go.mod: %v", err)
	}
	defer f.Close()

	var mods []string
	inBlock := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "require ("):
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		}
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if !inBlock {
			if !strings.HasPrefix(line, "require ") {
				continue
			}
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.Contains(fields[0], ".") {
			continue
		}
		mods = append(mods, fields[0])
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning go.mod: %v", err)
	}
	return mods
}

// fmtSscan wraps strconv so the callers above read cleanly.
func fmtSscan(s string, out *int) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errNotANumber
		}
		n = n*10 + int(c-'0')
	}
	*out = n
	return 1, nil
}

var errNotANumber = errStr("not a number")

type errStr string

func (e errStr) Error() string { return string(e) }
