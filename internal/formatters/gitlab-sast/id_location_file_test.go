// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// #1017: the vulnerability id hashed match.Filename, which the CLI sets to the ABSOLUTE scanned
// path, so one file checked out in two directories got two ids, and the web (whose Filename is
// the upload name) got a third. The id is now a hash of what the report prints in location.file.

func vulnIDs(t *testing.T, matches []detector.Match, root string) []string {
	t.Helper()
	out, err := NewFormatter().Format(matches, nil, formatters.FormatterOptions{ConfidenceLevel: allLevels(), SourceRoot: root})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var report GitLabSecurityReport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	ids := make([]string, 0, len(report.Vulnerabilities))
	for _, v := range report.Vulnerabilities {
		ids = append(ids, v.ID)
	}
	return ids
}

func TestIDIsStableAcrossCheckoutDirectories(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	idA := vulnIDs(t, []detector.Match{pathMatch(filepath.Join(a, "src", "config.py"), 3)}, a)
	idB := vulnIDs(t, []detector.Match{pathMatch(filepath.Join(b, "src", "config.py"), 3)}, b)
	if len(idA) != 1 || len(idB) != 1 {
		t.Fatalf("control: got %d and %d vulnerabilities, want 1 each", len(idA), len(idB))
	}
	if idA[0] != idB[0] {
		t.Errorf("same relative file, line and type in two checkouts: ids %s and %s", idA[0], idB[0])
	}
}

// The web formats with no SourceRoot and a Filename that is already the upload name; the CLI
// formats an absolute path against its root. Same printed path, same id.
func TestIDEqualsTheWebIDForTheSameName(t *testing.T) {
	root := t.TempDir()
	cli := vulnIDs(t, []detector.Match{pathMatch(filepath.Join(root, "payroll.txt"), 2)}, root)
	web := vulnIDs(t, []detector.Match{pathMatch("payroll.txt", 2)}, "")
	if len(cli) != 1 || len(web) != 1 || cli[0] != web[0] {
		t.Errorf("cli ids %v, web ids %v, want one equal id", cli, web)
	}
}

// The id follows location.file, so it still separates what location.file separates.
func TestIDStillSeparatesPathLineAndType(t *testing.T) {
	root := t.TempDir()
	base := pathMatch(filepath.Join(root, "a", "x.py"), 1)
	otherFile := pathMatch(filepath.Join(root, "b", "x.py"), 1)
	otherLine := pathMatch(filepath.Join(root, "a", "x.py"), 2)
	otherType := base
	otherType.Type = "SSN"
	ids := vulnIDs(t, []detector.Match{base, otherFile, otherLine, otherType}, root)
	seen := map[string]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if len(ids) != 4 || len(seen) != 4 {
		t.Errorf("ids %v, want four distinct", ids)
	}
}

// A path the root does not contain degrades to its basename in location.file, so two such files
// of one name share an id exactly as they share a location (the #328 guard separates them).
func TestIDFollowsTheDegradedBasename(t *testing.T) {
	root := t.TempDir()
	m := NewVulnerabilityMapper()
	outside := pathMatch(filepath.Join(t.TempDir(), "deep", "n.txt"), 1)
	if got, want := m.GenerateVulnerabilityID(outside, root), m.GenerateVulnerabilityID(pathMatch("n.txt", 1), ""); got != want {
		t.Errorf("id %s, want the id of the printed path n.txt (%s)", got, want)
	}
}
