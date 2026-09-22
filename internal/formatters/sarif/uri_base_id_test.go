// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
)

// sarifRun formats one match and returns the decoded runs[0].
func sarifRun(t *testing.T, match detector.Match, options formatters.FormatterOptions) map[string]any {
	t.Helper()

	out, err := NewFormatter().Format([]detector.Match{match}, nil, options)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	var doc struct {
		Runs []map[string]any `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF output is not JSON (%v): %s", err, out)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(doc.Runs))
	}
	return doc.Runs[0]
}

// artifactLocationOf digs out runs[0].results[0].locations[0].physicalLocation.artifactLocation.
func artifactLocationOf(t *testing.T, run map[string]any) map[string]any {
	t.Helper()

	results, ok := run["results"].([]any)
	if !ok || len(results) == 0 {
		t.Fatalf("no results in run: %v", run)
	}
	locations, ok := results[0].(map[string]any)["locations"].([]any)
	if !ok || len(locations) == 0 {
		t.Fatalf("no locations in result: %v", results[0])
	}
	physical, ok := locations[0].(map[string]any)["physicalLocation"].(map[string]any)
	if !ok {
		t.Fatalf("no physicalLocation: %v", locations[0])
	}
	artifact, ok := physical["artifactLocation"].(map[string]any)
	if !ok {
		t.Fatalf("no artifactLocation: %v", physical)
	}
	return artifact
}

// absPath makes a path absolute on EVERY platform. A leading separator alone is not absolute
// on Windows (filepath.IsAbs needs a volume), and the containment test these cases exercise
// runs only for absolute paths.
func absPath(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil {
		t.Fatalf("Abs(%q): %v", path, err)
	}
	return abs
}

func matchAt(filename string) detector.Match {
	return detector.Match{
		Text:       "452-11-9384",
		Type:       "SSN",
		Confidence: 100,
		LineNumber: 2,
		Filename:   filename,
		Validator:  "ssn",
	}
}

// A result inside the scan root is reported through SARIF's two-field mechanism, with the base
// it names actually defined. Before this, the %SRCROOT% branch was conditioned on the path
// being RELATIVE while the CLI resolves every input with filepath.Abs, so the branch was
// unreachable and the absolute path landed in uri with no base at all (#711).
func TestArtifactLocationInsideRootIsRelativeWithABaseThatResolves(t *testing.T) {
	root := absPath(t, "/repo")
	run := sarifRun(t, matchAt(filepath.Join(root, "src", "nested", "config.py")),
		formatters.FormatterOptions{
			ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
			SourceRoot:      root,
		})

	artifact := artifactLocationOf(t, run)
	if got := artifact["uri"]; got != "src/nested/config.py" {
		t.Errorf("uri = %v, want src/nested/config.py", got)
	}
	if got := artifact["uriBaseId"]; got != srcRootBaseID {
		t.Errorf("uriBaseId = %v, want %s", got, srcRootBaseID)
	}

	bases, ok := run["originalUriBaseIds"].(map[string]any)
	if !ok {
		t.Fatalf("run has no originalUriBaseIds, so %s is a dangling reference: %v",
			srcRootBaseID, run)
	}
	base, ok := bases[srcRootBaseID].(map[string]any)
	if !ok {
		t.Fatalf("originalUriBaseIds does not define %s: %v", srcRootBaseID, bases)
	}
	uri, _ := base["uri"].(string)
	if !strings.HasPrefix(uri, "file:///") {
		t.Errorf("base uri = %q, want an absolute file: URI (SARIF 2.1.0 §3.10.2)", uri)
	}
	if !strings.HasSuffix(uri, "/") {
		t.Errorf("base uri = %q; a directory's uri should end with a slash (§3.14.14)", uri)
	}
}

// Outside the root, the absolute file: URI stays. It is the #633 fix, and it is the only
// fallback a consumer can resolve: a basename is neither root-relative with a base nor absolute.
func TestArtifactLocationOutsideRootKeepsTheAbsoluteFileURI(t *testing.T) {
	run := sarifRun(t, matchAt(absPath(t, "/elsewhere/config.py")),
		formatters.FormatterOptions{
			ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
			SourceRoot:      absPath(t, "/repo"),
		})

	artifact := artifactLocationOf(t, run)
	uri, _ := artifact["uri"].(string)
	if !strings.HasPrefix(uri, "file:///") {
		t.Errorf("uri = %q, want an absolute file: URI for a path outside the root", uri)
	}
	if _, present := artifact["uriBaseId"]; present {
		t.Error("an absolute uri must not also claim a base; the two would contradict")
	}
}

// A virtual source has no filesystem location at all: the synthetic label passes through with
// no scheme and no base. Pinned because tests/integration's stdin contract depends on it.
func TestArtifactLocationForVirtualSourceIsUntouched(t *testing.T) {
	match := matchAt("<stdin>")
	match.SourceKind = detector.SourceKindVirtual
	run := sarifRun(t, match, formatters.FormatterOptions{
		ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		SourceRoot:      absPath(t, "/repo"),
	})

	artifact := artifactLocationOf(t, run)
	if got := artifact["uri"]; got != "<stdin>" {
		t.Errorf("uri = %v, want the verbatim virtual label", got)
	}
	if _, present := artifact["uriBaseId"]; present {
		t.Error("a virtual source was given a uriBaseId; there is no root to resolve it against")
	}
}

// With no root known, no base is declared — a %SRCROOT% nothing defines is exactly the dangling
// reference #711 named.
func TestNoRootDeclaresNoBase(t *testing.T) {
	run := sarifRun(t, matchAt(absPath(t, "/repo/src/config.py")),
		formatters.FormatterOptions{
			ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
		})

	if _, present := run["originalUriBaseIds"]; present {
		t.Errorf("a run with no SourceRoot declared a base: %v", run["originalUriBaseIds"])
	}
	artifact := artifactLocationOf(t, run)
	if _, present := artifact["uriBaseId"]; present {
		t.Error("a result cited a base that the run does not define")
	}
}

// The wrong-repository block is gone (#713), and nothing replaced it with the same claim.
func TestVersionControlProvenanceIsNotEmitted(t *testing.T) {
	root := absPath(t, "/repo")
	out, err := NewFormatter().Format([]detector.Match{matchAt(filepath.Join(root, "x.py"))}, nil,
		formatters.FormatterOptions{
			ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
			SourceRoot:      root,
		})
	if err != nil {
		t.Fatalf("Format: %v", err)
	}

	if strings.Contains(out, "versionControlProvenance") {
		t.Error("versionControlProvenance is emitted again; it described ferret-scan's own " +
			"repository as the ANALYZED source, and its revisionId was the TOOL version")
	}
	// Non-vacuity: the analyzer's own URL is still allowed — and expected — under tool.driver.
	if !strings.Contains(out, `"informationUri"`) {
		t.Error("tool.driver.informationUri is missing, so the assertion above proves nothing " +
			"about WHERE the repository URL may appear")
	}
	if !strings.Contains(out, "originalUriBaseIds") {
		t.Error("nothing declares the base that replaced the provenance block")
	}
}

// #712's SARIF half: message.text must not name a different path than the result's own location.
func TestMessageNamesTheSamePathAsTheLocation(t *testing.T) {
	root := absPath(t, "/repo")
	run := sarifRun(t, matchAt(filepath.Join(root, "src", "nested", "config.py")),
		formatters.FormatterOptions{
			ConfidenceLevel: map[string]bool{"high": true, "medium": true, "low": true},
			SourceRoot:      root,
		})

	results := run["results"].([]any)
	message, ok := results[0].(map[string]any)["message"].(map[string]any)
	if !ok {
		t.Fatalf("no message on the result: %v", results[0])
	}
	text, _ := message["text"].(string)

	uri, _ := artifactLocationOf(t, run)["uri"].(string)
	if !strings.Contains(text, " in "+uri+" at line ") {
		t.Errorf("message.text does not name %q, the path its own artifactLocation carries:\n%s",
			uri, text)
	}
}
