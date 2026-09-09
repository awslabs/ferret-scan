// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package sarif

import (
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// #633: artifactLocation.uri was built as `"file://" + cleanPath`, which is correct on POSIX only by
// accident — the path's own leading slash supplies the third one — and wrong three ways otherwise.
//
// Both specs are explicit. SARIF 2.1.0 §3.10.2: for a path that is not network-accessible the
// producer "SHOULD NOT include the host name", and on omitting the authority the URI "SHOULD start
// with 'file:///'"; its own example is `file:///C:/src`. RFC 8089 §2 states `file:///c:/path/to/file`
// is "already supported by the path-absolute rule" and Appendix D.2 that "the drive letter (e.g.,
// "c:") is typically mapped into the first path segment". SARIF §3.10.1 requires the value to be "a
// string in the format specified by the standard [RFC3986]".

// oldURI is the expression this replaced, kept so the tests can show what changed and — more
// importantly — assert that the ordinary case did NOT change.
func oldURI(p string) string { return "file://" + filepath.ToSlash(filepath.Clean(p)) }

func TestAbsoluteFileURIRoundTripsThePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"ordinary posix path", "/tmp/report.txt", "file:///tmp/report.txt"},
		// The Windows case, which is why this exists: the drive letter must be the first PATH segment,
		// not the authority. Written with forward slashes because buildArtifactLocation applies
		// filepath.ToSlash before calling this, so that is the shape it receives.
		{"windows drive letter", "C:/Users/alice/report.txt", "file:///C:/Users/alice/report.txt"},
		{"space in the filename", "/tmp/my report.txt", "file:///tmp/my%20report.txt"},
		// A '#' is legal in a POSIX filename and starts a FRAGMENT in a URI, so unencoded it silently
		// truncates the path a consumer resolves.
		{"hash in the filename", "/tmp/a#b.txt", "file:///tmp/a%23b.txt"},
		{"percent and space", "/tmp/100% done.txt", "file:///tmp/100%25%20done.txt"},
		{"non-ascii", "/tmp/café.txt", "file:///tmp/caf%C3%A9.txt"},
		{"windows path with a space", "C:/Users/alice/my report.txt", "file:///C:/Users/alice/my%20report.txt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := absoluteFileURI(filepath.ToSlash(filepath.Clean(tc.path)))
			if got != tc.want {
				t.Errorf("absoluteFileURI(%q) = %q, want %q", tc.path, got, tc.want)
			}

			// The property that actually matters to a consumer: parse it back and recover the path
			// EXACTLY. A URI that parses but yields a different path is the worst outcome, because it
			// resolves silently to another file.
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("the URI this produced does not parse: %v", err)
			}
			if u.Host != "" {
				t.Errorf("host = %q, want empty. SARIF §3.10.2 says a producer SHOULD NOT include the "+
					"host name for a path that is not network-accessible, and a drive letter in the "+
					"authority is how the path loses it", u.Host)
			}
			wantPath := filepath.ToSlash(filepath.Clean(tc.path))
			if !strings.HasPrefix(wantPath, "/") {
				wantPath = "/" + wantPath
			}
			if u.Path != wantPath {
				t.Errorf("parsed path = %q, want %q — a consumer would resolve a different file",
					u.Path, wantPath)
			}
			if !strings.HasPrefix(got, "file:///") {
				t.Errorf("%q does not start with file:/// — SARIF §3.10.2 SHOULD, and RFC 8089 "+
					"Appendix B calls it \"the most common format in use today\"", got)
			}
		})
	}
}

// TestTheOrdinaryPosixCaseIsUnchanged is the must-NOT-change half.
//
// This alters SARIF output, so the claim "only malformed output changes" has to be asserted rather
// than asserted-in-a-comment. If an ordinary path's URI moved, every consumer's stored baseline moves
// with it and the golden corpus would have shifted — it did not, 0 files changed.
func TestTheOrdinaryPosixCaseIsUnchanged(t *testing.T) {
	for _, p := range []string{
		"/tmp/report.txt",
		"/var/folders/x/y/scan.docx",
		"/Users/someone/Documents/notes.txt",
		"/a/b/c/d/e/f.json",
	} {
		clean := filepath.ToSlash(filepath.Clean(p))
		if got, before := absoluteFileURI(clean), oldURI(p); got != before {
			t.Errorf("absoluteFileURI(%q) = %q but the previous expression gave %q — an ordinary path's "+
				"URI must not move, or every consumer's baseline moves with it", p, got, before)
		}
	}
}

// TestTheOldExpressionReallyWasBroken pins the defect itself, so the fix cannot be reverted as
// unnecessary and so the failure modes are recorded in runnable form rather than only in prose.
func TestTheOldExpressionReallyWasBroken(t *testing.T) {
	t.Run("windows drive letter became the authority", func(t *testing.T) {
		u, err := url.Parse(oldURI("C:/Users/alice/report.txt"))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if u.Host != "C:" {
			t.Skipf("the old expression no longer yields host=C: (host=%q); the defect this test "+
				"documents may have changed shape", u.Host)
		}
		if strings.Contains(u.Path, "C:") {
			t.Errorf("path %q still contains the drive letter, so the premise of the fix is wrong", u.Path)
		}
	})

	t.Run("hash truncated the path", func(t *testing.T) {
		u, err := url.Parse(oldURI("/tmp/a#b.txt"))
		if err != nil {
			t.Fatalf("unexpected parse error: %v", err)
		}
		if u.Path != "/tmp/a" {
			t.Skipf("the old expression no longer truncates at '#' (path=%q)", u.Path)
		}
		// And the fix must not truncate.
		fixed, err := url.Parse(absoluteFileURI("/tmp/a#b.txt"))
		if err != nil {
			t.Fatalf("the fixed URI does not parse: %v", err)
		}
		if fixed.Path != "/tmp/a#b.txt" {
			t.Errorf("the fixed URI parses to %q, want the whole filename", fixed.Path)
		}
	})

	t.Run("percent made the URI unparseable", func(t *testing.T) {
		if _, err := url.Parse(oldURI("/tmp/100% done.txt")); err == nil {
			t.Skip("the old expression no longer produces an unparseable URI")
		}
		if _, err := url.Parse(absoluteFileURI("/tmp/100% done.txt")); err != nil {
			t.Errorf("the fixed URI still does not parse: %v", err)
		}
	})
}
