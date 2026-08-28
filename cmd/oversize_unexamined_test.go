// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// A file refused for being over the size limit must be COUNTED, and its treatment
// must follow from whether the tool could have processed its type.
//
// Before this, a size refusal reached no counter anywhere. Measured on a directory
// holding one 105MB file plus a small file with an SSN:
//
//	Files: 1 scanned | Findings: 1
//	total_files 1, files_skipped 0, files_not_examined absent
//	--fail-on-incomplete -> exit 0
//
// So the artifact described a complete, clean scan of a directory containing a file
// that was never opened. The only trace was a stderr line, which is exactly what CI
// discards when it redirects stdout to a report. See #324.
//
// The warning decision was also a hardcoded 11-extension list, duplicated at three
// call sites, so the tool was quiet about a few known-big binary types and noisy about
// everything else — including files it could never have scanned at any size, and
// including browser partial downloads whose random suffixes no list can cover.

// bigTextFile writes a sparse file over the limit whose FIRST 512 bytes are real text.
//
// The leading text has to fill more than the sniff window: Truncate extends with NULs,
// so a file with only a line or two of text sniffs as binary and the fixture silently
// tests the wrong branch.
func bigTextFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if _, err := f.WriteString("Quarterly report text content.\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return path
}

// bigOpaqueFile writes a sparse over-limit file of binary bytes with a random-suffix
// name, the browser-partial-download shape no extension list can match.
func bigOpaqueFile(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(make([]byte, 600)); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return path
}

// audioFile writes a .wav whose RIFF LIST/INFO chunk carries an SSN in its IART field,
// sparse-extended to the requested size.
//
// Real header bytes rather than a stub, because the point of the over-limit case is that
// this file WOULD have yielded a finding: the same header under the limit reports SSN at
// HIGH 100. A fixture that could not produce a finding either way would pass whether or
// not the coverage loss is disclosed.
func audioFile(t *testing.T, path string, size int64) string {
	t.Helper()
	var buf bytes.Buffer
	fmtChunk := []byte{
		1, 0, 1, 0, 0x40, 0x1f, 0, 0, 0x80, 0x3e, 0, 0, 2, 0, 0x10, 0,
	}
	value := append([]byte("SSN: 452-11-9384"), 0)
	var info bytes.Buffer
	info.WriteString("INFO")
	info.WriteString("IART")
	_ = binary.Write(&info, binary.LittleEndian, uint32(len(value)))
	info.Write(value)

	var body bytes.Buffer
	body.WriteString("fmt ")
	_ = binary.Write(&body, binary.LittleEndian, uint32(len(fmtChunk)))
	body.Write(fmtChunk)
	body.WriteString("LIST")
	_ = binary.Write(&body, binary.LittleEndian, uint32(info.Len()))
	body.Write(info.Bytes())

	buf.WriteString("RIFF")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(4+body.Len()))
	buf.WriteString("WAVE")
	buf.Write(body.Bytes())

	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if size > int64(buf.Len()) {
		if err := f.Truncate(size); err != nil {
			t.Fatal(err)
		}
	}
	_ = f.Close()
	return path
}

func pathsOf(entries []SkippedFile) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, filepath.Base(e.Path))
	}
	return out
}

// The glob and recursive-walk discovery routes must agree.
//
// The third route — a file named directly on the command line — is covered by
// TestOversizeAudioNamedDirectlyIsUnexamined below, and it is worth its own test because
// it was the one route with a size limit of its own. This table claimed to cover all
// three and never did, which is where #355 hid.
func TestOversizeProcessableFileIsUnexamined(t *testing.T) {
	routes := []struct {
		name  string
		input func(dir string) string
		rec   bool
	}{
		{"directory walk", func(dir string) string { return dir }, true},
		{"glob", func(dir string) string { return filepath.Join(dir, "*") }, false},
	}

	for _, route := range routes {
		t.Run(route.name, func(t *testing.T) {
			dir := t.TempDir()
			bigTextFile(t, filepath.Join(dir, "big_report.txt"))
			bigOpaqueFile(t, filepath.Join(dir, ".com.brave.Browser.ABCdef"))
			small := filepath.Join(dir, "normal.txt")
			if err := os.WriteFile(small, []byte("SSN: 452-11-9384\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			res, err := getFilesToProcess(route.input(dir), route.rec, nil, nil, true)
			if err != nil {
				t.Fatalf("getFilesToProcess: %v", err)
			}

			// The small file is scanned.
			if len(res.FilesToProcess) != 1 || filepath.Base(res.FilesToProcess[0]) != "normal.txt" {
				t.Errorf("FilesToProcess = %v, want just normal.txt", res.FilesToProcess)
			}

			// The oversize TEXT file is a coverage loss: unexamined, with its own cause.
			var found *SkippedFile
			for i := range res.UnexaminedFiles {
				if filepath.Base(res.UnexaminedFiles[i].Path) == "big_report.txt" {
					found = &res.UnexaminedFiles[i]
				}
			}
			if found == nil {
				t.Fatalf("big_report.txt is not in UnexaminedFiles %v — a processable file "+
					"refused for size was expected to produce a result and did not, so it must "+
					"reach files_not_examined and --fail-on-incomplete",
					pathsOf(res.UnexaminedFiles))
			}
			if found.Cause != causeTooLarge {
				t.Errorf("cause = %v (%q), want causeTooLarge. The zero value is causeUnreadable, "+
					"which would claim the file could not be opened — a failure that did not happen",
					found.Cause, found.Cause.String())
			}
			if !strings.Contains(found.Reason, "too large") {
				t.Errorf("reason = %q, want it to say the file was too large", found.Reason)
			}
			// Payload-free: the reason reaches stderr and every machine format.
			if strings.Contains(found.Reason, "452-11-9384") {
				t.Errorf("reason %q leaked file content", found.Reason)
			}

			// The opaque binary is a genuine SKIP, and silent: nothing would have read
			// it at any size, so a warning would be noise about a non-event.
			var opaque *SkippedFile
			for i := range res.SkippedFiles {
				if strings.Contains(res.SkippedFiles[i].Path, "Browser") {
					opaque = &res.SkippedFiles[i]
				}
			}
			if opaque == nil {
				t.Fatalf("the opaque binary is not in SkippedFiles %v — it must still be "+
					"recorded so it stays in the denominator", pathsOf(res.SkippedFiles))
			}
			if !opaque.Silent {
				t.Error("the opaque binary produced a visible warning; no extension list can " +
					"ever cover random-suffix partial downloads, which is why the predicate " +
					"must be capability-derived")
			}
			for _, u := range res.UnexaminedFiles {
				if strings.Contains(u.Path, "Browser") {
					t.Error("the opaque binary was reported as unexamined; nothing would have " +
						"read it, so no coverage was lost")
				}
			}
		})
	}
}

// With preprocessors DISABLED, an oversize binary document is not a coverage loss:
// nothing would have read it either way.
func TestOversizeBinaryDocumentWithoutPreprocessorsIsASkip(t *testing.T) {
	dir := t.TempDir()
	// A .docx is a binary document: processable only with preprocessors.
	f, err := os.Create(filepath.Join(dir, "big.docx")) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("PK\x03\x04")); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(101 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	withPre, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(withPre.UnexaminedFiles) != 1 {
		t.Errorf("with preprocessors: UnexaminedFiles = %v, want the .docx — its content "+
			"would have been extracted and scanned", pathsOf(withPre.UnexaminedFiles))
	}

	without, err := getFilesToProcess(dir, true, nil, nil, false)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(without.UnexaminedFiles) != 0 {
		t.Errorf("without preprocessors: UnexaminedFiles = %v, want none — nothing would "+
			"have read a .docx, so refusing it for size loses nothing",
			pathsOf(without.UnexaminedFiles))
	}
}

// Every cmd-side cause must map to a distinct formatter cause.
//
// causeNotFollowed had no case in the mapping switch and fell through to the
// conservative default, so machine formats said "cannot read" for every refused
// symlink while the text report said "symlink not followed" — a file the tool
// deliberately declined, reported as an I/O failure that never happened.
func TestEveryCauseMapsToItsOwnFormatterCause(t *testing.T) {
	cases := []struct {
		cause unscannedCause
		want  formatters.NotExaminedCause
	}{
		{causeUnreadable, formatters.NotExaminedUnreadable},
		{causeUnparseable, formatters.NotExaminedUnparseable},
		{causeNoText, formatters.NotExaminedNoText},
		{causeCutShort, formatters.NotExaminedCutShort},
		{causeNotFollowed, formatters.NotExaminedNotFollowed},
		{causeTooLarge, formatters.NotExaminedTooLarge},
	}

	seen := make(map[formatters.NotExaminedCause]unscannedCause, len(cases))
	for _, c := range cases {
		got := toFormatterNotExamined([]unscannedEntry{{Path: "f", Cause: c.cause, Detail: "d"}})
		if len(got) != 1 {
			t.Fatalf("cause %v produced %d entries", c.cause, len(got))
		}
		if got[0].Cause != c.want {
			t.Errorf("cause %v (%q) mapped to %q, want %q — an unmapped cause silently "+
				"becomes 'cannot read', asserting a failure that did not happen",
				c.cause, c.cause.String(), got[0].Cause.String(), c.want.String())
		}
		if prev, dup := seen[c.want]; dup {
			t.Errorf("formatter cause %q is used by both %v and %v; the two are "+
				"indistinguishable in every machine format", c.want.String(), prev, c.cause)
		}
		seen[c.want] = c.cause
		// The two sides must also agree on the wording, since an operator compares a
		// human report against a machine artifact from the same run.
		if c.cause.String() != c.want.String() {
			t.Errorf("wording differs: cmd says %q, formatter says %q",
				c.cause.String(), c.want.String())
		}
	}
}

// A refused symlink must keep its own cause through discovery. The cause now travels
// on SkippedFile, and the zero value is causeUnreadable, so a producer that forgets to
// set it silently mislabels the entry.
func TestSymlinkDisclosureCarriesItsCause(t *testing.T) {
	root := t.TempDir()
	link := filepath.Join(root, "dangling.txt")
	if err := os.Symlink(filepath.Join(root, "nope.txt"), link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	d, resolved, reason := classifySymlink(link, root)
	if d != symlinkDisclose {
		t.Fatalf("fixture: disposition = %v, want symlinkDisclose", d)
	}
	_, disclose := resolveSymlinkCandidates(
		[]symlinkCandidate{{linkPath: link, resolved: resolved, reason: reason, disp: d}}, nil)
	if len(disclose) != 1 {
		t.Fatalf("got %d disclosures, want 1", len(disclose))
	}
	if disclose[0].Cause != causeNotFollowed {
		t.Errorf("cause = %v (%q), want causeNotFollowed. The zero value claims the link "+
			"could not be read, which is not what happened — the tool declined to follow it",
			disclose[0].Cause, disclose[0].Cause.String())
	}
}

// The collapsed per-cause breakdown must account for EVERY entry the header counts.
//
// Above inlineDetailLimit entries the report prints a per-cause tally instead of paths,
// and that tally iterated a hardcoded list of the four ORIGINAL causes while the header
// printed len(entries). Every cause added since was counted in the header and given no
// bucket line: causeNotFollowed (#326) and causeTooLarge (#324) both vanished.
//
// Measured on a ~1,870-file scan, the header read 65 while the buckets summed to 64 —
// and the entry missing from the breakdown was exactly the oversize file this report
// exists to disclose. See #336.
//
// The assertion is the INVARIANT rather than a list of expected labels: buckets must sum
// to the header, whatever the cause set becomes. A future cause therefore cannot regress
// this the way the last two did.
func TestBreakdownAccountsForEveryCause(t *testing.T) {
	allCauses := []unscannedCause{
		causeUnreadable, causeUnparseable, causeNoText, causeCutShort,
		causeNotFollowed, causeTooLarge,
	}

	// More than inlineDetailLimit entries, so the collapsed tally path is taken.
	var entries []unscannedEntry
	want := map[unscannedCause]int{}
	for i, c := range allCauses {
		n := i + 2 // distinct per-cause counts, so a mis-attributed bucket shows up
		for j := 0; j < n; j++ {
			entries = append(entries, unscannedEntry{
				Path:   fmt.Sprintf("/f/%d-%d.txt", i, j),
				Cause:  c,
				Detail: "detail",
			})
		}
		want[c] = n
	}
	if len(entries) <= inlineDetailLimit {
		t.Fatalf("fixture has %d entries, need more than %d to exercise the collapsed tally",
			len(entries), inlineDetailLimit)
	}

	var buf strings.Builder
	if !writeUnscannedReport(&buf, entries, len(entries), false, false) {
		t.Fatal("writeUnscannedReport reported nothing to write")
	}
	out := buf.String()

	// Every cause must have a bucket, with the right count.
	sum := 0
	for c, n := range want {
		label := fmt.Sprintf("%s: %d", c, n)
		if !strings.Contains(out, label) {
			t.Errorf("breakdown is missing %q.\nA cause counted in the header with no bucket "+
				"line is invisible to the operator — and the last two causes added were the "+
				"symlink and oversize disclosures.\n--- report ---\n%s", label, out)
		}
		sum += n
	}

	// The invariant: buckets sum to the header count.
	if !strings.Contains(out, fmt.Sprintf("NOT FULLY EXAMINED: %d of %d", len(entries), len(entries))) {
		t.Errorf("header does not report %d entries.\n--- report ---\n%s", len(entries), out)
	}
	if sum != len(entries) {
		t.Fatalf("fixture inconsistent: buckets sum to %d, header counts %d", sum, len(entries))
	}
}

// A SOLO oversize processable file is the third discovery route, and the one that was
// missing from the route table above.
//
// Its FilesToProcess is empty, which sent main() down the "No files to process" early
// exit: it printed one stdout line and exited 0, BEFORE the unscanned report and the
// --fail-on-incomplete gate. So the one invocation this feature exists for produced a
// silent, complete-looking, zero-exit result. Both existing route fixtures create a
// small companion file, so FilesToProcess was never empty in any test. See #339.
func TestSoloOversizeFileIsUnexaminedWithEmptyQueue(t *testing.T) {
	dir := t.TempDir()
	solo := bigTextFile(t, filepath.Join(dir, "big_report.txt"))

	res, err := getFilesToProcess(solo, false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	if len(res.FilesToProcess) != 0 {
		t.Errorf("FilesToProcess = %v, want empty — the file is over the limit", res.FilesToProcess)
	}
	if len(res.UnexaminedFiles) != 1 {
		t.Fatalf("UnexaminedFiles = %v, want exactly the oversize file", pathsOf(res.UnexaminedFiles))
	}
	if res.UnexaminedFiles[0].Cause != causeTooLarge {
		t.Errorf("cause = %q, want causeTooLarge", res.UnexaminedFiles[0].Cause.String())
	}

	// The report must be produced for this entry: an empty scan queue must not mean an
	// empty disclosure.
	entries := []unscannedEntry{{
		Path:   res.UnexaminedFiles[0].Path,
		Cause:  res.UnexaminedFiles[0].Cause,
		Detail: res.UnexaminedFiles[0].Reason,
	}}
	var buf strings.Builder
	if !writeUnscannedReport(&buf, entries, len(entries), true, false) {
		t.Fatal("no report written for a run whose only input was refused")
	}
	if !strings.Contains(buf.String(), "file too large to scan") {
		t.Errorf("report does not name the cause:\n%s", buf.String())
	}

	// And it must escalate under --fail-on-incomplete.
	if got := resolveIncompleteExitCode(0, true, len(entries)); got != 3 {
		t.Errorf("resolveIncompleteExitCode = %d, want 3 — a refused input is exactly the "+
			"coverage loss this flag exists to surface", got)
	}
	if got := resolveIncompleteExitCode(0, false, len(entries)); got != 0 {
		t.Errorf("resolveIncompleteExitCode without the flag = %d, want 0", got)
	}
}

// A file named DIRECTLY on the command line takes its own branch of getFilesToProcess, and
// that branch used to carry a size limit of its own: 500MB for .mp3/.wav/.m4a/.flac against
// the 100MB every other gate applies.
//
// The consequence was not a larger scan, it was a silent one. The router refuses the file at
// 100MB, and the router's refusal lands in the "unsupported file types" bucket rather than in
// files_not_examined — so a 150MB .wav named directly gave exit 0, "No matches found", no
// files_not_examined entry, and success from --fail-on-incomplete for a file that was never
// opened (#355). Audio metadata is exactly where this tool finds PII in media, so the file
// most likely to hold an unredacted name was the one reported as an unsupported type.
//
// Every audio extension that had the allowance is checked, because the fix removes a map and
// a partial revert would restore one entry.
func TestOversizeAudioNamedDirectlyIsUnexamined(t *testing.T) {
	for _, ext := range []string{".mp3", ".wav", ".m4a", ".flac"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			big := filepath.Join(dir, "recording"+ext)

			// Audio must NOT have acquired the video exemption (#410). Asserted before the
			// fixture is built, because if it ever did, the flat-ceiling fixture below would
			// simply be under the limit and every assertion in this test would invert its
			// meaning while still passing.
			if got := maxScanSizeFor(big); got != router.MaxFileSize {
				t.Fatalf("maxScanSizeFor(%s) = %d, want the flat %d. Audio was measured to gain "+
					"NOTHING from a raised ceiling — three gates downstream cap it at 100MB — so "+
					"an allowance here only moves the miss into a bucket that never reaches "+
					"--fail-on-incomplete, which is #355 all over again", ext, got, router.MaxFileSize)
			}
			big = audioFile(t, big, router.MaxFileSize+1)

			res, err := getFilesToProcess(big, false, nil, nil, true)
			if err != nil {
				t.Fatalf("getFilesToProcess: %v", err)
			}

			if len(res.FilesToProcess) != 0 {
				t.Errorf("FilesToProcess = %v, want empty: the router refuses this file at "+
					"%dMB, so admitting it here only moves the miss to a bucket that does not "+
					"reach --fail-on-incomplete", res.FilesToProcess, router.MaxFileSize/(1024*1024))
			}
			if len(res.UnexaminedFiles) != 1 {
				t.Fatalf("UnexaminedFiles = %v, want the oversize recording: a processable type "+
					"refused for size is a coverage loss", pathsOf(res.UnexaminedFiles))
			}
			if got := res.UnexaminedFiles[0].Cause; got != causeTooLarge {
				t.Errorf("Cause = %v, want causeTooLarge", got)
			}
			if got := res.UnexaminedFiles[0].Reason; !strings.Contains(got, "100MB") {
				t.Errorf("Reason = %q, want it to name the limit that refused the file", got)
			}
			if len(res.SkippedFiles) != 0 {
				t.Errorf("SkippedFiles = %v, want empty: this is not a skip, and the messages on "+
					"that bucket call it an unsupported TYPE", pathsOf(res.SkippedFiles))
			}
		})
	}
}

// The limit must still ADMIT audio under it, or the test above would pass on a build that
// refuses every audio file and reports a coverage loss for all of them.
func TestUnderLimitAudioNamedDirectlyIsScanned(t *testing.T) {
	dir := t.TempDir()
	small := audioFile(t, filepath.Join(dir, "recording.wav"), 0)

	res, err := getFilesToProcess(small, false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(res.FilesToProcess) != 1 || res.FilesToProcess[0] != small {
		t.Errorf("FilesToProcess = %v, want the recording itself", res.FilesToProcess)
	}
	if len(res.UnexaminedFiles) != 0 {
		t.Errorf("UnexaminedFiles = %v, want empty", pathsOf(res.UnexaminedFiles))
	}
}

// Discovery's limit and the router's must never disagree.
//
// They were independent numbers and they drifted, which is the whole of #355. This compares
// the two VALUES, so it fails the moment either side moves without the other — the failure
// mode that produced the bug. It cannot see how each is spelled, so it would not notice
// maxScanSizeFor being rewritten as its own literal while the numbers still match; the
// derivation is what makes that harmless, and the comment on maxScanSizeFor is what asks a
// future editor to keep it.
//
// Now checked per TYPE rather than once, because the limit became type-aware (#410): a single
// comparison would only have covered whichever type the test happened to name, and the
// interesting case is precisely the one where the two sides could disagree about the
// EXEMPTION rather than about the flat number.
func TestDiscoveryLimitIsTheRouterLimit(t *testing.T) {
	for _, name := range []string{
		"movie.mp4", "clip.mov", "clip.m4v", "phone.3gp", "phone.3g2", // exempt
		"MOVIE.MP4", "Clip.MOV", // exempt, and the test is case-insensitive
		"notes.txt", "book.pdf", "sheet.xlsx", "recording.wav", "song.mp3",
		"photo.jpg", "archive.zip", "noextension",
	} {
		if got, want := maxScanSizeFor(name), router.MaxSizeForPath(name); got != want {
			t.Errorf("maxScanSizeFor(%q) = %d, router.MaxSizeForPath = %d: discovery must admit "+
				"exactly what the router accepts, or a file admitted here is refused there and "+
				"the refusal is filed as an unsupported type", name, got, want)
		}
	}
}
