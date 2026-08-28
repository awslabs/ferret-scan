// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/router"
)

// #410 at the layer where it bit.
//
// The router has its own size gate, but on the CLI file path it never runs: discovery refuses
// the file first and the router is never consulted. So the fix is only observable end to end if
// DISCOVERY admits the file — a router-only change would have left the measured symptom
// (files_processed: 0) exactly as it was.
//
// Measured before the fix on a real 205MB .mov, against a 7MB cut of the SAME file carrying the
// SAME exiftool-written metadata:
//
//	7.3MB    2 findings (1 high)      INTELLECTUAL_PROPERTY, SSN
//	205.7MB  0 findings               files_not_examined: 1, exit 3
//
// Size was the only difference between the two inputs.

// sparseFile creates a file of exactly size bytes without writing them. Sparse because the size
// is the only property under test; a real 500MB fixture per case is not worth the disk, and this
// repository has a note about checking free space before building one.
func sparseFile(t *testing.T, path string, size int64) string {
	t.Helper()
	f, err := os.Create(path) // #nosec G304 -- test temp dir
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close()
		t.Skipf("cannot create a sparse %d-byte file here: %v", size, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	// A fixture that is not the size we asked for would make every assertion below describe a
	// file that does not exist as described.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != size {
		t.Fatalf("fixture %s is %d bytes, want %d", path, info.Size(), size)
	}
	return path
}

// TestOversizeVideoNamedDirectlyIsScanned is the regression test for the reported symptom.
//
// Every exempted extension is covered, because the ceiling is applied by extension and a
// partial fix would raise it for .mp4 while leaving the phone formats refused — and .3gp/.3g2
// are precisely the old footage most likely to carry GPS.
func TestOversizeVideoNamedDirectlyIsScanned(t *testing.T) {
	for _, ext := range []string{".mp4", ".m4v", ".mov", ".3gp", ".3g2"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			big := sparseFile(t, filepath.Join(dir, "clip"+ext), router.MaxFileSize+1)

			res, err := getFilesToProcess(big, false, nil, nil, true)
			if err != nil {
				t.Fatalf("getFilesToProcess: %v", err)
			}

			if len(res.FilesToProcess) != 1 || res.FilesToProcess[0] != big {
				t.Errorf("FilesToProcess = %v, want the clip itself.\nThe video extractor reads "+
					"this container up to %dMB and both downstream ceilings already said so; "+
					"discovery refusing it at %dMB declines a file the tool can scan (#410).",
					res.FilesToProcess, router.MaxVideoFileSize/(1024*1024),
					router.MaxFileSize/(1024*1024))
			}
			if len(res.UnexaminedFiles) != 0 {
				t.Errorf("UnexaminedFiles = %v, want empty — the file was scanned, so there is no "+
					"coverage gap to disclose", pathsOf(res.UnexaminedFiles))
			}
			if len(res.SkippedFiles) != 0 {
				t.Errorf("SkippedFiles = %v, want empty", pathsOf(res.SkippedFiles))
			}
		})
	}
}

// TestVideoBeyondItsOwnCeilingIsStillDisclosed is the other half, and the more important one:
// the ceiling still has to BIND. A fix that merely removed the gate would pass the test above.
//
// The disclosure matters as much as the refusal. A processable type refused for size is lost
// coverage, so it belongs in files_not_examined where --fail-on-incomplete can see it — not in
// the skipped bucket whose messages call it an unsupported TYPE (#355).
func TestVideoBeyondItsOwnCeilingIsStillDisclosed(t *testing.T) {
	dir := t.TempDir()
	huge := sparseFile(t, filepath.Join(dir, "clip.mp4"), router.MaxVideoFileSize+1)

	res, err := getFilesToProcess(huge, false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	if len(res.FilesToProcess) != 0 {
		t.Errorf("FilesToProcess = %v, want empty: %d bytes is past the video ceiling too, and "+
			"the extractor refuses it, so admitting it here only moves the refusal deeper",
			res.FilesToProcess, router.MaxVideoFileSize+1)
	}
	if len(res.UnexaminedFiles) != 1 {
		t.Fatalf("UnexaminedFiles = %v, want the oversize clip: a processable type refused for "+
			"size is a coverage LOSS and has to reach --fail-on-incomplete",
			pathsOf(res.UnexaminedFiles))
	}
	if got := res.UnexaminedFiles[0].Cause; got != causeTooLarge {
		t.Errorf("Cause = %v, want causeTooLarge", got)
	}

	// The number in the message must be the number that refused. Telling the operator "max size:
	// 100MB" about a 501MB video is advice they have already followed — the file is a video, its
	// limit is 500MB, and shrinking it to 100MB was never required.
	reason := res.UnexaminedFiles[0].Reason
	if !strings.Contains(reason, "500MB") {
		t.Errorf("Reason = %q, want it to name 500MB — the limit that actually refused this "+
			"file. tooLargeReason takes the path for exactly this reason.", reason)
	}
	if strings.Contains(reason, "100MB") {
		t.Errorf("Reason = %q names 100MB, which is not the limit this video was refused by", reason)
	}
}

// TestExactlyAtTheVideoCeilingIsScanned pins the boundary. An off-by-one here refuses a file
// that is precisely admissible, and the two neighbouring tests would both still pass.
func TestExactlyAtTheVideoCeilingIsScanned(t *testing.T) {
	dir := t.TempDir()
	atLimit := sparseFile(t, filepath.Join(dir, "clip.mov"), router.MaxVideoFileSize)

	res, err := getFilesToProcess(atLimit, false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(res.FilesToProcess) != 1 {
		t.Errorf("a file of exactly %d bytes was not admitted; the comparison must be > and not >=",
			router.MaxVideoFileSize)
	}
}

// TestOversizeNonVideoIsStillRefused bounds the blast radius of the change.
//
// These are the types whose preprocessors hold the whole file, so the flat ceiling is what
// bounds their memory. If the exemption leaked to them, the file's size would become the bound
// on the work — the thing the gate exists to prevent.
func TestOversizeNonVideoIsStillRefused(t *testing.T) {
	for _, ext := range []string{".txt", ".pdf", ".docx", ".xlsx", ".jpg", ".zip", ".mp3", ".wav"} {
		t.Run(ext, func(t *testing.T) {
			dir := t.TempDir()
			big := sparseFile(t, filepath.Join(dir, "doc"+ext), router.MaxFileSize+1)

			res, err := getFilesToProcess(big, false, nil, nil, true)
			if err != nil {
				t.Fatalf("getFilesToProcess: %v", err)
			}
			if len(res.FilesToProcess) != 0 {
				t.Errorf("FilesToProcess = %v: %s must still be refused at %dMB. Its preprocessor "+
					"holds the whole file, so the exemption would make the input's size the bound "+
					"on memory", res.FilesToProcess, ext, router.MaxFileSize/(1024*1024))
			}
			// Still disclosed as lost coverage or a benign skip, depending on the type — but
			// never dropped, which is what #355 and #485 were both about.
			if len(res.UnexaminedFiles)+len(res.SkippedFiles) != 1 {
				t.Errorf("the refusal reached no counter: Unexamined=%v Skipped=%v",
					pathsOf(res.UnexaminedFiles), pathsOf(res.SkippedFiles))
			}
		})
	}
}

// TestOversizeVideoWithATrailingSlashIsScanned covers the THIRD directly-named-file gate.
//
// getFilesToProcess has three paths that size-check a named file, and this one is only reached
// when os.Stat(inputPath) FAILS while os.Stat(filepath.Clean(inputPath)) succeeds. A trailing
// slash does exactly that: stat("clip.mp4/") returns ENOTDIR, so the literal-filename branch is
// skipped, the path has no glob metacharacters so the glob branch is skipped too, and execution
// reaches the Clean-then-Stat path at the bottom.
//
// This test exists because a mutation SURVIVED without it. Reverting that gate to the flat
// constant failed nothing, since every other test reaches the file through the first branch and
// returns before this code runs.
//
// The defect it pins: filepath.Ext("clip.mp4/") is "", so a limit taken from the raw argument
// falls back to 100MB where the clean path gives 500MB, and the video exemption would not have
// applied to `--file clip.mp4/`. The companion test below covers the classification half.
func TestOversizeVideoWithATrailingSlashIsScanned(t *testing.T) {
	dir := t.TempDir()
	video := sparseFile(t, filepath.Join(dir, "clip.mp4"), router.MaxFileSize+1)

	// Confirm the fixture really takes the path under test, or this passes for the wrong
	// reason by going through the first branch like every other test here.
	if _, err := os.Stat(video + string(os.PathSeparator)); err == nil {
		t.Skipf("this platform stats %q successfully, so the Clean-then-Stat path is not "+
			"reached and there is nothing to test here", video+"/")
	}

	res, err := getFilesToProcess(video+string(os.PathSeparator), false, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}
	if len(res.FilesToProcess) != 1 {
		t.Errorf("FilesToProcess = %v, want the clip.\nfilepath.Ext of the raw argument is empty "+
			"because the base name after the last separator is empty, so a limit taken from it "+
			"falls back to %dMB and refuses a video the tool can scan.",
			res.FilesToProcess, router.MaxFileSize/(1024*1024))
	}
}

// TestOversizeBinaryWithATrailingSlashIsDisclosed is the classification half, and the bug it
// pins is older than the video ceiling.
//
// A processable type refused for size is lost coverage and must reach files_not_examined, where
// --fail-on-incomplete can see it. router.CanProcessType answers from the EXTENSION for a binary
// document and otherwise sniffs the content, so an empty extension sends a binary file down the
// text-sniffing arm, where it reads as binary and comes back false. The refusal was then filed
// in SkippedFiles with Silent: true — reaching no counter, absent from files_not_examined, and
// exiting 0 under --fail-on-incomplete for a file the tool never opened. That is the #355
// mislabelling, reached by a different route.
//
// The fixture is a BINARY type on purpose. A .txt cannot show this: sniffing its content returns
// the same answer with or without the trailing slash, so a text fixture passes whichever path
// the code takes — which is exactly how a first version of this test passed under the mutation
// it was written to catch, and how the note in main.go came to claim more than was measured.
func TestOversizeBinaryWithATrailingSlashIsDisclosed(t *testing.T) {
	// Every binary family whose processability comes from its extension, so the case is not
	// pinned to one format's quirks. Each is over ITS OWN ceiling: video is exempt to 500MB,
	// the rest are refused past 100MB.
	cases := []struct {
		name string
		size int64
	}{
		{"clip.mp4", router.MaxVideoFileSize + 1},
		{"book.pdf", router.MaxFileSize + 1},
		{"doc.docx", router.MaxFileSize + 1},
		{"photo.jpg", router.MaxFileSize + 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			doc := sparseFile(t, filepath.Join(dir, tc.name), tc.size)

			raw := doc + string(os.PathSeparator)
			if _, err := os.Stat(raw); err == nil {
				t.Skip("this platform stats a trailing-slash file path, so this branch is " +
					"unreachable and there is nothing to test")
			}

			res, err := getFilesToProcess(raw, false, nil, nil, true)
			if err != nil {
				t.Fatalf("getFilesToProcess: %v", err)
			}

			if len(res.UnexaminedFiles) != 1 {
				t.Errorf("UnexaminedFiles = %v, want the oversize %s.\nA processable type refused "+
					"for size is a COVERAGE LOSS. Filed as a silent skip it reaches no counter, "+
					"files_not_examined is absent, and --fail-on-incomplete exits 0 for a file "+
					"the tool never opened (#355).", pathsOf(res.UnexaminedFiles), tc.name)
			}
			for _, s := range res.SkippedFiles {
				if s.Silent {
					t.Errorf("the refusal was filed as a SILENT skip (%s: %s), the bucket whose "+
						"messages call it an unsupported TYPE", s.Path, s.Reason)
				}
			}
		})
	}
}

// TestOversizeVideoIsScannedInARecursiveWalk.
//
// The walk is a SEPARATE gate site from the directly-named path, and there are six of them in
// discovery. A fix applied to one leaves a file scanned or refused depending on how the
// operator spelled the path, which is the inconsistency #326 was filed for.
func TestOversizeVideoIsScannedInARecursiveWalk(t *testing.T) {
	dir := t.TempDir()
	video := sparseFile(t, filepath.Join(dir, "clip.mp4"), router.MaxFileSize+1)
	doc := sparseFile(t, filepath.Join(dir, "notes.txt"), router.MaxFileSize+1)

	res, err := getFilesToProcess(dir, true, nil, nil, true)
	if err != nil {
		t.Fatalf("getFilesToProcess: %v", err)
	}

	var sawVideo bool
	for _, p := range res.FilesToProcess {
		if p == video {
			sawVideo = true
		}
		if p == doc {
			t.Errorf("the walk admitted the oversize .txt (%s); only the video is exempt", doc)
		}
	}
	if !sawVideo {
		t.Errorf("the recursive walk did not admit %s.\nFilesToProcess = %v\nDiscovery has six "+
			"size gate sites; a file must not be scanned or refused depending on whether its "+
			"path was named directly or reached by a walk.", video, res.FilesToProcess)
	}
}

// TestOversizeVideoIsScannedThroughASymlink.
//
// classifySymlink judges the RESOLVED TARGET, and it used to be handed a single flat limit by
// its caller — which could not be type-aware, because the caller does not know what the link
// resolves to. So a 200MB video reached through a symlink would have stayed refused after the
// rest of this fix landed: identical bytes scanned or not depending on how the path was spelled,
// which is exactly the defect #326 added this function to fix.
func TestOversizeVideoIsScannedThroughASymlink(t *testing.T) {
	root := t.TempDir()
	target := sparseFile(t, filepath.Join(root, "clip.mp4"), router.MaxFileSize+1)
	link := filepath.Join(root, "link.mp4")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}

	d, resolved, reason := classifySymlink(link, root)
	if d != symlinkFollow {
		t.Errorf("disposition = %v (%q), want symlinkFollow. The target is a %dMB video and the "+
			"extractor reads those; refusing it here means a symlinked video is treated "+
			"differently from the same file named directly (#326, #410).",
			d, reason, (router.MaxFileSize+1)/(1024*1024))
	}
	if resolved == "" {
		t.Error("resolved target is empty")
	}

	// And the ceiling still binds for the target's own type.
	tooBig := sparseFile(t, filepath.Join(root, "huge.mp4"), router.MaxVideoFileSize+1)
	hugeLink := filepath.Join(root, "hugelink.mp4")
	if err := os.Symlink(tooBig, hugeLink); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if d, _, reason := classifySymlink(hugeLink, root); d != symlinkDisclose {
		t.Errorf("a target past the VIDEO ceiling gave disposition %v (%q), want symlinkDisclose",
			d, reason)
	}
}

// TestSymlinkLimitFollowsTheTargetsType is the sharper half of the case above: a link whose OWN
// name suggests one type pointing at a file of another.
//
// The walk hands `resolved` to the scanner, so the target's extension decides which preprocessor
// reads it — and therefore must also decide how many bytes are admitted. Taking the limit from
// the link's name instead would admit a 200MB text file through a link called `x.mp4`, which is
// the exemption leaking to a type that cannot afford it.
func TestSymlinkLimitFollowsTheTargetsType(t *testing.T) {
	root := t.TempDir()

	// A .mp4-named link pointing at an oversize TEXT file must be refused.
	textTarget := sparseFile(t, filepath.Join(root, "notes.txt"), router.MaxFileSize+1)
	videoNamedLink := filepath.Join(root, "looks-like.mp4")
	if err := os.Symlink(textTarget, videoNamedLink); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if d, _, reason := classifySymlink(videoNamedLink, root); d != symlinkDisclose {
		t.Errorf("a link NAMED .mp4 pointing at a %dMB .txt gave %v (%q), want symlinkDisclose.\n"+
			"The scanner reads the resolved target, so the target's type has to decide the "+
			"limit; taking it from the link's name lets any file borrow the video exemption.",
			(router.MaxFileSize+1)/(1024*1024), d, reason)
	}

	// And the converse: a .txt-named link pointing at an oversize VIDEO must be followed.
	videoTarget := sparseFile(t, filepath.Join(root, "real.mp4"), router.MaxFileSize+1)
	textNamedLink := filepath.Join(root, "looks-like.txt")
	if err := os.Symlink(videoTarget, textNamedLink); err != nil {
		t.Skipf("cannot create symlinks here: %v", err)
	}
	if d, _, reason := classifySymlink(textNamedLink, root); d != symlinkFollow {
		t.Errorf("a link NAMED .txt pointing at a %dMB .mp4 gave %v (%q), want symlinkFollow",
			(router.MaxFileSize+1)/(1024*1024), d, reason)
	}
}

// TestStdinKeepsTheFlatCeiling records a deliberate exclusion rather than an oversight.
//
// stdin has no path to take a type from — --stdin-name is a synthetic label the caller chooses,
// so honouring it would let `--stdin-name x.mp4` pick the limit — and this path refuses binary
// content outright a few lines after the read, so a video can never be scanned through it. A
// raised ceiling would buy a larger buffer before the same refusal.
//
// The limit is a local inside runStdinScan and observing it through the function would need a
// 100MB pipe, so this reads the source instead. Structural rather than behavioural, and stated
// as such: it catches the one edit that would matter — swapping the flat constant for the
// type-aware function — which is a plausible tidy-up for someone making the gates consistent.
func TestStdinKeepsTheFlatCeiling(t *testing.T) {
	if router.MaxFileSize == router.MaxVideoFileSize {
		t.Fatal("the two ceilings are equal, so nothing here can distinguish them")
	}

	src, err := os.ReadFile("stdin.go")
	if err != nil {
		t.Fatalf("cannot read stdin.go: %v", err)
	}

	// Comments are stripped before searching. The first version of this test did not, and
	// failed on the unmutated tree: the comment in stdin.go explaining why it does NOT use
	// MaxSizeForPath contains the name, so the check tripped on its own documentation.
	text := stripLineComments(string(src))

	// Non-vacuity: if the assignment this test is about is gone or renamed, the absence of
	// MaxSizeForPath below would pass for the wrong reason.
	if !strings.Contains(text, "limit := router.MaxFileSize") {
		t.Fatalf("cmd/stdin.go no longer contains `limit := router.MaxFileSize`, so this test is " +
			"asserting nothing. Find the stdin size limit and re-point this check at it.")
	}
	if strings.Contains(text, "MaxSizeForPath") {
		t.Error("cmd/stdin.go now uses router.MaxSizeForPath. stdin must keep the FLAT ceiling: " +
			"the only name available here is --stdin-name, which the caller invents, so a " +
			"type-aware limit would let `--stdin-name x.mp4` choose a 500MB buffer. This path " +
			"also refuses binary content outright, so it can never scan a video anyway — the " +
			"raised ceiling would buy a bigger read before the same refusal.")
	}
}

// stripLineComments removes // comments so a source check reads CODE and not prose about it.
//
// Line comments only, which is all this file has, and it does not try to understand string
// literals — a `//` inside a string would be treated as a comment. That is acceptable for the
// one narrow check above and is stated so nobody reuses it as a general tool.
func stripLineComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, ln := range lines {
		if idx := strings.Index(ln, "//"); idx >= 0 {
			lines[i] = ln[:idx]
		}
	}
	return strings.Join(lines, "\n")
}
