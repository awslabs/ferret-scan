// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	meta_extract_videolib "github.com/awslabs/ferret-scan/v2/internal/preprocessors/meta-extractors/meta-extract-videolib"
)

// #410: a video container between 100MB and 500MB was refused before the extractor that
// supports it ever ran.
//
// Two downstream ceilings had said 500MB since they were written —
// meta-extract-videolib.MaxFileSize and preprocessors.DefaultResourceLimits().MaxVideoFileSize
// — and NEITHER was reachable, because every file met the flat 100MB gate first. So the tool
// declined to scan a file it was fully capable of scanning, and video metadata is where GPS
// coordinates and device owner names live.
//
// Measured before the fix on a real 205MB .mov (a GarageBand lesson asset with metadata written
// by exiftool), against a 7MB cut of the SAME file carrying the SAME metadata:
//
//	size     findings                        types
//	7.3MB    2 (1 high)                      INTELLECTUAL_PROPERTY, SSN
//	205.7MB  0, files_not_examined: 1        —
//
// One SSN at HIGH, found at 7MB and lost at 205MB, with size the only difference between the
// two inputs. Nothing reported is nothing redacted, so the recall loss is the whole cost.

// TestMaxSizeForPathExemptsVideoOnly is the core of the fix.
//
// Every non-video type is listed as well as the video ones, because the risk in a type-aware
// gate is not that the exemption fails to apply — that shows up immediately — but that it
// applies too widely and quietly raises the ceiling for a format whose cost really is
// proportional to its size.
func TestMaxSizeForPathExemptsVideoOnly(t *testing.T) {
	video := []string{"movie.mp4", "clip.m4v", "reel.mov", "phone.3gp", "phone.3g2"}
	for _, name := range video {
		t.Run("video/"+name, func(t *testing.T) {
			if got := MaxSizeForPath(name); got != MaxVideoFileSize {
				t.Errorf("MaxSizeForPath(%q) = %d, want MaxVideoFileSize (%d). A video is the one "+
					"type read WITHOUT being held in memory, which is what earns the exemption",
					name, got, MaxVideoFileSize)
			}
		})
	}

	// Everything else, including the audio formats whose allowance #355 deliberately REMOVED.
	other := []string{
		"notes.txt", "page.html", "data.json", "book.pdf",
		"sheet.xlsx", "doc.docx", "deck.pptx", "legacy.doc", "sheet.ods",
		"photo.jpg", "photo.png", "scan.tiff", "photo.heic",
		"song.mp3", "voice.wav", "voice.m4a", "master.flac",
		"archive.zip", "backup.tar.gz", "noextension", "", ".", "..",
		"trailingdot.", "movie.mp4.txt", "mp4", ".mp4suffix",
	}
	for _, name := range other {
		t.Run("other/"+name, func(t *testing.T) {
			if got := MaxSizeForPath(name); got != MaxFileSize {
				t.Errorf("MaxSizeForPath(%q) = %d, want the flat MaxFileSize (%d). Raising the "+
					"ceiling for a type whose preprocessor holds the whole file makes the file's "+
					"size the bound on memory, which is what the gate exists to prevent",
					name, got, MaxFileSize)
			}
		})
	}
}

// TestMaxSizeForPathIsCaseInsensitive. Camera and phone firmware writes .MP4 and .MOV in upper
// case routinely, and a case-sensitive test would exempt the lower-case spelling only — so the
// same recording would be scanned or refused depending on which device wrote it.
func TestMaxSizeForPathIsCaseInsensitive(t *testing.T) {
	for _, name := range []string{"MOVIE.MP4", "Clip.MoV", "REEL.M4V", "PHONE.3GP", "x.3G2"} {
		if got := MaxSizeForPath(name); got != MaxVideoFileSize {
			t.Errorf("MaxSizeForPath(%q) = %d, want MaxVideoFileSize (%d)", name, got, MaxVideoFileSize)
		}
	}
}

// TestMaxSizeForPathIgnoresDirectoryNames. The extension of a PARENT directory must not decide
// the file's limit: a repository directory called "campaign.mp4" holding text files would
// otherwise raise the ceiling for every one of them.
func TestMaxSizeForPathIgnoresDirectoryNames(t *testing.T) {
	for _, name := range []string{
		filepath.Join("campaign.mp4", "notes.txt"),
		filepath.Join("a.mov", "b.mp3"),
		filepath.Join("videos.m4v", "sub", "report.pdf"),
	} {
		if got := MaxSizeForPath(name); got != MaxFileSize {
			t.Errorf("MaxSizeForPath(%q) = %d, want the flat MaxFileSize (%d) — only the FILE's "+
				"own extension may raise the ceiling", name, got, MaxFileSize)
		}
	}
}

// TestRouterVideoCeilingMatchesTheExtractor.
//
// The router must not admit a file the extractor then refuses. If MaxVideoFileSize rose above
// meta-extract-videolib.MaxFileSize, the refusal would move to a deeper layer whose message
// names a different number, which is the exact shape of #355: two gates disagreeing, and the
// operator told about the wrong one.
func TestRouterVideoCeilingMatchesTheExtractor(t *testing.T) {
	if MaxVideoFileSize != int64(meta_extract_videolib.MaxFileSize) {
		t.Errorf("router.MaxVideoFileSize = %d but meta-extract-videolib.MaxFileSize = %d.\n"+
			"The router decides what is admitted and the extractor decides what is read; if the "+
			"router is the larger, a file is admitted and then refused deeper down with a "+
			"message naming a limit the operator was never shown.",
			MaxVideoFileSize, meta_extract_videolib.MaxFileSize)
	}
}

// TestEveryExemptedExtensionReachesTheExtractor closes the gap my own notes call out: three
// separate lists have to agree for a video to be scanned at all, and adding a size exemption
// makes this the FOURTH consumer of "is this a video".
//
// An extension exempted here but absent from the extractor's list would be admitted at 500MB
// and then read by nothing — a bigger read for the same zero findings, which looks like the
// fix working while it does nothing.
func TestEveryExemptedExtensionReachesTheExtractor(t *testing.T) {
	// Derived from the extractor rather than written out, so a format added there is covered
	// here without editing this test.
	formats := meta_extract_videolib.GetSupportedVideoFormats()
	if len(formats) == 0 {
		t.Fatal("the extractor reports no supported formats; this test would be vacuous")
	}

	for _, ext := range formats {
		name := "probe" + ext
		if got := MaxSizeForPath(name); got != MaxVideoFileSize {
			t.Errorf("the extractor reads %s but MaxSizeForPath(%q) = %d, not the video ceiling "+
				"%d. The file is refused before the extractor that supports it, which is #410 "+
				"for that format.", ext, name, got, MaxVideoFileSize)
		}
		if !meta_extract_videolib.CanProcessVideo(name) {
			t.Errorf("GetSupportedVideoFormats lists %s but CanProcessVideo(%q) is false", ext, name)
		}
	}

	// And the reverse direction: nothing may be exempted that the extractor cannot read.
	supported := make(map[string]bool, len(formats))
	for _, ext := range formats {
		supported[strings.ToLower(ext)] = true
	}
	for _, ext := range videoSizeClass.GetVideoExtensions() {
		if !supported[strings.ToLower(ext)] {
			t.Errorf("%s is exempted to %dMB by MaxSizeForPath but the extractor does not read it, "+
				"so the larger read finds nothing", ext, MaxVideoFileSize/(1024*1024))
		}
	}
}

// TestMaxSizeForPathDoesNotAllocate pins the one performance property this function needs.
//
// It is called once per entry of a directory walk, so it sits on the hot path of every
// recursive scan. The obvious implementation — constructing a FileExtensionValidator per call —
// builds five maps each time, which would put five allocations on every file in the tree. The
// package-level value is what avoids that, and nothing else in the code says so.
//
// The bound is 1, not 0, and the difference is worth stating because the first version of this
// test asserted 0 against lower-case names only and would have passed while the upper-case path
// allocated. strings.ToLower inside IsVideoFile returns its input untouched when there is
// nothing to fold, so ".mp4" is allocation-free and ".MP4" costs exactly one — measured 0.0 and
// 1.0 per call. That allocation is inherited from IsVideoFile, which the video preprocessor's
// CanProcess already called per file, so it is not new here; a ceiling of 1 still catches the
// five-map mistake this test exists for.
func TestMaxSizeForPathDoesNotAllocate(t *testing.T) {
	cases := []struct {
		name string
		max  float64
	}{
		// Lower case: the fast path, and the spelling almost every real file uses.
		{"/some/dir/movie.mp4", 0},
		{"/some/dir/notes.txt", 0},
		// Upper case: one allocation from folding the extension, and no more.
		{"/some/dir/MOVIE.MP4", 1},
		{"/some/dir/NOTES.TXT", 1},
	}
	for _, tc := range cases {
		got := testing.AllocsPerRun(200, func() { _ = MaxSizeForPath(tc.name) })
		if got > tc.max {
			t.Errorf("MaxSizeForPath(%q) allocates %.1f times per call, want at most %.0f. It runs "+
				"once per file in a recursive walk; constructing the extension validator per call "+
				"would add five map allocations to every entry of the tree.", tc.name, got, tc.max)
		}
	}
}

// TestCanProcessFileAdmitsAnOversizeVideo is the end-to-end half at this layer: the gate inside
// CanProcessFile, not just the helper it consults.
//
// The fixture is sparse — Truncate sets the length without writing bytes — because the size is
// the only property under test and a real 200MB file per run is not worth the disk. The
// extractor is never invoked here; CanProcessFile only decides admission.
func TestCanProcessFileAdmitsAnOversizeVideo(t *testing.T) {
	dir := t.TempDir()

	cases := []struct {
		name       string
		size       int64
		wantOK     bool
		wantReason string
	}{
		{"movie.mp4", MaxFileSize + 1, true, ""},
		{"movie.mov", MaxVideoFileSize, true, ""},
		{"movie.m4v", MaxVideoFileSize + 1, false, "500MB"},
		{"notes.txt", MaxFileSize + 1, false, "100MB"},
	}

	fr := NewFileRouter(false)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name)
			f, err := os.Create(p) // #nosec G304 -- test temp dir
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(tc.size); err != nil {
				_ = f.Close()
				t.Skipf("cannot create a sparse %d-byte file here: %v", tc.size, err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}

			// Confirm the fixture really is the size we asked for, or every assertion below
			// is about a file that does not exist as described.
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() != tc.size {
				t.Fatalf("fixture is %d bytes, want %d", info.Size(), tc.size)
			}

			ok, reason := fr.CanProcessFile(p, true)

			if tc.wantOK && !ok {
				t.Errorf("CanProcessFile refused a %d-byte %s: %q\nThe extractor reads this "+
					"container up to %dMB, so refusing it here declines a file the tool can scan (#410).",
					tc.size, tc.name, reason, MaxVideoFileSize/(1024*1024))
			}
			if !tc.wantOK {
				if ok {
					t.Errorf("CanProcessFile ADMITTED a %d-byte %s; the ceiling must still bind",
						tc.size, tc.name)
				} else if !strings.Contains(reason, tc.wantReason) {
					// The number in the message has to be the number that refused, or the
					// operator is told to shrink the file below a threshold it already cleared.
					t.Errorf("reason = %q, want it to name %s", reason, tc.wantReason)
				}
			}
		})
	}
}
