// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docs/reference/quotas-and-limits.md publishes the size ceilings, and an operator deciding
// whether to split a 200MB recording reads that table rather than the source.
//
// The document has a history of describing code that no longer exists: two "Corrected 2026-08"
// notes in it record a whole performance table whose every row described deleted code, and two
// error strings the tool has never been able to emit. #410 is the same failure in the other
// direction — the table said "100MB is the effective limit for every file type, including audio
// and video", which was TRUE of shipped behaviour and true only because a gate was refusing files
// the extractor supported.
//
// Every expected string is BUILT from the constants rather than written out, so changing a
// ceiling in code fails this test until the document is updated too. This follows
// TestDocumentedWorkerCapMatchesTheCode in internal/parallel, which exists for the same reason.

// docPath is internal/router -> repo root.
func quotasDocPath() string {
	return filepath.Join("..", "..", "docs", "reference", "quotas-and-limits.md")
}

func readQuotasDoc(t *testing.T) (string, string) {
	t.Helper()
	p := quotasDocPath()
	raw, err := os.ReadFile(p) // #nosec G304 -- a fixed path inside the repo
	if err != nil {
		t.Skipf("cannot read %s: %v", p, err)
	}
	return string(raw), p
}

// TestDocumentedSizeLimitsMatchTheCode.
func TestDocumentedSizeLimitsMatchTheCode(t *testing.T) {
	doc, p := readQuotasDoc(t)

	for _, want := range []string{
		fmt.Sprintf("%dMB", MaxVideoFileSize/(1024*1024)),
		fmt.Sprintf("%dMB", MaxFileSize/(1024*1024)),
		"router.MaxVideoFileSize",
		"router.MaxSizeForPath",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("%s does not mention %q. It is the table an operator reads before deciding "+
				"whether a file can be scanned at all.", p, want)
		}
	}

	// Every exempted extension has to appear, because the exemption is applied BY extension and
	// a reader with a .3gp cannot infer it from a table that only names .mp4.
	for _, ext := range videoSizeClass.GetVideoExtensions() {
		if !strings.Contains(doc, ext) {
			t.Errorf("%s does not name %s, which MaxSizeForPath exempts to %dMB. An operator with "+
				"that format would read the 100MB row and split a file needlessly.",
				p, ext, MaxVideoFileSize/(1024*1024))
		}
	}
}

// TestTheDocumentNoLongerClaimsOneLimitForEveryType.
//
// This is the specific sentence #410 falsified. It is checked in its own test because the claim
// is the thing that misled, not the numbers around it — and it must be permitted on a blockquote
// line, since the document deliberately records what it used to say in "> Corrected" notes and a
// plain Contains check would push the next person to delete that history.
func TestTheDocumentNoLongerClaimsOneLimitForEveryType(t *testing.T) {
	doc, p := readQuotasDoc(t)

	stale := []string{
		"100MB is the effective limit for every file type, including audio and video",
		"ceilings are never reached",
	}
	for _, claim := range stale {
		for i, line := range strings.Split(doc, "\n") {
			if !strings.Contains(line, claim) {
				continue
			}
			if strings.HasPrefix(strings.TrimSpace(line), ">") {
				continue // a deliberate record of what the document used to say
			}
			t.Errorf("%s:%d still asserts %q as current behaviour.\nA video container is admitted "+
				"to %dMB (#410), so this tells an operator to split a file the tool would scan.",
				p, i+1, claim, MaxVideoFileSize/(1024*1024))
		}
	}
}

// TestTheDocumentStillSaysAudioIsNotExempt.
//
// The exemption is video-only and that is a MEASURED decision, not an oversight: audio is capped
// at 100MB by three gates downstream, so a raised ceiling there yields nothing. Someone reading
// the video row could reasonably assume audio followed, and the document has to say it does not —
// otherwise the next person to "finish the job" reintroduces the allowance #355 removed.
func TestTheDocumentStillSaysAudioIsNotExempt(t *testing.T) {
	doc, p := readQuotasDoc(t)
	if !strings.Contains(doc, "Audio is deliberately not exempt") {
		t.Errorf("%s does not record that audio is deliberately excluded from the video size "+
			"exemption. Without it the exclusion reads as an omission, and restoring the "+
			"allowance is the bug #355 was filed for.", p)
	}
}
