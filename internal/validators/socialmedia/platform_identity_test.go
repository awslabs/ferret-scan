// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The platform is an INPUT to a social media score, not a label on the result: roughly ten
// validations in calculateConfidenceForPlatform take it as an argument (validateURLFormat,
// validateDomain, validateUsernameFormat, validatePatternSpecificity ...).
//
// identifyPlatform used to answer by ranging v.compiledPatterns and returning the first
// platform whose pattern matched ANYWHERE. Both halves were wrong for an overlapping value:
// Go randomizes map iteration, and a 7-character substring hit counted the same as a
// 36-character whole-string hit. Measured through the CLI on
// "https://www.youtube.com/@tkaminski_1", 30 identical runs of one binary: the underlying
// match scored 100 in 18 runs and 17 in 12, and the split was visible in the report as the
// original_confidences metadata.

const overlappingHandleURL = "https://www.youtube.com/@tkaminski_1"

// TestIdentifyPlatformIsDeterministic ranges the map many times in ONE process, which is
// where Go's per-range randomization shows up. A cross-process comparison would be a weaker
// test: it can also pass by luck.
func TestIdentifyPlatformIsDeterministic(t *testing.T) {
	v := newConfiguredValidator()

	for _, match := range []string{
		overlappingHandleURL,
		"https://twitter.com/tkaminski_1",
		"@tkaminski_1",
		"https://www.linkedin.com/in/some-person",
	} {
		t.Run(match, func(t *testing.T) {
			first := v.identifyPlatform(match)
			if first == "" {
				t.Fatalf("no platform identified for %q, so determinism is untested", match)
			}
			for i := 0; i < 500; i++ {
				if got := v.identifyPlatform(match); got != first {
					t.Fatalf("iteration %d returned %q, first call returned %q", i, got, first)
				}
			}
		})
	}
}

// TestIdentifyPlatformBreaksATieDeterministically is what makes the SORTED iteration
// load-bearing rather than decorative.
//
// Longest-match-wins is already order-independent whenever one platform's pattern matches more
// of the value than another's, which is the normal case — so a test using only realistic
// patterns passes with map iteration restored. A genuine tie is the one case where the
// iteration order decides, and two platforms claiming the identical span is exactly that.
// Sorted order sends the tie to the lexicographically first platform, every time.
func TestIdentifyPlatformBreaksATieDeterministically(t *testing.T) {
	v := NewValidator()
	const tied = `(?i)dualclaim\.example/[a-z0-9_]+`
	v.platformPatterns = map[string][]string{
		"zebra":    {tied},
		"linkedin": {tied},
		"alpha":    {tied},
	}
	v.patternsConfigured = true
	v.compilePlatformPatterns()

	const match = "dualclaim.example/person1"
	if got := v.identifyPlatform(match); got != "alpha" {
		t.Errorf("identifyPlatform(%q) = %q, want the lexicographically first tied platform "+
			"%q", match, got, "alpha")
	}
	for i := 0; i < 500; i++ {
		if got := v.identifyPlatform(match); got != "alpha" {
			t.Fatalf("iteration %d returned %q: a tie is still resolved by map order", i, got)
		}
	}
}

// TestIdentifyPlatformPrefersTheLongerMatch is the correctness half. Determinism alone could
// be satisfied by always answering "twitter" for a YouTube URL, which would be stably wrong.
func TestIdentifyPlatformPrefersTheLongerMatch(t *testing.T) {
	v := newConfiguredValidator()

	// Both platforms match this value: youtube's URL pattern spans the whole string,
	// twitter's bare "@handle" pattern spans 12 characters of it.
	ytMatched, twMatched := false, false
	for _, re := range v.compiledPatterns["youtube"] {
		if re.MatchString(overlappingHandleURL) {
			ytMatched = true
		}
	}
	for _, re := range v.compiledPatterns["twitter"] {
		if re.MatchString(overlappingHandleURL) {
			twMatched = true
		}
	}
	if !ytMatched || !twMatched {
		t.Fatalf("fixture no longer overlaps (youtube=%v twitter=%v); pick a value both "+
			"platforms match or this test proves nothing", ytMatched, twMatched)
	}

	if got := v.identifyPlatform(overlappingHandleURL); got != "youtube" {
		t.Errorf("identifyPlatform(%q) = %q, want youtube: the platform whose pattern "+
			"explains the whole value should win over one matching a substring",
			overlappingHandleURL, got)
	}
}

// TestScoreIsStableForAnOverlappingMatch drives the scoring entry point rather than the
// helper, so it covers the path the scanner actually takes.
func TestScoreIsStableForAnOverlappingMatch(t *testing.T) {
	v := newConfiguredValidator()

	first, _ := v.CalculateConfidence(overlappingHandleURL)
	for i := 0; i < 500; i++ {
		if got, _ := v.CalculateConfidence(overlappingHandleURL); got != first {
			t.Fatalf("iteration %d scored %.0f, first call scored %.0f — the platform used "+
				"for scoring is still being re-derived from a map range", i, got, first)
		}
	}
	if first <= 0 {
		t.Fatalf("scored %.0f, so stability is being measured on a rejected match", first)
	}
}

// TestValidateContentIsStableAcrossRuns is the end-to-end form: the reported findings for one
// input must be identical every time, values and confidences included.
func TestValidateContentIsStableAcrossRuns(t *testing.T) {
	v := newConfiguredValidator()
	content := strings.Join([]string{
		"Follow me: " + overlappingHandleURL,
		"Connect with me: https://www.linkedin.com/in/some-person",
		"Profile: https://www.instagram.com/user_42",
	}, "\n")

	fingerprint := func() string {
		matches, err := v.ValidateContent(content, "profiles.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		rows := make([]string, 0, len(matches))
		for _, m := range matches {
			rows = append(rows, m.Text+"|"+m.Type)
		}
		sort.Strings(rows)
		return strings.Join(rows, ",")
	}

	want := fingerprint()
	if want == "" {
		t.Fatalf("no findings, so stability is untested")
	}
	for i := 0; i < 100; i++ {
		if got := fingerprint(); got != want {
			t.Fatalf("run %d produced %q, first run produced %q", i, got, want)
		}
	}
}

// TestSortedPlatformsMatchesCompiledPatterns keeps the cached iteration order honest. It is
// rebuilt wherever compiledPatterns is finalised, and a future assignment that forgets to
// rebuild would leave identifyPlatform silently skipping a platform.
func TestSortedPlatformsMatchesCompiledPatterns(t *testing.T) {
	v := newConfiguredValidator()

	want := make([]string, 0, len(v.compiledPatterns))
	for platform := range v.compiledPatterns {
		want = append(want, platform)
	}
	sort.Strings(want)

	got := v.sortedCompiledPlatforms()
	if len(got) != len(want) {
		t.Fatalf("sortedCompiledPlatforms has %d entries, compiledPatterns has %d: %v vs %v",
			len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("position %d: got %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
	if !sort.StringsAreSorted(got) {
		t.Errorf("not sorted: %v", got)
	}
}

// TestSortedPlatformsIsRebuiltOnReconfiguration covers the reset path: loading a second
// configuration must not leave the previous platform list behind.
func TestSortedPlatformsIsRebuiltOnReconfiguration(t *testing.T) {
	v := newConfiguredValidator()
	before := append([]string(nil), v.sortedCompiledPlatforms()...)
	if len(before) < 2 {
		t.Fatalf("fixture has %d platforms; need at least 2 to see a change", len(before))
	}

	v.platformPatterns = map[string][]string{
		"twitter": {`(?i)https?://(?:www\.)?twitter\.com/[a-zA-Z0-9_]{1,15}`},
	}
	v.compilePlatformPatterns()

	after := v.sortedCompiledPlatforms()
	if len(after) != 1 || after[0] != "twitter" {
		t.Errorf("after reconfiguration got %v, want [twitter]: the cached order is stale", after)
	}
}

// TestIdentifyPlatformFallbackStillWorks pins the domain-based fallback chain, which is what
// answers when no configured pattern matches. The longest-match loop must not shadow it.
func TestIdentifyPlatformFallbackStillWorks(t *testing.T) {
	v := NewValidator()
	// No configured patterns at all: SOCIAL_MEDIA ships none, so this is the default state.
	v.compiledPatterns = map[string][]*regexp.Regexp{}
	v.rebuildSortedPlatforms()

	for _, tc := range []struct{ match, want string }{
		{"https://www.linkedin.com/in/person", "linkedin"},
		{"https://twitter.com/person", "twitter"},
		{"https://www.youtube.com/@person", "youtube"},
		{"https://tiktok.com/@person", "tiktok"},
		{"@person", "twitter"},
	} {
		if got := v.identifyPlatform(tc.match); got != tc.want {
			t.Errorf("identifyPlatform(%q) = %q, want %q", tc.match, got, tc.want)
		}
	}
}
