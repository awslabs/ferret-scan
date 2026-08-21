// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"
	"testing"
)

// systemURLs are platform system pages. None of them is a profile, and citing one in a document
// is ordinary prose.
var systemURLs = []string{
	"instagram.com/explore",
	"instagram.com/reels",
	"instagram.com/tv",
	"instagram.com/legal",
	"instagram.com/about",
	"pinterest.com/today",
	"pinterest.com/business",
	"pinterest.com/categories",
	"facebook.com/help",
	"facebook.com/privacy",
	"facebook.com/business",
	"facebook.com/legal",
	"twitter.com/home",
	"twitter.com/settings",
	"twitter.com/tos",
	"x.com/explore",
	"t.me/joinchat",
	"t.me/share",
	"twitch.tv/directory",
	"skype.com/features",
}

// profileURLs are real profiles on the same prefix-less platforms. Every one must stay detected:
// only reported findings reach the redactor, so suppressing one of these is a cleartext leak.
var profileURLs = []string{
	"instagram.com/reneemueller",
	"pinterest.com/johnsmith",
	"facebook.com/carlos.ramirez",
	"twitter.com/kwilson",
	"t.me/dcheng",
	"twitch.tv/mgarcia",
}

// platformOf maps each fixture URL to the platform key the scanner would pass alongside it.
func platformOf(t *testing.T, url string) string {
	t.Helper()
	switch {
	case strings.Contains(url, "instagram.com"), strings.Contains(url, "instagr.am"):
		return "instagram"
	case strings.Contains(url, "pinterest.com"):
		return "pinterest"
	case strings.Contains(url, "facebook.com"), strings.Contains(url, "fb.com"):
		return "facebook"
	case strings.Contains(url, "twitter.com"), strings.Contains(url, "x.com"):
		return "twitter"
	case strings.Contains(url, "t.me"):
		return "telegram"
	case strings.Contains(url, "twitch.tv"):
		return "twitch"
	case strings.Contains(url, "skype.com"):
		return "skype"
	case strings.Contains(url, "linkedin.com"):
		return "linkedin"
	case strings.Contains(url, "reddit.com"):
		return "reddit"
	case strings.Contains(url, "medium.com"):
		return "medium"
	case strings.Contains(url, "tiktok.com"):
		return "tiktok"
	case strings.Contains(url, "bsky.app"):
		return "bluesky"
	case strings.Contains(url, "snapchat.com"):
		return "snapchat"
	}
	t.Fatalf("fixture %q has no platform mapping; add one rather than letting it fall through to "+
		"a key with no reserved table, which would make the assertion vacuous", url)
	return ""
}

// The two directions are asserted on ONE fixture set, in one test, deliberately.
//
// They pull against each other: a suppressor wide enough to kill every system URL also kills real
// profiles, and a suppressor narrow enough to spare every profile catches nothing. Asserted apart,
// a fix for either half looks correct on its own — `return false` passes the profile half and
// `return true` passes the system half. Only together do they pin the discriminator.
func TestReservedPathsSuppressSystemURLsAndSpareProfiles(t *testing.T) {
	for _, url := range systemURLs {
		if !isReservedPlatformPath(url, platformOf(t, url)) {
			t.Errorf("%q was NOT recognised as a system page, so it is reported as somebody's "+
				"profile and the redactor overwrites it — a documentation URL is corrupted in the "+
				"redacted copy", url)
		}
	}
	for _, url := range profileURLs {
		if isReservedPlatformPath(url, platformOf(t, url)) {
			t.Errorf("%q was suppressed as a system page, but it is a real profile. A suppressed "+
				"finding never reaches the redactor, so this is a cleartext leak", url)
		}
	}
}

// A reserved word must match the WHOLE path segment. Substring matching here would suppress real
// handles that merely contain a reserved word, which is the leak direction.
func TestReservedPathsMatchWholeSegmentsOnly(t *testing.T) {
	for _, url := range []string{
		"instagram.com/exploration", // contains "explore"
		"instagram.com/helper",      // contains "help"
		"instagram.com/aboutface",   // contains "about"
		"pinterest.com/todayshow",   // contains "today"
		"twitter.com/homer",         // contains "home"
		"t.me/shared",               // contains "share"
		"twitch.tv/teamwork",        // contains "team"
		"facebook.com/sharert",      // contains "share"
	} {
		if isReservedPlatformPath(url, platformOf(t, url)) {
			t.Errorf("%q was suppressed: a reserved word is being matched as a substring rather "+
				"than as the whole segment, so real handles containing one are leaked", url)
		}
	}
}

// Platforms whose profile pattern carries a path prefix put the handle in the SECOND segment, so a
// reserved word appearing there is part of somebody's handle and must be left alone. This is what
// makes it safe to apply the shared table to every platform.
func TestReservedPathsIgnoreHandlesBehindAPathPrefix(t *testing.T) {
	for _, url := range []string{
		"linkedin.com/in/about",
		"reddit.com/user/privacy",
		"medium.com/@help",
		"tiktok.com/@legal",
		"bsky.app/profile/terms",
		"snapchat.com/add/settings",
	} {
		if isReservedPlatformPath(url, platformOf(t, url)) {
			t.Errorf("%q was suppressed: only the FIRST path segment may be judged, and here that "+
				"segment is the platform's own prefix, not a reserved name", url)
		}
	}
}

// Real documents cite these URLs in every shape. Suppression must not depend on the scheme, the
// www. prefix, letter case, a deeper path, or the short domain.
func TestReservedPathsNormaliseTheURLShape(t *testing.T) {
	for _, url := range []string{
		"https://www.instagram.com/explore",
		"http://instagram.com/legal",
		"INSTAGRAM.COM/EXPLORE",
		"Instagram.com/Reels",
		"https://instagr.am/about",
		"instagram.com/explore/tags/summer", // deeper path, same system page
		"instagram.com/explore?hl=en",       // query string
	} {
		if !isReservedPlatformPath(url, "instagram") {
			t.Errorf("%q was not recognised: the shape of the URL is changing the verdict, so the "+
				"same system page is suppressed in one document and reported in another", url)
		}
	}
}

// facebook.com/profile.php?id=<n> is a REAL profile and the shipped config has a pattern dedicated
// to it. The .php trim that lets "sharer.php" match "sharer" turns this into a lookup for
// "profile", so adding "profile" to the facebook table would suppress a genuine profile into
// cleartext. This pins that it is absent.
func TestFacebookProfilePHPIsNotTreatedAsASystemPage(t *testing.T) {
	if isReservedPlatformPath("facebook.com/profile.php?id=61550000000000", "facebook") {
		t.Error("facebook.com/profile.php was suppressed as a system page, but it identifies a " +
			"specific person — the .php trim maps it onto \"profile\", which must never be a " +
			"reserved segment for facebook")
	}
	// The trim must still do its job for the segments that ARE reserved.
	if !isReservedPlatformPath("facebook.com/sharer.php?u=x", "facebook") {
		t.Error("facebook.com/sharer.php was not suppressed: the .php trim is not reaching the " +
			"reserved table, so every one of Facebook's .php system endpoints stays a false positive")
	}
}

// A match with no path at all — a bare @handle, a skype: URI, a bare host — carries no segment to
// judge, and the veto must not fire on it.
func TestReservedPathsRequireAPathSegment(t *testing.T) {
	for _, match := range []string{
		"@explore",
		"skype:legal",
		"about.medium.com",
		"instagram.com",
		"instagram.com/",
	} {
		if isReservedPlatformPath(match, "instagram") {
			t.Errorf("%q was suppressed although it has no first path segment; the veto is firing "+
				"on something other than a path", match)
		}
	}
}

// firstPathSegment's contract, asserted directly.
//
// Its "no path means no verdict" half is not observable through isReservedPlatformPath today: no
// shipped pattern can produce a bare token equal to a reserved name (the handle patterns all carry
// @, skype: carries a colon, the medium subdomain form carries dots), so a version that returned
// the whole host instead would behave identically. Pinning the helper keeps that from silently
// becoming a leak if a future pattern does match a bare word.
func TestFirstPathSegment(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"instagram.com/explore", "explore", true},
		{"https://www.instagram.com/explore", "explore", true},
		{"http://instagram.com/explore/tags/x", "explore", true},
		{"instagram.com/explore?hl=en", "explore", true},
		{"instagram.com/explore#top", "explore", true},
		{"t.me/s/channel", "s", true},
		// No path at all: there is nothing to judge, and the veto must not fire.
		{"instagram.com", "", false},
		{"@explore", "", false},
		{"skype:legal", "", false},
		{"about.medium.com", "", false},
		{"instagram.com/", "", false},
	}
	for _, c := range cases {
		got, ok := firstPathSegment(c.in)
		if got != c.want || ok != c.wantOK {
			t.Errorf("firstPathSegment(%q) = (%q, %v), want (%q, %v)", c.in, got, ok, c.want, c.wantOK)
		}
	}
}

// The platform key reaches this package in both spellings. Every platform switch in validator.go
// accepts "<platform>" and "<platform>_patterns", and this table has to agree with them or the
// per-platform entries silently never apply.
func TestReservedPathsAcceptBothPlatformKeySpellings(t *testing.T) {
	for _, key := range []string{"instagram", "instagram_patterns", "Instagram"} {
		if !isReservedPlatformPath("instagram.com/reels", key) {
			t.Errorf("platform key %q did not resolve to the instagram table, so its "+
				"platform-specific reserved segments never apply", key)
		}
	}
	// A platform with no table of its own still gets the shared set.
	if !isReservedPlatformPath("twitch.tv/settings", "twitch") {
		t.Error("the shared reserved set did not apply to twitch")
	}
	// And an unknown platform gets the shared set only, without panicking on the missing table.
	if !isReservedPlatformPath("example.com/privacy", "someplatform") {
		t.Error("the shared reserved set did not apply to an unknown platform")
	}
	if isReservedPlatformPath("example.com/reels", "someplatform") {
		t.Error("an unknown platform picked up instagram's platform-specific entries")
	}
}

// The end-to-end assertion: the veto has to be reached from the scanning path, not merely be
// correct in isolation. A helper that no emit path consults would pass every test above.
//
// Uses the SHIPPED config via configuredValidator — a bare NewValidator leaves patternsConfigured
// false and ValidateContent returns nothing at all, which would make both halves vacuous.
func TestValidatorDoesNotReportSystemURLsButStillReportsProfiles(t *testing.T) {
	v := configuredValidator(t)

	content := "Docs: instagram.com/explore and pinterest.com/today and twitter.com/settings\n" +
		"Contact: instagram.com/reneemueller\n"

	matches, err := v.ValidateContent(content, "policy.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}

	// Matched on the bare segment name, NOT on "/explore".
	//
	// Several system URLs on one line are collapsed by the clustering pass into a single
	// SOCIAL_MEDIA_CLUSTER match whose Text is a synthesised summary — here
	// "instagram: explore | pinterest: today | twitter: settings" — which contains no slashes and
	// does not appear in the file at all. An earlier version of this test looked for "/explore"
	// and so passed with the veto's call site disabled: the three URLs were still reported, just
	// under a shape the assertion could not see.
	segments := []string{"explore", "today", "settings"}

	var sawProfile bool
	for _, m := range matches {
		lower := strings.ToLower(m.Text)

		var namesSystemPage bool
		for _, seg := range segments {
			if strings.Contains(lower, seg) {
				namesSystemPage = true
				t.Errorf("a reported %s match still names the system page %q (text %q, confidence "+
					"%v): the reserved-path veto is not reached from the scanning path, so these "+
					"URLs are reported and the redactor overwrites them", m.Type, seg, m.Text,
					m.Confidence)
			}
		}
		if !namesSystemPage && strings.Contains(lower, "reneemueller") {
			sawProfile = true
		}
	}

	if !sawProfile {
		t.Error("the real profile instagram.com/reneemueller was NOT reported, so it is never " +
			"redacted — and the system-page assertion above would hold on a validator that " +
			"reports nothing at all")
	}
}
