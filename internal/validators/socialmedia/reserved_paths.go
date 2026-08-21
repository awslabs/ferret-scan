// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import "strings"

// Reserved first-path segments: a platform's own system pages, which are never anybody's profile.
//
// Most platform profile patterns carry a path prefix that disambiguates them — linkedin.com/in/,
// reddit.com/u/, bsky.app/profile/, and the /@handle forms (clubhouse, medium, threads, tiktok,
// mastodon). For those the first path segment is the prefix itself, so nothing here can apply to
// them. Eight platforms have no prefix, and for them any single path segment reads as a handle:
// facebook, instagram, pinterest, skype, telegram (t.me), twitch (twitch.tv), twitter/x, and
// discord (discord.gg). Those are the ones these tables exist for.
//
// Why a veto rather than a confidence penalty. validateNotFalsePositive is advisory: a failure
// costs 30 points at validator.go's scoring site. But the raw score for these URLs runs to 134
// before being capped at 100, so subtracting 30 leaves 104 — still capped to 100, still HIGH,
// still reported and still redacted. Measured on a fixture of 18 platform system URLs: every one
// scored 54-134 raw with false_positive_prevention exactly 0, and instagram.com/explore scored
// HIGHER (134) than the real profile instagram.com/reneemueller (124). No threshold can separate
// them, because there is no structural difference between the two — only vocabulary. So the
// discriminator has to be categorical.
//
// Why that is safe in the direction that matters. A wrong entry here suppresses a real finding,
// and a suppressed finding is a cleartext leak (only reported findings reach the redactor), so
// every entry must be a name the platform genuinely reserves and nobody can register. Matching is
// against the WHOLE segment, case-folded: instagram.com/exploration is not instagram.com/explore.
// The generic set below is limited to names reserved on every consumer platform; anything
// platform-specific, or that could plausibly be somebody's handle elsewhere, lives in the
// per-platform table instead of the shared one.
//
// Grounding. The per-platform entries are taken from each platform's own robots.txt Disallow list
// where it publishes one — pinterest.com/robots.txt names over 120 system segments, facebook's and
// twitter's name theirs — plus the platforms' documented feature paths. robots.txt is authoritative
// but incomplete (twitter publishes four segments, pinterest a hundred), which is why these tables
// do not attempt to be exhaustive: they cover the system pages that actually turn up cited in
// documents. An uncovered system path stays a false positive, which is the tolerable direction of
// error.

// sharedReservedPaths are first-path segments reserved as system pages on every consumer platform.
// No platform permits registering these as a profile name.
var sharedReservedPaths = map[string]struct{}{
	"about":         {},
	"account":       {},
	"accounts":      {},
	"admin":         {},
	"api":           {},
	"careers":       {},
	"contact":       {},
	"developer":     {},
	"developers":    {},
	"explore":       {},
	"faq":           {},
	"help":          {},
	"legal":         {},
	"login":         {},
	"logout":        {},
	"messages":      {},
	"notifications": {},
	"policies":      {},
	"policy":        {},
	"press":         {},
	"privacy":       {},
	"register":      {},
	"search":        {},
	"security":      {},
	"settings":      {},
	"signin":        {},
	"signup":        {},
	"support":       {},
	"terms":         {},
	"tos":           {},
}

// platformReservedPaths holds segments reserved by one platform in particular. Kept separate from
// the shared set because several — "business", "home", "today", "tv" — are plausible handles on a
// platform that does not reserve them, and vetoing those would suppress a real profile.
var platformReservedPaths = map[string]map[string]struct{}{
	"instagram": {
		"archive":   {},
		"business":  {},
		"challenge": {},
		"creators":  {},
		"direct":    {},
		"directory": {},
		"emails":    {},
		"invites":   {},
		"oauth":     {},
		"p":         {},
		"reel":      {},
		"reels":     {},
		"session":   {},
		"stories":   {},
		"tv":        {},
		"web":       {},
	},
	"pinterest": {
		"board":        {},
		"business":     {},
		"categories":   {},
		"discover":     {},
		"homefeed":     {},
		"ideas":        {},
		"invite":       {},
		"join":         {},
		"news_hub":     {},
		"oauth":        {},
		"password":     {},
		"pin":          {},
		"place":        {},
		"prefs":        {},
		"secure":       {},
		"shop":         {},
		"source":       {},
		"today":        {},
		"topics":       {},
		"tv":           {},
		"videos":       {},
		"website":      {},
		"welcome":      {},
		"your-shop":    {},
		"live-session": {},
	},
	"facebook": {
		"ads":         {},
		"adsmanager":  {},
		"ajax":        {},
		"bookmarks":   {},
		"business":    {},
		"checkpoint":  {},
		"community":   {},
		"dialog":      {},
		"events":      {},
		"feeds":       {},
		"friends":     {},
		"gaming":      {},
		"groups":      {},
		"hashtag":     {},
		"marketplace": {},
		"memories":    {},
		"notes":       {},
		"pages":       {},
		"permalink":   {},
		"plugins":     {},
		"safety":      {},
		"saved":       {},
		"share":       {},
		"sharer":      {},
		"watch":       {},
	},
	"twitter": {
		"bookmarks":       {},
		"compose":         {},
		"download":        {},
		"followers":       {},
		"following":       {},
		"hashtag":         {},
		"home":            {},
		"i":               {},
		"intent":          {},
		"lists":           {},
		"moments":         {},
		"oauth":           {},
		"personalization": {},
		"share":           {},
		"status":          {},
		"statuses":        {},
		"topics":          {},
		"who_to_follow":   {},
		"widgets":         {},
	},
	"telegram": {
		"addemoji":     {},
		"addlist":      {},
		"addstickers":  {},
		"addtheme":     {},
		"bg":           {},
		"c":            {},
		"confirmphone": {},
		"iv":           {},
		"joinchannel":  {},
		"joinchat":     {},
		"proxy":        {},
		"s":            {},
		"setlanguage":  {},
		"share":        {},
		"socks":        {},
	},
	"twitch": {
		"broadcast":     {},
		"communities":   {},
		"dashboard":     {},
		"directory":     {},
		"downloads":     {},
		"drops":         {},
		"friends":       {},
		"inventory":     {},
		"jobs":          {},
		"moderator":     {},
		"popout":        {},
		"prime":         {},
		"products":      {},
		"subscriptions": {},
		"team":          {},
		"teams":         {},
		"turbo":         {},
		"videos":        {},
		"wallet":        {},
	},
	// skype.com hosts no user profiles at all — it is a product site, so every segment is a
	// system page. Only the segments that actually appear in cited URLs are listed; the locale
	// codes it also serves are open-ended and are left alone.
	"skype": {
		"blogs":     {},
		"business":  {},
		"community": {},
		"de":        {},
		"download":  {},
		"en":        {},
		"en-us":     {},
		"es":        {},
		"features":  {},
		"fr":        {},
		"it":        {},
		"ja":        {},
		"plans":     {},
		"pricing":   {},
		"rates":     {},
	},
}

// firstPathSegment returns the first path segment of a matched URL, and whether there was one.
//
// It reports false for a match with no path at all — a bare @handle, a skype: URI, a
// sub.medium.com host — because there is then no segment to judge and the veto must not apply.
func firstPathSegment(match string) (string, bool) {
	s := match
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}

	// The host runs to the first slash. Without one, the match carries no path.
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return "", false
	}

	seg := s[slash+1:]
	if i := strings.IndexAny(seg, "/?#"); i >= 0 {
		seg = seg[:i]
	}
	if seg == "" {
		return "", false
	}
	return seg, true
}

// isReservedPlatformPath reports whether match addresses one of the platform's own system pages
// rather than somebody's profile.
func isReservedPlatformPath(match, platform string) bool {
	seg, ok := firstPathSegment(match)
	if !ok {
		return false
	}
	seg = strings.ToLower(seg)

	// Trailing dots and the .php suffix Facebook still serves (permalink.php, sharer.php) are not
	// part of the reserved name; its robots.txt lists these segments with the suffix attached.
	//
	// Note what this means for "profile": facebook.com/profile.php?id=<n> IS a real person's
	// profile — the shipped config has a pattern dedicated to it — and this trim would turn it
	// into a lookup for "profile". So "profile" must never be added to the facebook table below;
	// doing so would suppress a genuine profile reference into cleartext.
	seg = strings.TrimSuffix(seg, ".php")
	seg = strings.Trim(seg, ".")
	if seg == "" {
		return false
	}

	if _, reserved := sharedReservedPaths[seg]; reserved {
		return true
	}

	// Platform keys reach this package in both the bare and the "<platform>_patterns" form, so
	// normalise before the lookup rather than spelling both out — every platform switch in
	// validator.go accepts both spellings and this has to agree with them.
	key := strings.TrimSuffix(strings.ToLower(platform), "_patterns")
	if extra, ok := platformReservedPaths[key]; ok {
		if _, reserved := extra[seg]; reserved {
			return true
		}
	}
	return false
}
