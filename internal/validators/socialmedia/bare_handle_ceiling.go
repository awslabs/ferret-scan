// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/validators"
)

// A bare "@token" and a full profile URL are not equal evidence, and until now they scored the same.
//
// `@echo` in a Makefile and `https://twitter.com/awscloud` both reported TWITTER at 100, HIGH.
// Measured on this repository with social_media enabled: 387 of 504 findings were TWITTER, and 346 of
// those — 89% — came from one Makefile, `@echo` alone accounting for 270. Every one is a false
// positive. The only real handles in the scan were examples quoted in CHANGELOG.md by this
// validator's own documentation.
//
// # Why a ceiling and not another veto
//
// handle_syntax.go already vetoes CSS at-rules and JSON-LD keywords, and its comment records that
// reaching a safe veto took two leaks: a position-only rule silenced a one-handle-per-line mentions
// export and a handle-keyed JSON roster, and on the roster it produced NO redacted file at all, at
// exit 0. Vetoes in this validator have a bad history because a suppressed finding is a cleartext
// leak — only reported findings reach the redactor.
//
// A vocabulary veto also cannot keep up. Make (`@echo`, `@if`, `@go`), CSS (`@media`), JSDoc
// (`@returns`), JSON-LD (`@type`), Docker digests (`@sha256:`), email, IRC and shell all use a
// leading `@`, and each new format needs another list. The lists rot: an entry that names a TABLE
// rather than a column, or a term that turns out to be ordinary English, reads like a working guard
// while matching nothing or everything.
//
// So this demotes instead. dual_path_bridge.clampToCeiling states the contract:
//
//	"Deliberately a clamp and not a drop: only reported findings reach the redactor, so removing a
//	 finding would leave its value in the redacted output. A demoted finding is still reported and
//	 still redacted."
//
// That is exactly the property wanted here. `@echo` stops being a HIGH finding without ever being
// suppressed, so a `--confidence high` run is clean while a value that IS a handle is still reported
// and still redacted. It applies to every format at once, present and future, with no vocabulary.
//
// # Why a ceiling and not the existing penalty
//
// validateNotFalsePositive already exists and the caller turns it into a -30 penalty. It does not
// work, and handle_syntax.go says why: "these score 100 and the raw score runs higher still, so the
// cap absorbs the penalty entirely." A penalty subtracted before a cap is a no-op. A ceiling is
// applied AFTER every adjustment that can raise confidence, including the +20 context adjustment and
// the cross-path correlation boost, which is the whole reason ConfidenceCeilingKey exists.

// bareHandleCeiling is the confidence a bare, uncorroborated "@token" may not exceed.
//
// 55, which is inside the LOW band (the bands are 90 and 60), so an uncorroborated token is excluded
// by `--confidence high` and by `--confidence high,medium` alike — the two views a reviewer actually
// uses. It is deliberately NOT 0: the value is still reported, still counted and still redacted, and
// a reviewer asking for everything still sees it.
const bareHandleCeiling = 55.0

// socialCorroboration are the phrases that make a bare "@token" a handle rather than syntax.
//
// PHRASES AND PLATFORM NAMES ONLY — no bare generic word, and that constraint was measured rather
// than reasoned. A first version held "handle", "username", "follow" and "following", matched as
// substrings. On 400 real JavaScript files from /Library, /Applications and local projects:
//
//	handle      66 files (16.5%)   <- "handleClick", "handleRequest", "file handle"
//	follow      27 files
//	following   17 files           <- "the following steps"
//	username    15 files
//	mentions     0 files
//	twitter      0 files
//
// So one real JS file in five lifted the ceiling on a word that has nothing to do with social media —
// `function handleClick()` alone promoted a JSDoc `@returns` out of the LOW band. Two entries did all
// the damage and neither was about Twitter.
//
// The rule this settles on: an entry must be a platform name, or a multi-word phrase, or a compound a
// document only writes when it means an account. "follow us" is safe where "follow" is not; "twitter
// handle" is safe where "handle" is not. Note the asymmetry with the substring matching below — the
// entries are chosen so that substring matching is harmless, rather than the matching being tightened
// to rescue bad entries.
//
// Deliberately ABSENT, each for a measured or stated reason:
//
//   - "handle", "username" — see the table above.
//   - "follow", "following" — the verb is ordinary English; "followers" and "follow us" are kept.
//   - "threads" — the platform shares its name with concurrency. "threads.net" is kept instead.
//   - "profile" — appears in every settings page and every performance tool.
var socialCorroboration = []string{
	// Platform names. Specific enough to stand alone; measured at 0 occurrences across 400 real JS files.
	"twitter", "x.com", "tweet", "retweet",
	"instagram", "mastodon", "bluesky", "threads.net",
	// Mentions, which is what a bare handle IS.
	"@mention", "mentions", "mentioned by",
	// Phrases. Each names an account rather than describing an action on one.
	"follow us", "follow me", "followers",
	"twitter handle", "social handle", "handle is",
	"screen name", "social media", "socialmedia",
}

// isBareHandle reports whether a match is a bare "@token" rather than a URL.
//
// A URL carries the platform in the value itself — nothing but Twitter produces
// "twitter.com/awscloud" — so it needs no corroboration and keeps its score. This is the whole
// distinction the change rests on, so it is decided on the VALUE and not on the pattern index, which
// a config can reorder.
func isBareHandle(match string) bool {
	if !strings.HasPrefix(match, "@") {
		return false
	}
	return !strings.Contains(match, "/") && !strings.Contains(match, ":")
}

// hasSocialCorroboration reports whether the context around a match says social media.
func hasSocialCorroboration(ctx detector.ContextInfo) bool {
	// FullLine is not always a superset of BeforeText+AfterText — see the context-population
	// matrix — so all three are read rather than assuming one covers the others.
	haystack := strings.ToLower(ctx.FullLine + "\n" + ctx.BeforeText + "\n" + ctx.AfterText)
	for _, kw := range socialCorroboration {
		if strings.Contains(haystack, kw) {
			return true
		}
	}
	return false
}

// documentHasSocialCorroboration reports whether the document anywhere says social media.
//
// DOCUMENT-scoped, not line-scoped, and the reason is a measured recall gap. detector.ContextInfo here
// carries only the match's own line plus a 50-byte window inside it, so a heading cannot vouch for the
// handles beneath it. Measured on the canonical shape:
//
//	Twitter mentions export      <- heading on line 1
//	@schneems                    <- reported at LOW under line-scoped corroboration
//	@tleish
//
// That is precisely the artifact handle_syntax.go records two leaks defending, so demoting it was the
// wrong trade even though a demoted finding is still redacted.
//
// It is safe to widen this far because the corroboration list only ever PROMOTES. A file that mentions
// Twitter and also contains @-syntax gets some findings it would otherwise have demoted — measured
// cost on this repository is small and stated in the CHANGELOG entry — whereas a file that mentions
// nothing social keeps every bare token demoted. Verified on the case that matters: this repository's
// Makefile contains ZERO corroboration words, so its 346 findings are unaffected by the widening.
//
// Computed once per document by the caller. It lowercases the content once rather than per keyword,
// which costs one transient copy; that is why it is hoisted rather than called per match.
func documentHasSocialCorroboration(content string) bool {
	lower := strings.ToLower(content)
	for _, kw := range socialCorroboration {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// applyBareHandleCeiling declares a confidence ceiling on a bare, uncorroborated handle.
//
// Sets the metadata key rather than clamping Confidence directly, because a validator that clamps
// its own return value has no way to make the bound stick: the +20 context adjustment and the
// cross-path correlation boost are both applied downstream. Measured elsewhere in this tree, a value
// a validator scored 55 was reported at 80 once those had run.
func applyBareHandleCeiling(m *detector.Match, ctx detector.ContextInfo, documentCorroborated bool) {
	if m == nil || m.Metadata == nil {
		return
	}
	if !isBareHandle(m.Text) {
		return
	}
	if documentCorroborated || hasSocialCorroboration(ctx) {
		return
	}
	m.Metadata[validators.ConfidenceCeilingKey] = bareHandleCeiling
}
