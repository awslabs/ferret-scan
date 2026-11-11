// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package replacement provides a single source of truth for all redaction
// replacement generation. Previously this logic was duplicated across the
// plaintext, office, and pdf redactors. All redactors now call Generate().
package replacement

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"unicode"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/validators/personname"

	"github.com/awslabs/ferret-scan/v2/internal/textnorm"
)

// nameLists is the embedded name databases, title-cased and SORTED.
//
// Sorted because the databases are maps: ranging one gives a different order in every process, so an
// index drawn into an unsorted list named a different person in every run, and a seeded draw could
// never be reproduced.
type nameLists struct {
	first, last []string
}

// nameDB loads the name lists once, for every goroutine.
//
// It used to be a hand-rolled once whose done flag was set BEFORE the lists were assigned, so a
// goroutine arriving in between read nil lists and SyntheticName returned the simple placeholder with
// a nil error: one name in 24 files came out as [PERSON-NAME-REDACTED] in 1 to 7 of the 24, at exit 0
// (#886), and 32 goroutines making the first call together got 31 placeholders. sync.OnceValues makes
// every caller wait for the one load, and a failed load is an error, never a placeholder.
var nameDB = sync.OnceValues(loadNameLists)

func loadNameLists() (*nameLists, error) {
	db, err := personname.LoadNameDatabases()
	if err != nil {
		return nil, fmt.Errorf("loading the name databases for synthetic names: %w", err)
	}
	if db == nil || len(db.FirstNames) == 0 || len(db.LastNames) == 0 {
		return nil, errors.New("the name databases for synthetic names are empty")
	}
	titled := func(set map[string]bool) []string {
		out := make([]string, 0, len(set))
		for n := range set {
			if len(n) > 0 {
				out = append(out, strings.ToUpper(n[:1])+n[1:])
			}
		}
		sort.Strings(out)
		return out
	}
	return &nameLists{first: titled(db.FirstNames), last: titled(db.LastNames)}, nil
}

// Generate returns the replacement for originalText, a value of dataType, under strategy.
//
// scope is the synthetic strategy's memory for the invocation (see redactors.SyntheticScope): under
// synthetic, one value receives one replacement however many times and wherever it occurs, and a nil
// scope is an error (redactors.ErrNoSyntheticScope). simple and format_preserving never read it.
//
// A synthetic generator that fails returns its error. It used to return the simple placeholder in its
// place, at a nil error, so a run asked for synthetic values silently wrote placeholders (#886).
func Generate(originalText, dataType string, strategy redactors.RedactionStrategy, scope redactors.SyntheticScope) (string, error) {
	r, err := Render(originalText, dataType, strategy, scope)
	if err != nil {
		return "", err
	}
	return r.Text, nil
}

// ─── Renderings and the bytes they keep ──────────────────────────────────────

// Copy is one run of the original value that a rendering writes back verbatim, by construction.
//
// In is the run's byte offset in the original value, Out the offset of the same bytes in
// Rendering.Text, Len its length. In and Out differ only where a renderer shifts what it keeps:
// preserveEmail with an empty local part writes "*" ahead of the "@" and the domain.
type Copy struct {
	In  int
	Out int
	Len int
}

// Rendering is a replacement together with the original bytes it keeps.
//
// The ranges are returned WITH the string rather than inferred from it afterwards, because only the
// renderer knows which bytes it copied: a random synthetic digit can equal the original's by chance,
// and a mask can coincide with a value written as asterisks. Overlap groups need the real answer to
// decide whether a byte may survive (RenderGroup).
type Rendering struct {
	// Text is the replacement, exactly what Generate returns for the same arguments.
	Text string

	// Copies lists every run of the original that Text repeats BY CONSTRUCTION and that holds at
	// least one letter, digit or non-ASCII byte: the last four digits format_preserving keeps of a
	// card, SSN or phone; an email's first character and its domain; an IP's first two octets; a
	// synthetic card's issuer prefix; a synthetic name's title; a synthetic token's provider
	// prefix. Runs holding only ASCII separators kept for shape ("-", " ", ".") are not listed:
	// they carry no part of the value.
	Copies []Copy

	// Normalized marks a synthetic rendering generated from a folded spelling of the value (see
	// Synthetic). Its Copies are offsets into that spelling, so a caller combining renderings
	// cannot place them on the original's bytes.
	Normalized bool

	kept int
}

// Kept counts the bytes of the original value the rendering keeps (the letter, digit and
// non-ASCII bytes of Copies). Of two renderings of the same value, the one keeping fewer is the
// stricter.
func (r Rendering) Kept() int { return r.kept }

// Render is Generate together with the original bytes the replacement keeps.
func Render(original, dataType string, strategy redactors.RedactionStrategy, scope redactors.SyntheticScope) (Rendering, error) {
	switch strategy {
	case redactors.RedactionSimple:
		return Rendering{Text: simpleFor(dataType, original)}, nil
	case redactors.RedactionFormatPreserving:
		text := FormatPreserving(original, dataType)
		return newRendering(text, original, formatPreservingCopies(original, dataType), false), nil
	case redactors.RedactionSynthetic:
		text, err := syntheticIn(scope, original, dataType)
		if err != nil {
			return Rendering{}, err
		}
		folded := textnorm.Fold(original)
		return newRendering(text, folded, syntheticCopies(folded, dataType), folded != original), nil
	default:
		return Rendering{}, fmt.Errorf("redaction strategy %d is not one of %s",
			int(strategy), strings.Join(redactors.RedactionStrategyNames, ", "))
	}
}

// memberCopies is the original bytes a member's own rendering keeps, without drawing a synthetic
// value: which bytes a synthetic generator copies is a property of the value's shape (its separators,
// a card's issuer prefix, a name's title), never of the random digits it writes. The overlap-group
// rule asks this of every member, and drawing would hand a value that is never written a replacement
// of its own in the scope.
func memberCopies(original, dataType string, strategy redactors.RedactionStrategy) (copies []Copy, normalized bool) {
	switch strategy {
	case redactors.RedactionSynthetic:
		folded := textnorm.Fold(original)
		return valueCopies(folded, syntheticCopies(folded, dataType)), folded != original
	case redactors.RedactionFormatPreserving:
		text := FormatPreserving(original, dataType)
		return newRendering(text, original, formatPreservingCopies(original, dataType), false).Copies, false
	default:
		return nil, false // simple copies nothing
	}
}

// valueCopies keeps the copies that lie inside value and hold part of it.
func valueCopies(value string, copies []Copy) []Copy {
	var out []Copy
	for _, c := range copies {
		if c.Len <= 0 || c.In < 0 || c.In+c.Len > len(value) {
			continue
		}
		for p := c.In; p < c.In+c.Len; p++ {
			if isValueByte(value[p]) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// newRendering keeps only the copies that hold part of the value and counts what they keep.
func newRendering(text, value string, copies []Copy, normalized bool) Rendering {
	r := Rendering{Text: text, Normalized: normalized}
	for _, c := range copies {
		if c.Len <= 0 || c.In < 0 || c.In+c.Len > len(value) || c.Out < 0 || c.Out+c.Len > len(text) {
			continue
		}
		n := 0
		for p := c.In; p < c.In+c.Len; p++ {
			if isValueByte(value[p]) {
				n++
			}
		}
		if n == 0 {
			continue
		}
		r.Copies = append(r.Copies, c)
		r.kept += n
	}
	return r
}

// isValueByte reports whether a kept byte is part of a value rather than shape: an ASCII letter or
// digit, or any byte of a non-ASCII character. Counting every non-ASCII byte errs towards masking --
// a non-breaking-space separator is masked along with the letters -- which is the safe direction.
func isValueByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b >= 0x80
}

// runsWhere turns a per-byte "kept" predicate into same-offset runs.
func runsWhere(value string, kept func(i int) bool) []Copy {
	var out []Copy
	start := -1
	for i := 0; i <= len(value); i++ {
		if i < len(value) && kept(i) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			out = append(out, Copy{In: start, Out: start, Len: i - start})
			start = -1
		}
	}
	return out
}

// digitTailKept reports, per byte, what a digit-walking mask keeps: every non-digit byte (it is
// written back unchanged) and the last `tail` ASCII digits.
func digitTailKept(value string, tail int) func(i int) bool {
	total := 0
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			total++
		}
	}
	index := make([]int, len(value))
	d := 0
	for i := 0; i < len(value); i++ {
		if value[i] >= '0' && value[i] <= '9' {
			index[i] = d
			d++
		}
	}
	return func(i int) bool {
		if value[i] < '0' || value[i] > '9' {
			return true
		}
		return index[i] >= total-tail
	}
}

func countASCIIDigits(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			n++
		}
	}
	return n
}

// formatPreservingCopies mirrors FormatPreserving branch for branch.
func formatPreservingCopies(original, dataType string) []Copy {
	switch {
	case isCreditCardType(dataType):
		if countASCIIDigits(original) < 8 {
			return nil
		}
		return runsWhere(original, digitTailKept(original, 4))
	case dataType == "SSN", dataType == "PHONE":
		if countASCIIDigits(original) < 4 {
			return nil
		}
		return runsWhere(original, digitTailKept(original, 4))
	case isEmailType(dataType, original):
		at := strings.IndexByte(original, '@')
		switch {
		case at < 0:
			return nil
		case at == 0:
			return []Copy{{In: 0, Out: 1, Len: len(original)}}
		case at == 1:
			return []Copy{{In: 1, Out: 1, Len: len(original) - 1}}
		default:
			return []Copy{{In: 0, Out: 0, Len: 1}, {In: at, Out: at, Len: len(original) - at}}
		}
	case dataType == "IP_ADDRESS":
		parts := strings.Split(original, ".")
		if len(parts) != 4 {
			return nil
		}
		return []Copy{{In: 0, Out: 0, Len: len(parts[0]) + len(parts[1]) + 2}}
	}
	return nil
}

// syntheticCopies mirrors the synthetic generators: the bytes each writes back from the value
// rather than generating. value is the folded spelling Synthetic generated from.
//
// They depend on the value's shape alone, never on what was drawn, which is what lets memberCopies
// answer for a member without drawing for it.
func syntheticCopies(value, dataType string) []Copy {
	switch {
	case isCreditCardType(dataType):
		// syntheticCreditCard keeps the issuer prefix (up to four digits) and every non-digit rune.
		prefix := countASCIIDigits(value)
		if prefix > 4 {
			prefix = 4
		}
		d := 0
		index := make([]int, len(value))
		for i := 0; i < len(value); i++ {
			if value[i] >= '0' && value[i] <= '9' {
				index[i] = d
				d++
			}
		}
		return runsWhere(value, func(i int) bool {
			if value[i] < '0' || value[i] > '9' {
				return true
			}
			return index[i] < prefix
		})
	case dataType == "CARD_TRACK_DATA":
		return syntheticTrackCopies(value)
	case dataType == "SSN":
		// Digits are regenerated one for one; everything else is written back.
		return runsWhere(value, func(i int) bool { return value[i] < '0' || value[i] > '9' })
	case dataType == "PHONE":
		// As SSN, except that an eleven-digit number's leading NANP trunk prefix "1" is written
		// back too: it is the same for every number written that way, and it is not part of the
		// ten digits that identify the line (see phoneKey).
		_, trunk := phoneKey(digitsOf(value))
		first := strings.IndexFunc(value, func(r rune) bool { return r >= '0' && r <= '9' })
		return runsWhere(value, func(i int) bool {
			return value[i] < '0' || value[i] > '9' || (trunk && i == first)
		})
	case dataType == "PERSON_NAME":
		// The generator keeps a leading title ("Dr.") and writes it first.
		sh := parseName(value)
		if sh.title == "" {
			return nil
		}
		return []Copy{{In: strings.Index(value, sh.title), Out: 0, Len: len(sh.title)}}
	case dataType == "GITHUB_TOKEN":
		if len(value) >= 4 {
			return []Copy{{In: 0, Out: 0, Len: 4}}
		}
	case dataType == "STRIPE_API_KEY":
		if strings.HasPrefix(value, "pk_") {
			return []Copy{{In: 0, Out: 0, Len: 3}}
		}
	case dataType == "SLACK_TOKEN":
		if strings.HasPrefix(value, "xoxp-") {
			return []Copy{{In: 0, Out: 0, Len: 5}}
		}
	}
	return nil
}

// ─── Overlap groups ──────────────────────────────────────────────────────────

// RenderGroup returns the ONE write that replaces every member of an overlap group, over g.Text.
//
// A single match renders exactly as Render always has. For a group, the rule is:
//
//   - CONTAINED (one member spans the union): the widest member's rendering, as before, except that
//     no original letter or digit inside a contained SECRETS-check member is copied. Every other
//     contained member is ignored, which keeps every contained pair outside SECRETS byte-identical
//     (an IP_ADDRESS keeps its two octets over a DATE_OF_BIRTH inside them -- #687's call, not this
//     one's).
//   - IDENTICAL (two or more members span the union): the representative's rendering, keeping a copied
//     letter or digit only if EVERY member covering that byte would keep it in its own rendering.
//     PASSPORT and SSN on one 9-digit number therefore render "*********", whichever came first: the
//     PASSPORT rendering keeps nothing, so the SSN's last four cannot survive.
//   - PARTIAL (no member spans the union): the union written once. Members of one shared Type take
//     that type's rendering of the union under the same per-byte rule; members of different types
//     take a full "*" mask under format_preserving and the representative's placeholder otherwise,
//     because no single type's rendering is correct for bytes that belong to two values.
//
// When the rule masks anything, format_preserving masks those bytes with '*' and synthetic falls back
// to the representative's simple placeholder (a plausible fake must not carry a byte a member's own
// rendering would have hidden). simple copies nothing, so it is the representative's placeholder.
//
// The representative and its tie-breaks are redactors.ResolveOverlaps'; nothing here reads the order
// matches arrived in.
//
// scope is Render's: synthetic draws the union's replacement from it, so every occurrence of the same
// union is given the same one.
func RenderGroup(g redactors.OverlapGroup, matches []detector.Match, strategy redactors.RedactionStrategy, scope redactors.SyntheticScope) (Rendering, error) {
	rep := matches[g.Representative]
	if !g.IsGroup() {
		return Render(rep.Text, rep.Type, strategy, scope)
	}

	switch g.Kind {
	case redactors.GroupContained:
		guarded := make([]bool, len(g.Text))
		anyGuard := false
		for k, i := range g.Members {
			if i == g.Representative || !redactors.IsSecretsMember(matches[i]) {
				continue
			}
			for p := g.Spans[k].Start - g.Start; p < g.Spans[k].End-g.Start; p++ {
				guarded[p] = true
				anyGuard = true
			}
		}
		r, err := Render(g.Text, rep.Type, strategy, scope)
		if err != nil || !anyGuard {
			return r, err
		}
		return withhold(r, g.Text, strategy, simpleFor(rep.Type, rep.Text), func(p int) bool { return !guarded[p] }), nil

	case redactors.GroupIdentical:
		r, err := Render(g.Text, rep.Type, strategy, scope)
		if err != nil {
			return r, err
		}
		return withhold(r, g.Text, strategy, simpleFor(rep.Type, rep.Text), keptByEveryCoveringMember(g, matches, strategy)), nil

	case redactors.GroupPartial:
		if t, ok := sharedType(g, matches); ok {
			r, err := Render(g.Text, t, strategy, scope)
			if err != nil {
				return r, err
			}
			return withhold(r, g.Text, strategy, simpleFor(rep.Type, rep.Text), keptByEveryCoveringMember(g, matches, strategy)), nil
		}
		if strategy == redactors.RedactionFormatPreserving {
			return Rendering{Text: strings.Repeat("*", len(g.Text))}, nil
		}
		return Rendering{Text: simpleFor(rep.Type, rep.Text)}, nil
	}
	return Render(g.Text, rep.Type, strategy, scope)
}

// sharedType returns the members' Type when they all have the same one.
func sharedType(g redactors.OverlapGroup, matches []detector.Match) (string, bool) {
	t := matches[g.Members[0]].Type
	for _, i := range g.Members[1:] {
		if matches[i].Type != t {
			return "", false
		}
	}
	return t, true
}

// keptByEveryCoveringMember returns the per-byte rule for identical and partial groups: a byte of the
// union may be copied only if every member whose span covers it copies it in its own rendering.
//
// A member whose copies cannot be placed (a synthetic rendering of a folded spelling) counts as
// copying nothing, which can only mask more.
func keptByEveryCoveringMember(g redactors.OverlapGroup, matches []detector.Match, strategy redactors.RedactionStrategy) func(p int) bool {
	n := len(g.Text)
	cover := make([]int, n)
	kept := make([]int, n)
	for k, i := range g.Members {
		off := g.Spans[k].Start - g.Start
		for p := off; p < g.Spans[k].End-g.Start && p < n; p++ {
			cover[p]++
		}
		copies, normalized := memberCopies(matches[i].Text, matches[i].Type, strategy)
		if normalized {
			continue
		}
		for _, c := range copies {
			for q := 0; q < c.Len; q++ {
				if p := off + c.In + q; p >= 0 && p < n {
					kept[p]++
				}
			}
		}
	}
	return func(p int) bool { return p >= 0 && p < n && cover[p] > 0 && kept[p] >= cover[p] }
}

// withhold applies a group's per-byte rule to a rendering of the union: every copied value byte the
// rule does not allow is masked (format_preserving) or the whole rendering falls back to the
// representative's placeholder, repSimple (synthetic).
func withhold(r Rendering, value string, strategy redactors.RedactionStrategy, repSimple string, allowed func(p int) bool) Rendering {
	if len(r.Copies) == 0 {
		return r
	}
	if r.Normalized {
		// The copies are offsets into a folded spelling and cannot be checked byte by byte.
		return Rendering{Text: repSimple}
	}

	out := []byte(r.Text)
	masked := false
	var keep []Copy
	for _, c := range r.Copies {
		start := -1
		for q := 0; q <= c.Len; q++ {
			hide := false
			if q < c.Len {
				p := c.In + q
				hide = isValueByte(value[p]) && !allowed(p)
				if hide {
					out[c.Out+q] = '*'
					masked = true
				}
			}
			if q == c.Len || hide {
				if start >= 0 {
					keep = append(keep, Copy{In: c.In + start, Out: c.Out + start, Len: q - start})
					start = -1
				}
				continue
			}
			if start < 0 {
				start = q
			}
		}
	}
	if !masked {
		return r
	}
	if strategy != redactors.RedactionFormatPreserving {
		return Rendering{Text: repSimple}
	}
	return newRendering(string(out), value, keep, false)
}

// ─── Type families ───────────────────────────────────────────────────────────

// Three validators report one family of value under many Type values (#864): email under 24 (the
// generic EMAIL, one per provider, one per sector), social media under one per platform plus the
// cluster, and secrets under one per credential kind. The renderers switched on the Type, and their
// email arms listed three of the 24, so the other 21 took the generic arm in every strategy: simple
// named the provider or sector ("[SALESFORCE-REDACTED]", "[GOVERNMENT-REDACTED]"), format_preserving
// wrote an all-'*' mask with no '@' or domain, and synthetic random alphanumerics with no '@'.
// Measured on main at b0a9163 with one address per type: 3 of 24 lines kept an '@' under
// format_preserving and under synthetic. The same switch left synthetic's social media arm reached by
// no platform type, and synthetic's secrets arm by 12 of the 13 secret types.
//
// The family is chosen from the Type and, for the one Type two validators share, from the value: a
// renderer is handed the value and its Type, not the validator that reported it. The lists are kept
// honest by a test that reads the validators' own type functions (family_guard_test.go).

// emailTypes is every Type internal/validators/email reports (getEmailProviderType), plus nothing
// else: each one is an email address. The metadata validator reports "EMAIL" too, for an address in
// document properties, and renders as an email through the same entry.
var emailTypes = map[string]bool{
	"EMAIL": true, "BUSINESS": true, "EDUCATIONAL": true, "GOVERNMENT": true, "DISPOSABLE": true,
	"GMAIL": true, "GOOGLE_WORKSPACE": true, "OUTLOOK": true, "MICROSOFT_365": true, "YAHOO": true,
	"ICLOUD": true, "APPLE_CORPORATE": true, "AOL": true, "PROTONMAIL": true, "TUTANOTA": true,
	"FASTMAIL": true, "ZOHO": true, "YANDEX": true, "MAIL_RU": true, "SALESFORCE": true,
	"SLACK": true, "ATLASSIAN": true, "GITHUB": true, "GITLAB": true,
}

// socialMediaTypes is every Type internal/validators/socialmedia reports for a built-in platform
// (getPlatformDisplayName, and the upper-cased names identifyPlatform returns), its cluster type, and
// the family's own name. A platform a user adds in config reports its upper-cased name, which this
// list cannot know, and takes the generic arm.
var socialMediaTypes = map[string]bool{
	"SOCIAL_MEDIA": true, "SOCIAL_MEDIA_CLUSTER": true,
	"LINKEDIN": true, "TWITTER": true, "GITHUB": true, "FACEBOOK": true, "INSTAGRAM": true,
	"YOUTUBE": true, "TIKTOK": true, "DISCORD": true, "REDDIT": true, "SNAPCHAT": true,
	"PINTEREST": true, "TWITCH": true, "MEDIUM": true, "STACKOVERFLOW": true, "MASTODON": true,
	"TELEGRAM": true, "WHATSAPP": true, "SKYPE": true, "CLUBHOUSE": true, "THREADS": true,
	"BLUESKY": true,
}

// secretTypes is every Type internal/validators/secrets reports, plus the family's own name. synthetic
// sends all of them to syntheticSecret; simple keeps naming the credential kind
// ("[GITHUB_TOKEN-REDACTED]"), which docs/configuration.md documents as deliberate.
var secretTypes = map[string]bool{
	"SECRETS": true, "API_KEY_OR_SECRET": true, "AWS_ACCESS_KEY": true, "AWS_SECRET_ACCESS_KEY": true,
	"GITHUB_TOKEN": true, "GOOGLE_CLOUD_API_KEY": true, "STRIPE_API_KEY": true, "GITLAB_TOKEN": true,
	"DOCKER_TOKEN": true, "SLACK_TOKEN": true, "JWT_TOKEN": true, "SSH_PRIVATE_KEY": true,
	"CERTIFICATE": true, "PGP_PRIVATE_KEY": true,
}

// isEmailType reports whether a value of this Type renders as an email address.
//
// GITHUB is both an email provider type (an address at github.com) and a social media platform (a
// GitHub profile). Only the value tells them apart, so it decides: an address renders as an email,
// a profile URL or handle as a profile.
func isEmailType(dataType, value string) bool {
	if !emailTypes[dataType] {
		return false
	}
	return !socialMediaTypes[dataType] || looksLikeEmailAddress(value)
}

// isSocialMediaType reports whether a value of this Type renders as a social media profile.
func isSocialMediaType(dataType, value string) bool {
	return socialMediaTypes[dataType] && !isEmailType(dataType, value)
}

// looksLikeEmailAddress reports whether v has an email address's shape: one '@' after a non-empty
// local part, a dotted domain, and nothing a URL or a handle carries (a '/', a ':' or white space).
func looksLikeEmailAddress(v string) bool {
	at := strings.IndexByte(v, '@')
	if at <= 0 || at != strings.LastIndexByte(v, '@') || strings.ContainsAny(v, "/: \t\r\n") {
		return false
	}
	domain := v[at+1:]
	dot := strings.IndexByte(domain, '.')
	return dot > 0 && dot < len(domain)-1
}

// ─── Simple ──────────────────────────────────────────────────────────────────

// creditCardTypes is the set of finding types the credit-card validator can
// emit: the generic "CREDIT_CARD" plus every brand-specific sub-type
// getCreditCardType can return. All of them must route to credit-card
// redaction so that (a) a brand name never leaks through the Simple
// placeholder (e.g. "[JCB-REDACTED]") and (b) every brand gets the same
// format-preserving credit-card mask instead of falling through to the
// generic full-mask branch. Previously only VISA/MASTERCARD/AMERICAN_EXPRESS/
// DISCOVER were listed, so MAESTRO/JCB/DINERS_CLUB/UNIONPAY were handled
// inconsistently. Keep this list in sync with getCreditCardType in
// internal/validators/creditcard.
var creditCardTypes = map[string]bool{
	"CREDIT_CARD":      true,
	"VISA":             true,
	"MASTERCARD":       true,
	"MAESTRO":          true,
	"AMERICAN_EXPRESS": true,
	"JCB":              true,
	"DINERS_CLUB":      true,
	"DISCOVER":         true,
	"UNIONPAY":         true,
}

// isCreditCardType reports whether dataType is a credit-card finding type
// (generic or any brand sub-type).
func isCreditCardType(dataType string) bool {
	return creditCardTypes[dataType]
}

// Simple returns a bracketed placeholder for the given data type.
//
// Every email type writes "[EMAIL-REDACTED]" and every social media platform
// "[SOCIAL-MEDIA-REDACTED]", as every card brand writes "[CREDIT-CARD-REDACTED]":
// the placeholder names the kind of value, never the provider, employer, sector
// or platform, which identify the person behind it (#864). A secret keeps its
// credential kind ("[GITHUB_TOKEN-REDACTED]").
//
// Simple has no value to look at, so GITHUB -- an email provider type and a social
// media platform -- takes the social media placeholder here. Render and Generate,
// which have the value, write "[EMAIL-REDACTED]" for an address at github.com.
func Simple(dataType string) string {
	return simpleFor(dataType, "")
}

// simpleFor is Simple, with the value to decide GITHUB by.
func simpleFor(dataType, value string) string {
	if isCreditCardType(dataType) {
		return "[CREDIT-CARD-REDACTED]"
	}
	if isEmailType(dataType, value) {
		return "[EMAIL-REDACTED]"
	}
	if isSocialMediaType(dataType, value) {
		return "[SOCIAL-MEDIA-REDACTED]"
	}
	switch dataType {
	case "SSN":
		return "[SSN-REDACTED]"
	case "PHONE":
		return "[PHONE-REDACTED]"
	case "IP_ADDRESS":
		return "[IP-ADDRESS-REDACTED]"
	case "PASSPORT":
		return "[PASSPORT-REDACTED]"
	case "PERSON_NAME":
		return "[PERSON-NAME-REDACTED]"
	default:
		return "[" + dataType + "-REDACTED]"
	}
}

// ─── Format-preserving ───────────────────────────────────────────────────────

// FormatPreserving returns a replacement that keeps the original structure
// (separators, length, character types) while masking the sensitive content.
//
// Every email type keeps the first character and the domain ("j***@acme.com"),
// as documented and pinned by TestEmail_FormatPreserving_KeepsDomain; before #864
// only EMAIL, GMAIL and BUSINESS did, and the other 21 email types were masked whole.
func FormatPreserving(original, dataType string) string {
	if isCreditCardType(dataType) {
		return preserveCreditCard(original)
	}
	if isEmailType(dataType, original) {
		return preserveEmail(original)
	}
	switch dataType {
	case "SSN":
		return preserveSSN(original)
	case "PHONE":
		return preservePhone(original)
	case "IP_ADDRESS":
		return preserveIP(original)
	default:
		return strings.Repeat("*", len(original))
	}
}

func preserveCreditCard(original string) string {
	cleaned := nonDigit.ReplaceAllString(original, "")
	if len(cleaned) < 8 {
		return strings.Repeat("*", len(original))
	}
	// Mask everything except the last 4 digits. The BIN / first-4 digits are
	// sensitive (they identify the issuer and card range) and must not survive
	// into the redacted output — only the tail is kept for reference.
	last4 := cleaned[len(cleaned)-4:]
	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		defer func() { di++ }()
		if di < len(cleaned)-4 {
			return "*"
		}
		return string(last4[di-(len(cleaned)-4)])
	})
}

func preserveSSN(original string) string {
	cleaned := nonDigit.ReplaceAllString(original, "")
	if len(cleaned) < 4 {
		return strings.Repeat("*", len(original))
	}
	last4 := cleaned[len(cleaned)-4:]
	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		defer func() { di++ }()
		if di < len(cleaned)-4 {
			return "*"
		}
		if di < len(cleaned) {
			return string(last4[di-(len(cleaned)-4)])
		}
		return "*"
	})
}

func preserveEmail(original string) string {
	parts := strings.SplitN(original, "@", 2)
	if len(parts) != 2 {
		return strings.Repeat("*", len(original))
	}
	user := parts[0]
	if len(user) == 0 {
		return "*@" + parts[1]
	}
	// Mask the WHOLE local part when it is a single character.
	//
	// The previous branch returned `user + "@" + domain` unchanged, so
	// "a@b.co" redacted to "a@b.co" -- a redaction that redacts nothing, and a
	// cleartext leak in the shipped binary: scanning a .txt containing
	// "contact a@b.co for details" with --redaction-strategy format_preserving
	// wrote the address back out verbatim.
	//
	// Keeping the first character is a readability affordance for a long local
	// part ("j***@example.com"), not a rule to apply when the first character IS
	// the entire local part. This is the same defect class the phone helper below
	// already documents: a masking scheme whose "middle" is empty at the smallest
	// input size, so the value survives.
	if len(user) == 1 {
		return "*@" + parts[1]
	}
	return string(user[0]) + strings.Repeat("*", len(user)-1) + "@" + parts[1]
}

func preservePhone(original string) string {
	cleaned := nonDigit.ReplaceAllString(original, "")
	// Mask everything except the last 4 digits — the same policy as SSN and
	// credit card. The previous "first3 + stars + last4" scheme had two security
	// defects: for a 7-digit number the middle was Repeat("*", 0) so ALL seven
	// digits survived verbatim (a redaction that redacts nothing), and for a
	// 6-digit number it computed Repeat("*", -1) which PANICS — an unrecovered
	// crash for any pkg/redact embedder. Keeping only the last 4 fixes both.
	if len(cleaned) < 4 {
		return strings.Repeat("*", len(original))
	}
	last4 := cleaned[len(cleaned)-4:]
	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		defer func() { di++ }()
		if di < len(cleaned)-4 {
			return "*"
		}
		if di < len(cleaned) {
			return string(last4[di-(len(cleaned)-4)])
		}
		return "*"
	})
}

func preserveIP(original string) string {
	parts := strings.Split(original, ".")
	if len(parts) != 4 {
		return strings.Repeat("*", len(original))
	}
	return parts[0] + "." + parts[1] + ".*.*"
}

// ─── Synthetic ───────────────────────────────────────────────────────────────

// Synthetic generates realistic-looking but fake data of the same type: ONE draw, with no memory.
//
// Two calls on one value return two different values. That is the generator a redaction draws from,
// without the scope that gives a value one replacement per invocation; every redactor renders through
// Generate, Render or RenderGroup with a scope instead (#886). This stays for a caller that needs an
// independent draw: pkg/redact's gate samples it to show the generators are not constant and never
// write a value that could be live.
func Synthetic(original, dataType string) (string, error) {
	g := generatorFor(dataType, textnorm.Fold(original))
	stored, err := g.drawFrom(rand.Reader, 0)
	if err != nil {
		return "", err
	}
	return g.render(stored), nil
}

// syntheticIn is the scoped draw: the replacement scope holds for the value, drawn there on first use
// and written in this occurrence's shape.
func syntheticIn(scope redactors.SyntheticScope, original, dataType string) (string, error) {
	if scope == nil {
		return "", redactors.ErrNoSyntheticScope
	}
	g := generatorFor(dataType, textnorm.Fold(original))
	stored, err := scope.Resolve(g.family, g.key, g.distinct, g.drawFrom)
	if err != nil {
		return "", err
	}
	return g.render(stored), nil
}

// synthGen is one value's synthetic generator: the family and canonical key the scope files it under,
// how to draw a replacement, and how to write that replacement in this occurrence's shape.
//
// What is stored and what is written differ wherever two spellings are one value. The SSN family
// stores nine digits and writes them into each occurrence's own separators; the name family stores a
// first and last name and writes them in each occurrence's order, comma and case. Elsewhere the
// stored value is what is written.
type synthGen struct {
	family string
	key    string
	// distinct is redactors.SyntheticScope's: whether the replacement must be unique in its family.
	distinct bool
	draw     func(s *source, attempt int) (string, error)
	render   func(stored string) string
}

// drawFrom is the redactors.SyntheticDraw a scope calls. A failed read of the random source is
// returned as the error; it used to be replaced by the clock (time.Now().UnixNano() % max).
func (g synthGen) drawFrom(rnd io.Reader, attempt int) (string, error) {
	s := &source{r: rnd}
	v, err := g.draw(s, attempt)
	if err == nil {
		err = s.err
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func verbatim(stored string) string { return stored }

// generatorFor returns the generator for a value of dataType, given the value's FOLDED spelling.
//
// Folded (textnorm.Fold) because every generator rebuilds a value by walking it and substituting the
// parts it recognises -- ASCII digits, the passport generator's A-Z. None recognises a fullwidth digit
// or a Unicode dash, so for a value written with those the walk substituted nothing and returned the
// original UNCHANGED, and the residue guard then correctly refused the file: measured, three of ninety
// substituted fixtures (SSN, VISA and PHONE with fullwidth digits) were refused under synthetic while
// simple and format_preserving redacted them cleanly (#671). A synthetic replacement is a
// realistic-looking substitute, not a byte-shape copy, so it has no reason to keep the exotic spelling.
//
// The family follows the renderers' dispatch (#864): every card brand is one family, every email type
// another, every social media platform a third, each credential type its own, and every other type its
// own. The canonical key merges only the spellings the type treats as one value, and each occurrence
// is written in its own shape:
//
//	family       canonical key                                 each occurrence written as
//	CREDIT_CARD  its digits                                    the replacement's digits in its own separators
//	SSN          its digits                                    the same
//	PHONE        its digits, an 11-digit NANP "1" dropped      the same, the "1" kept where it has one
//	EMAIL        the address, lower-cased                      the replacement address
//	PERSON_NAME  tokens case-folded, "Last, First" read as     the replacement name in its own order,
//	             "First Last", the title left out              comma, case and title
//	IP_ADDRESS   net/netip's canonical form                    the replacement address
//	(any other)  the folded value                              the replacement
//
// An email address's local part is case-sensitive by RFC 5321, but relying on that "impedes
// interoperability and is discouraged" (§2.4); one address written in two cases is one person here.
func generatorFor(dataType, value string) synthGen {
	switch {
	case isCreditCardType(dataType):
		key := digitsOf(value)
		return synthGen{family: "CREDIT_CARD", key: key, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return cardDigits(key, s), nil },
			render: func(stored string) string { return writeDigits(value, stored) }}
	// By family (#864): every email type gets a random address at example.com, every social media
	// platform a fake profile on its own host, every secret type a token of its own shape.
	case isEmailType(dataType, value):
		key := strings.ToLower(value)
		return synthGen{family: "EMAIL", key: key, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return syntheticEmail(key, s), nil },
			render: verbatim}
	case isSocialMediaType(dataType, value):
		return synthGen{family: "SOCIAL_MEDIA", key: value, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return syntheticSocialMedia(value, s), nil },
			render: verbatim}
	case secretTypes[dataType]:
		return synthGen{family: dataType, key: value, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return syntheticSecret(value, dataType, s), nil },
			render: verbatim}
	}
	switch dataType {
	case "SSN":
		return synthGen{family: "SSN", key: digitsOf(value), distinct: true,
			draw:   func(s *source, _ int) (string, error) { return ssnDigits(s), nil },
			render: func(stored string) string { return writeDigits(value, stored) }}
	case "PHONE":
		key, trunk := phoneKey(digitsOf(value))
		return synthGen{family: "PHONE", key: key, distinct: true,
			draw: func(s *source, _ int) (string, error) { return phoneDigits(len(key), s), nil },
			render: func(stored string) string {
				if trunk {
					stored = "1" + stored
				}
				return writeDigits(value, stored)
			}}
	case "IP_ADDRESS":
		return synthGen{family: "IP_ADDRESS", key: ipKey(value), distinct: true, draw: drawIP, render: verbatim}
	case "CARD_TRACK_DATA":
		return synthGen{family: "CARD_TRACK_DATA", key: value, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return syntheticTrack(value, s), nil },
			render: verbatim}
	case "PERSON_NAME":
		sh := parseName(value)
		return synthGen{family: "PERSON_NAME", key: sh.key(), distinct: true,
			draw:   func(s *source, _ int) (string, error) { return drawName(len(sh.tokens), s) },
			render: sh.render}
	case "PASSPORT":
		return synthGen{family: "PASSPORT", key: value, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return syntheticPassport(value, s), nil },
			render: verbatim}
	case "INTELLECTUAL_PROPERTY":
		// Only a patent number stands in for an identity. The other arms write a generic notice
		// ("© 2013 Redacted Corporation. All rights reserved.", "CONFIDENTIAL", "[IP-REDACTED]") from
		// at most 26 choices, and two notices sharing one merges nothing a reader joins on; held to
		// one-to-one, the second distinct trademark of a run would refuse its file.
		arm := intellectualPropertyArm(value)
		return synthGen{family: "INTELLECTUAL_PROPERTY", key: value, distinct: arm == ipPatent,
			draw:   func(s *source, _ int) (string, error) { return syntheticIntellectualProperty(arm, s), nil },
			render: verbatim}
	default:
		return synthGen{family: dataType, key: value, distinct: true,
			draw:   func(s *source, _ int) (string, error) { return randomString(len(value), s), nil },
			render: verbatim}
	}
}

// digitsOf returns the ASCII digits of s, in order.
func digitsOf(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] >= '0' && s[i] <= '9' {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// writeDigits writes digits into value's shape: each ASCII digit of value takes the next of digits
// ("0" once they run out), and every other byte is written back unchanged.
func writeDigits(value, digits string) string {
	b := make([]byte, len(value))
	di := 0
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= '0' && c <= '9' {
			c = '0'
			if di < len(digits) {
				c = digits[di]
				di++
			}
		}
		b[i] = c
	}
	return string(b)
}

// trackPAN returns the bounds of a card track's PAN (#905): the first run of 13 to 19 ASCII digits.
// Every frame the credit-card validator reports as CARD_TRACK_DATA puts its PAN first, after at most
// a start sentinel and a format code (`%B`, `B`, `;`, `%3B`), none of which holds a digit run that
// long; a tag 57 value inside TLV is reported from the first byte after its length byte.
func trackPAN(value string) (start, end int, ok bool) {
	for i := 0; i < len(value); {
		if value[i] < '0' || value[i] > '9' {
			i++
			continue
		}
		j := i
		for j < len(value) && value[j] >= '0' && value[j] <= '9' {
			j++
		}
		if n := j - i; n >= 13 && n <= 19 {
			return i, j, true
		}
		i = j
	}
	return 0, 0, false
}

// trackHasName reports whether a track's PAN is followed by Track 1's field separator, so the bytes
// after it hold a cardholder name and alphanumeric discretionary data rather than Track 2's or tag
// 57's structural letters (`D`, `F`, a percent-encoded `%3D`/`%3F`).
func trackHasName(value string, panEnd int) bool {
	return panEnd < len(value) && value[panEnd] == '^'
}

// syntheticTrack writes a card track of the same shape with nothing of the original in it but its
// structure (#905). The PAN is cardDigits' (the issuer prefix kept, the check digit wrong, so no
// validator reads it as a card); every other digit is drawn at random; in a Track 1 every letter after
// the PAN (the name, any alphanumeric discretionary data) is drawn at random in its own case. The
// sentinels, separators and Track 2 / tag 57 structural letters are written back.
//
// Before CARD_TRACK_DATA had a type, a frame went through the card generator, which keeps every
// non-digit byte and writes one Luhn-INVALID number over ALL the frame's digits: the name survived,
// and the PAN (the first 13 to 19 of those digits) was Luhn-valid one time in ten. A re-scan of the
// issue's synthetic copies reported 6 such cards.
func syntheticTrack(value string, s *source) string {
	b := []byte(value)
	panStart, panEnd, ok := trackPAN(value)
	if ok {
		copy(b[panStart:panEnd], cardDigits(value[panStart:panEnd], s))
	}
	name := ok && trackHasName(value, panEnd)
	for i := 0; i < len(b); i++ {
		if ok && i >= panStart && i < panEnd {
			continue
		}
		switch c := b[i]; {
		case c >= '0' && c <= '9':
			b[i] = byte('0' + s.intn(10)) // #nosec G115 -- a decimal digit
		case name && i > panEnd && c >= 'A' && c <= 'Z':
			b[i] = byte('A' + s.intn(26)) // #nosec G115 -- a letter offset
		case name && i > panEnd && c >= 'a' && c <= 'z':
			b[i] = byte('a' + s.intn(26)) // #nosec G115 -- a letter offset
		}
	}
	return string(b)
}

// syntheticTrackCopies mirrors syntheticTrack: every byte it writes back, which is every byte that
// is not a digit and not a letter it redraws, and the PAN's issuer prefix cardDigits keeps.
func syntheticTrackCopies(value string) []Copy {
	panStart, panEnd, ok := trackPAN(value)
	name := ok && trackHasName(value, panEnd)
	return runsWhere(value, func(i int) bool {
		c := value[i]
		if c >= '0' && c <= '9' {
			return ok && i >= panStart && i < panStart+4
		}
		isLetter := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		return !(name && i > panEnd && isLetter)
	})
}

// cardDigits draws the digits of a card-SHAPED value that is deliberately Luhn-INVALID and
// keeps the original's issuer prefix. key is the original's digits; writeDigits puts the
// result into each occurrence's own grouping and separators.
//
// Two defects were fixed here, both measured (#669).
//
//  1. IT PRODUCED VALID CARD NUMBERS. The prefix was drawn at random from {4000, 4111,
//     5555, 3782} — all real issuer ranges — and luhnCheck appended a CORRECT check digit,
//     so the value written into a "redacted" document was a structurally valid primary
//     account number. Re-scanning a redacted file reported a card at 95, which defeats the
//     thing a user does before sharing a document; and a randomly generated Luhn-valid
//     number on a live IIN is a number an issuer may actually have assigned.
//
//  2. IT DID NOT PRESERVE THE BRAND. Because the prefix was random rather than taken from
//     the original, a Visa redacted to a Mastercard and vice versa — measured, 12 of 12
//     replacements for a Visa input came back detected as MASTERCARD. That is a silent
//     change of meaning in a document, in a strategy whose entire purpose is plausibility.
//
// The fix keeps the original's leading digits, so brand and format survive, and inverts
// the final check digit. Length, grouping and separators are unchanged, so a
// format-sensitive consumer sees what it expects; every Luhn validator rejects it.
//
// An alternative was the brands' published test numbers, but those are FEWER than the
// values needing replacement and are themselves Luhn-valid, so a document with several
// cards would repeat one — losing the distinctness the synthetic strategy exists to keep.
func cardDigits(key string, s *source) string {
	// Take the issuer prefix from the ORIGINAL so the brand is preserved.
	origDigits := make([]int, len(key))
	for i := 0; i < len(key); i++ {
		origDigits[i] = int(key[i] - '0')
	}
	// A card shorter than a plausible IIN cannot carry a brand; fall back to a Visa-shaped
	// prefix rather than indexing past the end.
	prefixLen := 4
	if len(origDigits) < prefixLen {
		prefixLen = len(origDigits)
	}
	digits := make([]int, 0, len(origDigits))
	digits = append(digits, origDigits[:prefixLen]...)
	if len(digits) == 0 {
		digits = append(digits, 4, 0, 0, 0)
	}

	// Fill to one short of the original's digit count, then append a WRONG check digit.
	target := len(origDigits)
	if target < 12 {
		target = 12 // shortest real card length; keeps luhn arithmetic meaningful
	}
	for len(digits) < target-1 {
		digits = append(digits, s.intn(10))
	}
	digits = append(digits, invalidLuhnDigit(digits))

	b := make([]byte, len(digits))
	for i, d := range digits {
		b[i] = byte('0' + d) // #nosec G115 -- d is a decimal digit
	}
	return string(b)
}

// ssnDigits draws nine digits that are neither an SSN nor an ITIN.
//
// The areas used to be {000, 666, 900, 999} with any group. 000 and 666 are never issued as anything.
// The 9xx areas are never an SSN, but they are where the IRS issues ITINs, and the SSN validator now
// reports an ITIN (#884): a 9xx area with a group in 50-65, 70-88, 90-92 or 94-99 is one. So a 9xx
// area is drawn only with a group in 01-49, which no ITIN carries. The digits come from the run's
// scope source, so one original maps to one replacement per run (#886).
func ssnDigits(s *source) string {
	var area, group string
	if s.intn(2) == 0 {
		area = []string{"000", "666"}[s.intn(2)]
		group = fmt.Sprintf("%02d", s.intn(100))
	} else {
		area = fmt.Sprintf("9%02d", s.intn(100))
		group = fmt.Sprintf("%02d", 1+s.intn(49))
	}
	return area + group + fmt.Sprintf("%04d", s.intn(10000))
}

// minSyntheticLocal is the shortest local part a synthetic address gets.
//
// The local part is lower-case alphanumeric, 36 symbols, and every synthetic address is at
// example.com, so a one-character local part had 36 possible replacements: one-to-one (#886) would
// have refused the file holding a run's 37th distinct one-character address. Four characters give
// 1,679,616.
const minSyntheticLocal = 4

// syntheticEmail draws a random lower-case local part of the original's length (at least
// minSyntheticLocal; eight when the value has no usable local part) at example.com.
func syntheticEmail(value string, s *source) string {
	userLen := 8
	if at := strings.IndexByte(value, '@'); at > 0 {
		userLen = max(at, minSyntheticLocal)
	}
	return strings.ToLower(randomString(userLen, s)) + "@example.com"
}

// phoneKey is the canonical form of a phone number's digits: an eleven-digit number starting with
// the NANP trunk prefix "1" is the ten-digit number after it, so "+1 312 555 0142" and
// "(312) 555-0142" are one line. trunk reports that the prefix was dropped.
func phoneKey(digits string) (key string, trunk bool) {
	if len(digits) == 11 && digits[0] == '1' {
		return digits[1:], true
	}
	return digits, false
}

// phoneDigits draws n digits in the NANP 555 fictional exchange: "555" and n-3 random digits.
func phoneDigits(n int, s *source) string {
	var b strings.Builder
	b.WriteString("555")
	for b.Len() < n {
		b.WriteByte(byte('0' + s.intn(10))) // #nosec G115 -- s.intn(10) is in [0, 9]
	}
	return b.String()
}

// ipKey is an address's canonical spelling (net/netip; an IPv4-mapped IPv6 address is its IPv4
// address), or the value itself when it does not parse.
func ipKey(value string) string {
	if a, err := netip.ParseAddr(value); err == nil {
		return a.Unmap().String()
	}
	return value
}

// rfc1918Size counts the addresses of 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
const rfc1918Size = 1<<24 + 1<<20 + 1<<16 // 17,891,328

// drawIP draws a private (RFC 1918) address.
//
// A value's first draw is in 192.168.0.0/16, as every synthetic address was before (#886). That range
// holds 65,536 addresses, too few to give every address of a large log one of its own, so a re-draw --
// which happens only when the address drawn is already another value's -- is taken from all
// 17,891,328 addresses of RFC 1918, and may start 10. or 172.16-31.
func drawIP(s *source, attempt int) (string, error) {
	if attempt == 0 {
		return fmt.Sprintf("192.168.%d.%d", s.intn(256), s.intn(256)), nil
	}
	i := s.intn(rfc1918Size)
	switch {
	case i < 1<<24:
		return fmt.Sprintf("10.%d.%d.%d", i>>16, i>>8&0xff, i&0xff), nil
	case i < 1<<24+1<<20:
		i -= 1 << 24
		return fmt.Sprintf("172.%d.%d.%d", 16+i>>16, i>>8&0xff, i&0xff), nil
	default:
		i -= 1<<24 + 1<<20
		return fmt.Sprintf("192.168.%d.%d", i>>8, i&0xff), nil
	}
}

// SyntheticName returns one random name for original, drawn from the embedded name databases (5,301
// first names, 2,333 last names). It keeps the original's title (Dr., Mr., Ms., ...), its number of
// tokens (one; two; three or more, written First M. Last), a "Last, First" order and an all-upper or
// all-lower case. It is an error, never a placeholder, when the databases cannot be loaded.
func SyntheticName(original string) (string, error) {
	g := generatorFor("PERSON_NAME", original)
	stored, err := g.drawFrom(rand.Reader, 0)
	if err != nil {
		return "", err
	}
	return g.render(stored), nil
}

// nameShape is how one occurrence of a PERSON_NAME is written.
type nameShape struct {
	title  string   // a leading title ("Dr."), written back unchanged
	tokens []string // the name's tokens in First ... Last order
	comma  bool     // written "Last, First ..."
	upper  bool     // every letter is upper case
	lower  bool     // every letter is lower case
}

// parseName reads a name's title, tokens, order and case. The title rule is the generator's
// historical one: a first token ending in "." of at most five bytes.
func parseName(value string) nameShape {
	var sh nameShape
	fields := strings.Fields(value)
	if len(fields) > 0 && strings.HasSuffix(fields[0], ".") && len(fields[0]) <= 5 {
		sh.title = fields[0]
		fields = fields[1:]
	}
	rest := strings.Join(fields, " ")
	if i := strings.IndexByte(rest, ','); i >= 0 {
		last := strings.Fields(rest[:i])
		first := strings.Fields(strings.ReplaceAll(rest[i+1:], ",", " "))
		if len(last) > 0 && len(first) > 0 {
			sh.comma = true
			sh.tokens = append(first, last...)
		}
	}
	if !sh.comma {
		sh.tokens = strings.Fields(strings.ReplaceAll(rest, ",", " "))
	}
	hasUpper, hasLower := false, false
	for _, r := range rest {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		}
	}
	sh.upper = hasUpper && !hasLower
	sh.lower = hasLower && !hasUpper
	return sh
}

// key is the canonical spelling: the tokens in First ... Last order, case-folded, single-spaced.
func (sh nameShape) key() string {
	return strings.ToLower(strings.Join(sh.tokens, " "))
}

// render writes a stored name (first, middle initial, last, NUL-separated) in this occurrence's
// order, case and title.
func (sh nameShape) render(stored string) string {
	p := strings.SplitN(stored, "\x00", 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	first, mid, last := p[0], p[1], p[2]
	var parts []string
	if sh.comma && last != "" {
		parts = append(parts, last+",", first)
		if mid != "" {
			parts = append(parts, mid)
		}
	} else {
		for _, x := range []string{first, mid, last} {
			if x != "" {
				parts = append(parts, x)
			}
		}
	}
	name := strings.Join(parts, " ")
	switch {
	case sh.upper:
		name = strings.ToUpper(name)
	case sh.lower:
		name = strings.ToLower(name)
	}
	if sh.title != "" {
		name = sh.title + " " + name
	}
	return name
}

// drawName draws a stored name for a value of n tokens: a first name; a first and last name; or, for
// three or more, a first name, a middle initial and a last name.
func drawName(n int, s *source) (string, error) {
	db, err := nameDB()
	if err != nil {
		return "", err
	}
	first := db.first[s.intn(len(db.first))]
	switch {
	case n <= 1:
		return first + "\x00\x00", nil
	case n == 2:
		return first + "\x00\x00" + db.last[s.intn(len(db.last))], nil
	default:
		last := db.last[s.intn(len(db.last))]
		mid := strings.ToUpper(db.first[s.intn(len(db.first))][:1]) + "."
		return first + "\x00" + mid + "\x00" + last, nil
	}
}

// syntheticSecret generates a realistic-looking but fake secret value.
// It preserves the prefix pattern of well-known token formats so the
// replacement is recognisable as the same type of credential.
// awsExampleMarker is the literal AWS embeds in the credential values it publishes in
// documentation, and the literal internal/validators/secrets keys its placeholder ceiling
// on. Duplicated rather than imported to avoid a dependency from a redactor onto a
// validator; a test asserts the two agree.
const awsExampleMarker = "EXAMPLE"

// exampleBody is woven into synthetic credentials whose issuer publishes no reserved test
// namespace, so the value cannot be mistaken for a live secret by a person triaging a
// document. Unlike the AWS marker it carries no scoring meaning — no validator keys on it
// — so it is a legibility measure, not a detection one, and the gate in pkg/redact asserts
// which types actually stop being reported.
const exampleBody = "EXAMPLE"

func syntheticSecret(original, dataType string, s *source) string {
	const hexChars = "0123456789abcdef"
	const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	randHex := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = hexChars[s.intn(len(hexChars))]
		}
		return string(b)
	}
	randAlphaNum := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphaNum[s.intn(len(alphaNum))]
		}
		return string(b)
	}

	switch dataType {
	case "AWS_ACCESS_KEY":
		// AKIA + 9 random chars + "EXAMPLE" (16 after the prefix, as AWS keys are).
		//
		// The marker is not decorative: internal/validators/secrets recognises "EXAMPLE"
		// anywhere in an AWS credential as a documentation placeholder and caps it at
		// awsDocPlaceholderCeiling. Measured — AKIAU2I2TJRJVJN7HEHA scores 100, and the same
		// shape carrying EXAMPLE scores 15. So this reuses the tool's own placeholder
		// machinery instead of inventing a convention, and the replacement is unmistakable
		// to a human reading the file as well as to the scanner. AWS publishes
		// AKIAIOSFODNN7EXAMPLE for exactly this purpose.
		upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, 9)
		for i := range b {
			b[i] = upper[s.intn(len(upper))]
		}
		return "AKIA" + string(b) + awsExampleMarker
	case "GITHUB_TOKEN":
		// Preserve prefix (ghp_, gho_, etc.) from original
		prefix := "ghp_"
		if len(original) >= 4 {
			prefix = original[:4]
		}
		return prefix + exampleBody + randAlphaNum(29)
	case "GOOGLE_CLOUD_API_KEY":
		return "AIza" + exampleBody + randAlphaNum(28)
	case "STRIPE_API_KEY":
		prefix := "sk_test_"
		if strings.HasPrefix(original, "pk_") {
			prefix = "pk_test_"
		}
		return prefix + exampleBody + randAlphaNum(17)
	case "GITLAB_TOKEN":
		return "glpat-" + exampleBody + randAlphaNum(13)
	case "DOCKER_TOKEN":
		return "dckr_pat_" + randAlphaNum(36)
	case "SLACK_TOKEN":
		prefix := "xoxb-"
		if strings.HasPrefix(original, "xoxp-") {
			prefix = "xoxp-"
		}
		return prefix + randAlphaNum(12) + "-" + randAlphaNum(12) + "-" + randAlphaNum(24)
	case "JWT_TOKEN":
		// Generate a fake but structurally valid JWT (3 base64url parts)
		header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		payload := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlJlZGFjdGVkIiwiaWF0IjoxNTE2MjM5MDIyfQ"
		sig := randAlphaNum(43)
		return header + "." + payload + "." + sig
	case "SSH_PRIVATE_KEY", "CERTIFICATE", "PGP_PRIVATE_KEY":
		// Return a clearly fake but structurally similar placeholder
		return "[PRIVATE-KEY-REDACTED-" + randHex(8) + "]"
	default:
		// Generic: preserve length and rough character class of original
		if len(original) == 0 {
			return "[SECRET-REDACTED]"
		}
		// Detect if original looks like hex
		isHex := true
		for _, c := range original {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				isHex = false
				break
			}
		}
		if isHex && len(original) >= 16 {
			return randHex(len(original))
		}
		return randAlphaNum(len(original))
	}
}

// syntheticPassport generates a realistic-looking but fake passport number.
// It detects the country format from the original and generates a matching fake.
func syntheticPassport(original string, s *source) string {
	upper := strings.ToUpper(strings.ReplaceAll(original, " ", ""))

	upper26 := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randLetter := func() byte { return upper26[s.intn(26)] }
	// #nosec G115 -- s.intn(10) returns [0,9]; '0' + 9 = 57, fits in byte
	randDigit := func() byte { return byte('0' + s.intn(10)) }

	switch {
	case len(upper) == 9 && upper[0] >= 'A' && upper[0] <= 'Z' && isAllDigits(upper[1:]):
		// US format: L########
		b := []byte{randLetter()}
		for i := 0; i < 8; i++ {
			b = append(b, randDigit())
		}
		return string(b)

	case len(upper) == 9 && isAllDigits(upper):
		// UK format: #########
		b := make([]byte, 9)
		for i := range b {
			b[i] = randDigit()
		}
		return string(b)

	case len(upper) == 8 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] >= 'A' && upper[1] <= 'Z' && isAllDigits(upper[2:]):
		// Canada format: LL######
		b := []byte{randLetter(), randLetter()}
		for i := 0; i < 6; i++ {
			b = append(b, randDigit())
		}
		return string(b)

	case len(upper) == 9 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] >= 'A' && upper[1] <= 'Z':
		// EU format: LL + 7 alphanumeric
		alphaNum := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := []byte{randLetter(), randLetter()}
		for i := 0; i < 7; i++ {
			b = append(b, alphaNum[s.intn(len(alphaNum))])
		}
		return string(b)

	default:
		// Generic: same length, same character class pattern
		b := make([]byte, len(upper))
		for i, c := range upper {
			if c >= 'A' && c <= 'Z' {
				b[i] = randLetter()
			} else if c >= '0' && c <= '9' {
				b[i] = randDigit()
			} else {
				// #nosec G115 -- c is a rune iterated from upper, an ASCII-only string
				// (uppercased + space-stripped at line 444), so it fits in byte.
				b[i] = byte(c)
			}
		}
		return string(b)
	}
}

// syntheticSocialMedia generates a fake but realistic-looking social media URL or handle.
func syntheticSocialMedia(original string, s *source) string {
	lower := strings.ToLower(original)

	// Detect platform and generate matching fake
	fakeUsernames := []string{
		"user_redacted", "profile_hidden", "account_removed",
		"redacted_user", "hidden_profile",
	}
	fakeUser := fakeUsernames[s.intn(len(fakeUsernames))]
	fakeNum := s.intn(9999)
	fakeHandle := fmt.Sprintf("%s_%04d", fakeUser, fakeNum)

	switch {
	case strings.Contains(lower, "linkedin.com"):
		return fmt.Sprintf("https://www.linkedin.com/in/%s", fakeHandle)
	case strings.Contains(lower, "twitter.com") || strings.Contains(lower, "x.com"):
		return fmt.Sprintf("https://x.com/%s", fakeHandle)
	case strings.Contains(lower, "github.com"):
		return fmt.Sprintf("https://github.com/%s", fakeHandle)
	case strings.Contains(lower, "facebook.com") || strings.Contains(lower, "fb.com"):
		return fmt.Sprintf("https://www.facebook.com/%s", fakeHandle)
	case strings.Contains(lower, "instagram.com"):
		return fmt.Sprintf("https://www.instagram.com/%s/", fakeHandle)
	case strings.Contains(lower, "youtube.com"):
		return fmt.Sprintf("https://www.youtube.com/@%s", fakeHandle)
	case strings.Contains(lower, "tiktok.com"):
		return fmt.Sprintf("https://www.tiktok.com/@%s/", fakeHandle)
	case strings.Contains(lower, "reddit.com"):
		return fmt.Sprintf("https://www.reddit.com/user/%s", fakeHandle)
	case strings.HasPrefix(original, "@"):
		// Plain handle
		return "@" + fakeHandle
	default:
		return "@" + fakeHandle
	}
}

// ipArm is the kind of INTELLECTUAL_PROPERTY value syntheticIntellectualProperty writes for.
type ipArm int

const (
	ipNotice ipArm = iota // anything else: "[IP-REDACTED]"
	ipCopyright
	ipPatent
	ipTrademark
	ipConfidential
)

// intellectualPropertyArm classifies an INTELLECTUAL_PROPERTY value, in the generator's order.
func intellectualPropertyArm(original string) ipArm {
	lower := strings.ToLower(original)
	switch {
	case strings.Contains(lower, "©") || strings.Contains(lower, "copyright") || strings.Contains(lower, "(c)"):
		return ipCopyright
	case strings.Contains(lower, "patent") || strings.HasPrefix(strings.ToUpper(original), "US") ||
		strings.HasPrefix(strings.ToUpper(original), "EP"):
		return ipPatent
	case strings.Contains(lower, "™") || strings.Contains(lower, "®") ||
		strings.Contains(lower, "(tm)") || strings.Contains(lower, "(r)"):
		return ipTrademark
	case strings.Contains(lower, "confidential") || strings.Contains(lower, "proprietary") ||
		strings.Contains(lower, "trade secret") || strings.Contains(lower, "restricted"):
		return ipConfidential
	default:
		return ipNotice
	}
}

// syntheticIntellectualProperty generates a fake but structurally valid IP reference.
func syntheticIntellectualProperty(arm ipArm, s *source) string {
	switch arm {
	case ipCopyright:
		year := 2000 + s.intn(26) // 2000–2025
		return fmt.Sprintf("© %d Redacted Corporation. All rights reserved.", year)

	case ipPatent:
		prefixes := []string{"US", "EP", "WO", "JP", "CN"}
		prefix := prefixes[s.intn(len(prefixes))]
		num := 1000000 + s.intn(8999999)
		return fmt.Sprintf("%s%d", prefix, num)

	case ipTrademark:
		return "[TRADEMARK-REDACTED]™"

	case ipConfidential:
		labels := []string{
			"CONFIDENTIAL", "PROPRIETARY", "INTERNAL USE ONLY",
			"RESTRICTED", "COMPANY CONFIDENTIAL",
		}
		return labels[s.intn(len(labels))]

	default:
		return "[IP-REDACTED]"
	}
}

// isAllDigits returns true if every character in s is an ASCII digit.
func isAllDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

var (
	nonDigit = regexp.MustCompile(`\D`)
	digitRe  = regexp.MustCompile(`\d`)
)

// source is the randomness one synthetic draw reads: crypto/rand.Reader in a real run, a stream
// derived from a seed under redactors.NewSeededSyntheticScope in a test.
//
// The first failed read is kept in err and every later draw returns 0; the generator's caller returns
// err (synthGen.drawFrom). The previous helper replaced a failed crypto/rand read with
// time.Now().UnixNano() % max, a value an observer of the clock can predict.
type source struct {
	r   io.Reader
	err error
}

// intn returns a uniform value in [0, n), by rejection sampling over 64 random bits.
func (s *source) intn(n int) int {
	if n <= 1 || s.err != nil {
		return 0
	}
	bound := uint64(n)
	limit := math.MaxUint64 - math.MaxUint64%bound // [0, limit) holds whole cycles of bound
	var b [8]byte
	for {
		if _, err := io.ReadFull(s.r, b[:]); err != nil {
			s.err = fmt.Errorf("reading randomness for a synthetic value: %w", err)
			return 0
		}
		if v := binary.BigEndian.Uint64(b[:]); v < limit {
			return int(v % bound) // #nosec G115 -- v % bound < n, which is an int
		}
	}
}

func randomString(length int, s *source) string {
	if length <= 0 {
		return ""
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[s.intn(len(charset))]
	}
	return string(b)
}

// invalidLuhnDigit returns a final digit that makes the sequence FAIL the Luhn check.
//
// Deliberately (correct + 1) mod 10 rather than a random digit: a random choice would land
// on the correct digit one time in ten, so one card in ten would still be valid — and a
// generator that is right 90% of the time is the hardest kind of bug to notice, because
// every test that samples once usually passes. This is wrong by construction.
func invalidLuhnDigit(digits []int) int {
	return (luhnCheck(digits) + 1) % 10
}

func luhnCheck(digits []int) int {
	sum := 0
	alt := true
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d = d/10 + d%10
			}
		}
		sum += d
		alt = !alt
	}
	return (10 - (sum % 10)) % 10
}
