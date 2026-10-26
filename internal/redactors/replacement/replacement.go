// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package replacement provides a single source of truth for all redaction
// replacement generation. Previously this logic was duplicated across the
// plaintext, office, and pdf redactors. All redactors now call Generate().
package replacement

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
	"github.com/awslabs/ferret-scan/v2/internal/validators/personname"

	"github.com/awslabs/ferret-scan/v2/internal/textnorm"
)

// nameDB caches the loaded name databases so they are only decompressed once.
var (
	nameDBOnce  = struct{ done bool }{}
	cachedFirst []string
	cachedLast  []string
)

func loadNames() ([]string, []string) {
	if nameDBOnce.done {
		return cachedFirst, cachedLast
	}
	nameDBOnce.done = true

	db, err := personname.LoadNameDatabases()
	if err != nil || db == nil {
		return nil, nil
	}

	first := make([]string, 0, len(db.FirstNames))
	for n := range db.FirstNames {
		if len(n) > 0 {
			first = append(first, strings.ToUpper(n[:1])+n[1:])
		}
	}
	last := make([]string, 0, len(db.LastNames))
	for n := range db.LastNames {
		if len(n) > 0 {
			last = append(last, strings.ToUpper(n[:1])+n[1:])
		}
	}

	cachedFirst = first
	cachedLast = last
	return first, last
}

// Generate returns a replacement string for originalText of the given dataType
// using the requested strategy. It never returns an error — on any failure it
// falls back to the simple placeholder so callers stay clean.
func Generate(originalText, dataType string, strategy redactors.RedactionStrategy) string {
	return Render(originalText, dataType, strategy).Text
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
func Render(original, dataType string, strategy redactors.RedactionStrategy) Rendering {
	switch strategy {
	case redactors.RedactionSimple:
		return Rendering{Text: Simple(dataType)}
	case redactors.RedactionFormatPreserving:
		text := FormatPreserving(original, dataType)
		return newRendering(text, original, formatPreservingCopies(original, dataType), false)
	case redactors.RedactionSynthetic:
		text, err := Synthetic(original, dataType)
		if err != nil {
			return Rendering{Text: Simple(dataType)}
		}
		folded := textnorm.Fold(original)
		return newRendering(text, folded, syntheticCopies(folded, dataType, text), folded != original)
	default:
		return Rendering{Text: Simple(dataType)}
	}
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
	case dataType == "EMAIL", dataType == "GMAIL", dataType == "BUSINESS":
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
func syntheticCopies(value, dataType, text string) []Copy {
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
	case dataType == "SSN", dataType == "PHONE":
		// Digits are regenerated one for one; everything else is written back.
		return runsWhere(value, func(i int) bool { return value[i] < '0' || value[i] > '9' })
	case dataType == "PERSON_NAME":
		// SyntheticName keeps a leading title ("Dr.") when it produced a name at all.
		fields := strings.Fields(value)
		if len(fields) == 0 || !strings.HasSuffix(fields[0], ".") || len(fields[0]) > 5 {
			return nil
		}
		if !strings.HasPrefix(text, fields[0]+" ") && text != fields[0] {
			return nil // the placeholder fallback: nothing of the value was kept
		}
		return []Copy{{In: strings.Index(value, fields[0]), Out: 0, Len: len(fields[0])}}
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
func RenderGroup(g redactors.OverlapGroup, matches []detector.Match, strategy redactors.RedactionStrategy) Rendering {
	rep := matches[g.Representative]
	if !g.IsGroup() {
		return Render(rep.Text, rep.Type, strategy)
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
		r := Render(g.Text, rep.Type, strategy)
		if !anyGuard {
			return r
		}
		return withhold(r, g.Text, strategy, rep.Type, func(p int) bool { return !guarded[p] })

	case redactors.GroupIdentical:
		r := Render(g.Text, rep.Type, strategy)
		return withhold(r, g.Text, strategy, rep.Type, keptByEveryCoveringMember(g, matches, strategy))

	case redactors.GroupPartial:
		if t, ok := sharedType(g, matches); ok {
			r := Render(g.Text, t, strategy)
			return withhold(r, g.Text, strategy, rep.Type, keptByEveryCoveringMember(g, matches, strategy))
		}
		if strategy == redactors.RedactionFormatPreserving {
			return Rendering{Text: strings.Repeat("*", len(g.Text))}
		}
		return Rendering{Text: Simple(rep.Type)}
	}
	return Render(g.Text, rep.Type, strategy)
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
		r := Render(matches[i].Text, matches[i].Type, strategy)
		if r.Normalized {
			continue
		}
		for _, c := range r.Copies {
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
// representative's placeholder (synthetic).
func withhold(r Rendering, value string, strategy redactors.RedactionStrategy, repType string, allowed func(p int) bool) Rendering {
	if len(r.Copies) == 0 {
		return r
	}
	if r.Normalized {
		// The copies are offsets into a folded spelling and cannot be checked byte by byte.
		return Rendering{Text: Simple(repType)}
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
		return Rendering{Text: Simple(repType)}
	}
	return newRendering(string(out), value, keep, false)
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
func Simple(dataType string) string {
	if isCreditCardType(dataType) {
		return "[CREDIT-CARD-REDACTED]"
	}
	switch dataType {
	case "SSN":
		return "[SSN-REDACTED]"
	case "EMAIL", "GMAIL", "BUSINESS":
		return "[EMAIL-REDACTED]"
	case "PHONE":
		return "[PHONE-REDACTED]"
	case "SECRETS":
		return "[SECRET-REDACTED]"
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
func FormatPreserving(original, dataType string) string {
	if isCreditCardType(dataType) {
		return preserveCreditCard(original)
	}
	switch dataType {
	case "SSN":
		return preserveSSN(original)
	case "EMAIL", "GMAIL", "BUSINESS":
		return preserveEmail(original)
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

// Synthetic generates realistic-looking but fake data of the same type.
func Synthetic(original, dataType string) (string, error) {
	// Generate from the CANONICAL form of the value.
	//
	// Every generator below rebuilds a value by walking the original and substituting the parts it
	// recognises — digitRe is [0-9], the passport generator copies A-Z. None of them recognises a
	// fullwidth digit or a Unicode dash, so for a value written with those the walk substitutes
	// nothing and returns the original UNCHANGED. The residue guard then correctly refuses to write a
	// file that still holds the reported value, so `--redaction-strategy synthetic` failed outright on
	// a document whose digits came from a CJK-locale form.
	//
	// Measured: with the normalization pass of #671 making these values reportable, three of ninety
	// substituted fixtures — SSN, VISA and PHONE with fullwidth digits — were refused under synthetic
	// while simple and format_preserving redacted them cleanly. Before #671 they were never reported
	// at all, so the refusal is new only in the sense that the value is finally visible.
	//
	// Folding here rather than widening each generator's character class: a synthetic replacement is a
	// realistic-looking SUBSTITUTE, not a byte-shape copy, so it has no reason to preserve the exotic
	// spelling of the value it replaces. format_preserving, which does have that reason, is untouched.
	original = textnorm.Fold(original)

	if isCreditCardType(dataType) {
		return syntheticCreditCard(original)
	}
	switch dataType {
	case "SSN":
		return syntheticSSN(original)
	case "EMAIL", "GMAIL", "BUSINESS":
		return syntheticEmail(original)
	case "PHONE":
		return syntheticPhone(original)
	case "IP_ADDRESS":
		return syntheticIP()
	case "PERSON_NAME":
		return SyntheticName(original)
	case "SECRETS", "API_KEY_OR_SECRET", "AWS_ACCESS_KEY", "GITHUB_TOKEN",
		"GOOGLE_CLOUD_API_KEY", "STRIPE_API_KEY", "GITLAB_TOKEN",
		"DOCKER_TOKEN", "SLACK_TOKEN", "JWT_TOKEN", "SSH_PRIVATE_KEY",
		"CERTIFICATE", "PGP_PRIVATE_KEY":
		return syntheticSecret(original, dataType)
	case "PASSPORT":
		return syntheticPassport(original)
	case "SOCIAL_MEDIA":
		return syntheticSocialMedia(original)
	case "INTELLECTUAL_PROPERTY":
		return syntheticIntellectualProperty(original)
	default:
		return randomString(len(original))
	}
}

// syntheticCreditCard produces a card-SHAPED value that is deliberately Luhn-INVALID and
// keeps the original's issuer prefix.
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
func syntheticCreditCard(original string) (string, error) {
	// Take the issuer prefix from the ORIGINAL so the brand is preserved.
	var origDigits []int
	for _, c := range original {
		if c >= '0' && c <= '9' {
			origDigits = append(origDigits, int(c-'0'))
		}
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
		digits = append(digits, secureRandom(10))
	}
	digits = append(digits, invalidLuhnDigit(digits))

	di := 0
	var b strings.Builder
	for _, c := range original {
		if c >= '0' && c <= '9' {
			if di < len(digits) {
				b.WriteString(fmt.Sprintf("%d", digits[di]))
				di++
			} else {
				b.WriteByte('0')
			}
		} else {
			b.WriteRune(c)
		}
	}
	return b.String(), nil
}

func syntheticSSN(original string) (string, error) {
	// Use area codes that are permanently invalid per SSA rules
	areas := []string{"000", "666", "900", "999"}
	area := areas[secureRandom(len(areas))]
	group := fmt.Sprintf("%02d", secureRandom(100))
	serial := fmt.Sprintf("%04d", secureRandom(10000))
	syn := area + group + serial

	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		if di < len(syn) {
			r := string(syn[di])
			di++
			return r
		}
		return "0"
	}), nil
}

func syntheticEmail(original string) (string, error) {
	parts := strings.SplitN(original, "@", 2)
	userLen := 8
	if len(parts) == 2 && len(parts[0]) > 0 {
		userLen = len(parts[0])
	}
	user, err := randomString(userLen)
	if err != nil {
		return "user@example.com", nil
	}
	return strings.ToLower(user) + "@example.com", nil
}

func syntheticPhone(original string) (string, error) {
	cleaned := nonDigit.ReplaceAllString(original, "")
	syn := "555"
	for len(syn) < len(cleaned) {
		syn += fmt.Sprintf("%d", secureRandom(10))
	}
	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		if di < len(syn) {
			r := string(syn[di])
			di++
			return r
		}
		return "0"
	}), nil
}

func syntheticIP() (string, error) {
	return fmt.Sprintf("192.168.%d.%d", secureRandom(256), secureRandom(256)), nil
}

// SyntheticName returns a realistic random name drawn from the embedded name
// databases (~5 200 first names, ~2 100 last names). It preserves the
// structure of the original: single token, two-part, three-part, and any
// title prefix (Dr., Mr., Ms., etc.).
func SyntheticName(original string) (string, error) {
	first, last := loadNames()
	if len(first) == 0 || len(last) == 0 {
		return "[PERSON-NAME-REDACTED]", nil
	}

	parts := strings.Fields(original)
	title := ""
	nameParts := parts
	if len(parts) > 0 && strings.HasSuffix(parts[0], ".") && len(parts[0]) <= 5 {
		title = parts[0] + " "
		nameParts = parts[1:]
	}

	f := first[secureRandom(len(first))]
	l := last[secureRandom(len(last))]

	switch len(nameParts) {
	case 0, 1:
		return title + f, nil
	case 2:
		return title + f + " " + l, nil
	default:
		mid := strings.ToUpper(first[secureRandom(len(first))][:1]) + "."
		return title + f + " " + mid + " " + l, nil
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

func syntheticSecret(original, dataType string) (string, error) {
	const hexChars = "0123456789abcdef"
	const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	randHex := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = hexChars[secureRandom(len(hexChars))]
		}
		return string(b)
	}
	randAlphaNum := func(n int) string {
		b := make([]byte, n)
		for i := range b {
			b[i] = alphaNum[secureRandom(len(alphaNum))]
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
			b[i] = upper[secureRandom(len(upper))]
		}
		return "AKIA" + string(b) + awsExampleMarker, nil
	case "GITHUB_TOKEN":
		// Preserve prefix (ghp_, gho_, etc.) from original
		prefix := "ghp_"
		if len(original) >= 4 {
			prefix = original[:4]
		}
		return prefix + exampleBody + randAlphaNum(29), nil
	case "GOOGLE_CLOUD_API_KEY":
		return "AIza" + exampleBody + randAlphaNum(28), nil
	case "STRIPE_API_KEY":
		prefix := "sk_test_"
		if strings.HasPrefix(original, "pk_") {
			prefix = "pk_test_"
		}
		return prefix + exampleBody + randAlphaNum(17), nil
	case "GITLAB_TOKEN":
		return "glpat-" + exampleBody + randAlphaNum(13), nil
	case "DOCKER_TOKEN":
		return "dckr_pat_" + randAlphaNum(36), nil
	case "SLACK_TOKEN":
		prefix := "xoxb-"
		if strings.HasPrefix(original, "xoxp-") {
			prefix = "xoxp-"
		}
		return prefix + randAlphaNum(12) + "-" + randAlphaNum(12) + "-" + randAlphaNum(24), nil
	case "JWT_TOKEN":
		// Generate a fake but structurally valid JWT (3 base64url parts)
		header := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		payload := "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlJlZGFjdGVkIiwiaWF0IjoxNTE2MjM5MDIyfQ"
		sig := randAlphaNum(43)
		return header + "." + payload + "." + sig, nil
	case "SSH_PRIVATE_KEY", "CERTIFICATE", "PGP_PRIVATE_KEY":
		// Return a clearly fake but structurally similar placeholder
		return "[PRIVATE-KEY-REDACTED-" + randHex(8) + "]", nil
	default:
		// Generic: preserve length and rough character class of original
		if len(original) == 0 {
			return "[SECRET-REDACTED]", nil
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
			return randHex(len(original)), nil
		}
		return randAlphaNum(len(original)), nil
	}
}

// syntheticPassport generates a realistic-looking but fake passport number.
// It detects the country format from the original and generates a matching fake.
func syntheticPassport(original string) (string, error) {
	upper := strings.ToUpper(strings.ReplaceAll(original, " ", ""))

	upper26 := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	randLetter := func() byte { return upper26[secureRandom(26)] }
	// #nosec G115 -- secureRandom(10) returns [0,9]; '0' + 9 = 57, fits in byte
	randDigit := func() byte { return byte('0' + secureRandom(10)) }

	switch {
	case len(upper) == 9 && upper[0] >= 'A' && upper[0] <= 'Z' && isAllDigits(upper[1:]):
		// US format: L########
		b := []byte{randLetter()}
		for i := 0; i < 8; i++ {
			b = append(b, randDigit())
		}
		return string(b), nil

	case len(upper) == 9 && isAllDigits(upper):
		// UK format: #########
		b := make([]byte, 9)
		for i := range b {
			b[i] = randDigit()
		}
		return string(b), nil

	case len(upper) == 8 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] >= 'A' && upper[1] <= 'Z' && isAllDigits(upper[2:]):
		// Canada format: LL######
		b := []byte{randLetter(), randLetter()}
		for i := 0; i < 6; i++ {
			b = append(b, randDigit())
		}
		return string(b), nil

	case len(upper) == 9 && upper[0] >= 'A' && upper[0] <= 'Z' && upper[1] >= 'A' && upper[1] <= 'Z':
		// EU format: LL + 7 alphanumeric
		alphaNum := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := []byte{randLetter(), randLetter()}
		for i := 0; i < 7; i++ {
			b = append(b, alphaNum[secureRandom(len(alphaNum))])
		}
		return string(b), nil

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
		return string(b), nil
	}
}

// syntheticSocialMedia generates a fake but realistic-looking social media URL or handle.
func syntheticSocialMedia(original string) (string, error) {
	lower := strings.ToLower(original)

	// Detect platform and generate matching fake
	fakeUsernames := []string{
		"user_redacted", "profile_hidden", "account_removed",
		"redacted_user", "hidden_profile",
	}
	fakeUser := fakeUsernames[secureRandom(len(fakeUsernames))]
	fakeNum := secureRandom(9999)
	fakeHandle := fmt.Sprintf("%s_%04d", fakeUser, fakeNum)

	switch {
	case strings.Contains(lower, "linkedin.com"):
		return fmt.Sprintf("https://www.linkedin.com/in/%s", fakeHandle), nil
	case strings.Contains(lower, "twitter.com") || strings.Contains(lower, "x.com"):
		return fmt.Sprintf("https://x.com/%s", fakeHandle), nil
	case strings.Contains(lower, "github.com"):
		return fmt.Sprintf("https://github.com/%s", fakeHandle), nil
	case strings.Contains(lower, "facebook.com") || strings.Contains(lower, "fb.com"):
		return fmt.Sprintf("https://www.facebook.com/%s", fakeHandle), nil
	case strings.Contains(lower, "instagram.com"):
		return fmt.Sprintf("https://www.instagram.com/%s/", fakeHandle), nil
	case strings.Contains(lower, "youtube.com"):
		return fmt.Sprintf("https://www.youtube.com/@%s", fakeHandle), nil
	case strings.Contains(lower, "tiktok.com"):
		return fmt.Sprintf("https://www.tiktok.com/@%s/", fakeHandle), nil
	case strings.Contains(lower, "reddit.com"):
		return fmt.Sprintf("https://www.reddit.com/user/%s", fakeHandle), nil
	case strings.HasPrefix(original, "@"):
		// Plain handle
		return "@" + fakeHandle, nil
	default:
		return "@" + fakeHandle, nil
	}
}

// syntheticIntellectualProperty generates a fake but structurally valid IP reference.
func syntheticIntellectualProperty(original string) (string, error) {
	lower := strings.ToLower(original)

	switch {
	case strings.Contains(lower, "©") || strings.Contains(lower, "copyright") || strings.Contains(lower, "(c)"):
		year := 2000 + secureRandom(26) // 2000–2025
		return fmt.Sprintf("© %d Redacted Corporation. All rights reserved.", year), nil

	case strings.Contains(lower, "patent") || strings.HasPrefix(strings.ToUpper(original), "US") ||
		strings.HasPrefix(strings.ToUpper(original), "EP"):
		prefixes := []string{"US", "EP", "WO", "JP", "CN"}
		prefix := prefixes[secureRandom(len(prefixes))]
		num := 1000000 + secureRandom(8999999)
		return fmt.Sprintf("%s%d", prefix, num), nil

	case strings.Contains(lower, "™") || strings.Contains(lower, "®") ||
		strings.Contains(lower, "(tm)") || strings.Contains(lower, "(r)"):
		return "[TRADEMARK-REDACTED]™", nil

	case strings.Contains(lower, "confidential") || strings.Contains(lower, "proprietary") ||
		strings.Contains(lower, "trade secret") || strings.Contains(lower, "restricted"):
		labels := []string{
			"CONFIDENTIAL", "PROPRIETARY", "INTERNAL USE ONLY",
			"RESTRICTED", "COMPANY CONFIDENTIAL",
		}
		return labels[secureRandom(len(labels))], nil

	default:
		return "[IP-REDACTED]", nil
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

func secureRandom(max int) int {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return int(time.Now().UnixNano()) % max
	}
	return int(n.Int64())
}

func randomString(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[secureRandom(len(charset))]
	}
	return string(b), nil
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
