// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Private-key containers outside 5-dash PEM (#902 Part B).
//
// The multi-line pass (findMultiLineSecretsWithContext) knows exactly three PEM label families, all
// in 5-dash armour. Every other way a private key is written to disk reached no capture path at
// all: a PuTTY .ppk, an ssh.com (RFC 4716 style, 4-dash) private key, an OpenVPN static or
// tls-crypt-v2 key, an age identity, and a 5-dash armour whose label is not in the alternation
// (`ED25519 PRIVATE KEY`, ...). This file is a separate, ADDITIVE source for them:
//
//   - Structure is the corroboration: each grammar is the container's own framing, so a found
//     container scores like the PEM arm (CalculateConfidence's privateKeyContainerKind arm, 95,
//     specific_pattern) and a test/dev marker demotes it but never drops it.
//   - It never changes what an existing path reports. A container whose bytes an existing finding
//     already reports -- the same text or a wider one on its first line, like a .ppk held in a JSON
//     string under `"private_key"` -- is not emitted, so that finding keeps its Type, Text and line.
//   - Each grammar has a literal prefilter and a bounded scan: the armour END search is memoised
//     per label, so a file of BEGIN markers with no END is one pass, not one pass per marker.
//
// Framing literals are concatenated like pemBeginMarker so this file does not itself look like a
// key to the repository's pre-commit hooks.
const (
	puttyHeaderLiteral = "PuTTY-User-Key-File-"
	ageSecretPrefix    = "AGE-" + "SECRET-KEY-1"
	// ageBech32Charset is BIP-173's data alphabet, upper case as age writes identities.
	ageBech32Charset = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L"
	ageDataLen       = 58

	containerMethodArmour  = "armoured_private_key"
	containerMethodPutty   = "putty_private_key"
	containerMethodOpenVPN = "openvpn_static_key"
	containerMethodAge     = "age_secret_key"

	// puttyPrivateLinesWindow bounds how far after a PPK header its Private-Lines record is looked
	// for. A real PPK's public block is a few KiB at most (an RSA-16384 public key is ~2.8 KiB of
	// base64); the bound keeps a file of headers with no key body linear.
	puttyPrivateLinesWindow = 64 << 10
)

var (
	// containerArmourBegin is a 4- or 5-dash BEGIN line for a private-key label: any upper-case
	// label ending `PRIVATE KEY` (ssh.com writes `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`), or an
	// OpenVPN static / tls-crypt-v2 key. RE2 has no backreferences, so the matching END is found in
	// code, by the label (findArmouredContainers).
	containerArmourBegin = regexp.MustCompile(`-{4,5} ?BEGIN ([A-Z0-9 ]*PRIVATE KEY|OpenVPN Static key V1|OpenVPN tls-crypt-v2 (?:client|server) key) ?-{4,5}`)

	// puttyHeader is the first line of every PPK version: `PuTTY-User-Key-File-<N>: <algorithm>`.
	// An unknown version is reported rather than skipped.
	puttyHeader = regexp.MustCompile(puttyHeaderLiteral + `(\d{1,3}): *([A-Za-z0-9@._-]+)`)

	// puttyPrivateLines is the record that introduces the private blob and gives its line count.
	puttyPrivateLines = regexp.MustCompile(`Private-Lines: *(\d{1,4})`)

	// puttyMAC is the optional trailer after the private blob (v2 and v3).
	puttyMAC = regexp.MustCompile(`^Private-MAC: *[0-9a-fA-F]{20,128}`)
)

// legacyArmourLabels are the 5-dash labels findMultiLineSecretsWithContext already reports. A
// 5-dash armour with one of them is left to that pass, so nothing it reports is reported twice.
var legacyArmourLabels = map[string]bool{
	"PRIVATE KEY": true, "RSA PRIVATE KEY": true, "DSA PRIVATE KEY": true, "EC PRIVATE KEY": true,
	"OPENSSH PRIVATE KEY": true, "ENCRYPTED PRIVATE KEY": true,
}

// keyContainer is one private-key container found in a file's content.
type keyContainer struct {
	start, end int    // byte span in the content
	method     string // detection_method
	secretType string
}

// findPrivateKeyContainers returns every non-legacy private-key container in content, in order of
// position, non-overlapping per grammar.
func findPrivateKeyContainers(content string) []keyContainer {
	var out []keyContainer
	if strings.Contains(content, "BEGIN ") {
		out = append(out, findArmouredContainers(content)...)
	}
	if strings.Contains(content, puttyHeaderLiteral) {
		out = append(out, findPuttyContainers(content)...)
	}
	if strings.Contains(content, ageSecretPrefix) {
		out = append(out, findAgeIdentities(content)...)
	}
	return out
}

// findArmouredContainers finds 4/5-dash armour blocks whose label the legacy pass does not know.
// The END marker must carry the same label; it is searched once per label from the furthest point
// a previous search reached, so the scan is linear in the content however many BEGINs it holds.
func findArmouredContainers(content string) []keyContainer {
	var out []keyContainer
	noEndAfter := map[string]int{} // label -> offset after which no END for it exists
	pos := 0
	for pos < len(content) {
		loc := containerArmourBegin.FindStringSubmatchIndex(content[pos:])
		if loc == nil {
			break
		}
		begin, beginEnd := pos+loc[0], pos+loc[1]
		label := content[pos+loc[2] : pos+loc[3]]
		fiveDash := strings.HasPrefix(content[begin:], "-----") && !strings.HasPrefix(content[begin:], "----- ")
		if fiveDash && legacyArmourLabels[label] {
			pos = beginEnd
			continue
		}
		if limit, ok := noEndAfter[label]; ok && beginEnd >= limit {
			pos = beginEnd
			continue
		}
		endRel := strings.Index(content[beginEnd:], "END "+label)
		if endRel < 0 {
			noEndAfter[label] = beginEnd
			pos = beginEnd
			continue
		}
		end := beginEnd + endRel + len("END "+label)
		// The END line's own trailing dashes (and the optional space before them) belong to the span.
		if end < len(content) && content[end] == ' ' {
			end++
		}
		for end < len(content) && content[end] == '-' {
			end++
		}
		method, typ := containerMethodArmour, "SSH_PRIVATE_KEY"
		if strings.HasPrefix(label, "OpenVPN") {
			method, typ = containerMethodOpenVPN, genericSecretType
		}
		out = append(out, keyContainer{start: begin, end: end, method: method, secretType: typ})
		pos = end
	}
	return out
}

// findPuttyContainers finds PuTTY private-key files: the header, then `Private-Lines: N` and N
// base64 lines, then the optional `Private-MAC:` trailer. Lines may be indented (a YAML block
// scalar, a heredoc), end in CRLF, or be joined by a literal `\n` escape (a JSON string). A
// header with no Private-Lines record after it is prose, not a key, and is not reported.
func findPuttyContainers(content string) []keyContainer {
	var out []keyContainer
	pos := 0
	for pos < len(content) {
		loc := puttyHeader.FindStringIndex(content[pos:])
		if loc == nil {
			break
		}
		start, hdrEnd := pos+loc[0], pos+loc[1]
		pos = hdrEnd
		window := content[hdrEnd:min(len(content), hdrEnd+puttyPrivateLinesWindow)]
		if next := strings.Index(window, puttyHeaderLiteral); next >= 0 {
			window = window[:next]
		}
		pl := puttyPrivateLines.FindStringSubmatchIndex(window)
		if pl == nil {
			continue
		}
		n, err := strconv.Atoi(window[pl[2]:pl[3]])
		if err != nil || n < 1 {
			continue
		}
		cur := hdrEnd + pl[1]
		lines := 0
		for lines < n {
			next, ok := nextContainerLine(content, cur)
			if !ok {
				break
			}
			b64End := next
			for b64End < len(content) && isBase64Byte(content[b64End]) {
				b64End++
			}
			if b64End == next {
				break
			}
			cur = b64End
			lines++
		}
		if lines == 0 {
			continue
		}
		end := cur
		if next, ok := nextContainerLine(content, cur); ok {
			if m := puttyMAC.FindStringIndex(content[next:min(len(content), next+160)]); m != nil {
				end = next + m[1]
			}
		}
		out = append(out, keyContainer{start: start, end: end, method: containerMethodPutty, secretType: "SSH_PRIVATE_KEY"})
		pos = end
	}
	return out
}

// nextContainerLine skips one line break at i -- `\n`, `\r\n`, or a literal two-byte `\n` escape --
// and the indentation after it, and returns where the next line's text starts.
func nextContainerLine(content string, i int) (int, bool) {
	switch {
	case strings.HasPrefix(content[i:], "\r\n"):
		i += 2
	case strings.HasPrefix(content[i:], "\n"):
		i++
	case strings.HasPrefix(content[i:], `\r\n`):
		i += 4
	case strings.HasPrefix(content[i:], `\n`):
		i += 2
	default:
		return i, false
	}
	for i < len(content) && (content[i] == ' ' || content[i] == '\t') {
		i++
	}
	return i, i < len(content)
}

func isBase64Byte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' || c == '='
}

// findAgeIdentities finds age X25519 identities: `AGE-SECRET-KEY-1` and 58 bech32 data characters,
// bounded on both sides by a non-alphanumeric byte. The checksum is not verified: a key with a
// typo is still a key someone meant to keep secret.
func findAgeIdentities(content string) []keyContainer {
	var out []keyContainer
	pos := 0
	for {
		rel := strings.Index(content[pos:], ageSecretPrefix)
		if rel < 0 {
			return out
		}
		start := pos + rel
		dataStart := start + len(ageSecretPrefix)
		pos = dataStart
		if start > 0 && isAlnumByte(content[start-1]) {
			continue
		}
		end := dataStart
		for end < len(content) && end-dataStart < ageDataLen && strings.IndexByte(ageBech32Charset, content[end]) >= 0 {
			end++
		}
		if end-dataStart != ageDataLen || (end < len(content) && isAlnumByte(content[end])) {
			continue
		}
		out = append(out, keyContainer{start: start, end: end, method: containerMethodAge, secretType: genericSecretType})
		pos = end
	}
}

func isAlnumByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

// privateKeyContainerKind reports whether match is, in its entirety, one private-key container this
// file finds, and which. CalculateConfidence uses it to score a container like the PEM arm. The
// literal prefilter keeps the check free for every other candidate.
func privateKeyContainerKind(match string) (string, bool) {
	if !strings.Contains(match, "BEGIN ") && !strings.Contains(match, puttyHeaderLiteral) && !strings.Contains(match, ageSecretPrefix) {
		return "", false
	}
	for _, c := range findPrivateKeyContainers(match) {
		if c.start == 0 && c.end == len(match) {
			return c.method, true
		}
	}
	return "", false
}

// appendPrivateKeyContainers is the post-pass of validateContentCtx for whole-content key framing.
// matches holds the whole file's findings, the first nMultiLine of them from
// findMultiLineSecretsWithContext. It does two things:
//
//  1. It drops a per-line copy of a multi-line PEM finding: a later finding on a line inside a PEM
//     finding whose text equals, contains or is contained in the PEM's. Before this, a PEM written
//     on one line (space-joined, or a JSON string with `\n` escapes) was reported by the multi-line
//     pass AND by the keyword pass's copy of the same pattern, and a third time under a
//     `"private_key"` label: 2-3 findings, 2-3 suppression rules, for one key. The multi-line
//     finding, the exact PEM span, is the one kept, so its suppression hash does not move.
//  2. It appends the containers findPrivateKeyContainers finds, unless a finding already reports
//     the same bytes or a wider span holding them on the container's first line.
func (v *Validator) appendPrivateKeyContainers(matches []detector.Match, nMultiLine int, content, filePath string, contextInsights context.ContextInsights, isShellScript bool, envType string) []detector.Match {
	if nMultiLine > 0 {
		matches = dropPerLineCopiesOfPEM(matches, nMultiLine)
	}
	containers := findPrivateKeyContainers(content)
	if len(containers) == 0 {
		return matches
	}
	byLine := make(map[int][]int, len(matches))
	for i, m := range matches {
		byLine[m.LineNumber] = append(byLine[m.LineNumber], i)
	}
	line, at := 1, 0
	for _, c := range containers {
		line += strings.Count(content[at:c.start], "\n")
		at = c.start
		text := content[c.start:c.end]
		covered := false
		for _, i := range byLine[line] {
			if strings.Contains(matches[i].Text, text) {
				covered = true
				break
			}
		}
		if covered {
			continue
		}
		confidence, checks := v.calculateEnhancedConfidenceWithCacheAndEnv(text, content, contextInsights, isShellScript, envType)
		matches = append(matches, detector.Match{
			Text:       text,
			LineNumber: line,
			Type:       c.secretType,
			Confidence: confidence,
			Filename:   filePath,
			Validator:  "secrets",
			// #nosec G101 -- detection metadata; secret_type is a label classifying what we found.
			Metadata: map[string]any{
				"validation_checks": checks,
				"detection_method":  c.method,
				"secret_type":       c.secretType,
				"context_domain":    contextInsights.Domain,
				"context_doc_type":  contextInsights.DocumentType,
				"environment_type":  envType,
			},
		})
	}
	return matches
}

// dropPerLineCopiesOfPEM removes, from matches[nMultiLine:], every finding that sits on a line a
// multi-line finding spans and whose text equals, contains or is contained in that finding's.
func dropPerLineCopiesOfPEM(matches []detector.Match, nMultiLine int) []detector.Match {
	spans := make(map[int][]int, nMultiLine) // line -> indices of multi-line findings covering it
	for i := 0; i < nMultiLine; i++ {
		m := matches[i]
		last := m.LineNumber + strings.Count(m.Text, "\n")
		for l := m.LineNumber; l <= last; l++ {
			spans[l] = append(spans[l], i)
		}
	}
	kept := matches[:nMultiLine]
	for _, p := range matches[nMultiLine:] {
		copyOf := false
		for _, i := range spans[p.LineNumber] {
			if t := matches[i].Text; strings.Contains(t, p.Text) || strings.Contains(p.Text, t) {
				copyOf = true
				break
			}
		}
		if !copyOf {
			kept = append(kept, p)
		}
	}
	return kept
}
