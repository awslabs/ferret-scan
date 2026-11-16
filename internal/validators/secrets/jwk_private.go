// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"slices"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/context"
	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// JWK private members (#902 Part C).
//
// A JSON Web Key carries its private half in named members (RFC 7518 §6): `d` for RSA/EC/OKP, the
// RSA CRT members `p`, `q`, `dp`, `dq`, `qi`, and `k` for a symmetric (`oct`) key. On main such a
// value was seen only by the quoted-entropy path, which has no evidence it is a credential and caps
// it at 55 (LOW): a private JWKS was never reported at the documented pre-commit `high,medium`
// filter. The evidence is structural: the member sits in the same JSON object as a `"kty"` naming a
// key type. This post-pass finds exactly those members:
//
//   - One linear pass over the content, only when it contains `"kty"`: a JSON tokenizer that tracks
//     the object stack, so a member in a pretty-printed key (kty and d on different lines) and one in
//     a one-line JWKS are found alike, and a `d` in an object without `kty` is not.
//   - Additive and type-preserving: a member whose exact text a finding on its line already reports
//     keeps that finding's Type, Text and line (Type derives from the text, so it is the same); the
//     finding is replaced by this one only when this one scores higher, which is what
//     mergeBySpanKeepStrongest does for two claims on one span. A member inside a wider finding is
//     left to it.
//
// shortcut: a JWK serialised inside a JSON string (`"{\"kty\":...}"`) is not parsed; upgrade by
// unescaping one level when a carrier like that is measured.
const (
	methodJWKPrivateMember = "jwk_private_member"
	jwkMemberMinLen        = 22
)

// jwkKeyTypes are the RFC 7518 `kty` values, and jwkPrivateMembers the members that hold private
// key material for them.
var (
	jwkKeyTypes       = map[string]bool{"RSA": true, "EC": true, "OKP": true, "oct": true}
	jwkPrivateMembers = map[string]bool{"d": true, "p": true, "q": true, "dp": true, "dq": true, "qi": true, "k": true}
)

type jwkSpan struct{ start, end int }

// findJWKPrivateMembers returns the byte spans (the string value, without quotes) of every private
// member of a JSON object that also has a known `"kty"`. Linear: each byte is visited once, and a
// frame's members are emitted when the frame closes (or at end of input, for a truncated document).
func findJWKPrivateMembers(content string) []jwkSpan {
	if !strings.Contains(content, `"kty"`) {
		return nil
	}
	type frame struct {
		kty     bool
		members []jwkSpan
	}
	var (
		stack []frame
		out   []jwkSpan
	)
	pendingKey := "" // the key whose value comes next, in the innermost object
	emit := func(f frame) {
		if f.kty {
			out = append(out, f.members...)
		}
	}
	readString := func(i int) (int, int, bool) { // i at the opening quote; returns value span
		for j := i + 1; j < len(content); j++ {
			switch content[j] {
			case '\\':
				j++
			case '"':
				return i + 1, j, true
			case '\n':
				return 0, 0, false // not a JSON string
			}
		}
		return 0, 0, false
	}
	for i := 0; i < len(content); i++ {
		switch c := content[i]; c {
		case '{':
			stack = append(stack, frame{})
			pendingKey = ""
		case '}':
			if n := len(stack); n > 0 {
				emit(stack[n-1])
				stack = stack[:n-1]
			}
			pendingKey = ""
		case ',', '[', ']':
			pendingKey = ""
		case '"':
			s, e, ok := readString(i)
			if !ok {
				continue
			}
			i = e
			if len(stack) == 0 {
				continue
			}
			// A key is a string followed by a colon; anything else is a value.
			j := e + 1
			for j < len(content) && (content[j] == ' ' || content[j] == '\t' || content[j] == '\r' || content[j] == '\n') {
				j++
			}
			if j < len(content) && content[j] == ':' {
				pendingKey = content[s:e]
				i = j
				continue
			}
			top := &stack[len(stack)-1]
			switch {
			case pendingKey == "kty" && jwkKeyTypes[content[s:e]]:
				top.kty = true
			case jwkPrivateMembers[pendingKey] && jwkMemberValue(content[s:e]):
				top.members = append(top.members, jwkSpan{s, e})
			}
			pendingKey = ""
		}
	}
	for k := len(stack) - 1; k >= 0; k-- {
		emit(stack[k])
	}
	return out
}

// jwkMemberValue reports whether v is a base64url value long enough to be key material (RFC 7515
// base64url, padding tolerated).
func jwkMemberValue(v string) bool {
	v = strings.TrimRight(v, "=")
	if len(v) < jwkMemberMinLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !isAlnumByte(c) && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

// appendJWKPrivateMembers is the post-pass of validateContentCtx for JWK private members. The
// member is scored as a corroborated, structural candidate (the `kty` object is the keyword), so it
// is not held at the 55 cap and a test/dev marker demotes it without dropping it.
func (v *Validator) appendJWKPrivateMembers(matches []detector.Match, content, filePath string, contextInsights context.ContextInsights, isShellScript bool, envType string) []detector.Match {
	spans := findJWKPrivateMembers(content)
	if len(spans) == 0 {
		return matches
	}
	slices.SortFunc(spans, func(a, b jwkSpan) int { return a.start - b.start })
	byLine := make(map[int][]int, len(matches))
	for i, m := range matches {
		byLine[m.LineNumber] = append(byLine[m.LineNumber], i)
	}
	line, at, lineStart, lineEnd := 1, 0, 0, -1
	var same map[string]int // text -> index of the findings on the current line
	perLine := 0
	for _, sp := range spans {
		if n := strings.Count(content[at:sp.start], "\n"); n > 0 || lineEnd < 0 {
			line += n
			if n > 0 {
				lineStart = at + strings.LastIndexByte(content[at:sp.start], '\n') + 1
			}
			if lineEnd = strings.IndexByte(content[sp.start:], '\n'); lineEnd < 0 {
				lineEnd = len(content)
			} else {
				lineEnd += sp.start
			}
			same, perLine = make(map[string]int, len(byLine[line])), 0
			for _, i := range byLine[line] {
				same[matches[i].Text] = i
			}
		}
		at = sp.start
		perLine++
		lineText := content[lineStart:lineEnd]
		text := content[sp.start:sp.end]
		confidence, reported, checks := v.calculateEnhancedConfidenceWithCacheAndEnvAndLine(text, content, lineText, lineKeywordPresent, contextInsights, isShellScript, envType, true, 0)
		if confidence <= 0 || reported <= passwordHashThreshold {
			continue
		}
		secretType := v.getSecretType(text)
		m := detector.Match{
			Text:       text,
			LineNumber: line,
			Type:       secretType,
			Confidence: confidence,
			Filename:   filePath,
			Validator:  "secrets",
			// #nosec G101 -- detection metadata; secret_type is a label classifying what we found.
			Metadata: map[string]any{
				"validation_checks": checks,
				"detection_method":  methodJWKPrivateMember,
				"secret_type":       secretType,
				"context_domain":    contextInsights.Domain,
				"context_doc_type":  contextInsights.DocumentType,
				"environment_type":  envType,
			},
			Context: detector.LineContext(lineText, sp.start-lineStart, sp.end-lineStart),
		}
		if i, ok := same[text]; ok {
			// Same bytes already reported: keep the stronger of the two claims (Type is the same,
			// since it derives from the text).
			if matches[i].Confidence < confidence {
				matches[i] = m
			}
			continue
		}
		if perLine <= containerCoverScanLimit && containerEnclosed(matches, byLine[line], text) {
			continue
		}
		matches = append(matches, m)
	}
	return matches
}
