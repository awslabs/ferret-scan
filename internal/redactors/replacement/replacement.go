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

	"ferret-scan/internal/redactors"
	"ferret-scan/internal/validators/personname"
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
	switch strategy {
	case redactors.RedactionSimple:
		return Simple(dataType)
	case redactors.RedactionFormatPreserving:
		return FormatPreserving(originalText, dataType)
	case redactors.RedactionSynthetic:
		result, err := Synthetic(originalText, dataType)
		if err != nil {
			return Simple(dataType)
		}
		return result
	default:
		return Simple(dataType)
	}
}

// ─── Simple ──────────────────────────────────────────────────────────────────

// Simple returns a bracketed placeholder for the given data type.
func Simple(dataType string) string {
	switch dataType {
	case "CREDIT_CARD", "VISA", "MASTERCARD", "AMERICAN_EXPRESS", "DISCOVER":
		return "[CREDIT-CARD-REDACTED]"
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
	switch dataType {
	case "CREDIT_CARD", "VISA", "MASTERCARD", "AMERICAN_EXPRESS", "DISCOVER":
		return preserveCreditCard(original)
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
	first4 := cleaned[:4]
	last4 := cleaned[len(cleaned)-4:]
	middle := strings.Repeat("*", len(cleaned)-8)
	digits := first4 + middle + last4
	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		if di < len(digits) {
			r := string(digits[di])
			di++
			return r
		}
		return "*"
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
	if len(user) == 1 {
		return user + "@" + parts[1]
	}
	return string(user[0]) + strings.Repeat("*", len(user)-1) + "@" + parts[1]
}

func preservePhone(original string) string {
	cleaned := nonDigit.ReplaceAllString(original, "")
	if len(cleaned) < 6 {
		return strings.Repeat("*", len(original))
	}
	first3 := cleaned[:3]
	last4 := cleaned[len(cleaned)-4:]
	middle := strings.Repeat("*", len(cleaned)-7)
	masked := first3 + middle + last4
	di := 0
	return digitRe.ReplaceAllStringFunc(original, func(_ string) string {
		if di < len(masked) {
			r := string(masked[di])
			di++
			return r
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
	switch dataType {
	case "CREDIT_CARD", "VISA", "MASTERCARD", "AMERICAN_EXPRESS", "DISCOVER":
		return syntheticCreditCard(original)
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

func syntheticCreditCard(original string) (string, error) {
	prefixes := []string{"4000", "4111", "5555", "3782"}
	prefix := prefixes[secureRandom(len(prefixes))]

	var digits []int
	for _, c := range prefix {
		if c >= '0' && c <= '9' {
			digits = append(digits, int(c-'0'))
		}
	}
	for len(digits) < 15 {
		digits = append(digits, secureRandom(10))
	}
	digits = append(digits, luhnCheck(digits))

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
		// AKIA + 16 uppercase alphanumeric chars
		upper := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		b := make([]byte, 16)
		for i := range b {
			b[i] = upper[secureRandom(len(upper))]
		}
		return "AKIA" + string(b), nil
	case "GITHUB_TOKEN":
		// Preserve prefix (ghp_, gho_, etc.) from original
		prefix := "ghp_"
		if len(original) >= 4 {
			prefix = original[:4]
		}
		return prefix + randAlphaNum(36), nil
	case "GOOGLE_CLOUD_API_KEY":
		return "AIza" + randAlphaNum(35), nil
	case "STRIPE_API_KEY":
		prefix := "sk_test_"
		if strings.HasPrefix(original, "pk_") {
			prefix = "pk_test_"
		}
		return prefix + randAlphaNum(24), nil
	case "GITLAB_TOKEN":
		return "glpat-" + randAlphaNum(20), nil
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
