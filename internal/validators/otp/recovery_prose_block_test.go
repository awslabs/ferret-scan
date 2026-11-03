// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package otp

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"testing"
)

// A bare topic word anywhere on a line (backup, recovery, emergency, 2fa, mfa) gives it recovery
// context, and reRecoveryCodeBlock matches any run of hyphenated words, so a runbook line with
// "backup" in a path reported its kebab-case flags and path segments as RECOVERY_CODES (#798).

// recoveryFindings returns "text=confidence" for each RECOVERY_CODES finding on line, sorted.
func recoveryFindings(t *testing.T, line string) []string {
	t.Helper()
	matches, err := NewValidator().ValidateContent(line, "runbook.md")
	if err != nil {
		t.Fatalf("ValidateContent(%q): %v", line, err)
	}
	var got []string
	for _, m := range matches {
		if m.Type == "RECOVERY_CODES" {
			got = append(got, fmt.Sprintf("%s=%.0f", m.Text, m.Confidence))
		}
	}
	sort.Strings(got)
	return got
}

func TestHyphenatedWordsAreNotRecoveryCodes(t *testing.T) {
	cases := []struct{ name, line string }{
		// The issue's shell lines. "backup" is only a path segment or a prose prefix.
		{"s3 cp with backup in a path",
			`aws s3 cp --recursive "$WORK/backup/data-bucket/" "s3://$BUCKET/" --only-show-errors`},
		{"template body with backup in a path",
			`  --template-body "file://$WORK/backup/data-bucket/templates/main-template.yaml" \`},
		{"lambda update after a backup prefix",
			"Restore from backup: aws lambda update-function-code --function-name my-func --s3-bucket data-bucket"},
		{"s3 sync from a backup prefix",
			"aws s3 sync s3://my-bucket/backup ./local-copy --only-show-errors --dry-run"},
		// The prose lines from the issue's comment, the dominant shape in documentation.
		{"lowercase compounds",
			"Backup and recovery plan for high-risk, cross-account, least-privilege and multi-region workloads."},
		{"Title-case compounds",
			"Role-Based access and Multi-Factor authentication are part of the emergency recovery runbook."},
		// This repository's own rollback steps (docs/deployment/enhanced-architecture-deployment.md).
		{"a binary name copied to a backup",
			"cp /production/bin/ferret-scan /production/bin/ferret-scan.backup"},
		// An explicit label vouches neither for words before it nor for its own spelling, and words
		// after it with unequal groups are still words.
		{"flags before the label",
			"Archive with --only-show-errors into ./mfa/backup-codes.json and keep a saved-copy"},
		{"equal-group compounds before the label",
			"Run the read-only self-test before you regenerate the backup codes"},
		{"the label's own spelling, twice",
			"mv mfa-backup-codes.txt old-backup-codes.txt"},
		{"compounds after the label",
			"Store recovery codes in a well-known, tamper-evident location."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := recoveryFindings(t, tc.line); len(got) != 0 {
				t.Errorf("reported %v on %q: a hyphenated word is not a recovery code", got, tc.line)
			}
		})
	}
}

// The controls #798 named, which must come through exactly as before: real-shaped codes are found
// at the same confidence, and obvious examples are not. The two known misses are all-hex and
// all-digit codes, which reHexDashBlock drops whatever the context. That trade is recorded by the
// issue rather than changed by it, and pinned here so it stays visible.
func TestRecoveryCodeControlsAreUnchanged(t *testing.T) {
	cases := []struct {
		name, line string
		want       string
	}{
		{"real-shaped codes",
			"Recovery codes: 4f9k2-8xq3m 7b2n9-k4p8w a3m7q-9x2k5",
			"[4f9k2-8xq3m=60 7b2n9-k4p8w=60 a3m7q-9x2k5=60]"},
		{"obvious digit examples",
			"Backup codes: 1234-5678 8765-4321 2468-1357", "[]"},
		{"an all-hex example beside a real-shaped code",
			"GitHub recovery codes: abcde-12345 fghij-67890", "[fghij-67890=60]"},
		{"known miss: random all-hex codes",
			"Recovery codes: 7d3a0-f2c91 e84b6-1a5fd 0c9e2-b7d43", "[]"},
		{"known miss: random all-digit codes",
			"Backup codes: 3819-2047 5562-9031 7740-1286", "[]"},
		{"uppercase letters carry no lowercase",
			"Your recovery codes: ABCD-EFGH-IJKL MNOP-QRST-UVWX", "[ABCD-EFGH-IJKL=70 MNOP-QRST-UVWX=70]"},
		{"a bare topic word still admits codes with digits",
			"MFA emergency recovery: XYZW-ABCD-1234 EFGH-IJKL-5678 MNOP-QRST-9012",
			"[EFGH-IJKL-5678=85 MNOP-QRST-9012=85 XYZW-ABCD-1234=85]"},
		// A rule that rejected every block without a digit would drop this one.
		{"lowercase letters after a leading label",
			"2FA backup codes: 1234-5678 abcd-efgh 9012-3456", "[abcd-efgh=75]"},
		// Source or JSON text joins codes with a literal \n, so each block starts at the escape's n.
		{"uppercase codes after a backslash escape",
			`Your recovery codes:\nABCD-EFGH-IJKL\nMNOP-QRST-UVWX`, "[nABCD-EFGH-IJKL=60 nMNOP-QRST-UVWX=60]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := fmt.Sprint(recoveryFindings(t, tc.line)); got != tc.want {
				t.Errorf("on %q reported %s, want %s as before #798", tc.line, got, tc.want)
			}
		})
	}
}

// randomCode returns groups of size characters drawn from alphabet, joined by dashes.
func randomCode(rng *rand.Rand, alphabet string, groups, size int) string {
	parts := make([]string, groups)
	b := make([]byte, size)
	for g := range parts {
		for i := range b {
			b[i] = alphabet[rng.Intn(len(alphabet))]
		}
		parts[g] = string(b)
	}
	return strings.Join(parts, "-")
}

// A code drawn from a letters-only or lowercase alphabet is prose-shaped whenever it has no digit,
// and a leading label keeps every such code: these random codes are all found after "Recovery
// codes:", whatever the alphabet. What #798 costs is the same digit-free code with only a bare
// topic word on the line, pinned here so it stays visible. On main both lines reported it.
func TestProseShapedCodesNeedALeadingLabel(t *testing.T) {
	alphabets := map[string]string{
		"lowercase letters":    "abcdefghijklmnopqrstuvwxyz",
		"mixed-case letters":   "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"lowercase and digits": "abcdefghijklmnopqrstuvwxyz0123456789",
		"uppercase and digits": "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	}
	shapes := [][2]int{{2, 4}, {2, 5}, {3, 4}, {4, 4}, {2, 10}}
	names := make([]string, 0, len(alphabets))
	for name := range alphabets {
		names = append(names, name)
	}
	sort.Strings(names)

	rng := rand.New(rand.NewSource(798))
	labelled, bare := 0, 0
	for _, name := range names {
		for _, shape := range shapes {
			for i := 0; i < 40; i++ {
				a := randomCode(rng, alphabets[name], shape[0], shape[1])
				b := randomCode(rng, alphabets[name], shape[0], shape[1])
				if reHexDashBlock.MatchString(a) || reHexDashBlock.MatchString(b) {
					continue // dropped by the hex rule in every context, before and after #798
				}
				pair := a + " " + b
				if got := recoveryFindings(t, "Recovery codes: "+pair); len(got) != 2 {
					t.Fatalf("%s %v: after a leading label reported %v, want both codes", name, shape, got)
				}
				labelled++

				// With only a bare topic word, a code is reported exactly when it has a digit or
				// no lowercase letter.
				want := 0
				for _, c := range []string{a, b} {
					if strings.ContainsAny(c, "0123456789") || c == strings.ToUpper(c) {
						want++
					}
				}
				if got := recoveryFindings(t, "MFA backup: "+pair); len(got) != want {
					t.Fatalf("%s %v: with a bare topic word reported %v, want %d of %q",
						name, shape, got, want, pair)
				}
				bare += 2 - want
			}
		}
	}
	if bare == 0 {
		t.Fatal("no digit-free lowercase code was generated, so the bare-word half proves nothing")
	}
	t.Logf("%d labelled pairs all reported; %d digit-free codes unreported with a bare topic word",
		labelled, bare)
}
