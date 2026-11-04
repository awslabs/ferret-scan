// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"regexp"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Temporary AWS access key IDs (#881 Part 2).
//
// An ASIA ID is the access key ID AWS STS issues with a secret access key and a session token.
// Until #881 the AWS_ACCESS_KEY row was AKIA-only, so an ASIA ID was reported nowhere -- not bare,
// not as `aws_access_key_id = ASIA...`, not in a credentials file beside its own secret -- although
// the AWS secret-key pairing gate and the OTP filter both listed `AKIA|ASIA`. It is now a prefix of
// the same row, typed AWS_ACCESS_KEY with `aws_key_kind: temporary`, and scored by what is beside
// it rather than like AKIA:
//
//   - paired (a secret access key or session token VALUE on the same or an adjacent line): the
//     row's full score, HIGH;
//   - unpaired, bare or under its own label: at most awsTemporaryKeyUnpairedCeiling, LOW;
//   - containing AWS's documentation marker EXAMPLE: at most 15, as AKIA (awsDocPlaceholderCap).
//
// The other IAM unique-ID prefixes (AIDA, AROA, ANPA, ...) name users, roles and policies, not
// access keys, and stay out of the row.

// reAWSSessionToken matches a session token VALUE beside its label -- `aws_session_token = `,
// `AWS_SESSION_TOKEN=`, `"SessionToken": "`, `x-amz-security-token: ` -- of 100 or more base64
// bytes; an STS session token runs to several hundred. Capture group 1 is the value.
var reAWSSessionToken = regexp.MustCompile(`(?i)(?:session|security)[_-]?token["']?\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})`)

// awsTemporaryKeyUnpairedCeiling is the highest confidence a temporary access key ID may carry
// when no secret access key or session token value sits on its line or an adjacent one: 55, LOW,
// the generic unlabelled cap (M24). Still a finding, so still redacted.
//
// Why not AKIA's scoring: an ASIA ID authenticates nothing on its own, and the files that hold one
// alone are audit records. A CloudTrail event-history export writes the caller's access key ID on
// every row, next to no secret; scored like AKIA, every ASIA row of one is HIGH. Beside its secret
// or session token it is a live credential and keeps the row's full score.
const awsTemporaryKeyUnpairedCeiling = 55.0

// applyTemporaryAccessKey records an ASIA finding's kind and, when nothing pairs it, publishes the
// unpaired ceiling (a lower ceiling already published, the EXAMPLE placeholder's 15, still wins).
// clampToPublishedCeiling applies it in this validator; the bridge applies it again after its own
// adjustments, which is why it is published rather than only clamped.
func applyTemporaryAccessKey(m *detector.Match, paired bool) {
	if m.Metadata == nil {
		m.Metadata = map[string]any{}
	}
	m.Metadata["aws_key_kind"] = "temporary"
	if checks, ok := m.Metadata["validation_checks"].(map[string]bool); ok {
		checks["paired_secret_or_session_token"] = paired
	}
	if paired {
		return
	}
	ceiling := awsTemporaryKeyUnpairedCeiling
	if c, ok := m.Metadata[ConfidenceCeilingKey].(float64); ok && c > 0 && c < ceiling {
		ceiling = c
	}
	m.Metadata[ConfidenceCeilingKey] = ceiling
}

// temporaryKeyPaired reports whether an ASIA ID on line is paired with the rest of its
// credential: an AWS secret access key VALUE or a session token VALUE on the same line or an
// adjacent one, the adjacency findAWSSecretKeys uses for the reverse question. A label with no
// value (`aws_secret_access_key = `, a template) pairs nothing.
func (v *Validator) temporaryKeyPaired(line, prevLine, nextLine string) bool {
	for _, l := range [...]string{line, prevLine, nextLine} {
		if v.lineCarriesAWSSecretValue(l) || v.lineCarriesSessionToken(l) {
			return true
		}
	}
	return false
}

// lineCarriesAWSSecretValue reports whether line holds a 40-byte value findAWSSecretKeys would
// accept as an AWS secret access key (awsSecretShaped), other than AWS's documentation
// placeholder.
func (v *Validator) lineCarriesAWSSecretValue(line string) bool {
	if len(line) < 40 {
		return false
	}
	for _, m := range reAWSSecretCandidate.FindAllStringSubmatchIndex(line, -1) {
		c := line[m[4]:m[5]]
		if v.awsSecretShaped(c) && awsDocPlaceholderCap("AWS_SECRET_ACCESS_KEY", c) == 0 {
			return true
		}
	}
	return false
}

// lineCarriesSessionToken reports whether line holds a session token value: reAWSSessionToken's
// capture, mixed case and above the base64 entropy floor, so a run of one repeated byte or an
// all-caps placeholder pairs nothing.
func (v *Validator) lineCarriesSessionToken(line string) bool {
	if len(line) < 100 {
		return false
	}
	for _, m := range reAWSSessionToken.FindAllStringSubmatchIndex(line, -1) {
		c := line[m[2]:m[3]]
		if strings.ToLower(c) != c && strings.ToUpper(c) != c &&
			v.calculateShannonEntropy(c, v.base64Charset) > v.base64Limit {
			return true
		}
	}
	return false
}
