// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// The #742 regression net at the level the symptom was actually reported.
//
// The veto itself is pinned in TestPlausibleUnquotedSecret, but that test exercises the
// predicate in isolation: it cannot catch a regression that reintroduces the finding through a
// different route — a new pattern in compileUnquotedPatterns, a change to the capture's
// character classes, or a second matcher that claims the same line. #742 was reported as
// "API_KEY_OR_SECRET at HIGH 100% on ordinary typed Python", so the contract worth pinning is
// the scored output of ValidateContent, not only the filter's return value.
//
// It also pins what --confidence cannot do. The issue notes that narrowing to `high` is not a
// workaround because `session:` and `password:` annotations reach HIGH themselves, and that the
// secrets validator reads no validator config, so there is no lever to tune this off. That is
// why these must be vetoed rather than merely demoted: a demotion to LOW would still surface
// under the default `high,medium` for some stems and would still be unsuppressable per-codebase.
//
// SCOPE — the veto is PARTIAL, and deliberately so here.
//
// #742's suggested guard names four shapes. typeAnnotationValue is anchored on square brackets,
// so it closes the parameterized form only. Three sibling shapes still report, every one a
// declaration whose value is a type or a call:
//
//	token: AuthToken               bare capitalized identifier  100%
//	token: Promise<AuthToken>      TypeScript generic           100%
//	session = get_session()        bare function call            75%
//
// They are not asserted here, because asserting current-but-wrong behavior in a unit test
// invites someone to "fix the test" instead of the bug. They are recorded as a golden snapshot
// in internal/goldencorpus — case secrets_code_expression_known_fp — where closing them shows
// up as a reviewable corpus diff. That case carries the full reasoning, including why the
// comma-truncated `Record<string` capture means a value-shape veto alone cannot close shape 2.

// typedDeclarations are ordinary declarations whose field name carries a secret stem. Every one
// is a type annotation or an empty initializer — none contains a credential.
var typedDeclarations = []string{
	"session: Optional[Session] = None",
	"password: Optional[str] = None",
	"api_key: Optional[SecretStr] = None",
	"token: Optional[Token] = None",
	"secret: Optional[SecretRef] = None",
	"tokens: List[str] = []",
	"creds: Dict[str,int] = {}",
	"fallback_secret: typing.Optional[str] = None",
}

// A typed declaration must produce NO finding, at ANY confidence level.
//
// Asserted across the whole scored path rather than on the predicate, and with no confidence
// filter applied, so that a future change which demotes these to LOW instead of vetoing them
// fails here. Demotion is not sufficient: LOW findings still fail a consumer that gates on any
// finding (awslabs/automated-security-helper#684 is the case that prompted #742).
func TestTypedDeclarationsProduceNoFinding(t *testing.T) {
	for _, line := range typedDeclarations {
		t.Run(line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(line+"\n", "models.py")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				t.Errorf("reported %q as %s at confidence %.2f — the value is a type, not a "+
					"credential. The unquoted matcher reads ':' as an assignment delimiter, so a "+
					"secret-stemmed field name plus an annotation looks like `password=<value>`. "+
					"See #742.", m.Text, m.Type, m.Confidence)
			}
		})
	}
}

// The declarations must stay clean when they appear together in one file, which is the shape a
// real schema takes. A per-line test cannot catch a regression in line-indexed or memoized
// state (findKeywordSecrets is backed by a per-line keyword memo), so the multi-line form is
// pinned separately.
func TestTypedDeclarationFileProducesNoFinding(t *testing.T) {
	content := strings.Join(typedDeclarations, "\n") + "\n"
	v := NewValidator()
	matches, err := v.ValidateContent(content, "models.py")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	if len(matches) != 0 {
		for _, m := range matches {
			t.Errorf("line %d: reported %q as %s at %.2f", m.LineNumber, m.Text, m.Type, m.Confidence)
		}
		t.Errorf("a %d-line typed schema produced %d findings, want 0",
			len(typedDeclarations), len(matches))
	}
}

// The cost of the veto, pinned so that over-correction is a test failure rather than a silent
// loss of detection.
//
// A veto on the unquoted path is only acceptable while the credentials #395 was written to
// catch still report. These are the forms .env, shell exports, CI variables and Dockerfile ENV
// use, and they are what the #742 fix must not take with it.
func TestRealCredentialsStillReportAlongsideTheVeto(t *testing.T) {
	cases := []struct{ line, want string }{
		{"password = \"Sup3rS3cretDbPass!\"", "Sup3rS3cretDbPass!"},
		{"api_key=hunter2XYZsecretvalue123", "hunter2XYZsecretvalue123"},
		{"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI"},
		{"export API_TOKEN=ghp_aBcD1234efGH5678ijKL", "ghp_aBcD1234efGH5678ijKL"},
		{"db_password: Tr0ub4dor&3", "Tr0ub4dor"},
		// A quoted value that happens to be shaped like an annotation is still a secret: the
		// quotes are the author's intent, and the veto is scoped to the unquoted path. This is
		// the case that distinguishes "reject this shape" from "reject this shape when the
		// author did not mark it as a value".
		{"token = \"Optional[X]\"", "Optional[X]"},
	}

	for _, tc := range cases {
		t.Run(tc.line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(tc.line+"\n", "config.env")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			for _, m := range matches {
				if strings.Contains(m.Text, tc.want) {
					return
				}
			}
			t.Errorf("no finding covering %q — the #742 veto must reject the type-annotation "+
				"shape without costing the unquoted credentials #395 was added to catch", tc.want)
		})
	}
}

// A declaration whose field name is NOT a secret stem was never affected, and must stay that
// way: it establishes that the trigger is the keyword path and not the annotation shape itself,
// so a future reader can tell which half of the matcher to look at.
func TestNonSecretStemDeclarationsWereNeverAffected(t *testing.T) {
	for _, line := range []string{
		"items: Optional[List[str]] = None",
		"config: Dict[str,str] = {}",
		"count: Optional[int] = None",
	} {
		t.Run(line, func(t *testing.T) {
			v := NewValidator()
			matches, err := v.ValidateContent(line+"\n", "models.py")
			if err != nil {
				t.Fatalf("ValidateContent: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("%d finding(s) on a declaration with no secret stem: %q", len(matches), line)
			}
		})
	}
}
