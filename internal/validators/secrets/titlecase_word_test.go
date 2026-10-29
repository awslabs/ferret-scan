// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Tests for #787: plausibleUnquotedSecret rejected a short all-lowercase word (`token: creating`) but
// not the same word with a capital, and prose capitalises the word after a colon. `Onboarding
// session: Checklist review` reported `Checklist` as API_KEY_OR_SECRET at MEDIUM 85, and at HIGH 100
// in a document whose first lines were a tab-separated table (+20). A sentence-case word under 16
// characters is now rejected like its lower-case spelling.
//
// The end-to-end assertions are by presence, absence and band, never by an exact confidence: the
// document-type heuristic (#788) moves the baseline every candidate is scored from, and a vetoed
// value is not reported at any baseline.

// band is the reporting band a confidence falls in.
func band(confidence float64) string {
	switch {
	case confidence >= 90:
		return "HIGH"
	case confidence >= 60:
		return "MEDIUM"
	}
	return "LOW"
}

// TestSentenceCaseWordIsImplausible is the filter's contract for the new shape and its edges.
func TestSentenceCaseWordIsImplausible(t *testing.T) {
	for _, c := range []struct {
		value string
		want  bool
		why   string
	}{
		{"Checklist", false, "the issue's word"},
		{"Milestones", false, "the issue's other word"},
		{"Required", false, "#787 P5, a policy document"},
		{"Fifteenletterss", false, "15 bytes, under the floor"},
		{"Sixteenletterssx", true, "16 bytes: the floor keeps a passphrase"},
		{"Correcthorsebatterystaple", true, "a sentence-case passphrase, accepted by length"},
		{"CHECKLIST", true, "all caps is left alone: it is also the shape of a sentinel constant"},
		{"ChangeMeNow", true, "a capital after position 0"},
		{"Checklist7", true, "a digit"},
		{"Check-list", true, "a symbol"},
		{"checklist", false, "the lower-case rule, unchanged"},
		{uriPW(787000, 24), true, "a generated credential"},
	} {
		if got := plausibleUnquotedSecret(c.value); got != c.want {
			t.Errorf("plausibleUnquotedSecret(%q) = %v, want %v: %s", c.value, got, c.want, c.why)
		}
	}
}

// secretsFindings returns every SECRETS finding on a document.
func secretsFindings(t *testing.T, content, path string) []detector.Match {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, path)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

// TestSentenceCaseProseIsNotACredential is the issue's reproduction through ValidateContent: P1
// (prose), P4 (P1 under a tab-separated header block, the HIGH 100 case) and P5 (a policy document,
// typed Configuration) report nothing; P6 reports the real value beside the prose and only it; the
// quoted spelling still reports, because quotes are intent. Every assertion fails on main.
func TestSentenceCaseProseIsNotACredential(t *testing.T) {
	const p1 = "Weekly agenda\n\n" +
		"Onboarding session: Checklist review and owner assignment\n" +
		"Planning session: Milestones for the next quarter\n"
	real := uriPW(787100, 24)

	for _, c := range []struct{ name, content string }{
		{"P1 prose", p1},
		{"P4 tab-separated header block above P1", strings.Repeat("Field\tValue\tNote\n", 10) + p1},
		{"P5 policy prose", "Password: Required for all accounts\nToken: Rotation happens quarterly\n" +
			"Secret: Management is centralised\nAPI key: Provisioning is self-service\n"},
	} {
		for _, m := range secretsFindings(t, c.content, "notes.txt") {
			t.Errorf("%s: reported %s %q at %s; a sentence-case word is not a credential", c.name, m.Type, m.Text, band(m.Confidence))
		}
	}

	got := secretsFindings(t, p1+"password: "+real+"\n", "notes.txt")
	if len(got) != 1 || got[0].Text != real || band(got[0].Confidence) == "LOW" {
		var texts []string
		for _, m := range got {
			texts = append(texts, m.Text+" "+band(m.Confidence))
		}
		t.Errorf("P6: got [%s], want only the real value, reported at MEDIUM or above", strings.Join(texts, "; "))
	}

	quoted := secretsFindings(t, `password="Checklist"`+"\n", "notes.txt")
	if len(quoted) != 1 || quoted[0].Text != "Checklist" || band(quoted[0].Confidence) == "LOW" {
		t.Errorf(`password="Checklist": got %v, want it reported at MEDIUM or above: the quoted path does not run this filter`, quoted)
	}
}

// TestSentenceCaseURIPasswordIsKeptLow pins the URI user-info consequence: its disposition table
// sends a value plausibleUnquotedSecret rejects to LOW, kept and redacted, never dropped, as it does
// the lower-case word. On main `Clustering` as a URI password scored HIGH.
func TestSentenceCaseURIPasswordIsKeptLow(t *testing.T) {
	got := secretsFindings(t, "DATABASE_URL=postgres://app:Clustering@db1.orders.invalid/app\n", "app.env")
	if len(got) != 1 || got[0].Text != "Clustering" || got[0].Metadata["detection_method"] != uriUserinfoMethod {
		t.Fatalf("got %v, want one uri_userinfo finding of the password", got)
	}
	if b := band(got[0].Confidence); b != "LOW" {
		t.Errorf("a sentence-case URI password is %s, want LOW: kept and redacted, like the lower-case word", b)
	}
}
