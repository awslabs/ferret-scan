package secrets

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// Tests for the provider rows #881 added (fine-grained GitHub, Hugging Face, Anthropic,
// restricted Stripe, the rest of GitLab's prefix table, Slack app-level and 3-digit user ids).
// Every token is assembled at run time from a prefix and a seeded random body of the row's
// alphabet, so no value here is a real credential and a static scanner reading this source
// finds no token in it.

const (
	testAlnum  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	testB64URL = testAlnum + "_-"
	testHex    = "0123456789abcdef"
	testDigits = "0123456789"
)

func syntheticBody(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// newProviderShapes returns one synthetic token per new row, keyed by a short name, each at the
// shape the issue measured (the vendor publishes the prefix; the body is the observed shape).
func newProviderShapes(seed int64) (shapes map[string]string, types map[string]string) {
	r := rand.New(rand.NewSource(seed))
	shapes = map[string]string{
		"github_pat":  "github_pat_" + syntheticBody(r, testAlnum, 22) + "_" + syntheticBody(r, testAlnum, 59),
		"hf":          "hf_" + syntheticBody(r, testAlnum, 34),
		"ant_api03":   "sk-ant-api03-" + syntheticBody(r, testB64URL, 93) + "AA",
		"ant_admin01": "sk-ant-admin01-" + syntheticBody(r, testB64URL, 93) + "AA",
		"rk_live":     "rk_live_" + syntheticBody(r, testAlnum, 24),
		"rk_test":     "rk_test_" + syntheticBody(r, testAlnum, 24),
		"xoxb13":      "xoxb-" + syntheticBody(r, testDigits, 13) + "-" + syntheticBody(r, testDigits, 13) + "-" + syntheticBody(r, testAlnum, 24),
		"xoxp3":       "xoxp-" + syntheticBody(r, testDigits, 3) + "-" + syntheticBody(r, testDigits, 3) + "-" + syntheticBody(r, testDigits, 3) + "-" + syntheticBody(r, testHex, 32),
		"xapp":        "xapp-1-A" + syntheticBody(r, "ABCDEFGHIJKLMNOPQRSTUVWXYZ", 10) + "-" + syntheticBody(r, testDigits, 13) + "-" + syntheticBody(r, testHex, 64),
	}
	types = map[string]string{
		"github_pat": "GITHUB_TOKEN", "hf": "API_KEY_OR_SECRET", "ant_api03": "API_KEY_OR_SECRET",
		"ant_admin01": "API_KEY_OR_SECRET", "rk_live": "STRIPE_API_KEY", "rk_test": "STRIPE_API_KEY",
		"xoxb13": "SLACK_TOKEN", "xoxp3": "SLACK_TOKEN", "xapp": "SLACK_TOKEN",
	}
	// GitLab's prefix table, one token per prefix.
	for _, p := range []string{"gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "glwt-", "glsoat-", "glffct-"} {
		body := syntheticBody(r, testB64URL, 20)
		if p == "gloas-" {
			body = syntheticBody(r, testHex, 64)
		}
		shapes[strings.TrimSuffix(p, "-")] = p + body
		types[strings.TrimSuffix(p, "-")] = "GITLAB_TOKEN"
	}
	return shapes, types
}

// providerContexts are the eight contexts the issue's matrix measured.
func providerContexts(tok string) [][2]string {
	return [][2]string{
		{"bare", tok},
		{"prose", "Please use " + tok + " for the deploy."},
		{"cfg", `cfg = "` + tok + `"`},
		{"json", `{"PROVIDER_VALUE": "` + tok + `"}`},
		{"x-api-key", "x-api-key: " + tok},
		{"bearer", "Authorization: Bearer " + tok},
		{"stem", "SERVICE_API_KEY=" + tok},
		{"api_key", `api_key = "` + tok + `"`},
	}
}

// TestNewProviderRowsReportInEveryContext is the issue's table as a test: every new prefix is
// reported at HIGH (90 and over) with the row's type, whole, in all eight contexts, under three
// seeds.
func TestNewProviderRowsReportInEveryContext(t *testing.T) {
	v := NewValidator()
	for seed := int64(1); seed <= 3; seed++ {
		shapes, types := newProviderShapes(seed)
		for name, tok := range shapes {
			for _, c := range providerContexts(tok) {
				t.Run(fmt.Sprintf("seed%d/%s/%s", seed, name, c[0]), func(t *testing.T) {
					ms, err := v.ValidateContent(c[1]+"\n", "settings.txt")
					if err != nil {
						t.Fatal(err)
					}
					var whole int
					for _, m := range ms {
						if m.Text == tok {
							whole++
							if m.Type != types[name] {
								t.Errorf("%s: type %s, want %s", name, m.Type, types[name])
							}
							if m.Confidence < 90 {
								t.Errorf("%s: confidence %v, want 90 or more", name, m.Confidence)
							}
						}
					}
					if whole == 0 {
						t.Errorf("%s not reported whole in %q; findings: %v", name, c[1], ms)
					}
				})
			}
		}
	}
}

// TestNewProviderRowsDecoys: shapes that carry a new prefix and are not a token. None may be
// reported. Each is the kind of text a README, an identifier or a log carries.
func TestNewProviderRowsDecoys(t *testing.T) {
	v := NewValidator()
	decoys := []string{
		// A prefix named in prose, or with a body below the row's minimum.
		"Runner tokens begin with glrt- and job tokens with glcbt-.",
		"Fine-grained tokens begin with github_pat_ and classic ones with ghp_.",
		"Hugging Face tokens begin with hf_ and Stripe restricted keys with rk_live_.",
		"Anthropic keys begin sk-ant-api03- and admin keys sk-ant-admin01-.",
		"export GLAGENT=glagent-xxx",
		"hf_hub_download(repo_id, filename)",
		"from huggingface_hub import hf_api, hf_hub_url",
		"hf_transfer_enabled_for_large_model_downloads_in_this_deployment",
		"xapp-deploy-notes-for-the-whole-team-and-the-release-train",
		"rk_live_",
		"rk_live_short",
		"glft-feed-token-goes-here",
		// Ten-digit ids: the placeholder docs/examples/integration-demo.md carries. Slack ids are 11 to 13 digits.
		"SLACK_WEBHOOK=xoxb-" + "1234567890-1234567890-abcdefghijklmnopqrstuvwx",
		// Identifier-shaped values: a snake_case name has `_` inside its run.
		"github_pat_rotation_schedule_for_the_platform_team_every_ninety_days",
		"kubectl get glwt-workspace-token-secret-name-for-the-dev-cluster -o yaml",
	}
	for _, line := range decoys {
		t.Run(line, func(t *testing.T) {
			ms, err := v.ValidateContent(line+"\n", "settings.txt")
			if err != nil {
				t.Fatal(err)
			}
			if len(ms) != 0 {
				t.Errorf("%q: want no finding, got %v", line, ms)
			}
		})
	}
}

// TestProviderTokenIsNotHeldAtTheHyphenCap pins validator.go's uncorroboratedHyphenatedCap
// exemption: an Anthropic key is typed API_KEY_OR_SECRET (its row has no type of its own), holds
// `-`, and nothing beside it corroborates, and it must still score as the provider row says. A
// value that only looks like one (the prefix with a short body) keeps the cap.
func TestProviderTokenIsNotHeldAtTheHyphenCap(t *testing.T) {
	shapes, _ := newProviderShapes(7)
	tok := shapes["ant_api03"]
	if got := uncorroboratedHyphenatedCap(genericSecretType, tok, lineKeywordAbsent, false); got != 0 {
		t.Errorf("cap for a whole provider token = %v, want 0", got)
	}
	if got := uncorroboratedHyphenatedCap(genericSecretType, "sk-ant-api03-short-body-value", lineKeywordAbsent, false); got != uncorroboratedHyphenatedCeiling {
		t.Errorf("cap for a prefix with a short body = %v, want %v", got, uncorroboratedHyphenatedCeiling)
	}
}

// TestSlackDocumentedShape: the example on Slack's token page (three-digit ids) and a 13-digit
// bot token are Slack tokens; a pre-2016 short secret is below the minimum.
func TestSlackDocumentedShape(t *testing.T) {
	user := "xoxp-" + "111-222-333-" + "d6bc768406e5c2e6958cfc399b438004"
	if typ, _ := providerTypeOf(user); typ != "SLACK_TOKEN" {
		t.Errorf("documented xoxp- shape typed %q", typ)
	}
	short := "xoxp-" + "111-222-333-" + "d6bc768412"
	if typ, _ := providerTypeOf(short); typ != "" {
		t.Errorf("a 10-character secret typed %q, want none", typ)
	}
}

// TestPrefixInsideAnotherTokenIsNotASecondFinding: the first segment of a fine-grained GitHub token
// ends `hf`, so the token holds `hf_` and 59 more characters. That is the same secret, reported
// once, as the token; and two tokens side by side are still two findings.
func TestPrefixInsideAnotherTokenIsNotASecondFinding(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(11))
	pat := "github_pat_" + syntheticBody(r, testAlnum, 20) + "hf" + "_" + syntheticBody(r, testAlnum, 59)
	for _, line := range []string{pat, "token: " + pat, "Please use " + pat + " now."} {
		ms, err := v.ValidateContent(line+"\n", "settings.txt")
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != 1 || ms[0].Text != pat || ms[0].Type != "GITHUB_TOKEN" {
			t.Errorf("%q: want one GITHUB_TOKEN over the whole token, got %v", line, ms)
		}
	}
	other := "hf_" + syntheticBody(r, testAlnum, 34)
	ms, err := v.ValidateContent(pat+" "+other+"\n", "settings.txt")
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 {
		t.Errorf("two tokens side by side: want 2 findings, got %d: %v", len(ms), ms)
	}
}
