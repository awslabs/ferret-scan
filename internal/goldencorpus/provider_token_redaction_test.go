// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// TestProviderTokensRedactWhole is the redaction half of #769's grammar contract,
// here rather than in internal/validators/secrets because pkg/redact depends on
// that package. For a token of every provider family that has no vendor-fixed
// length -- Stripe, GitLab, Slack -- at the minimum body and at the minimum plus
// 1, 8 and 75 bytes, in the contexts where the leak was measured, no 8-byte
// substring of the body may survive redaction under either deterministic strategy.
//
// Before #769 a 107-byte Stripe key in prose was redacted as its first 32 bytes
// and the other 75 were written back as text, under every strategy, exit 0.
// The two fixed-length families (AWS, GitHub) are included at their exact length
// as the control that this is not a test of something unrelated to length.
func TestProviderTokensRedactWhole(t *testing.T) {
	type family struct {
		name   string
		build  func(body string) string
		minLen int
		exact  bool
	}
	families := []family{
		{"stripe", func(b string) string { return "sk_" + "live_" + b }, 24, false},
		{"gitlab", func(b string) string { return "glpat-" + b }, 20, false},
		{"slack_bot", func(b string) string { return "xoxb-123456789012-123456789012-" + b }, 24, false},
		{"slack_user", func(b string) string { return "xoxp-123456789012-123456789012-123456789012-" + b }, 32, false},
		{"aws_exact", func(b string) string { return "AKIA" + b }, 16, true},
		{"github_exact", func(b string) string { return "ghp_" + b }, 36, true},
	}
	alphabet := "aB1cD2eF3gH4jK5mN6pQ7rS8tU9vWxYz"
	body := func(f family, n int) string {
		if f.name == "aws_exact" {
			alphabet = "Q7Z2M9K4P1L8V3N6B5R0TX"
		}
		var sb strings.Builder
		for i := 0; i < n; i++ {
			sb.WriteByte(alphabet[i%len(alphabet)])
		}
		return sb.String()
	}
	contexts := func(tok string) map[string]string {
		return map[string]string{
			"prose":      "the old value " + tok + " was rotated\n",
			"log":        "2026-10-13 08:00:01 INFO payments: client configured with " + tok + "\n",
			"bearer":     "Authorization: Bearer " + tok + "\n",
			"csv":        "merchant-7," + tok + ",active\n",
			"env":        "STRIPE_SK=" + tok + "\n",
			"keyword":    "SERVICE_TOKEN=" + tok + "\n",
			"quoted":     `api_key = "` + tok + "\"\n",
			"json_u0022": `{"a": "\u0022` + tok + `\u0022"}` + "\n",
			"percent":    "q=%22" + tok + "%22\n",
			"glued_x":    "x" + tok + "\n",
		}
	}
	strategies := []struct {
		name string
		s    redact.Strategy
	}{{"simple", redact.Simple}, {"format_preserving", redact.FormatPreserving}}

	for _, f := range families {
		lens := []int{f.minLen, f.minLen + 1, f.minLen + 8, f.minLen + 75}
		if f.exact {
			lens = []int{f.minLen}
		}
		for _, n := range lens {
			b := body(f, n)
			tok := f.build(b)
			for ctxName, text := range contexts(tok) {
				for _, st := range strategies {
					t.Run(fmt.Sprintf("%s/body%d/%s/%s", f.name, n, ctxName, st.name), func(t *testing.T) {
						eng, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"SECRETS"}, Strategy: st.s})
						if err != nil {
							t.Fatal(err)
						}
						defer func() { _ = eng.Close() }()
						ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
						defer cancel()
						res, err := eng.Redact(ctx, redact.Request{Text: text, Label: "settings.txt"})
						if err != nil {
							t.Fatal(err)
						}
						if len(res.Findings()) == 0 {
							t.Fatalf("no finding at all; the redaction claim would be vacuous")
						}
						for i := 0; i+8 <= len(b); i++ {
							if strings.Contains(res.Redacted, b[i:i+8]) {
								t.Fatalf("%d bytes of the body survive redaction: %q is in %q", len(b)-i, b[i:i+8], res.Redacted)
							}
						}
					})
				}
			}
		}
	}
}
