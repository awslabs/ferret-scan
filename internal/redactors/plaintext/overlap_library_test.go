// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext_test

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
	"github.com/awslabs/ferret-scan/v2/pkg/scan"
)

// The library sinks reach the same writer as --stdin and --file, so the identical-span rule must hold
// through them too. 512010001 is synthetic (area 512); the emails are example.com.

const libPassport = "Passport number: 512010001"

func paddedPassport(k int) string {
	var b strings.Builder
	for i := 1; i <= k; i++ {
		fmt.Fprintf(&b, "Contact %d: user%d@example.com\n", i, i)
	}
	b.WriteString(libPassport + "\n")
	for i := k + 1; i <= 2*k; i++ {
		fmt.Fprintf(&b, "Contact %d: user%d@example.com\n", i, i)
	}
	return b.String()
}

func passportLine(t *testing.T, out string) string {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Passport number: ") {
			return l
		}
	}
	t.Fatalf("no passport line in output:\n%s", out)
	return ""
}

// pkg/scan.RedactText takes findings from the caller in whatever order the caller holds them. 200
// shuffles at sizes either side of the 12-element threshold must give identical bytes.
func TestScanRedactTextRendersIdenticalSpansOrderIndependently(t *testing.T) {
	rng := rand.New(rand.NewSource(773))
	for _, k := range []int{0, 5, 6, 24} {
		text := paddedPassport(k)
		res, err := scan.ScanText(context.Background(), text, scan.TextOptions{
			Checks: []string{"EMAIL", "PASSPORT", "SSN"}, DisableConfigDiscovery: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		var types []string
		for _, f := range res.Findings {
			if f.Text == "512010001" {
				types = append(types, f.Type)
			}
		}
		if len(types) != 2 {
			t.Fatalf("k=%d: the fixture must report the identical pair, got %v", k, types)
		}
		for _, st := range []struct {
			s    scan.RedactStrategy
			want string
		}{{scan.StrategyFormatPreserving, "Passport number: *********"}, {scan.StrategySimple, "Passport number: [PASSPORT-REDACTED]"}} {
			var first string
			for p := 0; p < 200; p++ {
				fs := append([]scan.Finding(nil), res.Findings...)
				rng.Shuffle(len(fs), func(i, j int) { fs[i], fs[j] = fs[j], fs[i] })
				out, err := scan.RedactText(text, fs, st.s)
				if err != nil {
					t.Fatal(err)
				}
				if p == 0 {
					first = out.Text
					if got := passportLine(t, out.Text); got != st.want {
						t.Fatalf("k=%d (%d findings): got %q, want %q", k, len(fs), got, st.want)
					}
					continue
				}
				if out.Text != first {
					t.Fatalf("k=%d (%d findings): shuffle %d changed the output", k, len(fs), p)
				}
			}
		}
	}
}

// pkg/redact scans and redacts in one call; the rendering must not depend on how many unrelated
// findings the request holds (the CLI's 12 -> 13 flip).
func TestRedactEngineRendersIdenticalSpansAtAnySize(t *testing.T) {
	for _, st := range []struct {
		s    redact.Strategy
		want string
	}{{redact.FormatPreserving, "Passport number: *********"}, {redact.Simple, "Passport number: [PASSPORT-REDACTED]"}} {
		eng, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"EMAIL", "PASSPORT", "SSN"}, Strategy: st.s})
		if err != nil {
			t.Fatal(err)
		}
		for _, k := range []int{0, 1, 5, 6, 10, 11, 30} {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			res, err := eng.Redact(ctx, redact.Request{Text: paddedPassport(k)})
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if got := passportLine(t, res.Redacted); got != st.want {
				t.Errorf("%s k=%d: got %q, want %q", st.s, k, got, st.want)
			}
		}
		_ = eng.Close()
	}
}
