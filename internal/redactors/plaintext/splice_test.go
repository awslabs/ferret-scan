// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"math/rand"
	"strings"
	"testing"
)

// spliceText must be, at every step, the string the old per-write rebuild produced:
// text = text[:start] + repl + text[end:]. This drives it with random writes (descending, which is
// the pass's shape, and arbitrary, which forces the collapse paths) against that string model and
// compares Len, Slice, lineFrom and the final text after every operation.
func TestSpliceTextMatchesStringRebuild(t *testing.T) {
	rng := rand.New(rand.NewSource(1005))
	const alphabet = "ab\n\r é"
	randStr := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteByte(alphabet[rng.Intn(len(alphabet))])
		}
		return b.String()
	}
	for trial := 0; trial < 300; trial++ {
		model := randStr(rng.Intn(120))
		s := newSpliceText(model)
		descending := trial%2 == 0
		limit := len(model)
		for op := 0; op < 25; op++ {
			hi := len(model)
			if descending && limit < hi {
				hi = limit
			}
			start := rng.Intn(hi + 1)
			end := start + rng.Intn(hi-start+1)
			repl := randStr(rng.Intn(8))
			model = model[:start] + repl + model[end:]
			s.Replace(start, end, repl)
			limit = start

			if s.Len() != len(model) {
				t.Fatalf("trial %d op %d: Len %d, want %d", trial, op, s.Len(), len(model))
			}
			a := rng.Intn(len(model) + 1)
			b := a + rng.Intn(len(model)-a+1)
			if got := s.Slice(a, b); got != model[a:b] {
				t.Fatalf("trial %d op %d: Slice(%d,%d) = %q, want %q", trial, op, a, b, got, model[a:b])
			}
			from := rng.Intn(len(model) + 3)
			got, ok := s.lineFrom(from)
			if from > len(model) {
				if ok {
					t.Fatalf("trial %d op %d: lineFrom(%d) ok past the end", trial, op, from)
				}
			} else {
				want := model[from:]
				if i := strings.IndexByte(want, '\n'); i >= 0 {
					want = want[:i]
				}
				if !ok || got != want {
					t.Fatalf("trial %d op %d: lineFrom(%d) = %q,%v want %q", trial, op, from, got, ok, want)
				}
			}
		}
		if got := s.String(); got != model {
			t.Fatalf("trial %d: final text %q, want %q", trial, got, model)
		}
	}
}
