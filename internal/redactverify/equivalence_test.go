// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactverify

import (
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The one-pass SweepRemaining, ResidualTypes and scanKinds must give EXACTLY the answers of the
// per-value-scan implementations they replaced (reference_test.go): the text, the swept list, the
// error text, the order replacementFor is called in, and the types ResidualTypes names. The inputs
// are built to hit what makes a multi-pattern matcher differ from a loop of searches: values that
// overlap, nest, repeat, share prefixes and suffixes, sit at the document's ends, abut word bytes
// (embedded) and non-word bytes (standalone), occur wide (UTF-16LE/BE) and as XML entities, and
// replacements that contain another value or the value itself.

// fuzzAlphabet is small on purpose: with four letters, a separator, '_' and an entity character,
// random substrings collide constantly.
const fuzzAlphabet = "abab_ \n-&;"

func fuzzDoc(r *rand.Rand) string {
	n := r.Intn(80)
	var b strings.Builder
	for i := 0; i < n; i++ {
		switch r.Intn(14) {
		case 0:
			b.WriteString("&amp;")
		case 1:
			b.WriteString("&lt;")
		case 2:
			b.WriteString("\x00")
		default:
			b.WriteByte(fuzzAlphabet[r.Intn(len(fuzzAlphabet))])
		}
	}
	return b.String()
}

// wide returns s as UTF-16LE or BE, the spellings the sweep also removes.
func wide(r *rand.Rand, s string) string {
	if r.Intn(2) == 0 {
		return string(utf16LE(s))
	}
	return string(utf16BE(s))
}

func fuzzValues(r *rand.Rand, doc string) []detector.Match {
	var ms []detector.Match
	types := []string{"EMAIL", "SSN", "", "NAME"}
	for i, n := 0, r.Intn(12); i < n; i++ {
		var v string
		switch r.Intn(6) {
		case 0:
			v = fuzzDoc(r) // unrelated, usually absent
		case 1:
			// a spelling the document may carry as an entity or wide
			v = "a&b"
		default:
			if len(doc) > 0 {
				a := r.Intn(len(doc))
				l := 1 + r.Intn(9)
				if a+l > len(doc) {
					l = len(doc) - a
				}
				v = doc[a : a+l]
			}
		}
		ms = append(ms, detector.Match{Text: v, Type: types[r.Intn(len(types))], LineNumber: i})
		if r.Intn(4) == 0 { // a repeat, possibly under another type
			ms = append(ms, detector.Match{Text: v, Type: types[r.Intn(len(types))]})
		}
	}
	return ms
}

// replacer builds a replacementFor from a mode and records the order it was called in.
func fuzzReplacer(mode int, calls *[]string) func(detector.Match) (string, error) {
	return func(m detector.Match) (string, error) {
		*calls = append(*calls, m.Type+"|"+m.Text)
		switch mode {
		case 1: // keeps the value: declined
			return "<" + m.Text + ">", nil
		case 2: // empty: declined
			return "", nil
		case 3: // a different, shorter token per value, which may itself abut word bytes
			return fmt.Sprintf("R%d", len(m.Text)), nil
		case 4: // fails on one value
			if strings.HasPrefix(m.Text, "a") {
				return "", errors.New("no replacement for this one")
			}
			return "###", nil
		case 5: // replacement carries a word byte so it abuts its neighbours differently
			return "_" + strings.Repeat("z", len(m.Text)), nil
		}
		return strings.Repeat("*", len(m.Text)), nil
	}
}

func TestSweepRemainingMatchesPerValueReference(t *testing.T) {
	r := rand.New(rand.NewSource(1005))
	const rounds = 6000
	var swept, errs, mixedSeen, wideSeen, bothKinds, altOnly, entityOnly int
	for i := 0; i < rounds; i++ {
		doc := fuzzDoc(r)
		ms := fuzzValues(r, doc)
		// Plant a wide and an entity copy of a value so the alternate spellings are exercised, and a
		// copy at each end so the boundary checks see no byte on one side.
		if len(ms) > 0 && ms[0].Text != "" {
			switch r.Intn(4) {
			case 0:
				doc += " " + wide(r, ms[0].Text)
			case 1:
				doc = strings.ReplaceAll(doc, "&", "&amp;") + " " + strings.ReplaceAll(ms[0].Text, "&", "&amp;")
			case 2:
				doc = ms[0].Text + doc + ms[0].Text
			}
		}
		mode := r.Intn(6)

		var wantCalls, gotCalls []string
		wantOut, wantSw, wantErr := sweepRemainingReference(doc, ms, fuzzReplacer(mode, &wantCalls))
		gotOut, gotSw, gotErr := SweepRemaining(doc, ms, fuzzReplacer(mode, &gotCalls))

		if gotOut != wantOut || !reflect.DeepEqual(gotSw, wantSw) || fmt.Sprint(gotErr) != fmt.Sprint(wantErr) ||
			!reflect.DeepEqual(gotCalls, wantCalls) {
			t.Fatalf("round %d mode %d differs\ndoc  %q\nvals %s\nwant out %q swept %q err %v calls %q\n got out %q swept %q err %v calls %q",
				i, mode, doc, describe(ms), wantOut, wantSw, wantErr, wantCalls, gotOut, gotSw, gotErr, gotCalls)
		}
		if len(wantSw) > 0 {
			swept++
		}
		for _, m := range ms {
			if len(m.Text) < minSweepLen {
				continue
			}
			lit, emb := occurrenceKinds([]byte(doc), []byte(m.Text))
			if lit > 0 && emb > 0 {
				bothKinds++ // the mixed value: replaced standalone, spared embedded
			}
			if lit == 0 {
				for k, alt := range altSpellings(m.Text, m.Text) {
					if c, _ := occurrenceKinds([]byte(doc), []byte(alt.from)); c > 0 {
						altOnly++ // admitted only through a wide or entity spelling
						if k >= 2 {
							entityOnly++
						}
						break
					}
				}
			}
		}
		if wantErr != nil {
			errs++
		}
		if wantOut != doc && strings.Contains(doc, "_") {
			mixedSeen++
		}
		if strings.Contains(doc, "\x00") && len(wantSw) > 0 {
			wideSeen++
		}
	}
	// Non-vacuity of the generator: the comparison is only worth anything if it reached the branches.
	t.Logf("values with both kinds %d, admitted only by an alternate spelling %d (entity %d)", bothKinds, altOnly, entityOnly)
	if bothKinds < 100 || altOnly < 100 || entityOnly < 20 {
		t.Fatalf("generator misses a branch: both=%d alt=%d entity=%d", bothKinds, altOnly, entityOnly)
	}
	t.Logf("%d rounds: %d swept something, %d errored, %d changed a doc with '_', %d swept in a doc with NUL", rounds, swept, errs, mixedSeen, wideSeen)
	if swept < rounds/5 || errs < rounds/50 || mixedSeen < rounds/20 {
		t.Fatalf("generator too weak: swept=%d errs=%d mixed=%d of %d", swept, errs, mixedSeen, rounds)
	}
}

func TestResidualTypesMatchesPerValueReference(t *testing.T) {
	r := rand.New(rand.NewSource(1006))
	var survived int
	for i := 0; i < 6000; i++ {
		doc := fuzzDoc(r)
		ms := fuzzValues(r, doc)
		if len(ms) > 0 && ms[0].Text != "" && r.Intn(3) == 0 {
			doc += wide(r, ms[0].Text) + strings.ReplaceAll(ms[0].Text, "&", "&amp;")
		}
		want := residualTypesReference([]byte(doc), ms)
		got := ResidualTypes([]byte(doc), ms)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round %d: want %q got %q\ndoc %q\nvals %s", i, want, got, doc, describe(ms))
		}
		if len(want) > 0 {
			survived++
		}
	}
	if survived < 600 {
		t.Fatalf("generator too weak: %d of 6000 rounds had a survivor", survived)
	}
}

// scanKinds against occurrenceKinds directly, over every needle that is a substring of a random
// document plus some that are not, so nested/overlapping/prefix-sharing needles all meet.
func TestScanKindsMatchesOccurrenceKinds(t *testing.T) {
	r := rand.New(rand.NewSource(1007))
	for i := 0; i < 3000; i++ {
		doc := fuzzDoc(r)
		var needles []string
		for j, n := 0, r.Intn(30); j < n; j++ {
			if len(doc) == 0 || r.Intn(5) == 0 {
				needles = append(needles, "ab_-"[:r.Intn(5)])
				continue
			}
			a := r.Intn(len(doc))
			l := r.Intn(8)
			if a+l > len(doc) {
				l = len(doc) - a
			}
			needles = append(needles, doc[a:a+l])
		}
		got := scanKinds(doc, needles)
		gotB := scanKinds([]byte(doc), needles)
		if !reflect.DeepEqual(got, gotB) {
			t.Fatalf("string and []byte haystacks disagree: %v vs %v", got, gotB)
		}
		for _, n := range needles {
			s, e := occurrenceKinds([]byte(doc), []byte(n))
			if want := (kinds{s > 0, e > 0}); got[n] != want {
				t.Fatalf("round %d: doc %q needle %q: want %+v got %+v", i, doc, n, want, got[n])
			}
		}
	}
}

func describe(ms []detector.Match) string {
	parts := make([]string, len(ms))
	for i, m := range ms {
		parts[i] = fmt.Sprintf("%s:%q", m.Type, m.Text)
	}
	return strings.Join(parts, " ")
}
