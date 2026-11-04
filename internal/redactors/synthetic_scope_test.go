// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

// drawFrom returns a SyntheticDraw that picks one of choices uniformly, reading rnd.
func drawFrom(choices ...string) SyntheticDraw {
	return func(rnd io.Reader, _ int) (string, error) {
		var b [1]byte
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return "", err
		}
		return choices[int(b[0])%len(choices)], nil
	}
}

// counter returns a SyntheticDraw that hands out "v0", "v1", ... and counts its calls.
func counter(calls *int) SyntheticDraw {
	return func(io.Reader, int) (string, error) {
		*calls++
		return fmt.Sprintf("v%d", *calls), nil
	}
}

func TestScopeGivesOneValueOneReplacement(t *testing.T) {
	s := NewSyntheticScope()
	calls := 0
	first, err := s.Resolve("SSN", "234560001", true, counter(&calls))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		again, err := s.Resolve("SSN", "234560001", true, counter(&calls))
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatalf("occurrence %d of one value got %q, the first got %q", i+2, again, first)
		}
	}
	if calls != 1 {
		t.Errorf("the generator was called %d times for one value, want once", calls)
	}
	other, err := s.Resolve("SSN", "234560002", true, counter(&calls))
	if err != nil {
		t.Fatal(err)
	}
	if other == first {
		t.Errorf("two values were given one replacement %q", other)
	}
	// The same canonical spelling in another family is another value.
	phone, err := s.Resolve("PHONE", "234560001", true, counter(&calls))
	if err != nil {
		t.Fatal(err)
	}
	if phone == first {
		t.Errorf("an SSN and a PHONE with the same digits share %q; families are separate values", phone)
	}
}

// One-to-one, or refuse. A family whose generator can produce four values serves four values and
// refuses the fifth -- it never hands an output out twice and never falls back to anything.
func TestScopeIsOneToOneOrRefuses(t *testing.T) {
	s := NewSyntheticScope()
	draw := drawFrom("a", "b", "c", "d")
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		v, err := s.Resolve("TINY", fmt.Sprintf("value-%d", i), true, draw)
		if err != nil {
			t.Fatalf("value %d of a 4-value family was refused: %v", i, err)
		}
		if seen[v] {
			t.Fatalf("value %d reused the replacement %q", i, v)
		}
		seen[v] = true
	}
	_, err := s.Resolve("TINY", "value-4", true, draw)
	if !errors.Is(err, ErrSyntheticSpaceExhausted) {
		t.Fatalf("the fifth value of a 4-value family: err = %v, want ErrSyntheticSpaceExhausted", err)
	}
	if strings.Contains(err.Error(), "value-4") {
		t.Errorf("the refusal names the value: %v", err)
	}
	if !strings.Contains(err.Error(), "TINY") {
		t.Errorf("the refusal does not name the family: %v", err)
	}
	// The refusal holds: asking again does not succeed by luck or reuse a value.
	if _, err := s.Resolve("TINY", "value-4", true, draw); !errors.Is(err, ErrSyntheticSpaceExhausted) {
		t.Errorf("a second request for the refused value: %v", err)
	}
	// The values already served keep their replacements.
	for i := 0; i < 4; i++ {
		v, err := s.Resolve("TINY", fmt.Sprintf("value-%d", i), true, draw)
		if err != nil || !seen[v] {
			t.Errorf("value %d changed after a refusal: %q, %v", i, v, err)
		}
	}
}

// A generic notice is not an identity: two values may share one, and nothing is refused.
func TestScopeLetsANoticeBeShared(t *testing.T) {
	s := NewSyntheticScope()
	draw := drawFrom("[TRADEMARK-REDACTED]")
	for i := 0; i < 10; i++ {
		if _, err := s.Resolve("INTELLECTUAL_PROPERTY", fmt.Sprintf("Mark %d(tm)", i), false, draw); err != nil {
			t.Fatalf("notice %d: %v", i, err)
		}
	}
}

func TestScopeReturnsTheGeneratorsError(t *testing.T) {
	s := NewSyntheticScope()
	boom := errors.New("name database unavailable")
	_, err := s.Resolve("PERSON_NAME", "dana whitfield", true, func(io.Reader, int) (string, error) { return "", boom })
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the generator's error", err)
	}
	// Nothing was stored: the next request draws again.
	v, err := s.Resolve("PERSON_NAME", "dana whitfield", true, drawFrom("Anna Jones"))
	if err != nil || v != "Anna Jones" {
		t.Fatalf("after a failed draw: %q, %v", v, err)
	}
}

// The worker pool redacts files in parallel against one scope: every goroutine asking for one value
// gets the one replacement, and the generator runs once.
func TestScopeIsSafeForConcurrentUse(t *testing.T) {
	s := NewSyntheticScope()
	var mu sync.Mutex
	calls := 0
	draw := func(io.Reader, int) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return fmt.Sprintf("fake-%d", calls), nil
	}
	const workers = 64
	got := make([]string, workers)
	var start, done sync.WaitGroup
	start.Add(1)
	for i := 0; i < workers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			v, err := s.Resolve("SSN", "234560001", true, draw)
			if err != nil {
				t.Error(err)
			}
			got[i] = v
		}(i)
	}
	start.Done()
	done.Wait()
	for i := range got {
		if got[i] != got[0] {
			t.Fatalf("goroutine %d got %q, goroutine 0 got %q", i, got[i], got[0])
		}
	}
	if calls != 1 {
		t.Errorf("the generator ran %d times for one value", calls)
	}
}

// A seeded draw depends on (seed, family, canonical, attempt) only, so a value's replacement does not
// depend on which values were drawn before it -- which is what makes a seeded multi-file run
// byte-identical however the worker pool schedules its files.
func TestSeededScopeIsIndependentOfOrder(t *testing.T) {
	draw := func(rnd io.Reader, _ int) (string, error) {
		b := make([]byte, 8)
		if _, err := io.ReadFull(rnd, b); err != nil {
			return "", err
		}
		return fmt.Sprintf("%x", b), nil
	}
	keys := []string{"a", "b", "c", "d", "e"}
	resolveAll := func(s SyntheticScope, order []string) map[string]string {
		out := map[string]string{}
		for _, k := range order {
			v, err := s.Resolve("SSN", k, true, draw)
			if err != nil {
				t.Fatal(err)
			}
			out[k] = v
		}
		return out
	}
	seed := []byte("ferret-scan test seed")
	forward := resolveAll(NewSeededSyntheticScope(seed), keys)
	backward := resolveAll(NewSeededSyntheticScope(seed), []string{"e", "d", "c", "b", "a"})
	for _, k := range keys {
		if forward[k] != backward[k] {
			t.Errorf("%s: %q in one order, %q in the other", k, forward[k], backward[k])
		}
	}
	other := resolveAll(NewSeededSyntheticScope([]byte("another seed")), keys)
	same := 0
	for _, k := range keys {
		if other[k] == forward[k] {
			same++
		}
	}
	if same == len(keys) {
		t.Error("two seeds drew identical replacements: the seed is not reaching the draw")
	}
	// An unseeded scope reads crypto/rand: two of them do not agree.
	a, b := resolveAll(NewSyntheticScope(), keys), resolveAll(NewSyntheticScope(), keys)
	if fmt.Sprint(a) == fmt.Sprint(b) {
		t.Error("two unseeded scopes drew identical replacements")
	}
}

// The scope keeps no cleartext copy of the values it has seen: its entries are named by an HMAC.
func TestScopeStoresNoValue(t *testing.T) {
	s := newSyntheticScope(nil)
	const value = "234-56-0001-a-value-to-find"
	if _, err := s.Resolve("SSN", value, true, drawFrom("666-00-1234")); err != nil {
		t.Fatal(err)
	}
	for id, repl := range s.held {
		if strings.Contains(string(id[:]), value) || strings.Contains(repl, value) {
			t.Errorf("an entry holds the value: %x -> %q", id, repl)
		}
	}
	for k := range s.taken {
		if strings.Contains(k, value) {
			t.Errorf("the reverse index holds the value: %q", k)
		}
	}
}

// scopeUser records the scope a manager hands it.
type scopeUser struct {
	stubRedactor
	scope SyntheticScope
}

func (u *scopeUser) SetSyntheticScope(s SyntheticScope) { u.scope = s }

// One manager, one scope, for every redactor registered with it; a replacement scope reaches all.
func TestTheManagerHandsOneScopeToEveryRedactor(t *testing.T) {
	om, err := NewOutputStructureManager(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := NewRedactionManagerWithConfig(om, nil, nil)
	a := &scopeUser{stubRedactor: stubRedactor{exts: []string{".aaa"}}}
	b := &scopeUser{stubRedactor: stubRedactor{exts: []string{".bbb"}}}
	for _, r := range []Redactor{a, b} {
		if err := m.RegisterRedactor(r); err != nil {
			t.Fatal(err)
		}
	}
	if a.scope == nil || a.scope != b.scope {
		t.Fatalf("redactors of one manager hold scopes %p and %p, want one", a.scope, b.scope)
	}
	seeded := NewSeededSyntheticScope([]byte("seed"))
	m.SetSyntheticScope(seeded)
	if a.scope != seeded || b.scope != seeded {
		t.Fatalf("SetSyntheticScope did not reach every registered redactor")
	}
	om2, err := NewOutputStructureManager(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m2 := NewRedactionManagerWithConfig(om2, nil, nil)
	c := &scopeUser{stubRedactor: stubRedactor{exts: []string{".ccc"}}}
	if err := m2.RegisterRedactor(c); err != nil {
		t.Fatal(err)
	}
	if c.scope == nil || c.scope == seeded || c.scope == a.scope {
		t.Fatal("a second manager shares the first one's scope; its lifetime is one manager")
	}
}
