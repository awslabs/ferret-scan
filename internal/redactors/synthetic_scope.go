// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// One replacement per value per invocation, under the synthetic strategy (#886).
//
// Every synthetic replacement used to be drawn independently, per match: an SSN written four times
// in a .txt came back as four different SSNs, --stdin, .svg, .rtf and pkg/redact did the same, and
// the documented CSV-directory recipe gave one customer's SSN three unrelated fakes across two files,
// so a join on the SSN returned three rows on the input and none on the output. The code's own
// contract (office.partcoverage: a second fake "reads as two distinct values") and the docs ("test
// data generation") need one fake per value.
//
// A SyntheticScope is that memory. It maps a value, identified by its family and its canonical
// spelling, to the replacement drawn for it the first time it was seen, and it is ONE-TO-ONE: two
// different values of a family never receive the same replacement, so a join on the output finds
// exactly the rows it found on the input. Its lifetime is the invocation -- one per
// RedactionManager (a CLI run, a core.RedactFile call), one per in-memory call (--stdin, a pkg/scan
// call, a pkg/redact Request) -- and never longer: a scope shared by an Engine's callers would link
// one tenant's values to another's.

// MaxSyntheticDraws bounds the draws for one value. A draw that lands on a replacement another value
// of the family already holds is discarded and drawn again; after this many, the value cannot be
// given a replacement of its own and the file is refused (ErrSyntheticSpaceExhausted). With the
// smallest space a typed generator has -- a single-token name, 5,301 first names -- the 5,000th
// distinct name still finds a free one in 64 draws with probability 0.977.
const MaxSyntheticDraws = 64

// ErrNoSyntheticScope is returned when the synthetic strategy is asked to render a value with no
// scope to hold it. Drawing a fresh value instead is how every occurrence used to get a different
// one, so there is no fallback: a redactor built outside a RedactionManager, and handed no scope,
// refuses.
var ErrNoSyntheticScope = errors.New("synthetic redaction has no synthetic scope; " +
	"a redactor writes synthetic values only through a RedactionManager or with SetSyntheticScope")

// ErrSyntheticSpaceExhausted is wrapped by the error a scope returns when MaxSyntheticDraws draws all
// produced replacements other values already hold. The redactor refuses the file with it: reusing a
// replacement would merge two values in the output, and the simple placeholder would write another
// strategy than the one asked for. The message names the family, never a value.
var ErrSyntheticSpaceExhausted = errors.New("synthetic replacement space exhausted")

// SyntheticDraw draws one candidate replacement for a value, reading its randomness from rnd.
// attempt counts the candidates already discarded for this value (0 for the first).
type SyntheticDraw func(rnd io.Reader, attempt int) (string, error)

// SyntheticScope holds the synthetic replacement of every value an invocation has rendered.
//
// family names the generator a value belongs to (one family can span several finding types: every
// card brand is one family, every email type another), and canonical is the spelling that decides
// which occurrences are the same value: "234-56-0001" and "234 56 0001" share one canonical form, so
// they share one replacement, each written in its own shape by the caller. The scope never sees the
// rendered occurrence and never stores a value in clear: entries are keyed on an HMAC of
// (family, canonical) under a key drawn when the scope is created.
//
// distinct says whether the replacement stands in for an identity and must therefore be unique within
// the family. It is false only for a generator whose output is a generic notice rather than a value
// (an INTELLECTUAL_PROPERTY copyright line or confidentiality label), where two notices sharing one
// replacement merges nothing a reader could join on.
//
// Implementations are safe for concurrent use: the worker pool redacts files in parallel.
type SyntheticScope interface {
	Resolve(family, canonical string, distinct bool, draw SyntheticDraw) (string, error)
}

// SyntheticScopeUser is implemented by every redactor that can write a synthetic value.
// RegisterRedactor hands it the manager's scope, so every redactor of one manager -- and the
// redactors those compose, such as SVG's and RTF's inner text redactor -- shares one.
type SyntheticScopeUser interface {
	SetSyntheticScope(SyntheticScope)
}

// NewSyntheticScope returns an empty scope whose draws read crypto/rand.
func NewSyntheticScope() SyntheticScope { return newSyntheticScope(nil) }

// NewSeededSyntheticScope returns a scope whose draws are a deterministic function of
// (seed, family, canonical, attempt), so a seeded run is byte-identical however its files are
// scheduled.
//
// FOR TESTS ONLY. It is what makes synthetic output reproducible enough to assert on, and nothing
// outside a _test.go file may call it: no flag, environment variable or configuration key reaches
// it, and TestNoProductionCodeSeedsTheSyntheticScope enforces that. A seeded scope in a shipped
// binary would make every "synthetic" value a function of a constant.
func NewSeededSyntheticScope(seed []byte) SyntheticScope {
	return newSyntheticScope(append([]byte{}, seed...))
}

// syntheticScope is the in-memory scope.
type syntheticScope struct {
	// key keys the HMAC that names an entry, so the map holds no second cleartext copy of a value.
	key []byte
	// seed, when non-nil, makes every draw deterministic (NewSeededSyntheticScope).
	seed []byte

	mu sync.Mutex
	// held maps HMAC(key, family, canonical) to the replacement drawn for that value.
	held map[[sha256.Size]byte]string
	// taken records every distinct replacement handed out, per family, so a second value never
	// receives one the first already holds.
	taken map[string]struct{}
}

func newSyntheticScope(seed []byte) *syntheticScope {
	key := make([]byte, sha256.Size)
	// crypto/rand.Read never returns an error and always fills the buffer (Go 1.24+).
	_, _ = rand.Read(key)
	return &syntheticScope{
		key:   key,
		seed:  seed,
		held:  make(map[[sha256.Size]byte]string),
		taken: make(map[string]struct{}),
	}
}

// Resolve returns the replacement held for (family, canonical), drawing one on first use.
func (s *syntheticScope) Resolve(family, canonical string, distinct bool, draw SyntheticDraw) (string, error) {
	if draw == nil {
		return "", fmt.Errorf("synthetic scope: no generator for a %s value", family)
	}
	id := s.entryID(family, canonical)

	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.held[id]; ok {
		return v, nil
	}
	for attempt := 0; attempt < MaxSyntheticDraws; attempt++ {
		v, err := draw(s.source(family, canonical, attempt), attempt)
		if err != nil {
			return "", err
		}
		if distinct {
			k := family + "\x00" + v
			if _, dup := s.taken[k]; dup {
				continue
			}
			s.taken[k] = struct{}{}
		}
		s.held[id] = v
		return v, nil
	}
	return "", fmt.Errorf("%w: each of %d draws for a %s value produced a replacement that another %s value "+
		"in this run already holds; refusing rather than write two values as one",
		ErrSyntheticSpaceExhausted, MaxSyntheticDraws, family, family)
}

// entryID names a value without storing it: HMAC-SHA256(key, family || 0 || canonical).
func (s *syntheticScope) entryID(family, canonical string) [sha256.Size]byte {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(family))
	mac.Write([]byte{0})
	mac.Write([]byte(canonical))
	var id [sha256.Size]byte
	copy(id[:], mac.Sum(nil))
	return id
}

// source is the randomness one draw reads: crypto/rand, or for a seeded scope a stream derived from
// (seed, family, canonical, attempt) alone, so that a value's replacement does not depend on which
// values were drawn before it.
func (s *syntheticScope) source(family, canonical string, attempt int) io.Reader {
	if s.seed == nil {
		return rand.Reader
	}
	mac := hmac.New(sha256.New, s.seed)
	mac.Write([]byte(family))
	mac.Write([]byte{0})
	mac.Write([]byte(canonical))
	mac.Write([]byte{0})
	var a [8]byte
	binary.BigEndian.PutUint64(a[:], uint64(attempt)) // #nosec G115 -- attempt is in [0, MaxSyntheticDraws)
	mac.Write(a[:])
	return &counterStream{key: mac.Sum(nil)}
}

// counterStream is SHA-256 in counter mode: block i is SHA-256(key || i). Deterministic and
// unbounded, which is all a seeded test draw needs; it is never used for a real redaction.
type counterStream struct {
	key []byte
	ctr uint64
	buf []byte
}

func (c *counterStream) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(c.buf) == 0 {
			block := make([]byte, 0, len(c.key)+8)
			block = append(block, c.key...)
			block = binary.BigEndian.AppendUint64(block, c.ctr)
			c.ctr++
			sum := sha256.Sum256(block)
			c.buf = sum[:]
		}
		k := copy(p[n:], c.buf)
		c.buf = c.buf[k:]
		n += k
	}
	return n, nil
}
