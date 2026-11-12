// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// scanStore keeps the result of each /scan the server ran, so /export can format THAT result rather
// than whatever the browser posts back (#923).
//
// /export used to rebuild detector.Match from the browser's copy of the /scan JSON. That wire shape
// does not carry the explanation, the context keywords or the typed metadata the formatters read, so
// 18 of 28 exported bodies differed from the CLI's report of the same findings; and because the whole
// result set travelled in one request body under the 1 MiB JSON cap, 782 findings answered HTTP 400.
// /scan now returns a scan_id and /export takes ids, so the request stays small and the formatter sees
// the detector.Match values the scan produced.
//
// Bounded three ways, because every entry holds matched values in memory:
//   - by age: an entry expires scanTTL after it was stored;
//   - by count: at most maxStoredScans entries (one per uploaded file, the front-end's upload unit);
//   - by size: at most maxStoredFindings findings across all entries.
//
// The oldest entries go first when a bound is reached. An entry belongs to the session that created it
// (the scanSessionCookie value) and is invisible to any other: an id alone does not reach a result.
//
// shortcut: one global bound shared by every session, so a session that stores a lot can evict another
// session's older results; fine for a single-operator tool on loopback, upgrade to per-session quotas
// if the UI is ever served to several people at once.
type scanStore struct {
	mu       sync.Mutex
	entries  map[string]*storedScan
	order    []string // insertion order, oldest first
	findings int
	now      func() time.Time
}

// storedScan is one /scan's result, as the server ran it.
type storedScan struct {
	session    string
	created    time.Time
	matches    []detector.Match
	suppressed []detector.SuppressedMatch
	// settings is the scan's own confidence and checks; /export refuses to merge scans that disagree,
	// because one report has one confidence filter and one scope.
	settings   string
	confidence map[string]bool
}

const (
	scanTTL           = time.Hour
	maxStoredScans    = 4096
	maxStoredFindings = 200_000

	// scanSessionCookie names the cookie that scopes stored scans to one browser session. HttpOnly and
	// SameSite=Strict: the page's script never needs it, and a cross-site request must not carry it.
	scanSessionCookie = "ferret_scan_session"
)

func newScanStore() *scanStore {
	return &scanStore{entries: map[string]*storedScan{}, now: time.Now}
}

// randomToken returns 16 random bytes as hex, the form of both session values and scan ids.
func randomToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// validToken reports whether s has the shape randomToken produces, so a cookie or id that could not
// have come from this server is refused before it is used as a map key.
func validToken(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// put stores one scan's result for session and returns its id.
func (s *scanStore) put(session string, entry *storedScan) (string, error) {
	id, err := randomToken()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.session = session
	entry.created = s.now()
	s.expireLocked()
	n := len(entry.matches) + len(entry.suppressed)
	for len(s.order) > 0 && (len(s.order) >= maxStoredScans || s.findings+n > maxStoredFindings) {
		s.dropLocked(s.order[0])
	}
	s.entries[id] = entry
	s.order = append(s.order, id)
	s.findings += n
	return id, nil
}

// get returns the stored scans for ids, in the order given, or ok=false naming the first id that is
// unknown, expired, or another session's. Repeated ids are returned once.
func (s *scanStore) get(session string, ids []string) (out []*storedScan, missing string, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		e, found := s.entries[id]
		if !found || e.session != session {
			return nil, id, false
		}
		out = append(out, e)
	}
	return out, "", true
}

func (s *scanStore) expireLocked() {
	cutoff := s.now().Add(-scanTTL)
	for len(s.order) > 0 {
		e := s.entries[s.order[0]]
		if e != nil && e.created.After(cutoff) {
			return
		}
		s.dropLocked(s.order[0])
	}
}

func (s *scanStore) dropLocked(id string) {
	if e, ok := s.entries[id]; ok {
		s.findings -= len(e.matches) + len(e.suppressed)
		delete(s.entries, id)
	}
	for i, v := range s.order {
		if v == id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
}

// scanSession returns the request's session value, minting one and setting the cookie when the
// request carries none (or one this server could not have issued).
func scanSession(w http.ResponseWriter, r *http.Request) (string, error) {
	if c, err := r.Cookie(scanSessionCookie); err == nil && validToken(c.Value) {
		return c.Value, nil
	}
	v, err := randomToken()
	if err != nil {
		return "", err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     scanSessionCookie,
		Value:    v,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	return v, nil
}

// existingScanSession returns the request's session value, or "" when it has none: /export never mints
// one, because a new session has no scans to export.
func existingScanSession(r *http.Request) string {
	if c, err := r.Cookie(scanSessionCookie); err == nil && validToken(c.Value) {
		return c.Value
	}
	return ""
}
