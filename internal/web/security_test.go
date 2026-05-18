// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestResolveBindAddress_PriorityOrder(t *testing.T) {
	// Save and restore env to keep tests hermetic.
	prev, hadPrev := os.LookupEnv("FERRET_CONTAINER_MODE")
	t.Cleanup(func() {
		if hadPrev {
			os.Setenv("FERRET_CONTAINER_MODE", prev)
		} else {
			os.Unsetenv("FERRET_CONTAINER_MODE")
		}
	})

	t.Run("explicit flag wins over env", func(t *testing.T) {
		os.Setenv("FERRET_CONTAINER_MODE", "true")
		got, auto := ResolveBindAddress("127.0.0.1")
		if got != "127.0.0.1" {
			t.Errorf("got %q, want 127.0.0.1", got)
		}
		if auto {
			t.Error("autoDetected should be false when explicit flag is given")
		}
	})

	t.Run("env=true triggers 0.0.0.0", func(t *testing.T) {
		os.Setenv("FERRET_CONTAINER_MODE", "true")
		got, auto := ResolveBindAddress("")
		if got != "0.0.0.0" {
			t.Errorf("got %q, want 0.0.0.0", got)
		}
		if !auto {
			t.Error("autoDetected should be true when env triggers")
		}
	})

	t.Run("env=true case-insensitive and trimmed", func(t *testing.T) {
		os.Setenv("FERRET_CONTAINER_MODE", "  TRUE ")
		got, _ := ResolveBindAddress("")
		if got != "0.0.0.0" {
			t.Errorf("got %q, want 0.0.0.0", got)
		}
	})

	t.Run("env=false falls through to default", func(t *testing.T) {
		os.Setenv("FERRET_CONTAINER_MODE", "false")
		// Note: this test assumes /.dockerenv doesn't exist on the test
		// runner. If the test ever runs inside a container, this will
		// flip — t.Skip on /.dockerenv presence.
		if _, err := os.Stat("/.dockerenv"); err == nil {
			t.Skip("test runner is inside a container; default would be 0.0.0.0")
		}
		got, _ := ResolveBindAddress("")
		if got != "127.0.0.1" {
			t.Errorf("got %q, want 127.0.0.1", got)
		}
	})

	t.Run("no env, no flag, no /.dockerenv => loopback", func(t *testing.T) {
		os.Unsetenv("FERRET_CONTAINER_MODE")
		if _, err := os.Stat("/.dockerenv"); err == nil {
			t.Skip("test runner is inside a container; default would be 0.0.0.0")
		}
		got, auto := ResolveBindAddress("")
		if got != "127.0.0.1" {
			t.Errorf("got %q, want 127.0.0.1", got)
		}
		if auto {
			t.Error("autoDetected should be false for the loopback default")
		}
	})
}

func TestIsLoopbackBind(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"localhost", true},
		{"0.0.0.0", false},
		{"::", false},
		{"192.168.1.5", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := IsLoopbackBind(tc.addr); got != tc.want {
			t.Errorf("IsLoopbackBind(%q)=%v, want %v", tc.addr, got, tc.want)
		}
	}
}

func TestSecurityHeadersMiddleware_AddsAllHeaders(t *testing.T) {
	h := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	wantHeaders := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	}
	for k, want := range wantHeaders {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy header missing")
	}
	for _, frag := range []string{
		"default-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, frag) {
			t.Errorf("CSP missing %q. Full: %s", frag, csp)
		}
	}
}

func TestOriginCheckMiddleware(t *testing.T) {
	expected := sameOriginHostSet("127.0.0.1", "8080")

	// Tracks whether the inner handler ran.
	var inner http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot) // sentinel
	}
	mw := originCheckMiddleware(expected)(inner)

	type tc struct {
		name     string
		method   string
		origin   string
		referer  string
		wantCode int
	}
	cases := []tc{
		{"GET passes regardless", http.MethodGet, "http://evil.example", "", http.StatusTeapot},
		{"HEAD passes regardless", http.MethodHead, "http://evil.example", "", http.StatusTeapot},
		{"OPTIONS passes regardless", http.MethodOptions, "", "http://evil.example", http.StatusTeapot},
		{"POST without Origin/Referer is allowed (curl)", http.MethodPost, "", "", http.StatusTeapot},
		{"POST with matching Origin", http.MethodPost, "http://127.0.0.1:8080", "", http.StatusTeapot},
		{"POST with localhost Origin (alias)", http.MethodPost, "http://localhost:8080", "", http.StatusTeapot},
		{"POST with cross-origin Origin", http.MethodPost, "http://evil.example", "", http.StatusForbidden},
		{"POST with mismatched port", http.MethodPost, "http://127.0.0.1:9999", "", http.StatusForbidden},
		{"POST with cross-origin Referer when Origin missing", http.MethodPost, "", "http://evil.example/page", http.StatusForbidden},
		{"POST with same-origin Referer", http.MethodPost, "", "http://127.0.0.1:8080/page", http.StatusTeapot},
		{"PUT enforced", http.MethodPut, "http://evil.example", "", http.StatusForbidden},
		{"DELETE enforced", http.MethodDelete, "http://evil.example", "", http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, "/scan", nil)
			if c.origin != "" {
				req.Header.Set("Origin", c.origin)
			}
			if c.referer != "" {
				req.Header.Set("Referer", c.referer)
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Errorf("%s: got %d, want %d. body=%s",
					c.name, rec.Code, c.wantCode, rec.Body.String())
			}
		})
	}
}

func TestSameOriginHostSet_LocalhostAlias(t *testing.T) {
	set := sameOriginHostSet("127.0.0.1", "8080")
	for _, host := range []string{"127.0.0.1:8080", "localhost:8080"} {
		if _, ok := set[host]; !ok {
			t.Errorf("expected host %q in set, got %v", host, set)
		}
	}
}

func TestSameOriginHostSet_AllInterfacesAcceptsLocalhost(t *testing.T) {
	// When bound to 0.0.0.0 the operator opted into broader exposure;
	// localhost variants must still be accepted as same-origin so a user
	// browsing http://localhost:port can issue mutations.
	set := sameOriginHostSet("0.0.0.0", "8080")
	for _, host := range []string{"localhost:8080", "127.0.0.1:8080", "0.0.0.0:8080"} {
		if _, ok := set[host]; !ok {
			t.Errorf("expected %q in same-origin set for 0.0.0.0 bind, got %v", host, set)
		}
	}
}
