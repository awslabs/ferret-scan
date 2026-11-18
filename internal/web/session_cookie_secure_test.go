// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The session cookie carries Secure exactly when the request arrived over HTTPS (#1014): a TLS
// connection to this process, or a reverse proxy that terminated TLS and says so. Over plain HTTP it
// stays unmarked, because the documented origin is http://localhost (an SSH port-forward to the
// loopback bind), where Safari refuses to store a Secure cookie and nothing is in transit to protect.
// Measured on main @ 946294f: the cookie never carried Secure, over TLS included (CodeQL #3845).
func TestSessionCookieSecureFollowsTheRequestScheme(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(r *http.Request)
		secure bool
	}{
		{"plain http (the documented localhost path)", func(*http.Request) {}, false},
		{"TLS connection to this process", func(r *http.Request) { r.TLS = &tls.ConnectionState{} }, true},
		{"TLS terminated by a proxy", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") }, true},
		{"proxy chain, https first", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "HTTPS, http") }, true},
		{"proxy says http", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/scan", nil)
			tc.mutate(r)
			rec := httptest.NewRecorder()
			if _, err := scanSession(rec, r); err != nil {
				t.Fatal(err)
			}
			var got *http.Cookie
			for _, c := range rec.Result().Cookies() {
				if c.Name == scanSessionCookie {
					got = c
				}
			}
			if got == nil {
				t.Fatalf("no %s cookie set", scanSessionCookie)
			}
			if got.Secure != tc.secure {
				t.Fatalf("Secure = %v, want %v (cookie %+v)", got.Secure, tc.secure, got)
			}
			if !got.HttpOnly || got.SameSite != http.SameSiteStrictMode || got.Path != "/" {
				t.Fatalf("the other attributes moved: %+v", got)
			}
		})
	}
}
