// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"net/http"
	"net/url"
	"os"
	"strings"
)

// ResolveBindAddress decides which network interface the web UI should bind
// to. Resolution order (highest precedence first):
//
//  1. explicit --bind flag value passed by the operator
//  2. FERRET_CONTAINER_MODE=true env var (set by the published Docker image)
//  3. /.dockerenv exists (Docker / Podman / containerd convention)
//  4. fallback: 127.0.0.1 (loopback only)
//
// Containers default to 0.0.0.0 because the container's network namespace IS
// the trust boundary — port publishing (`docker run -p 127.0.0.1:8080:8080
// ...`) is what decides whether the host exposes the port to the LAN.
//
// Returns the bind address and a boolean indicating whether the choice was
// made automatically (used to drive a startup warning when binding broadly).
func ResolveBindAddress(explicitFlag string) (addr string, autoDetected bool) {
	if explicitFlag != "" {
		return explicitFlag, false
	}
	if v := os.Getenv("FERRET_CONTAINER_MODE"); strings.EqualFold(strings.TrimSpace(v), "true") {
		return "0.0.0.0", true
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "0.0.0.0", true
	}
	return "127.0.0.1", false
}

// IsLoopbackBind reports whether the given bind address restricts the server
// to the local machine. Used to decide whether to emit a LAN-exposure warning.
func IsLoopbackBind(addr string) bool {
	switch addr {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// securityHeadersMiddleware injects defense-in-depth response headers on
// every response. Once XSS or CSRF slips into a handler, these headers limit
// what an attacker can do; they are not a substitute for input sanitization
// and Origin checks (handled separately).
//
// script-src is strict ('self', no 'unsafe-inline'): all front-end code
// lives in the embedded /app.js asset and the template carries no inline
// <script> blocks or on*= handler attributes (interactivity is bound via
// data-action/data-change delegation — see assets/app.js). Structural tests
// in template_xss_test.go fail the build if inline script sneaks back in.
//
// style-src intentionally keeps 'unsafe-inline': the template still uses
// ~301 inline style attributes. Hoisting those into the stylesheet is a
// separate follow-up (issue #147 covers script-src only). Even so, CSP
// blocks:
//   - inline and external scripts (script-src 'self')
//   - external style sources other than the allow-listed CDN
//   - cross-origin form posts (form-action 'self')
//   - object/embed/applet (object-src 'none')
//   - base-uri tampering (base-uri 'self')
//
// The Cloudscape design system stylesheet served from d0.awsstatic.com is
// allow-listed in style-src. Removing that dependency is tracked separately.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline' https://d0.awsstatic.com; " +
		"img-src 'self' data:; " +
		"font-src 'self' data:; " +
		"connect-src 'self'; " +
		"object-src 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'; " +
		"frame-ancestors 'none'"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// HSTS is intentionally omitted: the embedded server is HTTP-only by
		// design. If a deployment fronts the UI with a TLS-terminating proxy,
		// the proxy is the right layer to set HSTS.
		next.ServeHTTP(w, r)
	})
}

// originCheckMiddleware rejects state-changing requests whose Origin or
// Referer doesn't match the bound host. Allows non-browser callers
// (curl, Go clients) that send neither header — they are out of scope for
// CSRF since CSRF specifically exploits the browser's ambient credentials.
//
// Read-only methods (GET, HEAD, OPTIONS) pass through unconditionally.
//
// expectedHosts is the set of host:port combinations the server considers
// same-origin. When binding to 127.0.0.1:8080, it includes both
// "127.0.0.1:8080" and "localhost:8080" so links from either name work.
func originCheckMiddleware(expectedHosts map[string]struct{}) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			referer := r.Header.Get("Referer")

			// Non-browser callers (curl, scripted clients) typically send
			// neither header. Allow those — they aren't subject to CSRF.
			if origin == "" && referer == "" {
				next.ServeHTTP(w, r)
				return
			}

			if origin != "" {
				if hostFromURL(origin, expectedHosts) {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, "cross-origin request rejected", http.StatusForbidden)
				return
			}

			// Origin missing but Referer set — fall back to Referer.
			if hostFromURL(referer, expectedHosts) {
				next.ServeHTTP(w, r)
				return
			}
			http.Error(w, "cross-origin request rejected", http.StatusForbidden)
		})
	}
}

// hostFromURL parses raw and returns true when the resulting Host (host:port)
// is in the expected set. Returns false on parse error or empty input.
func hostFromURL(raw string, expected map[string]struct{}) bool {
	if raw == "" {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	_, ok := expected[strings.ToLower(u.Host)]
	return ok
}

// sameOriginHostSet builds the set of host:port strings that count as
// same-origin for the bound address. localhost and 127.0.0.1 are treated as
// equivalent so a user navigating to either name doesn't get cross-origin
// errors.
func sameOriginHostSet(bindAddr, port string) map[string]struct{} {
	set := map[string]struct{}{}
	add := func(host string) {
		set[strings.ToLower(host+":"+port)] = struct{}{}
	}
	add(bindAddr)
	if bindAddr == "127.0.0.1" || bindAddr == "::1" {
		add("localhost")
	}
	if bindAddr == "localhost" {
		add("127.0.0.1")
	}
	if bindAddr == "0.0.0.0" {
		// When bound to all interfaces, accept localhost variants. The
		// LAN-side hostnames are not enumerable from the server, so a
		// determined cross-origin POST from a LAN-resolvable hostname will
		// pass — that's by design: the operator opted into LAN exposure,
		// CSRF protection at this layer becomes best-effort.
		add("localhost")
		add("127.0.0.1")
	}
	return set
}
