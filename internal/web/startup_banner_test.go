// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// bannerFor prints the startup banner for bindAddr and port and returns what went to stdout and to
// stderr. It swaps the process's os.Stdout and os.Stderr, so it must not run in parallel with other
// tests (none in this package does).
func bannerFor(t *testing.T, bindAddr, port string) (stdout, stderr string) {
	t.Helper()
	capture := func(target **os.File) (func() string, error) {
		r, w, err := os.Pipe()
		if err != nil {
			return nil, err
		}
		saved := *target
		*target = w
		done := make(chan string)
		go func() {
			b, _ := io.ReadAll(r)
			done <- string(b)
		}()
		return func() string {
			*target = saved
			_ = w.Close()
			out := <-done
			_ = r.Close()
			return out
		}, nil
	}
	stopOut, err := capture(&os.Stdout)
	if err != nil {
		t.Fatal(err)
	}
	stopErr, err := capture(&os.Stderr)
	if err != nil {
		stopOut()
		t.Fatal(err)
	}
	NewWebServerWithOptions(port, bindAddr, "", "", nil).printStartupBanner(port)
	return stopOut(), stopErr()
}

// TestStartupBannerSuggestsNoWiderExposure holds both access hints to the loopback posture. The
// loopback line suggested `--bind 0.0.0.0`, which serves the unauthenticated UI on every interface,
// and the container line suggested `-p 8082:<port>`, which publishes on every host interface and, with
// a host port other than the server's, fails the Origin check on every POST. Fails on the parent
// commit, which printed both.
func TestStartupBannerSuggestsNoWiderExposure(t *testing.T) {
	t.Run("loopback", func(t *testing.T) {
		out, _ := bannerFor(t, "127.0.0.1", "8080")
		if strings.Contains(out, "0.0.0.0") {
			t.Errorf("the loopback banner suggests an every-interface bind:\n%s", out)
		}
		for _, want := range []string{
			"Ferret Scan Web UI started on 127.0.0.1:8080\n", // scripts/surface-parity.sh reads this line
			"Local:     http://localhost:8080\n",
			"ssh -N -L 8080:127.0.0.1:8080 <this host>",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the loopback banner lacks %q:\n%s", want, out)
			}
		}
	})
	t.Run("IPv6 loopback", func(t *testing.T) {
		out, _ := bannerFor(t, "::1", "8080")
		for _, want := range []string{
			"Ferret Scan Web UI started on [::1]:8080\n",
			"Local:     http://[::1]:8080\n",
			"ssh -N -L 8080:[::1]:8080 <this host>",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the [::1] banner lacks %q:\n%s", want, out)
			}
		}
	})
	t.Run("every interface, as in a container", func(t *testing.T) {
		out, errOut := bannerFor(t, "0.0.0.0", "8080")
		if strings.Contains(out, "8082") {
			t.Errorf("the banner suggests another host port, which fails the Origin check:\n%s", out)
		}
		if !strings.Contains(out, "-p 127.0.0.1:8080:8080") {
			t.Errorf("the banner does not name a loopback publish of the same port:\n%s", out)
		}
		if !strings.Contains(errOut, "WARNING: web UI is bound to 0.0.0.0 with no authentication") {
			t.Errorf("the every-interface warning is gone from stderr:\n%s", errOut)
		}
	})
}

// TestPublishedPortMustMatchForTheOriginCheck is why the container hint keeps the port: behind
// `-p 127.0.0.1:8082:8080` the page is http://localhost:8082, and the Origin check of a server on
// 8080 refuses its POSTs.
func TestPublishedPortMustMatchForTheOriginCheck(t *testing.T) {
	h := originCheckMiddleware(sameOriginHostSet("0.0.0.0", "8080"))(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for origin, want := range map[string]int{
		"http://localhost:8080": http.StatusNoContent,
		"http://127.0.0.1:8080": http.StatusNoContent,
		"http://localhost:8082": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodPost, "/scan", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("POST from %s to a server on 0.0.0.0:8080: HTTP %d, want %d", origin, rec.Code, want)
		}
	}
}
