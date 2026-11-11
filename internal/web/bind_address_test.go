// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSameOriginHostSetJoinsIPv6Hosts pins the Origin check for an IPv6 bind. The set held "::1:8080",
// while a browser at http://[::1]:8080/ sends that Origin, whose Host url.Parse returns as
// "[::1]:8080", so every POST from the UI on an IPv6 loopback bind was refused (#926). Fails on the
// parent commit.
func TestSameOriginHostSetJoinsIPv6Hosts(t *testing.T) {
	set := sameOriginHostSet("::1", "8080")
	for _, want := range []string{"[::1]:8080", "localhost:8080"} {
		if _, ok := set[want]; !ok {
			t.Errorf("sameOriginHostSet(::1, 8080) lacks %q: %v", want, set)
		}
	}
	h := originCheckMiddleware(set)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	for origin, want := range map[string]int{
		"http://[::1]:8080":        http.StatusNoContent,
		"http://localhost:8080":    http.StatusNoContent,
		"http://[::1]:9090":        http.StatusForbidden,
		"http://evil.example:8080": http.StatusForbidden,
	} {
		req := httptest.NewRequest(http.MethodPost, "/scan", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("POST with Origin %s: HTTP %d, want %d", origin, rec.Code, want)
		}
	}
	// IPv4 entries are spelled as before.
	if _, ok := sameOriginHostSet("127.0.0.1", "8080")["127.0.0.1:8080"]; !ok {
		t.Error("sameOriginHostSet(127.0.0.1, 8080) lacks 127.0.0.1:8080")
	}
}

// syncBuffer is a bytes.Buffer safe for a child process writing and a test reading.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startWebCLI runs `ferret-scan --web` with args and returns the first startup line ("Ferret Scan Web
// UI started on ...") and the process's stderr so far. The process is killed when the test ends.
func startWebCLI(t *testing.T, bin string, args ...string) (string, *syncBuffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	all := append([]string{"--web", "--config", cfg, "--suppression-file", filepath.Join(dir, "none.yaml")}, args...)
	cmd := exec.Command(bin, all...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &syncBuffer{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	lines := make(chan string, 64)
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	deadline := time.After(90 * time.Second)
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				_ = cmd.Wait() // finishes copying stderr before it is read
				t.Fatalf("ferret-scan %s exited before it started serving; stderr:\n%s", strings.Join(args, " "), stderr.String())
			}
			if strings.HasPrefix(l, "Ferret Scan Web UI started on ") {
				go func() { // keep draining so the child never blocks on a full pipe
					for range lines {
					}
				}()
				return l, stderr
			}
		case <-deadline:
			t.Fatalf("ferret-scan %s printed no startup line in 90s; stderr:\n%s", strings.Join(args, " "), stderr.String())
		}
	}
}

// getStatus GETs or POSTs url and returns the status code, failing the test on a transport error.
func getStatus(t *testing.T, req *http.Request) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(req.Context(), 30*time.Second)
	defer cancel()
	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

// TestWebCLIBindsTheAddressItIsGiven holds `ferret-scan --web` to listening on --bind and nowhere
// else, measured on the built binary because the probe that broke it lives in cmd/main.go.
//
// isPortAvailable probed ":port", every interface, before the loopback bind (#926). The first
// subtest makes that observable without listening beyond loopback: it holds the port on [::1], the
// IPv6 loopback, as a dev server on "localhost" does. An every-interface probe collides with that
// listener (Go's ":port" is the dual-stack [::]), so the parent commit reported the port taken and
// started on 8080 instead; a probe of 127.0.0.1 does not collide, so the server starts on the port it
// was given. The second subtest is --bind ::1, which never started on the parent commit: the address
// was concatenated as "::1:port", which net.Listen refuses. Every listener here is loopback.
func TestWebCLIBindsTheAddressItIsGiven(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the CLI binary; skipped under -short")
	}
	name := "ferret-scan-bind"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	build := exec.Command("go", "build", "-o", bin, "../../cmd")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build ./cmd: %v\n%s", err, out)
	}

	t.Run("a port held on [::1] does not move a 127.0.0.1 server", func(t *testing.T) {
		held, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback here (%v), so nothing tells the two probes apart", err)
		}
		defer held.Close()
		_, port, _ := net.SplitHostPort(held.Addr().String())
		free, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", port))
		if err != nil {
			t.Skipf("127.0.0.1:%s is in use as well (%v); the outcome would show nothing", port, err)
		}
		free.Close()

		started, stderr := startWebCLI(t, bin, "--bind", "127.0.0.1", "--port", port)
		if want := "Ferret Scan Web UI started on 127.0.0.1:" + port; started != want {
			t.Fatalf("startup line %q, want %q: the port probe answered for another address than the "+
				"server binds; stderr:\n%s", started, want, stderr.String())
		}
		if strings.Contains(stderr.String(), "is not available") {
			t.Errorf("the CLI reported port %s taken, though only [::1]:%s was: %s", port, port, stderr.String())
		}
		req, _ := http.NewRequest(http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", port)+"/health", nil)
		if code := getStatus(t, req); code != http.StatusOK {
			t.Errorf("GET /health on 127.0.0.1:%s: HTTP %d", port, code)
		}
	})

	t.Run("--bind ::1 serves the IPv6 loopback", func(t *testing.T) {
		probe, err := net.Listen("tcp", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback here: %v", err)
		}
		_, port, _ := net.SplitHostPort(probe.Addr().String())
		probe.Close()

		started, stderr := startWebCLI(t, bin, "--bind", "::1", "--port", port)
		if !strings.HasSuffix(started, ":"+port) {
			t.Fatalf("startup line %q does not name port %s; stderr:\n%s", started, port, stderr.String())
		}
		base := "http://" + net.JoinHostPort("::1", port)
		req, _ := http.NewRequest(http.MethodGet, base+"/health", nil)
		if code := getStatus(t, req); code != http.StatusOK {
			t.Fatalf("GET /health on [::1]:%s: HTTP %d", port, code)
		}
		// A POST the UI makes from that page carries its Origin, which the Origin check must accept.
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("files", "note.txt")
		_, _ = fw.Write([]byte("nothing sensitive here\n"))
		_ = mw.Close()
		post, _ := http.NewRequest(http.MethodPost, base+"/scan", &body)
		post.Header.Set("Content-Type", mw.FormDataContentType())
		post.Header.Set("Origin", base)
		if code := getStatus(t, post); code != http.StatusOK {
			t.Errorf("POST /scan from Origin %s: HTTP %d, want 200", base, code)
		}
	})
}
