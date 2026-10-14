// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// scripts/go-version.sh resolves the digest behind golang:<version>-alpine so that `make
// sync-go-version` can rewrite the Dockerfile's load-bearing @sha256 pin and `make check-go-version`
// can compare the pin with the registry. Its docker branch was
//
//	docker buildx imagetools inspect "$ref" | awk '/Digest:/ {print $2; exit}' && return 0
//
// under `set -o pipefail`. awk exits on the first Digest: line, which closes the pipe before docker
// has finished writing the manifest list that follows; docker then dies on the write, pipefail marks
// the pipeline failed, and the branch has already PRINTED the digest but does not return. The HTTP
// fallback prints it again. Observed on `main` with docker present and crane absent:
//
//   - `check` saw two lines in $actual and reported the pinned digest as drifted against a registry
//     that was serving exactly that digest.
//   - `update` fed the two lines into sed's replacement, sed failed on the embedded newline
//     ("unterminated `s' command"), set -e aborted the script, and the Dockerfile kept its old digest
//     while .gitlab-ci.yml was never reached.
//
// The test reproduces the write-after-exit with fake tools on PATH: crane refuses, docker streams the
// digest line, pauses, then writes the rest; curl and jq stand in for the registry so the fallback
// answers the same digest. Each case runs the real script against a scratch repository root.
func TestGoVersionScriptResolvesTheBuilderDigestExactlyOnce(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("drives a bash script; contributors run it from a POSIX shell")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "go-version.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatalf("script not found: %v", err)
	}

	const (
		version  = "1.27.2"
		registry = "public.ecr.aws/docker/library/golang"
		// What the fake registry answers for golang:1.27.2-alpine, through docker and through HTTP.
		served = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
		// A pin that predates `served`, for the update case.
		stale = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	)
	fromLine := regexp.MustCompile(`(?m)^FROM ` + regexp.QuoteMeta(registry) + `:` + regexp.QuoteMeta(version) + `-alpine@(sha256:[a-f0-9]{64}) AS builder$`)

	fakes := t.TempDir()
	writeTool := func(name, body string) {
		if err := os.WriteFile(filepath.Join(fakes, name), []byte("#!/bin/bash\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// crane is preferred when present; refuse so the docker branch is what gets exercised.
	writeTool("crane", "exit 1\n")
	// docker: `info` and `manifest inspect` succeed; `buildx imagetools inspect` writes the header,
	// waits for the reader to act on the Digest: line, then writes the manifest list -- the shape
	// of the real output.
	writeTool("docker", `case "$1 $2" in
  "info ") exit 0 ;;
  "manifest inspect") exit 0 ;;
  "buildx imagetools")
    [ "$3" = inspect ] || exit 1
    printf 'Name:      %s\nMediaType: application/vnd.oci.image.index.v1+json\nDigest:    %s\n' "$4" "`+served+`"
    sleep 0.3
    printf '           \nManifests:\n  Name:      %s@sha256:3333333333333333333333333333333333333333333333333333333333333333\n  MediaType: application/vnd.oci.image.manifest.v1+json\n  Platform:  linux/amd64\n' "$4"
    exit 0 ;;
  *) exit 1 ;;
esac
`)
	// curl: the anonymous-token request gets a token, the manifest HEAD gets the digest header.
	writeTool("curl", `for a in "$@"; do case "$a" in *"/token/"*) echo '{"token":"t"}'; exit 0 ;; esac; done
for a in "$@"; do case "$a" in -sfI) printf 'Docker-Content-Digest: %s\r\n' "`+served+`"; exit 0 ;; esac; done
exit 1
`)
	writeTool("jq", "echo t\n")

	run := func(t *testing.T, dir string, args ...string) (string, int) {
		t.Helper()
		cmd := exec.Command(script, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+fakes+string(os.PathListSeparator)+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		code := 0
		if err != nil {
			ee, ok := err.(*exec.ExitError)
			if !ok {
				t.Fatalf("running %s %v: %v\n%s", script, args, err, out)
			}
			code = ee.ExitCode()
		}
		return string(out), code
	}
	seed := func(t *testing.T, pinned string) string {
		t.Helper()
		dir := t.TempDir()
		// Every file the script reads, so the only thing that varies between runs is the digest.
		files := map[string]string{
			".go-version": version + "\n",
			"go.mod":      "module example.com/scratch\n\ngo 1.27\n",
			".gitlab-ci.yml": "variables:\n  GO_VERSION: \"" + version + "\"\n" +
				"  GO_DOCKER_IMAGE: \"golang:" + version + "-alpine\"\n",
			".github/workflows/ci.yml": "jobs:\n  go:\n    steps:\n      - uses: actions/setup-go@v7\n" +
				"        with:\n          go-version-file: '.go-version'\n",
			"Dockerfile": "# crane digest " + registry + ":" + version + "-alpine\n" +
				"FROM " + registry + ":" + version + "-alpine@" + pinned + " AS builder\n" +
				"FROM scratch\n",
		}
		for name, body := range files {
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}

	t.Run("check accepts a pin the registry still serves", func(t *testing.T) {
		dir := seed(t, served)
		out, code := run(t, dir, "check")
		if code != 0 {
			t.Errorf("exit %d, want 0:\n%s", code, out)
		}
		if !strings.Contains(out, "matches registry") {
			t.Errorf("the digest verdict is missing:\n%s", out)
		}
		if strings.Contains(out, "registry now serves") {
			t.Errorf("a pin equal to the served digest was reported as drift:\n%s", out)
		}
	})

	t.Run("update rewrites a stale pin to the served digest", func(t *testing.T) {
		dir := seed(t, stale)
		out, code := run(t, dir, "update")
		if code != 0 {
			t.Errorf("exit %d, want 0:\n%s", code, out)
		}
		if strings.Contains(out, "unterminated") {
			t.Errorf("sed received a multi-line digest:\n%s", out)
		}
		dockerfile, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
		if err != nil {
			t.Fatal(err)
		}
		m := fromLine.FindSubmatch(dockerfile)
		if m == nil {
			t.Fatalf("FROM line not found or malformed after update:\n%s", dockerfile)
		}
		if got := string(m[1]); got != served {
			t.Errorf("Dockerfile digest after update = %s, want %s\n%s", got, served, out)
		}
		if _, err := os.Stat(filepath.Join(dir, "Dockerfile.bak")); err == nil {
			t.Error("Dockerfile.bak was left behind")
		}
	})
}
