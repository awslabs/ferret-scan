// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
)

// TestQueryParamRedactionSink checks the sink for an OAuth implicit-flow redirect. Each
// token-keyed parameter must be redacted: trimming one value at `&` once left the next,
// same-keyword parameter in cleartext, which a candidate-level test alone does not show.
func TestQueryParamRedactionSink(t *testing.T) {
	const (
		access  = "Qw7Er4Ty1Ui8Op5As2Df"
		refresh = "Zx9Cv6Bn3Mq0Wp7Lk4Jh"
	)
	dir := t.TempDir()
	path := filepath.Join(dir, "redirect.txt")
	line := "redirect: https://app.example/cb#access_token=" + access + "&refresh_token=" + refresh + "&expires_in=3600\n"
	if err := os.WriteFile(path, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}

	outDir := filepath.Join(dir, "redacted")
	res, err := core.RedactFile(core.RedactConfig{
		FilePath:  path,
		OutputDir: outDir,
		Strategy:  "simple",
		Checks:    []string{"SECRETS"},
		Config:    config.LoadConfigOrDefault(""),
		LogWriter: io.Discard,
	})
	if err != nil {
		t.Fatalf("RedactFile: %v", err)
	}
	redacted := res.RedactedFilePath
	if redacted == "" {
		redacted = findRedactedArtifact(t, outDir)
	}
	if redacted == "" {
		t.Fatalf("no redacted artifact under %s (%d findings)", outDir, len(res.Matches))
	}
	body, err := os.ReadFile(redacted)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{"access_token": access, "refresh_token": refresh} {
		if strings.Contains(string(body), v) {
			t.Errorf("%s value survives in the redacted output", name)
		}
	}
}
