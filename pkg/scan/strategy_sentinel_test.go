// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/olefixture"
)

// #863's library box: a format that refuses the requested strategy (legacy .doc takes simple and
// format_preserving, not synthetic) is told apart from every other redaction failure by
// errors.Is(err, ErrStrategyNotSupported), not by reading the message. The message itself is the
// one the CLI and existing callers read, so it is pinned too.
func TestRedactFileRefusalWrapsErrStrategyNotSupported(t *testing.T) {
	const email, card = "jane.doe@example.com", "4123456789012349"
	dir := t.TempDir()
	src := filepath.Join(dir, "w.doc")
	if err := os.WriteFile(src, olefixture.LegacyDoc("Email "+email+"\rCard "+card+"\r", nil), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := func(s RedactStrategy) RedactFileOptions {
		return RedactFileOptions{
			OutputDir: filepath.Join(dir, "out-"+s.String()), Strategy: s,
			Checks: []string{"EMAIL", "CREDIT_CARD"}, DisableConfigDiscovery: true,
		}
	}

	res, err := RedactFile(src, opts(StrategySynthetic))
	if err == nil {
		t.Fatalf("synthetic on .doc returned %+v with no error; want a refusal", res)
	}
	if !errors.Is(err, ErrStrategyNotSupported) {
		t.Errorf("errors.Is(err, ErrStrategyNotSupported) = false for the refusal: %v", err)
	}
	if errors.Is(err, ErrIncomplete) {
		t.Errorf("a refusal is not an incomplete scan, but errors.Is(err, ErrIncomplete): %v", err)
	}
	// The text is unchanged: the same "could not redact <path>: <refusal>" callers already read.
	want := "could not redact " + src + ": redaction strategy not supported for this file type: "
	if !strings.HasPrefix(err.Error(), want) || !strings.Contains(err.Error(), "not synthetic") {
		t.Errorf("refusal text changed:\n got %q\nwant prefix %q, naming synthetic", err.Error(), want)
	}
	if res != nil {
		t.Errorf("a refused file returned a result: %+v", res)
	}

	// Controls: the strategies .doc declares still redact, with no error at all.
	for _, s := range []RedactStrategy{StrategySimple, StrategyFormatPreserving} {
		if r, err := RedactFile(src, opts(s)); err != nil || r == nil || r.RedactionCount == 0 {
			t.Errorf("%v: result %+v, err %v; want a redacted copy", s, r, err)
		}
	}

	// Another failure is not a refusal: a ctx done before the scan is ErrIncomplete only.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = RedactFileContext(ctx, src, opts(StrategySynthetic))
	if err == nil || !errors.Is(err, ErrIncomplete) || errors.Is(err, ErrStrategyNotSupported) {
		t.Errorf("cancelled ctx: err = %v; want ErrIncomplete and not ErrStrategyNotSupported", err)
	}
}
