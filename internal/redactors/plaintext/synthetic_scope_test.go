// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plaintext

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// #886 case A: record.txt. Synthetic values: SSN 234-56-0001, example.org.
const recordTxt = "SSN: 234-56-0001\n" +
	"Confirmed again SSN: 234-56-0001\n" +
	"Twice on one line: SSN 234-56-0001 and SSN 234-56-0001\n" +
	"Contact dana.whitfield@example.org or dana.whitfield@example.org\n"

// recordMatches reports every occurrence, as the validators do.
func recordMatches() []detector.Match {
	var ms []detector.Match
	for i, line := range strings.Split(strings.TrimSuffix(recordTxt, "\n"), "\n") {
		for _, v := range []struct{ text, typ string }{{"234-56-0001", "SSN"}, {"dana.whitfield@example.org", "BUSINESS"}} {
			for off := 0; ; {
				at := strings.Index(line[off:], v.text)
				if at < 0 {
					break
				}
				ms = append(ms, detector.Match{Text: v.text, Type: v.typ, Confidence: 90, LineNumber: i + 1,
					Context: detector.ContextInfo{FullLine: line}})
				off += at + len(v.text)
			}
		}
	}
	return ms
}

var (
	ssnRE   = regexp.MustCompile(`\d{3}-\d{2}-\d{4}`)
	emailRE = regexp.MustCompile(`[a-z0-9]+@example\.com`)
)

func distinct(re *regexp.Regexp, s string) map[string]bool {
	out := map[string]bool{}
	for _, v := range re.FindAllString(s, -1) {
		out[v] = true
	}
	return out
}

// One call of RedactString is one invocation: one replacement per value within it, and a fresh draw in
// the next call -- the lifetime --stdin, pkg/scan.RedactText and each pkg/redact Request get.
func TestRedactStringGivesAValueOneReplacementPerCall(t *testing.T) {
	ms := recordMatches()
	if len(ms) != 6 {
		t.Fatalf("fixture: %d matches, want 6", len(ms))
	}
	ptr := NewPlainTextRedactor(nil, nil)
	ptr.SetPositionCorrelationEnabled(false) // as --stdin and pkg/redact run it
	firsts := map[string]bool{}
	for call := 0; call < 20; call++ {
		out, _, err := ptr.RedactString(recordTxt, ms, redactors.RedactionSynthetic)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(out, "234-56-0001") || strings.Contains(out, "dana.whitfield") {
			t.Fatalf("a value survived:\n%s", out)
		}
		ssns, emails := distinct(ssnRE, out), distinct(emailRE, out)
		if len(ssns) != 1 || len(emails) != 1 || len(ssnRE.FindAllString(out, -1)) != 4 || len(emailRE.FindAllString(out, -1)) != 2 {
			t.Fatalf("call %d wrote %d SSN and %d email replacements for one SSN x4 and one email x2:\n%s",
				call, len(ssns), len(emails), out)
		}
		for v := range ssns {
			firsts[v] = true
		}
	}
	if len(firsts) < 2 {
		t.Errorf("20 calls drew %d distinct replacements: each call must draw afresh", len(firsts))
	}
}

// The completeness sweep writes the replacement the positional pass wrote: a value reported once but
// present three times reads as one value.
func TestTheSweepWritesTheSameReplacement(t *testing.T) {
	content := "SSN 234-56-0001\nagain 234-56-0001 and 234-56-0001\n"
	ms := []detector.Match{{Text: "234-56-0001", Type: "SSN", Confidence: 95, LineNumber: 1,
		Context: detector.ContextInfo{FullLine: "SSN 234-56-0001"}}}
	out, _, err := NewPlainTextRedactor(nil, nil).RedactString(content, ms, redactors.RedactionSynthetic)
	if err != nil {
		t.Fatal(err)
	}
	if got := distinct(ssnRE, out); len(got) != 1 || len(ssnRE.FindAllString(out, -1)) != 3 {
		t.Fatalf("one SSN in three places became %v:\n%s", got, out)
	}
}

// RedactDocument draws from the redactor's scope, so two files redacted by one redactor -- one
// RedactionManager -- give a value one replacement.
func TestRedactDocumentSharesTheScopeAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	ptr := NewPlainTextRedactor(nil, nil)
	ptr.SetSyntheticScope(redactors.NewSyntheticScope())
	var outs []string
	for _, name := range []string{"a.txt", "b.txt"} {
		in := filepath.Join(dir, name)
		if err := os.WriteFile(in, []byte(recordTxt), 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(dir, "out-"+name)
		if _, err := ptr.RedactDocument(in, out, recordMatches(), redactors.RedactionSynthetic); err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		outs = append(outs, string(b))
	}
	if outs[0] != outs[1] {
		t.Errorf("one content in two files of one run was redacted differently:\n%s\n---\n%s", outs[0], outs[1])
	}
}

// No scope, no synthetic: the file is refused, nothing is written, and the placeholder that used to be
// substituted for a failed draw is not.
func TestRedactDocumentWithoutAScopeRefusesSynthetic(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte(recordTxt), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewPlainTextRedactor(nil, nil).RedactDocument(in, out, recordMatches(), redactors.RedactionSynthetic)
	if !errors.Is(err, redactors.ErrNoSyntheticScope) {
		t.Fatalf("err = %v, want ErrNoSyntheticScope", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("an output was written: %v", statErr)
	}
	// The masking strategies need no scope.
	if _, err := NewPlainTextRedactor(nil, nil).RedactDocument(in, out, recordMatches(), redactors.RedactionFormatPreserving); err != nil {
		t.Errorf("format_preserving without a scope: %v", err)
	}
}

// exhaustedScope refuses every value, as a real scope does when a family has no replacement left.
type exhaustedScope struct{}

func (exhaustedScope) Resolve(family, _ string, _ bool, _ redactors.SyntheticDraw) (string, error) {
	return "", errors.Join(redactors.ErrSyntheticSpaceExhausted, errors.New(family))
}

// One-to-one or refuse: an exhausted family refuses the file, with no output, no reused replacement and
// no simple placeholder, and the error names no value.
func TestAnExhaustedFamilyRefusesTheFile(t *testing.T) {
	dir := t.TempDir()
	in, out := filepath.Join(dir, "in.txt"), filepath.Join(dir, "out.txt")
	if err := os.WriteFile(in, []byte(recordTxt), 0o600); err != nil {
		t.Fatal(err)
	}
	ptr := NewPlainTextRedactor(nil, nil)
	ptr.SetSyntheticScope(exhaustedScope{})
	_, err := ptr.RedactDocument(in, out, recordMatches(), redactors.RedactionSynthetic)
	if !errors.Is(err, redactors.ErrSyntheticSpaceExhausted) {
		t.Fatalf("err = %v, want ErrSyntheticSpaceExhausted", err)
	}
	if strings.Contains(err.Error(), "234-56-0001") || strings.Contains(err.Error(), "dana.whitfield") {
		t.Errorf("the refusal names a value: %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Errorf("an output was written for a refused file: %v", statErr)
	}
	if _, _, err := ptr.RedactString(recordTxt, recordMatches(), redactors.RedactionSimple); err != nil {
		t.Errorf("simple reads no scope: %v", err)
	}
}
