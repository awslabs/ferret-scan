// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package gitlabsast

import (
	"regexp"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// #381, the two gitlab-sast halves.
//
// (a) The description is rendered as MARKDOWN in the GitLab UI. JSON encoding escapes a raw
// ESC to  on the wire, so this is not JSON structural injection — but the UI decodes
// it back before rendering, so the bytes arrive. Measured on the CLI, the decoded
// description carried ESC=2 and the injected text as its own markdown line.
//
// (b) The code fences were hardcoded to three backticks. CommonMark §4.5 closes a fenced
// block at the first run of AT LEAST the opening length, so any three-backtick line inside
// the content closes it early.

// TestTheDescriptionCarriesNoBorrowedControlBytes covers (a).
func TestTheDescriptionCarriesNoBorrowedControlBytes(t *testing.T) {
	payloads := []string{
		"quarterly-report.txt\x1b[2K\r",
		"ok.txt\n\nNo sensitive information found. Scan complete: 0 findings.",
		"evil\x1b[31mRED\x1b[0m.txt",
	}
	s := NewDataSanitizer()
	for _, payload := range payloads {
		t.Run(strings.SplitN(payload, "\x1b", 2)[0], func(t *testing.T) {
			desc := s.SanitizeDescription(detector.Match{
				Text:       "449-87-4100",
				LineNumber: 1,
				Type:       "SSN",
				Confidence: 100,
				Filename:   payload,
				Validator:  "ssn",
				Context:    detector.ContextInfo{FullLine: "SSN: 449-87-4100"},
			}, false)

			// Non-vacuity: the description must actually mention the file.
			if !strings.Contains(desc, "**Location:**") {
				t.Fatalf("no Location line, so nothing here is tested:\n%s", desc)
			}
			// The sanitizer writes its own \n between sections; anything else is borrowed.
			for i := 0; i < len(desc); i++ {
				if c := desc[i]; c != '\n' && (c < 0x20 || c == 0x7F) {
					t.Fatalf("byte 0x%02x at offset %d is a borrowed control byte reaching the "+
						"GitLab markdown renderer.\nsurrounding: %q",
						c, i, desc[maxI(0, i-40):minI(len(desc), i+20)])
				}
			}
			// And the fabricated sentence must not stand as its own markdown line.
			for _, line := range strings.Split(desc, "\n") {
				if strings.TrimSpace(line) == "No sensitive information found. Scan complete: 0 findings." {
					t.Errorf("the filename fabricated a markdown line:\n%s", desc)
				}
			}
		})
	}
}

// TestTheFenceOutrunsAnInjectedFence covers (b), at the level that matters: whether a
// CommonMark parser keeps the matched value inside one code block.
//
// The odd and even cases are BOTH asserted, because they fail differently and only one of
// them is obvious. An odd number of injected fences leaves the closing fence acting as an
// opener, so everything after it — including the Remediation section — is swallowed into an
// unclosed block. An even number re-pairs into balanced blocks, which looks fine and is not:
// the content between them renders as ordinary prose outside any code block.
func TestTheFenceOutrunsAnInjectedFence(t *testing.T) {
	cases := []struct {
		name  string
		value string
	}{
		{
			name:  "one injected fence (odd)",
			value: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n```\n-----END RSA PRIVATE KEY-----",
		},
		{
			name:  "two injected fences (even)",
			value: "-----BEGIN RSA PRIVATE KEY-----\n```\nMIIEowIBAAKCAQEA\n```\n-----END RSA PRIVATE KEY-----",
		},
		{
			name:  "a longer injected run",
			value: "-----BEGIN RSA PRIVATE KEY-----\n``````\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----",
		},
	}

	s := NewDataSanitizer()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// SSH_PRIVATE_KEY is the real multi-line case: Context.FullLine is empty for a
			// match that spans lines, so --show-match falls back to Match.Text.
			desc := s.SanitizeDescription(detector.Match{
				Text:       tc.value,
				LineNumber: 1,
				Type:       "SECRETS",
				Confidence: 95,
				Filename:   "key.txt",
				Validator:  "secrets",
			}, true)

			if !strings.Contains(desc, "**Matched value:**") {
				t.Fatalf("no Matched value block, so the fence is untested:\n%s", desc)
			}

			blocks := parseFenced(desc)
			for _, b := range blocks {
				if b.unclosed {
					t.Errorf("an UNCLOSED code block swallows everything after it:\n%s", desc)
				}
			}
			// The whole value must sit inside ONE code block.
			intact := false
			for _, b := range blocks {
				if b.code && strings.Contains(b.body, "BEGIN RSA PRIVATE KEY") &&
					strings.Contains(b.body, "MIIEowIBAAKCAQEA") {
					intact = true
				}
			}
			if !intact {
				t.Errorf("the matched value is split across blocks or leaked outside one:\n%s", desc)
			}
			// Nothing from the value may render as prose.
			for _, b := range blocks {
				if !b.code && strings.Contains(b.body, "RSA PRIVATE KEY") {
					t.Errorf("part of the key renders as prose outside a code block:\n%s", desc)
				}
			}
			// Remediation must still render normally.
			if !strings.Contains(desc, "**Remediation:**") {
				t.Errorf("the Remediation section is missing:\n%s", desc)
			}
		})
	}
}

// TestAnOrdinaryValueStillGetsAThreeBacktickFence: the fix must not widen every fence, or
// every existing report changes for no reason.
func TestAnOrdinaryValueStillGetsAThreeBacktickFence(t *testing.T) {
	desc := NewDataSanitizer().SanitizeDescription(detector.Match{
		Text:       "449-87-4100",
		LineNumber: 1,
		Type:       "SSN",
		Confidence: 100,
		Filename:   "a.txt",
		Validator:  "ssn",
		Context:    detector.ContextInfo{FullLine: "SSN: 449-87-4100"},
	}, true)

	if !strings.Contains(desc, "\n```\n") {
		t.Errorf("an ordinary value no longer uses a plain three-backtick fence:\n%s", desc)
	}
	if strings.Contains(desc, "````") {
		t.Errorf("an ordinary value was given a wider fence than it needs:\n%s", desc)
	}
}

// --- a minimal CommonMark fenced-block parser, for the assertions above ---

type fencedBlock struct {
	code     bool
	unclosed bool
	body     string
}

var fenceOpen = regexp.MustCompile("^\\s*(`{3,})\\s*\\S*\\s*$")

// parseFenced implements the one CommonMark rule this test depends on (§4.5): a fence of N
// backticks is closed only by a later line that is a run of at least N.
//
// Written out rather than counting fence lines, because counting is the wrong metric and
// gave the wrong answer while I was measuring this: a three-line-fence description reads
// "unbalanced" by count even when the outer fences are four backticks and correct.
func parseFenced(md string) []fencedBlock {
	lines := strings.Split(md, "\n")
	var out []fencedBlock
	var prose []string

	flushProse := func() {
		if len(prose) > 0 {
			out = append(out, fencedBlock{body: strings.Join(prose, "\n")})
			prose = nil
		}
	}

	for i := 0; i < len(lines); {
		m := fenceOpen.FindStringSubmatch(lines[i])
		if m == nil {
			prose = append(prose, lines[i])
			i++
			continue
		}
		flushProse()
		n := len(m[1])
		closer := regexp.MustCompile("^\\s*`{" + itoa(n) + ",}\\s*$")
		i++
		var body []string
		closed := false
		for i < len(lines) {
			if closer.MatchString(lines[i]) {
				closed = true
				i++
				break
			}
			body = append(body, lines[i])
			i++
		}
		out = append(out, fencedBlock{code: closed, unclosed: !closed, body: strings.Join(body, "\n")})
	}
	flushProse()
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// TestParseFencedActuallyDetectsTheDefect is the harness's non-vacuity check.
//
// If parseFenced treated every fence line as a pair, the assertions above would pass on the
// unfixed sanitizer. These two inputs are the before and after.
func TestParseFencedActuallyDetectsTheDefect(t *testing.T) {
	broken := "**Matched value:**\n```\nkey\n```\nEND\n```\n\n**Remediation:**\ndo this"
	blocks := parseFenced(broken)
	sawUnclosed := false
	for _, b := range blocks {
		if b.unclosed && strings.Contains(b.body, "Remediation") {
			sawUnclosed = true
		}
	}
	if !sawUnclosed {
		t.Error("parseFenced did not detect that a three-backtick fence around content " +
			"containing a three-backtick line swallows the Remediation section. With this " +
			"harness inert, every fence test here would pass on the unfixed sanitizer.")
	}

	fixed := "**Matched value:**\n````\nkey\n```\nEND\n````\n\n**Remediation:**\ndo this"
	for _, b := range parseFenced(fixed) {
		if b.unclosed {
			t.Errorf("parseFenced reported an unclosed block for correctly fenced input: %+v", b)
		}
	}
}

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minI(a, b int) int {
	if a < b {
		return a
	}
	return b
}
