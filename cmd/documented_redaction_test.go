// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// The guard for a documented redaction capability the build does not have.
//
// #686: `--help` advertised
//
//	ferret-scan --file *.pdf --enable-redaction --redaction-output-dir ./safe-docs
//
// a command that can never succeed. PDF content redaction is not implemented, and refusing is
// correct — a "redacted" PDF still holding the values would be worse than no output. But the help
// text presented it as a supported workflow, so a user followed the example, got one refusal per
// file, and had to work out whether they had hit a bug, a permissions problem, or a limitation.
//
// It was not one bad line. The same false claim sat in README.md (".pdf→.pdf"),
// docs/ferret-application-flow.md (an example command, a sequence-diagram note and a feature list)
// and docs/architecture-diagram.md (a node label, a class assignment and a prose paragraph promising
// "four different redactor types (text, PDF, Office, image)").
//
// And PDF is not the only case. The image redactor declares EIGHT extensions and implements JPEG and
// PNG only, so .gif, .tiff, .tif, .bmp and .webp are registered and always refuse. Measured with the
// real binary: a .tiff carrying an ImageDescription reports its finding and writes zero artifacts,
// while .jpg and .png each write one.
//
// This is the same class as cmd/documented_flags_test.go — a documented capability that does not
// exist — so it is a sibling of that family and follows its idiom, including a planted-shape control.
// What is different is the source of truth: flags are read from their registrations, and redaction
// capability is read from the live redactor registry via core.RedactionCapabilities. Nothing here is
// a hand-kept list, which is the only reason it can catch the NEXT such claim.

// redactionDocRoots are the documentation files a redaction claim can hide in.
var redactionDocRoots = []string{"../docs", "../README.md"}

// goDocRoots are the packages whose DOC COMMENTS also make capability claims to a reader.
//
// A third documentation surface, and it had the same defect: pkg/scan/redactfile.go promised "a
// redacted .docx stays a .docx, a .pdf stays a .pdf" in the doc comment of the public RedactFile API,
// where a consumer of the library reads it instead of the CLI help. Only the exported surface is
// walked — internal packages describe their own refusals at length, including the reasons this guard
// quotes, and reading those as claims would make the guard fight its own explanations.
var goDocRoots = []string{"../pkg"}

// ferretRedactionCommand finds a `ferret-scan` invocation that enables redaction and captures the
// whole command line.
//
// The leading `^\s*` matters: commands in documentation are nearly always inside a fenced block and
// indented, and anchoring on a bare `^` silently matches nothing — the same mistake the invocation
// guard's own comment records catching with its control test.
var ferretRedactionCommand = regexp.MustCompile(`(?m)^\s*(?:\$\s*)?(?:cat .*\|\s*)?ferret-scan\s+([^\n]*--enable-redaction[^\n]*)`)

// fileArgExtensions pulls the file types out of a command's --file / -f argument.
var fileArg = regexp.MustCompile(`--?file[=\s]+("[^"]+"|'[^']+'|\S+)`)

func capabilitiesForTest(t *testing.T) redactors.Capabilities {
	t.Helper()
	caps, err := core.RedactionCapabilities(t.TempDir())
	if err != nil {
		t.Fatalf("reading the redaction capability set: %v", err)
	}
	if len(caps.Redactable) == 0 || len(caps.Unimplemented) == 0 {
		t.Fatalf("the capability set is empty (%d redactable, %d unimplemented); every assertion "+
			"below would pass vacuously", len(caps.Redactable), len(caps.Unimplemented))
	}
	return caps
}

// extensionsIn returns the distinct file extensions named by a command's --file argument.
//
// A glob is handled by taking its extension: `--file *.pdf` names .pdf as surely as `--file a.pdf`
// does, and the glob form is what #686 actually shipped.
func extensionsIn(command string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range fileArg.FindAllStringSubmatch(command, -1) {
		arg := strings.Trim(m[1], `"'`)
		ext := strings.ToLower(filepath.Ext(arg))
		// A directory, `.`, or a bare name carries no type claim.
		if ext == "" || ext == "." {
			continue
		}
		if !seen[ext] {
			seen[ext] = true
			out = append(out, ext)
		}
	}
	sort.Strings(out)
	return out
}

// documentedRedactionCommands returns every redaction command found in the documentation, with the
// file and line it came from.
func documentedRedactionCommands(t *testing.T) []struct {
	Where   string
	Command string
} {
	t.Helper()
	var found []struct {
		Where   string
		Command string
	}
	consider := func(path string) {
		data, err := os.ReadFile(path) // #nosec G304 -- paths come from the repository walk below
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(data)
		for _, m := range ferretRedactionCommand.FindAllStringSubmatchIndex(text, -1) {
			line := 1 + strings.Count(text[:m[0]], "\n")
			found = append(found, struct {
				Where   string
				Command string
			}{
				Where:   path + ":" + itoa(line),
				Command: strings.TrimSpace(text[m[2]:m[3]]),
			})
		}
	}
	for _, root := range redactionDocRoots {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatalf("stat %s: %v", root, err)
		}
		if !info.IsDir() {
			consider(root)
			continue
		}
		err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if strings.EqualFold(filepath.Ext(path), ".md") {
				consider(path)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	return found
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestNoDocumentedRedactionCommandNamesAnUnredactableType is the #686 case.
func TestNoDocumentedRedactionCommandNamesAnUnredactableType(t *testing.T) {
	caps := capabilitiesForTest(t)
	commands := documentedRedactionCommands(t)

	// Non-vacuity: the documentation DOES show redaction commands, and if the regex stops matching
	// them this test would pass while checking nothing.
	if len(commands) == 0 {
		t.Fatalf("no `ferret-scan ... --enable-redaction` command found across %v. Either the "+
			"documentation stopped showing one or the pattern stopped matching; both make this "+
			"guard vacuous", redactionDocRoots)
	}

	var bad []string
	typed := 0
	for _, c := range commands {
		for _, ext := range extensionsIn(c.Command) {
			typed++
			if reason := caps.ReasonUnimplemented(ext); reason != "" {
				bad = append(bad, c.Where+"\n      "+c.Command+"\n      "+ext+" cannot be redacted: "+reason)
			}
		}
	}
	if typed == 0 {
		t.Errorf("%d redaction command(s) found but not one names a file TYPE, so nothing was "+
			"checked. A command like `--file report.docx` is what carries the claim; if every "+
			"example now uses a directory, this guard has nothing to assert and the extension "+
			"parser should be re-checked against the real examples", len(commands))
	}
	if len(bad) > 0 {
		t.Errorf("%d documented redaction command(s) name a type this build cannot redact:\n    %s\n\n"+
			"Detection and redaction are different capabilities: these types ARE scanned and their "+
			"findings ARE reported, but no redacted copy is written. Documenting the command as a "+
			"redaction workflow sends a user to debug a limitation.\nFix the example, or implement "+
			"the type and remove it from the redactor's UnimplementedTypes declaration.\n"+
			"The supported set is generated into docs/redaction-support.md.",
			len(bad), strings.Join(bad, "\n    "))
	}
	t.Logf("checked %d redaction command(s), %d type claim(s)", len(commands), typed)
}

// TestTheHelpTextAdvertisesNoUnredactableType checks the BINARY's own help output.
//
// Separate from the documentation walk because the help text is not a .md file and is the thing a
// user reads first — it is where #686 actually was. Driven through the built binary rather than by
// calling the help package, because what matters is what the shipped program prints.
func TestTheHelpTextAdvertisesNoUnredactableType(t *testing.T) {
	caps := capabilitiesForTest(t)
	bin := buildScanner(t)

	out, err := exec.Command(bin, "--help").CombinedOutput() // #nosec G204 -- bin is built by the test
	if err != nil {
		t.Fatalf("--help failed: %v\n%s", err, out)
	}
	help := string(out)
	if !strings.Contains(help, "--enable-redaction") {
		t.Fatalf("the help text does not mention --enable-redaction at all; this guard would pass " +
			"vacuously")
	}

	var bad []string
	checked := 0
	for _, m := range ferretRedactionCommand.FindAllStringSubmatch(help, -1) {
		for _, ext := range extensionsIn(m[1]) {
			checked++
			if reason := caps.ReasonUnimplemented(ext); reason != "" {
				bad = append(bad, strings.TrimSpace(m[1])+"  ["+ext+": "+reason+"]")
			}
		}
	}
	if checked == 0 {
		t.Errorf("the help text shows redaction examples but none names a file type, so nothing " +
			"was checked. #686 was exactly such an example (`--file *.pdf`), so losing the ability " +
			"to see one is losing the guard")
	}
	if len(bad) > 0 {
		t.Errorf("--help advertises redaction for %d type(s) this build cannot redact:\n  %s\n\n"+
			"internal/help/help.go is the source. Use a type from docs/redaction-support.md.",
			len(bad), strings.Join(bad, "\n  "))
	}
	t.Logf("checked %d help redaction example(s), %d type claim(s)", checked, checked)
}

// redactionVerb matches prose that CLAIMS redaction, as opposed to merely mentioning a format.
var redactionVerb = regexp.MustCompile(`(?i)\bredact(?:s|ed|ing|ion|or|ors)?\b`)

// redactionCaveat marks prose that has already been corrected to say the type cannot be rewritten.
//
// Deliberately generous, and evaluated over a PARAGRAPH rather than a line. The guard's job is to
// catch a NEW claim that a type can be redacted, not to police wording — and documentation wraps, so
// a line-scoped version of this check flagged four passages that were already correct: the caveat in
// docs/user-guides/README-Redaction.md sits on the line AFTER the one naming `.tiff`, and "produces
// **no redacted copy**" is a whole line away from "Only **JPEG and PNG** have an implementation".
// Reporting an accurate passage as a defect is how a guard gets switched off.
//
// `\bno\b[^.]{0,40}redact` is what admits "No PDF/Office redaction" — a caveat phrased as an absent
// feature rather than as a refusal.
var redactionCaveat = regexp.MustCompile(`(?i)cannot|can't|not implemented|not supported|unsupported|no redactor|refus|reports only|unredact|is not able|roadmap|\bno\b[^.]{0,40}redact|\bnot\b[^.]{0,40}redact|\bneither\b|\bnor\b[^.]{0,30}redact`)

// fencedBlock matches a Markdown fenced code block, including one indented inside a list.
//
// Code blocks are excluded from the PROSE guard because a command in one is the other guard's job,
// and because a configuration example is not a claim: docs/configuration.md's annotated `defaults:`
// block mentions both a redaction key and a `*.pdf` exclude pattern, which the prose rule read as
// "this document says PDFs can be redacted".
var fencedBlock = regexp.MustCompile("(?s)```.*?```")

// paragraphBreak matches a blank line, including the "empty" line of a Markdown blockquote (`>`),
// which is what separates paragraphs in the redaction guide where four of the false positives were.
var paragraphBreak = regexp.MustCompile(`^[\s>]*$`)

// paragraphsOf splits Markdown into paragraphs, returning each with the 1-based line it starts on.
func paragraphsOf(text string) []struct {
	Line int
	Body string
} {
	var out []struct {
		Line int
		Body string
	}
	var cur []string
	start := 1
	flush := func(end int) {
		if len(cur) > 0 {
			out = append(out, struct {
				Line int
				Body string
			}{Line: start, Body: strings.Join(cur, "\n")})
			cur = nil
		}
		start = end + 1
	}
	for i, line := range strings.Split(text, "\n") {
		if paragraphBreak.MatchString(line) {
			flush(i + 1)
			continue
		}
		if len(cur) == 0 {
			start = i + 1
		}
		cur = append(cur, line)
	}
	flush(0)
	return out
}

// TestNoProseClaimsRedactionForAnUnredactableType covers what a command-line guard cannot.
//
// Half of #686's false claims were not commands. They were prose and diagram labels — "4 Redactors:
// Text, PDF, Office, Image", "Multi-format document redaction (text, PDF, Office, images)",
// "supporting four different redactor types (text, PDF, Office, image)". A reader takes those as
// authoritative exactly as they take a command.
//
// The rule: a line that uses a redaction word AND names an unredactable type must also carry a
// caveat. That admits every corrected line in the tree and rejects a newly-added bare claim.
func TestNoProseClaimsRedactionForAnUnredactableType(t *testing.T) {
	caps := capabilitiesForTest(t)

	// The bare format names to look for, derived from the capability set so a newly-unimplemented
	// type is covered without editing this test.
	names := make([]string, 0, len(caps.Unimplemented))
	for ext := range caps.Unimplemented {
		names = append(names, strings.TrimPrefix(ext, "."))
	}
	sort.Strings(names)
	// Word-boundary match on the bare name, so "webp" does not match inside another word and ".tif"
	// does not fire on "certificate".
	nameRe := regexp.MustCompile(`(?i)\b(` + strings.Join(names, "|") + `)\b`)

	var bad []string
	lines := 0
	for _, root := range redactionDocRoots {
		info, err := os.Stat(root)
		if err != nil {
			t.Fatalf("stat %s: %v", root, err)
		}
		walk := func(path string) {
			data, err := os.ReadFile(path) // #nosec G304 -- repository paths only
			if err != nil {
				t.Fatalf("reading %s: %v", path, err)
			}
			text := string(data)
			lines += strings.Count(text, "\n") + 1
			// Blank the fences rather than deleting them, so reported line numbers stay true.
			text = fencedBlock.ReplaceAllStringFunc(text, func(block string) string {
				return strings.Repeat("\n", strings.Count(block, "\n"))
			})
			for _, para := range paragraphsOf(text) {
				if !redactionVerb.MatchString(para.Body) {
					continue
				}
				hit := nameRe.FindString(para.Body)
				if hit == "" || redactionCaveat.MatchString(para.Body) {
					continue
				}
				excerpt := strings.Join(strings.Fields(para.Body), " ")
				if len(excerpt) > 160 {
					excerpt = excerpt[:160] + "…"
				}
				bad = append(bad, path+":"+itoa(para.Line)+"  ["+strings.ToLower(hit)+"]  "+excerpt)
			}
		}
		if !info.IsDir() {
			walk(root)
			continue
		}
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.EqualFold(filepath.Ext(path), ".md") {
				walk(path)
			}
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if lines < 100 {
		t.Fatalf("only %d documentation lines were read; the walk is not finding the docs and this "+
			"guard is vacuous", lines)
	}
	if len(bad) > 0 {
		t.Errorf("%d documentation line(s) claim redaction while naming a type this build cannot "+
			"redact:\n  %s\n\nEither say that the type cannot be rewritten (any of \"cannot\", "+
			"\"not implemented\", \"no redactor\", \"reports only\" in the same line satisfies this "+
			"guard) or name a type from docs/redaction-support.md.\nDetection is not the issue — "+
			"these types are scanned and reported; only rewriting them is unimplemented.",
			len(bad), strings.Join(bad, "\n  "))
	}
	t.Logf("read %d documentation lines, %d unredactable type name(s) watched: %v", lines, len(names), names)
}

// TestNoPublicAPIDocCommentClaimsRedactionForAnUnredactableType covers the library surface.
//
// A caller of pkg/scan never sees --help or docs/. The doc comment on the exported function IS the
// documentation, and it carried the same false ".pdf stays a .pdf" promise. Comments only: a string
// literal naming ".pdf" is usually a type check or a test fixture, not a claim.
func TestNoPublicAPIDocCommentClaimsRedactionForAnUnredactableType(t *testing.T) {
	caps := capabilitiesForTest(t)
	names := make([]string, 0, len(caps.Unimplemented))
	for ext := range caps.Unimplemented {
		names = append(names, strings.TrimPrefix(ext, "."))
	}
	sort.Strings(names)
	nameRe := regexp.MustCompile(`(?i)\b(` + strings.Join(names, "|") + `)\b`)

	var bad []string
	comments := 0
	for _, root := range goDocRoots {
		if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			data, rerr := os.ReadFile(path) // #nosec G304 -- repository paths only
			if rerr != nil {
				return rerr
			}
			for i, line := range strings.Split(string(data), "\n") {
				trimmed := strings.TrimSpace(line)
				if !strings.HasPrefix(trimmed, "//") {
					continue
				}
				comments++
				if !redactionVerb.MatchString(trimmed) && !strings.Contains(trimmed, "stays a") {
					continue
				}
				hit := nameRe.FindString(trimmed)
				if hit == "" || redactionCaveat.MatchString(trimmed) {
					continue
				}
				bad = append(bad, path+":"+itoa(i+1)+"  ["+strings.ToLower(hit)+"]  "+trimmed)
			}
			return nil
		}); err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}
	if comments < 50 {
		t.Fatalf("only %d comment lines read across %v; the walk is not finding the public packages "+
			"and this guard is vacuous", comments, goDocRoots)
	}
	if len(bad) > 0 {
		t.Errorf("%d public-API doc comment(s) claim redaction for a type this build cannot "+
			"redact:\n  %s\n\nA library caller reads this instead of --help.", len(bad),
			strings.Join(bad, "\n  "))
	}
	t.Logf("read %d comment lines across %v", comments, goDocRoots)
}

// TestTheRedactionDocGuardCatchesThePlantedShapes is the control, and it is not optional.
//
// Every assertion above is a search that finds nothing when it is working. A regex that stopped
// matching, a capability set that came back empty, or an extension parser that dropped globs would
// all present as a clean pass. So each shape is planted here and must be caught.
func TestTheRedactionDocGuardCatchesThePlantedShapes(t *testing.T) {
	caps := capabilitiesForTest(t)

	t.Run("a glob command, the #686 shape", func(t *testing.T) {
		const planted = "  ferret-scan --file *.pdf --enable-redaction --redaction-output-dir ./safe-docs"
		m := ferretRedactionCommand.FindStringSubmatch(planted)
		if m == nil {
			t.Fatalf("the command pattern no longer matches the exact line #686 was about")
		}
		exts := extensionsIn(m[1])
		if len(exts) != 1 || exts[0] != ".pdf" {
			t.Fatalf("extensionsIn(%q) = %v, want [.pdf]", m[1], exts)
		}
		if caps.ReasonUnimplemented(".pdf") == "" {
			t.Errorf(".pdf is not reported as unredactable, so the #686 line would pass")
		}
	})

	t.Run("an indented fenced command", func(t *testing.T) {
		if ferretRedactionCommand.FindStringSubmatch("    ferret-scan --file a.tiff --enable-redaction") == nil {
			t.Errorf("an indented command is not matched; documentation commands are nearly always " +
				"indented inside a fence, and anchoring on a bare ^ is the documented way this " +
				"family of guard has silently matched nothing before")
		}
	})

	t.Run("a shell-prompt prefix and a pipe", func(t *testing.T) {
		for _, line := range []string{
			"$ ferret-scan --file a.tiff --enable-redaction",
			"cat x | ferret-scan --file a.tiff --enable-redaction",
		} {
			if ferretRedactionCommand.FindStringSubmatch(line) == nil {
				t.Errorf("not matched: %q", line)
			}
		}
	})

	t.Run("prose", func(t *testing.T) {
		claim := "The RedactionManager supports four redactor types (text, PDF, Office, image)."
		if !redactionVerb.MatchString(claim) {
			t.Errorf("the redaction verb does not match %q", claim)
		}
		if redactionCaveat.MatchString(claim) {
			t.Errorf("the caveat pattern matches a bare claim, so the prose guard would never fire")
		}
		fixed := "PDF cannot be rewritten; it is scanned and reported only."
		if !redactionCaveat.MatchString(fixed) {
			t.Errorf("a corrected line is not accepted by the caveat pattern: %q", fixed)
		}
	})

	t.Run("a caveat that wraps onto the next line is accepted", func(t *testing.T) {
		// The exact shape that made the line-scoped version of this guard report four already-correct
		// passages in docs/user-guides/README-Redaction.md.
		wrapped := "> in image pixels is not redacted. Only **JPEG and PNG** have an implementation: a `.tiff` `.gif`\n" +
			"> `.bmp` or `.webp` file with findings produces **no redacted copy**, and the run reports"
		paras := paragraphsOf(wrapped)
		if len(paras) != 1 {
			t.Fatalf("a wrapped blockquote sentence split into %d paragraphs, want 1", len(paras))
		}
		if !redactionCaveat.MatchString(paras[0].Body) {
			t.Errorf("the wrapped caveat is not accepted, so an accurate passage would be reported " +
				"as a defect")
		}
	})

	t.Run("a fenced code block is not prose", func(t *testing.T) {
		md := "text\n\n```yaml\nexclude_patterns:\n  - \"*.pdf\"   # redaction skips these\n```\n"
		blanked := fencedBlock.ReplaceAllStringFunc(md, func(b string) string {
			return strings.Repeat("\n", strings.Count(b, "\n"))
		})
		if strings.Contains(blanked, "pdf") {
			t.Errorf("a fenced block survived blanking, so a configuration example is still read as " +
				"a redaction claim")
		}
		if strings.Count(blanked, "\n") != strings.Count(md, "\n") {
			t.Errorf("blanking changed the line count (%d -> %d), so reported line numbers would be "+
				"wrong", strings.Count(md, "\n"), strings.Count(blanked, "\n"))
		}
	})

	t.Run("a caveat phrased as neither/nor is accepted", func(t *testing.T) {
		real := "six values neither reported nor redacted, with nothing saying the scan had stopped."
		if !redactionCaveat.MatchString(real) {
			t.Errorf("an accurate statement that values were NOT redacted is rejected: %q", real)
		}
	})

	t.Run("a blockquote > line separates paragraphs", func(t *testing.T) {
		paras := paragraphsOf("> claim one\n>\n> claim two")
		if len(paras) != 2 {
			t.Errorf("a `>` separator produced %d paragraphs, want 2; without this a caveat "+
				"anywhere in a long blockquote would mask an unrelated claim", len(paras))
		}
	})

	t.Run("the public-API doc comment shape", func(t *testing.T) {
		claim := "// (a redacted .docx stays a .docx, a .pdf stays a .pdf, images get EXIF/GPS"
		if !regexp.MustCompile(`(?i)\bpdf\b`).MatchString(claim) {
			t.Fatalf("the type name is not found in the exact comment #686 shipped")
		}
		if redactionCaveat.MatchString(claim) {
			t.Errorf("the caveat pattern accepts the bare claim, so the doc-comment guard would " +
				"never fire on it")
		}
	})

	t.Run("a quoted --file argument", func(t *testing.T) {
		got := extensionsIn(`--file "my report.tiff" --enable-redaction`)
		if len(got) != 1 || got[0] != ".tiff" {
			t.Errorf("extensionsIn on a quoted argument = %v, want [.tiff]", got)
		}
	})

	t.Run("a directory argument carries no type claim", func(t *testing.T) {
		if got := extensionsIn("--file ./inbox --enable-redaction"); len(got) != 0 {
			t.Errorf("a directory produced %v; a path with no extension makes no claim about a "+
				"file type and must not be reported", got)
		}
	})
}

// minimalPDFWithSSN builds a small, structurally valid PDF whose page content holds one SSN.
//
// Hand-built rather than committed so a reviewer can see exactly what is being asserted, and so this
// file needs no binary fixture. It is valid enough for the text extractor: measured, the scanner
// reports one finding from it.
func minimalPDFWithSSN(t *testing.T, dir, ssn string) string {
	t.Helper()
	stream := "BT /F1 12 Tf 72 720 Td (Employee SSN: " + ssn + ") Tj ET"
	objs := []string{
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
		"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] " +
			"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\nendobj\n",
		"4 0 obj\n<< /Length " + itoa(len(stream)) + " >>\nstream\n" + stream + "\nendstream\nendobj\n",
		"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
	}
	var b strings.Builder
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, 0, len(objs))
	for _, o := range objs {
		offsets = append(offsets, b.Len())
		b.WriteString(o)
	}
	xref := b.Len()
	b.WriteString("xref\n0 " + itoa(len(objs)+1) + "\n0000000000 65535 f \n")
	for _, off := range offsets {
		s := itoa(off)
		b.WriteString(strings.Repeat("0", 10-len(s)) + s + " 00000 n \n")
	}
	b.WriteString("trailer\n<< /Size " + itoa(len(objs)+1) + " /Root 1 0 R >>\nstartxref\n" +
		itoa(xref) + "\n%%EOF\n")

	path := filepath.Join(dir, "doc.pdf")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("writing the PDF fixture: %v", err)
	}
	return path
}

// TestADeclaredUnredactableTypeWritesNothingAndNamesTheCause is the empirical cross-check on the
// declaration, run through the real binary.
//
// The declaration in internal/redactors is what every guard above reads, so a declaration that
// drifted from reality would make all of them confidently wrong in one direction or the other:
//
//	declared unimplemented, actually works  -> the documentation is forced to under-claim, and a
//	                                           working capability is hidden from users
//	declared working, actually refuses      -> #686 all over again, with the guards asserting it is fine
//
// So both directions are asserted here against what the binary actually does, and the positive
// control is not optional: without it a broken build that writes NO artifact for anything would pass
// the unredactable half perfectly.
func TestADeclaredUnredactableTypeWritesNothingAndNamesTheCause(t *testing.T) {
	caps := capabilitiesForTest(t)
	bin := buildScanner(t)
	const ssn = "219-09-9998"

	if reason := caps.ReasonUnimplemented(".pdf"); reason == "" {
		t.Fatalf(".pdf is not declared unimplemented, so this test is measuring the wrong thing")
	}

	run := func(t *testing.T, file string) (findings int, artifacts int, unredactedCause, detail string) {
		t.Helper()
		outDir := filepath.Join(t.TempDir(), "out")
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- bin is built by this test and every argument is a literal or a temp path
		out, err := exec.Command(bin, "--file", file, "--config", os.DevNull, "--checks", "all",
			"--confidence", "all", "--limit", "0", "--format", "json",
			"--enable-redaction", "--redaction-strategy", "simple",
			"--redaction-output-dir", outDir).Output()
		if err != nil {
			// A refusal is not a process failure; only report a genuine launch/parse problem.
			if len(out) == 0 {
				t.Fatalf("running the scanner on %s: %v", filepath.Base(file), err)
			}
		}
		findings, unredactedCause, detail = parseRedactionReport(t, out)
		artifacts = countFiles(t, outDir)
		return
	}

	t.Run("pdf: reported, refused, and the cause is named", func(t *testing.T) {
		pdf := minimalPDFWithSSN(t, t.TempDir(), ssn)
		findings, artifacts, cause, detail := run(t, pdf)

		// Non-vacuity first. A PDF that yields no finding never reaches the redactor, and every
		// assertion below would hold for a reason that has nothing to do with redaction.
		if findings == 0 {
			t.Fatalf("the PDF fixture produced no findings, so nothing was asked of the redactor")
		}
		if artifacts != 0 {
			t.Errorf("%d artifact(s) written for a type declared unredactable. Either PDF redaction "+
				"now works — in which case delete it from PDFRedactor.UnimplementedTypes and "+
				"regenerate docs/redaction-support.md — or something wrote an output that was NOT "+
				"redacted, which is the outcome the refusal exists to prevent", artifacts)
		}
		if cause != "no redactor for this file type" {
			t.Errorf("cause = %q, want %q.\nThe operator-facing cause is how a user tells a "+
				"limitation from a bug: a residue refusal means investigate, an unimplemented type "+
				"means the tool cannot do it. Sharing one label loses that distinction.", cause,
				"no redactor for this file type")
		}
		if !strings.Contains(strings.ToLower(detail), "pdf") {
			t.Errorf("detail = %q; it should name the format so the reader knows WHICH capability "+
				"is missing", detail)
		}
	})

	t.Run("txt: the positive control — an artifact IS written and the value is gone", func(t *testing.T) {
		dir := t.TempDir()
		txt := filepath.Join(dir, "doc.txt")
		if err := os.WriteFile(txt, []byte("Employee SSN: "+ssn+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		outDir := filepath.Join(t.TempDir(), "out")
		if err := os.MkdirAll(outDir, 0o750); err != nil {
			t.Fatal(err)
		}
		// #nosec G204 -- bin is built by this test and every argument is a literal or a temp path
		out, err := exec.Command(bin, "--file", txt, "--config", os.DevNull, "--checks", "all",
			"--confidence", "all", "--limit", "0", "--format", "json",
			"--enable-redaction", "--redaction-strategy", "simple",
			"--redaction-output-dir", outDir).Output()
		if err != nil && len(out) == 0 {
			t.Fatalf("running the scanner: %v", err)
		}
		findings, cause, _ := parseRedactionReport(t, out)
		if findings == 0 {
			t.Fatalf("the txt fixture produced no findings; the control asserts nothing")
		}
		if n := countFiles(t, outDir); n == 0 {
			t.Fatalf("no artifact written for .txt, which IS redactable. Every assertion in the " +
				"sibling subtest would pass on a build that redacts nothing at all, so this control " +
				"failing means those results cannot be trusted")
		}
		if cause != "" {
			t.Errorf("a redactable type reported an unredacted cause %q", cause)
		}
		// And the value must actually be gone, read out of the artifact.
		var leaked []string
		err = filepath.WalkDir(outDir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			data, rerr := os.ReadFile(path) // #nosec G304 -- a path under the test's own output dir
			if rerr != nil {
				return rerr
			}
			if strings.Contains(string(data), ssn) {
				leaked = append(leaked, filepath.Base(path))
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walking the output: %v", err)
		}
		if len(leaked) > 0 {
			t.Errorf("the reported value survives in %v", leaked)
		}
	})
}

// parseRedactionReport pulls the finding count and the first unredacted entry out of a JSON report.
//
// Hand-parsed rather than unmarshalled into the formatter's structs, because the point is to read
// what a CONSUMER sees in the document — a schema change that dropped the disclosure should fail here.
func parseRedactionReport(t *testing.T, out []byte) (findings int, cause, detail string) {
	t.Helper()
	var doc struct {
		Results    []map[string]any `json:"results"`
		Unredacted []struct {
			Cause  string `json:"cause"`
			Detail string `json:"detail"`
		} `json:"unredacted"`
		Stats map[string]any `json:"stats"`
	}
	if err := jsonUnmarshal(out, &doc); err != nil {
		t.Fatalf("the report is not valid JSON (%v); first 200 bytes: %.200s", err, out)
	}
	if doc.Stats == nil {
		t.Fatalf("the report carries no stats block, so it is not the document a consumer reads")
	}
	if len(doc.Unredacted) > 0 {
		cause, detail = doc.Unredacted[0].Cause, doc.Unredacted[0].Detail
	}
	return len(doc.Results), cause, detail
}

// jsonUnmarshal is a thin alias so the import reads as a deliberate dependency of the report parser.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

func countFiles(t *testing.T, dir string) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			n++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("counting artifacts in %s: %v", dir, err)
	}
	return n
}
