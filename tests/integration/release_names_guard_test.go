// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The release-names guard (#866). Shipped text must not tell a user to run a program no release
// builds: `cmd/suppress` printed `Usage: ferret-suppress ...` for a tool .goreleaser.yml never
// built, and the docs once walked users through it.
//
// "Named as a command" is deliberately narrow. The tree holds some 3,000 `ferret-scan` words and a
// long tail of file and artifact names (`ferret-scan-suppressions.yaml`, `ferret-sast-report.json`,
// `ferret-scan-linux-amd64`) that are not commands. A `ferret-*` word is a command when, on one line
// of the text that is read as shell:
//
//  1. it is the program of the line: first word after the line start, a prompt (`$`, `>`, `PS>`),
//     a YAML list dash, `run:`, `sudo`, or one of `|`, `&&`, `||`, `;`, `(`;
//  2. or it is followed by a flag (`ferret-x --file a`, `ferret-x -h`);
//  3. or it follows `Usage:`.
//
// A leading path (`./`, `bin/`, `C:\tools\`) and a trailing `.exe` do not change the name. A word
// followed by anything but white space, a quote, a backtick or a closing bracket
// (`ferret-scan-suppressions.yaml`, `ferret-scan-<version>`) is a file or a template, not a command.
//
// Where it is read: lines inside fenced blocks and inline code spans of docs/**/*.md and README.md;
// every line of the other files under docs/ and of internal/web/assets/**; and every Go string
// literal (parsed, not grepped, so comments are not read) of every .go file in the module.
//
// By this reading tests/integration/windows_release_comprehensive_test.go, which #866 listed as an
// allowlist candidate, names no command: its mock package copies `bin\ferret-suppress.exe` as a file
// in an install script it assembles itself and checks for, and never runs it. The documented-flag
// tests' `.\ferret-scan-profile.exe scan . --cpuprofile` negative cases are not commands either
// (a word sits between the name and the flag). Neither needs an allowlist line.
//
// shortcut: a command written in prose outside code (`run ferret-x to ...`) or built by string
// concatenation is not seen; that is the price of not reading every `ferret-*` word. Widen the three
// patterns when one is found.

var (
	cmdName = `(ferret-[a-z0-9]+(?:-[a-z0-9]+)*)(?:\.exe)?`
	// A path in front of a name: anything for the flag and usage readings; for the program of a
	// line only the relative forms a command is run by (./x, bin/x, ./bin/x, and their backslash
	// spellings), because `/usr/local/bin/x` or `../x` alone on a line is a listed path.
	anyPath  = `(?:[^\s"'` + "`" + `|;&()]*[/\\])?`
	runPath  = `(?:\.[/\\])?(?:bin[/\\])?`
	progMark = `(?:(?:[$>]|PS[^>\s]*>|-|run:|sudo)\s+)`
	// What may follow a command name: the end of the line, white space, a quote, a backtick or a
	// closing bracket. A '.', '<', '*' or '$' means the word is a file name or a template.
	cmdEnd = "(?:$|[\\s\"'`)\\]])"

	// 1. the program of a line, or of a pipeline stage. In a fenced block the line start is enough
	// (`ferret-x list`); elsewhere (a string literal, an asset, an inline span) a bare word at the
	// start of a line is as likely a temp-dir prefix or a service name, so a prompt, a list dash,
	// `run:`, `sudo` or a pipeline operator must come first.
	reCmdProgramFenced = regexp.MustCompile(`(?:^|[|;&(])\s*` + progMark + `*` + runPath + cmdName + cmdEnd)
	reCmdProgramMarked = regexp.MustCompile(`(?:[|;&(]\s*|^\s*` + progMark + `)` + progMark + `*` + runPath + cmdName + cmdEnd)
	// 2. followed by a flag.
	reCmdFlag = regexp.MustCompile(`(?:^|[\s"'` + "`" + `(])` + anyPath + cmdName + `\s+--?[A-Za-z]`)
	// 3. a usage line.
	reCmdUsage = regexp.MustCompile(`(?i)usage:\s+` + anyPath + cmdName + cmdEnd)

	reInlineCode = regexp.MustCompile("`([^`]+)`")
)

// commandNames returns every ferret-* name the line names as a command, per the reading above.
// fenced is true for a line of a markdown fenced block.
func commandNames(line string, fenced bool) []string {
	prog := reCmdProgramMarked
	if fenced {
		prog = reCmdProgramFenced
	}
	var out []string
	seen := map[string]bool{}
	for _, re := range []*regexp.Regexp{prog, reCmdFlag, reCmdUsage} {
		for _, m := range re.FindAllStringSubmatch(line, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
	}
	return out
}

type namedCommand struct {
	file string
	line int
	name string
	text string
}

// markdownCommands reads fenced blocks and inline code spans.
func markdownCommands(file, src string) []namedCommand {
	var out []namedCommand
	inFence := false
	for i, line := range strings.Split(src, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			inFence = !inFence
			continue
		}
		var segs []string
		if inFence {
			segs = []string{line}
		} else {
			for _, m := range reInlineCode.FindAllStringSubmatch(line, -1) {
				segs = append(segs, m[1])
			}
		}
		for _, s := range segs {
			for _, n := range commandNames(s, inFence) {
				out = append(out, namedCommand{file, i + 1, n, strings.TrimSpace(s)})
			}
		}
	}
	return out
}

// plainCommands reads every line.
func plainCommands(file, src string) []namedCommand {
	var out []namedCommand
	for i, line := range strings.Split(src, "\n") {
		for _, n := range commandNames(line, false) {
			out = append(out, namedCommand{file, i + 1, n, strings.TrimSpace(line)})
		}
	}
	return out
}

// goLiteralCommands reads the string literals of one Go file.
func goLiteralCommands(file, src string) ([]namedCommand, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []namedCommand
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		base := fset.Position(lit.Pos()).Line
		for i, line := range strings.Split(s, "\n") {
			for _, name := range commandNames(line, false) {
				out = append(out, namedCommand{file, base + i, name, strings.TrimSpace(line)})
			}
		}
		return true
	})
	return out, nil
}

// releasedBinaries is every `binary:` of .goreleaser.yml's builds, without a .exe suffix.
func releasedBinaries(t *testing.T, root string) map[string]bool {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, ".goreleaser.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Builds []struct {
			Binary string `yaml:"binary"`
		} `yaml:"builds"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, b := range cfg.Builds {
		if b.Binary != "" {
			out[strings.TrimSuffix(b.Binary, ".exe")] = true
		}
	}
	return out
}

// namesGuardAllowlist is the only place a name no release builds may stay: file and name, with the
// reason.
var namesGuardAllowlist = map[[2]string]string{
	// A profiling build the reader makes for themselves: the block's first line is
	// `go build -o ferret-scan-profile.exe ./cmd`.
	{"docs/development/WINDOWS_DEVELOPMENT.md", "ferret-scan-profile"}: "built by the reader with go build -o in the same block",
}

func repoCommandNames(t *testing.T, root string) []namedCommand {
	t.Helper()
	var out []namedCommand
	walk := func(dir string, read func(rel, src string) error) {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if os.IsNotExist(err) {
				return nil // a root without this directory (the planted-tree test)
			}
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == ".git" || d.Name() == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			rel, _ := filepath.Rel(root, p)
			return read(filepath.ToSlash(rel), string(b))
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	text := func(rel, src string) error {
		if strings.HasSuffix(rel, ".md") {
			out = append(out, markdownCommands(rel, src)...)
		} else if !strings.ContainsRune(src, 0) { // not a binary asset
			out = append(out, plainCommands(rel, src)...)
		}
		return nil
	}
	walk("docs", text)
	walk("internal/web/assets", text)
	if b, err := os.ReadFile(filepath.Join(root, "README.md")); err == nil {
		out = append(out, markdownCommands("README.md", string(b))...)
	}
	for _, dir := range []string{"cmd", "internal", "pkg", "tests", "scripts"} {
		walk(dir, func(rel, src string) error {
			// This file spells the planted offenders its own checks use.
			if !strings.HasSuffix(rel, ".go") || rel == "tests/integration/release_names_guard_test.go" {
				return nil
			}
			cs, err := goLiteralCommands(rel, src)
			if err != nil {
				t.Errorf("%s: %v", rel, err)
			}
			out = append(out, cs...)
			return nil
		})
	}
	return out
}

func TestEveryNamedCommandIsABinaryTheReleaseBuilds(t *testing.T) {
	root := filepath.Join("..", "..")
	built := releasedBinaries(t, root)
	if !built["ferret-scan"] {
		t.Fatalf(".goreleaser.yml builds %v, expected ferret-scan: the guard cannot read the release", built)
	}
	all := repoCommandNames(t, root)

	// Non-vacuity: the reading must still see the commands the tree is full of.
	seen := 0
	var bad []string
	used := map[[2]string]bool{}
	for _, c := range all {
		if built[c.name] {
			seen++
			continue
		}
		if _, ok := namesGuardAllowlist[[2]string{c.file, c.name}]; ok {
			used[[2]string{c.file, c.name}] = true
			continue
		}
		bad = append(bad, c.file+":"+strconv.Itoa(c.line)+": "+c.name+"  (in: "+c.text+")")
	}
	t.Logf("%d command mentions of %v; %d allowlisted names", seen, built, len(namesGuardAllowlist))
	if seen < 100 {
		t.Errorf("only %d command mentions of %v found: the patterns no longer read the tree", seen, built)
	}
	for k, why := range namesGuardAllowlist {
		if !used[k] {
			t.Errorf("allowlist entry %v (%s) matches nothing: remove it", k, why)
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("names a command no release builds (.goreleaser.yml builds %v): %s", built, b)
	}
}

// The reading itself: what is a command and what is a file name. A planted offender must fail, a
// file name must not.
func TestCommandNameReading(t *testing.T) {
	cases := []struct {
		line   string
		fenced bool
		want   []string
	}{
		{"ferret-suppress --action list", false, []string{"ferret-suppress"}},
		{"ferret-suppress list", true, []string{"ferret-suppress"}},
		{"$ ferret-suppress list", false, []string{"ferret-suppress"}},
		{"PS> .\\bin\\ferret-suppress.exe list", false, []string{"ferret-suppress"}},
		{"  - ./bin/ferret-scan --file . --format json", false, []string{"ferret-scan"}},
		{"cat x | ferret-redact", false, []string{"ferret-redact"}},
		{"make && sudo ferret-tool", true, []string{"ferret-tool"}},
		{`Usage: ferret-suppress <list>`, false, []string{"ferret-suppress"}},
		{`fmt.Println("Usage: ferret-suppress")`, false, []string{"ferret-suppress"}},
		// not commands:
		{"ferret-scan-test", false, nil},
		{"/usr/local/bin/ferret-scan-precommit", true, nil},
		{"../ferret-corpus", true, nil},
		{"--suppression-file ferret-scan-suppressions.yaml", true, nil},
		{"--output ferret-sast-report.json", true, nil},
		{"chmod +x ferret-scan-linux-amd64", true, nil},
		{"the ferret-suppress tool", true, nil},
		{"ferret-scan-<version>.zip", true, nil},
		{"mktemp ferret-scan-XXXX", true, nil},
	}
	for _, c := range cases {
		got := commandNames(c.line, c.fenced)
		sort.Strings(got)
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%q: got %v, want %v", c.line, got, want)
		}
	}
}

// A planted offender in each kind of source is reported, and the released name is not.
func TestPlantedOffendersAreFoundInEverySource(t *testing.T) {
	md := "Prose `ferret-ghost --x` and:\n\n```bash\n$ ferret-ghost list\nferret-scan --file a\n```\n"
	if got := markdownCommands("x.md", md); len(got) != 3 {
		t.Errorf("markdown: %+v", got)
	}
	got, err := goLiteralCommands("x.go", "package x\n\nvar u = \"Usage: ferret-ghost [options]\"\n// ferret-ghost --in a comment\n")
	if err != nil || len(got) != 1 || got[0].name != "ferret-ghost" || got[0].line != 3 {
		t.Errorf("go literal: %+v, %v", got, err)
	}
	if got := plainCommands("a.js", "x = 1\n  ferret-ghost --serve\n"); len(got) != 1 || got[0].line != 2 {
		t.Errorf("plain: %+v", got)
	}
}

// Through the whole walk: a planted tree with one offender per source is reported, one name per
// source, and the released name beside each of them is not.
func TestPlantedTreeIsReportedThroughTheWalk(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("README.md", "```sh\nferret-in-readme --version\nferret-scan --version\n```\n")
	write("docs/guide.md", "Run `ferret-in-docs --help`.\n")
	write("docs/notes.txt", "$ ferret-in-text list\n")
	write("internal/web/assets/app.js", "const hint = 'ferret-in-asset --serve'\n")
	write("cmd/x/main.go", "package main\n\nvar u = \"Usage: ferret-in-go [flags]\"\n")
	got := map[string]bool{}
	for _, c := range repoCommandNames(t, root) {
		got[c.name] = true
	}
	for _, want := range []string{"ferret-in-readme", "ferret-in-docs", "ferret-in-text", "ferret-in-asset", "ferret-in-go", "ferret-scan"} {
		if !got[want] {
			t.Errorf("planted %s not found; found %v", want, got)
		}
	}
}
