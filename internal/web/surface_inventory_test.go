// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Every flag the CLI registers has exactly one recorded answer to "does the web UI get this?", in one
// of the three tables below. TestCLIFlagsHaveAWebDecision reads the flags from the BUILT BINARY and
// fails for a flag in no table, a flag in two, and a table entry the binary no longer has, so a new
// CLI flag cannot reach main without a decision for the web (#907).
//
// The source of each reason is cited where it is code: cmd/main.go validateWebModeFlags is the list of
// flags `--web` refuses, each with its own troubleshooting line, and handleWebMode/startWebServer pass
// --config, --suppression-file and --exclude through to NewWebServerWithOptions.

// webEquivalent maps a flag to how the web UI exposes the same capability.
var webEquivalent = map[string]string{
	"checks":                "/scan form field `checks` (comma list or all); falls back to the config's defaults.checks, then all",
	"confidence":            "/scan form field `confidence`, parsed by core.ParseConfidenceLevels; an unknown level is refused (#683)",
	"verbose":               "/scan form field `verbose`, and /export `verbose`",
	"recursive":             "/scan form field `recursive`; a dropped folder is walked by the browser, one /scan per file",
	"format":                "/export `format`, any formatters.List() entry, and the UI's export menu; validateWebModeFlags refuses --format with --web",
	"show-match":            "/export `show_match`; /scan always sends the value and the UI hides it until clicked; validateWebModeFlags refuses --show-match with --web",
	"suppression-file":      "`--web --suppression-file <path>` names the file the /suppressions endpoints read and write (NewWebServerWithOptions)",
	"config":                "`--web --config <path>`: Start() loads it with LoadConfigStrict and refuses to start on an error; its defaults are /scan's fallbacks",
	"exclude":               "`--web --exclude <patterns>` is served by /config-info as exclude_patterns, which the browser applies to a dropped folder",
	"explain":               "implicit: runFullCLIScan runs explain.Annotate on every finding (the Add Suppression reason prefill); /export drops it, see exportLosses",
	"enable-preprocessors":  "implicit: on by default; the config's defaults.enable_preprocessors is honored by runFullCLIScan",
	"show-suppressed":       "implicit: /scan always returns the suppressed findings in `suppressed`; validateWebModeFlags refuses --show-suppressed with --web",
	"generate-suppressions": "/suppressions/create per finding and /suppressions/bulk-create with `findings`; validateWebModeFlags refuses --generate-suppressions with --web",
	"suppression-expires":   "`expires_at` on /suppressions/create and /suppressions/edit, and /suppressions/bulk-update-expiration",
	"version":               "/health `version` and `build_info`, which the UI shows top-right; validateWebModeFlags refuses --version with --web",
}

// webDeliberatelyAbsent maps a flag to the reason it is a CLI-only concern.
var webDeliberatelyAbsent = map[string]string{
	"web":                  "starts the web server; it is the web",
	"port":                 "the web server's own port; it configures the web rather than a scan",
	"bind":                 "the web server's own listen address (ResolveBindAddress); it configures the web rather than a scan",
	"file":                 "the web's input is the multipart upload `files`; handleWebMode refuses --file with --web",
	"stdin":                "streams standard input into one scan; an upload is a file, so there is no stream to read",
	"stdin-name":           "labels --stdin findings; an upload is named by its own filename or relative_path",
	"output":               "writes the report to a path on the CLI's host; the web returns it as the /export download (validateWebModeFlags refuses it)",
	"no-color":             "ANSI colour for a terminal; /export always renders with NoColor (validateWebModeFlags refuses it)",
	"quiet":                "silences terminal progress lines; the web reports progress in the page (validateWebModeFlags refuses it)",
	"pre-commit-mode":      "the pre-commit hook contract: exit codes, quiet output, the commit verdict; a server has no per-scan exit code",
	"fail-on-incomplete":   "turns incomplete coverage into exit code 3; the web reports it per scan as `incomplete` and `not_examined` (validateWebModeFlags refuses it)",
	"preprocess-only":      "prints the extracted text and exits without scanning; validateWebModeFlags refuses it with --web",
	"p":                    "alias of --preprocess-only; validateWebModeFlags refuses it with --web",
	"enable-redaction":     "writes redacted copies to a directory on the CLI's host, which the web does not serve; the UI hides values client-side (validateWebModeFlags refuses it)",
	"redaction-output-dir": "where --enable-redaction writes; the web writes no redacted copy (validateWebModeFlags refuses it)",
	"redaction-strategy":   "how --enable-redaction rewrites; the web writes no redacted copy (validateWebModeFlags refuses it)",
	"redaction-audit-log":  "the audit log of --enable-redaction; the web writes no redacted copy (validateWebModeFlags refuses it)",
	"help":                 "prints the CLI's usage; the web has its own help panel (validateWebModeFlags refuses it)",
}

// webUndecided holds the flags with no recorded decision for the web. Each value is the issue where the
// decision is asked for. Moving a flag out of here is a maintainer's call: put it in one of the two
// tables above with its mechanism, in the same pull request that implements or documents it.
var webUndecided = map[string]string{
	"validator-budget":  "#907", // validateWebModeFlags refuses it ("runs with the default per-file timeout"), but no budget exists for a server either
	"max-live-bytes":    "#907", // validateWebModeFlags refuses it; concurrent /scan requests are not capped together
	"profile":           "#907", // accepted and ignored with --web: runFullCLIScan passes Profile: nil
	"list-profiles":     "#907", // validateWebModeFlags refuses it: "does not currently support configuration profiles"
	"disable-ip-types":  "#907", // accepted and ignored with --web: not passed to NewWebServerWithOptions
	"limit":             "#907", // /scan returns every finding; the CLI caps the report at 200 by default
	"respect-gitignore": "#907", // a dropped folder is walked by the browser (app.js isExcludedByPatterns), which reads no .gitignore
	"debug":             "#907", // accepted and ignored with --web: runFullCLIScan sets Debug: false
}

var (
	inventoryOnce   sync.Once
	inventoryFlags  []string
	inventoryOutput string
	inventoryErr    error
)

// reDefaultsFlag matches one flag line of Go's flag.PrintDefaults: two spaces, a dash, the name.
var reDefaultsFlag = regexp.MustCompile(`(?m)^  -([A-Za-z0-9][A-Za-z0-9_-]*)`)

// binaryFlags builds ./cmd once per test binary and returns every flag it registers.
//
// The list comes from the binary, not from --help: --help is hand-written prose (internal/help) and
// omits registered flags (--bind, --show-suppressed and -p among them), while an undefined flag makes
// the standard library print flag.PrintDefaults, which enumerates every registration. So a flag added
// to cmd/main.go appears here with nobody editing this file.
func binaryFlags(t *testing.T) []string {
	t.Helper()
	inventoryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "ferret-inventory-")
		if err != nil {
			inventoryErr = err
			return
		}
		defer os.RemoveAll(dir)
		name := "ferret-scan-inventory"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		bin := filepath.Join(dir, name)
		build := exec.Command("go", "build", "-o", bin, "../../cmd")
		build.Env = os.Environ()
		if out, err := build.CombinedOutput(); err != nil {
			inventoryErr = err
			inventoryOutput = string(out)
			return
		}
		// Exit status 2 is the flag package's answer to an undefined flag; the listing is on stderr.
		out, _ := exec.Command(bin, "-surface-inventory-undefined-flag").CombinedOutput()
		inventoryOutput = string(out)
		seen := map[string]bool{}
		for _, m := range reDefaultsFlag.FindAllStringSubmatch(inventoryOutput, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				inventoryFlags = append(inventoryFlags, m[1])
			}
		}
		sort.Strings(inventoryFlags)
	})
	if inventoryErr != nil {
		t.Fatalf("build ./cmd: %v\n%s", inventoryErr, inventoryOutput)
	}
	if !strings.Contains(inventoryOutput, "flag provided but not defined") || len(inventoryFlags) < 20 {
		t.Fatalf("the binary did not list its flags the way flag.PrintDefaults does (%d found); if cmd/main.go "+
			"now sets flag.Usage, read the flags another way. Output:\n%s", len(inventoryFlags), truncate(inventoryOutput, 600))
	}
	return inventoryFlags
}

// TestCLIFlagsHaveAWebDecision fails for any CLI flag with no recorded web decision, any flag with two,
// and any table entry naming a flag the binary no longer registers.
func TestCLIFlagsHaveAWebDecision(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI binary; skipped under -short")
	}
	flags := binaryFlags(t)
	tables := []struct {
		name string
		m    map[string]string
	}{
		{"webEquivalent", webEquivalent},
		{"webDeliberatelyAbsent", webDeliberatelyAbsent},
		{"webUndecided", webUndecided},
	}
	registered := map[string]bool{}
	for _, f := range flags {
		registered[f] = true
		var in []string
		for _, tb := range tables {
			if _, ok := tb.m[f]; ok {
				in = append(in, tb.name)
			}
		}
		switch len(in) {
		case 0:
			t.Errorf("CLI flag --%s has no web decision: add it to webEquivalent (how the web exposes it), "+
				"webDeliberatelyAbsent (why it is CLI-only) or webUndecided (the issue that asks) in %s",
				f, "internal/web/surface_inventory_test.go")
		case 1:
		default:
			t.Errorf("CLI flag --%s is in %s; a flag has exactly one web decision", f, strings.Join(in, " and "))
		}
	}
	reIssue := regexp.MustCompile(`^#[0-9]+$`)
	for _, tb := range tables {
		for f, why := range tb.m {
			if !registered[f] {
				t.Errorf("%s lists --%s, which the binary no longer registers; remove the entry", tb.name, f)
			}
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s[%q] has no reason", tb.name, f)
			}
			if tb.name == "webUndecided" && !reIssue.MatchString(why) {
				t.Errorf("webUndecided[%q] = %q; an undecided flag points at the issue that asks for the decision (#NNN)", f, why)
			}
		}
	}
	t.Logf("%d CLI flags: %d web-equivalent, %d deliberately absent, %d undecided (%s)",
		len(flags), len(webEquivalent), len(webDeliberatelyAbsent), len(webUndecided), strings.Join(sortedKeys(webUndecided), ", "))
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
