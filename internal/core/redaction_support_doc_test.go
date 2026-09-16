// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// docs/redaction-support.md is GENERATED from the live redactor registry.
//
// It exists because the answer to "can this tool redact a PDF?" was previously asserted in prose in
// four places and implemented in a fifth, with nothing connecting them. `--help` advertised
// `--file *.pdf --enable-redaction`, README promised ".pdf→.pdf", and two architecture documents
// listed a working "PDF Redactor" — while both PDF entry points returned an error unconditionally and
// five of the image redactor's eight declared formats reached an unimplemented arm (#686).
//
// A generated page cannot drift: implementing PDF redaction, or adding a redactor that declares a
// format it cannot rewrite, changes this file on the next run and the test says so.
const docsRedactionSupport = "../../docs/redaction-support.md"

func redactionSupportPage(t *testing.T) string {
	t.Helper()
	caps, err := RedactionCapabilities(t.TempDir())
	if err != nil {
		t.Fatalf("RedactionCapabilities: %v", err)
	}

	var b strings.Builder
	b.WriteString("# Redaction support by file type\n\n")
	b.WriteString("<!-- GENERATED FILE — do not edit by hand.\n")
	b.WriteString("     Regenerate with:\n")
	b.WriteString("       UPDATE_REDACTION_DOCS=1 go test ./internal/core/ -run TestRedactionSupportPageIsUpToDate\n")
	b.WriteString("     The contents come from the live redactor registry in internal/core/redact.go, so this\n")
	b.WriteString("     page cannot claim a capability the build does not have. -->\n\n")
	b.WriteString("`--enable-redaction` writes a redacted copy of a file **of the same type**. Detection is\n")
	b.WriteString("independent of this table: every type the scanner can read is scanned and reported whether or\n")
	b.WriteString("not it can be rewritten.\n\n")

	b.WriteString("## Cannot be rewritten\n\n")
	b.WriteString("These types are recognised and **scanned**, and their findings are reported — but no redacted\n")
	b.WriteString("copy is written. The file is named in the report with the cause `no redactor for this file\n")
	b.WriteString("type`, and **no output is produced at all** rather than a copy that still holds the values.\n")
	b.WriteString("That is deliberate: a file in a directory named `redacted` that still contains an SSN is the\n")
	b.WriteString("artefact a user forwards.\n\n")
	b.WriteString("| type | why |\n|---|---|\n")
	unimplemented := make([]string, 0, len(caps.Unimplemented))
	for t := range caps.Unimplemented {
		unimplemented = append(unimplemented, t)
	}
	sort.Strings(unimplemented)
	for _, ft := range unimplemented {
		fmt.Fprintf(&b, "| `%s` | %s |\n", ft, caps.Unimplemented[ft])
	}

	b.WriteString("\n## Can be rewritten\n\n")
	for _, ft := range caps.Redactable {
		fmt.Fprintf(&b, "- `%s`\n", ft)
	}
	b.WriteString("\n## Checking this from a script\n\n")
	b.WriteString("A run that could not redact everything it reported says so on stderr and in the structured\n")
	b.WriteString("output. In JSON the `unredacted` array carries one entry per such file, each with a `cause`\n")
	b.WriteString("and a `detail`; the same disclosure appears in every other output format. Do not rely on the\n")
	b.WriteString("exit code alone.\n")
	return b.String()
}

// TestRedactionSupportPageIsUpToDate regenerates the page from the registry and diffs it.
func TestRedactionSupportPageIsUpToDate(t *testing.T) {
	want := redactionSupportPage(t)
	path := filepath.Clean(docsRedactionSupport)

	if os.Getenv("UPDATE_REDACTION_DOCS") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		t.Logf("regenerated %s", path)
		return
	}

	got, err := os.ReadFile(path) // #nosec G304 -- a constant path inside the repository
	if err != nil {
		t.Fatalf("%s is missing. Generate it with:\n"+
			"  UPDATE_REDACTION_DOCS=1 go test ./internal/core/ -run TestRedactionSupportPageIsUpToDate\n"+
			"error: %v", path, err)
	}
	if string(got) != want {
		t.Errorf("%s is out of date with the redactor registry.\nRegenerate with:\n"+
			"  UPDATE_REDACTION_DOCS=1 go test ./internal/core/ -run TestRedactionSupportPageIsUpToDate\n\n"+
			"This usually means a redactor was added, removed, or changed which types it declares it "+
			"cannot rewrite. That is exactly the change this page exists to keep honest.", path)
	}
}

// TestTheCapabilitySetIsNotVacuous is the floor under every other assertion here and in cmd.
//
// A registry that failed to build, or a Capabilities() that returned nothing, would make the doc
// guard and the documentation guards all pass by having nothing to check. Each number below is a
// property of the build rather than a snapshot: the specific counts are logged, not asserted.
func TestTheCapabilitySetIsNotVacuous(t *testing.T) {
	caps, err := RedactionCapabilities(t.TempDir())
	if err != nil {
		t.Fatalf("RedactionCapabilities: %v", err)
	}
	if len(caps.Redactable) < 10 {
		t.Errorf("only %d redactable types; the registry declares plain text, Office, images, audio, "+
			"video, SVG and RTF, so a number this small means the registry did not build and every "+
			"guard reading it is asserting nothing", len(caps.Redactable))
	}
	if len(caps.Unimplemented) == 0 {
		t.Errorf("no type is declared unimplemented. PDF and five image formats are registered and " +
			"refuse; an empty map means the declarations were dropped and the documentation guards " +
			"can no longer catch a false claim")
	}
	for ft, reason := range caps.Unimplemented {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("%s is declared unimplemented with no reason; the reason is what the report and "+
				"the documentation guard both quote", ft)
		}
		if ft != redactors.NormalizeType(ft) {
			t.Errorf("unimplemented key %q is not normalised (want %q); the registry indexes "+
				"normalised types, so an unnormalised key silently never matches",
				ft, redactors.NormalizeType(ft))
		}
	}
	// The two known instances, by name. If either starts working, this fails and whoever implemented
	// it gets to delete the line — which is the correct direction for this test to break in.
	for _, ft := range []string{".pdf", ".tiff"} {
		if caps.IsRedactable(ft) {
			t.Errorf("%s is now reported as redactable. If that is real, remove it from the "+
				"UnimplementedTypes declaration and from this list, and regenerate "+
				"docs/redaction-support.md", ft)
		}
	}
	// And a control in the other direction: the types that DO work must not be listed as broken.
	for _, ft := range []string{".txt", ".docx", ".jpg", ".png"} {
		if !caps.IsRedactable(ft) {
			t.Errorf("%s is not reported as redactable, but redaction of it is implemented and "+
				"measured. A declaration that over-claims breakage silences the documentation guard "+
				"for a type that works", ft)
		}
	}
	t.Logf("%d redactable, %d unimplemented", len(caps.Redactable), len(caps.Unimplemented))
}
