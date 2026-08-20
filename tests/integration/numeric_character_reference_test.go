// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"archive/zip"
	"bytes"
	"html"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The two halves of the escaped-value leak, composed, through the real binary.
//
// A numeric character reference is a legitimate XML spelling of an ordinary character and Word
// renders it as that character, so `51&#57;-42-8836` is an SSN on screen. Measured on this exact
// fixture, at three points in this change:
//
//	main                      1 of 4 reported; 3 readable in the redacted copy
//	redactor fix alone        1 of 4 reported; 3 readable
//	extractor fix alone       4 of 4 reported; 3 STILL readable, no warning  <- worse
//	both (this branch)        4 of 4 reported; none readable
//
// The third row is why these ship together. Fixing detection alone converts a silent miss into
// "4 SSNs found and handled" while Word still renders three of them — a report that is now
// actively misleading. A unit test on either side passes in that state; only the pipeline shows
// it.
//
// Residue is checked on the DECODED part text. Grepping the .docx searches COMPRESSED bytes and
// always "finds nothing"; grepping the raw XML misses the escaped spelling, which is the whole
// defect.
func TestNumericCharacterReferencesAreDetectedAndRedacted(t *testing.T) {
	bin := numrefBinary(t)
	dir := t.TempDir()

	values := []string{"449-87-4100", "519-42-8836", "563-18-7249", "607-31-9284"}
	src := filepath.Join(dir, "numrefs.docx")
	if err := os.WriteFile(src, buildNumrefDocx(), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	stdout, _, code := runNumref(t, bin, "--file", src, "--confidence", "all", "--format", "csv")
	if code != 0 {
		t.Fatalf("scan exit = %d, want 0\n%s", code, stdout)
	}
	if n := strings.Count(stdout, ",SSN,"); n != len(values) {
		t.Fatalf("reported %d SSNs, want %d. Every value below the count is invisible to every "+
			"validator, and only reported findings are redacted.\n%s", n, len(values), stdout)
	}

	outDir := filepath.Join(dir, "out")
	if _, _, code = runNumref(t, bin, "--file", src, "--confidence", "all",
		"--enable-redaction", "--redaction-output-dir", outDir, "--format", "csv"); code != 0 {
		t.Fatalf("redaction exit = %d, want 0", code)
	}

	var redacted string
	err := filepath.Walk(outDir, func(p string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || filepath.Base(p) != "numrefs.docx" {
			return werr
		}
		redacted = p
		return nil
	})
	if err != nil {
		t.Fatalf("walking output: %v", err)
	}
	if redacted == "" {
		t.Fatal("no redacted copy was written, so nothing can be verified")
	}

	decoded := html.UnescapeString(numrefPartText(t, redacted, "word/document.xml"))
	var survived []string
	for _, v := range values {
		if strings.Contains(decoded, v) {
			survived = append(survived, v)
		}
	}
	if len(survived) > 0 {
		t.Errorf("%d of %d values survived in word/document.xml of a file the tool reported as "+
			"successfully redacted: %v\nWord renders every one of them as the real digits, so the "+
			"document a human opens still shows the SSN.\ndecoded part text: %s",
			len(survived), len(values), survived, decoded)
	}
}

// buildNumrefDocx writes the paragraphs VERBATIM: references spelled as references is the point,
// and an escaping helper would store "&amp;#57;" and test nothing.
func buildNumrefDocx() []byte {
	paras := []string{
		"Employee SSN: 449-87-4100",
		"Employee SSN: 51&#57;-42-8836",
		"Employee SSN: &#53;&#54;&#51;-&#49;&#56;-&#55;&#50;&#52;&#57;",
		"Employee SSN: 60&#x37;-31-9284",
	}
	var body strings.Builder
	for _, p := range paras {
		body.WriteString(`<w:p><w:r><w:t xml:space="preserve">` + p + `</w:t></w:r></w:p>`)
	}
	doc := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
		body.String() + `</w:body></w:document>`
	ctypes := `<?xml version="1.0" encoding="UTF-8"?>` +
		`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
		`<Default Extension="xml" ContentType="application/xml"/>` +
		`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
		`</Types>`

	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)
	for _, e := range []struct{ name, body string }{
		{"[Content_Types].xml", ctypes},
		{"word/document.xml", doc},
	} {
		w, err := zw.Create(e.name)
		if err != nil {
			panic(err)
		}
		if _, err := io.WriteString(w, e.body); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// numrefPartText returns one part's raw bytes from an OOXML package on disk.
func numrefPartText(t *testing.T, pkgPath, part string) string {
	t.Helper()
	zr, err := zip.OpenReader(pkgPath)
	if err != nil {
		t.Fatalf("opening %s: %v", pkgPath, err)
	}
	defer func() { _ = zr.Close() }()

	for _, f := range zr.File {
		if f.Name != part {
			continue
		}
		rc, oerr := f.Open()
		if oerr != nil {
			t.Fatalf("opening %s: %v", part, oerr)
		}
		defer func() { _ = rc.Close() }()
		b, rerr := io.ReadAll(rc)
		if rerr != nil {
			t.Fatalf("reading %s: %v", part, rerr)
		}
		return string(b)
	}
	t.Fatalf("%s not found in %s", part, pkgPath)
	return ""
}

// numrefBinary builds ferret-scan for this file's tests.
//
// Deliberately its own helper rather than a shared one: package integration has several
// independent binary builders, and a name shared across files that arrive on different branches
// is a merge that compiles apart and fails together.
func numrefBinary(t *testing.T) string {
	t.Helper()
	name := "ferret-scan"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	bin := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", bin, "../../cmd")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build ferret-scan: %v\n%s", err, out)
	}
	return bin
}

func runNumref(t *testing.T, bin string, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command(bin, args...) //nolint:gosec // bin is built by the test
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0
	if err != nil {
		ee, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatalf("unexpected exec error: %v\nstderr=%s", err, stderr.String())
		}
		code = ee.ExitCode()
	}
	return stdout.String(), stderr.String(), code
}
