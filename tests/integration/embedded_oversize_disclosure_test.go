// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// maxEmbeddedMediaSize mirrors metaextractofficelib.MaxEmbeddedMediaSize.
//
// Duplicated rather than imported because this test's job is to describe what an OPERATOR sees
// at the CLI boundary, and importing an internal constant would make the fixture agree with the
// implementation by construction. If the cap changes and this is not updated, the padded
// fixture stops being over-cap and the assertions below fail loudly — which is the intended
// outcome, not a maintenance trap.
const maxEmbeddedMediaSize = 50 * 1024 * 1024

// The operator-visible half of #374.
//
// A .docx whose embedded document is refused for size used to report "No matches found" at exit
// 0, and exit 0 AGAIN under --fail-on-incomplete — the flag whose entire purpose is to escalate
// incomplete coverage — with nothing on stderr. The identical inner document under the cap
// reports its SSN at HIGH 100. A container declared clean while sensitive content sits unread
// inside it is the cleartext-passthrough shape this tool exists to prevent.
//
// This runs the real binary because every hop matters here: the extractor's note, the
// preprocessor's merge, the router's combine step, the parallel processor's diagnostic channel,
// the cause classification, the stderr section, the exit code, and the machine formats. A unit
// test on any one of them would pass while an operator saw nothing.
func TestOversizeEmbeddedPartIsDisclosedAndExitsThree(t *testing.T) {
	bin := embeddedDisclosureBinary(t)
	dir := t.TempDir()

	control := buildOuterDocx(t, dir, "outer_small.docx", 0)
	oversize := buildOuterDocx(t, dir, "outer_big.docx", maxEmbeddedMediaSize+4096)

	// The control proves the pair is comparable: the SAME inner document, under the cap, is
	// scanned and its SSN reported. Without this, "0 findings" on the oversize file could
	// mean the fixture was simply wrong.
	// Asserted on the TYPE and band, not on the value: csv prints "[HIDDEN]" unless
	// --show-match is passed, so a test that looked for the digits would pass for the wrong
	// reason on the control and be vacuous on the oversize case below.
	stdout, _, code := runFerret(t, bin, "--file", control, "--format", "csv", "--confidence", "high,medium,low")
	if !strings.Contains(stdout, ",SSN,HIGH,") {
		t.Fatalf("the under-cap control did not report the embedded SSN, so this pair proves "+
			"nothing.\nstdout:\n%s", stdout)
	}
	if code != 0 {
		t.Errorf("control exit = %d, want 0", code)
	}

	// The oversize case: still no findings — the part genuinely was not read — but it must
	// now SAY so, and --fail-on-incomplete must escalate.
	stdout, stderr, code := runFerret(t, bin, "--file", oversize, "--fail-on-incomplete",
		"--format", "csv", "--confidence", "high,medium,low")
	if strings.Contains(stdout, ",SSN,") {
		t.Fatalf("the over-cap part was scanned after all; the fixture is not over the cap and "+
			"the rest of this test is vacuous.\nstdout:\n%s", stdout)
	}
	if code != 3 {
		t.Errorf("exit = %d, want 3.\n--fail-on-incomplete exists to turn incomplete coverage "+
			"into a build failure. An embedded document refused for size is the clearest case "+
			"of incomplete coverage there is, and it used to exit 0.\nstderr:\n%s", code, stderr)
	}
	if !strings.Contains(stderr, "NOT FULLY EXAMINED") {
		t.Errorf("stderr has no NOT FULLY EXAMINED section:\n%s", stderr)
	}
	if !strings.Contains(stderr, "attachment.docx") {
		t.Errorf("stderr does not name the part that was not examined:\n%s", stderr)
	}
	if !strings.Contains(stderr, "coverage cut short") {
		t.Errorf("stderr does not file this under 'coverage cut short':\n%s\n"+
			"This container's own body text WAS read and scanned; reporting it as having no "+
			"body text describes a failure that did not happen.", stderr)
	}
	// Payload-free: this text reaches stderr and every machine format.
	if strings.Contains(stderr, "452-11-9384") {
		t.Errorf("the disclosure leaked content from the part it is reporting:\n%s", stderr)
	}

	// And the machine formats have to agree with the human one, since an operator compares a
	// report against an artifact from the same run.
	stdout, _, _ = runFerret(t, bin, "--file", oversize, "--format", "json")
	var doc struct {
		Stats struct {
			FilesNotExamined int `json:"files_not_examined"`
		} `json:"stats"`
		NotExamined []struct {
			Path   string `json:"path"`
			Cause  string `json:"cause"`
			Detail string `json:"detail"`
		} `json:"files_not_examined_detail"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("json output did not parse: %v\n%s", err, stdout)
	}
	if doc.Stats.FilesNotExamined != 1 {
		t.Errorf("stats.files_not_examined = %d, want 1 — a scan that reports complete coverage "+
			"while a part went unread is the defect, whatever stderr says",
			doc.Stats.FilesNotExamined)
	}
}

// embeddedDisclosureBinary builds ferret-scan once for this file's tests.
func embeddedDisclosureBinary(t *testing.T) string {
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

// runFerret runs the binary and returns stdout, stderr and the exit code.
func runFerret(t *testing.T, bin string, args ...string) (string, string, int) {
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

// buildOuterDocx writes a .docx carrying word/embeddings/attachment.docx, whose own body holds
// an SSN and which is padded with `pad` STORED bytes.
//
// STORED padding inside the inner file, deflated by the outer archive: the cap is compared
// against the outer entry's declared uncompressed size, which is the inner file's byte length,
// so the padding has to be incompressible WITHIN the inner file and is then squeezed to almost
// nothing by the outer one. That keeps the fixture on disk at a few tens of KB.
//
// Padding is streamed, never buffered — a 50 MB []byte in a test is 50 MB of RSS for nothing.
func buildOuterDocx(t *testing.T, dir, name string, pad int64, extra ...embeddedPart) string {
	t.Helper()

	innerPath := filepath.Join(dir, "inner_"+name)
	inner, err := os.Create(innerPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create inner: %v", err)
	}
	iz := zip.NewWriter(inner)
	writeEntry(t, iz, "[Content_Types].xml", officeContentTypes)
	writeEntry(t, iz, "word/document.xml", officeDocumentXML("Attached record SSN: 452-11-9384"))
	if pad > 0 {
		w, werr := iz.CreateHeader(&zip.FileHeader{Name: "word/media/pad.bin", Method: zip.Store})
		if werr != nil {
			t.Fatalf("create pad: %v", werr)
		}
		if _, werr = io.CopyN(w, nulReader{}, pad); werr != nil {
			t.Fatalf("write pad: %v", werr)
		}
	}
	if err := iz.Close(); err != nil {
		t.Fatalf("close inner zip: %v", err)
	}
	if err := inner.Close(); err != nil {
		t.Fatalf("close inner file: %v", err)
	}

	outPath := filepath.Join(dir, name)
	out, err := os.Create(outPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("create outer: %v", err)
	}
	oz := zip.NewWriter(out)
	writeEntry(t, oz, "[Content_Types].xml", officeContentTypes)
	writeEntry(t, oz, "word/document.xml", officeDocumentXML("Cover letter, see attachment"))

	src, err := os.Open(innerPath) // #nosec G304 -- test-controlled temp path
	if err != nil {
		t.Fatalf("open inner: %v", err)
	}
	w, err := oz.Create("word/embeddings/attachment.docx")
	if err != nil {
		t.Fatalf("create embedded entry: %v", err)
	}
	if _, err := io.Copy(w, src); err != nil {
		t.Fatalf("copy inner: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("close inner reader: %v", err)
	}

	// Additional embedded parts, each a small .docx of its own. A container with BOTH a
	// refused part and a readable one is the realistic shape, and it is the only one that
	// exercises the path where the refusal notes have to be MERGED with the descent's own
	// warnings rather than returned on their own.
	for _, e := range extra {
		nested := filepath.Join(dir, "extra_"+e.entry+".tmp")
		innerExtra, cerr := os.Create(nested) // #nosec G304 -- test-controlled temp path
		if cerr != nil {
			t.Fatalf("create extra: %v", cerr)
		}
		ez := zip.NewWriter(innerExtra)
		writeEntry(t, ez, "[Content_Types].xml", officeContentTypes)
		writeEntry(t, ez, "word/document.xml", officeDocumentXML(e.body))
		if cerr = ez.Close(); cerr != nil {
			t.Fatalf("close extra zip: %v", cerr)
		}
		if cerr = innerExtra.Close(); cerr != nil {
			t.Fatalf("close extra file: %v", cerr)
		}

		rd, cerr := os.Open(nested) // #nosec G304 -- test-controlled temp path
		if cerr != nil {
			t.Fatalf("open extra: %v", cerr)
		}
		ew, cerr := oz.Create("word/embeddings/" + e.entry)
		if cerr != nil {
			t.Fatalf("create extra entry: %v", cerr)
		}
		if _, cerr = io.Copy(ew, rd); cerr != nil {
			t.Fatalf("copy extra: %v", cerr)
		}
		if cerr = rd.Close(); cerr != nil {
			t.Fatalf("close extra reader: %v", cerr)
		}
	}
	if err := oz.Close(); err != nil {
		t.Fatalf("close outer zip: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close outer file: %v", err)
	}
	return outPath
}

// embeddedPart describes an extra embedded .docx to place alongside the padded one.
type embeddedPart struct {
	entry string
	body  string
}

func writeEntry(t *testing.T, zw *zip.Writer, name, body string) {
	t.Helper()
	w, err := zw.Create(name)
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if _, err := io.WriteString(w, body); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// nulReader is an endless source of NUL bytes.
type nulReader struct{}

func (nulReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

const officeContentTypes = `<?xml version="1.0" encoding="UTF-8"?>` +
	`<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">` +
	`<Default Extension="xml" ContentType="application/xml"/>` +
	`<Default Extension="bin" ContentType="application/octet-stream"/>` +
	`<Default Extension="docx" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document"/>` +
	`<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>` +
	`</Types>`

func officeDocumentXML(body string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>` +
		`<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
		`<w:body><w:p><w:r><w:t>` + body + `</w:t></w:r></w:p></w:body></w:document>`
}

// A container with one refused part AND one readable part must report BOTH facts.
//
// This is the merge: the refusal notes come from the extractor before the router is ever
// consulted, and the descent produces its own warnings afterwards, so a fix that returned only
// one of the two lists would pass every single-part test. Measured as a survived mutation —
// dropping the merge left this case silent while the single-part case still passed.
func TestAContainerReportsBothItsReadablePartAndItsRefusedOne(t *testing.T) {
	bin := embeddedDisclosureBinary(t)
	dir := t.TempDir()

	mixed := buildOuterDocx(t, dir, "outer_mixed.docx", maxEmbeddedMediaSize+4096,
		embeddedPart{entry: "readable.docx", body: "Reachable by phone 415-555-0142"})

	stdout, stderr, code := runFerret(t, bin, "--file", mixed, "--fail-on-incomplete",
		"--format", "csv", "--confidence", "high,medium,low")

	// The readable part still contributes its findings: a disclosure that suppressed the
	// scan would be a worse bug than the one being fixed.
	if !strings.Contains(stdout, ",PHONE,") {
		t.Errorf("the readable embedded part produced no finding, so the refusal cost the "+
			"container its working coverage.\nstdout:\n%s", stdout)
	}
	// ...and the refused one is still disclosed, in the same run.
	if !strings.Contains(stderr, "attachment.docx") {
		t.Errorf("the refused part is not named while another part scanned fine — the notes "+
			"were dropped in favour of the descent's own warnings.\nstderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "coverage cut short") {
		t.Errorf("stderr does not file this under 'coverage cut short':\n%s", stderr)
	}
	if code != 3 {
		t.Errorf("exit = %d, want 3: a partly examined container is incomplete coverage even "+
			"when some of its parts scanned fine.\nstderr:\n%s", code, stderr)
	}
}
