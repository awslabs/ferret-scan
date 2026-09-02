// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/embedded"
	"github.com/awslabs/ferret-scan/v2/internal/redactverify"
)

// Redacting a file that lives INSIDE another file.
//
// The read side already descends: an embedded part is written to a temp file and
// routed back through the router, so an SSN in word/embeddings/oleObject1.docx or
// in word/media/image1.jpg's EXIF is REPORTED. The write side did not, so those
// values were never rewritten. Measured on main, with the outer document's own SSN
// correctly redacted in every case:
//
//	outer.docx -> word/embeddings/oleObject1.docx   SSN in cleartext in the output
//	outer.docx -> word/media/image1.jpg  (EXIF)     SSN in cleartext in the output
//
// both at exit 0, with nothing on stderr and a file sitting in a directory called
// "redacted". Only reported findings are redacted, so a value the redactor cannot
// reach is a leak that reports as success.
//
// The mechanism here is deliberately TYPE-AGNOSTIC: hand the child's bytes to
// whichever registered redactor claims its extension and take the bytes back. The
// alternative that was tried first — teaching the Office redactor to do zip surgery
// on nested OOXML parts — fixed exactly one of the two cases above and could not fix
// the other even in principle, because redacting a JPEG's EXIF is not a text
// substitution in a zip member. Dispatching instead means embedded .docx/.xlsx/.pptx,
// legacy .doc/.xls/.ppt, images and plain text are all covered by one loop, and each
// child is redacted by the code that already knows its format.

// EmbeddedRedactionRequest asks for the bytes of one embedded part to be redacted.
//
// Bytes in, bytes out. The caller (a container redactor) never touches the
// filesystem for its children: materializing the part as a temp file is this
// package's job, so the path-safety rules live in exactly one place rather than in
// every container redactor that might grow a nested case.
type EmbeddedRedactionRequest struct {
	// ParentPath is the file this part was taken out of. It is the depth-accounting
	// key and is not otherwise interpreted.
	ParentPath string

	// PartName is the archive entry name, e.g. word/embeddings/oleObject1.docx.
	//
	// It is PRODUCER-CONTROLLED and is used for two things only: choosing the
	// redactor via its allowlisted extension, and naming the part in disclosure
	// text. It never reaches a filesystem path — see embedded.SafeExt.
	PartName string

	// Content is the part's decompressed bytes.
	Content []byte

	// Matches is the FULL match list for the top-level file, not a subset.
	//
	// It cannot be a subset, because a finding carries no attribution to the part
	// it came from: every match from an embedded child reports the OUTER file as
	// its origin (verified — metadata.original_file names the container for all of
	// them). So the child is handed everything and locates what is actually in it,
	// which is the same thing every redactor already does at the top level. A value
	// present in both container and child is redacted in both, which is correct.
	Matches []detector.Match

	// Strategy is the redaction strategy to apply, unchanged from the parent so a
	// nested value is masked the same way as a top-level one.
	Strategy RedactionStrategy
}

// EmbeddedRedactionResult carries the redacted bytes back to the container.
type EmbeddedRedactionResult struct {
	// Content is the redacted part, to be stored back at the same archive entry.
	Content []byte

	// RedactionMap describes what was redacted inside the part, so the container
	// can merge it into its own audit trail instead of under-reporting.
	RedactionMap []RedactionMapping

	// PartName echoes the request, so a caller collecting results from several
	// children can attribute them without keeping a parallel slice.
	PartName string
}

// EmbeddedRedactor redacts a file extracted OUT OF another file.
//
// Declared here, next to the Redactor interface it complements, and satisfied by
// *RedactionManager. A container redactor holds this interface rather than the
// concrete manager so the dependency runs container -> interface <- manager: the
// manager already knows every redactor, and a format redactor must not.
//
// Mirrors preprocessors.RouterInterface.ProcessEmbedded on purpose. That is the
// read-side counterpart, and keeping the two shaped alike is what makes it obvious
// that both halves bound depth, both disclose truncation, and both admit the same
// set of file types.
type EmbeddedRedactor interface {
	// RedactEmbedded redacts one embedded part.
	//
	// Returns embedded.ErrTooDeep when the nesting bound is reached, and an
	// ordinary error when no redactor handles the part's type or the redaction
	// fails. Callers must DISCLOSE every one of those outcomes: each leaves a value
	// the scanner reported sitting in the output in cleartext.
	RedactEmbedded(req EmbeddedRedactionRequest) (*EmbeddedRedactionResult, error)
}

// ErrNoEmbeddedRedactor reports that no registered redactor handles a part's type.
//
// A distinct sentinel because the part was scanned and may hold reported findings,
// but nothing can rewrite it: a property of the tool's coverage rather than a
// failure of this run, so the disclosure wording differs accordingly.
//
// This used to name audio as the example. Audio is redactable since #357 and video
// since #358, so what reaches here now is PDF — and any type admitted on the read
// side in future before its redactor exists.
var ErrNoEmbeddedRedactor = errors.New("no redactor handles this embedded file type")

// embeddedDepthState tracks nesting depth across re-entrant redaction.
//
// The manager owns it for the same reason the router owns its counterpart: a
// redactor instance is shared across concurrent files, so it cannot hold per-call
// state, and RedactDocument's signature has no context to thread a counter
// through. Keyed on the temp path the manager itself handed out, which the child's
// own recursive call passes back as ParentPath.
type embeddedDepthState struct {
	mu    sync.Mutex
	depth map[string]int
}

func (s *embeddedDepthState) depthOf(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.depth[path]
}

func (s *embeddedDepthState) set(path string, d int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.depth == nil {
		s.depth = make(map[string]int)
	}
	s.depth[path] = d
}

// clear removes an entry once its child finishes, so the map holds only the files
// currently being redacted rather than growing across a directory scan.
func (s *embeddedDepthState) clear(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.depth, path)
}

// RedactEmbedded implements EmbeddedRedactor.
//
// The whole function is the read side's ProcessEmbedded with the arrow reversed:
// bound the depth, materialize the child, dispatch it to the component that knows
// its format, and hand the result back to the container.
func (rm *RedactionManager) RedactEmbedded(req EmbeddedRedactionRequest) (*EmbeddedRedactionResult, error) {
	// Bound the depth FIRST, before any allocation or filesystem work, so a deep
	// nest costs nothing past the limit.
	depth := rm.embeddedDepth.depthOf(req.ParentPath) + 1
	if depth > embedded.MaxDepth {
		return nil, fmt.Errorf("%w: %s is nested %d levels deep (limit %d)",
			embedded.ErrTooDeep, filepath.Base(req.PartName), depth, embedded.MaxDepth)
	}

	// The extension comes from the admission allowlist, never from the entry name.
	// req.PartName is producer-controlled and the value below is concatenated into
	// a filesystem path, so per BSC1 it is validated against an allowlist at the
	// sink. embedded.SafeExt returns either ".bin" or a dot followed by 1-10
	// characters drawn from [a-z0-9] and nothing else, which makes "..", separators
	// and NUL unrepresentable in the result rather than something to strip.
	safeExt, ok := embedded.SafeExt(req.PartName)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNoEmbeddedRedactor, filepath.Ext(req.PartName))
	}

	// A private directory per child, removed on every path out.
	//
	// MkdirTemp is 0700 and CreateTemp/WriteFile below are 0600, which matters more
	// than usual here: these files hold the part's UNREDACTED bytes, i.e. exactly
	// the sensitive values the run exists to remove. A predictable name or a
	// group-readable mode would publish them to any other account on the host for
	// the duration of the scan.
	dir, err := os.MkdirTemp("", "ferret-embedded-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir for embedded part: %w", err)
	}
	// Deferred so it runs on the error paths too. An early return that left the
	// cleartext part on disk would turn a redaction failure into a second
	// disclosure.
	defer func() { _ = os.RemoveAll(dir) }()

	inPath := filepath.Join(dir, "embedded"+safeExt)
	outPath := filepath.Join(dir, "redacted"+safeExt)

	// Containment assertion at the sink. SafeExt already makes an escaping path
	// unrepresentable, so on today's code this cannot fire — it is defence in depth,
	// for the refactor that starts deriving the basename from the entry name and
	// only notices later. A traversal here would write a document's UNREDACTED bytes
	// to an attacker-chosen location, so the cost of the check is not worth saving.
	//
	// It is also what a scanner can see: CodeQL's go/zipslip models a cleaned-prefix
	// containment test as a barrier but not a per-character allowlist, so without
	// this the flow from the zip entry to these writes reads as unsanitized (alert
	// 3820, 19 sinks, all of them downstream of this one construction).
	for _, p := range []string{inPath, outPath} {
		if !withinDir(dir, p) {
			return nil, fmt.Errorf("%w: embedded part %s resolved outside its temp directory",
				ErrNoEmbeddedRedactor, filepath.Base(req.PartName))
		}
	}

	if err := os.WriteFile(inPath, req.Content, 0o600); err != nil {
		return nil, fmt.Errorf("writing embedded part to temp file: %w", err)
	}

	// Record the depth against the path the child will report as its parent, so a
	// container nested inside this one is measured from here.
	rm.embeddedDepth.set(inPath, depth)
	defer rm.embeddedDepth.clear(inPath)

	// Dispatch by type. GetRedactorForFile also diverts a container extension whose
	// bytes are not that container to the text redactor, which is wanted here too:
	// an entry named .docx that is actually plain text is still redactable.
	redactor, err := rm.GetRedactorForFile(inPath)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNoEmbeddedRedactor, filepath.Ext(req.PartName))
	}

	result, err := redactor.RedactDocument(inPath, outPath, req.Matches, req.Strategy)
	if err != nil {
		return nil, fmt.Errorf("redacting embedded part %s: %w", filepath.Base(req.PartName), err)
	}
	if result == nil || !result.Success {
		return nil, fmt.Errorf("redacting embedded part %s: redactor reported failure",
			filepath.Base(req.PartName))
	}

	// Read back whatever the redactor actually wrote. Its own RedactedFilePath is
	// preferred over outPath because a redactor is free to choose its output name,
	// and trusting our guess would silently return the UNREDACTED bytes if the two
	// ever differed.
	written := result.RedactedFilePath
	if written == "" {
		written = outPath
	}
	redacted, err := os.ReadFile(written) // #nosec G304 -- path built from MkdirTemp and an allowlisted extension
	if err != nil {
		return nil, fmt.Errorf("reading redacted embedded part %s: %w",
			filepath.Base(req.PartName), err)
	}

	// THE FLOOR. The bytes are already in hand, so the only question left is whether a reported
	// value is still in them. Asking here rather than in each redactor is the point of #459: this
	// was per-redactor policy, and #449 was the case where one forgot — tagmeta.Residual searched
	// only the ranges it had rewritten, so a value surviving outside them was invisible by
	// construction, and a part containing a reported SSN was embedded back into the container at
	// exit 0.
	//
	// Refusing rather than returning the bytes matches every redactor that already verifies
	// (audio, office, tagmeta, video): a part that would look redacted and is not is worse than a
	// disclosed refusal, because the container is rebuilt around it and nothing downstream looks
	// again. The caller turns this into a disclosed, non-fatal skip for the whole file.
	if residual := redactverify.ResidualTypes(redacted, req.Matches); len(residual) > 0 {
		return nil, fmt.Errorf("redacted embedded part %s still holds reported value(s) of type %s; "+
			"refusing to embed a part that would look redacted",
			filepath.Base(req.PartName), strings.Join(residual, ", "))
	}

	return &EmbeddedRedactionResult{
		Content:      redacted,
		RedactionMap: result.RedactionMap,
		PartName:     req.PartName,
	}, nil
}

// withinDir reports whether path is dir itself or a descendant of it.
//
// Both sides are cleaned before comparison, so a "." or ".." element is resolved
// rather than compared literally, and the separator is appended to dir so a
// sibling with dir as a name prefix ("/tmp/ferret-embedded-1-evil" against
// "/tmp/ferret-embedded-1") is not mistaken for a child.
func withinDir(dir, path string) bool {
	cleanDir := filepath.Clean(dir)
	cleanPath := filepath.Clean(path)
	if cleanPath == cleanDir {
		return true
	}
	return strings.HasPrefix(cleanPath, cleanDir+string(os.PathSeparator))
}
