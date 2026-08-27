// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package metaextractofficelib

import (
	"archive/zip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/embedded"
)

// TestTraversalBudgetIsChargedByTheWritingLoop is the charge half of #474.
//
// The per-container budget was already enforced; what was missing is that every container drew a
// FRESH one, so the aggregate over a nested or fanned-out tree was unbounded. The fix threads one
// budget per top-level file, and this asserts the extractor actually spends it — a budget that is
// threaded but never charged is indistinguishable from a fixed one anywhere except here.
func TestTraversalBudgetIsChargedByTheWritingLoop(t *testing.T) {
	const per = 4 * 1024 * 1024
	path := buildDocxWithParts(t, 3, per)

	traversal := embedded.NewBudget()
	before := traversal.Remaining()

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(path, traversal)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	if len(media) != 3 {
		t.Fatalf("extracted %d of 3 parts (notExamined=%v); this fixture is well under the budget so "+
			"all three must be admitted, or the assertion below measures a refusal instead of a charge",
			len(media), notExamined)
	}

	spent := before - traversal.Remaining()
	if spent == 0 {
		t.Fatal("the traversal budget was not charged at all; every container would still draw a " +
			"fresh 200MB allowance (#474)")
	}

	// Charged with the bytes actually written, so the spend must match the temp files on disk.
	var written int64
	for _, m := range media {
		info, statErr := os.Stat(m.TempFilePath)
		if statErr != nil {
			t.Fatalf("stat %s: %v", m.TempFilePath, statErr)
		}
		written += info.Size()
	}
	defer CleanupEmbeddedMedia(media)

	if spent != written {
		t.Errorf("charged %d bytes but wrote %d; the traversal must be settled to the ACTUAL length, "+
			"or a producer's over-declaration would deny coverage to the rest of the document",
			spent, written)
	}
}

// TestTraversalIsChargedOncePerPartNotTwice is the constraint that keeps the fix from cutting
// detection in half.
//
// ExtractMetadata's own loop inflates every part to io.Discard to decide membership of
// EmbeddedMediaCount and the EmbeddedMedia_N_* properties — and that text is what the validators
// scan. Charging that loop against the same allowance put the aggregate at exactly 2x the bytes ever
// written, so the writing loop would then refuse parts the metadata loop had already counted. The
// traversal bound covers bytes that PERSIST and re-enter the router; inflate work is bounded
// per-container.
//
// An earlier version of this test created a Budget, called ExtractMetadata, and asserted the Budget
// was untouched. That could not fail: ExtractMetadata takes no budget, so the loop has no way to
// reach that object. It was replaced with an assertion on the CHARGE ITSELF, which is where a second
// charge would actually show up — exactly one part's bytes, once.
func TestTraversalIsChargedOncePerPartNotTwice(t *testing.T) {
	const per = 4 * 1024 * 1024
	const parts = 3
	path := buildDocxWithParts(t, parts, per)

	// Both loops run over this file: ExtractMetadata first, as the preprocessor does, then the
	// writing loop. If the metadata loop charged the same allowance, the spend would double.
	traversal := embedded.NewBudget()
	before := traversal.Remaining()

	meta, err := ExtractMetadata(path)
	if err != nil {
		t.Fatalf("ExtractMetadata: %v", err)
	}
	if meta.Properties["EmbeddedMediaCount"] != "3" {
		t.Fatalf("EmbeddedMediaCount = %q, want 3 — the metadata loop did not walk the parts, so the "+
			"double-charge this guards against could not occur either",
			meta.Properties["EmbeddedMediaCount"])
	}

	media, _, err := ExtractEmbeddedMediaForProcessing(path, traversal)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	defer CleanupEmbeddedMedia(media)

	var written int64
	for _, m := range media {
		info, statErr := os.Stat(m.TempFilePath)
		if statErr != nil {
			t.Fatalf("stat: %v", statErr)
		}
		written += info.Size()
	}
	spent := before - traversal.Remaining()

	if written == 0 {
		t.Fatal("nothing was written, so a double charge would be invisible")
	}
	if spent != written {
		t.Errorf("charged %d bytes for %d bytes written (ratio %.2f). Anything above 1.0 means a part "+
			"is charged more than once, which refuses parts the metadata loop already counted into the "+
			"text the validators scan", spent, written, float64(spent)/float64(written))
	}
}

// TestFailedOpenRefundsItsReservation is the refund assertion at the seam that has to make it.
//
// An earlier version tested settleTraversal directly, so removing the deferred call from
// admitEmbeddedPart survived: the method was correct and nothing invoked it. This drives the real
// path with an entry that RESERVES its declared size and then writes nothing, because it cannot be
// opened — an unregistered compression method, which is what an unknown or corrupt entry looks like.
//
// Leaking that reservation is how a document full of unreadable entries would deny coverage to its
// own readable ones: each failure would permanently spend up to 50MB of a 200MB allowance.
func TestFailedOpenRefundsItsReservation(t *testing.T) {
	const declared = 40 * 1024 * 1024

	path := filepath.Join(t.TempDir(), "unopenable.docx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	z := zip.NewWriter(f)
	// CreateRaw takes the header's sizes verbatim, so the entry can DECLARE 40MB while carrying a
	// handful of bytes — and method 99 is not registered, so Open fails before any copy.
	w, err := z.CreateRaw(&zip.FileHeader{
		Name:               "word/media/image0.png",
		Method:             99,
		UncompressedSize64: declared,
		CompressedSize64:   4,
		CRC32:              0,
	})
	if err != nil {
		t.Fatalf("CreateRaw: %v", err)
	}
	if _, err := w.Write([]byte("junk")); err != nil {
		t.Fatalf("write raw: %v", err)
	}
	if err := z.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close file: %v", err)
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer reader.Close()
	if len(reader.File) != 1 {
		t.Fatalf("fixture holds %d entries, want 1", len(reader.File))
	}
	part := reader.File[0]
	if part.UncompressedSize64 != declared {
		t.Fatalf("the entry declares %d bytes, want %d — the fixture is not exercising an over-declaration",
			part.UncompressedSize64, declared)
	}

	traversal := embedded.NewBudget()
	var sink countingWriter
	n, err := admitEmbeddedPart(part, newExtractionBudget(traversal), &sink)
	if err == nil {
		t.Fatal("an entry with an unregistered compression method was admitted; the fixture is not " +
			"failing the way this test needs")
	}
	if n != 0 || sink.n != 0 {
		t.Fatalf("the unopenable entry wrote %d bytes", sink.n)
	}

	if got := embedded.BudgetBytes - traversal.Remaining(); got != 0 {
		t.Errorf("a part that failed to open permanently spent %d bytes of the traversal budget; the "+
			"reservation must be handed back, or unreadable entries starve the readable ones", got)
	}
}

// TestExhaustedTraversalRefusesWithoutWriting is the assertion that made the first version of this
// fix ineffective.
//
// Charging the traversal AFTER the copy bounded what got scanned but not what got written. Measured
// end to end on a 642KB document holding 16 heavy children: 12 of the 16 parts were correctly refused
// and disclosed, and all 16 had already written their 45MB — 659MB of disk, with the bound working
// exactly as designed. A bound that fires after the cost is paid is not a bound.
func TestExhaustedTraversalRefusesWithoutWriting(t *testing.T) {
	const per = 4 * 1024 * 1024
	path := buildDocxWithParts(t, 3, per)

	// Arrive with the allowance already spent, as the fifth container in a fan-out does.
	traversal := embedded.NewBudget()
	if !traversal.Reserve(embedded.BudgetBytes) {
		t.Fatal("could not spend the budget to set up the test")
	}

	media, notExamined, err := ExtractEmbeddedMediaForProcessing(path, traversal)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing: %v", err)
	}
	defer CleanupEmbeddedMedia(media)

	if len(media) != 0 {
		t.Errorf("an exhausted traversal still admitted %d part(s)", len(media))
	}
	if len(notExamined) == 0 {
		t.Fatal("the refusal was SILENT; a budget that cuts coverage without disclosing it turns a " +
			"resource bug into a clean-looking result, which is the worse failure")
	}
	joined := strings.Join(notExamined, " | ")
	if !strings.Contains(joined, "nested inside it") {
		t.Errorf("the note must distinguish the whole-traversal bound from the per-document one — they "+
			"send an operator to different places: %q", joined)
	}
}

// countingWriter records how many bytes were actually written to it.
type countingWriter struct{ n int64 }

func (w *countingWriter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }

// TestExhaustedTraversalWritesNoBytes is the assertion that actually pins the pre-copy reservation,
// and it exists because the version above did NOT.
//
// The integration-level test asserts the part list is empty and the refusal is disclosed. Both of
// those hold whether the traversal is charged before the copy or after it — so a mutation moving the
// charge back to post-copy survived, silently reintroducing the 659MB-of-disk behaviour this whole
// change exists to stop. Its "nothing was written" loop iterated the ADMITTED parts, which is empty
// by construction when everything is refused: the check could not fail.
//
// This one measures the bytes, at the seam where they are written, so post-copy charging cannot pass.
func TestExhaustedTraversalWritesNoBytes(t *testing.T) {
	const per = 4 * 1024 * 1024
	path := buildDocxWithParts(t, 1, per)

	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer reader.Close()

	var part *zip.File
	for _, f := range reader.File {
		if isEmbeddedPartPath(f.Name) {
			part = f
			break
		}
	}
	if part == nil {
		t.Fatal("the fixture holds no embedded part, so this test measures nothing")
	}

	// First prove the writer DOES see bytes when the traversal allows it. Without this the
	// assertion below would pass on a fixture whose part is empty.
	{
		var sink countingWriter
		if _, err := admitEmbeddedPart(part, newExtractionBudget(embedded.NewBudget()), &sink); err != nil {
			t.Fatalf("admitting a part against a fresh traversal failed: %v", err)
		}
		if sink.n == 0 {
			t.Fatal("an admitted part wrote 0 bytes; the fixture cannot show the difference this test needs")
		}
	}

	exhausted := embedded.NewBudget()
	if !exhausted.Reserve(embedded.BudgetBytes) {
		t.Fatal("setup: could not spend the traversal budget")
	}

	var sink countingWriter
	n, err := admitEmbeddedPart(part, newExtractionBudget(exhausted), &sink)
	if err == nil {
		t.Fatal("an exhausted traversal admitted the part")
	}
	if !errors.Is(err, embedded.ErrBudgetExhausted) {
		t.Errorf("refusal %v does not wrap embedded.ErrBudgetExhausted", err)
	}
	if sink.n != 0 || n != 0 {
		t.Errorf("an exhausted traversal still wrote %d bytes (reported %d). The bytes are the cost: "+
			"charging after the copy refuses the part once it has already been paid for, which is how a "+
			"642KB document still put 659MB on disk with the bound working as designed", sink.n, n)
	}
}

// TestTraversalRefusalWrapsTheSentinel: callers branch on embedded.ErrBudgetExhausted with errors.Is,
// and the redaction side raises the same condition. A refusal that did not wrap it would be
// downgraded to a generic failure on the way up.
func TestTraversalRefusalWrapsTheSentinel(t *testing.T) {
	b := &extractionBudget{remaining: embedded.BudgetBytes, traversal: embedded.NewBudget()}
	if !b.traversal.Reserve(embedded.BudgetBytes) {
		t.Fatal("setup: could not spend the traversal budget")
	}
	err := b.reserveTraversal(1)
	if err == nil {
		t.Fatal("an exhausted traversal did not refuse")
	}
	if !errors.Is(err, embedded.ErrBudgetExhausted) {
		t.Errorf("error %v does not wrap embedded.ErrBudgetExhausted", err)
	}
}

// TestOverDeclaredPartIsRefundedToTheTraversal pins the answer to the objection against reserving on
// a producer-controlled declared size.
//
// A part that declares more than it writes must hand the difference back BEFORE the next part is
// considered, or one lying declaration would deny coverage to the document's honest parts — the
// hazard that made the per-container budget charge post-copy in the first place.
func TestOverDeclaredPartIsRefundedToTheTraversal(t *testing.T) {
	traversal := embedded.NewBudget()
	b := &extractionBudget{remaining: embedded.BudgetBytes, traversal: traversal}

	const declared = 40 * 1024 * 1024
	const actual = 1024

	if err := b.reserveTraversal(declared); err != nil {
		t.Fatalf("reserveTraversal: %v", err)
	}
	if got := embedded.BudgetBytes - traversal.Remaining(); got != declared {
		t.Fatalf("reserved %d, want the declared %d", got, declared)
	}

	b.settleTraversal(declared, actual)

	if got := embedded.BudgetBytes - traversal.Remaining(); got != actual {
		t.Errorf("after settling, %d bytes are still spent; want the actual %d — the over-claim was "+
			"not handed back", got, actual)
	}
}

// TestReleaseCannotMintBudget: a release without a matching reservation must not raise the allowance
// above its limit, or a document full of tiny parts could manufacture headroom.
func TestReleaseCannotMintBudget(t *testing.T) {
	b := embedded.NewBudget()
	b.Release(embedded.BudgetBytes * 4)
	if b.Remaining() != embedded.BudgetBytes {
		t.Errorf("Remaining = %d after an unmatched release, want the limit %d",
			b.Remaining(), embedded.BudgetBytes)
	}
}

// TestExhaustionIsOrderIndependent: once refused, a later SMALLER part must still be refused.
//
// Otherwise which parts get examined depends on the order they appear in the archive, and the
// producer chooses that order. It is also why exhaustion is a latched flag rather than a zeroed
// counter: refunds would otherwise resurrect a traversal that had already been refused.
func TestExhaustionIsOrderIndependent(t *testing.T) {
	b := embedded.NewBudget()

	if b.Reserve(embedded.BudgetBytes + 1) {
		t.Fatal("a reservation above the limit was allowed")
	}
	if !b.Exhausted() {
		t.Error("the budget did not latch exhausted after refusing")
	}
	if b.Reserve(1) {
		t.Error("a 1-byte part was admitted after the traversal was refused; coverage now depends on " +
			"the order the producer wrote the archive")
	}

	// A refund must not un-refuse it.
	b.Release(embedded.BudgetBytes)
	if b.Reserve(1) {
		t.Error("a refund resurrected an exhausted traversal")
	}
}

// TestNilTraversalBehavesExactlyAsBefore: the extractor is exported and has callers with no router
// to ask. A bound that failed closed for them would turn a resource fix into a coverage loss.
func TestNilTraversalBehavesExactlyAsBefore(t *testing.T) {
	const per = 4 * 1024 * 1024
	path := buildDocxWithParts(t, 3, per)

	withNil, notExamined, err := ExtractEmbeddedMediaForProcessing(path, nil)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing(nil): %v", err)
	}
	defer CleanupEmbeddedMedia(withNil)

	if len(withNil) != 3 {
		t.Errorf("with no traversal budget, extracted %d of 3 parts (notExamined=%v); a nil budget "+
			"must allow everything the per-container budget allows", len(withNil), notExamined)
	}
	if len(notExamined) != 0 {
		t.Errorf("a nil traversal budget produced refusals: %v", notExamined)
	}
}

// TestAddingATraversalBudgetNeverWidensAdmission is the safety property for the second bound.
//
// The two bounds happen to be the same size — embedded.BudgetBytes — so on a single container they
// bite at nearly the same point and no assertion here can attribute a refusal to one rather than the
// other. What CAN be established, and is what matters, is direction: adding the traversal budget must
// never admit a part the per-container budget alone would have refused. A second bound that widened
// admission would be worse than no second bound.
//
// The per-container bound in isolation is covered by TestAggregateExtractionBudgetIsEnforced, which
// passes nil.
func TestAddingATraversalBudgetNeverWidensAdmission(t *testing.T) {
	const per = 40 * 1024 * 1024
	parts := int(embedded.BudgetBytes/per) + 2

	path := buildDocxWithParts(t, parts, per)

	withoutTraversal, _, err := ExtractEmbeddedMediaForProcessing(path, nil)
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing(nil): %v", err)
	}
	defer CleanupEmbeddedMedia(withoutTraversal)

	withTraversal, notExamined, err := ExtractEmbeddedMediaForProcessing(path, embedded.NewBudget())
	if err != nil {
		t.Fatalf("ExtractEmbeddedMediaForProcessing(budget): %v", err)
	}
	defer CleanupEmbeddedMedia(withTraversal)

	// Non-vacuity: the per-container bound must actually be biting, or "no wider" is trivially true.
	if len(withoutTraversal) == 0 || len(withoutTraversal) >= parts {
		t.Fatalf("the per-container bound admitted %d of %d parts; this fixture must be one where it "+
			"bites, or the comparison below proves nothing", len(withoutTraversal), parts)
	}

	if len(withTraversal) > len(withoutTraversal) {
		t.Errorf("adding the traversal budget admitted MORE parts (%d) than the per-container budget "+
			"alone (%d); a second bound must only ever narrow", len(withTraversal), len(withoutTraversal))
	}
	if len(notExamined) == 0 {
		t.Error("the truncation was not disclosed")
	}
}
