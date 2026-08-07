// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

// The unscanned-file contract: a file the tool did not examine must never be
// reportable as clean.
//
// This is a different assertion from every other case in this corpus. Elsewhere the
// question is "was the right thing detected in this document". Here the document is
// deliberately broken, nothing can be detected, and the only thing that matters is
// whether the tool ADMITS it. A validator cannot leak from a file it never opened —
// but a scanner that reports `[]` and exits 0 on a file it never opened causes the
// same harm by a different route: a CI job merges the change believing the file was
// checked.
//
// Measured on main before these cases existed, one file per mode:
//
//	noperm.txt     rc=0  json=[]   (permission denied)
//	corrupt.docx   rc=0  json=[]   (not a valid zip)
//	empty.csv      rc=0  json=[]   (0 bytes)
//
// All three print a warning on stderr and are counted toward
// --fail-on-incomplete, so the information exists. What is missing is that the
// MACHINE-READABLE output says nothing at all: `[]` is indistinguishable from a
// clean scan, and rc is 0 unless the operator already knew to pass an opt-in flag.
//
// These cases pin today's library-level behaviour so the upcoming error-reporting
// change can be measured rather than asserted. They exist BEFORE that change on
// purpose: a fix to a silent-failure class needs a gate that would have caught the
// silence, otherwise the same class returns unnoticed.
type UnscannedCase struct {
	// Name is the subtest name.
	Name string
	// Origin records provenance.
	Origin string
	// Rationale says why this shape matters, in user terms.
	Rationale string
	// Basename's extension drives routing, so it must be plausible for the content.
	Basename string
	// Build returns the (broken) file bytes.
	Build func() []byte
	// Unreadable makes the fixture unreadable (chmod 0o000) after it is written.
	//
	// A bool rather than an os.FileMode field: 0o000 IS the zero value, so a
	// `Mode os.FileMode` field cannot distinguish "no permissions" from "not set".
	// The first version of this file made exactly that mistake and the chmod never
	// ran — the fixture stayed readable and the case passed for the wrong reason
	// until a probe printed the actual mode (rw------- instead of ---------).
	Unreadable bool
	// Checks is the validator set, validated against core.CheckNames().
	Checks []string

	// MustNotBeReportedClean is the whole point: after scanning, the tool must
	// signal that this file was not examined — via ScanResult.Incomplete, or by
	// returning an error. Both mean "not scanned"; the corpus accepts either
	// because the two failure modes genuinely take different paths today
	// (measured: an unreadable file ERRORS out of ScanFile, while a corrupt or
	// empty one sets Incomplete).
	MustNotBeReportedClean bool

	// IsGenuinelyClean marks a file that is NOT a failure and must therefore be
	// scanned normally: today an empty file is reported as "could not be
	// processed... any sensitive data in them was NOT detected", which is a false
	// alarm. A 0-byte file contains no sensitive data; saying otherwise trains
	// operators to ignore the warning that matters.
	//
	// Set true for exactly that case, so the upcoming fix has a witness. Until it
	// lands, KnownFalseAlarm below records that the current behaviour is wrong.
	IsGenuinelyClean bool

	// KnownFalseAlarm records that today's behaviour contradicts
	// IsGenuinelyClean. It is the honest way to commit a case whose CORRECT
	// outcome is known but not yet implemented, without either a permanently
	// failing test or a test that asserts the bug is right.
	KnownFalseAlarm bool
}

// UnscannedCases are the inputs the tool cannot examine.
var UnscannedCases = []UnscannedCase{
	{
		Name:   "unreadable_permission_denied",
		Origin: "authored 2026-08 for scorecorpus; behavior measured on main",
		Rationale: "A file the process cannot open may be full of PII. Reporting it as clean " +
			"is the worst possible answer, because a reviewer has no way to tell it apart " +
			"from a file that was read and found empty. Measured on main: rc=0 and `[]` in " +
			"JSON; only stderr mentions it.",
		Basename:               "unreadable_permission_denied.txt",
		Build:                  func() []byte { return []byte("SSN 130-07-5728\n") },
		Unreadable:             true,
		Checks:                 []string{"SSN"},
		MustNotBeReportedClean: true,
	},
	{
		Name:   "unparseable_container",
		Origin: "authored 2026-08 for scorecorpus; behavior measured on main",
		Rationale: "A truncated or corrupt .docx — the shape produced by a failed download or " +
			"a partial upload. The extension promises a container the bytes cannot deliver, " +
			"so no text is extracted and no validator ever runs. This is the case most " +
			"likely to occur by accident rather than by attack.",
		Basename:               "unparseable_container.docx",
		Build:                  func() []byte { return []byte("PK\x03\x04truncated-not-a-real-zip") },
		Checks:                 []string{"SSN"},
		MustNotBeReportedClean: true,
	},
	{
		Name:   "empty_file_is_genuinely_clean",
		Origin: "authored 2026-08 for scorecorpus; behavior measured on main",
		Rationale: "A 0-byte file is NOT a failure: it contains no sensitive data, so " +
			"'scanned and clean' is the correct answer. Today it is reported as 'could not " +
			"be processed ... any sensitive data in them was NOT detected', which is a false " +
			"alarm, and false alarms are how a warning becomes noise that operators filter " +
			"out — including the ones that matter. Recorded as a known defect so the fix " +
			"has a witness.",
		Basename:         "empty_file_is_genuinely_clean.csv",
		Build:            func() []byte { return nil },
		Checks:           []string{"SSN"},
		IsGenuinelyClean: true,
		KnownFalseAlarm:  true,
	},
	{
		Name:   "control_readable_file_scans_cleanly",
		Origin: "authored 2026-08 for scorecorpus; the anti-vacuity control",
		Rationale: "The control that makes the three cases above meaningful. A well-formed " +
			"file with a real SSN must be scanned, must NOT be flagged incomplete, and must " +
			"produce a finding. Without it, a change that marked EVERY file unscanned would " +
			"satisfy MustNotBeReportedClean everywhere and look like a pass.",
		Basename:               "control_readable_file_scans_cleanly.csv",
		Build:                  func() []byte { return []byte("ssn\n130-07-5728\n") },
		Checks:                 []string{"SSN"},
		MustNotBeReportedClean: false,
		IsGenuinelyClean:       false,
	},
}
