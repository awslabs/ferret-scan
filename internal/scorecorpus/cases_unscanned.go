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
// Measured at HEAD, one file per mode:
//
//	noperm.txt     rc=0  stats.files_not_examined=1  results=[]  (permission denied)
//	corrupt.docx   rc=0  stats.files_not_examined=1  results=[]  (not a valid zip)
//	empty.csv      rc=0  no files_not_examined count  results=[]  (0 bytes: correctly clean)
//
// All of them print a warning on stderr, and the two real failures are counted toward
// --fail-on-incomplete. Machine output now carries the COUNT as well, so `results: []`
// alone is no longer the whole story a JSON consumer receives.
//
// This block previously read "rc=0 json=[]" for all three plus "the MACHINE-READABLE output
// says nothing at all". That was accurate when written and stopped being so in 33b1f44
// (#316, always emit stats in json and yaml). It is corrected rather than deleted because
// these are the sentences that get quoted, and prose that UNDERSTATES today's disclosure
// invites re-filing an issue that is already fixed (#385).
//
// One caveat still holds: stdout carries the count, not the file list. Per-file detail is
// stderr-only.
//
// These cases exist to gate a silent-failure class: a fix to that class needs a test that
// would have caught the silence, or the same class returns unnoticed.
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

	// IsGenuinelyClean marks a file that is NOT a failure and must therefore be scanned
	// normally. A 0-byte file contains no sensitive data, so "scanned, clean" is the correct
	// answer; reporting it as unexamined trains operators to ignore the warning that matters.
	//
	// This once had a companion KnownFalseAlarm field, because an empty file WAS reported as
	// not-scanned and the case was committed with a witness for the then-unfixed behaviour. The
	// behaviour was fixed and the field became unreachable: the test branch reading it could not
	// run, and the flag was left set to true on a case that no longer false-alarms. Both are
	// removed (#385). Measured at HEAD, a 0-byte file emits no files_not_examined count at all,
	// which is the correct answer.
	IsGenuinelyClean bool
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
