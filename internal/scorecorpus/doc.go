// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scorecorpus scores detection QUALITY against a hand-labelled corpus:
// precision, recall, and how much of a labelled value survives redaction.
//
// It is the complement of internal/goldencorpus, not a replacement. That package
// snapshots output bytes and says so explicitly: "The purpose is NOT to assert
// that any particular detection is 'correct' — it is to assert that detection,
// confidence scoring, output formats, and redaction do not CHANGE." A golden diff
// therefore answers "did anything move?", never "did it move the right way". This
// package answers the second question, so a change that trades a real detection
// for a quieter report fails here even when every golden file still matches.
//
// # Why the score is three numbers per check and not one
//
// A single precision/recall pair is blind to the failure this tool actually ships.
// Measured on main, three separate regressions:
//
//	mutation                          full suite   detection      redaction sink
//	fixed-width veto before the regex rc=0, 64 ok  111->108 TP    3 whole leaks
//	revert PR #250 (Office redactor)  rc=1         IDENTICAL      1 container leak
//	band-demote a bare 9-digit SSN    rc=0, 64 ok  recall_all =   no leak
//
// Row two is the reason this package exists: reverting a real cleartext-leak fix
// leaves the detection score bit-for-bit identical, because the finding was
// reported correctly and then dropped during redaction. Rows one and three pass
// the entire test suite today. So:
//
//   - RecallAll counts every band. This is the REDACTION surface, which is
//     confidence-blind: a LOW finding is still written to the redacted file
//     (measured: a bare 9-digit SSN at confidence 50 redacts to *****5728).
//     A label that stops being found at all is a value the redactor never sees,
//     which is a cleartext leak — so this floor is hard.
//   - RecallHM counts >= MEDIUM only. This is the PRE-COMMIT EXIT CODE surface,
//     the one a band drop actually moves: the same finding at confidence 60 gives
//     rc=0 under FERRET_PRECOMMIT_EXIT_ON=high and rc=1 under =medium.
//   - The sink metrics (WholeLeak, Residue4) drive core.RedactFile and measure
//     what bytes of the labelled value survive in the artifact. This is the only
//     signal that moves for row two.
//
// # What this package deliberately does NOT prove
//
// The corpus is hand-labelled, so a WRONG label is invisible to every test here;
// only review catches that. Each case therefore carries Origin and Rationale, and
// TestEveryLabelIsSatisfiedToday refuses labels that no version of the tool has
// ever satisfied, so the recall denominator cannot be padded with aspirations.
//
// It is also synthetic and commit-safe, which is not the same as representative.
// Scoring real documents (TEST_PLAN dimension 9) still requires the manual,
// un-committable measurement described there.
//
// Some baselined numbers record BUGS, not goals: the 45 high-confidence false
// positives from non-SSN column headers are real defects captured so a later fix
// can be measured. A baseline is a floor to ratchet, never a statement of intent.
package scorecorpus
