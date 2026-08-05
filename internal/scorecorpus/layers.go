// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

// The four layers this package scores, and why one number per layer is not enough.
//
// A labelled value passes through four independent stages before the user is
// protected, and EACH can fail while the others look perfect. Measured on main:
//
//	layer        a regression that moves ONLY this layer
//	----------   ----------------------------------------------------------------
//	validator    a "fixed-width report noise" veto: recall 111->108 TP.
//	             The whole 65-package suite still passes at rc=0.
//	redaction    reverting PR #250: detection is BIT-IDENTICAL (111 TP, 0 FN,
//	             precision 0.7097) and the SSN survives in word/document.xml.
//	suppression  a suppression rule silences a finding: the validator still
//	             detects it, the redactor never sees it, output says clean.
//	executable   the CLI exit code: the same finding at confidence 60 gives
//	             rc=0 under FERRET_PRECOMMIT_EXIT_ON=high and rc=1 under =medium,
//	             so a band drop silently stops blocking a commit.
//
// Scoring only the validator layer would have certified two of those four as
// harmless. So the gate reports and ratchets each layer separately rather than
// collapsing them into one precision/recall pair.
type Layer string

const (
	// LayerValidator is detection: did the validator report the labelled value,
	// with an acceptable type, at or above its expected band?
	LayerValidator Layer = "validator"

	// LayerRedaction is the sink: after redaction, is the value's byte sequence
	// gone from the artifact? This is the layer that answers "was the user
	// actually protected", and it is measured by reading the output file, never by
	// trusting a reported count.
	LayerRedaction Layer = "redaction"

	// LayerSuppression is the filter: a suppression rule must silence exactly the
	// finding it names and nothing else. Over-broad suppression is a leak with an
	// audit trail that says everything is fine.
	LayerSuppression Layer = "suppression"

	// LayerExecutable is the end-to-end binary: the same corpus driven through the
	// real CLI, checking the exit code and that the reported findings match the
	// in-process score. A library that scores perfectly behind a CLI that prints
	// nothing (or exits 0 on a blocking finding) protects no one — both have
	// shipped here before.
	LayerExecutable Layer = "executable"
)

// AllLayers is the scoring order, cheapest first.
var AllLayers = []Layer{LayerValidator, LayerRedaction, LayerSuppression, LayerExecutable}
