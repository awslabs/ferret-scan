// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package medicalid

import "testing"

// This file is a PRECISION BASELINE, not a feature.
//
// #533 asks that an OMOP CDM export's `person_id` be admitted as an MRN. It is a real gap and a real
// leak: an OMOP `person` export reports 0 MEDICAL_ID findings, `--enable-redaction` writes no file at
// all, and the exit code is 0, so the patient key stays cleartext. The same synthetic value in an Epic
// Clarity layout (`PAT_ID,PAT_MRN_ID,…`) reports at 90 — measured, and asserted below as the control.
//
// TestOMOPGenericIdentifierColumnsStayUnadmitted already records why the obvious fix is refused:
// `person_id` is a generic surrogate key, and admitting the NAME would make every `person_id` column in
// every schema a medical context. It also names the only direction that could work — a TABLE-level
// signal, such as a sibling column called `care_site_id` or `visit_concept_id`.
//
// # Why this corpus exists
//
// That table-level rule was implemented once and REJECTED, not on review but on measurement. It passed
// every acceptance case #533 listed, and then fired at HIGH/90 on 17 of 17 constructed non-clinical
// schemas — and with `--enable-redaction` it would have REWRITTEN those files, where the baseline wrote
// nothing. A false positive that only reports is a nuisance; one that rewrites the operator's data is
// damage.
//
// The specific traps, because they are what any future design has to clear:
//
//   - `concept_id` is not clinical vocabulary. It is the standard identifier name in every terminology
//     service, ontology and ML feature store.
//   - `observation_period` is ordinary statistics, actuarial and ecology English.
//   - Substring matching turned "care_site" into a match for `daycare_site_id`. Any admitting
//     vocabulary must match on WORD BOUNDARIES.
//   - `observation_fact` is an i2b2 TABLE name and can never appear as a column, so a vocabulary entry
//     for it is dead code wearing a guard's clothes.
//
// So this file commits the attack corpus as a permanent gate, ahead of any rule that would need it.
// Every row asserts the CURRENT behaviour, which is silence, so the file is green at HEAD and changes
// no behaviour. Its value is that a later table-level signal cannot be merged while turning any of
// these into a finding — the failure the previous attempt shipped into review.
//
// See also [[passing-the-issues-tests-is-not-evidence]]: the acceptance list in an issue tests the
// design's own assumptions, because its must-not-fire cases have neither signal and its must-fire cases
// have both. Nothing in it probes the region where one signal is present and the data is not clinical,
// which is the entire failure surface.

// nonClinicalSchemas are plausible tables from other domains that reuse the vocabulary an OMOP-shaped
// clinical signal would key on: person/subject keys, `concept_id`, `observation_period`, visit and site
// columns. Every one must report zero MRNs.
//
// The value 4471926 is a synthetic 7-digit number in every row, so a rule that keys on value SHAPE
// alone cannot pass this corpus either.
var nonClinicalSchemas = []struct {
	domain  string
	content string
}{
	{"education / LMS",
		"person_id,concept_id,curriculum_year,mastery_score,teacher_id\n4471926,8507,1974,88,12\n"},
	{"ML feature store",
		"subject_id,concept_id,feature_version,observation_period,drift_score\n4471926,8507,3,90,0.02\n"},
	{"knowledge graph / ontology",
		"concept_id,person_id,predicate,object_id,confidence\n8507,4471926,broader,9911,0.91\n"},
	{"hotel reservations",
		"person_id,visit_id,site_id,check_in,room_concept_id\n4471926,55,12,2026-01-04,8507\n"},
	{"support tickets",
		"person_id,visit_count,site_id,first_seen,resolution_concept_id\n4471926,3,12,2026-01-04,8507\n"},
	{"actuarial exposure",
		"person_id,observation_period,exposure_years,claim_count,cohort_id\n4471926,90,7,2,12\n"},
	{"childcare attendance",
		"person_id,daycare_site_id,visit_date,guardian_id,concept_id\n4471926,12,2026-01-04,7781,8507\n"},
	{"game telemetry",
		"person_id,session_id,visit_concept_id,level_reached,site_id\n4471926,9,8507,42,12\n"},
	{"XBRL financial facts",
		"person_id,concept_id,period_start,period_end,fact_value\n4471926,8507,2026-01-01,2026-12-31,55\n"},
	{"ecology field survey",
		"subject_id,observation_period,site_id,species_concept_id,count\n4471926,90,12,8507,17\n"},
	{"HR headcount",
		"person_id,site_id,visit_date,cost_centre,role_concept_id\n4471926,12,2026-01-04,CC12,8507\n"},
	{"library circulation",
		"person_id,item_id,visit_date,branch_site_id,subject_concept_id\n4471926,55,2026-01-04,12,8507\n"},
	{"retail loyalty",
		"person_id,visit_count,store_site_id,last_visit,tier_concept_id\n4471926,9,12,2026-01-04,8507\n"},
	{"transit ridership",
		"person_id,trip_id,station_site_id,observation_period,fare_concept_id\n4471926,55,12,90,8507\n"},
	{"agricultural trials",
		"subject_id,plot_site_id,observation_period,treatment_concept_id,yield\n4471926,12,90,8507,3.4\n"},
	{"sports analytics",
		"person_id,match_id,venue_site_id,minutes_played,position_concept_id\n4471926,55,12,90,8507\n"},
	{"survey research",
		"person_id,wave_id,observation_period,item_concept_id,response\n4471926,3,90,8507,4\n"},
	// Plus the two shapes the rejected design got wrong for structural reasons rather than vocabulary.
	{"generic table, no clinical siblings at all",
		"person_id,email,created_at\n4471926,a@example.com,2026-01-01\n"},
	{"same-line prose, no table at all",
		"person_id: 4471926\n"},
}

// TestNonClinicalSchemasReportNoMRN locks in the precision half.
//
// A table-level clinical signal is the only viable direction for #533, and this is the corpus it has to
// clear. Each row is green at HEAD, so this asserts current behaviour and changes nothing; it exists so
// that a later rule cannot quietly turn these into findings.
func TestNonClinicalSchemasReportNoMRN(t *testing.T) {
	for _, c := range nonClinicalSchemas {
		got := mrnFindings(t, c.content)
		if len(got) != 0 {
			t.Errorf("%s: reported %d MRN value(s) at %v\n"+
				"This schema is NOT clinical. It reuses the vocabulary an OMOP-shaped signal keys on — "+
				"person/subject keys, concept_id, observation_period, visit and site columns — which is "+
				"exactly why the previous attempt at #533 was rejected: it fired on 17 of 17 such "+
				"schemas at HIGH/90, and under --enable-redaction it would have REWRITTEN them.\n"+
				"If a table-level clinical signal is being added, it must require a COUNT of clinical "+
				"markers rather than the presence of one, match on WORD BOUNDARIES (\"care_site\" as a "+
				"substring matches daycare_site_id), and be checked against the header spellings "+
				"tabular.NormalizeHeader actually produces.", c.domain, len(got), got)
		}
	}
}

// TestARealClinicalLayoutStillReports is the non-vacuity floor beneath the corpus above.
//
// Nineteen assertions that something reports NOTHING would pass just as well if the validator were
// broken, or if mrnFindings were mis-keyed. This proves the probe is live using the SAME synthetic value
// the corpus uses, in a layout real EHRs actually emit.
func TestARealClinicalLayoutStillReports(t *testing.T) {
	// Epic Clarity: the column name says medical record number, so no table-level inference is needed.
	const epic = "PAT_ID,PAT_MRN_ID,BIRTH_DATE\n99,4471926,1974-03-02\n"

	got := mrnFindings(t, epic)
	if len(got) == 0 {
		t.Fatal("an Epic Clarity layout carrying the same synthetic value reported no MRN. Every " +
			"assertion in TestNonClinicalSchemasReportNoMRN is then vacuous — a validator that reports " +
			"nothing passes all of them.")
	}
	if _, ok := got["4471926"]; !ok {
		t.Errorf("reported %v, but not the value the non-clinical corpus uses; the two are no longer "+
			"comparable and the corpus proves less than it appears to", got)
	}
}

// TestTheOMOPGapIsStillOpen states the DEFECT as a fact rather than leaving it implicit.
//
// This is deliberately an assertion on the current, WRONG behaviour. #533 is open: an OMOP export's
// patient key is not reported, so it is never redacted. When a fix lands, this test FAILS — and that is
// the point. It has to be inverted deliberately, in the same change that makes the corpus above still
// pass, which is the pairing the rejected attempt lacked.
func TestTheOMOPGapIsStillOpen(t *testing.T) {
	const omopPerson = "person_id,gender_concept_id,year_of_birth,person_source_value,care_site_id\n" +
		"4471926,8507,1974,4471926,12\n"

	got := mrnFindings(t, omopPerson)
	if len(got) != 0 {
		t.Errorf("an OMOP CDM person export now reports %d MRN value(s) at %v — #533 appears FIXED.\n"+
			"That is good news, and this test must be inverted in the same change: assert the OMOP "+
			"layouts report, and confirm TestNonClinicalSchemasReportNoMRN is still green. Do not "+
			"delete this test; flip it, so the pairing that the previous attempt lacked is preserved.",
			len(got), got)
	}
	t.Logf("OMOP person export reports %d MRN findings (the #533 gap, unfixed at this commit)", len(got))
}
