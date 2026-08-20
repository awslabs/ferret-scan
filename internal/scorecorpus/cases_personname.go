// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

// PERSON_NAME cases, positive and negative.
//
// The corpus had three PERSON_NAME positives and ZERO negatives, which made the
// validator's precision unmeasurable — and the first thing measuring it revealed was
// a false-positive population nobody had counted. On shipped code, ordinary business
// prose produces MEDIUM findings:
//
//	"Please review the Rich Text format."        -> Rich Text (67)
//	"The Grace Period expires Friday."           -> "The Grace" (67)
//	"Submit the Bill Rate by May Day."           -> Bill Rate (67), May Day (67)
//	"Frank Discussion about the Art Director."   -> Art Director (79), Frank Discussion (79)
//	"Deposit at Chase Bank today."               -> Chase Bank (67)
//	"Enjoy the Summer Sale on a Sunny Day."      -> Summer Sale (67), Sunny Day (67)
//
// At scale: 200 lines of business prose, a quarter of them containing such a phrase,
// yielded 43 MEDIUM findings. All false. Note "The Grace" — the article "The" is
// being captured as a given name.
//
// The mechanism is the database gate. A detection requires a hit in EITHER the
// first-name OR the last-name list, and "mark", "bill", "grace", "may", "art",
// "chase", "rich", "sunny" and "summer" are all first names. One hit is enough, so
// an English noun phrase whose leading word happens to be a given name passes.
//
// That same OR rule is why non-Anglo names are missed from the other direction: it
// under-covers surnames the list does not carry. Measured across 14 locales, overall
// coverage is 85.1%, but Turkish is 20% and Dutch, Japanese and African are 60%.
//
// These cases exist so both directions are gated before either is changed. A
// database expansion adds names, and without negatives an FP regression would be
// invisible.
var PersonNameCases = []Case{
	{
		Name:   "person_prose_multiple_locales",
		Origin: "authored 2026-08 for scorecorpus; every value verified against the real CLI",
		Rationale: "Names from the largest language communities, in ordinary prose. A person's " +
			"name is PII whatever its origin, and an undetected name is never redacted — so a " +
			"recall gap here is a cleartext leak that falls unevenly on people whose names the " +
			"tool's database does not carry.",
		Checks: []string{"PERSON_NAME"},
		Input: "Prepared by James Smith on Monday.\n" +
			"Reviewed by Maria Rodriguez in Madrid.\n" +
			"Approved by Priya Patel for the team.\n" +
			"Signed by Mohammed Ahmed at the branch.\n" +
			"Filed by Olga Petrova last quarter.\n" +
			"Checked by Minjun Kim this morning.\n",
		// MinBand records what the tool produces TODAY, not what it ought to produce.
		// Measured: the four Anglo/Hispanic/Indian/Arabic names reach 92 (HIGH) because
		// BOTH halves are in the name database; Olga Petrova and Minjun Kim reach only
		// 67 (MEDIUM) because just one half is. My first draft labelled all six HIGH and
		// the corpus rejected two of them — an aspirational label would have sat in the
		// band denominator forever, so the number it reports would never be reachable.
		//
		// That split is itself the finding: band follows database coverage, and database
		// coverage follows locale.
		Labels: []Label{
			{Line: 1, Value: "James Smith", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 2, Value: "Maria Rodriguez", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 3, Value: "Priya Patel", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 4, Value: "Mohammed Ahmed", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 5, Value: "Olga Petrova", Types: []string{"PERSON_NAME"}, MinBand: BandMedium},
			{Line: 6, Value: "Minjun Kim", Types: []string{"PERSON_NAME"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:   "person_locale_surnames_recovered",
		Origin: "promoted out of quarantine 2026-08-19 after the surname/first-name data fix; bands measured against the real CLI",
		Rationale: "Was person_locale_surnames_UNSUPPORTED. #282 diagnosed these as a DATA gap " +
			"rather than a pattern one — the surname gate rejected them because neither half was " +
			"in the name database — and recorded that the surname list was the fix. That data " +
			"landed, so the case is now asserted rather than quarantined.\n" +
			"Measured before and after, same fixture, same flags:\n" +
			"  Mehmet Yilmaz  0 -> 67 -> 92   |   Haruto Sato  0 -> 67 -> 92   |   Thabo Nkosi  0 -> 67 -> 92\n" +
			"The middle figure is the surname list alone; 92 needs the FIRST name too, which is " +
			"why both lists were extended. The Dutch particle line that used to sit in this case " +
			"moved to person_lowercase_particles_UNSUPPORTED, where it belongs: 'Piet de Vries' " +
			"fails on the lowercase particle, not on database coverage.",
		Checks: []string{"PERSON_NAME"},
		Input: "Prepared by Mehmet Yilmaz on Monday.\n" +
			"Reviewed by Haruto Sato in Osaka.\n" +
			"Approved by Thabo Nkosi for the team.\n",
		Labels: []Label{
			{Line: 1, Value: "Mehmet Yilmaz", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 2, Value: "Haruto Sato", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 3, Value: "Thabo Nkosi", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
		},
		Redactable: true,
	},
	{
		Name:   "fp__business_noun_phrases",
		Origin: "harvested from probes against shipped code, 2026-08",
		Rationale: "Capitalised business vocabulary whose FIRST word is also a given name: " +
			"mark, bill, grace, may, art, chase, rich, sunny, summer. The database gate accepts " +
			"a hit in EITHER list, so one given-name collision is enough and an ordinary noun " +
			"phrase is reported as a person. Measured at 67-79 confidence, i.e. MEDIUM — on the " +
			"default review surface, and blocking a pre-commit hook. 43 such findings in 200 " +
			"lines of business prose.",
		Checks: []string{"PERSON_NAME"},
		Input: "Please review the Rich Text format.\n" +
			"The Grace Period expires Friday.\n" +
			"Submit the Bill Rate by May Day.\n" +
			"Frank Discussion about the Art Director role.\n" +
			"Deposit at Chase Bank today.\n" +
			"Track the Miles Driven this quarter.\n" +
			"Enjoy the Summer Sale on a Sunny Day.\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:   "fp__function_word_before_a_real_surname",
		Origin: "harvested from probes against shipped code, 2026-08",
		Rationale: "An English function word in front of a GENUINE surname. This class is " +
			"invisible to the surname gate — grace, morgan, young and stone are all real " +
			"entries in the name database — because what fails is the pattern shape: " +
			"basic_western_name asks for two capitalised tokens of 2+ letters, and an " +
			"article satisfies that as well as a given name does. Measured: 49 of 49 " +
			"leading function words produced a finding at MEDIUM, and on a 1,388-file " +
			"real-world corpus 156 of 5,888 PERSON_NAME findings (2.6%) had this shape, " +
			"spanning 43 distinct leading words.",
		Checks: []string{"PERSON_NAME"},
		Input: "The Grace Period expires Friday.\n" +
			"Their Morgan account was closed.\n" +
			"Via Morgan we shipped the order.\n" +
			"Please review Every Stone carefully.\n" +
			"This Young cohort was surveyed.\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:   "person_function_word_collisions",
		Origin: "authored 2026-08 for scorecorpus; every value verified against the real CLI",
		Rationale: "Real names whose GIVEN half is also an English function word: the modals " +
			"will and may, the article an, the pronoun he. The function-word filter is a word " +
			"list, so it necessarily collides with real people, and the name database has to " +
			"arbitrate. Pinned as POSITIVES because the failure mode is a cleartext leak: an " +
			"unreported name is never handed to the redactor. Mutation-proven — removing the " +
			"database deference compiles and drops all four to zero findings.",
		Checks: []string{"PERSON_NAME"},
		Input: "Signed by Will Smith today.\n" +
			"Approved by May Chen this morning.\n" +
			"Filed by An Nguyen last week.\n" +
			"Reviewed by He Zhang in Beijing.\n",
		// Measured: Will Smith and May Chen reach 92 because both halves are in the
		// database; An Nguyen and He Zhang reach 67 because only the surname is.
		Labels: []Label{
			{Line: 1, Value: "Will Smith", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 2, Value: "May Chen", Types: []string{"PERSON_NAME"}, MinBand: BandHigh},
			{Line: 3, Value: "An Nguyen", Types: []string{"PERSON_NAME"}, MinBand: BandMedium},
			{Line: 4, Value: "He Zhang", Types: []string{"PERSON_NAME"}, MinBand: BandMedium},
		},
		Redactable: true,
	},
	{
		Name:   "fp__document_structure_vocabulary",
		Origin: "authored 2026-08 for scorecorpus; behavior verified against the real CLI",
		Rationale: "Capitalised document and org vocabulary that is currently silent, pinned so " +
			"it STAYS silent. These are the cases the database gate earns its keep on: none of " +
			"section/table/customer/project/general/human/control/release/privacy is in either " +
			"name list. A future expansion that added any of them as a surname would turn every " +
			"one of these lines into a finding, which is exactly the regression this case exists " +
			"to catch.",
		Checks: []string{"PERSON_NAME"},
		Input: "Please review Section Three now.\n" +
			"See Table Four for details.\n" +
			"Contact Customer Service today.\n" +
			"The Project Manager approved it.\n" +
			"Filed under General Ledger yesterday.\n" +
			"Sent to Human Resources.\n" +
			"Open the Control Panel now.\n" +
			"Check the Release Notes please.\n" +
			"Read the Privacy Policy first.\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:   "fp__eponym_technical_terms",
		Origin: "authored 2026-08 for scorecorpus; behavior verified against the real CLI",
		Rationale: "Scientific terms that ARE people's surnames: van der Waals, von Neumann, " +
			"de Morgan, le Chatelier. Structurally identical to a real particle name, so any " +
			"particle-aware pattern will match them. Currently silent, and pinned as a negative " +
			"because a naive fix for the missing-particle recall gap would light all four up. " +
			"They are also not the PII the tool exists to find: a long-dead scientist named in a " +
			"formula is public vocabulary, not a data subject.",
		Checks: []string{"PERSON_NAME"},
		Input: "The van der Waals force is weak.\n" +
			"Discussed von Neumann architecture today.\n" +
			"Applied de Morgan's law here.\n" +
			"The le Chatelier principle applies.\n" +
			"Reviewed the van Hove singularity.\n",
		Negative:   true,
		Redactable: true,
	},
	{
		Name:   "fp__latin_and_prose_particles",
		Origin: "authored 2026-08 for scorecorpus; behavior verified against the real CLI",
		Rationale: "Lowercase particles in non-name usage: de novo, de facto, la Poste, and a " +
			"hyphen-split verb. Pinned as negatives so a fix for the missing-particle recall gap " +
			"cannot reach ordinary prose. The distinguishing structure is that no capitalised " +
			"GIVEN name precedes the particle here, which is what a correct pattern must require.",
		Checks: []string{"PERSON_NAME"},
		Input: "See Figure 3 de novo synthesis.\n" +
			"Please review Section de Facto rules.\n" +
			"We shipped via la Poste yesterday.\n" +
			"The flight will de part at noon.\n",
		Negative:   true,
		Redactable: true,
	},
}

// PersonNameQuarantine holds name shapes the validator cannot satisfy today.
//
// Counted and printed, never scored: a label the tool cannot satisfy would sit in
// the recall denominator forever. The count is baselined, so moving a case in or out
// changes a number and fails until explained.
var PersonNameQuarantine = []Case{
	{
		Name:   "person_lowercase_particles_UNSUPPORTED",
		Origin: "authored 2026-08 for scorecorpus; measured against the real CLI",
		Rationale: "Surnames with a lowercase nobiliary particle are NOT detected: de la Cruz, " +
			"dos Santos, van der Berg, von Mises, de Vries, van den Heuvel, al-Rashid, El-Sayed. " +
			"Isolated to prove the particle is the sole cause — capitalising it works and the " +
			"correct lowercase form does not:\n" +
			"  \"Ana de la Cruz\" -> NONE   |   \"Ana De La Cruz\" -> 94   |   \"Ana Cruz\" -> 92\n" +
			"Measured 0 of 4 Dutch/German, 1 of 4 Arabic, 0 of 3 Hispanic-with-particle. Roughly " +
			"a quarter of Dutch surnames carry one. An undetected name is never redacted, so this " +
			"is a cleartext leak concentrated on non-Anglo names.\n" +
			"Quarantined rather than labelled because the fix is not a pattern change alone: a " +
			"particle-aware regex also matches the eponym negatives above, so it needs the " +
			"surname-anchored gate underneath it.\n" +
			"As of 2026-08-19 this case owns the Dutch particle line exclusively: the surname " +
			"data gap it used to share with person_locale_surnames_UNSUPPORTED is closed, and " +
			"that case was promoted to person_locale_surnames_recovered. What remains here is " +
			"purely the lowercase particle.",
		Checks: []string{"PERSON_NAME"},
		Input: "Signed by Ana de la Cruz.\n" +
			"Signed by Carlos dos Santos.\n" +
			"Signed by Jan van der Berg.\n" +
			"Signed by Piet de Vries.\n" +
			"Signed by Mohammed al-Rashid.\n",
		Redactable: true,
	},
}
