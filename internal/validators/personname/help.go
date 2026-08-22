// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import "github.com/awslabs/ferret-scan/v2/internal/help"

// GetCheckInfo returns standardized information about the person name check
func (v *Validator) GetCheckInfo() help.CheckInfo {
	return help.CheckInfo{
		Name:             "PERSON_NAME",
		ShortDescription: "Detects human names using pattern matching and name databases",
		DetailedDescription: `The Person Name check detects human names in documents using a combination of pattern matching and embedded name database lookups.

It identifies various name formats including first and last names, names with titles (Mr./Ms./Dr.), names with suffixes (Jr./Sr./III), and names with middle initials. The validator uses an embedded database of ~5,200 common first names and ~2,100 surnames with database-first optimization for 98% performance improvement.

A name is reported only when its SURNAME is confirmed by the database, or when a title or generational suffix explicitly states that the tokens are a person's name. A name admitted on that marker alone is capped inside MEDIUM, so it always reaches review and redaction but never outranks a database-confirmed name.

The check analyzes surrounding context to distinguish between person names and business/product names. It applies confidence adjustments based on contextual keywords, validates names against common test data patterns, and includes enhanced technical context detection for reduced false positives.

**Supported Name Patterns:**
- **Basic Names** - First and last name (e.g., "John Smith")
- **Names with Titles** - Formal titles before names (e.g., "Dr. Jane Doe")
- **Names with Suffixes** - Generational suffixes (e.g., "Robert Johnson Jr.")
- **Names with Middle Initials** - Middle initial format (e.g., "Mary J. Watson")
- **Multiple Names** - Three or more name components (e.g., "Mary Jane Watson")
- **Hyphenated Names** - Hyphenated last names (e.g., "Sarah Smith-Jones")
- **Names with Apostrophes** - Cultural variations (e.g., "Patrick O'Connor")
- **Names with a Nobiliary Particle** - A connective inside a multi-word surname, in either spelling (e.g., "Ana de la Cruz", "Dr. Marco Di Salvo")
- **Two-Column Table Rows** - A name split across adjacent table cells (e.g., a "First Name / Last Name" spreadsheet row). Requires BOTH tokens to be database-confirmed, because a tab is a column boundary rather than a word space

**Deliberately Not Reported:**
- **Routing words** - A salutation or memo header in front of a name is excluded from the reported value, so "Attn Marcus Whitfield" reports "Marcus Whitfield" rather than nothing or the whole string
- **Font family names** - Document formatting such as "Times New Roman" or "Arial Black", matched as a whole phrase only, so a person named Roman or Black is unaffected
- **Leading function words** - An article, pronoun or preposition before a real surname ("The Grace", "Via Morgan"), unless the name database recognizes the word as a name itself ("Will Smith", "May Chen")

**Cultural Support:**
Beyond Western First/Last forms, the validator recognizes multi-word surnames carrying a nobiliary or patronymic particle — Dutch and German (van, von, van der, van den), Iberian (de, del, de la, dos, das), Italian (di, della, dal) and Arabic (bin, bint, ibn, al) — in both the lowercase and capitalized spellings. A particle attached to the surname by a HYPHEN (al-Rashid, El-Sayed) is not yet matched. It includes recognition of common titles, suffixes, and name structures used in English-speaking countries.`,

		Patterns: []string{
			"First Last (e.g., John Smith)",
			"Title First Last (e.g., Dr. Jane Doe)",
			"First Middle Last (e.g., Mary Jane Watson)",
			"First M. Last (e.g., John M. Smith)",
			"First Last Suffix (e.g., Robert Johnson Jr.)",
			"First Hyphenated-Last (e.g., Sarah Smith-Jones)",
			"First O'Last (e.g., Patrick O'Connor)",
			"First particle Last (e.g., Ana de la Cruz, Ludwig van Beethoven)",
			"Title First particle Last (e.g., Dr. Marco Di Salvo)",
			"First<TAB>Last across two table columns (e.g., a First Name / Last Name spreadsheet row)",
		},

		SupportedFormats: []string{
			"Western name patterns (First Last)",
			"Names with academic/professional titles (Dr., Prof., Mr., Ms., Mrs.)",
			"Names with generational suffixes (Jr., Sr., III, IV)",
			"Names with middle initials or full middle names",
			"Hyphenated surnames and compound names",
			"Names with apostrophes (Irish, French origins)",
			"Multiple first names or compound first names",
			"Multi-word surnames with a nobiliary or patronymic particle, lowercase or capitalized (Dutch, German, Iberian, Italian, Arabic)",
			"Names split across two adjacent table or spreadsheet columns",
		},

		ConfidenceFactors: []help.ConfidenceFactor{
			{Name: "Database-First Check", Description: "Performance optimization: Names checked against database before pattern matching (98% faster)", Weight: 0},
			{Name: "Pattern Match", Description: "Must match valid name pattern", Weight: 15},
			{Name: "Known First Name", Description: "First name found in database (~5.2K names)", Weight: 25},
			{Name: "Known Last Name", Description: "Last name found in database (~2.1K names)", Weight: 20},
			{Name: "Proper Capitalization", Description: "Names must be properly capitalized", Weight: 15},
			{Name: "Reasonable Length", Description: "Names should be 4-60 characters", Weight: 10},
			{Name: "Not Test Data", Description: "Must not match test/placeholder patterns", Weight: 35},
			{Name: "Not Business Name", Description: "Must not contain business indicators", Weight: 25},
			{Name: "Not Technical Context", Description: "Technical terms (API, function, method) reduce confidence", Weight: 15},
			{Name: "Title Present", Description: "Formal titles increase confidence", Weight: 5},
			{Name: "Suffix Present", Description: "Generational suffixes increase confidence", Weight: 3},
		},

		PositiveKeywords: v.positiveKeywords,
		NegativeKeywords: v.negativeKeywords,

		ConfigurationInfo: `The Person Name validator works out-of-the-box with embedded name databases and requires no additional configuration.

**Performance Characteristics:**
- Memory usage: <5MB (embedded compressed databases)
- Initialization time: <200ms (one-time decompression)
- Lookup performance: ~2 microseconds per name (database-first optimization)
- Early exit: ~100 nanoseconds for non-matches (98% performance improvement)

**Context Analysis:**
The validator analyzes surrounding text for contextual clues:
- Positive contexts: employee lists, contact forms, directories, email signatures
- Negative contexts: product catalogs, technical documentation, business names

**Cross-Validator Integration:**
Works with other validators to improve accuracy:
- Email addresses near names boost confidence
- Phone numbers in context increase likelihood
- Metadata fields (author, creator) provide strong signals`,

		Examples: []string{
			"ferret-scan --file employee-directory.csv --checks PERSON_NAME",
			"ferret-scan --file contact-list.txt --checks PERSON_NAME --verbose",
			"ferret-scan --file documents/ --recursive --checks PERSON_NAME --confidence high",
			"ferret-scan --file medical-records.pdf --checks PERSON_NAME,EMAIL --format json",
		},
	}
}
