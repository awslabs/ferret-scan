// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package personname

import (
	"regexp"
	"strings"
)

// NamePattern represents a compiled regex pattern with metadata
type NamePattern struct {
	Pattern     *regexp.Regexp
	Name        string
	Description string
	Priority    int
	Cultural    []string // Cultural contexts where this pattern is common
}

// Latin letter character classes used to build name patterns.
//
// The previous patterns used [A-ZÀ-ÿ] / [a-zà-ÿ]. Those have two problems:
//  1. A leading/trailing ASCII \b does not fire next to an accented letter, so
//     names starting with an accented capital (Ángel, Óscar) never matched and
//     names ending in an accent (José) were truncated ("Jos").
//  2. The range À-ÿ wrongly includes U+00D7 (×) and U+00F7 (÷), which are math
//     symbols, not letters.
//
// We therefore use explicit Latin-1 letter ranges that exclude × and ÷, and
// build word boundaries by consuming a non-letter (or string edge) on each side
// via wrapNamePattern (RE2 has no look-around), capturing the actual name in
// group 1.
const (
	nameUpper  = `A-ZÀ-ÖØ-Þ` // Latin-1 uppercase letters (excludes × at U+00D7)
	nameLower  = `a-zß-öø-ÿ` // Latin-1 lowercase letters (excludes ÷ at U+00F7)
	nameLetter = nameUpper + nameLower
)

// nameSpace is the separator allowed BETWEEN the tokens of one name: a run of
// ordinary spaces.
//
// It deliberately excludes the tab, which the `\s+` these patterns used to use
// would accept. A tab is a column boundary in extracted table and spreadsheet
// content, not a word space, so `\s+` glued two adjacent cells into a single
// "name". Measured over 714 real Office/PDF documents before this change: 95 of
// 1931 PERSON_NAME findings (4.9%) spanned a tab and 32 of those presented as
// HIGH — a two-column table row "Preventative<TAB>Strong" scored 100, and
// "Financial Services<TAB>Washington" scored 100, because the second cell
// happened to hold a real surname.
//
// The tab still separates: wrapNamePattern's boundary class is "not a letter",
// so a tab bounds a name rather than joining two. \n cannot appear here at all —
// ValidateContentCtx splits content on newlines before these patterns run — and
// \f/\r are excluded for the same reason as the tab.
//
// A genuine "First Name | Last Name" two-column row does exist, and excluding
// the tab here would make it unreportable. tabSeparatedNamePattern below keeps
// that shape reachable on stricter evidence rather than on the tab alone.
const nameSpace = `[ ]+`

// nameTabSpace is a separator run containing at least one tab, used only by
// tabSeparatedNamePattern. It tolerates spaces around the tab so a padded cell
// boundary ("Marcus \t Holloway") is still one candidate.
const nameTabSpace = `[ ]*\t[ \t]*`

// tabSeparatedNamePattern is the one pattern whose tokens may be separated by a
// tab. Because a tab is a column boundary, the shape "X<TAB>Y" is far weaker
// evidence of a name than "X Y" is, so findNamesInLine requires BOTH tokens to
// be database-confirmed for this pattern alone (see requiresBothNamesKnown).
// Every other pattern keeps the surname-only bar documented in
// CalculateConfidenceWithComponents.
const tabSeparatedNamePattern = "tab_separated_name"

// wrapNamePattern turns a "core" name pattern into a boundary-anchored pattern
// with the name captured in group 1. The leading/trailing groups consume a
// non-letter character (or the string start/end) so the match does not run into
// an adjacent word, while correctly handling accented letters that ASCII \b
// cannot. Callers must read submatch group 1 (see FindMatches).
func wrapNamePattern(core string) string {
	return `(?:^|[^` + nameLetter + `])(` + core + `)(?:[^` + nameLetter + `]|$)`
}

// nameParticle matches a nobiliary or patronymic particle — the connective inside a
// multi-word surname (van Beethoven, von Bismarck, de Silva, Di Salvo, bin Salman).
//
// Every other pattern here requires each name token to begin with a capital, so a
// lowercase particle terminated the match: "Dr. Ludwig van Beethoven" produced no
// candidate at all, and the title marker that would have admitted the off-list
// surname never got the chance to apply. Capitalised spellings are accepted on the
// same footing because English usage varies ("Di Salvo", "Van Damme", "De Luca"), and
// a capitalised particle caused the mirror-image defect: name_with_title claimed
// "Dr. Marco Di" and left "Salvo" out of the reported value.
//
// The set is closed and small on purpose. "of" and "and" are deliberately absent:
// they are ordinary English function words, and admitting them would match
// "Institute of Technology". Even for the particles listed, the surname bar in
// CalculateConfidenceWithComponents still applies, so "Ministerio de Educación" is
// rejected on the surname rather than on the particle.
const nameParticle = `(?:[Vv]an|[Vv]on|[Dd]ell[ao]|[Dd]el|[Dd]en|[Dd]er|[Dd]es|[Dd]os|[Dd]as|[Dd]al|[Dd]e|[Dd]a|[Dd]i|[Dd]o|[Dd]u|[Tt]en|[Tt]er|[Ll]a|[Ll]e|[Ee]l|[Aa]l|[Bb]int|[Bb]in|[Ii]bn)`

// nameParticleRun allows one or two particles so the common compounds are matched in
// full: "de la Cruz", "van der Berg", "van den Broek".
const nameParticleRun = `(?:` + nameParticle + nameSpace + `){1,2}`

// requiresBothNamesKnown reports whether a pattern's candidates must have BOTH a
// database-confirmed given name and a database-confirmed surname, rather than the
// surname-only bar that CalculateConfidenceWithComponents applies to the rest.
//
// Two patterns need it, for the same underlying reason — the shape they match is
// something document text produces on its own, so the surname alone is not enough to
// tell a name from a coincidence:
//
//   - tab_separated_name: its tokens sit in different table columns, so their
//     adjacency is a layout artefact rather than evidence that they form one name.
//
//   - name_with_particle: a lowercase particle between two capitalised words is
//     ordinary prose as often as it is a name. "Discussed von Neumann architecture"
//     and "Applied de Morgan's law" both have a genuine surname after the particle,
//     and both are eponyms rather than data subjects. Requiring the GIVEN half to be
//     a known name is what separates them from "Ana de la Cruz", and it is what the
//     fp__latin_and_prose_particles corpus case prescribes.
//
// The titled variant is deliberately NOT here. Its title is an explicit statement
// that the following tokens name a person, which is evidence the database cannot
// supply — that is the whole reason "Dr. Ludwig van Beethoven" is reportable when
// the surname is off-list. Nothing writes "Dr. Applied de Morgan".
func requiresBothNamesKnown(patternName string) bool {
	switch patternName {
	case tabSeparatedNamePattern, "name_with_particle":
		return true
	}
	return false
}

// PatternManager manages name detection patterns
type PatternManager struct {
	patterns []NamePattern
}

// NewPatternManager creates a new pattern manager with compiled patterns
func NewPatternManager() *PatternManager {
	pm := &PatternManager{}
	pm.compileAllPatterns()
	return pm
}

// compileAllPatterns compiles all name detection patterns
func (pm *PatternManager) compileAllPatterns() {
	patternDefinitions := []struct {
		name        string
		pattern     string
		description string
		priority    int
		cultural    []string
	}{
		{
			name:        "basic_western_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Basic Western name format: First Last (minimum 2 chars each)",
			priority:    5,
			cultural:    []string{"western", "english", "european"},
		},
		{
			// A name split across two table columns: "First Name | Last Name".
			//
			// This is the only pattern that may span a tab, and it exists so that
			// excluding the tab from nameSpace does not silently drop a real
			// two-column roster row. It is the weakest candidate finder here — a tab
			// says the two tokens are in DIFFERENT cells, which is evidence against a
			// name relationship, not for it — so requiresBothNamesKnown demands a
			// database hit on BOTH tokens rather than the usual surname-only bar.
			//
			// Measured over 714 real Office/PDF documents: 95 tab-spanning findings
			// (44 distinct values) were reported before this change, and in 94 of the
			// 95 the left-hand token was not a known given name ("Closed<TAB>Cook",
			// "Project<TAB>Sun", "Preventative<TAB>Strong"), so the both-known bar
			// removes them while keeping "Marcus<TAB>Holloway" reportable.
			name:        tabSeparatedNamePattern,
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameTabSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name split across two table columns: First<TAB>Last",
			priority:    2,
			cultural:    []string{"tabular", "database"},
		},
		{
			name: "all_caps_name",
			// ALL-CAPS names (JOHN SMITH, GRACE HILL) are common in forms,
			// spreadsheets and legal records but never matched the Title-case
			// patterns. This pattern surfaces them, but it is only a candidate
			// finder: CalculateConfidenceWithComponents still requires a name-DB
			// hit (lowercasing the tokens), so non-name all-caps prose ("ERROR
			// CODE", "TODO FIXME") is rejected, and the common-word-bigram gate
			// keeps DB-colliding word pairs out of the HIGH bucket. Low priority —
			// all-caps is weaker evidence than mixed-case.
			pattern:     `[` + nameUpper + `]{2,30}` + nameSpace + `[` + nameUpper + `]{2,30}`,
			description: "All-caps name: FIRST LAST",
			priority:    3,
			cultural:    []string{"western", "formal"},
		},
		{
			name:        "name_with_middle_initial",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `]\.` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with middle initial: First M. Last",
			priority:    7,
			cultural:    []string{"western", "american"},
		},
		{
			name:        "name_with_title",
			pattern:     `(?:Mr|Ms|Mrs|Dr|Prof|Sir|Dame|Lord|Lady)\.` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with title: Dr. First Last",
			priority:    8,
			cultural:    []string{"western", "formal"},
		},
		{
			name: "name_with_suffix",
			// Bare single-letter "V" was dropped from the suffix alternation: as a
			// lone Roman numeral it matched ordinary "First Last Vword" triples
			// ("Grace Park Verified") far more often than a real generational
			// suffix. Jr/Sr/III/IV plus the academic suffixes cover the common
			// cases; wrapNamePattern supplies the trailing boundary that stops
			// "IV"/"III" matching inside "IVory"/"IIIumination".
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `(?:Jr\.?|Sr\.?|III|IV|PhD|MD|Esq\.?)`,
			description: "Name with suffix: First Last Jr.",
			priority:    8,
			cultural:    []string{"western", "american", "academic"},
		},
		{
			// "Ludwig van Beethoven", "Maria de la Cruz", "Ahmed bin Salman".
			//
			// Priority sits with three_part_name: this is the same three-token shape,
			// with a particle in the middle slot instead of a middle name.
			name:        "name_with_particle",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + nameParticleRun + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with a nobiliary particle: First van Last",
			priority:    6,
			cultural:    []string{"dutch", "german", "spanish", "portuguese", "italian", "arabic"},
		},
		{
			// The titled form of the pattern above, and the fix for the truncation a
			// CAPITALISED particle used to cause: name_with_title matches exactly two
			// name tokens after the title, so "Dr. Marco Di Salvo" was reported as
			// "Dr. Marco Di" — a name whose reported value stops mid-surname.
			//
			// Restricting the extra token to a particle is what keeps this safe: a
			// pattern that simply allowed a fourth token would claim
			// "Dr. John Smith Reviewed" and put the following word inside the name.
			//
			// Registered in hasExplicitNameMarker and isFormalNamePattern alongside
			// name_with_title — the title is the same evidence of personhood here, and
			// it is what admits an off-list surname such as "Beethoven" at all.
			name:        "name_with_title_and_particle",
			pattern:     `(?:Mr|Ms|Mrs|Dr|Prof|Sir|Dame|Lord|Lady)\.` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + nameParticleRun + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Titled name with a nobiliary particle: Dr. First van Last",
			priority:    8,
			cultural:    []string{"western", "formal", "dutch", "german"},
		},
		{
			name:        "three_part_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Three-part name: First Middle Last",
			priority:    6,
			cultural:    []string{"western", "hispanic", "compound"},
		},
		{
			name:        "hyphenated_last_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Hyphenated last name: First Last-Name",
			priority:    7,
			cultural:    []string{"western", "modern", "compound"},
		},
		{
			name:        "name_with_apostrophe_first",
			pattern:     `[` + nameUpper + `][` + nameLower + `]*'[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with apostrophe in first name: O'Connor Smith",
			priority:    7,
			cultural:    []string{"irish", "scottish", "western"},
		},
		{
			name:        "name_with_apostrophe_last",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]*'[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with apostrophe in last name: David O'Connor",
			priority:    7,
			cultural:    []string{"irish", "scottish", "western"},
		},
		{
			name:        "compound_first_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Compound first name: Mary-Jane Smith",
			priority:    6,
			cultural:    []string{"western", "compound", "modern"},
		},
		{
			// A hyphen in BOTH parts. Without this pattern the name is never matched
			// in full: compound_first_name claims "Anne-Marie Delacroix" and
			// hyphenated_last_name claims "Marie Delacroix-Webb", two overlapping
			// partials that each stop short, and no rule spans the whole thing.
			//
			// That shortfall reached the redacted file, so it was a cleartext leak of
			// real name fragments, not a cosmetic scoring issue. Measured before this
			// pattern existed:
			//
			//	Anne-Marie Delacroix-Webb -> "Reviewed by Anne-********************"
			//	Mary-Jane Watson-Parker   -> "Contact ****************-Parker today"
			//	Jean-Claude Van Damme     -> "Signed: Jean-****************"
			//
			// Priority 8 puts it above both partial patterns (6 and 7) so the full
			// span wins the overlap rather than tying with a fragment of itself.
			name:        "compound_first_and_hyphenated_last",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Hyphen in both parts: Anne-Marie Delacroix-Webb",
			priority:    8,
			cultural:    []string{"western", "french", "compound", "modern"},
		},
		{
			// A hyphenated first name followed by a MULTI-TOKEN surname, e.g. a
			// nobiliary particle: "Jean-Claude Van Damme", "Marie-Claire de la Cruz".
			//
			// Same root cause as the pattern above — a missing combination rather than
			// a broken rule. four_part_name already covers the unhyphenated
			// "Jean Claude Van Damme" (measured: matched in full at 69), and
			// compound_first_name covers "Mary-Jane Smith", but nothing covered the
			// two together, so the hyphenated form was split into "Jean-Claude Van"
			// plus "Claude Van Damme" and redaction left "Jean-" in cleartext.
			//
			// The trailing token count is bounded at two extra words so this cannot
			// run away across a sentence; priority 8 matches the sibling above so the
			// widest span wins over the partials it contains.
			name:        "compound_first_and_multiword_last",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Compound first name with two-part surname: Jean-Claude Van Damme",
			priority:    8,
			cultural:    []string{"western", "french", "dutch", "compound"},
		},
		{
			name:        "name_with_multiple_titles",
			pattern:     `(?:Dr|Prof)\.` + nameSpace + `(?:Mr|Ms|Mrs)\.` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Multiple titles: Dr. Ms. First Last",
			priority:    9,
			cultural:    []string{"academic", "formal"},
		},
		{
			name:        "four_part_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Four-part name: First Middle Middle Last",
			priority:    4,
			cultural:    []string{"hispanic", "compound", "formal"},
		},
		{
			name:        "last_comma_first",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29},` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Last, First format (database/directory style)",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "last_comma_first_middle",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29},` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Last, First Middle format",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "last_comma_first_initial",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29},` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `]\.`,
			description: "Last, First M. format",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "name_with_professional_suffix",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}` + nameSpace + `[` + nameUpper + `][` + nameLower + `]{1,29},` + nameSpace + `(?:PhD|MD|DDS|JD|EdD|PharmD|PsyD|DVM|RN|CPA|PE)`,
			description: "Name with professional suffix: John Smith, PhD",
			priority:    9,
			cultural:    []string{"academic", "professional", "formal"},
		},
	}

	pm.patterns = make([]NamePattern, len(patternDefinitions))
	for i, def := range patternDefinitions {
		// Each definition is a "core" pattern; wrapNamePattern adds Unicode-aware
		// word boundaries and captures the name in group 1.
		compiled := regexp.MustCompile(wrapNamePattern(def.pattern))
		pm.patterns[i] = NamePattern{
			Pattern:     compiled,
			Name:        def.name,
			Description: def.description,
			Priority:    def.priority,
			Cultural:    def.cultural,
		}
	}
}

// GetPatterns returns all compiled patterns
func (pm *PatternManager) GetPatterns() []NamePattern {
	return pm.patterns
}

// FindMatches finds all pattern matches in the given text.
//
// Patterns are boundary-wrapped (see wrapNamePattern): group 0 includes the
// consumed boundary characters, while group 1 is the actual name. We therefore
// read group 1 and use its exact submatch offsets — this both strips the
// boundary chars from the reported name and gives correct StartIndex/EndIndex
// even when the same name appears more than once on a line (the old
// strings.Index returned the first occurrence regardless).
func (pm *PatternManager) FindMatches(text string) []PatternMatch {
	var matches []PatternMatch

	for _, pattern := range pm.patterns {
		locs := pattern.Pattern.FindAllStringSubmatchIndex(text, -1)
		for _, loc := range locs {
			// loc layout: [g0start, g0end, g1start, g1end, ...]; need group 1.
			if len(loc) < 4 || loc[2] < 0 || loc[3] < 0 {
				continue
			}
			start, end := loc[2], loc[3]
			matches = append(matches, PatternMatch{
				Text:       text[start:end],
				Pattern:    pattern,
				StartIndex: start,
				EndIndex:   end,
			})
		}
	}

	return matches
}

// PatternMatch represents a match found by a pattern
type PatternMatch struct {
	Text       string
	Pattern    NamePattern
	StartIndex int
	EndIndex   int
}

// NameComponents represents the parsed components of a name
type NameComponents struct {
	FullName   string
	Title      string
	FirstName  string
	MiddleName string
	LastName   string
	Suffix     string
	Pattern    string
	Cultural   []string
}

// ParseNameComponents parses a name string into its components
func ParseNameComponents(nameText string, pattern NamePattern) NameComponents {
	components := NameComponents{
		FullName: nameText,
		Pattern:  pattern.Name,
		Cultural: pattern.Cultural,
	}

	// Clean and tokenize the name
	tokens := strings.Fields(strings.TrimSpace(nameText))
	if len(tokens) == 0 {
		return components
	}

	// Parse based on pattern type
	switch pattern.Name {
	case "name_with_title", "name_with_title_and_particle", "name_with_multiple_titles":
		components = parseNameWithTitle(tokens, components)
	case "name_with_suffix", "name_with_professional_suffix":
		components = parseNameWithSuffix(tokens, components)
	case "name_with_middle_initial":
		components = parseNameWithMiddleInitial(tokens, components)
	case "last_comma_first", "last_comma_first_middle", "last_comma_first_initial":
		components = parseCommaName(nameText, components)
	default:
		components = parseBasicName(tokens, components)
	}

	return components
}

// parseNameWithTitle parses names that start with titles
func parseNameWithTitle(tokens []string, components NameComponents) NameComponents {
	titleCount := 0
	for i, token := range tokens {
		if isTitle(token) {
			if components.Title == "" {
				components.Title = token
			} else {
				components.Title += " " + token
			}
			titleCount++
		} else {
			// Remaining tokens are the actual name
			nameTokens := tokens[i:]
			components = parseBasicName(nameTokens, components)
			break
		}
	}
	return components
}

// parseNameWithSuffix parses names that end with suffixes
func parseNameWithSuffix(tokens []string, components NameComponents) NameComponents {
	// Find suffix from the end
	suffixStart := len(tokens)
	for i := len(tokens) - 1; i >= 0; i-- {
		if isSuffix(tokens[i]) {
			if components.Suffix == "" {
				components.Suffix = tokens[i]
			} else {
				components.Suffix = tokens[i] + " " + components.Suffix
			}
			suffixStart = i
		} else {
			break
		}
	}

	// Parse the name part (before suffix)
	if suffixStart > 0 {
		nameTokens := tokens[:suffixStart]
		components = parseBasicName(nameTokens, components)
	}

	return components
}

// parseNameWithMiddleInitial parses names with middle initials
func parseNameWithMiddleInitial(tokens []string, components NameComponents) NameComponents {
	if len(tokens) >= 3 {
		components.FirstName = tokens[0]
		// Check if second token is an initial (single letter followed by period)
		if len(tokens[1]) == 2 && tokens[1][1] == '.' {
			components.MiddleName = tokens[1]
			components.LastName = tokens[2]
		} else {
			// Fallback to basic parsing
			components = parseBasicName(tokens, components)
		}
	} else {
		components = parseBasicName(tokens, components)
	}
	return components
}

// parseCommaName parses comma-separated name formats (Last, First)
func parseCommaName(nameText string, components NameComponents) NameComponents {
	// Split on comma first
	parts := strings.Split(nameText, ",")
	if len(parts) != 2 {
		// Fallback to basic parsing if comma format is unexpected
		tokens := strings.Fields(strings.TrimSpace(nameText))
		return parseBasicName(tokens, components)
	}

	// Last name is before the comma
	components.LastName = strings.TrimSpace(parts[0])

	// Parse the part after the comma (First [Middle] [Initial])
	afterComma := strings.TrimSpace(parts[1])
	afterTokens := strings.Fields(afterComma)

	if len(afterTokens) >= 1 {
		components.FirstName = afterTokens[0]
	}
	if len(afterTokens) >= 2 {
		// Check if it's an initial (single letter with period)
		if len(afterTokens[1]) == 2 && afterTokens[1][1] == '.' {
			components.MiddleName = afterTokens[1]
		} else if len(afterTokens) == 2 {
			// Two tokens: assume second is middle name
			components.MiddleName = afterTokens[1]
		} else {
			// More than 2 tokens: join the rest as middle name
			components.MiddleName = strings.Join(afterTokens[1:], " ")
		}
	}

	return components
}

// parseBasicName parses basic name formats
func parseBasicName(tokens []string, components NameComponents) NameComponents {
	switch len(tokens) {
	case 1:
		components.FirstName = tokens[0]
	case 2:
		components.FirstName = tokens[0]
		components.LastName = tokens[1]
	case 3:
		components.FirstName = tokens[0]
		components.MiddleName = tokens[1]
		components.LastName = tokens[2]
	case 4:
		components.FirstName = tokens[0]
		components.MiddleName = tokens[1] + " " + tokens[2]
		components.LastName = tokens[3]
	default:
		// For longer names, assume first is first name, last is last name, rest is middle
		if len(tokens) > 0 {
			components.FirstName = tokens[0]
		}
		if len(tokens) > 1 {
			components.LastName = tokens[len(tokens)-1]
		}
		if len(tokens) > 2 {
			middleTokens := tokens[1 : len(tokens)-1]
			components.MiddleName = strings.Join(middleTokens, " ")
		}
	}
	return components
}

// isTitle checks if a token is a title
func isTitle(token string) bool {
	titles := []string{
		"Mr.", "Ms.", "Mrs.", "Dr.", "Prof.", "Sir", "Dame", "Lord", "Lady",
		"Mr", "Ms", "Mrs", "Dr", "Prof", // Without periods
	}
	for _, title := range titles {
		if token == title {
			return true
		}
	}
	return false
}

// isSuffix checks if a token is a suffix
func isSuffix(token string) bool {
	suffixes := []string{
		"Jr.", "Sr.", "III", "IV", "V", "PhD", "MD", "Esq.", "Esq",
		"Jr", "Sr", // Without periods
	}
	for _, suffix := range suffixes {
		if token == suffix {
			return true
		}
	}
	return false
}

// GetCulturalVariations returns cultural context information for a pattern
func (pm *PatternManager) GetCulturalVariations(patternName string) []string {
	for _, pattern := range pm.patterns {
		if pattern.Name == patternName {
			return pattern.Cultural
		}
	}
	return []string{}
}

// GetPatternPriority returns the priority of a pattern (higher = more specific/reliable)
func (pm *PatternManager) GetPatternPriority(patternName string) int {
	for _, pattern := range pm.patterns {
		if pattern.Name == patternName {
			return pattern.Priority
		}
	}
	return 0
}
