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

// wrapNamePattern turns a "core" name pattern into a boundary-anchored pattern
// with the name captured in group 1. The leading/trailing groups consume a
// non-letter character (or the string start/end) so the match does not run into
// an adjacent word, while correctly handling accented letters that ASCII \b
// cannot. Callers must read submatch group 1 (see FindMatches).
func wrapNamePattern(core string) string {
	return `(?:^|[^` + nameLetter + `])(` + core + `)(?:[^` + nameLetter + `]|$)`
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
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Basic Western name format: First Last (minimum 2 chars each)",
			priority:    5,
			cultural:    []string{"western", "english", "european"},
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
			pattern:     `[` + nameUpper + `]{2,30}\s+[` + nameUpper + `]{2,30}`,
			description: "All-caps name: FIRST LAST",
			priority:    3,
			cultural:    []string{"western", "formal"},
		},
		{
			name:        "name_with_middle_initial",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `]\.\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with middle initial: First M. Last",
			priority:    7,
			cultural:    []string{"western", "american"},
		},
		{
			name:        "name_with_title",
			pattern:     `(?:Mr|Ms|Mrs|Dr|Prof|Sir|Dame|Lord|Lady)\.\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
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
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+(?:Jr\.?|Sr\.?|III|IV|PhD|MD|Esq\.?)`,
			description: "Name with suffix: First Last Jr.",
			priority:    8,
			cultural:    []string{"western", "american", "academic"},
		},
		{
			name:        "three_part_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Three-part name: First Middle Last",
			priority:    6,
			cultural:    []string{"western", "hispanic", "compound"},
		},
		{
			name:        "hyphenated_last_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Hyphenated last name: First Last-Name",
			priority:    7,
			cultural:    []string{"western", "modern", "compound"},
		},
		{
			name:        "name_with_apostrophe_first",
			pattern:     `[` + nameUpper + `][` + nameLower + `]*'[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with apostrophe in first name: O'Connor Smith",
			priority:    7,
			cultural:    []string{"irish", "scottish", "western"},
		},
		{
			name:        "name_with_apostrophe_last",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]*'[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Name with apostrophe in last name: David O'Connor",
			priority:    7,
			cultural:    []string{"irish", "scottish", "western"},
		},
		{
			name:        "compound_first_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}-[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Compound first name: Mary-Jane Smith",
			priority:    6,
			cultural:    []string{"western", "compound", "modern"},
		},
		{
			name:        "name_with_multiple_titles",
			pattern:     `(?:Dr|Prof)\.\s+(?:Mr|Ms|Mrs)\.\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Multiple titles: Dr. Ms. First Last",
			priority:    9,
			cultural:    []string{"academic", "formal"},
		},
		{
			name:        "four_part_name",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Four-part name: First Middle Middle Last",
			priority:    4,
			cultural:    []string{"hispanic", "compound", "formal"},
		},
		{
			name:        "last_comma_first",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29},\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Last, First format (database/directory style)",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "last_comma_first_middle",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29},\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29}`,
			description: "Last, First Middle format",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "last_comma_first_initial",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29},\s+[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `]\.`,
			description: "Last, First M. format",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "name_with_professional_suffix",
			pattern:     `[` + nameUpper + `][` + nameLower + `]{1,29}\s+[` + nameUpper + `][` + nameLower + `]{1,29},\s+(?:PhD|MD|DDS|JD|EdD|PharmD|PsyD|DVM|RN|CPA|PE)`,
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
	case "name_with_title", "name_with_multiple_titles":
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
