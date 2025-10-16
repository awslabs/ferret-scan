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
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Basic Western name format: First Last (minimum 2 chars each)",
			priority:    5,
			cultural:    []string{"western", "english", "european"},
		},
		{
			name:        "name_with_middle_initial",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ]\.\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Name with middle initial: First M. Last",
			priority:    7,
			cultural:    []string{"western", "american"},
		},
		{
			name:        "name_with_title",
			pattern:     `\b(?:Mr|Ms|Mrs|Dr|Prof|Sir|Dame|Lord|Lady)\.\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Name with title: Dr. First Last",
			priority:    8,
			cultural:    []string{"western", "formal"},
		},
		{
			name:        "name_with_suffix",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+(?:Jr\.?|Sr\.?|III|IV|V|PhD|MD|Esq\.?)`,
			description: "Name with suffix: First Last Jr.",
			priority:    8,
			cultural:    []string{"western", "american", "academic"},
		},
		{
			name:        "three_part_name",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Three-part name: First Middle Last",
			priority:    6,
			cultural:    []string{"western", "hispanic", "compound"},
		},
		{
			name:        "hyphenated_last_name",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}-[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Hyphenated last name: First Last-Name",
			priority:    7,
			cultural:    []string{"western", "modern", "compound"},
		},
		{
			name:        "name_with_apostrophe_first",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]*'[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Name with apostrophe in first name: O'Connor Smith",
			priority:    7,
			cultural:    []string{"irish", "scottish", "western"},
		},
		{
			name:        "name_with_apostrophe_last",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]*'[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Name with apostrophe in last name: David O'Connor",
			priority:    7,
			cultural:    []string{"irish", "scottish", "western"},
		},
		{
			name:        "compound_first_name",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}-[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Compound first name: Mary-Jane Smith",
			priority:    6,
			cultural:    []string{"western", "compound", "modern"},
		},
		{
			name:        "name_with_multiple_titles",
			pattern:     `\b(?:Dr|Prof)\.\s+(?:Mr|Ms|Mrs)\.\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Multiple titles: Dr. Ms. First Last",
			priority:    9,
			cultural:    []string{"academic", "formal"},
		},
		{
			name:        "four_part_name",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Four-part name: First Middle Middle Last",
			priority:    4,
			cultural:    []string{"hispanic", "compound", "formal"},
		},
		{
			name:        "last_comma_first",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29},\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Last, First format (database/directory style)",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "last_comma_first_middle",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29},\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\b`,
			description: "Last, First Middle format",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "last_comma_first_initial",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29},\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ]\.\b`,
			description: "Last, First M. format",
			priority:    8,
			cultural:    []string{"formal", "database", "directory"},
		},
		{
			name:        "name_with_professional_suffix",
			pattern:     `\b[A-ZÀ-ÿ][a-zà-ÿ]{1,29}\s+[A-ZÀ-ÿ][a-zà-ÿ]{1,29},\s+(?:PhD|MD|DDS|JD|EdD|PharmD|PsyD|DVM|RN|CPA|PE)\b`,
			description: "Name with professional suffix: John Smith, PhD",
			priority:    9,
			cultural:    []string{"academic", "professional", "formal"},
		},
	}

	pm.patterns = make([]NamePattern, len(patternDefinitions))
	for i, def := range patternDefinitions {
		compiled := regexp.MustCompile(def.pattern)
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

// FindMatches finds all pattern matches in the given text
func (pm *PatternManager) FindMatches(text string) []PatternMatch {
	var matches []PatternMatch

	for _, pattern := range pm.patterns {
		regexMatches := pattern.Pattern.FindAllStringSubmatch(text, -1)
		for _, match := range regexMatches {
			if len(match) > 0 {
				matches = append(matches, PatternMatch{
					Text:       match[0],
					Pattern:    pattern,
					StartIndex: strings.Index(text, match[0]),
					EndIndex:   strings.Index(text, match[0]) + len(match[0]),
				})
			}
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
