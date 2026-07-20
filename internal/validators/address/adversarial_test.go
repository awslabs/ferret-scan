// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package address

import (
	"testing"
)

// TestAdversarial exercises attack vectors against the address validator
// to find false positives, false negatives, context weaknesses, and edge cases.
func TestAdversarial(t *testing.T) {
	validator := NewValidator()

	// ========================================================================
	// Section 1: FALSE POSITIVES — things that MUST NOT match
	// ========================================================================

	t.Run("FalsePositives", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			maxConf float64 // max acceptable confidence; 0 means must not match at all
		}{
			// ATTACK VECTOR: "123 main" without street type must NOT match
			{
				name:    "number_plus_word_no_suffix",
				input:   "123 main",
				maxConf: 0,
			},
			{
				name:    "number_plus_words_no_suffix",
				input:   "There are 456 items on the main floor",
				maxConf: 0,
			},

			// ATTACK VECTOR: Code references must NOT match
			{
				name:    "code_ref_line_in_main_go",
				input:   "line 456 in main.go",
				maxConf: 0,
			},
			{
				name:    "code_ref_error_at_file",
				input:   "error at line 100 in utils.py",
				maxConf: 0,
			},
			// Trickier: file name contains a street suffix word
			{
				name:    "code_ref_file_with_Dr_suffix",
				input:   "see file 100 North Dr.go for details",
				maxConf: 25, // if it matches at all, must be very low
			},

			// ATTACK VECTOR: IP addresses must NOT match
			{
				name:    "bare_ip_address",
				input:   "192.168.1.1",
				maxConf: 0,
			},
			{
				name:    "ip_in_sentence",
				input:   "Connect to server at 10.0.0.1 on port 443",
				maxConf: 0,
			},

			// ATTACK VECTOR: Version strings must NOT match
			{
				name:    "version_string",
				input:   "Version 1.2.3",
				maxConf: 0,
			},
			{
				name:    "semver_in_context",
				input:   "Upgraded package from 2.0.0 to 3.1.4",
				maxConf: 0,
			},

			// ATTACK VECTOR: Just a ZIP code alone must NOT match as an address
			{
				name:    "bare_zip_code_5digit",
				input:   "62701",
				maxConf: 0,
			},
			{
				name:    "bare_zip_code_plus4",
				input:   "62701-1234",
				maxConf: 0,
			},
			{
				name:    "zip_in_sentence_no_address",
				input:   "The ZIP code is 90210 for that area",
				maxConf: 0,
			},

			// Cross-validator confusion: things that look numeric but aren't addresses
			{
				name:    "phone_number_like",
				input:   "Call 555 Main St extension 1234",
				maxConf: 50, // "555 Main St" does look like an address but in phone context
			},
			{
				name:    "date_like_pattern",
				input:   "On 12 January Dr. Smith arrived",
				maxConf: 0, // "12 January Dr" - "January" then "Dr" could match but "Dr" has a dot after it that's part of "Dr."
			},
			{
				name:    "numbered_list_with_suffix_word",
				input:   "3. Drive to the store and pick up groceries",
				maxConf: 0,
			},
			{
				name:    "log_timestamp_adjacent",
				input:   "2024-01-15 08:30:00 100 connections on Main Loop",
				maxConf: 25, // "100 connections on Main Loop" - Loop is a suffix!
			},
			{
				name:    "table_row_with_numbers",
				input:   "| 42 | Oak | Drive | $500 |",
				maxConf: 50, // "42 Oak Drive" could look like an address in a table
			},
			{
				name:    "env_variable_like",
				input:   "PORT=8080 100 processes on Round Loop daemon",
				maxConf: 25,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches, err := validator.ValidateContent(tt.input, "test.txt")
				if err != nil {
					t.Fatalf("ValidateContent() error = %v", err)
				}
				if tt.maxConf == 0 {
					if len(matches) > 0 {
						t.Errorf("MUST NOT match but got %d match(es): %q (confidence=%.1f)",
							len(matches), matches[0].Text, matches[0].Confidence)
					}
				} else {
					for _, m := range matches {
						if m.Confidence > tt.maxConf {
							t.Errorf("confidence %.1f exceeds max acceptable %.1f for match %q",
								m.Confidence, tt.maxConf, m.Text)
						}
					}
				}
			})
		}
	})

	// ========================================================================
	// Section 2: FALSE NEGATIVES — things that MUST match
	// ========================================================================

	t.Run("FalseNegatives", func(t *testing.T) {
		tests := []struct {
			name    string
			input   string
			minConf float64 // minimum expected confidence
		}{
			// ATTACK VECTOR: full address must match HIGH
			{
				name:    "full_address_high_confidence",
				input:   "123 Main St, Springfield, IL 62701",
				minConf: 75,
			},
			{
				name:    "full_address_with_keyword",
				input:   "Shipping address: 456 Oak Avenue, Portland, OR 97201",
				minConf: 85,
			},

			// Directional prefixes (common in US addresses)
			{
				name:    "directional_N_prefix",
				input:   "100 North Main St, Denver, CO 80202",
				minConf: 75,
			},
			{
				name:    "directional_South",
				input:   "200 South Elm Ave, Austin, TX 78701",
				minConf: 75,
			},
			// N. with period — potential recall gap
			{
				name:    "directional_N_dot_prefix",
				input:   "100 N. Main St, Denver, CO 80202",
				minConf: 50, // may not match due to period in "N."
			},

			// Multi-line address (city/state/ZIP on next line)
			{
				name:    "multiline_address",
				input:   "789 Elm Boulevard\nSuite 300\nDenver, CO 80202",
				minConf: 60,
			},

			// PO Box variations
			{
				name:    "po_box_with_city",
				input:   "P.O. Box 1234, Anytown, NY 10001",
				minConf: 75,
			},

			// Long multi-word street names
			{
				name:    "long_street_name",
				input:   "2000 Martin Luther King Jr Blvd, Atlanta, GA 30303",
				minConf: 75,
			},

			// Address with Apt/Suite
			{
				name:    "address_with_apt",
				input:   "Address: 500 Broadway Ave, Apt 4B, New York, NY 10012",
				minConf: 80,
			},

			// Highway addresses
			{
				name:    "highway_address",
				input:   "Located at 12345 Old State Highway, Nashville, TN 37201",
				minConf: 75,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches, err := validator.ValidateContent(tt.input, "test.txt")
				if err != nil {
					t.Fatalf("ValidateContent() error = %v", err)
				}
				if len(matches) == 0 {
					t.Fatalf("MUST match but got no matches for input: %q", tt.input)
				}
				// Find the highest confidence match
				best := matches[0]
				for _, m := range matches[1:] {
					if m.Confidence > best.Confidence {
						best = m
					}
				}
				if best.Confidence < tt.minConf {
					t.Errorf("confidence %.1f below minimum expected %.1f (match=%q)",
						best.Confidence, tt.minConf, best.Text)
				}
			})
		}
	})

	// ========================================================================
	// Section 3: CONTEXT WEAKNESS — same value, different context
	// ========================================================================

	t.Run("ContextWeakness", func(t *testing.T) {
		tests := []struct {
			name       string
			withCtx    string // with positive keywords
			withoutCtx string // without keywords
			minDelta   float64
		}{
			{
				name:       "shipping_keyword_boost",
				withCtx:    "Shipping address: 42 Oak Ave",
				withoutCtx: "near 42 Oak Ave today",
				minDelta:   10,
			},
			{
				name:       "billing_keyword_boost",
				withCtx:    "Billing: 100 Elm Rd, Portland, OR 97201",
				withoutCtx: "100 Elm Rd, Portland, OR 97201",
				minDelta:   10,
			},
			// ATTACK VECTOR: "Item 42 on List Ave" — negative keyword should suppress
			// "42 on List Ave" is blocked by FP filter (unlikely word "on" in street name).
			// Instead test that negative keyword "item" lowers confidence vs positive "deliver".
			{
				name:       "item_negative_keyword_suppresses",
				withCtx:    "Deliver to 42 List Ave please",
				withoutCtx: "item 42 List Ave info",
				minDelta:   10, // "deliver" is positive, "item" is negative
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matchesWith, err := validator.ValidateContent(tt.withCtx, "test.txt")
				if err != nil {
					t.Fatalf("ValidateContent() error = %v", err)
				}
				matchesWithout, err := validator.ValidateContent(tt.withoutCtx, "test.txt")
				if err != nil {
					t.Fatalf("ValidateContent() error = %v", err)
				}

				if len(matchesWith) == 0 {
					t.Fatalf("expected match with positive context for %q", tt.withCtx)
				}
				if len(matchesWithout) == 0 {
					t.Fatalf("expected match without context for %q", tt.withoutCtx)
				}

				confWith := matchesWith[0].Confidence
				confWithout := matchesWithout[0].Confidence

				delta := confWith - confWithout
				if delta < tt.minDelta {
					t.Errorf("context should create confidence delta >= %.1f but got %.1f (with=%.1f, without=%.1f)",
						tt.minDelta, delta, confWith, confWithout)
				}
			})
		}
	})

	// ========================================================================
	// Section 4: EDGE CASES
	// ========================================================================

	t.Run("EdgeCases", func(t *testing.T) {
		t.Run("empty_string", func(t *testing.T) {
			matches, err := validator.ValidateContent("", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(matches) != 0 {
				t.Errorf("empty string should produce no matches, got %d", len(matches))
			}
		})

		t.Run("unicode_street_name", func(t *testing.T) {
			// Street with unicode characters in context (should still detect)
			matches, err := validator.ValidateContent("Dirección: 123 Main St, pueblo", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(matches) == 0 {
				t.Error("should detect English address pattern even with unicode context")
			}
		})

		t.Run("very_long_street_number_rejected", func(t *testing.T) {
			// 7+ digit street number should NOT match (regex limits to 1-6)
			matches, err := validator.ValidateContent("1234567 Main St", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(matches) > 0 {
				t.Errorf("7-digit street number should not match, got %q", matches[0].Text)
			}
		})

		t.Run("street_number_zero", func(t *testing.T) {
			// Street number 0 — unusual but technically valid in some places
			matches, err := validator.ValidateContent("0 Main St", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			// regex allows \d{1,6} which includes 0
			if len(matches) == 0 {
				t.Error("street number 0 should match (it's a valid 1-digit number)")
			}
		})

		t.Run("multiple_addresses_same_line", func(t *testing.T) {
			input := "From 100 Oak Ave to 200 Pine Rd and then 300 Elm Ct"
			matches, err := validator.ValidateContent(input, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(matches) < 3 {
				t.Errorf("expected at least 3 matches, got %d", len(matches))
			}
		})

		t.Run("address_at_line_boundary", func(t *testing.T) {
			// Address split so suffix is technically start of "next word" group
			matches, err := validator.ValidateContent("123 Main\nSt", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			// Split across lines — the regex operates per-line, so this should NOT match
			if len(matches) > 0 {
				t.Errorf("address split across lines should not match per-line regex, got %q", matches[0].Text)
			}
		})

		t.Run("max_length_street_number", func(t *testing.T) {
			matches, err := validator.ValidateContent("999999 Industrial Pkwy", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			if len(matches) == 0 {
				t.Error("6-digit street number should match")
			}
		})

		t.Run("confidence_capped_at_100", func(t *testing.T) {
			// Combine all boosters: keyword + city/state/ZIP + apt
			input := "Shipping address: 123 Main St, Apt 4B, Springfield, IL 62701"
			matches, err := validator.ValidateContent(input, "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			for _, m := range matches {
				if m.Confidence > 100 {
					t.Errorf("confidence should be capped at 100, got %.1f", m.Confidence)
				}
			}
		})

		t.Run("all_caps_address", func(t *testing.T) {
			// USPS-style all-caps address
			matches, err := validator.ValidateContent("123 MAIN ST APT 4B", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			// The regex uses case-sensitive matching for suffixes (St vs ST)
			// This tests whether case sensitivity is handled
			_ = matches // just checking it doesn't crash; we'll evaluate separately
		})

		t.Run("suffix_as_name_part_not_standalone", func(t *testing.T) {
			// "Street" appearing as part of a longer word should not trigger suffix match
			// e.g., "Streetwise" — but the regex requires \b word boundary so this should be fine
			matches, err := validator.ValidateContent("100 Oak Streetwise building", "test.txt")
			if err != nil {
				t.Fatalf("error: %v", err)
			}
			// "100 Oak Streetwise" — "Streetwise" != "Street" due to word boundary
			// But "100 Oak Street" would be embedded... let's check what actually matches
			for _, m := range matches {
				if m.Text == "100 Oak Streetwise" {
					t.Errorf("should not match 'Streetwise' as a street suffix, got %q", m.Text)
				}
			}
		})
	})

	// ========================================================================
	// Section 5: CASE SENSITIVITY for street suffixes
	// ========================================================================

	t.Run("CaseSensitivity", func(t *testing.T) {
		// The primary regex is case-exact (St|Street|Ave|...), but a
		// case-insensitive fallback fires on lines that independently carry
		// address context (positive keyword or city/state/ZIP shape). So
		// case-mismatched addresses match only when that context gate opens:
		// a ZIP line or the word "street" itself opens it; a bare "456 OAK
		// AVE" (no keyword, no ZIP) stays unmatched.
		tests := []struct {
			name        string
			input       string
			expectMatch bool
		}{
			{
				name:        "lowercase_st",
				input:       "123 Main st, Springfield, IL 62701",
				expectMatch: true, // city/state/ZIP opens the case-relaxed gate
			},
			{
				name:        "uppercase_ST",
				input:       "123 MAIN ST",
				expectMatch: false, // no keyword, no ZIP: gate stays closed
			},
			{
				name:        "mixed_case_Street",
				input:       "123 Main Street, Portland, OR 97201",
				expectMatch: true, // "Street" is in the regex
			},
			{
				name:        "uppercase_STREET",
				input:       "123 MAIN STREET",
				expectMatch: true, // "street" keyword opens the gate (envelope format)
			},
			{
				name:        "uppercase_AVE",
				input:       "456 OAK AVE",
				expectMatch: false, // "AVE" is not an address keyword: gate stays closed
			},
			{
				name:        "proper_case_Ave",
				input:       "456 Oak Ave",
				expectMatch: true,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				matches, err := validator.ValidateContent(tt.input, "test.txt")
				if err != nil {
					t.Fatalf("error: %v", err)
				}
				got := len(matches) > 0
				if got != tt.expectMatch {
					if tt.expectMatch {
						t.Errorf("expected match for %q but got none", tt.input)
					} else {
						t.Errorf("expected NO match for %q but got %q (conf=%.1f)",
							tt.input, matches[0].Text, matches[0].Confidence)
					}
				}
			})
		}
	})
}
