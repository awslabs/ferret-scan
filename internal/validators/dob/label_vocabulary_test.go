// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package dob

import (
	"reflect"
	"strings"
	"testing"
)

// Tests for the one DOB vocabulary of #857: scoring, admission of the
// label-adjacent shapes and the positional disqualifier rule all derive from
// positiveVocabulary and all match it as LABELS (kwmatch.ContainsLabelLower /
// IndexLabelLower), while every suppressor keeps requiring a separator.

// TestCamelCaseLabelsScoreAsLabels: the camelCase and concatenated keys of JSON,
// XML and ORM exports scored 5 (LOW) on main while their snake_case twins scored
// 90, because a multi-word keyword needed a separator between its words.
func TestCamelCaseLabelsScoreAsLabels(t *testing.T) {
	cases := []struct {
		line, label string
	}{
		{`{"dateOfBirth": "1987-03-14"}`, "date of birth"},
		{`{"DateOfBirth": "1987-03-14"}`, "date of birth"},
		{"<DateOfBirth>1987-03-14</DateOfBirth>", "date of birth"},
		{`{"patientDob": "1987-03-14"}`, "patient dob"},
		{`{"memberDOB": "03/14/1987"}`, "member dob"},
		{`{"applicantDob": "03/14/1987"}`, "applicant dob"},
	}
	v := NewValidator()
	for _, c := range cases {
		got := dobMatches(t, v, c.line)
		if len(got) != 1 || got[0].Confidence != 90 {
			t.Errorf("%q: got %s, want one finding at 90 like its snake_case twin", c.line, renderMatches(got))
			continue
		}
		// The recorded keywords must explain the score.
		found := false
		for _, kw := range got[0].Context.PositiveKeywords {
			if kw == c.label {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: PositiveKeywords %v lack %q, the label that scored it",
				c.line, got[0].Context.PositiveKeywords, c.label)
		}
	}
}

// TestPositionalRuleUsesTheVocabulary covers the positional disqualifier rule
// after its separate label list was deleted. That list lacked "d.o.b", so a
// "D.O.B.:" line with "sample" later in it found no label, fell back to "the
// disqualifier wins" and reported nothing; and it could not see camelCase.
func TestPositionalRuleUsesTheVocabulary(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		line, want string
	}{
		{`{"dateOfBirth": "1987-03-14", "notes": "blood sample collected"}`, "90[1987-03-14]@17"},
		{"Test dateOfBirth: 1987-03-14", "-"},
		{"D.O.B.: 03/14/1987, blood sample collected", "90[03/14/1987]@8"},
		{"Test D.O.B.: 03/14/1987", "-"},
		// The label is located as a whole word: "dob" inside "adobe" is not it.
		{"adobe test DOB: 01/01/2000", "-"},
	}
	for _, c := range cases {
		if got := renderMatches(dobMatches(t, v, c.line)); got != c.want {
			t.Errorf("%q: got %s, want %s", c.line, got, c.want)
		}
	}

	// Every strong label, in its listed spelling and its concatenated one, is
	// located by the rule: a marker before it suppresses, clinical vocabulary
	// after it does not.
	for _, label := range strongLabels {
		for _, spelling := range []string{label, strings.ReplaceAll(label, " ", "")} {
			real := spelling + ": 03/14/1987, blood sample collected"
			if got := dobMatches(t, v, real); len(got) != 1 || got[0].Confidence < 90 {
				t.Errorf("%q: got %s, want one finding at >= 90 (the marker follows the label)",
					real, renderMatches(got))
			}
			fixture := "test " + spelling + ": 03/14/1987"
			if got := dobMatches(t, v, fixture); len(got) != 0 {
				t.Errorf("%q: got %s, want nothing (the marker precedes the label)",
					fixture, renderMatches(got))
			}
			if !markerBeforeDOBLabel(fixture) {
				t.Errorf("markerBeforeDOBLabel(%q) = false; the strong label %q was not located", fixture, label)
			}
		}
	}
}

// TestOneVocabularyDrivesScoringAdmissionAndPosition pins how the derived
// lists relate to positiveVocabulary, so a fourth list cannot drift in.
func TestOneVocabularyDrivesScoringAdmissionAndPosition(t *testing.T) {
	v := NewValidator()

	// The recorded PositiveKeywords order is part of SARIF output; it is the
	// order the keyword list had before the vocabulary was introduced.
	wantPositive := []string{
		"date of birth", "dob", "born", "birthday", "birth date",
		"birthdate", "d.o.b", "age", "years old", "birth",
		"date-of-birth", "date_of_birth", "born on", "patient dob",
		"applicant dob", "member dob",
	}
	if !reflect.DeepEqual(v.positiveKeywords, wantPositive) {
		t.Errorf("positiveKeywords = %q, want %q", v.positiveKeywords, wantPositive)
	}

	wantStrong := map[string]bool{
		"date of birth": true, "dob": true, "d.o.b": true,
		"date-of-birth": true, "date_of_birth": true,
		"patient dob": true, "applicant dob": true, "member dob": true,
		"birthdate": true, "birth date": true,
	}
	if !reflect.DeepEqual(strongPositiveKeywords, wantStrong) {
		t.Errorf("strongPositiveKeywords = %v, want %v", strongPositiveKeywords, wantStrong)
	}

	// Admitting labels are the strong labels plus "born", "born on" and
	// "birthday"; the weak "age", "years old" and "birth" never admit.
	admits := make(map[string]bool, len(admittingLabels))
	for _, l := range admittingLabels {
		admits[l] = true
	}
	for _, k := range positiveVocabulary {
		weakOnly := k.word == "age" || k.word == "years old" || k.word == "birth"
		if admits[k.word] == weakOnly {
			t.Errorf("admitting(%q) = %v", k.word, admits[k.word])
		}
		if k.strong && !admits[k.word] {
			t.Errorf("strong label %q does not admit a label-adjacent value", k.word)
		}
	}
	if len(strongLabels) != len(wantStrong) {
		t.Errorf("strongLabels has %d entries, want %d", len(strongLabels), len(wantStrong))
	}
}

// TestSuppressorsStillRequireASeparator is the asymmetry kwmatch documents:
// label semantics widen what a POSITIVE keyword matches, and must never reach a
// suppressor. "created at" matching the key "createdAt" would veto a weakly
// labelled date of birth beside it.
func TestSuppressorsStillRequireASeparator(t *testing.T) {
	if !containsLabelLower("createdat", "created at") {
		t.Fatal("test premise: label semantics do match the concatenated spelling")
	}
	if containsKeywordLower("createdat", "created at") {
		t.Error(`containsKeywordLower("createdat", "created at") = true; suppressors must keep requiring a separator`)
	}

	v := NewValidator()
	if got := renderMatches(dobMatches(t, v, "born 03/14/1987 createdAt")); got != "70[03/14/1987]@5" {
		t.Errorf("camelCase createdAt beside a weak label: got %s, want 70[03/14/1987]@5", got)
	}
	if got := dobMatches(t, v, "born 03/14/1987 created at"); len(got) != 0 {
		t.Errorf("spaced \"created at\" beside a weak label: got %s, want nothing", renderMatches(got))
	}
}
