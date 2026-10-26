// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"reflect"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

func mkMatch(dataType, text, fullLine string, line int) detector.Match {
	return detector.Match{
		Text:       text,
		Type:       dataType,
		LineNumber: line,
		Context:    detector.ContextInfo{FullLine: fullLine},
	}
}

// groupShape is what a test asserts about one group: its kind, its members' types in input
// order, its union, and its representative's type.
type groupShape struct {
	Kind    GroupKind
	Members []string
	Text    string
	Rep     string
}

func shapes(ms []detector.Match, gs []OverlapGroup) []groupShape {
	out := make([]groupShape, len(gs))
	for i, g := range gs {
		types := make([]string, len(g.Members))
		for k, m := range g.Members {
			types[k] = ms[m].Type
		}
		out[i] = groupShape{Kind: g.Kind, Members: types, Text: g.Text, Rep: ms[g.Representative].Type}
	}
	return out
}

func assertGroups(t *testing.T, ms []detector.Match, want []groupShape) []OverlapGroup {
	t.Helper()
	got := ResolveOverlaps(ms)
	if s := shapes(ms, got); !reflect.DeepEqual(s, want) {
		t.Fatalf("groups:\n got %+v\nwant %+v", s, want)
	}
	return got
}

func TestResolveOverlaps_ContainedMatchJoinsTheWidest(t *testing.T) {
	line := "spaced 4532 0151 1283 0366"
	for _, order := range [][]detector.Match{
		{mkMatch("VISA", "4532 0151 1283 0366", line, 1), mkMatch("PHONE", "0151 1283 0366", line, 1)},
		{mkMatch("PHONE", "0151 1283 0366", line, 1), mkMatch("VISA", "4532 0151 1283 0366", line, 1)},
	} {
		got := ResolveOverlaps(order)
		if len(got) != 1 || got[0].Kind != GroupContained || order[got[0].Representative].Type != "VISA" ||
			got[0].Text != "4532 0151 1283 0366" || !got[0].IsGroup() {
			t.Fatalf("a contained PHONE must group under the widest VISA, whatever the order: %+v", shapes(order, got))
		}
	}
}

func TestResolveOverlaps_ThreeNested(t *testing.T) {
	line := "xx 4532 0151 1283 0366 yy"
	assertGroups(t, []detector.Match{
		mkMatch("VISA", "4532 0151 1283 0366", line, 1),
		mkMatch("PHONE", "0151 1283 0366", line, 1),
		mkMatch("OTHER", "1283 0366", line, 1),
	}, []groupShape{{GroupContained, []string{"VISA", "PHONE", "OTHER"}, "4532 0151 1283 0366", "VISA"}})
}

// The issue's identical pair, in both input orders: one group, and the representative is decided by
// confidence, never by which arrived first.
func TestResolveOverlaps_IdenticalSpansAreOneGroupWhateverTheOrder(t *testing.T) {
	line := "Passport number: 512010001"
	pass := mkMatch("PASSPORT", "512010001", line, 1)
	pass.Confidence = 100
	ssn := mkMatch("SSN", "512010001", line, 1)
	ssn.Confidence = 50
	for _, order := range [][]detector.Match{{pass, ssn}, {ssn, pass}} {
		got := ResolveOverlaps(order)
		if len(got) != 1 || got[0].Kind != GroupIdentical || order[got[0].Representative].Type != "PASSPORT" {
			t.Fatalf("identical spans must form one group represented by PASSPORT (100 > 50): %+v", shapes(order, got))
		}
	}
}

// Representative tie-breaks: confidence, then Type, then input index -- never input order between
// different types.
func TestResolveOverlaps_RepresentativeTieBreaks(t *testing.T) {
	line := "id 512010001"
	a := mkMatch("SSN", "512010001", line, 1)
	b := mkMatch("DRIVERS_LICENSE", "512010001", line, 1)
	a.Confidence, b.Confidence = 70, 70
	for _, order := range [][]detector.Match{{a, b}, {b, a}} {
		got := ResolveOverlaps(order)
		if order[got[0].Representative].Type != "DRIVERS_LICENSE" {
			t.Fatalf("equal confidence must fall to Type order (DRIVERS_LICENSE < SSN), got %s", order[got[0].Representative].Type)
		}
	}
	twin := mkMatch("SSN", "512010001", line, 1)
	twin.Confidence = 70
	got := ResolveOverlaps([]detector.Match{a, twin})
	if got[0].Representative != 0 {
		t.Fatalf("identical type and confidence must fall to input index, got %d", got[0].Representative)
	}
}

// Replaces TestResolveOverlaps_PartialOverlapKeepsBoth: two crossing spans used to be returned as two
// survivors, and every writer then wrote one and stranded the rest of the other.
func TestResolveOverlaps_PartialOverlapIsOneGroupOverTheUnion(t *testing.T) {
	line := "Residence: 77 August Lane, Boise ID 83702"
	addr := mkMatch("US_STREET_ADDRESS", "77 August Lane", line, 1)
	addr.Confidence = 95
	inner := mkMatch("PERSON_NAME", "August Lane", line, 1)
	inner.Confidence = 92
	cross := mkMatch("PERSON_NAME", "Lane, Boise", line, 1)
	cross.Confidence = 67
	assertGroups(t, []detector.Match{addr, inner, cross},
		[]groupShape{{GroupPartial, []string{"US_STREET_ADDRESS", "PERSON_NAME", "PERSON_NAME"}, "77 August Lane, Boise", "US_STREET_ADDRESS"}})
}

func TestResolveOverlaps_ChainIsOneGroup(t *testing.T) {
	line := "aaabbbcccddd"
	assertGroups(t, []detector.Match{
		mkMatch("A", "aaabbb", line, 1),
		mkMatch("B", "bbbccc", line, 1),
		mkMatch("C", "cccddd", line, 1),
	}, []groupShape{{GroupPartial, []string{"A", "B", "C"}, "aaabbbcccddd", "A"}})
}

// Touching spans share no byte: each value is whole and keeps its own rendering.
func TestResolveOverlaps_TouchingSpansDoNotGroup(t *testing.T) {
	line := "aaabbbccc"
	assertGroups(t, []detector.Match{
		mkMatch("A", "aaabbb", line, 1),
		mkMatch("B", "ccc", line, 1),
	}, []groupShape{
		{GroupSingle, []string{"A"}, "aaabbb", "A"},
		{GroupSingle, []string{"B"}, "ccc", "B"},
	})
}

func TestResolveOverlaps_KeepsNonOverlapping(t *testing.T) {
	line := "call 212-555-0142 or card 4532-0151-1283-0366"
	got := assertGroups(t, []detector.Match{
		mkMatch("PHONE", "212-555-0142", line, 1),
		mkMatch("VISA", "4532-0151-1283-0366", line, 1),
	}, []groupShape{
		{GroupSingle, []string{"PHONE"}, "212-555-0142", "PHONE"},
		{GroupSingle, []string{"VISA"}, "4532-0151-1283-0366", "VISA"},
	})
	for _, g := range got {
		if g.IsGroup() {
			t.Fatalf("disjoint matches must not group: %+v", g)
		}
	}
}

func TestResolveOverlaps_DifferentLinesNeverGroup(t *testing.T) {
	// Identical text on different lines must not group.
	assertGroups(t, []detector.Match{
		mkMatch("VISA", "4532 0151 1283 0366", "card 4532 0151 1283 0366", 1),
		mkMatch("PHONE", "0151 1283 0366", "phone 0151 1283 0366", 2),
	}, []groupShape{
		{GroupSingle, []string{"VISA"}, "4532 0151 1283 0366", "VISA"},
		{GroupSingle, []string{"PHONE"}, "0151 1283 0366", "PHONE"},
	})
}

func TestResolveOverlaps_SameLineNumberDifferentSourceNeverGroup(t *testing.T) {
	// Regression: an Office package numbers lines per part, so a metadata match
	// in docProps/core.xml and a body match in word/document.xml both arrive as
	// "line 1" with offsets measured against DIFFERENT strings. Comparing those
	// offsets is meaningless. Here the body SSN's span [9,20) falls numerically
	// inside the author's [8,20), and the SSN was dropped before redaction was
	// ever attempted — leaving it in cleartext in the "redacted" output.
	//
	// The two matches are on different lines despite sharing a line NUMBER, so
	// neither may join the other.
	ms := []detector.Match{
		mkMatch("SSN", "449-87-4100", "body ssn 449-87-4100", 1),
		mkMatch("AUTHOR_INFO", "Jane Analyst", "Author: Jane Analyst", 1),
	}
	got := ResolveOverlaps(ms)
	if len(got) != 2 || got[0].IsGroup() || got[1].IsGroup() {
		t.Fatalf("matches from different source text must stay apart; got %+v — a body SSN folded into a metadata span is never written", shapes(ms, got))
	}
}

func TestResolveOverlaps_UnresolvablePositionStaysSingle(t *testing.T) {
	// No FullLine context: position can't be resolved, so it is its own group and absorbs nothing.
	ms := []detector.Match{
		{Text: "4532 0151 1283 0366", Type: "VISA", LineNumber: 1},
		{Text: "0151 1283 0366", Type: "PHONE", LineNumber: 1},
	}
	got := ResolveOverlaps(ms)
	if len(got) != 2 || got[0].Resolved || got[1].Resolved || got[0].Text != ms[0].Text {
		t.Fatalf("unresolvable matches must stay single and carry their own Text, got %+v", got)
	}
}

// One value reported by two checks, twice on one line. The span resolver's cursor is per TEXT, so
// resolved together the SSN matches find both occurrences consumed by PASSPORT and both fall back to
// the first: the second PASSPORT would stand alone and render on its own. Resolved per type, each
// occurrence is one identical group.
func TestResolveOverlaps_SameValueTwoChecksTwiceOnALine(t *testing.T) {
	line := "Passport 512010001 renewed as 512010001"
	p1, p2 := mkMatch("PASSPORT", "512010001", line, 1), mkMatch("PASSPORT", "512010001", line, 1)
	s1, s2 := mkMatch("SSN", "512010001", line, 1), mkMatch("SSN", "512010001", line, 1)
	for _, ms := range [][]detector.Match{{p1, p2, s1, s2}, {s1, s2, p1, p2}, {p1, s1, p2, s2}} {
		got := ResolveOverlaps(ms)
		if len(got) != 2 {
			t.Fatalf("want one identical group per occurrence, got %+v", shapes(ms, got))
		}
		for _, g := range got {
			if g.Kind != GroupIdentical || len(g.Members) != 2 {
				t.Fatalf("each occurrence must be a PASSPORT+SSN group, got %+v", shapes(ms, got))
			}
		}
		if got[0].Start == got[1].Start {
			t.Fatalf("the two groups must sit on the two occurrences, both at %d", got[0].Start)
		}
	}
}

func TestResolveOverlaps_GroupsInInputOrderOfFirstMember(t *testing.T) {
	line := "a 212-555-0142 b 449-87-4100"
	ms := []detector.Match{
		mkMatch("SSN", "449-87-4100", line, 1),
		mkMatch("PHONE", "212-555-0142", line, 1),
	}
	got := ResolveOverlaps(ms)
	if got[0].Members[0] != 0 || got[1].Members[0] != 1 {
		t.Fatalf("groups must come back in input order of their first member, got %+v", got)
	}
}

func TestResolveOverlaps_EmptyAndSingle(t *testing.T) {
	if got := ResolveOverlaps(nil); got != nil {
		t.Errorf("nil in -> nil out, got %v", got)
	}
	one := []detector.Match{mkMatch("VISA", "x", "x", 1)}
	if got := ResolveOverlaps(one); len(got) != 1 || got[0].IsGroup() || got[0].Unit(one).Text != "x" {
		t.Errorf("single match must pass through, got %+v", got)
	}
}

func TestOverlapGroup_UnitCarriesTheUnionAndMemberTypesAreSorted(t *testing.T) {
	line := "aaabbbccc"
	ms := []detector.Match{mkMatch("Z", "aaabbb", line, 1), mkMatch("A", "bbbccc", line, 1)}
	g := ResolveOverlaps(ms)[0]
	if u := g.Unit(ms); u.Text != "aaabbbccc" || u.Type != ms[g.Representative].Type {
		t.Fatalf("unit must be the representative carrying the union, got %+v", u)
	}
	if got := g.MemberTypes(ms); !reflect.DeepEqual(got, []string{"A", "Z"}) {
		t.Fatalf("member types must be sorted, got %v", got)
	}
}

func TestIsSecretsMember(t *testing.T) {
	for _, c := range []struct {
		validator string
		want      bool
	}{{"secrets", true}, {"SECRETS", true}, {"", true}, {"email", false}, {"otp", false}} {
		if got := IsSecretsMember(detector.Match{Validator: c.validator}); got != c.want {
			t.Errorf("IsSecretsMember(Validator=%q) = %v, want %v", c.validator, got, c.want)
		}
	}
}
