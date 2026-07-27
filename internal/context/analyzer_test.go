// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package context

import "testing"

// TestClassifyDomainIsDeterministic locks the tie-break in ClassifyDomain. The
// best-domain search ranged a map with a strict >, so when two domains scored
// equally Go's randomized map iteration order picked the winner: the same
// content classified as "Financial" on one run and "Retail" on the next. The
// domain is reported in finding metadata, so that flapping made scan output
// non-reproducible and any golden file covering a tied input permanently flaky.
func TestClassifyDomainIsDeterministic(t *testing.T) {
	dc := NewDomainClassifier()

	// Each input ties two domains on exactly one keyword apiece:
	//   "account" -> Financial, "customer" -> Retail
	//   "taxpayer" -> Government, "bank" -> Financial
	for _, content := range []string{
		"customer_ssn: 449-87-4100\naccount_number_test: 4012888888881881\n",
		"taxpayer id on file, bank record attached",
		"order product inventory patient medical hospital",
	} {
		first, firstConf := dc.ClassifyDomain(content)
		for i := 0; i < 200; i++ {
			got, conf := dc.ClassifyDomain(content)
			if got != first || conf != firstConf {
				t.Fatalf("ClassifyDomain(%q) is not deterministic: got (%q, %.4f) on iteration %d, want (%q, %.4f)",
					content, got, conf, i, first, firstConf)
			}
		}
	}
}

// TestClassifyDomainTieBreaksAlphabetically pins the chosen tie-break rule, so a
// future refactor cannot silently swap it for another arbitrary order.
func TestClassifyDomainTieBreaksAlphabetically(t *testing.T) {
	dc := NewDomainClassifier()

	// One Financial keyword ("account") against one Retail keyword ("customer"):
	// "Financial" < "Retail", so Financial wins.
	if got, _ := dc.ClassifyDomain("customer account"); got != "Financial" {
		t.Errorf("tie between Financial and Retail should resolve to Financial, got %q", got)
	}

	// A strict majority must still beat the alphabetical order: "Retail" sorts
	// after "Financial" but carries three keywords to Financial's one.
	if got, _ := dc.ClassifyDomain("account customer order product"); got != "Retail" {
		t.Errorf("higher score must win regardless of name order, got %q", got)
	}
}

// TestClassifyDomainUnknown covers the two paths that bypass the ranking: no
// keyword at all, and a winner too weak to clear the density threshold.
func TestClassifyDomainUnknown(t *testing.T) {
	dc := NewDomainClassifier()

	if got, conf := dc.ClassifyDomain("the quick brown fox"); got != "Unknown" || conf != 0 {
		t.Errorf("keyword-free content should be (Unknown, 0), got (%q, %.4f)", got, conf)
	}
}

// TestDetectStructureIsDeterministic locks the tie-break in DetectStructure, the
// second instance of the same defect as ClassifyDomain's: the best-type search
// ranged a map with a strict >, so tied pattern scores were resolved by Go's
// randomized map iteration order.
//
// This one was the more damaging of the two. DocumentType feeds
// calculateConfidenceAdjustments, where a tabular type grants tabular_boost of
// +20 — so a coin flip between "TSV" and "Code" moved EVERY finding in the
// document across a confidence band. Confidence is part of the suppression hash,
// so the flapping could also invalidate users' suppression rules between runs.
func TestDetectStructureIsDeterministic(t *testing.T) {
	sd := NewStructureDetector()

	for _, content := range []string{
		// Tab-separated prose that also looks like code to the Code pattern.
		"name\tvalue\tnotes\nfoo\t1\tok\nbar\t2\tok\n",
		"key: value\nother: thing\n",
		"a,b,c\n1,2,3\n",
		"func main() {\n\tx := 1\n}\n",
	} {
		first, firstConf := sd.DetectStructure(content, "input.txt")
		for i := 0; i < 200; i++ {
			got, conf := sd.DetectStructure(content, "input.txt")
			if got != first || conf != firstConf {
				t.Fatalf("DetectStructure(%q) is not deterministic: got (%q, %.4f) on iteration %d, want (%q, %.4f)",
					content, got, conf, i, first, firstConf)
			}
		}
	}
}

// TestAnalyzeContextIsDeterministic is the end-to-end guard: the two tie-breaks
// above must make the whole insight bundle reproducible, including the
// ConfidenceAdjustments map that scoring actually consumes.
func TestAnalyzeContextIsDeterministic(t *testing.T) {
	ca := NewContextAnalyzer()
	const content = "customer_ssn\tvalue\n449-87-4100\t1\naccount_number_test\t4012888888881881\n"

	first := ca.AnalyzeContext(content, "export.txt")
	for i := 0; i < 100; i++ {
		got := ca.AnalyzeContext(content, "export.txt")
		if got.Domain != first.Domain || got.DocumentType != first.DocumentType {
			t.Fatalf("AnalyzeContext not deterministic on iteration %d: (%q,%q) vs (%q,%q)",
				i, got.Domain, got.DocumentType, first.Domain, first.DocumentType)
		}
		if len(got.ConfidenceAdjustments) != len(first.ConfidenceAdjustments) {
			t.Fatalf("ConfidenceAdjustments size differs on iteration %d: %d vs %d",
				i, len(got.ConfidenceAdjustments), len(first.ConfidenceAdjustments))
		}
		for k, v := range first.ConfidenceAdjustments {
			if got.ConfidenceAdjustments[k] != v {
				t.Fatalf("ConfidenceAdjustments[%q] differs on iteration %d: %v vs %v",
					k, i, got.ConfidenceAdjustments[k], v)
			}
		}
	}
}
