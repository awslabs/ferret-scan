// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import "testing"

// These tests lock the invariants of the per-type metadata registry that the
// SARIF and gitlab-sast formatters now read from (v2 gap 3.3). They guard
// against accidental drift in the registry itself; byte-equality with the
// formatters' previous output is separately guaranteed by the golden corpus.

// TestTypeMeta_KnownTypesResolve spot-checks representative entries across the
// keying tiers (validator-name-level and sub-type-level).
func TestTypeMeta_KnownTypesResolve(t *testing.T) {
	cases := []struct {
		typ           string
		wantSARIF     string  // expected SARIFShort ("" = none)
		wantWeight    float64 // expected SARIFSensitivityWeight
		wantGitLab    string  // expected GitLabCheckDesc ("" = none)
		wantRemediate bool    // whether GitLabRemediation is set
	}{
		{"EMAIL", "Email Address Detected", 5.0, "Email address", true},
		{"SSN", "Social Security Number Detected", 10.0, "Social Security Number", true},
		// AWS_ARN was "SARIF only" — it had a SARIF description and no gitlab copy at all.
		// #662 filled gitlab for every type, so both gitlab columns move here.
		{"AWS_ARN", "Cloud Resource Identifier Detected", 7.0, "AWS resource ARN", true},
		// These rows previously asserted SARIFShort == "" — that these types had gitlab
		// copy and NO SARIF copy. #662 gave every one of the 64 types both a SARIF
		// description and gitlab copy, so those columns move.
		//
		// What must NOT move is any value that already existed. VISA keeps "Visa credit
		// card" and the card brands' shared remediation, assigned by a LOOP rather than a
		// literal; SLACK_TOKEN and AUTHOR_INFO keep their descriptions. An earlier attempt
		// at #662 rewrote the map literals and silently dropped exactly those, because
		// pattern-matching the source found 6 types with gitlab fields when there are 20.
		// This test caught it, which is why the fill is read-modify-write and fill-if-empty.
		//
		// wantRemediate flips to true where a type had a description but no remediation.
		// That asymmetry came from the legacy maps this registry replaced, not from a
		// decision: a finding with no remediation tells a reviewer what was found and
		// nothing about what to do.
		{"VISA", "Visa Card Number Detected", 0, "Visa credit card", true},
		{"SLACK_TOKEN", "Slack Token Detected", 0, "Slack token", true},
		{"AUTHOR_INFO", "Document Author Metadata Detected", 0, "Author information", true},
	}
	for _, c := range cases {
		d, ok := TypeMeta(c.typ)
		if !ok {
			t.Errorf("TypeMeta(%q): not found", c.typ)
			continue
		}
		if d.SARIFShort != c.wantSARIF {
			t.Errorf("TypeMeta(%q).SARIFShort = %q, want %q", c.typ, d.SARIFShort, c.wantSARIF)
		}
		if d.SARIFSensitivityWeight != c.wantWeight {
			t.Errorf("TypeMeta(%q).SARIFSensitivityWeight = %v, want %v", c.typ, d.SARIFSensitivityWeight, c.wantWeight)
		}
		if d.GitLabCheckDesc != c.wantGitLab {
			t.Errorf("TypeMeta(%q).GitLabCheckDesc = %q, want %q", c.typ, d.GitLabCheckDesc, c.wantGitLab)
		}
		if (d.GitLabRemediation != "") != c.wantRemediate {
			t.Errorf("TypeMeta(%q).GitLabRemediation set = %v, want %v", c.typ, d.GitLabRemediation != "", c.wantRemediate)
		}
	}
}

// TestTypeMeta_UnknownTypeMisses confirms an unregistered type returns ok=false
// so every consumer takes its own generic fallback.
func TestTypeMeta_UnknownTypeMisses(t *testing.T) {
	if _, ok := TypeMeta("DEFINITELY_NOT_A_TYPE"); ok {
		t.Error("TypeMeta returned ok=true for an unknown type")
	}
}

// TestTypeMeta_CloudSubTypesShareDescriptionDistinctWeight locks the nuance that
// all 7 cloud sub-types share ONE SARIF description object but each carries the
// 7.0 sensitivity weight independently.
func TestTypeMeta_CloudSubTypesShareDescriptionDistinctWeight(t *testing.T) {
	cloud := []string{"AWS_ARN", "AZURE_RESOURCE_ID", "GCP_RESOURCE_NAME", "OCI_OCID", "IBM_CRN", "ALIBABA_ARN", "CLOUD_RESOURCE_ID"}
	const wantShort = "Cloud Resource Identifier Detected"
	for _, k := range cloud {
		d, ok := TypeMeta(k)
		if !ok {
			t.Errorf("cloud type %q missing from registry", k)
			continue
		}
		if d.SARIFShort != wantShort {
			t.Errorf("cloud type %q SARIFShort = %q, want shared %q", k, d.SARIFShort, wantShort)
		}
		if d.SARIFSensitivityWeight != 7.0 {
			t.Errorf("cloud type %q weight = %v, want 7.0", k, d.SARIFSensitivityWeight)
		}
	}
}

// TestTypeMeta_GitLabName locks the name-tier (gap 3.3 remainder): gitlab-sast
// vulnerability display names, keyed by validator name. Captures the nuances
// that (a) GitLabName is NOT always == SARIFShort (SECRETS differs), and (b)
// sub-types like VISA have no GitLabName so the mapper's title-case fallback
// applies.
func TestTypeMeta_GitLabName(t *testing.T) {
	cases := []struct {
		typ  string
		want string // expected GitLabName ("" = none → mapper fallback)
	}{
		{"CREDIT_CARD", "Credit Card Number Detected"},
		{"SECRETS", "Secret/API Key Detected"}, // differs from SARIFShort "Secret or API Key Detected"
		{"VIN", "Vehicle Identification Number Detected"},
		{"VISA", ""},           // sub-type: no name-tier entry → mapper title-case fallback
		{"AWS_ACCESS_KEY", ""}, // sub-type
	}
	for _, c := range cases {
		d, _ := TypeMeta(c.typ)
		if d.GitLabName != c.want {
			t.Errorf("TypeMeta(%q).GitLabName = %q, want %q", c.typ, d.GitLabName, c.want)
		}
	}
	// Guard the SECRETS != SARIFShort invariant explicitly (the reason GitLabName
	// is a distinct field, not an alias of SARIFShort).
	if d, _ := TypeMeta("SECRETS"); d.GitLabName == d.SARIFShort {
		t.Errorf("SECRETS GitLabName and SARIFShort must differ; both = %q", d.GitLabName)
	}
}
