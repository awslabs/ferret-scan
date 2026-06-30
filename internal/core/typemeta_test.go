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
		{"AWS_ARN", "Cloud Resource Identifier Detected", 7.0, "", false}, // SARIF only
		{"VISA", "", 0, "Visa credit card", true},                         // gitlab only
		{"SLACK_TOKEN", "", 0, "Slack token", false},                      // gitlab desc, NO remediation
		{"AUTHOR_INFO", "", 0, "Author information", false},               // gitlab desc only
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
