// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/redactors"
)

// Generate() is the single source of truth for redaction replacement across all
// redactors (plaintext, office, pdf). The CLOUD_RESOURCES validator emits cloud
// provider resource identifiers (AWS ARN incl. GovCloud/China, Azure resource
// ID, GCP resource name, OCI OCID, IBM CRN, Alibaba ARN). None of these has a
// bespoke generator, so they intentionally fall through to each strategy's
// generic branch. These tests lock in that behavior — most importantly that the
// sensitive content (account IDs, resource names, regions) never survives into
// the replacement, regardless of strategy.

// cloudResourceCases are representative findings per provider, each carrying
// sensitive tokens we assert must NOT leak into any redacted output.
var cloudResourceCases = []struct {
	dataType string // the type the validator emits
	original string
	// secrets are substrings of original that must never appear in any redaction
	secrets []string
}{
	{"AWS_ARN", "arn:aws:iam::123456789012:role/ProdAdmin", []string{"123456789012", "ProdAdmin"}},
	{"AWS_ARN", "arn:aws-us-gov:lambda:us-gov-west-1:210987654321:function:gov-fn", []string{"210987654321", "gov-fn", "us-gov-west-1"}},
	{"AZURE_RESOURCE_ID", "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/acmeprodstore", []string{"12345678-1234-1234-1234-123456789012", "prod-rg", "acmeprodstore"}},
	{"GCP_RESOURCE_NAME", "projects/acme-prod-7281/zones/us-central1-a/instances/db-primary", []string{"acme-prod-7281", "db-primary"}},
	{"OCI_OCID", "ocid1.instance.oc1.us-phoenix-1.abcdefghijk123456", []string{"abcdefghijk123456", "us-phoenix-1"}},
	{"IBM_CRN", "crn:v1:bluemix:public:cos:us-south:a/abc123def456:bucket-id:object-key", []string{"abc123def456", "bucket-id", "object-key"}},
	{"ALIBABA_ARN", "acs:ecs:cn-hangzhou:123456789:instance/i-abc123def", []string{"123456789", "i-abc123def"}},
	{"CLOUD_RESOURCE_ID", "arn:custom:service:region:000000000000:resource/secret-name", []string{"secret-name"}},
}

var allStrategies = []struct {
	name     string
	strategy redactors.RedactionStrategy
}{
	{"simple", redactors.RedactionSimple},
	{"format_preserving", redactors.RedactionFormatPreserving},
	{"synthetic", redactors.RedactionSynthetic},
}

// TestCloudResources_NoLeakAcrossStrategies is the load-bearing security test:
// for every provider and every strategy, the sensitive content of the original
// identifier must NOT appear in the redacted replacement.
func TestCloudResources_NoLeakAcrossStrategies(t *testing.T) {
	for _, st := range allStrategies {
		for _, tc := range cloudResourceCases {
			t.Run(st.name+"/"+tc.dataType+"/"+tc.original, func(t *testing.T) {
				got := Generate(tc.original, tc.dataType, st.strategy)
				if got == "" {
					t.Fatalf("Generate returned empty for %q (%s, %s)", tc.original, tc.dataType, st.name)
				}
				if got == tc.original {
					t.Errorf("redaction was a no-op: output equals original %q", tc.original)
				}
				for _, secret := range tc.secrets {
					if strings.Contains(got, secret) {
						t.Errorf("LEAK: %s/%s redaction of %q still contains %q\n  got: %q",
							st.name, tc.dataType, tc.original, secret, got)
					}
				}
			})
		}
	}
}

// TestCloudResources_SimplePlaceholder documents simple-strategy behavior: cloud
// types fall to the generic "[<TYPE>-REDACTED]" placeholder.
func TestCloudResources_SimplePlaceholder(t *testing.T) {
	for _, tc := range cloudResourceCases {
		got := Generate(tc.original, tc.dataType, redactors.RedactionSimple)
		want := "[" + tc.dataType + "-REDACTED]"
		if got != want {
			t.Errorf("simple redaction of %s = %q, want %q", tc.dataType, got, want)
		}
	}
}

// TestCloudResources_FormatPreservingMasksAndKeepsLength documents
// format-preserving behavior: cloud types fall to a full asterisk mask of the
// same byte length (no provider-specific structure is preserved).
func TestCloudResources_FormatPreservingMasksAndKeepsLength(t *testing.T) {
	for _, tc := range cloudResourceCases {
		got := Generate(tc.original, tc.dataType, redactors.RedactionFormatPreserving)
		if len(got) != len(tc.original) {
			t.Errorf("format_preserving %s: length %d != original %d", tc.dataType, len(got), len(tc.original))
		}
		if strings.Trim(got, "*") != "" {
			t.Errorf("format_preserving %s should be an all-asterisk mask, got %q", tc.dataType, got)
		}
	}
}

// TestCloudResources_SyntheticIsLengthMatchedToken documents synthetic behavior:
// cloud types fall to a length-matched random alphanumeric token (no
// provider-specific format — see README-Redaction Validator×Strategy table).
func TestCloudResources_SyntheticIsLengthMatchedToken(t *testing.T) {
	const alphaNum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	for _, tc := range cloudResourceCases {
		got := Generate(tc.original, tc.dataType, redactors.RedactionSynthetic)
		if len(got) != len(tc.original) {
			t.Errorf("synthetic %s: length %d != original %d (expected length-matched)", tc.dataType, len(got), len(tc.original))
		}
		for _, r := range got {
			if !strings.ContainsRune(alphaNum, r) {
				t.Errorf("synthetic %s produced non-alphanumeric %q in %q", tc.dataType, r, got)
				break
			}
		}
	}
}
