// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"strings"
	"testing"
)

// TestPrivateProjectsAreNotSuppressed is the leak gate.
//
// The public-project allowlist used to be tested with
// strings.Contains(match, "projects/"+prefix), with no segment boundary. Because
// the list carried the broad bare entry "public-data", any project whose ID merely
// STARTED with it was silently dropped — and a suppressed cloud resource is a
// finding the report never shows, which is the same class of miss as a detection
// failure.
//
// The first two cases need no attacker at all: "public-database-prod" and
// "public-datastore-pii" are ordinary project names.
func TestPrivateProjectsAreNotSuppressed(t *testing.T) {
	cases := []struct {
		name string
		id   string
	}{
		{"ordinary name extending public-data", "public-database-prod"},
		{"ordinary name extending public-data (2)", "public-datastore-pii"},
		{"attacker extends bigquery-public-data", "bigquery-public-data-evilcorp"},
		{"attacker extends gcp-public-data", "gcp-public-data-internal-acme"},
		{"unrelated private project", "acme-prod-internal"},
		{"public-data as a mid-word substring", "not-public-database"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resource := "projects/" + tc.id + "/zones/us-central1-a/instances/customer-db"
			if isPublicResource(resource) {
				t.Errorf("isPublicResource(%q) = true — this is a PRIVATE project, and "+
					"suppressing it means the resource never appears in the report. The "+
					"allowlist must match the project segment exactly, not as a prefix of it.",
					resource)
			}
		})
	}
}

// TestPublicProjectsStaySuppressed is the other direction: the allowlist must keep
// doing its job, or every IaC file full of public dataset references becomes noise.
//
// gcp-public-data-landsat is the load-bearing case. It is a REAL Google public
// project whose ID extends "gcp-public-data", so a blanket segment-boundary rule
// would have broken it — which is why the list enumerates real project IDs rather
// than matching a shape.
func TestPublicProjectsStaySuppressed(t *testing.T) {
	cases := []string{
		"bigquery-public-data",
		"gcp-public-data-landsat",
		"gcp-public-data-sentinel-2",
		"gcp-public-data-nexrad-l2",
		"public-data",
		"google.com:my-project",
	}

	for _, id := range cases {
		t.Run(id, func(t *testing.T) {
			resource := "projects/" + id + "/zones/us/instances/x"
			if !isPublicResource(resource) {
				t.Errorf("isPublicResource(%q) = false — this is a public-by-design Google "+
					"project and must stay suppressed, or IaC files become pure noise", resource)
			}
		})
	}
}

// TestProjectSegmentBoundary pins the segment logic directly, including the shapes
// the resource-level test cannot express.
func TestProjectSegmentBoundary(t *testing.T) {
	cases := []struct {
		seg  string
		want bool
	}{
		// Exact IDs.
		{"bigquery-public-data", true},
		{"bigquery-public-data/datasets/samples", true},
		{"public-data", true},
		{"public-data/datasets/x", true},
		// Extensions of an exact ID are somebody else's project.
		{"bigquery-public-data-evilcorp", false},
		{"public-database-prod", false},
		{"public-datax", false},
		// Enumerated real extensions.
		{"gcp-public-data-landsat", true},
		{"gcp-public-data-landsat/zones/us/instances/x", true},
		// Not enumerated: fails safe.
		{"gcp-public-data", false},
		{"gcp-public-data-internal-acme", false},
		// The colon form is prefix-matched by design.
		{"google.com:anything-here", true},
		{"google.com:anything/zones/us", true},
		{"googlexcom:notreally", false},
		// Degenerate.
		{"", false},
		{"/", false},
	}

	for _, tc := range cases {
		if got := projectSegmentIsPublic(tc.seg); got != tc.want {
			t.Errorf("projectSegmentIsPublic(%q) = %v, want %v", tc.seg, got, tc.want)
		}
	}
}

// TestPublicAllowlistFailsSafeOnUnknown states the design rule as a test, so a
// future change back to prefix matching has to argue with it.
//
// An ID the allowlist has not heard of must be REPORTED. Adding a newly published
// Google project is a one-line change; failing to report a private one is a finding
// the user never sees.
func TestPublicAllowlistFailsSafeOnUnknown(t *testing.T) {
	unknown := []string{
		"gcp-public-data-somethingnew", // plausibly real, but not enumerated
		"bigquery-public-data-v2",      // plausibly real, but not enumerated
		"public-data-archive",          // plausibly real, but not enumerated
	}
	for _, id := range unknown {
		if projectSegmentIsPublic(id) {
			t.Errorf("projectSegmentIsPublic(%q) = true, but this ID is not in the "+
				"allowlist — unknown projects must fail SAFE (reported), not be suppressed "+
				"on the strength of resembling a public one", id)
		}
	}
}

// TestAWSManagedPolicyArmIsBuiltinUnreachable documents a measured fact that is
// easy to misread from the code alone: isPublicResource's AWS managed-policy arms
// return true for these ARNs, but NO built-in pattern matches them, so on a default
// configuration the arm is never consulted.
//
// Pattern 1 requires a 12-digit account slot (a managed policy has the literal
// "aws" there) and pattern 2 requires "s3:::". The arm therefore contributes zero
// recall on built-in patterns and exists for custom-pattern users, who CAN reach it.
//
// This is asserted rather than deleted for two reasons: deleting it would regress
// those users, and pinning the reachability means a future pattern change that
// makes managed-policy ARNs matchable will fail here and prompt a deliberate
// decision about whether suppressing them is still wanted.
func TestAWSManagedPolicyArmIsBuiltinUnreachable(t *testing.T) {
	arns := []string{
		"arn:aws:iam::aws:policy/AdministratorAccess",
		"arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
		"arn:aws-us-gov:iam::aws:policy/AdministratorAccess",
		"arn:aws-cn:iam::aws:policy/AdministratorAccess",
	}

	patterns := compileCloudResourcePatterns()
	for _, arn := range arns {
		// The allowlist says "public".
		if !isPublicResource(arn) {
			t.Errorf("isPublicResource(%q) = false, want true (AWS-managed policy)", arn)
		}
		// But nothing matches it, so the allowlist is never reached.
		for i, p := range patterns {
			if m := p.FindString(arn); m != "" {
				t.Errorf("built-in pattern %d now matches %q as %q — the managed-policy "+
					"suppression arm just became reachable on a default config. Decide "+
					"deliberately whether these should be suppressed before updating this test.",
					i, arn, m)
			}
		}
		if strings.Contains(arn, "iam::aws:") && !strings.Contains(arn, ":::") {
			continue // shape sanity: these are managed-policy ARNs, as intended
		}
		t.Errorf("test fixture %q is not a managed-policy ARN", arn)
	}
}
