// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/internal/config"
	"github.com/awslabs/ferret-scan/internal/detector"
)

// scan is a test helper that runs the validator over content and returns the matches.
func scan(t *testing.T, content string) []detector.Match {
	t.Helper()
	v := NewValidator()
	ms, err := v.ValidateContent(content, "test.txt")
	if err != nil {
		t.Fatalf("ValidateContent error: %v", err)
	}
	return ms
}

// findByType returns the matches of a given resource type.
func findByType(ms []detector.Match, typ string) []detector.Match {
	var out []detector.Match
	for _, m := range ms {
		if m.Type == typ {
			out = append(out, m)
		}
	}
	return out
}

func TestNewValidator(t *testing.T) {
	v := NewValidator()
	if v == nil {
		t.Fatal("NewValidator returned nil")
	}
	if len(v.patterns) == 0 {
		t.Error("expected compiled patterns")
	}
	for _, p := range []string{"aws", "azure", "gcp", "oci", "ibm", "alibaba"} {
		if !v.enabledProviders[p] {
			t.Errorf("provider %q should be enabled by default", p)
		}
	}
}

// --- Detection of canonical formats per provider ---

func TestDetectsCanonicalFormats(t *testing.T) {
	cases := []struct {
		name    string
		content string
		wantTyp string
	}{
		{"aws-iam-role", "arn:aws:iam::123456789012:role/MyRole", "AWS_ARN"},
		{"aws-lambda", "arn:aws:lambda:us-east-1:123456789012:function:my-fn", "AWS_ARN"},
		{"aws-ec2", "arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123def456789", "AWS_ARN"},
		{"aws-s3", "arn:aws:s3:::my-prod-bucket/path/obj", "AWS_ARN"},
		{"azure-sub", "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct", "AZURE_RESOURCE_ID"},
		{"gcp-zone", "projects/acme-prod-7281/zones/us-central1-a/instances/db", "GCP_RESOURCE_NAME"},
		{"gcp-location", "projects/acme-prod-7281/locations/us-central1/functions/fn", "GCP_RESOURCE_NAME"},
		{"oci", "ocid1.instance.oc1.us-phoenix-1.abcdefghijk123456", "OCI_OCID"},
		{"ibm-crn", "crn:v1:bluemix:public:cos:us-south:a/abc123def456:bucket-id:object-key", "IBM_CRN"},
		{"alibaba", "acs:ecs:cn-hangzhou:123456789:instance/i-abc123def", "ALIBABA_ARN"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := scan(t, c.content)
			if len(findByType(ms, c.wantTyp)) == 0 {
				t.Errorf("expected a %s match for %q, got %d matches %v", c.wantTyp, c.content, len(ms), ms)
			}
		})
	}
}

// --- Regression: GovCloud / China / ISO partitions (were silently missed) ---

func TestDetectsNonStandardAWSPartitions(t *testing.T) {
	cases := []string{
		"arn:aws-us-gov:iam::123456789012:role/GovAdmin",
		"arn:aws-cn:lambda:cn-north-1:123456789012:function:cn-fn",
		"arn:aws-iso:ec2:us-iso-east-1:123456789012:instance/i-0abc123",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			ms := findByType(scan(t, c), "AWS_ARN")
			if len(ms) == 0 {
				t.Errorf("non-standard AWS partition ARN not detected: %q", c)
			}
			if ms[0].Metadata["account_id"] != "123456789012" {
				t.Errorf("account ID not extracted for %q: got %v", c, ms[0].Metadata["account_id"])
			}
		})
	}
}

// --- Regression: no duplicate emission ---

func TestNoDuplicateEmission(t *testing.T) {
	for _, c := range []string{
		"arn:aws:iam::123456789012:role/MyRole",
		"arn:aws:lambda:us-east-1:123456789012:function:fn",
		"arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123",
	} {
		t.Run(c, func(t *testing.T) {
			ms := scan(t, c)
			if len(ms) != 1 {
				t.Errorf("expected exactly 1 match for %q, got %d: %v", c, len(ms), ms)
			}
		})
	}
}

func TestAzureNestedSpansDeduped(t *testing.T) {
	// The full resource path also contains a /subscriptions/.../resourceGroups/<rg>
	// prefix that the shorter pattern matches; only the maximal span should emit.
	content := "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct"
	ms := scan(t, content)
	if len(ms) != 1 {
		t.Errorf("expected 1 Azure match (longest span), got %d: %v", len(ms), ms)
	}
	if ms[0].Text != content {
		t.Errorf("expected the full path, got %q", ms[0].Text)
	}
}

// --- Regression: correct line numbers via byte offset ---

func TestLineNumbersUseByteOffset(t *testing.T) {
	content := "line1\narn:aws:iam::111122223333:role/A\nline3\narn:aws:iam::444455556666:role/B"
	ms := scan(t, content)
	got := map[string]int{}
	for _, m := range ms {
		got[m.Metadata["account_id"].(string)] = m.LineNumber
	}
	if got["111122223333"] != 2 {
		t.Errorf("first ARN should be line 2, got %d", got["111122223333"])
	}
	if got["444455556666"] != 4 {
		t.Errorf("second ARN should be line 4, got %d", got["444455556666"])
	}
}

func TestRepeatedResourceDistinctLines(t *testing.T) {
	content := "header\narn:aws:iam::111122223333:role/A\nfiller\nfiller\narn:aws:iam::111122223333:role/A"
	ms := scan(t, content)
	if len(ms) != 2 {
		t.Fatalf("expected 2 matches (same ARN on 2 lines), got %d", len(ms))
	}
	lines := map[int]bool{ms[0].LineNumber: true, ms[1].LineNumber: true}
	if !lines[2] || !lines[5] {
		t.Errorf("expected matches on lines 2 and 5, got %d and %d", ms[0].LineNumber, ms[1].LineNumber)
	}
}

// --- Regression: local (not document-wide) test-keyword penalty ---

func TestTestKeywordPenaltyIsLineLocal(t *testing.T) {
	// "example" on an unrelated line must NOT penalize the real ARN on another line.
	content := "see the example below\narn:aws:iam::999988887777:role/ProdRole"
	ms := findByType(scan(t, content), "AWS_ARN")
	if len(ms) != 1 {
		t.Fatalf("expected the real ARN to be detected, got %d", len(ms))
	}
	if ms[0].Confidence < 90 {
		t.Errorf("ARN on a clean line should keep HIGH confidence; got %.0f (document-wide penalty leaked?)", ms[0].Confidence)
	}
}

func TestTestKeywordPenaltyAppliesOnSameLine(t *testing.T) {
	content := "example: arn:aws:iam::999988887777:role/SampleRole"
	ms := findByType(scan(t, content), "AWS_ARN")
	if len(ms) != 1 {
		t.Fatalf("expected detection, got %d", len(ms))
	}
	// base 85 + account 10 - 20 (same-line "example") = 75
	if ms[0].Confidence > 80 {
		t.Errorf("same-line 'example' should lower confidence; got %.0f", ms[0].Confidence)
	}
}

// --- Regression: substring vs whole-token keyword matching ---

func TestProductionNamesWithKeywordSubstringsNotDropped(t *testing.T) {
	// These names embed test/demo/sample/template as SUBSTRINGS but are real resources.
	cases := []string{
		"arn:aws:iam::123456789012:role/attestation-signer",               // 'test'
		"arn:aws:iam::123456789012:role/latest-deployer",                  // 'test'
		"arn:aws:lambda:us-east-1:123456789012:function:demographics-agg", // 'demo'
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			ms := findByType(scan(t, c), "AWS_ARN")
			if len(ms) == 0 {
				t.Errorf("production resource with keyword-substring name was dropped: %q", c)
			}
		})
	}
}

// --- Account-gated confidence tiering ---

func TestConfidenceTiering(t *testing.T) {
	cases := []struct {
		name    string
		content string
		minConf float64
		maxConf float64
	}{
		{"iam-high", "arn:aws:iam::123456789012:role/Admin", 90, 100},
		{"azure-sub-high", "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a", 90, 100},
		{"gcp-project-high", "context project\nprojects/acme-prod-7281/zones/us-central1-a/instances/db", 90, 100},
		{"s3-low", "arn:aws:s3:::acme-prod-backups", 0, 59},
		{"oci-low", "ocid1.instance.oc1.us-phoenix-1.abcdefghijk123456", 0, 59},
		{"mgmt-group-low", "/providers/Microsoft.Management/managementGroups/mg-corp", 0, 59},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := scan(t, c.content)
			if len(ms) == 0 {
				t.Fatalf("no match for %q", c.content)
			}
			conf := ms[0].Confidence
			if conf < c.minConf || conf > c.maxConf {
				t.Errorf("%s confidence %.0f outside expected [%.0f,%.0f]", c.name, conf, c.minConf, c.maxConf)
			}
		})
	}
}

// --- Public-by-design allowlist ---

func TestPublicResourcesNotDetected(t *testing.T) {
	cases := []string{
		"arn:aws:iam::aws:policy/AdministratorAccess",
		"arn:aws:iam::aws:policy/service-role/AmazonEC2RoleforSSM",
		"projects/bigquery-public-data/datasets/samples",
		"projects/gcp-public-data-landsat/zones/us/instances/x",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			ms := scan(t, c)
			if len(ms) != 0 {
				t.Errorf("public-by-design resource should not be flagged: %q -> %v", c, ms)
			}
		})
	}
}

// --- Regression: patterns must not bleed across newlines ---

func TestNoNewlineBleed(t *testing.T) {
	content := "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1\nprojects/acme-prod-7281/zones/us-central1-a/instances/db"
	ms := scan(t, content)
	for _, m := range ms {
		if strings.Contains(m.Text, "\n") {
			t.Errorf("match bled across newline: %q", m.Text)
		}
	}
	if len(findByType(ms, "AZURE_RESOURCE_ID")) == 0 || len(findByType(ms, "GCP_RESOURCE_NAME")) == 0 {
		t.Errorf("expected both Azure and GCP matches as independent findings, got %v", ms)
	}
}

// --- Regression: IBM CRN README examples (9-segment) must match ---

func TestIBMCRNNineSegmentMatches(t *testing.T) {
	for _, c := range []string{
		"crn:v1:bluemix:public:cos:us-south:a/abc123def456:bucket-id:object-key",
		"crn:v1:bluemix:public:iam:global:a/abc123def456:policy:policy-id",
	} {
		t.Run(c, func(t *testing.T) {
			ms := findByType(scan(t, c), "IBM_CRN")
			if len(ms) == 0 {
				t.Errorf("9-segment IBM CRN not detected: %q", c)
			}
		})
	}
}

// --- Regression: over-broad / decoy rejection ---

func TestRejectsShortOCIDDecoy(t *testing.T) {
	ms := scan(t, "ocid1.x.oc1..short")
	if len(ms) != 0 {
		t.Errorf("implausibly short OCID should be rejected, got %v", ms)
	}
}

func TestAzureUUIDMustBeWellFormed(t *testing.T) {
	// 36 hyphens is not a UUID; the old [0-9a-f-]{36} class accepted it.
	bad := "/subscriptions/------------------------------------/resourceGroups/rg/providers/x/y/z"
	if ms := scan(t, bad); len(ms) != 0 {
		t.Errorf("malformed Azure subscription should not match, got %v", ms)
	}
}

func TestAzureUUIDCaseInsensitive(t *testing.T) {
	up := "/subscriptions/ABCDEF01-1234-1234-1234-123456789012/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
	if len(findByType(scan(t, up), "AZURE_RESOURCE_ID")) == 0 {
		t.Error("uppercase Azure subscription GUID should match")
	}
}

// --- Unicode: match must not truncate mid-name (validated content) ---

func TestUnicodeInResourceNameNotTruncated(t *testing.T) {
	// The resource name contains a non-ASCII char. We accept either a clean
	// full-name match or no match, but NOT a silently truncated partial value.
	content := "arn:aws:iam::123456789012:role/Próduction"
	ms := findByType(scan(t, content), "AWS_ARN")
	for _, m := range ms {
		if strings.HasPrefix(m.Text, "arn:aws:iam::123456789012:role/Pr") && !strings.Contains(m.Text, "ó") {
			t.Errorf("match truncated at non-ASCII byte: %q (should capture the full name or not match)", m.Text)
		}
	}
}

// --- Metadata correctness ---

func TestMetadataFields(t *testing.T) {
	ms := findByType(scan(t, "arn:aws:lambda:us-east-1:123456789012:function:billing"), "AWS_ARN")
	if len(ms) == 0 {
		t.Fatal("no match")
	}
	md := ms[0].Metadata
	if md["resource_type"] != "AWS_ARN" {
		t.Errorf("resource_type = %v, want AWS_ARN", md["resource_type"])
	}
	if md["provider"] != "aws" {
		t.Errorf("provider = %v, want aws", md["provider"])
	}
	if md["account_id"] != "123456789012" {
		t.Errorf("account_id = %v", md["account_id"])
	}
	if md["region"] != "us-east-1" {
		t.Errorf("region = %v", md["region"])
	}
	if md["service"] != "lambda" {
		t.Errorf("service = %v", md["service"])
	}
}

// --- Provider enable/disable ---

func TestProviderDisable(t *testing.T) {
	v := NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]interface{}{
		"cloud_resources": {"enabled_providers": map[string]interface{}{"aws": false}},
	}})
	ms, _ := v.ValidateContent("arn:aws:iam::123456789012:role/X\nocid1.instance.oc1.iad.abcdefghij012345", "t.txt")
	if len(findByType(ms, "AWS_ARN")) != 0 {
		t.Error("AWS should be disabled")
	}
	if len(findByType(ms, "OCI_OCID")) == 0 {
		t.Error("OCI should still be enabled")
	}
}

func TestCustomPattern(t *testing.T) {
	v := NewValidator()
	v.Configure(&config.Config{Validators: map[string]map[string]interface{}{
		"cloud_resources": {"custom_patterns": []interface{}{`myc:[a-z]+:[0-9]{6,}`}},
	}})
	ms, _ := v.ValidateContent("ref myc:prod:123456 here", "t.txt")
	if len(ms) == 0 {
		t.Error("custom pattern should match")
	}
}

func TestInvalidCustomPatternIgnored(t *testing.T) {
	v := NewValidator()
	// Must not panic or error on an invalid regex.
	v.Configure(&config.Config{Validators: map[string]map[string]interface{}{
		"cloud_resources": {"custom_patterns": []interface{}{`[unclosed`}},
	}})
	if _, err := v.ValidateContent("arn:aws:iam::123456789012:role/X", "t.txt"); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- DoS guard: oversize input is skipped ---

func TestOversizeContentSkipped(t *testing.T) {
	big := strings.Repeat("arn:aws:iam::123456789012:role/X\n", (maxContentBytes/33)+100)
	if len(big) <= maxContentBytes {
		t.Fatalf("test setup: content not over cap (%d <= %d)", len(big), maxContentBytes)
	}
	ms := scan(t, big)
	if len(ms) != 0 {
		t.Errorf("oversize content should be skipped, got %d matches", len(ms))
	}
}

// --- Interface methods ---

func TestCalculateConfidence(t *testing.T) {
	v := NewValidator()
	conf, checks := v.CalculateConfidence("arn:aws:iam::123456789012:role/X")
	if conf < 90 {
		t.Errorf("IAM ARN with account should score HIGH, got %.0f", conf)
	}
	if !checks["valid_account_id"] {
		t.Error("valid_account_id check should be true")
	}
}

func TestAnalyzeContextPositiveNegative(t *testing.T) {
	v := NewValidator()
	pos := v.AnalyzeContext("arn:aws:iam::123456789012:role/X", detector.ContextInfo{
		FullLine: "production aws account role arn",
	})
	if pos <= 0 {
		t.Errorf("positive keywords should raise impact, got %.0f", pos)
	}
	neg := v.AnalyzeContext("arn:aws:iam::123456789012:role/X", detector.ContextInfo{
		FullLine: "this is an example",
	})
	if neg >= 0 {
		t.Errorf("negative keyword should lower impact, got %.0f", neg)
	}
}

func TestGetCheckInfo(t *testing.T) {
	v := NewValidator()
	info := v.GetCheckInfo()
	if info.Name != "CLOUD_RESOURCES" {
		t.Errorf("check name = %q", info.Name)
	}
	if info.ShortDescription == "" {
		t.Error("short description should not be empty")
	}
}

// --- Helper unit tests ---

func TestIsAWSARNPrefix(t *testing.T) {
	cases := map[string]bool{
		"arn:aws:iam::123:role/x":        true,
		"arn:aws-us-gov:iam::123:role/x": true,
		"arn:aws-cn:s3:::b":              true,
		"arn:awssomething":               false,
		"arn:aws":                        false,
		"notanarn":                       false,
	}
	for in, want := range cases {
		if got := isAWSARNPrefix(in); got != want {
			t.Errorf("isAWSARNPrefix(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestHasKeywordToken(t *testing.T) {
	kws := []string{"test", "example"}
	if hasKeywordToken("company-templates bucket", kws) {
		t.Error("'templates' should NOT match token 'test'")
	}
	if !hasKeywordToken("see the example here", kws) {
		t.Error("'example' as a whole token should match")
	}
	if !hasKeywordToken("a test case", kws) {
		t.Error("'test' as a whole token should match")
	}
}

func TestGetProviderFromType(t *testing.T) {
	cases := map[string]string{
		"AWS_ARN": "aws", "AZURE_RESOURCE_ID": "azure", "GCP_RESOURCE_NAME": "gcp",
		"OCI_OCID": "oci", "IBM_CRN": "ibm", "ALIBABA_ARN": "alibaba", "CLOUD_RESOURCE_ID": "",
	}
	for typ, want := range cases {
		if got := getProviderFromType(typ); got != want {
			t.Errorf("getProviderFromType(%q) = %q, want %q", typ, got, want)
		}
	}
}

func TestExtractAccountIDAcrossProviders(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::123456789012:role/x":                                     "123456789012",
		"arn:aws-us-gov:iam::123456789012:role/x":                              "123456789012",
		"/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/x": "12345678-1234-1234-1234-123456789012",
		"crn:v1:bluemix:public:cos:us-south:a/acct789:bucket:b":                "acct789",
		"acs:ecs:cn-hangzhou:123456789:instance/i-x":                           "123456789",
		"ocid1.instance.oc1.iad.abcdefghij012345":                              "",
	}
	for in, want := range cases {
		if got := extractAccountID(in); got != want {
			t.Errorf("extractAccountID(%q) = %q, want %q", in, got, want)
		}
	}
}
