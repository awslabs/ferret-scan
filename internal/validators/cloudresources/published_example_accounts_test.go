// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cloudresources

import "testing"

func arnFindings(t *testing.T, content string) []float64 {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, "probe.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	var got []float64
	for _, m := range ms {
		if m.Type == "AWS_ARN" {
			got = append(got, m.Confidence)
		}
	}
	return got
}

// #1027: an ARN in the AWS documentation account is reported, never dropped, at LOW with a
// published ceiling; any other account (one digit away included) is untouched.
func TestPublishedExampleAccountIsHeldAtLow(t *testing.T) {
	for _, line := range []string{
		"Role: arn:aws:iam::123456789012:role/MyRole",
		"arn:aws:iam::123456789012:role/MyRole",
		"arn:aws:lambda:us-east-1:123456789012:function:my-function",
		"arn:aws-cn:lambda:cn-north-1:123456789012:function:cn-fn",
		"arn:aws:sts::123456789012:assumed-role/Accounting-Role/Jane",
	} {
		got := arnFindings(t, line)
		if len(got) != 1 || got[0] > publishedExampleCeiling {
			t.Errorf("%q: AWS_ARN %v, want one finding at most %v", line, got, publishedExampleCeiling)
		}
		ms, _ := NewValidator().ValidateContent(line, "probe.txt")
		if len(ms) > 0 {
			if c, ok := ms[0].Metadata[confidenceCeilingKey].(float64); !ok || c != publishedExampleCeiling {
				t.Errorf("%q: %s = %v, want %v", line, confidenceCeilingKey, ms[0].Metadata[confidenceCeilingKey], publishedExampleCeiling)
			}
		}
	}
}

func TestOtherAccountsKeepTheirScore(t *testing.T) {
	for _, line := range []string{
		"arn:aws:iam::123456789013:role/MyRole",
		"arn:aws:iam::023456789012:role/MyRole",
		"arn:aws:iam::210987654321:role/MyRole",
		"arn:aws:lambda:us-east-1:111122223333:function:my-function",
		"arn:aws:s3:::123456789012-backups", // account-less form: the id is part of a bucket name
	} {
		got := arnFindings(t, line)
		if len(got) != 1 {
			t.Errorf("%q: %v, want one finding", line, got)
			continue
		}
		ms, _ := NewValidator().ValidateContent(line, "probe.txt")
		if _, ok := ms[0].Metadata[confidenceCeilingKey]; ok {
			t.Errorf("%q: an unlisted account published a ceiling", line)
		}
		if line != "arn:aws:s3:::123456789012-backups" && got[0] < 90 {
			t.Errorf("%q: AWS_ARN %v, want HIGH", line, got)
		}
	}
}

func TestPublishedExampleAccountsAreWellFormed(t *testing.T) {
	for id, src := range publishedExampleAWSAccounts {
		if src == "" || !awsAccountIDPattern.MatchString(id) {
			t.Errorf("%q: bad entry (source %q)", id, src)
		}
	}
	if publishedExampleCeiling >= 60 {
		t.Errorf("publishedExampleCeiling = %v is MEDIUM or above", publishedExampleCeiling)
	}
}
