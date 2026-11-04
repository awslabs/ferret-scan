// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Tests for #881 Part 2, temporary (ASIA) access key IDs. Values are assembled at run time; none
// is a real credential.

var (
	tmpKeyID     = "AS" + "IA" + "QZ7MK2PL9VNB4RTX"
	longKeyID    = "AK" + "IA" + "QZ7MK2PL9VNB4RTX"
	tmpSecret    = "tIWgqmCdzQo6ZmMWR4A92POE5IkrJSPkdQYtpCx5"
	tmpSession   = "IQoJb3JpZ2luX2VjE" + strings.Repeat("Kx9mQ2pZ7vR4tW8yB3nL6cF1hJ5dG0sA", 10) + "=="
	docTmpKeyID  = "AS" + "IA" + "IOSFODNN7EXAMPLE"
	iamUniqueIDs = []string{"AI" + "DA", "AR" + "OA", "AN" + "PA"}
)

func awsKeyFindings(t *testing.T, v *Validator, content, path string) []detector.Match {
	t.Helper()
	ms, err := v.ValidateContent(content, path)
	if err != nil {
		t.Fatal(err)
	}
	var out []detector.Match
	for _, m := range ms {
		if m.Type == "AWS_ACCESS_KEY" {
			out = append(out, m)
		}
	}
	return out
}

// TestTemporaryAccessKeyID is #881's ASIA table: reported everywhere as AWS_ACCESS_KEY with
// aws_key_kind temporary; LOW bare or under its own label; HIGH beside its secret key or session
// token; 15 when it is AWS's documentation placeholder. Before #881 every row reported nothing.
func TestTemporaryAccessKeyID(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		name, content string
		paired        bool
		want          float64 // exact for unpaired; a floor for paired
	}{
		{"bare", tmpKeyID + "\n", false, 55},
		{"in prose", "the caller used " + tmpKeyID + " for the upload\n", false, 55},
		{"ini label", "[default]\naws_access_key_id = " + tmpKeyID + "\n", false, 55},
		{"env label", "AWS_ACCESS_KEY_ID=" + tmpKeyID + "\n", false, 55},
		{"a stem label is still label-only", "SERVICE_API_KEY=" + tmpKeyID + "\n", false, 55},
		{"template with empty values", "aws_access_key_id = " + tmpKeyID + "\naws_secret_access_key = \naws_session_token = \n", false, 55},
		{"credentials triple", "[default]\naws_access_key_id = " + tmpKeyID + "\naws_secret_access_key = " + tmpSecret + "\naws_session_token = " + tmpSession + "\n", true, 90},
		{"env exports", "export AWS_ACCESS_KEY_ID=" + tmpKeyID + "\nexport AWS_SECRET_ACCESS_KEY=" + tmpSecret + "\nexport AWS_SESSION_TOKEN=" + tmpSession + "\n", true, 90},
		{"sts json", "{\n  \"Credentials\": {\n    \"AccessKeyId\": \"" + tmpKeyID + "\",\n    \"SecretAccessKey\": \"" + tmpSecret + "\",\n    \"SessionToken\": \"" + tmpSession + "\"\n  }\n}\n", true, 90},
		{"one line", `{"Version": 1, "AccessKeyId": "` + tmpKeyID + `", "SecretAccessKey": "` + tmpSecret + `", "SessionToken": "` + tmpSession + `"}` + "\n", true, 90},
		{"secret key only", "aws_access_key_id = " + tmpKeyID + "\naws_secret_access_key = " + tmpSecret + "\n", true, 90},
		{"session token only", "aws_access_key_id = " + tmpKeyID + "\naws_session_token = " + tmpSession + "\n", true, 90},
		{"secret on the line before", "aws_secret_access_key = " + tmpSecret + "\naws_access_key_id = " + tmpKeyID + "\n", true, 90},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ms := awsKeyFindings(t, v, c.content, "credentials")
			if len(ms) != 1 || ms[0].Text != tmpKeyID {
				t.Fatalf("want one AWS_ACCESS_KEY over the ASIA ID, got %v", ms)
			}
			m := ms[0]
			if m.Metadata["aws_key_kind"] != "temporary" {
				t.Errorf("aws_key_kind = %v, want temporary", m.Metadata["aws_key_kind"])
			}
			checks, _ := m.Metadata["validation_checks"].(map[string]bool)
			if checks["paired_secret_or_session_token"] != c.paired {
				t.Errorf("paired_secret_or_session_token = %v, want %v", checks["paired_secret_or_session_token"], c.paired)
			}
			ceiling, published := m.Metadata[ConfidenceCeilingKey].(float64)
			if c.paired {
				if published || m.Confidence < c.want {
					t.Errorf("paired: confidence %v (ceiling published: %v %v), want >= %v and no ceiling", m.Confidence, published, ceiling, c.want)
				}
			} else if m.Confidence != c.want || ceiling != awsTemporaryKeyUnpairedCeiling {
				t.Errorf("unpaired: confidence %v under ceiling %v, want %v under %v", m.Confidence, ceiling, c.want, awsTemporaryKeyUnpairedCeiling)
			}
		})
	}

	t.Run("documentation placeholder keeps the EXAMPLE ceiling", func(t *testing.T) {
		for _, content := range []string{
			"aws_access_key_id = " + docTmpKeyID + "\n",
			"aws_access_key_id = " + docTmpKeyID + "\naws_secret_access_key = " + tmpSecret + "\n",
		} {
			ms := awsKeyFindings(t, v, content, "credentials")
			if len(ms) != 1 || ms[0].Confidence != awsDocPlaceholderCeiling || ms[0].Metadata[ConfidenceCeilingKey] != awsDocPlaceholderCeiling {
				t.Errorf("%q: got %v, want one finding at the %v placeholder ceiling", content, ms, awsDocPlaceholderCeiling)
			}
		}
	})

	t.Run("AKIA is unchanged", func(t *testing.T) {
		ms := awsKeyFindings(t, v, "aws_access_key_id = "+longKeyID+"\n", "credentials")
		if len(ms) != 1 || ms[0].Confidence < 90 {
			t.Fatalf("got %v, want one AKIA finding at its full score", ms)
		}
		if _, ok := ms[0].Metadata["aws_key_kind"]; ok {
			t.Error("an AKIA finding carries aws_key_kind; AKIA findings are unchanged by #881")
		}
		if _, ok := ms[0].Metadata[ConfidenceCeilingKey]; ok {
			t.Error("an AKIA finding carries a ceiling")
		}
	})

	t.Run("other IAM unique IDs are not access keys", func(t *testing.T) {
		for _, p := range iamUniqueIDs {
			id := p + "QZ7MK2PL9VNB4RTX"
			for _, content := range []string{id + "\n", `{"UserId": "` + id + `"}` + "\n", "RoleId=" + id + "\n"} {
				if ms := awsKeyFindings(t, v, content, "x.txt"); len(ms) != 0 {
					t.Errorf("%q reported %v, want no AWS_ACCESS_KEY", content, ms)
				}
			}
		}
	})
}

// TestCloudTrailTemporaryKeysStayLow is #881's CloudTrail decoy: an event-history export writes the
// caller's access key ID on every row and no secret anywhere. Every ASIA row is reported, LOW; the
// AKIA rows keep their score.
func TestCloudTrailTemporaryKeysStayLow(t *testing.T) {
	v := NewValidator()
	var b strings.Builder
	b.WriteString("Event ID,Event time,User name,Event name,Event source,AWS access key,Source IP address,AWS region\n")
	for i := 0; i < 50; i++ {
		prefix := "AS" + "IA"
		if i%5 == 0 {
			prefix = "AK" + "IA"
		}
		fmt.Fprintf(&b, "%08x-1111-2222-3333-%012x,2026-10-%02dT10:00:00Z,alice,GetObject,s3.amazonaws.com,%sQZ7MK2PL9VNB%04d,203.0.113.%d,us-east-1\n",
			i*7919, i*104729, 1+i%28, prefix, i, 1+i)
	}
	ms := awsKeyFindings(t, v, b.String(), "event_history.csv")
	var tmp, long int
	for _, m := range ms {
		switch {
		case strings.HasPrefix(m.Text, awsTemporaryKeyPrefix):
			tmp++
			if m.Confidence >= 60 {
				t.Errorf("ASIA row %d at %v, want LOW", m.LineNumber, m.Confidence)
			}
		default:
			long++
			if m.Confidence < 90 {
				t.Errorf("AKIA row %d at %v, want its full score", m.LineNumber, m.Confidence)
			}
		}
	}
	if tmp != 40 || long != 10 {
		t.Errorf("got %d ASIA and %d AKIA findings, want 40 and 10", tmp, long)
	}
}

// TestOneAWSAccessKeyDefinition: the row, isAWSAccessKey and the pairing regex agree on what an
// access key ID is, because the regex is rendered from the row.
func TestOneAWSAccessKeyDefinition(t *testing.T) {
	v := NewValidator()
	if got, want := reAKIAAnywhere.String(), `\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`; got != want {
		t.Errorf("reAKIAAnywhere = %s, want %s", got, want)
	}
	for _, p := range awsAccessKeyRule.Prefixes {
		id := p + "QZ7MK2PL9VNB4RTX"
		if !v.isAWSAccessKey(id) || !reAKIAAnywhere.MatchString("x "+id+" y") || !hasAWSAccessKeyPrefix(id) {
			t.Errorf("%s: the row, isAWSAccessKey and reAKIAAnywhere disagree", id)
		}
	}
	found := false
	for _, p := range awsAccessKeyRule.Prefixes {
		found = found || p == awsTemporaryKeyPrefix
	}
	if !found {
		t.Errorf("awsTemporaryKeyPrefix %q is not a prefix of the AWS_ACCESS_KEY row", awsTemporaryKeyPrefix)
	}
	for _, p := range iamUniqueIDs {
		if v.isAWSAccessKey(p + "QZ7MK2PL9VNB4RTX") {
			t.Errorf("%s ID typed as an access key", p)
		}
	}
}
