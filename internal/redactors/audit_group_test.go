// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redactors

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// One write for an overlap group is ONE audit entry, and that entry names every finding it covered:
// before #773 the audit for "Residence: 77 August Lane, Boise ID 83702" said one PERSON_NAME was
// redacted, failed_redactions 0, for three findings of which two were partly left in cleartext.
func TestAuditRecordsOneEntryPerGroupWithMemberTypes(t *testing.T) {
	rm := newDocIDTestManager(t)
	members := []string{"PERSON_NAME", "PERSON_NAME", "US_STREET_ADDRESS"}
	rm.AddRedactionResult("/in/x1.txt", "/out/x1.txt", &RedactionResult{RedactionMap: []RedactionMapping{
		{DataType: "US_STREET_ADDRESS", RedactedText: "*********************", Confidence: 95,
			Metadata: map[string]interface{}{OverlapGroupKindKey: "partial", OverlapMemberTypesKey: members}},
		{DataType: "EMAIL", RedactedText: "[EMAIL-REDACTED]", Confidence: 70},
	}})

	log, ok := rm.auditLogManager.GetAuditLogByPath("/in/x1.txt")
	if !ok {
		t.Fatal("no audit log for the redacted file")
	}
	if n := len(log.ContentRedactions); n != 2 || log.RedactionSummary.TotalRedactions != 2 {
		t.Fatalf("want one entry per write (2), got %d entries, total %d", n, log.RedactionSummary.TotalRedactions)
	}
	if got := log.ContentRedactions[0].MemberTypes; !reflect.DeepEqual(got, members) {
		t.Fatalf("the group entry must name its members, got %v", got)
	}
	if got := log.ContentRedactions[1].MemberTypes; got != nil {
		t.Fatalf("a single finding's entry carries no member list, got %v", got)
	}
	if got := log.RedactionSummary.DataTypes; !reflect.DeepEqual(got, []string{"US_STREET_ADDRESS", "PERSON_NAME", "EMAIL"}) {
		t.Fatalf("data_types must include every member's type, got %v", got)
	}

	raw, err := json.Marshal(log.ContentRedactions[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "member_types") {
		t.Fatalf("member_types must be omitted for a single finding, so existing audit logs are unchanged: %s", raw)
	}
}
