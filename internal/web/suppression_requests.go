// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// optionalTime is a JSON field that is absent, null, or an RFC 3339 time.
//
// A *string cannot tell the first two apart — an omitted key and `null` both leave it nil — so the edit
// endpoint could not distinguish "keep the expiry" from "clear it", and it cleared it on every edit,
// including the edits that only changed the reason (#866). Set records whether the key was present.
// A value that is neither null nor an RFC 3339 time is kept as Err rather than failing the whole
// decode, so the handler can answer with a message that names the field.
type optionalTime struct {
	Set   bool
	Value *time.Time
	Err   error
}

// UnmarshalJSON reads null, "" (treated as null, as bulk-update-expiration always has) or a time.
func (o *optionalTime) UnmarshalJSON(data []byte) error {
	o.Set = true
	if string(data) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		o.Err = fmt.Errorf("invalid expires_at: want an RFC 3339 time or null")
		return nil
	}
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		o.Err = fmt.Errorf("invalid expires_at %q: want an RFC 3339 time or null", s)
		return nil
	}
	o.Value = &t
	return nil
}

// statusError is a handler error answered with a specific HTTP status instead of 400.
type statusError struct {
	status int
	msg    string
}

func (e *statusError) Error() string { return e.msg }

// badRequest wraps err as a 400.
func badRequest(err error) error {
	return &statusError{status: http.StatusBadRequest, msg: err.Error()}
}

// requireUniqueIDs refuses an id-keyed action on an id that two or more rules share, with 409 Conflict.
//
// The manager's id-keyed mutators act on the FIRST rule with the id, so with a duplicated id an edit,
// disable or removal changed whichever rule came first in the file, which need not be the one the
// operator clicked, and reported success either way (#866). The file can hold a duplicate (a hand edit,
// a merge of two files); refusing to guess is the only safe answer until it is fixed. Checked for every
// id before anything is changed, so a bulk request is refused whole.
func requireUniqueIDs(mgr *suppressions.SuppressionManager, ids ...string) error {
	counts := make(map[string]int, len(ids))
	for _, rule := range mgr.ListSuppressions() {
		counts[rule.ID]++
	}
	for _, id := range ids {
		if counts[id] > 1 {
			return &statusError{
				status: http.StatusConflict,
				msg: fmt.Sprintf("suppression id %s is used by %d rules, so this action cannot tell which one "+
					"you mean; give each rule its own id in the suppression file first", id, counts[id]),
			}
		}
	}
	return nil
}

// ruleWithID returns the rule with id, if there is one.
func ruleWithID(mgr *suppressions.SuppressionManager, id string) (suppressions.SuppressionRule, bool) {
	for _, rule := range mgr.ListSuppressions() {
		if rule.ID == id {
			return rule, true
		}
	}
	return suppressions.SuppressionRule{}, false
}

// restoredRule is one entry of an undo-delete: the rule as GET /suppressions listed it, plus the index
// it had in that list.
type restoredRule struct {
	suppressions.SuppressionRule
	Position *int `json:"position"`
}
