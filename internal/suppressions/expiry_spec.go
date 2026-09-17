// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// How long a generated suppression rule should live, parsed from one string.
//
// # Why this is not just time.ParseDuration
//
// Go's duration parser understands ns, us, ms, s, m and h — and nothing longer. There is no `d` and no
// `w`, deliberately, because a day is not a fixed number of hours across a DST boundary. That is the
// right call for a timeout and the wrong vocabulary for this: a suppression lifetime is a human review
// interval, measured in weeks and months. The first version of --suppression-expires took a bare
// time.Duration, which meant the only way to say "30 days" was `720h`, and every natural spelling
// failed:
//
//	720h        accepted
//	1h30m       accepted
//	30d         parse error
//	4w          parse error
//	30          parse error
//	2026-12-31  parse error
//
// So this parser accepts all of them. `d` and `w` are resolved as exactly 24h and 168h — see Resolve
// for why that approximation is stated rather than hidden.
//
// # Why an absolute date is also allowed
//
// "Expire these before the next audit" is a real thing to want, and it is not expressible as a
// duration: every rule generated in the run should lapse on the SAME day, not N days after whenever
// the run happened. A date is unambiguous against every duration spelling, so accepting both costs
// nothing in parsing and removes a whole class of "720h from when, exactly?" arithmetic.
type ExpirySpec struct {
	// relative is a lifetime from the moment a rule is created; zero when unset.
	relative time.Duration
	// absolute is a fixed expiry instant; nil when unset. At most one of the two is set.
	absolute *time.Time
	// source is the string this was parsed from, for error messages and round-tripping to config.
	source string
}

// dateLayouts are the absolute forms accepted, in the order tried.
//
// Date-only is the documented form. The RFC 3339 variants are accepted because a config file written
// by a tool, or a value copied out of an existing rule's expires_at, will carry them — rejecting a
// value the tool itself emits would be its own small trap.
var dateLayouts = []string{
	"2006-01-02",
	time.RFC3339,
	"2006-01-02T15:04:05",
}

// ParseExpirySpec reads a suppression lifetime.
//
// Accepted, in the order tried:
//
//	""            no expiry (the default)
//	"0"           no expiry, said explicitly
//	"never"       no expiry, said readably — what a config file wants to hold
//	"2026-12-31"  an absolute date (also RFC 3339)
//	"30d" "4w"    days and weeks
//	"720h" "90m"  any Go duration
//	"30"          a bare number, read as DAYS
//
// A bare number means days rather than seconds or hours, which is a judgement: nobody sets a
// suppression to lapse in 30 seconds, and reading `30` as half a minute would silently expire every
// rule in the run. It is documented, and the error message for anything unparseable lists the forms.
func ParseExpirySpec(s string) (ExpirySpec, error) {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return ExpirySpec{}, nil
	}
	lower := strings.ToLower(raw)
	if lower == "never" || lower == "none" || lower == "0" {
		return ExpirySpec{source: raw}, nil
	}

	// An absolute date first: it cannot collide with any duration spelling.
	for _, layout := range dateLayouts {
		if t, err := time.Parse(layout, raw); err == nil {
			at := t
			return ExpirySpec{absolute: &at, source: raw}, nil
		}
	}

	// Days and weeks, which Go's parser does not have.
	if d, ok := parseDayWeek(lower); ok {
		if d <= 0 {
			return ExpirySpec{}, fmt.Errorf("suppression expiry %q is not positive", raw)
		}
		return ExpirySpec{relative: d, source: raw}, nil
	}

	// A bare number is days.
	if n, err := strconv.Atoi(lower); err == nil {
		if n <= 0 {
			return ExpirySpec{}, fmt.Errorf("suppression expiry %q is not positive; use \"never\" for no expiry", raw)
		}
		return ExpirySpec{relative: time.Duration(n) * 24 * time.Hour, source: raw}, nil
	}

	// Anything else must be a Go duration.
	if d, err := time.ParseDuration(lower); err == nil {
		if d <= 0 {
			return ExpirySpec{}, fmt.Errorf("suppression expiry %q is not positive; use \"never\" for no expiry", raw)
		}
		return ExpirySpec{relative: d, source: raw}, nil
	}

	return ExpirySpec{}, fmt.Errorf(
		"invalid suppression expiry %q: use a number of days (30), days or weeks (30d, 4w), "+
			"a Go duration (720h, 90m), an absolute date (2026-12-31), or \"never\"", raw)
}

// parseDayWeek reads "30d" or "4w", which time.ParseDuration rejects.
func parseDayWeek(s string) (time.Duration, bool) {
	if len(s) < 2 {
		return 0, false
	}
	unit := s[len(s)-1]
	var mult time.Duration
	switch unit {
	case 'd':
		mult = 24 * time.Hour
	case 'w':
		mult = 7 * 24 * time.Hour
	default:
		return 0, false
	}
	n, err := strconv.ParseFloat(s[:len(s)-1], 64)
	if err != nil {
		return 0, false
	}
	return time.Duration(n * float64(mult)), true
}

// IsZero reports whether this spec means "no expiry".
func (e ExpirySpec) IsZero() bool { return e.relative <= 0 && e.absolute == nil }

// String returns the spec as written, so a value read from config round-trips into an error message or
// a log line looking like what the user typed.
func (e ExpirySpec) String() string {
	if e.source != "" {
		return e.source
	}
	if e.absolute != nil {
		return e.absolute.Format("2006-01-02")
	}
	if e.relative > 0 {
		return e.relative.String()
	}
	return "never"
}

// Resolve returns the expiry instant for a rule created at now, or nil for no expiry.
//
// A `d` is 24h and a `w` is 168h, which is wall-clock arithmetic rather than calendar arithmetic: a
// "30d" expiry set the day before a DST change lands an hour off. That is stated rather than corrected
// because an hour does not matter to a review interval measured in weeks, and calendar arithmetic here
// would mean carrying a location — which a suppression file, shared across machines in different
// zones, cannot meaningfully have.
func (e ExpirySpec) Resolve(now time.Time) *time.Time {
	if e.absolute != nil {
		at := *e.absolute
		return &at
	}
	if e.relative > 0 {
		at := now.Add(e.relative)
		return &at
	}
	return nil
}
