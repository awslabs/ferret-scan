// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"regexp/syntax"
	"strings"
	"time"
)

// ValueWarning is one configured VALUE under `validators:` that its validator could not use: a regex RE2
// rejects, an entry of the wrong type, a scalar where a list belongs, a provider or pattern name the
// validator does not know. The value was dropped, so the detection, disable or allowlist it configured did
// not take effect (#903).
//
// The unknown-KEY warning (#735) cannot see these: the key is spelled correctly, so the strict YAML pass has
// nothing to report, and only the validator's own parser knows what it did with the value. A schema check
// here would drift from that parser and cannot know the provider or sub-type sets. So the validators
// RECORD warnings while they configure (exposed by a ConfigWarnings method, see ValueWarningSource), and the
// caller that owns the output prints them. Recording rather than printing is the other half of the design:
// Configure runs on every entry point (the CLI's file and stdin paths, the web server, pkg/scan,
// core.RedactFile), on most of them before any observer is attached, and on some of them stderr is not a
// human channel. A validator that did not run records nothing.
type ValueWarning struct {
	// Path is the dotted path of the value, in the form the unknown-key warning uses, with an index for a
	// list entry: validators.cloud_resources.custom_patterns[1].
	Path string
	// Message is "<problem> — <effect>": what is wrong with the value, then what the scan does instead.
	Message string
}

// String renders the warning as one line, without the "Warning: " prefix the CLI adds when it prints it.
func (w ValueWarning) String() string {
	return "config value " + w.Path + ": " + w.Message
}

// ValueWarningSource is implemented by a validator that records the configured values it could not use.
type ValueWarningSource interface {
	ConfigWarnings() []ValueWarning
}

// NewValueWarning builds the one message shape every validator uses: "<problem> — <effect>".
func NewValueWarning(path, problem, effect string) ValueWarning {
	return ValueWarning{Path: path, Message: problem + " — " + effect}
}

// ValidatorKeyPath returns the path of key in a `validators:` section: validators.<section>.<key>.
func ValidatorKeyPath(section, key string) string {
	return "validators." + section + "." + key
}

// ElementPath returns the path of entry i of the list at path. The index is zero-based, as in yq and jq.
func ElementPath(path string, i int) string {
	return fmt.Sprintf("%s[%d]", path, i)
}

// WrongType describes a value of the wrong YAML type: "expected <want>, got <what it is>".
//
// Only the TYPE is named, never the value: a pattern in the wrong place is still an internal hostname or
// a detection rule, and this text is printed to logs.
func WrongType(want string, got any) string {
	return "expected " + want + ", got " + yamlKind(got)
}

// NotABoolean describes a value where true or false belongs.
//
// The config is read by yaml.v3, which follows YAML 1.2: yes, no, on and off are plain strings, and so is
// anything quoted. So `aws: no` is the string "no", which a bool check drops, and the provider stays on. A
// string that spells a boolean is named, with that hint; it can only be one of a fixed set of words, so
// naming it echoes nothing a user wrote that is not on this list.
func NotABoolean(got any) string {
	s, ok := got.(string)
	if !ok {
		return WrongType("true or false", got)
	}
	switch strings.ToLower(s) {
	case "true", "false":
		return fmt.Sprintf("expected true or false, got the string %q (quoted, so YAML reads it as text; remove the quotes)", s)
	case "yes", "no", "on", "off", "y", "n":
		return fmt.Sprintf("expected true or false, got the string %q (YAML 1.2 reads it as text, not a boolean; write true or false)", s)
	}
	return "expected true or false, got a string"
}

// InvalidRegex describes a pattern regexp.Compile rejected: RE2's error code and, for the constructs people
// bring from PCRE, what the construct is.
//
// The hint matters most for the commonest case, where RE2's own message misleads: a lookbehind "(?<=" fails
// as "invalid named capture", because "(?<" opens a named group in RE2.
//
// The pattern text is deliberately not echoed. RE2's error quotes the pattern from the offending construct
// to its end, and an internal_urls entry is an internal hostname; this text goes to CI logs. The path and
// index locate the value, and the hint names the construct.
func InvalidRegex(err error) string {
	var se *syntax.Error
	if !errors.As(err, &se) {
		return "not a valid RE2 regular expression"
	}
	msg := "not a valid RE2 regular expression: " + string(se.Code)
	if hint := re2Hint(se); hint != "" {
		msg += " (" + hint + ")"
	}
	return msg
}

// re2Hint names the construct behind an RE2 syntax error, or returns "" when there is nothing to add to
// the error code. Matched on the code first, so a hint is only given when it explains the error RE2
// actually raised, then on the fragment RE2 reports, which for these codes starts at the construct.
func re2Hint(se *syntax.Error) string {
	const noLookaround = "; RE2, Go's regex engine, has no lookaround"
	switch se.Code {
	case syntax.ErrInvalidNamedCapture:
		switch {
		case strings.HasPrefix(se.Expr, "(?<="):
			return `"(?<=" is a PCRE lookbehind` + noLookaround
		case strings.HasPrefix(se.Expr, "(?<!"):
			return `"(?<!" is a PCRE negative lookbehind` + noLookaround
		}
	case syntax.ErrInvalidPerlOp:
		switch {
		case strings.HasPrefix(se.Expr, "(?="):
			return `"(?=" is a PCRE lookahead` + noLookaround
		case strings.HasPrefix(se.Expr, "(?!"):
			return `"(?!" is a PCRE negative lookahead` + noLookaround
		case strings.HasPrefix(se.Expr, "(?>"):
			return `"(?>" is a PCRE atomic group; RE2 has none`
		case strings.HasPrefix(se.Expr, "(?#"):
			return `"(?#" is a PCRE inline comment; RE2 has none`
		case strings.HasPrefix(se.Expr, "(?|"):
			return `"(?|" is a PCRE branch reset; RE2 has none`
		case strings.HasPrefix(se.Expr, "(?("):
			return `"(?(" is a PCRE conditional; RE2 has none`
		}
	case syntax.ErrInvalidRepeatOp:
		if len(se.Expr) > 1 && strings.HasSuffix(se.Expr, "+") {
			return `a possessive quantifier such as "++" or "*+" is PCRE-only; RE2 has none, so drop the extra "+"`
		}
	case syntax.ErrInvalidEscape:
		switch {
		case len(se.Expr) == 2 && se.Expr[0] == '\\' && se.Expr[1] >= '1' && se.Expr[1] <= '9':
			return `a backreference such as "\1" is PCRE-only; RE2 has none`
		case se.Expr == `\Z`:
			return `"\Z" is PCRE's end-of-subject anchor; RE2 writes end of text as "\z"`
		}
	case syntax.ErrMissingBracket:
		return `a "[" character class is not closed`
	case syntax.ErrMissingParen:
		return `a "(" group is not closed`
	case syntax.ErrUnexpectedParen:
		return `a ")" has no matching "("`
	}
	return ""
}

// yamlKind names the YAML type of a value decoded from the config file, in words.
func yamlKind(v any) string {
	switch v.(type) {
	case nil:
		return "an empty value"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return "a number"
	case []any:
		return "a list"
	case map[string]any:
		return "a map"
	case map[any]any:
		return "a map with non-string keys"
	case time.Time:
		return "a timestamp"
	}
	return fmt.Sprintf("a value of type %T", v)
}
