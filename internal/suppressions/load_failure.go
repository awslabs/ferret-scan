// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package suppressions

import (
	"errors"
	"fmt"
)

// A suppression file that exists but cannot be read or parsed loads as empty, so the scan applies none
// of its rules and says so. It must never be SAVED in that state: the save would write the empty
// fallback over the operator's file. It used to, because nothing recorded that the load had failed and
// the saver could not tell "a new file" from "a file I could not read". Measured on the issue's
// reproduction: one --generate-suppressions run over a two-rule file with one bad line rewrote it with
// the two rules disabled and the bad line gone, printed no warning about it and exited 0 (#880).

// ErrFileNotLoaded is matched (errors.Is) by every error a save returns because the suppression file
// exists but could not be read or parsed.
var ErrFileNotLoaded = errors.New("suppression file could not be loaded")

// loadFailure is a suppression file that exists but could not be read or parsed. Its text is the
// message for the refused save, and names the read or YAML error, with its line.
type loadFailure struct {
	path string
	// verb is "read" or "parsed".
	verb string
	err  error
}

func (f *loadFailure) Error() string {
	return fmt.Sprintf("suppression file %s could not be %s (%v); fix it or move it aside before regenerating; nothing was written",
		f.path, f.verb, f.err)
}

func (f *loadFailure) Unwrap() error { return f.err }

func (f *loadFailure) Is(target error) bool { return target == ErrFileNotLoaded }

// LoadError reports why the suppression file could not be loaded: it exists, but could not be read or
// could not be parsed. It is nil when the file loaded, or does not exist yet.
//
// While it is set the manager holds no rules, and every method that would write the file returns this
// error and writes nothing, so the file stays byte-identical until it is fixed or moved aside. A file
// that does not exist is not a load failure: the first save creates it.
func (sm *SuppressionManager) LoadError() error {
	return sm.loadErr
}
