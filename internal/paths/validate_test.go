// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package paths

import "testing"

// TestValidatePathRejectsNULOnEveryPlatform pins the one rule both platform
// validators must agree on. validateWindowsPath only screened the Win32
// reserved characters (< > : " | ? *) and let a NUL byte through, so the same
// config that ValidateConfig rejected on Linux and macOS passed validation on
// Windows and then failed deeper down at the syscall, where the error no longer
// names the offending setting. It is checked here against both validators
// directly rather than through ValidatePath, so the case is exercised on every
// runner instead of only the one matching the host OS.
func TestValidatePathRejectsNULOnEveryPlatform(t *testing.T) {
	bad := "/tmp/out\x00dir"

	if err := validateUnixPath(bad); err == nil {
		t.Error("validateUnixPath accepted a path containing a NUL byte")
	}
	if err := validateWindowsPath(bad); err == nil {
		t.Error("validateWindowsPath accepted a path containing a NUL byte")
	}

	// ValidatePath dispatches on the host platform; whichever branch it takes
	// must reject the NUL too.
	if err := ValidatePath(bad); err == nil {
		t.Error("ValidatePath accepted a path containing a NUL byte")
	}
}

// TestValidateWindowsPathAcceptsOrdinaryPaths is the no-false-rejection guard
// for the NUL check added above: it must not reject paths that are legitimate
// on Windows, including a drive-letter colon.
func TestValidateWindowsPathAcceptsOrdinaryPaths(t *testing.T) {
	for _, p := range []string{
		`C:\Users\someone\redacted`,
		`redacted`,
		`.\redacted`,
		`\\server\share\redacted`,
		``,
	} {
		if err := validateWindowsPath(p); err != nil {
			t.Errorf("validateWindowsPath(%q) = %v, want nil", p, err)
		}
	}
}

// TestValidateWindowsPathRejectsReservedChars keeps the pre-existing behavior
// covered, so a future edit to the NUL check cannot quietly drop it.
func TestValidateWindowsPathRejectsReservedChars(t *testing.T) {
	for _, p := range []string{`bad<name`, `bad>name`, `bad"name`, `bad|name`, `bad?name`, `bad*name`} {
		if err := validateWindowsPath(p); err == nil {
			t.Errorf("validateWindowsPath(%q) = nil, want an error", p)
		}
	}
}
