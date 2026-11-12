// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

// generationExitCode ends a --generate-suppressions run that wrote no rule file with exit 1 (#880).
//
// GenerateSuppressionRules refuses to save over a rule file that did not parse (#893), and returns an error
// for a save that failed. Both meant "nothing was written", and both printed a line and exited 0 in --file
// and --stdin, so a CI job that regenerates its baseline read the refusal as success. The run still renders
// its findings report first, so stdout is what it was; only the exit code and the stderr line's prefix
// change. Exit 1 is what a failed --output write exits with. A non-zero
// base (blocking findings, a tool error, incomplete coverage) is never downgraded, as in
// resolveIncompleteExitCode.
func generationExitCode(base int, generationFailed bool) int {
	if generationFailed && base == 0 {
		return 1
	}
	return base
}
