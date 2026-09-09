// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package perfguard

import "errors"

// ErrCyclesUnsupported is returned by ProcessCPUCycles where no process-wide cycle counter is
// available through a documented, unprivileged API.
//
// Declared in an UNTAGGED file on purpose. It first lived in cycles_other.go, and the test that
// asserts the stub's contract then failed `GOOS=windows go vet` with "undefined:
// ErrCyclesUnsupported" — a break that would only have shown up on the Windows runner, in a change
// whose entire point is Windows.
//
// Returned as an ERROR rather than a zero count, because a stub returning (0, nil) is the failure
// mode worth guarding against: a caller would divide zeros, or read "0 cycles" as a genuine
// measurement of instantaneous work. Both look like a passing guard.
var ErrCyclesUnsupported = errors.New("perfguard: no process-wide cycle counter on this platform")
