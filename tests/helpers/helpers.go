// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package helpers provides shared test-mode lifecycle hooks for integration
// tests under tests/integration. It is intentionally minimal: the integration
// tests existed in the repo with imports of `ferret-scan/tests/helpers` but
// the package itself was never committed, so building those tests on Windows
// failed at compile time. This package restores the missing imports as
// no-op hooks plus an opt-in FERRET_TEST_MODE env var, which the integration
// tests themselves propagate to subprocess invocations of ferret-scan.
//
// Production code does not read FERRET_TEST_MODE today; the variable exists
// purely for tests that want to recognize they're under test if they need
// to vary behavior in the future.
package helpers

import (
	"os"
	"sync"
)

const testModeEnv = "FERRET_TEST_MODE"

// active tracks whether SetupTestMode is currently in effect so calls can
// nest without each Cleanup clearing what an outer Setup established.
var (
	active     int
	activeMu   sync.Mutex
	priorValue string
	hadValue   bool
)

// SetupTestMode marks the current process as running under integration
// tests by setting the FERRET_TEST_MODE env var. Safe to call from
// multiple parallel tests; the matching CleanupTestMode call balances it.
func SetupTestMode() {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active == 0 {
		priorValue, hadValue = os.LookupEnv(testModeEnv)
		_ = os.Setenv(testModeEnv, "true")
	}
	active++
}

// CleanupTestMode unwinds a SetupTestMode call. The env var is restored
// to its prior value (or unset if there wasn't one) once the last
// outstanding Setup is balanced.
func CleanupTestMode() {
	activeMu.Lock()
	defer activeMu.Unlock()
	if active <= 0 {
		return
	}
	active--
	if active == 0 {
		if hadValue {
			_ = os.Setenv(testModeEnv, priorValue)
		} else {
			_ = os.Unsetenv(testModeEnv)
		}
	}
}
