// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package goldencorpus

import (
	"syscall"
	"time"
)

// processCPUTime returns CPU time consumed by this process, kernel plus user.
//
// GetProcessTimes reports in 100-nanosecond units. Its effective granularity is the system
// timer interval, typically 15.6ms, which is coarse relative to a base reading of a few
// milliseconds — cpuMeasurable is what callers use to decide whether a reading is usable, so
// this returns the raw value and does not pretend to a resolution it does not have.
func processCPUTime() (time.Duration, error) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, err
	}
	var creation, exit, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	// Filetime is 100ns ticks since an epoch; for kernel/user times it is a duration already.
	ticks := func(f syscall.Filetime) time.Duration {
		return time.Duration(uint64(f.HighDateTime)<<32|uint64(f.LowDateTime)) * 100 * time.Nanosecond
	}
	return ticks(kernel) + ticks(user), nil
}
