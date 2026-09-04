// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package perfguard

import (
	"syscall"
	"time"
)

// processCPUTime returns CPU time consumed by this process, user plus system.
//
// getrusage reports microseconds. The kernel accumulates at timer-tick granularity on some
// platforms, so a reading below a couple of milliseconds is not trustworthy — MinMeasurableCPU
// is what callers use to decide, rather than assuming a resolution here.
func ProcessCPUTime() (time.Duration, error) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0, err
	}
	user := time.Duration(ru.Utime.Sec)*time.Second + time.Duration(ru.Utime.Usec)*time.Microsecond
	sys := time.Duration(ru.Stime.Sec)*time.Second + time.Duration(ru.Stime.Usec)*time.Microsecond
	return user + sys, nil
}
