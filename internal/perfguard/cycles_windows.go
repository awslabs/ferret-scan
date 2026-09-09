// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package perfguard

import (
	"fmt"
	"syscall"
	"unsafe"
)

// The lazy-DLL route rather than golang.org/x/sys/windows: that module is an INDIRECT dependency
// today, and promoting it to direct for one call would put a supply-chain edge in go.mod to save a
// dozen lines. kernel32 is already loaded in every Windows process.
var (
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procQueryProcessCycleTime = kernel32.NewProc("QueryProcessCycleTime")
)

// ProcessCPUCycles returns the sum of CPU cycles consumed by every thread of this process, user plus
// kernel, via QueryProcessCycleTime.
//
// WHY THIS EXISTS. GetProcessTimes — what ProcessCPUTime uses — reports in 100ns units but
// accumulates at the scheduler's clock interrupt, measured on windows-latest at exactly 15.625ms per
// step. That is coarse enough that the O(n^2) complexity guard asserts NOTHING on that platform:
// all 18 validator targets and both controls have base readings spanning 1-7 ticks, under the 8 that
// Growth.Ticks requires, so the resolution gate correctly declines every one of them (#619).
//
// QueryProcessCycleTime has the SAME semantics as the statistic it would replace — the docs say
// "the sum of the cycle time of all threads of the specified process" and "includes cycles spent in
// both user mode and kernel mode", which is what getrusage(RUSAGE_SELF) and GetProcessTimes both
// report — so it substitutes without changing any assumption the guard rests on. In particular
// AssertNoParallelTests stays necessary for exactly the reason it is today.
//
// It is deliberately NOT QueryThreadCycleTime, which is the API that first looks right. That one is
// per-THREAD, and the Go runtime migrates goroutines between OS threads freely, so a single
// goroutine's work lands on several threads and a per-thread count under-reports by an unpredictable
// amount. Making it correct would need runtime.LockOSThread around every measurement, which changes
// the scheduling of the code being measured.
//
// WHY IT RETURNS A COUNT AND NOT A DURATION. Microsoft's own remark, on the thread-scoped sibling:
// "Do not attempt to convert the CPU clock cycles returned by QueryThreadCycleTime to elapsed time.
// This function uses timer services provided by the CPU, which can vary in implementation." A
// complexity guard needs a RATIO of two measurements of the same code, which is unitless and
// therefore unaffected — but a Duration would print fabricated milliseconds in every log line, and
// ResolutionNote would report a resolution the counter does not have. So the unit stays cycles.
//
// Whether the guard should switch to it is not decided here: this reports the counter, and
// TestWindowsCycleCounterIsUsableForRatios establishes the properties a switch would depend on.
func ProcessCPUCycles() (uint64, error) {
	h, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, fmt.Errorf("perfguard: current process handle: %w", err)
	}
	var cycles uint64
	r, _, e := procQueryProcessCycleTime.Call(uintptr(h), uintptr(unsafe.Pointer(&cycles)))
	if r == 0 {
		return 0, fmt.Errorf("perfguard: QueryProcessCycleTime: %w", e)
	}
	return cycles, nil
}

// CyclesSupported reports whether ProcessCPUCycles can be used on this platform.
func CyclesSupported() bool { return true }
