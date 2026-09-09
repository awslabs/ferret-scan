// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package perfguard

// ProcessCPUCycles is unavailable outside Windows.
//
// Deliberately not implemented for darwin or linux, because neither needs it and neither has a clean
// equivalent. The problem it solves is specific to Windows' 15.625ms CPU-time accounting granularity
// (#619); getrusage on ubuntu-latest and darwin/arm64 resolves finely enough that all 18 complexity
// targets assert today.
//
// The alternatives were considered and rejected rather than overlooked. On arm64 macOS there is no
// user-space cycle counter without kernel entitlements. On x86 the TSC is INVARIANT — a fixed-rate
// clock that keeps advancing while a thread is descheduled — so reading it directly would reintroduce
// exactly the wall-clock defect the CPU statistic exists to remove (#579). Linux
// perf_event_open(PERF_COUNT_HW_CPU_CYCLES) is real but needs a permitted perf_event_paranoid, which
// a CI container cannot be assumed to grant.
func ProcessCPUCycles() (uint64, error) { return 0, ErrCyclesUnsupported }

// CyclesSupported reports whether ProcessCPUCycles can be used on this platform.
func CyclesSupported() bool { return false }
