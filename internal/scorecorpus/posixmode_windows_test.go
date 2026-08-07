// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scorecorpus

// posixModesEnforced reports whether chmod 0o000 actually makes a file unreadable.
//
// False on Windows: os.Chmod only toggles the read-only attribute, so a 0o000 file
// remains readable and the permission-denied case would pass for the wrong reason.
// The unreadable-file contract is still covered on ubuntu and macos in CI.
func posixModesEnforced() bool { return false }
