// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package scorecorpus

// posixModesEnforced reports whether chmod 0o000 actually makes a file unreadable.
//
// True on unix. Split by build tag rather than checked at runtime because the
// answer is a property of the platform, and a runtime probe would itself have to
// create and read a file to find out.
func posixModesEnforced() bool { return true }
