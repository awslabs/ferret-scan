// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package security

// SecureString wraps sensitive data with best-effort memory scrubbing on Clear.
//
// Limitations: Go's garbage collector may move or copy memory at any time, and
// string-to-[]byte conversions (e.g. in String()) create immutable copies that
// cannot be zeroed. Clear() zeroes the internal byte slice, which reduces the
// window of exposure, but cannot guarantee that no copies exist elsewhere in
// the heap. Do not rely on this for cryptographic-strength memory protection.
type SecureString struct {
	data []byte
}

// NewSecureString creates a new SecureString by copying s into a mutable byte slice.
func NewSecureString(s string) *SecureString {
	data := make([]byte, len(s))
	copy(data, s)
	return &SecureString{data: data}
}

// String returns the string value. Use sparingly — each call creates an
// immutable copy that cannot be zeroed by Clear.
func (ss *SecureString) String() string {
	return string(ss.data)
}

// Clear overwrites the internal byte slice with zeros and releases it.
// This reduces the window of exposure but cannot guarantee all copies are erased.
func (ss *SecureString) Clear() {
	if ss.data != nil {
		for i := range ss.data {
			ss.data[i] = 0
		}
		ss.data = nil
	}
}
