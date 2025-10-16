// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package security

// SecureString wraps sensitive data with automatic scrubbing
type SecureString struct {
	data []byte
}

// NewSecureString creates a new secure string
func NewSecureString(s string) *SecureString {
	data := make([]byte, len(s))
	copy(data, s)
	return &SecureString{data: data}
}

// String returns the string value (use sparingly)
func (ss *SecureString) String() string {
	return string(ss.data)
}

// Clear securely wipes the memory
func (ss *SecureString) Clear() {
	if ss.data != nil {
		for i := range ss.data {
			ss.data[i] = 0
		}
		ss.data = nil
	}
}
