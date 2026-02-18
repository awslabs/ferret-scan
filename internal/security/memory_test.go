// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"testing"
)

func TestNewSecureString_StoresValue(t *testing.T) {
	ss := NewSecureString("hello")
	if ss.String() != "hello" {
		t.Errorf("expected 'hello', got %q", ss.String())
	}
}

func TestNewSecureString_EmptyString(t *testing.T) {
	ss := NewSecureString("")
	if ss.String() != "" {
		t.Errorf("expected empty string, got %q", ss.String())
	}
}

func TestSecureString_Clear_ZeroesData(t *testing.T) {
	ss := NewSecureString("sensitive-data")
	ss.Clear()
	// After Clear, String() should return empty (data is nil)
	if ss.String() != "" {
		t.Errorf("expected empty string after Clear, got %q", ss.String())
	}
}

func TestSecureString_Clear_Idempotent(t *testing.T) {
	ss := NewSecureString("data")
	ss.Clear()
	// Calling Clear again should not panic
	ss.Clear()
}

func TestNewSecureString_IsolatesFromOriginal(t *testing.T) {
	// Modifying the original string variable should not affect SecureString
	// (Go strings are immutable, but this verifies the copy semantics)
	original := "original"
	ss := NewSecureString(original)
	// The secure string should hold its own copy
	if ss.String() != original {
		t.Errorf("expected %q, got %q", original, ss.String())
	}
}

func TestSecureString_LargeValue(t *testing.T) {
	large := make([]byte, 10000)
	for i := range large {
		large[i] = byte('a' + i%26)
	}
	s := string(large)
	ss := NewSecureString(s)
	if ss.String() != s {
		t.Error("large string not stored correctly")
	}
	ss.Clear()
	if ss.String() != "" {
		t.Error("large string not cleared correctly")
	}
}
