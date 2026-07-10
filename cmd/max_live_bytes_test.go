// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestParseByteSize(t *testing.T) {
	tests := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"", 0, false}, // empty = disabled
		{"1024", 1024, false},
		{"512B", 512, false},
		{"1KB", 1024, false},
		{"256MB", 256 * 1024 * 1024, false},
		{"1GB", 1024 * 1024 * 1024, false},
		{"2gb", 2 * 1024 * 1024 * 1024, false}, // case-insensitive
		{"  64MB  ", 64 * 1024 * 1024, false},  // trimmed
		{"0", 0, true},                         // non-positive rejected
		{"-5MB", 0, true},                      // negative rejected
		{"abc", 0, true},                       // non-numeric rejected
		{"10XB", 0, true},                      // unknown unit rejected
		{"MB", 0, true},                        // no number rejected
	}
	for _, tc := range tests {
		got, err := parseByteSize(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseByteSize(%q): expected error, got %d", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseByteSize(%q): unexpected error %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseByteSize(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
