// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"sync"
	"testing"
)

// TestTempDirOverrideConcurrentAccess exercises SetTempDirOverride against
// GetTempDir from many goroutines, so `go test -race` can see the access pattern.
//
// This test exists because the override is process-wide package state and config
// loading is NOT confined to startup: internal/web falls back to a per-request
// LoadConfigOrDefault, and every pkg/scan entry point loads a config. A library
// caller scanning from several goroutines therefore writes this while others read
// it. Without the mutex this test fails under -race; the rest of the suite does
// not, because nothing else touches the override concurrently.
func TestTempDirOverrideConcurrentAccess(t *testing.T) {
	t.Cleanup(func() { SetTempDirOverride("") })

	const goroutines = 16
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// Alternate between setting and clearing, so readers see both.
				if j%2 == 0 {
					SetTempDirOverride("/tmp/ferret-probe")
				} else {
					SetTempDirOverride("")
				}
			}
		}(i)

		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				// The value is racing by design; only that it is read safely
				// (and non-empty) matters here.
				if got := GetTempDir(); got == "" {
					t.Error("GetTempDir returned an empty path")
					return
				}
			}
		}()
	}

	wg.Wait()
}

// TestSetTempDirOverrideRoundTrip pins the basic contract the config loader
// depends on: a set value is returned, and an empty value restores the platform
// default rather than yielding an empty path.
func TestSetTempDirOverrideRoundTrip(t *testing.T) {
	t.Cleanup(func() { SetTempDirOverride("") })

	SetTempDirOverride("")
	platformDefault := GetTempDir()
	if platformDefault == "" {
		t.Fatal("the platform default temp dir is empty")
	}

	SetTempDirOverride("/tmp/ferret-override")
	if got := GetTempDir(); got != "/tmp/ferret-override" {
		t.Errorf("GetTempDir() = %q, want the override", got)
	}

	SetTempDirOverride("")
	if got := GetTempDir(); got != platformDefault {
		t.Errorf("GetTempDir() = %q after clearing the override, want the platform "+
			"default %q — clearing must not leave an empty path", got, platformDefault)
	}
}
