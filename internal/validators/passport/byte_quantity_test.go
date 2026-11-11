// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package passport

import (
	"strings"
	"testing"
)

func TestPassportIsByteQuantityAt(t *testing.T) {
	const v = "209715200"
	for after, want := range map[string]bool{
		"-byte": true, " bytes": true, " B": true, " KiB": true, " GB.": true,
		"": false, " b": false, " Baker": false, " bytecode": false, " B_x": false, "  B": false,
	} {
		line := v + after
		if got := isByteQuantityAt(line, strings.Index(line, v)+len(v)); got != want {
			t.Errorf("isByteQuantityAt(%q) = %v, want %v", line, got, want)
		}
	}
}
