// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// The [DEBUG] lines the validators write from Configure (#903 box 8) reach the debug log only when the
// observer is attached before Configure runs. ValidatorOverrides.Observer is that attachment.
func TestConfigureTimeDebugLinesNeedTheObserverFirst(t *testing.T) {
	cfg := &config.Config{Validators: map[string]map[string]interface{}{
		"cloud_resources":       {"custom_patterns": []interface{}{`bucket-[a-z]+`}},
		"intellectual_property": {"internal_urls": []interface{}{`corp\.example\.test`}},
	}}
	checks := map[string]bool{"CLOUD_RESOURCES": true, "INTELLECTUAL_PROPERTY": true}

	var buf bytes.Buffer
	dbg := observability.NewDebugObserver(&buf)
	dbg.StandardObserver.DebugObserver = dbg
	BuildValidatorSetWithOverrides(checks, cfg, nil, &ValidatorOverrides{Observer: dbg.StandardObserver})
	for _, want := range []string{
		"Cloud Resource Validator initialized: ",
		"1 custom patterns",
		"Successfully loaded 1 internal URL patterns",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("debug log lacks %q:\n%s", want, buf.String())
		}
	}

	// Control: with no observer in the overrides, the set builds and writes nothing, as before.
	buf.Reset()
	BuildValidatorSetWithOverrides(checks, cfg, nil, &ValidatorOverrides{})
	if buf.Len() != 0 {
		t.Errorf("no observer was passed, but %d bytes were written: %s", buf.Len(), buf.String())
	}
}
