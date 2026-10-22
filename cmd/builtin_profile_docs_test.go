// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/config"
)

// TestDocsStateTheBuiltinPrecommitChecks: no doc listed the built-in precommit profile's checks
// before #768, and docs/configuration.md presented examples/ferret.yaml's own profile (PASSPORT,
// PERSON_NAME) as the one a hook runs. The two docs that now state the list must state the one
// config.BuiltinPrecommitChecks holds, so a change to the profile cannot leave them behind.
func TestDocsStateTheBuiltinPrecommitChecks(t *testing.T) {
	for _, doc := range []string{"../docs/PRE_COMMIT_INTEGRATION.md", "../docs/configuration.md"} {
		b, err := os.ReadFile(doc) // #nosec G304 -- fixed repository path
		if err != nil {
			t.Fatalf("reading %s: %v", doc, err)
		}
		if !strings.Contains(string(b), "`"+config.BuiltinPrecommitChecks+"`") {
			t.Errorf("%s does not state the built-in precommit profile's checks as `%s`",
				doc, config.BuiltinPrecommitChecks)
		}
	}
}
