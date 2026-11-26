// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAllowProjectConfigIsNotAConfigKey: --allow-project-config opts a pre-commit run into a config
// discovered in the working directory (#293, THREAT_MODEL TM-13), so no key in that file may set it. The
// schema must report both spellings as unknown, which is also what warnUnknownConfigKeys prints.
func TestAllowProjectConfigIsNotAConfigKey(t *testing.T) {
	for name, body := range map[string]string{
		"defaults": "defaults:\n  allow_project_config: true\n",
		"profile":  "profiles:\n  precommit:\n    allow_project_config: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "c.yaml")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(strings.Join(cfg.UnknownKeys, ","), "allow_project_config") {
				t.Errorf("allow_project_config is a recognised key (UnknownKeys %v); a config file must not be able to set the flag that gates it", cfg.UnknownKeys)
			}
		})
	}
}
