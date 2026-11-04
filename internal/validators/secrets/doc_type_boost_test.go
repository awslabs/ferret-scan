// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"
)

// Tests for #849 item 3. The document-type switch in calculateEnhancedConfidenceWithCacheAndEnvAndLine
// had a `case "JSON", "YAML"` branch (+12, structured_config_boost), and nothing produces "YAML":
// DetectStructure has no YAML pattern and no .yaml/.yml extension hint, so a YAML file is typed by its
// lines, and since #788 its `key: value` lines type it Configuration (+15, config_file_boost). The
// label is gone. These tests pin which branch each structured document reaches: YAML the
// Configuration one, JSON the structured one, by its extension or by its lines.

// docTypeOf returns the document type and the validation checks of the one SECRETS finding on the
// line holding marker.
func docTypeOf(t *testing.T, content, path, marker string) (string, map[string]bool) {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if !strings.Contains(m.Text, marker) {
			continue
		}
		docType, _ := m.Metadata["context_doc_type"].(string)
		checks, _ := m.Metadata["validation_checks"].(map[string]bool)
		return docType, checks
	}
	t.Fatalf("%s: no finding on %q among %d", path, marker, len(ms))
	return "", nil
}

func TestStructuredDocumentBoosts(t *testing.T) {
	pw := uriPW(849300, 24)
	for _, c := range []struct {
		name, path, content, wantType, wantCheck string
	}{
		{"YAML block map", "config.yaml",
			"database:\n  host: db.orders.invalid\n  port: 5432\n  password: " + pw + "\ncache:\n  ttl: 300\n",
			"Configuration", "config_file_boost"},
		{"YAML, .yml", "values.yml",
			"image: registry.orders.invalid/api\nreplicas: 3\napi_token: " + pw + "\n",
			"Configuration", "config_file_boost"},
		{"JSON by its extension", "settings.json",
			"{\n  \"service\": \"orders\",\n  \"password\": \"" + pw + "\"\n}\n",
			"JSON", "structured_config_boost"},
		// JSON lines of three schemas. Every line also holds two or more commas, so main counted all
		// three as CSV rows, tied CSV with JSON at 1.0 and typed the file CSV on the tie-break; a CSV
		// table's rows have one field count, and these have three (#849).
		{"JSON lines", "events.txt",
			"{\"user\": \"app\", \"role\": \"reader\", \"team\": \"core\"}\n" +
				"{\"user\": \"svc\", \"role\": \"writer\", \"region\": \"eu\", \"password\": \"" + pw + "\"}\n" +
				"{\"user\": \"ops\", \"role\": \"admin\", \"region\": \"us\", \"shift\": \"night\", \"tier\": \"2\"}\n",
			"JSON", "structured_config_boost"},
	} {
		docType, checks := docTypeOf(t, c.content, c.path, pw)
		if docType != c.wantType {
			t.Errorf("%s: context_doc_type = %q, want %q", c.name, docType, c.wantType)
		}
		if !checks[c.wantCheck] {
			t.Errorf("%s: validation checks %v lack %s", c.name, checks, c.wantCheck)
		}
		other := "structured_config_boost"
		if c.wantCheck == other {
			other = "config_file_boost"
		}
		if checks[other] {
			t.Errorf("%s: validation checks %v carry %s as well", c.name, checks, other)
		}
	}
}
