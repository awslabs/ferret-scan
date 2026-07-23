// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"strings"
	"testing"
)

// TestLooksLikeText locks the UTF-8-aware text sniff. The previous heuristic
// counted ASCII-printable BYTES (32..126) against a 95% bar, so every byte of
// a multi-byte UTF-8 character counted as "unprintable": a short line with a
// ™ or an em-dash, accented names, or any non-Latin-script document was
// classified binary and the file silently skipped by every validator in file
// mode (stdin was unaffected, which is how the gap hid).
func TestLooksLikeText(t *testing.T) {
	textCases := map[string]string{
		"plain ascii":               "Contact john.doe@example.com about the contract\n",
		"trademark symbol short":    "Acme ™ contact john.doe@example.com\n",
		"em-dash short":             "Contract — contact john.doe@example.com\n",
		"copyright dense":           strings.Repeat("© 2026 Acme. ", 10),
		"accented names":            "Renée Müller, José García, François Lefèvre\n",
		"french prose":              "Le numéro de sécurité sociale de l'employé est confidentiel.\n",
		"japanese":                  "顧客の個人情報：山田太郎、東京都渋谷区\n",
		"cyrillic":                  "Персональные данные клиента: Иван Петров\n",
		"emoji":                     "credit card 5500-0000-0000-0004 \U0001f4b3\n",
		"curly quotes":              "“confidential” ‘internal’ draft\n",
		"crlf windows text":         "line one\r\nline two\r\n",
		"tab separated":             "name\temail\tssn\n",
		"latin-1 legacy (fallback)": string([]byte{'c', 'a', 'f', 0xe9, ' ', 'm', 'e', 'n', 'u', '\n', 'p', 'r', 'i', 'x', ':', ' ', '5', '0', '\n'}),
	}
	for name, content := range textCases {
		t.Run("text/"+name, func(t *testing.T) {
			if !LooksLikeText([]byte(content)) {
				t.Errorf("%s should be classified as text; content=%q", name, content[:min(len(content), 60)])
			}
		})
	}

	binaryCases := map[string][]byte{
		// PNG header (no null in first 8 bytes; invalid UTF-8)
		"png header": {0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xD8, 0xFE, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86},
		// dense control characters, valid UTF-8 (all < 0x80)
		"control-char soup": {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 'a', 'b'},
		// random high bytes, invalid UTF-8
		"random high bytes": {0xFE, 0xFF, 0xC0, 0xC1, 0xF5, 0xF6, 0x80, 0x81, 0xFE, 0xFF, 0xC0, 0xC1, 0xF5, 0xF6, 0x80, 0x81, 0xFE, 0xFF, 0xC0, 0xC1},
	}
	for name, content := range binaryCases {
		t.Run("binary/"+name, func(t *testing.T) {
			if LooksLikeText(content) {
				t.Errorf("%s should be classified as binary", name)
			}
		})
	}

	t.Run("split multibyte rune at 512-byte boundary", func(t *testing.T) {
		// A buffer ending mid-™ (0xE2 0x84 0xA2 truncated to 0xE2 0x84) must
		// still classify as text — the read window can split a rune.
		buf := append([]byte(strings.Repeat("legal notice ™ ", 20)), 0xE2, 0x84)
		if !LooksLikeText(buf) {
			t.Error("buffer ending in a truncated UTF-8 rune should still be text")
		}
	})

	t.Run("empty", func(t *testing.T) {
		if LooksLikeText(nil) || LooksLikeText([]byte{}) {
			t.Error("empty buffer is not text")
		}
	})
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
