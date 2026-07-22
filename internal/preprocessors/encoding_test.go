// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package preprocessors

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf16"
)

// encodeUTF16LE / encodeUTF16BE build test fixtures independently of the
// production encoder so encode/decode bugs can't cancel each other out.
func fixtureUTF16(s string, bigEndian, withBOM bool) []byte {
	units := utf16.Encode([]rune(s))
	var b bytes.Buffer
	if withBOM {
		if bigEndian {
			b.Write([]byte{0xFE, 0xFF})
		} else {
			b.Write([]byte{0xFF, 0xFE})
		}
	}
	for _, u := range units {
		if bigEndian {
			b.WriteByte(byte(u >> 8))
			b.WriteByte(byte(u))
		} else {
			b.WriteByte(byte(u))
			b.WriteByte(byte(u >> 8))
		}
	}
	return b.Bytes()
}

func TestDetectTextEncoding(t *testing.T) {
	const sample = "Contact john.doe@example.com or SSN 449-87-4100 on file.\n"
	cases := []struct {
		name string
		data []byte
		want TextEncoding
	}{
		{"utf-8 plain", []byte(sample), EncodingUTF8},
		{"utf-8 BOM", append([]byte{0xEF, 0xBB, 0xBF}, sample...), EncodingUTF8BOM},
		{"utf-16le BOM", fixtureUTF16(sample, false, true), EncodingUTF16LE},
		{"utf-16be BOM", fixtureUTF16(sample, true, true), EncodingUTF16BE},
		{"utf-16le no BOM", fixtureUTF16(sample, false, false), EncodingUTF16LENoBOM},
		{"utf-16be no BOM", fixtureUTF16(sample, true, false), EncodingUTF16BENoBOM},
		{"utf-32le BOM rejected", []byte{0xFF, 0xFE, 0x00, 0x00, 'a', 0, 0, 0}, EncodingUnknown},
		{"short buffer defaults utf-8", []byte("hi"), EncodingUTF8},
		// Binary with scattered nulls must NOT read as UTF-16: nulls appear
		// on both even and odd positions.
		{"binary scattered nulls", bytes.Repeat([]byte{0x00, 0x00, 0x41, 0x42}, 16), EncodingUTF8},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectTextEncoding(tc.data); got != tc.want {
				t.Errorf("DetectTextEncoding = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecodeEncodeRoundTrip(t *testing.T) {
	// Content mixes ASCII PII shapes, multibyte chars (™ becomes a single
	// UTF-16 unit; 💳 needs a surrogate pair), and CRLF line endings.
	const content = "SSN: 449-87-4100\r\nemail john.doe@example.com ™ card 💳\r\n"
	for _, enc := range []TextEncoding{
		EncodingUTF8, EncodingUTF8BOM,
		EncodingUTF16LE, EncodingUTF16BE,
		EncodingUTF16LENoBOM, EncodingUTF16BENoBOM,
	} {
		t.Run(enc.String(), func(t *testing.T) {
			raw := EncodeFromUTF8(content, enc)
			if det := DetectTextEncoding(raw); det != enc {
				// BOM-less encodings may legitimately re-detect as their
				// heuristic form; everything else must round-trip exactly.
				t.Errorf("re-detect: got %v, want %v", det, enc)
			}
			decoded, ok := DecodeToUTF8(raw, enc)
			if !ok {
				t.Fatal("DecodeToUTF8 refused a transcodable encoding")
			}
			if decoded != content {
				t.Errorf("round-trip mismatch:\n got %q\nwant %q", decoded, content)
			}
		})
	}
}

func TestDecodeUTF16Malformed(t *testing.T) {
	t.Run("odd trailing byte dropped", func(t *testing.T) {
		raw := append(fixtureUTF16("abc", false, true), 0x41) // stray byte
		decoded, ok := DecodeToUTF8(raw, EncodingUTF16LE)
		if !ok || decoded != "abc" {
			t.Errorf("got %q ok=%v, want \"abc\"", decoded, ok)
		}
	})
	t.Run("lone surrogate becomes U+FFFD not panic", func(t *testing.T) {
		raw := []byte{0xFF, 0xFE, 0x00, 0xD8, 'a', 0x00} // lone high surrogate + 'a'
		decoded, ok := DecodeToUTF8(raw, EncodingUTF16LE)
		if !ok {
			t.Fatal("decode refused")
		}
		if !strings.Contains(decoded, "�") || !strings.Contains(decoded, "a") {
			t.Errorf("lone surrogate handling: got %q", decoded)
		}
	})
	t.Run("empty payload after BOM", func(t *testing.T) {
		if decoded, ok := DecodeToUTF8([]byte{0xFF, 0xFE}, EncodingUTF16LE); !ok || decoded != "" {
			t.Errorf("got %q ok=%v", decoded, ok)
		}
	})
}

// TestLooksLikeText_Encodings extends the sniff matrix to the encodings the
// legacy null-byte gate previously rejected wholesale.
func TestLooksLikeText_Encodings(t *testing.T) {
	const sample = "Contact john.doe@example.com or SSN 449-87-4100 on file.\n"
	textCases := map[string][]byte{
		"utf-16le BOM":    fixtureUTF16(sample, false, true),
		"utf-16be BOM":    fixtureUTF16(sample, true, true),
		"utf-16le no BOM": fixtureUTF16(sample, false, false),
		"utf-16be no BOM": fixtureUTF16(sample, true, false),
		"utf-8 BOM":       append([]byte{0xEF, 0xBB, 0xBF}, sample...),
		"cp1252 smart quotes 0x80-0x9F": {
			'S', 'e', 'e', ' ', 0x93, 'q', 'u', 'o', 't', 'e', 'd', 0x94, ' ',
			0x96, ' ', 'd', 'a', 's', 'h', ' ', 0x85, ' ', 'e', 'l', 'l', 'i', 'p', '\n',
		},
	}
	for name, data := range textCases {
		t.Run("text/"+name, func(t *testing.T) {
			if !LooksLikeText(data) {
				t.Errorf("%s should classify as text", name)
			}
		})
	}

	binaryCases := map[string][]byte{
		// UTF-16-looking but nulls on both byte positions (UTF-32-ish)
		"nulls both positions": bytes.Repeat([]byte{0x41, 0x00, 0x00, 0x00}, 32),
		// dense control chars encoded as UTF-16LE with BOM: decodes fine but
		// is control soup — must still be rejected by the decoded-text judge
		"utf-16 control soup": fixtureUTF16(strings.Repeat("\x01\x02\x03\x04", 16), false, true),
	}
	for name, data := range binaryCases {
		t.Run("binary/"+name, func(t *testing.T) {
			if LooksLikeText(data) {
				t.Errorf("%s should classify as binary", name)
			}
		})
	}
}

// TestAdversarialFindings locks the fixes for the three regressions the
// adversarial verification panel proved against the first version of this
// change (PR #165). Each subtest is a distilled attacker repro.
func TestAdversarialFindings(t *testing.T) {
	t.Run("cp1251 Cyrillic prose is text (majority high-byte)", func(t *testing.T) {
		// Attack: Russian cp1251 prose + ASCII email. The first version's
		// ASCII-majority gate classified it binary — silent skip of every
		// non-Latin Windows codepage. cp1251 letters are 0xC0-0xFF.
		prose := bytes.Repeat([]byte{0xD3, 0xE2, 0xE0, 0xE6, 0xE0, 0xE5, 0xEC, 0xFB, 0xE9, 0x20}, 20) // "Уважаемый " x20
		prose = append(prose, []byte("ivan.petrov@example.com\n")...)
		if !LooksLikeText(prose) {
			t.Error("cp1251 Cyrillic prose must classify as text (was the panel's major regression)")
		}
	})
	t.Run("cp1253 Greek prose is text", func(t *testing.T) {
		prose := bytes.Repeat([]byte{0xC1, 0xE3, 0xE1, 0xF0, 0xE7, 0xF4, 0xDD, 0x20}, 25) // Greek letters cp1253
		prose = append(prose, []byte("SSN 449-87-4100\n")...)
		if !LooksLikeText(prose) {
			t.Error("cp1253 Greek prose must classify as text")
		}
	})
	t.Run("legacy text starting with FF FE bytes is not UTF-16", func(t *testing.T) {
		// Attack: cp1252 text beginning with 'ÿþ' (FF FE) was decoded as
		// UTF-16LE, turning the file to mojibake and hiding its PII.
		// Real UTF-16 always contains nulls; this file has none.
		data := append([]byte{0xFF, 0xFE}, []byte(" starts this legacy file. SSN: 449-87-4100\n")...)
		if enc := DetectTextEncoding(data); enc != EncodingUTF8 {
			t.Errorf("null-free FF FE-leading buffer detected as %v, want fallback (utf-8/legacy)", enc)
		}
		if !LooksLikeText(data) {
			t.Error("FF FE-leading legacy text must classify as text")
		}
	})
	t.Run("legacy text starting with FE FF bytes is not UTF-16", func(t *testing.T) {
		data := append([]byte{0xFE, 0xFF}, []byte(" also legacy. email a@b.co\n")...)
		if enc := DetectTextEncoding(data); enc != EncodingUTF8 {
			t.Errorf("null-free FE FF-leading buffer detected as %v", enc)
		}
	})
	t.Run("real UTF-16LE BOM still detected (has nulls)", func(t *testing.T) {
		data := fixtureUTF16("real utf-16 content\n", false, true)
		if enc := DetectTextEncoding(data); enc != EncodingUTF16LE {
			t.Errorf("genuine UTF-16LE+BOM detected as %v", enc)
		}
	})
	t.Run("random high-byte binary still rejected despite 0x80-0x9F allowance", func(t *testing.T) {
		// The cp1252 typographic allowance is gated on ASCII majority, so
		// structureless high-byte spans must stay binary.
		data := bytes.Repeat([]byte{0x81, 0x8D, 0x8F, 0x90, 0x9D, 0xC3, 0xF7, 0x85}, 16)
		if LooksLikeText(data) {
			t.Error("random high-byte binary must remain binary")
		}
	})
}
