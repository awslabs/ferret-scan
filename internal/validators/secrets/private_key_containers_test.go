// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Tests for the private-key container source (private_key_containers.go, #902 Part B).
//
// Every key body is synthetic and built at run time by keyBody: consonants, digits, `+` and `/`
// only, so no word and no test/example/demo/dev marker can be spelt and no committed byte is a key.
// Framing markers are concatenated like pemBeginMarker, so this file holds no literal BEGIN line
// for the repository's pre-commit hooks or GitHub push protection to read as a key.

var (
	tBegin5 = "-----" + "BEGIN"
	tEnd5   = "-----" + "END"
	tPutty  = "PuTTY-User-" + "Key-File-"
	tAge    = "AGE-" + "SECRET-KEY-1"
)

// keyBody returns n deterministic base64-alphabet bytes, distinct per seed.
func keyBody(seed, n int) string {
	const alpha = "BCDFGHJKLMNPQRSTVWXZbcdfghjkmnpqrstvwxz23456789+/"
	x := uint32(seed*2654435761 + 977)
	b := make([]byte, n)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = alpha[int(x>>8)%len(alpha)]
	}
	return string(b)
}

// keyLines folds s into lines of width w joined by sep.
func keyLines(s string, w int, sep string) string {
	var parts []string
	for len(s) > w {
		parts = append(parts, s[:w])
		s = s[w:]
	}
	return strings.Join(append(parts, s), sep)
}

func hexBody(seed, n int) string {
	const hex = "0123456789abcdef"
	x := uint32(seed*40503 + 7)
	b := make([]byte, n)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = hex[int(x>>8)%16]
	}
	return string(b)
}

// ppk builds a PuTTY private-key file of the given version and algorithm, its lines joined by sep.
func ppk(version, algo, encryption string, mac bool, sep string, seed int) string {
	lines := []string{
		tPutty + version + ": " + algo,
		"Encryption: " + encryption,
		"Comment: orders-svc",
		"Public-Lines: 2",
		keyBody(seed, 64), keyBody(seed+1, 24),
	}
	if encryption != "none" {
		lines = append(lines, "Key-Derivation: Argon2id", "Argon2-Memory: 8192", "Argon2-Passes: 13",
			"Argon2-Parallelism: 1", "Argon2-Salt: "+hexBody(seed, 32))
	}
	lines = append(lines, "Private-Lines: 2", keyBody(seed+2, 64), keyBody(seed+3, 24))
	if mac {
		lines = append(lines, "Private-MAC: "+hexBody(seed+4, 64))
	}
	return strings.Join(lines, sep)
}

func armour(dashes, label, body string) string {
	return dashes + " BEGIN " + label + " " + dashes + "\n" + body + "\n" + dashes + " END " + label + " " + dashes
}

func ageIdentity(seed int) string {
	x := uint32(seed*69069 + 3)
	b := make([]byte, ageDataLen)
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = ageBech32Charset[int(x>>8)%len(ageBech32Charset)]
	}
	return tAge + string(b)
}

func validateAll(t *testing.T, content, path string) []detector.Match {
	t.Helper()
	ms, err := NewValidator().ValidateContent(content, path)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

// TestPrivateKeyContainersAreReported: every container shape reports exactly one finding of the
// expected type and method, at or above the documented pre-commit `high,medium` floor (60), whose
// Text holds the private blob and never only a label.
func TestPrivateKeyContainersAreReported(t *testing.T) {
	ppkV3 := ppk("3", "ssh-ed25519", "none", true, "\n", 1)
	privBlob := keyBody(1+2, 64)
	ovpnBody := keyLines(hexBody(9, 512), 32, "\n")
	sshcomBody := "Comment: \"rsa-key-orders\"\n" + keyLines(keyBody(11, 700), 70, "\n")
	age := ageIdentity(5)

	cases := []struct {
		name, path, content, mustHold, method, typ string
		line                                       int
	}{
		{"ppk v3", "orders.ppk", ppkV3, privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ppk v2 rsa", "orders.ppk", ppk("2", "ssh-rsa", "none", true, "\n", 1), privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ppk v3 encrypted", "orders.ppk", ppk("3", "ssh-rsa", "aes256-cbc", true, "\n", 1), privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ppk unknown version", "orders.ppk", ppk("4", "ssh-ed25519", "none", true, "\n", 1), privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ppk without MAC", "orders.ppk", ppk("3", "ssh-ed25519", "none", false, "\n", 1), privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ppk CRLF", "orders.ppk", ppk("3", "ssh-ed25519", "none", true, "\r\n", 1), privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ppk as txt", "notes.txt", "key below\n\n" + ppkV3 + "\n", privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 3},
		{"ppk in a markdown fence", "README.md", "# Access\n\n```\n" + ppkV3 + "\n```\n", privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 4},
		{"ppk in a yaml block", "values.yaml", "deploy:\n  private_key: |\n    " + ppk("3", "ssh-ed25519", "none", true, "\n    ", 1) + "\n", privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 3},
		{"ppk in a terraform heredoc", "main.tf", "locals {\n  ppk = <<EOT\n" + ppkV3 + "\nEOT\n}\n", privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 3},
		{"ppk in a json string under ppk", "keys.json", `{"ppk": "` + ppk("3", "ssh-ed25519", "none", true, `\n`, 1) + `"}`, privBlob, containerMethodPutty, "SSH_PRIVATE_KEY", 1},
		{"ssh.com encrypted", "orders.key", armour("----", "SSH2 ENCRYPTED PRIVATE KEY", sshcomBody), keyBody(11, 70), containerMethodArmour, "SSH_PRIVATE_KEY", 1},
		{"5-dash label outside the legacy alternation", "orders.key", armour("-----", "ED25519 PRIVATE KEY", keyLines(keyBody(12, 128), 64, "\n")), keyBody(12, 64), containerMethodArmour, "SSH_PRIVATE_KEY", 1},
		{"openvpn ta.key", "ta.key", "#\n# 2048 bit OpenVPN static key\n#\n" + strings.ReplaceAll(armour("-----", "OpenVPN Static key V1", ovpnBody), "V1 -----", "V1-----"), hexBody(9, 32), containerMethodOpenVPN, genericSecretType, 4},
		{"openvpn inline tls-auth", "client.ovpn", "client\nremote vpn.orders.invalid 1194\n<tls-auth>\n" + strings.ReplaceAll(armour("-----", "OpenVPN Static key V1", ovpnBody), "V1 -----", "V1-----") + "\n</tls-auth>\n", hexBody(9, 32), containerMethodOpenVPN, genericSecretType, 4},
		{"openvpn tls-crypt-v2 client key", "client.key", strings.ReplaceAll(armour("-----", "OpenVPN tls-crypt-v2 client key", keyLines(keyBody(13, 300), 64, "\n")), "key -----", "key-----"), keyBody(13, 64), containerMethodOpenVPN, genericSecretType, 1},
		{"age identity file", "keys.txt", "# created: 2026-11-11T09:00:00Z\n# public key: age1qqqq\n" + age + "\n", age, containerMethodAge, genericSecretType, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ms := validateAll(t, tc.content, tc.path)
			if len(ms) != 1 {
				t.Fatalf("got %d findings, want 1: %+v", len(ms), ms)
			}
			m := ms[0]
			if m.Metadata["detection_method"] != tc.method || m.Type != tc.typ {
				t.Errorf("method/type = %v/%s, want %s/%s", m.Metadata["detection_method"], m.Type, tc.method, tc.typ)
			}
			if m.Confidence < 60 {
				t.Errorf("confidence %.0f below the pre-commit floor 60", m.Confidence)
			}
			if m.LineNumber != tc.line {
				t.Errorf("line %d, want %d", m.LineNumber, tc.line)
			}
			if !strings.Contains(m.Text, tc.mustHold) {
				t.Errorf("finding text does not hold the private blob")
			}
		})
	}
}

// TestPrivateKeyContainerDecoys: framing words, public halves and prose are not keys.
func TestPrivateKeyContainerDecoys(t *testing.T) {
	cases := []struct{ name, path, content string }{
		{"public key pem", "orders.pem", tBegin5 + " PUBLIC KEY-----\n" + keyLines(keyBody(20, 128), 64, "\n") + "\n" + tEnd5 + " PUBLIC KEY-----\n"},
		{"ssh public line", "id_ed25519.pub", "ssh-ed25519 " + strings.ReplaceAll(keyBody(21, 68), "/", "") + " orders@build\n"},
		{"age recipient", "recipients.txt", "age1" + strings.ToLower(ageIdentity(6)[len(tAge):]) + "\n"},
		{"ppk header in prose", "notes.md", "A PuTTY key starts with " + tPutty + "3: ssh-ed25519 and the lines that follow.\n"},
		{"ppk header and public lines only", "pub.ppk", tPutty + "3: ssh-ed25519\nPublic-Lines: 1\n" + keyBody(22, 64) + "\n"},
		{"openvpn genkey prose", "README.md", "Run `openvpn --genkey secret ta.key` to write a static key.\n"},
		{"armour begin without end", "notes.md", "---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nthe body goes here\n"},
		{"age prefix one character short", "keys.txt", ageIdentity(7)[:len(tAge)+ageDataLen-1] + "\n"},
		{"age prefix glued to a word", "keys.txt", "X" + ageIdentity(8) + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if ms := validateAll(t, tc.content, tc.path); len(ms) != 0 {
				t.Errorf("got %d findings, want none: %+v", len(ms), ms)
			}
		})
	}
}

// TestOneLinePEMIsReportedOnce is the issue's one-line PEM matrix: a PEM joined onto one line by
// spaces, in a JSON string with `\n` escapes under a neutral key, and the same under
// `"private_key"`, yields exactly one finding, the multi-line pass's, never a label. On main the
// cells reported 2, 2 and 3 (an OPENSSH key added a finding whose Text was `OPENSSH `).
func TestOneLinePEMIsReportedOnce(t *testing.T) {
	labels := []struct{ label, typ, method string }{
		{"PRIVATE KEY", "SSH_PRIVATE_KEY", "ssh_private_key"},
		{"RSA PRIVATE KEY", "SSH_PRIVATE_KEY", "ssh_private_key"},
		{"EC PRIVATE KEY", "SSH_PRIVATE_KEY", "ssh_private_key"},
		{"OPENSSH PRIVATE KEY", "SSH_PRIVATE_KEY", "ssh_private_key"},
		{"ENCRYPTED PRIVATE KEY", "CERTIFICATE", "certificate"},
	}
	for i, l := range labels {
		body := keyBody(30+i, 256)
		pem := func(sep string) string {
			return tBegin5 + " " + l.label + "-----" + sep + keyLines(body, 64, sep) + sep + tEnd5 + " " + l.label + "-----"
		}
		shapes := []struct{ name, path, content string }{
			{"multi-line control", "k.pem", pem("\n") + "\n"},
			{"space-joined", "k.pem", pem(" ") + "\n"},
			{"json neutral key", "k.json", `{"blob": "` + pem(`\n`) + `\n"}` + "\n"},
			{"json private_key", "k.json", `{"private_key": "` + pem(`\n`) + `\n"}` + "\n"},
		}
		for _, s := range shapes {
			t.Run(l.label+"/"+s.name, func(t *testing.T) {
				ms := validateAll(t, s.content, s.path)
				if len(ms) != 1 {
					t.Fatalf("got %d findings, want 1: %+v", len(ms), ms)
				}
				m := ms[0]
				if m.Type != l.typ || m.Metadata["detection_method"] != l.method {
					t.Errorf("type/method = %s/%v, want %s/%s", m.Type, m.Metadata["detection_method"], l.typ, l.method)
				}
				if !strings.Contains(m.Text, body[:64]) || !strings.HasPrefix(m.Text, tBegin5) {
					t.Errorf("kept finding is not the whole PEM: %.40q", m.Text)
				}
			})
		}
	}
}

// TestContainerKeepsAnExistingFinding: a container whose bytes a finding already reports adds
// nothing, so that finding keeps its Type, Text and line (resolution 2 of #902). A PPK held in a
// JSON string under "private_key" is the keyword path's finding on main, and stays it.
func TestContainerKeepsAnExistingFinding(t *testing.T) {
	content := `{"private_key": "` + ppk("3", "ssh-ed25519", "none", true, `\n`, 2) + `"}` + "\n"
	ms := validateAll(t, content, "keys.json")
	if len(ms) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(ms), ms)
	}
	if ms[0].Metadata["detection_method"] != "keyword_pattern" || ms[0].Type != genericSecretType || ms[0].LineNumber != 1 {
		t.Errorf("got %s %v line %d, want the keyword path's API_KEY_OR_SECRET on line 1", ms[0].Type, ms[0].Metadata["detection_method"], ms[0].LineNumber)
	}
}

// TestFindPrivateKeyContainersSpans pins the grammar's spans directly, independent of scoring.
func TestFindPrivateKeyContainersSpans(t *testing.T) {
	ppkText := ppk("3", "ssh-ed25519", "none", true, "\n", 3)
	sshcom := armour("----", "SSH2 ENCRYPTED PRIVATE KEY", keyLines(keyBody(40, 140), 70, "\n"))
	age := ageIdentity(9)
	legacy := tBegin5 + " RSA PRIVATE KEY-----\n" + keyBody(41, 64) + "\n" + tEnd5 + " RSA PRIVATE KEY-----"
	content := "lead\n" + ppkText + "\ntrailing words\n" + sshcom + "\n" + legacy + "\n# " + age + ".\n"
	got := findPrivateKeyContainers(content)
	want := []string{sshcom, ppkText, age} // armour, then PuTTY, then age; the legacy RSA block is left to the PEM pass
	if len(got) != len(want) {
		t.Fatalf("got %d containers, want %d", len(got), len(want))
	}
	for i, c := range got {
		if content[c.start:c.end] != want[i] {
			t.Errorf("container %d = %.60q, want %.60q", i, content[c.start:c.end], want[i])
		}
	}
	if kind, ok := privateKeyContainerKind(ppkText); !ok || kind != containerMethodPutty {
		t.Errorf("privateKeyContainerKind(ppk) = %q, %v", kind, ok)
	}
	if _, ok := privateKeyContainerKind("x" + age); ok {
		t.Error("a glued age prefix must not be a whole container")
	}
}
