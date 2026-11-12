// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// Tests for the password-hash source (password_hashes.go, #902 Part C).
//
// No value here is a real hash of anything: each is the scheme's framing around random characters
// from the scheme's alphabet, drawn at run time from a fixed seed, so a failure reproduces and no
// committed byte is a crackable hash. Salts are drawn letter-led and digit-led alike, because on
// main whether a quoted hash was reported depended on exactly that.

const (
	tC64   = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	tB64   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	tAlnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)

func tRand(r *rand.Rand, alpha string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[r.Intn(len(alpha))]
	}
	return string(b)
}

// tSalt is a crypt salt whose first byte alternates between a letter and a digit.
func tSalt(r *rand.Rand, i, n int) string {
	if i%2 == 0 {
		return tRand(r, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", 1) + tRand(r, tC64, n-1)
	}
	return tRand(r, "0123456789", 1) + tRand(r, tC64, n-1)
}

// hashSchemes builds one synthetic hash per scheme; idSchemes are the `$id$` crypt schemes the
// salt sweep runs at full size.
var hashSchemes = map[string]func(r *rand.Rand, i int) string{
	"md5crypt":    func(r *rand.Rand, i int) string { return "$1$" + tSalt(r, i, 8) + "$" + tRand(r, tC64, 22) },
	"apr1":        func(r *rand.Rand, i int) string { return "$apr1$" + tSalt(r, i, 8) + "$" + tRand(r, tC64, 22) },
	"sha256crypt": func(r *rand.Rand, i int) string { return "$5$" + tSalt(r, i, 16) + "$" + tRand(r, tC64, 43) },
	"sha512crypt": func(r *rand.Rand, i int) string { return "$6$" + tSalt(r, i, 16) + "$" + tRand(r, tC64, 86) },
	"sha512rounds": func(r *rand.Rand, i int) string {
		return "$6$rounds=656000$" + tSalt(r, i, 16) + "$" + tRand(r, tC64, 86)
	},
	"bcrypt":   func(r *rand.Rand, i int) string { return "$2b$12$" + tSalt(r, i, 53) },
	"bcrypt2y": func(r *rand.Rand, i int) string { return "$2y$10$" + tSalt(r, i, 53) },
	"yescrypt": func(r *rand.Rand, i int) string { return "$y$j9T$" + tSalt(r, i, 22) + "$" + tRand(r, tC64, 43) },
	"scrypt":   func(r *rand.Rand, i int) string { return "$7$" + tSalt(r, i, 30) + "$" + tRand(r, tC64, 43) },
	"argon2id": func(r *rand.Rand, i int) string {
		return "$argon2id$v=19$m=65536,t=3,p=4$" + tRand(r, tB64, 22) + "$" + tRand(r, tB64, 43)
	},
	"passlib_pbkdf2": func(r *rand.Rand, i int) string {
		return "$pbkdf2-sha256$29000$" + tRand(r, tB64, 22) + "$" + tRand(r, tB64, 43)
	},
	"django_pbkdf2": func(r *rand.Rand, i int) string {
		return "pbkdf2_sha256$600000$" + tRand(r, tAlnum, 22) + "$" + tRand(r, tB64, 43) + "="
	},
	"django_bcrypt": func(r *rand.Rand, i int) string { return "bcrypt_sha256$$2b$12$" + tSalt(r, i, 53) },
	"ldap_ssha":     func(r *rand.Rand, i int) string { return "{SSHA}" + tRand(r, tB64, 32) },
	"mysql":         func(r *rand.Rand, i int) string { return "*" + tRand(r, "0123456789ABCDEF", 40) },
}

var idSchemes = map[string]bool{"md5crypt": true, "apr1": true, "sha256crypt": true, "sha512crypt": true, "bcrypt": true, "yescrypt": true}

// hashCarriers are the four carriers of the issue's salt sweep: quoted under a password label,
// unquoted under a *_PASSWORD_HASH label, a shadow record, and an htpasswd record.
var hashCarriers = []struct {
	name, path, tmpl string
}{
	{"quoted", "vars.yaml", "password: \"%s\"\n"},
	{"unquoted", "app.env", "ADMIN_PASSWORD_HASH=%s\n"},
	{"shadow", "shadow", "svc-orders:%s:19800:0:99999:7:::\n"},
	{"htpasswd", ".htpasswd", "svc-orders:%s\n"},
}

func findText(ms []detector.Match, text string) *detector.Match {
	for i := range ms {
		if ms[i].Text == text {
			return &ms[i]
		}
	}
	return nil
}

// TestPasswordHashSaltSweep is the issue's acceptance sweep: every `$id$` scheme, 200 hashes each
// (half letter-led salts), on four carriers, is reported at >= 60, whatever its salt. The other
// schemes run 20 each.
func TestPasswordHashSaltSweep(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(902))
	for scheme, gen := range hashSchemes {
		n := 20
		if idSchemes[scheme] {
			n = 200
		}
		for _, c := range hashCarriers {
			missed := 0
			var first string
			for i := 0; i < n; i++ {
				h := gen(r, i)
				ms, err := v.ValidateContent(fmt.Sprintf(c.tmpl, h), c.path)
				if err != nil {
					t.Fatal(err)
				}
				if m := findText(ms, h); m == nil || m.Confidence < 60 {
					missed++
					if first == "" {
						first = fmt.Sprintf("%q -> %+v", h, ms)
					}
				}
			}
			if missed > 0 {
				t.Errorf("%s on %s: %d/%d not reported at >= 60; first: %s", scheme, c.name, missed, n, first)
			}
		}
	}
}

// TestPasswordHashCarriers covers the carriers that reached no path on main, one scheme pair each.
func TestPasswordHashCarriers(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(9020))
	carriers := []struct{ path, tmpl string }{
		{"ks.cfg", "rootpw --iscrypted %s\n"},
		{"user.json", "{\"password_hash\": \"%s\"}\n"},
		{"seed.sql", "INSERT INTO users (login, password_digest) VALUES ('svc-orders', '%s');\n"},
		{"Dockerfile", "RUN echo 'svc-orders:%s' | chpasswd -e\n"},
		{"hash.txt", "%s\n"},
		{"user-data.yaml", "users:\n  - name: svc-orders\n    passwd: %s\n"},
		{"q.env", "ADMIN_PASSWORD='%s'\n"},
		{"shadow", "svc-orders:!%s:19800:0:99999:7:::\n"}, // locked: still crackable
	}
	for _, c := range carriers {
		for _, scheme := range []string{"sha512crypt", "bcrypt", "argon2id", "ldap_ssha", "mysql", "django_pbkdf2"} {
			for i := 0; i < 2; i++ {
				h := hashSchemes[scheme](r, i)
				ms, _ := v.ValidateContent(fmt.Sprintf(c.tmpl, h), c.path)
				m := findText(ms, h)
				if m == nil || m.Confidence < 60 {
					t.Errorf("%s in %s (salt %d): want a finding >= 60 with Text = the hash, got %+v", scheme, c.path, i, ms)
					continue
				}
				if m.Type != genericSecretType {
					t.Errorf("%s in %s: Type %s, want %s", scheme, c.path, m.Type, genericSecretType)
				}
			}
		}
	}
}

// TestPasswordHashDESRecord: a 13-byte DES crypt is only a hash as field 2 of a shadow or passwd
// record, or of a two-field record in an htpasswd file.
func TestPasswordHashDESRecord(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(9021))
	des := tRand(r, "BCDFGHJKLMNPQRSTVWXZ", 2) + tRand(r, tC64, 11)
	for _, tc := range []struct {
		path, content string
		want          bool
	}{
		{"shadow", "svc-orders:" + des + ":19800:0:99999:7:::\n", true},
		{"passwd", "svc-orders:" + des + ":1001:1001::/home/svc-orders:/bin/sh\n", true},
		{".htpasswd", "svc-orders:" + des + "\n", true},
		{"notes.txt", "svc-orders:" + des + "\n", false}, // a two-field record outside an htpasswd file
	} {
		ms, _ := v.ValidateContent(tc.content, tc.path)
		m := findText(ms, des)
		if got := m != nil && m.Confidence >= 60; got != tc.want {
			t.Errorf("%s: reported=%v, want %v (%+v)", tc.path, got, tc.want, ms)
		}
	}
}

// TestPasswordHashDecoys: shapes that share a hash's `$` framing but match no exact grammar, and the
// records that hold no hash, report nothing from this validator.
func TestPasswordHashDecoys(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(9022))
	salt, tail := tSalt(r, 0, 16), tRand(r, tC64, 86)
	decoys := []struct{ path, content string }{
		{"run.sh", "echo \"$1$2\"\n"},
		{"tag.sh", "TAG=\"$USER$HOST$SUFFIX\"\n"},
		{"swap.pl", "my $s = \"$2$1\";\n"},
		{"Makefile", "x:\n\techo $$a$$a\n"},
		{"notes.md", "The $6$ prefix marks a SHA-512 crypt hash.\n"},
		{"shadow", "svc-a:*:19800:0:99999:7:::\nsvc-b:!:19800:0:99999:7:::\nsvc-c:!!:19800:0:99999:7:::\nsvc-d:!*:19800:0:99999:7:::\n"},
		{"passwd", "svc-orders:x:1001:1001::/home/svc-orders:/bin/bash\n"},
		{"ref.env", "password=\"$DB_PASSWORD\"\n"},
		{"ref.yaml", "password: ${DB_PASSWORD}\n"},
		{"redacted.json", "{\"password_hash\": \"<redacted>\"}\n"},
		{"short.txt", "$6$" + salt + "$" + tail[:85] + "\n"}, // one byte short of sha512crypt
		{"long.txt", "$6$" + salt + "$" + tail + "Q\n"},      // tail continues past 86
		{"make2.mk", "x = $$6$" + salt + "$" + tail + "\n"},  // Make escape, not a hash
		{"paths.go", "p := \"$WORK${/}gopath$1$2$3\"\n"},
	}
	for _, d := range decoys {
		ms, _ := v.ValidateContent(d.content, d.path)
		for _, m := range ms {
			if m.Confidence >= 60 || m.Metadata["detection_method"] == methodPasswordHash || m.Metadata["detection_method"] == methodPasswordRecord {
				t.Errorf("%s: unexpected finding %q %s %.0f %v", d.path, m.Text, m.Type, m.Confidence, m.Metadata["detection_method"])
			}
		}
	}
}

// TestPasswordHashKeepsExistingFinding: a quoted hash main already reported (digit-led salt, so no
// `$` letter on its line) keeps that finding's Type, Text, line and detection_method; the new source
// adds no second finding for it.
func TestPasswordHashKeepsExistingFinding(t *testing.T) {
	v := NewValidator()
	r := rand.New(rand.NewSource(9023))
	h := hashSchemes["sha512crypt"](r, 1)
	ms, _ := v.ValidateContent("password: \""+h+"\"\n", "vars.yaml")
	if len(ms) != 1 {
		t.Fatalf("want exactly one finding, got %+v", ms)
	}
	m := ms[0]
	if m.Text != h || m.LineNumber != 1 || m.Type != genericSecretType || m.Metadata["detection_method"] != "keyword_pattern" {
		t.Errorf("existing finding changed: %q line %d %s %v", m.Text, m.LineNumber, m.Type, m.Metadata["detection_method"])
	}
}

// TestIsPasswordHashText pins the exact-grammar predicate the veto exemption and the confidence
// arm key on.
func TestIsPasswordHashText(t *testing.T) {
	r := rand.New(rand.NewSource(9024))
	for scheme, gen := range hashSchemes {
		if h := gen(r, 0); !isPasswordHashText(h) {
			t.Errorf("%s: %q not recognised", scheme, h)
		}
	}
	for _, s := range []string{"", "$USER$HOST$SUFFIX", "$1$2$3", "$6$" + strings.Repeat("a", 16), "*" + strings.Repeat("a", 40)} {
		if isPasswordHashText(s) {
			t.Errorf("%q recognised as a hash", s)
		}
	}
}
