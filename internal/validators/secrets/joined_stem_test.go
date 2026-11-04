// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"reflect"
	"testing"
)

// Tests for #881 Part 4, joined stems. Values are assembled at run time; none is a real
// credential.

var joinedValues = []string{
	"Kx9mQ2pZ" + "7vR4tW8yB3nL6cF1hJ5dG0sAeU2iO9qT",
	"Pq4nW7sX" + "2kM9vB5zL8hR3jT6fY1cD0gA4eU7iO2m",
	"Zr8cV3mN" + "6qK1wP9sJ4xF7hB2tL5yD0gE3aU8iO1n",
}

// TestJoinedStemsAreDerived pins the derived list: exactly the multi-word stems of the keyword
// patterns with their separator removed, each one a stem the line gate admits.
func TestJoinedStemsAreDerived(t *testing.T) {
	want := []string{"apikey", "authkey", "servicekey", "accountkey", "dbkey", "databasekey",
		"privkey", "privatekey", "clientkey", "accesstoken", "accesskey", "secretaccesskey", "secretkey"}
	if !reflect.DeepEqual(joinedSecretStems, want) {
		t.Errorf("joinedSecretStems = %v\nwant %v", joinedSecretStems, want)
	}
	for _, s := range joinedSecretStems {
		if !lineHasKeywordStem(s + "=x") {
			t.Errorf("%q is not a stem the keyword patterns are anchored on", s)
		}
	}
}

// TestJoinedStemsScoreLikeSeparatedStems is #881's acceptance row: each joined spelling, and
// APIKEY, scores as `api_key` does, with `:` and with `=`; and `apikey = "v"` reaches HIGH. Before
// #881 the unquoted rows reported nothing and the quoted row 55.
func TestJoinedStemsScoreLikeSeparatedStems(t *testing.T) {
	v := NewValidator()
	score := func(t *testing.T, line string) (string, float64) {
		t.Helper()
		ms, err := v.ValidateContent(line+"\n", "app.env")
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != 1 {
			t.Fatalf("%q: want one finding, got %v", line, ms)
		}
		return ms[0].Type, ms[0].Confidence
	}
	for _, val := range joinedValues {
		for _, delim := range []string{": ", "="} {
			_, control := score(t, "api_key"+delim+val)
			for _, stem := range append(append([]string{}, joinedSecretStems...), "APIKEY", "ACCESSTOKEN") {
				if stem == "secretaccesskey" {
					continue // the AWS secret-key path claims it; see below
				}
				typ, got := score(t, stem+delim+val)
				if typ != genericSecretType || got != control {
					t.Errorf("%s%s<v>: %s %v, want %s %v as api_key%s<v>", stem, delim, typ, got, genericSecretType, control, delim)
				}
			}
		}
		if _, got := score(t, `apikey = "`+val+`"`); got < 90 {
			t.Errorf(`apikey = "<v>": %v, want >= 90`, got)
		}
	}

	// secretaccesskey also opens the AWS path, which types the value; the joined spelling now
	// scores as secret_access_key does, where before it kept only that path's own 90.
	for _, val := range []string{"tIWgqmCdzQo6ZmMWR4A92POE5IkrJSPkdQYtpCx5"} {
		for _, delim := range []string{": ", "="} {
			ctyp, control := score(t, "secret_access_key"+delim+val)
			typ, got := score(t, "secretaccesskey"+delim+val)
			if typ != ctyp || got != control {
				t.Errorf("secretaccesskey%s<v>: %s %v, want %s %v", delim, typ, got, ctyp, control)
			}
		}
	}
}

// TestJoinedStemGovernsASequence: a YAML block sequence under a joined plural key is governed by it,
// as one under `api_keys:` is.
func TestJoinedStemGovernsASequence(t *testing.T) {
	v := NewValidator()
	for _, key := range []string{"api_keys", "apikeys"} {
		ms, err := v.ValidateContent(key+":\n  - "+joinedValues[0]+"\n  - "+joinedValues[1]+"\n", "app.yaml")
		if err != nil {
			t.Fatal(err)
		}
		if len(ms) != 2 {
			t.Errorf("%s: want both items reported, got %v", key, ms)
		}
	}
}

// TestJoinedStemPathSkip: the joined-stem lift is withheld from a rooted value holding a `.`, so
// certbot's renewal file and `<joined stem> = <path>` stay as they were on main, with no finding;
// a path a positive keyword already corroborates keeps reporting; a joined-stem value that is no
// path is lifted.
func TestJoinedStemPathSkip(t *testing.T) {
	v := NewValidator()
	count := func(t *testing.T, content string) int {
		t.Helper()
		ms, err := v.ValidateContent(content, "renewal.conf")
		if err != nil {
			t.Fatal(err)
		}
		return len(ms)
	}
	if n := count(t, "[renewalparams]\nprivkey = /etc/letsencrypt/live/mail.internal/privkey.pem\ncert = /etc/letsencrypt/live/mail.internal/cert.pem\n"); n != 0 {
		t.Errorf("certbot renewal file: %d finding(s), want none", n)
	}
	for _, stem := range joinedSecretStems {
		for _, p := range []string{"/srv/app/conf/abc.pem", "./conf/abc.pem", "../conf/abc.pem", "~/conf/abc.pem", `C:\app\conf\abc.pem`, "C:/app/conf/abc.pem", "~/.ssh/id_ed25519"} {
			if n := count(t, stem+" = "+p+"\n"); n != 0 {
				t.Errorf("%s = %s: %d finding(s), want none", stem, p, n)
			}
		}
	}
	// Corroborated by a positive keyword on main, and still reported.
	for _, line := range []string{"private_key=/etc/ssl/private/server.key", "private-key=/etc/ssl/private/server.key", "apikey=~/keys/id_ed25519.pub"} {
		if n := count(t, line+"\n"); n != 1 {
			t.Errorf("%s: %d finding(s), want the one main reports", line, n)
		}
	}
	// A joined-stem value that is no rooted path is lifted.
	if n := count(t, "privkey = "+joinedValues[2]+"\n"); n != 1 {
		t.Errorf("privkey = <v>: %d finding(s), want 1", n)
	}

	for in, want := range map[string]bool{
		"/srv/app/abc.pem": true, "./a.b": true, "../a.b": true, "~/.ssh/id_rsa": true, `C:\a\b.c`: true, "c:/a/b.c": true,
		`"/srv/app/abc.pem"`:   true,
		"/srv/app/conf/apikey": false, "srv/app/abc.pem": false, "abc.pem": false, "/" + joinedValues[0]: false,
		"C:abc.pem": false, "~abc.pem": false, "": false,
	} {
		if got := pathRootedValue(in); got != want {
			t.Errorf("pathRootedValue(%q) = %v, want %v", in, got, want)
		}
	}
}
