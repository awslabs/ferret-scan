// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
)

// Generators for the #902 Part C anchors of TestValidatorComplexityIsSubQuadratic (#1023).
//
// Every repetition derives its secret bytes from a hash of the index, so no two repetitions carry the
// same value (a repeated value is deduplicated by the validator and pins the finding count flat; see
// complexity_generators_test.go) and every value has the entropy of a real credential, which the
// carriers' shape gates require. Nothing here is a real credential: the bytes are SHA-512 of a counter.

// partCBytes returns n deterministic bytes that depend on (tag, i) and nothing else.
func partCBytes(tag string, i, n int) []byte {
	sum := sha512.Sum512([]byte(fmt.Sprintf("%s/%d", tag, i)))
	out := sum[:]
	for len(out) < n {
		more := sha512.Sum512(out)
		out = append(out, more[:]...)
	}
	return out[:n]
}

// partCURL returns n base64url characters (no padding) that depend on (tag, i).
func partCURL(tag string, i, n int) string {
	return base64.RawURLEncoding.EncodeToString(partCBytes(tag, i, n))[:n]
}

// genHTTPAuthHeaders emits, per index, one `Authorization: Basic` header and one `Authorization:
// Bearer` header on the SAME line, each with its own distinct credential (A1 and A2 of http_auth.go).
// The Basic blob decodes to `svc<i>:<password>`, the printable user:pass the decode pipeline wants.
func genHTTPAuthHeaders(i int) string {
	pass := partCURL("basic", i, 18)
	blob := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("svc%d:%s", i, pass)))
	return fmt.Sprintf("Authorization: Basic %s Authorization: Bearer %s ", blob, partCURL("bearer", i, 32))
}

// genPuttyPrivateLines emits, per index, one PuTTY v3 ed25519 key file as it sits on disk: header, two
// public lines, a `Private-Lines: 1` record with one distinct base64 line, and the MAC trailer
// (private_key_containers.go findPuttyContainers). Real line breaks, so the generic per-line passes
// stay cheap and the container pass, which reads the whole content, is a large share of the reading.
func genPuttyPrivateLines(i int) string {
	var sb strings.Builder
	sb.WriteString("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n")
	fmt.Fprintf(&sb, "Comment: key-%d\nPublic-Lines: 2\n", i)
	sb.WriteString(base64.StdEncoding.EncodeToString(partCBytes("ppk-pub-a", i, 48)) + "\n")
	sb.WriteString(base64.StdEncoding.EncodeToString(partCBytes("ppk-pub-b", i, 24)) + "\n")
	sb.WriteString("Private-Lines: 1\n")
	sb.WriteString(base64.StdEncoding.EncodeToString(partCBytes("ppk-priv", i, 48)) + "\n")
	fmt.Fprintf(&sb, "Private-MAC: %x\n\n", partCBytes("ppk-mac", i, 32))
	return sb.String()
}

// genSHA512CryptLine emits, per index, one sha512crypt hash (`$6$<salt>$<86 crypt(3) characters>`) and
// a space, so a run of them is ONE long line, which is how a hash dump reads when its line breaks are
// lost (password_hashes.go findPasswordHashes). The salt carries the index.
func genSHA512CryptLine(i int) string {
	const c64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	raw := partCBytes("sha512crypt", i, 86)
	tail := make([]byte, len(raw))
	for k, b := range raw {
		tail[k] = c64[int(b)%len(c64)]
	}
	return fmt.Sprintf("$6$salt%d$%s ", i, tail)
}

// genJWKPrivateMembers emits, per index, one RSA JWK with all six private members (d, p, q, dp, dq,
// qi), each a distinct 43-character base64url value, and a space: one single-line run of objects, each
// with several members for jwk_private.go to report. Six findings per repetition.
func genJWKPrivateMembers(i int) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, `{"kty":"RSA","kid":"k%d","n":"%s","e":"AQAB"`, i, partCURL("jwk-n", i, 43))
	for _, m := range []string{"d", "p", "q", "dp", "dq", "qi"} {
		fmt.Fprintf(&sb, `,"%s":"%s"`, m, partCURL("jwk-"+m, i, 43))
	}
	sb.WriteString("} ")
	return sb.String()
}
