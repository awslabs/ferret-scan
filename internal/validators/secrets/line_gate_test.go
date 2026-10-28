// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Tests for the keyword pass's line gate, containsSecretIndicators (#765). Every secret-shaped
// value is assembled at run time from pieces, so a static scanner reading this source finds none;
// none is a real credential.

// gateRand is a small deterministic generator, so every population here is reproducible from its
// seed and a failure names a line that can be re-derived.
type gateRand struct{ x uint64 }

func (r *gateRand) intn(n int) int {
	r.x = r.x*6364136223846793005 + 1442695040888963407
	return int((r.x >> 33) % uint64(n))
}

func (r *gateRand) pick(xs []string) string { return xs[r.intn(len(xs))] }

func (r *gateRand) str(alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.intn(len(alphabet))]
	}
	return string(b)
}

const (
	gateConsonantsDigits = "BCDFGHJKLMNPQRSTVWXZbcdfghjkmnpqrstvwxz23456789"
	gateUpperDigits      = "BCDFGHJKLMNPQRSTVWXZ234567"
	gateBase64           = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	gateBase64URL        = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
)

// gateSecrets builds one value of each secret shape #765 measured.
type gateSecrets struct{ r *gateRand }

func (g gateSecrets) akia() string  { return "AK" + "IA" + g.r.str(gateUpperDigits, 16) }
func (g gateSecrets) ghp() string   { return "gh" + "p_" + g.r.str(gateConsonantsDigits, 36) }
func (g gateSecrets) glpat() string { return "gl" + "pat-" + g.r.str(gateConsonantsDigits, 20) }
func (g gateSecrets) xoxb() string {
	return "xo" + "xb-" + g.r.str("23456789", 12) + "-" + g.r.str("23456789", 12) + "-" + g.r.str(gateConsonantsDigits, 24)
}
func (g gateSecrets) jwt() string {
	return "ey" + "J" + g.r.str(gateBase64URL, 30) + "." + g.r.str(gateBase64URL, 40) + "." + g.r.str(gateBase64URL, 30)
}
func (g gateSecrets) pw(n int) string { return g.r.str(gateConsonantsDigits, n) }
func (g gateSecrets) dotted() string  { return "7." + g.r.str(gateConsonantsDigits, 10) }
func (g gateSecrets) integrity() string {
	return "sha512-" + g.r.str(gateBase64, 86) + "=="
}

var gatePackages = []string{"left-pad", "lodash", "@babel/core", "ansi-styles", "semver", "minimist", "@types/node", "is-number", "debug", "ms"}

// benignMembers are the manifest members the veto exists for, one of each shape it accepts.
func (g gateSecrets) benignMembers() []string {
	p := g.r.pick(gatePackages)
	return []string{
		`"version": "1.3.0"`,
		`"version": "^2.0.1"`,
		`"` + p + `": "~0.4.2"`,
		`"dev": true`,
		`"optional": false`,
		`"resolved": "https://registry.npmjs.org/` + p + `/-/left-pad-1.3.0.tgz"`,
		`"url": "https://github.com/orders/app"`,
		`"url": "git+https://bitbucket.org/orders/app.git"`,
		`"homepage": "https://gitlab.com/orders/app#readme"`,
		`"url": "http://registry.orders.invalid/app"`,
		`"integrity": "` + g.integrity() + `"`,
		`"checksum": "sha256-` + g.r.str(gateBase64, 43) + `="`,
	}
}

// plantedLine is a benign member and a secret on one line, in one of #765's four positions: before
// the member, after it, inside its value, or as its key. The veto must not hide any of them.
func (g gateSecrets) plantedLine() string {
	member := g.r.pick(g.benignMembers())
	var secretMember, secretText string
	switch g.r.intn(8) {
	case 0:
		secretText = g.akia()
		secretMember = `"key_id": "` + secretText + `"`
	case 1:
		secretText = g.ghp()
		secretMember = `"token": "` + secretText + `"`
	case 2:
		secretText = g.glpat()
		secretMember = `"ci": "` + secretText + `"`
	case 3:
		secretText = g.xoxb()
		secretMember = `"bot": "` + secretText + `"`
	case 4:
		secretText = g.jwt()
		secretMember = `"auth": "Bearer ` + secretText + `"`
	case 5:
		secretText = `password: "` + g.pw(16) + `"`
		secretMember = `"password": "` + g.pw(16) + `"`
	case 6:
		secretText = "token=" + g.pw(16)
		secretMember = `"cmd": "curl -H token=` + g.pw(16) + `"`
	default:
		secretText = `api_key: "` + g.dotted() + `"`
		secretMember = `"api_key": "` + g.dotted() + `"`
	}
	indent := strings.Repeat(" ", g.r.intn(8))
	switch g.r.intn(4) {
	case 0: // before
		return indent + "{" + secretMember + ", " + member + "}"
	case 1: // after
		return indent + member + ", " + secretMember
	case 2: // inside the value
		if strings.HasSuffix(member, `"`) {
			return indent + member[:len(member)-1] + " " + secretText + `",`
		}
		return indent + member + " " + secretText + ","
	default: // as the key
		_, value, _ := strings.Cut(member, ": ")
		return indent + `"` + secretText + `": ` + value + ","
	}
}

// gateStemMaterial is text that spells a keyword stem in a slot a benign shape allows.
var gateStemMaterial = []string{"token", "TOKEN", "js-tokens", "secret", "password", "Passwd", "pwd", "session", "jwt", "oauth", "bearer", "credential", "api_key", "apikey", "access_token", "db_key", "client-key", "private_key"}

// inShapeLine is a line of one of the veto's own shapes with chosen material in one of its slots:
// the key, a version's suffix, a URL's host (with or without a port), path or fragment, or an SRI
// digest's body. Some material is a stem, some a provider literal or JWT marker, some neither.
func (g gateSecrets) inShapeLine() string {
	material := func(class string) string {
		switch g.r.intn(4) {
		case 0:
			return g.r.pick(gateStemMaterial)
		case 1:
			switch g.r.intn(3) {
			case 0:
				return g.akia()
			case 1:
				return g.ghp()
			default:
				return "eyJ" + g.r.str(gateBase64URL[:62], 12)
			}
		default:
			return g.r.str(class, 4+g.r.intn(12))
		}
	}
	alnum := "abcdefghijklmnopqrstuvwxyz0123456789"
	stemOrMaterial := func() string {
		if g.r.intn(2) == 0 {
			return g.r.pick(gateStemMaterial)
		}
		return material(alnum)
	}
	port := ""
	if g.r.intn(2) == 0 {
		port = ":" + strconv.Itoa(1000+g.r.intn(9000))
	}
	host := g.r.pick([]string{"github.com", "gitlab.com", "bitbucket.org", "registry.npmjs.org", "registry.orders.invalid"})
	indent := strings.Repeat(" ", g.r.intn(8))
	var line string
	switch g.r.intn(7) {
	case 0: // the key
		key := strings.ReplaceAll(stemOrMaterial(), "_", "-")
		line = `"` + key + `": "` + g.r.pick([]string{"1.2.3", "^4.0.0", "7.1234567890"}) + `"`
		if g.r.intn(2) == 0 {
			key = stemOrMaterial()
			line = `"` + key + `": true`
		}
	case 1: // a version's suffix
		line = `"` + g.r.pick([]string{"version", "password", "token", "api_key", "left-pad"}) + `": "1.2.3-` + strings.ReplaceAll(stemOrMaterial(), "_", ".") + `"`
	case 2: // a URL's host, the stem at its end and optionally a port
		line = `"url": "https://api.` + stemOrMaterial() + port + `/` + host + `/x"`
	case 3: // a URL's host before a forge host
		line = `"homepage": "https://` + strings.ReplaceAll(stemOrMaterial(), "_", "-") + `.` + host + port + `/orders/app"`
	case 4: // a URL's path
		line = `"resolved": "https://` + host + port + `/` + stemOrMaterial() + `/-/x-1.0.0.tgz"`
	case 5: // a URL's fragment
		line = `"url": "git+https://` + host + `/orders/app.git#` + strings.ReplaceAll(stemOrMaterial(), "_", "-") + `"`
	default: // an SRI digest's body
		body := g.r.str(gateBase64, 30) + strings.ReplaceAll(stemOrMaterial(), "_", "/") + g.r.str(gateBase64, 30)
		line = `"` + g.r.pick([]string{"integrity", "checksum"}) + `": "sha512-` + body + `=="`
	}
	if g.r.intn(2) == 0 {
		line += ","
	}
	return indent + line
}

// soundnessLines is how many lines per population TestLineGateIsSound draws. A few thousand cover
// every slot, shape and position many times over (the keyword pass costs about 0.25 ms a line, so
// this is what keeps the test near a second); LINE_GATE_SOUNDNESS_N raises it for a census.
func soundnessLines(t *testing.T) int {
	if s := os.Getenv("LINE_GATE_SOUNDNESS_N"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n <= 0 {
			t.Fatalf("LINE_GATE_SOUNDNESS_N=%q", s)
		}
		return n
	}
	if raceEnabled || testing.Short() {
		return 1500
	}
	return 5000
}

// TestLineGateIsSound is the gate's contract: a line containsSecretIndicators rejects has no
// keyword-pass candidate. Three seeded populations, the first two as #765 specifies:
//
//   - planted: a benign manifest member and a secret on one line, the secret before or after the
//     member, inside its value, or as its key. Before #765 the three whole-line checks rejected
//     three quarters of these, every one with a candidate the keyword pass would have reported.
//   - in-shape: a line of one of the veto's own shapes with secret material, a keyword stem or
//     neither in each slot the shape allows. This is the population a narrower veto can still get
//     wrong: a stem in the key, or a host ending in a stem with a port after it, makes the keyword
//     pass read an assignment, and the veto must let those lines through.
//   - short assignment (#815): a stem assigned an 8- to 11-byte value, mostly under 20 bytes, where
//     the generic fall-through cannot admit a line and only an admit for the stem can. Before #815
//     every `session` line under 20 bytes here was rejected with a candidate.
//
// All three also carry a floor that keeps the test from passing vacuously: most planted and short
// lines must have a candidate, and the veto must still reject a share of the in-shape lines.
func TestLineGateIsSound(t *testing.T) {
	v := NewValidator()
	n := soundnessLines(t)
	populations := []struct {
		name string
		seed uint64
		gen  func(gateSecrets) string
		// minWithCandidate is the floor on lines with a candidate; minRejected on rejected lines.
		minWithCandidate, minRejected float64
	}{
		{"planted", 765001, gateSecrets.plantedLine, 0.90, 0},
		{"in-shape", 765002, gateSecrets.inShapeLine, 0.10, 0.10},
		{"short assignment", 815001, gateSecrets.shortAssignmentLine, 0.90, 0},
	}
	for _, p := range populations {
		t.Run(p.name, func(t *testing.T) {
			g := gateSecrets{r: &gateRand{x: p.seed}}
			rejected, withCandidate, unsound := 0, 0, 0
			for i := 0; i < n; i++ {
				line := p.gen(g)
				cands := v.keywordCandidates(line)
				if len(cands) > 0 {
					withCandidate++
				}
				if v.containsSecretIndicators(line) {
					continue
				}
				rejected++
				if len(cands) > 0 {
					unsound++
					if unsound <= 5 {
						t.Errorf("rejected a line with keyword candidate %q: %s", cands[0].text, line)
					}
				}
			}
			t.Logf("%s: %d lines, %d with a keyword candidate, %d rejected, %d rejected with a candidate", p.name, n, withCandidate, rejected, unsound)
			if unsound > 0 {
				t.Errorf("%d of %d rejected lines hold a keyword candidate", unsound, rejected)
			}
			if got := float64(withCandidate) / float64(n); got < p.minWithCandidate {
				t.Errorf("only %.1f%% of lines hold a candidate, want >= %.0f%%: the population no longer tests anything", 100*got, 100*p.minWithCandidate)
			}
			if got := float64(rejected) / float64(n); got < p.minRejected {
				t.Errorf("the veto rejects only %.1f%% of in-shape lines, want >= %.0f%%: it no longer fires on its own shapes", 100*got, 100*p.minRejected)
			}
		})
	}
}

// generatedLockfile renders a deterministic npm v3 package-lock.json with the members real ones
// carry: version, resolved, integrity, flags, dependency ranges, engines, funding URLs and license.
// The rates of the shapes the veto lets through by design are those of the 39 public lockfiles the
// #765 PR measured (25,928 packages): a package name that spells a keyword stem (js-tokens) 0.4%,
// a dependency range that is not one version (`^3.0.0 || ^4.0.0`) 1.4%, a funding URL with a query
// (`?sponsor=1`) 10% of 0.27 per package.
func generatedLockfile(packages int) string {
	r := &gateRand{x: 765003}
	names := []string{"left-pad", "ansi-styles", "semver", "minimist", "is-number", "debug", "ms", "chalk",
		"@babel/core", "@babel/parser", "@types/node", "picomatch", "glob", "yargs", "ws", "acorn",
		"safe-buffer", "inherits", "once", "wrappy", "uuid", "mime-types", "supports-color", "has-flag"}
	ranges := []string{"^1.2.3", "~2.0.1", "^0.4.0", "3.1.4", "^10.0.0", ">=1.0.0", "*", "^7.22.5"}
	pickName := func() string {
		if r.intn(250) == 0 {
			return "js-tokens"
		}
		return names[r.intn(len(names))]
	}
	pickRange := func() string {
		if r.intn(70) == 0 {
			return "^3.0.0 || ^4.0.0"
		}
		return ranges[r.intn(len(ranges))]
	}
	var b strings.Builder
	b.WriteString("{\n  \"name\": \"orders-app\",\n  \"version\": \"1.0.0\",\n  \"lockfileVersion\": 3,\n  \"requires\": true,\n  \"packages\": {\n")
	for i := 0; i < packages; i++ {
		name := pickName()
		if r.intn(3) > 0 {
			name += "-" + r.str("abcdefghijklmnopqrstuvwxyz", 3+r.intn(5))
		}
		ver := strconv.Itoa(r.intn(12)) + "." + strconv.Itoa(r.intn(30)) + "." + strconv.Itoa(r.intn(20))
		base := name
		if j := strings.LastIndex(name, "/"); j >= 0 {
			base = name[j+1:]
		}
		b.WriteString("    \"node_modules/" + name + "\": {\n")
		b.WriteString("      \"version\": \"" + ver + "\",\n")
		b.WriteString("      \"resolved\": \"https://registry.npmjs.org/" + name + "/-/" + base + "-" + ver + ".tgz\",\n")
		b.WriteString("      \"integrity\": \"sha512-" + r.str(gateBase64, 86) + "==\",\n")
		switch r.intn(4) {
		case 0, 1:
			b.WriteString("      \"dev\": true,\n")
		case 2:
			b.WriteString("      \"optional\": true,\n")
		}
		if deps := r.intn(4); deps > 0 {
			b.WriteString("      \"dependencies\": {\n")
			for d := 0; d < deps; d++ {
				sep := ","
				if d == deps-1 {
					sep = ""
				}
				b.WriteString("        \"" + pickName() + "\": \"" + pickRange() + "\"" + sep + "\n")
			}
			b.WriteString("      },\n")
		}
		if r.intn(4) == 0 {
			b.WriteString("      \"engines\": {\n        \"node\": \">=" + strconv.Itoa(8+r.intn(12)) + "\"\n      },\n")
		}
		if r.intn(4) == 0 {
			q := ""
			if r.intn(10) == 0 {
				q = "?sponsor=1"
			}
			b.WriteString("      \"funding\": {\n        \"url\": \"https://github.com/sponsors/" + base + q + "\"\n      },\n")
		}
		b.WriteString("      \"license\": \"MIT\"\n    },\n")
	}
	b.WriteString("    \"node_modules/zz\": {\n      \"version\": \"0.0.1\"\n    }\n  }\n}\n")
	return b.String()
}

// TestLineGateCoverageFloor is the veto's non-vacuity floor, as a count and not a clock: on a
// generated npm v3 lockfile it still rejects at least 95% of the lines the three checks it replaced
// rejected. Below that the CPU those lines cost comes back (deleting the veto outright measured
// 2.2-2.7x of SECRETS CPU on lockfiles). The misses are by design: a query (`?sponsor=1`), a range
// that is not one version (`^3.0.0 || ^4.0.0`), a stem in a package name, a JWT marker or stem that
// a digest's random body happens to spell.
func TestLineGateCoverageFloor(t *testing.T) {
	v := NewValidator()
	legacyRejected, rejected := 0, 0
	for _, line := range strings.Split(generatedLockfile(2000), "\n") {
		trimmed := strings.TrimSpace(line)
		if len(line) < 12 || len(trimmed) <= 2 || !legacyManifestVeto(trimmed) {
			continue
		}
		legacyRejected++
		if !v.containsSecretIndicators(line) {
			rejected++
		}
	}
	share := float64(rejected) / float64(legacyRejected)
	t.Logf("the veto rejects %d of the %d lines the replaced checks rejected (%.2f%%)", rejected, legacyRejected, 100*share)
	if legacyRejected < 5000 {
		t.Fatalf("the generated lockfile has only %d lines the replaced checks reject; the floor measures nothing", legacyRejected)
	}
	if share < 0.95 {
		t.Errorf("the veto rejects %.2f%% of what the replaced checks rejected, want >= 95%%", 100*share)
	}
}

// TestLineGateArmOrder is the derived guard on the class #765 is about: whole-line rejections in
// front of the keyword pass. It parses containsSecretIndicators and enumerates every `return false`
// in it; each must be one of the arms listed below, with its reason, and in its place relative to
// the provider-literal admits. A new whole-line veto fails here until it is listed, which is the
// point: such a veto has to be shown to reject only lines without a candidate (TestLineGateIsSound)
// before it may run. It also pins that the gate has one caller and that the URI user-info source
// (#766) does not depend on it.
func TestLineGateArmOrder(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "validator.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := findFunc(file, "containsSecretIndicators")
	if fn == nil {
		t.Fatal("containsSecretIndicators not found in validator.go")
	}
	render := func(n ast.Node) string {
		var b strings.Builder
		_ = printer.Fprint(&b, fset, n)
		return strings.Join(strings.Fields(b.String()), " ")
	}

	type site struct {
		pos  token.Pos
		cond string // the innermost enclosing if-condition, "" for none
		val  string
	}
	var sites []site
	var stack []*ast.IfStmt
	var walk func(n ast.Node)
	walk = func(n ast.Node) {
		ast.Inspect(n, func(c ast.Node) bool {
			switch x := c.(type) {
			case *ast.IfStmt:
				if x == n {
					return true
				}
				stack = append(stack, x)
				walk(x)
				stack = stack[:len(stack)-1]
				return false
			case *ast.ReturnStmt:
				if len(x.Results) == 1 {
					cond := ""
					if len(stack) > 0 {
						cond = render(stack[len(stack)-1].Cond)
					}
					sites = append(sites, site{x.Pos(), cond, render(x.Results[0])})
				}
			}
			return true
		})
	}
	walk(fn.Body)

	// The provider-literal admits: each a `return true` under its own condition.
	admits := map[string]string{
		`strings.Contains(line, "eyJ")`:       "a JWT marker",
		`lineHasProviderPrefix(line)`:         "a provider prefix from the grammar table",
		`strings.Contains(line, beginMarker)`: "a PEM marker",
	}
	firstAdmit, lastAdmit := token.NoPos, token.NoPos
	for _, s := range sites {
		if _, ok := admits[s.cond]; ok && s.val == "true" {
			if firstAdmit == token.NoPos {
				firstAdmit = s.pos
			}
			lastAdmit = s.pos
			delete(admits, s.cond)
		}
	}
	for cond, what := range admits {
		t.Errorf("the provider-literal admit for %s (`if %s { return true }`) is missing", what, cond)
	}

	// Every `return false`, with the reason it is allowed and where.
	before, after := "before every provider-literal admit", "after every provider-literal admit"
	allowed := map[string]struct{ reason, where string }{
		`len(line) < 12`: {"no secret fits in eleven bytes", before},
		`trimmed == "{" || trimmed == "}" || trimmed == "[" || trimmed == "]" || trimmed == "{}" || trimmed == "[]" || trimmed == "," || trimmed == "-"`: {"a structural token alone", before},
		`benignManifestLine(trimmed)`: {"the one veto: wholly one benign manifest member, no keyword stem", after},
		``:                            {"no admit fired", after},
	}
	for _, s := range sites {
		if s.val != "false" {
			continue
		}
		a, ok := allowed[s.cond]
		if !ok {
			t.Errorf("%s: containsSecretIndicators returns false under `%s`, which is not a listed arm. A whole-line rejection "+
				"must reject only lines with no keyword candidate (#765); list it here with its reason once TestLineGateIsSound covers it",
				fset.Position(s.pos), s.cond)
			continue
		}
		if a.where == before && s.pos > firstAdmit || a.where == after && s.pos < lastAdmit {
			t.Errorf("%s: the arm `%s` (%s) must run %s", fset.Position(s.pos), s.cond, a.reason, a.where)
		}
		delete(allowed, s.cond)
	}
	for cond, a := range allowed {
		t.Errorf("the arm `%s` (%s) is no longer in containsSecretIndicators; update this guard", cond, a.reason)
	}

	// One caller, and the URI user-info source does not depend on the gate.
	callers := map[string]bool{}
	paths, _ := filepath.Glob("*.go")
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok {
					switch sel.Sel.Name {
					case "containsSecretIndicators":
						callers[path+":"+fd.Name.Name] = true
					case "findKeywordSecrets", "keywordCandidates":
						if path == "uri_userinfo.go" {
							t.Errorf("uri_userinfo.go:%s calls %s; the URI user-info source must not depend on the line gate", fd.Name.Name, sel.Sel.Name)
						}
					}
				}
				return true
			})
		}
	}
	if len(callers) != 1 || !callers["validator.go:findKeywordSecrets"] {
		t.Errorf("containsSecretIndicators is called from %v, want only validator.go:findKeywordSecrets", callers)
	}
}

func findFunc(f *ast.File, name string) *ast.FuncDecl {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == name {
			return fd
		}
	}
	return nil
}

// TestKeywordStemCoversEveryPattern is the derived guard behind the veto's stem check: every pattern
// of the keyword pass is anchored on something the gate looks at before it may reject. A provider,
// JWT or PEM pattern is anchored on a literal admitted before the veto; every other pattern must be
// built from a stem keywordStem is built from. A pattern with a new anchor fails here, and so does
// a new candidate source in keywordCandidates, until it is listed with the reason it is covered.
func TestKeywordStemCoversEveryPattern(t *testing.T) {
	v := NewValidator()
	exactProvider := map[string]string{}
	for _, r := range providerRules {
		if r.Mode == modeExact {
			for _, p := range r.Prefixes {
				exactProvider[r.pattern(p)] = r.Type
			}
		}
	}
	stems := keywordPassStems()
	sets := []struct {
		name string
		res  []*regexp.Regexp
	}{
		{"keywordPatterns", v.keywordPatterns},
		{"unquotedPatterns", v.unquotedPatterns},
		{"pluralQuotedPatterns", v.pluralQuotedPatterns},
		{"pluralUnquotedPatterns", v.pluralUnquotedPatterns},
		{"listOpenerPatterns", v.listOpenerPatterns},
	}
	for _, set := range sets {
		for _, re := range set.res {
			src := re.String()
			switch {
			case exactProvider[src] != "":
				continue // admitted by lineHasProviderPrefix
			case strings.HasPrefix(src, "eyJ"):
				continue // admitted by the JWT marker
			case strings.HasPrefix(src, "-----"+"BEGIN"):
				continue // admitted by the PEM marker
			}
			covered := false
			for _, s := range stems {
				if strings.Contains(src, s) {
					covered = true
					break
				}
			}
			if !covered {
				t.Errorf("%s pattern %q is anchored on nothing keywordStem matches and nothing the gate admits first", set.name, src)
			}
		}
	}

	// The anchors exempted above are admitted even on a line the veto would otherwise reject.
	vetoed := `      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",`
	if v.containsSecretIndicators(vetoed) {
		t.Fatal("precondition: the plain lockfile line is no longer vetoed")
	}
	anchors := append([]string{"eyJ", "-----" + "BEGIN"}, allProviderPrefixes...)
	for _, a := range anchors {
		line := `      "resolved": "https://registry.npmjs.org/` + a + `/-/left-pad-1.3.0.tgz",`
		if !v.containsSecretIndicators(line) {
			t.Errorf("a lockfile line carrying %q is rejected; the admit for it must run before the veto", a)
		}
	}

	// The candidate sources keywordCandidates draws on. Each is a pattern set checked above, or a
	// helper that filters or splits what one of them found.
	known := map[string]string{
		"findProviderRuns":           "modeAtLeast provider runs, admitted by lineHasProviderPrefix",
		"keywordPatterns":            "checked above",
		"unquotedPatterns":           "checked above",
		"pluralQuotedPatterns":       "checked above",
		"pluralUnquotedPatterns":     "checked above",
		"findCollectionSecrets":      "anchored on listOpenerPatterns, checked above",
		"findListTailSecrets":        "anchored on unquotedPatterns, checked above",
		"plausibleUnquotedSecret":    "a filter",
		"isQueryKeyByte":             "a filter",
		"queryParamSeparator":        "splits an unquoted match",
		"appendValue":                "a closure applying plausibleUnquotedSecret to one split segment",
		"FindAllStringSubmatchIndex": "regexp method",
		"FindAllStringIndex":         "regexp method",
		"FindStringSubmatchIndex":    "regexp method",
		"IndexByte":                  "strings",
		"append":                     "builtin",
		"len":                        "builtin",
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "validator.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	fn := findFunc(file, "keywordCandidates")
	if fn == nil {
		t.Fatal("keywordCandidates not found in validator.go")
	}
	seen := map[string]bool{}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			switch f := x.Fun.(type) {
			case *ast.Ident:
				seen[f.Name] = true
			case *ast.SelectorExpr:
				seen[f.Sel.Name] = true
			}
		case *ast.SelectorExpr:
			if id, ok := x.X.(*ast.Ident); ok && id.Name == "v" {
				seen[x.Sel.Name] = true
			}
		}
		return true
	})
	var unknown []string
	for name := range seen {
		if _, ok := known[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(unknown)
	for _, name := range unknown {
		t.Errorf("keywordCandidates uses %s, which this guard does not know: show that its candidates are anchored on a stem or an admitted literal, then list it", name)
	}
}

// TestLineHasKeywordStemIsTheRegexp pins that the fast path and keywordStem agree, on every line
// the other tests here generate, on case variants, and on the non-ASCII folds (?i) honours.
func TestLineHasKeywordStemIsTheRegexp(t *testing.T) {
	var lines []string
	g := gateSecrets{r: &gateRand{x: 765004}}
	for i := 0; i < 2000; i++ {
		lines = append(lines, g.plantedLine(), g.inShapeLine())
	}
	lines = append(lines, strings.Split(generatedLockfile(200), "\n")...)
	lines = append(lines,
		"", "a", "TOKEN", "ToKeN", "api-key", "API_KEY", "apikey", "ap_ikey", "db_key", "dbkey", "db__key",
		"\u017fecret", "pa\u017f\u017fword", "api_\u212aey", "secre\u0074", "caf\u00e9 token", "caf\u00e9 tokn",
		strings.Repeat("x", 300)+"jwt", strings.Repeat("x", 300)+"jw t",
	)
	for _, l := range lines {
		if got, want := lineHasKeywordStem(l), keywordStem.MatchString(l); got != want {
			t.Errorf("lineHasKeywordStem(%q) = %v, keywordStem.MatchString = %v", l, got, want)
		}
	}
	// The folds are real: the patterns read U+017F as s, so the gate must as well.
	if !keywordStem.MatchString("\u017fecret") || !lineHasKeywordStem("pa\u017f\u017fword") {
		t.Error("keywordStem no longer folds U+017F to s; the fast path's ASCII argument needs re-checking")
	}
}

// vetoPairs are #765's nine trigger files, each with the control that differs from it in one key,
// host or word, plus the npm lockfile decoy the replaced checks existed for.
func vetoPairs(g gateSecrets) (pairs [][3]string, roles map[string]string, decoy string) {
	pw, pw40, ak, gh, dot, xb := g.pw(16), g.pw(40), g.akia(), g.ghp(), g.dotted(), g.xoxb()
	roles = map[string]string{ak: "key_id", gh: "ghp", xb: "xoxb", dot: "dotpw", pw40: "pw40", pw: "pw"}
	pairs = [][3]string{
		{"v3_json.json",
			`{"url": "https://github.com/orders/app", "password": "` + pw + `", "key_id": "` + ak + `"}`,
			`{"repo": "https://github.com/orders/app", "password": "` + pw + `", "key_id": "` + ak + `"}`},
		{"v3_reqlog.log",
			`{"ts":"2026-01-01T00:00:00Z","method":"GET","url":"https://api.github.com/user","headers":{"Authorization":"token ` + gh + `"}}`,
			`{"ts":"2026-01-01T00:00:00Z","method":"GET","path":"https://api.github.com/user","headers":{"Authorization":"token ` + gh + `"}}`},
		{"v3_package.json",
			"{\n  \"repository\": {\n    \"url\": \"git+https://x-access-token:" + gh + "@github.com/orders/app.git\"\n  }\n}",
			"{\n  \"repository\": {\n    \"link\": \"git+https://x-access-token:" + gh + "@github.com/orders/app.git\"\n  }\n}"},
		{"v3_minified.json",
			`{"name":"svc","version":"0.0.1","homepage":"https://github.com/orders/svc","db":{"host":"db.invalid","password":"` + pw + `"},"slack":{"bot_token":"` + xb + `"}}`,
			`{"name":"svc","version":"0.0.1","site":"https://github.com/orders/svc","db":{"host":"db.invalid","password":"` + pw + `"},"slack":{"bot_token":"` + xb + `"}}`},
		{"v3_partial.json",
			`{"url": "https://github.com/orders/app", "password": "` + pw40 + `", "key_id": "` + ak + `"}`,
			`{"repo": "https://github.com/orders/app", "password": "` + pw40 + `", "key_id": "` + ak + `"}`},
		{"v2_checksum.json",
			`{"bucket":"shared-assets","checksum":"crc32:00000000","password":"` + pw + `","key_id":"` + ak + `"}`,
			`{"bucket":"public-assets","checksum":"crc32:00000000","password":"` + pw + `","key_id":"` + ak + `"}`},
		{"v1_trailing.sh",
			`export API_TOKEN=` + pw + ` # "verbose": true`,
			`export API_TOKEN=` + pw + ` # "verbose": yes`},
		{"v1_keyed.json",
			"{\n  \"allowed\": {\n    \"" + ak + "\": true\n  }\n}",
			"{\n  \"allowed\": {\n    \"" + ak + "\": \"on\"\n  }\n}"},
		{"v1_value.json",
			"{\n  \"password\": \"" + dot + "\"\n}",
			"{\n  \"password\": \"x" + dot + "\"\n}"},
	}
	decoy = "{\n  \"packages\": {\n    \"node_modules/left-pad\": {\n      \"version\": \"1.3.0\",\n" +
		"      \"resolved\": \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\",\n" +
		"      \"integrity\": \"sha512-" + g.r.str(gateBase64, 86) + "==\",\n      \"dev\": true\n    }\n  }\n}"
	return pairs, roles, decoy
}

// TestLineVetoTriggersMatchControls is #765's acceptance row through the validator: each trigger
// reports what its control reports -- the same types over the same values -- and the lockfile decoy
// reports nothing. Before the fix eight of the nine reported nothing, and the ninth (the token in
// URI user info) only what #766's source finds outside the gate.
func TestLineVetoTriggersMatchControls(t *testing.T) {
	v := NewValidator()
	for seed := uint64(1); seed <= 3; seed++ {
		pairs, roles, decoy := vetoPairs(gateSecrets{r: &gateRand{x: 765100 + seed}})
		label := func(text string) string {
			for _, k := range []string{"key_id", "ghp", "xoxb", "dotpw", "pw40", "pw"} {
				for val, role := range roles {
					if role == k && strings.Contains(text, val) {
						return role
					}
				}
			}
			return "other"
		}
		report := func(t *testing.T, content, path string) []string {
			t.Helper()
			ms, err := v.ValidateContent(content+"\n", path)
			if err != nil {
				t.Fatal(err)
			}
			var out []string
			for _, m := range ms {
				out = append(out, m.Type+":"+label(m.Text))
			}
			sort.Strings(out)
			return out
		}
		for _, p := range pairs {
			t.Run(p[0]+"/seed"+strconv.Itoa(int(seed)), func(t *testing.T) {
				got, want := report(t, p[1], p[0]), report(t, p[2], strings.Replace(p[0], ".", "_ctl.", 1))
				if len(want) == 0 {
					t.Fatalf("the control reports nothing; the pair tests nothing")
				}
				if strings.Join(got, " ") != strings.Join(want, " ") {
					t.Errorf("trigger reports %v, its control %v", got, want)
				}
			})
		}
		if got := report(t, decoy, "decoy_lock.json"); len(got) != 0 {
			t.Errorf("seed %d: the lockfile decoy reports %v, want nothing", seed, got)
		}
	}
}
