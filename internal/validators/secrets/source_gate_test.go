// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	stdctx "context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// The #753 lexical gate, end to end through ValidateContent with no confidence filter.
//
// THE ORACLE. Every comparison here is between the SAME content and the SAME path scanned twice:
// once through ValidateContent (the gate derives its grammar from the path, as in production) and
// once through validateContentCtx with langNone, which is the identical code with the gate removed.
// Context analysis reads the path, so a comparison against a different path would conflate the
// gate with a confidence change; this one cannot. "Behaves exactly as today" therefore means
// "identical finding set, line, text and confidence", and "the gate only drops" means "the gated set
// is a subset of the ungated one" -- both asserted on every case.
//
// NON-VACUITY. Every case that asserts something is KEPT also carries a code-position line that
// must be DROPPED in the same file. A test of preserved findings alone passes with the gate deleted,
// and passes with the gate failing open on that file; the dropped control is what makes each one
// fail when the fix is reverted.

// synth returns a distinct credential-shaped synthetic value, assembled at runtime so that no
// token-shaped literal sits in this file. 17 bytes, under the 20-byte floor of the entropy path, so
// only the keyword paths can find it -- which is what makes a dropped keyword candidate visible.
func synth(i int) string {
	return buildTestToken("Xk9mQ2", "vL7pR4", string(rune('A'+i%26)), string(rune('a'+(i*7)%26)), "tW8zN")
}

// synthLong is a value the entropy path finds on its own when quoted (28 bytes, base64 alphabet).
func synthLong(i int) string {
	return buildTestToken("Hq7Zp2", "Lm9Xw4", string(rune('A'+i%26)), "Rt6Vb1", "Nc8Ks3", "Jd5Fg0")
}

// synthHex is a numeric hex literal, the shape isLiteralToken keeps in code position.
func synthHex() string { return buildTestToken("0x", "9f3c2a7b", "e41d5c08") }

type finding struct {
	line int
	text string
	conf float64
	typ  string
}

func (f finding) String() string {
	return fmt.Sprintf("line %d %s %q @ %.1f", f.line, f.typ, f.text, f.conf)
}

func findingsOf(ms []detector.Match) []finding {
	out := make([]finding, 0, len(ms))
	for _, m := range ms {
		out = append(out, finding{line: m.LineNumber, text: m.Text, conf: m.Confidence, typ: m.Type})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].line != out[j].line {
			return out[i].line < out[j].line
		}
		if out[i].text != out[j].text {
			return out[i].text < out[j].text
		}
		return out[i].conf < out[j].conf
	})
	return out
}

// scanBoth returns the gated and the ungated findings for content at path.
func scanBoth(t *testing.T, content, path string) (gated, ungated []finding) {
	t.Helper()
	v := NewValidator()
	g, err := v.ValidateContent(content, path)
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	u, err := v.validateContentCtx(stdctx.Background(), content, path, langNone)
	if err != nil {
		t.Fatalf("validateContentCtx: %v", err)
	}
	return findingsOf(g), findingsOf(u)
}

// subtract returns the findings of a that are not in b (multiset difference).
func subtract(a, b []finding) []finding {
	left := map[finding]int{}
	for _, f := range b {
		left[f]++
	}
	var out []finding
	for _, f := range a {
		if left[f] > 0 {
			left[f]--
			continue
		}
		out = append(out, f)
	}
	return out
}

func withText(fs []finding, sub string) []finding {
	var out []finding
	for _, f := range fs {
		if strings.Contains(f.text, sub) {
			out = append(out, f)
		}
	}
	return out
}

// gateCase is one file: values that must be KEPT at the ungated confidence, and values that must
// be reported ungated and DROPPED gated. Anything the gate removes that is not listed in drop is a
// failure, so a case also proves the gate removed nothing else.
type gateCase struct {
	name    string
	path    string
	content string
	keep    []string
	drop    []string
}

func checkGateCase(t *testing.T, tc gateCase) {
	t.Helper()
	gated, ungated := scanBoth(t, tc.content, tc.path)
	if added := subtract(gated, ungated); len(added) > 0 {
		t.Errorf("the gate ADDED findings -- it may only drop:\n  %v", added)
	}
	removed := subtract(ungated, gated)
	for _, k := range tc.keep {
		u := withText(ungated, k)
		if len(u) == 0 {
			t.Errorf("fixture is vacuous: %q is not reported even without the gate\nungated: %v", k, ungated)
			continue
		}
		if r := withText(removed, k); len(r) > 0 {
			t.Errorf("literal-context value %q was dropped or changed by the gate: %v\ngated: %v", k, r, gated)
		}
	}
	for _, d := range tc.drop {
		if len(withText(ungated, d)) == 0 {
			t.Errorf("fixture is vacuous: code-position value %q is not reported even without the gate\n"+
				"ungated: %v", d, ungated)
			continue
		}
		if g := withText(gated, d); len(g) > 0 {
			t.Errorf("code-position value %q still reported in %s: %v", d, tc.path, g)
		}
	}
	for _, r := range removed {
		expected := false
		for _, d := range tc.drop {
			if strings.Contains(r.text, d) {
				expected = true
			}
		}
		if !expected {
			t.Errorf("the gate removed a finding the case does not expect: %v", r)
		}
	}
}

// probeShapes are the 24 everyday code lines of the #753 probe, each in the grammar it is
// syntactically sensible in: Java and C# read as TS, Ruby as Python. On v2.5.3 17 of them reported.
var probeShapes = []struct{ ext, line string }{
	{".py", "session = get_session()"},
	{".py", `token = request.headers.get("Authorization")`},
	{".py", `password = os.environ["DB_PASSWORD"]`},
	{".py", `api_key = os.getenv("API_KEY")`},
	{".py", "self.token = token_value"},
	{".py", "secret = config.secret_key"},
	{".py", "token = jwt.encode(payload, key)"},
	{".py", "session: Optional[Session] = None"},
	{".py", "password: SecretStr"},
	{".py", "credential = DefaultAzureCredential()"},
	{".py", "session = boto3.session.Session()"},
	{".ts", "token: AuthToken"},
	{".ts", "let token: Promise<AuthToken>;"},
	{".ts", "const session = await getSession();"},
	{".ts", "private readonly tokenService: TokenService"},
	{".ts", "const secret = process.env.JWT_SECRET;"},
	{".ts", "password: this.form.value.password,"},
	{".ts", "token = response.data.accessToken"},
	{".ts", "private String password = getPassword();"},
	{".ts", "String token = tokenProvider.createToken(auth);"},
	{".ts", "var credential = new ClientSecretCredential(tenantId, clientId, secret);"},
	{".go", `token := os.Getenv("TOKEN")`},
	{".go", "Password: cfg.Password,"},
	{".py", "session = Session.find(params[:id])"},
}

// (a) Code expressions produce no finding in a gated file.
func TestSourceGateDropsCodeExpressions(t *testing.T) {
	reportedUngated := 0
	for i, s := range probeShapes {
		t.Run(fmt.Sprintf("probe%02d%s", i+1, s.ext), func(t *testing.T) {
			gated, ungated := scanBoth(t, s.line+"\n", "probe"+s.ext)
			if len(ungated) > 0 {
				reportedUngated++
			}
			for _, f := range gated {
				t.Errorf("%s: code expression reported: %v", s.line, f)
			}
		})
	}
	// 17 of 24 on v2.5.3. Asserted so the probe cannot go vacuous: if the ungated baseline stopped
	// reporting these, the zero above would prove nothing about the gate.
	if reportedUngated != 17 {
		t.Errorf("ungated, %d of %d probe lines report; the #753 probe measured 17 on v2.5.3",
			reportedUngated, len(probeShapes))
	}

	// #753's own shapes and the corpus case's lines, read as the languages they come from, plus
	// composite literals, list tails, the plural key and a block sequence in code position -- every
	// member of the unquoted family.
	cases := []gateCase{
		{name: "753 shapes in Python", path: "models.py", content: "token: AuthToken\n" +
			"password: SecretProvider\nsession: SessionFactory\nsession = get_session()\n" +
			"api_key = loadSecret(ctx)\n",
			drop: []string{"AuthToken", "SecretProvider", "SessionFactory", "get_session()", "loadSecret(ctx)"}},
		{name: "753 shapes in TS", path: "models.ts", content: "token: AuthToken\n" +
			"let token: Promise<AuthToken>;\nsecret: Record<string,string>\napiKey: Observable<string>\n",
			drop: []string{"AuthToken", "Promise<AuthToken>", "Record<string", "Observable<string>"}},
		{name: "python call kwargs and list tail", path: "client.py",
			content: "client = Client(password=settings.DB_PASSWORD, token=auth.token_value)\n" +
				"token = first_token_value, second_token_value\n",
			drop: []string{"settings.DB_PASSWORD", "auth.token_value", "first_token_value", "second_token_value"}},
		{name: "python plural key", path: "store.py", content: "tokens = load_tokens(user_id)\n",
			drop: []string{"load_tokens(user_id)"}},
		{name: "python collection of calls", path: "store.py",
			content: "creds = {\"api_keys\": [load_key(primary), load_key(secondary)]}\n",
			drop:    []string{"load_key(primary"}},
		{name: "ts object literal", path: "client.ts",
			content: "const creds = { password: this.password, token: session.accessToken };\n" +
				"this.client = new Client({ apiKey: config.apiKey, secret: process.env.SECRET });\n",
			drop: []string{"this.password", "config.apiKey", "process.env.SECRET"}},
		{name: "go composite literal", path: "client.go",
			content: "package x\n\nvar c = Config{\n\tPassword: cfg.Password, Token: cfg.AuthToken,\n}\n" +
				"func f() *Creds { return &Creds{Secret: cfg.SecretValue, Token: cfg.TokenValue} }\n",
			drop: []string{"cfg.Password", "cfg.AuthToken", "cfg.SecretValue", "cfg.TokenValue"}},
		{name: "terraform reference", path: "main.tf",
			content: "resource \"aws_db_instance\" \"db\" {\n  password = random_password.db.result\n}\n",
			drop:    []string{"random_password.db.result"}},
		// A JS label followed by a unary-minus expression statement is valid code, and is a YAML
		// block sequence to the sequence path. Kept because it is the only syntactically sensible
		// way to put a sequence item in code position, so the only test of that call site.
		{name: "sequence item in code position", path: "label.js",
			content: "api_keys:\n  - fetchApiKeyValue()\n",
			drop:    []string{"fetchApiKeyValue()"}},
		// A regex holding both quote characters, then an FP. Without regex lexing the quotes
		// desynchronise the string state and the file fails open, so the FP would survive.
		{name: "regex with quotes before an FP", path: "util.ts",
			content: "const q = s.replace(/[\"']/g, '');\nconst secret = process.env.JWT_SECRET;\n",
			drop:    []string{"process.env.JWT_SECRET"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkGateCase(t, tc) })
	}
}

// (b) Literal contexts in source keep reporting, at the same confidence as without the gate. Each
// file also carries a code-position control that must drop, so a gate that failed open on the
// file -- or was removed -- fails here too.
func TestSourceGateKeepsLiteralContexts(t *testing.T) {
	v := make([]string, 16)
	for i := range v {
		v[i] = synth(i)
	}
	long := synthLong(1)
	hex := synthHex()

	cases := []gateCase{
		{name: "python", path: "settings.py", content: strings.Join([]string{
			`DATABASE_URL = "postgresql://app@db:5432/app?sslmode=require&password=` + v[0] + `"`,
			`JDBC = "jdbc:mysql://db:3306/app?user=app&password=` + v[1] + `"`,
			`URL = "https://api.acme.io/v1/items?token=` + v[2] + `"`,
			`x = 1  # password: ` + v[3],
			`def f():`,
			`    """Usage:`,
			``,
			`        export API_TOKEN=` + v[4],
			`    """`,
			`ENV = """`,
			`API_KEY=` + v[5],
			`DB_PASSWORD=` + v[6],
			`"""`,
			`SECRET_KEY = ` + hex,
			`password = os.getenv("DB_PASSWORD", "` + long + `")`,
			`API_KEYS = ["` + v[7] + `", "` + v[8] + `"]`,
			`MSG = "connect with token=` + v[9] + ` \`,
			`and retry"`,
			`session = get_session()`,
		}, "\n") + "\n",
			keep: []string{v[0], v[1], v[2], v[3], v[4], v[5], v[6], hex, long, v[7], v[8], v[9]},
			drop: []string{"get_session()", "os.getenv("}},
		{name: "typescript", path: "settings.ts", content: strings.Join([]string{
			`const conn = "Server=db;User Id=sa;Password=` + v[0] + `;";`,
			`const jdbc = 'jdbc:postgresql://db/app?user=app&password=` + v[1] + `';`,
			"const url = `https://api.acme.io/v1?token=" + v[2] + "`;",
			`const a = 1; // remove before release: secret=` + v[3],
			`/**`,
			` * Usage: api_key=` + v[4],
			` */`,
			"const t = `",
			`export API_TOKEN=` + v[5],
			"`;",
			"const token = `" + v[6] + "`;",
			`const secret_key = ` + hex + `;`,
			`const password = process.env.DB_PASSWORD || "` + long + `";`,
			`const apiKeys = ["` + v[7] + `"];`,
			`const msg = "token=` + v[8] + ` \`,
			`continued";`,
			`const secret = process.env.JWT_SECRET;`,
		}, "\n") + "\n",
			keep: []string{v[0], v[1], v[2], v[3], v[4], v[5], v[6], hex, long, v[7], v[8]},
			drop: []string{"process.env.JWT_SECRET", "process.env.DB_PASSWORD"}},
		{name: "go", path: "settings.go", content: strings.Join([]string{
			`package settings`,
			``,
			`const conn = "postgres://app@db/app?password=` + v[0] + `"`,
			"var cfg = `",
			`password: ` + v[1],
			`token=` + v[2],
			"`",
			`// secret=` + v[3],
			`/* password: ` + v[4] + ` */`,
			`var SecretKey = ` + hex,
			`var c = exec.Command("sh", "-c", "PASSWORD=` + v[5] + ` ./run")`,
			"var token = `" + v[6] + "`",
			`var secret = cfg.SecretValue`,
		}, "\n") + "\n",
			keep: []string{v[0], v[1], v[2], v[3], v[4], hex, v[5], v[6]},
			drop: []string{"cfg.SecretValue"}},
		{name: "terraform", path: "main.tf", content: strings.Join([]string{
			`resource "aws_instance" "web" {`,
			`  password = random_password.db.result`,
			`  user_data = <<-EOF`,
			`    export DB_PASSWORD=` + v[0],
			`  EOF`,
			`  connection = "Server=db;Password=` + v[1] + `;"`,
			`  # token=` + v[2],
			`}`,
		}, "\n") + "\n",
			keep: []string{v[0], v[1], v[2]},
			drop: []string{"random_password.db.result"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { checkGateCase(t, tc) })
	}
}

// (c) A backtick string is a quoted literal in JS/TS (a template without `${`) and in Go (a raw
// string), so every quoted case has a backtick twin that must report identically -- otherwise the
// quote character alone would decide 85 versus 0. A template WITH `${` is an interpolated
// expression and is dropped; in Go the same bytes are a raw string and keep reporting.
func TestSourceGateBacktickTwinsReportLikeQuotes(t *testing.T) {
	templates := []string{
		"token = @",
		"const token = @;",
		"let apiKey = @;",
		"password: @,",
		"const cfg = { secret: @ };",
		"var password = @",
		"Password: @,",
		"const Secret = @",
		"db.connect({ password: @ })",
		"api_key = @",
	}
	val := synthLong(2)
	for _, ext := range []string{".js", ".ts", ".go"} {
		for i, tmpl := range templates {
			t.Run(fmt.Sprintf("%s/%d", ext, i), func(t *testing.T) {
				quoted := strings.ReplaceAll(tmpl, "@", `"`+val+`"`)
				tick := strings.ReplaceAll(tmpl, "@", "`"+val+"`")
				control := "\nsecret = config.secret_value\n"
				qg, _ := scanBoth(t, quoted+control, "twin"+ext)
				checkGateCase(t, gateCase{path: "twin" + ext, content: tick + control,
					keep: []string{val}, drop: []string{"config.secret_value"}})
				bg, _ := scanBoth(t, tick+control, "twin"+ext)
				q, b := withText(qg, val), withText(bg, val)
				if len(q) == 0 {
					t.Fatalf("fixture is vacuous: the quoted twin %q does not report", quoted)
				}
				if len(b) != len(q) || b[0].conf != q[0].conf {
					t.Errorf("backtick twin reports %v, quoted twin %v -- the quote character must "+
						"not decide the confidence", b, q)
				}
			})
		}
	}

	interp := "const token = `${prefix}" + synth(3) + "`;\n"
	for _, ext := range []string{".js", ".ts"} {
		t.Run("interpolated template is code"+ext, func(t *testing.T) {
			checkGateCase(t, gateCase{path: "interp" + ext, content: interp, drop: []string{"${prefix}"}})
		})
	}
	t.Run("the same bytes in a Go raw string are literal", func(t *testing.T) {
		checkGateCase(t, gateCase{path: "interp.go", content: "var token = `${prefix}" + synth(3) + "`\n" +
			"password = os.Getenv(\"DB_PASSWORD\")\n",
			keep: []string{"${prefix}"}, drop: []string{"os.Getenv("}})
	})
}

// (d) Channels the gate does not cover behave exactly as today. Config and prose types, an
// unlisted extension, and every extension-less label. The .ts row is the contrast: the same bytes
// in a gated file drop, which is what makes this fail if the table stops deciding.
func TestSourceGateLeavesUngatedChannelsAlone(t *testing.T) {
	yamlBody := "token: AuthToken\npassword: MixedCaseNoDigits\n"
	envBody := "API_KEY=" + synth(4) + "\nDB_PASSWORD=" + synth(5) + "\n"
	for _, path := range []string{
		"config/settings.yaml", ".env", "<stdin>", "<text>", "clipboard", "<golden:x>", "notes",
		"report.docx", "App.jsx", "App.tsx", ".env.example", "x.ts.txt", "Main.java",
	} {
		for _, body := range []string{yamlBody, envBody} {
			t.Run(path, func(t *testing.T) {
				if lang := sourceLanguageFor(path); lang != langNone {
					t.Fatalf("%q is gated as %s", path, lang)
				}
				gated, ungated := scanBoth(t, body, path)
				if len(ungated) != 2 {
					t.Fatalf("fixture is vacuous: %d ungated findings, want 2: %v", len(ungated), ungated)
				}
				if d := append(subtract(gated, ungated), subtract(ungated, gated)...); len(d) > 0 {
					t.Errorf("an ungated channel changed: %v", d)
				}
			})
		}
	}
	t.Run("contrast: the same YAML bytes in a .ts file", func(t *testing.T) {
		checkGateCase(t, gateCase{path: "settings.ts", content: yamlBody,
			drop: []string{"AuthToken", "MixedCaseNoDigits"}})
	})
}

// (f) Fail-open: a file the lexer cannot vouch for behaves exactly as today, FPs included. Each row
// has a twin with the defect repaired, in which the same FP is dropped -- so these fail both when
// fail-open is removed (the defective file drops the FP) and when the gate is removed (the repaired
// one keeps it).
func TestSourceGateFailsOpen(t *testing.T) {
	cases := []struct {
		name, path, broken, repaired, fp, reason string
	}{
		{"unterminated string", "a.py",
			"x = 'unterminated\nsession = get_session()\n",
			"x = 'terminated'\nsession = get_session()\n", "get_session()", "unterminated single-line string"},
		{"unbalanced template", "a.ts",
			"const secret = process.env.JWT_SECRET;\nconst t = `a ${ b\n",
			"const secret = process.env.JWT_SECRET;\nconst t = `a ${ b }`\n", "process.env.JWT_SECRET",
			"unbalanced interpolation"},
		{"non-code end state", "a.go",
			"password = os.Getenv(\"DB_PASSWORD\")\n/* never closed\n",
			"password = os.Getenv(\"DB_PASSWORD\")\n/* closed */\n", "os.Getenv(", "content ends inside a literal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, reason := newSourceGate(tc.broken, sourceLanguageFor(tc.path)); reason != tc.reason {
				t.Fatalf("fail-open reason %q, want %q", reason, tc.reason)
			}
			gated, ungated := scanBoth(t, tc.broken, tc.path)
			if len(withText(ungated, tc.fp)) == 0 {
				t.Fatalf("fixture is vacuous: %q not reported even without the gate", tc.fp)
			}
			if d := append(subtract(gated, ungated), subtract(ungated, gated)...); len(d) > 0 {
				t.Errorf("a file that fails open must behave exactly as today; differs by %v", d)
			}
			checkGateCase(t, gateCase{path: tc.path, content: tc.repaired, drop: []string{tc.fp}})
		})
	}
}

// The size ceiling is a fail-open condition too. Checked on newSourceGate alone: the decision is
// made before any lexing, so a full scan of 100MB would only time the validator.
func TestSourceGateFailsOpenAboveTheSizeCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates maxLexBytes")
	}
	big := strings.Repeat("x", maxLexBytes+1)
	if g, reason := newSourceGate(big, langJS); g != nil || reason == "" {
		t.Errorf("content of %d bytes was gated; above maxLexBytes the gate must fail open", len(big))
	}
	if g, _ := newSourceGate(big[:1024], langJS); g == nil {
		t.Error("a small file of the same bytes was not gated -- the ceiling test above is vacuous")
	}
}

// (g) THE ACCEPTED LOSS, pinned so it is a decision rather than an accident. A credential pasted
// unquoted in code position is not a string in these languages -- the program would not run -- and
// the gate cannot tell it from an identifier without guessing at the value, which is exactly the
// value-shape veto #753 rejects. If this starts reporting again, the gate has stopped reading the
// grammar.
func TestSourceGateAcceptedLossIsPinned(t *testing.T) {
	for _, path := range []string{"settings.py", "settings.ts", "settings.go"} {
		t.Run(path, func(t *testing.T) {
			checkGateCase(t, gateCase{path: path, content: "API_KEY = " + synth(6) + "\n",
				drop: []string{synth(6)}})
		})
	}
}

// Provider literals are never gated. An AWS key id pasted unquoted in code is matched both by the
// AKIA literal and by the unquoted assignment pattern on the same span; the gate drops only the
// latter, before dedupe, so the AWS_ACCESS_KEY finding survives.
func TestSourceGateNeverDropsProviderLiterals(t *testing.T) {
	key := buildTestToken("AKIA", "Z7QW3XK9", "PL2MN4RT")
	gated, ungated := scanBoth(t, "aws_key = "+key+"\nsession = get_session()\n", "creds.py")
	g, u := withText(gated, key), withText(ungated, key)
	if len(u) == 0 {
		t.Fatalf("fixture is vacuous: %q not reported without the gate", key)
	}
	if len(g) != len(u) || g[0] != u[0] {
		t.Errorf("provider literal changed under the gate: gated %v, ungated %v", g, u)
	}
	if len(withText(gated, "get_session()")) > 0 {
		t.Error("the code-position control still reports; the gate is not active on this file")
	}
}
