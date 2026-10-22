// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/explain"
)

// Tests for the URI user-info source (uri_userinfo.go, #766). Every value is synthetic: consonants
// and digits (no vowel, so no word and no test/example/demo marker can be spelt), hosts under the
// reserved .invalid TLD, and no provider prefix.

// uriPW builds a deterministic synthetic password of n bytes, distinct per seed, with an upper-case
// letter, a digit and a lower-case letter in its first three bytes so plausibleUnquotedSecret
// accepts it at every length the tests use.
func uriPW(seed, n int) string {
	const upper, digits, alpha = "BCDFGHJKLMNPQRSTVWXZ", "23456789", "BCDFGHJKLMNPQRSTVWXZbcdfghjkmnpqrstvwxz23456789"
	x := uint32(seed*2654435761 + 12345)
	next := func(m int) int { x = x*1664525 + 1013904223; return int(x>>8) % m }
	b := make([]byte, n)
	for i := range b {
		switch i {
		case 0:
			b[i] = upper[next(len(upper))]
		case 1:
			b[i] = digits[next(len(digits))]
		case 2:
			b[i] = "bcdfghjkmnpqrstvwxz"[next(19)]
		default:
			b[i] = alpha[next(len(alpha))]
		}
	}
	return string(b)
}

// secretsOn returns every SECRETS finding ValidateContent reports for a one-line input.
func secretsOn(t *testing.T, v *Validator, line, path string) []detector.Match {
	t.Helper()
	ms, err := v.ValidateContent(line+"\n", path)
	if err != nil {
		t.Fatal(err)
	}
	return ms
}

func uriTexts(ms []detector.Match) []string {
	var out []string
	for _, m := range ms {
		if m.Metadata["detection_method"] == uriUserinfoMethod {
			out = append(out, m.Text)
		}
	}
	return out
}

// TestURIUserinfoGrammar pins the authority grammar row by row (#766's design table): scheme,
// terminators, trailing trim, the last-@ split, user-info and host grammar, the empty password and
// the token-shaped user name. It drives findURIUserinfo directly, so it states what the grammar
// accepts independently of scoring.
func TestURIUserinfoGrammar(t *testing.T) {
	pw := uriPW(1, 16)
	tok := uriPW(2, 40)
	cases := []struct {
		name, line string
		want       []string
	}{
		// scheme
		{"plain", "postgres://app_user:" + pw + "@db1.orders.invalid:5432/appdb", []string{pw}},
		{"jdbc yields the inner scheme", "jdbc:mysql://app_user:" + pw + "@db1.orders.invalid:3306/shop", []string{pw}},
		{"scheme with plus", "postgresql+psycopg2://app_user:" + pw + "@db1.orders.invalid/appdb", []string{pw}},
		{"uppercase scheme", "POSTGRES://app_user:" + pw + "@db1.orders.invalid/appdb", []string{pw}},
		{"no scheme", " ://app_user:" + pw + "@db1.orders.invalid/appdb", nil},
		{"scheme without a letter", "42://app_user:" + pw + "@db1.orders.invalid/appdb", nil},
		// terminators
		{"query", "postgres://u:" + pw + "@db1.orders.invalid?sslmode=require", []string{pw}},
		{"fragment", "postgres://u:" + pw + "@db1.orders.invalid#primary", []string{pw}},
		{"single quotes", "broker_url = 'amqp://u:" + pw + "@mq.orders.invalid:5672//'", []string{pw}},
		{"double quotes", `url = "postgres://u:` + pw + `@db1.orders.invalid"`, []string{pw}},
		{"backtick", "run `psql postgresql://u:" + pw + "@db1.orders.invalid/appdb` now", []string{pw}},
		{"angle brackets", "<postgres://u:" + pw + "@db1.orders.invalid>", []string{pw}},
		{"backslash", `"postgres://u:` + pw + `@db1.orders.invalid\n"`, []string{pw}},
		{"tab", "postgres://u:" + pw + "@db1.orders.invalid\tnext", []string{pw}},
		{"trailing comment", "postgres://u:" + pw + "@db1.orders.invalid:5432/appdb # primary", []string{pw}},
		// trailing trim
		{"comma in prose", "use postgres://u:" + pw + "@db1.orders.invalid, then migrate", []string{pw}},
		{"closing paren", "connect(postgres://u:" + pw + "@db1.orders.invalid)", []string{pw}},
		{"full stop", "the URL is postgres://u:" + pw + "@db1.orders.invalid.", []string{pw}},
		{"several", "(see postgres://u:" + pw + "@db1.orders.invalid).", []string{pw}},
		{"IP literal keeps its bracket", "[postgres://u:" + pw + "@[2001:db8::1]]", []string{pw}},
		// last @
		{"@ inside the password", "postgres://u:" + pw[:8] + "@" + pw[8:] + "@db1.orders.invalid/appdb", []string{pw[:8] + "@" + pw[8:]}},
		// user-info grammar
		{"percent-encoded", "postgres://u:" + pw[:6] + "%40" + pw[6:] + "@db1.orders.invalid/appdb", []string{pw[:6] + "%40" + pw[6:]}},
		{"brace template", "postgres://${DB_USER}:${DB_PASSWORD}@db:5432/app", nil},
		{"double-brace template", "postgres://{{db_user}}:{{db_password}}@db:5432/app", nil},
		{"angle placeholder", "postgres://user:<password>@host:5432/db", nil},
		{"printf verb", "redis://:%s@cache:6379/0", nil},
		{"python format", "postgres://u:%(pw)s@db1.orders.invalid/appdb", nil},
		{"caret", "postgres://u:" + pw + "^x@db1.orders.invalid/appdb", nil},
		// host grammar
		{"multi-host", "mongodb://u:" + pw + "@m1.orders.invalid:27017,m2.orders.invalid:27017,m3.orders.invalid:27017/appdb?replicaSet=rs0", []string{pw}},
		{"IPv4", "postgres://u:" + pw + "@10.0.0.5:5432/appdb", []string{pw}},
		{"IPv6", "postgres://u:" + pw + "@[2001:db8::1]:5432/appdb", []string{pw}},
		{"empty host", "postgres://u:" + pw + "@/appdb", nil},
		{"bad port", "postgres://u:" + pw + "@db1.orders.invalid:54x2/appdb", nil},
		{"sub-delim in host", "postgres://u:" + pw + "@db1$orders.invalid/appdb", nil},
		{"empty list entry", "mongodb://u:" + pw + "@m1.orders.invalid,,m2.orders.invalid/appdb", nil},
		// an @ in a path or query is never in the authority
		{"path @", "http://localhost:5173/@vite/client", nil},
		{"query @", "https://cal.orders.invalid/book?slot=10:30@room4", nil},
		{"IP literal then path @", "http://[::1]:8080/@admin", nil},
		{"file URI", "file:///home/app/data@2026/report.csv", nil},
		// password
		{"empty password", "http://user:@db1.orders.invalid/appdb", nil},
		{"empty user", "redis://:" + pw + "@cache.orders.invalid:6379/0", []string{pw}},
		// user name only
		{"token as user name", "git clone https://" + tok + "@git.orders.invalid/orders/app.git", []string{tok}},
		{"short user name", "ssh://git@git.orders.invalid/app.git", nil},
		{"person", "https://alice@git.orders.invalid/app.git", nil},
		{"service user", "postgresql://app_user@db1.orders.invalid:5432/appdb", nil},
		{"letters only", "https://serviceaccountdeploymentbot@git.orders.invalid/app.git", nil},
		{"low entropy", "https://aaaaaaaaaa1111111111@git.orders.invalid/app.git", nil},
		{"punctuation in user", "https://" + tok[:20] + "_" + tok[20:] + "@git.orders.invalid/app.git", nil},
		// several URIs, and one glued to the next
		{"two on a line", "a=postgres://u:" + pw + "@h1.orders.invalid/x b=redis://:" + tok + "@h2.orders.invalid/0", []string{pw, tok}},
		{"scheme glued to an authority", "a://b://u:" + pw + "@db1.orders.invalid/appdb", []string{pw}},
		{"no @", "jdbc:postgresql://db1.orders.invalid:5432/appdb", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, cand := range findURIUserinfo(c.line) {
				if c.line[cand.start:cand.end] != cand.text {
					t.Fatalf("span [%d,%d) is %q, text is %q", cand.start, cand.end, c.line[cand.start:cand.end], cand.text)
				}
				got = append(got, cand.text)
			}
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Errorf("findURIUserinfo(%q) = %q, want %q", c.line, got, c.want)
			}
		})
	}
}

// TestURIUserinfoDispositions pins the value-intrinsic disposition table: references and mask
// output give no candidate, default vocabulary, the user name repeated and implausible values are
// LOW with a published ceiling of 55, and anything else is scored normally. No row reads the
// host: the same default credential on two hosts gets the same disposition.
func TestURIUserinfoDispositions(t *testing.T) {
	v := NewValidator()
	const host = "@db1.orders.invalid:5432/appdb"
	pw := uriPW(3, 16)

	for name, line := range map[string]string{
		"whole $NAME":   "postgres://app:$DB_PASSWORD" + host,
		"whole $(...)":  "postgres://app:$(DB_PASSWORD)" + host,
		"asterisks":     "postgres://user:****" + host,
		"user only $":   "https://$GIT_TOKEN" + host,
		"empty":         "postgres://user:" + host,
		"masked longer": "postgres://user:****************" + host,
	} {
		if got := secretsOn(t, v, line, "settings.txt"); len(got) != 0 {
			t.Errorf("%s: %q reported %d finding(s), want none: %v", name, line, len(got), got)
		}
	}

	// LOW: kept at <= 55 with a published ceiling, or dropped where ordinary scoring already puts
	// the value under the threshold (`guest:guest` is 5 bytes of low entropy). The rows #766 measured
	// at LOW 55 must be REPORTED, so this cannot pass by reporting nothing.
	for _, c := range []struct {
		name, line string
		mustReport bool
	}{
		{"postgres:postgres", "postgres://postgres:postgres" + host, true},
		{"root:changeme", "postgres://root:changeme" + host, true},
		{"user:REDACTED", "postgres://user:REDACTED" + host, true},
		{"user:xxxxxxxx", "postgres://user:xxxxxxxx" + host, true},
		{"user:password", "postgres://user:password" + host, true},
		{"shouty", "postgres://user:CHANGEME2024" + host, true},
		{"all-lowercase short", "postgres://user:mypasswordx" + host, true},
		{"vocabulary, other case", "postgres://user:PassWord" + host, true},
		{"user name repeated", "postgres://" + pw + ":" + pw + host, true},
		{"guest:guest", "amqp://guest:guest@mq.orders.invalid:5672/", false},
		{"admin:Admin", "postgres://admin:Admin" + host, false},
		{"vocabulary on localhost", "postgres://user:Secret@localhost:5432/appdb", false},
	} {
		ms := secretsOn(t, v, c.line, "settings.txt")
		if c.mustReport && len(ms) != 1 {
			t.Errorf("%s: got %d findings, want the value reported once at LOW", c.name, len(ms))
		}
		for _, m := range ms {
			if m.Metadata["detection_method"] != uriUserinfoMethod {
				t.Errorf("%s: unexpected %s finding %q", c.name, m.Metadata["detection_method"], m.Text)
				continue
			}
			if m.Confidence > uriUserinfoLowCeiling {
				t.Errorf("%s: %q reported at %.0f, want LOW (<= %.0f)", c.name, m.Text, m.Confidence, uriUserinfoLowCeiling)
			}
			if ceil, _ := m.Metadata[ConfidenceCeilingKey].(float64); ceil != uriUserinfoLowCeiling {
				t.Errorf("%s: %q published ceiling %v, want %.0f so the bridge cannot lift it", c.name, m.Text, m.Metadata[ConfidenceCeilingKey], uriUserinfoLowCeiling)
			}
		}
	}

	// Scored normally, and above the keyword path's threshold: the M24 cap does not hold it.
	line := "DATABASE_URL=postgresql://app_user:" + pw + host
	ms := secretsOn(t, v, line, ".env")
	if len(ms) != 1 || ms[0].Text != pw || ms[0].Confidence < 60 {
		t.Fatalf("DATABASE_URL: got %v, want one finding of the password at >= 60", ms)
	}
	if _, capped := ms[0].Metadata[ConfidenceCeilingKey]; capped {
		t.Errorf("a scored password carries a ceiling: %v", ms[0].Metadata[ConfidenceCeilingKey])
	}
	if got := ms[0].Metadata["detection_method"]; got != uriUserinfoMethod {
		t.Errorf("detection_method = %v, want %s", got, uriUserinfoMethod)
	}
	if ms[0].Type != genericSecretType {
		t.Errorf("type = %s, want %s (no new type)", ms[0].Type, genericSecretType)
	}
	// A '$' inside a password is a sub-delim, not a reference.
	dollar := pw[:5] + "$" + pw[5:]
	if got := uriTexts(secretsOn(t, v, "postgres://app:"+dollar+host, "settings.txt")); len(got) != 1 || got[0] != dollar {
		t.Errorf("a password containing '$' reported %q, want %q", got, dollar)
	}
}

// TestURIUserinfoIsAdditive pins the rows whose result must equal main's (#766, Resolution 7). They
// were written against main before the fix and pass there too, by design: a key carrying a stem
// keeps reporting the whole URI, a `token:` user name keeps its wider span, a query or JDBC
// password keeps its keyword finding, and none of them gains a nested second finding.
func TestURIUserinfoIsAdditive(t *testing.T) {
	v := NewValidator()
	pw := uriPW(4, 16)
	tok := uriPW(5, 40)
	uri := "postgresql://app_user:" + pw + "@db1.orders.invalid:5432/appdb"
	for _, c := range []struct {
		name, line, want string
	}{
		{"key stem carries the whole URI", "DB_PASSWORD=" + uri, uri},
		{"secret stem carries the whole URI", "DB_SECRET=" + uri, uri},
		{"x-access-token user name", "git clone https://x-access-token:" + tok + "@git.orders.invalid/orders/app.git", tok + "@git.orders.invalid/orders/app.git"},
		{"gitlab-ci-token user name", "git clone https://gitlab-ci-token:" + tok + "@git.orders.invalid/orders/app.git", tok + "@git.orders.invalid/orders/app.git"},
		{"query-string password", "DATABASE_URL=postgres://db1.orders.invalid:5432/appdb?user=app_user&password=" + pw, pw},
		{"JDBC property", "jdbc:sqlserver://db1.orders.invalid:1433;databaseName=shop;user=app_user;password=" + pw, pw},
	} {
		t.Run(c.name, func(t *testing.T) {
			ms := secretsOn(t, v, c.line, ".env")
			if len(ms) != 1 {
				t.Fatalf("got %d findings %v, want exactly one", len(ms), ms)
			}
			if ms[0].Text != c.want || ms[0].Metadata["detection_method"] != "keyword_pattern" {
				t.Errorf("got %s %q, want keyword_pattern %q", ms[0].Metadata["detection_method"], ms[0].Text, c.want)
			}
		})
	}

	// A provider token as the password: the provider literal claims the identical span first and
	// keeps it, typed by getSecretType as always (built at run time; not a real token).
	gh := "ghs" + "_" + strings.Repeat("Q7mZ2vX9pL4kR8tB1nW6", 2)[:36]
	ms := secretsOn(t, v, "git clone https://x:"+gh+"@git.orders.invalid/orders/app.git", "clone.sh")
	if len(ms) != 1 || ms[0].Text != gh || ms[0].Type != "GITHUB_TOKEN" {
		t.Errorf("provider token as password: got %v, want one GITHUB_TOKEN finding of the token", ms)
	}
}

// TestURIUserinfoOutsideTheLinePreCheck pins that the source runs outside containsSecretIndicators
// and changes none of its arms: the npm "resolved" registry line is still skipped by the pre-check,
// and its password is still found.
func TestURIUserinfoOutsideTheLinePreCheck(t *testing.T) {
	v := NewValidator()
	tok := uriPW(6, 40)
	line := `      "resolved": "https://deploy:` + tok + `@registry.orders.invalid/left-pad/-/left-pad-1.3.0.tgz",`
	if v.containsSecretIndicators(line) {
		t.Fatal("precondition: containsSecretIndicators admits the npm registry line; this test no longer pins the outside-the-gate path")
	}
	if got := uriTexts(secretsOn(t, v, line, "package-lock.json")); len(got) != 1 || got[0] != tok {
		t.Errorf("got %q, want the token", got)
	}
}

// TestURIUserinfoCarriesNoURIPart pins Resolution 5: the finding's metadata, and the explanation
// --explain renders from it, carry no part of the URI -- not the password, the user, the host or
// the scheme. (Match.Context carries the line, as for every finding.)
func TestURIUserinfoCarriesNoURIPart(t *testing.T) {
	v := NewValidator()
	pw := uriPW(7, 16)
	parts := []string{pw, "app_user", "db1.orders.invalid", "postgresql", "appdb"}
	ms := secretsOn(t, v, "DATABASE_URL=postgresql://app_user:"+pw+"@db1.orders.invalid:5432/appdb", ".env")
	if len(ms) != 1 {
		t.Fatalf("want one finding, got %v", ms)
	}
	for k, val := range ms[0].Metadata {
		s := fmt.Sprint(val)
		for _, p := range parts {
			if strings.Contains(s, p) || strings.Contains(k, p) {
				t.Errorf("metadata %s = %q carries %q", k, s, p)
			}
		}
	}
	e := explain.NewSignalSynthesizer().Explain(ms[0])
	for _, s := range []string{e.Rationale, string(e.Verdict), e.DraftSuppressReason} {
		for _, p := range parts {
			if strings.Contains(s, p) {
				t.Errorf("explanation %q carries %q", s, p)
			}
		}
	}
}

// uriMatrixSchemes and uriMatrixPlacements are #766's matrix A: 25 schemes, each with its default
// port and a path, in 7 placements.
var uriMatrixSchemes = []struct{ scheme, hostport, path string }{
	{"postgres", "db1.orders.invalid:5432", "/appdb"},
	{"postgresql", "db1.orders.invalid:5432", "/appdb"},
	{"postgresql+psycopg2", "db1.orders.invalid:5432", "/appdb"},
	{"mysql", "db1.orders.invalid:3306", "/shop"},
	{"mysql+pymysql", "db1.orders.invalid:3306", "/shop"},
	{"mariadb", "db1.orders.invalid:3306", "/shop"},
	{"mongodb", "mongo1.orders.invalid:27017", "/appdb"},
	{"mongodb+srv", "cluster0.orders.invalid", "/appdb"},
	{"redis", "cache.orders.invalid:6379", "/0"},
	{"rediss", "cache.orders.invalid:6380", "/0"},
	{"amqp", "mq.orders.invalid:5672", "/orders"},
	{"amqps", "mq.orders.invalid:5671", "/orders"},
	{"ftp", "files.orders.invalid:21", "/upload"},
	{"sftp", "files.orders.invalid:22", "/upload"},
	{"smtp", "mail.orders.invalid:25", "/"},
	{"smtps", "mail.orders.invalid:465", "/"},
	{"sqlserver", "db1.orders.invalid:1433", "/shop"},
	{"mssql", "db1.orders.invalid:1433", "/shop"},
	{"oracle", "db1.orders.invalid:1521", "/ORCL"},
	{"http", "proxy.orders.invalid:3128", "/"},
	{"https", "registry.orders.invalid:443", "/v2/"},
	{"ldap", "ldap.orders.invalid:389", "/dc=orders,dc=invalid"},
	{"clickhouse", "ch.orders.invalid:9000", "/default"},
	{"nats", "nats.orders.invalid:4222", "/"},
	{"cockroachdb", "crdb.orders.invalid:26257", "/defaultdb"},
}

var uriMatrixPlacements = []struct {
	name, path string
	place      func(uri string) string
}{
	{"bare", "notes.txt", func(u string) string { return u }},
	{"env", ".env", func(u string) string { return "DATABASE_URL=" + u }},
	{"env quoted", ".env", func(u string) string { return `DATABASE_URL="` + u + `"` }},
	{"yaml", "config.yaml", func(u string) string { return "  url: " + u }},
	{"json", "appsettings.json", func(u string) string { return `{"ConnectionStrings": {"connectionString": "` + u + `"}}` }},
	{"python", "db.py", func(u string) string { return `engine = create_engine("` + u + `")` }},
	{"prose", "README.md", func(u string) string { return "Connect with " + u + " and run the migration." }},
}

// TestURIUserinfoMatrix is the self-policing half of #766: every scheme in every placement, and the
// length sweep, reports exactly one finding whose text is the password, at 60 or more. On main all
// 185 report nothing from any path.
func TestURIUserinfoMatrix(t *testing.T) {
	v := NewValidator()
	seed := 100
	check := func(t *testing.T, line, path, pw string) {
		t.Helper()
		ms := secretsOn(t, v, line, path)
		if len(ms) != 1 || ms[0].Text != pw || ms[0].Confidence < 60 {
			var got []string
			for _, m := range ms {
				got = append(got, fmt.Sprintf("%s %q %.0f", m.Metadata["detection_method"], m.Text, m.Confidence))
			}
			t.Errorf("%q in %s: got %v, want one finding of the password at >= 60", line, path, got)
		}
	}
	for _, s := range uriMatrixSchemes {
		for _, p := range uriMatrixPlacements {
			seed++
			pw := uriPW(seed, 16)
			uri := s.scheme + "://app_user:" + pw + "@" + s.hostport + s.path
			t.Run(s.scheme+"/"+p.name, func(t *testing.T) { check(t, p.place(uri), p.path, pw) })
		}
	}
	for _, n := range []int{12, 16, 24, 32, 48} {
		for _, p := range []int{1, 5} { // .env and Python
			seed++
			pw := uriPW(seed, n)
			uri := "postgresql://app_user:" + pw + "@db1.orders.invalid:5432/appdb"
			t.Run(fmt.Sprintf("length%d/%s", n, uriMatrixPlacements[p].name), func(t *testing.T) {
				check(t, uriMatrixPlacements[p].place(uri), uriMatrixPlacements[p].path, pw)
			})
		}
	}
}
