// SPDX-License-Identifier: Apache-2.0

package goldencorpus

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// TestURIUserinfoRedactsThePassword is the redaction half of #766, here rather than in
// internal/validators/secrets because pkg/redact depends on that package. For #766's matrix A --
// 25 schemes, each with its default port and a path, in 7 placements -- the password must be the
// ONLY bytes the redactor rewrites, and none of it may survive, under every strategy: the text
// before and after the password is byte-identical to the input, and what replaced the password
// shares no 4-byte run with it (8 for synthetic, whose replacement is random). Before the fix
// there was no finding, so every one of these was written back in the clear: a DATABASE_URL-only
// .env got no redacted copy at all, and the --stdin gateway passed the password through.
func TestURIUserinfoRedactsThePassword(t *testing.T) {
	type scheme struct{ scheme, hostport, path string }
	schemes := []scheme{
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
	placements := []struct {
		name, label string
		place       func(uri string) string
	}{
		{"bare", "notes.txt", func(u string) string { return u }},
		{"env", ".env", func(u string) string { return "DATABASE_URL=" + u }},
		{"env_quoted", ".env", func(u string) string { return `DATABASE_URL="` + u + `"` }},
		{"yaml", "config.yaml", func(u string) string { return "  url: " + u }},
		{"json", "appsettings.json", func(u string) string { return `{"ConnectionStrings": {"connectionString": "` + u + `"}}` }},
		{"python", "db.py", func(u string) string { return `engine = create_engine("` + u + `")` }},
		{"prose", "README.md", func(u string) string { return "Connect with " + u + " and run the migration." }},
	}
	strategies := []struct {
		name   string
		s      redact.Strategy
		window int
	}{{"simple", redact.Simple, 4}, {"format_preserving", redact.FormatPreserving, 4}, {"synthetic", redact.Synthetic, 8}}

	// Consonants and digits only, so no test marker or word is spelt; distinct per case.
	alphabet := "BCDFGHJKLMNPQRSTVWXZbcdfghjkmnpqrstvwxz23456789"
	pwFor := func(i int) string {
		var b strings.Builder
		b.WriteString("Q7k") // an upper, a digit and a lower, so the value is plausible at once
		x := uint32(i*2654435761 + 7)
		for b.Len() < 16 {
			x = x*1664525 + 1013904223
			b.WriteByte(alphabet[int(x>>8)%len(alphabet)])
		}
		return b.String()
	}

	for _, st := range strategies {
		eng, err := redact.NewEngine(redact.EngineOptions{Checks: []string{"SECRETS"}, Strategy: st.s})
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, sc := range schemes {
			for _, p := range placements {
				n++
				pw := pwFor(n)
				line := p.place(sc.scheme + "://app_user:" + pw + "@" + sc.hostport + sc.path)
				t.Run(fmt.Sprintf("%s/%s/%s", st.name, sc.scheme, p.name), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					res, err := eng.Redact(ctx, redact.Request{Text: line + "\n", Label: p.label})
					if err != nil {
						t.Fatal(err)
					}
					if len(res.Findings()) != 1 {
						t.Fatalf("%d findings, want exactly the password: %q", len(res.Findings()), line)
					}
					i := strings.Index(line, pw)
					prefix, suffix := line[:i], line[i+len(pw):]+"\n"
					got := res.Redacted
					if !strings.HasPrefix(got, prefix) || !strings.HasSuffix(got, suffix) || len(got) < len(prefix)+len(suffix) {
						t.Fatalf("the redactor rewrote more than the password:\n in: %q\nout: %q", line, got)
					}
					middle := got[len(prefix) : len(got)-len(suffix)]
					for k := 0; k+st.window <= len(pw); k++ {
						if strings.Contains(middle, pw[k:k+st.window]) {
							t.Fatalf("%q of the password survives as %q", pw[k:k+st.window], middle)
						}
					}
				})
			}
		}
		_ = eng.Close()
	}
}
