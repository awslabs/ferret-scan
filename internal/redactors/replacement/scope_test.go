// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/redactors"
)

// One replacement per value per invocation (#886). Every value below is synthetic: SSN 234-56-000N,
// phone 312-555-0142 (the fictional 555 exchange), a card with a sequential serial, example.org.

func genIn(t *testing.T, s redactors.SyntheticScope, v, typ string) string {
	t.Helper()
	out, err := Generate(v, typ, redactors.RedactionSynthetic, s)
	if err != nil {
		t.Fatalf("Generate(%q, %s): %v", v, typ, err)
	}
	return out
}

// A synthetic draw needs a scope, and there is no fallback: not a fresh draw, not the placeholder.
func TestSyntheticWithoutAScopeIsAnError(t *testing.T) {
	if got, err := Generate("234-56-0001", "SSN", redactors.RedactionSynthetic, nil); !errors.Is(err, redactors.ErrNoSyntheticScope) || got != "" {
		t.Errorf("Generate with no scope = %q, %v; want \"\" and ErrNoSyntheticScope", got, err)
	}
	if r, err := Render("234-56-0001", "SSN", redactors.RedactionSynthetic, nil); !errors.Is(err, redactors.ErrNoSyntheticScope) || r.Text != "" {
		t.Errorf("Render with no scope = %q, %v", r.Text, err)
	}
	ms := []detector.Match{{Type: "SSN", Text: "234-56-0001", Confidence: 90, LineNumber: 1, Context: detector.ContextInfo{FullLine: "SSN 234-56-0001"}}}
	g := redactors.ResolveOverlaps(ms)[0]
	if _, err := RenderGroup(g, ms, redactors.RedactionSynthetic, nil); !errors.Is(err, redactors.ErrNoSyntheticScope) {
		t.Errorf("RenderGroup with no scope: %v", err)
	}
	// The masking strategies read no scope.
	for st, want := range map[redactors.RedactionStrategy]string{
		redactors.RedactionSimple: "[SSN-REDACTED]", redactors.RedactionFormatPreserving: "***-**-0001",
	} {
		if got, err := Generate("234-56-0001", "SSN", st, nil); err != nil || got != want {
			t.Errorf("%s with no scope = %q, %v; want %q", st, got, err, want)
		}
	}
	// A strategy outside the three is an error, never the placeholder it used to become.
	if got, err := Generate("234-56-0001", "SSN", redactors.RedactionStrategy(7), nil); err == nil {
		t.Errorf("an undefined strategy rendered %q", got)
	}
}

// Case A of #886: the SSN four times and the email twice, one scope.
func TestOneValueGetsOneReplacementPerScope(t *testing.T) {
	s := redactors.NewSyntheticScope()
	ssn := map[string]bool{}
	for i := 0; i < 4; i++ {
		ssn[genIn(t, s, "234-56-0001", "SSN")] = true
	}
	email := map[string]bool{}
	for i := 0; i < 2; i++ {
		email[genIn(t, s, "dana.whitfield@example.org", "BUSINESS")] = true
	}
	if len(ssn) != 1 || len(email) != 1 {
		t.Fatalf("one SSN got %d replacements and one email %d, want 1 each: %v %v", len(ssn), len(email), ssn, email)
	}
	// A second invocation draws afresh: synthetic stays random between runs.
	differs := false
	for i := 0; i < 5 && !differs; i++ {
		differs = genIn(t, redactors.NewSyntheticScope(), "234-56-0001", "SSN") != genIn(t, s, "234-56-0001", "SSN")
	}
	if !differs {
		t.Error("five new scopes all drew the first scope's replacement")
	}
}

// An email type and the metadata validator's EMAIL are one family: one address, one replacement.
func TestAFamilySpansItsTypes(t *testing.T) {
	s := redactors.NewSyntheticScope()
	if a, b := genIn(t, s, "dana.whitfield@example.org", "BUSINESS"), genIn(t, s, "dana.whitfield@example.org", "EMAIL"); a != b {
		t.Errorf("BUSINESS %q and EMAIL %q for one address", a, b)
	}
	if a, b := genIn(t, s, "4123456789012349", "VISA"), genIn(t, s, "4123456789012349", "CREDIT_CARD"); a != b {
		t.Errorf("VISA %q and CREDIT_CARD %q for one card", a, b)
	}
}

// Case E of #886: sixteen spellings of five entities. Each spelling the format treats as the same value
// shares one replacement, written in that spelling's own shape.
func TestSpellingsOfOneValueShareItsReplacement(t *testing.T) {
	s := redactors.NewSyntheticScope()
	digits := regexp.MustCompile(`[0-9]`)
	shapeOf := func(v string) string { return digits.ReplaceAllString(v, "9") }
	onlyDigits := func(v string) string { return digitsOf(v) }

	// SSN: four spellings, one set of nine digits, each in its own separators. The fullwidth one is
	// folded first (its replacement is ASCII), as before.
	ssn := []string{"234-56-0001", "234 56 0001", "234560001", "２３４-５６-０００１"}
	var ssnDigits string
	for i, v := range ssn {
		got := genIn(t, s, v, "SSN")
		if i == 0 {
			ssnDigits = onlyDigits(got)
		}
		if onlyDigits(got) != ssnDigits {
			t.Errorf("SSN %q -> %q: digits %s, the first spelling's were %s", v, got, onlyDigits(got), ssnDigits)
		}
		want := shapeOf(v)
		if i == 3 {
			want = "999-99-9999"
		}
		if shapeOf(got) != want {
			t.Errorf("SSN %q -> %q: shape %s, want %s", v, got, shapeOf(got), want)
		}
		if strings.Contains(got, "0001") && strings.HasPrefix(onlyDigits(got), "234") {
			t.Errorf("SSN %q survived as %q", v, got)
		}
	}

	// PHONE: punctuation kept; an 11-digit NANP number is the 10-digit one with its "1" kept.
	phone := []string{"312-555-0142", "(312) 555-0142", "312.555.0142", "312 555 0142", "1-312-555-0142"}
	var line string
	for i, v := range phone {
		got := genIn(t, s, v, "PHONE")
		d := onlyDigits(got)
		if i == 4 {
			if !strings.HasPrefix(got, "1-") {
				t.Errorf("PHONE %q -> %q: the trunk prefix was not kept", v, got)
			}
			d = d[1:]
		}
		if i == 0 {
			line = d
		}
		if d != line || shapeOf(got) != shapeOf(v) || !strings.HasPrefix(d, "555") {
			t.Errorf("PHONE %q -> %q: want the 555 line %s in the shape %s", v, got, line, shapeOf(v))
		}
	}

	// EMAIL: case-folded to one address.
	if a, b := genIn(t, s, "michael.torres@example.org", "BUSINESS"), genIn(t, s, "Michael.Torres@Example.ORG", "BUSINESS"); a != b || !strings.HasSuffix(a, "@example.com") {
		t.Errorf("one address in two cases: %q and %q", a, b)
	}

	// PERSON_NAME: one name in its order, comma and case.
	plain := genIn(t, s, "Michael Torres", "PERSON_NAME")
	f := strings.Fields(plain)
	if len(f) != 2 {
		t.Fatalf("a two-token name became %q", plain)
	}
	if got := genIn(t, s, "MICHAEL TORRES", "PERSON_NAME"); got != strings.ToUpper(plain) {
		t.Errorf("MICHAEL TORRES -> %q, want %q", got, strings.ToUpper(plain))
	}
	if got := genIn(t, s, "Torres, Michael", "PERSON_NAME"); got != f[1]+", "+f[0] {
		t.Errorf("Torres, Michael -> %q, want %q", got, f[1]+", "+f[0])
	}
	if got := genIn(t, s, "Dr. Michael Torres", "PERSON_NAME"); got != "Dr. "+plain {
		t.Errorf("Dr. Michael Torres -> %q, want the title kept outside the key: %q", got, "Dr. "+plain)
	}

	// CREDIT_CARD: digits shared, separators kept, issuer prefix kept, check digit wrong.
	card := []string{"4123 4567 8901 2349", "4123-4567-8901-2349", "4123456789012349"}
	var cardDigits string
	for i, v := range card {
		got := genIn(t, s, v, "VISA")
		if i == 0 {
			cardDigits = onlyDigits(got)
		}
		if onlyDigits(got) != cardDigits || shapeOf(got) != shapeOf(v) || !strings.HasPrefix(got, "4123") || luhnCheck(digitInts(cardDigits[:15])) == int(cardDigits[15]-'0') {
			t.Errorf("VISA %q -> %q (first spelling's digits %s)", v, got, cardDigits)
		}
	}
}

func digitInts(s string) []int {
	out := make([]int, len(s))
	for i := range s {
		out[i] = int(s[i] - '0')
	}
	return out
}

// The decoys of #886: values that look alike are still different values, and keep different
// replacements.
func TestNearValuesKeepTheirOwnReplacements(t *testing.T) {
	s := redactors.NewSyntheticScope()
	for _, c := range []struct{ a, b, typ string }{
		{"234-56-0001", "234-56-0010", "SSN"},
		{"Dana Whitfield", "Dana Whitfield-Ames", "PERSON_NAME"},
		{"Michael Torres", "Maria Torres", "PERSON_NAME"},
		{"dana.whitfield@example.org", "dana.whitfeld@example.org", "BUSINESS"},
		{"10.1.2.3", "10.1.2.4", "IP_ADDRESS"},
		{"312-555-0142", "312-555-0143", "PHONE"},
		{"4123456789012349", "4123456789012357", "VISA"},
	} {
		if x, y := genIn(t, s, c.a, c.typ), genIn(t, s, c.b, c.typ); x == y {
			t.Errorf("%s %q and %q share the replacement %q", c.typ, c.a, c.b, x)
		}
	}
	// One digit string reported as an SSN and as a phone is two values.
	counting := &countingScope{inner: redactors.NewSyntheticScope()}
	if _, err := Generate("3125550142", "SSN", redactors.RedactionSynthetic, counting); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate("3125550142", "PHONE", redactors.RedactionSynthetic, counting); err != nil {
		t.Fatal(err)
	}
	if counting.families["SSN"] != 1 || counting.families["PHONE"] != 1 {
		t.Errorf("one digit string as SSN and PHONE resolved as %v, want one value in each family", counting.families)
	}
}

// countingScope counts Resolve calls per family.
type countingScope struct {
	inner    redactors.SyntheticScope
	mu       sync.Mutex
	families map[string]int
}

func (c *countingScope) Resolve(family, canonical string, distinct bool, draw redactors.SyntheticDraw) (string, error) {
	c.mu.Lock()
	if c.families == nil {
		c.families = map[string]int{}
	}
	c.families[family]++
	c.mu.Unlock()
	return c.inner.Resolve(family, canonical, distinct, draw)
}

// The overlap-group rule asks every member what it would keep. That must not draw a replacement for
// a member value that is never written.
func TestAGroupDrawsOnlyTheValueItWrites(t *testing.T) {
	line := "id 512010001"
	ms := []detector.Match{
		{Type: "SSN", Text: "512010001", Validator: "ssn", Confidence: 90, LineNumber: 1, Context: detector.ContextInfo{FullLine: line}},
		{Type: "PASSPORT", Text: "512010001", Validator: "passport", Confidence: 40, LineNumber: 1, Context: detector.ContextInfo{FullLine: line}},
	}
	groups := redactors.ResolveOverlaps(ms)
	if len(groups) != 1 || !groups[0].IsGroup() {
		t.Fatalf("fixture formed %d groups", len(groups))
	}
	c := &countingScope{inner: redactors.NewSyntheticScope()}
	if _, err := RenderGroup(groups[0], ms, redactors.RedactionSynthetic, c); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, n := range c.families {
		total += n
	}
	if total != 1 {
		t.Errorf("rendering one group drew %d values (%v), want 1: the union", total, c.families)
	}
}

// failingReaderScope hands every draw a reader that fails.
type failingReaderScope struct{}

var errNoEntropy = errors.New("entropy source failed")

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errNoEntropy }

func (failingReaderScope) Resolve(_, _ string, _ bool, draw redactors.SyntheticDraw) (string, error) {
	return draw(failingReader{}, 0)
}

// A failed read of the random source is an error. It used to be replaced by the clock.
func TestAFailedRandomReadIsAnError(t *testing.T) {
	for _, typ := range []string{"SSN", "PHONE", "VISA", "BUSINESS", "IP_ADDRESS", "PERSON_NAME", "PASSPORT", "GITHUB_TOKEN", "IBAN"} {
		v := map[string]string{"SSN": "234-56-0001", "PHONE": "312-555-0142", "VISA": "4123456789012349",
			"BUSINESS": "dana@example.org", "IP_ADDRESS": "10.1.2.3", "PERSON_NAME": "Dana Whitfield",
			"PASSPORT": "C87654321", "GITHUB_TOKEN": "ghp_0123456789abcdefghijklmnopqrstuvwxyz", "IBAN": "GB82WEST12345698765432"}[typ]
		got, err := Generate(v, typ, redactors.RedactionSynthetic, failingReaderScope{})
		if !errors.Is(err, errNoEntropy) {
			t.Errorf("%s with a failing random source = %q, %v; want the read error", typ, got, err)
		}
	}
}

// The name lists load once for every goroutine (#886, case D). The hand-rolled once marked itself done
// before the lists were assigned, so a goroutine arriving in between got nil lists and the
// placeholder: 31 of 32 concurrent first calls.
func TestTheNameDatabaseLoadsOnceForEveryGoroutine(t *testing.T) {
	saved := nameDB
	t.Cleanup(func() { nameDB = saved })
	nameDB = sync.OnceValues(loadNameLists)

	const workers = 32
	var start, done sync.WaitGroup
	start.Add(1)
	results := make([]string, workers)
	errs := make([]error, workers)
	for i := 0; i < workers; i++ {
		done.Add(1)
		go func(i int) {
			defer done.Done()
			start.Wait()
			results[i], errs[i] = SyntheticName("Dana Whitfield")
		}(i)
	}
	start.Done()
	done.Wait()
	for i := range results {
		if errs[i] != nil || results[i] == "" || strings.Contains(results[i], "REDACTED") {
			t.Errorf("goroutine %d: %q, %v", i, results[i], errs[i])
		}
	}
}

// A name database that cannot be loaded is an error, never the placeholder at a nil error.
func TestNoNameDatabaseIsAnError(t *testing.T) {
	saved := nameDB
	t.Cleanup(func() { nameDB = saved })
	boom := errors.New("embedded name data unreadable")
	nameDB = sync.OnceValues(func() (*nameLists, error) { return nil, boom })

	if got, err := SyntheticName("Dana Whitfield"); !errors.Is(err, boom) || got != "" {
		t.Errorf("SyntheticName = %q, %v; want the load error", got, err)
	}
	if got, err := Generate("Dana Whitfield", "PERSON_NAME", redactors.RedactionSynthetic, redactors.NewSyntheticScope()); !errors.Is(err, boom) {
		t.Errorf("Generate = %q, %v; want the load error", got, err)
	}
}

// Sorted, because a map's order differs per process and a seeded draw must name the same person in
// every one.
func TestTheNameListsAreSortedAndComplete(t *testing.T) {
	db, err := nameDB()
	if err != nil {
		t.Fatal(err)
	}
	if !sort.StringsAreSorted(db.first) || !sort.StringsAreSorted(db.last) {
		t.Error("the name lists are not sorted")
	}
	// The counts the documentation states.
	if len(db.first) != 5301 || len(db.last) != 2333 {
		t.Errorf("%d first and %d last names, the docs say 5,301 and 2,333", len(db.first), len(db.last))
	}
}

// One-to-one needs room: 65,536 addresses in 192.168.0.0/16 cannot give every address of a large log
// its own. A first draw stays in 192.168/16; a collision draws from all of RFC 1918.
func TestSyntheticAddressesSpanAllOfRFC1918(t *testing.T) {
	s := redactors.NewSyntheticScope()
	seen := map[string]bool{}
	blocks := map[string]int{}
	const n = 70000 // more distinct addresses than 192.168.0.0/16 holds
	for i := 0; i < n; i++ {
		in := fmt.Sprintf("203.%d.%d.%d", i>>16, (i>>8)&0xff, i&0xff)
		out, err := Generate(in, "IP_ADDRESS", redactors.RedactionSynthetic, s)
		if err != nil {
			t.Fatalf("address %d of %d refused: %v", i+1, n, err)
		}
		if seen[out] {
			t.Fatalf("two addresses share %s", out)
		}
		seen[out] = true
		a, err := netip.ParseAddr(out)
		if err != nil || !a.IsPrivate() || !a.Is4() {
			t.Fatalf("%q is not a private IPv4 address", out)
		}
		switch {
		case strings.HasPrefix(out, "10."):
			blocks["10/8"]++
		case strings.HasPrefix(out, "172."):
			blocks["172.16/12"]++
		default:
			blocks["192.168/16"]++
		}
	}
	for _, b := range []string{"10/8", "172.16/12", "192.168/16"} {
		if blocks[b] == 0 {
			t.Errorf("no synthetic address in %s: %v", b, blocks)
		}
	}
	// A single draw is 192.168.x.y, as every synthetic address was before.
	for i := 0; i < 20; i++ {
		if out, err := Synthetic("172.217.14.206", "IP_ADDRESS"); err != nil || !strings.HasPrefix(out, "192.168.") {
			t.Fatalf("a first draw = %q, %v", out, err)
		}
	}
	// An IPv4-mapped spelling of an address is the address.
	if a, b := genIn(t, s, "10.9.8.7", "IP_ADDRESS"), genIn(t, s, "::ffff:10.9.8.7", "IP_ADDRESS"); a != b {
		t.Errorf("10.9.8.7 and ::ffff:10.9.8.7 drew %q and %q", a, b)
	}
}

func TestDrawIPCoversEveryBlock(t *testing.T) {
	for _, c := range []struct {
		i    int
		want string
	}{
		{0, "10.0.0.0"}, {1<<24 - 1, "10.255.255.255"},
		{1 << 24, "172.16.0.0"}, {1<<24 + 1<<20 - 1, "172.31.255.255"},
		{1<<24 + 1<<20, "192.168.0.0"}, {rfc1918Size - 1, "192.168.255.255"},
	} {
		got, err := drawIP(&source{r: fixedIndex(c.i)}, 1)
		if err != nil || got != c.want {
			t.Errorf("index %d -> %q, %v; want %s", c.i, got, err, c.want)
		}
	}
}

// fixedIndex is a reader whose first eight bytes encode i, so source.intn(n) returns i for any n > i.
func fixedIndex(i int) io.Reader {
	b := make([]byte, 8)
	for k := 7; k >= 0; k-- {
		b[k] = byte(i)
		i >>= 8
	}
	return strings.NewReader(string(b))
}

// A one-character local part had 36 possible replacements; one-to-one would have refused the 37th.
func TestShortLocalPartsHaveRoom(t *testing.T) {
	s := redactors.NewSyntheticScope()
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		addr := fmt.Sprintf("%c@host%d.example.org", 'a'+i%26, i)
		out, err := Generate(addr, "BUSINESS", redactors.RedactionSynthetic, s)
		if err != nil {
			t.Fatalf("address %d refused: %v", i+1, err)
		}
		if at := strings.IndexByte(out, '@'); at != minSyntheticLocal || seen[out] {
			t.Fatalf("%q -> %q: want a fresh %d-character local part", addr, out, minSyntheticLocal)
		}
		seen[out] = true
	}
	// A longer local part keeps its length, as before.
	if out := genIn(t, s, "michael.torres@example.org", "BUSINESS"); strings.IndexByte(out, '@') != len("michael.torres") {
		t.Errorf("a 14-character local part became %q", out)
	}
}

// The notice arms of INTELLECTUAL_PROPERTY may share their generic text; a patent number may not.
func TestNoticesMayRepeatButPatentsMayNot(t *testing.T) {
	s := redactors.NewSyntheticScope()
	for i := 0; i < 40; i++ {
		if _, err := Generate(fmt.Sprintf("Widget%d(tm)", i), "INTELLECTUAL_PROPERTY", redactors.RedactionSynthetic, s); err != nil {
			t.Fatalf("trademark %d refused: %v", i, err)
		}
		if _, err := Generate(fmt.Sprintf("Copyright %d Example Corp", 1900+i), "INTELLECTUAL_PROPERTY", redactors.RedactionSynthetic, s); err != nil {
			t.Fatalf("copyright notice %d refused: %v", i, err)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		out := genIn(t, s, fmt.Sprintf("US%07d", 1000000+i), "INTELLECTUAL_PROPERTY")
		if seen[out] {
			t.Fatalf("two patent numbers share %q", out)
		}
		seen[out] = true
	}
}
