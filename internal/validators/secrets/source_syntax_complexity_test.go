// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"fmt"
	"strings"
	"testing"

	"github.com/awslabs/ferret-scan/v2/internal/perfguard"
)

// The #753 lexer runs over the WHOLE content of every gated file before the line loop, so its cost
// is paid on every .py/.js/.ts/.go/.tf scan whether or not a single candidate exists. It must be
// O(n), with no per-line rescans: one forward pass, every backward look bounded by a constant, and
// a forward look that fails stopping at the first byte that decides it (see lexSource). The
// per-candidate gate test is O(1) for the value start plus the value's own length over 64 for the
// backtick-text span check, both independent of the file.
//
// Five targets, each base vs 4x on perfguard.Measure, bound 8.0 -- linear is ~4x, quadratic ~16x,
// so the bound sits between the two populations. Each catches a regression the others cannot: the
// first four were proven against a planted one, the HCL target against the opener check it
// replaced:
//
//   - the gated VALIDATOR on a lexer-heavy .ts file, the path a user actually pays for. It catches
//     an INTEGRATION quadratic: the content re-lexed once per line read 10.77x here, against 4.06x
//     and 4.01x on the two lexer targets. It is blind to a quadratic INSIDE the lexer, which the
//     validator's own larger per-line cost dilutes -- a rescan of the content so far at every quote
//     read 4.12x here -- which is why the lexer is also measured alone;
//   - the LEXER alone on the same many-line file, where that per-quote rescan read 16.65x;
//   - the LEXER alone on ONE long line, the shape that turns any per-line rescan -- a lookback to
//     the line start, a re-scan for the line end -- into a quadratic. A lineEnd computed at every
//     '/' read 15.74x here and 3.99x and 4.08x on the other two, whose lines are short;
//   - the LEXER alone on Python f-string replacement fields, which push and pop a frame each. A
//     rescan of the content so far at every field read 17.00x here, and 4.03x to 4.43x on the
//     other four, which never reach the Python field code;
//   - the LEXER alone on one long HCL line of rejected heredoc openers. None of the targets above
//     is HCL. The opener check this replaced found the end of the line before it judged the bytes
//     after `<<ID`, so every rejected opener re-read the rest of the line: 17.64x here (a 3.2MB
//     .tf file took 18.1s through the CLI, against 0.86s on main).
//
// Measured on darwin/arm64, correct code, in target order: 4.02x, 4.19x, 4.15x, 4.14x and 4.23x,
// and on a second run 3.96x, 4.05x, 4.26x, 4.13x and 4.37x. Under -race the four lexer targets
// read 3.97x, 4.06x, 4.06x and 4.19x; the validator target is not timed under -race (see the
// test).
//
// The fixtures are lexer-heavy on purpose: every line opens and closes templates with nested
// interpolations, escaped quotes of all three kinds, a block comment, and a regex holding quote
// bytes, so each construct is exercised at the rate the input grows. Every value is DISTINCT per
// line -- identical repeats let a cache or a dedupe flatten the curve for a reason unrelated to the
// algorithm.

// lexHeavyTSLine is one line of every construct the JS lexer has a state for.
func lexHeavyTSLine(i int) string {
	return fmt.Sprintf("const t%d = `head ${user.n%d + `inner ${k%d}`} tail` + 'it\\'s %d' + "+
		"\"q\\\"%d\" /* c%d */ + (/[\"'`]x%d/g.test(s) ? a%d / b : c); // n%d", i, i, i, i, i, i, i, i, i)
}

// lexHeavyPyLine exercises the Python-only states, PEP 701 replacement fields included: a field
// holding a string in the f-string's own quote, a nested field in a format spec, and a t-string.
// A frame is pushed and popped per field, so a quadratic in that handling shows up as growth.
func lexHeavyPyLine(i int) string {
	return fmt.Sprintf("v%d = f\"{cfg[\"k%d\"]} {n%d:{w%d}} tail\" + t\"{d[\"t%d\"]}\" + "+
		"rf'(\\{{)%d' + '''tri%d''' + b\"b%d\"  # c%d", i, i, i, i, i, i, i, i, i)
}

// distinctCredential is a credential-shaped value unique to i, built at runtime.
func distinctCredential(i int) string {
	return buildTestToken("Xk9mQ2", fmt.Sprintf("%06d", i), "vL7pR4tW")
}

// lexHeavyTSFile is lines groups of three: a lexer-heavy line, a literal-context credential in a
// comment (which must report), and a code-position FP (which the gate must drop).
func lexHeavyTSFile(lines int) string {
	var b strings.Builder
	b.Grow(lines * 260)
	for i := 0; i < lines; i++ {
		b.WriteString(lexHeavyTSLine(i))
		b.WriteString("\n// rotate before release: secret=")
		b.WriteString(distinctCredential(i))
		b.WriteString("\nconst secret = process.env.JWT_SECRET;\n")
	}
	return b.String()
}

// countGated returns how many reported findings are the in-comment credentials and how many are the
// code-position FP; the latter must be zero for the measurement to be of the GATED path.
func countGated(t *testing.T, v *Validator, content string) (literal, code int) {
	t.Helper()
	ms, err := v.ValidateContent(content, "heavy.ts")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	for _, m := range ms {
		switch {
		case strings.HasPrefix(m.Text, "Xk9mQ2"):
			literal++
		case strings.Contains(m.Text, "process.env"):
			code++
		}
	}
	return literal, code
}

func assertGrowth(t *testing.T, what string, g perfguard.Growth) {
	t.Helper()
	t.Logf("%s over a 4x input: %s", what, g)
	const ceiling = 8.0
	if _, resolvable := g.Ticks(); !resolvable {
		t.Logf("%s growth NOT asserted -- %s", what, g.ResolutionNote())
		return
	}
	if g.Ratio > ceiling {
		t.Errorf("%s scaled %s over a 4x input -- linear is ~4x and quadratic ~16x, so this is "+
			"superlinear beyond noise: the #753 lexer must be one forward pass", what, g)
	}
}

func TestSourceLexerIsLinearThroughTheGatedValidator(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}
	// 400 groups (1,200 lines, ~110KB): the base reading is ~210ms on the CPU clock, over the
	// 8-tick floor even on a 15.625ms-tick Windows runner, and the pair stays a few seconds.
	base := 400
	if raceEnabled {
		// -race multiplies the validator's cost about 20x -- measured 4.7s base and 19.4s big, 75s
		// for this test against 3.3s without it, which would more than double this package's race
		// run -- and it compresses the ratio being measured. The scans still run, smaller, so the
		// detector sees the gate's per-file state; the ratio is asserted by the non-race runs.
		base = 50
	}
	small, large := lexHeavyTSFile(base), lexHeavyTSFile(4*base)
	if _, reason := newSourceGate(large, langJS); reason != "" {
		t.Fatalf("the fixture fails the gate open (%s); the measurement would not be of the gated path", reason)
	}

	v := NewValidator()
	// Non-vacuity, before any timing claim: the gate is ON (every FP dropped) and the literal
	// findings grow exactly with the input.
	litBase, codeBase := countGated(t, v, small)
	litBig, codeBig := countGated(t, v, large)
	if codeBase != 0 || codeBig != 0 {
		t.Fatalf("%d and %d code-position findings survived; the gate is not active on the fixture",
			codeBase, codeBig)
	}
	if litBase != base || litBig != 4*base {
		t.Fatalf("literal-context findings %d and %d, want %d and %d: the match count must grow with "+
			"the input or the ratio below measures less work at the larger size", litBase, litBig, base, 4*base)
	}

	if raceEnabled {
		t.Logf("gated validator growth NOT measured under -race (see above); non-vacuity checked at %d and %d groups",
			base, 4*base)
		return
	}

	var outBase, outBig int
	g, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { outBase, _ = countGated(t, v, small) },
		func() { outBig, _ = countGated(t, v, large) })
	if err != nil {
		t.Fatalf("measuring the gated validator: %v", err)
	}
	if outBase != base || outBig != 4*base {
		t.Fatalf("timed scans produced %d and %d findings; the ratio would measure nothing", outBase, outBig)
	}
	assertGrowth(t, "the gated validator on a lexer-heavy .ts file", g)
}

func TestSourceLexerIsLinearOnManyLines(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}
	const base = 20000
	small, large := lexHeavyTSFile(base), lexHeavyTSFile(4*base)
	g := measureLexer(t, small, large)
	assertGrowth(t, "the lexer on many lines", g)
}

// The Python lexer, whose PEP 701 field handling is the one state machine that pushes a frame per
// construct, measured on its own: the JS fixtures above never reach it.
func TestSourceLexerIsLinearOnPythonFStringFields(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}
	build := func(n int) string {
		var b strings.Builder
		b.Grow(n * 120)
		for i := 0; i < n; i++ {
			b.WriteString(lexHeavyPyLine(i))
			b.WriteString("\n")
		}
		return b.String()
	}
	const base = 20000
	g := measureLexerIn(t, langPython, build(base), build(4*base))
	assertGrowth(t, "the lexer on Python f-string fields", g)
}

func TestSourceLexerIsLinearOnOneLongLine(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}
	build := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			// No newline anywhere: a block comment stands in for the line comment, which would
			// otherwise swallow the rest of the line.
			b.WriteString(strings.ReplaceAll(lexHeavyTSLine(i), "// n", "/* n"))
			b.WriteString(" */ ;   ")
		}
		return b.String()
	}
	const base = 20000
	g := measureLexer(t, build(base), build(4*base))
	assertGrowth(t, "the lexer on one long line", g)
}

// TestSourceLexerIsLinearOnHCLHeredocOpeners is the HCL target. Every `<<ID` in code position is
// checked as a heredoc opener, and the opener is only valid when nothing but whitespace follows the
// identifier on its line. A check that looks for that line's END before judging the bytes after
// the identifier pays the rest of the line for every rejected opener, so one long line of them is
// quadratic: `<<a ` x n read 4x per doubling, and a 3.2 MB .tf file took 18.1 s through the CLI
// against 0.86 s on main. A --validator-budget cannot stop it, because the lexer runs before the
// line loop polls the deadline: with SECRETS=2s the same file took 47.3 s (0.83 s with the fix).
// The other targets cannot see it, because none of them is HCL.
func TestSourceLexerIsLinearOnHCLHeredocOpeners(t *testing.T) {
	if testing.Short() {
		t.Skip("scaling measurement")
	}
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("x = 1\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "<<a%d \"s%d\" <<-b%d ", i, i, i)
		}
		b.WriteString("x\ny = <<EOT\nbody\nEOT\n")
		return b.String()
	}
	// 120,000 rejected openers on one 1.6MB line: the base reads ~8ms on the CPU clock, against
	// ~1s for the opener check that read to the end of the line.
	const base = 60000
	g := measureLexerIn(t, langHCL, build(base), build(4*base))
	assertGrowth(t, "the lexer on HCL heredoc openers", g)
}

// measureLexer times lexLiterals alone, after checking it lexes both inputs without failing open
// and marks a literal fraction that grows with them.
func measureLexer(t *testing.T, small, large string) perfguard.Growth {
	t.Helper()
	return measureLexerIn(t, langJS, small, large)
}

func measureLexerIn(t *testing.T, lang sourceLanguage, small, large string) perfguard.Growth {
	t.Helper()
	litBase, reason := lexLiterals(small, lang)
	if reason != "" {
		t.Fatalf("base fixture fails open: %s", reason)
	}
	litBig, reason := lexLiterals(large, lang)
	if reason != "" {
		t.Fatalf("big fixture fails open: %s", reason)
	}
	if nb, ng := popcount(litBase), popcount(litBig); nb == 0 || ng < 3*nb {
		t.Fatalf("literal bytes %d and %d: the lexer is not marking literals in proportion to the input", nb, ng)
	}
	var sink int
	g, err := perfguard.Measure(perfguard.DefaultPairs,
		func() { l, _ := lexLiterals(small, lang); sink += len(l) },
		func() { l, _ := lexLiterals(large, lang); sink += len(l) })
	if err != nil {
		t.Fatalf("measuring the lexer: %v", err)
	}
	if sink == 0 {
		t.Fatal("timed lexes produced nothing")
	}
	return g
}

func popcount(s literalSet) int {
	n := 0
	for _, w := range s {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	return n
}
