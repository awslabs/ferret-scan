// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package socialmedia

import (
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"testing"
)

// TestNoRegexIsCompiledPerCall is the guard on the fix for #606.
//
// This validator recompiled regexes inside per-match code paths, costing ~34 KB and 372 allocations for
// every finding — 207.8 MB for a 126 KB input, roughly 1,730x its size, with regexp.compile accounting
// for 522 MB of an 861 MB profile.
//
// Two shapes caused it, and both are checked, because neither is visible in the package's behaviour:
//
//   - regexp.MustCompile called inside a function body rather than at package scope
//   - the package-level regexp.MatchString(pattern, s), which COMPILES ITS PATTERN ON EVERY CALL.
//     That one reads like a plain predicate, which is exactly why it survived review.
//
// # Why this parses the AST instead of scanning lines
//
// The first version of this guard tracked "am I inside a function" by watching for `func ` and a bare
// `}`, and a mutation that re-inlined a MustCompile SURVIVED it: the first closing brace of any inner
// `if` block reset the flag, so most of every function body was invisible. Counting braces instead
// would fail differently — this file's patterns contain literal braces (`{22}`, `\{.*\}`) inside
// backticks, which no brace counter can distinguish from code.
//
// go/ast has neither problem. It is also why the assertion can be exact: a compile at package scope is
// the fix, a compile inside a FuncDecl is the defect, and nothing else needs judgement.
func TestNoRegexIsCompiledPerCall(t *testing.T) {
	const src = "validator.go"
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, src, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("cannot parse %s: %v — if the file moved this guard must move with it, or it silently "+
			"stops checking anything", src, err)
	}

	isRegexpCall := func(call *ast.CallExpr, fn string) bool {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != fn {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "regexp"
	}

	// The ONE function allowed to compile per call, with the reason. Everything else is a defect.
	//
	// isPartOfEmailAddress builds its pattern from regexp.QuoteMeta(domainPart), so the pattern differs
	// per match and there is no literal to hoist. It is also not on the hot path this issue is about: it
	// returns early unless the match starts with "@", which a URL match never does. Caching it would
	// need a decision about cache growth on attacker-influenced input, so it is left as-is deliberately
	// rather than by omission.
	dynamicOK := map[string]string{
		"isPartOfEmailAddress": "pattern embeds regexp.QuoteMeta(domainPart), so it is per-match by construction",
		// Configure runs ONCE per run, validating patterns that arrive from configuration. Compiling
		// there is the point -- it is how an invalid configured pattern is rejected instead of silently
		// never matching. The cost this rule exists to prevent is per-MATCH, not per-run.
		"Configure": "validates configured patterns once at startup, not per match",
		// These two ARE the compilation step, by name. They run at configure time and their results go
		// into the validator's own pattern cache, so compiling in them is what makes every later match
		// cheap. Exempting them is not a loophole: the mutation test confirms an inlined compile in a
		// per-match validator is still reported with these three in place.
		"compileOptimizedPattern":  "the configure-time compile helper whose result is cached",
		"compileAllowlistPatterns": "compiles the configured allowlist once, at configure time",
	}
	usedExemption := map[string]bool{}

	var offenders []string
	var funcsSeen, hoisted int

	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			// Package-level declarations: count the hoisted patterns for the non-vacuity check below.
			ast.Inspect(decl, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && isRegexpCall(call, "MustCompile") {
					hoisted++
				}
				return true
			})
			continue
		}
		funcsSeen++
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			pos := fset.Position(call.Pos())
			switch {
			case isRegexpCall(call, "MustCompile"), isRegexpCall(call, "Compile"):
				if _, ok := dynamicOK[fd.Name.Name]; ok {
					usedExemption[fd.Name.Name] = true
					return true
				}
				offenders = append(offenders, src+":"+itoa(pos.Line)+
					": regexp compile inside func "+fd.Name.Name)
			case isRegexpCall(call, "MatchString"):
				// regexp.MatchString is the PACKAGE function (it takes a pattern); re.MatchString on a
				// compiled value is a method call and is fine. The selector base being the `regexp`
				// identifier is what distinguishes them.
				offenders = append(offenders, src+":"+itoa(pos.Line)+
					": package-level regexp.MatchString inside func "+fd.Name.Name+
					" — compiles its pattern on EVERY call")
			}
			return true
		})
	}

	// NON-VACUITY. Without these, a rename or a parse quirk makes this pass by inspecting nothing.
	if funcsSeen < 50 {
		t.Fatalf("walked only %d function declarations in %s; the guard is not reading the real source",
			funcsSeen, src)
	}
	if hoisted < 10 {
		t.Errorf("found only %d package-level compiled patterns; the fix for #606 hoisted 16, so either "+
			"they were re-inlined or this guard is looking in the wrong place", hoisted)
	}

	// A stale exemption is worse than none: it silently permits a defect that no longer needs
	// permitting. If the exempt function stops compiling anything, the entry must go.
	for fn, why := range dynamicOK {
		if !usedExemption[fn] {
			t.Errorf("func %s is exempted from the no-per-call-compile rule (%q) but no longer compiles "+
				"anything — remove the exemption so the rule applies to it again", fn, why)
		}
	}

	for _, o := range offenders {
		t.Errorf("%s\n\tCompiling a regex in a function body costs ~34 KB and 372 allocations PER MATCH "+
			"(measured: 207.8 MB for a 126 KB input, 1,730x its size). Hoist it to the package-level var "+
			"block. If the pattern is genuinely dynamic, say so in a comment and cache it.", o)
	}
}

// TestHoistedPatternsStillMatchWhatTheyReplaced pins each hoisted pattern against the literal it was
// written as, so a later edit cannot silently widen or narrow a username rule.
//
// Widening is the dangerous direction: these decide whether a handle is accepted, so a looser pattern
// admits handles the platform would reject and turns them into findings.
func TestHoistedPatternsStillMatchWhatTheyReplaced(t *testing.T) {
	expect := []struct {
		re   *regexp.Regexp
		want string
	}{
		{reAlnumUnderscoreDash, `^[a-zA-Z0-9_-]+$`},
		{reAlnumUnderscoreDot, `^[a-zA-Z0-9_.]+$`},
		{reAlnumUnderscore, `^[a-zA-Z0-9_]+$`},
		{reAlnumDotUnderscoreDash, `^[a-zA-Z0-9._-]+$`},
		{reAlnumDotUnderscore, `^[a-zA-Z0-9._]+$`},
		{reAlnum, `^[a-zA-Z0-9]+$`},
		{reAlnumInnerDash, `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`},
		{reAlnumDash, `^[a-zA-Z0-9-]+$`},
		{reNotAlnumDotUnderscoreDash, `[^a-zA-Z0-9._-]`},
		{reAlnumUnderscoreSlashDash, `^[a-zA-Z0-9_/-]+$`},
		{reYouTubeChannelID, `^UC[a-zA-Z0-9_-]{22}$`},
		{reNotAlnumUnderscore, `[^a-zA-Z0-9_]`},
		{reNotAlnumDash, `[^a-zA-Z0-9-]`},
	}
	for _, c := range expect {
		if c.re == nil {
			t.Errorf("a hoisted pattern is nil; want %q", c.want)
			continue
		}
		if got := c.re.String(); got != c.want {
			t.Errorf("hoisted pattern is %q, want %q — a username rule changed shape", got, c.want)
		}
	}
	if len(expect) < 13 {
		t.Errorf("only %d patterns pinned; the hoist introduced 16", len(expect))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
