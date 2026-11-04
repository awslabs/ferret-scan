// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package replacement

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The family lists against the validators that emit the types (#864).
//
// The renderer's email arm listed three of the 24 email types, and nothing noticed, because no list
// was ever compared with what the validator reports. #136 found the same drift for card brands. This
// reads each multi-type validator's OWN type function from source, so a type added there and not
// here fails, and so does a type listed here that nothing emits. core.KnownTypes is no substitute: it
// omits 20 of the 21 platform types.

func TestFamilyListsMatchWhatTheValidatorsEmit(t *testing.T) {
	root := guardModuleRoot(t)

	t.Run("email", func(t *testing.T) {
		emitted := returnLiterals(t, filepath.Join(root, "internal/validators/email/validator.go"), "getEmailProviderType")
		if len(emitted) < 20 {
			t.Fatalf("harvested %d email types; the guard is not reading getEmailProviderType", len(emitted))
		}
		for _, typ := range emitted {
			if !isEmailType(typ, "zz.synthetic.0001@domain.test") {
				t.Errorf("the email validator emits %s, which does not render as an email", typ)
			}
		}
		assertSameSet(t, "emailTypes", keys(emailTypes), emitted)
		assertSameSet(t, "emailProviderTypes (tests)", emailProviderTypes, emitted)
	})

	t.Run("social media", func(t *testing.T) {
		src := filepath.Join(root, "internal/validators/socialmedia/validator.go")
		emitted := mapValueLiterals(t, src, "getPlatformDisplayName")
		if len(emitted) < 15 {
			t.Fatalf("harvested %d display names; the guard is not reading getPlatformDisplayName", len(emitted))
		}
		// identifyPlatform's names reach the Type through getPlatformDisplayName's fallback, which
		// upper-cases them and drops a "_patterns" suffix.
		for _, p := range returnLiterals(t, src, "identifyPlatform") {
			if p != "" {
				emitted = append(emitted, strings.ReplaceAll(strings.ToUpper(p), "_PATTERNS", ""))
			}
		}
		emitted = append(emitted, typeFieldLiterals(t, []string{src})...)
		emitted = unique(emitted)
		for _, typ := range emitted {
			if !isSocialMediaType(typ, "https://social.test/zz-synthetic") {
				t.Errorf("the social media validator emits %s, which does not render as a profile", typ)
			}
		}
		// SOCIAL_MEDIA is the family's own name: tests and per-family callers pass it.
		assertSameSet(t, "socialMediaTypes", keys(socialMediaTypes), append(emitted, "SOCIAL_MEDIA"))
	})

	t.Run("secrets", func(t *testing.T) {
		dir := filepath.Join(root, "internal/validators/secrets")
		files := goFiles(t, dir)
		emitted := typeFieldLiterals(t, files)
		emitted = append(emitted, returnLiterals(t, filepath.Join(dir, "validator.go"), "getSecretType")...)
		emitted = unique(emitted)
		if len(emitted) < 10 {
			t.Fatalf("harvested %d secret types; the guard is not reading the secrets validator", len(emitted))
		}
		for _, typ := range emitted {
			if !secretTypes[typ] {
				t.Errorf("the secrets validator emits %s, which synthetic does not send to the secret generator", typ)
			}
		}
		assertSameSet(t, "secretTypes", keys(secretTypes), append(emitted, "SECRETS"))
	})

	t.Run("credit card", func(t *testing.T) {
		emitted := returnLiterals(t, filepath.Join(root, "internal/validators/creditcard/validator.go"), "getCreditCardType")
		if len(emitted) < 5 {
			t.Fatalf("harvested %d card types; the guard is not reading getCreditCardType", len(emitted))
		}
		assertSameSet(t, "creditCardTypes", keys(creditCardTypes), emitted)
	})

	// The one Type two families share is decided by the value, and only that one.
	t.Run("overlap", func(t *testing.T) {
		var shared []string
		for typ := range emailTypes {
			if socialMediaTypes[typ] || secretTypes[typ] || creditCardTypes[typ] {
				shared = append(shared, typ)
			}
		}
		for typ := range socialMediaTypes {
			if secretTypes[typ] || creditCardTypes[typ] {
				shared = append(shared, typ)
			}
		}
		if len(shared) != 1 || shared[0] != "GITHUB" {
			t.Errorf("types in two families: %v, want [GITHUB]; a new one needs a value test like GITHUB's", shared)
		}
	})
}

// ---------- source readers ----------

func guardModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func parse(t *testing.T, path string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return f
}

func funcNamed(t *testing.T, f *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, d := range f.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("no function %s; the guard must follow the validator", name)
	return nil
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	return s, err == nil
}

// returnLiterals is every string literal function name returns directly.
func returnLiterals(t *testing.T, path, name string) []string {
	t.Helper()
	var out []string
	ast.Inspect(funcNamed(t, parse(t, path), name), func(n ast.Node) bool {
		if ret, ok := n.(*ast.ReturnStmt); ok {
			for _, r := range ret.Results {
				if s, ok := stringLit(r); ok {
					out = append(out, s)
				}
			}
		}
		return true
	})
	return unique(out)
}

// mapValueLiterals is every string value of the map literals inside function name.
func mapValueLiterals(t *testing.T, path, name string) []string {
	t.Helper()
	var out []string
	ast.Inspect(funcNamed(t, parse(t, path), name), func(n ast.Node) bool {
		if kv, ok := n.(*ast.KeyValueExpr); ok {
			if s, ok := stringLit(kv.Value); ok {
				out = append(out, s)
			}
		}
		return true
	})
	return unique(out)
}

// typeFieldLiterals is every `Type: "LITERAL"` in the files' composite literals.
func typeFieldLiterals(t *testing.T, files []string) []string {
	t.Helper()
	var out []string
	for _, p := range files {
		ast.Inspect(parse(t, p), func(n ast.Node) bool {
			kv, ok := n.(*ast.KeyValueExpr)
			if !ok {
				return true
			}
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Type" {
				if s, ok := stringLit(kv.Value); ok && s != "" {
					out = append(out, s)
				}
			}
			return true
		})
	}
	return unique(out)
}

func goFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

func unique(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func assertSameSet(t *testing.T, name string, got, want []string) {
	t.Helper()
	g, w := map[string]bool{}, map[string]bool{}
	for _, s := range got {
		g[s] = true
	}
	for _, s := range want {
		w[s] = true
	}
	for s := range w {
		if !g[s] {
			t.Errorf("%s is missing %s, which the validator emits", name, s)
		}
	}
	for s := range g {
		if !w[s] {
			t.Errorf("%s lists %s, which the validator does not emit; delete it", name, s)
		}
	}
}
