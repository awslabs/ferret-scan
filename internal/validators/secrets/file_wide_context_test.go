package secrets

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

// The tests in this file pin the two halves of the #785 fix, which together stop a
// whole-file heuristic from deciding whether a credential is reported.
//
// Before the fix, detectEnvironmentType matched its marker words as substrings over
// the lowercased file and the resulting verdict moved EVERY candidate in the file:
// test -25, development -15, production +10. So one comment saying "pinned to the
// latest image" ("latest" contains "test") took a GitHub token from HIGH 93 to
// MEDIUM 68, below the shipped pre-commit gate, and two hostnames containing
// "example" took a six-line credentials file to exactly 60 on every line, where the
// strict reporting threshold dropped all six: "No matches found", exit 0.
//
// The fix: (1) a candidate that carries its own evidence -- a typed provider literal
// or a secret keyword on its line -- no longer takes the file-wide test/dev penalty;
// it stays, unbounded, for entropy-only candidates, which are what the signal was
// written for. (2) Marker words are matched as whole tokens, so "latest" is not
// "test", "device" is not "dev" and "metadata.Producer" is not ".prod".
//
// Values are synthetic. The token-shaped ones are assembled at runtime through
// buildTestToken so that a static secret scanner reading this source does not
// report them.

// sixLineCredentialsFile is reproduction file A from #785: six lines, each holding a
// credential beside a secret keyword, two of them naming an "example" hostname. Each
// line alone reported one finding and any five of the six reported five; all six
// together reported nothing.
func sixLineCredentialsFile() string {
	v := "Zq8vTtq2Lm4pQ&x=9yHgRrWw7Kz"
	return ";password=" + v + "\n" +
		"    #db_password=" + v + "\n" +
		"#api_key=" + v + "\n" +
		"redirect: https://app.example/cb#access_token=Zq8vTtq2Lm4pQ&refresh_token=9yHgRrWw7KzAaBbCc&expires_in=3600\n" +
		"Server=db.example.internal;Password=" + v + ";Encrypt=true\n" +
		";password=" + v + "\n"
}

// findingKeys renders a match list as sorted "line:TYPE:text" strings, so two scans
// can be compared on WHAT was found independently of confidence.
func findingKeys(t *testing.T, v *Validator, content string) []string {
	t.Helper()
	matches, err := v.ValidateContent(content, "settings.txt")
	if err != nil {
		t.Fatalf("ValidateContent: %v", err)
	}
	keys := make([]string, 0, len(matches))
	for _, m := range matches {
		keys = append(keys, fmt.Sprintf("%d:%s:%s", m.LineNumber, m.Type, m.Text))
	}
	sort.Strings(keys)
	return keys
}

// TestTrailingNewlineDoesNotDecideWhetherAFileReports is the headline reproduction:
// the same six credential lines, with and without the final newline. Before the fix
// the file WITH the newline reported zero findings and the file without it reported
// six, because the newline was one more line in the Configuration ratio's
// denominator (2 of 7 is under the 30% that earns +15, 2 of 6 is over it) and the
// file-wide "test" penalty had already put every candidate at exactly 60, so the
// +15 was the difference between dropped and reported.
//
// With the penalty waived for these corroborated candidates the six report either
// way. Their confidence still differs between the two files (85 against 100): the
// Configuration ratio itself is item 3 of #785 and lives in internal/context,
// analyzer-wide, so it is fixed separately. This test owns the finding set, not the
// number.
func TestTrailingNewlineDoesNotDecideWhetherAFileReports(t *testing.T) {
	v := NewValidator()
	withNewline := sixLineCredentialsFile()
	withoutNewline := strings.TrimSuffix(withNewline, "\n")
	if withNewline == withoutNewline {
		t.Fatal("fixture must end with a newline for this test to mean anything")
	}

	a := findingKeys(t, v, withNewline)
	b := findingKeys(t, v, withoutNewline)
	if len(a) != 6 {
		t.Errorf("six credential lines with a trailing newline reported %d findings, want 6:\n%s",
			len(a), strings.Join(a, "\n"))
	}
	if strings.Join(a, "\n") != strings.Join(b, "\n") {
		t.Errorf("the trailing newline changed WHICH findings are reported.\nwith:\n%s\nwithout:\n%s",
			strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}

// TestFileWideMarkerDoesNotMoveCorroboratedFindingAcrossBand pairs each marker file
// with a control that differs only in the comment line. The credential, its line and
// its keyword are identical, so the findings must be identical too -- same count,
// same type, same confidence. Before the fix every marker file landed one band below
// its control: the "latest" comment cost the password 25 points (97 -> 72) and the
// GitHub token 25 points (93 -> 68), and the "device locale" comment cost 15 (85 ->
// 70) by way of the development verdict.
func TestFileWideMarkerDoesNotMoveCorroboratedFindingAcrossBand(t *testing.T) {
	v := NewValidator()
	const value = "Zq8vTtq2Lm4pQ9yHgRrWw7Kz"
	pat := buildTestToken("ghp_", "Q7mZ2vX9pL4kR8tB1nW6yC3hJ5dF0sG2aE7u")

	type pair struct {
		name, marker, control string
		wantHigh              bool // the control is HIGH, so the gate is what is at stake
	}
	cases := []pair{
		{
			name:     "latest above a password",
			marker:   "# Database settings\n# pinned to the latest image\n# rotate quarterly\npassword=" + value + "\n",
			control:  "# Database settings\n# see the wiki\n# rotate quarterly\npassword=" + value + "\n",
			wantHigh: true,
		},
		{
			name:     "example.com hostname above a password",
			marker:   "# Database settings\n# see https://wiki.example.com/setup\n# rotate quarterly\npassword=" + value + "\n",
			control:  "# Database settings\n# see the wiki\n# rotate quarterly\npassword=" + value + "\n",
			wantHigh: true,
		},
		{
			name:     "latest above a GitHub token",
			marker:   "# CI settings\n# pinned to the latest image\n# rotate quarterly\nGITHUB_TOKEN=" + pat + "\n",
			control:  "# CI settings\n# see the wiki\n# rotate quarterly\nGITHUB_TOKEN=" + pat + "\n",
			wantHigh: true,
		},
		{
			name:    "device and locale above a password",
			marker:  "# device locale settings\n# rotate quarterly\npassword=" + value + "\n",
			control: "# display settings\n# rotate quarterly\npassword=" + value + "\n",
		},
	}

	render := func(content string) []string {
		matches, err := v.ValidateContent(content, "settings.txt")
		if err != nil {
			t.Fatalf("ValidateContent: %v", err)
		}
		out := make([]string, 0, len(matches))
		for _, m := range matches {
			out = append(out, fmt.Sprintf("%d:%s:%.0f", m.LineNumber, m.Type, m.Confidence))
		}
		sort.Strings(out)
		return out
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, want := render(tc.marker), render(tc.control)
			if len(want) == 0 {
				t.Fatal("control file reported nothing; the comparison is vacuous")
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("a comment elsewhere in the file changed the findings.\nmarker:  %v\ncontrol: %v", got, want)
			}
			if tc.wantHigh {
				// --pre-commit-mode exits non-zero when the STRONGEST finding is HIGH, so
				// that is the number the gate turns on. (The token line also yields a
				// MEDIUM entropy twin on the 36-character tail after "ghp_", a different
				// span; it is the same on both files and not what is at stake here.)
				matches, _ := v.ValidateContent(tc.marker, "settings.txt")
				strongest := 0.0
				for _, m := range matches {
					if m.Confidence > strongest {
						strongest = m.Confidence
					}
				}
				if strongest < 90 {
					t.Errorf("strongest finding is %.0f, below HIGH: --pre-commit-mode with the shipped default exits 0 on this file",
						strongest)
				}
			}
		})
	}
}

// TestFileWideEnvironmentPenaltyIsWaivedOnlyForCorroboratedCandidates exercises the
// scoring function directly with an explicit environment verdict, so each branch of
// the waiver is pinned on its own, independently of how the verdict was reached.
func TestFileWideEnvironmentPenaltyIsWaivedOnlyForCorroboratedCandidates(t *testing.T) {
	v := NewValidator()
	const value = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2u"
	ci := contextInsightsForTest("")

	score := func(match, line, env string) (float64, map[string]bool) {
		return v.calculateEnhancedConfidenceWithCacheAndEnv(match, line, ci, false, env)
	}

	t.Run("keyword on the line waives the penalty", func(t *testing.T) {
		line := "db_password = " + value
		neutral, _ := score(value, line, "unknown")
		for _, env := range []string{"test", "development"} {
			got, checks := score(value, line, env)
			if got != neutral {
				t.Errorf("env %q moved a keyword-corroborated candidate from %.0f to %.0f", env, neutral, got)
			}
			if checks["test_environment_penalty"] || checks["dev_environment_penalty"] {
				t.Errorf("env %q recorded a penalty check on a corroborated candidate: %v", env, checks)
			}
		}
	})

	t.Run("provider literal waives the penalty", func(t *testing.T) {
		pat := buildTestToken("ghp_", "Q7mZ2vX9pL4kR8tB1nW6yC3hJ5dF0sG2aE7u")
		line := "x = " + pat // no secret keyword anywhere on the line
		neutral, checks := score(pat, line, "unknown")
		if !checks["specific_pattern"] {
			t.Fatal("fixture is not a typed provider literal; the test would not exercise that branch")
		}
		got, _ := score(pat, line, "test")
		if got != neutral {
			t.Errorf("test verdict moved a provider literal from %.0f to %.0f", neutral, got)
		}
	})

	t.Run("entropy-only candidate still takes the penalty", func(t *testing.T) {
		// Over 100 characters, so the base score is 75 rather than 85 and the -25
		// lands below the M24 cap (55) where it is observable; at base 85 the cap
		// would hide it (85-25 = 60 and 85 both clamp to 55).
		long := strings.Repeat(value, 4)
		if len(long) <= 100 {
			t.Fatalf("fixture is %d chars; needs > 100", len(long))
		}
		line := "checksum " + long // no secret keyword, no provider literal
		neutral, nchecks := score(long, line, "unknown")
		if nchecks["specific_pattern"] {
			t.Fatal("fixture matched a typed pattern; it must be entropy-only")
		}
		got, checks := score(long, line, "test")
		if !checks["test_environment_penalty"] {
			t.Errorf("test verdict did not record its penalty on an uncorroborated candidate: %v", checks)
		}
		if got >= neutral {
			t.Errorf("test verdict left an uncorroborated candidate at %.0f (neutral %.0f); the penalty must still apply there",
				got, neutral)
		}
	})

	t.Run("production boost still applies to corroborated candidates", func(t *testing.T) {
		line := "db_password = " + value
		neutral, _ := score(value, line, "unknown")
		got, checks := score(value, line, "production")
		if got != neutral+10 || !checks["prod_environment_boost"] {
			t.Errorf("production verdict: got %.0f (neutral %.0f), checks %v; want +10 with prod_environment_boost",
				got, neutral, checks)
		}
	})
}

// TestDetectEnvironmentTypeMatchesMarkersAsTokens pins the token rule on the words
// that produced the false verdicts measured in #785, and that the affix spellings
// in the production list ("prod-", "prod_", ".prod") still reach their targets.
func TestDetectEnvironmentTypeMatchesMarkersAsTokens(t *testing.T) {
	v := NewValidator()
	cases := []struct {
		content, want string
	}{
		// Substrings inside longer words no longer count.
		{"pinned to the latest image", "unknown"},       // was test, via "test"
		{"attestation report attached", "unknown"},      // was test
		{"device locale settings", "unknown"},           // was development, via "dev" and "local"
		{"metadata.Producer: Word 97", "unknown"},       // was production, via ".prod"
		{"delivery in three stages", "unknown"},         // was production/development, via "live" and "stage"
		{"the deployment finished", "unknown"},          // was production, via "deploy"
		{"product catalogue export", "unknown"},         // never matched; must stay that way
		{"localhost:5432 is the dev-db", "development"}, // real tokens still count
		// '_' is a token boundary, as everywhere in this tree (kwmatch).
		{"TEST_VALUE=1", "test"},
		{"unit_test fixture", "test"},
		{"backend_prod_cluster", "production"},
		// Affix markers are bounded on their word side only.
		{"db.prod.internal", "production"},
		{"my-prod-db", "production"},
		{"NODE_ENV=production", "production"},
		// A hostname is still an "example" token: the fix does not exclude URLs
		// (the second half of #785 item 2). What protects a credential beside it
		// is the waiver, not the verdict -- see the band test above.
		{"see https://wiki.example.com/setup", "test"},
	}
	for _, tc := range cases {
		if got := v.detectEnvironmentType(tc.content); got != tc.want {
			t.Errorf("detectEnvironmentType(%q) = %q, want %q", tc.content, got, tc.want)
		}
	}
}

// TestHasEnvMarker pins the boundary rule of the helper itself, in particular the
// asymmetric handling of affix markers that kwmatch cannot express.
func TestHasEnvMarker(t *testing.T) {
	cases := []struct {
		text, marker string
		want         bool
	}{
		{"latest", "test", false},
		{"unit_test", "test", true},
		{"test", "test", true},
		{"a test b", "test", true},
		{"device", "dev", false},
		{"dev-db", "dev", true},
		{"my-prod-db", "prod-", true},
		{"my-prod-", "prod-", true},
		{"reprod-x", "prod-", false}, // left side of an affix marker is still a boundary
		{"db.prod", ".prod", true},
		{"db.prod.x", ".prod", true},
		{"metadata.producer", ".prod", false}, // right side runs into a word
		{"x_prod_y", "prod_", true},
		{"node_env=production", "node_env=production", true},
		{"anything", "", false},
	}
	for _, tc := range cases {
		if got := hasEnvMarker(tc.text, tc.marker); got != tc.want {
			t.Errorf("hasEnvMarker(%q, %q) = %v, want %v", tc.text, tc.marker, got, tc.want)
		}
	}
}
