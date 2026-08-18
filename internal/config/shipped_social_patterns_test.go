// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The shipped configs' social-media patterns must actually match the profile URLs people
// paste.
//
// Nothing in the test suite loaded a shipped config and exercised its regexes, so a
// pattern bug was invisible to every gate. The instagram entry required a TRAILING SLASH:
//
//	"(?i)https?://(?:www\\.)?instagram\\.com/[a-zA-Z0-9_.]+/"
//
// while every other platform omitted it. Measured on the shipped binary:
//
//	https://instagram.com/janedoe/   -> 1 finding
//	https://instagram.com/janedoe    -> 0 findings, "No matches found."
//
// The unslashed form is what a browser address bar shows and what people paste, so the
// common case was the undetected one — and by the sink rule an undetected value is an
// unredacted one: it passes through --enable-redaction in cleartext with no disclosure.
// See #343, found while fixing #289.
//
// The inconsistency with its siblings was the tell, which is what this test encodes:
// a platform pattern that only matches one of the two forms is almost certainly an
// anchoring mistake rather than a deliberate choice.

// shippedConfigs are the files a user actually gets. config.yaml is the repo's tracked
// config; examples/ferret.yaml is what `make install-config` installs.
var shippedConfigs = []string{
	filepath.Join("..", "..", "config.yaml"),
	filepath.Join("..", "..", "examples", "ferret.yaml"),
	filepath.Join("..", "..", "examples", "ferret-windows.yaml"),
}

// profileURLs are canonical profile links per platform, in BOTH the slashed and unslashed
// form. A platform must match both: the character class stops at "/", so a pattern with no
// trailing slash matches either, while one that requires the slash matches only the first.
var profileURLs = map[string][]string{
	"instagram": {"https://instagram.com/janedoe", "https://instagram.com/janedoe/"},
	"twitter":   {"https://twitter.com/janedoe", "https://twitter.com/janedoe/"},
	"linkedin":  {"https://linkedin.com/in/janedoe", "https://linkedin.com/in/janedoe/"},
	"facebook":  {"https://facebook.com/janedoe", "https://facebook.com/janedoe/"},
}

func TestShippedSocialMediaPatternsMatchCanonicalProfileURLs(t *testing.T) {
	for _, path := range shippedConfigs {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig(%s): %v", path, err)
			}
			sm, ok := cfg.Validators["social_media"]
			if !ok {
				t.Skipf("%s defines no social_media validator config", path)
			}
			raw, ok := sm["platform_patterns"].(map[string]any)
			if !ok || len(raw) == 0 {
				t.Skipf("%s defines no platform_patterns", path)
			}

			// Non-vacuity: the platforms we assert on must actually be present, or this
			// test would silently assert nothing after a config rename.
			var checked int
			for platform, urls := range profileURLs {
				patterns, present := raw[platform]
				if !present {
					continue
				}
				list, ok := patterns.([]any)
				if !ok || len(list) == 0 {
					t.Errorf("%s: platform %q has no patterns", path, platform)
					continue
				}
				checked++

				for _, url := range urls {
					var matched bool
					for _, p := range list {
						expr, ok := p.(string)
						if !ok {
							t.Errorf("%s: platform %q has a non-string pattern %v", path, platform, p)
							continue
						}
						re, err := regexp.Compile(expr)
						if err != nil {
							// A pattern Go's RE2 cannot compile is silently dropped at
							// runtime, so the platform stops detecting with no warning.
							t.Errorf("%s: platform %q pattern %q does not compile: %v",
								path, platform, expr, err)
							continue
						}
						if re.MatchString(url) {
							matched = true
							break
						}
					}
					if !matched {
						t.Errorf("%s: platform %q matches none of its patterns against %q.\n"+
							"Both the slashed and unslashed profile form must match — the "+
							"unslashed one is what a browser shows and what people paste, and "+
							"an undetected value is also an unredacted one.",
							path, platform, url)
					}
				}
			}
			if checked == 0 {
				t.Errorf("%s: none of the expected platforms (%v) were found in "+
					"platform_patterns — this test asserted nothing",
					path, keysOf(profileURLs))
			}
		})
	}
}

// No shipped platform pattern may require a trailing slash.
//
// Asserted separately from the match test because it names the specific mistake, so a
// reviewer seeing this fail knows immediately what to look for rather than deducing it
// from a failed URL match.
func TestNoShippedSocialPatternRequiresATrailingSlash(t *testing.T) {
	for _, path := range shippedConfigs {
		cfg, err := LoadConfig(path)
		if err != nil {
			t.Fatalf("LoadConfig(%s): %v", path, err)
		}
		sm, ok := cfg.Validators["social_media"]
		if !ok {
			continue
		}
		raw, ok := sm["platform_patterns"].(map[string]any)
		if !ok {
			continue
		}
		for platform, patterns := range raw {
			list, ok := patterns.([]any)
			if !ok {
				continue
			}
			for _, p := range list {
				expr, ok := p.(string)
				if !ok {
					continue
				}
				// A character class immediately followed by "/" at the END of the pattern
				// makes the slash mandatory, which excludes the canonical form.
				if strings.HasSuffix(expr, "]+/") || strings.HasSuffix(expr, "]*/") {
					t.Errorf("%s: platform %q pattern %q ends with a mandatory trailing "+
						"slash, so the canonical profile URL without one never matches",
						path, platform, expr)
				}
			}
		}
	}
}

func keysOf(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
