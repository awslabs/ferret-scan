// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The shipped configs' `internal_urls` patterns must be generic.
//
// `intellectual_property.internal_urls` tells the validator which hostnames count as an
// organisation's internal infrastructure. The shipped defaults are copied into every new
// user's config (`make install-config`, `docs/INSTALLATION.md`) and inherited by every
// profile that does not override the key. A pattern that names one organisation's own
// hosts therefore ships to every other organisation's users as an irrelevant detection,
// and publishes that organisation's hostnames in a public default.
//
// What a shipped default may name is decided by shape, so this test never has to list the
// hosts it rejects:
//
//   - a naming convention with no literal registrable domain (`.*\.internal\..*`,
//     `.*-dev\..*`, `localhost`, `127\..*`, `192\.168\..*`, `.*\.local`);
//   - a private-use top-level label (`.internal`, `.local`, `.lan`, `.corp`, `.test`, ...);
//   - a documented placeholder domain a user is expected to replace (`example.com`,
//     `company.com`, `startup.com`, ...);
//   - a public cloud provider's service endpoint (`amazonaws.com`, `windows.net`,
//     `googleapis.com`, ...), which is infrastructure every tenant shares.
//
// Anything else is some organisation's own hostname and belongs in that organisation's
// config, not in the one everybody gets.

// privateUseTLDs are top-level labels that cannot name a public registrable domain, so a
// pattern ending in one is a convention, not a specific organisation.
var privateUseTLDs = map[string]bool{
	"internal": true, "local": true, "lan": true, "corp": true, "intranet": true,
	"home": true, "test": true, "example": true, "invalid": true, "localhost": true,
}

// placeholderDomains are the documented stand-ins the shipped config uses in examples and
// profiles; INSTALLATION and configuration docs tell users to replace them.
var placeholderDomains = map[string]bool{
	"example.com": true, "company.com": true, "company-internal.com": true, "startup.com": true,
}

// cloudProviderDomains are shared public-cloud service endpoints. They identify a provider,
// not a tenant, so they are legitimate shipped defaults.
var cloudProviderDomains = map[string]bool{
	"amazonaws.com": true, "cloudfront.net": true,
	"windows.net": true, "azurewebsites.net": true, "azure-api.net": true, "azureedge.net": true, "azure.net": true,
	"googleapis.com": true, "appspot.com": true, "run.app": true, "cloudfunctions.net": true,
	"firebaseapp.com": true, "web.app": true,
}

// publicSecondLevel are second-level labels under which registrations happen one level
// down (`example.org.cn`, `example.co.uk`), so the registrable domain is three labels.
var publicSecondLevel = map[string]bool{"co": true, "com": true, "org": true, "net": true, "gov": true, "edu": true, "ac": true}

var (
	regexNoise = regexp.MustCompile(`\(\.\*\\\.\)\?|\[s\]\?|\.\*|[()?*+^$|\[\]]`)
	hostToken  = regexp.MustCompile(`[a-z0-9][a-z0-9.-]*[a-z0-9]`)
	alphaLabel = regexp.MustCompile(`^[a-z]+$`)
	escapedDot = strings.NewReplacer(`\.`, ".", `\/`, "/", `\-`, "-")
)

// registrableDomains returns the literal registrable domains a pattern names, lower-cased.
// A pattern that names none is a naming convention and is accepted outright.
func registrableDomains(pattern string) []string {
	s := strings.ToLower(escapedDot.Replace(pattern))
	s = regexNoise.ReplaceAllString(s, " ")
	seen := map[string]bool{}
	for _, tok := range hostToken.FindAllString(s, -1) {
		labels := strings.Split(strings.Trim(tok, "."), ".")
		if len(labels) < 2 {
			continue
		}
		tld := labels[len(labels)-1]
		if !alphaLabel.MatchString(tld) || privateUseTLDs[tld] {
			continue // an IP prefix, a bare word, or a private-use label
		}
		n := 2
		if len(labels) >= 3 && len(tld) == 2 && publicSecondLevel[labels[len(labels)-2]] {
			n = 3
		}
		seen[strings.Join(labels[len(labels)-n:], ".")] = true
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// internalURLPatterns walks the defaults and every profile of a loaded config.
func internalURLPatterns(cfg *Config) map[string][]string {
	out := map[string][]string{}
	collect := func(scope string, validators map[string]map[string]interface{}) {
		ip, ok := validators["intellectual_property"]
		if !ok {
			return
		}
		forEachPatternString(ip["internal_urls"], func(p string) {
			out[scope] = append(out[scope], p)
		})
	}
	collect("defaults", cfg.Validators)
	for _, name := range sortedProfileNames(cfg.Profiles) {
		collect("profiles."+name, cfg.Profiles[name].Validators)
	}
	return out
}

func TestShippedInternalURLPatternsNameNoSpecificOrganisation(t *testing.T) {
	var examined, conventions, placeholders, providers int
	for _, path := range shippedConfigs {
		t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatalf("LoadConfig(%s): %v", path, err)
			}
			for scope, patterns := range internalURLPatterns(cfg) {
				for _, p := range patterns {
					examined++
					domains := registrableDomains(p)
					if len(domains) == 0 {
						conventions++
						continue
					}
					for _, d := range domains {
						switch {
						case placeholderDomains[d]:
							placeholders++
						case cloudProviderDomains[d]:
							providers++
						default:
							t.Errorf("%s: internal_urls pattern %q names the registrable domain %q, which is one "+
								"organisation's own host. The shipped default reaches every user and every profile "+
								"that does not override internal_urls; move the pattern to that organisation's own "+
								"config, or use a generic convention such as `.*\\.internal\\..*`.", scope, p, d)
						}
					}
				}
			}
		})
	}

	// Non-vacuity: the walk must reach the patterns, and every accepting arm must have fired
	// on something real, or a config reshuffle could turn this into a test of nothing.
	if examined < 100 {
		t.Fatalf("only %d internal_urls patterns examined across the shipped configs; the walk is no longer reaching them", examined)
	}
	for name, n := range map[string]int{"naming conventions": conventions, "placeholder domains": placeholders, "cloud-provider endpoints": providers} {
		if n == 0 {
			t.Errorf("no shipped pattern was classified as %s; the shipped configs are expected to carry some, so the classifier's arm is untested", name)
		}
	}
	t.Logf("examined %d patterns: %d conventions, %d placeholder, %d provider", examined, conventions, placeholders, providers)
}

// TestRegistrableDomainsClassifier pins the classifier itself, so a future pattern shape
// cannot slip past it unnoticed in either direction.
func TestRegistrableDomainsClassifier(t *testing.T) {
	cases := []struct {
		pattern string
		want    []string
	}{
		// conventions and private-use labels: nothing registrable
		{`http[s]?:\/\/.*\.internal\..*`, nil},
		{`http[s]?:\/\/.*-internal\..*`, nil},
		{`http[s]?:\/\/.*internal-.*`, nil},
		{`http[s]?:\/\/localhost`, nil},
		{`http[s]?:\/\/127\..*`, nil},
		{`http[s]?:\/\/192\.168\..*`, nil},
		{`http[s]?:\/\/.*\.local`, nil},
		{`http[s]?:\/\/.*\.dev`, nil},
		{`http[s]?:\/\/.*\.bank\.internal`, nil},
		{`http[s]?:\/\/company-wiki\.internal`, nil},
		{`http[s]?:\/\/core-banking\..*`, nil},
		// placeholders and providers: registrable, and accepted by the allow-lists
		{`http[s]?:\/\/docs\.example\.com`, []string{"example.com"}},
		{`http[s]?:\/\/.*\.corp\.company\.com`, []string{"company.com"}},
		{`http[s]?:\/\/.*\.s3-.*\.amazonaws\.com`, []string{"amazonaws.com"}},
		{`http[s]?:\/\/.*\.blob\.core\.windows\.net`, []string{"windows.net"}},
		// an organisation's own hosts, in the shapes a config can spell them: a literal host, an
		// optional-subdomain prefix, a registrable domain under a public second level, a
		// hostname with a path tail
		{`http[s]?:\/\/intranet\.acme-corp\.com`, []string{"acme-corp.com"}},
		{`(.*\.)?acme-corp\.io`, []string{"acme-corp.io"}},
		{`(.*\.)?acme-corp\.co\.uk`, []string{"acme-corp.co.uk"}},
		{`http[s]?:\/\/.*\.acme-corp\.com\/.*`, []string{"acme-corp.com"}},
	}
	for _, c := range cases {
		got := registrableDomains(c.pattern)
		if fmt.Sprint(got) != fmt.Sprint(c.want) {
			t.Errorf("registrableDomains(%q) = %v, want %v", c.pattern, got, c.want)
		}
	}
}
