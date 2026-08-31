// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
)

// SignalSynthesizer is the default Explainer: a deterministic, dependency-free
// synthesis of signals the detection engine already computed and stored on
// Match.Metadata. It performs no inference and makes no network calls.
//
// It is intentionally NOT "AI": it re-phrases existing data (validation checks,
// vendor, context impact, file location) so a reviewer sees the "why" at the
// point of decision (pre-commit, PR comment, suppression file) instead of only
// in verbose scan output.
type SignalSynthesizer struct{}

// NewSignalSynthesizer returns the default explainer.
func NewSignalSynthesizer() *SignalSynthesizer { return &SignalSynthesizer{} }

// confidence tier thresholds, kept consistent with the text formatter
// (internal/formatters/text/formatter.go getConfidenceLevel).
const (
	highConfidence   = 90.0
	mediumConfidence = 60.0
)

// Explain implements Explainer. It never mutates m.
func (s *SignalSynthesizer) Explain(m detector.Match) Explanation {
	checks := validationChecks(m)
	inTestFile := looksLikeTestPath(m.Filename)

	return Explanation{
		Rationale:           s.rationale(m, checks, inTestFile),
		Verdict:             s.verdict(m, checks, inTestFile),
		DraftSuppressReason: s.draftSuppressReason(m, checks, inTestFile),
	}
}

// rationale builds a plain-language "why this matched" sentence from the
// signals the validator already recorded.
func (s *SignalSynthesizer) rationale(m detector.Match, checks map[string]bool, inTestFile bool) string {
	var parts []string

	subject := describeType(m)
	parts = append(parts, fmt.Sprintf("Flagged as %s", subject))

	// Positive structural checks that passed (e.g. luhn, length, prefix).
	if passed := passedChecks(checks); len(passed) > 0 {
		parts = append(parts, fmt.Sprintf("it passed %s", joinHuman(passed)))
	}

	// Context contribution, if the engine scored one.
	if impact, ok := metaFloat(m, "context_impact"); ok && impact != 0 {
		if impact > 0 {
			parts = append(parts, fmt.Sprintf("nearby context raised confidence by %.0f%%", impact))
		} else {
			parts = append(parts, fmt.Sprintf("nearby context lowered confidence by %.0f%%", -impact))
		}
	}

	// Signals that point toward test / placeholder data.
	var weak []string
	// Every validator's own test-check key, not just creditcard's "not_test" —
	// see testCheckKeys. Before this the "Why" sentence silently omitted the one
	// signal that mattered most for a reserved or published value.
	if hasFailedTestCheck(checks) {
		weak = append(weak, "it matches a known test/placeholder pattern")
	}
	if v, ok := checks["not_repeating"]; ok && !v {
		weak = append(weak, "it is a repeating/sequential value")
	}
	if inTestFile {
		weak = append(weak, fmt.Sprintf("it is in a test file (%s)", filepath.Base(m.Filename)))
	}
	if len(weak) > 0 {
		parts = append(parts, "but "+joinHuman(weak))
	}

	sentence := strings.Join(parts, "; ")
	if !strings.HasSuffix(sentence, ".") {
		sentence += "."
	}
	// Always anchor on the engine's confidence so the reader sees the basis.
	return fmt.Sprintf("%s (confidence %.0f%%, %s)", sentence, m.Confidence, tier(m.Confidence))
}

// testCheckKeys are the validation-check keys that mean "the validator itself
// judged this value to be test or example data". A false value under any of them
// is a test signal.
//
// There are seven names for one concept because each validator grew its own, and
// verdict() previously consulted only "not_test" — which creditcard uses and
// nothing else does. So every other validator's own test judgement was invisible
// here: a phone number in the NANP reserved fictional range came back
// `Not Test Number: false` in the rendered check list and `Verdict: likely_real`
// in the same output, and --explain then advised "REVIEW BEFORE SUPPRESSING".
//
// Consulting all seven rather than renaming them keeps this a display-layer fix.
// The keys are part of each finding's Metadata["validation_checks"], which is
// machine-readable output that consumers may already parse, so renaming them is a
// breaking change that belongs in its own PR.
var testCheckKeys = []string{
	"not_test",                  // creditcard
	"not_test_number",           // phone, ssn
	"not_test_email",            // email
	"not_test_ip",               // ipaddress
	"not_test_data",             // personname
	"not_example",               // passport
	"not_published_test_secret", // otp
}

// hasFailedTestCheck reports whether any validator-supplied test check failed.
func hasFailedTestCheck(checks map[string]bool) bool {
	for _, k := range testCheckKeys {
		if v, ok := checks[k]; ok && !v {
			return true
		}
	}
	return false
}

// verdict glosses the EXISTING confidence, nudged by explicit test signals.
// It is never an independent claim and never contradicts a HIGH finding.
func (s *SignalSynthesizer) verdict(m detector.Match, checks map[string]bool, inTestFile bool) Verdict {
	// A HIGH-confidence finding always surfaces as likely-real regardless of
	// weaker test hints — never talk a reviewer out of a real secret.
	if m.Confidence >= highConfidence {
		return VerdictLikelyReal
	}

	testSignal := inTestFile || hasFailedTestCheck(checks)

	switch {
	case testSignal && m.Confidence < mediumConfidence:
		return VerdictLikelyTest
	case m.Confidence >= mediumConfidence:
		return VerdictLikelyReal
	default:
		return VerdictUncertain
	}
}

// draftSuppressReason produces a human-reviewable justification for a generated
// suppression rule. It is a suggestion, never an auto-suppression.
func (s *SignalSynthesizer) draftSuppressReason(m detector.Match, checks map[string]bool, inTestFile bool) string {
	loc := "this location"
	if m.Filename != "" {
		loc = filepath.Base(m.Filename)
	}
	switch s.verdict(m, checks, inTestFile) {
	case VerdictLikelyTest:
		switch {
		case inTestFile:
			return fmt.Sprintf("Test fixture: %s in test file %s; not a real %s.", describeType(m), loc, m.Type)
		default:
			return fmt.Sprintf("Placeholder/example: %s matches a known test pattern; not a real %s.", describeType(m), m.Type)
		}
	case VerdictLikelyReal:
		return fmt.Sprintf("REVIEW BEFORE SUPPRESSING: %s in %s looks like real %s (confidence %.0f%%).", describeType(m), loc, m.Type, m.Confidence)
	default:
		return fmt.Sprintf("Confirm whether %s in %s is real before suppressing (confidence %.0f%%).", describeType(m), loc, m.Confidence)
	}
}

// --- helpers over the verified Metadata contract ---

// validationChecks pulls the map[string]bool the validators store under
// "validation_checks" (e.g. creditcard: luhn, length, not_test, ...).
func validationChecks(m detector.Match) map[string]bool {
	if m.Metadata == nil {
		return nil
	}
	if c, ok := m.Metadata["validation_checks"].(map[string]bool); ok {
		return c
	}
	return nil
}

// passedChecks returns the human-formatted names of structural checks that
// passed, excluding the negative-signal keys handled separately.
func passedChecks(checks map[string]bool) []string {
	if checks == nil {
		return nil
	}
	// The test-signal keys are excluded because verdict() already reports that concept, and
	// repeating them as "it passed the not test check" adds nothing. Built from testCheckKeys
	// rather than a second literal list: when only the bare "not_test" was skipped, every
	// validator using a variant name leaked its raw key into user-facing prose —
	// "it passed the not test ip check", "it passed the not test number check" — while the
	// same concept stayed correctly hidden for creditcard (#363).
	//
	// Deriving the set from testCheckKeys is what keeps the two in step. A new validator that
	// adds its own spelling to that list gets the prose handled at the same time, which is the
	// half that was missed when verdict() was widened to consult all seven.
	skip := map[string]bool{"not_repeating": true}
	for _, k := range testCheckKeys {
		skip[k] = true
	}
	var passed []string
	for name, ok := range checks {
		if ok && !skip[name] {
			passed = append(passed, humanizeCheck(name))
		}
	}
	sort.Strings(passed)
	return passed
}

// typeDisplay is how one finding type reads in prose: its display form, and the article that
// belongs in front of it.
type typeDisplay struct {
	display string
	// article is "a", "an", or "" for a mass or plural noun that takes none.
	article string
}

// typeDisplays maps a finding type to its prose form, for the types whose default rendering is
// wrong. Anything unlisted falls back to friendlyType plus an article chosen by spelling, which
// is correct for ordinary words.
//
// Two independent failures made a table necessary (#363), and they compound:
//
//   - friendlyType lowercases, so every acronym came out as prose: "a ssn", "an iban",
//     "an aws arn". These are the first words of every explanation.
//   - the article was chosen by startsWithVowel on that lowercased string — i.e. by SPELLING,
//     not pronunciation. "SSN" got "a" because it is spelled with a consonant though it is said
//     "ess-ess-en"; "US_STREET_ADDRESS" got "an" because it is spelled with a vowel though it is
//     said "you-ess".
//
// So the article is stored per entry rather than derived. Inferring pronunciation from spelling
// is the bug, and a heuristic over an initialism cannot be made reliable — "an SSN" and "a
// SWIFT code" differ only in how the letters are read aloud. Hardcoding is the honest fix, and
// the fallback keeps the table from having to be exhaustive.
//
// Grounded in the Type strings the validators actually emit, not invented: every entry below was
// produced by a real finding, and the set was checked against the golden corpus and against the
// types built from variables (cloudresources, secrets, email, socialmedia) which a grep for
// `Type: "..."` does not find.
//
// CARD BRANDS MUST NOT BE LISTED HERE. describeType prefers a vendor when one is present, and
// creditcard sets vendor == Type for every brand; the EqualFold comparison it uses then collapses
// "a Visa visa" to "a Visa card". A "JCB" entry here made t = "JCB card", which no longer equals
// the vendor, and the output became "a JCB JCB card" — caught by a surviving mutation, not by
// reading the code. The vendor path already renders these correctly.
var typeDisplays = map[string]typeDisplay{
	// Initialisms read letter by letter, so the article follows the letter's sound.
	"SSN":                 {"SSN", "an"}, // ess-ess-en
	"VIN":                 {"VIN", "a"},  // said as a word, "vin"
	"IBAN":                {"IBAN", "an"},
	"MRN":                 {"MRN", "an"},           // em-ar-en
	"NPI":                 {"NPI", "an"},           // en-pee-eye
	"GPS":                 {"GPS coordinate", "a"}, // jee-pee-ess
	"IP_ADDRESS":          {"IP address", "an"},    // eye-pee
	"DEA_NUMBER":          {"DEA number", "a"},     // dee-ee-ay
	"ABA_ROUTING":         {"ABA routing number", "an"},
	"SWIFT_BIC":           {"SWIFT/BIC code", "a"}, // said as the word "swift"
	"OTP_SECRET":          {"OTP secret", "an"},    // oh-tee-pee
	"OTPAUTH_URI":         {"otpauth URI", "an"},
	"MEDICARE_MBI":        {"Medicare MBI", "a"},
	"INSURANCE_MEMBER_ID": {"insurance member ID", "an"},
	"PO_BOX":              {"PO box", "a"}, // pee-oh

	// "US" is said "you-ess", a consonant sound, so it takes "a" despite the vowel spelling.
	"US_STREET_ADDRESS":   {"US street address", "a"},
	"US_BANK_ACCOUNT":     {"US bank account", "a"},
	"US_MILITARY_ADDRESS": {"US military address", "a"},
	"US_RURAL_ROUTE":      {"US rural route", "a"},

	// AWS is said "ay-double-you-ess" and ARN "arn", both vowel sounds.
	"AWS_ACCESS_KEY":        {"AWS access key", "an"},
	"AWS_SECRET_ACCESS_KEY": {"AWS secret access key", "an"},

	"PGP_PRIVATE_KEY": {"PGP private key", "a"},  // pee-jee-pee
	"SSH_PRIVATE_KEY": {"SSH private key", "an"}, // ess-ess-aitch

	// The remaining secrets subtypes. These came from comparing the FULL before/after phrase
	// set across every validator rather than from the issue, which listed only the ten it
	// happened to sample — "an api key or secret" was sitting unfixed in the branch output.
	"API_KEY_OR_SECRET":    {"API key or secret", "an"}, // ay-pee-eye
	"JWT_TOKEN":            {"JWT", "a"},                // jay-double-you-tee; "token" is the T
	"GOOGLE_CLOUD_API_KEY": {"Google Cloud API key", "a"},
	"STRIPE_API_KEY":       {"Stripe API key", "a"},
	"GITHUB_TOKEN":         {"GitHub token", "a"},
	"GITLAB_TOKEN":         {"GitLab token", "a"},
	"SLACK_TOKEN":          {"Slack token", "a"},
	"DOCKER_TOKEN":         {"Docker token", "a"},

	// A bare platform name is not a thing you can have one of; the noun is the profile.
	"SOCIAL_MEDIA": {"social media profile", "a"},
	// A cluster stands for SEVERAL profiles collapsed into one synthesized finding, so calling
	// it "a profile" understates what the reviewer is looking at.
	"SOCIAL_MEDIA_CLUSTER": {"group of social media profiles", "a"},

	// Cloud resource identifiers. These types are built from a VARIABLE rather than written as
	// a literal, so a grep for `Type: "..."` does not find them — they were collected from
	// cloudresources' own resourceType values and from the golden corpus, after the first
	// version of this table missed AWS_ARN and left "an aws arn" in place.
	"AWS_ARN":           {"AWS ARN", "an"},
	"ALIBABA_ARN":       {"Alibaba ARN", "an"},
	"AZURE_RESOURCE_ID": {"Azure resource ID", "an"},
	"GCP_RESOURCE_NAME": {"GCP resource name", "a"}, // jee-see-pee
	"IBM_CRN":           {"IBM CRN", "an"},          // eye-bee-em
	"OCI_OCID":          {"OCI OCID", "an"},         // oh-see-eye
	"CLOUD_RESOURCE_ID": {"cloud resource ID", "a"},
	"CLOUD_RESOURCES":   {"cloud resource", "a"},

	// Mass and plural nouns take no article at all. "an intellectual property" was the
	// worst-reading line in the audit.
	"INTELLECTUAL_PROPERTY": {"intellectual property", ""},
	"RECOVERY_CODES":        {"recovery codes", ""},
}

// emailProviderDisplay renders the display name for an email provider subtype.
//
// The EMAIL validator sets Type to the PROVIDER — GMAIL, ICLOUD, BUSINESS, PROTONMAIL and about
// twenty more — so an explanation read "Flagged as a business" or "Flagged as a gmail": a bare
// provider name with no noun after it.
//
// Handled structurally rather than by adding twenty rows to typeDisplays, because that list
// lives in the email validator and grows whenever a provider is added; a table here would go
// stale silently. Every email finding carries Metadata["email_provider"], so the family is
// identifiable without enumerating it.
//
// Only the casing is special-cased, for the few names that are not simply capitalised.
var emailProviderNames = map[string]string{
	"GMAIL":            "Gmail",
	"ICLOUD":           "iCloud",
	"PROTONMAIL":       "ProtonMail",
	"AOL":              "AOL",
	"MICROSOFT_365":    "Microsoft 365",
	"GOOGLE_WORKSPACE": "Google Workspace",
	"APPLE_CORPORATE":  "Apple corporate",
	"BUSINESS":         "business",
	"EDUCATIONAL":      "educational",
	"GOVERNMENT":       "government",
	"EMAIL":            "",
}

// describeEmail renders an email finding as "<Provider> email address", or plain
// "email address" when the provider adds nothing.
func describeEmail(provider string) string {
	name, known := emailProviderNames[provider]
	if !known {
		// An unlisted provider: title-case the token so a newly added one still reads as a
		// name rather than as prose. PROTON_MAIL -> "Proton Mail".
		parts := strings.Split(strings.ToLower(strings.ReplaceAll(provider, "_", " ")), " ")
		for i, w := range parts {
			if w != "" {
				parts[i] = strings.ToUpper(w[:1]) + w[1:]
			}
		}
		name = strings.Join(parts, " ")
	}
	if name == "" {
		return "an email address"
	}
	if startsWithVowel(name) {
		return "an " + name + " email address"
	}
	return "a " + name + " email address"
}

// socialPlatformNames renders a social-media platform as it is written, for the few whose
// casing is not simple capitalisation.
//
// SOCIAL_MEDIA has the same shape as EMAIL: the validator sets Type to the PLATFORM — TWITTER,
// GITHUB, TIKTOK and a dozen more — so an explanation read "Flagged as a twitter", a bare
// platform name with no noun (#363). Handled by family via Metadata["platform"] rather than by
// sixteen typeDisplays rows, because that list lives in the socialmedia validator and grows.
var socialPlatformNames = map[string]string{
	"github":    "GitHub",
	"linkedin":  "LinkedIn",
	"tiktok":    "TikTok",
	"youtube":   "YouTube",
	"whatsapp":  "WhatsApp",
	"bluesky":   "Bluesky",
	"snapchat":  "Snapchat",
	"pinterest": "Pinterest",
}

// describeSocial renders a social-media finding as "a <Platform> profile".
func describeSocial(platform string) string {
	name, known := socialPlatformNames[strings.ToLower(platform)]
	if !known {
		p := strings.ToLower(platform)
		if p == "" {
			return "a social media profile"
		}
		name = strings.ToUpper(p[:1]) + p[1:]
	}
	if startsWithVowel(name) {
		return "an " + name + " profile"
	}
	return "a " + name + " profile"
}

// describeType renders a readable subject, preferring vendor when present
// (e.g. "a Visa card"). It avoids redundancy when the vendor and the finding
// type are the same word (e.g. type "VISA" + vendor "Visa" -> "a Visa card",
// not "a Visa visa").
func describeType(m detector.Match) string {
	// EMAIL and SOCIAL_MEDIA both set Type to the SUBTYPE — the provider or the platform — so
	// both are handled by family rather than by a table row per value. Those two lists live in
	// their validators and grow; a table here would go stale silently.
	if provider, ok := metaString(m, "email_provider"); ok && provider != "" {
		return describeEmail(provider)
	}
	if platform, ok := metaString(m, "platform"); ok && platform != "" {
		return describeSocial(platform)
	}
	// typeDisplays is consulted AFTER the vendor branch, not before it. Assigning the display
	// form to t up here looked tidier and was unreachable: the only way t survives to be used is
	// via the vendor branch below, and no type carrying a vendor is in the table — asserted by
	// TestNoTypeDisplaysEntrySetsAVendor. It was also actively wrong while it lasted, turning
	// "a JCB card" into "a JCB JCB card" by breaking the EqualFold comparison.
	t := friendlyType(m.Type)
	if vendor, ok := metaString(m, "vendor"); ok && vendor != "" {
		if strings.EqualFold(vendor, t) {
			// Vendor already names the type. Add a generic noun for readability
			// only for card-like findings (the credit-card validator is the
			// one that sets a vendor matching the type); otherwise the vendor
			// name alone reads fine.
			if _, ok := m.Metadata["card_type"]; ok {
				return "a " + vendor + " card"
			}
			return "a " + vendor
		}
		return fmt.Sprintf("a %s %s", vendor, t)
	}
	if d, ok := typeDisplays[m.Type]; ok {
		if d.article == "" {
			return d.display
		}
		return d.article + " " + d.display
	}
	if startsWithVowel(t) {
		return "an " + t
	}
	return "a " + t
}

// friendlyType lowercases and de-snakes a finding type for prose.
func friendlyType(t string) string {
	return strings.ToLower(strings.ReplaceAll(t, "_", " "))
}

// humanizeCheck renders a validation_checks key for prose (mirrors the text
// formatter's formatCheckName, lowercased for mid-sentence use).
func humanizeCheck(check string) string {
	switch check {
	case "luhn":
		return "the Luhn checksum"
	case "mod97_checksum":
		return "the mod-97 checksum"
	case "length":
		return "the length check"
	case "entropy":
		return "the entropy check"
	case "vendor":
		return "vendor-prefix validation"
	case "prefix":
		return "the prefix check"
	case "npi_checksum":
		// The CMS NPI check digit: Luhn over "80840" + the 10-digit NPI. Named for what it
		// is rather than left to the fallback, which would render "the npi checksum check" —
		// a doubled noun with a lower-cased acronym (#537).
		return "the CMS NPI check digit"
	case "dea_checksum":
		return "the DEA check digit"
	case "mbi_format":
		// Deliberately "format", not "checksum": an MBI has no check digit, and claiming one
		// would tell a reviewer a proof exists that does not.
		return "the Medicare MBI positional format"
	case "medicare_context":
		// The fallback would render "the medicare context check", lower-casing a proper noun in
		// the same sentence that spells "Medicare MBI" correctly.
		return "the Medicare context check"

	// The negative and shape checks below need explicit prose because the fallback renders a
	// key as "the <words> check", which for a negated name produces "it passed the not phone
	// context check" — clumsy enough that a reviewer has to stop and parse it. Naming them as
	// EXCLUSIONS reads correctly in the "it passed ..." frame the caller builds (#537).
	case "not_phone_context":
		return "the phone-context exclusion"
	case "not_an_npi":
		return "the NPI-overlap exclusion"
	case "not_other_number_type":
		return "the other-number-type exclusion"
	case "not_a_more_specific_id":
		return "the more-specific-identifier exclusion"
	case "not_other_id_shape":
		return "the other-identifier-shape exclusion"
	case "letters_and_digits":
		return "the letters-and-digits shape check"
	case "mrn_label":
		return "the medical-record-number label check"
	case "insurance_label":
		return "the insurance label check"
	}
	return "the " + strings.ReplaceAll(check, "_", " ") + " check"
}

func tier(confidence float64) string { return strings.ToLower(tierUpper(confidence)) }

func tierUpper(confidence float64) string {
	switch {
	case confidence >= highConfidence:
		return "HIGH"
	case confidence >= mediumConfidence:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

// looksLikeTestPath reports whether a path is conventionally a test/fixture
// location. Conservative: only well-known markers.
func looksLikeTestPath(path string) bool {
	if path == "" {
		return false
	}
	p := strings.ToLower(filepath.ToSlash(path))
	base := strings.ToLower(filepath.Base(path))
	if strings.HasSuffix(base, "_test.go") || strings.HasPrefix(base, "test_") {
		return true
	}
	for _, marker := range []string{"/testdata/", "/test/", "/tests/", "/fixtures/", "/__tests__/", "/examples/"} {
		if strings.Contains(p, marker) {
			return true
		}
	}
	return false
}

func metaString(m detector.Match, key string) (string, bool) {
	if m.Metadata == nil {
		return "", false
	}
	v, ok := m.Metadata[key].(string)
	return v, ok
}

func metaFloat(m detector.Match, key string) (float64, bool) {
	if m.Metadata == nil {
		return 0, false
	}
	v, ok := m.Metadata[key].(float64)
	return v, ok
}

func startsWithVowel(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}

// joinHuman renders a slice as "a", "a and b", or "a, b, and c".
func joinHuman(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}
