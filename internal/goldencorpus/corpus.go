// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package goldencorpus provides the behavior-locking regression net for the v2
// consolidation (Phase 0 in docs/proposals/V2_ARCHITECTURE.md). It scans a
// curated set of representative and adversarial inputs through the REAL scan and
// formatting paths (core.ScanContent + formatters.Export + pkg/redact) and
// snapshots the output to committed golden files.
//
// The purpose is NOT to assert that any particular detection is "correct" — it
// is to assert that detection, confidence scoring, output formats, and redaction
// do not CHANGE as the internal architecture is consolidated. Any diff against a
// golden file during a refactor is a signal to stop and confirm the change is
// intended (then regenerate with UPDATE_GOLDEN=1), rather than a silent
// behavioral regression.
//
// Determinism: the scan pipeline aggregates matches in goroutine-completion
// order, and a couple of formatters embed wall-clock timestamps. This package
// canonicalizes match order (CanonicalSort) and normalizes timestamps
// (NormalizeOutput) so snapshots are byte-stable across runs.
package goldencorpus

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/pkg/redact"
)

// Case is one corpus entry: a named input plus the validator set to run against
// it. Keeping checks explicit per-case (rather than always "all") makes each
// snapshot small, focused, and stable — adding a new validator does not churn
// every unrelated golden file.
type Case struct {
	// Name is a filesystem-safe identifier used for the golden filename.
	Name string
	// Description documents what behavior this case is meant to lock.
	Description string
	// Checks is the validator set to enable (nil/empty means "all").
	Checks []string
	// Input is the content scanned via core.ScanContent.
	Input string
}

// Cases is the curated corpus. It deliberately mixes:
//   - representative positives (real-shaped secrets/PII that SHOULD match),
//   - negatives / known false-positive guards (test values that must NOT match),
//   - adversarial / pathological shapes (single very long line, many matches,
//     dense punctuation) that exercise the DoS-prone scanning paths.
//
// SSNs use realistic, non-denylisted values (e.g. 449-87-4100); well-known fakes
// like 123-45-6789 are intentionally used only where a NEGATIVE is expected.
var Cases = []Case{
	{
		Name:        "mixed_pii_basic",
		Description: "Representative multi-type document: email, phone, AWS key, valid SSN, credit card.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD"},
		Input: "Contact john.doe@example.com or call 212-555-0142.\n" +
			"AWS key AKIAIOSFODNN7EXAMPLE in the config.\n" +
			"SSN 449-87-4100 on file.\n" +
			"Card 4532-0151-1283-0366 expires soon.\n",
	},
	{
		Name:        "email_variants",
		Description: "Business vs personal-domain emails; locks EMAIL confidence tiers.",
		Checks:      []string{"EMAIL"},
		Input: "support@acme-corp.com\n" +
			"alice@gmail.com\n" +
			"no-reply@internal.example.org\n" +
			"not.an.email.at.all\n",
	},
	{
		Name:        "ssn_positive_and_denylisted",
		Description: "A realistic SSN must match; the canonical fake 123-45-6789 must be rejected as a false positive.",
		Checks:      []string{"SSN"},
		Input: "real: 449-87-4100\n" +
			"fake-should-not-match: 123-45-6789\n" +
			"sequential-should-not-match: 111-11-1111\n",
	},
	{
		Name:        "creditcard_brands",
		Description: "Luhn-valid cards across brands; locks brand classification in Match.Type.",
		Checks:      []string{"CREDIT_CARD"},
		Input: "visa 4532015112830366\n" +
			"mastercard 5425233430109903\n" +
			"amex 374245455400126\n" +
			"invalid-luhn 4532015112830367\n",
	},
	{
		Name: "creditcard_phone_overlap",
		Description: "A space-separated card the PHONE validator also fires on (its trailing " +
			"groups look like a phone number). Locks the overlap fix: format-preserving " +
			"redaction must mask the whole card including the BIN (**** **** **** 0366), " +
			"not just the head — the contained PHONE match must not win the tail and hide " +
			"the card's un-redacted BIN. A standalone phone on the next line must still redact.",
		Checks: []string{"CREDIT_CARD", "PHONE"},
		Input: "card 4532 0151 1283 0366 here\n" +
			"call 212-555-0142 today\n",
	},
	{
		Name:        "secrets_aws",
		Description: "AWS access key + secret-key shaped strings; locks SECRETS detection and confidence.",
		Checks:      []string{"SECRETS"},
		Input: "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n" +
			"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
			"just_a_word=hello\n",
	},
	{
		Name:        "ip_addresses",
		Description: "Public vs private/loopback IPv4; locks IP_ADDRESS context handling.",
		Checks:      []string{"IP_ADDRESS"},
		Input: "server 203.0.113.42 reached\n" +
			"localhost 127.0.0.1 ignored-ish\n" +
			"private 10.0.0.5 internal\n" +
			"version string 1.2.3.4 maybe\n",
	},
	{
		Name:        "negative_clean_text",
		Description: "Ordinary prose with no secrets; the no-finding case must stay empty.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD", "IP_ADDRESS"},
		Input: "The quick brown fox jumps over the lazy dog.\n" +
			"Meeting at 3pm to discuss the roadmap for version 2.\n",
	},
	{
		Name:        "adversarial_single_long_line",
		Description: "One very long single line (~8KB) with an embedded email — exercises the per-line scanning path the audit flagged as O(n^2)-prone. Locks (a) that the scan completes (with bounded execution it cannot hang) and (b) the CURRENT detection outcome on this shape, whatever it is, so a future refactor that changes long-line handling is flagged.",
		Checks:      []string{"EMAIL"},
		Input:       longLineWithEmbeddedEmail(),
	},
	{
		Name:        "adversarial_many_matches",
		Description: "Twelve emails across twelve lines — exercises high match counts and aggregation ordering without bloating the committed fixtures.",
		Checks:      []string{"EMAIL"},
		Input:       manyEmails(12),
	},
	{
		Name:        "cloud_resources_test_context",
		Description: "Same AWS IAM-role ARN on two lines: one clean, one carrying a same-line test-context keyword (\"example\"). Locks the CLOUD_RESOURCES negative-keyword penalty (-20, per-line/local), the behavior the per-line hasKeywordToken hoist must preserve.",
		Checks:      []string{"CLOUD_RESOURCES"},
		Input: "prod arn:aws:iam::123456789012:role/PaymentsAdmin\n" +
			"example arn:aws:iam::123456789012:role/PaymentsAdmin\n",
	},
	{
		Name: "new_validators_display_formats",
		Description: "Card/print display formats for the new validators: dashed MBI (as printed " +
			"on Medicare cards), space-grouped IBAN (invoice format), dashed DL, dotted and " +
			"2-digit-year DOB, ordinal street name, highway with route number, lowercase address " +
			"with keyword context. Locks the separator-normalization and format-coverage behavior " +
			"added after the recall-gap audit.",
		Checks: []string{"MEDICAL_ID", "BANK_ACCOUNT", "DRIVERS_LICENSE", "DATE_OF_BIRTH", "PHYSICAL_ADDRESS"},
		Input: "medicare beneficiary 1EG4-TE5-MK73 on card\n" +
			"pay to IBAN DE89 3704 0044 0532 0130 00 per invoice\n" +
			"driver's license D123-4567-8901 verified\n" +
			"patient dob 3/14/87 and sibling born March 14th, 1987\n" +
			"admission date of birth 03.14.1987 on form\n" +
			"ship to 123 42nd Street, New York, NY 10036\n" +
			"mailing address 1234 US Highway 61\n" +
			"deliver to 742 evergreen terrace, springfield, il 62704\n",
	},
	{
		Name: "validator_coverage_expansion",
		Description: "Formats added in the coverage-expansion pass: military APO/FPO (PSC/Unit + " +
			"Box + APO/FPO/DPO + AA/AE/AP + ZIP), rural routes (full and Box-anchored short " +
			"forms), apostrophe/hyphen street names, NJ (1L+14D) and WI (1L+13D) licenses, and " +
			"lowercase base32 OTP secrets (keyword-gated, word-guarded). Decoy lines lock the " +
			"guards: RR-as-abbreviation stays LOW, APO-as-word and prose apostrophes stay out, " +
			"lowercase English prose is not a secret.",
		Checks: []string{"PHYSICAL_ADDRESS", "DRIVERS_LICENSE", "OTP"},
		Input: "mail to PSC 1523, Box 25, APO AE 09009 promptly\n" +
			"mailing Rural Route 3 Box 88, Roanoke, VA 24012\n" +
			"send to 123 O'Brien St, Boston, MA 02101\n" +
			"deliver 456 King-Smith Rd today\n" +
			"new jersey driver license D12345678901234 on record\n" +
			"wisconsin dl J1234567890123 verified\n" +
			"2fa secret: jbswy3dpehpk3pxp lowercase\n" +
			"The package weighs RR 4 lbs on the scale\n" +
			"APO is an abbreviation for Apollo\n" +
			"123 O' clock reading on the dial\n" +
			"the authentication protocol requires base configuration\n",
	},
	{
		Name: "new_validators_decoys",
		Description: "Shape-valid values in PII-contradicting context for the new validators' " +
			"broadest patterns: SSN-shaped and date-shaped tokens near DL keywords, a version " +
			"string near DOB keywords, test-context IBAN/routing numbers, an MBI shape without " +
			"medicare context, and prose that embeds lowercase suffix words. Locks the " +
			"suppression behavior (shape guards, denylists, keyword gates) that keeps the " +
			"normalization passes from widening the false-positive surface.",
		Checks: []string{"MEDICAL_ID", "BANK_ACCOUNT", "DRIVERS_LICENSE", "DATE_OF_BIRTH", "PHYSICAL_ADDRESS"},
		Input: "license check ssn 123-45-6789 cross-reference\n" +
			"license issued 12-31-1987 expires 12-31-2031\n" +
			"zip on license record 12345-6789\n" +
			"upgrade dob service to version 2.14.87 build\n" +
			"test iban DE89 3704 0044 0532 0130 00 example fixture\n" +
			"routing 021000021 test transfer\n" +
			"shape only 1EG4-TE5-MK73 without context\n" +
			"5 people way too many for the room\n" +
			"3 items in way of progress\n",
	},
	{
		Name: "context_decoys_original",
		Description: "Real-context vs decoy-context pairs for the ORIGINAL validators (SSN, " +
			"PHONE, CREDIT_CARD, EMAIL): the same shaped value framed as PII on one line and " +
			"as a part number / error code / SKU on another. Locks CURRENT context-scoring " +
			"behavior including known warts — e.g. SSN-shaped part numbers today score the " +
			"same as real SSNs (no context discrimination). A future context-scoring change " +
			"must show up here as an intentional diff, not slip through silently.",
		Checks: []string{"SSN", "PHONE", "CREDIT_CARD", "EMAIL"},
		Input: "employee ssn 449-87-4100 on file\n" +
			"part number 449-87-4100 from the catalog\n" +
			"requisition 526-33-8210 approved for shipment\n" +
			"call us at 212-555-0142 today\n" +
			"error code 212-555-0142 in the diagnostics log\n" +
			"SKU 313-555-0175 restocked\n",
	},
	{
		Name: "context_decoys_personname",
		Description: "Multi-line document (PERSON_NAME is document-length sensitive) mixing " +
			"real person references with decoy name-shaped strings: geographic features " +
			"(Jordan River), products (Lincoln Continental), and companies (Amazon Web " +
			"Services) that share surface shape with person names. Locks CURRENT " +
			"disambiguation behavior, whatever it is, so future name-context changes " +
			"surface as intentional diffs.",
		Checks: []string{"PERSON_NAME"},
		Input: "Contact Maria Delgado for approval\n" +
			"the Jordan River flows north\n" +
			"Please forward the report to James Whitfield by Friday\n" +
			"Lincoln Continental parked outside\n" +
			"Sarah Okonkwo will present the quarterly results\n" +
			"Amazon Web Services launched\n" +
			"Schedule a review with Daniel Moreau next week\n" +
			"the Hudson Valley orchard shipped apples\n" +
			"Priya Raghavan approved the budget request\n" +
			"Ford Mustang sales rose sharply\n",
	},
}

// FileCase is one file-based corpus entry. Unlike Case (which scans an in-memory
// string via core.ScanContent), a FileCase is written to a real file on disk and
// scanned via core.ScanFile — exercising the worker pool, the FileRouter,
// CanProcessFile/CanContainMetadata routing, and (for metadata-bearing types)
// the dual-path metadata branch that core.ScanContent skips entirely.
type FileCase struct {
	// Name is a filesystem-safe identifier used for the golden filename.
	Name string
	// Description documents what file-path behavior this case locks.
	Description string
	// Checks is the validator set to enable (nil/empty means "all").
	Checks []string
	// Filename is the basename written into the temp dir. Its EXTENSION drives
	// FileRouter routing (text vs metadata-capable), so it is significant.
	Filename string
	// Content is written verbatim to the file as bytes.
	Content []byte
	// Tier1Parity, when true, asserts that file-mode findings equal
	// content-mode (core.ScanContent) findings for the same bytes — the
	// file-path-specific machinery must not change WHICH matches are produced
	// for plain-text/source inputs. Only valid for non-metadata file types.
	Tier1Parity bool
	// EnablePreprocessors must be true for binary/metadata-capable file types
	// (e.g. .wav): CanProcessFile rejects binary documents unless preprocessors
	// are enabled. Plain-text/source cases leave this false (the CLI default).
	EnablePreprocessors bool
}

// FileCases is the Tier 1 + Tier 2 file corpus.
//
//	Tier 1 (text/source): fully deterministic, no binaries, no external
//	  extraction libs. Exercises ScanFile -> worker pool -> FileRouter ->
//	  non-metadata dual-path branch. Asserts file-mode == content-mode parity.
//	Tier 2 (metadata-bearing, generated in-test): a deterministically
//	  constructed file whose metadata branch can be exercised without
//	  committing an opaque binary. See metadata determinism note in NormalizeOutput.
//
// Snapshotting third-party PDF/Office *extraction byte-output* is intentionally
// OUT OF SCOPE (it would lock library behavior, not ferret-scan's, and require
// committed binaries). See README.md "What it does NOT cover".
var FileCases = []FileCase{
	// --- Tier 1: text / source-code files (deterministic, parity-checked) ---
	{
		Name:        "file_txt_mixed_pii",
		Description: "Tier 1: a .txt file with mixed PII through the full ScanFile/worker-pool path. Parity-checked against ScanContent.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD"},
		Filename:    "notes.txt",
		Content: []byte("Contact john.doe@example.com or call 212-555-0142.\n" +
			"AWS key AKIAIOSFODNN7EXAMPLE in the config.\n" +
			"SSN 449-87-4100 on file.\n" +
			"Card 4532-0151-1283-0366 expires soon.\n"),
		Tier1Parity: true,
	},
	{
		Name:        "file_source_code_secrets",
		Description: "Tier 1: a .go source file with an embedded secret + email — locks source-code routing (must NOT take the metadata path).",
		Checks:      []string{"SECRETS", "EMAIL"},
		Filename:    "config.go",
		Content: []byte("package config\n\n" +
			"// owner: ops@example.com\n" +
			"const AWSKey = \"AKIAIOSFODNN7EXAMPLE\"\n" +
			"const Secret = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n"),
		Tier1Parity: true,
	},
	{
		Name:        "file_json_config",
		Description: "Tier 1: a .json config with PII — locks structured-text routing and parity.",
		Checks:      []string{"EMAIL", "IP_ADDRESS"},
		Filename:    "settings.json",
		Content: []byte("{\n" +
			"  \"admin_email\": \"admin@example.com\",\n" +
			"  \"server_ip\": \"203.0.113.42\",\n" +
			"  \"note\": \"no secrets here\"\n" +
			"}\n"),
		Tier1Parity: true,
	},
	{
		Name:        "file_negative_clean",
		Description: "Tier 1: a clean .txt with no PII — file-mode no-finding case must stay empty.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "SSN", "CREDIT_CARD", "IP_ADDRESS"},
		Filename:    "readme.txt",
		Content:     []byte("The quick brown fox jumps over the lazy dog.\nNothing sensitive here.\n"),
		Tier1Parity: true,
	},
	// --- Tier 2: metadata-bearing file, generated deterministically in-test ---
	// A CSV is plain text (so no external extractor / no binary), but exercises
	// the FileRouter's metadata-capability decision and the dual-path routing
	// for a "data" file type. This locks the routing branch without committing
	// an opaque binary. (PDF/Office/image extraction byte-output is out of scope
	// per the README; here we lock our routing + validation, not a 3rd-party lib.)
	{
		Name:        "file_csv_tabular_pii",
		Description: "Tier 2: a .csv with PII columns — exercises FileRouter routing for a data file and locks detection through ScanFile.",
		Checks:      []string{"EMAIL", "SSN", "CREDIT_CARD"},
		Filename:    "people.csv",
		Content: []byte("name,email,ssn,card\n" +
			"Alice,alice@example.com,449-87-4100,4532015112830366\n" +
			"Bob,bob@example.org,529-11-2233,5425233430109903\n"),
		Tier1Parity: false, // CSV may route differently than raw plaintext; lock file-mode output only
	},
	// --- Tier 2: TRUE metadata/dual-path branch coverage via a synthesized WAV ---
	// This is the case that actually exercises the metadata branch core.ScanContent
	// skips: a .wav routes to the audio_metadata preprocessor (pure-Go RIFF/LIST
	// parser — no external binary, no committed fixture), whose extracted INFO
	// fields feed the METADATA validator through the dual-path bridge. PII is
	// embedded in the INFO tags (IART=artist, ICMT=comment). The WAV is built
	// deterministically in-test; its ModTime is normalized in the snapshot.
	{
		Name:        "file_wav_metadata_pii",
		Description: "Tier 2 (the real one): synthesized .wav with PII in INFO tags — exercises the audio_metadata preprocessor + METADATA validator + dual-path branch that ScanContent cannot reach.",
		Checks:      []string{"EMAIL", "PHONE", "SECRETS", "METADATA"},
		Filename:    "clip.wav",
		Content: BuildWAVWithInfo(map[string]string{
			"INAM": "Quarterly Review Recording",
			"IART": "john.doe@example.com",
			"ICMT": "contact 212-555-0142 or AKIAIOSFODNN7EXAMPLE",
		}),
		Tier1Parity:         false, // metadata branch has no content-mode equivalent
		EnablePreprocessors: true,  // required: .wav is a binary document
	},
}

// BuildWAVWithInfo synthesizes a minimal but valid WAV file (RIFF/WAVE + fmt +
// LIST/INFO + data) carrying the given INFO tags, in a DETERMINISTIC field order
// (sorted by id) so the bytes are stable across runs. This lets the corpus
// exercise the audio metadata extraction + dual-path validation branch without
// committing an opaque binary fixture. Supported INFO ids include INAM (title),
// IART (artist), ICMT (comment), ICOP (copyright) — see the WAV extractor.
func BuildWAVWithInfo(info map[string]string) []byte {
	// fmt chunk: 16-byte PCM, mono, 8kHz, 8-bit.
	fmtChunk := new(bytes.Buffer)
	writeLE(fmtChunk, uint16(1), uint16(1), uint32(8000), uint32(8000), uint16(1), uint16(8))

	// INFO chunk body, fields emitted in sorted id order for determinism.
	ids := make([]string, 0, len(info))
	for id := range info {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	infoBody := new(bytes.Buffer)
	infoBody.WriteString("INFO")
	for _, id := range ids {
		v := info[id]
		field := append([]byte(v), 0) // null-terminated
		if len(field)%2 == 1 {
			field = append(field, 0) // pad to even boundary
		}
		infoBody.WriteString(id)
		writeLE(infoBody, uint32(len(v)+1))
		infoBody.Write(field)
	}

	list := new(bytes.Buffer)
	list.WriteString("LIST")
	writeLE(list, uint32(infoBody.Len()))
	list.Write(infoBody.Bytes())

	data := []byte{0, 0, 0, 0} // 4 bytes of silence

	body := new(bytes.Buffer)
	body.WriteString("WAVE")
	body.WriteString("fmt ")
	writeLE(body, uint32(fmtChunk.Len()))
	body.Write(fmtChunk.Bytes())
	body.Write(list.Bytes())
	body.WriteString("data")
	writeLE(body, uint32(len(data)))
	body.Write(data)

	out := new(bytes.Buffer)
	out.WriteString("RIFF")
	writeLE(out, uint32(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

// writeLE writes each value to buf in little-endian order, panicking on error
// (bytes.Buffer writes never fail; this keeps the builder readable).
func writeLE(buf *bytes.Buffer, vals ...any) {
	for _, v := range vals {
		if err := binary.Write(buf, binary.LittleEndian, v); err != nil {
			panic(err)
		}
	}
}

// longLineWithEmbeddedEmail builds a single ~8KB line of filler with one real
// email embedded near the end. This is the input shape that drove the documented
// quadratic blowups; the golden snapshot locks the resulting findings.
func longLineWithEmbeddedEmail() string {
	const filler = "lorem ipsum dolor sit amet consectetur adipiscing elit "
	line := ""
	for len(line) < 8000 {
		line += filler
	}
	return line + "needle@example.com end\n"
}

// manyEmails generates n lines each containing a distinct email address.
func manyEmails(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += fmt.Sprintf("user%02d@example.com line %d\n", i, i)
	}
	return out
}

// CanonicalSort imposes a deterministic TOTAL order on matches so snapshots are
// stable regardless of the goroutine-completion order in which validators emit
// them. The formatters' own sorts (text/junit) are stable but not total — they
// leave equal-confidence matches in input order — so we sort here before
// formatting. The key is intentionally exhaustive: every field that can vary is
// part of the order, with Text last so two otherwise-identical matches still
// have a defined sequence.
func CanonicalSort(matches []detector.Match) []detector.Match {
	out := make([]detector.Match, len(matches))
	copy(out, matches)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Validator != b.Validator {
			return a.Validator < b.Validator
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence // higher confidence first
		}
		if a.Filename != b.Filename {
			return a.Filename < b.Filename
		}
		return a.Text < b.Text
	})
	return out
}

// timestampPatterns matches the non-deterministic wall-clock timestamps that a
// couple of formatters embed (gitlab-sast emits ISO-8601 start/end times). They
// are replaced with a fixed sentinel so the snapshot is byte-stable.
var timestampPatterns = []*regexp.Regexp{
	// gitlab-sast: "2026-06-30T11:07:42"
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?`),
}

// NormalizeOutput makes formatter output byte-stable for snapshotting by
// removing sources of run-to-run variance that are NOT behavior:
//
//   - wall-clock timestamps (gitlab-sast) → "<TIMESTAMP>" sentinel;
//   - JSON object-key order and reorderable arrays (SARIF rules) → canonical
//     sorted form, because Go map iteration order is randomized;
//   - the gitlab-sast "Additional Information" bullet list, which is rendered
//     from a Go map into a description STRING (so JSON canonicalization can't
//     reach it) → bullets sorted.
//
// These normalizations lock the *content* of the output, not the incidental
// ordering the current formatters happen to emit. If a future change alters
// what data appears (a new field, a changed message, a different detection),
// the snapshot still catches it. format is the formatter name (e.g. "sarif").
func NormalizeOutput(format, s string) string {
	for _, re := range timestampPatterns {
		s = re.ReplaceAllString(s, "<TIMESTAMP>")
	}

	switch format {
	case "sarif", "gitlab-sast", "json":
		if c, ok := canonicalizeJSON(s); ok {
			s = c
		}
	}
	if format == "gitlab-sast" {
		s = sortAdditionalInfoBullets(s)
		s = ferretIDPattern.ReplaceAllString(s, "ferret-<HASH>")
	}
	return s
}

// ferretIDPattern matches the gitlab-sast vulnerability id "ferret-<16 hex>".
// The id is a SHA256 over "filename:line:type" (mapper.go GenerateVulnerabilityID),
// so it is stable for a fixed file path but varies with the per-run temp dir.
// The snapshot already locks the filename/line/type it derives from, so the raw
// hash carries no extra signal — normalize it to keep file-mode snapshots stable.
var ferretIDPattern = regexp.MustCompile(`ferret-[0-9a-f]{16}`)

// canonicalizeJSON re-marshals a JSON document with object keys sorted
// (encoding/json sorts map keys deterministically) and the SARIF rules array
// sorted by "id". Returns (normalized, true) on success, or ("", false) if the
// input is not valid JSON (in which case the caller keeps the original).
func canonicalizeJSON(s string) (string, bool) {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return "", false
	}
	v = sortReorderableArrays(v)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return "", false
	}
	// Unmarshaling into any -> map[string]any means re-marshaling already emits
	// keys in sorted order, so object key order is now canonical.
	return buf.String(), true
}

// sortReorderableArrays walks a decoded JSON value and sorts arrays whose order
// is not semantically meaningful but is emitted from a Go map (currently the
// SARIF tool.driver.rules array, keyed by "id"). It recurses through all
// objects/arrays.
func sortReorderableArrays(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			t[k] = sortReorderableArrays(child)
			if k == "rules" {
				if arr, ok := t[k].([]any); ok {
					sortByStringField(arr, "id")
				}
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = sortReorderableArrays(t[i])
		}
		return t
	default:
		return v
	}
}

// sortByStringField sorts a slice of JSON objects by a top-level string field.
func sortByStringField(arr []any, field string) {
	sort.SliceStable(arr, func(i, j int) bool {
		mi, _ := arr[i].(map[string]any)
		mj, _ := arr[j].(map[string]any)
		si, _ := mi[field].(string)
		sj, _ := mj[field].(string)
		return si < sj
	})
}

// additionalInfoBlock matches the gitlab-sast "Additional Information" bullet
// list inside a description string. The bullets are rendered from a Go map, so
// their order is randomized; we sort them to a stable order.
var additionalInfoBlock = regexp.MustCompile(`(\*\*Additional Information:\*\*\\n)((?:- [^\n]*?\\n)+)`)

// sortAdditionalInfoBullets finds each "Additional Information" block in the
// (JSON-escaped) gitlab-sast output and sorts its "- key: value\n" bullet lines.
func sortAdditionalInfoBullets(s string) string {
	return additionalInfoBlock.ReplaceAllStringFunc(s, func(block string) string {
		m := additionalInfoBlock.FindStringSubmatch(block)
		if len(m) != 3 {
			return block
		}
		header, bullets := m[1], m[2]
		lines := strings.Split(strings.TrimSuffix(bullets, `\n`), `\n`)
		sort.Strings(lines)
		return header + strings.Join(lines, `\n`) + `\n`
	})
}

// sortFindings imposes a deterministic total order on redact findings so the
// redaction snapshot is stable regardless of emission order.
func sortFindings(f []redact.FindingWithMatchText) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.LineNumber != b.LineNumber {
			return a.LineNumber < b.LineNumber
		}
		if a.Confidence != b.Confidence {
			return a.Confidence < b.Confidence
		}
		return a.MatchText < b.MatchText
	})
}

// itoa is a tiny wrapper kept local so the test file doesn't import strconv.
func itoa(n int) string { return strconv.Itoa(n) }

// formatConf renders a confidence score as a stable 2-decimal string for use in
// identity keys (avoids float formatting drift across the comparison).
func formatConf(c float64) string { return strconv.FormatFloat(c, 'f', 2, 64) }

// NormalizePaths replaces the per-run temp directory (which varies by machine,
// run, and OS) with a stable sentinel so file-mode snapshots are portable —
// including ACROSS OPERATING SYSTEMS. The FileRouter stamps the absolute file
// path into Match.Filename and metadata keys ("source_file"/"original_file");
// without this every file-mode snapshot would change on every run, and on
// Windows the path separator (`\`) and JSON-escaped form (`\\`) would diverge
// from snapshots generated on Unix. tmpDir is the t.TempDir() the fixture was
// written into. Applied BEFORE NormalizeOutput (which canonicalizes JSON), so
// the sentinel survives JSON round-tripping.
//
// Cross-platform strategy: replace the temp dir in BOTH its native form and a
// forward-slash form (covers raw text/csv/yaml and unescaped JSON values), then
// collapse any path separator that immediately follows the <TMPDIR> sentinel to
// "/" so a fixture's basename renders identically on every OS. We only rewrite
// separators adjacent to the sentinel, never globally, so JSON string escaping
// elsewhere is untouched.
func NormalizePaths(s, tmpDir string) string {
	if tmpDir == "" {
		return s
	}
	// Forms the temp dir can appear in: native (filepath separators), forward-
	// slash (Unix / some renderers), and JSON-escaped backslashes (`\\`, Windows
	// inside JSON string values). Replace longest/most-specific first.
	fwd := strings.ReplaceAll(tmpDir, "\\", "/")
	jsonEsc := strings.ReplaceAll(tmpDir, "\\", "\\\\")
	for _, form := range []string{jsonEsc, tmpDir, fwd} {
		s = strings.ReplaceAll(s, form, "<TMPDIR>")
	}
	// Collapse the separator immediately after the sentinel to "/" so
	// "<TMPDIR>\notes.txt", "<TMPDIR>\\notes.txt", and "<TMPDIR>/notes.txt" all
	// normalize to "<TMPDIR>/notes.txt".
	s = strings.ReplaceAll(s, `<TMPDIR>\\`, "<TMPDIR>/")
	s = strings.ReplaceAll(s, `<TMPDIR>\`, "<TMPDIR>/")
	return s
}
