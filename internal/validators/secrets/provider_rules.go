package secrets

import (
	"regexp"
	"strings"
)

// The provider grammar table. One row per vendor token family; everything the
// validator knows about a provider literal is DERIVED from it: the regexes in
// compileKeywordPatterns, the anchored predicates behind getSecretType and
// CalculateConfidence, the prefix admits in containsSecretIndicators, and the
// GetCheckInfo text. TestProviderRulesAreTheOnlySource fails on a literal that
// lives anywhere else.
//
// Why a table (#769). The same facts were hand-copied into five places and had
// drifted into a leak: the Stripe, GitLab and Slack regexes matched a FIXED
// window (`sk_live_[0-9a-zA-Z]{24}`) with no boundary, the predicates were
// locked to the same lengths (`len == 32`), and no vendor publishes those
// lengths. A longer token was reported, and redacted, as its first N bytes: a
// 107-character Stripe key kept 75 in the clear in 9 of 11 realistic shapes,
// under every strategy, through --file and --stdin, exit 0. On a keyword line a
// second, generic finding over the whole value hid the leak; in prose there was
// nothing to hide it.
//
// Two modes, and which one a row gets is a fact about the vendor, not a choice:
//
//   - modeExact: the vendor fixes the body length, so the window IS the key and
//     anything after it is other bytes. AKIA (16), gh?_ (36), AIza (35),
//     dckr_pat_ (36). A run longer than the window reports the window, as it
//     always has. This is load-bearing for awsDocPlaceholderCap: the "EXAMPLE"
//     marker can only sit INSIDE the 20-byte AKIA window, never be appended to
//     a real key by an author, because appended bytes are never in the match.
//   - modeAtLeast: the vendor publishes a prefix and a minimum, or nothing at
//     all, so the body runs to the end of its character run. Stripe documents
//     prefixes only (its own CLI checks the prefix and "at least 12
//     characters"); a GitLab PAT is a routable token (payload of 27 to 300
//     characters, then `.vv.` and 9 more); Slack says the final `-` section is
//     the secret, whatever its length. Minimums are unchanged from the old
//     windows, so a short placeholder (`sk_test_1234567890abcdef`) still does
//     not match.
//
// No row has a maximum. A documented maximum may annotate a finding; it may
// never shorten or reject one, because the bytes past it would then be left in
// the clear, which is the bug.
type providerRule struct {
	// Type is the finding type (secret_type) for tokens of this row.
	Type string
	// Prefixes are the literal prefixes of the row, e.g. "sk_live_". Every
	// prefix is also an admit in containsSecretIndicators.
	Prefixes []string
	// Head is an optional regex fragment between the prefix and the body:
	// Slack's digit groups. Empty for every other row.
	Head string
	// Charset is the regex character class of a body byte.
	Charset string
	// MinBody is the body length: exact for modeExact, a floor for modeAtLeast.
	MinBody int
	// Mode decides whether the body is a fixed window or runs to the end.
	Mode providerMode
	// Trailer is an optional regex fragment that may follow the body: GitLab's
	// routable-token suffix. Only meaningful for modeAtLeast.
	Trailer string
	// RandomBody asks that the body carry a digit or an upper-case letter. A prefix of a few
	// letters followed by lower-case words (`glft-feed-token-goes-here`,
	// `github_pat_rotation_schedule_for_the_platform_team`) is a slug, not an issued token: a
	// random body of 20 characters over base64url has none with probability about 5e-8, and
	// 30 over base62 about 1e-13 (#881). Only the rows #881 added set it; a row that already
	// reported slugs keeps reporting them, so no finding on main moves.
	RandomBody bool
	// Base is the confidence CalculateConfidence starts from for this type.
	Base float64
	// Describe is the GetCheckInfo line for the row, or "" for a row that shares
	// its type with an earlier row and is described there.
	Describe string
}

type providerMode uint8

const (
	modeExact providerMode = iota
	modeAtLeast
)

// providerRules is the table. Order is the order the regexes are compiled in
// and the predicates are tried in; the prefixes are disjoint, so it decides
// nothing about results, only about the order of the derived lists.
var providerRules = []providerRule{
	{
		// AKIA is a long-term key ID, ASIA a temporary (STS) one (#881). One row, so the
		// regex, isAWSAccessKey, the line pre-check and reAKIAAnywhere share one definition.
		// An ASIA ID is scored by applyTemporaryAccessKey: LOW unless the rest of its
		// credential sits beside it.
		Type: "AWS_ACCESS_KEY", Prefixes: []string{"AKIA", awsTemporaryKeyPrefix},
		Charset: `[0-9A-Z]`, MinBody: 16, Mode: modeExact, Base: 94,
		Describe: "AWS Access Keys: AKIA[16 characters] (long-term), ASIA[16 characters] (temporary; LOW unless a secret access key or session token is on the same or an adjacent line)",
	},
	{
		Type: "GITHUB_TOKEN", Prefixes: []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"},
		Charset: `[a-zA-Z0-9]`, MinBody: 36, Mode: modeExact, Base: 93,
		Describe: "GitHub Tokens: ghp_[36 characters], gho_[36 characters], etc.",
	},
	{
		Type: "GOOGLE_CLOUD_API_KEY", Prefixes: []string{"AIza"},
		Charset: `[0-9A-Za-z_-]`, MinBody: 35, Mode: modeExact, Base: 94,
		Describe: "Google Cloud API Keys: AIza[35 characters]",
	},
	{
		// rk_live_ and rk_test_ are Stripe's restricted API keys, published beside the secret and
		// publishable prefixes at https://docs.stripe.com/keys ("Key types" and "Switch to live
		// mode"). Stripe publishes no length for any of them (#881).
		Type: "STRIPE_API_KEY", Prefixes: []string{"sk_live_", "pk_live_", "sk_test_", "pk_test_", "rk_live_", "rk_test_"},
		Charset: `[0-9a-zA-Z]`, MinBody: 24, Mode: modeAtLeast, Base: 95,
		Describe: "Stripe API Keys: sk_live_, pk_live_, rk_live_, sk_test_, pk_test_, rk_test_ + at least 24 characters, to the end of the run",
	},
	{
		// glpat- is GitLab's personal access token prefix (https://docs.gitlab.com/security/tokens/,
		// "Token prefixes"); its routable-token suffix is GitLab's routable_token.rb.
		Type: "GITLAB_TOKEN", Prefixes: []string{"glpat-"},
		Charset: `[a-zA-Z0-9_-]`, MinBody: 20, Mode: modeAtLeast,
		// A routable token (GitLab's routable_token.rb) ends in `.` + 2 base36
		// (version) + `.` + 2 base36 (payload length) + 7 base36 (CRC32).
		Trailer:  `(?:\.[0-9a-z]{2}\.[0-9a-z]{9})?`,
		Base:     93,
		Describe: "GitLab Personal Access Tokens: glpat-[at least 20 characters], optionally followed by the routable-token suffix .vv.lliiiiiii",
	},
	{
		// The rest of GitLab's "Token prefixes" table (https://docs.gitlab.com/security/tokens/),
		// which says they are fixed and designed as standard identifications: gloas- OAuth
		// application secret, gldt- deploy, glrt- and glrtr- runner authentication, glcbt- CI/CD
		// job, glptt- trigger, glft- feed, glimt- incoming mail, glagent- agent for Kubernetes,
		// glwt- workspace, glsoat- SCIM, glffct- feature flags client (#881). GitLab publishes
		// no body length, so the minimum is the one glpat- has always had. No routable-token
		// Trailer: the suffix is documented here for glpat- only, and was not checked for these prefixes.
		Type: "GITLAB_TOKEN", Prefixes: []string{"gloas-", "gldt-", "glrt-", "glrtr-", "glcbt-", "glptt-", "glft-", "glimt-", "glagent-", "glwt-", "glsoat-", "glffct-"},
		Charset: `[a-zA-Z0-9_-]`, MinBody: 20, Mode: modeAtLeast, RandomBody: true, Base: 93,
		Describe: "GitLab Tokens: gloas-, gldt-, glrt-, glrtr-, glcbt-, glptt-, glft-, glimt-, glagent-, glwt-, glsoat-, glffct- + at least 20 characters, with a digit or an upper-case letter",
	},
	{
		Type: "DOCKER_TOKEN", Prefixes: []string{"dckr_pat_"},
		Charset: `[a-zA-Z0-9_-]`, MinBody: 36, Mode: modeExact, Base: 92,
		Describe: "Docker Hub Tokens: dckr_pat_[36 characters]",
	},
	{
		Type: "SLACK_TOKEN", Prefixes: []string{"xoxb-"},
		Head: `[0-9]{10,13}-[0-9]{10,13}-`, Charset: `[a-zA-Z0-9]`, MinBody: 24, Mode: modeAtLeast, Base: 94,
		Describe: "Slack Tokens: xoxb-[bot tokens], xoxp-[user tokens], xapp-[app-level tokens]; the final section is the secret and is taken whole",
	},
	{
		Type: "SLACK_TOKEN", Prefixes: []string{"xoxp-"},
		// Slack's own example is xoxp-111-222-333-<32 hex> (https://docs.slack.dev/authentication/tokens,
		// "Rotating a short token secret"): ids are not fixed at 11-12 digits (#881). The pre-2016
		// 6- and 10-character secrets that page describes stay below the minimum.
		Head: `[0-9]{3,13}-[0-9]{3,13}-[0-9]{3,13}-`, Charset: `[a-zA-Z0-9]`, MinBody: 32, Mode: modeAtLeast, Base: 94,
	},
	{
		// App-level tokens begin xapp- (https://docs.slack.dev/authentication/tokens, "App-level
		// tokens"). The page publishes the prefix only; the `1-<app id>-<digits>-<hex>` sections
		// are the observed shape, and the final section is the secret, as for the rows above.
		Type: "SLACK_TOKEN", Prefixes: []string{"xapp-"},
		Head: `[0-9]-[A-Z0-9]{8,}-[0-9]{8,}-`, Charset: `[a-zA-Z0-9]`, MinBody: 32, Mode: modeAtLeast, Base: 94,
	},
	{
		// github_pat_ is the fine-grained personal access token prefix
		// (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github,
		// "GitHub's token formats"). GitHub publishes no length; the body carries `_` (observed
		// shape: 22 characters, `_`, 59 characters), so it is its own row, not a ghp_-style window.
		Type: "GITHUB_TOKEN", Prefixes: []string{"github_pat_"},
		Charset: `[a-zA-Z0-9_]`, MinBody: 40, Mode: modeAtLeast, RandomBody: true, Base: 93,
	},
	{
		// Hugging Face user access tokens begin hf_ (https://huggingface.co/docs/hub/security-tokens,
		// "How to use User Access Tokens"). No length is published; 30 is below the observed 34.
		Type: "API_KEY_OR_SECRET", Prefixes: []string{"hf_"},
		Charset: `[a-zA-Z0-9]`, MinBody: 30, Mode: modeAtLeast, RandomBody: true, Base: 92,
		Describe: "Hugging Face User Access Tokens: hf_[at least 30 characters]",
	},
	{
		// Anthropic API keys begin sk-ant-api03- (the partial_key_hint in
		// https://platform.claude.com/docs/en/api/admin/api_keys/update) and Admin API keys
		// sk-ant-admin (https://platform.claude.com/docs/en/build-with-claude/administration-api,
		// "Authentication"). The documented prefix of an admin key stops at `admin`; the `01-`
		// is the observed shape. No length is published; the observed bodies are about 93 characters.
		Type: "API_KEY_OR_SECRET", Prefixes: []string{"sk-ant-api03-", "sk-ant-admin01-"},
		Charset: `[a-zA-Z0-9_-]`, MinBody: 80, Mode: modeAtLeast, RandomBody: true, Base: 92,
		Describe: "Anthropic API Keys: sk-ant-api03-, sk-ant-admin01- + at least 80 characters",
	},
}

// awsTemporaryKeyPrefix is the prefix of a temporary access key ID, the kind AWS STS issues
// together with a secret access key and a session token. AWS's IAM identifier table says such an
// ID identifies a credential only together with those two, and audit exports (CloudTrail event
// history) carry one on most rows with neither, which is why it is scored apart from AKIA.
const awsTemporaryKeyPrefix = "ASIA"

// awsAccessKeyRule is the AWS_ACCESS_KEY row, found by type so the table's order cannot move it.
var awsAccessKeyRule = func() providerRule {
	for _, r := range providerRules {
		if r.Type == "AWS_ACCESS_KEY" {
			return r
		}
	}
	panic("secrets: providerRules has no AWS_ACCESS_KEY row")
}()

// hasAWSAccessKeyPrefix reports whether s starts with a prefix of the AWS_ACCESS_KEY row.
func hasAWSAccessKeyPrefix(s string) bool {
	for _, p := range awsAccessKeyRule.Prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// compiledProviderRule is a row with its derived matchers.
type compiledProviderRule struct {
	providerRule
	// whole is the anchored predicate for a complete token of this row.
	whole *regexp.Regexp
	// head matches the prefix and head at the start of a string, for modeAtLeast
	// rows: `^(?:p1|p2)Head`. Nil for modeExact rows, which are found by the
	// regexes compileKeywordPatterns derives.
	head *regexp.Regexp
	// body matches the longest run of body bytes at the start of a string:
	// `^Charset*`. Nil for modeExact rows.
	body *regexp.Regexp
	// trailer matches the optional trailer at the start of a string, or nil.
	trailer *regexp.Regexp
}

// bodyQuantifier renders the row's body length as a regex quantifier.
func (r providerRule) bodyQuantifier() string {
	if r.Mode == modeExact {
		return "{" + itoa(r.MinBody) + "}"
	}
	return "{" + itoa(r.MinBody) + ",}"
}

// pattern renders the unanchored regex for one prefix of the row, which is what
// compileKeywordPatterns appends for modeExact rows and what the derivation
// guard compares against.
func (r providerRule) pattern(prefix string) string {
	return regexp.QuoteMeta(prefix) + r.Head + r.Charset + r.bodyQuantifier() + r.Trailer
}

// alternation renders the row's prefixes as a non-capturing group.
func (r providerRule) alternation() string {
	quoted := make([]string, len(r.Prefixes))
	for i, p := range r.Prefixes {
		quoted[i] = regexp.QuoteMeta(p)
	}
	return "(?:" + strings.Join(quoted, "|") + ")"
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

// compiledProviderRules is built once; the table is immutable after init.
var compiledProviderRules = compileProviderRules(providerRules)

func compileProviderRules(rules []providerRule) []compiledProviderRule {
	out := make([]compiledProviderRule, 0, len(rules))
	for _, r := range rules {
		c := compiledProviderRule{providerRule: r}
		c.whole = regexp.MustCompile(`^` + r.alternation() + r.Head + r.Charset + r.bodyQuantifier() + r.Trailer + `$`)
		if r.Mode == modeAtLeast {
			c.head = regexp.MustCompile(`^` + r.alternation() + r.Head)
			c.body = regexp.MustCompile(`^` + r.Charset + `*`)
			if r.Trailer != "" {
				c.trailer = regexp.MustCompile(`^` + r.Trailer)
			}
		}
		out = append(out, c)
	}
	return out
}

// allProviderPrefixes is every prefix of every row, longest first, for the
// straddle check and the derivation guard.
var allProviderPrefixes = func() []string {
	var ps []string
	for _, r := range providerRules {
		ps = append(ps, r.Prefixes...)
	}
	// Longest first, so a straddle check that stops at the first hit reports
	// the most specific prefix. Stable insertion sort; the list is tiny.
	for i := 1; i < len(ps); i++ {
		for j := i; j > 0 && len(ps[j]) > len(ps[j-1]); j-- {
			ps[j], ps[j-1] = ps[j-1], ps[j]
		}
	}
	return ps
}()

// providerTypeOf returns the type of the row whose anchored predicate accepts
// match, or "" when no row does. This is the one predicate behind getSecretType
// and CalculateConfidence for provider literals.
func providerTypeOf(match string) (string, float64) {
	for _, c := range compiledProviderRules {
		if c.whole.MatchString(match) && (!c.RandomBody || hasRandomBodyByte(c.bodyOf(match))) {
			return c.Type, c.Base
		}
	}
	return "", 0
}

// bodyOf returns the part of a whole token of this row after its prefix, which is where
// RandomBody looks: Slack's digit groups are not in a RandomBody row, so Head is empty there.
func (c *compiledProviderRule) bodyOf(match string) string {
	for _, p := range c.Prefixes {
		if rest, ok := strings.CutPrefix(match, p); ok {
			return rest
		}
	}
	return match
}

// hasRandomBodyByte reports whether s holds a digit or an upper-case letter (RandomBody).
func hasRandomBodyByte(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// lineHasProviderPrefix is the containsSecretIndicators admit for provider
// literals: any row's prefix anywhere on the line.
func lineHasProviderPrefix(line string) bool {
	for _, p := range allProviderPrefixes {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// findProviderRuns finds every modeAtLeast token on the line and returns each
// as a candidate spanning the WHOLE token. modeExact rows are not handled here;
// their derived regexes sit in keywordPatterns and the regex engine's fixed
// window is exactly their grammar.
//
// It is a hand-rolled scan rather than `prefix+charset{min,}` through
// FindAllStringIndex, for two rules the regex engine cannot express:
//
// The straddle cut. Two tokens glued together, `sk_live_<99>pk_live_<99>`, are
// one run of body bytes as far as the charset knows (the `_` in `pk_live_`
// stops it two bytes late), and a regex would consume `pk` into the first
// token and then never see `pk_live_` at all, leaving the second key wholly in
// the clear. So after a run is taken, the last len(prefix)-1 bytes of it are
// checked for the START of any provider prefix that continues past the end of
// the run; if one is there, and the shortened token still meets its own
// minimum, the run is cut there and the scan resumes AT the cut, so the second
// token is found whole. Only the tail is searched: a prefix wholly inside a run
// (`sk_live_<20>AKIA<16>`) is body bytes that happen to spell a prefix, and
// cutting there would split a key. Provider spans therefore never partly
// overlap: a token ends where the next one begins, or the two are disjoint.
//
// The Stripe left-glue rule. `task_live_RefreshInterval` has `sk_live_` inside
// it at offset 2, and with a fixed window that identifier was
// a STRIPE_API_KEY at 100; with a run to the end it still would be. A Stripe
// key whose prefix is glued to a word byte on the left, and whose body carries
// no digit, is dropped: issued keys carry digits an author cannot remove (a
// random 24-byte body has none with probability (52/62)^24, about 1.5%, and
// that residual is pinned by a test as a stated cost), while an identifier
// spelt from words has none. The left byte is not glue when it ends an escape:
// a JSON `\n` or `\u0022`, a URL `%22`. Measured, consuming a boundary into the
// regex instead silenced 33 of 180 over-long tokens (every escaped or adjacent
// one), which is why the rule is this narrow and why it is Stripe-only: the
// other AtLeast prefixes contain `-`, which no identifier is spelt with.
func findProviderRuns(line string) []candidate {
	type run struct {
		candidate
		bodyStart int
		typ       string
	}
	var runs []run
	for ci := range compiledProviderRules {
		c := &compiledProviderRules[ci]
		if c.Mode != modeAtLeast {
			continue
		}
		for _, prefix := range c.Prefixes {
			from := 0
			for from < len(line) {
				i := strings.Index(line[from:], prefix)
				if i < 0 {
					break
				}
				start := from + i
				hm := c.head.FindStringIndex(line[start:])
				if hm == nil {
					// The prefix is there but the head (Slack's digit groups) is not.
					from = start + 1
					continue
				}
				bodyStart := start + hm[1]
				bm := c.body.FindStringIndex(line[bodyStart:])
				end := bodyStart + bm[1]
				if end-bodyStart < c.MinBody || (c.RandomBody && !hasRandomBodyByte(line[bodyStart:end])) {
					from = start + 1
					continue
				}
				// Straddle cut: a provider prefix beginning in the last bytes of the run
				// and continuing past it starts the NEXT token.
				cut := straddleCut(line, bodyStart+c.MinBody, end)
				if cut >= 0 {
					end = cut
				} else if c.trailer != nil {
					if tm := c.trailer.FindStringIndex(line[end:]); tm != nil {
						end += tm[1]
					}
				}
				runs = append(runs, run{
					candidate: candidate{text: line[start:end], start: start, end: end},
					bodyStart: bodyStart, typ: c.Type,
				})
				from = end
			}
		}
	}

	// Left-glue pass, Stripe only, after every run on the line is known: the byte
	// before a glued token is the last byte of the token before it -- the straddle
	// cut put the boundary exactly there -- and is not an identifier's letter. So a
	// start that is another provider run's end is exempt. Two no-digit keys glued
	// together, `sk_live_<24>sk_live_<24>`, would otherwise lose the second.
	ends := make(map[int]struct{}, len(runs))
	for _, r := range runs {
		ends[r.end] = struct{}{}
	}
	out := make([]candidate, 0, len(runs))
	for _, r := range runs {
		if r.typ == "STRIPE_API_KEY" {
			if _, boundary := ends[r.start]; !boundary && stripeLeftGlue(line, r.start, r.bodyStart, r.end) {
				continue
			}
		}
		out = append(out, r.candidate)
	}
	return out
}

// straddleCut returns the offset in [floor, end) at which a provider prefix
// begins and runs past end, or -1. Only the last len(prefix)-1 bytes of the run
// are examined, and never below floor, which is where the current token would
// fall under its own minimum.
func straddleCut(line string, floor, end int) int {
	for _, p := range allProviderPrefixes {
		lo := end - len(p) + 1
		if lo < floor {
			lo = floor
		}
		for s := lo; s < end; s++ {
			if s+len(p) > end && strings.HasPrefix(line[s:], p) {
				return s
			}
		}
	}
	return -1
}

// stripeLeftGlue reports whether a Stripe run starting at start is glued to a
// word byte on its left that is not the tail of an escape, and its body has no
// digit. See findProviderRuns.
func stripeLeftGlue(line string, start, bodyStart, end int) bool {
	if start == 0 || !isKeywordAlnum(line[start-1]) && line[start-1] != '_' {
		return false
	}
	if endsEscape(line[:start]) {
		return false
	}
	for i := bodyStart; i < end; i++ {
		if line[i] >= '0' && line[i] <= '9' {
			return false
		}
	}
	return true
}

// endsEscape reports whether s ends with an escape sequence whose last byte
// could be mistaken for glue: `\` + one byte (JSON `\n`, `\t`, `\"`), `%XX`
// (URL encoding), `\uXXXX` (JSON unicode).
func endsEscape(s string) bool {
	n := len(s)
	if n >= 2 && s[n-2] == '\\' {
		return true
	}
	if n >= 3 && s[n-3] == '%' && isHexByte(s[n-2]) && isHexByte(s[n-1]) {
		return true
	}
	if n >= 6 && s[n-6] == '\\' && s[n-5] == 'u' &&
		isHexByte(s[n-4]) && isHexByte(s[n-3]) && isHexByte(s[n-2]) && isHexByte(s[n-1]) {
		return true
	}
	return false
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// providerCheckInfo renders the GetCheckInfo lines for every described row, in
// table order.
func providerCheckInfo() []string {
	var out []string
	for _, r := range providerRules {
		if r.Describe != "" {
			out = append(out, r.Describe)
		}
	}
	return out
}
