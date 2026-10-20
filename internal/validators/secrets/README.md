# Enhanced Secrets Validator

The Enhanced Secrets Validator detects API keys, tokens, passwords, and other sensitive credentials using advanced techniques inspired by the [detect-secrets](https://github.com/Yelp/detect-secrets) project, enhanced with context analysis, environment detection, and intelligent pattern learning.

## Advanced Detection Methods

### 1. High Entropy String Analysis with Statistical Validation

Uses Shannon entropy to identify random-looking strings that are likely to be cryptographic material:

- **Base64 strings**: Entropy threshold 4.5, minimum 20 characters
- **Hex strings**: Entropy threshold 3.0, minimum 16 characters
- **Statistical validation**: Analyzes character distribution patterns
- **Context-aware entropy**: Adjusts thresholds based on document context

### 2. Enhanced Keyword Pattern Matching

Searches for common secret keywords followed by values with context understanding:

```text
api_key = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6"
"password": "super_secret_password_123"
auth_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

### 3. Environment Detection & Context Analysis 🚀

**Automatic Environment Recognition:**

- **Development Environment**: Detects dev/staging keywords, applies -15% confidence penalty
- **Production Environment**: Identifies prod/live keywords, applies +10% confidence boost
- **Test Environment**: Recognizes test patterns, applies -25% confidence penalty

**Domain-Specific Intelligence:**

- **Financial Domain**: +12% confidence boost for API keys (higher likelihood)
- **Healthcare Domain**: Variable adjustments based on secret type
- **Document Type Analysis**: Configuration files (+15%), Code files (+8%), JSON/YAML (+12%)

### 4. Global Test Pattern Database

**Comprehensive Test Secret Detection:**

- 16+ common test patterns: `test_api_key_here`, `your_api_key_here`, `example_secret_key`
- Pattern variations: `abcdef123456789`, `xxxxxxxxxxxxxxxx`, `replace_with_actual`
- Documentation patterns: `tutorial_secret`, `readme_example`, `documentation_key`
- **Impact**: -35% confidence penalty for matches

## Supported Secret Types

The validator now identifies specific secret types and displays them in the TYPE column for better categorization:

### **Cryptographic Keys (High Confidence: 95-96%)**

The validator detects various cryptographic key formats:

- **SSH_PRIVATE_KEY** - SSH private key detection
- **CERTIFICATE** - Certificate and private key detection
- **PGP_PRIVATE_KEY** - PGP private key detection

### **Cloud Provider API Keys (High Confidence: 94-95%)**

- **AWS_ACCESS_KEY** - `AKIA[0-9A-Z]{16}` (Amazon Web Services; the vendor fixes the length, so the 20-byte window is the key)
- **GOOGLE_CLOUD_API_KEY** - `AIza[0-9A-Za-z_-]{35}` (Google Cloud Platform; fixed length)

### **Development Platform Tokens (High Confidence: 92-94%)**

- **GITHUB_TOKEN** - `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 characters (fixed length)
- **GITLAB_TOKEN** - `glpat-` + at least 20 of `[a-zA-Z0-9_-]`, to the end of the run, then optionally the routable-token suffix `.vv.lliiiiiii` (GitLab publishes no length: a routable token's payload is 27 to 300 characters)
- **DOCKER_TOKEN** - `dckr_pat_[a-zA-Z0-9_-]{36}` (Docker Hub Personal Access Tokens; Docker publishes no format, the window is kept as is)
- **SLACK_TOKEN** - `xoxb-` or `xoxp-` + the digit groups, then the final `-` section taken whole, at least 24 or 32 characters (Slack: "the final section is the secret")

### **Payment Processing Keys (High Confidence: 95%)**

- **STRIPE_API_KEY** - `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` + at least 24 of `[0-9a-zA-Z]`, to the end of the run (Stripe documents prefixes only)

These seven families are one table, `providerRules` in `provider_rules.go`, from which the
regexes, the type predicates, the line pre-check and the `--help` text are all derived; a test
fails on a provider literal written anywhere else. Rows with a vendor-fixed length report the
window; rows without one report the whole run, because a token reported as its first N bytes is
redacted as its first N bytes and the rest is left in the clear (#769: 75 of a 107-byte Stripe
key, under every strategy). Two tokens glued together are split where the second one's prefix
begins; a Stripe prefix glued to a word on its left with no digit in the body
(`task_live_RefreshInterval`) is an identifier, not a key, and is not reported.

### **Authentication Tokens (High Confidence: 92%)**

- **JWT_TOKEN** - `eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` (JSON Web Tokens)

### **Generic Secrets (Medium-High Confidence: 60-85%)**

- **API Keys** - Keyword patterns like `api_key = "value"`
- **Passwords** - Password fields like `"password": "value"`
- **Tokens** - Authentication tokens with keyword patterns
- **High Entropy Strings** - Base64 (4.5+ entropy, 20+ chars) and Hex (3.0+ entropy, 16+ chars)
- **Credentials in URIs** - The password in `scheme://user:password@host`, or a token-shaped user name in `https://token@host`, with no keyword needed (see [Credentials in URIs](#credentials-in-uris))

## Detection Capabilities

### High Entropy Detection

- **Shannon Entropy Calculation**: Measures randomness in character distribution
- **Charset-Specific Analysis**: Different thresholds for base64 vs hex strings
- **Length Filtering**: Minimum lengths to reduce false positives
- **Quote Detection**: Focuses on quoted strings to reduce noise

### Keyword Pattern Detection

- **Assignment Patterns**: `keyword = "value"`
- **JSON/YAML Patterns**: `"keyword": "value"`
- **Case Insensitive**: Matches regardless of case
- **Flexible Separators**: Handles various assignment operators

### Credentials in URIs

A password in URI user info (RFC 3986 §3.2.1) is how `DATABASE_URL`, broker,
proxy and registry URLs and JDBC DSNs carry a credential, and it has no key
stem, no provider prefix and no quotes of its own:

```text
DATABASE_URL=postgresql://app_user:<password>@db1.internal:5432/appdb
spring.datasource.url=jdbc:mysql://app_user:<password>@db1.internal:3306/shop
git clone https://<token>@git.internal/orders/app.git
```

Before #766 none of these reported anything. A separate source,
`findURIUserinfo` (`uri_userinfo.go`), now parses the authority of every URI
on the line and reports the password, exactly as written (percent-encoding
included, so a redacted URI still parses), with `detection_method:
uri_userinfo` and the type `getSecretType` gives the value (a GitHub token
stays `GITHUB_TOKEN`). It runs on every line holding `://` and `@`, outside the
line pre-check, and is never gated by the source-code lexer.

**The grammar.** Hand-written rather than `net/url`, which reads
`jdbc:postgresql://…` as an opaque URI with no user, rejects MongoDB's comma
host list, and quotes the whole raw URI (password included) in its errors.

| step | rule |
|---|---|
| scheme | any `ALPHA *( ALPHA / DIGIT / + / - / . )` before `://`; `jdbc:mysql://` reads as `mysql` |
| authority | runs to the first `/ ? #`, whitespace, quote, backtick, `<`, `>` or `\`, then loses any trailing `, ; . ! ) ] }` (never an IP literal's `]`) |
| `@` | the authority is split at its LAST `@`, as `net/url` and WHATWG split it, so an `@` in a path or query is never in it |
| user info | unreserved, percent-encoded, sub-delims, `:` and `@` only, so `${X}`, double-brace templates, `<password>`, `%s` and `%(pw)s` fail by grammar |
| host | one or more of a host name, IPv4 address or `[IP literal]`, each with an optional `:port`, separated by `,` |
| password | everything after the first `:`; an empty one is no candidate |
| user name only | a candidate only when shaped like a token: 20+ bytes, letters and digits only and both present, 3.5+ bits of entropy per byte (`git@`, `alice@` stay silent) |

**What the value decides.** Every disposition reads only the value's own bytes,
never the key, scheme or host, all of which the author of the line controls:

| value | disposition |
|---|---|
| the whole value is `$NAME` or `$(…)`, or only `*` | no candidate |
| default vocabulary (`password`, `passwd`, `pass`, `pwd`, `secret`, `guest`, `postgres`, `root`, `admin`, `changeme`, `user`, `username`, `default`, `test`, `example`, `demo`, any case), or the user name repeated | **LOW**, at most 55 |
| rejected by `plausibleUnquotedSecret` (shorter than 8, all-lowercase under 16, digits only, a UUID) or `shoutySentinel` (`REDACTED`, `CHANGEME`) | **LOW**, at most 55 |
| anything else | scored like any other candidate |

A LOW finding is kept, not dropped: `postgres:postgres` can be the real
password of a real database, and only a reported value is redacted. Its 55 is
published as `confidence_ceiling`, so the document bridge's context adjustment
cannot lift it into MEDIUM. A scored candidate is exempt from the M24 cap (the
URI grammar is its corroboration) and from nothing else: its threshold is 50,
and the test/dev, shell-variable, global-test-pattern and generic-boost
adjustments apply to it as to every other candidate.

**Additive.** The source runs after every other path has reported and merged.
A password whose span equals or lies inside a span already reported keeps that
finding and adds nothing: `DB_PASSWORD=<uri>` still reports the whole URI, and
`https://x-access-token:<token>@host` still reports the `token:` stem's wider
span. No existing finding's type, text, line, context or confidence changes, so
every existing suppression rule still matches.

**Recall cost.** An unencoded `/`, `?` or `#` in a password ends the authority
there, as it does for every URI parser, and that URI reports nothing. Not in
scope: Oracle's `user/pass@host` (not URI syntax), `.netrc`, `curl -u`,
`.pgpass` and command-line flags.

### Unquoted assignments in source code

The keyword path also matches assignments whose value is **not** quoted —
`password=Sup3rS3cret`, `token: abc123XYZ`, a list tail, a YAML block-sequence
item. In `.env`, shell `export`, Dockerfile `ENV`, ini and unquoted YAML that is
the literal value. In an expression language it is not: a string has to be
quoted, so an unquoted right-hand side in code is an identifier, a member
access, a call or a type. `secret = config.secret_key` in Python and
`password: this.form.value.password` in TypeScript reported HIGH 100 before
this gate existed (#753).

**The rule.** An unquoted-family candidate is dropped only when all four hold:

1. the file's extension is in the table below and the gate is active for the
   file (see *Fail-open* below);
2. the candidate's **value start** lies in CODE position, i.e. outside every
   string (delimiters included), comment, docstring, regex literal and heredoc
   body;
3. no byte of the captured value is the **text of a backtick string** — a
   JavaScript template segment or a Go raw string. A capture that starts in
   code can run into one (`atob(`…`)`, `strings.TrimSpace(`…`)`,
   `` `${PREFIX}…` ``) and then it carries a literal the lexer itself
   classified, so it is kept, exactly as on `main`. For the unquoted and plural
   patterns a backtick string is the only kind there is to run into, because
   their value class stops at `'` and `"`. A collection or list-tail element
   can also run into a quoted string, and that still drops (see *Residual
   loss* below); and
4. the value is not a literal token: a hex literal (`0x` followed by 8 or more
   hex digits), or — in Python and HCL, where a backtick opens no string — a
   backtick-delimited value that closes before any `${`.

The value start is the anchor, not the keyword. In
`password = os.getenv(DB_PASSWORD_ENV, "<value>")` the unquoted capture
`os.getenv(DB_PASSWORD_ENV` starts in code and is dropped, while the list-tail
candidate that starts at the fallback's opening quote is kept, because a
hard-coded fallback is still a credential. A quoted element of a collection
after a code-position head works the same way. (With a **quoted** env-var name,
`os.getenv("DB_PASSWORD", "<value>")`, the unquoted capture stops at the first
quote, so no keyword candidate reaches the fallback at all — on `main` or here.
Only the ungated entropy path reports it, and only at 20+ characters above its
entropy floor. The gate neither causes nor closes that gap.)

A template literal whose first byte after the backtick is `${` counts as code
at that backtick, because the value captured from there starts with an
interpolated expression. With literal text before the first `${` the backtick
stays literal, like the opening quote of `"<value>" + suffix`. Either way the
template's text segments are backtick text (condition 3), so a credential
written inside them keeps reporting.

Only the unquoted family is gated. It covers the unquoted and plural unquoted
patterns, the collection and list-tail paths, and block-sequence items. Quoted
keyword patterns, provider literals (`AKIA…`, `ghp_…`), the entropy path,
PEM blocks and the AWS secret-key path are never gated. A gateable candidate
that the entropy path, a quoted pattern, a provider literal or the AWS
secret-key path claims on **exactly the same span** is not gated either:
dropping it would remove nothing, but the AWS path's same-span merge takes the
highest confidence any candidate on the span reached, so gating the twin would
lower what that span reports (an unquoted 40-character AWS secret in code would
go from 100 to 95). The gate runs before the same-span dedupe, so a quoted or
entropy twin survives. No
value shape is consulted, so the gate is justified by the grammar alone.
Relabelling or reshaping a credential cannot hide it.

| Language | Extensions | Literal syntax the lexer reads |
|---|---|---|
| Python | `.py` `.pyi` `.pyw` | `#` comments; `'…'` and `"…"` with escapes and backslash-newline continuation; triple-quoted strings and docstrings; `r b f u t rb br fr rf tr rt` prefixes in any case. A raw prefix changes what a backslash means, not where the string ends, so boundaries match Python's own tokenizer. An f-string or t-string is literal as a whole, but its replacement fields are lexed as code, so a PEP 701 (3.12+) field holding a string in the f-string's own quote — `f"{d["k"]}"` — does not end the f-string early. A `:` at bracket depth 0 starts the format spec, which is text again. |
| JavaScript | `.js` `.mjs` `.cjs` | `//` and `/* */`; `'…'` and `"…"` with escapes and continuation; backtick templates across lines with `${ … }` read as code, including nested templates and braces; regex literals by the previous-significant-byte heuristic, judged across newlines and comments, since JavaScript inserts no semicolon before a `/`; a `)` reads as the end of an operand unless it closes an `if`/`for`/`while`/`with` header, after which a `/` starts the body and is a regex (a `for await (…)` header is not tracked and keeps the division reading). A JSX element in code position fails the file open (below). |
| TypeScript | `.ts` `.mts` `.cts` | The same lexer, with two differences. TypeScript accepts JSX only in `.tsx`, so `<T` at an expression start is a type parameter list or an assertion, not a tag, and does not fail the file open. A `!` straight after an identifier, `)` or `]` is the non-null assertion, which ends the operand, so in `done! / total; // …` the `/` is a division and the comment stays a comment. Only the byte before the `!` is read, so `a!! / b` and `a ! / b` keep the regex reading. |
| Go | `.go` | `//` and `/* */`; `"…"` with escapes; `'…'` runes; backtick raw strings across lines. |
| Terraform / HCL | `.tf` `.tfvars` `.hcl` | `#`, `//` and `/* */`; `"…"` with `${ }` and `%{ }` read as code (`$${` and `%%{` are literal); `<<EOT` and `<<-EOT` heredoc bodies. |

`.jsx` and `.tsx` are deliberately absent. JSX text between tags is neither code
nor a JS string, and the lexer does not model it. JSX is just as common in `.js`
files — Create React App, Next.js pages and React Native all default to `.js` —
so there a JSX element in code position fails the gate open for the whole file,
which makes it behave exactly as if it were named `.jsx`. Other languages are
added by measurement. A missing entry keeps today's behaviour, which is the
safe direction.

**Fail-open.** The lexer makes one pass over the whole file, in linear time.
If it cannot vouch for its own state, the gate is disabled for that file and
the file behaves exactly as it did before the gate. That happens when:

- the file ends inside anything but code: an unclosed block comment,
  triple-quoted string, template, raw string, heredoc or interpolation;
- a single-line string reaches the end of its line unterminated and without a
  continuation backslash. That is a syntax error in all five grammars, so
  either the lexer is wrong about the file or the file is not what its
  extension says. A JS regex literal that does not close on its line, and an
  f-string whose own quote or a newline turns up in a format spec, are treated
  the same way;
- template or interpolation nesting is unbalanced, or deeper than 256;
- a JSX element stands in code position: a closing tag (`</Name`, `</>`) in any
  of the six JS/TS extensions — in a `.ts` file that means the bytes are not
  TypeScript at all, for instance a Qt Linguist `.ts` translation file — or, in
  `.js`/`.mjs`/`.cjs` only, an opening tag (`<Name`, `<>`) where an operand is
  expected, which catches a closing tag the lexer cannot see because a `//` in
  the JSX text hides it;
- a typographic quote stands in code position: any rune other than `"` and `'`
  with the Unicode `Quotation_Mark` property or in the quote punctuation
  categories `Pi` and `Pf` (`“` `”` `‘` `’` `„` `«` `»` `‹` `›` `＂` `＇` `「`
  `」` `『` `』` …), or a Windows-1252 smart quote, whether it arrives
  Latin-1-transcoded (`U+0093`, from a file or `--stdin`) or as the raw byte
  (`0x93`, from `ScanText`). No grammar here accepts one there — Python, node,
  `gofmt` and `terraform fmt` each reject it — so the file is not valid source,
  typically a credential pasted from a page, a chat or a word processor, and the
  lexer cannot know where the author meant the string to be;
- any other non-ASCII punctuation or symbol stands in code position — a prime
  (`′` `″`), a dingbat ornament (`❝` `❞`), a dash, a math or currency sign, an
  emoji — for the same reason. Excluded are the runes these grammars accept in
  identifiers: connector punctuation (`‿`) and Unicode's `Other_ID_Start` and
  `Other_ID_Continue` (`℘` `℮` `·` `・`), pinned by
  `TestLexNonASCIICodeDoesNotFailOpen`. On the corpus below this changed no
  finding;
- the replacement character `U+FFFD` stands in code position. It replaces a
  byte a decoder could not read — `Redact` turns every invalid UTF-8 sequence
  into one before the gate runs, a raw Windows-1252 quote included — so the
  lexer cannot know whether that byte was a quote; or
- the content is larger than 100 MB, the most this validator is handed in one
  piece (`router.MaxFileSize`).

Measured on 58,055 public source files, the gate failed open on 0 of 21,538
Python files, 20 of 31,303 JS/TS files (0.06%), 0 of 3,714 Go files and 1 of
1,500 HCL files (0.07%, a deliberately broken test fixture). All 20 JS/TS
fail-opens are `.js` files holding JSX (semgrep test fixtures: 18 parse as
JSX with `acorn-jsx`, the other 2 are TSX written into `.js`), and none is
TypeScript. No file failed open on a typographic quote. Over a wider set of
the same public sources (65,710 content-distinct gated files, Go's own
toolchain sources included) the lexer fails open on two more: a Go toolchain
test fixture that uses `«` `»` as range markers, which gives 0 findings either
way, and a gzip file named `.py` (a bandit test fixture), which the CLI does
not scan as text at all.

**Channels.** The file type comes from the name on every channel: a CLI path,
`--stdin-name`, a `pkg/scan` `ScanFile` path, and a `ScanText` or `Redact`
label. `--stdin-name app.ts` and a `ScanText` label `app.ts` are gated exactly
like a file called `app.ts`. With no extension there is no gate: `<stdin>`,
`<text>`, `<request>`, `clipboard`. An unlisted extension is not gated either:
`.docx`, `.env.example`, `x.ts.txt`. Without a file type, `token: AuthToken` is
as likely to be a YAML value as a TypeScript type, so untyped input keeps
reporting it.

**The accepted loss.** A bare credential pasted unquoted in code position is
no longer reported, e.g. `API_KEY = Xk9…` in a `.py`. It is not a string in
these languages and the program would not run. Telling it apart from an
identifier would need a guess at the value, the kind of value-shape veto this
gate avoids. Because it is not reported, it is not redacted either, and a
redacted copy of that file still contains it. The loss is pinned by
`TestSourceGateAcceptedLossIsPinned`.

**Residual loss.** A collection or list-tail element that starts in code and
runs into a quoted string drops with its head: in
`token = first_token_value, decode("<value>")` neither `first_token_value` nor
`decode("<value>")` is reported, and the quoted value is found only if a
never-gated path finds it on its own (the entropy path can, from 20
characters up). Counting
quoted-string text the way backtick text is counted would keep it, but on the
measured corpus it also kept 35,974 more JS/TS findings, every one on a
minified line of 200 or more characters (`HZ="X-Amzn-Bedrock-…"`), and 5 in
Python. The shape is pinned by `TestSourceGateKeepIsScopedToBacktickText`.

**Residual false positives.** Docstrings and comments are literal text, so a
keyword inside one still reports. The common case is a Sphinx field,
`:type token: RequestToken`: 36 findings in the measured Python corpus, about
250 in the larger corpus #753 measured. A follow-up can key on Sphinx field
syntax, which is a docstring-grammar marker rather than a guess at the value.

**Measured** with the CLI on 58,055 content-deduplicated public source files
(CPython 3.10 stdlib, Homebrew Python 3.14 site-packages, global npm packages,
this repository's Go module dependencies, ASH, the pre-commit cache):

| | before | after | removed |
|---|---|---|---|
| Python | 3,403 (HIGH 631) | 1,796 (HIGH 131) | 1,607 |
| JS/TS | 134,755 (HIGH 94,766) | 16,735 (HIGH 10,812) | 118,020 |
| Go | 5,693 (HIGH 519) | 5,628 (HIGH 505) | 65 |
| HCL | 197 (HIGH 27) | 94 (HIGH 10) | 103 |

Nothing was added, and every finding that survives is identical to `main`'s:
same file, line, type, text, confidence and detection method. Only
`API_KEY_OR_SECRET` findings were removed; every other type is unchanged.
Every removed value starts in code, checked against the language's own
tokenizer: Python's `tokenize`, esprima for JS/TS and `go/scanner`. The 14
Python values in Handlebars-templated files that `tokenize` rejects, and all
103 HCL removals, were read by hand. The 36,983 non-source files in the same
run (config, prose, JSX and every other type) gave identical findings. The
#753 probe of 24 everyday code lines went from 17 reported to 0.

## Confidence Scoring

### Base Confidence (85%)

Starting confidence level for detected patterns.

### Positive Factors

- **High Entropy**: +0-15% based on Shannon entropy score
- **Keyword Context**: +5-10% for relevant keywords nearby
- **Proper Format**: +0% (maintains base confidence)

### Negative Factors

- **Short Length**: -30% for strings under 8 characters
- **Common Words**: -20% for containing "password", "secret", etc.
- **Low Entropy**: -25% for entropy below threshold
- **Test Patterns**: -30% for "test", "demo", "example", etc.
- **Invalid Format**: -15% for containing spaces or tabs

### Context Analysis

- **Positive Keywords**: `api`, `key`, `secret`, `token`, `password`, `passwd`,
  `pass`, `pwd`, `passphrase`, `auth`, `credential`, `private`, `access`,
  `session`, `bearer`, `oauth`, `jwt`, `signature`, `salt`, `nonce`, `seed`,
  `entropy`, `connectionstring`
- **Negative Keywords**: `test`, `example`, `demo`, `sample`, `fake`, `mock`,
  `dummy`, `placeholder`, `template`, `default`, `null`, `empty`, `none`,
  `public`, `open`, `free`, `guest`, `anonymous`, `debug`
- **Token-boundary matching**: keywords match as whole tokens (case-insensitive)
  across `snake_case`, `SCREAMING_SNAKE`, `kebab-case`, and `camelCase`, so
  `token` matches `authToken` / `AUTH_TOKEN` / `auth-token` but `auth` does **not**
  match `author`, `pass` does not match `passenger`, and the negative `open` does
  not penalize `openai_api_key`. This removes a class of substring false positives
  (and false penalties) that plain containment produced.
- **Hash-scheme labels are NOT positive**: words like `hash`, `checksum`, `digest`,
  and `integrity` label the protected (non-reversible) form, not a credential, so
  they do not lift a nearby high-entropy hex string above the generic-entropy cap.
  This keeps SBOM content hashes (CycloneDX), SRI digests, and git SHAs out of the
  HIGH band. A password hash is still flagged because its line carries a real
  credential word (`password`/`pwd`).

### Published Ceilings (context cannot lift these)

A ceiling is an upper bound the validator publishes in
`Match.Metadata["confidence_ceiling"]`. Unlike the penalties above it is not an
addend competing with context — nothing downstream can out-vote it. Two apply here:

| Value class | Ceiling | Reason |
|---|---|---|
| A bare 32/40/64-char hex identifier on a line naming nothing secret | 55 | GUIDs, digests, ETags and commit ids share the shape of a key. `api_key = "14f6…"` keeps its full score; `ImageUniqueID: "14f6…"` is capped. |
| An AWS credential whose own bytes contain `EXAMPLE` — `AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` | 15 | AWS publishes these in its documentation. Measured before: 84% and 75% MEDIUM, i.e. presented as real credentials (#364). |

Both are **demotions, not suppressions**: the finding is still reported, so it is
still redacted. `--confidence low` shows it; `--explain` reports
`not_test_data: false` and a `likely_test` verdict.

The `EXAMPLE` rule applies only to the `AWS_ACCESS_KEY` and
`AWS_SECRET_ACCESS_KEY` types, both of which are matched as a fixed window an author
cannot widen: a real 20-char `AKIA` key with `EXAMPLE` appended is matched as its first
20 bytes and the appended bytes are never in the match, so the marker can only ever sit
*inside* a window (the AWS secret key's 40-char capture ends the same way). An earlier
version of this paragraph said the longer key "fails detection entirely"; it does not,
it reports the 20-byte window at full confidence, uncapped, and that is pinned by
`TestAKIAWindowPins`. It is deliberately **not** applied to
`API_KEY_OR_SECRET`, which has no length gate and where the same rule would let
anyone silence a real credential by appending seven characters, nor to any provider
row whose body runs to the end of its character run (Stripe, GitLab, Slack), for the
same reason. Vendor **test-mode**
credentials such as `sk_test_…` are unaffected: those authenticate, so they are
real secrets and keep their full confidence.

Full policy: [docs/proposals/CONFIDENCE_CONTRACT.md](../../../docs/proposals/CONFIDENCE_CONTRACT.md) §7c.

## Implementation Details

### Memory Security

- Uses `SecureString` for sensitive data storage
- Multiple memory overwrite passes during cleanup
- Automatic memory clearing after processing

### Pattern Compilation

- Pre-compiled regex patterns for performance
- Optimized for common secret formats
- Flexible keyword matching with optional separators

### Entropy Calculation

```go
entropy := 0.0
for _, char := range charset {
    count := strings.Count(data, string(char))
    if count > 0 {
        p := float64(count) / float64(len(data))
        entropy += -p * math.Log2(p)
    }
}
```

## Usage Examples

### Command Line

```bash
# Scan for secrets in a file
./ferret-scan --file config.json --checks SECRETS

# High confidence secrets only
./ferret-scan --file .env --checks SECRETS --confidence high

# Verbose output with entropy scores
./ferret-scan --file app.py --checks SECRETS --verbose
```

### Configuration File

```yaml
profiles:
  security-audit:
    checks: SECRETS
    confidence_levels: high,medium
    verbose: true
    description: "Security audit focusing on secrets detection"
```

## Detection Examples

### ✅ Detected Secrets

```bash
# Cloud Service Keys
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
GOOGLE_API_KEY=AIzaSyDaGmWKa4JsXZ-HjGw7ISLan_Qkby0Oc-0
STRIPE_SECRET_KEY=sk_live_1234567890abcdef1234567890abcdef

# Platform Tokens
GITHUB_TOKEN=ghp_1234567890abcdef1234567890abcdef123456
GITLAB_TOKEN=glpat-xxxxxxxxxxxxxxxxxxxx
SLACK_BOT_TOKEN=xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx
DOCKER_TOKEN=dckr_pat_1234567890abcdef1234567890abcdef123456

# JWT Tokens
jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

# SSH Private Keys
-----BEGIN [EXAMPLE] PRIVATE KEY-----
MIIEpAIBAAKCAQEA4f5wg5l2hKsTeNem/V41fGnJm6gOdrj8xtarhDdXMCbVvdaZ
[... truncated for security ...]
-----END [EXAMPLE] PRIVATE KEY-----

# Generic API Keys
api_key = "sk_live_51H7qYKJ2eZvKYlo2C8nKqp6rQqXYZ1234567890abcdef"
db_password = "P@ssw0rd!2023_SecureDB"
```

### ❌ Ignored Patterns

```javascript
// Test data
api_key = "test_key_123"

// Placeholder values
password = "your_password_here"

// Short strings
token = "abc123"

// Common words
secret = "password"
```

## Performance Considerations

- **Regex Optimization**: Pre-compiled patterns for better performance
- **Entropy Caching**: Calculated once per unique string
- **Context Limiting**: Bounded context analysis to prevent slowdowns
- **Memory Efficient**: Streaming file processing for large files

## Security Features

- **Memory Scrubbing**: Sensitive data cleared from memory after processing
- **Secure Storage**: Uses controlled byte slices instead of strings
- **Minimal Exposure**: Reduces time sensitive data remains in memory
- **Multiple Overwrites**: Paranoid memory clearing with multiple passes

## Integration

The Secrets Validator integrates seamlessly with:

- **CLI Tool**: Available via `--checks SECRETS`
- **Web UI**: Accessible through the web interface
- **Configuration**: Supports profile-based configuration
- **Suppressions**: Compatible with the suppression system
