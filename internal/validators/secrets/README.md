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

- **AWS_ACCESS_KEY** - `AKIA[0-9A-Z]{16}` (Amazon Web Services)
- **GOOGLE_CLOUD_API_KEY** - `AIza[0-9A-Za-z_-]{35}` (Google Cloud Platform)

### **Development Platform Tokens (High Confidence: 92-94%)**

- **GITHUB_TOKEN** - `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 characters
- **GITLAB_TOKEN** - `glpat-[a-zA-Z0-9_-]{20}` (GitLab Personal Access Tokens)
- **DOCKER_TOKEN** - `dckr_pat_[a-zA-Z0-9_-]{36}` (Docker Hub Personal Access Tokens)
- **SLACK_TOKEN** - `xoxb-` or `xoxp-` + structured format

### **Payment Processing Keys (High Confidence: 95%)**

- **STRIPE_API_KEY** - `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_` + 24 characters

### **Authentication Tokens (High Confidence: 92%)**

- **JWT_TOKEN** - `eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*` (JSON Web Tokens)

### **Generic Secrets (Medium-High Confidence: 60-85%)**

- **API Keys** - Keyword patterns like `api_key = "value"`
- **Passwords** - Password fields like `"password": "value"`
- **Tokens** - Authentication tokens with keyword patterns
- **High Entropy Strings** - Base64 (4.5+ entropy, 20+ chars) and Hex (3.0+ entropy, 16+ chars)

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

### Unquoted assignments in source code

The keyword path also matches assignments whose value is **not** quoted —
`password=Sup3rS3cret`, `token: abc123XYZ`, a list tail, a YAML block-sequence
item. In `.env`, shell `export`, Dockerfile `ENV`, ini and unquoted YAML that is
the literal value. In an expression language it is not: a string has to be
quoted, so an unquoted right-hand side in code is an identifier, a member
access, a call or a type. `secret = config.secret_key` in Python and
`password: this.form.value.password` in TypeScript reported HIGH 100 before
this gate existed (#753).

**The rule.** An unquoted-family candidate is dropped only when all three hold:

1. the file's extension is in the table below and the gate is active for the
   file (see *Fail-open* below);
2. the candidate's **value start** lies in CODE position, i.e. outside every
   string (delimiters included), comment, docstring, regex literal and heredoc
   body; and
3. the value is not a literal token: a backtick string whose template closes
   before any `${`, or a hex literal (`0x` followed by 8 or more hex digits).

The value start is the anchor, not the keyword. In
`password = os.getenv("DB_PASSWORD", "<value>")` the keyword is in code, and
the quoted fallback is still a hard-coded credential. A quoted element of a
collection after a code-position head works the same way. A template literal
with `${` counts as code at its opening backtick, because the value captured
there is an interpolated expression. Its text segments are still literal.

Only the unquoted family is gated. It covers the unquoted and plural unquoted
patterns, the collection and list-tail paths, and block-sequence items. Quoted
keyword patterns, provider literals (`AKIA…`, `ghp_…`), the entropy path,
PEM blocks and the AWS secret-key path are never gated. The gate runs before
the same-span dedupe, so a quoted or entropy twin on the same bytes survives.
No value shape is consulted, so the gate is justified by the grammar alone.
Relabelling or reshaping a credential cannot hide it.

| Language | Extensions | Literal syntax the lexer reads |
|---|---|---|
| Python | `.py` `.pyi` `.pyw` | `#` comments; `'…'` and `"…"` with escapes and backslash-newline continuation; triple-quoted strings and docstrings; `r b f u rb br fr rf` prefixes in any case. A raw prefix changes what a backslash means, not where the string ends, so boundaries match Python's own tokenizer. f-strings are literal as a whole. |
| JavaScript / TypeScript | `.js` `.mjs` `.cjs` `.ts` `.mts` `.cts` | `//` and `/* */`; `'…'` and `"…"` with escapes and continuation; backtick templates across lines with `${ … }` read as code, including nested templates and braces; regex literals by the previous-byte heuristic. |
| Go | `.go` | `//` and `/* */`; `"…"` with escapes; `'…'` runes; backtick raw strings across lines. |
| Terraform / HCL | `.tf` `.tfvars` `.hcl` | `#`, `//` and `/* */`; `"…"` with `${ }` and `%{ }` read as code (`$${` and `%%{` are literal); `<<EOT` and `<<-EOT` heredoc bodies. |

`.jsx` and `.tsx` are deliberately absent. JSX text between tags is neither
code nor a JS string, and the lexer does not model it. Other languages are
added by measurement. A missing entry keeps today's behaviour, which is the
safe direction.

**Fail-open.** The lexer makes one pass over the whole file, in linear time.
If it cannot vouch for its own state, the gate is disabled for that file and
the file behaves exactly as it did before the gate. That happens when:

- the file ends inside anything but code: an unclosed block comment,
  triple-quoted string, template, raw string, heredoc or interpolation;
- a single-line string reaches the end of its line unterminated and without a
  continuation backslash. That is a syntax error in all four languages, so
  either the lexer is wrong about the file or the file is not what its
  extension says. A JS regex literal that does not close on its line is
  treated the same way;
- template or interpolation nesting is unbalanced, or deeper than 256; or
- the content is larger than 100 MB, the most this validator is handed in one
  piece (`router.MaxFileSize`).

Measured on 58,055 public source files, the gate failed open on 0.01% of
Python, 0.02% of JS/TS (all JSX in `.js` files), 0% of Go and 0.07% of HCL
(one deliberately broken test fixture).

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
| JS/TS | 134,755 (HIGH 94,766) | 15,920 (HIGH 10,286) | 118,835 |
| Go | 5,693 (HIGH 519) | 5,627 (HIGH 505) | 66 |
| HCL | 197 (HIGH 27) | 94 (HIGH 10) | 103 |

Nothing was added. Every removed value was checked against the language's own
tokenizer: Python's `tokenize`, esprima for JS/TS and `go/scanner`. The 14
Python values in Handlebars-templated files that `tokenize` rejects, and all
103 HCL removals, were read by hand. Every removed value starts in code. The
36,983 non-source files in the same run (config, prose, JSX and every other
type) gave identical findings: same file, line, type, text and confidence. The
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
`AWS_SECRET_ACCESS_KEY` types, both of which have an exact-length gate an author
cannot get past — appending `EXAMPLE` to a real 20-char `AKIA` key makes it 27 and
fails detection entirely. It is deliberately **not** applied to
`API_KEY_OR_SECRET`, which has no length gate and where the same rule would let
anyone silence a real credential by appending seven characters. Vendor **test-mode**
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
