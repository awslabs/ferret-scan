# Ferret Scan — Threat Model

**Version:** 0.1 (PCSR draft)
**Last reviewed:** 2026-07-12
**Owner:** Andrea Di Fabio (adifabio@) — pending handover to OSS maintainer team on publication

This is a starting-point threat model drafted during PCSR prep so a reviewer can edit and sign off before publication. Update whenever a new trust boundary, route, or ingestion path is added. The current model covers two execution modes — CLI scanner and embedded web UI.

## 1. System overview

Ferret Scan is a Go-based CLI/web tool that detects sensitive content (PII, secrets, IP markers) in local files and produces redacted output or structured findings. Two execution surfaces:

1. **CLI** — `ferret-scan --file <path>` reads files from the local filesystem; no listening sockets, no inbound trust boundaries.
2. **Web UI** — `ferret-scan --web --port 8080` starts an HTTP server bound to `:<port>` (all interfaces). Accepts multipart file uploads and JSON suppression-rule mutations.

A former optional cloud-preprocessor path (Amazon Textract / Transcribe / Comprehend) was removed entirely from the codebase; the associated trust boundaries (TB-5, TB-6) are retained below for the record, marked eliminated.

## 2. Trust boundaries

| # | Boundary | Direction | Notes |
|---|----------|-----------|-------|
| TB-1 | User filesystem → CLI process | inbound | Operator-controlled paths; `filepath.Clean` / `filepath.Abs` applied (cmd/main.go:1259, 2085, 2145). |
| TB-2 | Browser → web server | inbound | No authentication. Server binds to `:<port>` (all interfaces). |
| TB-3 | Web server → uploaded file content | inbound | Multipart upload, 100 MB cap (server.go:323, 425). Written to OS temp dir, removed on scan completion. |
| TB-4 | Web server → suppression YAML on disk | bidirectional | `suppressions/` package mutates the YAML file. Path comes from `--suppression-file` flag at startup; not request-controlled. |
| TB-5 | Process → AWS APIs (formerly Textract/Transcribe/Comprehend) | outbound | **Eliminated** — the GenAI integration was removed entirely; the tool makes no outbound AWS API calls. Row retained for the record. |
| TB-6 | Process → external HTTP (formerly the Transcribe transcript URI fetch) | outbound | **Eliminated** — the Transcribe integration (including the transcript-URI `http.Get`) was removed entirely; the tool makes no outbound HTTP calls. Row retained for the record. |
| TB-7 | Pre-commit hook → ferret-scan binary | inbound (developer machine) | Pre-commit invokes the binary against staged files; same trust as CLI. |
| TB-8 | GitHub Actions runners → external registries (ECR Public / GHCR / PyPI) | outbound | Build, package, and publish flow. Workflows run with `contents: write`, `packages: write`, and `id-token: write` (PyPI trusted publishing + AWS OIDC for ECR). Third-party actions are SHA-pinned with version comments (`@<sha> # vX.Y.Z`) — see PR #64 and `.github/workflows/README.md`. Auto-version-tag job pushes tags to `main` on every push. |

## 3. STRIDE threats and mitigations

### TB-1 (user FS → CLI)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Path traversal via `--file ../../etc/passwd` | T (Tampering) | **Mitigated in code** — `filepath.Clean` + `filepath.Abs` in cmd/main.go:1259, 2085. The scanner reads files; it does not write to operator-controlled paths from CLI. |
| Decompression bomb via `.zip` / `.tar.gz` preprocessor input | D (DoS) | **Compensating control** — 100 MB upload cap in web mode (server.go:425). CLI mode reads files directly; per-file size cap is the operator's responsibility, but peak memory across a concurrent scan is now bounded by the opt-in `--max-live-bytes` admission budget (`internal/execguard` BytesLimiter; default: no cap). Document `--max-live-bytes` in the README hardening section for constrained hosts (e.g. Lambda). |
| Runaway / pathological-input validator hang (e.g. O(n²) on a single very long line) exhausts CPU on CLI or web | D (DoS) | **Mitigated in code (v2)** — validators poll `context.Context` in their hot loops, so the per-job context deadline (and cancellation) can now interrupt an in-flight validator instead of hanging unbounded. The opt-in `--validator-budget NAME=DURATION` sets a per-validator time cap; over-budget validators are stopped and the file is flagged incomplete (`ScanResult.Incomplete` / `IncompleteReason`). `--fail-on-incomplete` makes truncated coverage a non-zero (3) exit instead of a stderr warning. |
| Reading sensitive system files (`/etc/shadow`, `~/.aws/credentials`) the operator did not intend to scan | I (Info disclosure) | **Compensating control** — the tool only reads files the operator explicitly passes. `--exclude` and `respect_gitignore` reduce scope. No additional sandbox. |

### TB-2 (browser → web server)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Unauthenticated remote access — server binds to `0.0.0.0:8080` and any LAN host can scan/suppress | S (Spoofing), I (Info disclosure), E (Elevation) | **Mitigated in code** — server binds to `127.0.0.1` by default ([server.go](internal/web/server.go) `createSecureServer`). Container runtimes (Docker/Podman, detected via `/.dockerenv` or `FERRET_CONTAINER_MODE=true`) auto-bind to `0.0.0.0` since the container's network namespace is the trust boundary; port publishing decides host exposure. Operators wanting LAN binding from bare metal pass `--bind 0.0.0.0` and receive a stderr warning at startup. Resolution helper: [security.go](internal/web/security.go) `ResolveBindAddress`. |
| CSRF on `/scan`, `/suppressions/*` POST endpoints | T, E | **Mitigated in code** — `originCheckMiddleware` ([security.go](internal/web/security.go)) rejects POST/PUT/DELETE/PATCH whose `Origin` (or `Referer` when `Origin` is absent) does not match the bound host:port. Non-browser callers (curl, scripts) that send neither header are allowed — they're not subject to CSRF. Localhost ↔ 127.0.0.1 alias handled in `sameOriginHostSet`. |
| Reflected XSS via uploaded filename rendered back in HTML | T | **Mitigated in code** — `sanitizeFilenameForDisplay` (server.go:494) rewrites the filename before it leaves the API. Verify the front-end uses `textContent` not `innerHTML` when rendering match excerpts. |
| Missing security headers (CSP / X-Frame-Options / X-Content-Type-Options / HSTS) | T, I | **Mitigated in code (defense-in-depth)** — `securityHeadersMiddleware` ([security.go](internal/web/security.go)) sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` on every response. CSP `script-src` is strict (`'self'`, no `'unsafe-inline'`): all front-end code lives in the embedded `/app.js` asset, and interactivity binds via `data-action`/`data-change` event delegation — structural tests fail the build if inline script returns. `style-src` still carries `'unsafe-inline'` for the template's ~301 inline `style` attributes; hoisting those is tracked as a follow-up. CSP also blocks: external script/style sources, cross-origin form posts (`form-action 'self'`), object/embed (`object-src 'none'`), framing the page (`frame-ancestors 'none'`). HSTS intentionally omitted — server is HTTP-only by design; TLS-terminating proxies are the right layer. |
| Slowloris / slow-header attacks | D | **Mitigated in code** — `ReadHeaderTimeout: 15s`, `ReadTimeout: 30s`, `WriteTimeout: 30s`, `IdleTimeout: 60s` (server.go:217-225). |
| Decompression bomb / oversized upload | D | **Mitigated in code** — `ParseMultipartForm(100<<20)` and `io.LimitReader` cap to 100 MB (server.go:323, 425). |
| Repudiation — no audit log of suppression rule changes | R | **Compensating control** — suppressions YAML is the source of truth and is git-trackable in dev workflows. Production deployments should rely on file-level audit (auditd, fs-events). |

### TB-3 (uploaded file content)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Malicious file content (e.g. crafted PDF/DOCX) exploiting a preprocessor parser | E | **Compensating control** — risk surface is local Go libraries (PDF, DOCX); no cloud preprocessors exist. Recommend dependency-pin review in PCSR follow-up. |
| Temp file leakage to `/tmp` after process crash | I | **Compensating control** — `os.CreateTemp` uses random filenames; `defer os.Remove(...)` (server.go:436). Crash mid-scan leaves the file behind, but content is bounded by what the operator already had locally. |

### TB-4 (suppression YAML mutation)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Malicious suppression rule hides real findings | T, R | **Mitigated** — gated by TB-2's localhost-only default. Any caller able to reach the suppression endpoints is on the local machine; LAN binding requires explicit `--bind 0.0.0.0` plus the cross-origin check (which still applies). The pragma `# pragma: allowlist secret` is appended automatically (suppressions package), preventing the suppressions file from triggering ferret-scan itself. **Re-evaluate** if a future deployment exposes the UI remotely (add explicit auth on `suppressions/*` routes at that point). |

### TB-5 (process → AWS APIs — eliminated)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Hardcoded AWS credentials in source | I | **Eliminated** — the GenAI integration was removed entirely; the codebase contains no AWS SDK usage and no credential handling. No `AWS_ACCESS_KEY_ID` literals in source. |
| Excessive IAM permissions when role is assumed | E | **Eliminated** — the GenAI integration was removed entirely; no IAM role is assumed and no IAM template ships with the project. |

### TB-6 (Transcribe transcript URI — eliminated)

| Threat | STRIDE | Mitigation |
|---|---|---|
| SSRF via `http.Get(uri)` with attacker-controlled URI | T, I | **Eliminated** — the Transcribe integration (and its transcript-URI fetch) was removed entirely; the tool makes no outbound HTTP requests. |

### TB-7 (pre-commit hook)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Pre-commit hook bypassed (`--no-verify`) | E | **Compensating control** — server-side ferret-scan in CI (gitlab-ci.yml has `ferret-sast` and `gosec-sast` jobs). Pre-commit is best-effort developer hygiene. |

### TB-8 (CI runners → external registries)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Compromised third-party action (e.g. attacker repoints `softprops/action-gh-release@v3` upstream) reads `${{ secrets.* }}`, exfiltrates `GITHUB_TOKEN` / OIDC issuance, pushes commits to `main` as `github-actions[bot]`, publishes a tampered `ferret-scan` to PyPI / ECR Public / GHCR. | T (Tampering), E (Elevation of Privilege) | **Mitigated** — every external `uses:` reference is SHA-pinned (PR #64). Dependabot tracks upstream releases against the version-comment field (PR #66). The trust path is now git's content-addressing + dependabot review surface, not GitHub's tag mutability. Tracked as TM-08. |
| `auto-version-tag` job in `.gitlab-ci.yml` pushes tags to `main` on every push using `GITLAB_RELEASE_TOKEN`. No human approval gate beyond the originating commit. | E | **Compensating control** — `if:` condition limits the job to default-branch pushes by humans (not MRs, not tag pushes). Token can still issue a release without explicit `/release`-style gate. Tracked as TM-09. |
| Dockerfile `FROM` lines reference upstream images by tag (`golang:1.26.5-alpine`), not by `@sha256:<digest>`. Final image is `FROM scratch`, so the runtime impact is bounded to the builder stage's compiled binary, but the upstream image swap surface is real. | T | **Compensating control** — final stage is `FROM scratch` with no upstream layer; only the builder-stage compilation is at risk. Defense-in-depth fix is digest pinning. Tracked as TM-10 (now mitigated — the builder is digest-pinned). |

## 4. Open items / unmitigated threats blocking publication

| ID | Threat | Severity | Status |
|---|---|---|---|
| TM-01 | Web UI binds to all interfaces with no auth (TB-2 spoofing/info disclosure) | Major | **Mitigated** — loopback default + container auto-detect + `--bind` opt-in flag with stderr warning when bound broadly. See `internal/web/security.go` `ResolveBindAddress`. |
| TM-02 | Web UI POST endpoints have no CSRF protection (TB-2 tampering) | Major | **Mitigated** — Origin/Referer check on POST/PUT/DELETE/PATCH (`originCheckMiddleware`). |
| TM-03 | Web UI emits no security headers (TB-2 tampering/info disclosure) | Major | **Mitigated (defense-in-depth)** — `securityHeadersMiddleware` sets CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy. CSP `script-src` is strict (`'self'`, no `'unsafe-inline'`) — see TM-05 for the remaining `style-src` half. |
| TM-04 | Suppression mutation has no auth (TB-4) — gated by TM-01 fix | Major | **Mitigated** — closed by TM-01's loopback default. Re-evaluate if `--bind 0.0.0.0` becomes the documented deployment posture. |
| TM-05 | Embedded HTML template has ~90 inline event handlers and ~301 inline `style` attributes; CSP must include `'unsafe-inline'` until refactored | Minor (defense-in-depth) | **Partially closed (script half done)** — inline `<script>` block extracted to the embedded `/app.js` asset and all 93 inline `on*` handlers replaced with `data-action`/`data-change` event delegation; CSP `script-src` is now `'self'` (issue #147 item 1). Remaining: hoist inline `style` attributes into the stylesheet, then drop `'unsafe-inline'` from `style-src`. |
| TM-06 | Cloudscape design-system stylesheet loaded from `https://d0.awsstatic.com` (CSP allow-listed) | Minor (defense-in-depth) | **Open** — tracked. Self-host the CSS in the embed to drop the third-party `style-src` allowance. |
| TM-07 | SSRF defense-in-depth on Transcribe transcript URI fetch (TB-6) | Minor | **Eliminated** — the GenAI integration (including the Transcribe transcript-URI fetch) was removed entirely; the code no longer exists. |
| TM-08 | Floating-tag GitHub Actions chained with elevated runner permissions and auto-commit (TB-8) | **Major** | **In progress** — added 2026-05-22 by REPO scan. PR #64 SHA-pins every `uses:` reference (`@<sha> # vX.Y.Z` pattern); PR #66 adds dependabot config so the pins stay maintainable. Worst offender pre-fix was `pypa/gh-action-pypi-publish@release/v1` (a branch reference); now pinned to `cef22109... # release/v1 (2026-04-07)`. |
| TM-09 | `auto-version-tag` GitLab job pushes tags without manual approval (TB-8) | Minor | **In progress** — added 2026-05-22 by REPO scan. PR #69 adds `when: manual` + `allow_failure: true` on the rule (a maintainer must click "play" in the GitLab UI for the tag to push) and inline-documents the expectation that `GITLAB_RELEASE_TOKEN` is scoped `write_repository` only. Final closure also requires verifying the token scope in the GitLab project-settings UI. |
| TM-10 | Dockerfile builder-stage `FROM` not pinned by digest (TB-8) | Minor | **Mitigated** — added 2026-05-22 by REPO scan; PR #70 introduced digest pinning. The builder is now pinned to `golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2` (Go 1.26.5 picks up fixes for CVE-2026-39822 and CVE-2026-42505). The tag+digest are kept in sync via `scripts/go-version.sh` from the `.go-version` source of truth; the digest references a multi-arch manifest list covering both `linux/amd64` and `linux/arm64`, matching the platforms `docker-multiarch.yml` builds. Final stage is `FROM scratch` and is unaffected. |
| TM-11 | **Context-suppression evasion (TB-3): an attacker who authors the scanned content can drive a REAL, mathematically-valid secret below the detection threshold — to zero — by padding the surrounding line with negative-context keywords, so the match is never emitted and (in redaction mode) passes through in cleartext.** | **Major** | **Open** — added 2026-07-23. Root cause: validator confidence scoring treats attacker-controllable *context* (keywords like `test`/`invoice`/`serial`/`example`) as authoritative and lets it override *value-intrinsic* validity (Luhn/mod-97/NPI-Luhn checksums, the published-test denylists). The creditcard validator returns `-100` on any single negative keyword regardless of Luhn; SSN/phone/DL/secrets have the same `confidence <= 0 → not emitted` shape. Reproduced end-to-end 2026-07-23: a Luhn-valid Visa (`4532015112830366`), a mod-97-valid IBAN, and an NPI-Luhn-valid NPI each go from confidence 100 to **not detected at all** when the line is padded with `test example fake mock sample serial tracking invoice order …`; VIN degrades 100→50 and SSN 100→20 (still emitted). Because `pkg/redact` faithfully redacts only what validators *emit* (it applies no confidence floor of its own — verified), a non-emitted match is a redaction bypass: the value leaks. This is the inverse risk of the false-positive-reduction work (PR #166) — every decoy-suppressing keyword is also a suppression oracle. See §4.7 for the analysis and chosen mitigation. |

## 4.5 Highest-leverage attack paths

Three numbered chains the model should be evaluated against. Each names the starting trust zone, the chain of steps to impact, and the defense that breaks the chain.

1. **Compromised third-party GitHub Action → tampered PyPI / GHCR / ECR release.**
   Starting position: attacker controls one upstream action (or its mutable tag/branch). Chain: floating tag in `.github/workflows/*.yml` → action runs with `id-token: write` and `contents: write` → exfiltrates OIDC token / `GITHUB_TOKEN` → pushes a tampered package to PyPI via the `pypi` environment, or pushes a tampered image to GHCR / ECR Public. Impact: every downstream `pip install ferret-scan` or `docker pull public.ecr.aws/awslabs/ferret-scan:latest` receives the tampered artefact. Defense that breaks the chain: SHA-pin every `uses:` (TM-08).

2. **Operator binds web UI to LAN → cross-origin POST forges suppression rule.**
   Starting position: A1 unauthenticated remote attacker on the same LAN as an operator who has passed `--bind 0.0.0.0`. Chain: attacker sends `POST /suppressions/create` with a spoofed `Origin` header matching the operator's `host:port`. Defense that breaks the chain: `originCheckMiddleware` requires the Origin / Referer to be in `sameOriginHostSet`, which excludes LAN-resolvable hostnames the server can't enumerate. Today's mitigation is "best-effort" by design; re-evaluate if a future deployment moves to LAN-default. Stays at "compensating control" until then.

3. **Operator scans an attacker-supplied PDF / DOCX → preprocessor parser exploit.**
   Starting position: operator runs `ferret-scan --file <attacker-supplied.pdf>`. Chain: bug in `pdfcpu`, `ledongthuc/pdf`, or office-extractor library is triggered. Defense: dependency provenance (gemnasium dep-scan in `.gitlab-ci.yml`, `go mod tidy` pre-commit hook), 100 MB size cap, sandboxed `FROM scratch` runtime. Still relies on upstream library quality; the `gemnasium-python-dependency_scanning` job was previously blocked by the Phase 3 #3 YAML parse error and is restored in PR #69.

4. **Attacker authors scanned content → context padding hides a real secret from detection/redaction.**
   Starting position: attacker controls the bytes ferret-scan will scan — an outside contributor's PR run through a maintainer's pre-commit/CI (TB-7), or any content flowing through a redaction gateway (TB-3). Chain: attacker embeds a real, checksum-valid secret (card / IBAN / NPI) and pads the same line with negative-context keywords (`test invoice serial example …`) → validator scores it to zero → match is never emitted → in redaction mode the value passes through in cleartext; in scan mode it never appears in the report a reviewer/CI acts on. Verified reproducible 2026-07-23 (creditcard/bankaccount/medicalid: 100 → not detected). Defense that breaks the chain: the value-intrinsic confidence floor (checksum-valid ⇒ cannot be zeroed by context) + `--assume-hostile` mode for the no-checksum validators (TM-11 / §4.7). **Currently open** — the highest-severity unmitigated detection-integrity gap.

## 4.6 Action items

In priority order. Numbered for cross-reference from the REPO scan punch list.

1. **~~Pin every `uses:` in `.github/workflows/*` to commit SHA with version comment.~~** (TM-08 / Phase 3 #1.) Shipped in PR #64. Companion PR #66 adds dependabot tracking and a workflow-conventions README so the pins stay maintainable. PR #65 takes available major-version upgrades on top of the pins.
2. **~~Fix `.gitlab-ci.yml` line 175~~** (`[redacted-internal-ci-component]/kaniko/executor@~latest`). Shipped in PR #69. With the parse error fixed, `gosec-sast`, `ferret-sast`, and `gemnasium-python-dependency_scanning` are restored.
3. **~~Pin Dockerfile `FROM` lines to `@sha256:<digest>`.~~** (TM-10.) Shipped in PR #70.
4. **~~Add a manual approval gate or token-scope reduction on `auto-version-tag`.~~** (TM-09.) Shipped in PR #69. Final closure of TM-09 also requires verifying `GITLAB_RELEASE_TOKEN` scope in GitLab project settings — the YAML inline comment points to the right place.
5. **Refactor `internal/web/assets/template.html` to drop `'unsafe-inline'`** from CSP `script-src` ~~and~~ `style-src`. (TM-05.) `script-src` half shipped (issue #147 item 1): script extracted to embedded `/app.js`, handlers converted to event delegation, `script-src 'self'` enforced. `style-src` half (inline `style` attributes) still tracked, no time pressure.
6. **Self-host the Cloudscape stylesheet** to drop the `https://d0.awsstatic.com` allowance. (TM-06.)
7. **Add the value-intrinsic confidence floor + `--assume-hostile` mode** to close context-suppression evasion. (TM-11 / §4.7.) Two parts: (a) checksum-valid, non-denylisted matches cannot be suppressed below the emit/redact threshold by context alone — closes the creditcard/bankaccount/medicalid/VIN cleartext-leak paths by default; (b) `--assume-hostile` / `--no-context-suppression` surfaces every structural candidate for the no-intrinsic-check validators, default-on for the redaction gateway. Sequence with the negative-keyword consolidation refactor (tag keywords intrinsic-vs-contextual once). Ship as its own security-reviewed PR with regression cases proving a padded valid card/IBAN/NPI still surfaces.

## 4.7 TM-11 analysis: context-suppression evasion and the chosen mitigation

**The core design flaw.** Validator confidence scoring conflates two signals that have opposite trust properties under an adversarial author:

- **Value-intrinsic** — the value itself proves real-or-fake independent of context: Luhn (creditcard), mod-97 (IBAN), ABA checksum, NPI-Luhn / DEA checksum (medicalid), VIN check digit; and the *fakeness* side: published-test denylists (`4111 1111 1111 1111`, SSN `123-45-6789`), all-same-digit, sequential. **An attacker cannot forge these away** — a real card they want to exfiltrate must pass Luhn, so it cannot masquerade as a checksum failure.
- **Contextual** — surrounding words that *claim* (non)sensitivity: `test`, `invoice`, `serial`, `example`. **Fully attacker-controlled** in authored content.

Today context can zero out a value-intrinsically-valid match. That is the bug: a signal the attacker controls overrides a signal they cannot.

**Threat-model framing.** The current default encodes "the document author is trusted" — correct for the *accidental-leak* model (a developer's own repo, where `test`/`example` genuinely mark fixtures and suppressing them cuts false positives). It is wrong for the *adversarial-author* model: PR content from an outside contributor scanned by a maintainer's pre-commit/CI (TB-7), or any deployment scanning third-party-supplied content. The tool cannot know which model applies — **only the operator can declare it.**

**Chosen mitigation — both, layered, because they address different halves:**

1. **Confidence floor for value-intrinsically-valid matches (always on).** When a value passes its checksum AND is not on a published-test denylist, context penalties may *lower* its confidence for triage ordering but must not pull it below the emit/redact threshold. Value-intrinsic *fakeness* (denylist, sequential, all-same) still hard-drops — those are not attacker-forgeable in the dangerous direction. This closes the high-severity leaks (creditcard, bankaccount IBAN/ABA, medicalid NPI/DEA, VIN) with no operator action and minimal FP cost (its only cost is resurfacing genuine checksum-valid *documentation* cards, which is the safe direction for a detector). It does **nothing** for validators with no intrinsic check — see the residual.

2. **Opt-in hostile mode — `--assume-hostile` (alias `--no-context-suppression`).** Disables *all* context-driven suppression, so every structural candidate surfaces regardless of surrounding keywords. This is the only mitigation that helps the no-intrinsic-check validators, and it puts the threat-model choice in the operator's hands rather than the tool guessing. Default stays trust-context (low FP for the common accidental-leak case); pre-commit-on-untrusted-PRs and gateway/DLP deployments opt in. The redaction gateway (`pkg/redact`) should default this to **on** — its entire input is adversarial by definition — but that is one consumer of the flag, not the whole fix.

Why not either alone: the floor can't protect MRN / bare US bank account / generic-entropy secrets / person names (no math to floor on); hostile-mode alone would force every self-scan to eat the full false-positive load that the negative-keyword work (PR #166) deliberately removed. Together: the floor makes the checksum validators safe *by default*, and hostile-mode lets the operator extend "surface everything" to the rest when the threat model demands it.

**Rejected:** a padding-density anomaly heuristic ("too many negative keywords near a match = suspicious"). Gameable, adds its own FPs, and is an arms race — not a trust-boundary fix.

**Residual (documented, not closable).** Validators with no value-intrinsic signal — MRN, bare US bank account numbers, generic high-entropy secrets, person names, phone/SSN structural-only — cannot be made evasion-proof: there is no attacker-unforgeable property to floor on. For these, `--assume-hostile` degrades to "surface every structural candidate," which is correct but carries the full FP cost. This is a fundamental limit of pattern-plus-context detection, not a ferret-scan defect.

**Implementation note.** The floor and hostile-mode both want each negative keyword tagged *value-intrinsic* vs *contextual*, which is exactly the classification the planned negative-keyword consolidation refactor introduces — build them together so the security logic has a structural basis rather than per-validator special-casing.

## 5. Out of scope

- Supply-chain attacks on the `go.mod` dependency tree — covered by `go mod tidy`, license check, and gemnasium dependency scanning in CI.
- Compromise of the developer machine itself.
- Side-channel attacks on the running process.
