# Ferret Scan — Threat Model

**Version:** 0.1 (PCSR draft)
**Last reviewed:** 2026-05-18
**Owner:** Andrea Di Fabio (adifabio@) — pending handover to OSS maintainer team on publication

This is a starting-point threat model drafted during PCSR prep so a reviewer can edit and sign off before publication. Update whenever a new trust boundary, route, or ingestion path is added. The current model covers two execution modes — CLI scanner and embedded web UI — plus the optional GenAI/Textract/Transcribe preprocessor path.

## 1. System overview

Ferret Scan is a Go-based CLI/web tool that detects sensitive content (PII, secrets, IP markers) in local files and produces redacted output or structured findings. Three execution surfaces:

1. **CLI** — `ferret-scan --file <path>` reads files from the local filesystem; no listening sockets, no inbound trust boundaries.
2. **Web UI** — `ferret-scan --web --port 8080` starts an HTTP server bound to `:<port>` (all interfaces). Accepts multipart file uploads and JSON suppression-rule mutations.
3. **Optional cloud preprocessors** — Amazon Textract / Transcribe / Comprehend, gated behind a build flag and currently disabled in the source tree (`<!-- GENAI_DISABLED: ... -->` markers throughout).

## 2. Trust boundaries

| # | Boundary | Direction | Notes |
|---|----------|-----------|-------|
| TB-1 | User filesystem → CLI process | inbound | Operator-controlled paths; `filepath.Clean` / `filepath.Abs` applied (cmd/main.go:1259, 2085, 2145). |
| TB-2 | Browser → web server | inbound | No authentication. Server binds to `:<port>` (all interfaces). |
| TB-3 | Web server → uploaded file content | inbound | Multipart upload, 100 MB cap (server.go:323, 425). Written to OS temp dir, removed on scan completion. |
| TB-4 | Web server → suppression YAML on disk | bidirectional | `suppressions/` package mutates the YAML file. Path comes from `--suppression-file` flag at startup; not request-controlled. |
| TB-5 | Process → AWS APIs (Textract/Transcribe/Comprehend) | outbound | Only when GenAI flag enabled. Credentials from standard AWS chain (env, profile, IAM role). Currently disabled in source. |
| TB-6 | Process → external HTTP (Transcribe transcript URI) | outbound | `http.Get(uri)` in transcribe-extractor.go:186 against a URI returned by `GetTranscriptionJob`. Service-controlled, not user-controlled. |
| TB-7 | Pre-commit hook → ferret-scan binary | inbound (developer machine) | Pre-commit invokes the binary against staged files; same trust as CLI. |
| TB-8 | GitHub Actions runners → external registries (ECR Public / GHCR / PyPI) | outbound | Build, package, and publish flow. Workflows run with `contents: write`, `packages: write`, and `id-token: write` (PyPI trusted publishing + AWS OIDC for ECR). Third-party actions are SHA-pinned with version comments (`@<sha> # vX.Y.Z`) — see PR #64 and `.github/workflows/README.md`. Auto-version-tag job pushes tags to `main` on every push. |

## 3. STRIDE threats and mitigations

### TB-1 (user FS → CLI)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Path traversal via `--file ../../etc/passwd` | T (Tampering) | **Mitigated in code** — `filepath.Clean` + `filepath.Abs` in cmd/main.go:1259, 2085. The scanner reads files; it does not write to operator-controlled paths from CLI. |
| Decompression bomb via `.zip` / `.tar.gz` preprocessor input | D (DoS) | **Compensating control** — 100 MB upload cap in web mode (server.go:425). CLI mode reads files directly; size cap not enforced — operator's responsibility. Document this in the README hardening section. |
| Reading sensitive system files (`/etc/shadow`, `~/.aws/credentials`) the operator did not intend to scan | I (Info disclosure) | **Compensating control** — the tool only reads files the operator explicitly passes. `--exclude` and `respect_gitignore` reduce scope. No additional sandbox. |

### TB-2 (browser → web server)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Unauthenticated remote access — server binds to `0.0.0.0:8080` and any LAN host can scan/suppress | S (Spoofing), I (Info disclosure), E (Elevation) | **Mitigated in code** — server binds to `127.0.0.1` by default ([server.go](internal/web/server.go) `createSecureServer`). Container runtimes (Docker/Podman, detected via `/.dockerenv` or `FERRET_CONTAINER_MODE=true`) auto-bind to `0.0.0.0` since the container's network namespace is the trust boundary; port publishing decides host exposure. Operators wanting LAN binding from bare metal pass `--bind 0.0.0.0` and receive a stderr warning at startup. Resolution helper: [security.go](internal/web/security.go) `ResolveBindAddress`. |
| CSRF on `/scan`, `/suppressions/*` POST endpoints | T, E | **Mitigated in code** — `originCheckMiddleware` ([security.go](internal/web/security.go)) rejects POST/PUT/DELETE/PATCH whose `Origin` (or `Referer` when `Origin` is absent) does not match the bound host:port. Non-browser callers (curl, scripts) that send neither header are allowed — they're not subject to CSRF. Localhost ↔ 127.0.0.1 alias handled in `sameOriginHostSet`. |
| Reflected XSS via uploaded filename rendered back in HTML | T | **Mitigated in code** — `sanitizeFilenameForDisplay` (server.go:494) rewrites the filename before it leaves the API. Verify the front-end uses `textContent` not `innerHTML` when rendering match excerpts. |
| Missing security headers (CSP / X-Frame-Options / X-Content-Type-Options / HSTS) | T, I | **Mitigated in code (defense-in-depth)** — `securityHeadersMiddleware` ([security.go](internal/web/security.go)) sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` on every response. CSP includes `'unsafe-inline'` for scripts and styles because the embedded template at `internal/web/assets/template.html` uses ~90 inline event handlers and ~301 inline `style` attributes; refactoring those to enable a strict CSP is tracked as a follow-up. CSP still blocks: external script/style sources, cross-origin form posts (`form-action 'self'`), object/embed (`object-src 'none'`), framing the page (`frame-ancestors 'none'`). HSTS intentionally omitted — server is HTTP-only by design; TLS-terminating proxies are the right layer. |
| Slowloris / slow-header attacks | D | **Mitigated in code** — `ReadHeaderTimeout: 15s`, `ReadTimeout: 30s`, `WriteTimeout: 30s`, `IdleTimeout: 60s` (server.go:217-225). |
| Decompression bomb / oversized upload | D | **Mitigated in code** — `ParseMultipartForm(100<<20)` and `io.LimitReader` cap to 100 MB (server.go:323, 425). |
| Repudiation — no audit log of suppression rule changes | R | **Compensating control** — suppressions YAML is the source of truth and is git-trackable in dev workflows. Production deployments should rely on file-level audit (auditd, fs-events). |

### TB-3 (uploaded file content)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Malicious file content (e.g. crafted PDF/DOCX) exploiting a preprocessor parser | E | **Compensating control** — preprocessors are disabled by default (`enable_preprocessors: true` is on, but GenAI/Textract paths are gated behind `<!-- GENAI_DISABLED: -->` markers and absent from current builds). Risk surface is local Go libraries (PDF, DOCX). Recommend dependency-pin review in PCSR follow-up. |
| Temp file leakage to `/tmp` after process crash | I | **Compensating control** — `os.CreateTemp` uses random filenames; `defer os.Remove(...)` (server.go:436). Crash mid-scan leaves the file behind, but content is bounded by what the operator already had locally. |

### TB-4 (suppression YAML mutation)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Malicious suppression rule hides real findings | T, R | **Mitigated** — gated by TB-2's localhost-only default. Any caller able to reach the suppression endpoints is on the local machine; LAN binding requires explicit `--bind 0.0.0.0` plus the cross-origin check (which still applies). The pragma `# pragma: allowlist secret` is appended automatically (suppressions package), preventing the suppressions file from triggering ferret-scan itself. **Re-evaluate** if a future deployment exposes the UI remotely (add explicit auth on `suppressions/*` routes at that point). |

### TB-5 (process → AWS APIs)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Hardcoded AWS credentials in source | I | **Mitigated in code** — credentials come from the standard AWS chain (env, shared config, IAM role). README and aws-iam-role.yaml document IAM-role-based access with ExternalId and PrincipalArn constraints. No `AWS_ACCESS_KEY_ID` literals in source. |
| Excessive IAM permissions when role is assumed | E | **Compensating control** — aws-iam-role.yaml scopes permissions to Textract/Transcribe/Comprehend only and uses ExternalId. Reviewer should run `cfn-nag` against the template before publication. |

### TB-6 (Transcribe transcript URI)

| Threat | STRIDE | Mitigation |
|---|---|---|
| SSRF via `http.Get(uri)` with attacker-controlled URI | T, I | **Compensating control** — the URI returned by `GetTranscriptionJob` is service-issued (S3 pre-signed URL, validated origin). User cannot influence the URI directly. Recommend wrapping with a redirect-disabling client and an allowlist of `*.s3.amazonaws.com` / `*.s3.<region>.amazonaws.com` hosts as defense in depth. |

### TB-7 (pre-commit hook)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Pre-commit hook bypassed (`--no-verify`) | E | **Compensating control** — server-side ferret-scan in CI (gitlab-ci.yml has `ferret-sast` and `gosec-sast` jobs). Pre-commit is best-effort developer hygiene. |

### TB-8 (CI runners → external registries)

| Threat | STRIDE | Mitigation |
|---|---|---|
| Compromised third-party action (e.g. attacker repoints `softprops/action-gh-release@v3` upstream) reads `${{ secrets.* }}`, exfiltrates `GITHUB_TOKEN` / OIDC issuance, pushes commits to `main` as `github-actions[bot]`, publishes a tampered `ferret-scan` to PyPI / ECR Public / GHCR. | T (Tampering), E (Elevation of Privilege) | **Mitigated** — every external `uses:` reference is SHA-pinned (PR #64). Dependabot tracks upstream releases against the version-comment field (PR #66). The trust path is now git's content-addressing + dependabot review surface, not GitHub's tag mutability. Tracked as TM-08. |
| `auto-version-tag` job in `.gitlab-ci.yml` pushes tags to `main` on every push using `GITLAB_RELEASE_TOKEN`. No human approval gate beyond the originating commit. | E | **Compensating control** — `if:` condition limits the job to default-branch pushes by humans (not MRs, not tag pushes). Token can still issue a release without explicit `/release`-style gate. Tracked as TM-09. |
| Dockerfile `FROM` lines reference upstream images by tag (`golang:1.26.3-alpine`), not by `@sha256:<digest>`. Final image is `FROM scratch`, so the runtime impact is bounded to the builder stage's compiled binary, but the upstream image swap surface is real. | T | **Compensating control** — final stage is `FROM scratch` with no upstream layer; only the builder-stage compilation is at risk. Defense-in-depth fix is digest pinning. Tracked as TM-10. |

## 4. Open items / unmitigated threats blocking publication

| ID | Threat | Severity | Status |
|---|---|---|---|
| TM-01 | Web UI binds to all interfaces with no auth (TB-2 spoofing/info disclosure) | Major | **Mitigated** — loopback default + container auto-detect + `--bind` opt-in flag with stderr warning when bound broadly. See `internal/web/security.go` `ResolveBindAddress`. |
| TM-02 | Web UI POST endpoints have no CSRF protection (TB-2 tampering) | Major | **Mitigated** — Origin/Referer check on POST/PUT/DELETE/PATCH (`originCheckMiddleware`). |
| TM-03 | Web UI emits no security headers (TB-2 tampering/info disclosure) | Major | **Mitigated (defense-in-depth)** — `securityHeadersMiddleware` sets CSP/X-Frame-Options/X-Content-Type-Options/Referrer-Policy. Strict CSP (no `'unsafe-inline'`) deferred pending template refactor — see TM-05. |
| TM-04 | Suppression mutation has no auth (TB-4) — gated by TM-01 fix | Major | **Mitigated** — closed by TM-01's loopback default. Re-evaluate if `--bind 0.0.0.0` becomes the documented deployment posture. |
| TM-05 | Embedded HTML template has ~90 inline event handlers and ~301 inline `style` attributes; CSP must include `'unsafe-inline'` until refactored | Minor (defense-in-depth) | **Open** — tracked. Refactor handlers to `addEventListener`, hoist inline styles into the embedded stylesheet, then tighten CSP. |
| TM-06 | Cloudscape design-system stylesheet loaded from `https://d0.awsstatic.com` (CSP allow-listed) | Minor (defense-in-depth) | **Open** — tracked. Self-host the CSS in the embed to drop the third-party `style-src` allowance. |
| TM-07 | SSRF defense-in-depth on Transcribe transcript URI fetch (TB-6) | Minor | **Deferred** — file is `GENAI_DISABLED` and not compiled in. Re-evaluate when GenAI is re-enabled. |
| TM-08 | Floating-tag GitHub Actions chained with elevated runner permissions and auto-commit (TB-8) | **Major** | **In progress** — added 2026-05-22 by REPO scan. PR #64 SHA-pins every `uses:` reference (`@<sha> # vX.Y.Z` pattern); PR #66 adds dependabot config so the pins stay maintainable. Worst offender pre-fix was `pypa/gh-action-pypi-publish@release/v1` (a branch reference); now pinned to `cef22109... # release/v1 (2026-04-07)`. |
| TM-09 | `auto-version-tag` GitLab job pushes tags without manual approval (TB-8) | Minor | **In progress** — added 2026-05-22 by REPO scan. PR #69 adds `when: manual` + `allow_failure: true` on the rule (a maintainer must click "play" in the GitLab UI for the tag to push) and inline-documents the expectation that `GITLAB_RELEASE_TOKEN` is scoped `write_repository` only. Final closure also requires verifying the token scope in the GitLab project-settings UI. |
| TM-10 | Dockerfile builder-stage `FROM` not pinned by digest (TB-8) | Minor | **In progress** — added 2026-05-22 by REPO scan. PR #70 pins `golang:1.26.3-alpine@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d`. The digest references a multi-arch manifest list covering both `linux/amd64` and `linux/arm64v8`, matching the platforms `docker-multiarch.yml` builds. Final stage is `FROM scratch` and is unaffected. |

## 4.5 Highest-leverage attack paths

Three numbered chains the model should be evaluated against. Each names the starting trust zone, the chain of steps to impact, and the defense that breaks the chain.

1. **Compromised third-party GitHub Action → tampered PyPI / GHCR / ECR release.**
   Starting position: attacker controls one upstream action (or its mutable tag/branch). Chain: floating tag in `.github/workflows/*.yml` → action runs with `id-token: write` and `contents: write` → exfiltrates OIDC token / `GITHUB_TOKEN` → pushes a tampered package to PyPI via the `pypi` environment, or pushes a tampered image to GHCR / ECR Public. Impact: every downstream `pip install ferret-scan` or `docker pull ghcr.io/awslabs/ferret-scan:latest` receives the tampered artefact. Defense that breaks the chain: SHA-pin every `uses:` (TM-08).

2. **Operator binds web UI to LAN → cross-origin POST forges suppression rule.**
   Starting position: A1 unauthenticated remote attacker on the same LAN as an operator who has passed `--bind 0.0.0.0`. Chain: attacker sends `POST /suppressions/create` with a spoofed `Origin` header matching the operator's `host:port`. Defense that breaks the chain: `originCheckMiddleware` requires the Origin / Referer to be in `sameOriginHostSet`, which excludes LAN-resolvable hostnames the server can't enumerate. Today's mitigation is "best-effort" by design; re-evaluate if a future deployment moves to LAN-default. Stays at "compensating control" until then.

3. **Operator scans an attacker-supplied PDF / DOCX → preprocessor parser exploit.**
   Starting position: operator runs `ferret-scan --file <attacker-supplied.pdf>`. Chain: bug in `pdfcpu`, `ledongthuc/pdf`, or office-extractor library is triggered. Defense: dependency provenance (gemnasium dep-scan in `.gitlab-ci.yml`, `go mod tidy` pre-commit hook), 100 MB size cap, sandboxed `FROM scratch` runtime. Still relies on upstream library quality; the `gemnasium-python-dependency_scanning` job was previously blocked by the Phase 3 #3 YAML parse error and is restored in PR #69.

## 4.6 Action items

In priority order. Numbered for cross-reference from the REPO scan punch list.

1. **~~Pin every `uses:` in `.github/workflows/*` to commit SHA with version comment.~~** (TM-08 / Phase 3 #1.) Shipped in PR #64. Companion PR #66 adds dependabot tracking and a workflow-conventions README so the pins stay maintainable. PR #65 takes available major-version upgrades on top of the pins.
2. **~~Fix `.gitlab-ci.yml` line 175~~** (`[redacted-internal-ci-component]/kaniko/executor@~latest`). Shipped in PR #69. With the parse error fixed, `gosec-sast`, `ferret-sast`, and `gemnasium-python-dependency_scanning` are restored.
3. **~~Pin Dockerfile `FROM` lines to `@sha256:<digest>`.~~** (TM-10.) Shipped in PR #70.
4. **~~Add a manual approval gate or token-scope reduction on `auto-version-tag`.~~** (TM-09.) Shipped in PR #69. Final closure of TM-09 also requires verifying `GITLAB_RELEASE_TOKEN` scope in GitLab project settings — the YAML inline comment points to the right place.
5. **Refactor `internal/web/assets/template.html` to drop `'unsafe-inline'`** from CSP `script-src` and `style-src`. (TM-05.) Tracked, no time pressure.
6. **Self-host the Cloudscape stylesheet** to drop the `https://d0.awsstatic.com` allowance. (TM-06.)

## 5. Out of scope

- Supply-chain attacks on the `go.mod` dependency tree — covered by `go mod tidy`, license check, and gemnasium dependency scanning in CI.
- Compromise of the developer machine itself.
- Side-channel attacks on the running process.
