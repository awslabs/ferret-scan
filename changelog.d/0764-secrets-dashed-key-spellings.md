### 🐛 Bug Fixes

- **secrets (kebab-case keys, `X-Api-Key`):** a key spelled with a dash is detected like the same
  key spelled with an underscore. Every multi-word stem in both keyword lists was spelled `_?`
  (`api_?key`, `private_?key`, `access_?token`, ...), so `api-key=`, `private-key:`, the
  `X-API-KEY:` header and `curl -H "X-Api-Key: ..."` matched no pattern and reported nothing at any
  confidence while `api_key=` reported the same value at 100. The stems are now spelled `[_-]?`, the
  quoted JSON/dict key pattern also takes the HTTP header prefix `x-` (`{"x-api-key": "..."}`,
  `{'X-Api-Key': '...'}`), and the AWS secret-key label gate reads `aws-secret-access-key` (the
  GitHub Actions input name) as it reads `aws_secret_access_key`. Under the same document type the
  dash spelling reports the same value, type, confidence and detection method as the underscore
  spelling; the document-type heuristic does not count a dashed key as a configuration line, so a
  file of dashed keys can score up to 15 lower. Additive: every span the old patterns matched is
  matched at the same position with the same capture, so no existing finding changes its text or
  its suppression hash. Measured on main vs this branch: the issue's 11 dashed lines, nothing to
  `API_KEY_OR_SECRET` 85 (97-100 for the quoted JSON and dict headers); 18,867 files of public
  repositories holding 1,595 dashed-key lines, +67 findings, 0 lost, 0 changed, each of the 67 what
  main reports for the same file with the key spelled with an underscore; 21,439 third-party files
  (Go module cache, Python site-packages, `/usr/share/doc`), no change; golden corpus and
  `make score` unchanged ([#764](https://github.com/awslabs/ferret-scan/issues/764)).
