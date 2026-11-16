### 🔒 Security

- **web (session cookie):** the `ferret_scan_session` cookie, which scopes stored scans to one
  browser session for `/export`, now carries the `Secure` attribute when the request arrived over
  HTTPS: a TLS connection to the server, or a reverse proxy that terminated TLS and sends
  `X-Forwarded-Proto: https` ([#1014](https://github.com/awslabs/ferret-scan/issues/1014), CodeQL
  `go/cookie-secure-not-set`). Over plain HTTP the cookie is unchanged, so the documented
  `http://localhost` path (the loopback bind reached directly or through an SSH port-forward) keeps
  working in every browser; Safari refuses to store a `Secure` cookie from `http://localhost`, and on
  a loopback connection nothing is in transit for the flag to protect. `HttpOnly` and
  `SameSite=Strict` are as before.
