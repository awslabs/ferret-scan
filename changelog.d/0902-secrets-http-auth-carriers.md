### 🚀 Features

- **secrets (HTTP auth carriers):** detect credentials in HTTP authentication carriers that were
  previously unreported, so `--enable-redaction` rewrites them instead of exiting 0 with the value
  in cleartext ([#902](https://github.com/awslabs/ferret-scan/issues/902), Part A): `Authorization`
  and `Proxy-Authorization` `Basic` (base64 `user:pass`, decoded only to validate and never
  disclosed) and `Bearer`/`Token` headers, the `.npmrc` `_auth=` line, the `.netrc` `password` field
  and `curl -u user:pass`. On the issue's 23-file reproduction these reported nothing on v2.5.3 and
  now report each planted credential at 85-100 (`http_basic_auth`/`http_bearer_auth`/`npmrc_auth`/
  `netrc_password`/`curl_userinfo`); a base `simple` and `format_preserving` redaction run left 4 of
  4 planted values in cleartext before and 0 after. The detectors are structural: a span already
  reported by a provider literal or the keyword path (a `Bearer ghp_<...>` run, a quoted
  `auth_token = "Bearer <jwt>"`) keeps that path's type and single finding. A high-entropy value on
  an `Authorization:` line is now corroborated by the `authorization` keyword, so for example
  `{"Authorization": "<token>"}` reports HIGH where it was LOW (55); the added findings can change
  `--pre-commit-mode` exit codes.
