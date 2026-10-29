### 🐛 Bug Fixes

- **secrets (hex password in URI user info):** a hexadecimal password in URI user info, the shape
  `openssl rand -hex 16` prints (`REDIS_URL=redis://default:<32 hex>@cache:6379/0`), is no longer
  held at 55 LOW, so `--pre-commit-mode` blocks on it. `unlabelledHexIdentifierCap` demotes a bare
  32/40/64-hex value when no secret word is on the line. It read the line for a label, and a URI
  password is labelled by its position in the URI grammar (#766), so a keyword-free URL with a hex
  password was capped while the same URL with a mixed-case password reported 100 HIGH. A URI
  user-info candidate is now exempt from that ceiling, as it already was from the M24 cap; the
  user-info dispositions' own LOW ceiling is unchanged. Measured on main vs this branch: the
  issue's line, 55 LOW (exit 0) to 100 HIGH (exit 1); 40- and 64-hex passwords and a 40-hex token
  in a clone URL, 55 to 100; `ImageUniqueID: "<32 hex>"` stays at 55
  ([#808](https://github.com/awslabs/ferret-scan/issues/808)).
