### 🐛 Bug Fixes

- **secrets**: stored password hashes are now reported as `API_KEY_OR_SECRET` with `detection_method`
  `password_hash`, wherever they are written: crypt(3) `$1$`, `$apr1$`, `$5$`, `$6$` (with or without
  `rounds=`), bcrypt `$2a$/$2b$/$2y$`, yescrypt `$y$`, scrypt `$7$`, PHC argon2 and pbkdf2, Django
  `pbkdf2_sha256$`/`argon2$`/`bcrypt_sha256$`, LDAP `{SSHA}`-style and MySQL `*`+40 hex, in shadow and
  htpasswd records, kickstart, cloud-init, `.env`, JSON, SQL, Dockerfile and bare lines. A
  traditional 13-character DES crypt is reported (`password_hash_record`) as field 2 of a shadow or
  passwd record or in an htpasswd file. A quoted hash is no longer dropped when its salt starts with
  a letter (it read as a shell variable): in the issue's salt batches 6 of 120 were reported, now 120
  of 120. A text that is exactly one hash grammar now scores as a specific pattern, so a hash an
  existing path already reported keeps its type, text, line and `detection_method` and may score
  higher (a quoted `password: "$6$..."` with a digit-led salt: 90 to 100). Lookalikes such as `"$USER$HOST$SUFFIX"`, `$1$2`
  and locked `!`/`*` shadow fields report nothing. ([#902](https://github.com/awslabs/ferret-scan/issues/902))
- **secrets**: the private members of a JSON Web Key (`d`, `p`, `q`, `dp`, `dq`, `qi`, `k` in an
  object with a known `"kty"`) are reported with `detection_method` `jwk_private_member` at 60 or
  more; they were seen only by the quoted-entropy path, capped at 55 (LOW). A member that path already
  reported keeps its type, text and line. Public members (`n`, `e`, `x`, `y`) are unchanged.
  ([#902](https://github.com/awslabs/ferret-scan/issues/902))
