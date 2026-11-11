### 🐛 Bug Fixes

- **otp (`otpauth://` URIs without a secret):** a URI with no `secret=` parameter, an empty one,
  or a placeholder such as `otpauth://totp/...` is no longer reported as `OTPAUTH_URI`; it read
  100 HIGH while the same URI carrying the published example secret read LOW 15. A provisioning URI
  is reported for the secret it holds, which the Key Uri Format makes a required parameter and
  `docs/validators-new.md` already listed as required. Measured on this repository's own lines
  (the validator's help text, its source comment and the validator documentation): 6 findings at
  100 HIGH become 0; every URI that carries a secret, whatever its parameter order or the case of
  the parameter name, keeps its score, and an account name in the URI's label is still reported
  by the email validator ([#940](https://github.com/awslabs/ferret-scan/issues/940)).
