### 🐛 Bug Fixes

- **ipaddress (`::` identifiers, four-part versions):** three shapes that are not addresses no
  longer read `IP_ADDRESS` 100 HIGH. A `::`-separated identifier segment such as `"::EC2"` is not
  reported: `::/96` (the unspecified address, the loopback and the deprecated IPv4-compatible block)
  joins the non-sensitive ranges, and a match followed by a second `::` is a path, not one address.
  A version quoted beside its own product token (`` `4.3.3.2` out of `LibreOffice/4.3.3.2` ``) is
  held to the product-version ceiling, LOW 55, and one directly after a capitalised name (`Acme
  Server Manager 26.8.0.3`) is no longer lifted by an IP keyword elsewhere on the line, so it stays
  at the context-free cap, MEDIUM 75. Measured on this repository's own lines: 4 findings at 100
  HIGH become 1 dropped, 1 LOW and 2 MEDIUM. Versions are demoted, never dropped, so they are still
  redacted; a labelled or URL-authority address and every public compressed IPv6 address keep
  their score ([#937](https://github.com/awslabs/ferret-scan/issues/937)).
