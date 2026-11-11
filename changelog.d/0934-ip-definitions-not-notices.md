### 🐛 Bug Fixes

- **intellectualproperty**: source code and markup that merely contain an IP marker word are no
  longer reported as copyright, trademark or confidentiality notices: a keyword that is an
  alternative inside a regular expression (the `trade_secret:` regex in a ferret-scan config), two
  or more keywords quoted as a string list, a lowercase `trademark` or a `™` after a function word
  ("with trademark", "a ™"), a lowercase `(r)` call argument (`basename(r)`), and a year-less `©`,
  `(c)` or `Copyright` followed by a lowercase word (the QuickTime `©xyz` atom name, "copyright
  notice with ..."). On this repository's own `config.yaml`, `docs/configuration.md`, both
  `examples/*.yaml`, the validator's source and the files the issue names, HIGH findings go from 20
  to 0 (178 to 97 at any confidence). Real notices keep their confidence, including "X is a
  trademark of Y", "Amazon Confidential and Trademark", `Windows(R)` and a quoted CSV
  classification cell. ([#934](https://github.com/awslabs/ferret-scan/issues/934))
