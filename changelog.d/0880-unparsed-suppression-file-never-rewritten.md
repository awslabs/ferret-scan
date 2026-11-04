### 🐛 Bug Fixes

- **suppressions (saving):** a suppression file that exists but does not parse, or cannot be read, is
  no longer overwritten by the next save. It loads as empty, and `--generate-suppressions` or any web
  UI edit used to write that empty state back: measured on the issue's two-rule file with one bad
  line, one regeneration left 2 rules with `enabled: true` 0 and `enabled: false` 2, the bad line
  gone, and exit 0, and a web UI create replaced the file with a single rule. Every save now refuses
  and leaves the file byte-identical, with `suppression file <path> could not be parsed (<yaml
  error>); fix it or move it aside before regenerating; nothing was written` on stderr and a 409
  Conflict carrying the same text from the web UI's 11 write requests; a file that does not exist is
  still created ([#880](https://github.com/awslabs/ferret-scan/issues/880)).
