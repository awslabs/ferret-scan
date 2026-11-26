### 🐛 Bug Fixes

- **`--version`, `--help`:** both are now answered before any configuration is read, so neither depends on
  a config file in the working directory or the user config dir. Before, each ran the scan's front half
  first: a configured regex RE2 rejects printed its `Warning: config value …` line above the version, a
  malformed config printed its load failure there, and with the pre-commit refusal of a discovered config
  (#293) a hook environment would have exited 1 before the version printed. `--version` is one line on
  stdout and nothing on stderr in every directory; `--help`, `--help checks` and `--help <check>` print
  what they printed (the help text is the validators' own, built from the defaults). The warnings
  themselves are unchanged where they matter: every `--file` and `--stdin` run still prints them
  ([#1085](https://github.com/awslabs/ferret-scan/issues/1085)).
