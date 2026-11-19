### 🐛 Bug Fixes

- **formatters (config provenance):** a project config found in the working directory is now named
  in the report whether or not it narrowed anything, and gitlab-sast and text name it too
  ([#1007](https://github.com/awslabs/ferret-scan/issues/1007)). Before this, `ScanScope` existed
  only for a narrowed run, so a `.ferret-scan.yaml` that disabled nothing was disclosed on stderr
  alone, in every format, and json had no `scan` block at all; gitlab-sast and text dropped the
  config name even on a narrowed run. Now json and yaml carry `scan.config`, junit and sarif their
  config properties, gitlab-sast an `info` entry in `scan.messages[]`, and text a `Config:` line
  after the report. csv stays stderr-only. A run with no config in the working directory keeps
  every byte. ⚠ A json, yaml, junit or sarif report of a run governed by a working-directory config
  now gains the `scan` block (junit and sarif the matching properties), and a gitlab-sast or text
  report one `info` message or `Config:` line; a consumer that compared those documents byte for
  byte against a stored baseline will see the difference.
