### 🐛 Bug Fixes

- **web (`/scan`):** a finding inside an embedded attachment is now named `<upload> -> <member>`, as
  the CLI names it, instead of by the upload alone. Over the 639 public corpus files, 90 findings in
  4 uploads had lost which attachment held them. The suppression hash folds in the file name, so a
  rule the CLI generated for such a finding did not suppress it on the web; it now does, and a rule
  created in the web UI before this change keeps suppressing what it did
  ([#924](https://github.com/awslabs/ferret-scan/issues/924)).
- **web (`/scan`):** a text upload carrying a NUL byte, which the router refuses, is now reported as
  not examined with the cause `cannot parse`, as on the CLI, instead of answering success with no
  finding and no disclosure (2 of the 639 public corpus files)
  ([#924](https://github.com/awslabs/ferret-scan/issues/924)).
