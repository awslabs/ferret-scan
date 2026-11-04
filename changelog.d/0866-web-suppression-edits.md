### 🐛 Bug Fixes

- **web (suppressions):** the web UI's rule actions lost or misplaced data. An edit made the rule
  permanent whatever it sent, including an edit that changed only the reason and the undo of an
  edit; it now keeps an omitted expiry, clears it on `null`, sets an RFC 3339 time, and answers
  anything else with a 400 that leaves the file unchanged. Create ignored its `expires_at` (and the
  add dialog still sent a one-week default that #696 had removed elsewhere); it now stores it, and
  the dialog sends none. The undo of a delete posted the rules to a field the endpoint never read, so
  it restored 0 rules and reported success; it now puts back the whole rule at its position (delete
  then undo leaves the file byte-identical), and `bulk-create` returns `{created, failed}` with
  `success: false` when nothing of a non-empty request was created. An edit, enable, disable or
  removal of an `id` two rules share acted on the first of them; every id-keyed action now answers
  409 and changes nothing. The scan hashed the display copy of the upload name, which drops
  `& < > " '`, so a CLI rule for `q&a.txt` suppressed 0 of 2 findings in the web UI and a rule made
  there suppressed 0 of 2 on the CLI; both are now 2 of 2. The help text no longer says rules expire
  automatically or in a week ([#866](https://github.com/awslabs/ferret-scan/issues/866)).
