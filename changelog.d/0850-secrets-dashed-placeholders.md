### 🐛 Bug Fixes

- **secrets (dashed and bare placeholders):** placeholder values written with dashes, in upper
  case or as a bare token (`api_key=your-api-key`, `api_key=REPLACE_ME`, `token=YOUR-TOKEN`) are
  no longer reported as credentials; before, they scored 75 to 100. The placeholder list is now
  compared with case folded and `-` read as `_`, but the placeholder must still be the whole value,
  so a real secret that only contains one of these words is reported as before. `changeme` is
  still reported, as before: it is a real vendor default password
  ([#850](https://github.com/awslabs/ferret-scan/issues/850)).
