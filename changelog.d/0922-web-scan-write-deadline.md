### 🐛 Bug Fixes

- **web (`/scan`):** a scan that runs longer than 30 seconds now gets its response instead of an
  empty reply. The server's 30-second write timeout started when the request headers were read, so it
  also covered reading and scanning the upload, and a longer scan found it already expired: on a
  29,938,764-byte CSV the CLI reported 8,812 findings in 41.5 s while `/scan` answered
  `curl: (52) Empty reply from server` after 39.4 s. `/scan` now starts the 30-second write budget
  when its response starts, so the same upload returns HTTP 200 with all 8,812 findings; the read
  timeouts are unchanged ([#922](https://github.com/awslabs/ferret-scan/issues/922)).
