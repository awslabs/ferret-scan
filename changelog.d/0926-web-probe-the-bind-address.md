### 🐛 Bug Fixes

- **cli (`--web`):** the port check before the server starts now probes the address `--bind` names
  instead of every interface, so `--web --bind 127.0.0.1` no longer listens on `0.0.0.0` and `[::]`
  for a moment before its loopback bind. It also answers for the right address: with a port held only
  on `[::1]`, as a dev server on `localhost` holds it, `--port <that port>` moved the server to 8080
  with `Port <n> is not available`; it now starts on the port it was given. The server listens once
  and serves that listener, so the check and the bind can no longer disagree
  ([#926](https://github.com/awslabs/ferret-scan/issues/926)).
- **web (`--bind ::1`):** an IPv6 bind address now starts the server. It failed with `could not find
  an available port ... too many colons in address`, and behind that the Origin check answered 403 to
  a POST from a page served on `[::1]`; both now work
  ([#926](https://github.com/awslabs/ferret-scan/issues/926)).
