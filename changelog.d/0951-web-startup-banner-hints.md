### 🐛 Bug Fixes

- **web (startup banner):** the `--web` banner no longer suggests exposures. On a loopback bind it
  suggested `--bind 0.0.0.0`, which serves the unauthenticated UI on every interface; it now names an
  SSH local forward of the same port (`ssh -N -L <port>:127.0.0.1:<port> <this host>`). On a
  non-loopback bind it suggested `-p 8082:<port>`, which publishes on every host interface and, with a
  host port other than the server's, fails the Origin check on every POST (403); it now names
  `-p 127.0.0.1:<port>:<port>`. An IPv6 loopback bind is shown as `http://[::1]:<port>`
  ([#951](https://github.com/awslabs/ferret-scan/issues/951)).
