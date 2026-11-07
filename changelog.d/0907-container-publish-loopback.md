### 🐛 Bug Fixes

- **container (publish):** `make container-run`, `make container-test` and `docker-compose.yml`
  publish the web UI port on `127.0.0.1` only (`-p 127.0.0.1:8080:8080`, `-p 127.0.0.1:8081:8080`,
  `"127.0.0.1:8080:8080"`). A bare host port publishes on every interface of the host: `docker
  compose config` showed no `host_ip` for the old mapping and shows `host_ip: 127.0.0.1` now, and
  during `make container-test` `docker port ferret-test` reads `8080/tcp -> 127.0.0.1:8081` and
  nothing else, `/health` answers 200 on `127.0.0.1:8081` and the host's own non-loopback address
  refuses the connection. Loopback is the posture TM-01 in `THREAT_MODEL.md` makes the default. The
  bind inside the container is unchanged (`FERRET_CONTAINER_MODE=true` still binds `0.0.0.0`
  there, so the publish is the boundary). To reach the UI from another machine, use an SSH local
  port forward rather than a wider publish
  ([#907](https://github.com/awslabs/ferret-scan/issues/907)).
- **container (make targets):** `make container-run` and `make container-test` now start the image
  with `--web --port 8080`. Without it the image ran the CLI with no input and exited 1 at once
  (`Error: Input file or directory is required`), so neither target ever served the port it
  published, and `make container-test` still printed `✓ Container test passed` and exited 0: its
  health check was `curl … || (… && exit 1)`, and the `exit 1` left only that subshell. The check
  now fails the target (measured with a failing `curl`: exit 2, container removed)
  ([#907](https://github.com/awslabs/ferret-scan/issues/907)).
