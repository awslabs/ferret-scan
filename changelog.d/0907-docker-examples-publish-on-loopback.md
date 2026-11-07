### 📚 Documentation

- **docs (Docker):** the `docker run` examples that start the web UI now publish it on the host's
  loopback, `-p 127.0.0.1:8080:8080`, instead of `-p 8080:8080`, which put the unauthenticated UI on
  every interface of the host ([#907](https://github.com/awslabs/ferret-scan/issues/907)). Inside the
  container the server still binds `0.0.0.0` (`FERRET_CONTAINER_MODE=true`), so the publish is the
  boundary; the docs now say to reach the UI from another machine through an SSH port-forward, and
  the README says so instead of suggesting `--bind 0.0.0.0`. The examples in
  `docs/user-guides/README-Docker.md` also gain the `--web --port 8080` they lacked (with no
  arguments the image exits 1, `Input file or directory is required`), and its custom-port example
  keeps one port on both sides (`-p 127.0.0.1:3000:3000 … --port 3000`): the UI refuses a POST whose
  `Origin` names a port it does not listen on, so behind `-p 3000:8080` a scan from
  `http://localhost:3000` was refused with `403 cross-origin request rejected`.
