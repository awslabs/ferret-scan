## Pull

```bash
docker pull public.ecr.aws/awslabs/ferret-scan:latest
docker pull public.ecr.aws/awslabs/ferret-scan:2.6.2
```

The entrypoint is `/ferret-scan`: everything after the image name is an argument to it. Do not
repeat `ferret-scan` after the image name. `finch` takes the same commands as `docker`.

## Scan files (mount a directory at /data)

```bash
docker run --rm -v "$PWD:/data" public.ecr.aws/awslabs/ferret-scan:latest --file /data --recursive
docker run --rm -v "$PWD:/data" public.ecr.aws/awslabs/ferret-scan:latest --file /data/report.pdf --format json
docker run --rm -t -v "$PWD:/data" public.ecr.aws/awslabs/ferret-scan:latest --file "/data/*.log" --checks SECRETS,CREDIT_CARD
```

Quote globs so the shell does not expand them; `-t` gives coloured output. Findings hide the
matched values by default; `--show-match` prints them.

## Redact a stream (redacted bytes to stdout, findings to stderr)

```bash
cat export.csv | docker run --rm -i public.ecr.aws/awslabs/ferret-scan:latest --stdin --enable-redaction > safe-export.csv
```

## CI report (SARIF, GitLab SAST or JUnit)

```bash
docker run --rm -v "$PWD:/data" public.ecr.aws/awslabs/ferret-scan:latest --file /data --recursive --format sarif --quiet > ferret.sarif
```

## Web UI

```bash
docker run --rm -p 127.0.0.1:8080:8080 public.ecr.aws/awslabs/ferret-scan:latest --web --port 8080
```

Open http://localhost:8080. Keep the `127.0.0.1:` prefix: inside the container the server binds
`0.0.0.0`, so the port publish is the boundary. Reach it from another machine over an SSH tunnel,
not by publishing the port wider.

## Keep configuration and suppressions between runs

Add `-v ~/.ferret-scan:/home/ferret/.ferret-scan` to any command above.

## Exit codes

`0` the scan ran (findings do not change it; read them from the output) · `1` the run failed ·
`3` with `--fail-on-incomplete`, the run did not fully do what was asked. `--pre-commit-mode` maps
findings onto the exit code instead. Full table: https://github.com/awslabs/ferret-scan#exit-codes

All options: `docker run --rm public.ecr.aws/awslabs/ferret-scan:latest --help`, or
https://github.com/awslabs/ferret-scan/blob/main/docs/README.md
