# ECR Public Gallery page

[← Back to Documentation Index](../README.md)

The text on <https://gallery.ecr.aws/awslabs/ferret-scan> is written here and applied to the
registry with [`scripts/ecr-public-catalog.sh`](../../scripts/ecr-public-catalog.sh). Before this
directory existed the page was typed into the registry console: nothing re-read it, and by v2.6.2
its "About" tab named features the README does not claim, listed Windows for a Linux-only image,
and had no link to this repository, while its "Usage" tab was empty.

| File | Gallery field | Limit (API) |
|---|---|---|
| [`catalog.json`](catalog.json) | `description` (the one-paragraph text in search results and under the title), `architectures`, `operatingSystems` (the badges and search filters) | description 1,024 chars; badges from the API's fixed lists |
| [`about.md`](about.md) | the **About** tab, markdown | 25,600 chars |
| [`usage.md`](usage.md) | the **Usage** tab, markdown | 25,600 chars |

The limits and the badge vocabularies (`x86`, `x86-64`, `ARM`, `ARM 64`; `Linux`, `Windows`) are
from `RepositoryCatalogDataInput` in the ECR Public API reference; `check` enforces them.

## Rules for the text

The page is a channel page, not a second README. It carries what someone who found the image needs
to pull and run it, exit codes, and links; everything else (validators, flags, configuration) is a
link into this repository so that the page cannot drift from it again. The badges describe the image,
not the project: the manifest list has `linux/amd64` and `linux/arm64`, so the operating system is
`Linux` only, even though release binaries exist for Windows. A version tag quoted in `usage.md` is
the latest release at the time of writing; the `latest` tag in the same block is what most readers
copy.

## Applying a change

```bash
scripts/ecr-public-catalog.sh check    # limits and badge values, no network
scripts/ecr-public-catalog.sh diff     # the files against the live page; anonymous; exit 1 on drift
scripts/ecr-public-catalog.sh apply    # write, then read back and compare
```

`apply` needs credentials for the AWS account that owns the `awslabs` alias, with
`ecr-public:GetRepositoryCatalogData` and `ecr-public:PutRepositoryCatalogData` on the repository;
it runs in `us-east-1`, the only Region ECR Public has. `PutRepositoryCatalogData` replaces the whole
catalog object and the logo is not kept in this repository, so `apply` downloads the live logo first
and sends it back unchanged. The gallery page can show the previous text for a few minutes after a
successful put.

The release workflow does not run `apply`: its role (`AWS_ROLE_ARN` in
[`docker-multiarch.yml`](../../.github/workflows/docker-multiarch.yml)) pushes images and has no
catalog-data permission. Until it does, a maintainer runs `apply` after merging a change here;
`diff` tells anyone, without credentials, whether the page matches `main`.
