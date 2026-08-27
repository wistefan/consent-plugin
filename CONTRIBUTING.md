# Contributing

## Reporting a vulnerability

Do not open a public issue. See [SECURITY.md](SECURITY.md) — this plugin decides
whether personal data is released, so a defect in it is handled privately first.

## Local toolchain

`go.mod` requires **Go 1.26**. If your system Go is older, the build tries to
fetch the toolchain automatically — and in an environment where `GOTOOLCHAIN`
cannot download (an air-gapped machine, a restricted proxy) it fails with
`toolchain not available`, which reads like "Go 1.26 does not exist" rather than
"the download was blocked".

Either install Go 1.26+ directly, or point at a full patch version already in the
module cache and disable switching:

```bash
ls -d "$(go env GOMODCACHE)"/golang.org/toolchain@*/   # what is cached
export PATH="$(go env GOMODCACHE)/golang.org/toolchain@v0.0.1-go1.26.7.linux-amd64/bin:$PATH"
export GOTOOLCHAIN=local
```

Note the bare major version (`go1.26`) is what fails; the full patch version
(`go1.26.7`) is what the cache holds.

`golangci-lint` must match the version CI pins — see
`.github/workflows/style-guide.yml` and `.gitea/workflows/ci.yaml`, which are
kept in step with each other.

## Pull requests

- Target the `main` branch.
- The PR pipeline (`pr.yml`) runs lint, build, unit + integration tests and
  security analysis. All must pass.
- **Every PR must carry exactly one semver label** — `patch`, `minor`, or
  `major`. The `check.yml` workflow enforces this and comments on the PR when
  the label is missing.

## Versioning & releases

Releases are driven by the semver label on the merged PR:

| Label | Bump | Example |
|-------|------|---------|
| `patch` | `x.y.Z` | bug fixes, no API change |
| `minor` | `x.Y.0` | backwards-compatible features/config |
| `major` | `X.0.0` | breaking changes |

On merge to `main`, `main.yml` re-runs the gates and calls `release.yml`, which:

1. computes the next version from the label,
2. builds, scans and pushes the multi-arch image to
   `quay.io/seamware/consent-plugin`, and
3. publishes a GitHub Release with the `go-runner` binaries.

While a PR is open, `pre-release.yml` publishes a `…-PRE-<pr>` image and a GitHub
pre-release so the change can be deployed and tested before merge.

Merging without a semver label runs the pipeline but produces no release.

## Copyright headers

Every Go source file must carry the Apache-2.0 copyright header. The canonical text lives in
[`hack/license-header.txt`](hack/license-header.txt) - edit it there and nowhere else.

```bash
make license-check   # verify (what CI runs)
make license-fix     # add the header to files that lack it
```

CI enforces this on pull requests and on pushes to `main`, and gates both the pre-release and the
release on it, so a version can never ship a file without the header. The Gitea pipeline
(`.gitea/workflows/ci.yaml`) runs the same check. It covers `*.go` only: the header is a `/* */`
block, which is not valid comment syntax in the Dockerfile or the Makefile.

## Local checks

Run the same gates locally before opening a PR:

```bash
make license-check # copyright headers
make lint          # golangci-lint
make test          # unit + integration tests (race)
make build         # compile the go-runner
make docker-build  # build the image
```
