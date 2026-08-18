# CI/CD Workflows

The pipeline mirrors the [FIWARE/VCVerifier](https://github.com/FIWARE/VCVerifier)
structure: quality gates run on every PR and on `main`, and releases are
**semver-label driven** — the label on a merged PR decides the next version.

## Workflows

| File | Trigger | Purpose |
|------|---------|---------|
| `pr.yml` | PR → `main` | Fan-out of the quality gates: `style-guide`, `build`, `tests`, `security-analysis`. |
| `check.yml` | PR labeled/opened | Enforces exactly one semver label (`patch`/`minor`/`major`); comments if missing. |
| `pre-release.yml` | PR → `main` | Builds/scans/pushes a `…-PRE-<pr>` image and a GitHub **pre-release** with binaries. |
| `main.yml` | push → `main`, manual | Re-runs the gates, then calls `release.yml`. |
| `release.yml` | called by `main.yml` | Computes the version, pushes the multi-arch image, publishes the GitHub release + binaries. |
| `build.yml` | reusable | `go build` the `go-runner`. |
| `tests.yml` | reusable | `go test -race` (unit + integration) with coverage. |
| `style-guide.yml` | reusable | `golangci-lint` using `.golangci.yml`. |
| `security-analysis.yml` | reusable | `govulncheck` + `gosec`, SARIF → Security tab (non-blocking). |

## Release artifacts

Each release produces:

- **Container image** — `quay.io/wi_stefan/consent-plugin:<version>` (plus `:latest`
  and `:<sha>`), multi-arch `linux/amd64,linux/arm64`. **This is the primary
  deployment artifact**: the APISIX deployment's init container copies
  `/app/go-runner` out of the image into the `ext-plugin` volume
  (see [consent-provider.yaml](https://github.com/FIWARE/data-space-connector/blob/consent-management/k3s/consent-provider.yaml)).
- **Standalone binaries** — `consent-plugin-linux-amd64` / `consent-plugin-linux-arm64`
  (the `go-runner` binary), attached to the GitHub Release for bare-metal runners.

## Versioning

A merged PR must carry one of `patch`, `minor`, `major`. `release.yml` reads that
label and computes the next semver tag via `zwaldowski/semver-release-action`.
Merging a PR with **no** semver label runs the pipeline but cuts **no** release.
`main.yml`'s `workflow_dispatch` accepts an explicit `version` to force a release.

## Required secrets

| Secret | Used by | Purpose |
|--------|---------|---------|
| `QUAY_USERNAME` | `release.yml`, `pre-release.yml` | quay.io robot/user for image push. |
| `QUAY_PASSWORD` | `release.yml`, `pre-release.yml` | quay.io token/password. |

`GITHUB_TOKEN` is provided automatically and covers version detection, SARIF
upload and GitHub Release creation.
