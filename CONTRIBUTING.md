# Contributing

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
   `quay.io/wi_stefan/consent-plugin`, and
3. publishes a GitHub Release with the `go-runner` binaries.

While a PR is open, `pre-release.yml` publishes a `…-PRE-<pr>` image and a GitHub
pre-release so the change can be deployed and tested before merge.

Merging without a semver label runs the pipeline but produces no release.

## Local checks

Run the same gates locally before opening a PR:

```bash
make lint          # golangci-lint
make test          # unit + integration tests (race)
make build         # compile the go-runner
make docker-build  # build the image
```
