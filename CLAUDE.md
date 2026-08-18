# consent-plugin

## Overview
An Apache APISIX Go plugin that gates access to personal data on the data
subject's **consent**. It uses the APISIX go-plugin-runner to hook into the
request/response lifecycle: the request phase (`ext-plugin-pre-req`) captures
the JWT `sub`, and the response phase (`ext-plugin-post-resp`) runs a **two-call
check** against a Prometheus-X / Visions consent-manager (resolve the subject's
`userIdentifier`, then list its consents) and allows the response only when a
granted consent exists — otherwise it replaces the response with a configurable
deny. The two phases are correlated by the Nginx `$request_id` (not the runner's
per-RPC `ID()`). The gate is coarse (allow/deny) and independent of the response
body; there is no field-level filtering.

## Tech Stack
- Language: Go 1.21+
- Framework: Apache APISIX go-plugin-runner (`github.com/apache/apisix-go-plugin-runner`)
- Test: Go standard `testing` package with `testify` for assertions
- Build: Makefile + Docker

## Project Structure
```
consent-plugin/
├── CLAUDE.md                  # This file — AI agent codebase context
├── IMPLEMENTATION_PLAN.md     # Step-by-step implementation plan
├── README.md                  # Project README
├── Makefile                   # Build, test, lint targets
├── Dockerfile                 # Build the go-runner binary
├── go.mod                     # Go module definition
├── go.sum                     # Go dependency checksums
├── main.go                    # Entry point — registers plugin, starts runner
├── internal/
│   ├── plugin/
│   │   ├── consent.go         # Plugin struct, Name(), ParseConf(), RequestFilter(), ResponseFilter()
│   │   ├── consent_test.go    # Unit tests for plugin logic
│   │   └── config.go          # Configuration schema struct and validation
│   ├── consent/
│   │   ├── client.go          # HTTP client for external consent API
│   │   ├── client_test.go     # Unit tests for consent client
│   │   └── models.go          # Request/response models for consent API
│   ├── jwt/
│   │   ├── extractor.go       # JWT extraction and parsing from request headers
│   │   └── extractor_test.go  # Unit tests for JWT extraction
│   └── filter/
│       ├── response.go        # JSON response body filtering/redaction logic
│       └── response_test.go   # Unit tests for response filtering
└── docker-compose.yaml        # Local dev with APISIX + plugin runner
```

## Build & Test
```bash
# Build the go-runner binary
make build

# Run all tests
make test

# Run tests with coverage
make test-cover

# Run linter
make lint

# Build Docker image
make docker-build
```

## Key Conventions
- All exported types and functions must have GoDoc comments.
- No magic constants — use named constants with descriptive names.
- Internal packages under `internal/` to enforce encapsulation.
- Table-driven tests with `t.Run()` subtests.
- Configuration structs use JSON tags matching APISIX plugin config format.
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)`.

## Important Files
- `main.go` — Entry point; registers the consent plugin and starts the runner.
- `internal/plugin/consent.go` — Core plugin: `RequestFilter` captures context (keyed by `$request_id`), `ResponseFilter` runs the two-call check and allows/denies.
- `internal/plugin/config.go` — Plugin configuration schema (consent-manager URL + prefix, `consent_key`, participant `client_id`/`client_secret` (or a static `participant_token`), optional `provider_sd`, JWT settings, deny behavior, `fail_open`). `consent_key` is **optional** (the authority's facade injects it and overrides anything sent). `consent_key`/`client_id`/`client_secret` fall back to env vars `CONSENT_KEY`/`CONSENT_CLIENT_ID`/`CONSENT_CLIENT_SECRET` (config wins) so the secret stays out of the route config; `applyEnv()` runs in `ParseConfig`.
- `internal/plugin/context.go` — Concurrent request-context store bridging the two phases, keyed by the Nginx `$request_id`.
- `internal/consent/client.go` — Consent-manager client: participant client-credentials login (`/participants/login`, token cached/refreshed) + provider-SD derivation (`/participants/me`), then the two-call check (`/users/identifier/search` + `/consents/participants/{id}`). Token/SD cache is keyed per participant with a per-entry lock, so concurrent first requests coalesce onto one login without a global lock across the HTTP call.
- `internal/audit/audit.go` — Access-decision audit emitter: exports one OTLP/HTTP log record per decision to the OTel Collector (marked `service.name=consent-access-audit` for routing). Async, batched, best-effort (bounded queue drops rather than blocking); gated by `audit_enabled` + `audit_otlp_endpoint`. `ResponseFilter` → `recordAudit` calls it.
- `go.mod` — Module path: `consent-plugin` (or as configured).
