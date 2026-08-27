# consent-plugin

## Overview
An Apache APISIX Go plugin that gates access to personal data on the **consent
of the data owner**. It uses the APISIX go-plugin-runner to hook into the
request/response lifecycle: the request phase (`ext-plugin-pre-req`) captures the
JWT claims, and the response phase (`ext-plugin-post-resp`) asks an external
**OwnerResolver** who owns the data in the upstream payload, then runs a
**two-call check** against a Prometheus-X / Visions consent-manager per resolved
owner (resolve the owner's `userIdentifier`, then list its consents) and allows
the response only when every owner has a granted consent **for this consuming
participant**. Otherwise the response is replaced with a configurable deny.

Ownership never comes from the requestor: the token's `sub` says who is asking,
not whose data is returned. `owner_resolver_url` is therefore required. The two
phases are correlated by the Nginx `$request_id` (not the runner's per-RPC
`ID()`). The gate is coarse (allow/deny) and independent of the response body's
shape; there is no field-level filtering.

The plugin decodes but does **not verify** the JWT — an authentication plugin
earlier in the route is a hard prerequisite.

## Tech Stack
- Language: Go (see `go.mod` for the pinned version)
- Framework: Apache APISIX go-plugin-runner (`github.com/apache/apisix-go-plugin-runner`)
- Test: Go standard `testing` package with `testify` for assertions
- Build: Makefile + Docker

## Project Structure
```
consent-plugin/
├── CLAUDE.md                  # This file — AI agent codebase context
├── README.md                  # Project README (the config surface is contract)
├── Makefile                   # Build, test, lint targets
├── Dockerfile                 # Build the go-runner binary
├── go.mod / go.sum            # Go module definition and checksums
├── main.go                    # Entry point — registers plugin, starts runner
├── internal/
│   ├── plugin/
│   │   ├── consent.go         # Plugin struct, Name(), ParseConf(), RequestFilter(), ResponseFilter()
│   │   ├── config.go          # Configuration schema and validation
│   │   ├── context.go         # Bounded request-context store keyed by $request_id
│   │   ├── consent_test.go    # Unit tests for plugin logic
│   │   ├── config_test.go     # Unit tests for configuration
│   │   ├── config_doc_test.go # Doc-drift guard: README must document every config field
│   │   └── context_test.go    # Unit tests for the context store
│   ├── consent/
│   │   ├── client.go          # Two-call consent-manager client
│   │   ├── client_test.go     # Unit tests for the consent client
│   │   └── models.go          # Request/response models for the consent check
│   ├── ownerresolver/
│   │   ├── client.go          # OwnerResolver /resolve client (who owns the data)
│   │   └── client_test.go     # Unit tests for the resolver client
│   ├── audit/
│   │   ├── audit.go           # OTLP/HTTP access-decision audit exporter
│   │   └── audit_test.go      # Unit tests for the audit exporter
│   ├── logging/
│   │   ├── logging.go         # Leveled logging front end: redaction, sanitisation, rate limiting
│   │   └── logging_test.go    # Unit tests for the logging front end
│   ├── jwt/
│   │   ├── extractor.go       # JWT extraction and claim decoding (no verification)
│   │   └── extractor_test.go  # Unit tests for JWT extraction
│   └── integration/
│       └── integration_test.go # End-to-end plugin lifecycle tests
├── dev/
│   ├── apisix-config.yaml     # APISIX config for the local stack (ext-plugin wiring)
│   ├── otel-collector.yaml    # Collector config receiving the audit log
│   └── mocks/                 # WireMock stubs: consent-manager, OwnerResolver, token service
└── docker-compose.yaml        # Local dev with APISIX + plugin runner + mocks
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
- `internal/plugin/consent.go` — Core plugin: `RequestFilter` captures context
  (keyed by `$request_id`), `ResponseFilter` resolves the data owners and runs
  the per-owner check. `failMode` distinguishes dependency outages (governed by
  `fail_open`) from structural failures that always deny.
- `internal/plugin/config.go` — Plugin configuration schema. `owner_resolver_url`
  is **required**; `fail_open` defaults to **false**. `consent_key`,
  `token_service_url` and `audit_otlp_endpoint` fall back to `CONSENT_KEY`,
  `CONSENT_TOKEN_SERVICE_URL` and `CONSENT_AUDIT_OTLP_ENDPOINT` (config wins) so
  secrets stay out of the route config; `applyEnv()` runs in `ParseConfig`.
- `internal/plugin/config_doc_test.go` — Fails the build when the README's
  configuration table and the `Config` json tags disagree in either direction.
- `internal/plugin/context.go` — Bounded request-context store bridging the two
  phases, keyed by the Nginx `$request_id`: TTL, size cap, background sweep, and
  size/eviction gauges. It deliberately holds no request headers.
- `internal/ownerresolver/client.go` — Client for the external OwnerResolver
  `/resolve` endpoint, which answers from the DATA alone who the owners are and
  whether consent is required. `parties` is for contract identification only.
- `internal/consent/client.go` — Consent-manager client: token from the
  participant-local OID4VP token service (`token_service_url`, cached/refreshed
  per credential identity) + provider-SD derivation (`/participants/me`), the
  participant registry (`/participants`) for DID → self-description mapping, and
  the two-call check (`/users/identifier/search` + `/consents/participants/{id}`).
  A consent counts only if it is granted **to the named consumer** (and covers
  the purpose/resource when known).
- `internal/logging/logging.go` — Logging front end over the runner's zap logger:
  `Redact` fingerprints identifiers, `Sanitize` strips error bodies, and the
  `*Every` variants rate-limit a repeated failure to one line per interval.
  Nothing in the plugin calls `log.Printf` directly.
- `internal/audit/audit.go` — Access-decision audit emitter: one OTLP/HTTP log
  record per decision to the OTel Collector (`service.name=consent-access-audit`
  for routing). Async, batched, best-effort; gated by `audit_enabled` +
  `audit_otlp_endpoint`. `ResponseFilter` → `recordAudit` calls it.
- `go.mod` — Module path: `consent-plugin`.
