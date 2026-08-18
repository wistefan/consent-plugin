# consent-plugin

An Apache APISIX Go plugin that gates access to personal data on the **consent of the data subject**. It hooks into the APISIX request/response lifecycle via the [go-plugin-runner](https://github.com/apache/apisix-go-plugin-runner) and verifies consent against a [Prometheus-X / Visions consent-manager](https://github.com/Prometheus-X-association/consent-manager) before letting a response reach the client.

## How It Works

The plugin is attached to a route in **both** external-plugin phases:

1. **Request phase** (`ext-plugin-pre-req` → `RequestFilter`): captures the request context — method, path, and the JWT claims (notably `sub`) extracted from the configured header — and stores it keyed by the Nginx `$request_id`.
2. **Response phase** (`ext-plugin-post-resp` → `ResponseFilter`): loads that context and runs a **two-call consent check** against the consent-manager for the request subject:
   - **allow** (a granted consent exists) — the response passes through unchanged.
   - **deny** (no granted consent, or the subject is unknown) — the response is replaced with a configurable error status and body.

The decision is a coarse allow/deny on the subject's consent and is **independent of the response body**, so an empty or non-JSON personal-data response is still gated. If the consent-manager is unreachable, or the plugin's context/credentials are missing, it applies the configured fail-open (default) or fail-closed policy.

> The `$request_id` correlation is required: `ext-plugin-pre-req` and `ext-plugin-post-resp` are separate RPCs to the runner and do **not** share the runner's per-call `ID()`.

## The two-call consent check

The consent-manager has no single "is there consent?" endpoint, so a check is two calls (`{consent_api_url}{consent_api_prefix}` is the base, e.g. `http://consent-manager:3000/v1`):

**1. Resolve the subject to a user identifier** — authenticated with the consent key:
```
POST {base}/users/identifier/search
Header: x-visionstrust-consent-key: <consent_key>
Body:   { "selfDescription": "<provider_sd>", "email": "<subject DID>" }
→      { "userIdentifier": "<id>" }        (404 / empty ⇒ unknown subject ⇒ deny)
```

**2. List that user's consents** — authenticated with the participant JWT:
```
GET {base}/consents/participants/{userIdentifier}?receipt=true
Header: Authorization: Bearer <participant_token>
→      { "consents": [ { "status": "granted" | "revoked" | ... } ] }
```
Access is **allowed** iff at least one returned consent has `status == "granted"`.

The subject DID is taken from the JWT `sub` claim (so `jwt_claims_to_forward` must include `sub`) and sent as the user `email` (the consent-manager's DID-in-email convention).

### Participant authentication (client credentials)

Call 2 needs a **participant JWT**, and call 1 needs the **provider self-description**. Rather than pinning a static (expiring) token and a per-registration SD, the plugin obtains both from **participant client credentials**:

```
POST {base}/participants/login   { "clientID": ..., "clientSecret": ... }  →  { "jwt": ... }   (1h token, cached & refreshed)
GET  {base}/participants/me      Authorization: Bearer <jwt>               →  { "selfDescriptionURL": ... }
```

So configuring `client_id` + `client_secret` is enough: the token is fetched (and re-fetched on expiry or a 401), and `provider_sd` is derived from `/participants/me` when not set explicitly. Tokens are cached process-wide (keyed by base URL + client id). A static `participant_token` and/or explicit `provider_sd` remain supported as overrides.

## Configuration Reference

Configured via the APISIX route plugin JSON (identically on both `ext-plugin-pre-req` and `ext-plugin-post-resp`):

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `consent_api_url` | `string` | **Yes** | — | Base URL of the consent-manager (e.g. `http://consent-manager:3000`). `http`/`https` only. |
| `consent_api_prefix` | `string` | No | `/v1` | API prefix prepended to endpoint paths (the consent-manager's `API_PREFIX`). |
| `consent_key` | `string` | No | — | Shared secret sent as `x-visionstrust-consent-key` on call 1. **Optional**: when the plugin sits behind the authority's facade, the facade injects it server-side (and overrides anything sent here). Falls back to the `CONSENT_KEY` env var. Only needed for a facade-less deployment. |
| `client_id` | `string` | Yes* | — | Participant client id; exchanged (with `client_secret`) for a participant token via `/participants/login`. Falls back to the `CONSENT_CLIENT_ID` env var. |
| `client_secret` | `string` | Yes* | — | Participant client secret. Falls back to the `CONSENT_CLIENT_SECRET` env var, so it need not sit in the route config (etcd). |
| `participant_token_ttl` | `int` | No | `3000` | Seconds a client-credentials token is cached before re-login. |
| `participant_token` | `string` | No | — | *Static* participant JWT override (legacy). Prefer `client_id`/`client_secret`. |
| `provider_sd` | `string` | No | — | Provider self-description URL for call 1. Optional: derived from `/participants/me` when unset. |
| `jwt_header_name` | `string` | No | `Authorization` | Header carrying the JWT. |
| `jwt_claims_to_forward` | `[]string` | No | `[]` | JWT claims to decode. **Must include `sub`** — the subject is resolved from it. |
| `consent_api_timeout` | `int` | No | `5000` | Per-call timeout in ms. Range 1–60000. |
| `deny_status_code` | `int` | No | `403` | Status returned on deny. Range 100–599. |
| `deny_response_body` | `string` | No | `{"error":"access denied by consent policy"}` | Body returned on deny. |
| `deny_response_content_type` | `string` | No | `application/json` | `Content-Type` for deny responses. |
| `fail_open` | `bool` | No | `true` | On a consent-manager error / missing context / missing credential: `true` passes through, `false` denies. |
| `audit_enabled` | `bool` | No | `false` | Emit an access-decision audit event (OTLP/HTTP log) to a Collector for every decision. Async + best-effort; never affects the decision. |
| `audit_otlp_endpoint` | `string` | Yes† | — | Base OTLP/HTTP endpoint of the Collector (e.g. `http://otel-collector:4318`); `/v1/logs` is appended. Falls back to `CONSENT_AUDIT_OTLP_ENDPOINT`. |
| `audit_service_name` | `string` | No | `consent-access-audit` | Resource `service.name` on audit records — the marker the Collector routes on to keep audit logs separate from traces. |

\* Provide **either** `client_id`+`client_secret` (recommended) **or** a static `participant_token`. None are enforced at parse time (the route still loads), but the check cannot succeed without a way to authenticate as the participant: when absent the plugin denies (unless `fail_open` is `true`).

† Required only when `audit_enabled` is `true`.

**Credentials via env.** `consent_key`, `client_id` and `client_secret` each fall back to an environment variable (`CONSENT_KEY`, `CONSENT_CLIENT_ID`, `CONSENT_CLIENT_SECRET`) when omitted from the route config; a value in the config always wins. The plugin runner inherits these from the APISIX container, which sources them from a Kubernetes Secret — so the participant secret need not be stored as plaintext in the route config (etcd).

**Access audit log.** With `audit_enabled`, the plugin emits one OTLP/HTTP **log record** per decision to `audit_otlp_endpoint`, stamped with resource `service.name=<audit_service_name>` and attributes `event.domain=audit`, `consent.decision`, `consent.reason`, `enduser.id`, `http.request.method`, `url.path`, `http.request.id`. Emission is asynchronous, batched, and best-effort (a bounded queue drops rather than blocking the request path), so a slow/absent Collector never affects data access. Mark-based routing lets the Collector send these to an append-only audit sink separate from traces.

## APISIX Route Configuration Example

```bash
curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/*",
    "host": "data-service.example.org",
    "upstream": { "type": "roundrobin", "nodes": { "backend-service:8080": 1 } },
    "plugins": {
      "ext-plugin-pre-req":  { "conf": [ { "name": "consent-filter", "value": "{\"consent_api_url\":\"http://consent-manager:3000\",\"consent_api_prefix\":\"/v1\",\"jwt_claims_to_forward\":[\"sub\"],\"consent_key\":\"<consent-key>\",\"client_id\":\"<participant-client-id>\",\"client_secret\":\"<participant-client-secret>\",\"fail_open\":false}" } ] },
      "ext-plugin-post-resp": { "conf": [ { "name": "consent-filter", "value": "{\"consent_api_url\":\"http://consent-manager:3000\",\"consent_api_prefix\":\"/v1\",\"jwt_claims_to_forward\":[\"sub\"],\"consent_key\":\"<consent-key>\",\"client_id\":\"<participant-client-id>\",\"client_secret\":\"<participant-client-secret>\",\"fail_open\":false}" } ] }
    }
  }'
```

Both phases are required: `pre-req` captures the JWT context; `post-resp` performs the check and blocks the response.

## Build and Deployment

### Prerequisites

- Go (see `go.mod` for the required version)
- Docker (for containerized builds)
- [golangci-lint](https://golangci-lint.run/) (for linting)

### Build / Test / Lint

```bash
make build         # build the go-runner binary
make docker-build  # build the Docker image
make test          # unit + integration tests
make test-cover    # tests with coverage
make lint          # golangci-lint
```

### Local Development with Docker Compose

```bash
docker compose up --build
```

| Service | Description | Ports |
|---------|-------------|-------|
| `etcd` | APISIX configuration store | `2379` |
| `apisix` | APISIX gateway | `9080` (HTTP), `9180` (Admin API) |
| `plugin-runner` | consent-filter plugin runner | — (Unix socket) |

## Project Structure

```
consent-plugin/
├── main.go                        # Entry point — registers plugin, starts runner
├── Makefile / Dockerfile / docker-compose.yaml
├── internal/
│   ├── plugin/
│   │   ├── consent.go             # RequestFilter + ResponseFilter (the consent gate)
│   │   ├── config.go              # Configuration schema and validation
│   │   └── context.go             # Request context store keyed by $request_id
│   ├── consent/
│   │   ├── client.go              # Two-call consent-manager client
│   │   └── models.go              # Request/response models and Decision type
│   ├── jwt/
│   │   └── extractor.go           # JWT extraction and claim decoding
│   └── integration/
│       └── integration_test.go    # End-to-end integration tests
```

## CI & Releases

GitHub Actions run the quality gates on every PR and cut releases on merge to
`main`, following the [FIWARE/VCVerifier](https://github.com/FIWARE/VCVerifier)
structure. See [.github/workflows/README.md](.github/workflows/README.md) for the
full pipeline and [CONTRIBUTING.md](CONTRIBUTING.md) for the label-driven
versioning rules.

Each release publishes:

- a multi-arch (`linux/amd64,arm64`) image
  `quay.io/wi_stefan/consent-plugin:<version>` (also `:latest`, `:<sha>`), and
- standalone `go-runner` binaries (`consent-plugin-linux-{amd64,arm64}`) on the
  GitHub Release.

### Using the release image in APISIX

The image is the primary artifact. In the APISIX deployment an init container
stages the runner binary out of the image into a shared `ext-plugin` volume, and
APISIX launches it as the external plugin runner:

```yaml
initContainers:
  - name: install-consent-plugin
    image: quay.io/wi_stefan/consent-plugin:<version>
    command: ["cp", "/app/go-runner", "/ext-plugin/go-runner"]
    volumeMounts:
      - name: ext-plugin-bin
        mountPath: /ext-plugin
# ... APISIX then runs: exec /ext-plugin/go-runner
```

See the reference
[consent-provider.yaml](https://github.com/FIWARE/data-space-connector/blob/consent-management/k3s/consent-provider.yaml)
for the complete deployment (secret mounting, env, socket wiring).

Releasing requires the `QUAY_USERNAME` / `QUAY_PASSWORD` repository secrets.

## License

See [LICENSE](LICENSE) for details.
