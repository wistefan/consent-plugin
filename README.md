# consent-plugin

An Apache APISIX Go plugin that intercepts HTTP responses and applies consent-based filtering for personal data. It hooks into the APISIX request/response lifecycle using the [go-plugin-runner](https://github.com/apache/apisix-go-plugin-runner), consults an external consent API, and filters or denies responses based on consent decisions.

## How It Works

1. **Request Phase** (`RequestFilter`): Captures the incoming request context — HTTP method, path, headers, and JWT claims — and stores it for use during the response phase.
2. **Response Phase** (`ResponseFilter`): Reads the upstream response body, extracts top-level JSON field names, sends a consent check request to the external consent API, and applies the returned decision:
   - **allow** — The response passes through unchanged.
   - **deny** — The response is replaced with a configurable error status code and body.
   - **filter** — Specified fields (including nested fields via dot-notation) are removed from the JSON response body.

Non-JSON responses pass through without modification. If the consent API is unreachable, the plugin applies a configurable fail-open (default) or fail-closed policy.

## Configuration Reference

The plugin is configured via APISIX route/service plugin configuration JSON:

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `consent_api_url` | `string` | **Yes** | — | Base URL of the external consent API (e.g., `https://consent.example.com`). Must use `http` or `https` scheme. |
| `consent_api_timeout` | `int` | No | `5000` | Timeout in milliseconds for consent API calls. Range: 1–60000. |
| `jwt_header_name` | `string` | No | `"Authorization"` | Name of the HTTP header containing the JWT token. |
| `jwt_claims_to_forward` | `[]string` | No | `[]` | JWT claim keys to extract and forward to the consent API (e.g., `["sub", "scope"]`). |
| `deny_status_code` | `int` | No | `403` | HTTP status code returned when consent is denied. Range: 100–599. |
| `deny_response_body` | `string` | No | `{"error":"access denied by consent policy"}` | Response body returned when consent is denied. |
| `deny_response_content_type` | `string` | No | `"application/json"` | `Content-Type` header for denial responses. |
| `fail_open` | `bool` | No | `true` | Behavior when the consent API is unreachable. `true` = pass through (fail-open). `false` = deny (fail-closed). |

## APISIX Route Configuration Example

Enable the plugin on an APISIX route using the Admin API:

```bash
curl -X PUT http://127.0.0.1:9180/apisix/admin/routes/1 \
  -H "X-API-KEY: your-admin-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "uri": "/api/v1/users/*",
    "upstream": {
      "type": "roundrobin",
      "nodes": {
        "backend-service:8080": 1
      }
    },
    "plugins": {
      "ext-plugin-pre-req": {
        "conf": [
          {
            "name": "consent-filter",
            "value": "{\"consent_api_url\":\"http://consent-service:8080\",\"jwt_claims_to_forward\":[\"sub\",\"scope\"],\"deny_status_code\":403,\"fail_open\":true}"
          }
        ]
      }
    }
  }'
```

## Consent API Contract

The plugin POSTs a JSON request to `{consent_api_url}/check` and expects a JSON response.

### Request (`POST /check`)

```json
{
  "subject": "user-123",
  "resource": "/api/v1/users/42",
  "method": "GET",
  "claims": {
    "sub": "user-123",
    "scope": "read"
  },
  "response_fields": ["id", "name", "email", "phone"]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `subject` | `string` | Identity of the requester (from JWT `sub` claim). |
| `resource` | `string` | The request path being accessed. |
| `method` | `string` | HTTP method of the original request. |
| `claims` | `object` | Forwarded JWT claims as key-value pairs. |
| `response_fields` | `[]string` | Top-level field names found in the upstream response body. |

### Response

```json
{
  "decision": "filter",
  "denied_fields": ["email", "phone"],
  "reason": "user has not consented to share contact information"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `decision` | `string` | Consent verdict: `"allow"`, `"deny"`, or `"filter"`. |
| `denied_fields` | `[]string` | Field names/paths to remove when decision is `"filter"`. Supports dot-notation (e.g., `"address.street"`). |
| `reason` | `string` | Human-readable explanation for the decision. |

## Build and Deployment

### Prerequisites

- Go 1.21 or later
- Docker (for containerized builds)
- [golangci-lint](https://golangci-lint.run/) (for linting)

### Build

```bash
# Build the go-runner binary
make build

# Build the Docker image
make docker-build
```

### Test

```bash
# Run all tests (unit + integration)
make test

# Run tests with coverage report
make test-cover
```

### Lint

```bash
# Run golangci-lint
make lint
```

### Local Development with Docker Compose

Start a local APISIX instance with the plugin runner:

```bash
docker compose up --build
```

This starts three services:

| Service | Description | Ports |
|---------|-------------|-------|
| `etcd` | APISIX configuration store | `2379` |
| `apisix` | APISIX gateway | `9080` (HTTP), `9180` (Admin API) |
| `plugin-runner` | consent-filter plugin runner | — (Unix socket) |

## Project Structure

```
consent-plugin/
├── main.go                        # Entry point — registers plugin, starts runner
├── Makefile                       # Build, test, lint, docker targets
├── Dockerfile                     # Multi-stage Docker build
├── docker-compose.yaml            # Local dev environment
├── .golangci.yml                  # Linter configuration
├── .gitea/workflows/ci.yaml       # CI pipeline (lint, test, build)
├── internal/
│   ├── plugin/
│   │   ├── consent.go             # Core plugin (RequestFilter, ResponseFilter)
│   │   ├── config.go              # Configuration schema and validation
│   │   └── context.go             # Request context store (sync.Map)
│   ├── consent/
│   │   ├── client.go              # HTTP client for consent API
│   │   └── models.go              # Request/response models and Decision type
│   ├── jwt/
│   │   └── extractor.go           # JWT extraction and claim decoding
│   ├── filter/
│   │   └── response.go            # JSON field removal (dot-notation support)
│   └── integration/
│       └── integration_test.go    # End-to-end integration tests
```

## License

See [LICENSE](LICENSE) for details.
