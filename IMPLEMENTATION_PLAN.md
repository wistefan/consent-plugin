# Implementation Plan: APISIX plugin to filter responses

## Overview
Build a Go-based Apache APISIX plugin using the go-plugin-runner that intercepts HTTP responses, consults an external consent API with the original request context (including JWT), and filters or denies responses based on consent decisions for personal data fields.

## Steps

### Step 1: Project scaffolding and go-plugin-runner setup

Set up the Go module, directory structure, build tooling, and a minimal working plugin runner.

**Files to create:**
- `go.mod` — Initialize Go module with `github.com/apache/apisix-go-plugin-runner` dependency (and `github.com/stretchr/testify` for tests).
- `main.go` — Entry point that imports the plugin package (to trigger `init()` registration) and calls `runner.Run()`.
- `Makefile` — Targets: `build` (produces `go-runner` binary), `test`, `test-cover`, `lint`, `docker-build`, `clean`.
- `Dockerfile` — Multi-stage build: compile the Go binary, copy into a minimal runtime image.
- `docker-compose.yaml` — Local development environment with APISIX and the plugin runner.
- `internal/plugin/consent.go` — Minimal plugin skeleton: struct with `Name()` returning `"consent-filter"`, stub `ParseConf()`, stub `RequestFilter()`, stub `ResponseFilter()`. Register via `init()` calling `plugin.RegisterPlugin()`.

**Acceptance criteria:**
- `go mod tidy` succeeds with no errors.
- `make build` produces a `go-runner` binary.
- The plugin registers itself with the name `"consent-filter"`.
- The project compiles and the runner starts (and exits cleanly if no APISIX socket is present).

---

### Step 2: Plugin configuration schema and validation

Define the plugin's configuration struct that APISIX will pass as JSON, and implement `ParseConf()` with validation.

**Files to create/modify:**
- `internal/plugin/config.go` — Define `Config` struct with fields:
  - `ConsentAPIURL` (string, required) — URL of the external consent API.
  - `ConsentAPITimeout` (int, optional, default 5000ms) — Timeout in milliseconds for consent API calls.
  - `JWTHeaderName` (string, optional, default `"Authorization"`) — Header containing the JWT.
  - `JWTClaimsToForward` ([]string, optional) — Which JWT claims to send to the consent API (e.g., `["sub", "scope"]`).
  - `DenyStatusCode` (int, optional, default 403) — HTTP status code when consent is denied.
  - `DenyResponseBody` (string, optional, default `{"error":"access denied by consent policy"}`) — Body returned on denial.
  - `DenyResponseContentType` (string, optional, default `"application/json"`) — Content-Type header for denial responses.
- `internal/plugin/config.go` — `Validate()` method on Config that checks required fields and value ranges.
- `internal/plugin/consent.go` — Update `ParseConf()` to unmarshal JSON into `Config`, call `Validate()`, return error on failure.
- `internal/plugin/config_test.go` — Table-driven tests for config parsing and validation: valid config, missing required fields, invalid values, defaults applied.

**Acceptance criteria:**
- `ParseConf()` correctly deserializes valid JSON into `Config`.
- Missing `ConsentAPIURL` returns an error.
- Default values are applied for optional fields.
- All tests pass.

---

### Step 3: Request context capture and JWT extraction

Implement `RequestFilter()` to capture request headers and extract JWT claims, storing them for use during the response phase.

**Files to create/modify:**
- `internal/jwt/extractor.go` — Functions:
  - `ExtractToken(headerValue string) (string, error)` — Strips `"Bearer "` prefix, returns raw JWT string.
  - `DecodeClaims(token string, claimKeys []string) (map[string]interface{}, error)` — Base64-decodes the JWT payload (no signature verification — APISIX/upstream handles authn), extracts requested claim keys. Returns a map of claim key → value.
- `internal/jwt/extractor_test.go` — Table-driven tests: valid Bearer token, missing prefix, malformed JWT, empty claims list, specific claim extraction.
- `internal/plugin/consent.go` — Implement `RequestFilter()`:
  - Extract request ID via `r.ID()`.
  - Read JWT from configured header via `r.Header().Get()`.
  - Call JWT extractor to get claims.
  - Capture all request headers.
  - Store request context (headers map, JWT claims, request path, method) in a package-level concurrent-safe map (`sync.Map`) keyed by request ID.
- `internal/plugin/context.go` — Define `RequestContext` struct (method, path, headers, JWT claims) and the `sync.Map`-based store with `Store()`, `Load()`, `Delete()` functions.
- `internal/plugin/context_test.go` — Tests for concurrent store/load/delete operations.

**Acceptance criteria:**
- JWT extraction works for standard `Bearer <token>` headers.
- JWT payload claims are correctly decoded (base64url).
- Request context is stored and retrievable by request ID.
- Concurrent access to context store is safe.
- All tests pass.

---

### Step 4: External consent API client

Build the HTTP client that calls the external consent API to get allow/deny/filter decisions.

**Files to create/modify:**
- `internal/consent/models.go` — Define types:
  - `ConsentRequest` struct — Fields: `Subject` (from JWT sub claim), `Resource` (request path), `Method` (HTTP method), `Claims` (map of JWT claims), `ResponseFields` ([]string — top-level field names found in the response body).
  - `ConsentResponse` struct — Fields: `Decision` (string: `"allow"`, `"deny"`, `"filter"`), `DeniedFields` ([]string — field names/paths to remove), `Reason` (string — human-readable reason for the decision).
  - `Decision` type (string enum with constants `DecisionAllow`, `DecisionDeny`, `DecisionFilter`).
- `internal/consent/client.go` — Define:
  - `Client` struct with `baseURL`, `httpClient` (with configurable timeout), and `NewClient(baseURL string, timeoutMs int) *Client` constructor.
  - `CheckConsent(ctx context.Context, req ConsentRequest) (*ConsentResponse, error)` method — POST JSON to `{baseURL}/check`, parse response, validate decision field.
  - Named constants for the endpoint path, default timeout, etc.
- `internal/consent/client_test.go` — Table-driven tests using `httptest.NewServer`:
  - Successful allow response.
  - Successful deny response.
  - Successful filter response with denied fields.
  - Consent API returns non-200 status.
  - Consent API timeout.
  - Malformed response body.

**Acceptance criteria:**
- Client correctly serializes `ConsentRequest` and deserializes `ConsentResponse`.
- Timeout is respected.
- Non-200 responses from consent API produce descriptive errors.
- All tests pass.

---

### Step 5: Response filtering and denial logic

Implement `ResponseFilter()` to call the consent API and apply filtering/denial to the upstream response.

**Files to create/modify:**
- `internal/filter/response.go` — Functions:
  - `ExtractFieldNames(body []byte) ([]string, error)` — Parse JSON body, return top-level field names.
  - `RemoveFields(body []byte, fields []string) ([]byte, error)` — Parse JSON body, remove specified fields (supports dot-notation paths for nested fields, e.g., `"user.email"`), re-serialize to JSON.
- `internal/filter/response_test.go` — Table-driven tests:
  - Remove top-level fields.
  - Remove nested fields via dot-notation.
  - Empty denied fields list (no-op).
  - Non-JSON body (pass through unchanged).
  - Empty body.
- `internal/plugin/consent.go` — Implement `ResponseFilter()`:
  1. Get request ID from the response (or from a header set during RequestFilter).
  2. Load stored `RequestContext` from the context store; delete after loading (cleanup).
  3. Read response body via `w.ReadBody()`.
  4. If body is empty or not JSON content-type, pass through.
  5. Extract top-level field names from body.
  6. Build `ConsentRequest` from stored context + response field names.
  7. Call consent client's `CheckConsent()`.
  8. Handle decision:
     - `allow` → do nothing, response passes through.
     - `deny` → call `w.WriteHeader(conf.DenyStatusCode)`, `w.Write([]byte(conf.DenyResponseBody))`.
     - `filter` → call `RemoveFields()` on body with denied fields, then `w.Write(filteredBody)`.
  9. On consent API error: log warning, apply a configurable fail-open or fail-closed policy (default: fail-open, pass through).
- `internal/plugin/consent_test.go` — Tests for the full ResponseFilter flow using mocked consent client and test HTTP objects:
  - Allow decision passes response through.
  - Deny decision returns configured error response.
  - Filter decision removes specified fields.
  - Consent API error with fail-open passes through.
  - Non-JSON response passes through unchanged.
  - Missing request context is handled gracefully.

**Acceptance criteria:**
- Responses are correctly denied with configured status code and body.
- JSON response fields are correctly removed when decision is `"filter"`.
- Non-JSON responses pass through without modification.
- Consent API failures are handled according to fail-open/fail-closed policy.
- Request context is cleaned up after use (no memory leaks).
- All tests pass.

---

### Step 6: Integration tests, CI configuration, and documentation

Add integration tests, CI pipeline, and update documentation.

**Files to create/modify:**
- `integration_test.go` (or `internal/integration/integration_test.go`) — Integration test that:
  - Starts a mock consent API server (`httptest.NewServer`).
  - Creates a plugin instance with real config pointing to mock server.
  - Simulates a full request→response cycle through RequestFilter and ResponseFilter.
  - Verifies allow, deny, and filter scenarios end-to-end.
- `.github/workflows/ci.yaml` (or `.gitea/workflows/ci.yaml` depending on the Git platform) — CI pipeline:
  - Run on push and PR.
  - Steps: checkout, setup Go, `make lint`, `make test-cover`, `make build`.
- `README.md` — Update with:
  - Project description and purpose.
  - Configuration reference (all config fields with types, defaults, descriptions).
  - APISIX route configuration example showing how to enable the plugin.
  - Build and deployment instructions.
  - Example consent API contract (request/response JSON).
- `.golangci.yml` — Linter configuration for `golangci-lint` with standard rules.

**Acceptance criteria:**
- Integration tests pass and cover the full plugin lifecycle.
- CI pipeline runs successfully.
- README contains clear usage instructions and configuration reference.
- `make lint` passes with no warnings.
- `make test` passes with all unit and integration tests green.
