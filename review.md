# Code Review — `consent-plugin`

**Reviewer:** senior engineer review, whole repository
**Date:** 2026-08-27
**Revision reviewed:** `463ed56` (branch `main`, clean tree)

---

## 1. Executive summary

`consent-plugin` is a small, well-groomed Go codebase (≈5 000 lines incl. tests) that
implements an APISIX external plugin gating personal-data responses on the data
subject's consent. Craftsmanship at the *file* level is high: every exported symbol
is documented, magic numbers are named constants, errors are wrapped, `golangci-lint`
(15 extra linters, incl. `gosec`) reports **0 issues**, `govulncheck` reports **no
vulnerabilities**, tests pass under `-race`, and CI/release plumbing is complete.

The problems are at the *design and lifecycle* level, and they cluster in one place:
**the security semantics of the default configuration, and the behaviour of the
newer owner-resolver path.** In its documented default shape the plugin answers the
wrong question ("does the *caller* have any consent?" instead of "did the *data
owner* consent to *this* caller?"), and the code path that fixes this
(`owner_resolver_url`) has **zero test coverage** and several silent fail-open holes.
Secondarily, the request-context store is an unbounded in-memory map with no
eviction — a slow leak with a credential-retention angle — and the README documents
a configuration surface (`client_id`/`client_secret`) that **no longer exists in the
code**, so anyone following it deploys a gate that never authenticates and, at the
default `fail_open: true`, silently allows everything.

**Verdict:** the code is production-*grade* but not production-*ready*. The
must-fix set is C-1 … C-4 plus H-1; those are days of work, not weeks, and none
require re-architecture.

### Verification performed

| Check | Result |
| --- | --- |
| `go vet ./...` (go1.26.7) | clean |
| `golangci-lint run ./...` (v2.13.1) | **0 issues** |
| `govulncheck ./...` | no vulnerabilities |
| `go test -race ./...` | all pass |
| `go test -coverpkg=./... ` total | **69.1 %** (see §5) |
| `docker compose up` | **cannot start** — missing file (M-6) |

### Findings at a glance

| ID | Severity | Finding | Location |
| --- | --- | --- | --- |
| C-1 | Critical | Default (legacy) mode checks the **requestor's** consent, not the data owner's — an authenticated caller can read any subject's data | `internal/plugin/consent.go:404` |
| C-2 | Critical | Any `granted` consent authorises access, regardless of which consumer/purpose it was granted for | `internal/consent/client.go:621` |
| C-3 | Critical | Credential cache key omits `token_service_url` → cross-participant token / provider-SD confusion between routes | `internal/consent/client.go:190` |
| C-4 | Critical | README + CLAUDE.md document a removed config surface (`client_id`/`client_secret`); following them yields a silently open gate | `README.md:51-80` |
| H-1 | High | Party-resolution failures in resolver mode are logged and ignored → resolver called with no parties → possible `consentRequired:false` → allow | `internal/plugin/consent.go:251,257` |
| H-2 | High | `fail_open` defaults to **true** on a security control | `internal/plugin/config.go:229` |
| H-3 | High | Unbounded request-context store: no TTL, no cap, no eviction; retains `Authorization` bearer tokens | `internal/plugin/context.go:53` |
| H-4 | High | Owner-resolver path (the sound mode) has **0 % test coverage** | `internal/plugin/consent.go:233` |
| H-5 | High | Serialised per-owner consent checks with no request budget and no claim cap → unbounded response latency | `internal/plugin/consent.go:284-311` |
| M-1 | Medium | Deny response inherits all upstream headers (incl. `Content-Length`, `Set-Cookie`, pagination counters) | `internal/plugin/consent.go:425` |
| M-2 | Medium | `Validate()` accepts a config that cannot possibly authenticate | `internal/plugin/config.go:286` |
| M-3 | Medium | Audit trail is at-most-once and silently droppable — floodable, and never flushed at shutdown | `internal/audit/audit.go:164` |
| M-4 | Medium | `consumerFromClaims` cannot traverse arrays — fails silently on ordinary VP tokens | `internal/plugin/consent.go:461` |
| M-5 | Medium | Subject DIDs and upstream error bodies go to unstructured stdout logs, unrated | throughout |
| M-6 | Medium | `docker compose up` cannot work — `apisix-config.yaml` absent, socket bind-mount wrong | `docker-compose.yaml:29` |
| M-7 | Medium | Security scanners are `continue-on-error` and pinned to `latest` | `.github/workflows/security-analysis.yml` |
| L-1…L-11 | Low | Dead code, doc drift, container hardening, dependency age, unbounded resolver payload, misc. | see §6 |

---

## 2. Architecture assessment

### What the design gets right

* **Phase correlation via `$request_id`** (`consent.go:44-66`) is the correct call and
  the reasoning is documented at the point of use. The runner's per-RPC `ID()` really
  is not stable across `ext-plugin-pre-req` / `ext-plugin-post-resp`; getting this
  wrong is the classic bug in two-phase APISIX plugins, and this code avoids it.
* **Ownership from the data, not the requestor.** The `ownerresolver` package and the
  emphatic comments around it ("Parties are for CONTRACT identification only — never
  for ownership") show the right threat model. This is the correct architecture.
* **Coarse allow/deny rather than field filtering.** Deliberately chosen and
  justified (`consent.go:158-178`): an empty or non-JSON personal-data response is
  still gated. Better than a redaction filter that silently misses a field.
* **Per-entry credential cache locking** (`client.go:180-188`) coalesces concurrent
  first-requests onto one token fetch without a global lock across the HTTP call.
  That is a genuinely good piece of concurrency design, and it is tested
  (`TestCheckConsent_ConcurrentTokenFetchCoalesced`).
* **Audit decoupled from the decision path** — bounded queue, background batching,
  best-effort export. The right shape for a sidecar-adjacent gate.
* **Credentials via env, not route config**, keeping secrets out of etcd
  (`config.go:272-284`). Correct instinct, correctly documented.

### Structural concerns

1. **Two modes, one of them unsound, and the unsound one is the default.**
   `owner_resolver_url` is optional; when unset the plugin silently falls back to the
   "legacy" JWT-subject mode (C-1). The two modes have very different security
   properties but the same config surface and the same log prefix, and the README
   documents only the weaker one. The legacy
   mode should be dropped, setting a resolver is required.

2. **The response phase is a synchronous fan-out of unbounded size.**
   In resolver mode one client response can trigger `1 + 1 + 3N` HTTP calls (parties
   mapping, `/resolve`, then per owner: identifier search + consents lookup, plus
   token refresh) — all sequential, all on `context.Background()`, while APISIX holds
   the buffered response. There is no per-request deadline, no concurrency, no cap on
   `N`, and no negative caching (H-5).

3. **No decision caching anywhere.** Every single response re-runs the whole chain.
   Consent state changes rarely; a short-TTL (owner, resource) → decision cache with
   explicit invalidation would cut the hot-path cost by an order of magnitude. The
   token and participant-SD caches show the pattern is understood — it just was not
   applied to the decision itself.

4. **`ext-plugin-post-resp` implications are undocumented.** Attaching this phase
   forces APISIX to buffer the entire upstream response (`ReadBody()` is a blocking
   extra-info RPC over the unix socket), which defeats streaming and makes large
   responses a memory multiplier. The README should state the constraint and a
   recommended `max` response size for gated routes.

---

## 3. Critical findings

### C-1 — Legacy mode verifies the consent of the *requestor*, not of the data owner

`internal/plugin/consent.go:404-423` (`buildConsentRequest`), reached from
`evaluate()` whenever `owner_resolver_url` is empty — the documented default.

```go
if sub, ok := reqCtx.JWTClaims[jwtSubjectClaim]; ok { consentReq.Subject = subStr }
```

The `sub` of the *access token* becomes the consent subject. The check therefore
answers "has the caller granted some consent?" — it never establishes any link
between the caller and the data the upstream is about to return.

**Failure scenario.** Alice (`did:key:zAlice`) has granted a consent. Alice obtains a
valid token and requests `/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:bob`.
The plugin resolves *Alice's* user identifier, finds *Alice's* granted consent, and
returns **Bob's** personal data. Any subject with one granted consent becomes a
universal reader. The gate is a no-op against the very threat it exists for.

Compounding this, the JWT signature is **not verified** (`internal/jwt/extractor.go:19-21`
documents the assumption that APISIX or the upstream did it). Nothing in the plugin,
the config validation, or the README enforces that an auth plugin is actually attached
to the route. On a route without one, `sub` is attacker-supplied and the check
collapses entirely.

**Recommendation.** Remove legacy mode: require `owner_resolver_url`, fail `Validate()` when no resolver is configured.

### C-2 — Any granted consent authorises access, regardless of consumer or purpose

`internal/consent/client.go:597-635` (`hasGrantedConsent`).

```go
for _, consent := range out.Consents {
    if consent.Status != grantedStatus { continue }
    if dataResource == "" { return true, nil }        // ← any consent, any consumer
    ...
}
```

The consent list is filtered only on `status` (and optionally `data[].resource`).
It is never filtered by the **consuming participant** or the **purpose/contract**,
even though the plugin has just gone to the trouble of resolving the consumer's
self-description URL for the resolver call and *has* it in hand.

**Failure scenario.** Bob grants consent to participant *X* for purpose "insurance
quote". Participant *Y* — a different consumer, with no consent from Bob — requests
Bob's data through this gateway. `hasGrantedConsent` sees Bob's granted consent to
*X* and allows *Y*. Under GDPR terms the plugin authorises a processing purpose the
subject never agreed to; the consent record it relied on is evidence of the wrong
agreement.

**Recommendation.** Pass the consumer self-description (and, where the contract model
supports it, the purpose/contract id) into `hasGrantedConsent` and require the
consent's own participant/purpose to match. Until that is possible, the `?receipt=true`
payload should be inspected for the consumer field and mismatches treated as deny.
This is the single highest-value correctness fix in the codebase.

### C-3 — Credential cache key omits the token source → cross-participant confusion

`internal/consent/client.go:190`:

```go
func (c *Client) cacheKey() string { return c.baseURL + "|" + c.tokenAudience }
```

The cached entry holds **both** the participant access token and the derived provider
self-description (`client.go:264-305`), but the key contains neither
`tokenServiceURL`, nor the static `ParticipantToken`, nor `consentKey`. `TokenAudience`
defaults to the constant `"consent-manager"` for every route.

**Failure scenario.** One APISIX instance fronts two provider tenants — routes A and B
— both pointing at the same consent-manager `baseURL`, each with its own
`token_service_url` (its own participant credential). Both hash to the identical
cache key `"<baseURL>|consent-manager"`. Whichever route warms the cache first
installs *its* token and *its* `selfDescriptionURL`; the other route then performs the
identifier search scoped to the **wrong provider** and the consents lookup **as the
wrong participant**. Decisions are silently wrong in both directions: denials for
subjects who did consent, and allows against the wrong provider's consent records.
The same collision occurs when only `consent_key` or a static `provider_sd` differs
(the early-return at `client.go:255` only covers the case where *both* static token
*and* static SD are set).

**Recommendation.** Key the cache on the full credential identity — e.g.
`baseURL | apiPrefix | tokenAudience | tokenServiceURL | sha256(staticToken) | providerSD`.
Add a test with two clients differing only in `token_service_url` asserting they do
not share a token. This is a small fix with a large blast radius; treat as must-fix
before any multi-tenant deployment.

### C-4 — README and CLAUDE.md document a configuration surface that no longer exists

`README.md:51-80` (config table + env note), `README.md:40-49` (participant-auth
section), `README.md:86-99` (route example), `CLAUDE.md` ("Important Files").

The docs describe participant **client credentials**:

| Documented | Actually in the code |
| --- | --- |
| `client_id`, `client_secret` | *removed* — no such fields in `Config` |
| `CONSENT_CLIENT_ID`, `CONSENT_CLIENT_SECRET` | *removed* — env vars are `CONSENT_KEY`, `CONSENT_TOKEN_SERVICE_URL`, `CONSENT_AUDIT_OTLP_ENDPOINT` |
| `POST /participants/login` | *removed* — `fetchToken` posts to `token_service_url` (OID4VP facade) |
| — | `token_service_url`, `token_audience` — **undocumented** |
| — | `owner_resolver_url`, `owner_resolver_timeout`, `service`, `consumer_claim` — **undocumented** (the entire sound mode!) |
| — | `consent_api_host` — **undocumented** |

`Config` has no `UnknownFields` rejection, so `client_id`/`client_secret` in a route
JSON are **silently discarded** by `json.Unmarshal`.

**Failure scenario.** An operator copies the README's `curl` example verbatim. The
config parses and validates successfully. At request time `credentials()` returns
`"consent client: no participant_token and no token_service_url configured"` → the
fail policy applies. With the example's `"fail_open":false` this is a total outage of
every gated route with only a log line to explain it. With the *documented default*
(`fail_open: true`) it is worse: **every request is allowed, the consent gate is
entirely bypassed, and nothing signals it** beyond one log line per request. A
documentation defect here is a security defect.

**Recommendation.** Rewrite the README config table and route example against
`internal/plugin/config.go`; document `owner_resolver_url` as the recommended mode
with an example; refresh `CLAUDE.md` (it also still lists an `internal/filter`
package that does not exist and omits `internal/audit` and `internal/ownerresolver`).
Add a CI check that every `json:` tag in `Config` appears in the README table — doc
drift on a security control needs a machine, not discipline.

---

## 4. High-severity findings

### H-1 — Party-resolution failures are logged and ignored, then the resolver's answer is trusted

`internal/plugin/consent.go:249-262`:

```go
if consumerSD, sdErr := consentClient.ParticipantSelfDescriptionByDID(...); sdErr != nil {
    log.Printf(...)                      // ← swallowed
} else { resolveParties.Consumer = consumerSD }
if providerSD, sdErr := consentClient.ProviderSelfDescription(...); sdErr != nil {
    log.Printf(...)                      // ← swallowed
} else { resolveParties.Provider = providerSD }
```

Both failures leave `resolveParties` empty; `Parties.IsZero()` then **omits the field
entirely** from the `/resolve` request (`ownerresolver/client.go:140-142`). The plugin
proceeds to trust whatever the resolver returns — including
`consentRequired: false`, which is an unconditional **allow** (`consent.go:273-275`).

**Failure scenario.** The consent-manager is briefly unreachable, or the cached
participant token has been revoked. `ParticipantSelfDescriptionByDID` returns
`errParticipantUnauthorized` — and note it has **no 401-refresh-and-retry** of its own,
unlike `CheckConsent` (`client.go:340-389` calls `credentials(ctx, false)`), so a stale
token is terminal for the mapping. The plugin then asks the resolver "who owns this
payload?" with no parties at all. A resolver that cannot identify a contract and
answers `consentRequired: false` (a plausible, arguably correct answer for "no
contract governs this exchange") causes personal data to be released. A fail-closed
design has a fail-open seam in the middle of it.

**Recommendation.** Treat both resolution failures as `failOutcome(...)` — the same
policy already applied to a resolver error. If a degraded mode is genuinely wanted,
make it explicit (`allow_unidentified_parties`), default it off, and never let an
unidentified-party `/resolve` result reach the allow branch. Add the 401-refresh
retry to `ParticipantSelfDescriptionByDID`, and cache negative lookups briefly so a
misconfigured DID does not re-fetch the whole participant list per request.

### H-2 — `fail_open` defaults to `true`

`internal/plugin/config.go:228-233`. Every unresolved situation — consent-manager
down, missing request context, missing credentials, resolver error, unreadable body —
becomes **allow** unless the operator explicitly sets `fail_open: false`.

For an availability-shaped filter that default is defensible. For a **consent gate on
personal data** it inverts the safe default: the failure mode of the security control
is "release the data", and it is reached by *omission*. Combined with C-4 the two
compose into a silent full bypass.

**Recommendation.** Flip the default to fail-closed (a `major` semver bump — the
repo's label-driven release process handles this cleanly), keep `fail_open: true`
available as a deliberate, documented opt-out, and log a warning at `ParseConf` when
it is enabled. At minimum, distinguish the reasons: a consent-manager timeout is a
plausible fail-open case; *missing credentials* and *missing request context* never are.

### H-3 — Unbounded request-context store; retains bearer tokens

`internal/plugin/context.go:53` — a package-level `sync.Map`, written in
`RequestFilter` and deleted only by `LoadAndDeleteRequestContext` in `ResponseFilter`.
There is **no TTL, no size cap, no eviction sweep, and no gauge**.

**Failure scenario.** Any request whose response phase never runs leaks one entry
permanently: client disconnects before the upstream responds; upstream connect
timeout; a preceding APISIX plugin short-circuits the request after `pre-req`;
`ext-plugin-post-resp` misconfigured on one of several routes; the runner restarting
between phases. The runner is a long-lived process, so the map grows monotonically
until OOM. It is also remotely drivable: open connections, send the request, abort
before the response — an unauthenticated memory-exhaustion primitive.

Each leaked entry holds `RequestContext.Headers`, which is a **copy of every request
header including `Authorization: Bearer <jwt>`** (`consent.go:110-116`) — so the leak
is a leak of credentials retained indefinitely in process memory. And `Headers` is
never read: the only consumer is `len(rc.Headers)` in `String()`
(`context.go:107`). It is pure cost and pure risk.

**Recommendation.** (a) Delete the `Headers` field and its capture loop — dead weight
holding secrets. (b) Store `{ctx, insertedAt}` and add a janitor goroutine evicting
entries older than a bounded lifetime (a few seconds beyond the upstream timeout),
plus a hard cap that rejects/evicts oldest on overflow. The runner already pulls in
`ReneKroon/ttlcache/v2` transitively if a library is preferred. (c) Export the
store size so the leak is observable.

### H-4 — The owner-resolver path has zero test coverage

Measured with `go test -coverpkg=./... ./...` (the repo's own `make test-cover` omits
`-coverpkg`, so cross-package integration coverage is not attributed at all — the
53.9 % it prints for `internal/plugin` is an artefact, the true figure is higher):

| Symbol | Coverage |
| --- | --- |
| `plugin.evaluateWithResolver` | **0.0 %** |
| `plugin.consumerFromClaims` | **0.0 %** |
| `plugin.resourceOrPath` | **0.0 %** |
| `consent.ParticipantSelfDescriptionByDID` | **0.0 %** |
| `consent.decodeParticipants` | **0.0 %** |
| `consent.ProviderSelfDescription` | **0.0 %** |
| `plugin.claimKeysToDecode` | 40.0 % |
| **total (all packages)** | **69.1 %** |

Every finding in C-3, H-1, H-5 and M-4 lives in that untested region. The legacy
mode — the one that is architecturally unsound — is the one with good integration
coverage (11 end-to-end cases in `internal/integration`). `internal/ownerresolver`
itself is tested in isolation (82.9 %), but nothing exercises the plugin↔resolver↔
consent-manager composition.

**Recommendation.** Extend `internal/integration` with a resolver-mode harness: a
mock `/resolve`, multi-owner `deny_all` (one owner denies → whole response denied),
`consentRequired: false`, empty `claims`, a claim with an empty `ownerId`, resolver
5xx/timeout under both fail policies, and party-resolution failure (H-1). Add
`-coverpkg=./...` to `make test-cover` and to `.github/workflows/tests.yml`, and gate
CI on a coverage floor so this cannot regress silently.

### H-5 — Serialised per-owner checks, no request budget, no claim cap

`internal/plugin/consent.go:284-311`. The loop over `result.Claims` performs one full
two-call consent check per distinct `(owner, dataResource)` pair, sequentially, each
on `context.Background()` with its own `consent_api_timeout`.

**Failure scenario.** A collection endpoint returns 200 entities with 200 distinct
owners. The plugin issues ~400 sequential HTTP calls; at the default 5 s per-call
timeout the worst case is ~2 000 s of held-open response while APISIX buffers the
body. Long before that, the client and APISIX time out, but the runner's goroutine
keeps working and its connections stay open — a small number of such requests
saturates the runner and the consent-manager. Any caller who can reach a
list endpoint can trigger it; no authentication beyond the ordinary token is needed.

Related inefficiencies in the same loop: the dedup key is `(owner, dataResource)`, so
the same owner with two resources performs the identifier search **twice**; there is
no negative caching of "unknown subject"; and no decision cache (see §2.3).

**Recommendation.** (a) Derive one `context.WithTimeout` for the whole response phase
and pass it to the resolver and every consent call, so the total is bounded and
cancellation propagates. (b) Cap the number of distinct claims checked (configurable,
e.g. `max_owners_per_response`) and fail closed above it. (c) Run the per-owner
checks with bounded concurrency (`errgroup.WithContext`, limit ~8) and short-circuit
on the first deny. (d) Memoise `subject → userIdentifier` for the duration of the
request.

---

## 5. Test suite assessment

**Strengths.** `-race` in both `make test` and CI. Table-driven subtests are the norm
(`config_test.go`, `consent_test.go`), matching the project convention. The
`internal/integration` package is a genuine end-to-end harness — real `ParseConf` →
`RequestFilter` → `ResponseFilter` against `httptest` consent-managers — not a mock
theatre; 11 scenarios cover pass-through, deny, unknown subject, custom deny
response, both fail policies, custom JWT header, context cleanup and the token
service. `internal/jwt` is at 100 %. `TestCheckConsent_ConcurrentTokenFetchCoalesced`
tests the coalescing invariant rather than the implementation. This is above-average
test discipline.

**Gaps.**

* **H-4**: the entire owner-resolver path is untested. Highest priority.
* **Coverage is mis-measured.** `make test-cover` and `tests.yml` omit `-coverpkg=./...`,
  so the integration package's coverage of `internal/plugin` is discarded. The printed
  numbers understate reality and, worse, make the *real* gaps (0 % functions) look
  like measurement noise. Fix the flag; add a floor.
* **No coverage gate in CI.** Coverage is uploaded as an artefact and never asserted.
* **Package-level cache pollution across tests.** `credCache`, `participantSDCache`
  and `emitters` are package globals with no test reset hook. Tests currently pass
  only because `httptest` allocates a distinct `baseURL` per server; a future test
  reusing a URL, or `t.Parallel()`, will produce order-dependent flakes. Add an
  exported-for-test reset (or key the caches off an injectable struct).
* **Mocks diverge from the real runner in a load-bearing way.** `mockResponse.Write`
  *replaces* `writtenBody` (`integration_test.go:154-157`) whereas the real
  `Response.Write` *appends* to a buffer; `mockResponse.Header()` never affects a
  `HasChange()`-equivalent. So no test can observe M-1 (header leakage on deny) or the
  `Content-Length` question, and no test would catch a double-write regression.
  Consider a fake that mirrors `internal/http.Response` semantics.
* **No `Content-Length`/header assertions on the deny path**, no test for a body
  larger than the resolver limit, no test for `$request_id` unavailable in only one
  phase, and no benchmark or load test despite H-5 being a latency finding.
* `TestConfig_IsFailOpen` lives in `consent_test.go` while the rest of the config
  tests are in `config_test.go` — minor misfiling.

---

## 6. Medium and low findings

### M-1 — Deny response inherits all upstream headers

`internal/plugin/consent.go:425-433` sets `Content-Type` and the status, writes the
deny body, and touches nothing else. Every other upstream response header survives
into the 403.

* **`Content-Length`** still advertises the upstream body's length while the body is
  now the 43-byte deny JSON. Whether the client sees a truncated/hung response
  depends on whether APISIX recomputes it when `ext-plugin-post-resp` replaces a body
  — **I could not verify this without a live APISIX**, and no test covers it. It is
  the first thing to check in an end-to-end run.
* **Information leak, verified by inspection:** `Set-Cookie`, `ETag`, `Last-Modified`,
  `Link`, and application headers such as `X-Total-Count` / `NGSILD-Results-Count`
  reach a client that was just denied the data. A denied caller can read pagination
  counts and entity versions — a side channel around the gate.

**Fix:** on deny, delete the upstream headers before writing (whitelist what may
survive), and set `Content-Length` explicitly. Add an assertion once the mock supports it.

### M-2 — `Validate()` accepts a configuration that cannot authenticate

`internal/plugin/config.go:286-336` validates URLs, timeout and status-code ranges,
and the audit endpoint, but never checks that *some* participant credential exists
(`participant_token` **or** `token_service_url`). The README even documents this as
intentional ("None are enforced at parse time"). Combined with H-2 the result is a
route that loads cleanly and allows everything. `owner_resolver_timeout` and
`participant_token_ttl` are also unvalidated (unlike `consent_api_timeout`), and
`consent_api_prefix` is concatenated unchecked in `endpoint()`
(`client.go:637-639`) — a prefix without a leading `/` silently produces a malformed
URL. **Fix:** require a credential source at parse time; range-check the other
numeric fields; normalise/validate the prefix.

### M-3 — Audit trail is silently droppable and never flushed

`internal/audit/audit.go:164-172`. The queue is bounded at 2048 and `Emit` drops on
overflow with only a rate-limited log line — deliberate and correct *for the request
path*, but it means the compliance record is at-most-once and **an attacker can
suppress the record of their own access by generating load**. Also:

* `main()` never calls `Shutdown()`, so up to `defaultFlushInterval` (2 s) of
  decisions are lost on every runner restart/redeploy. `Shutdown` exists and is
  tested; wire a `SIGTERM` handler.
* `Get()` caches emitters by `endpoint|serviceName` but **not** by `Timeout`
  (`audit.go:118-134`), so the first route's timeout silently wins for all others.
* In resolver mode only the **first denying** owner is recorded, and an allow records
  no owners at all (`consent.go:305-313`, `:315`) — so the audit log cannot answer
  "whose consent was checked?", which is the question an audit log exists to answer.
* `consent.reason` carries `truncateBody()` output from consent-manager errors
  (`client.go:666-672`), so upstream error bodies — potentially containing identifiers
  — land in the audit sink.
* No OTLP authentication headers are configurable.

**Fix:** record every checked `(owner, resource, decision)` per request; add a
`SIGTERM` flush; include `Timeout` in the emitter key; sanitise `reason` before
export; expose the dropped counter as a metric so suppression is detectable.

### M-4 — `consumerFromClaims` cannot traverse arrays

`internal/plugin/consent.go:461-482` walks a dotted path through
`map[string]interface{}` only. The default path is
`verifiableCredential.issuer` (`config.go:37-43`), but a Verifiable Presentation
commonly carries `verifiableCredential` as a **JSON array**. The type assertion
fails, `""` is returned, no error is logged from this function, and the consumer is
simply absent — feeding directly into H-1's allow seam. **Fix:** support array
indexing (`verifiableCredential[0].issuer` or implicit first-element traversal), and
distinguish "path not configured" from "path did not resolve" so the latter can be
treated as a failure.

### M-5 — Unstructured logging of personal identifiers, unrated

`log.Printf` with a hand-written `[consent-filter]` prefix appears ~15 times across
`plugin/` and `audit/`. Consequences: (a) the runner ships `pkg/log` (zap) whose level
configuration therefore does not apply — these lines cannot be filtered or
suppressed; (b) messages carry subject DIDs (`consent.go:251`) and upstream error
bodies, i.e. personal data in stdout with no retention policy, which is exactly what
the OTLP audit path was built to avoid; (c) there is no rate limiting, so a broken
consent-manager emits one line per request. **Fix:** switch to the runner's logger
with levels, drop or hash identifiers in non-audit logs, and rate-limit the
per-request failure paths.

### M-6 — The documented local dev setup cannot start

`docker-compose.yaml:29` mounts `./apisix-config.yaml`, which **does not exist in the
repository**; Docker will create a *directory* at that path and APISIX will fail to
parse its config. Additionally, both services bind-mount `/tmp/runner.sock` — a
socket file that does not exist at compose time, so Docker again creates a directory
and the runner cannot bind. The conventional fix is to share a *directory* (or named
volume) and put the socket inside it. `version: "3.8"` is also obsolete under Compose
v2. Since `README.md:121-124` advertises `docker compose up --build` as the dev workflow,
this is the first thing a new contributor hits. **Fix:** commit an
`apisix-config.yaml` with the `ext-plugin` wiring, switch to a shared socket
directory, drop `version:`, and add the consent-manager mock + otel-collector so the
stack is actually exercisable.

### M-7 — Security scans cannot fail the build; tool versions unpinned

`.github/workflows/security-analysis.yml` runs both `govulncheck` and `gosec` with
`continue-on-error: true`, so findings are informational only — a known-vulnerable
dependency merges cleanly. `gosec` is installed from `@latest` and
`golangci-lint-action` uses `version: latest`, making CI non-reproducible and
supply-chain-exposed; note the Gitea pipeline pins `v2.1.6`, so the two CIs can
disagree about whether the code lints. **Fix:** pin both tools; let `govulncheck` fail
the PR on a fixable vulnerability (allow-list with expiry for the rest); add
`go mod verify` and dependency review.

### Low

* **L-1 — Dead code from a removed field-filtering design.** `DecisionFilter`,
  `Decision.IsValid`, `ConsentResponse.Validate`, `ConsentResponse.DeniedFields`,
  `ConsentRequest.ResponseFields` and `ConsentRequest.Claims`
  (`internal/consent/models.go:36-107`) are unreferenced by production code — they are
  tested, which makes the coverage number flatter. Their `json:` tags describe a
  `POST /check` API that the two-call client never calls, so the file actively
  misleads. `ownerresolver.Claim.Selector`/`.Participant` and `Result.Scheme` are
  decoded and never read. `plugin.LoadRequestContext` and `plugin.DeleteRequestContext`
  are exported and unused. `RequestContext.Headers` — see H-3. Delete all of it.
* **L-2 — Package doc contradicts behaviour.** `internal/consent/models.go:19-21` and
  `internal/plugin/config.go:19-20` still describe "filtering personal data" /
  "allowed, denied, or filtered"; the plugin does coarse allow/deny. `CLAUDE.md` lists
  an `internal/filter` package that does not exist, describes `/participants/login`
  client credentials (see C-4), and omits `internal/audit` and `internal/ownerresolver`.
* **L-3 — Container hardening.** The runtime image (`Dockerfile:20-30`) runs as
  **root** with no `USER`, on `alpine:3.19` (past end-of-support), with no
  `HEALTHCHECK` and no `.dockerignore` (so `COPY . .` pulls `.git`, invalidating the
  build cache on every commit). Add a non-root user, bump the base, add
  `.dockerignore`.
* **L-4 — Dependency age.** Direct deps are stale: `testify` 1.8.4 → 1.12.1,
  `api7/ext-plugin-proto` v0.6.0 → v0.6.1. `apisix-go-plugin-runner` is pinned at
  v0.5.0 (its own transitive tree — zap 1.17, flatbuffers 2.0.0, grpc 1.38 — is
  years old); worth tracking whether the runner is still maintained, since a plugin
  whose runner is abandoned is a strategic risk. No Renovate/Dependabot config.
* **L-5 — `HasChange()` is forced true on every resolver-mode allow.**
  `evaluateWithResolver` calls `w.Header()` to read `Content-Type`
  (`consent.go:239-242`), which lazily initialises `hdr` and therefore makes the
  runner's `HasChange()` return true (`internal/http/response.go:207`) even when
  nothing was modified. Every gated response then travels the "response was
  modified" path back to APISIX with an empty header diff. Probably benign, entirely
  untested; read the `Content-Type` from the stored `RequestContext` or from
  `r.rawHdr` instead.
* **L-6 — No metrics.** For a component that can deny production traffic there is no
  counter for allow/deny/fail-open, no consent-manager latency histogram, no
  context-store gauge, no audit-drop counter. Operationally this is flying blind;
  logs are the only signal, and they are unstructured (M-5).
* **L-7 — `ParticipantTokenTTL` overflow.** `time.Duration(cfg.ParticipantTokenTTL) * time.Second`
  (`consent.go:349`) overflows for absurd values; unvalidated (see M-2).
* **L-8 — Repo hygiene.** No `SECURITY.md` (vulnerability reporting path) and no
  `CODEOWNERS` for a repo that gates personal-data access. `CONTRIBUTING.md` and the
  workflow set are otherwise good.
* **L-9 — Local toolchain friction.** `go.mod` requires `go 1.26` while the system Go
  is 1.22 and `GOTOOLCHAIN` cannot download; contributors need a pre-cached 1.26
  toolchain (this review used `go1.26.7` from the module cache). Worth a line in
  `CONTRIBUTING.md`.
* **L-10 — No size cap on the payload forwarded to the OwnerResolver.**
  `internal/plugin/consent.go:234` reads the whole upstream body, then
  `ownerresolver.Resolve` (`internal/ownerresolver/client.go:131-170`) runs
  `json.Valid(payload)` over it and `json.Marshal` copies it again into the request
  envelope as a `json.RawMessage`. Peak footprint is therefore roughly *3×* the body
  size per in-flight request, on top of APISIX's own buffering of the response — so a
  handful of concurrent large-collection responses can drive the runner's memory well
  past what the response size suggests. Unrelated to transport security: cluster mTLS
  does not bound the copy. **Fix:** add a `max_resolve_body_bytes` limit and fail
  closed above it rather than forwarding, and stream or reference the body instead of
  embedding it once a limit exists.
* **L-11 — A non-JSON body is indistinguishable from no body at all.**
  `internal/ownerresolver/client.go:132-135`: when `json.Valid(payload)` fails, the
  envelope is sent with `encoding: "none"`, exactly as it is when there was no body.
  The resolver cannot tell "this response carried a payload I could not parse" from
  "this response had no payload", so it resolves ownership from the resource
  descriptor alone. A malformed-but-personal payload (a truncated write, a
  content-type mismatch, an upstream returning XML or NDJSON on a route declared
  JSON) is therefore judged without ever being inspected. **Fix:** distinguish the
  two cases in the envelope — e.g. a third encoding value, or `encoding: "opaque"`
  with the content type — so the resolver can fail closed on an unparseable payload
  instead of silently falling back.

---

## 7. Prioritised action plan

**Must fix before production**

1. **C-4** — rewrite README + CLAUDE.md against the real config; add a doc-drift CI
   check. *(Cheapest fix, prevents the silent-bypass deployment.)*
2. **C-1** — make owner-resolver mode mandatory (or legacy mode a loud, explicit
   opt-in); document JWT verification as a hard route prerequisite.
3. **C-2** — scope the consent match to the consuming participant and purpose.
4. **C-3** — include the token source in the credential cache key; add the
   two-participant regression test.
5. **H-1** — fail closed when the consumer or provider cannot be resolved; add the
   401-refresh retry to `ParticipantSelfDescriptionByDID`.
6. **H-2** — default `fail_open` to false; **M-2** — require a credential source at
   parse time.
7. **H-3** — drop `RequestContext.Headers`; add TTL + cap + size gauge to the context store.

**Before scale / next iteration**

8. **H-4** — resolver-mode integration tests; `-coverpkg=./...` plus a CI coverage floor.
9. **H-5** — one request-scoped deadline, bounded concurrency, claim cap, identifier memoisation.
10. **M-1** — strip upstream headers on deny; verify `Content-Length` end-to-end against a real APISIX.
11. **M-3** — audit every checked owner; flush on `SIGTERM`; sanitise `reason`.
12. **M-6** — make `docker compose up` actually work; **M-7** — pin and enforce the scanners.
13. **L-6** — add Prometheus metrics for decisions, latency, drops and store size.

**Cleanup**

14. **L-1/L-2** — delete the dead field-filtering model and fix the stale package docs.
15. **L-3/L-4/L-8/L-9** — non-root container, base-image bump, `.dockerignore`,
    dependency refresh + Renovate, `SECURITY.md`, `CODEOWNERS`, toolchain note.
16. **L-10/L-11** — cap the body forwarded to the OwnerResolver, and distinguish
    "non-JSON body" from "no body" in the resolve envelope.

---

## 8. Closing note

The engineering hygiene here is genuinely good — the comments explain *why* rather
than *what*, the `$request_id` correlation and the per-entry credential locking show
real care, and the linter/CI/release setup is more complete than most projects of this
size. The gap is that the codebase is mid-migration: an older, unsound design
(requestor-subject consent) is still the default and still the only documented one,
while the sound design (owner-resolver) is present, undocumented, and untested. Most
of the critical findings are consequences of that unfinished transition rather than
of careless code. Finishing the migration — making resolver mode the only mode,
documenting it, testing it, and failing closed throughout — resolves C-1, C-4, H-1,
H-2 and H-4 together, and would move this from "promising" to "trustworthy".
