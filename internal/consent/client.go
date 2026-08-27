package consent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Endpoint paths and constants.
const (
	// DefaultAPIPrefix is the consent-manager API prefix prepended to every
	// endpoint path (matches the consent-manager's API_PREFIX).
	DefaultAPIPrefix = "/v1"

	// identifierSearchPath resolves a subject to the provider-scoped user
	// identifier. Authenticated with the consent key.
	identifierSearchPath = "/users/identifier/search"

	// participantConsentsPathFmt lists a user identifier's consents as seen by
	// the participant. Authenticated with the participant JWT. %s = identifier.
	participantConsentsPathFmt = "/consents/participants/%s"

	// participantMePath returns the calling participant (incl. selfDescriptionURL).
	participantMePath = "/participants/me"

	// participantsPath lists the known participants (the consent-manager is the
	// participant registry), used to map a participant DID to its
	// self-description URL.
	participantsPath = "/participants"

	// consentKeyHeader carries the shared consent key on the identifier search.
	consentKeyHeader = "x-visionstrust-consent-key"

	// grantedStatus is the consent status that authorizes access.
	grantedStatus = "granted"

	// DefaultTimeoutMs is the default per-call HTTP timeout in milliseconds.
	DefaultTimeoutMs = 5000

	// MinTimeoutMs is the minimum allowed timeout in milliseconds.
	MinTimeoutMs = 1

	// DefaultTokenTTL is how long a participant token obtained via client
	// credentials is cached before re-login. The consent-manager issues 1h
	// tokens, so the default keeps a safety margin.
	DefaultTokenTTL = 50 * time.Minute

	// tokenRefreshSkew is subtracted from a token's cached lifetime so it is never
	// presented in the last moments before it expires.
	tokenRefreshSkew = 60 * time.Second

	// ContentTypeJSON is the Content-Type used for JSON request bodies.
	ContentTypeJSON = "application/json"
)

// errParticipantUnauthorized signals that the participant token was rejected
// (HTTP 401), so a cached token should be refreshed and the call retried.
var errParticipantUnauthorized = errors.New("consent client: participant token unauthorized")

// ClientConfig holds everything needed to verify consent against the
// (Prometheus-X / Visions) consent-manager.
type ClientConfig struct {
	// BaseURL is the consent-manager root (e.g. "http://consent-manager:3000").
	BaseURL string
	// Host, if set, overrides the HTTP Host header on every request (the URL host
	// is still used for the connection). Needed for host-scoped gateway routes.
	Host string
	// APIPrefix is prepended to endpoint paths (defaults to DefaultAPIPrefix).
	APIPrefix string
	// ConsentKey is the shared secret sent on the identifier search (required).
	ConsentKey string
	// ProviderSD, if empty, is derived from GET /participants/me after login.
	ProviderSD string
	// ParticipantToken, if set, is used as a static token (nothing is fetched).
	// Otherwise a token is obtained from TokenServiceURL.
	ParticipantToken string
	// TokenServiceURL is the participant-local OID4VP token service that mints an
	// access token for this participant (the consent-facade's /internal/tokens).
	TokenServiceURL string
	// TokenAudience is the audience name asked of the token service.
	TokenAudience string
	// TokenTTL caps how long a fetched token is cached (defaults to
	// DefaultTokenTTL); the token service's own expiry wins when shorter.
	TokenTTL time.Duration
	// TimeoutMs is the per-call HTTP timeout (defaults to DefaultTimeoutMs).
	TimeoutMs int
}

// Client verifies consent against the consent-manager. The consent-manager has
// no single "is there consent?" endpoint, so a check is a two-call chain:
//
//  1. POST {base}/users/identifier/search  — resolve the subject (a DID carried
//     as the user "email") to the provider-scoped user identifier, authenticated
//     with the shared consent key and scoped by the provider self-description.
//  2. GET  {base}/consents/participants/{id}?receipt=true — list that user's
//     consents, authenticated with the participant JWT.
//
// The access token is obtained from the participant-local OID4VP token service
// (POST {TokenServiceURL} with the configured audience), so this plugin holds no
// participant credentials of its own: the token service presents the
// participant's verifiable credential and returns a short-lived token. GET
// /participants/me then yields the provider selfDescriptionURL. Tokens are cached
// package-wide (keyed by base URL + audience) and refreshed on expiry or a 401.
// Access is allowed iff a returned consent is "granted".
type Client struct {
	baseURL         string
	host            string
	apiPrefix       string
	consentKey      string
	providerSD      string
	staticToken     string
	tokenServiceURL string
	tokenAudience   string
	tokenTTL        time.Duration
	httpClient      *http.Client
}

// NewClient creates a consent-manager client from cfg, applying defaults for
// APIPrefix, TokenTTL and TimeoutMs.
func NewClient(cfg ClientConfig) *Client {
	timeout := cfg.TimeoutMs
	if timeout < MinTimeoutMs {
		timeout = DefaultTimeoutMs
	}
	prefix := cfg.APIPrefix
	if prefix == "" {
		prefix = DefaultAPIPrefix
	}
	ttl := cfg.TokenTTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	return &Client{
		baseURL:         cfg.BaseURL,
		host:            cfg.Host,
		apiPrefix:       prefix,
		consentKey:      cfg.ConsentKey,
		providerSD:      cfg.ProviderSD,
		staticToken:     cfg.ParticipantToken,
		tokenServiceURL: cfg.TokenServiceURL,
		tokenAudience:   cfg.TokenAudience,
		tokenTTL:        ttl,
		httpClient:      &http.Client{Timeout: time.Duration(timeout) * time.Millisecond},
	}
}

// --- package-wide credential cache (token + derived provider SD) -------------

type cacheEntry struct {
	// mu serializes the login / provider-SD refresh for this one cache key, so
	// concurrent first requests for the same participant coalesce onto a single
	// login instead of stampeding the consent-manager — while requests for other
	// participants, and cache hits, never block on it.
	mu          sync.Mutex
	token       string
	tokenExpiry time.Time
	providerSD  string
}

var (
	credCacheMu sync.Mutex
	credCache   = map[string]*cacheEntry{}
)

func (c *Client) cacheKey() string { return c.baseURL + "|" + c.tokenAudience }

// CheckConsent runs the two-call consent verification for req.Subject, allowing
// when a granted consent exists and denying otherwise. An unknown subject is a
// definite deny (not an error). A 401 from the participant-authenticated calls
// triggers one token refresh + retry. Transport/protocol failures are returned
// as errors so the caller can apply its fail policy.
func (c *Client) CheckConsent(ctx context.Context, req ConsentRequest) (*ConsentResponse, error) {
	if req.Subject == "" {
		return &ConsentResponse{Decision: DecisionDeny, Reason: "no subject in request"}, nil
	}

	resp, err := c.check(ctx, req.Subject, req.DataResource, false)
	if errors.Is(err, errParticipantUnauthorized) && c.staticToken == "" {
		// The cached token was rejected — refresh it and retry once.
		resp, err = c.check(ctx, req.Subject, req.DataResource, true)
	}
	if errors.Is(err, errParticipantUnauthorized) {
		// Still unauthorized (or a static token was rejected): surface a plain error.
		return nil, fmt.Errorf("consent client: participant token rejected (401)")
	}
	return resp, err
}

// check performs one full verification attempt. forceLogin refreshes a cached
// client-credentials token before use. When dataResource is non-empty the check
// is scoped: a granted consent counts only if it covers that resource.
func (c *Client) check(ctx context.Context, subject, dataResource string, forceLogin bool) (*ConsentResponse, error) {
	token, providerSD, err := c.credentials(ctx, forceLogin)
	if err != nil {
		return nil, err
	}

	userIdentifier, found, err := c.resolveUserIdentifier(ctx, subject, providerSD, token)
	if err != nil {
		return nil, err
	}
	if !found {
		return &ConsentResponse{Decision: DecisionDeny, Reason: "no user identifier for subject"}, nil
	}

	granted, err := c.hasGrantedConsent(ctx, token, userIdentifier, dataResource)
	if err != nil {
		return nil, err
	}
	if granted {
		return &ConsentResponse{Decision: DecisionAllow}, nil
	}
	if dataResource != "" {
		return &ConsentResponse{Decision: DecisionDeny, Reason: "no granted consent for resource " + dataResource}, nil
	}
	return &ConsentResponse{Decision: DecisionDeny, Reason: "no granted consent"}, nil
}

// credentials resolves the participant token and provider self-description,
// preferring static configuration and otherwise using the client-credentials
// the token service (cached) and GET /participants/me. forceFetch bypasses a cached token.
//
// The global map lock is held only long enough to get-or-create this key's cache
// entry; the login/me HTTP calls run under the entry's own lock. So a refresh for
// one participant never blocks cache hits (or refreshes) for another, and
// concurrent first requests for the same participant coalesce onto one fetch.
func (c *Client) credentials(ctx context.Context, forceFetch bool) (token, providerSD string, err error) {
	// Fully static: no cache or HTTP needed.
	if c.staticToken != "" && c.providerSD != "" {
		return c.staticToken, c.providerSD, nil
	}
	if c.staticToken == "" && c.tokenServiceURL == "" {
		return "", "", fmt.Errorf("consent client: no participant_token and no token_service_url configured")
	}

	// Get-or-create the per-key entry under the map lock (brief), then release it
	// before any HTTP so other keys are not blocked.
	credCacheMu.Lock()
	entry := credCache[c.cacheKey()]
	if entry == nil {
		entry = &cacheEntry{}
		credCache[c.cacheKey()] = entry
	}
	credCacheMu.Unlock()

	// Serialize only this participant's refresh; the double-check inside means
	// followers return the freshly-cached token without a second login.
	entry.mu.Lock()
	defer entry.mu.Unlock()

	// Participant token: static override, or a cached/refreshed login token.
	token = c.staticToken
	if token == "" {
		if forceFetch {
			entry.token = ""
		}
		if entry.token == "" || time.Now().After(entry.tokenExpiry) {
			fetched, lifetime, lerr := c.fetchToken(ctx)
			if lerr != nil {
				return "", "", lerr
			}
			entry.token = fetched
			entry.tokenExpiry = time.Now().Add(cacheFor(lifetime, c.tokenTTL))
		}
		token = entry.token
	}

	// Provider self-description: static override, or derived from /me (cached).
	providerSD = c.providerSD
	if providerSD == "" {
		if entry.providerSD == "" {
			sd, serr := c.fetchProviderSD(ctx, token)
			if serr != nil {
				return "", "", serr
			}
			entry.providerSD = sd
		}
		providerSD = entry.providerSD
	}

	return token, providerSD, nil
}

// participantSDCacheTTL bounds how long a DID -> self-description mapping is
// reused. Participants change rarely, so a generous TTL keeps the registry call
// off the request path.
const participantSDCacheTTL = 10 * time.Minute

type participantSDEntry struct {
	selfDescriptionURL string
	expiry             time.Time
}

var (
	participantSDMu    sync.Mutex
	participantSDCache = map[string]participantSDEntry{}
)

// participantListEntry is the (subset of the) consent-manager participant record.
type participantListEntry struct {
	DID                string `json:"did"`
	SelfDescriptionURL string `json:"selfDescriptionURL"`
}

// participantsResponse tolerates both a bare array and a wrapped list.
type participantsResponse struct {
	Participants []participantListEntry `json:"participants"`
}

// ParticipantSelfDescriptionByDID maps a participant DID to its self-description
// URL using the consent-manager's participant registry. Contracts name their
// parties by self-description URL, so a DID taken from a credential must be
// translated before it can be used in a contract lookup. Results are cached for
// participantSDCacheTTL.
func (c *Client) ParticipantSelfDescriptionByDID(ctx context.Context, did string) (string, error) {
	if did == "" {
		return "", fmt.Errorf("consent client: empty participant did")
	}
	cacheKey := c.baseURL + "|" + did

	participantSDMu.Lock()
	entry, hit := participantSDCache[cacheKey]
	participantSDMu.Unlock()
	if hit && time.Now().Before(entry.expiry) {
		return entry.selfDescriptionURL, nil
	}

	token, _, err := c.credentials(ctx, false)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(participantsPath), nil)
	if err != nil {
		return "", fmt.Errorf("consent client: failed to create participants request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return "", err
	}
	if status == http.StatusUnauthorized {
		return "", errParticipantUnauthorized
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("consent client: participants lookup returned status %d, body: %s", status, truncateBody(body))
	}

	participants, err := decodeParticipants(body)
	if err != nil {
		return "", err
	}
	for _, p := range participants {
		if p.DID == did && p.SelfDescriptionURL != "" {
			participantSDMu.Lock()
			participantSDCache[cacheKey] = participantSDEntry{selfDescriptionURL: p.SelfDescriptionURL, expiry: time.Now().Add(participantSDCacheTTL)}
			participantSDMu.Unlock()
			return p.SelfDescriptionURL, nil
		}
	}
	return "", fmt.Errorf("consent client: no participant registered for did %q", did)
}

// decodeParticipants accepts either a bare array or a {"participants": [...]}
// wrapper, since the consent-manager has used both shapes.
func decodeParticipants(body []byte) ([]participantListEntry, error) {
	var bare []participantListEntry
	if err := json.Unmarshal(body, &bare); err == nil {
		return bare, nil
	}
	var wrapped participantsResponse
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return nil, fmt.Errorf("consent client: failed to unmarshal participants response: %w", err)
	}
	return wrapped.Participants, nil
}

// ProviderSelfDescription returns this participant's self-description URL - the
// static override when configured, otherwise the value derived from
// GET /participants/me (cached with the participant token). Callers use it to
// name the provider side of a contract lookup.
func (c *Client) ProviderSelfDescription(ctx context.Context) (string, error) {
	_, providerSD, err := c.credentials(ctx, false)
	if err != nil {
		return "", err
	}
	return providerSD, nil
}

// loginResponse is the consent-manager response to POST /participants/login.
// tokenResponse is the OAuth2-shaped reply of the participant-local token service.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// tokenRequest asks the token service for a token for one configured audience.
// The audience is a NAME the token service resolves against its own configuration,
// never a URL - a caller that could name an arbitrary host would make the token
// service present this participant's credential to it.
type tokenRequest struct {
	Audience string `json:"audience"`
}

// cacheFor returns how long a fetched token may be cached: the shorter of the
// lifetime the token service reported and the configured cap, less a small skew
// so a token is never presented in the last moments of its life. A service that
// reports no usable lifetime falls back to the cap.
func cacheFor(lifetime, cap time.Duration) time.Duration {
	ttl := cap
	if lifetime > 0 && lifetime < cap {
		ttl = lifetime
	}
	if ttl > tokenRefreshSkew {
		return ttl - tokenRefreshSkew
	}
	return ttl
}

// fetchToken asks the participant-local token service for an access token,
// returning the token and the lifetime it reported.
//
// The plugin fails closed, so the returned error names the status: the token
// service answers 502 when the verifier could not be reached (retryable) and
// 403/400/500 when the credential was refused or it is misconfigured (terminal).
func (c *Client) fetchToken(ctx context.Context) (string, time.Duration, error) {
	payload, err := json.Marshal(tokenRequest{Audience: c.tokenAudience})
	if err != nil {
		return "", 0, fmt.Errorf("consent client: failed to marshal token request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenServiceURL, bytes.NewReader(payload))
	if err != nil {
		return "", 0, fmt.Errorf("consent client: failed to create token request: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeJSON)

	// Deliberately not c.do(): the token service is a local, same-namespace
	// service, not the consent-manager, so the Host override and API prefix that
	// c.do() applies for the gateway route must not be used here.
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("consent client: token service request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", 0, fmt.Errorf("consent client: failed to read token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("consent client: token service returned status %d, body: %s",
			resp.StatusCode, truncateBody(body))
	}
	var out tokenResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", 0, fmt.Errorf("consent client: failed to unmarshal token response: %w", err)
	}
	if out.AccessToken == "" {
		return "", 0, fmt.Errorf("consent client: token service returned no access token")
	}
	return out.AccessToken, time.Duration(out.ExpiresIn) * time.Second, nil
}

// meResponse is the (subset of the) consent-manager response to GET /participants/me.
type meResponse struct {
	SelfDescriptionURL string `json:"selfDescriptionURL"`
}

// fetchProviderSD reads the calling participant's self-description URL.
func (c *Client) fetchProviderSD(ctx context.Context, token string) (string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(participantMePath), nil)
	if err != nil {
		return "", fmt.Errorf("consent client: failed to create /me request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return "", err
	}
	if status == http.StatusUnauthorized {
		return "", errParticipantUnauthorized
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("consent client: participant lookup (/me) returned status %d, body: %s",
			status, truncateBody(body))
	}
	var out meResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", fmt.Errorf("consent client: failed to unmarshal /me response: %w", err)
	}
	if out.SelfDescriptionURL == "" {
		return "", fmt.Errorf("consent client: /me returned no selfDescriptionURL")
	}
	return out.SelfDescriptionURL, nil
}

// identifierSearchResponse is the consent-manager response to the identifier search.
type identifierSearchResponse struct {
	UserIdentifier string `json:"userIdentifier"`
}

// resolveUserIdentifier performs call 1: it maps the subject (a DID, sent as the
// user "email") to the provider-scoped user identifier. A 404 or empty identifier
// means the subject is unknown (found == false).
//
// It carries both the shared consent key (which the consent-manager's
// consentKeyCheck validates) and the participant token as a Bearer credential,
// so an authenticating facade in front of the consent-manager can validate the
// participant JWT on this call too (the consent-manager ignores the Bearer here).
func (c *Client) resolveUserIdentifier(ctx context.Context, subject, providerSD, token string) (identifier string, found bool, err error) {
	payload, err := json.Marshal(map[string]string{"selfDescription": providerSD, "email": subject})
	if err != nil {
		return "", false, fmt.Errorf("consent client: failed to marshal identifier search: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(identifierSearchPath), bytes.NewReader(payload))
	if err != nil {
		return "", false, fmt.Errorf("consent client: failed to create identifier search request: %w", err)
	}
	httpReq.Header.Set("Content-Type", ContentTypeJSON)
	// The consent key is optional here: when the plugin sits behind the
	// authority's facade, the facade injects x-visionstrust-consent-key from
	// its own secret and overrides anything we send. We only set it for a
	// direct (facade-less) deployment where the plugin holds the key itself.
	if c.consentKey != "" {
		httpReq.Header.Set(consentKeyHeader, c.consentKey)
	}
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	status, body, err := c.do(httpReq)
	if err != nil {
		return "", false, err
	}
	if status == http.StatusNotFound {
		return "", false, nil
	}
	if status == http.StatusUnauthorized {
		// a facade in front of the consent-manager rejected the participant token
		return "", false, errParticipantUnauthorized
	}
	if status != http.StatusOK {
		return "", false, fmt.Errorf("consent client: identifier search returned status %d, body: %s",
			status, truncateBody(body))
	}
	var out identifierSearchResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", false, fmt.Errorf("consent client: failed to unmarshal identifier search response: %w", err)
	}
	return out.UserIdentifier, out.UserIdentifier != "", nil
}

// participantConsentsResponse is the consent-manager response to call 2. The
// ?receipt=true form returns the raw consents, each carrying its status and the
// data resources it covers.
type participantConsentsResponse struct {
	Consents []struct {
		Status string `json:"status"`
		Data   []struct {
			Resource string `json:"resource"`
		} `json:"data"`
	} `json:"consents"`
}

// hasGrantedConsent performs call 2: it lists the user identifier's consents as
// seen by the participant and reports whether any granted consent authorizes
// access. When dataResource is empty the check is owner-level (any granted
// consent suffices); otherwise a granted consent counts only if it covers that
// resource (dataResource ∈ consent.data[].resource). A 401 is returned as
// errParticipantUnauthorized so the caller can refresh the token and retry.
func (c *Client) hasGrantedConsent(ctx context.Context, token, userIdentifier, dataResource string) (bool, error) {
	endpoint := c.endpoint(fmt.Sprintf(participantConsentsPathFmt, url.PathEscape(userIdentifier))) + "?receipt=true"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("consent client: failed to create consents request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	status, body, err := c.do(httpReq)
	if err != nil {
		return false, err
	}
	if status == http.StatusUnauthorized {
		return false, errParticipantUnauthorized
	}
	if status != http.StatusOK {
		return false, fmt.Errorf("consent client: consents lookup returned status %d, body: %s",
			status, truncateBody(body))
	}
	var out participantConsentsResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return false, fmt.Errorf("consent client: failed to unmarshal consents response: %w", err)
	}
	for _, consent := range out.Consents {
		if consent.Status != grantedStatus {
			continue
		}
		if dataResource == "" {
			return true, nil
		}
		for _, d := range consent.Data {
			if d.Resource == dataResource {
				return true, nil
			}
		}
	}
	return false, nil
}

// endpoint builds a full URL from the base URL, the API prefix and a path.
func (c *Client) endpoint(path string) string {
	return strings.TrimRight(c.baseURL, "/") + c.apiPrefix + path
}

// do executes the request and returns the response status code together with
// its fully read body, closing the body before returning. It intentionally does
// not surface the *http.Response: the body is already consumed and closed, so
// callers only need the status code and body bytes.
func (c *Client) do(httpReq *http.Request) (statusCode int, body []byte, err error) {
	if c.host != "" {
		httpReq.Host = c.host
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return 0, nil, fmt.Errorf("consent client: HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, fmt.Errorf("consent client: failed to read response body: %w", err)
	}
	return resp.StatusCode, body, nil
}

// maxBodyLogLength bounds error-body length in messages.
const maxBodyLogLength = 256

// truncateBody returns the response body as a string, truncated to maxBodyLogLength.
func truncateBody(body []byte) string {
	if len(body) <= maxBodyLogLength {
		return string(body)
	}
	return string(body[:maxBodyLogLength]) + "...(truncated)"
}
