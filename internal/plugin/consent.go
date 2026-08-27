/*
 * Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Package plugin implements the APISIX consent-filter plugin that intercepts
// HTTP responses and applies consent-based filtering for personal data.
package plugin

import (
	"consent-plugin/internal/audit"
	"consent-plugin/internal/consent"
	"consent-plugin/internal/jwt"
	"consent-plugin/internal/ownerresolver"
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
)

// pluginName is the registered name for this plugin in APISIX configuration.
const pluginName = "consent-filter"

// nginxRequestIDVar is the Nginx variable ($request_id) holding a unique id
// per HTTP request. Unlike the runner's per-RPC ID(), it is identical in the
// RequestFilter (ext-plugin-pre-req) and ResponseFilter (ext-plugin-post-resp)
// phases, so it is used to correlate the context captured in one phase with
// the other.
const nginxRequestIDVar = "request_id"

// varReader is the subset of the runner's Request/Response interfaces that
// exposes Nginx variables. Both pkgHTTP.Request and pkgHTTP.Response satisfy it.
type varReader interface {
	Var(name string) ([]byte, error)
}

// correlationKey returns a key that stably identifies the HTTP request across
// the request and response phases, based on the Nginx $request_id variable.
// It returns false if the variable cannot be read, in which case the two
// phases cannot be correlated.
func correlationKey(v varReader) (string, bool) {
	id, err := v.Var(nginxRequestIDVar)
	if err != nil || len(id) == 0 {
		return "", false
	}
	return string(id), true
}

func init() {
	if err := plugin.RegisterPlugin(&ConsentFilter{}); err != nil {
		panic("failed to register consent-filter plugin: " + err.Error())
	}
}

// ConsentFilter is the APISIX plugin that intercepts HTTP responses,
// consults an external consent API, and filters or denies responses
// based on consent decisions for personal data fields.
type ConsentFilter struct {
	plugin.DefaultPlugin
}

// Name returns the unique name of this plugin as registered with APISIX.
func (c *ConsentFilter) Name() string {
	return pluginName
}

// ParseConf deserializes and validates the plugin configuration from
// the JSON bytes provided by APISIX. Returns the parsed configuration
// or an error if the configuration is invalid.
func (c *ConsentFilter) ParseConf(in []byte) (interface{}, error) {
	return ParseConfig(in)
}

// RequestFilter intercepts incoming HTTP requests to capture request context
// (headers, JWT claims, path, method) for use during response filtering.
// It extracts the JWT from the configured header, decodes the requested claims,
// captures all request headers, and stores the context keyed by request ID
// for later retrieval in ResponseFilter.
//
// The JWT is decoded, NOT verified (see internal/jwt): the claims are used only
// to name the consuming participant for the contract lookup, and the route MUST
// have an authentication plugin in front of this one that validates the token.
func (c *ConsentFilter) RequestFilter(conf interface{}, w http.ResponseWriter, r pkgHTTP.Request) {
	cfg, ok := conf.(*Config)
	if !ok {
		log.Printf("[consent-filter] RequestFilter: invalid config type, skipping request %d", r.ID())
		return
	}

	reqCtx := &RequestContext{
		Method:  r.Method(),
		Path:    string(r.Path()),
		Headers: make(http.Header),
	}

	// Capture request headers from the request's Header view.
	if srcHeaders := r.Header().View(); srcHeaders != nil {
		for key, values := range srcHeaders {
			reqCtx.Headers[key] = values
		}
	}

	// Extract JWT token and decode claims from the configured header.
	jwtHeaderValue := r.Header().Get(cfg.JWTHeaderName)
	if jwtHeaderValue != "" {
		token, err := jwt.ExtractToken(jwtHeaderValue)
		if err != nil {
			log.Printf("[consent-filter] RequestFilter: failed to extract JWT from header %q for request %d: %v",
				cfg.JWTHeaderName, r.ID(), err)
		} else {
			claims, err := jwt.DecodeClaims(token, claimKeysToDecode(cfg))
			if err != nil {
				log.Printf("[consent-filter] RequestFilter: failed to decode JWT claims for request %d: %v",
					r.ID(), err)
			} else {
				reqCtx.JWTClaims = claims
			}
		}
	}

	// Correlate with the response phase via the stable Nginx $request_id, not
	// the runner's per-RPC ID() (which differs between pre-req and post-resp).
	key, ok := correlationKey(r)
	if !ok {
		log.Printf("[consent-filter] RequestFilter: could not read %q for request %d; consent context not stored",
			nginxRequestIDVar, r.ID())
		return
	}

	StoreRequestContext(key, reqCtx)
}

// decisionAllow and decisionDeny are the audit-facing labels for the decision.
const (
	decisionAllow = "allow"
	decisionDeny  = "deny"
)

// responseOutcome is the result of evaluating consent for one response: the
// decision to enforce plus the fields needed to record it in the audit log.
type responseOutcome struct {
	decision  string // decisionAllow | decisionDeny
	reason    string
	requestID string
	subject   string
	resource  string
	method    string
}

// ResponseFilter gates the upstream response on the data owner's consent.
//
// The flow is:
//  1. Correlate with the request phase and load (and delete) the stored context.
//  2. Ask the OwnerResolver, from the RESPONSE DATA, whether consent is required
//     and who the data owner(s) are.
//  3. Run the two-call consent check per resolved owner (deny_all: every owner
//     must have a granted consent).
//  4. Allow → pass the response through unchanged; deny → replace it with the
//     configured denial response.
//  5. On unresolved context, a resolver error, or a consent-manager error, apply
//     the fail policy (deny unless explicitly fail-open).
//
// The requestor's identity is NEVER used to determine ownership: the token's
// "sub" says who is asking, not whose data is being returned, so a check against
// it would let any subject holding one granted consent read everyone's data.
//
// Every decision is recorded to the audit sink (when enabled) before it is
// enforced. The check is a coarse allow/deny and is independent of the response
// body's shape, so — unlike a field-level filter — an empty or non-JSON
// personal-data response is still gated rather than passed through.
func (c *ConsentFilter) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	cfg, ok := conf.(*Config)
	if !ok {
		log.Printf("[consent-filter] ResponseFilter: invalid config type, skipping request %d", w.ID())
		return
	}

	outcome := c.evaluate(cfg, w)
	recordAudit(cfg, outcome)
	if outcome.decision == decisionDeny {
		denyResponse(w, cfg)
	}
}

// evaluate runs the consent decision for the current response and returns the
// outcome to enforce; it does not write the response. A missing correlation id,
// missing request context, or a consent-manager error falls back to the fail
// policy (deny unless explicitly fail-open).
func (c *ConsentFilter) evaluate(cfg *Config, w pkgHTTP.Response) responseOutcome {
	// Correlate with the request phase via the stable Nginx $request_id.
	key, ok := correlationKey(w)
	if !ok {
		log.Printf("[consent-filter] ResponseFilter: could not read %q for request %d; cannot verify consent", nginxRequestIDVar, w.ID())
		return failOutcome(cfg, "no request correlation id", "", nil)
	}

	// Load and delete stored request context (cleanup to prevent memory leaks).
	reqCtx, found := LoadAndDeleteRequestContext(key)
	if !found {
		// The request phase did not capture context for this request; the
		// consent decision cannot be made, so honor the fail policy instead
		// of silently passing the response through.
		log.Printf("[consent-filter] ResponseFilter: no request context found for request %s; cannot verify consent", key)
		return failOutcome(cfg, "no request context", key, nil)
	}

	// Resolve the data owner(s) from the response DATA and check consent per
	// owner. ParseConfig guarantees a resolver is configured.
	consentClient := consent.NewClient(clientConfigFromCfg(cfg))
	return c.evaluateWithResolver(cfg, w, key, reqCtx, consentClient)
}

// evaluateWithResolver reads the upstream body, asks the OwnerResolver who owns
// the data (and whether consent is required), and enforces deny_all: every
// distinct (owner, dataResource) claim must have a granted consent, or the whole
// response is denied. The requestor identity is never consulted for ownership.
func (c *ConsentFilter) evaluateWithResolver(cfg *Config, w pkgHTTP.Response, key string, reqCtx *RequestContext, consentClient *consent.Client) responseOutcome {
	body, err := w.ReadBody()
	if err != nil {
		log.Printf("[consent-filter] ResponseFilter: could not read upstream body for request %s: %v", key, err)
		return failOutcome(cfg, "read upstream body: "+err.Error(), key, nil)
	}

	contentType := ""
	if h := w.Header(); h != nil {
		contentType = h.Get("Content-Type")
	}

	// Parties are for CONTRACT identification only - never for ownership. The
	// token names the consumer by DID, while contracts name their parties by
	// self-description URL, so translate it via the participant registry.
	//
	// Both sides are resolved BEFORE the resolver is asked anything, and a failure
	// on either is terminal. Proceeding with an empty Parties would omit the field
	// from /resolve entirely, and a resolver that cannot identify a contract may
	// answer consentRequired:false — which is an unconditional allow. That would
	// put a fail-open seam in the middle of a fail-closed design, reachable by
	// nothing more than a briefly unreachable consent-manager or a revoked token.
	resolveParties := ownerresolver.Parties{}
	consumerDID := consumerFromClaims(reqCtx.JWTClaims, cfg.ConsumerClaim)
	if consumerDID == "" {
		log.Printf("[consent-filter] ResponseFilter: no consuming participant in the token claims (path %q) for request %s", cfg.ConsumerClaim, key)
		return failOutcome(cfg, "no consuming participant identified", key, nil)
	}
	consumerSD, sdErr := consentClient.ParticipantSelfDescriptionByDID(context.Background(), consumerDID)
	if sdErr != nil {
		log.Printf("[consent-filter] ResponseFilter: could not map the consumer to a participant for request %s: %v", key, sdErr)
		return failOutcome(cfg, "consumer participant lookup failed: "+sdErr.Error(), key, nil)
	}
	// The consumer also scopes the consent match itself: a consent names the one
	// participant it was granted to, so releasing data to any other participant
	// on the strength of it would authorise an agreement the subject never made.
	resolveParties.Consumer = consumerSD

	providerSD, sdErr := consentClient.ProviderSelfDescription(context.Background())
	if sdErr != nil {
		log.Printf("[consent-filter] ResponseFilter: could not determine the provider self-description for request %s: %v", key, sdErr)
		return failOutcome(cfg, "provider self-description lookup failed: "+sdErr.Error(), key, nil)
	}
	resolveParties.Provider = providerSD

	resolverClient := ownerresolver.NewClient(cfg.OwnerResolverURL, cfg.OwnerResolverTimeout)
	result, err := resolverClient.Resolve(context.Background(), ownerresolver.Resource{
		Service:     cfg.Service,
		Method:      reqCtx.Method,
		Path:        reqCtx.Path,
		ContentType: contentType,
	}, resolveParties, body)
	if err != nil {
		log.Printf("[consent-filter] ResponseFilter: owner resolver error for request %s: %v", key, err)
		return failOutcome(cfg, "owner resolver error: "+err.Error(), key, nil)
	}

	if !result.ConsentRequired {
		return responseOutcome{decision: decisionAllow, reason: "no consent required", requestID: key, resource: reqCtx.Path, method: reqCtx.Method}
	}
	if len(result.Claims) == 0 {
		// Consent required but no owner could be resolved — fail closed.
		return failOutcome(cfg, "consent required but no data owner resolved", key, nil)
	}

	// deny_all: every distinct (owner, dataResource) claim must be granted.
	type pair struct{ owner, resource string }
	checked := make(map[pair]bool)
	for _, claim := range result.Claims {
		if claim.OwnerID == "" {
			return failOutcome(cfg, "resolved claim without a data owner", key, nil)
		}
		p := pair{owner: claim.OwnerID, resource: claim.DataResource}
		if checked[p] {
			continue
		}
		checked[p] = true

		req := consent.ConsentRequest{
			Subject:      claim.OwnerID,
			Resource:     reqCtx.Path,
			Method:       reqCtx.Method,
			DataResource: claim.DataResource,
			Consumer:     consumerSD,
			Purpose:      claim.Purpose,
		}
		resp, err := consentClient.CheckConsent(context.Background(), req)
		if err != nil {
			log.Printf("[consent-filter] ResponseFilter: consent check error for request %s: %v", key, err)
			return failOutcome(cfg, "consent check error: "+err.Error(), key, &req)
		}
		if resp.Decision != consent.DecisionAllow {
			return responseOutcome{
				decision:  decisionDeny,
				reason:    resp.Reason,
				requestID: key,
				subject:   claim.OwnerID,
				resource:  resourceOrPath(claim.DataResource, reqCtx.Path),
				method:    reqCtx.Method,
			}
		}
	}
	return responseOutcome{decision: decisionAllow, requestID: key, resource: reqCtx.Path, method: reqCtx.Method}
}

// clientConfigFromCfg builds the consent-manager client config from the plugin config.
func clientConfigFromCfg(cfg *Config) consent.ClientConfig {
	return consent.ClientConfig{
		BaseURL:          cfg.ConsentAPIURL,
		Host:             cfg.ConsentAPIHost,
		APIPrefix:        cfg.ConsentAPIPrefix,
		ConsentKey:       cfg.ConsentKey,
		ProviderSD:       cfg.ProviderSD,
		ParticipantToken: cfg.ParticipantToken,
		TokenServiceURL:  cfg.TokenServiceURL,
		TokenAudience:    cfg.TokenAudience,
		TokenTTL:         time.Duration(cfg.ParticipantTokenTTL) * time.Second,
		TimeoutMs:        cfg.ConsentAPITimeout,
	}
}

// resourceOrPath returns dataResource when set, else the request path (for audit).
func resourceOrPath(dataResource, path string) string {
	if dataResource != "" {
		return dataResource
	}
	return path
}

// failOutcome builds the outcome for an unresolved consent check, applying the
// fail policy (allow when fail-open, otherwise deny). req may be nil when no
// request context was captured.
func failOutcome(cfg *Config, reason, requestID string, req *consent.ConsentRequest) responseOutcome {
	decision := decisionDeny
	if cfg.IsFailOpen() {
		decision = decisionAllow
	}
	o := responseOutcome{decision: decision, reason: reason, requestID: requestID}
	if req != nil {
		o.subject = req.Subject
		o.resource = req.Resource
		o.method = req.Method
	}
	return o
}

// recordAudit emits the decision to the audit sink when auditing is enabled.
// The emit is asynchronous and best-effort, so it never affects the decision.
func recordAudit(cfg *Config, outcome responseOutcome) {
	if !cfg.AuditEnabled {
		return
	}
	audit.Get(audit.Config{
		Endpoint:    cfg.AuditOTLPEndpoint,
		ServiceName: cfg.AuditServiceName,
		Timeout:     time.Duration(cfg.ConsentAPITimeout) * time.Millisecond,
	}).Emit(audit.Event{
		Time:      time.Now(),
		RequestID: outcome.requestID,
		Subject:   outcome.subject,
		Resource:  outcome.resource,
		Method:    outcome.method,
		Decision:  outcome.decision,
		Reason:    outcome.reason,
	})
}

// denyResponse writes a denial response to the client using the configured
// status code, body, and content type.
func denyResponse(w pkgHTTP.Response, cfg *Config) {
	w.Header().Set("Content-Type", cfg.DenyResponseContentType)
	w.WriteHeader(cfg.DenyStatusCode)
	if _, err := w.Write([]byte(cfg.DenyResponseBody)); err != nil {
		log.Printf("[consent-filter] ResponseFilter: failed to write deny body for request %d: %v", w.ID(), err)
	}
}

// claimKeysToDecode returns the claim keys the request phase must decode: the
// configured forward list plus the root of the consumer-claim path, so the
// consumer can be read in the response phase. An empty result means "all claims".
func claimKeysToDecode(cfg *Config) []string {
	if len(cfg.JWTClaimsToForward) == 0 {
		// DecodeClaims returns every claim in this case - nothing to add.
		return nil
	}
	keys := append([]string(nil), cfg.JWTClaimsToForward...)
	if cfg.ConsumerClaim == "" {
		return keys
	}
	root := strings.SplitN(cfg.ConsumerClaim, claimPathSeparator, 2)[0]
	for _, k := range keys {
		if k == root {
			return keys
		}
	}
	return append(keys, root)
}

// claimPathSeparator separates the segments of a dotted claim path.
const claimPathSeparator = "."

// consumerFromClaims reads the consuming participant from a dotted claim path
// (e.g. "verifiableCredential.issuer"). It returns "" when the path is unset or
// does not resolve to a string, which the caller treats as a failure to identify
// the exchange - the fail policy then applies.
func consumerFromClaims(claims map[string]interface{}, path string) string {
	if len(claims) == 0 || path == "" {
		return ""
	}
	var current interface{} = claims
	for _, segment := range strings.Split(path, claimPathSeparator) {
		node, ok := current.(map[string]interface{})
		if !ok {
			return ""
		}
		current, ok = node[segment]
		if !ok {
			return ""
		}
	}
	if s, ok := current.(string); ok {
		return s
	}
	return ""
}
