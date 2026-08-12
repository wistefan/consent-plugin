// Package plugin implements the APISIX consent-filter plugin that intercepts
// HTTP responses and applies consent-based filtering for personal data.
package plugin

import (
	"consent-plugin/internal/audit"
	"consent-plugin/internal/consent"
	"consent-plugin/internal/jwt"
	"context"
	"log"
	"net/http"
	"time"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"
)

// pluginName is the registered name for this plugin in APISIX configuration.
const pluginName = "consent-filter"

// jwtSubjectClaim is the JWT claim key used to extract the subject identity.
const jwtSubjectClaim = "sub"

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
			claims, err := jwt.DecodeClaims(token, cfg.JWTClaimsToForward)
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

// ResponseFilter gates the upstream response on the data subject's consent.
//
// The flow is:
//  1. Correlate with the request phase and load (and delete) the stored context.
//  2. Build a ConsentRequest (the subject comes from the JWT "sub" claim).
//  3. Run the two-call consent check against the consent-manager.
//  4. Allow → pass the response through unchanged; deny → replace it with the
//     configured denial response.
//  5. On unresolved context or a consent-manager error, apply the fail policy
//     (deny unless explicitly fail-open).
//
// Every decision is recorded to the audit sink (when enabled) before it is
// enforced. The check is a coarse allow/deny on the subject's consent and is
// independent of the response body, so — unlike a field-level filter — an empty
// or non-JSON personal-data response is still gated rather than passed through.
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

	// Run the two-call consent check for the request subject.
	consentReq := buildConsentRequest(reqCtx)
	consentClient := consent.NewClient(consent.ClientConfig{
		BaseURL:          cfg.ConsentAPIURL,
		APIPrefix:        cfg.ConsentAPIPrefix,
		ConsentKey:       cfg.ConsentKey,
		ProviderSD:       cfg.ProviderSD,
		ParticipantToken: cfg.ParticipantToken,
		ClientID:         cfg.ClientID,
		ClientSecret:     cfg.ClientSecret,
		TokenTTL:         time.Duration(cfg.ParticipantTokenTTL) * time.Second,
		TimeoutMs:        cfg.ConsentAPITimeout,
	})
	consentResp, err := consentClient.CheckConsent(context.Background(), consentReq)
	if err != nil {
		log.Printf("[consent-filter] ResponseFilter: consent check error for request %d: %v", w.ID(), err)
		return failOutcome(cfg, "consent check error: "+err.Error(), key, &consentReq)
	}

	decision := decisionDeny
	if consentResp.Decision == consent.DecisionAllow {
		decision = decisionAllow
	}
	return responseOutcome{
		decision:  decision,
		reason:    consentResp.Reason,
		requestID: key,
		subject:   consentReq.Subject,
		resource:  consentReq.Resource,
		method:    consentReq.Method,
	}
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

// buildConsentRequest creates a ConsentRequest from the stored request context.
// The subject (used to look up consent) is taken from the JWT "sub" claim.
func buildConsentRequest(reqCtx *RequestContext) consent.ConsentRequest {
	consentReq := consent.ConsentRequest{
		Resource: reqCtx.Path,
		Method:   reqCtx.Method,
		Claims:   reqCtx.JWTClaims,
	}

	// Extract subject from JWT claims if available.
	if reqCtx.JWTClaims != nil {
		if sub, ok := reqCtx.JWTClaims[jwtSubjectClaim]; ok {
			if subStr, ok := sub.(string); ok {
				consentReq.Subject = subStr
			}
		}
	}

	return consentReq
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
