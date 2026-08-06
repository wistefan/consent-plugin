// Package plugin implements the APISIX consent-filter plugin that intercepts
// HTTP responses and applies consent-based filtering for personal data.
package plugin

import (
	"context"
	"log"
	"net/http"
	"strings"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/apache/apisix-go-plugin-runner/pkg/plugin"

	"consent-plugin/internal/consent"
	"consent-plugin/internal/filter"
	"consent-plugin/internal/jwt"
)

// pluginName is the registered name for this plugin in APISIX configuration.
const pluginName = "consent-filter"

// jsonContentTypePrefix is the Content-Type value prefix that identifies JSON responses.
const jsonContentTypePrefix = "application/json"

// jwtSubjectClaim is the JWT claim key used to extract the subject identity.
const jwtSubjectClaim = "sub"

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

	StoreRequestContext(r.ID(), reqCtx)
}

// ResponseFilter intercepts upstream HTTP responses, consults the consent API,
// and applies filtering or denial based on the consent decision.
//
// The flow is:
//  1. Load and delete the stored RequestContext (cleanup to prevent memory leaks).
//  2. Read the upstream response body; pass through if empty or non-JSON.
//  3. Extract top-level field names from the JSON body.
//  4. Build a ConsentRequest and call the consent API.
//  5. Apply the consent decision: allow (pass through), deny (error response),
//     or filter (remove denied fields from the body).
//  6. On consent API errors, apply fail-open or fail-closed policy.
func (c *ConsentFilter) ResponseFilter(conf interface{}, w pkgHTTP.Response) {
	cfg, ok := conf.(*Config)
	if !ok {
		log.Printf("[consent-filter] ResponseFilter: invalid config type, skipping request %d", w.ID())
		return
	}

	// Load and delete stored request context (cleanup to prevent memory leaks).
	reqCtx, found := LoadAndDeleteRequestContext(w.ID())
	if !found {
		log.Printf("[consent-filter] ResponseFilter: no request context found for request %d, passing through", w.ID())
		return
	}

	// Read the upstream response body.
	body, err := w.ReadBody()
	if err != nil {
		log.Printf("[consent-filter] ResponseFilter: failed to read body for request %d: %v", w.ID(), err)
		return
	}

	// If body is empty, pass through.
	if len(body) == 0 {
		return
	}

	// Check if response Content-Type is JSON; pass through non-JSON responses.
	contentType := w.Header().Get("Content-Type")
	if !isJSONContentType(contentType) {
		return
	}

	// Extract top-level field names from the response body.
	fieldNames, err := filter.ExtractFieldNames(body)
	if err != nil {
		log.Printf("[consent-filter] ResponseFilter: failed to extract field names for request %d: %v", w.ID(), err)
		// Proceed with empty field names — the consent API can still make a decision.
	}

	// Build the consent request from stored context and response fields.
	consentReq := buildConsentRequest(reqCtx, fieldNames)

	// Create consent client and check consent.
	consentClient := consent.NewClient(cfg.ConsentAPIURL, cfg.ConsentAPITimeout)
	consentResp, err := consentClient.CheckConsent(context.Background(), consentReq)
	if err != nil {
		log.Printf("[consent-filter] ResponseFilter: consent API error for request %d: %v", w.ID(), err)
		if !cfg.IsFailOpen() {
			denyResponse(w, cfg)
		}
		return
	}

	// Apply the consent decision.
	switch consentResp.Decision {
	case consent.DecisionAllow:
		// Pass through unchanged.
		return

	case consent.DecisionDeny:
		denyResponse(w, cfg)

	case consent.DecisionFilter:
		filteredBody, err := filter.RemoveFields(body, consentResp.DeniedFields)
		if err != nil {
			log.Printf("[consent-filter] ResponseFilter: failed to filter response for request %d: %v", w.ID(), err)
			return
		}
		if _, err := w.Write(filteredBody); err != nil {
			log.Printf("[consent-filter] ResponseFilter: failed to write filtered body for request %d: %v", w.ID(), err)
		}
	}
}

// buildConsentRequest creates a ConsentRequest from the stored request
// context and the extracted response field names.
func buildConsentRequest(reqCtx *RequestContext, fieldNames []string) consent.ConsentRequest {
	consentReq := consent.ConsentRequest{
		Resource:       reqCtx.Path,
		Method:         reqCtx.Method,
		Claims:         reqCtx.JWTClaims,
		ResponseFields: fieldNames,
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

// isJSONContentType reports whether the given Content-Type header value
// indicates a JSON response body.
func isJSONContentType(contentType string) bool {
	return strings.Contains(strings.ToLower(contentType), jsonContentTypePrefix)
}
