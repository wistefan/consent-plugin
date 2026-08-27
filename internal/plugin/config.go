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
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
)

// Default values for optional configuration fields.
const (
	// DefaultConsentAPITimeout is the default timeout in milliseconds for consent API calls.
	DefaultConsentAPITimeout = 5000

	// DefaultOwnerResolverTimeout is the default timeout in milliseconds for
	// OwnerResolver calls.
	DefaultOwnerResolverTimeout = 2000

	// DefaultConsumerClaim is the dotted claim path holding the consuming
	// participant's identity. The provider's verifier embeds the presented
	// credential in the access token (jwtInclusion.fullInclusion), so the
	// credential's issuer is the consumer.
	DefaultConsumerClaim = "verifiableCredential.issuer"

	// DefaultTokenAudience is the audience asked of the token service when none is
	// configured. It names the token service's configured target for the
	// consent-manager, not a URL.
	DefaultTokenAudience = "consent-manager"

	// DefaultJWTHeaderName is the default HTTP header containing the JWT token.
	DefaultJWTHeaderName = "Authorization"

	// DefaultConsentAPIPrefix is the default consent-manager API prefix,
	// prepended to every endpoint path (matches the consent-manager's API_PREFIX).
	DefaultConsentAPIPrefix = "/v1"

	// DefaultDenyStatusCode is the default HTTP status code returned when consent is denied.
	DefaultDenyStatusCode = 403

	// DefaultDenyResponseBody is the default JSON body returned when consent is denied.
	DefaultDenyResponseBody = `{"error":"access denied by consent policy"}`

	// DefaultDenyResponseContentType is the default Content-Type header for denial responses.
	DefaultDenyResponseContentType = "application/json"

	// MinConsentAPITimeout is the minimum allowed timeout in milliseconds.
	MinConsentAPITimeout = 1

	// MaxConsentAPITimeout is the maximum allowed timeout in milliseconds (60 seconds).
	MaxConsentAPITimeout = 60000

	// MinHTTPStatusCode is the minimum valid HTTP status code for denial responses.
	MinHTTPStatusCode = 100

	// MaxHTTPStatusCode is the maximum valid HTTP status code for denial responses.
	MaxHTTPStatusCode = 599
)

// Environment variables that provide the participant credentials and consent
// key out-of-band, so they need not live in the route config (plaintext in
// etcd). A value set in the route config always takes precedence; the env var
// is only consulted when the corresponding field is empty. The plugin runner
// inherits these from the APISIX container, which sources them from a Secret.
const (
	// EnvConsentKey supplies ConsentKey (x-visionstrust-consent-key).
	EnvConsentKey = "CONSENT_KEY"

	// EnvTokenServiceURL supplies TokenServiceURL (the participant-local OID4VP
	// token service).
	EnvTokenServiceURL = "CONSENT_TOKEN_SERVICE_URL"

	// EnvAuditOTLPEndpoint supplies AuditOTLPEndpoint (the OTLP/HTTP Collector
	// endpoint access-decision audit events are exported to).
	EnvAuditOTLPEndpoint = "CONSENT_AUDIT_OTLP_ENDPOINT"
)

// Config holds the plugin configuration that APISIX passes as JSON.
// It defines how the consent-filter plugin connects to the external consent API
// and how it handles denial responses.
type Config struct {
	// ConsentAPIURL is the base URL of the external consent API (required).
	ConsentAPIURL string `json:"consent_api_url"`

	// ConsentAPITimeout is the timeout in milliseconds for consent API calls.
	// Defaults to DefaultConsentAPITimeout (5000ms).
	ConsentAPITimeout int `json:"consent_api_timeout,omitempty"`

	// JWTHeaderName is the name of the HTTP header containing the JWT token.
	// Defaults to DefaultJWTHeaderName ("Authorization").
	JWTHeaderName string `json:"jwt_header_name,omitempty"`

	// JWTClaimsToForward specifies which JWT claims to send to the consent API.
	// For example: ["sub", "scope"]. Must include "sub" — the consent check
	// resolves the data subject from the "sub" claim.
	JWTClaimsToForward []string `json:"jwt_claims_to_forward,omitempty"`

	// ConsentAPIPrefix is the consent-manager API prefix prepended to endpoint
	// paths. Defaults to DefaultConsentAPIPrefix ("/v1").
	ConsentAPIPrefix string `json:"consent_api_prefix,omitempty"`

	// OwnerResolverURL is the external OwnerResolver /resolve endpoint. When set,
	// the data owner is resolved from the RESPONSE DATA (never the requestor):
	// the plugin posts the payload, gets back (owner[, dataResource]) claims, and
	// checks consent per owner. When empty, the plugin falls back to the legacy
	// behaviour of taking the subject from the JWT.
	OwnerResolverURL string `json:"owner_resolver_url,omitempty"`

	// ConsentAPIHost overrides the HTTP Host header sent on consent-manager
	// calls. Needed when ConsentAPIURL points at an in-cluster gateway service
	// whose routes are host-scoped to the public ingress name: the TCP connection
	// still uses the URL's host, but the Host header must equal the route's host
	// or APISIX returns "404 Route Not Found".
	ConsentAPIHost string `json:"consent_api_host,omitempty"`

	// OwnerResolverTimeout is the per-call timeout in milliseconds for the
	// OwnerResolver (defaults to DefaultOwnerResolverTimeout).
	OwnerResolverTimeout int `json:"owner_resolver_timeout,omitempty"`

	// Service is the logical dataset id sent to the OwnerResolver as
	// resource.service, so it can select the right rule for this route.
	Service string `json:"service,omitempty"`

	// ConsumerClaim is the dotted path of the token claim identifying the
	// consuming participant, forwarded to the OwnerResolver as parties.consumer so
	// it can find the governing contract. Defaults to DefaultConsumerClaim. It is
	// used for contract lookup ONLY - never to determine the data owner.
	ConsumerClaim string `json:"consumer_claim,omitempty"`

	// ConsentKey is the shared secret sent as the x-visionstrust-consent-key
	// header on the identifier-search call. Optional: when the plugin runs
	// behind the authority's facade, the facade injects the key server-side and
	// this is not needed. Falls back to the EnvConsentKey env var when empty.
	ConsentKey string `json:"consent_key,omitempty"`

	// TokenServiceURL is the participant-local OID4VP token service the plugin
	// asks for an access token — the consent-facade's POST /internal/tokens. The
	// plugin holds no participant credentials of its own: the facade presents the
	// participant's verifiable credential and returns a short-lived token, which
	// the plugin caches and refreshes. Falls back to EnvTokenServiceURL when
	// empty. Required unless a static ParticipantToken is configured.
	TokenServiceURL string `json:"token_service_url,omitempty"`

	// TokenAudience is the audience name asked of the token service (its
	// configured target, not a URL). Defaults to DefaultTokenAudience.
	TokenAudience string `json:"token_audience,omitempty"`

	// ParticipantTokenTTL caps, in seconds, how long a fetched token is cached
	// (defaults to 3000s). The token service reports its own lifetime; the
	// shorter of the two wins. Ignored for a static token.
	ParticipantTokenTTL int `json:"participant_token_ttl,omitempty"`

	// ParticipantToken is an optional *static*, pre-obtained access token for the
	// consents-lookup call. An override for tests and manual runs; normally the
	// token comes from TokenServiceURL so it is refreshed automatically.
	ParticipantToken string `json:"participant_token,omitempty"`

	// ProviderSD is the provider self-description URL sent on the
	// identifier-search call. Optional: when empty it is derived from
	// /participants/me using the participant token.
	ProviderSD string `json:"provider_sd,omitempty"`

	// DenyStatusCode is the HTTP status code returned when consent is denied.
	// Defaults to DefaultDenyStatusCode (403).
	DenyStatusCode int `json:"deny_status_code,omitempty"`

	// DenyResponseBody is the body returned when consent is denied.
	// Defaults to DefaultDenyResponseBody.
	DenyResponseBody string `json:"deny_response_body,omitempty"`

	// DenyResponseContentType is the Content-Type header for denial responses.
	// Defaults to DefaultDenyResponseContentType ("application/json").
	DenyResponseContentType string `json:"deny_response_content_type,omitempty"`

	// FailOpen controls the behavior when the consent API is unavailable or
	// returns an error. When nil or true (default), responses pass through
	// on consent API errors (fail-open). When false, responses are denied
	// on consent API errors (fail-closed).
	FailOpen *bool `json:"fail_open,omitempty"`

	// AuditEnabled turns on emitting an access-decision audit event to an
	// OpenTelemetry Collector (as an OTLP/HTTP log record) for every consent
	// decision. Emission is asynchronous and best-effort, so it never blocks or
	// changes the access decision.
	AuditEnabled bool `json:"audit_enabled,omitempty"`

	// AuditOTLPEndpoint is the base OTLP/HTTP endpoint of the Collector
	// (e.g. http://otel-collector:4318); "/v1/logs" is appended. Required when
	// AuditEnabled. Falls back to the EnvAuditOTLPEndpoint env var when empty.
	AuditOTLPEndpoint string `json:"audit_otlp_endpoint,omitempty"`

	// AuditServiceName is the resource service.name stamped on audit records -
	// the marker the Collector routes on to keep audit logs separate from traces.
	// Empty defaults to the audit package's DefaultServiceName.
	AuditServiceName string `json:"audit_service_name,omitempty"`
}

// IsFailOpen returns whether the plugin should fail-open when the consent API
// is unavailable. Returns true (fail-open) by default when FailOpen is nil.
func (c *Config) IsFailOpen() bool {
	if c.FailOpen == nil {
		return true
	}
	return *c.FailOpen
}

// applyDefaults sets default values for optional fields that were not provided
// in the JSON configuration.
func (c *Config) applyDefaults() {
	if c.ConsentAPITimeout == 0 {
		c.ConsentAPITimeout = DefaultConsentAPITimeout
	}
	if c.JWTHeaderName == "" {
		c.JWTHeaderName = DefaultJWTHeaderName
	}
	if c.ConsentAPIPrefix == "" {
		c.ConsentAPIPrefix = DefaultConsentAPIPrefix
	}
	if c.OwnerResolverURL != "" && c.OwnerResolverTimeout == 0 {
		c.OwnerResolverTimeout = DefaultOwnerResolverTimeout
	}
	if c.OwnerResolverURL != "" && c.ConsumerClaim == "" {
		c.ConsumerClaim = DefaultConsumerClaim
	}
	if c.TokenAudience == "" {
		c.TokenAudience = DefaultTokenAudience
	}
	if c.DenyStatusCode == 0 {
		c.DenyStatusCode = DefaultDenyStatusCode
	}
	if c.DenyResponseBody == "" {
		c.DenyResponseBody = DefaultDenyResponseBody
	}
	if c.DenyResponseContentType == "" {
		c.DenyResponseContentType = DefaultDenyResponseContentType
	}
}

// applyEnv fills the credential fields from environment variables when they are
// not set in the route config. This keeps the consent key and the participant
// client secret out of the APISIX route config (and thus out of etcd): they are
// delivered to the plugin runner via the APISIX container's env, sourced from a
// Kubernetes Secret. A value present in the config always wins.
func (c *Config) applyEnv() {
	if c.ConsentKey == "" {
		c.ConsentKey = os.Getenv(EnvConsentKey)
	}
	if c.TokenServiceURL == "" {
		c.TokenServiceURL = os.Getenv(EnvTokenServiceURL)
	}
	if c.AuditOTLPEndpoint == "" {
		c.AuditOTLPEndpoint = os.Getenv(EnvAuditOTLPEndpoint)
	}
}

// Validate checks that the configuration is valid. It returns an error if any
// required field is missing or any field value is out of the allowed range.
func (c *Config) Validate() error {
	if c.ConsentAPIURL == "" {
		return errors.New("config validation: consent_api_url is required")
	}

	parsedURL, err := url.ParseRequestURI(c.ConsentAPIURL)
	if err != nil {
		return fmt.Errorf("config validation: consent_api_url is not a valid URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return fmt.Errorf("config validation: consent_api_url must use http or https scheme, got %q", parsedURL.Scheme)
	}

	if c.ConsentAPITimeout < MinConsentAPITimeout || c.ConsentAPITimeout > MaxConsentAPITimeout {
		return fmt.Errorf("config validation: consent_api_timeout must be between %d and %d, got %d",
			MinConsentAPITimeout, MaxConsentAPITimeout, c.ConsentAPITimeout)
	}

	if c.DenyStatusCode < MinHTTPStatusCode || c.DenyStatusCode > MaxHTTPStatusCode {
		return fmt.Errorf("config validation: deny_status_code must be between %d and %d, got %d",
			MinHTTPStatusCode, MaxHTTPStatusCode, c.DenyStatusCode)
	}

	if c.AuditEnabled && c.AuditOTLPEndpoint == "" {
		return errors.New("config validation: audit_otlp_endpoint is required when audit_enabled is true")
	}

	if c.OwnerResolverURL != "" {
		resolverURL, err := url.ParseRequestURI(c.OwnerResolverURL)
		if err != nil {
			return fmt.Errorf("config validation: owner_resolver_url is not a valid URL: %w", err)
		}
		if resolverURL.Scheme != "http" && resolverURL.Scheme != "https" {
			return fmt.Errorf("config validation: owner_resolver_url must use http or https scheme, got %q", resolverURL.Scheme)
		}
	}

	if c.TokenServiceURL != "" {
		tokenServiceURL, err := url.ParseRequestURI(c.TokenServiceURL)
		if err != nil {
			return fmt.Errorf("config validation: token_service_url is not a valid URL: %w", err)
		}
		if tokenServiceURL.Scheme != "http" && tokenServiceURL.Scheme != "https" {
			return fmt.Errorf("config validation: token_service_url must use http or https scheme, got %q", tokenServiceURL.Scheme)
		}
	}

	return nil
}

// ParseConfig deserializes JSON bytes into a Config struct, applies default
// values for omitted optional fields, and validates the result.
func ParseConfig(in []byte) (*Config, error) {
	if len(in) == 0 {
		return nil, errors.New("config parsing: input is empty")
	}

	var conf Config
	if err := json.Unmarshal(in, &conf); err != nil {
		return nil, fmt.Errorf("config parsing: failed to unmarshal JSON: %w", err)
	}

	conf.applyDefaults()
	conf.applyEnv()

	if err := conf.Validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}
