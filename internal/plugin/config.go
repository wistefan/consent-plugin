// Package plugin implements the APISIX consent-filter plugin that intercepts
// HTTP responses and applies consent-based filtering for personal data.
package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// Default values for optional configuration fields.
const (
	// DefaultConsentAPITimeout is the default timeout in milliseconds for consent API calls.
	DefaultConsentAPITimeout = 5000

	// DefaultJWTHeaderName is the default HTTP header containing the JWT token.
	DefaultJWTHeaderName = "Authorization"

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
	// For example: ["sub", "scope"].
	JWTClaimsToForward []string `json:"jwt_claims_to_forward,omitempty"`

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

	if err := conf.Validate(); err != nil {
		return nil, err
	}

	return &conf, nil
}
