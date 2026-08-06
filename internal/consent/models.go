// Package consent provides an HTTP client for communicating with an external
// consent API that determines whether response data should be allowed, denied,
// or filtered based on consent policies for personal data.
package consent

import "fmt"

// Decision represents the consent API's verdict on a request.
// It determines how the plugin handles the upstream response.
type Decision string

// Decision constants define the possible consent verdicts.
const (
	// DecisionAllow indicates the response should pass through unmodified.
	DecisionAllow Decision = "allow"

	// DecisionDeny indicates the response should be blocked entirely,
	// returning a configured error status and body to the client.
	DecisionDeny Decision = "deny"

	// DecisionFilter indicates the response should be modified by removing
	// specific fields identified in the DeniedFields list.
	DecisionFilter Decision = "filter"
)

// validDecisions is the set of recognized Decision values, used for validation.
var validDecisions = map[Decision]bool{
	DecisionAllow:  true,
	DecisionDeny:   true,
	DecisionFilter: true,
}

// IsValid reports whether d is a recognized Decision value.
func (d Decision) IsValid() bool {
	return validDecisions[d]
}

// ConsentRequest represents the payload sent to the consent API's /check endpoint.
// It contains information about the original request and the response fields
// so the consent API can make an informed allow/deny/filter decision.
type ConsentRequest struct {
	// Subject is the identity of the requester, typically from the JWT "sub" claim.
	Subject string `json:"subject"`

	// Resource is the request path being accessed (e.g., "/api/v1/users/123").
	Resource string `json:"resource"`

	// Method is the HTTP method of the original request (e.g., "GET", "POST").
	Method string `json:"method"`

	// Claims contains the forwarded JWT claims as key-value pairs.
	Claims map[string]interface{} `json:"claims,omitempty"`

	// ResponseFields lists the top-level field names found in the upstream
	// response body, enabling field-level consent decisions.
	ResponseFields []string `json:"response_fields,omitempty"`
}

// ConsentResponse represents the payload returned by the consent API's /check endpoint.
// It contains the consent decision and any additional information about which
// fields to remove or the reason for the decision.
type ConsentResponse struct {
	// Decision is the consent verdict: "allow", "deny", or "filter".
	Decision Decision `json:"decision"`

	// DeniedFields lists the field names or dot-notation paths (e.g., "user.email")
	// that should be removed from the response body when Decision is "filter".
	DeniedFields []string `json:"denied_fields,omitempty"`

	// Reason is a human-readable explanation for the consent decision,
	// useful for logging and debugging.
	Reason string `json:"reason,omitempty"`
}

// Validate checks that the ConsentResponse contains a valid decision.
// Returns an error if the decision field is empty or unrecognized.
func (r *ConsentResponse) Validate() error {
	if r.Decision == "" {
		return fmt.Errorf("consent response validation: decision field is empty")
	}
	if !r.Decision.IsValid() {
		return fmt.Errorf("consent response validation: unrecognized decision %q", r.Decision)
	}
	return nil
}
