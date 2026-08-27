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

// Package consent provides an HTTP client for the external consent-manager,
// which decides whether a data owner has granted the consuming participant
// consent to access their personal data. The verdict is coarse — allow or deny
// for the whole response — and is enforced by the plugin's response phase.
package consent

// Decision represents the consent-manager's verdict on one data owner.
// It determines how the plugin handles the upstream response.
type Decision string

// Decision constants define the possible consent verdicts.
const (
	// DecisionAllow indicates the response should pass through unmodified.
	DecisionAllow Decision = "allow"

	// DecisionDeny indicates the response should be blocked entirely,
	// returning a configured error status and body to the client.
	DecisionDeny Decision = "deny"
)

// ConsentRequest is one consent question: may this consumer be given this data
// owner's data, for this purpose and resource?
type ConsentRequest struct {
	// Subject is the DATA OWNER whose consent decides the access — resolved from
	// the response payload by the OwnerResolver. It is never the requestor.
	Subject string `json:"subject"`

	// Resource is the request path being accessed (e.g., "/api/v1/users/123").
	Resource string `json:"resource"`

	// Method is the HTTP method of the original request (e.g., "GET", "POST").
	Method string `json:"method"`

	// DataResource, when set, scopes the check: a granted consent counts only if
	// it covers this resource (matched against the consent's data[].resource).
	// Empty means owner-level (any granted consent counts).
	DataResource string `json:"data_resource,omitempty"`

	// Consumer identifies the participant the data is being released TO, as its
	// self-description URL. It is REQUIRED: a consent is an agreement between a
	// data subject and one named consumer for one named purpose, so a check that
	// ignores it would let participant Y ride on a consent the subject granted to
	// participant X. A check without a consumer is denied.
	Consumer string `json:"consumer,omitempty"`

	// Purpose, when set, further scopes the check to the processing purpose (or
	// contract) the exchange is governed by: a granted consent counts only if it
	// covers this purpose. Empty means the purpose is not known — the consumer
	// match still applies.
	Purpose string `json:"purpose,omitempty"`
}

// ConsentResponse is the verdict for one ConsentRequest.
type ConsentResponse struct {
	// Decision is the consent verdict: "allow" or "deny".
	Decision Decision `json:"decision"`

	// Reason is a human-readable explanation for the consent decision,
	// recorded in the audit log and useful for debugging.
	Reason string `json:"reason,omitempty"`
}
