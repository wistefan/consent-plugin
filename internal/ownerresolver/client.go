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

// Package ownerresolver is a client for the external OwnerResolver service.
//
// The OwnerResolver answers, from the DATA alone (never the requestor), whether
// a payload needs a consent check and who its data owner(s) are. The plugin
// calls it in the response phase and then verifies consent per resolved owner.
package ownerresolver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Body encodings understood by the resolver.
const (
	encodingJSON = "json"
	encodingNone = "none"

	// DefaultTimeoutMs is the default per-call timeout for /resolve.
	DefaultTimeoutMs = 2000

	resolvePath     = "/resolve"
	contentTypeJSON = "application/json"
)

// Claim is one (owner [× dataResource]) requirement found in the data.
//
// The resolver's reply carries more than this (a selector locating the claim in
// the payload, the participant, the scheme). Only the fields the plugin acts on
// are decoded; the rest is ignored, so an unread field cannot suggest the plugin
// considers something it does not.
type Claim struct {
	// OwnerID is the data owner whose consent decides this claim.
	OwnerID string `json:"ownerId"`

	// DataResource, when set, scopes the consent match to one resource.
	DataResource string `json:"dataResource,omitempty"`

	// Purpose names the processing purpose (or contract) governing this claim,
	// when the resolver could identify the contract from the parties. It scopes
	// the consent match: a granted consent counts only if it covers this purpose.
	// Empty means the purpose is unknown and only the consumer match applies.
	Purpose string `json:"purpose,omitempty"`
}

// Result is the OwnerResolver response.
type Result struct {
	// ConsentRequired reports whether the payload needs a consent check at all.
	ConsentRequired bool `json:"consentRequired"`

	// Claims are the ownership requirements found in the data. Every one must be
	// satisfied for the response to be released.
	Claims []Claim `json:"claims"`
}

type resourceDescriptor struct {
	Service     string `json:"service,omitempty"`
	Method      string `json:"method,omitempty"`
	Path        string `json:"path,omitempty"`
	ContentType string `json:"contentType,omitempty"`
}

type bodyDescriptor struct {
	Encoding string          `json:"encoding"`
	Content  json.RawMessage `json:"content,omitempty"`
}

// Parties names the exchange participants. It exists ONLY so the resolver can
// identify the governing contract; it must never be used to determine the data
// owner (that comes from the data itself).
type Parties struct {
	// Consumer is the requesting participant (e.g. the credential issuer DID).
	Consumer string `json:"consumer,omitempty"`
	// Provider is this participant's self-description URL - one side of the
	// contract lookup.
	Provider string `json:"provider,omitempty"`
}

// IsZero reports whether no party is known, in which case the field is omitted.
func (p Parties) IsZero() bool { return p.Consumer == "" && p.Provider == "" }

type resolveRequest struct {
	Resource resourceDescriptor `json:"resource"`
	Parties  *Parties           `json:"parties,omitempty"`
	Body     *bodyDescriptor    `json:"body,omitempty"`
}

// Client calls the OwnerResolver /resolve endpoint.
type Client struct {
	url        string
	httpClient *http.Client
}

// NewClient builds a resolver client for the given /resolve URL.
func NewClient(url string, timeoutMs int) *Client {
	if timeoutMs <= 0 {
		timeoutMs = DefaultTimeoutMs
	}
	return &Client{
		url:        url,
		httpClient: &http.Client{Timeout: time.Duration(timeoutMs) * time.Millisecond},
	}
}

// Resource identifies the data being resolved (never the requestor).
type Resource struct {
	Service     string
	Method      string
	Path        string
	ContentType string
}

// Resolve asks the OwnerResolver about a payload. payload may be nil, in which
// case the body is sent with encoding "none" (the resolver decides from the
// resource descriptor alone). consumer, when non-empty, is forwarded so the
// resolver can find the governing contract - they are never used for ownership.
// A non-2xx response is returned as an error so the caller can apply its fail
// policy — it never means "no consent needed".
func (c *Client) Resolve(ctx context.Context, res Resource, p Parties, payload []byte) (Result, error) {
	reqBody := &bodyDescriptor{Encoding: encodingNone}
	if len(payload) > 0 && json.Valid(payload) {
		reqBody = &bodyDescriptor{Encoding: encodingJSON, Content: json.RawMessage(payload)}
	}
	req := resolveRequest{
		Resource: resourceDescriptor(res),
		Body:     reqBody,
	}
	if !p.IsZero() {
		req.Parties = &p
	}
	raw, err := json.Marshal(req)
	if err != nil {
		return Result{}, fmt.Errorf("owner-resolver: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(raw))
	if err != nil {
		return Result{}, fmt.Errorf("owner-resolver: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", contentTypeJSON)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return Result{}, fmt.Errorf("owner-resolver: request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Result{}, fmt.Errorf("owner-resolver: read response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("owner-resolver: status %d: %s", resp.StatusCode, truncate(body))
	}

	var out Result
	if err := json.Unmarshal(body, &out); err != nil {
		return Result{}, fmt.Errorf("owner-resolver: decode response: %w", err)
	}
	return out, nil
}

func truncate(b []byte) string {
	const limit = 256
	if len(b) <= limit {
		return string(b)
	}
	return string(b[:limit]) + "...(truncated)"
}
