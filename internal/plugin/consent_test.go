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

package plugin

import (
	"consent-plugin/internal/audit"
	"consent-plugin/internal/ownerresolver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsentFilter_Name(t *testing.T) {
	p := &ConsentFilter{}
	assert.Equal(t, "consent-filter", p.Name())
}

func TestConsentFilter_ParseConf(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid config returns parsed Config",
			input:   []byte(`{"consent_api_url": "https://consent.example.com", "owner_resolver_url": "https://resolver.example.com/resolve", "participant_token": "t"}`),
			wantErr: false,
		},
		{
			name:    "missing required field returns error",
			input:   []byte(`{}`),
			wantErr: true,
		},
		{
			name:    "missing owner_resolver_url returns error",
			input:   []byte(`{"consent_api_url": "https://consent.example.com"}`),
			wantErr: true,
		},
		{
			name:    "nil input returns error",
			input:   nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ConsentFilter{}
			conf, err := p.ParseConf(tt.input)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, conf)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, conf)
				_, ok := conf.(*Config)
				assert.True(t, ok, "ParseConf should return *Config type")
			}
		})
	}
}

func TestPluginName_Constant(t *testing.T) {
	assert.Equal(t, "consent-filter", pluginName)
}

// --- Mock implementations for testing ResponseFilter ---

// mockHeader implements pkgHTTP.Header for testing.
// mockHeader mirrors the runner's header implementation: View() returns the LIVE
// header map (not a copy), so a caller iterating it and deleting through Del
// behaves exactly as it does in production.
type mockHeader struct {
	headers http.Header
}

func newMockHeader() *mockHeader {
	return &mockHeader{headers: make(http.Header)}
}

func (h *mockHeader) Set(key, value string) { h.headers.Set(key, value) }
func (h *mockHeader) Del(key string)        { h.headers.Del(key) }
func (h *mockHeader) Get(key string) string { return h.headers.Get(key) }
func (h *mockHeader) View() http.Header     { return h.headers }

// mockResponse implements pkgHTTP.Response for testing.
type mockResponse struct {
	id            uint32
	statusCode    int
	header        *mockHeader
	body          []byte
	readErr       error
	writtenBody   []byte
	writtenStatus int
}

// newMockResponse builds a JSON upstream response carrying body.
func newMockResponse(id uint32, body []byte) *mockResponse {
	h := newMockHeader()
	h.Set("Content-Type", responseContentTypeJSON)
	return &mockResponse{id: id, header: h, body: body}
}

func (r *mockResponse) ID() uint32             { return r.id }
func (r *mockResponse) StatusCode() int        { return r.statusCode }
func (r *mockResponse) Header() pkgHTTP.Header { return r.header }

// Var returns the Nginx request id ($request_id) derived from the mock's id so
// correlationKey resolves to the same key the tests store under.
func (r *mockResponse) Var(name string) ([]byte, error) {
	if name == nginxRequestIDVar {
		return []byte(testReqKey(r.id)), nil
	}
	return nil, nil
}

func (r *mockResponse) ReadBody() ([]byte, error) { return r.body, r.readErr }

// Write appends, as the runner's Response.Write does (it writes into a buffer).
// A mock that replaced the body would hide a double-write regression.
func (r *mockResponse) Write(b []byte) (int, error) {
	r.writtenBody = append(r.writtenBody, b...)
	return len(b), nil
}
func (r *mockResponse) WriteHeader(statusCode int) { r.writtenStatus = statusCode }

// testReqKey maps a numeric mock id to the string request key used as the
// context-store key (mirrors the Nginx $request_id used in production).
func testReqKey(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}

// --- Consent-manager mock (the two endpoints the plugin calls) ---

// newConsentManager starts a mock consent-manager. identifier-search returns
// userID (or 404 when empty); participant-consents returns one consent per
// entry in statuses.
func newConsentManager(t *testing.T, userID string, statuses []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		if userID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": userID})
	})
	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consentsGrantedTo(testConsumerSD, statuses)})
	})
	// The participant registry, used to translate the consumer DID from the token
	// into the self-description URL a contract names its parties by.
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"selfDescriptionURL": "http://catalog/participants/provider",
		})
	})
	return httptest.NewServer(mux)
}

// newFailingConsentManager returns a consent-manager whose CONSENT CHECK calls
// answer with the given status code (used to exercise the fail policy). The
// participant registry still answers, so the failure under test is the check
// itself and not the preceding contract lookup.
func newFailingConsentManager(status int) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	return httptest.NewServer(mux)
}

// participantRegistryHandler serves the consent-manager's participant registry,
// which maps the consumer DID from the token to its self-description URL.
func participantRegistryHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode([]map[string]string{
		{"did": testConsumerDID, "selfDescriptionURL": testConsumerSD},
	})
}

// newUncalledConsentManager fails the test if a CONSENT CHECK reaches the
// consent-manager. The participant registry is still served: mapping the
// consumer DID to a self-description is part of the contract lookup that
// precedes the check, and happens even when no check is performed.
func newUncalledConsentManager(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("consent-manager must not be called for a consent check (path %s)", r.URL.Path)
	})
	return httptest.NewServer(mux)
}

// --- OwnerResolver mock (the source of data ownership) ---

// resolverClaim is one (owner [x dataResource]) requirement in a mock /resolve reply.
type resolverClaim struct {
	OwnerID      string `json:"ownerId"`
	DataResource string `json:"dataResource,omitempty"`
}

// resolverResponse is the mock OwnerResolver's /resolve reply.
type resolverResponse struct {
	ConsentRequired bool            `json:"consentRequired"`
	Claims          []resolverClaim `json:"claims"`
}

// ownedBy builds a resolve reply naming the given data owners (consent required).
func ownedBy(owners ...string) resolverResponse {
	claims := make([]resolverClaim, 0, len(owners))
	for _, o := range owners {
		claims = append(claims, resolverClaim{OwnerID: o})
	}
	return resolverResponse{ConsentRequired: true, Claims: claims}
}

// newOwnerResolver starts a mock OwnerResolver answering every /resolve with resp.
func newOwnerResolver(t *testing.T, resp resolverResponse) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode resolve response: %v", err)
		}
	}))
}

// newFailingOwnerResolver returns a resolver answering every call with status.
func newFailingOwnerResolver(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	}))
}

// newUncalledOwnerResolver fails the test if the resolver is contacted.
func newUncalledOwnerResolver(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("owner resolver must not be called (path %s)", r.URL.Path)
	}))
}

// --- Helpers ---

func boolPtr(b bool) *bool { return &b }

// newTestConfig creates a valid plugin Config pointing at the given
// consent-manager and OwnerResolver.
func newTestConfig(consentAPIURL, resolverURL string) *Config {
	return &Config{
		ConsentAPIURL:           consentAPIURL,
		ConsentAPIPrefix:        DefaultConsentAPIPrefix,
		ConsentAPITimeout:       DefaultConsentAPITimeout,
		OwnerResolverURL:        resolverURL,
		OwnerResolverTimeout:    DefaultOwnerResolverTimeout,
		ResponsePhaseTimeout:    DefaultResponsePhaseTimeout,
		MaxOwnersPerResponse:    DefaultMaxOwnersPerResponse,
		ConsumerClaim:           DefaultConsumerClaim,
		JWTHeaderName:           DefaultJWTHeaderName,
		ConsentKey:              "test-consent-key",
		ParticipantToken:        "test-participant-token",
		ProviderSD:              "http://consent-facade:8080/participants/org-1",
		DenyStatusCode:          DefaultDenyStatusCode,
		DenyResponseBody:        DefaultDenyResponseBody,
		DenyResponseContentType: DefaultDenyResponseContentType,
	}
}

// storeRequest stores a request context for the given mock id. The consuming
// participant is named in the claims; the data owner comes from the resolver.
func storeRequest(id uint32) {
	StoreRequestContext(testReqKey(id), &RequestContext{
		Method: "GET",
		Path:   "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice",
		JWTClaims: map[string]interface{}{
			"verifiableCredential": map[string]interface{}{"issuer": testConsumerDID},
		},
	})
}

// testOwnerDID is the data owner a mock resolver reports.
const testOwnerDID = "did:key:zOwner"

// testConsumerDID is the requesting participant named in the token claims.
const testConsumerDID = "did:key:zConsumer"

// testConsumerSD is the self-description URL the participant registry maps
// testConsumerDID to — the consumer every consent check is scoped to.
const testConsumerSD = "http://catalog/participants/consumer"

// consentsGrantedTo builds consent records with the given statuses, each granted
// to the named consuming participant.
func consentsGrantedTo(consumer string, statuses []string) []map[string]interface{} {
	consents := make([]map[string]interface{}, 0, len(statuses))
	for _, s := range statuses {
		consents = append(consents, map[string]interface{}{
			"status":   s,
			"consumer": map[string]string{"selfDescriptionURL": consumer},
		})
	}
	return consents
}

// --- ResponseFilter tests (coarse allow/deny gate) ---

func TestConsentFilter_ResponseFilter(t *testing.T) {
	tests := []struct {
		name              string
		setupContext      func(id uint32)
		consentServer     func(t *testing.T) *httptest.Server
		resolverServer    func(t *testing.T) *httptest.Server
		configFn          func(cfg *Config)
		invalidConfig     bool
		wantWrittenBody   string
		wantWrittenStatus int
		wantNoWrite       bool
	}{
		{
			name:           "granted consent for the resolved owner passes the response through",
			setupContext:   storeRequest,
			consentServer:  func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"granted"}) },
			resolverServer: func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantNoWrite:    true,
		},
		{
			name:              "no granted consent denies with the default response",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"revoked"}) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "unknown owner (404 on search) denies",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, "", nil) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "deny uses the custom status code and body",
			setupContext:   storeRequest,
			consentServer:  func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"revoked"}) },
			resolverServer: func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			configFn: func(cfg *Config) {
				cfg.DenyStatusCode = 451
				cfg.DenyResponseBody = `{"msg":"legally blocked"}`
			},
			wantWrittenBody:   `{"msg":"legally blocked"}`,
			wantWrittenStatus: 451,
		},
		{
			name:          "consent not required allows without contacting the consent-manager",
			setupContext:  storeRequest,
			consentServer: newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server {
				return newOwnerResolver(t, resolverResponse{ConsentRequired: false})
			},
			wantNoWrite: true,
		},
		{
			name:          "consent required but no owner resolved denies",
			setupContext:  storeRequest,
			consentServer: newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server {
				return newOwnerResolver(t, resolverResponse{ConsentRequired: true})
			},
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:          "resolved claim without an owner id denies",
			setupContext:  storeRequest,
			consentServer: newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server {
				return newOwnerResolver(t, resolverResponse{ConsentRequired: true, Claims: []resolverClaim{{OwnerID: ""}}})
			},
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "one denying owner denies the whole response (deny_all)",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"revoked"}) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy("did:key:zA", "did:key:zB")) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "resolver error denies by default (fail-closed)",
			setupContext:      storeRequest,
			consentServer:     newUncalledConsentManager,
			resolverServer:    func(t *testing.T) *httptest.Server { return newFailingOwnerResolver(http.StatusInternalServerError) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "resolver error with fail-open explicitly enabled passes through",
			setupContext:   storeRequest,
			consentServer:  newUncalledConsentManager,
			resolverServer: func(t *testing.T) *httptest.Server { return newFailingOwnerResolver(http.StatusInternalServerError) },
			configFn:       func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantNoWrite:    true,
		},
		{
			name:              "resolver error with fail-closed denies",
			setupContext:      storeRequest,
			consentServer:     newUncalledConsentManager,
			resolverServer:    func(t *testing.T) *httptest.Server { return newFailingOwnerResolver(http.StatusInternalServerError) },
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "consent-manager error denies by default (fail-closed)",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newFailingConsentManager(http.StatusInternalServerError) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "consent-manager error with fail-open explicitly enabled passes through",
			setupContext:   storeRequest,
			consentServer:  func(t *testing.T) *httptest.Server { return newFailingConsentManager(http.StatusInternalServerError) },
			resolverServer: func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			configFn:       func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantNoWrite:    true,
		},
		{
			name:              "consent-manager error with fail-closed denies",
			setupContext:      storeRequest,
			consentServer:     func(t *testing.T) *httptest.Server { return newFailingConsentManager(http.StatusInternalServerError) },
			resolverServer:    func(t *testing.T) *httptest.Server { return newOwnerResolver(t, ownedBy(testOwnerDID)) },
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			// Losing the request context is not an outage to ride out: the plugin
			// cannot gate at all, so fail_open must not turn it into a bypass.
			name:              "missing request context denies even with fail-open enabled",
			setupContext:      nil,
			consentServer:     newUncalledConsentManager,
			resolverServer:    newUncalledOwnerResolver,
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "missing request context with fail-closed denies",
			setupContext:      nil,
			consentServer:     newUncalledConsentManager,
			resolverServer:    newUncalledOwnerResolver,
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name: "unresolvable consumer denies without asking the resolver",
			setupContext: func(id uint32) {
				StoreRequestContext(testReqKey(id), &RequestContext{
					Method: "GET", Path: "/data",
					JWTClaims: map[string]interface{}{
						"verifiableCredential": map[string]interface{}{"issuer": "did:key:zNotRegistered"},
					},
				})
			},
			consentServer:  newUncalledConsentManager,
			resolverServer: newUncalledOwnerResolver,
			// A consumer that is not in the registry is a permanent condition, so
			// fail_open must not grant it standing access.
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(true) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name: "no consumer claim in the token denies without asking the resolver",
			setupContext: func(id uint32) {
				StoreRequestContext(testReqKey(id), &RequestContext{
					Method: "GET", Path: "/data",
					JWTClaims: map[string]interface{}{"sub": "did:key:zCaller"},
				})
			},
			consentServer:     newUncalledConsentManager,
			resolverServer:    newUncalledOwnerResolver,
			configFn:          func(cfg *Config) { cfg.FailOpen = boolPtr(false) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			// A route with no way to authenticate as the participant is a
			// misconfiguration; fail_open must not make it a silent full bypass.
			name:           "missing participant credentials deny even with fail-open enabled",
			setupContext:   storeRequest,
			consentServer:  newUncalledConsentManager,
			resolverServer: newUncalledOwnerResolver,
			configFn: func(cfg *Config) {
				cfg.FailOpen = boolPtr(true)
				cfg.ParticipantToken = ""
				cfg.TokenServiceURL = ""
			},
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:           "invalid config type passes through",
			setupContext:   storeRequest,
			consentServer:  newUncalledConsentManager,
			resolverServer: newUncalledOwnerResolver,
			invalidConfig:  true,
			wantNoWrite:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearContextStore()

			server := tt.consentServer(t)
			defer server.Close()
			resolver := tt.resolverServer(t)
			defer resolver.Close()

			var cfg interface{}
			if tt.invalidConfig {
				cfg = "not-a-config"
			} else {
				c := newTestConfig(server.URL, resolver.URL+"/resolve")
				if tt.configFn != nil {
					tt.configFn(c)
				}
				cfg = c
			}

			resp := newMockResponse(1, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice"}`))
			if tt.setupContext != nil {
				tt.setupContext(resp.id)
			}

			p := &ConsentFilter{}
			p.ResponseFilter(cfg, resp)

			if tt.wantNoWrite {
				assert.Nil(t, resp.writtenBody, "expected no body written (passthrough)")
				assert.Equal(t, 0, resp.writtenStatus, "expected no status written (passthrough)")
				return
			}
			if tt.wantWrittenStatus != 0 {
				assert.Equal(t, tt.wantWrittenStatus, resp.writtenStatus)
			}
			if tt.wantWrittenBody != "" {
				assert.Equal(t, tt.wantWrittenBody, string(resp.writtenBody))
			}
		})
	}
}

// responseContentTypeJSON is the Content-Type of the simulated upstream responses.
const responseContentTypeJSON = "application/json"

func TestConsentFilter_ResponseFilter_ContextCleanup(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, "uid-1", []string{"granted"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	const id = uint32(200)
	storeRequest(id)

	resp := newMockResponse(id, []byte(`{}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, 0, RequestContextStoreSize(), "request context should be deleted after ResponseFilter")
}

func TestConsentFilter_ResponseFilter_DenySetsContentType(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, "uid-1", []string{"revoked"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.DenyResponseContentType = "text/plain"
	const id = uint32(201)
	storeRequest(id)

	resp := newMockResponse(id, []byte(`{}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, "text/plain", resp.header.Get("Content-Type"))
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
}

// TestResponseFilter_ConsentScopedToConsumer is the regression test for the
// consumer scoping: the owner's consent was granted to a DIFFERENT participant,
// so it is no authority for this consumer to read the data.
func TestResponseFilter_ConsentScopedToConsumer(t *testing.T) {
	clearContextStore()

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": "uid-owner"})
	})
	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"consents": consentsGrantedTo("http://catalog/participants/someone-else", []string{"granted"}),
		})
	})
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	const id = uint32(203)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:alice"}`))
	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"a consent granted to another participant must not authorise this consumer")
	assert.Equal(t, DefaultDenyResponseBody, string(resp.writtenBody))
}

// TestResponseFilter_OwnerNotRequestor is the regression test for the removed
// legacy mode: the consent that decides access must be the RESOLVED OWNER's, not
// the caller's. The resolver names Bob as the owner while the token's "sub" is
// Alice; the identifier search must ask about Bob.
func TestResponseFilter_OwnerNotRequestor(t *testing.T) {
	clearContextStore()

	const owner = "did:key:zBob"
	var searchedSubjects []string

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		searchedSubjects = append(searchedSubjects, body["email"])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": "uid-bob"})
	})
	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consentsGrantedTo(testConsumerSD, []string{"revoked"})})
	})
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	server := httptest.NewServer(mux)
	defer server.Close()

	resolver := newOwnerResolver(t, ownedBy(owner))
	defer resolver.Close()

	const id = uint32(202)
	// The caller is Alice; the data belongs to Bob.
	StoreRequestContext(testReqKey(id), &RequestContext{
		Method: "GET",
		Path:   "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:bob",
		JWTClaims: map[string]interface{}{
			"sub":                  "did:key:zAlice",
			"verifiableCredential": map[string]interface{}{"issuer": testConsumerDID},
		},
	})

	resp := newMockResponse(id, []byte(`{"id":"urn:ngsi-ld:PersonalProfile:bob"}`))
	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	assert.Equal(t, []string{owner}, searchedSubjects,
		"consent must be checked for the resolved data owner, never for the token subject")
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"the owner has no granted consent, so the caller's own consent must not unlock the data")
}

// TestResponseFilter_OwnerCapDenies verifies a response resolving to more data
// owners than the cap is denied outright, rather than answered after an
// unbounded number of consent calls. A collection endpoint returning hundreds of
// entities is otherwise a latency and load amplifier any caller can trigger.
func TestResponseFilter_OwnerCapDenies(t *testing.T) {
	clearContextStore()

	owners := make([]string, 0, 5)
	for i := 0; i < 5; i++ {
		owners = append(owners, fmt.Sprintf("did:key:zOwner%d", i))
	}

	server := newUncalledConsentManager(t)
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(owners...))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.MaxOwnersPerResponse = 3
	// Even with fail_open the cap must deny: it is a deliberate limit, not an outage.
	cfg.FailOpen = boolPtr(true)

	const id = uint32(210)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{}`))
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus,
		"more owners than the cap must deny without running the checks")
}

// TestResponseFilter_ResponsePhaseDeadline verifies the whole response phase is
// bounded: a consent-manager that never answers must not let APISIX hold the
// buffered response for per-call-timeout x owner-count.
func TestResponseFilter_ResponsePhaseDeadline(t *testing.T) {
	clearContextStore()

	// The consent-manager never answers, so the phase budget is the only thing
	// that can end the wait.
	release := make(chan struct{})
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/participants", participantRegistryHandler)
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})
	server := httptest.NewServer(mux)
	// Releasing the handlers must happen BEFORE Close, which waits for them.
	defer server.Close()
	defer close(release)

	resolver := newOwnerResolver(t, ownedBy("did:key:zA", "did:key:zB", "did:key:zC"))
	defer resolver.Close()

	cfg := newTestConfig(server.URL, resolver.URL+"/resolve")
	cfg.ResponsePhaseTimeout = 150
	cfg.ConsentAPITimeout = 60000 // far beyond the phase budget, so the phase budget must win

	const id = uint32(211)
	storeRequest(id)
	resp := newMockResponse(id, []byte(`{}`))

	start := time.Now()
	(&ConsentFilter{}).ResponseFilter(cfg, resp)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 5*time.Second, "the response phase must be bounded by response_phase_timeout")
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus, "a timed-out phase must fail closed by default")
}

// TestDistinctClaims verifies the resolver's claims collapse to the distinct
// (owner, dataResource) pairs that actually need checking, in resolver order.
func TestDistinctClaims(t *testing.T) {
	tests := []struct {
		name    string
		claims  []ownerresolver.Claim
		want    []ownerClaim
		wantErr bool
	}{
		{
			name:   "duplicates collapse",
			claims: []ownerresolver.Claim{{OwnerID: "a"}, {OwnerID: "a"}, {OwnerID: "b"}},
			want:   []ownerClaim{{owner: "a"}, {owner: "b"}},
		},
		{
			name:   "same owner with different resources stays distinct",
			claims: []ownerresolver.Claim{{OwnerID: "a", DataResource: "r1"}, {OwnerID: "a", DataResource: "r2"}},
			want:   []ownerClaim{{owner: "a", dataResource: "r1"}, {owner: "a", dataResource: "r2"}},
		},
		{
			name:   "the purpose is carried through",
			claims: []ownerresolver.Claim{{OwnerID: "a", Purpose: "p1"}},
			want:   []ownerClaim{{owner: "a", purpose: "p1"}},
		},
		{
			name:    "a claim without an owner is an error",
			claims:  []ownerresolver.Claim{{OwnerID: "a"}, {OwnerID: ""}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := distinctClaims(tt.claims)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestDenyResponse_StripsUpstreamHeaders verifies the denial does not inherit the
// upstream's headers. A denied caller must not be told that the entity exists
// (ETag/Last-Modified), how many records matched (X-Total-Count), that more
// pages follow (Link), or be handed a session cookie — that is a side channel
// straight around the gate. Content-Length must also describe the deny body, not
// the upstream's.
func TestDenyResponse_StripsUpstreamHeaders(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, "uid-1", []string{"revoked"})
	defer server.Close()
	resolver := newOwnerResolver(t, ownedBy(testOwnerDID))
	defer resolver.Close()

	const id = uint32(220)
	storeRequest(id)

	resp := newMockResponse(id, []byte(`{"records":[1,2,3]}`))
	resp.header.Set("ETag", `"v7"`)
	resp.header.Set("Last-Modified", "Wed, 27 Aug 2026 10:00:00 GMT")
	resp.header.Set("Set-Cookie", "session=abc123")
	resp.header.Set("Link", `</items?page=2>; rel="next"`)
	resp.header.Set("X-Total-Count", "4210")
	resp.header.Set("NGSILD-Results-Count", "4210")
	resp.header.Set("Content-Encoding", "gzip")
	resp.header.Set("Content-Length", "19")
	resp.header.Set("Access-Control-Allow-Origin", "https://app.example.org")

	(&ConsentFilter{}).ResponseFilter(newTestConfig(server.URL, resolver.URL+"/resolve"), resp)

	require.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
	for _, leaked := range []string{"ETag", "Last-Modified", "Set-Cookie", "Link", "X-Total-Count", "NGSILD-Results-Count", "Content-Encoding"} {
		assert.Empty(t, resp.header.Get(leaked), "%s must not survive a denial", leaked)
	}
	assert.Equal(t, "https://app.example.org", resp.header.Get("Access-Control-Allow-Origin"),
		"CORS headers describe the exchange, not the data, and must survive so the client sees the 403")
	assert.Equal(t, DefaultDenyResponseContentType, resp.header.Get("Content-Type"))
	assert.Equal(t, strconv.Itoa(len(DefaultDenyResponseBody)), resp.header.Get("Content-Length"),
		"Content-Length must describe the deny body, not the upstream's")
	assert.Equal(t, DefaultDenyResponseBody, string(resp.writtenBody))
}

// TestRecordAudit_RecordsEveryCheckedOwner verifies the audit log answers whose
// consent was checked and what each said. Recording only the response outcome
// named no owner at all on an allow, and only the first refusal on a deny —
// which is not what an access-decision log is for.
func TestRecordAudit_RecordsEveryCheckedOwner(t *testing.T) {
	type record struct {
		subject, decision string
	}
	var mu sync.Mutex
	var got []record

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []struct {
						Attributes []struct {
							Key   string `json:"key"`
							Value struct {
								StringValue string `json:"stringValue"`
							} `json:"value"`
						} `json:"attributes"`
					} `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode OTLP payload: %v", err)
		}
		mu.Lock()
		for _, rl := range payload.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				for _, lr := range sl.LogRecords {
					var rec record
					for _, attr := range lr.Attributes {
						switch attr.Key {
						case "enduser.id":
							rec.subject = attr.Value.StringValue
						case "consent.decision":
							rec.decision = attr.Value.StringValue
						}
					}
					got = append(got, rec)
				}
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	cfg := &Config{
		AuditEnabled:      true,
		AuditOTLPEndpoint: collector.URL,
		AuditServiceName:  "consent-access-audit-test",
		ConsentAPITimeout: DefaultConsentAPITimeout,
	}
	recordAudit(cfg, responseOutcome{
		decision:  decisionDeny,
		requestID: "req-1",
		method:    "GET",
		checked: []checkedOwner{
			{subject: "did:key:zA", resource: "/r", decision: decisionAllow},
			{subject: "did:key:zB", resource: "/r", decision: decisionDeny, reason: "no granted consent"},
		},
	})
	audit.ShutdownAll()

	mu.Lock()
	defer mu.Unlock()
	assert.ElementsMatch(t, []record{
		{subject: "did:key:zA", decision: decisionAllow},
		{subject: "did:key:zB", decision: decisionDeny},
	}, got, "every consulted owner must appear in the audit log, not only the one that denied")
}

// TestRecordAudit_RecordsOutcomeWhenNoOwnerReached verifies a request that
// failed before any owner was consulted still appears in the record.
func TestRecordAudit_RecordsOutcomeWhenNoOwnerReached(t *testing.T) {
	var mu sync.Mutex
	records := 0
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			ResourceLogs []struct {
				ScopeLogs []struct {
					LogRecords []json.RawMessage `json:"logRecords"`
				} `json:"scopeLogs"`
			} `json:"resourceLogs"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		mu.Lock()
		for _, rl := range payload.ResourceLogs {
			for _, sl := range rl.ScopeLogs {
				records += len(sl.LogRecords)
			}
		}
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	cfg := &Config{
		AuditEnabled:      true,
		AuditOTLPEndpoint: collector.URL,
		AuditServiceName:  "consent-access-audit-no-owner",
		ConsentAPITimeout: DefaultConsentAPITimeout,
	}
	recordAudit(cfg, responseOutcome{decision: decisionDeny, requestID: "req-2", reason: "owner resolver error"})
	audit.ShutdownAll()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, records, "a failure before any owner was reached must still be recorded")
}
