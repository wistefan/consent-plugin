// Package integration provides end-to-end integration tests for the
// consent-filter plugin. Each test starts a mock consent API server,
// creates a real plugin instance with configuration pointing to it,
// and simulates the full RequestFilter → ResponseFilter lifecycle.
package integration

import (
	"consent-plugin/internal/consent"
	"consent-plugin/internal/plugin"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mock types for APISIX request/response interfaces ---

// mockRequestHeader implements pkgHTTP.Header for request mocking.
type mockRequestHeader struct {
	headers http.Header
}

func newMockRequestHeader() *mockRequestHeader {
	return &mockRequestHeader{headers: make(http.Header)}
}

// Set sets a header value.
func (h *mockRequestHeader) Set(key, value string) {
	h.headers.Set(key, value)
}

// Del deletes a header.
func (h *mockRequestHeader) Del(key string) {
	h.headers.Del(key)
}

// Get returns the first value for the given header key.
func (h *mockRequestHeader) Get(key string) string {
	return h.headers.Get(key)
}

// View returns headers as http.Header.
func (h *mockRequestHeader) View() http.Header {
	return h.headers
}

// mockRequest implements pkgHTTP.Request for integration testing.
type mockRequest struct {
	id     uint32
	method string
	path   []byte
	header *mockRequestHeader
}

func (r *mockRequest) ID() uint32                 { return r.id }
func (r *mockRequest) SrcIP() net.IP              { return net.ParseIP("127.0.0.1") }
func (r *mockRequest) Method() string             { return r.method }
func (r *mockRequest) Path() []byte               { return r.path }
func (r *mockRequest) SetPath([]byte)             {}
func (r *mockRequest) Header() pkgHTTP.Header     { return r.header }
func (r *mockRequest) Args() url.Values           { return nil }
func (r *mockRequest) Var(string) ([]byte, error) { return nil, nil }
func (r *mockRequest) Body() ([]byte, error)      { return nil, nil }
func (r *mockRequest) Context() context.Context   { return context.Background() }
func (r *mockRequest) RespHeader() http.Header    { return nil }

// mockResponseHeader implements pkgHTTP.Header for response mocking.
type mockResponseHeader struct {
	headers http.Header
}

func newMockResponseHeader() *mockResponseHeader {
	return &mockResponseHeader{headers: make(http.Header)}
}

// Set sets a header value.
func (h *mockResponseHeader) Set(key, value string) {
	h.headers.Set(key, value)
}

// Del deletes a header.
func (h *mockResponseHeader) Del(key string) {
	h.headers.Del(key)
}

// Get returns the first value for the given header key.
func (h *mockResponseHeader) Get(key string) string {
	return h.headers.Get(key)
}

// View returns headers as http.Header.
func (h *mockResponseHeader) View() http.Header {
	return h.headers
}

// mockResponse implements pkgHTTP.Response for integration testing.
type mockResponse struct {
	id            uint32
	header        *mockResponseHeader
	body          []byte
	writtenBody   []byte
	writtenStatus int
}

func (r *mockResponse) ID() uint32                 { return r.id }
func (r *mockResponse) StatusCode() int            { return http.StatusOK }
func (r *mockResponse) Header() pkgHTTP.Header     { return r.header }
func (r *mockResponse) Var(string) ([]byte, error) { return nil, nil }
func (r *mockResponse) ReadBody() ([]byte, error)  { return r.body, nil }
func (r *mockResponse) WriteHeader(statusCode int) { r.writtenStatus = statusCode }
func (r *mockResponse) Write(b []byte) (int, error) {
	r.writtenBody = b
	return len(b), nil
}

// --- Test helpers ---

// buildMockJWT creates a minimal JWT (header.payload.signature) with the given claims.
// No signature verification is performed by the plugin; this is sufficient for testing.
func buildMockJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	return fmt.Sprintf("%s.%s.nosig", header, payloadB64)
}

// newConsentHandler returns an http.Handler that responds with the given consent decision.
func newConsentHandler(t *testing.T, decision consent.Decision, deniedFields []string, reason string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate the incoming consent request.
		var req consent.ConsentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode consent request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := consent.ConsentResponse{
			Decision:     decision,
			DeniedFields: deniedFields,
			Reason:       reason,
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode consent response: %v", err)
		}
	})
}

// verifyingConsentHandler returns an http.Handler that validates the consent request
// fields match expectations, then responds with the given decision.
func verifyingConsentHandler(
	t *testing.T,
	wantSubject, wantResource, wantMethod string,
	decision consent.Decision,
	deniedFields []string,
) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req consent.ConsentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("failed to decode consent request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		assert.Equal(t, wantSubject, req.Subject, "consent request subject mismatch")
		assert.Equal(t, wantResource, req.Resource, "consent request resource mismatch")
		assert.Equal(t, wantMethod, req.Method, "consent request method mismatch")

		resp := consent.ConsentResponse{
			Decision:     decision,
			DeniedFields: deniedFields,
			Reason:       "integration test decision",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode consent response: %v", err)
		}
	})
}

// runPluginCycle simulates the full APISIX plugin lifecycle: ParseConf, RequestFilter,
// then ResponseFilter. Returns the mock response for assertion.
func runPluginCycle(
	t *testing.T,
	configJSON []byte,
	req *mockRequest,
	responseBody []byte,
	responseContentType string,
) *mockResponse {
	t.Helper()

	p := &plugin.ConsentFilter{}

	// ParseConf
	conf, err := p.ParseConf(configJSON)
	require.NoError(t, err, "ParseConf should succeed")

	// RequestFilter — uses a no-op http.ResponseWriter since we don't
	// expect the plugin to write during the request phase.
	recorder := httptest.NewRecorder()
	p.RequestFilter(conf, recorder, req)

	// Build the mock response with the same request ID.
	respHeader := newMockResponseHeader()
	if responseContentType != "" {
		respHeader.Set("Content-Type", responseContentType)
	}
	resp := &mockResponse{
		id:     req.id,
		header: respHeader,
		body:   responseBody,
	}

	// ResponseFilter
	p.ResponseFilter(conf, resp)

	return resp
}

// --- Integration test cases ---

// TestIntegration_AllowDecision verifies that when the consent API returns "allow",
// the upstream response passes through unchanged.
func TestIntegration_AllowDecision(t *testing.T) {
	server := httptest.NewServer(newConsentHandler(t, consent.DecisionAllow, nil, "full access"))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q}`, server.URL))

	jwtToken := buildMockJWT(map[string]interface{}{
		"sub":   "user-100",
		"scope": "read",
	})

	reqHeader := newMockRequestHeader()
	reqHeader.Set("Authorization", "Bearer "+jwtToken)

	req := &mockRequest{
		id:     1,
		method: "GET",
		path:   []byte("/api/v1/users/42"),
		header: reqHeader,
	}

	responseBody := []byte(`{"id":42,"name":"Alice","email":"alice@example.com"}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	assert.Nil(t, resp.writtenBody, "allow decision should not modify the response body")
	assert.Equal(t, 0, resp.writtenStatus, "allow decision should not change the status code")
}

// TestIntegration_DenyDecision verifies that when the consent API returns "deny",
// the plugin replaces the response with the configured denial body and status code.
func TestIntegration_DenyDecision(t *testing.T) {
	server := httptest.NewServer(newConsentHandler(t, consent.DecisionDeny, nil, "no consent"))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{
		"consent_api_url": %q,
		"deny_status_code": 451,
		"deny_response_body": "{\"error\":\"legally restricted\"}",
		"deny_response_content_type": "application/json"
	}`, server.URL))

	jwtToken := buildMockJWT(map[string]interface{}{"sub": "user-200"})

	reqHeader := newMockRequestHeader()
	reqHeader.Set("Authorization", "Bearer "+jwtToken)

	req := &mockRequest{
		id:     2,
		method: "GET",
		path:   []byte("/api/v1/protected"),
		header: reqHeader,
	}

	responseBody := []byte(`{"secret":"classified-data","owner":"user-200"}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	assert.Equal(t, 451, resp.writtenStatus, "deny decision should use configured status code")
	assert.Equal(t, `{"error":"legally restricted"}`, string(resp.writtenBody),
		"deny decision should use configured body")
	assert.Equal(t, "application/json", resp.header.Get("Content-Type"),
		"deny decision should set configured Content-Type")
}

// TestIntegration_FilterDecision verifies that when the consent API returns "filter",
// the plugin removes the specified fields from the response body.
func TestIntegration_FilterDecision(t *testing.T) {
	server := httptest.NewServer(newConsentHandler(t, consent.DecisionFilter,
		[]string{"email", "phone", "address.street"}, "PII filtered"))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q}`, server.URL))

	jwtToken := buildMockJWT(map[string]interface{}{
		"sub":   "user-300",
		"scope": "limited",
	})

	reqHeader := newMockRequestHeader()
	reqHeader.Set("Authorization", "Bearer "+jwtToken)

	req := &mockRequest{
		id:     3,
		method: "GET",
		path:   []byte("/api/v1/users/99"),
		header: reqHeader,
	}

	responseBody := []byte(`{
		"id": 99,
		"name": "Bob",
		"email": "bob@example.com",
		"phone": "+1-555-0199",
		"age": 35,
		"address": {"street": "123 Main St", "city": "Springfield"}
	}`)

	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	require.NotNil(t, resp.writtenBody, "filter decision should write a modified body")

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.writtenBody, &result))

	// Allowed fields should remain.
	assert.Equal(t, float64(99), result["id"])
	assert.Equal(t, "Bob", result["name"])
	assert.Equal(t, float64(35), result["age"])

	// Denied top-level fields should be removed.
	assert.NotContains(t, result, "email", "email should be filtered out")
	assert.NotContains(t, result, "phone", "phone should be filtered out")

	// Nested denied field should be removed, but sibling preserved.
	address, ok := result["address"].(map[string]interface{})
	require.True(t, ok, "address should be a JSON object")
	assert.NotContains(t, address, "street", "address.street should be filtered out")
	assert.Equal(t, "Springfield", address["city"], "address.city should be preserved")
}

// TestIntegration_ConsentAPIError_FailOpen verifies that when the consent API
// returns an error and fail_open is true (default), the response passes through.
func TestIntegration_ConsentAPIError_FailOpen(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"internal server error"}`)
	}))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q, "fail_open": true}`, server.URL))

	reqHeader := newMockRequestHeader()
	req := &mockRequest{
		id:     4,
		method: "GET",
		path:   []byte("/api/v1/data"),
		header: reqHeader,
	}

	responseBody := []byte(`{"data":"should-pass-through"}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	assert.Nil(t, resp.writtenBody, "fail-open should pass response through on API error")
	assert.Equal(t, 0, resp.writtenStatus, "fail-open should not change status on API error")
}

// TestIntegration_ConsentAPIError_FailClosed verifies that when the consent API
// returns an error and fail_open is false, the response is denied.
func TestIntegration_ConsentAPIError_FailClosed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":"service unavailable"}`)
	}))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q, "fail_open": false}`, server.URL))

	reqHeader := newMockRequestHeader()
	req := &mockRequest{
		id:     5,
		method: "GET",
		path:   []byte("/api/v1/data"),
		header: reqHeader,
	}

	responseBody := []byte(`{"data":"should-be-denied"}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	assert.Equal(t, 403, resp.writtenStatus, "fail-closed should deny on API error")
	assert.Equal(t, `{"error":"access denied by consent policy"}`, string(resp.writtenBody))
}

// TestIntegration_NonJSONPassthrough verifies that non-JSON responses are passed
// through without consulting the consent API.
func TestIntegration_NonJSONPassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("consent API should not be called for non-JSON responses")
	}))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q}`, server.URL))

	reqHeader := newMockRequestHeader()
	req := &mockRequest{
		id:     6,
		method: "GET",
		path:   []byte("/page"),
		header: reqHeader,
	}

	htmlBody := []byte(`<html><body><h1>Hello World</h1></body></html>`)
	resp := runPluginCycle(t, configJSON, req, htmlBody, "text/html")

	assert.Nil(t, resp.writtenBody, "non-JSON response should pass through without modification")
	assert.Equal(t, 0, resp.writtenStatus, "non-JSON response should not change status")
}

// TestIntegration_VerifiesConsentRequestFields verifies that the consent request
// sent to the API contains the correct subject, resource, and method extracted
// from the JWT and original request.
func TestIntegration_VerifiesConsentRequestFields(t *testing.T) {
	handler := verifyingConsentHandler(t,
		"admin-user",       // expected subject
		"/api/v1/admin/42", // expected resource
		"DELETE",           // expected method
		consent.DecisionAllow,
		nil,
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{
		"consent_api_url": %q,
		"jwt_claims_to_forward": ["sub", "role"]
	}`, server.URL))

	jwtToken := buildMockJWT(map[string]interface{}{
		"sub":  "admin-user",
		"role": "admin",
	})

	reqHeader := newMockRequestHeader()
	reqHeader.Set("Authorization", "Bearer "+jwtToken)

	req := &mockRequest{
		id:     7,
		method: "DELETE",
		path:   []byte("/api/v1/admin/42"),
		header: reqHeader,
	}

	responseBody := []byte(`{"deleted": true}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	// The verifying handler checks the consent request fields via assertions.
	// An allow decision means the response passes through.
	assert.Nil(t, resp.writtenBody)
}

// TestIntegration_CustomJWTHeader verifies that the plugin reads the JWT from
// a custom header name when configured.
func TestIntegration_CustomJWTHeader(t *testing.T) {
	handler := verifyingConsentHandler(t,
		"custom-user",
		"/api/v1/items",
		"POST",
		consent.DecisionAllow,
		nil,
	)
	server := httptest.NewServer(handler)
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{
		"consent_api_url": %q,
		"jwt_header_name": "X-Auth-Token",
		"jwt_claims_to_forward": ["sub"]
	}`, server.URL))

	jwtToken := buildMockJWT(map[string]interface{}{
		"sub": "custom-user",
	})

	reqHeader := newMockRequestHeader()
	reqHeader.Set("X-Auth-Token", "Bearer "+jwtToken)

	req := &mockRequest{
		id:     8,
		method: "POST",
		path:   []byte("/api/v1/items"),
		header: reqHeader,
	}

	responseBody := []byte(`{"created": true, "id": 55}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	assert.Nil(t, resp.writtenBody, "allow with custom JWT header should pass through")
}

// TestIntegration_DefaultDenyResponse verifies that the default deny status code
// and body are used when no custom values are configured.
func TestIntegration_DefaultDenyResponse(t *testing.T) {
	server := httptest.NewServer(newConsentHandler(t, consent.DecisionDeny, nil, "denied"))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q}`, server.URL))

	reqHeader := newMockRequestHeader()
	req := &mockRequest{
		id:     9,
		method: "GET",
		path:   []byte("/api/v1/denied"),
		header: reqHeader,
	}

	responseBody := []byte(`{"secret":"value"}`)
	resp := runPluginCycle(t, configJSON, req, responseBody, "application/json")

	assert.Equal(t, 403, resp.writtenStatus, "default deny status should be 403")
	assert.Equal(t, `{"error":"access denied by consent policy"}`, string(resp.writtenBody),
		"default deny body should match DefaultDenyResponseBody")
}

// TestIntegration_EmptyResponsePassthrough verifies that an empty response body
// passes through without consulting the consent API.
func TestIntegration_EmptyResponsePassthrough(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("consent API should not be called for empty response bodies")
	}))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q}`, server.URL))

	reqHeader := newMockRequestHeader()
	req := &mockRequest{
		id:     10,
		method: "DELETE",
		path:   []byte("/api/v1/items/1"),
		header: reqHeader,
	}

	resp := runPluginCycle(t, configJSON, req, []byte{}, "application/json")

	assert.Nil(t, resp.writtenBody, "empty body should pass through")
	assert.Equal(t, 0, resp.writtenStatus, "empty body should not change status")
}

// TestIntegration_ContextCleanupAfterCycle verifies that the request context
// is cleaned up after a full request-response cycle (no memory leak).
func TestIntegration_ContextCleanupAfterCycle(t *testing.T) {
	server := httptest.NewServer(newConsentHandler(t, consent.DecisionAllow, nil, "allowed"))
	defer server.Close()

	configJSON := []byte(fmt.Sprintf(`{"consent_api_url": %q}`, server.URL))

	const testRequestID = uint32(999)

	reqHeader := newMockRequestHeader()
	req := &mockRequest{
		id:     testRequestID,
		method: "GET",
		path:   []byte("/api/v1/test"),
		header: reqHeader,
	}

	responseBody := []byte(`{"data":"test"}`)
	_ = runPluginCycle(t, configJSON, req, responseBody, "application/json")

	// Verify context was cleaned up.
	_, found := plugin.LoadRequestContext(testRequestID)
	assert.False(t, found, "request context should be deleted after response cycle")
}
