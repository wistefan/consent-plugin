// Package integration provides end-to-end integration tests for the
// consent-filter plugin. Each test starts a mock consent API server,
// creates a real plugin instance with configuration pointing to it,
// and simulates the full RequestFilter → ResponseFilter lifecycle.
package integration

import (
	"consent-plugin/internal/plugin"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"

	pkgHTTP "github.com/apache/apisix-go-plugin-runner/pkg/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationReqKey maps a numeric mock id to the request key used as the
// context-store key. It mirrors the Nginx $request_id the plugin reads via
// Var("request_id") to correlate the request and response phases.
func integrationReqKey(id uint32) string {
	return strconv.FormatUint(uint64(id), 10)
}

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

func (r *mockRequest) ID() uint32             { return r.id }
func (r *mockRequest) SrcIP() net.IP          { return net.ParseIP("127.0.0.1") }
func (r *mockRequest) Method() string         { return r.method }
func (r *mockRequest) Path() []byte           { return r.path }
func (r *mockRequest) SetPath([]byte)         {}
func (r *mockRequest) Header() pkgHTTP.Header { return r.header }
func (r *mockRequest) Args() url.Values       { return nil }
func (r *mockRequest) Var(name string) ([]byte, error) {
	if name == "request_id" {
		return []byte(integrationReqKey(r.id)), nil
	}
	return nil, nil
}
func (r *mockRequest) Body() ([]byte, error)    { return nil, nil }
func (r *mockRequest) Context() context.Context { return context.Background() }
func (r *mockRequest) RespHeader() http.Header  { return nil }

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

func (r *mockResponse) ID() uint32             { return r.id }
func (r *mockResponse) StatusCode() int        { return http.StatusOK }
func (r *mockResponse) Header() pkgHTTP.Header { return r.header }
func (r *mockResponse) Var(name string) ([]byte, error) {
	if name == "request_id" {
		return []byte(integrationReqKey(r.id)), nil
	}
	return nil, nil
}
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

// newConsentManager starts a mock consent-manager exposing the two endpoints
// the plugin calls. identifier-search returns userID (or 404 when empty) and,
// when wantSubject is non-empty, asserts the forwarded subject ("email");
// participant-consents returns one consent per entry in statuses.
func newConsentManager(t *testing.T, wantSubject, userID string, statuses []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "itest-consent-key", r.Header.Get("x-visionstrust-consent-key"),
			"identifier search must carry the consent key")
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("failed to decode identifier search body: %v", err)
		}
		if wantSubject != "" {
			assert.Equal(t, wantSubject, body["email"], "subject must be forwarded as the user email")
		}
		if userID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": userID})
	})

	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer itest-participant-token", r.Header.Get("Authorization"),
			"consents lookup must carry the participant token")
		consents := make([]map[string]string, 0, len(statuses))
		for _, s := range statuses {
			consents = append(consents, map[string]string{"status": s})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consents})
	})

	return httptest.NewServer(mux)
}

// baseConfig returns the minimal valid plugin configuration for the two-call
// check, pointing at the given consent-manager URL.
func baseConfig(consentURL string) map[string]interface{} {
	return map[string]interface{}{
		"consent_api_url":       consentURL,
		"consent_key":           "itest-consent-key",
		"participant_token":     "itest-participant-token",
		"provider_sd":           "http://consent-facade:8080/participants/org-itest",
		"jwt_claims_to_forward": []string{"sub"},
	}
}

// marshalConfig serializes a config map to the JSON bytes APISIX would pass.
func marshalConfig(t *testing.T, cfg map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(cfg)
	require.NoError(t, err)
	return b
}

// responseContentTypeJSON is the Content-Type set on simulated upstream
// responses in the plugin lifecycle helper; personal-data responses are JSON.
const responseContentTypeJSON = "application/json"

// runPluginCycle simulates the full APISIX plugin lifecycle: ParseConf, RequestFilter,
// then ResponseFilter. Returns the mock response for assertion.
func runPluginCycle(
	t *testing.T,
	configJSON []byte,
	req *mockRequest,
	responseBody []byte,
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
	respHeader.Set("Content-Type", responseContentTypeJSON)
	resp := &mockResponse{
		id:     req.id,
		header: respHeader,
		body:   responseBody,
	}

	// ResponseFilter
	p.ResponseFilter(conf, resp)

	return resp
}

// consentRequest builds a GET request for a personal-data entity, carrying the
// given subject DID in the JWT "sub" claim (Authorization: Bearer ...).
func consentRequest(id uint32, subject string) *mockRequest {
	h := newMockRequestHeader()
	h.Set("Authorization", "Bearer "+buildMockJWT(map[string]interface{}{"sub": subject}))
	return &mockRequest{
		id:     id,
		method: "GET",
		path:   []byte("/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice"),
		header: h,
	}
}

const defaultDenyBody = `{"error":"access denied by consent policy"}`

// --- Integration test cases (two-call consent check) ---

// TestIntegration_GrantedConsentPassthrough verifies a granted consent lets the
// response through unchanged.
func TestIntegration_GrantedConsentPassthrough(t *testing.T) {
	srv := newConsentManager(t, "did:key:zAlice", "uid-1", []string{"granted"})
	defer srv.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL)),
		consentRequest(1, "did:key:zAlice"), []byte(`{"email":"alice@example.org"}`))

	assert.Nil(t, resp.writtenBody, "granted consent should not modify the response")
	assert.Equal(t, 0, resp.writtenStatus)
}

// TestIntegration_NoGrantedConsentDenied verifies a subject with only a revoked
// consent is denied.
func TestIntegration_NoGrantedConsentDenied(t *testing.T) {
	srv := newConsentManager(t, "", "uid-1", []string{"revoked"})
	defer srv.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL)),
		consentRequest(2, "did:key:zAlice"), []byte(`{"email":"alice@example.org"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// TestIntegration_UnknownSubjectDenied verifies a subject unknown to the
// consent-manager (404 on identifier search) is denied.
func TestIntegration_UnknownSubjectDenied(t *testing.T) {
	srv := newConsentManager(t, "", "", nil)
	defer srv.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL)),
		consentRequest(3, "did:key:zStranger"), []byte(`{"email":"x@example.org"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// TestIntegration_CustomDenyResponse verifies the configured deny status/body are used.
func TestIntegration_CustomDenyResponse(t *testing.T) {
	srv := newConsentManager(t, "", "uid-1", []string{"revoked"})
	defer srv.Close()

	cfg := baseConfig(srv.URL)
	cfg["deny_status_code"] = 451
	cfg["deny_response_body"] = `{"error":"legally restricted"}`
	cfg["deny_response_content_type"] = "application/json"

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequest(4, "did:key:zAlice"), []byte(`{"secret":"x"}`))

	assert.Equal(t, 451, resp.writtenStatus)
	assert.Equal(t, `{"error":"legally restricted"}`, string(resp.writtenBody))
	assert.Equal(t, "application/json", resp.header.Get("Content-Type"))
}

// TestIntegration_ConsentManagerError_FailOpen verifies a consent-manager error
// passes through when fail-open is set.
func TestIntegration_ConsentManagerError_FailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := baseConfig(srv.URL)
	cfg["fail_open"] = true

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequest(5, "did:key:zAlice"), []byte(`{"data":"passes"}`))

	assert.Nil(t, resp.writtenBody, "fail-open should pass through on consent-manager error")
	assert.Equal(t, 0, resp.writtenStatus)
}

// TestIntegration_ConsentManagerError_FailClosed verifies a consent-manager error
// is denied when fail-closed.
func TestIntegration_ConsentManagerError_FailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := baseConfig(srv.URL)
	cfg["fail_open"] = false

	resp := runPluginCycle(t, marshalConfig(t, cfg),
		consentRequest(6, "did:key:zAlice"), []byte(`{"data":"denied"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}

// TestIntegration_SubjectForwardedFromJWT verifies the subject from the JWT "sub"
// claim is forwarded to the consent-manager as the user email (asserted in the mock).
func TestIntegration_SubjectForwardedFromJWT(t *testing.T) {
	srv := newConsentManager(t, "did:key:zBob", "uid-bob", []string{"granted"})
	defer srv.Close()

	resp := runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL)),
		consentRequest(7, "did:key:zBob"), []byte(`{"ok":true}`))

	assert.Nil(t, resp.writtenBody)
}

// TestIntegration_CustomJWTHeader verifies the plugin reads the JWT from a custom
// header when configured (subject still resolves and consent is granted).
func TestIntegration_CustomJWTHeader(t *testing.T) {
	srv := newConsentManager(t, "custom-user", "uid-c", []string{"granted"})
	defer srv.Close()

	cfg := baseConfig(srv.URL)
	cfg["jwt_header_name"] = "X-Auth-Token"

	h := newMockRequestHeader()
	h.Set("X-Auth-Token", "Bearer "+buildMockJWT(map[string]interface{}{"sub": "custom-user"}))
	req := &mockRequest{id: 8, method: "POST", path: []byte("/api/v1/items"), header: h}

	resp := runPluginCycle(t, marshalConfig(t, cfg), req, []byte(`{"created":true}`))

	assert.Nil(t, resp.writtenBody, "granted consent via custom JWT header should pass through")
}

// TestIntegration_ContextCleanupAfterCycle verifies the request context is
// cleaned up after a full request-response cycle (no memory leak).
func TestIntegration_ContextCleanupAfterCycle(t *testing.T) {
	srv := newConsentManager(t, "", "uid-1", []string{"granted"})
	defer srv.Close()

	const id = uint32(999)
	_ = runPluginCycle(t, marshalConfig(t, baseConfig(srv.URL)),
		consentRequest(id, "did:key:zAlice"), []byte(`{"data":"test"}`))

	_, found := plugin.LoadRequestContext(integrationReqKey(id))
	assert.False(t, found, "request context should be deleted after the response cycle")
}

// newConsentManagerCC starts a mock consent-manager exposing all four endpoints
// used by the client-credentials flow (login, me, identifier search, consents).
func newConsentManagerCC(t *testing.T, wantSubject, userID, selfDescriptionURL string, statuses []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/v1/participants/login", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		assert.Equal(t, "consent-demo-provider", b["clientID"])
		assert.Equal(t, "demo", b["clientSecret"])
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "jwt": "itest-token"})
	})

	mux.HandleFunc("/v1/participants/me", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer itest-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"selfDescriptionURL": selfDescriptionURL})
	})

	mux.HandleFunc("/v1/users/identifier/search", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "itest-consent-key", r.Header.Get("x-visionstrust-consent-key"))
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if wantSubject != "" {
			assert.Equal(t, wantSubject, b["email"])
		}
		assert.Equal(t, selfDescriptionURL, b["selfDescription"], "derived SD is used in the search")
		if userID == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"userIdentifier": userID})
	})

	mux.HandleFunc("/v1/consents/participants/", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer itest-token", r.Header.Get("Authorization"))
		consents := make([]map[string]string, 0, len(statuses))
		for _, s := range statuses {
			consents = append(consents, map[string]string{"status": s})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consents})
	})

	return httptest.NewServer(mux)
}

// ccConfig is a plugin config using participant client credentials (no static
// token, no explicit provider_sd — both are obtained from the consent-manager).
func ccConfig(consentURL string) map[string]interface{} {
	return map[string]interface{}{
		"consent_api_url":       consentURL,
		"consent_key":           "itest-consent-key",
		"client_id":             "consent-demo-provider",
		"client_secret":         "demo",
		"jwt_claims_to_forward": []string{"sub"},
	}
}

// TestIntegration_ClientCredentialsFlow drives the full client-credentials path:
// login for a token, derive the provider SD from /me, then the two-call check.
func TestIntegration_ClientCredentialsFlow(t *testing.T) {
	srv := newConsentManagerCC(t, "did:key:zAlice", "uid-1",
		"http://consent-facade:8080/participants/derived", []string{"granted"})
	defer srv.Close()

	resp := runPluginCycle(t, marshalConfig(t, ccConfig(srv.URL)),
		consentRequest(20, "did:key:zAlice"), []byte(`{"ok":true}`))

	assert.Nil(t, resp.writtenBody, "granted consent via client credentials should pass through")
}

// TestIntegration_ClientCredentialsDenied verifies a not-granted consent denies
// via the client-credentials path.
func TestIntegration_ClientCredentialsDenied(t *testing.T) {
	srv := newConsentManagerCC(t, "", "uid-1",
		"http://consent-facade:8080/participants/derived", []string{"revoked"})
	defer srv.Close()

	resp := runPluginCycle(t, marshalConfig(t, ccConfig(srv.URL)),
		consentRequest(21, "did:key:zAlice"), []byte(`{"secret":"x"}`))

	assert.Equal(t, 403, resp.writtenStatus)
	assert.Equal(t, defaultDenyBody, string(resp.writtenBody))
}
