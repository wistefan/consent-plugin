package plugin

import (
	"consent-plugin/internal/consent"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

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
			input:   []byte(`{"consent_api_url": "https://consent.example.com"}`),
			wantErr: false,
		},
		{
			name:    "missing required field returns error",
			input:   []byte(`{}`),
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
	// Verify the plugin name constant matches the expected APISIX plugin name.
	assert.Equal(t, "consent-filter", pluginName)
}

// --- Mock implementations for testing ResponseFilter ---

// mockHeader implements pkgHTTP.Header for testing.
type mockHeader struct {
	headers map[string]string
}

// newMockHeader creates a new mockHeader with an empty header map.
func newMockHeader() *mockHeader {
	return &mockHeader{headers: make(map[string]string)}
}

// Set sets a header value.
func (h *mockHeader) Set(key, value string) {
	h.headers[http.CanonicalHeaderKey(key)] = value
}

// Del deletes a header.
func (h *mockHeader) Del(key string) {
	delete(h.headers, http.CanonicalHeaderKey(key))
}

// Get returns a header value.
func (h *mockHeader) Get(key string) string {
	return h.headers[http.CanonicalHeaderKey(key)]
}

// View returns headers as http.Header.
func (h *mockHeader) View() http.Header {
	result := make(http.Header)
	for k, v := range h.headers {
		result[k] = []string{v}
	}
	return result
}

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

// newMockResponse creates a mockResponse with the given ID, body, and content type.
func newMockResponse(id uint32, body []byte, contentType string) *mockResponse {
	h := newMockHeader()
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &mockResponse{
		id:     id,
		header: h,
		body:   body,
	}
}

// ID returns the request ID.
func (r *mockResponse) ID() uint32 { return r.id }

// StatusCode returns the HTTP status code.
func (r *mockResponse) StatusCode() int { return r.statusCode }

// Header returns the mock header.
func (r *mockResponse) Header() pkgHTTP.Header { return r.header }

// Var returns nil (unused in tests).
func (r *mockResponse) Var(_ string) ([]byte, error) { return nil, nil }

// ReadBody returns the mock body or error.
func (r *mockResponse) ReadBody() ([]byte, error) { return r.body, r.readErr }

// Write captures the written body.
func (r *mockResponse) Write(b []byte) (int, error) {
	r.writtenBody = b
	return len(b), nil
}

// WriteHeader captures the written status code.
func (r *mockResponse) WriteHeader(statusCode int) {
	r.writtenStatus = statusCode
}

// --- Helper functions for tests ---

// boolPtr returns a pointer to the given bool value.
func boolPtr(b bool) *bool {
	return &b
}

// newConsentServer creates a test HTTP server that returns the given consent response.
func newConsentServer(t *testing.T, decision consent.Decision, deniedFields []string, reason string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
}

// newErrorConsentServer creates a test HTTP server that always returns the given status code.
func newErrorConsentServer(statusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statusCode)
		fmt.Fprint(w, `{"error":"consent API unavailable"}`)
	}))
}

// newTestConfig creates a Config pointing to the given consent API URL.
func newTestConfig(consentAPIURL string) *Config {
	return &Config{
		ConsentAPIURL:           consentAPIURL,
		ConsentAPITimeout:       DefaultConsentAPITimeout,
		JWTHeaderName:           DefaultJWTHeaderName,
		DenyStatusCode:          DefaultDenyStatusCode,
		DenyResponseBody:        DefaultDenyResponseBody,
		DenyResponseContentType: DefaultDenyResponseContentType,
	}
}

// --- ResponseFilter tests ---

func TestConsentFilter_ResponseFilter(t *testing.T) {
	tests := []struct {
		name string
		// Setup
		setupContext  func(requestID uint32) // stores a RequestContext
		consentServer func(t *testing.T) *httptest.Server
		configFn      func(consentURL string) *Config
		response      func() *mockResponse
		// Expectations
		wantWrittenBody   string
		wantWrittenStatus int
		wantNoWrite       bool // true if we expect no Write call (passthrough)
	}{
		{
			name: "allow decision passes response through unchanged",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method:    "GET",
					Path:      "/api/users/1",
					JWTClaims: map[string]interface{}{"sub": "user-123"},
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newConsentServer(t, consent.DecisionAllow, nil, "all data allowed")
			},
			response: func() *mockResponse {
				return newMockResponse(1, []byte(`{"name":"Alice","email":"alice@example.com"}`), "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "deny decision returns configured error response",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method:    "GET",
					Path:      "/api/users/1",
					JWTClaims: map[string]interface{}{"sub": "user-123"},
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newConsentServer(t, consent.DecisionDeny, nil, "no consent")
			},
			response: func() *mockResponse {
				return newMockResponse(2, []byte(`{"name":"Alice","email":"alice@example.com"}`), "application/json")
			},
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name: "deny decision uses custom status code and body",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/data",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newConsentServer(t, consent.DecisionDeny, nil, "blocked")
			},
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.DenyStatusCode = 451
				cfg.DenyResponseBody = `{"msg":"legally blocked"}`
				cfg.DenyResponseContentType = "application/json"
				return cfg
			},
			response: func() *mockResponse {
				return newMockResponse(3, []byte(`{"data":"sensitive"}`), "application/json")
			},
			wantWrittenBody:   `{"msg":"legally blocked"}`,
			wantWrittenStatus: 451,
		},
		{
			name: "filter decision removes specified fields",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method:    "GET",
					Path:      "/api/users/1",
					JWTClaims: map[string]interface{}{"sub": "user-456"},
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newConsentServer(t, consent.DecisionFilter, []string{"email", "phone"}, "PII filtered")
			},
			response: func() *mockResponse {
				return newMockResponse(4, []byte(`{"name":"Alice","email":"alice@example.com","phone":"555-0100","age":30}`), "application/json")
			},
			wantWrittenBody: "", // Checked via JSON parse below
		},
		{
			name: "filter decision removes nested fields via dot-notation",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method:    "GET",
					Path:      "/api/users/1",
					JWTClaims: map[string]interface{}{"sub": "user-789"},
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newConsentServer(t, consent.DecisionFilter, []string{"user.email"}, "nested PII filtered")
			},
			response: func() *mockResponse {
				return newMockResponse(5, []byte(`{"user":{"name":"Alice","email":"a@b.com"},"status":"active"}`), "application/json")
			},
			wantWrittenBody: "", // Checked via JSON parse below
		},
		{
			name: "consent API error with fail-open passes through",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/data",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newErrorConsentServer(http.StatusInternalServerError)
			},
			response: func() *mockResponse {
				return newMockResponse(6, []byte(`{"data":"value"}`), "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "consent API error with fail-closed denies response",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/data",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newErrorConsentServer(http.StatusInternalServerError)
			},
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.FailOpen = boolPtr(false)
				return cfg
			},
			response: func() *mockResponse {
				return newMockResponse(7, []byte(`{"data":"sensitive"}`), "application/json")
			},
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name: "non-JSON response passes through unchanged",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/page",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				// Should never be called for non-JSON responses.
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("consent API should not be called for non-JSON responses")
				}))
			},
			response: func() *mockResponse {
				return newMockResponse(8, []byte(`<html><body>Hello</body></html>`), "text/html")
			},
			wantNoWrite: true,
		},
		{
			name:         "missing request context passes through",
			setupContext: nil, // No context stored.
			consentServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("consent API should not be called when context is missing")
				}))
			},
			response: func() *mockResponse {
				return newMockResponse(9, []byte(`{"data":"value"}`), "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "empty body passes through",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/empty",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("consent API should not be called for empty body")
				}))
			},
			response: func() *mockResponse {
				return newMockResponse(10, []byte{}, "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "read body error passes through",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/error",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("consent API should not be called on read body error")
				}))
			},
			response: func() *mockResponse {
				resp := newMockResponse(11, nil, "application/json")
				resp.readErr = fmt.Errorf("connection closed")
				return resp
			},
			wantNoWrite: true,
		},
		{
			name: "invalid config type passes through",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/test",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("consent API should not be called with invalid config")
				}))
			},
			response: func() *mockResponse {
				return newMockResponse(12, []byte(`{"data":"value"}`), "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "JSON content type with charset passes through to consent check",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method:    "GET",
					Path:      "/api/users/1",
					JWTClaims: map[string]interface{}{"sub": "user-100"},
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newConsentServer(t, consent.DecisionAllow, nil, "allowed")
			},
			response: func() *mockResponse {
				return newMockResponse(13, []byte(`{"name":"Alice"}`), "application/json; charset=utf-8")
			},
			wantNoWrite: true,
		},
		{
			name: "consent request includes subject from JWT sub claim",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method:    "POST",
					Path:      "/api/data",
					JWTClaims: map[string]interface{}{"sub": "user-subject-42", "scope": "read"},
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var req consent.ConsentRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Errorf("failed to decode consent request: %v", err)
					}
					assert.Equal(t, "user-subject-42", req.Subject)
					assert.Equal(t, "/api/data", req.Resource)
					assert.Equal(t, "POST", req.Method)
					assert.Contains(t, req.ResponseFields, "name")

					resp := consent.ConsentResponse{Decision: consent.DecisionAllow}
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(resp)
				}))
			},
			response: func() *mockResponse {
				return newMockResponse(14, []byte(`{"name":"Alice"}`), "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "fail-open is default when FailOpen is nil",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/data",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newErrorConsentServer(http.StatusServiceUnavailable)
			},
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.FailOpen = nil // explicitly nil
				return cfg
			},
			response: func() *mockResponse {
				return newMockResponse(15, []byte(`{"data":"value"}`), "application/json")
			},
			wantNoWrite: true,
		},
		{
			name: "fail-open explicitly true passes through on error",
			setupContext: func(id uint32) {
				StoreRequestContext(id, &RequestContext{
					Method: "GET",
					Path:   "/api/data",
				})
			},
			consentServer: func(t *testing.T) *httptest.Server {
				return newErrorConsentServer(http.StatusBadGateway)
			},
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.FailOpen = boolPtr(true)
				return cfg
			},
			response: func() *mockResponse {
				return newMockResponse(16, []byte(`{"data":"value"}`), "application/json")
			},
			wantNoWrite: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create consent API test server.
			server := tt.consentServer(t)
			defer server.Close()

			// Create config.
			var cfg interface{}
			switch {
			case tt.name == "invalid config type passes through":
				cfg = "not-a-config"
			case tt.configFn != nil:
				cfg = tt.configFn(server.URL)
			default:
				cfg = newTestConfig(server.URL)
			}

			// Create response mock.
			resp := tt.response()

			// Store request context if provided.
			if tt.setupContext != nil {
				tt.setupContext(resp.id)
			}

			// Execute ResponseFilter.
			p := &ConsentFilter{}
			p.ResponseFilter(cfg, resp)

			// Verify expectations.
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

func TestConsentFilter_ResponseFilter_FilterRemovesFields(t *testing.T) {
	// Detailed test for filter decision: verify the written body has fields removed.
	server := newConsentServer(t, consent.DecisionFilter, []string{"email", "phone"}, "PII filtered")
	defer server.Close()

	cfg := newTestConfig(server.URL)
	StoreRequestContext(100, &RequestContext{
		Method:    "GET",
		Path:      "/api/users/1",
		JWTClaims: map[string]interface{}{"sub": "user-1"},
	})

	resp := newMockResponse(100,
		[]byte(`{"name":"Alice","email":"alice@example.com","phone":"555-0100","age":30}`),
		"application/json",
	)

	p := &ConsentFilter{}
	p.ResponseFilter(cfg, resp)

	require.NotNil(t, resp.writtenBody, "expected filtered body to be written")

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.writtenBody, &result))

	assert.Equal(t, "Alice", result["name"])
	assert.Equal(t, float64(30), result["age"])
	assert.NotContains(t, result, "email", "email field should be removed")
	assert.NotContains(t, result, "phone", "phone field should be removed")
}

func TestConsentFilter_ResponseFilter_FilterNestedFields(t *testing.T) {
	// Test that dot-notation nested fields are correctly removed.
	server := newConsentServer(t, consent.DecisionFilter, []string{"user.email"}, "nested PII filtered")
	defer server.Close()

	cfg := newTestConfig(server.URL)
	StoreRequestContext(101, &RequestContext{
		Method:    "GET",
		Path:      "/api/users/1",
		JWTClaims: map[string]interface{}{"sub": "user-2"},
	})

	resp := newMockResponse(101,
		[]byte(`{"user":{"name":"Alice","email":"a@b.com"},"status":"active"}`),
		"application/json",
	)

	p := &ConsentFilter{}
	p.ResponseFilter(cfg, resp)

	require.NotNil(t, resp.writtenBody, "expected filtered body to be written")

	var result map[string]interface{}
	require.NoError(t, json.Unmarshal(resp.writtenBody, &result))

	assert.Equal(t, "active", result["status"])
	user, ok := result["user"].(map[string]interface{})
	require.True(t, ok, "user should be a JSON object")
	assert.Equal(t, "Alice", user["name"])
	assert.NotContains(t, user, "email", "user.email should be removed")
}

func TestConsentFilter_ResponseFilter_ContextCleanup(t *testing.T) {
	// Verify that request context is deleted after ResponseFilter runs.
	server := newConsentServer(t, consent.DecisionAllow, nil, "allowed")
	defer server.Close()

	cfg := newTestConfig(server.URL)

	requestID := uint32(200)
	StoreRequestContext(requestID, &RequestContext{
		Method: "GET",
		Path:   "/api/cleanup",
	})

	resp := newMockResponse(requestID, []byte(`{"data":"value"}`), "application/json")

	p := &ConsentFilter{}
	p.ResponseFilter(cfg, resp)

	// Context should have been cleaned up.
	_, found := LoadRequestContext(requestID)
	assert.False(t, found, "request context should be deleted after ResponseFilter")
}

func TestConsentFilter_ResponseFilter_DenySetsContentType(t *testing.T) {
	// Verify that deny response sets the Content-Type header.
	server := newConsentServer(t, consent.DecisionDeny, nil, "denied")
	defer server.Close()

	cfg := newTestConfig(server.URL)
	cfg.DenyResponseContentType = "text/plain"

	StoreRequestContext(201, &RequestContext{
		Method: "GET",
		Path:   "/api/denied",
	})

	resp := newMockResponse(201, []byte(`{"data":"secret"}`), "application/json")

	p := &ConsentFilter{}
	p.ResponseFilter(cfg, resp)

	assert.Equal(t, "text/plain", resp.header.Get("Content-Type"))
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
}

// --- Helper function tests ---

func TestIsJSONContentType(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "exact application/json",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json with charset",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "uppercase APPLICATION/JSON",
			contentType: "APPLICATION/JSON",
			want:        true,
		},
		{
			name:        "text/html is not JSON",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "text/plain is not JSON",
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "empty string is not JSON",
			contentType: "",
			want:        false,
		},
		{
			name:        "application/xml is not JSON",
			contentType: "application/xml",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isJSONContentType(tt.contentType))
		})
	}
}

func TestBuildConsentRequest(t *testing.T) {
	tests := []struct {
		name       string
		reqCtx     *RequestContext
		fieldNames []string
		wantReq    consent.ConsentRequest
	}{
		{
			name: "builds request with all fields",
			reqCtx: &RequestContext{
				Method:    "GET",
				Path:      "/api/users/1",
				JWTClaims: map[string]interface{}{"sub": "user-42", "scope": "read"},
			},
			fieldNames: []string{"name", "email"},
			wantReq: consent.ConsentRequest{
				Subject:        "user-42",
				Resource:       "/api/users/1",
				Method:         "GET",
				Claims:         map[string]interface{}{"sub": "user-42", "scope": "read"},
				ResponseFields: []string{"name", "email"},
			},
		},
		{
			name: "builds request without JWT claims",
			reqCtx: &RequestContext{
				Method: "POST",
				Path:   "/api/data",
			},
			fieldNames: []string{"id"},
			wantReq: consent.ConsentRequest{
				Resource:       "/api/data",
				Method:         "POST",
				ResponseFields: []string{"id"},
			},
		},
		{
			name: "builds request with nil field names",
			reqCtx: &RequestContext{
				Method:    "DELETE",
				Path:      "/api/items/5",
				JWTClaims: map[string]interface{}{"sub": "admin"},
			},
			fieldNames: nil,
			wantReq: consent.ConsentRequest{
				Subject:  "admin",
				Resource: "/api/items/5",
				Method:   "DELETE",
				Claims:   map[string]interface{}{"sub": "admin"},
			},
		},
		{
			name: "non-string sub claim is ignored",
			reqCtx: &RequestContext{
				Method:    "GET",
				Path:      "/api/test",
				JWTClaims: map[string]interface{}{"sub": float64(123)},
			},
			fieldNames: []string{"data"},
			wantReq: consent.ConsentRequest{
				Resource:       "/api/test",
				Method:         "GET",
				Claims:         map[string]interface{}{"sub": float64(123)},
				ResponseFields: []string{"data"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildConsentRequest(tt.reqCtx, tt.fieldNames)
			assert.Equal(t, tt.wantReq, result)
		})
	}
}

func TestConfig_IsFailOpen(t *testing.T) {
	tests := []struct {
		name     string
		failOpen *bool
		want     bool
	}{
		{
			name:     "nil defaults to true (fail-open)",
			failOpen: nil,
			want:     true,
		},
		{
			name:     "explicitly true is fail-open",
			failOpen: boolPtr(true),
			want:     true,
		},
		{
			name:     "explicitly false is fail-closed",
			failOpen: boolPtr(false),
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{FailOpen: tt.failOpen}
			assert.Equal(t, tt.want, cfg.IsFailOpen())
		})
	}
}
