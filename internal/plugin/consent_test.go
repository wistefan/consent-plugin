package plugin

import (
	"consent-plugin/internal/consent"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
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
	assert.Equal(t, "consent-filter", pluginName)
}

// --- Mock implementations for testing ResponseFilter ---

// mockHeader implements pkgHTTP.Header for testing.
type mockHeader struct {
	headers map[string]string
}

func newMockHeader() *mockHeader {
	return &mockHeader{headers: make(map[string]string)}
}

func (h *mockHeader) Set(key, value string) { h.headers[http.CanonicalHeaderKey(key)] = value }
func (h *mockHeader) Del(key string)        { delete(h.headers, http.CanonicalHeaderKey(key)) }
func (h *mockHeader) Get(key string) string { return h.headers[http.CanonicalHeaderKey(key)] }
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

func newMockResponse(id uint32, body []byte, contentType string) *mockResponse {
	h := newMockHeader()
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
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
func (r *mockResponse) Write(b []byte) (int, error) {
	r.writtenBody = b
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
		consents := make([]map[string]string, 0, len(statuses))
		for _, s := range statuses {
			consents = append(consents, map[string]string{"status": s})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"consents": consents})
	})
	return httptest.NewServer(mux)
}

// newFailingConsentManager returns a consent-manager that answers every call
// with the given status code (used to exercise the fail policy).
func newFailingConsentManager(status int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))
}

// newUncalledConsentManager fails the test if the consent-manager is contacted.
func newUncalledConsentManager(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("consent-manager must not be called (path %s)", r.URL.Path)
	}))
}

// --- Helpers ---

func boolPtr(b bool) *bool { return &b }

// newTestConfig creates a valid plugin Config pointing at the given consent-manager.
func newTestConfig(consentAPIURL string) *Config {
	return &Config{
		ConsentAPIURL:           consentAPIURL,
		ConsentAPIPrefix:        DefaultConsentAPIPrefix,
		ConsentAPITimeout:       DefaultConsentAPITimeout,
		JWTHeaderName:           DefaultJWTHeaderName,
		ConsentKey:              "test-consent-key",
		ParticipantToken:        "test-participant-token",
		ProviderSD:              "http://consent-facade:8080/participants/org-1",
		DenyStatusCode:          DefaultDenyStatusCode,
		DenyResponseBody:        DefaultDenyResponseBody,
		DenyResponseContentType: DefaultDenyResponseContentType,
	}
}

// storeSubject stores a request context carrying the given subject DID.
func storeSubject(id uint32, subject string) {
	StoreRequestContext(testReqKey(id), &RequestContext{
		Method:    "GET",
		Path:      "/ngsi-ld/v1/entities/urn:ngsi-ld:PersonalProfile:alice",
		JWTClaims: map[string]interface{}{"sub": subject},
	})
}

const testSubjectDID = "did:key:zSubject"

// --- ResponseFilter tests (coarse allow/deny gate) ---

func TestConsentFilter_ResponseFilter(t *testing.T) {
	tests := []struct {
		name              string
		setupContext      func(id uint32)
		consentServer     func(t *testing.T) *httptest.Server
		configFn          func(consentURL string) *Config
		invalidConfig     bool
		wantWrittenBody   string
		wantWrittenStatus int
		wantNoWrite       bool
	}{
		{
			name:          "granted consent passes the response through",
			setupContext:  func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer: func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"granted"}) },
			wantNoWrite:   true,
		},
		{
			name:              "no granted consent denies with the default response",
			setupContext:      func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"revoked"}) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:              "unknown subject (404 on search) denies",
			setupContext:      func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer:     func(t *testing.T) *httptest.Server { return newConsentManager(t, "", nil) },
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:          "deny uses the custom status code and body",
			setupContext:  func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer: func(t *testing.T) *httptest.Server { return newConsentManager(t, "uid-1", []string{"revoked"}) },
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.DenyStatusCode = 451
				cfg.DenyResponseBody = `{"msg":"legally blocked"}`
				return cfg
			},
			wantWrittenBody:   `{"msg":"legally blocked"}`,
			wantWrittenStatus: 451,
		},
		{
			name:          "empty sub claim denies without contacting the consent-manager",
			setupContext:  func(id uint32) { storeSubject(id, "") },
			consentServer: newUncalledConsentManager,
			// empty subject => CheckConsent returns deny before any HTTP call
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:          "consent-manager error with fail-open passes through",
			setupContext:  func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer: func(t *testing.T) *httptest.Server { return newFailingConsentManager(http.StatusInternalServerError) },
			wantNoWrite:   true,
		},
		{
			name:          "consent-manager error with fail-closed denies",
			setupContext:  func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer: func(t *testing.T) *httptest.Server { return newFailingConsentManager(http.StatusInternalServerError) },
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.FailOpen = boolPtr(false)
				return cfg
			},
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:          "missing request context with fail-open passes through",
			setupContext:  nil,
			consentServer: newUncalledConsentManager,
			wantNoWrite:   true,
		},
		{
			name:          "missing request context with fail-closed denies",
			setupContext:  nil,
			consentServer: newUncalledConsentManager,
			configFn: func(consentURL string) *Config {
				cfg := newTestConfig(consentURL)
				cfg.FailOpen = boolPtr(false)
				return cfg
			},
			wantWrittenBody:   DefaultDenyResponseBody,
			wantWrittenStatus: DefaultDenyStatusCode,
		},
		{
			name:          "invalid config type passes through",
			setupContext:  func(id uint32) { storeSubject(id, testSubjectDID) },
			consentServer: newUncalledConsentManager,
			invalidConfig: true,
			wantNoWrite:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clearContextStore()

			server := tt.consentServer(t)
			defer server.Close()

			var cfg interface{}
			switch {
			case tt.invalidConfig:
				cfg = "not-a-config"
			case tt.configFn != nil:
				cfg = tt.configFn(server.URL)
			default:
				cfg = newTestConfig(server.URL)
			}

			resp := newMockResponse(1, nil, "")
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

func TestConsentFilter_ResponseFilter_ContextCleanup(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, "uid-1", []string{"granted"})
	defer server.Close()

	cfg := newTestConfig(server.URL)
	const id = uint32(200)
	storeSubject(id, testSubjectDID)

	resp := newMockResponse(id, nil, "")
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	_, found := LoadRequestContext(testReqKey(id))
	assert.False(t, found, "request context should be deleted after ResponseFilter")
}

func TestConsentFilter_ResponseFilter_DenySetsContentType(t *testing.T) {
	clearContextStore()
	server := newConsentManager(t, "uid-1", []string{"revoked"})
	defer server.Close()

	cfg := newTestConfig(server.URL)
	cfg.DenyResponseContentType = "text/plain"
	const id = uint32(201)
	storeSubject(id, testSubjectDID)

	resp := newMockResponse(id, nil, "")
	(&ConsentFilter{}).ResponseFilter(cfg, resp)

	assert.Equal(t, "text/plain", resp.header.Get("Content-Type"))
	assert.Equal(t, DefaultDenyStatusCode, resp.writtenStatus)
}

func TestBuildConsentRequest(t *testing.T) {
	tests := []struct {
		name    string
		reqCtx  *RequestContext
		wantReq consent.ConsentRequest
	}{
		{
			name: "builds request with subject from sub claim",
			reqCtx: &RequestContext{
				Method:    "GET",
				Path:      "/api/users/1",
				JWTClaims: map[string]interface{}{"sub": "did:key:z42", "scope": "read"},
			},
			wantReq: consent.ConsentRequest{
				Subject:  "did:key:z42",
				Resource: "/api/users/1",
				Method:   "GET",
				Claims:   map[string]interface{}{"sub": "did:key:z42", "scope": "read"},
			},
		},
		{
			name:   "builds request without JWT claims",
			reqCtx: &RequestContext{Method: "POST", Path: "/api/data"},
			wantReq: consent.ConsentRequest{
				Resource: "/api/data",
				Method:   "POST",
			},
		},
		{
			name: "non-string sub claim is ignored",
			reqCtx: &RequestContext{
				Method:    "GET",
				Path:      "/api/test",
				JWTClaims: map[string]interface{}{"sub": float64(123)},
			},
			wantReq: consent.ConsentRequest{
				Resource: "/api/test",
				Method:   "GET",
				Claims:   map[string]interface{}{"sub": float64(123)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantReq, buildConsentRequest(tt.reqCtx))
		})
	}
}

func TestConfig_IsFailOpen(t *testing.T) {
	tests := []struct {
		name     string
		failOpen *bool
		want     bool
	}{
		{name: "nil defaults to true (fail-open)", failOpen: nil, want: true},
		{name: "explicitly true is fail-open", failOpen: boolPtr(true), want: true},
		{name: "explicitly false is fail-closed", failOpen: boolPtr(false), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{FailOpen: tt.failOpen}
			assert.Equal(t, tt.want, cfg.IsFailOpen())
		})
	}
}
