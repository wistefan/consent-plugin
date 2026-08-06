package consent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewClient verifies the constructor applies defaults and configures timeout.
func TestNewClient(t *testing.T) {
	tests := []struct {
		name        string
		baseURL     string
		timeoutMs   int
		wantTimeout time.Duration
		wantBaseURL string
	}{
		{
			name:        "valid timeout",
			baseURL:     "http://localhost:8080",
			timeoutMs:   3000,
			wantTimeout: 3000 * time.Millisecond,
			wantBaseURL: "http://localhost:8080",
		},
		{
			name:        "zero timeout uses default",
			baseURL:     "http://consent-api:9090",
			timeoutMs:   0,
			wantTimeout: time.Duration(DefaultTimeoutMs) * time.Millisecond,
			wantBaseURL: "http://consent-api:9090",
		},
		{
			name:        "negative timeout uses default",
			baseURL:     "http://example.com",
			timeoutMs:   -100,
			wantTimeout: time.Duration(DefaultTimeoutMs) * time.Millisecond,
			wantBaseURL: "http://example.com",
		},
		{
			name:        "minimum timeout",
			baseURL:     "http://example.com",
			timeoutMs:   MinTimeoutMs,
			wantTimeout: time.Duration(MinTimeoutMs) * time.Millisecond,
			wantBaseURL: "http://example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewClient(tt.baseURL, tt.timeoutMs)
			assert.Equal(t, tt.wantBaseURL, client.baseURL)
			assert.Equal(t, tt.wantTimeout, client.httpClient.Timeout)
		})
	}
}

// TestCheckConsent uses table-driven tests with httptest.NewServer to verify
// the full request/response lifecycle of the consent client.
func TestCheckConsent(t *testing.T) {
	tests := []struct {
		name           string
		request        ConsentRequest
		serverHandler  http.HandlerFunc
		wantResponse   *ConsentResponse
		wantErr        bool
		wantErrContain string
	}{
		{
			name: "successful allow response",
			request: ConsentRequest{
				Subject:        "user-123",
				Resource:       "/api/v1/users/456",
				Method:         "GET",
				Claims:         map[string]interface{}{"sub": "user-123", "scope": "read"},
				ResponseFields: []string{"id", "name", "email"},
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				assertRequestMethod(t, r)
				assertRequestContentType(t, r)
				assertRequestBody(t, r, "user-123", "/api/v1/users/456", "GET")

				w.Header().Set("Content-Type", ContentTypeJSON)
				resp := ConsentResponse{
					Decision: DecisionAllow,
					Reason:   "user has full consent",
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantResponse: &ConsentResponse{
				Decision: DecisionAllow,
				Reason:   "user has full consent",
			},
			wantErr: false,
		},
		{
			name: "successful deny response",
			request: ConsentRequest{
				Subject:  "user-789",
				Resource: "/api/v1/admin/secrets",
				Method:   "GET",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				resp := ConsentResponse{
					Decision: DecisionDeny,
					Reason:   "no consent for this resource",
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantResponse: &ConsentResponse{
				Decision: DecisionDeny,
				Reason:   "no consent for this resource",
			},
			wantErr: false,
		},
		{
			name: "successful filter response with denied fields",
			request: ConsentRequest{
				Subject:        "user-100",
				Resource:       "/api/v1/profile",
				Method:         "GET",
				ResponseFields: []string{"id", "name", "email", "phone", "address"},
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				resp := ConsentResponse{
					Decision:     DecisionFilter,
					DeniedFields: []string{"email", "phone", "address"},
					Reason:       "partial consent: PII fields restricted",
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantResponse: &ConsentResponse{
				Decision:     DecisionFilter,
				DeniedFields: []string{"email", "phone", "address"},
				Reason:       "partial consent: PII fields restricted",
			},
			wantErr: false,
		},
		{
			name: "consent API returns non-200 status",
			request: ConsentRequest{
				Subject:  "user-err",
				Resource: "/api/v1/data",
				Method:   "POST",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte(`{"error":"internal server error"}`))
			},
			wantErr:        true,
			wantErrContain: "unexpected status code 500",
		},
		{
			name: "consent API returns 400 bad request",
			request: ConsentRequest{
				Subject: "",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"subject is required"}`))
			},
			wantErr:        true,
			wantErrContain: "unexpected status code 400",
		},
		{
			name: "malformed response body",
			request: ConsentRequest{
				Subject:  "user-bad",
				Resource: "/api/v1/data",
				Method:   "GET",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{not valid json`))
			},
			wantErr:        true,
			wantErrContain: "failed to unmarshal response",
		},
		{
			name: "response with empty decision field",
			request: ConsentRequest{
				Subject:  "user-empty",
				Resource: "/api/v1/data",
				Method:   "GET",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"decision":"","reason":"missing"}`))
			},
			wantErr:        true,
			wantErrContain: "decision field is empty",
		},
		{
			name: "response with unrecognized decision",
			request: ConsentRequest{
				Subject:  "user-unknown",
				Resource: "/api/v1/data",
				Method:   "GET",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"decision":"maybe","reason":"uncertain"}`))
			},
			wantErr:        true,
			wantErrContain: "unrecognized decision",
		},
		{
			name: "request with nil claims",
			request: ConsentRequest{
				Subject:  "user-nil",
				Resource: "/api/v1/data",
				Method:   "GET",
				Claims:   nil,
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				resp := ConsentResponse{
					Decision: DecisionAllow,
					Reason:   "allowed with no claims",
				}
				json.NewEncoder(w).Encode(resp)
			},
			wantResponse: &ConsentResponse{
				Decision: DecisionAllow,
				Reason:   "allowed with no claims",
			},
			wantErr: false,
		},
		{
			name: "empty response body with 200 status",
			request: ConsentRequest{
				Subject:  "user-empty-body",
				Resource: "/api/v1/data",
				Method:   "GET",
			},
			serverHandler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", ContentTypeJSON)
				w.WriteHeader(http.StatusOK)
				// Write nothing — empty body
			},
			wantErr:        true,
			wantErrContain: "failed to unmarshal response",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.serverHandler)
			defer server.Close()

			client := NewClient(server.URL, DefaultTimeoutMs)
			resp, err := client.CheckConsent(context.Background(), tt.request)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContain)
				assert.Nil(t, resp)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, resp)
			assert.Equal(t, tt.wantResponse.Decision, resp.Decision)
			assert.Equal(t, tt.wantResponse.Reason, resp.Reason)
			assert.Equal(t, tt.wantResponse.DeniedFields, resp.DeniedFields)
		})
	}
}

// TestCheckConsentTimeout verifies that the client respects the configured timeout.
func TestCheckConsentTimeout(t *testing.T) {
	// slowResponseDelay is how long the mock server waits before responding,
	// chosen to exceed the client's timeout.
	const slowResponseDelay = 200 * time.Millisecond
	// shortTimeoutMs is the client timeout in milliseconds, set lower than
	// slowResponseDelay so the request times out.
	const shortTimeoutMs = 50

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(slowResponseDelay)
		w.Header().Set("Content-Type", ContentTypeJSON)
		json.NewEncoder(w).Encode(ConsentResponse{Decision: DecisionAllow})
	}))
	defer server.Close()

	client := NewClient(server.URL, shortTimeoutMs)
	resp, err := client.CheckConsent(context.Background(), ConsentRequest{
		Subject:  "user-timeout",
		Resource: "/api/v1/data",
		Method:   "GET",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
	assert.Nil(t, resp)
}

// TestCheckConsentContextCancellation verifies that the client respects
// context cancellation.
func TestCheckConsentContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Wait long enough that cancellation takes effect.
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", ContentTypeJSON)
		json.NewEncoder(w).Encode(ConsentResponse{Decision: DecisionAllow})
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	client := NewClient(server.URL, DefaultTimeoutMs)
	resp, err := client.CheckConsent(ctx, ConsentRequest{
		Subject:  "user-cancel",
		Resource: "/api/v1/data",
		Method:   "GET",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
	assert.Nil(t, resp)
}

// TestCheckConsentInvalidURL verifies that the client returns an error when
// the base URL is unreachable.
func TestCheckConsentInvalidURL(t *testing.T) {
	client := NewClient("http://localhost:1", MinTimeoutMs)
	resp, err := client.CheckConsent(context.Background(), ConsentRequest{
		Subject:  "user-bad-url",
		Resource: "/api/v1/data",
		Method:   "GET",
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP request failed")
	assert.Nil(t, resp)
}

// TestCheckConsentRequestSerialization verifies that the ConsentRequest is
// correctly serialized to JSON in the HTTP request body.
func TestCheckConsentRequestSerialization(t *testing.T) {
	var receivedBody ConsentRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		err = json.Unmarshal(bodyBytes, &receivedBody)
		require.NoError(t, err)

		w.Header().Set("Content-Type", ContentTypeJSON)
		json.NewEncoder(w).Encode(ConsentResponse{Decision: DecisionAllow})
	}))
	defer server.Close()

	req := ConsentRequest{
		Subject:        "test-subject",
		Resource:       "/api/v1/users",
		Method:         "POST",
		Claims:         map[string]interface{}{"sub": "test-subject", "role": "admin"},
		ResponseFields: []string{"id", "name", "email"},
	}

	client := NewClient(server.URL, DefaultTimeoutMs)
	_, err := client.CheckConsent(context.Background(), req)
	require.NoError(t, err)

	assert.Equal(t, "test-subject", receivedBody.Subject)
	assert.Equal(t, "/api/v1/users", receivedBody.Resource)
	assert.Equal(t, "POST", receivedBody.Method)
	assert.Equal(t, []string{"id", "name", "email"}, receivedBody.ResponseFields)
	// Claims are deserialized as map[string]interface{}
	assert.Equal(t, "test-subject", receivedBody.Claims["sub"])
	assert.Equal(t, "admin", receivedBody.Claims["role"])
}

// TestCheckConsentEndpointPath verifies that the client POSTs to the correct
// endpoint path.
func TestCheckConsentEndpointPath(t *testing.T) {
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", ContentTypeJSON)
		json.NewEncoder(w).Encode(ConsentResponse{Decision: DecisionAllow})
	}))
	defer server.Close()

	client := NewClient(server.URL, DefaultTimeoutMs)
	_, err := client.CheckConsent(context.Background(), ConsentRequest{
		Subject:  "user-path",
		Resource: "/test",
		Method:   "GET",
	})
	require.NoError(t, err)
	assert.Equal(t, CheckEndpointPath, receivedPath)
}

// TestDecisionIsValid verifies the Decision.IsValid method.
func TestDecisionIsValid(t *testing.T) {
	tests := []struct {
		name     string
		decision Decision
		want     bool
	}{
		{name: "allow is valid", decision: DecisionAllow, want: true},
		{name: "deny is valid", decision: DecisionDeny, want: true},
		{name: "filter is valid", decision: DecisionFilter, want: true},
		{name: "empty is invalid", decision: "", want: false},
		{name: "unknown is invalid", decision: "maybe", want: false},
		{name: "uppercase is invalid", decision: "ALLOW", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.decision.IsValid())
		})
	}
}

// TestConsentResponseValidate verifies the Validate method on ConsentResponse.
func TestConsentResponseValidate(t *testing.T) {
	tests := []struct {
		name           string
		response       ConsentResponse
		wantErr        bool
		wantErrContain string
	}{
		{
			name:     "valid allow response",
			response: ConsentResponse{Decision: DecisionAllow},
			wantErr:  false,
		},
		{
			name:     "valid deny response",
			response: ConsentResponse{Decision: DecisionDeny, Reason: "no consent"},
			wantErr:  false,
		},
		{
			name:     "valid filter response",
			response: ConsentResponse{Decision: DecisionFilter, DeniedFields: []string{"email"}},
			wantErr:  false,
		},
		{
			name:           "empty decision",
			response:       ConsentResponse{Decision: ""},
			wantErr:        true,
			wantErrContain: "decision field is empty",
		},
		{
			name:           "unrecognized decision",
			response:       ConsentResponse{Decision: "block"},
			wantErr:        true,
			wantErrContain: "unrecognized decision",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.response.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrContain)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestTruncateBody verifies the body truncation helper.
func TestTruncateBody(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		wantSuffix bool
	}{
		{
			name:       "short body not truncated",
			body:       []byte("short error message"),
			wantSuffix: false,
		},
		{
			name:       "empty body",
			body:       []byte{},
			wantSuffix: false,
		},
		{
			name:       "body at max length not truncated",
			body:       make([]byte, maxBodyLogLength),
			wantSuffix: false,
		},
		{
			name:       "body exceeding max length is truncated",
			body:       make([]byte, maxBodyLogLength+100),
			wantSuffix: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateBody(tt.body)
			if tt.wantSuffix {
				assert.Contains(t, result, "...(truncated)")
				// Should contain exactly maxBodyLogLength bytes of content before truncation marker.
				assert.Equal(t, maxBodyLogLength+len("...(truncated)"), len(result))
			} else {
				assert.NotContains(t, result, "...(truncated)")
				assert.Equal(t, string(tt.body), result)
			}
		})
	}
}

// assertRequestMethod checks that the HTTP request used POST method.
func assertRequestMethod(t *testing.T, r *http.Request) {
	t.Helper()
	assert.Equal(t, http.MethodPost, r.Method)
}

// assertRequestContentType checks the Content-Type header.
func assertRequestContentType(t *testing.T, r *http.Request) {
	t.Helper()
	assert.Equal(t, ContentTypeJSON, r.Header.Get("Content-Type"))
}

// assertRequestBody reads and validates the request body fields.
func assertRequestBody(t *testing.T, r *http.Request, wantSubject, wantResource, wantMethod string) {
	t.Helper()
	bodyBytes, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	var req ConsentRequest
	err = json.Unmarshal(bodyBytes, &req)
	require.NoError(t, err)

	assert.Equal(t, wantSubject, req.Subject)
	assert.Equal(t, wantResource, req.Resource)
	assert.Equal(t, wantMethod, req.Method)
}
