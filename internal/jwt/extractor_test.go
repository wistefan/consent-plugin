package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// buildTestJWT constructs a minimal JWT string (header.payload.signature)
// from the given claims map for testing purposes.
func buildTestJWT(claims map[string]interface{}) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payloadBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	signature := base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
	return fmt.Sprintf("%s.%s.%s", header, payload, signature)
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		wantToken   string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid Bearer token",
			headerValue: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.sig",
			wantToken:   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.sig",
			wantErr:     false,
		},
		{
			name:        "empty header value",
			headerValue: "",
			wantErr:     true,
			errContains: "header value is empty",
		},
		{
			name:        "missing Bearer prefix",
			headerValue: "Basic dXNlcjpwYXNz",
			wantErr:     true,
			errContains: "missing Bearer prefix",
		},
		{
			name:        "lowercase bearer prefix is rejected",
			headerValue: "bearer some-token",
			wantErr:     true,
			errContains: "missing Bearer prefix",
		},
		{
			name:        "Bearer prefix only with no token",
			headerValue: "Bearer ",
			wantErr:     true,
			errContains: "token is empty after removing Bearer prefix",
		},
		{
			name:        "Bearer prefix without space is rejected",
			headerValue: "BearerTokenWithoutSpace",
			wantErr:     true,
			errContains: "missing Bearer prefix",
		},
		{
			name:        "valid token with extra whitespace in value",
			headerValue: "Bearer token-with-content",
			wantToken:   "token-with-content",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractToken(tt.headerValue)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Empty(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantToken, got)
			}
		})
	}
}

func TestDecodeClaims(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		claimKeys   []string
		wantClaims  map[string]interface{}
		wantErr     bool
		errContains string
	}{
		{
			name: "extract specific claims",
			token: buildTestJWT(map[string]interface{}{
				"sub":   "user-123",
				"scope": "read write",
				"iss":   "auth-server",
			}),
			claimKeys: []string{"sub", "scope"},
			wantClaims: map[string]interface{}{
				"sub":   "user-123",
				"scope": "read write",
			},
			wantErr: false,
		},
		{
			name: "empty claimKeys returns all claims",
			token: buildTestJWT(map[string]interface{}{
				"sub": "user-456",
				"aud": "my-api",
			}),
			claimKeys: []string{},
			wantClaims: map[string]interface{}{
				"sub": "user-456",
				"aud": "my-api",
			},
			wantErr: false,
		},
		{
			name: "nil claimKeys returns all claims",
			token: buildTestJWT(map[string]interface{}{
				"sub": "user-789",
			}),
			claimKeys: nil,
			wantClaims: map[string]interface{}{
				"sub": "user-789",
			},
			wantErr: false,
		},
		{
			name: "requested claim not present in payload",
			token: buildTestJWT(map[string]interface{}{
				"sub": "user-123",
			}),
			claimKeys:  []string{"email"},
			wantClaims: map[string]interface{}{},
			wantErr:    false,
		},
		{
			name: "numeric claim values are preserved",
			token: buildTestJWT(map[string]interface{}{
				"sub": "user-123",
				"iat": 1700000000,
				"exp": 1700003600,
			}),
			claimKeys: []string{"iat", "exp"},
			wantClaims: map[string]interface{}{
				"iat": float64(1700000000),
				"exp": float64(1700003600),
			},
			wantErr: false,
		},
		{
			name:        "malformed JWT with only one part",
			token:       "single-segment",
			claimKeys:   []string{"sub"},
			wantErr:     true,
			errContains: "expected 3 parts, got 1",
		},
		{
			name:        "malformed JWT with two parts",
			token:       "header.payload",
			claimKeys:   []string{"sub"},
			wantErr:     true,
			errContains: "expected 3 parts, got 2",
		},
		{
			name:        "malformed JWT with four parts",
			token:       "a.b.c.d",
			claimKeys:   []string{"sub"},
			wantErr:     true,
			errContains: "expected 3 parts, got 4",
		},
		{
			name:        "invalid base64 payload",
			token:       "header.!!!invalid-base64!!!.signature",
			claimKeys:   []string{"sub"},
			wantErr:     true,
			errContains: "failed to base64url-decode payload",
		},
		{
			name: "payload is valid base64 but not valid JSON",
			token: fmt.Sprintf("header.%s.signature",
				base64.RawURLEncoding.EncodeToString([]byte("not-json"))),
			claimKeys:   []string{"sub"},
			wantErr:     true,
			errContains: "failed to parse payload JSON",
		},
		{
			name: "boolean and nested claims",
			token: buildTestJWT(map[string]interface{}{
				"sub":            "user-123",
				"email_verified": true,
				"address": map[string]interface{}{
					"city": "Berlin",
				},
			}),
			claimKeys: []string{"email_verified", "address"},
			wantClaims: map[string]interface{}{
				"email_verified": true,
				"address": map[string]interface{}{
					"city": "Berlin",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeClaims(tt.token, tt.claimKeys)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errContains)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantClaims, got)
			}
		})
	}
}
