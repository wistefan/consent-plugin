package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validConfigJSON returns a minimal valid configuration JSON for testing.
func validConfigJSON() map[string]interface{} {
	return map[string]interface{}{
		"consent_api_url": "https://consent.example.com/api",
	}
}

// toJSON marshals a map to JSON bytes for test inputs.
func toJSON(t *testing.T, m map[string]interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	require.NoError(t, err)
	return b
}

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		wantErr   bool
		errSubstr string
		check     func(t *testing.T, cfg *Config)
	}{
		{
			name:  "valid config with only required field applies defaults",
			input: []byte(`{"consent_api_url": "https://consent.example.com/api"}`),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "https://consent.example.com/api", cfg.ConsentAPIURL)
				assert.Equal(t, DefaultConsentAPITimeout, cfg.ConsentAPITimeout)
				assert.Equal(t, DefaultJWTHeaderName, cfg.JWTHeaderName)
				assert.Equal(t, DefaultDenyStatusCode, cfg.DenyStatusCode)
				assert.Equal(t, DefaultDenyResponseBody, cfg.DenyResponseBody)
				assert.Equal(t, DefaultDenyResponseContentType, cfg.DenyResponseContentType)
				assert.Nil(t, cfg.JWTClaimsToForward)
			},
		},
		{
			name: "valid config with all fields set",
			input: func() []byte {
				m := map[string]interface{}{
					"consent_api_url":            "http://localhost:8080/consent",
					"consent_api_timeout":        10000,
					"jwt_header_name":            "X-Auth-Token",
					"jwt_claims_to_forward":      []string{"sub", "scope", "aud"},
					"deny_status_code":           451,
					"deny_response_body":         `{"msg":"blocked"}`,
					"deny_response_content_type": "text/plain",
				}
				b, _ := json.Marshal(m)
				return b
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, "http://localhost:8080/consent", cfg.ConsentAPIURL)
				assert.Equal(t, 10000, cfg.ConsentAPITimeout)
				assert.Equal(t, "X-Auth-Token", cfg.JWTHeaderName)
				assert.Equal(t, []string{"sub", "scope", "aud"}, cfg.JWTClaimsToForward)
				assert.Equal(t, 451, cfg.DenyStatusCode)
				assert.Equal(t, `{"msg":"blocked"}`, cfg.DenyResponseBody)
				assert.Equal(t, "text/plain", cfg.DenyResponseContentType)
			},
		},
		{
			name:      "empty input returns error",
			input:     nil,
			wantErr:   true,
			errSubstr: "input is empty",
		},
		{
			name:      "empty byte slice returns error",
			input:     []byte{},
			wantErr:   true,
			errSubstr: "input is empty",
		},
		{
			name:      "invalid JSON returns error",
			input:     []byte(`{not json}`),
			wantErr:   true,
			errSubstr: "failed to unmarshal JSON",
		},
		{
			name:      "missing consent_api_url returns error",
			input:     []byte(`{"consent_api_timeout": 3000}`),
			wantErr:   true,
			errSubstr: "consent_api_url is required",
		},
		{
			name:      "empty consent_api_url returns error",
			input:     []byte(`{"consent_api_url": ""}`),
			wantErr:   true,
			errSubstr: "consent_api_url is required",
		},
		{
			name:      "invalid URL for consent_api_url returns error",
			input:     []byte(`{"consent_api_url": "not-a-url"}`),
			wantErr:   true,
			errSubstr: "not a valid URL",
		},
		{
			name:      "non-http scheme in consent_api_url returns error",
			input:     []byte(`{"consent_api_url": "ftp://consent.example.com"}`),
			wantErr:   true,
			errSubstr: "must use http or https scheme",
		},
		{
			name: "consent_api_timeout below minimum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = -1
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "consent_api_timeout must be between",
		},
		{
			name: "consent_api_timeout above maximum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = 70000
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "consent_api_timeout must be between",
		},
		{
			name: "deny_status_code below minimum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["deny_status_code"] = 50
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "deny_status_code must be between",
		},
		{
			name: "deny_status_code above maximum returns error",
			input: func() []byte {
				m := validConfigJSON()
				m["deny_status_code"] = 600
				return toJSON(t, m)
			}(),
			wantErr:   true,
			errSubstr: "deny_status_code must be between",
		},
		{
			name: "consent_api_timeout at minimum boundary is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = MinConsentAPITimeout
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, MinConsentAPITimeout, cfg.ConsentAPITimeout)
			},
		},
		{
			name: "consent_api_timeout at maximum boundary is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["consent_api_timeout"] = MaxConsentAPITimeout
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, MaxConsentAPITimeout, cfg.ConsentAPITimeout)
			},
		},
		{
			name: "deny_status_code at boundaries is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["deny_status_code"] = MinHTTPStatusCode
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Equal(t, MinHTTPStatusCode, cfg.DenyStatusCode)
			},
		},
		{
			name: "empty jwt_claims_to_forward is valid",
			input: func() []byte {
				m := validConfigJSON()
				m["jwt_claims_to_forward"] = []string{}
				return toJSON(t, m)
			}(),
			check: func(t *testing.T, cfg *Config) {
				assert.Empty(t, cfg.JWTClaimsToForward)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := ParseConfig(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Nil(t, cfg)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, cfg)
			if tt.check != nil {
				tt.check(t, cfg)
			}
		})
	}
}

// TestParseConfig_EnvFallback verifies the credential fields fall back to their
// env vars when omitted from the route config, and that a value in the config
// always takes precedence over the env var.
func TestParseConfig_EnvFallback(t *testing.T) {
	t.Run("env fills empty credential fields", func(t *testing.T) {
		t.Setenv(EnvConsentKey, "ck-from-env")
		t.Setenv(EnvClientID, "cid-from-env")
		t.Setenv(EnvClientSecret, "sec-from-env")

		cfg, err := ParseConfig(toJSON(t, validConfigJSON()))
		require.NoError(t, err)
		assert.Equal(t, "ck-from-env", cfg.ConsentKey)
		assert.Equal(t, "cid-from-env", cfg.ClientID)
		assert.Equal(t, "sec-from-env", cfg.ClientSecret)
	})

	t.Run("config values win over env", func(t *testing.T) {
		t.Setenv(EnvConsentKey, "ck-from-env")
		t.Setenv(EnvClientID, "cid-from-env")
		t.Setenv(EnvClientSecret, "sec-from-env")

		in := validConfigJSON()
		in["consent_key"] = "ck-from-config"
		in["client_id"] = "cid-from-config"
		in["client_secret"] = "sec-from-config"
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.Equal(t, "ck-from-config", cfg.ConsentKey)
		assert.Equal(t, "cid-from-config", cfg.ClientID)
		assert.Equal(t, "sec-from-config", cfg.ClientSecret)
	})
}

// TestParseConfig_Audit covers the audit config: enabling requires an endpoint,
// and the endpoint falls back to its env var.
func TestParseConfig_Audit(t *testing.T) {
	t.Run("audit_enabled requires an endpoint", func(t *testing.T) {
		in := validConfigJSON()
		in["audit_enabled"] = true
		_, err := ParseConfig(toJSON(t, in))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "audit_otlp_endpoint is required")
	})

	t.Run("audit_enabled with an endpoint is valid", func(t *testing.T) {
		in := validConfigJSON()
		in["audit_enabled"] = true
		in["audit_otlp_endpoint"] = "http://otel:4318"
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.True(t, cfg.AuditEnabled)
		assert.Equal(t, "http://otel:4318", cfg.AuditOTLPEndpoint)
	})

	t.Run("endpoint falls back to env", func(t *testing.T) {
		t.Setenv(EnvAuditOTLPEndpoint, "http://otel-env:4318")
		in := validConfigJSON()
		in["audit_enabled"] = true
		cfg, err := ParseConfig(toJSON(t, in))
		require.NoError(t, err)
		assert.Equal(t, "http://otel-env:4318", cfg.AuditOTLPEndpoint)
	})
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		errSubstr string
	}{
		{
			name: "valid config passes validation",
			config: Config{
				ConsentAPIURL:           "https://consent.example.com",
				ConsentAPITimeout:       DefaultConsentAPITimeout,
				JWTHeaderName:           DefaultJWTHeaderName,
				DenyStatusCode:          DefaultDenyStatusCode,
				DenyResponseBody:        DefaultDenyResponseBody,
				DenyResponseContentType: DefaultDenyResponseContentType,
			},
		},
		{
			name: "missing URL fails",
			config: Config{
				ConsentAPITimeout: DefaultConsentAPITimeout,
				DenyStatusCode:    DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "consent_api_url is required",
		},
		{
			name: "negative timeout fails",
			config: Config{
				ConsentAPIURL:     "https://consent.example.com",
				ConsentAPITimeout: -1,
				DenyStatusCode:    DefaultDenyStatusCode,
			},
			wantErr:   true,
			errSubstr: "consent_api_timeout must be between",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestConsentFilter_ParseConf_Integration(t *testing.T) {
	// Verify that the plugin's ParseConf method correctly returns a *Config.
	p := &ConsentFilter{}

	t.Run("valid config returns *Config", func(t *testing.T) {
		input := []byte(`{"consent_api_url": "https://consent.example.com/api"}`)
		conf, err := p.ParseConf(input)
		require.NoError(t, err)

		cfg, ok := conf.(*Config)
		require.True(t, ok, "ParseConf should return *Config")
		assert.Equal(t, "https://consent.example.com/api", cfg.ConsentAPIURL)
		assert.Equal(t, DefaultConsentAPITimeout, cfg.ConsentAPITimeout)
	})

	t.Run("invalid config returns error", func(t *testing.T) {
		input := []byte(`{"consent_api_timeout": 3000}`)
		conf, err := p.ParseConf(input)
		require.Error(t, err)
		assert.Nil(t, conf)
	})

	t.Run("empty input returns error", func(t *testing.T) {
		conf, err := p.ParseConf(nil)
		require.Error(t, err)
		assert.Nil(t, conf)
	})
}
