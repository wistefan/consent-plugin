package plugin

import (
	"testing"

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
		wantNil bool
	}{
		{
			name:    "empty JSON object",
			input:   []byte(`{}`),
			wantNil: false,
		},
		{
			name:    "arbitrary JSON",
			input:   []byte(`{"key": "value"}`),
			wantNil: false,
		},
		{
			name:    "nil input returns nil conf without error",
			input:   nil,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ConsentFilter{}
			conf, err := p.ParseConf(tt.input)
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, conf)
			} else {
				assert.NotNil(t, conf)
			}
		})
	}
}

func TestPluginName_Constant(t *testing.T) {
	// Verify the plugin name constant matches the expected APISIX plugin name.
	assert.Equal(t, "consent-filter", pluginName)
}
