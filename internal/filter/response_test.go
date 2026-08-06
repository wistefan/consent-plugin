package filter

import (
	"encoding/json"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractFieldNames(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		wantNames []string
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "extracts top-level field names from JSON object",
			body:      []byte(`{"name":"Alice","age":30,"email":"alice@example.com"}`),
			wantNames: []string{"age", "email", "name"},
		},
		{
			name:      "single field object",
			body:      []byte(`{"id":1}`),
			wantNames: []string{"id"},
		},
		{
			name:      "nested object returns only top-level names",
			body:      []byte(`{"user":{"name":"Alice"},"status":"active"}`),
			wantNames: []string{"status", "user"},
		},
		{
			name:      "empty JSON object returns empty slice",
			body:      []byte(`{}`),
			wantNames: []string{},
		},
		{
			name:      "empty body returns error",
			body:      []byte{},
			wantErr:   true,
			errSubstr: "body is empty",
		},
		{
			name:      "nil body returns error",
			body:      nil,
			wantErr:   true,
			errSubstr: "body is empty",
		},
		{
			name:      "non-JSON body returns error",
			body:      []byte(`not json at all`),
			wantErr:   true,
			errSubstr: "failed to parse JSON",
		},
		{
			name:      "JSON array returns error",
			body:      []byte(`[1, 2, 3]`),
			wantErr:   true,
			errSubstr: "failed to parse JSON",
		},
		{
			name:      "JSON with various value types",
			body:      []byte(`{"str":"hello","num":42,"bool":true,"null":null,"arr":[1],"obj":{"k":"v"}}`),
			wantNames: []string{"arr", "bool", "null", "num", "obj", "str"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			names, err := ExtractFieldNames(tt.body)

			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errSubstr)
				assert.Nil(t, names)
				return
			}

			require.NoError(t, err)
			// Sort for deterministic comparison since map iteration order is random.
			sort.Strings(names)
			assert.Equal(t, tt.wantNames, names)
		})
	}
}

func TestRemoveFields(t *testing.T) {
	tests := []struct {
		name       string
		body       []byte
		fields     []string
		wantResult map[string]interface{}
		wantRaw    []byte // for non-JSON passthrough cases
		wantErr    bool
	}{
		{
			name:   "remove single top-level field",
			body:   []byte(`{"name":"Alice","age":30,"email":"alice@example.com"}`),
			fields: []string{"email"},
			wantResult: map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
		{
			name:   "remove multiple top-level fields",
			body:   []byte(`{"name":"Alice","age":30,"email":"alice@example.com","phone":"555-0100"}`),
			fields: []string{"email", "phone"},
			wantResult: map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
		{
			name:   "remove nested field via dot-notation",
			body:   []byte(`{"user":{"name":"Alice","email":"alice@example.com"},"status":"active"}`),
			fields: []string{"user.email"},
			wantResult: map[string]interface{}{
				"user":   map[string]interface{}{"name": "Alice"},
				"status": "active",
			},
		},
		{
			name:   "remove deeply nested field",
			body:   []byte(`{"data":{"user":{"contact":{"email":"a@b.com","phone":"555"}}}}`),
			fields: []string{"data.user.contact.email"},
			wantResult: map[string]interface{}{
				"data": map[string]interface{}{
					"user": map[string]interface{}{
						"contact": map[string]interface{}{
							"phone": "555",
						},
					},
				},
			},
		},
		{
			name:   "remove mix of top-level and nested fields",
			body:   []byte(`{"id":1,"user":{"name":"Alice","email":"a@b.com"},"secret":"s3cr3t"}`),
			fields: []string{"secret", "user.email"},
			wantResult: map[string]interface{}{
				"id":   float64(1),
				"user": map[string]interface{}{"name": "Alice"},
			},
		},
		{
			name:   "remove non-existent field is no-op",
			body:   []byte(`{"name":"Alice","age":30}`),
			fields: []string{"nonexistent"},
			wantResult: map[string]interface{}{
				"name": "Alice",
				"age":  float64(30),
			},
		},
		{
			name:   "remove non-existent nested field is no-op",
			body:   []byte(`{"user":{"name":"Alice"}}`),
			fields: []string{"user.nonexistent"},
			wantResult: map[string]interface{}{
				"user": map[string]interface{}{"name": "Alice"},
			},
		},
		{
			name:   "dot-notation into non-object is no-op",
			body:   []byte(`{"name":"Alice"}`),
			fields: []string{"name.sub"},
			wantResult: map[string]interface{}{
				"name": "Alice",
			},
		},
		{
			name:   "empty denied fields list returns body unchanged",
			body:   []byte(`{"name":"Alice","age":30}`),
			fields: []string{},
			wantRaw: []byte(`{"name":"Alice","age":30}`),
		},
		{
			name:    "nil denied fields list returns body unchanged",
			body:    []byte(`{"name":"Alice","age":30}`),
			fields:  nil,
			wantRaw: []byte(`{"name":"Alice","age":30}`),
		},
		{
			name:    "non-JSON body passes through unchanged",
			body:    []byte(`This is plain text, not JSON`),
			fields:  []string{"field"},
			wantRaw: []byte(`This is plain text, not JSON`),
		},
		{
			name:    "HTML body passes through unchanged",
			body:    []byte(`<html><body>Hello</body></html>`),
			fields:  []string{"body"},
			wantRaw: []byte(`<html><body>Hello</body></html>`),
		},
		{
			name:    "empty body returns empty body",
			body:    []byte{},
			fields:  []string{"field"},
			wantRaw: []byte{},
		},
		{
			name:    "nil body returns nil body",
			body:    nil,
			fields:  []string{"field"},
			wantRaw: nil,
		},
		{
			name:   "remove all fields leaves empty object",
			body:   []byte(`{"name":"Alice","age":30}`),
			fields: []string{"name", "age"},
			wantResult: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := RemoveFields(tt.body, tt.fields)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)

			if tt.wantRaw != nil || (tt.wantResult == nil && tt.wantRaw == nil && tt.body == nil) {
				// For passthrough cases, compare raw bytes.
				assert.Equal(t, tt.wantRaw, result)
				return
			}

			// For JSON cases, compare as parsed objects to ignore key ordering.
			var got map[string]interface{}
			require.NoError(t, json.Unmarshal(result, &got))
			assert.Equal(t, tt.wantResult, got)
		})
	}
}

func TestRemoveFields_EmptyBody(t *testing.T) {
	// Explicit test for empty byte slice passthrough.
	result, err := RemoveFields([]byte{}, []string{"field"})
	require.NoError(t, err)
	assert.Equal(t, []byte{}, result)
}
