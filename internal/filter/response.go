// Package filter provides functions for filtering and manipulating JSON
// response bodies based on consent decisions.
package filter

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ExtractFieldNames parses a JSON object body and returns the top-level
// field names. Returns an error if the body is empty or is not a valid
// JSON object.
func ExtractFieldNames(body []byte) ([]string, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("extract field names: body is empty")
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("extract field names: failed to parse JSON: %w", err)
	}

	names := make([]string, 0, len(obj))
	for key := range obj {
		names = append(names, key)
	}

	return names, nil
}

// RemoveFields parses a JSON object body, removes the specified fields,
// and returns the modified JSON. Field paths support dot-notation for
// nested fields (e.g., "user.email" removes the "email" key inside the
// "user" object). If fields is empty, the original body is returned
// unchanged. If the body is not valid JSON, it is returned unchanged
// (non-JSON passthrough).
func RemoveFields(body []byte, fields []string) ([]byte, error) {
	if len(fields) == 0 {
		return body, nil
	}
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]interface{}
	if err := json.Unmarshal(body, &obj); err != nil {
		// Non-JSON body: return unchanged.
		return body, nil
	}

	for _, field := range fields {
		parts := strings.Split(field, fieldPathSeparator)
		removeNestedField(obj, parts)
	}

	result, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remove fields: failed to marshal filtered JSON: %w", err)
	}

	return result, nil
}

// fieldPathSeparator is the delimiter used in dot-notation field paths
// (e.g., "user.email" splits into ["user", "email"]).
const fieldPathSeparator = "."

// removeNestedField recursively traverses the map following the path
// specified by parts and removes the leaf field. If any intermediate
// path segment does not exist or is not a JSON object, the operation
// is a no-op.
func removeNestedField(obj map[string]interface{}, parts []string) {
	if len(parts) == 0 {
		return
	}

	// Leaf node: delete the field directly.
	if len(parts) == 1 {
		delete(obj, parts[0])
		return
	}

	// Navigate into the nested object.
	nested, ok := obj[parts[0]]
	if !ok {
		return
	}

	nestedMap, ok := nested.(map[string]interface{})
	if !ok {
		return
	}

	removeNestedField(nestedMap, parts[1:])
}
