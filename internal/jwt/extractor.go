// Package jwt provides functions for extracting and decoding JWT tokens
// from HTTP request headers without performing signature verification.
// Signature verification is expected to be handled by APISIX or the upstream service.
package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// bearerPrefix is the standard prefix for Bearer token authorization headers.
const bearerPrefix = "Bearer "

// jwtPartCount is the expected number of dot-separated parts in a JWT (header.payload.signature).
const jwtPartCount = 3

// payloadPartIndex is the index of the payload segment in a dot-separated JWT.
const payloadPartIndex = 1

// ExtractToken strips the "Bearer " prefix from an authorization header value
// and returns the raw JWT string. Returns an error if the prefix is missing
// or the header value is empty.
func ExtractToken(headerValue string) (string, error) {
	if headerValue == "" {
		return "", errors.New("jwt extraction: header value is empty")
	}

	if !strings.HasPrefix(headerValue, bearerPrefix) {
		return "", errors.New("jwt extraction: missing Bearer prefix")
	}

	token := strings.TrimPrefix(headerValue, bearerPrefix)
	if token == "" {
		return "", errors.New("jwt extraction: token is empty after removing Bearer prefix")
	}

	return token, nil
}

// DecodeClaims base64-decodes the JWT payload segment and extracts the
// requested claim keys. It does not verify the JWT signature. If claimKeys
// is empty, all claims from the payload are returned. Returns a map of
// claim key to value for each requested key that exists in the payload.
func DecodeClaims(token string, claimKeys []string) (map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	if len(parts) != jwtPartCount {
		return nil, fmt.Errorf("jwt decoding: expected %d parts, got %d", jwtPartCount, len(parts))
	}

	payload := parts[payloadPartIndex]

	// JWT uses base64url encoding without padding; add padding if needed.
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("jwt decoding: failed to base64url-decode payload: %w", err)
	}

	var allClaims map[string]interface{}
	if err := json.Unmarshal(decoded, &allClaims); err != nil {
		return nil, fmt.Errorf("jwt decoding: failed to parse payload JSON: %w", err)
	}

	// If no specific claim keys requested, return all claims.
	if len(claimKeys) == 0 {
		return allClaims, nil
	}

	// Extract only the requested claims.
	result := make(map[string]interface{}, len(claimKeys))
	for _, key := range claimKeys {
		if val, ok := allClaims[key]; ok {
			result[key] = val
		}
	}

	return result, nil
}
