/*
 * Copyright 2026 Seamless Middleware Technologies S.L and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logging

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSanitize verifies an error body spliced into a message cannot be printed
// or exported verbatim: control characters collapse and the result is bounded.
func TestSanitize(t *testing.T) {
	tests := []struct {
		name    string
		message string
		want    string
	}{
		{name: "empty", message: "", want: ""},
		{name: "a plain message is untouched", message: "no granted consent", want: "no granted consent"},
		{
			name:    "newlines and tabs collapse to single spaces",
			message: "consent check error:\n\t{\"error\":\"boom\"}\r\n",
			want:    `consent check error: {"error":"boom"}`,
		},
		{
			name:    "an over-long message is truncated and marked",
			message: "x" + strings.Repeat("y", 500),
			want:    "x" + strings.Repeat("y", maxSanitizedLength-len(sanitizedRedaction)-1) + sanitizedRedaction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Sanitize(tt.message)
			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, len(got), maxSanitizedLength)
		})
	}
}

// TestRedact verifies an identifier becomes a stable, short, non-reversible
// fingerprint — enough to correlate lines about the same subject, not enough to
// put a subject DID in stdout.
func TestRedact(t *testing.T) {
	const did = "did:key:zAliceSomeVeryLongIdentifier"

	assert.Empty(t, Redact(""), "an empty identifier stays empty")

	redacted := Redact(did)
	assert.Equal(t, redacted, Redact(did), "the fingerprint must be stable")
	assert.NotContains(t, redacted, did)
	assert.NotContains(t, redacted, "Alice")
	assert.True(t, strings.HasPrefix(redacted, redactedPrefix), "a fingerprint must be recognisable as one")
	assert.Len(t, redacted, len(redactedPrefix)+fingerprintLength)
	assert.NotEqual(t, redacted, Redact("did:key:zBob"), "different identifiers must differ")
}

// TestRateLimiting verifies a repeated failure costs one line per interval and
// reports how many it swallowed. A broken consent-manager previously emitted one
// line per request.
func TestRateLimiting(t *testing.T) {
	ResetSuppression()
	t.Cleanup(ResetSuppression)

	const key = "test-key"

	ok, suppressed := allow(key)
	assert.True(t, ok, "the first occurrence must log")
	assert.Zero(t, suppressed)

	for i := 0; i < 5; i++ {
		ok, _ = allow(key)
		assert.False(t, ok, "occurrences within the interval must be suppressed")
	}

	// A different key is limited independently.
	ok, _ = allow("other-key")
	assert.True(t, ok, "each key has its own budget")
}

// TestSuppressedSuffix verifies the rate limiting is never silent about itself.
func TestSuppressedSuffix(t *testing.T) {
	assert.Empty(t, suppressedSuffix(0))
	assert.Contains(t, suppressedSuffix(7), "7 further occurrence(s) suppressed")
}
