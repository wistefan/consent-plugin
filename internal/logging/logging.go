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

// Package logging is the plugin's logging front end.
//
// It exists for three reasons, each of which was a problem with calling the
// standard library's log.Printf directly:
//
//   - Levels. The go-plugin-runner ships its own zap logger and configures its
//     level from the runner's environment. Lines written with log.Printf bypass
//     it entirely, so an operator could not raise or lower the plugin's verbosity
//     at all. Everything here goes through the runner's logger.
//
//   - Personal data. Log lines on the request path carry subject DIDs and
//     upstream error bodies, i.e. personal data on stdout with no retention
//     policy — exactly what the OTLP audit path exists to avoid. Redact turns an
//     identifier into a stable fingerprint that still correlates across lines,
//     and Sanitize strips an error body down to something safe to print.
//
//   - Volume. A broken consent-manager produced one line per request. The
//     Every variants collapse a repeated failure to one line per interval and
//     report how many were suppressed.
package logging

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	runnerlog "github.com/apache/apisix-go-plugin-runner/pkg/log"
)

// logPrefix marks every line as coming from this plugin.
const logPrefix = "[consent-filter] "

// Debugf logs at debug level.
func Debugf(template string, args ...interface{}) {
	runnerlog.Debugf(logPrefix+template, args...)
}

// Infof logs at info level.
func Infof(template string, args ...interface{}) {
	runnerlog.Infof(logPrefix+template, args...)
}

// Warnf logs at warn level.
func Warnf(template string, args ...interface{}) {
	runnerlog.Warnf(logPrefix+template, args...)
}

// Errorf logs at error level.
func Errorf(template string, args ...interface{}) {
	runnerlog.Errorf(logPrefix+template, args...)
}

// --- rate limiting -----------------------------------------------------------

// suppressionInterval is how long one key stays silenced after it has logged.
// A dependency that fails for every request should cost one line per interval,
// not one line per request.
const suppressionInterval = 10 * time.Second

type suppressionState struct {
	lastLogged time.Time
	suppressed uint64
}

var (
	suppressionMu     sync.Mutex
	suppressionByKey  = map[string]*suppressionState{}
	suppressionKeyCap = 1024
)

// allow reports whether key may log now, and how many lines it suppressed since
// it last did.
func allow(key string) (bool, uint64) {
	suppressionMu.Lock()
	defer suppressionMu.Unlock()

	state := suppressionByKey[key]
	if state == nil {
		// The key set is bounded: keys are compile-time constants in normal use,
		// but a cap means a caller passing a variable key cannot grow the map.
		if len(suppressionByKey) >= suppressionKeyCap {
			return true, 0
		}
		state = &suppressionState{}
		suppressionByKey[key] = state
	}

	now := time.Now()
	if !state.lastLogged.IsZero() && now.Sub(state.lastLogged) < suppressionInterval {
		state.suppressed++
		return false, 0
	}
	suppressed := state.suppressed
	state.suppressed = 0
	state.lastLogged = now
	return true, suppressed
}

// WarnfEvery logs at warn level at most once per suppressionInterval for the
// given key, noting how many occurrences were suppressed in between.
func WarnfEvery(key, template string, args ...interface{}) {
	if ok, suppressed := allow(key); ok {
		Warnf(template+suppressedSuffix(suppressed), args...)
	}
}

// ErrorfEvery logs at error level at most once per suppressionInterval for the
// given key, noting how many occurrences were suppressed in between.
func ErrorfEvery(key, template string, args ...interface{}) {
	if ok, suppressed := allow(key); ok {
		Errorf(template+suppressedSuffix(suppressed), args...)
	}
}

// suppressedSuffix renders the count of lines that were swallowed since this key
// last logged, so the rate limiting is never silent about itself.
func suppressedSuffix(suppressed uint64) string {
	if suppressed == 0 {
		return ""
	}
	return fmt.Sprintf(" (%d further occurrence(s) suppressed)", suppressed)
}

// ResetSuppression clears the rate-limiter state. For tests.
func ResetSuppression() {
	suppressionMu.Lock()
	defer suppressionMu.Unlock()
	suppressionByKey = map[string]*suppressionState{}
}

// --- redaction ---------------------------------------------------------------

// fingerprintLength is how many hex characters of the digest identify a value.
// Eight is enough to correlate lines about the same subject within a log without
// being a usable handle on the subject themselves.
const fingerprintLength = 8

// redactedPrefix marks a value as a fingerprint rather than an identifier.
const redactedPrefix = "id:"

// Redact turns an identifier (a subject DID, a participant DID) into a stable,
// non-reversible fingerprint.
//
// The identifier itself belongs in the audit record, which is exported to a
// controlled sink with a retention policy — not in stdout logs, which have
// neither. The fingerprint is stable, so lines about the same subject can still
// be correlated while debugging.
func Redact(identifier string) string {
	if identifier == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(identifier))
	return redactedPrefix + hex.EncodeToString(sum[:])[:fingerprintLength]
}

// --- sanitisation ------------------------------------------------------------

// maxSanitizedLength bounds a sanitised message. Longer than this and an error
// body has been spliced into it.
const maxSanitizedLength = 200

// sanitizedRedaction replaces the tail of an over-long message.
const sanitizedRedaction = "...(redacted)"

// Sanitize makes an error message safe to print or export: control characters
// (including the newlines of an HTML or JSON error page) collapse to single
// spaces, and the result is truncated.
//
// Messages built by wrapping dependency errors embed the dependency's response
// body, which can carry identifiers or other personal data.
func Sanitize(message string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, message)
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if len(cleaned) > maxSanitizedLength {
		return cleaned[:maxSanitizedLength-len(sanitizedRedaction)] + sanitizedRedaction
	}
	return cleaned
}
