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

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunAndFlushOrdering pins the ordering the audit flush depends on: it must
// happen after the runner has returned, not concurrently with it.
//
// The previous wiring ran the flush in its own goroutine waiting on the same
// signal the runner waits on, so the process exited before the flush finished
// and the queued records were lost. Nothing in the suite noticed, because a
// flush that never completes still compiles and still passes every test that
// only checks it was called.
func TestRunAndFlushOrdering(t *testing.T) {
	var sequence []string

	runAndFlush(
		func() { sequence = append(sequence, "run") },
		func() { sequence = append(sequence, "flush") },
	)

	require.Len(t, sequence, 2)
	assert.Equal(t, []string{"run", "flush"}, sequence,
		"the audit flush must run after the runner returns, or the process exits with the queue undrained")
}

// TestRunAndFlushFlushesAfterRunBlocks verifies the flush waits for a runner
// that returns only when it is good and ready — the real runner blocks until
// SIGTERM.
func TestRunAndFlushFlushesAfterRunBlocks(t *testing.T) {
	runnerReturned := false
	flushSawReturn := false

	runAndFlush(
		func() { runnerReturned = true },
		func() { flushSawReturn = runnerReturned },
	)

	assert.True(t, flushSawReturn, "the flush must not start until the runner has returned")
}
