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

// Package main is the entry point for the APISIX go-plugin-runner.
// It imports the consent-filter plugin package to trigger registration
// via init() and starts the plugin runner.
package main

import (
	"consent-plugin/internal/audit"
	// Import the plugin package to trigger init() registration.
	_ "consent-plugin/internal/plugin"
	"os"
	"os/signal"
	"syscall"

	"github.com/apache/apisix-go-plugin-runner/pkg/runner"
)

func main() {
	// The audit queue is flushed by a background worker on an interval, so a
	// redeploy or restart would otherwise discard up to one flush interval of
	// access decisions — silently, from the record whose whole purpose is to be
	// complete. runner.Run blocks, so the flush is driven from its own goroutine.
	go flushAuditOnShutdown()

	runner.Run(runner.RunnerConfig{})
}

// flushAuditOnShutdown waits for a termination signal and flushes every audit
// emitter before the process goes away.
func flushAuditOnShutdown() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
	audit.ShutdownAll()
}
