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
	"consent-plugin/internal/logging"
	"consent-plugin/internal/metrics"
	// Import the plugin package to trigger init() registration.
	_ "consent-plugin/internal/plugin"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/apache/apisix-go-plugin-runner/pkg/runner"
)

// EnvMetricsAddress is the listen address for the Prometheus metrics endpoint
// (e.g. ":9091"). Metrics are off unless it is set: the runner is normally
// reached only over its unix socket, so opening a TCP port is an explicit
// decision for the deployment to make.
const EnvMetricsAddress = "CONSENT_METRICS_ADDRESS"

// metricsPath is where the metrics are exposed.
const metricsPath = "/metrics"

// metricsServerTimeout bounds a metrics request, so a stuck scraper cannot hold
// a connection open indefinitely.
const metricsServerTimeout = 10 * time.Second

func main() {
	go serveMetrics()

	runAndFlush(func() { runner.Run(runner.RunnerConfig{}) }, audit.ShutdownAll)
}

// runAndFlush runs the plugin runner to completion and only then flushes the
// audit queue.
//
// The ordering is the whole point, and it is easy to get wrong. The runner
// installs its own signal.Notify for SIGINT/SIGTERM and returns from Run as soon
// as one arrives. An earlier version of this file waited for the same signal in
// a goroutine of its own and flushed there — but Go delivers a signal to every
// registered channel at once, so the runner's handler returned, main returned,
// and the process exited while the flush was still draining its queue and
// waiting on an HTTP export. The flush was present and essentially never
// completed: exactly the loss it was added to prevent, now wearing the
// appearance of being handled, and invisible to the dropped-events counter
// because these were not queue-overflow drops.
//
// Since Run already blocks until the signal, the flush belongs after it,
// synchronously, where nothing can exit out from under it — and the plugin needs
// no signal handler of its own.
func runAndFlush(run, flush func()) {
	run()
	flush()
}

// serveMetrics exposes the plugin's Prometheus metrics when an address is
// configured. A component that can deny production traffic should not be
// observable only through unstructured logs.
func serveMetrics() {
	address := os.Getenv(EnvMetricsAddress)
	if address == "" {
		return
	}
	mux := http.NewServeMux()
	mux.Handle(metricsPath, metrics.Handler())
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: metricsServerTimeout,
		ReadTimeout:       metricsServerTimeout,
		WriteTimeout:      metricsServerTimeout,
	}
	logging.Infof("serving metrics on %s%s", address, metricsPath)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		// The gate keeps working without metrics; do not take the runner down.
		logging.Errorf("metrics endpoint stopped: %s", logging.Sanitize(err.Error()))
	}
}
