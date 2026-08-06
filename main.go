// Package main is the entry point for the APISIX go-plugin-runner.
// It imports the consent-filter plugin package to trigger registration
// via init() and starts the plugin runner.
package main

import (
	"github.com/apache/apisix-go-plugin-runner/pkg/runner"

	// Import the plugin package to trigger init() registration.
	_ "consent-plugin/internal/plugin"
)

func main() {
	runner.Run(runner.RunnerConfig{})
}
