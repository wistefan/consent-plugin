// Package main is the entry point for the APISIX go-plugin-runner.
// It imports the consent-filter plugin package to trigger registration
// via init() and starts the plugin runner.
package main

import (
	_ "consent-plugin/internal/plugin"

	"github.com/apache/apisix-go-plugin-runner/pkg/runner"
	// Import the plugin package to trigger init() registration.
)

func main() {
	runner.Run(runner.RunnerConfig{})
}
