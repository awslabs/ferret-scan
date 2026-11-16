// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"os"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// webScanScope is the "scan" block of a /scan (#904): the same formatters.ScanScope the CLI's --file
// report carries, so a narrowed web scan says what it did not look for. nil for a full-scope scan.
//
// Sourced from what runs, not echoed from the form: the checks are the keys of the validator set
// core.ScanFileCtx builds for this request (core.ParseChecksToRun then core.BuildValidatorSetWithOverrides,
// the calls scanner.go makes), and the disabled sub-types are what those validators report. The web has
// no profile, so none is reported.
func (ws *WebServer) webScanScope(cfg *config.Config, checks string, confidence map[string]bool) *formatters.ScanScope {
	var checksSlice []string
	if checks != "" && checks != "all" {
		checksSlice = strings.Split(checks, ",")
	}
	validators := core.BuildValidatorSetWithOverrides(core.ParseChecksToRun(checksSlice), cfg, nil, nil)
	run := make([]string, 0, len(validators))
	for name := range validators {
		run = append(run, name)
	}
	disabled, _ := core.DisabledDetectionTypes(validators)

	sourcePath := ""
	if cfg != nil {
		sourcePath = cfg.SourcePath
	}
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	sm, _ := ws.initializeSuppressionManager(ws.suppressionsPath)
	return formatters.NewScanScope(formatters.ScopeInputs{
		ChecksRun:               run,
		AllChecks:               core.CheckNames(),
		ConfidenceLevel:         confidence,
		DisabledDetectionTypes:  disabled,
		Config:                  formatters.ConfigSourceOf(sourcePath, ws.configPath != "", cwd),
		SuppressionRulesEnabled: suppressionRulesInForce(sm),
	})
}

// suppressionRulesInForce counts the rules IsSuppressed can apply: enabled, applied by the loader and
// not expired, in a manager that is itself enabled. The same count as the CLI's helper of that name in
// cmd/stdin.go, which this package cannot import.
func suppressionRulesInForce(sm *suppressions.SuppressionManager) int {
	if sm == nil || !sm.IsEnabled() {
		return 0
	}
	now := time.Now()
	n := 0
	for _, rule := range sm.ListSuppressions() {
		if rule.Enabled && rule.NotApplied == "" && (rule.ExpiresAt == nil || now.Before(*rule.ExpiresAt)) {
			n++
		}
	}
	return n
}
