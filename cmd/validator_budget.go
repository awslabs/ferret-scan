// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/awslabs/ferret-scan/internal/core"
	"github.com/awslabs/ferret-scan/internal/execguard"
)

// parseValidatorBudgets parses the --validator-budget flag value into a
// per-validator time-budget map keyed by check name (e.g. "SSN"). The format is
// a comma-separated list of NAME=DURATION pairs, where DURATION is any Go
// duration (e.g. "30s", "500ms", "2m"):
//
//	--validator-budget "SSN=30s,IP_ADDRESS=10s"
//
// The special name "all" applies one budget to EVERY validator; specific names
// then override it, so "all=30s,SSN=5s" means 30s for everything except SSN at 5s
// (regardless of the order they appear). This is the one-flag way to bound every
// validator without naming all 13.
//
// An empty/whitespace value yields a nil map (budgets disabled — the scan is
// byte-identical to today). Names are validated against the known check set and
// must be positive durations, so a typo or a stray "0s" is a hard error rather
// than a silently-ignored budget. Returns an error describing the first problem.
func parseValidatorBudgets(spec string) (map[string]execguard.ValidatorBudget, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}

	valid := knownCheckNameSet()
	out := make(map[string]execguard.ValidatorBudget)
	specific := make(map[string]bool) // names set explicitly (not via "all")
	var allDur time.Duration          // >0 once an "all=..." entry is seen

	for _, pair := range strings.Split(spec, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue // tolerate trailing/duplicate commas
		}
		name, durStr, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --validator-budget entry %q: expected NAME=DURATION (e.g. SSN=30s)", pair)
		}
		name = strings.ToUpper(strings.TrimSpace(name))
		durStr = strings.TrimSpace(durStr)

		if name == "" {
			return nil, fmt.Errorf("invalid --validator-budget entry %q: missing check name", pair)
		}
		isAll := name == "ALL"
		if !isAll && !valid[name] {
			return nil, fmt.Errorf("unknown check %q in --validator-budget; valid checks: all, %s",
				name, strings.Join(core.CheckNames(), ", "))
		}

		dur, err := time.ParseDuration(durStr)
		if err != nil {
			return nil, fmt.Errorf("invalid duration %q for %q in --validator-budget: %v", durStr, name, err)
		}
		if dur <= 0 {
			return nil, fmt.Errorf("duration for %q in --validator-budget must be positive, got %q", name, durStr)
		}

		if isAll {
			if allDur > 0 {
				return nil, fmt.Errorf("duplicate \"all\" entry in --validator-budget")
			}
			allDur = dur
			continue
		}
		if specific[name] {
			return nil, fmt.Errorf("duplicate check %q in --validator-budget", name)
		}
		specific[name] = true
		out[name] = execguard.ValidatorBudget{TimeLimit: dur}
	}

	// Expand "all" to every known check, but never clobber an explicit per-name
	// budget (specific overrides the wildcard).
	if allDur > 0 {
		for name := range valid {
			if !specific[name] {
				out[name] = execguard.ValidatorBudget{TimeLimit: allDur}
			}
		}
	}

	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// knownCheckNameSet returns the set of valid check names for O(1) membership
// tests, upper-cased to match the flag's normalization.
func knownCheckNameSet() map[string]bool {
	names := core.CheckNames()
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[strings.ToUpper(n)] = true
	}
	return set
}

// sortedBudgetNames returns the budgeted check names in stable order, for
// deterministic log/debug output.
func sortedBudgetNames(budgets map[string]execguard.ValidatorBudget) []string {
	names := make([]string, 0, len(budgets))
	for n := range budgets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
