// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/awslabs/ferret-scan/v2/internal/execguard"
	"github.com/awslabs/ferret-scan/v2/internal/web"
)

// webScanOptions turns the CLI scan flags --web applies (#925: --profile, --disable-ip-types,
// --validator-budget, --debug) into the server's options. The rest of the scan flags are either
// equivalent in the page (the web inventory's webEquivalent) or refused by validateWebModeFlags.
func webScanOptions(flags extractedFlags, budgets map[string]execguard.ValidatorBudget) web.ScanOptions {
	o := web.ScanOptions{ProfileName: flags.profileName, ValidatorBudgets: budgets, Debug: flags.debug}
	if flags.disableIPTypes != "" {
		o.DisableIPTypes = ipTypeOverrides(&finalConfiguration{disableIPTypes: flags.disableIPTypes}).DisabledIPTypes
	}
	if flags.debug {
		// The validators' own [DEBUG] lines are gated on this, as prepareRun sets it for a CLI run.
		os.Setenv("FERRET_DEBUG", "1")
	}
	return o
}
