// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/formatters"
	"github.com/awslabs/ferret-scan/v2/internal/precommit"
)

// runCheckConfig answers --check-config (#1086): it resolves the configuration the way a scan would,
// builds every validator from it, scans nothing, and writes what it found to w, one fact per line, then
// a summary line. It returns the exit code: 0 when everything configured took effect, 1 when anything
// did not.
//
// The pre-commit refusal of a config discovered in the working directory (#293) does NOT apply here,
// and PRE_COMMIT=1 changes nothing about the output: an explicit request to read the file is not a
// scan, and the point of the command is to let a hook author see what the hook would refuse before the
// first commit does. The refusal is reported as a line instead.
//
// The loader is not loadConfiguration: that one exits on an unreadable --config and falls back to the
// built-in defaults, with a stderr warning, on a discovered file it cannot parse. Both would hide what
// this command exists to show, so a load failure is printed verbatim to w and is a problem.
func runCheckConfig(w io.Writer, flags extractedFlags) int {
	problems := 0
	explicit := flags.configFile != ""

	var cfg *config.Config
	var err error
	if explicit {
		cfg, err = config.LoadConfigStrict(flags.configFile)
	} else {
		cfg, err = config.LoadConfig(config.FindConfigFile())
	}
	if err != nil {
		where := flags.configFile
		if !explicit {
			where = config.FindConfigFile()
		}
		fmt.Fprintf(w, "config: %s\n", where)
		fmt.Fprintf(w, "config load failed: %v\n", err)
		fmt.Fprintln(w, "config check: 1 problem(s)")
		return 1
	}

	fmt.Fprintf(w, "config: %s\n", configInUse(cfg, explicit))

	for _, key := range cfg.UnknownKeys {
		problems++
		fmt.Fprintf(w, "Warning: unknown config key %q — ignored (check for a typo)\n", key)
	}

	// The profile a scan would run under: --profile, else the built-in precommit when pre-commit mode
	// applies (prepareRun's rule), else none. A named profile that does not exist is a refused scan.
	precommitMode := precommit.NewPrecommitDetectorWithFlag(flags.precommitMode).IsPrecommitEnvironment()
	profileName := flags.profileName
	if profileName == "" && precommitMode {
		profileName = "precommit"
	}
	profile := (*config.Profile)(nil)
	if profileName != "" {
		profile = cfg.GetProfile(profileName)
	}

	// Every validator, not only the --checks a scan would narrow to: the command reports the whole
	// configuration, and a pattern for a check that is off today is still a pattern that will not work.
	set := core.BuildValidatorSet(parseChecksToRun(""), cfg, profile)
	disabled, unrecognised := collectDisabledDetectionTypes(set)
	reportDisabledDetectionTypes(w, disabled, unrecognised, false)
	for _, subTypes := range unrecognised {
		problems += len(subTypes)
	}
	warnings := core.ConfigWarnings(set)
	writeConfigValueWarnings(w, warnings)
	problems += len(warnings)

	switch {
	case profileName == "":
		fmt.Fprintln(w, "profile: none")
	case profile == nil:
		problems++
		fmt.Fprintf(w, "profile: %s not found in %s; a scan with it is refused\n", profileName, configSourceLabel(cfg))
	case cfg.BuiltinProfile(profileName) != nil:
		fmt.Fprintf(w, "profile: %s (built-in%s)\n", profileName, profileWhy(flags.profileName))
	default:
		fmt.Fprintf(w, "profile: %s (defined in the config%s)\n", profileName, profileWhy(flags.profileName))
	}

	if rel, found := workingDirectoryConfig(cfg, flags.configFile); found {
		fmt.Fprintf(w, "pre-commit: %s was found in the working directory; in pre-commit mode it is refused "+
			"unless --allow-project-config is passed or it is named with --config (#293)\n", rel)
	}

	if problems == 0 {
		fmt.Fprintln(w, "config check: OK")
		return 0
	}
	fmt.Fprintf(w, "config check: %d problem(s)\n", problems)
	return 1
}

// profileWhy says why a profile applies when --profile did not name it.
func profileWhy(named string) string {
	if named != "" {
		return ""
	}
	return ", selected because this is a pre-commit run"
}

// configInUse names the file the run would read and where it came from, with the same classification
// the report's scope block uses (formatters.ConfigSourceOf).
func configInUse(cfg *config.Config, explicit bool) string {
	cwd, _ := os.Getwd()
	switch formatters.ConfigSourceOf(cfg.SourcePath, explicit, cwd).Source {
	case formatters.ConfigSourceExplicit:
		return cfg.SourcePath + " (--config)"
	case formatters.ConfigSourceWorkingDirectory:
		rel, _ := workingDirectoryConfig(cfg, "")
		return rel + " (working directory)"
	case formatters.ConfigSourceUserConfigDir:
		return cfg.SourcePath + " (user config dir)"
	}
	return "none found (built-in defaults)"
}
