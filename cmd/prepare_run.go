// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/config"
	"github.com/awslabs/ferret-scan/v2/internal/core"
	"github.com/awslabs/ferret-scan/v2/internal/observability"
	"github.com/awslabs/ferret-scan/v2/internal/precommit"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// The front half of a run: everything between parsing the flags and reading the input.
//
// runStdinScan used to be a hand-kept copy of main()'s front half, and main() handed off to it BEFORE
// the steps the copy did not repeat. Four of them were therefore file-mode only (#887), each measured on
// the same input through --file and --stdin:
//
//	--disable-ip-types t         --file: t's finding gone, a Note   --stdin: nothing removed, no Note
//	--suppression-expires 30d    --file: rules carry expires_at     --stdin: none; "bogus" accepted, rc 0
//	--profile nosuch             --file: rc 1, "not found"          --stdin: scans with the defaults, rc 0
//	--debug                      --file: FERRET_DEBUG exported      --stdin: validators stay silent
//
// and the copy's configFlags literal lacked suppressionExpiresIn, which #699 added to main()'s only: Go
// does not flag a field missing from a keyed literal. #295 and #617 had each patched one such member
// separately. prepareRun is the one front half both paths call, so a step added here reaches both.

// runMode names the input path a run takes, for the few front-half steps that differ between them.
type runMode int

const (
	fileRun runMode = iota
	stdinRun
)

// preparedRun is what the front half settles before either input path reads its input.
type preparedRun struct {
	cfg             *config.Config
	precommitConfig *precommit.PrecommitConfig
	// effectiveProfileName is the profile the run is under: --profile, or the precommit profile a
	// pre-commit environment selects when the config defines one. Empty for none.
	effectiveProfileName string
	activeProfile        *config.Profile
	final                *finalConfiguration
	// generatedExpiry is the lifetime --generate-suppressions gives new rules; the zero value is "never".
	generatedExpiry suppressions.ExpirySpec
	// validatorOverrides carries --disable-ip-types to the validator factory, nil when it is unset.
	validatorOverrides *core.ValidatorOverrides
}

// errRunRefused means prepareRun refused the run and has already said why on stderr. Both callers exit 1.
var errRunRefused = errors.New("run refused by the front half")

// prepareRun loads the configuration, detects pre-commit mode, selects and VALIDATES the profile,
// resolves the final configuration (config, then profile, then flags), parses the redaction strategy and
// the generated-rule expiry, and settles debug mode, for either input path.
//
// A step that can refuse the run prints its error in the pre-commit-aware shape and returns
// errRunRefused. Three steps it calls keep the exits they always had, identically on both paths: an
// unreadable --config, a malformed pre-commit setting and an unknown redaction strategy.
//
// debugObs is the caller's --debug observer, nil when --debug was not passed.
func prepareRun(flags extractedFlags, mode runMode, debugObs *observability.DebugObserver) (*preparedRun, error) {
	run := &preparedRun{cfg: loadConfiguration(flags.configFile)}

	precommitDetector := precommit.NewPrecommitDetectorWithFlag(flags.precommitMode)
	if precommitDetector.IsPrecommitEnvironment() {
		run.precommitConfig = precommitDetector.GetOptimizedConfig()
		refusePrecommitConfigError(precommitDetector)
	}

	// The precommit profile is used automatically in a pre-commit environment when the config defines
	// one and no profile was named.
	run.effectiveProfileName = flags.profileName
	if run.effectiveProfileName == "" && precommitDetector.IsPrecommitEnvironment() {
		suggested := precommitDetector.GetSuggestedProfile()
		if suggested != "" && run.cfg != nil && run.cfg.GetProfile(suggested) != nil {
			run.effectiveProfileName = suggested
		}
	}

	profile, err := selectProfile(run.cfg, run.effectiveProfileName)
	if err != nil {
		var pe *profileError
		if errors.As(err, &pe) {
			printPrecommitError(run.precommitConfig, pe.msg, pe.guidance)
		} else {
			printPrecommitError(run.precommitConfig, err.Error())
		}
		return nil, errRunRefused
	}
	run.activeProfile = profile

	run.final = resolveConfiguration(run.cfg, run.activeProfile, configFlagsFrom(flags, mode, run.effectiveProfileName))

	// A strategy typo is refused here, before the findings table or any redacted bytes are written (#772).
	applyRedactionStrategy(run.final, run.precommitConfig)

	// The expiry is read once, from the value that won the precedence, so a spelling ParseExpirySpec
	// refuses is refused before anything is scanned or written on either path.
	if run.final.suppressionExpiresIn != "" {
		spec, err := suppressions.ParseExpirySpec(run.final.suppressionExpiresIn)
		if err != nil {
			printPrecommitError(run.precommitConfig, err.Error(),
				"Use a number of days (30), days or weeks (30d, 4w), a Go duration (720h), an "+
					"absolute date (2026-12-31), or 'never'")
			return nil, errRunRefused
		}
		run.generatedExpiry = spec
	}

	// FERRET_DEBUG in the environment turns debug mode on, and debug mode exports it, which is what the
	// validators read for their own [DEBUG]/[INFO] lines. Before the shared front half --stdin did
	// neither, so `--stdin --debug` printed none of them.
	if os.Getenv("FERRET_DEBUG") != "" {
		run.final.debug = true
	}
	if run.final.debug {
		// Name the profile that shaped this run, and what it supplied (#768).
		profileObs := debugObs
		if profileObs == nil {
			profileObs = observability.NewDebugObserver(os.Stderr)
		}
		for _, line := range profileDebugRecord(run.cfg, run.effectiveProfileName, flags.profileName, flags.precommitMode) {
			profileObs.LogDetail("profile", line)
		}
		os.Setenv("FERRET_DEBUG", "1")
	}

	run.validatorOverrides = ipTypeOverrides(run.final)
	if run.validatorOverrides != nil && debugObs != nil {
		debugObs.LogDetail("config", fmt.Sprintf("CLI --disable-ip-types: %v", run.validatorOverrides.DisabledIPTypes))
	}
	return run, nil
}

// configFlagsFrom builds the command-line layer resolveConfiguration reads, for either input path.
//
// There used to be two keyed literals, main()'s and the copy in runStdinScan, and #699 added
// suppressionExpiresIn to main()'s alone: nothing flags a field missing from a keyed literal. One builder
// means a field added for one path reaches the other. The --stdin path's deliberate departures follow,
// each with its reason; TestConfigFlagsFromCarriesEveryFlag pins that nothing else differs.
func configFlagsFrom(flags extractedFlags, mode runMode, activeProfileName string) *configFlags {
	cf := &configFlags{
		outputFormat:         flags.outputFormat,
		confidenceLevels:     flags.confidenceLevels,
		checksToRun:          flags.checksToRun,
		verbose:              flags.verbose,
		debug:                flags.debug,
		noColor:              flags.noColor,
		recursive:            flags.recursive,
		enablePreprocessors:  flags.enablePreprocessors,
		preprocessOnly:       flags.preprocessOnly,
		precommitMode:        flags.precommitMode,
		excludePatterns:      flags.excludePatterns,
		respectGitignore:     flags.respectGitignore,
		showMatch:            flags.showMatch,
		quiet:                flags.quiet,
		showSuppressed:       flags.showSuppressed,
		generateSuppressions: flags.generateSuppressions,
		failOnIncomplete:     flags.failOnIncomplete,
		suppressionFile:      flags.suppressionFile,
		suppressionExpiresIn: flags.suppressionExpiresIn,
		enableRedaction:      flags.enableRedaction,
		redactionOutputDir:   flags.redactionOutputDir,
		redactionStrategy:    flags.redactionStrategy,
		redactionAuditLog:    flags.redactionAuditLog,
		disableIPTypes:       flags.disableIPTypes,
		activeProfileName:    activeProfileName,
	}
	if mode == stdinRun {
		// No directory is walked: validateStdinFlags refuses --recursive, and the walk's filters have
		// nothing to filter.
		cf.recursive = false
		cf.excludePatterns = nil
		cf.respectGitignore = false
		// The redacted content goes to stdout, not into a directory, and the audit log needs the on-disk
		// index manager; runStdinScan prints a notice for either flag instead.
		cf.redactionOutputDir = ""
		cf.redactionAuditLog = ""
	}
	return cf
}

// profileError is a --profile that cannot be honoured, with the guidance its message has always carried.
type profileError struct {
	msg      string
	guidance string
}

func (e *profileError) Error() string { return e.msg }

// selectProfile returns the named profile, or an error when one was named and cannot be used. An empty
// name selects none.
//
// It returns the error rather than exiting, as its predecessor handleProfiles did, so that --stdin, which
// returns its exit code to main(), can refuse the run too. It used to call cfg.GetProfile and carry on
// with nil: an unknown --profile scanned with the defaults at rc 0, and a gateway whose profile adds an
// internal-URL pattern passed that URL through in clear when the name was mistyped.
func selectProfile(cfg *config.Config, profileName string) (*config.Profile, error) {
	if profileName == "" {
		return nil, nil
	}
	if cfg == nil {
		return nil, &profileError{
			msg:      fmt.Sprintf("Cannot use profile '%s' - no configuration loaded", profileName),
			guidance: "Check that config file exists and is readable",
		}
	}
	profile := cfg.GetProfile(profileName)
	if profile == nil {
		return nil, &profileError{
			msg:      fmt.Sprintf("Profile '%s' not found in config file", profileName),
			guidance: "Check available profiles with --help or verify config file",
		}
	}
	return profile, nil
}

// ipTypeOverrides turns the resolved --disable-ip-types value into the override both input paths hand
// to the validator factory, or nil when the flag was not given. The list REPLACES the configured set, as
// the flag always has on --file without a profile; see core.ValidatorOverrides for the precedence.
func ipTypeOverrides(final *finalConfiguration) *core.ValidatorOverrides {
	if final.disableIPTypes == "" {
		return nil
	}
	types := []string{}
	for _, t := range strings.Split(final.disableIPTypes, ",") {
		if trimmed := strings.TrimSpace(t); trimmed != "" {
			types = append(types, trimmed)
		}
	}
	return &core.ValidatorOverrides{DisabledIPTypes: types}
}
