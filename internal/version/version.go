// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"runtime"
)

// Version information set by semantic-release
var (
	// Version is the current version of ferret-scan
	Version = "0.0.0-development"

	// GitCommit is the git commit hash
	GitCommit = "unknown"

	// BuildDate is when the binary was built
	BuildDate = "unknown"

	// GoVersion is the version of Go used to build
	GoVersion = runtime.Version()

	// Platform is the OS/Arch combination
	Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
)

// Info returns formatted version information
func Info() string {
	return fmt.Sprintf("ferret-scan %s (commit: %s, built: %s, go: %s, platform: %s)",
		Version, GitCommit, BuildDate, GoVersion, Platform)
}

// Short returns just the version number
func Short() string {
	return Version
}

// Full returns detailed version information
func Full() map[string]string {
	return map[string]string{
		"version":   Version,
		"commit":    GitCommit,
		"buildDate": BuildDate,
		"goVersion": GoVersion,
		"platform":  Platform,
	}
}
