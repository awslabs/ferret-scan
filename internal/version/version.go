// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package version

import (
	"fmt"
	"runtime"
)

// Project identity that is fixed at author time rather than build time.
const (
	// RepositoryURL is the canonical upstream repository, and the single source of
	// truth for it. Report formats that name where the analyzer came from MUST derive
	// it from here rather than repeating the literal: SARIF and GitLab SAST once
	// disagreed about the origin of this scanner because each carried its own copy,
	// and a consumer comparing two reports of the same scan had no way to tell which
	// was lying.
	RepositoryURL = "https://github.com/awslabs/ferret-scan"

	// IssuesURL is where users are told to report problems.
	IssuesURL = RepositoryURL + "/issues"
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
