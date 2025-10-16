// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package platform

import (
	"runtime"
)

// Platform defines the interface for platform-specific operations
type Platform interface {
	GetConfigDir() string
	GetTempDir() string
	GetExecutableExtension() string
	IsAbsolutePath(path string) bool
	NormalizePath(path string) string
	GetSystemInstallDir() string
	GetUserInstallDir() string
	GetPathSeparator() string
	SupportsCaseSensitivePaths() bool
	SupportsSymlinks() bool
}

// Config holds platform-specific configuration
type Config struct {
	OS                     string `json:"os"`
	Architecture           string `json:"architecture"`
	ConfigDirectory        string `json:"config_directory"`
	TempDirectory          string `json:"temp_directory"`
	ExecutableExtension    string `json:"executable_extension"`
	PathSeparator          string `json:"path_separator"`
	SupportsSymlinks       bool   `json:"supports_symlinks"`
	CaseSensitivePaths     bool   `json:"case_sensitive_paths"`
	SystemInstallDirectory string `json:"system_install_directory"`
	UserInstallDirectory   string `json:"user_install_directory"`
}

// GetPlatform returns the appropriate platform implementation for the current OS
func GetPlatform() Platform {
	switch runtime.GOOS {
	case "windows":
		return &WindowsPlatform{}
	default:
		return &UnixPlatform{}
	}
}

// GetConfig returns platform configuration for the current system
func GetConfig() *Config {
	platform := GetPlatform()
	return &Config{
		OS:                     runtime.GOOS,
		Architecture:           runtime.GOARCH,
		ConfigDirectory:        platform.GetConfigDir(),
		TempDirectory:          platform.GetTempDir(),
		ExecutableExtension:    platform.GetExecutableExtension(),
		PathSeparator:          platform.GetPathSeparator(),
		SupportsSymlinks:       platform.SupportsSymlinks(),
		CaseSensitivePaths:     platform.SupportsCaseSensitivePaths(),
		SystemInstallDirectory: platform.GetSystemInstallDir(),
		UserInstallDirectory:   platform.GetUserInstallDir(),
	}
}

// IsWindows returns true if running on Windows
func IsWindows() bool {
	return runtime.GOOS == "windows"
}

// IsUnix returns true if running on Unix-like systems (Linux, macOS, etc.)
func IsUnix() bool {
	return !IsWindows()
}
