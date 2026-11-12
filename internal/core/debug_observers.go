// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"io"

	"github.com/awslabs/ferret-scan/v2/internal/detector"

	"github.com/awslabs/ferret-scan/v2/internal/observability"
)

// attachDebugObservers gives each validator its own debug observer when debug is on, as the CLI's --file
// path does for its validators (cmd/main.go, "Set up observability for all components").
//
// ScanFile and ScanContent built their validators and never called SetObserver on them, so a validator's
// own debug lines (the intellectual-property validator's legal-notice summary, the per-validator
// validate_content records) were never written: `--stdin --debug` printed none of the [DEBUG] lines
// `--file --debug` prints (#887). With debug off nothing is attached, so a non-debug scan is unchanged.
func attachDebugObservers(vs map[string]detector.Validator, debug bool, logWriter io.Writer) {
	if !debug {
		return
	}
	for _, v := range vs {
		if ov, ok := v.(interface {
			SetObserver(observer observability.Observer)
		}); ok {
			debugObs := observability.NewDebugObserver(logWriter)
			observer := debugObs.StandardObserver
			observer.DebugObserver = debugObs
			ov.SetObserver(observer)
		}
	}
}
