// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package redact

import "github.com/awslabs/ferret-scan/v2/internal/redactors"

// SeedSyntheticScopeForTest makes every Redact call of e draw synthetic values from one seeded scope.
// It exists only in this package's test binary, so no shipped code can seed an Engine (#1070).
func SeedSyntheticScopeForTest(e *Engine, seed []byte) {
	e.syntheticScope = redactors.NewSeededSyntheticScope(seed)
}
