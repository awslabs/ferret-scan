// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

// ValidatorConfigKeysForTest exposes the key declaration to the external test package config_test,
// which builds the validators (so it cannot be package config) to check that EVERY declared key reports
// a value it cannot use.
var ValidatorConfigKeysForTest = validatorConfigKeys
