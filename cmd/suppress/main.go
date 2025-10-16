// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"flag"
	"fmt"
	"os"

	"ferret-scan/internal/suppressions"
)

func main() {
	var (
		suppressionFile = flag.String("suppression-file", "", "Path to suppression configuration file (default: .ferret-scan-suppressions.yaml)")
		action          = flag.String("action", "", "Action to perform: list, remove, cleanup, enable")
		id              = flag.String("id", "", "Suppression rule ID (for remove action)")
		hash            = flag.String("hash", "", "Finding hash (for enable action)")
		reason          = flag.String("reason", "", "Reason for suppression (for enable action)")
	)
	flag.Parse()

	if *action == "" {
		fmt.Println("Error: --action is required")
		fmt.Println("Usage: ferret-suppress --action <list|remove|cleanup|enable> [options]")
		os.Exit(1)
	}

	manager := suppressions.NewSuppressionManager(*suppressionFile)

	switch *action {
	case "list":
		listSuppressions(manager)
	case "remove":
		if *id == "" {
			fmt.Println("Error: --id is required for remove action")
			os.Exit(1)
		}
		removeSuppression(manager, *id)
	case "cleanup":
		cleanupExpired(manager)
	case "enable":
		if *hash == "" {
			fmt.Println("Error: --hash is required for enable action")
			os.Exit(1)
		}
		enableSuppression(manager, *hash, *reason)
	default:
		fmt.Printf("Error: Unknown action '%s'\n", *action)
		fmt.Println("Valid actions: list, remove, cleanup, enable")
		os.Exit(1)
	}
}

func listSuppressions(manager *suppressions.SuppressionManager) {
	rules := manager.ListSuppressions()
	if len(rules) == 0 {
		fmt.Println("No suppression rules found.")
		return
	}

	fmt.Printf("Found %d suppression rules:\n\n", len(rules))
	for _, rule := range rules {
		fmt.Printf("ID: %s\n", rule.ID)
		fmt.Printf("Hash: %s\n", rule.Hash)
		fmt.Printf("Reason: %s\n", rule.Reason)
		if rule.CreatedBy != "" {
			fmt.Printf("Created By: %s\n", rule.CreatedBy)
		}
		fmt.Printf("Created At: %s\n", rule.CreatedAt.Format("2006-01-02 15:04:05"))
		if rule.ExpiresAt != nil {
			fmt.Printf("Expires At: %s\n", rule.ExpiresAt.Format("2006-01-02 15:04:05"))
		}
		if len(rule.Metadata) > 0 {
			fmt.Println("Metadata:")
			for k, v := range rule.Metadata {
				fmt.Printf("  %s: %s\n", k, v)
			}
		}
		fmt.Println("---")
	}
}

func removeSuppression(manager *suppressions.SuppressionManager, id string) {
	err := manager.RemoveSuppression(id)
	if err != nil {
		fmt.Printf("Error removing suppression: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully removed suppression rule: %s\n", id)
}

func cleanupExpired(manager *suppressions.SuppressionManager) {
	removed := manager.CleanupExpired()
	fmt.Printf("Cleaned up %d expired suppression rules\n", removed)
}

func enableSuppression(manager *suppressions.SuppressionManager, hash, reason string) {
	err := manager.EnableSuppressionByHash(hash, reason)
	if err != nil {
		fmt.Printf("Error enabling suppression: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Successfully enabled suppression for hash: %s\n", hash[:8])
}
