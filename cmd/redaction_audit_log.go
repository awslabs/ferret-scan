// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"

	"github.com/awslabs/ferret-scan/v2/internal/precommit"
)

// auditLogExporter is the one method of *redactors.RedactionManager the export needs, so a test can
// supply an exporter that fails the way validation does.
type auditLogExporter interface {
	ExportAuditLog(path string) error
}

// exportRedactionAuditLog writes the --redaction-audit-log file (or the redaction.index_file /
// audit_log_file config key), and treats a failure as the run's failure: it prints an error and returns
// it, and the caller exits 1, as it does for an --output that cannot be written.
//
// It used to print `Warning: Failed to export redaction audit log: …` and carry on to exit 0 (#865), in
// every mode: measured with --redaction-audit-log /dev/null/audit.json, rc 0 plain, rc 0 under
// --fail-on-incomplete, and rc 1 under --pre-commit-mode only because the findings blocked the commit.
// The log is the compliance record of what was redacted, so a run that was asked for one and produced
// none did not do what it was asked. ExportAuditLog also fails, writing nothing, when an entry does not
// validate; that reached the same warning, which is how a one-line change to a confidence scale could
// drop the whole log at exit 0.
func exportRedactionAuditLog(rm auditLogExporter, path string, quiet bool, precommitConfig *precommit.PrecommitConfig) error {
	if err := rm.ExportAuditLog(path); err != nil {
		printPrecommitError(precommitConfig,
			fmt.Sprintf("Failed to export redaction audit log: %v", err),
			"Check that the audit log's directory exists and is writable; redacted files already written are left in place")
		return err
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "Redaction audit log exported to: %s\n", path)
	}
	return nil
}
