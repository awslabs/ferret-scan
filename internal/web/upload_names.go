// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"path/filepath"
	"strings"

	"github.com/awslabs/ferret-scan/v2/internal/detector"
	"github.com/awslabs/ferret-scan/v2/internal/suppressions"
)

// memberSeparator joins a container and the embedded attachment a finding came from, as the
// preprocessors write it (RouterIntegrationHelper.CreateEmbeddedMediaPath: "deck.pptx -> image3.png")
// and as the CLI prints it.
const memberSeparator = " -> "

// uploadMatchName is the name /scan gives a match: the upload's name in place of the temp file the
// scan read, with the member of an embedded attachment kept.
//
// The scan reads a temp copy of the upload, so a finding in the upload's own content is named by the
// temp path, and a finding inside an attachment by "<temp file's base name> -> <member>". Every match
// used to be renamed to the upload alone, which dropped the member: on the 639 public corpus files, 90
// findings in 4 uploads lost which attachment held them, and two attachments carrying the same value
// shared one key in the UI's suppression panel (app.js generateFindingHash: filename, type, line and
// text), so suppressing one removed both.
//
// The member is also part of the suppression identity, which folds in filepath.Base of the name. The
// CLI hashes "deck.pptx -> image3.png", so a rule it generated for such a finding never matched the
// web's "deck.pptx", and a rule created in the web UI never matched on the CLI (#924). The upload's
// name stays raw, for the reason the caller keeps it raw (#866).
func uploadMatchName(scanned, tempPath, upload string) string {
	for _, prefix := range []string{tempPath, filepath.Base(tempPath)} {
		if member, ok := strings.CutPrefix(scanned, prefix+memberSeparator); ok && member != "" {
			return upload + memberSeparator + member
		}
	}
	return upload
}

// suppressedUnderUploadName is IsSuppressed for a /scan match, which also honours the identity a
// finding inside an attachment had before it kept its member: the upload's name alone.
//
// A rule created in the web UI before #924 hashed such a finding under that name. internal/suppressions
// keeps every older hash formula matching, because a rule file is a record of decisions already made,
// and this keeps the older NAME matching for the same reason: such a rule suppresses what it
// suppressed before, while a rule written for the member's name, by the CLI or by the web UI now,
// matches that one attachment. A finding named by the upload alone has no older identity to try.
func suppressedUnderUploadName(mgr *suppressions.SuppressionManager, match detector.Match, upload string) (bool, *suppressions.SuppressionRule) {
	if ok, rule := mgr.IsSuppressed(match); ok || match.Filename == upload {
		return ok, rule
	}
	legacy := match
	legacy.Filename = upload
	return mgr.IsSuppressed(legacy)
}
