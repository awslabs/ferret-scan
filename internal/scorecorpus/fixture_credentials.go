// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package scorecorpus

// Credential-shaped fixture values, assembled at runtime rather than written as
// literals.
//
// A secret scanner's corpus has to contain things that look exactly like live
// credentials — that is the whole point of a SECRETS case. But a literal
// `ghp_...` in a committed .go file trips every scanner pointed at this
// repository, including our own pre-commit hook and GitHub's push protection,
// which BLOCKS the push outright. The repository already solved this for tests
// (see buildTestToken in internal/validators/secrets), and this is the same
// convention for non-test source.
//
// Splitting the prefix from the body defeats the pattern match without changing a
// single byte of what the validator sees: the concatenation happens at init, so
// the scanner under test receives the identical string it would have received
// from a literal. TestFixtureCredentialsAreWellFormed proves the assembly did not
// silently produce something the validator no longer recognises.
//
// None of these are real. They are shape-valid and structurally inert.
const (
	// fakeGitHubToken is a shape-valid GitHub personal access token: the `ghp_`
	// prefix plus 36 base62 characters.
	fakeGitHubToken = "ghp_" + "16C7e42F292c6912E7710c838347Ae178B4a"

	// fakeAWSAccessKeyID is AWS's own documentation example key. It is published in
	// public AWS docs, so it is deliberately NOT split — a scanner flagging it is
	// finding a value that is already public, and the corpus needs it recorded as
	// the reserved-example case it is (it scores MEDIUM, not HIGH, which is the
	// behavior worth pinning).
	fakeAWSAccessKeyID = "AKIAIOSFODNN7EXAMPLE"
)
