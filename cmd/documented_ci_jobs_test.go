// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #575 was the same defect class as #503 (see documented_flags_test.go), one layer out:
// docs/deployment/GITLAB_CI_SETUP.md documented a pipeline by inventory — a `#### `job-name`` heading
// per job, with a bullet list of what each did. Eighteen of its nineteen sections named a job that has
// never existed in .gitlab-ci.yml, and every real job went unmentioned. A reader debugging a red
// pipeline had no way to tell a job that had been renamed from one that was never written.
//
// The durable fix was to stop restating the file: that page now points at .gitlab-ci.yml and describes
// only what the file cannot say for itself. This guard exists so the inventory cannot creep back —
// a job-name heading in the deployment docs is a factual claim, and it is now checked.
//
// The doc tree deliberately contains no such claims today, so the walk below has nothing to reject.
// That makes TestJobClaimExtractionWorks the load-bearing test: it runs the extractor against
// synthetic markdown, so a regex that silently stopped matching cannot masquerade as a clean tree.

const (
	ciConfigPath       = "../.gitlab-ci.yml"
	deploymentDocsRoot = "../docs/deployment"
)

// jobClaimRe matches a markdown heading whose entire text is one backticked token, e.g.
//
//	#### `docker:build`
//
// That is the shape the #575 inventory used, and it is unambiguous: a heading naming a single
// code-formatted identifier in a CI setup document is asserting that identifier is a pipeline job.
var jobClaimRe = regexp.MustCompile("(?m)^#{2,5}[ \t]+`([A-Za-z0-9_][A-Za-z0-9_.:-]*)`[ \t]*$")

// ciReservedKeys are top-level .gitlab-ci.yml keys that configure the pipeline rather than define a
// job, so they are not valid targets for a job-name claim.
var ciReservedKeys = map[string]bool{
	"variables": true, "stages": true, "cache": true, "include": true, "default": true,
	"workflow": true, "image": true, "services": true, "before_script": true,
	"after_script": true, "script": true,
}

// templateProvidedJobs are jobs this pipeline gets from an included GitLab template rather than
// declaring itself. They are real, but they are not top-level keys in our file, and which of them
// materialise depends on the GitLab tier. A doc may name these; keep the list honest by only adding
// a name whose template is actually in the `include:` block.
var templateProvidedJobs = map[string]bool{
	"secret_detection":              true, // Security/Secret-Detection.gitlab-ci.yml
	"semgrep-sast":                  true, // Security/SAST.gitlab-ci.yml
	"dependency_scanning":           true, // Security/Dependency-Scanning.gitlab-ci.yml
	"gemnasium-dependency_scanning": true,
}

// realCIJobs returns the job names declared as top-level keys in .gitlab-ci.yml.
func realCIJobs(t *testing.T) map[string]bool {
	t.Helper()

	raw, err := os.ReadFile(ciConfigPath) // #nosec G304 -- the repo's own CI config at a fixed path
	if err != nil {
		t.Fatalf("read %s: %v", ciConfigPath, err)
	}

	// A job is a top-level mapping key: column 0, not a comment, not a list item. Hidden templates
	// (".build") are excluded because a doc naming one is documenting a template, not a job.
	keyRe := regexp.MustCompile(`(?m)^([A-Za-z0-9_][A-Za-z0-9_.:-]*):`)
	jobs := map[string]bool{}
	for _, m := range keyRe.FindAllStringSubmatch(string(raw), -1) {
		if name := m[1]; !ciReservedKeys[name] {
			jobs[name] = true
		}
	}
	return jobs
}

// deploymentDocClaims maps each deployment document to the job names it claims exist.
func deploymentDocClaims(t *testing.T) map[string][]string {
	t.Helper()

	claims := map[string][]string{}
	var walked int
	err := filepath.WalkDir(deploymentDocsRoot, func(path string, d os.DirEntry, err error) error {
		// A sibling guard (documented_env_vars_test.go) fails intermittently under `go test ./...`
		// because four internal/router tests create scratch directories with os.MkdirTemp(".", …)
		// inside the repo tree and remove them mid-walk, so a concurrent walk sees a path that has
		// just vanished. Tolerating that here is safe rather than silencing a real problem: if the
		// root itself is missing, nothing is walked and the walked == 0 check below fails loudly.
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		walked++

		raw, readErr := os.ReadFile(path) // #nosec G304 -- a markdown file inside the repo's docs tree
		if readErr != nil {
			return readErr
		}
		rel := filepath.ToSlash(path)
		for _, m := range jobClaimRe.FindAllStringSubmatch(string(raw), -1) {
			claims[rel] = append(claims[rel], m[1])
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", deploymentDocsRoot, err)
	}
	if walked == 0 {
		t.Fatalf("walked no markdown files under %s; the deployment docs tree has moved", deploymentDocsRoot)
	}
	return claims
}

// TestCIConfigParseFindsRealJobs is the non-vacuity guard for the .gitlab-ci.yml side. If the key
// regex stopped matching, every claim below would be reported as fiction instead of being checked.
func TestCIConfigParseFindsRealJobs(t *testing.T) {
	jobs := realCIJobs(t)

	if len(jobs) < 5 {
		names := make([]string, 0, len(jobs))
		for n := range jobs {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Fatalf("parsed only %d job(s) from %s (%s); the top-level key regex has stopped matching",
			len(jobs), ciConfigPath, strings.Join(names, " "))
	}
	if !jobs["build"] {
		t.Errorf("parsed %d jobs from %s but not the `build` job, which is the one job every "+
			"revision of this pipeline has had", len(jobs), ciConfigPath)
	}
}

// TestJobClaimExtractionWorks proves the extractor recognises the inventory shape #575 used, and
// ignores the prose shapes a correct document uses. Without this, the walk in
// TestDeploymentDocsClaimOnlyRealCIJobs would pass vacuously on a tree with no claims in it.
func TestJobClaimExtractionWorks(t *testing.T) {
	cases := []struct {
		name string
		md   string
		want []string
	}{
		{
			name: "the #575 inventory shape is a claim",
			md:   "## Job Details\n\n#### `docker:build`\n- Builds an image\n\n#### `test:unit`\n- Fast tests\n",
			want: []string{"docker:build", "test:unit"},
		},
		{
			name: "a backticked filename in prose is not a claim",
			md:   "Read `.gitlab-ci.yml` to see what runs. The `build` job is declared there.\n",
			want: nil,
		},
		{
			name: "a heading with prose around the token is not a claim",
			md:   "### The `build` job\n\nIt compiles.\n",
			want: nil,
		},
		{
			name: "a table row naming a job is not a heading claim",
			md:   "| Job | Note |\n|---|---|\n| `pages` | absent |\n",
			want: nil,
		},
		{
			name: "an unbackticked heading is not a claim",
			md:   "#### Multi-version Testing\n\n- test:go-1.24\n",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, m := range jobClaimRe.FindAllStringSubmatch(tc.md, -1) {
				got = append(got, m[1])
			}
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("extracted %v, want %v", got, tc.want)
			}
		})
	}
}

// TestDeploymentDocsClaimOnlyRealCIJobs is the regression guard for #575.
func TestDeploymentDocsClaimOnlyRealCIJobs(t *testing.T) {
	real := realCIJobs(t)
	claims := deploymentDocClaims(t)

	for doc, names := range claims {
		var absent []string
		for _, n := range names {
			if !real[n] && !templateProvidedJobs[n] {
				absent = append(absent, n)
			}
		}
		if len(absent) == 0 {
			continue
		}
		sort.Strings(absent)
		t.Errorf("%s documents %d job(s) that do not exist in %s: %s\n"+
			"A `#### `name`` heading asserts that `name` is a job in the pipeline. Either the job was "+
			"renamed or removed and this section should go, or it is a template-provided job that "+
			"belongs in templateProvidedJobs with its template named. Do not document a pipeline by "+
			"inventory — see the comment at the top of this file (#575).",
			doc, len(absent), ciConfigPath, strings.Join(absent, " "))
	}
}
