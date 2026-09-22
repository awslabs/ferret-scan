// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package gitignore provides opt-in .gitignore support for ferret-scan.
//
// When enabled, the scanner honors .gitignore files found from the scan root
// up to the filesystem root, plus .git/info/exclude and the user's global
// git excludesfile (core.excludesFile). The .git directory is always skipped.
//
// Note: .gitignore often excludes files that are high-value for secret scanning
// (e.g. .env, *.pem, credentials/). This package is intentionally opt-in so
// that behavior is surfaced by the caller, not hidden by default.
package gitignore

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
	"strings"

	gi "github.com/sabhiram/go-gitignore"
)

// Matcher evaluates paths against one or more .gitignore rule sets.
// A nil Matcher matches nothing (safe zero value).
type Matcher struct {
	// root is the absolute, cleaned path used to compute repo-relative paths
	// for matching. Patterns in .gitignore are evaluated relative to this.
	root       string
	ignorers   []scopedIgnorer
	enabled    bool
	skipDotGit bool
}

// scopedIgnorer pairs a compiled gitignore with the directory it applies to.
// Nested .gitignore files must only affect files within their own subtree.
// If dir is empty the ignorer is treated as global (used for the global
// excludes file).
type scopedIgnorer struct {
	dir    string // absolute directory the rules are scoped to; "" = global
	ignore *gi.GitIgnore
}

// Option configures Matcher construction.
type Option func(*Matcher)

// WithGlobalExcludes loads the user's global git excludesfile if present.
// Looks at $XDG_CONFIG_HOME/git/ignore, then ~/.config/git/ignore.
// (We deliberately do not shell out to `git config core.excludesFile` to avoid
// a hard dependency on the git binary; this covers the common case.)
func WithGlobalExcludes() Option {
	return func(m *Matcher) {
		for _, p := range globalExcludesPaths() {
			if fileExists(p) {
				if ign, err := gi.CompileIgnoreFile(p); err == nil {
					// Global excludes apply everywhere.
					m.ignorers = append(m.ignorers, scopedIgnorer{dir: "", ignore: ign})
				}
			}
		}
	}
}

// New builds a Matcher rooted at the given directory. It walks up the tree
// collecting .gitignore files, and also loads .git/info/exclude if present.
// If root is a file, its parent directory is used.
//
// Returns a disabled Matcher (Match always returns false) if no rules are found.
func New(root string, opts ...Option) (*Matcher, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(abs)
	if err == nil && !info.IsDir() {
		abs = filepath.Dir(abs)
	}

	m := &Matcher{
		root:       filepath.Clean(abs),
		skipDotGit: true,
	}

	// Walk up from root collecting .gitignore files. We load root-most first
	// so closer (more specific) rules are evaluated last and win.
	var dirs []string
	cur := m.root
	for {
		dirs = append(dirs, cur)
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	// Reverse: filesystem-root first, scan-root last.
	for i, j := 0, len(dirs)-1; i < j; i, j = i+1, j-1 {
		dirs[i], dirs[j] = dirs[j], dirs[i]
	}
	for _, d := range dirs {
		gitignorePath := filepath.Join(d, ".gitignore")
		if fileExists(gitignorePath) {
			if ign, err := gi.CompileIgnoreFile(gitignorePath); err == nil {
				m.ignorers = append(m.ignorers, scopedIgnorer{dir: d, ignore: ign})
			}
		}
	}

	// Also collect nested .gitignore files inside the scan root. Without this,
	// rules in subdirectory .gitignore files would be ignored (they live below
	// the root so the upward walk above never sees them). We pre-walk the tree
	// once so Match can stay stateless. This is cheap compared to the actual
	// scan: we only look for .gitignore files and skip common large dirs.
	_ = filepath.WalkDir(m.root, func(p string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // best-effort; skip unreadable paths
		}
		if d.IsDir() {
			name := d.Name()
			// Skip cost centers that never need their own gitignore parsed.
			if p != m.root && (name == ".git" || name == "node_modules") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() != ".gitignore" {
			return nil
		}
		// Skip the root-level .gitignore we already loaded above.
		dir := filepath.Dir(p)
		if dir == m.root {
			return nil
		}
		if ign, err := gi.CompileIgnoreFile(p); err == nil {
			m.ignorers = append(m.ignorers, scopedIgnorer{dir: dir, ignore: ign})
		}
		return nil
	})

	// info/exclude belongs to the nearest repository walking up from root. That
	// repository is marked by .git as a directory or as a `gitdir:` FILE (worktree,
	// submodule); see findGitInfoExclude for where each form keeps the file.
	if infoExclude, gitRoot := findGitInfoExclude(m.root); infoExclude != "" {
		if ign, err := gi.CompileIgnoreFile(infoExclude); err == nil {
			m.ignorers = append(m.ignorers, scopedIgnorer{dir: gitRoot, ignore: ign})
		}
	}

	for _, opt := range opts {
		opt(m)
	}

	m.enabled = len(m.ignorers) > 0 || m.skipDotGit
	return m, nil
}

// Enabled reports whether the matcher has any rules loaded. When false,
// Match always returns false.
func (m *Matcher) Enabled() bool {
	if m == nil {
		return false
	}
	return m.enabled
}

// Match reports whether the given path is ignored. The path may be absolute
// or relative; if relative, it is resolved against the scan root used at
// construction time.
//
// Match always returns true for paths inside a .git directory (so callers
// can safely skip them without adding .git to their exclude patterns).
func (m *Matcher) Match(path string) bool {
	if m == nil || !m.enabled {
		return false
	}

	abs := path
	if !filepath.IsAbs(path) {
		abs = filepath.Join(m.root, path)
	}
	abs = filepath.Clean(abs)

	if m.skipDotGit && containsGitDir(abs) {
		return true
	}

	// Evaluate ignorers in order. Later (more-specific, deeper) rules override
	// earlier ones, matching git's behavior. We return the final decision.
	ignored := false
	for _, s := range m.ignorers {
		// Scope: a non-global ignorer only applies to paths inside its dir.
		var rel string
		if s.dir == "" {
			// Global: evaluate against path relative to scan root.
			r, err := filepath.Rel(m.root, abs)
			if err != nil || strings.HasPrefix(r, "..") {
				continue
			}
			rel = r
		} else {
			r, err := filepath.Rel(s.dir, abs)
			if err != nil || strings.HasPrefix(r, "..") || r == "." {
				continue
			}
			rel = r
		}

		rel = filepath.ToSlash(rel)
		if s.ignore.MatchesPath(rel) {
			// Negation (e.g. !keep.log) works correctly within a single
			// .gitignore file — the sabhiram library handles it internally.
			// Cross-file negation is NOT supported: if parent/.gitignore
			// ignores *.log and child/.gitignore has !keep.log, the parent
			// rule still wins because each ignorer is evaluated independently.
			// This matches the most common usage; true cross-file negation
			// would require a single merged rule set which the library
			// doesn't support.
			ignored = true
		}
	}
	return ignored
}

// --- helpers ---

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func containsGitDir(abs string) bool {
	parts := strings.Split(filepath.ToSlash(abs), "/")
	for _, p := range parts {
		if p == ".git" {
			return true
		}
	}
	return false
}

// findGitInfoExclude walks up from start looking for a repository, and returns
// (path, repoRoot) for its info/exclude if that file exists. The returned repoRoot is
// the directory holding .git — the worktree the rules are scoped to, never the
// directory the rules were READ from, which for a worktree or submodule is elsewhere.
//
// A repository is marked by .git being a directory OR A FILE. The file form holds a
// `gitdir:` pointer and is what `git worktree add` and `git submodule add` write; this
// helper previously required a directory, so both forms walked straight PAST their own
// repository root. Two measured outcomes, neither of them "no rules, no harm":
//
//   - Not nested in another repository: the walk reached the filesystem root and
//     returned nothing, so a file the user excluded was scanned.
//   - Nested (the normal case for a submodule, and for a worktree placed beside its
//     main checkout): the walk found the OUTER repository's .git and applied an
//     unrelated project's exclude rules to this one.
//
// Where the rules live, measured with `git check-ignore -v` on git 2.x:
//
//	submodule   .git file "gitdir: ../.git/modules/sub" (RELATIVE), no commondir
//	            -> <outer>/.git/modules/sub/info/exclude, and the outer repository's
//	               own .git/info/exclude does NOT apply
//	worktree    .git file "gitdir: /abs/repo/.git/worktrees/wt2" (ABSOLUTE) plus a
//	            commondir file holding "../.."
//	            -> the COMMON dir's exclude, /abs/repo/.git/info/exclude. A rule written
//	               to .git/worktrees/wt2/info/exclude is ignored by git, so following the
//	               pointer alone would read a file git does not read.
func findGitInfoExclude(start string) (string, string) {
	cur := start
	for {
		gitPath := filepath.Join(cur, ".git")
		// Stat, not Lstat: a .git SYMLINK to a real repository directory is the shape
		// the previous dirExists accepted, and it stays accepted.
		if info, err := os.Stat(gitPath); err == nil {
			gitDir := gitPath
			if !info.IsDir() {
				gitDir = resolveGitDirPointer(gitPath)
				if gitDir == "" {
					// A .git file we cannot follow still marks a repository root, so the
					// walk STOPS. Stopping yields "no rules", which is wrong but local;
					// climbing past it yields another repository's rules, which is wrong
					// and silent.
					return "", ""
				}
				gitDir = gitCommonDir(gitDir)
			}
			candidate := filepath.Join(gitDir, "info", "exclude")
			if fileExists(candidate) {
				return candidate, cur
			}
			return "", ""
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return "", ""
		}
		cur = parent
	}
}

// maxGitDirPointerBytes caps the read of a .git file. The real thing is one short line;
// the cap exists because the name is attacker-supplied in the threat model's
// hostile-repository case and nothing else bounds it.
const maxGitDirPointerBytes = 4096

// resolveGitDirPointer reads a `.git` FILE and returns the absolute directory its
// `gitdir:` line names, or "" if it does not name a readable directory.
//
// A relative pointer is resolved against the directory HOLDING the .git file, which is
// what git does and the only interpretation that works for `gitdir: ../.git/modules/sub`.
func resolveGitDirPointer(gitFile string) string {
	f, err := os.Open(gitFile) //nolint:gosec // path is built from the walk, not from input content
	if err != nil {
		return ""
	}
	defer f.Close()

	var target string
	scanner := bufio.NewScanner(io.LimitReader(f, maxGitDirPointerBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "gitdir:")
		if !ok {
			continue
		}
		target = strings.TrimSpace(rest)
		break
	}
	if target == "" {
		return ""
	}

	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(gitFile), target)
	}
	target = filepath.Clean(target)
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		return ""
	}
	return target
}

// gitCommonDir resolves a worktree's per-worktree git directory to the repository's
// COMMON git directory, where info/exclude actually lives. A git directory with no
// commondir file — a submodule's, or a plain repository's — is already the common one.
func gitCommonDir(gitDir string) string {
	f, err := os.Open(filepath.Join(gitDir, "commondir")) //nolint:gosec // path is derived from the walk
	if err != nil {
		return gitDir
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, maxGitDirPointerBytes))
	if err != nil {
		return gitDir
	}
	common := strings.TrimSpace(string(data))
	if common == "" {
		return gitDir
	}
	if !filepath.IsAbs(common) {
		common = filepath.Join(gitDir, common)
	}
	common = filepath.Clean(common)
	if info, err := os.Stat(common); err != nil || !info.IsDir() {
		return gitDir
	}
	return common
}

func globalExcludesPaths() []string {
	var out []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		out = append(out, filepath.Join(xdg, "git", "ignore"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".config", "git", "ignore"))
	}
	// Dedupe
	seen := map[string]struct{}{}
	dedup := out[:0]
	for _, p := range out {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		dedup = append(dedup, p)
	}
	return dedup
}

// ReadPatterns is a convenience helper that reads a .gitignore file into a
// slice of pattern strings, stripping comments and blank lines. Exposed so
// callers can log or inspect loaded rules.
func ReadPatterns(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, scanner.Err()
}
