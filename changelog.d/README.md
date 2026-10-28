# Release-note fragments

A pull request that changes what a release ships adds its `CHANGELOG.md` entry here, as a file of
its own, instead of editing `CHANGELOG.md`. Two pull requests then never edit the same file, so they
never conflict. When a release tag is pushed, `scripts/promote-changelog.sh` renders every fragment
into a dated section of `CHANGELOG.md`, right below `## [Unreleased]`, and deletes the fragments in
the same commit. The entries stay hand-written: the release copies every line as it is.

## When a pull request needs one

When it changes what a release ships. [CONTRIBUTING.md](../CONTRIBUTING.md#changelog-entries) has
the list, and the `CHANGELOG` check on the pull request names the files that triggered it.
Test-only, docs and CI pull requests need none. A pull request that needs one but changes nothing a
user can notice (a pure refactor, say) takes the `no-changelog` label instead: that is the explicit
opt-out, and it records the decision on the pull request.

## The file name

`changelog.d/NNNN-slug.md`, where NNNN is the issue number zero-padded to four digits and the slug
is lowercase kebab-case (letters, digits and single hyphens): for example
`changelog.d/0800-otp-lowercase-word-not-base32.md`. Two entries for one issue take two slugs. This
README is the only other file the directory may hold.

## The content

Exactly what you would have written under `## [Unreleased]`:

1. The first line is one of these headings, copied character for character:
   - `### ⚠️ Breaking Changes`
   - `### 🔒 Security`
   - `### 🚀 Features`
   - `### 🐛 Bug Fixes`
   - `### ⚡ Performance`
   - `### 📚 Documentation`
   - `### 🛠 Build System`
   - `### 📦 Code Refactoring`
   - `### ✅ Tests`
   - `### 🔨 Internal`
2. Then one blank line.
3. Then one or more bullets, each starting with `- ` at column 0, its continuation lines indented two
   spaces and wrapped near 100 columns, with no blank line between bullets or inside one.
4. The file ends with a single newline.

Nothing else goes in the file: no title, no front matter, no second heading. An entry that belongs
under two headings is two fragments.

Match the style of the entries in `CHANGELOG.md`: a bold scope prefix, what changed for the person
upgrading, the measured numbers, and a link to the issue.

A release lists the headings in the order above and, under each heading, the fragments in file-name
order.

## Example

`changelog.d/0821-changelog-fragments.md`, the fragment of the pull request that introduced this
directory:

```markdown
### 🔨 Internal

- **changelog (fragments):** a release note is now a file of its own under `changelog.d/`, rendered
  into this file when the release tag is pushed, instead of an edit under `## [Unreleased]`, where
  every two open pull requests conflicted ([#821](https://github.com/awslabs/ferret-scan/issues/821));
  the entries already there moved into fragments byte for byte. Name one `NNNN-slug.md` and follow
  `changelog.d/README.md`; the `CHANGELOG` check requires and validates it.
```

## Preview

`make changelog-preview` prints the section the next release would add, from every fragment here.
The `CHANGELOG` check runs the same parser as the release on every fragment a pull request adds or
edits, so a malformed fragment fails its pull request instead of the release.
