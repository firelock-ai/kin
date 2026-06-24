# Contributing to Kin

Thanks for your interest in Kin. This guide covers local development, the
conventions this repository actually follows, and how to get changes reviewed.

## Development Setup

Kin is a Rust workspace. CI builds on **stable** Rust, so a current stable
toolchain via [rustup](https://rustup.rs/) is all you need:

```sh
rustup toolchain install stable
```

Build and test the workspace:

```sh
cargo build
cargo test
```

Before opening a pull request, make sure the standard checks pass:

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo test
```

CI treats clippy warnings as errors (`-D warnings`), so a clean clippy run
locally avoids surprises.

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/).
Recent history shows the expected shape — a `type(scope): summary` subject:

```
fix(locate): make scoring pipeline deterministic with explicit tie-breaks
feat(mcp): unify tool responses under a versioned response envelope
docs(planning): canonical roadmap status update
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, and
`chore`. Scopes match the area you touched (`cli`, `daemon`, `mcp`, `locate`,
`search`, `release`, and so on). Write the summary in the imperative mood and
keep it focused on what changed and why.

## Branch Naming and Commit Hygiene

Public Git history is part of the product, so keep it clean and reviewable:

- **Keep branch names topical, not tracker-coded.** Prefer short, descriptive
  names like `fix/locate-tie-breaks` or `docs/contributing-hygiene`. Avoid
  embedding internal issue or tracker IDs in a branch name — a squash merge
  copies the branch name into the public commit subject, so anything in the
  branch name lands in history verbatim.
- **Write durable subjects and bodies.** Commit messages should describe the
  technical change and why it was made. Keep internal tracker IDs, session
  identifiers, and automated authorship trailers out of public commit
  metadata; link that context from the pull request instead.
- **Don't bypass the hooks.** Repository hooks normalize commit metadata for
  consistency — don't skip them with `--no-verify`.

## Pull Requests

- **Keep PRs scoped.** Stage only the files your change actually needs.
  Unrelated cleanups belong in their own PR — this keeps review focused and
  history bisectable.
- Fill out the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).
- Make sure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
- If your change is user-facing, add an entry to the `[Unreleased]` section of
  [CHANGELOG.md](CHANGELOG.md) in the Keep a Changelog format already used there.

## Reporting Issues

File issues on [firelock-ai/kin](https://github.com/firelock-ai/kin/issues)
using the provided templates:

- **Bug reports** — use the bug report template.
- **Feature requests** — use the feature request template.

For security vulnerabilities, do **not** open a public issue. Follow the
private reporting process in [SECURITY.md](SECURITY.md).

## Issue Triage and Response

Kin is actively developed and pre-1.0, so issue triage is best-effort. The
target is to **acknowledge new issues within three business days** —
acknowledgement means an initial response (a label, a clarifying question, or a
triage decision), not a fix or a committed delivery date. Bug reports that
include a minimal reproduction and the `kin --version` output are usually
triaged fastest.

Security reports are handled separately and more urgently. Do not use the public
issue tracker for them; follow [SECURITY.md](SECURITY.md).

## Repository Boundaries

Kin is one repository within a larger ecosystem (`kin-db`, `kin-vfs`,
`kinlab`, and others). Graph storage and retrieval internals live in `kin-db`;
the filesystem projection lives in `kin-vfs`. If your change targets one of
those concerns, open it against the repository that owns the code.

## Releases and Security Disclosures

Kin follows [Semantic Versioning](https://semver.org/). The project is currently
pre-1.0, so it ships as `0.x` releases, and a minor version may include breaking
changes to APIs and on-disk formats while the system stabilizes.

Every release is documented in [CHANGELOG.md](CHANGELOG.md), which follows the
[Keep a Changelog](https://keepachangelog.com/) format. Land user-facing changes
with an entry under `[Unreleased]` (see [Pull Requests](#pull-requests)); cutting
a release promotes those entries under a versioned, dated heading.

Security vulnerabilities are not reported through the public issue tracker.
Report them privately as described in [SECURITY.md](SECURITY.md), which also
defines which versions receive fixes. Fixes ship in a new `0.x` release rather
than as backports to older tags.

## Contribution Sign-Off, IP, and AI Assistance

### Sign-off (DCO)

Every commit must carry a `Signed-off-by` trailer, added with `git commit -s`.
The repository hooks add it when it is missing — don't bypass them with
`--no-verify`. The sign-off is your Developer Certificate of Origin: by adding it
you certify that you wrote the contribution, or otherwise have the right to
submit it under the repository's license, and that you understand it becomes a
public, permanent part of the project.

### Contributor License Agreement

External contributions also pass a lightweight CLA gate before merge. The check
matches the pull request author against an allowlist of trusted accounts and the
recorded signatures in [`signatures/cla.json`](signatures/cla.json); see
[CLA.md](CLA.md). If you are a first-time external contributor, a maintainer will
help you get recorded there.

### IP ownership and AI assistance

Contributions may be AI-assisted — Kin does not prohibit AI coding tools. But the
human contributor remains the author of record and is fully responsible for the
contribution:

- **You assert ownership.** By signing off, you assert that you own or have the
  right to submit the contribution under the [Apache License 2.0](LICENSE),
  regardless of which tools helped produce it. Do not submit code that a tool
  reproduced from license-incompatible sources.
- **AI-generated code must be human-reviewed and owned.** Review, understand, and
  test anything a tool generated before you submit it. You are accountable for it
  exactly as if you had written every line yourself; "a tool wrote it" excuses
  neither a bug, a license violation, nor a security flaw.
- **Keep tool provenance out of commit metadata.** As noted under
  [Branch Naming and Commit Hygiene](#branch-naming-and-commit-hygiene), commit
  messages should describe the durable technical change. Leave AI-authorship
  trailers, tool banners, and session identifiers out of public commit metadata;
  if attribution matters for a change, record it in the pull request instead.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license that covers this repository.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
