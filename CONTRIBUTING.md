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

For changes to public onboarding documentation, install
[`lychee`](https://lychee.cli.rs/) and run the same bounded link check as CI:

```sh
lychee --config lychee.toml \
  ./README.md \
  ./CONTRIBUTING.md \
  ./SECURITY.md \
  ./docs/quickstart.md
```

The scheduled workflow also catches external links that rot without a source
change. Keep additions to the checked public-document set aligned between
`.github/workflows/link-check.yml` and this command, and keep any exclusions
bounded in `lychee.toml`.

CI treats clippy warnings as errors (`-D warnings`), so a clean clippy run
locally avoids surprises.

## DCO Sign-Off

This project uses the [Developer Certificate of Origin
(DCO)](https://developercertificate.org/). Every commit you push on a pull
request must carry a `Signed-off-by` trailer:

```
Signed-off-by: Your Name <you@example.com>
```

Add it by passing `-s` to `git commit`:

```sh
git commit -s -m "fix(locate): improve scoring tie-breaks"
```

If you forgot to sign off earlier commits on your branch:

```sh
git commit -s --amend              # amend only the last commit
git rebase --signoff HEAD~N        # add sign-off to the last N commits
```

By signing off you certify that you wrote the code (or have the right to
submit it) and that it may be distributed under the Apache License 2.0 that
governs this repository. Bot-authored commits (Dependabot, GitHub Actions)
are exempt.

The DCO sign-off is the only contributor agreement required. There is no
separate CLA or account allowlist.

## AI-Assisted Contributions

Kin is built with significant AI assistance, and we welcome AI-assisted
contributions from the community. A few requirements:

- **You are responsible for AI-generated code you submit.** Review every
  line before opening a PR. If the model hallucinated an API call, an
  unsound unsafe block, or a security hole, that is your bug to catch.
- **AI-generated code is your contribution.** By signing off your commits
  you assert that you have reviewed the generated code and are submitting it
  under your own name, not as a third-party work. Firelock asserts copyright
  over AI-generated code it produces; you assert copyright over what you
  produce and submit here.
- **No raw model output in commit messages or comments.** Clean up generated
  prose before it lands in public history. Write durable, human-authored
  commit messages that describe the technical change.

## Commit Messages

This repository uses [Conventional Commits](https://www.conventionalcommits.org/).
Recent history shows the expected shape: a `type(scope): summary` subject:

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
  embedding internal issue or tracker IDs in a branch name. A squash merge
  copies the branch name into the public commit subject, so anything in the
  branch name lands in history verbatim.
- **Keep private context private.** Do not publish private session URLs or IDs,
  secrets, or internal-only tracker references. Put non-sensitive technical
  context in the pull request.
- **Preserve provenance.** Tool-specific attribution is optional. Existing
  attribution must not be stripped, and authors, committers, timestamps, and
  history must not be rewritten.
- **Use hooks only for validation.** Hooks may reject private references or
  secrets, but they must not mutate commit metadata or history. Do not skip
  configured validation with `--no-verify`.

## Pull Requests

- **Keep PRs scoped.** Stage only the files your change actually needs.
  Unrelated cleanups belong in their own PR. This keeps review focused and
  history bisectable.
- Fill out the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).
- Make sure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
- If your change is user-facing, add an entry to the `[Unreleased]` section of
  [CHANGELOG.md](CHANGELOG.md) in the Keep a Changelog format already used there.

## Reporting Issues

File issues on [firelock-ai/kin](https://github.com/firelock-ai/kin/issues)
using the provided templates:

- **Bug reports:** use the bug report template.
- **Feature requests:** use the feature request template.

For security vulnerabilities, do **not** open a public issue. Follow the
private reporting process in [SECURITY.md](SECURITY.md).

Triage SLA: security issues are acknowledged within 48 hours; general issues
within 7 days. Response time may be longer during active release periods.

## Repository Boundaries

Kin is one repository within a larger ecosystem (`kin-db`, `kin-vfs`,
`kinlab`, and others). Graph storage and retrieval internals live in `kin-db`;
the filesystem projection lives in `kin-vfs`. If your change targets one of
those concerns, open it against the repository that owns the code.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license that covers this repository.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
