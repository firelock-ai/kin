# Contributing to kin-model

Thanks for your interest in kin-model. This guide covers local development, the
conventions this repository follows, and how to get changes reviewed.

## Development Setup

kin-model is a Rust crate. CI builds on **stable** Rust, so a current stable
toolchain via [rustup](https://rustup.rs/) is all you need:

```sh
rustup toolchain install stable
```

Build and test:

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

## Versioning Policy

kin-model is the **release/version source of truth** for canonical Kin types.
Every source change intended for publication must bump the crate version — the
registry is immutable and you cannot overwrite a published `(name, version)`.

See [`downstream-pins.json`](downstream-pins.json) and the scripts in
`scripts/` for the downstream compatibility gate. A breaking (MINOR) bump must
update `downstream-pins.json` in the same commit.

## DCO Sign-Off

This project uses the [Developer Certificate of Origin
(DCO)](https://developercertificate.org/). Every commit you push on a pull
request must carry a `Signed-off-by` trailer:

```
Signed-off-by: Your Name <you@example.com>
```

Add it by passing `-s` to `git commit`:

```sh
git commit -s -m "feat(types): add Provenance variant for external import"
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
A `type(scope): summary` subject is the expected shape:

```
feat(types): add WorkState::Reviewing variant
fix(serde): make RelationKey serialize as a flat string
chore(version): bump to 0.2.1 for additive WorkState variant
```

Common types are `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, and
`chore`. Write the summary in the imperative mood and keep it focused on what
changed and why.

## Branch Naming and Commit Hygiene

Public Git history is part of the product, so keep it clean and reviewable:

- **Keep branch names topical, not tracker-coded.** Prefer short, descriptive
  names like `feat/work-state-reviewing` or `fix/relation-key-serde`. Avoid
  embedding internal issue or tracker IDs in a branch name.
- **Write durable subjects and bodies.** Commit messages should describe the
  technical change and why it was made. Keep internal tracker IDs, session
  identifiers, and automated authorship trailers out of public commit metadata.
- **Don't bypass the hooks.** Repository hooks normalize commit metadata for
  consistency — don't skip them with `--no-verify`.

## Pull Requests

- **Keep PRs scoped.** Stage only the files your change actually needs.
  Unrelated cleanups belong in their own PR.
- Make sure `cargo fmt`, `cargo clippy`, and `cargo test` all pass before
  requesting review.
- Breaking changes (MINOR bumps) must update `downstream-pins.json` and pass
  the `scripts/check-downstream-pins.sh` gate.

## Reporting Issues

File issues on [firelock-ai/kin-model](https://github.com/firelock-ai/kin-model/issues).

For security vulnerabilities, do **not** open a public issue. Follow the
private reporting process in [SECURITY.md](SECURITY.md).

Triage SLA: security issues are acknowledged within 48 hours; general issues
within 7 days.

## Repository Boundaries

kin-model is the schema and domain boundary for the open local substrate. It
defines types, not behavior. Changes to graph storage or indexing belong in
`kin-db`; changes to CLI, daemon, and MCP behavior belong in `kin`. The hosted
KinLab control-plane types are out of scope for this crate.

## License

By contributing, you agree that your contributions are licensed under the
[Apache License 2.0](LICENSE), the license that covers this repository.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.
