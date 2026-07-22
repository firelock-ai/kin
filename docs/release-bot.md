# Release tag bot

`.github/workflows/release-tag.yml` lets the release captain create a `vX.Y.Z`
release tag **without holding the founder credential**, while keeping every
guarantee the manual tag push had. It is the front door to the existing
fail-closed release pipeline (`.github/workflows/release.yml`), which still
triggers on the tag push exactly as before.

## Why it exists

The repository ruleset **"Protect version release tags"** restricts creation of
`v*` tags. Previously only the founder's account could push a release tag. This
workflow moves that authority to a scoped **GitHub App** ("kin-release-bot")
that is allowlisted in the ruleset. The captain dispatches the workflow; the
workflow verifies the release is safe and then mints a short-lived App
installation token to create the tag ref.

The tag ref is created with the **App installation token, never the workflow's
`GITHUB_TOKEN`**. This matters for two reasons:

1. The ruleset admits the App, so the `v*` tag creation is allowed.
2. A ref created by the default `GITHUB_TOKEN` does **not** trigger further
   workflows (GitHub's recursion guard). A ref created by an App token **does**,
   so `release.yml` fires normally.

## What it does (fail-closed checks, in order)

The single job refuses — before any tag is created — unless **all** hold:

1. **Authorized actor + ref.** `github.actor` must be in the allowlist
   (`troyjr4103`, `kin-release-bot[bot]`) and the dispatch ref must be
   `refs/heads/main`. A branch dispatch of the workflow is refused loudly.
2. **Well-formed inputs.** `tag` must match `^v[0-9]+\.[0-9]+\.[0-9]+$`; `sha`
   must be a 40-character lowercase hex commit SHA. (`workflow_dispatch` cannot
   enforce a regex, so it is validated in-job. Both are handled only through the
   environment, never interpolated into a shell.)
3. **SHA is current `origin/main` HEAD.** The workflow checks out the SHA, fetches
   `origin/main`, and refuses unless the checked-out HEAD equals both the
   requested SHA and current `origin/main`. You can only tag the reviewed tip of
   main.
4. **Tag matches the workspace version.** `[workspace.package].version` in the
   root `Cargo.toml` **at that SHA** must equal the tag minus its `v`. This is
   the same version `release.yml` later asserts against the built packages.
5. **Required checks are green on that SHA.** Read from
   `repos/<owner>/<repo>/commits/<sha>/check-runs`. Two independent guards run.
   First, every context in the **presence-required release-critical set**
   (`REQUIRED_CHECKS`) must be present and green — a SHA missing any of these is
   refused even if nothing failed (a SHA that never ran CI is refused, not passed
   vacuously). Second, **no** check on the SHA may be failing or still in
   progress. The workflow's own `Mint release tag` check-run is self-excluded
   from this second guard — a refused dispatch is recorded as a failed
   `Mint release tag` check-run on the target SHA, and a gate must not read its
   own refusals as evidence. `skipped`/`neutral` count as non-failing — on a
   merged HEAD `DCO Sign-off` is `skipped` because the PR-time DCO already gated
   the merge.
   The presence-required set is:
   - `Check & Test (ubuntu-latest)`
   - `Check & Test (macos-latest)`
   - `DCO Sign-off`
   - `cargo-deny`
   - `gitleaks (full history)`
   - `Windows installer + vector-free release build`

   This is the `main` branch-protection required contexts **plus** the Windows
   installer leg, which is release-critical and never optional. Because the
   second guard already refuses any present check that is failing, this list need
   not mirror every CI context — extend it only to force *presence* of a
   release-critical check (add branch-protection additions here too).
6. **Tag does not already exist.** Refuses if `refs/tags/<tag>` is present.

Only then does it mint the App token, create `refs/tags/<tag>` at the SHA, and
**post-verify** that the new ref points at the SHA. A run summary records the
tag, SHA, and actor.

## Captain usage

One command, from a machine authenticated as an allowlisted actor:

```sh
gh workflow run release-tag.yml -f tag=v0.3.0 -f sha=<40-hex-sha>
```

Get the SHA to release (current reviewed main tip):

```sh
gh api repos/firelock-ai/kin/commits/main -q .sha
```

Watch it:

```sh
gh run list --workflow=release-tag.yml -L 1
gh run watch <run-id>
```

On success the tag exists and `release.yml` has started. On any refusal the job
fails at the offending step with a `::error::` line naming exactly what was
unmet; nothing is created.

## One-time founder setup

These steps require the founder / org owner and gate the bot going live.

1. **Create the GitHub App.** Org `firelock-ai` → Settings → Developer settings →
   GitHub Apps → New GitHub App. Name it **`kin-release-bot`**.
   - Repository permissions → **Contents: Read and write**. No other permissions.
   - **Uncheck** "Active" under Webhooks (no webhook needed).
   - "Where can this GitHub App be installed?" → **Only on this account**
     (org-only install).
   - Create the App. On its page, generate a **private key** (downloads a `.pem`).
     Note the **App ID**.
2. **Install the App.** App → Install App → install on the `firelock-ai` org.
   Scoping the install to **Only select repositories → `kin`** is the tightest
   posture, but the App is currently installed **org-wide** (founder decision) —
   see "Install scope and token narrowing" below for why that is still safe.
3. **Add the Actions secrets** (org-level, scoped to `kin`, or repo-level on
   `firelock-ai/kin`):
   - `KIN_RELEASE_BOT_APP_ID` — the App ID (numeric).
   - `KIN_RELEASE_BOT_PRIVATE_KEY` — the full PEM contents, including the
     `-----BEGIN...-----` / `-----END...-----` lines.
4. **Allowlist the App in the tag ruleset.** Org/repo → Rules → Rulesets →
   **"Protect version release tags"** → **Bypass list** → Add → the
   `kin-release-bot` App. Without this, the App's tag creation is rejected by the
   ruleset and the workflow fails at "Create release tag ref".
5. **Confirm the workflow token permission.** The workflow declares
   `permissions: contents: read` + `checks: read`. Ensure repo/org Actions
   settings permit those read scopes on `GITHUB_TOKEN` (default). The App token,
   not `GITHUB_TOKEN`, carries the write.

### Install scope and token narrowing

The `kin-release-bot` App is installed **org-wide** across `firelock-ai` (founder
decision), so the App itself can reach every repository in the org. The workflow
does not depend on a repo-scoped install: the "Mint kin-release-bot installation
token" step passes `owner: firelock-ai` + `repositories: kin` to
`actions/create-github-app-token`, which narrows every minted installation token
to the `kin` repository alone — so a compromised or misused run can only write to
`kin`, never a sibling repo. Extending bot-mediated tagging to another repo is a
deliberate act: replicate this workflow and its secrets in that repo and widen or
duplicate the `repositories:` narrowing to name the new repo explicitly — never
drop the `owner`/`repositories` inputs, since without them a single token would
span every repository the org-wide install can reach.

### Validating the setup

You cannot dry-run a real tag: a throwaway SHA will fail the "required checks"
and "current main HEAD" gates by design. Validate the **refusal path** instead —
dispatch with a deliberately wrong SHA and confirm the job refuses without
creating anything:

```sh
# 40 hex chars but not main HEAD -> must refuse at the origin/main HEAD check
gh workflow run release-tag.yml -f tag=v0.0.0 -f sha=0000000000000000000000000000000000000000
gh run list --workflow=release-tag.yml -L 1     # expect: failure
gh api repos/firelock-ai/kin/git/ref/tags/v0.0.0   # expect: 404 (nothing created)
```

A clean refusal with no tag created confirms the guards, token wiring, and
permissions are correct end-to-end short of an actual release.

## Recommended hardening (optional)

For defense-in-depth against a modified copy of this workflow being dispatched
from a branch (which could otherwise read the App secrets), bind
`KIN_RELEASE_BOT_APP_ID` / `KIN_RELEASE_BOT_PRIVATE_KEY` to a GitHub
**Environment** (e.g. `release-tag`) whose deployment branch policy allows only
`main`, and add `environment: release-tag` to the job. The environment's
branch policy then blocks secret access on any non-`main` dispatch, on top of
the in-job actor/ref guard. This mirrors how `release.yml` isolates its
publish secrets behind the protected `release` environment.
