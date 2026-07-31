# Release tag bot

Kin's release front door is automatic and fail closed:

1. `.github/workflows/release-train.yml` coalesces reviewed `main` drift into
   one `automation/release-next` PR.
2. The PR moves Cargo, npm, the explicit `kin-spine` path pin, `Cargo.lock`,
   and `CHANGELOG.md` together, then uses normal protected-main checks and
   GitHub auto-merge.
3. `.github/workflows/release-tag.yml` finds the exact reviewed commit where
   the coherent untagged version first appeared and creates `vX.Y.Z` with the
   scoped release App.
4. The existing tag-only `.github/workflows/release.yml` publishes and proves
   the release. `.github/workflows/release-recovery.yml` retries only failed or
   timed-out jobs, at most twice, while preserving the same immutable tag. Its
   final job publishes and attests deterministic `release-promotion.json`
   only after every stable-release capstone succeeds.
5. Installer and hosted reconcilers take over afterward.

The typed `repository_dispatch` remains a break-glass recovery path. It lets
the release captain create a tag **without holding the founder credential**,
while keeping every guarantee the manual tag push had. GitHub binds this event
to the last commit on the default branch and runs it only when the workflow
exists there, so the caller cannot select workflow code from another branch.

## Why it exists

The repository ruleset **"Protect version release tags"** restricts creation of
`v*` tags. Previously only the founder's account could push a release tag. This
workflow moves that authority to a scoped **GitHub App** ("kin-release-bot")
that is allowlisted in the ruleset. The captain sends an authenticated
`release_tag` repository dispatch with an exact tag and SHA; the workflow
verifies the release is safe and then mints a short-lived App installation
token to create the tag ref.

The release branch and tag ref are pushed with the **App installation token,
never the workflow's
`GITHUB_TOKEN`**. This matters for two reasons:

1. The ruleset admits the App, so the `v*` tag creation is allowed.
2. A ref created by the default `GITHUB_TOKEN` does **not** trigger further
   workflows (GitHub's recursion guard). A ref created by an App token **does**,
   so `release.yml` fires normally.

## Automatic release PR

The release train runs after successful `main` CI and on a staggered 15-minute
reconcile. If `main` is ahead of its already-tagged workspace version, it opens
or updates one automation-owned PR.

The SemVer bump is resolved only from `Kin-Release-Intent:` git trailers on the
first-parent commits between the prior stable tag and `main`. Patch is the
default, and the highest intent found in the range wins. Write the trailer as
the last block of the pull-request body:

```
Kin-Release-Intent: minor
```

Because the repository merges by squash with the pull-request body as the
commit message, that line becomes part of the immutable commit on `main`. The
train asserts the squash-only PR_TITLE + PR_BODY policy before trusting the
resolution, and refuses a mention of the key that git does not parse as a
trailer, a duplicate trailer, or an unsupported value.

Nothing editable resolves the bump. Labels are applied to describe the resolved
intent and are never read back, and the reconcile dispatch carries no bump
override. A merged pull request's labels can be changed afterwards, so reading
them would let a later scheduled run resolve a lower bump than an earlier one
and rewrite a prepared minor or major release back to a patch. A commit message
on protected main cannot change, and the first-parent range only grows, so the
resolution is stable and monotone.

The release App has repository Contents permission but no `main` bypass. It can
only update `automation/release-next`; the repository `GITHUB_TOKEN` opens the
PR, while the App activates ordinary checks and registers protected auto-merge.
That App identity is important: GitHub suppresses most workflow events caused
by `GITHUB_TOKEN`, whereas the App-owned merge emits the `main` push that starts
CI and automatic tag admission. Main must require up-to-date checks so new
merges cause the train to coalesce and re-test rather than release an older
changelog against newer code.

## Tag admission (fail-closed checks, in order)

The single job refuses — before any tag is created — unless **all** hold:

1. **Trusted trigger or authorized break-glass actor.** Scheduled and
   `workflow_run` events use workflow code from protected default-branch
   history. Break glass uses only the typed `repository_dispatch` action
   `release_tag`. GitHub assigns that event the last commit and ref of the
   default branch and runs it only when the workflow exists on that branch.
   The job additionally requires `github.actor` in the allowlist
   (`troyjr4103`, `kin-release-bot[bot]`), `main` as the reported default
   branch, and `refs/heads/main` as the event ref.
2. **Well-formed inputs.** `tag` must match `^v[0-9]+\.[0-9]+\.[0-9]+$`; `sha`
   must be a 40-character lowercase hex commit SHA. Both arrive under
   `github.event.client_payload`, are validated in-job, and are handled only
   through the environment, never interpolated into a shell.
3. **SHA is reviewed `origin/main` history.** The automatic path tags the exact
   coherent release-PR merge commit even if unrelated reviewed work has since
   advanced `main`; a break-glass request remains restricted to current `main`.
4. **Tag matches the workspace version.** `[workspace.package].version` in the
   root `Cargo.toml` **at that SHA** must equal the tag minus its `v`. This is
   the same version `release.yml` later asserts against the built packages.
5. **Required checks are green on that SHA.** Read from
   `repos/<owner>/<repo>/commits/<sha>/check-runs`. Two independent guards run.
   First, every context in the **presence-required release-critical set**
   (`REQUIRED_CHECKS`) must be present and green — a SHA missing any of these is
   refused even if nothing failed (a SHA that never ran CI is refused, not passed
   vacuously). Required contexts are bound to the GitHub Actions App identity,
   so another check-writing App cannot satisfy one by copying its name. Every
   required non-DCO context must conclude `success`; `DCO Sign-off` alone may
   be `skipped` on merged `main` because PR-time DCO already gated the merge.
   Second, **no** check on the SHA may be failing or still in progress. The
   workflow's own GitHub Actions `Mint release tag` check-run is self-excluded
   from this second guard — a refused dispatch is recorded as a failed
   `Mint release tag` check-run on the target SHA, and a gate must not read its
   own refusals as evidence. `skipped`/`neutral` remain non-failing only for
   checks outside the presence-required set.
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
6. **The prior release lane is settled.** No Release run may be queued or
   active, and the prior stable must have either a successful exact tag/SHA
   Release run or its attested terminal completion marker. This prevents GitHub
   concurrency from replacing a pending version without making Actions log
   retention part of durable release authority.
7. **Tag does not already exist.** Refuses if `refs/tags/<tag>` is present.

Only then does it mint the App token, create `refs/tags/<tag>` at the SHA, and
**post-verify** that the new ref points at the SHA. A run summary records the
tag, SHA, and actor.

## Automatic recovery

The release controller immediately and periodically reconciles failed,
timed-out, or runner-startup-failed `Release` runs. It re-fetches the run
through the Actions API, checks
the exact workflow path, repository, stable SemVer tag, peeled tag commit,
default-branch ancestry, absence of any successful attempt, and absence of an
active release before requesting `rerun-failed-jobs`. The initial attempt plus
two retries is the hard cap. Cancellation is treated as an operator stop and is
never retried. If all three attempts fail, the controller opens one
`Release blocked after automatic retries` issue and stops.

## Captain break-glass usage

Normal releases need no captain command. To recover a refused automatic path,
an allowlisted actor can dispatch the same admission workflow explicitly:

```sh
tag=v0.4.0
sha="$(gh api repos/firelock-ai/kin/git/ref/heads/main --jq .object.sha)"
jq -n --arg tag "$tag" --arg sha "$sha" \
  '{event_type:"release_tag",client_payload:{tag:$tag,sha:$sha}}' |
  gh api --method POST repos/firelock-ai/kin/dispatches --input -
```

If a successful historical Actions run has aged out or been deleted, automatic
admission re-establishes the prior stable from its checksum-bound terminal
completion marker and GitHub artifact attestation pinned to the exact release
workflow, tag, commit, GitHub-hosted runner, and transparency timestamp.
The marker also carries the stable numeric Release run ID as an attested audit
identifier, so downstream provenance can keep its existing linkage without
requiring GitHub to retain the mutable Actions record forever.
The one explicit pre-marker migration release, v0.3.6, additionally has to
prove exact npm latest versions, matching GHCR latest/version/tag digests, and
the exact source-bound GHCR attestation, plus aggregate release provenance.
Markerless fallback is retired for v0.4.0 and later. Missing logs therefore
cannot make the train permanently stale, while a preserved failed attempt can
never be overridden by public-surface fallback.

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
3. **Create the protected `release-tag` Environment.** Give it a custom
   deployment-branch policy that allows **only `main`**, with no required
   reviewer so trusted automatic reconciliation remains unattended.
   `release-train.yml` and `release-tag.yml` are the two token-minting
   workflows. Both declare that Environment before minting a token.
   `repository_dispatch` prevents a caller from selecting a branch copy of the
   tag controller, and the controller forbids branch-selectable
   `workflow_dispatch`. That still does not make a repository- or
   organization-scoped private key safe: any other eligible workflow in the
   repository could explicitly request a broadly scoped secret. The Environment
   is therefore a required credential boundary, not optional hardening.
4. **Add the App credentials only as `release-tag` Environment secrets:**
   - `KIN_RELEASE_BOT_APP_ID` — the App ID (numeric).
   - `KIN_RELEASE_BOT_PRIVATE_KEY` — the full PEM contents, including the
      `-----BEGIN...-----` / `-----END...-----` lines.
   Remove or rotate away every repository- or organization-level copy visible
   to `kin`. GitHub makes repository secrets available to every workflow in the
   repository; only Environment scope confines these credentials to jobs that
   name this main-only boundary.
5. **Allowlist the App in the tag ruleset.** Org/repo → Rules → Rulesets →
   **"Protect version release tags"** → **Bypass list** → Add → the
   `kin-release-bot` App. Without this, the App's tag creation is rejected by the
   ruleset and the workflow fails at "Create release tag ref".
6. **Confirm the workflow token permission.** The tag controller declares only
   read scopes on its `GITHUB_TOKEN`; the App token, not `GITHUB_TOKEN`, carries
   the tag write.
7. **Admit protected release PR automation.** Keep the repository default
   workflow token permission at **read**, enable **Allow GitHub Actions to create
   and approve pull requests**, and keep the main required-status rule in strict
   up-to-date mode. `release-train.yml` explicitly elevates only Issues and Pull
   requests for its PR metadata; its branch bytes still come from the
   repository-scoped App, and neither identity bypasses protected `main`.

### Install scope and token narrowing

The `kin-release-bot` App is installed **org-wide** across `firelock-ai` (founder
decision), so the App itself can reach every repository in the org. The workflow
does not depend on a repo-scoped install: the "Mint kin-release-bot installation
token" step passes `owner: firelock-ai` + `repositories: kin` to
`actions/create-github-app-token`, which narrows every minted installation token
to the `kin` repository alone. The raw private key is more powerful than one
narrowed token, so it must exist only as a secret in the main-only
`release-tag` Environment and only default-branch-pinned trigger paths may
consume it.
Extending bot-mediated tagging to another repo is a deliberate act: replicate
this workflow and its protected Environment in that repo and widen or duplicate
the `repositories:` narrowing to name the new repo explicitly — never drop the
`owner`/`repositories` inputs, since without them a single token would span
every repository the org-wide install can reach.

### Validating the setup

Break glass is an API event, not a branch-selectable workflow run. When a real
release requires it, read `main` immediately before dispatch and construct the
payload with `jq` so tag and SHA remain data:

```sh
tag=v0.4.0
sha="$(gh api repos/firelock-ai/kin/git/ref/heads/main --jq .object.sha)"
jq -n --arg tag "$tag" --arg sha "$sha" \
  '{event_type:"release_tag",client_payload:{tag:$tag,sha:$sha}}' |
  gh api --method POST repos/firelock-ai/kin/dispatches --input -
```

That is a real mutation request: use it only when the exact release should be
tagged. You cannot dry-run a real tag. To validate the **refusal path** instead,
send a deliberately wrong SHA and confirm the job refuses without creating
anything:

```sh
jq -n --arg tag v0.0.0 \
  --arg sha 0000000000000000000000000000000000000000 \
  '{event_type:"release_tag",client_payload:{tag:$tag,sha:$sha}}' |
  gh api --method POST repos/firelock-ai/kin/dispatches --input -
gh run list --workflow=release-tag.yml -L 1     # expect: failure
gh api repos/firelock-ai/kin/git/ref/tags/v0.0.0   # expect: 404 (nothing created)
```

A clean refusal with no tag created proves the untrusted input and head guards.
It deliberately stops before App-token minting, so verify the Environment
policy and secret placement independently during setup; the first admitted
release proves the complete token-and-ruleset path.
