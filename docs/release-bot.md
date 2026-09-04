# Release tag bot

Kin's release front door is automatic and fail closed:

1. `.github/workflows/release-train.yml` coalesces reviewed `main` drift into
   one `automation/release-next` PR.
2. The PR moves Cargo, npm, the explicit `kin-spine` path pin, `Cargo.lock`,
   and `CHANGELOG.md` together, then uses normal protected-main checks and
   GitHub auto-merge.
3. `.github/workflows/release-cut.yml` selects the candidate that version will
   be proven at, arms `release/vX.Y.Z-candidate`, dispatches the archive build,
   and publishes `preflight.json` for it.
4. `.github/workflows/release-tag.yml` finds the exact reviewed commit where
   the coherent untagged version first appeared and creates `vX.Y.Z` with the
   scoped release App.
5. The existing tag-only `.github/workflows/release.yml` publishes and proves
   the release. `.github/workflows/release-recovery.yml` retries only failed or
   timed-out jobs, at most twice, while preserving the same immutable tag. Its
   final job publishes and attests deterministic `release-promotion.json`
   only after every stable-release capstone succeeds.
6. Installer and hosted reconcilers take over afterward.

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
PR, while the App reads the repository merge policy, activates ordinary checks,
and registers protected auto-merge. GitHub returns the merge-policy settings
only to a token holding push-level repository access, so the deliberately
read-scoped `GITHUB_TOKEN` receives a response with those fields absent rather
than wrong. The train therefore reads that policy through the App token and
reports an unreadable policy separately from a violated one, because blaming
the repository settings for a policy no token ever read sends recovery after a
correctly configured repository.
That App identity is important: GitHub suppresses most workflow events caused
by `GITHUB_TOKEN`, whereas the App-owned merge emits the `main` push that starts
CI and automatic tag admission. Main must require up-to-date checks so new
merges cause the train to coalesce and re-test rather than release an older
changelog against newer code.

## Automatic release cut

The mint tags the newest reviewed `main` commit in the staged version's range
that carries `preflight.json` under `evidence/<sha>/` on the `release-evidence`
branch. The machine preflight alone is what makes a candidate mint-eligible, and
`stranger.env` beside it is a label on the release rather than a gate in front of
it: a stranger that cannot run, because a runner is offline or a weekly limit is
spent, must not hold a finished release. `release-cut.yml` is what puts a record
there without a captain.

It runs on a completed CI run for a `main` push, on a completed RC Build for a
`release/v*-candidate` branch, on the typed `release_cut` repository dispatch
from the same allowlist the mint admits, and on a fifteen-minute sweep offset
from the mint's and the train's. There is deliberately **no**
`workflow_dispatch`: a dispatch takes a ref, and the publish job reaches the
release App's key, so a branch must never be able to select the code running
beside it. `scripts/select-release-candidate.py` decides, and both of its
judgments are pure functions over one snapshot:

1. `vX.Y.Z` already exists, so the cut is done.
2. A sha in the range carries both records, so the mint owns it.
3. The current candidate is kept until it is proven or dead. With `preflight.json`
   recorded the mint can already tag it and the cut still runs the stranger,
   because that record is what the release gets to claim; alive with a usable RC
   Build it is proven; alive with none it is armed again, twice at most.
4. A sha carries `preflight.json` alone, so the mint owns it and the cut stands
   down rather than arming a newer sha it would only race.
5. Otherwise the newest `main` commit in the range whose CI **and** Acceptance
   push runs concluded success, and whose required contexts each appear exactly
   once under push provenance, becomes the candidate.

A sha still being graded is skipped rather than waited for, because on a busy
`main` the newest sha is always pending and a selector that waits never
converges. A sha whose required context is red, duplicated by a rerun, or
claimed by another App is named and skipped: the mint reads a duplicated
required context as ambiguous authority, so answering a flaky required job with
a rerun is what kills the sha, and the next first-pass-green commit becomes the
candidate instead.

The proof runs on hosted runners, one per archive on the runner that executes it
natively, using the tooling vendored under `scripts/release-proof/` from the
private `kin-ecosystem` umbrella. `VENDORED.json` records each file's sha256 and
`scripts/release-proof/vendored.test.mjs` refuses one that drifted. The three
leg records are merged by `scripts/release-proof/merge-preflight-records.mjs`,
which judges its own output with the mint's gate before anything is published;
the merge is deterministic because the evidence branch is append-only and a
re-publish of differing bytes is refused as tampering.

**The stranger runs on a runner the fleet owns.** It cannot run on a hosted one,
and the reason is memory rather than wall clock. `bin/kin-stranger` launches one
background process per arm and waits on them together, and each container is
created `--cpus=5 --memory=12g`, so three concurrent arms demand 15 CPUs and
36 GB, which no standard hosted tier holds. The caps cannot be lowered to fit:
the tool's own reference says they are deliberately below the capability tier
that gates the fused pipeline because they are the hardware a laptop audience
actually has, and that **the cap is the measurement**, printing MEASUREMENT
CONTAMINATED when the cgroup ceiling at capture differs from the flag the
container was created with. A smaller arm is not a smaller proof, it is an
unfilable one. Wall clock is not the constraint: the phase caps are 3600 s and
7200 s and the arms are concurrent, so a run fits a six-hour cap with room.

The job is gated on the repository variable `KIN_STRANGER_RUNNER`, which names
the runner, in the same shape `ci.yml` already uses for `KIN_HEAVY_RUNNER`. The
gate is a variable rather than a live runner query for two reasons: `GITHUB_TOKEN`
cannot list runners, because `administration` is not among the permissions a
workflow token can hold, and more importantly a job whose `runs-on` labels match
no online runner does not skip, it queues until the job timeout, which is the
silent hang this repository refuses everywhere else. Set the variable when a
runner is registered and clear it when it goes away:

```
gh variable set KIN_STRANGER_RUNNER --repo firelock-ai/kin --body '<runner label>'
gh secret set KIN_STRANGER_ANTHROPIC_API_KEY --repo firelock-ai/kin
```

**The stranger's home is a local run, and the hosted job is optional.** Founder
decision, 2026-09-04: "the damn smoke should never block release it is a nice to
have ONLY ... it should be mainly run locally not in the CI." The ordinary way to
measure first contact is `bin/kin-stranger` from the umbrella, against the
candidate archive before a tag or the published npm bytes after one.

It is two stages and both take the same `--run` id. `prepare` builds or reuses the
image and creates one container per arm; `run` drives both phases against whichever
source you name. `run` refuses without a run id, so the one-line form does not work
and never did. Archive mode also refuses without a candidate sha unless the archive's
own `.provenance.json` names one, and it refuses AFTER staging the archive into the
container, so leaving it out costs a prepared run. npm mode needs no sha. The two
`run` lines below are alternatives, not a sequence:

```
bin/kin-stranger prepare --run <id> --arms green,brown,vcs
bin/kin-stranger run --run <id> --archive <path> --candidate-sha <sha>   # the candidate bytes
bin/kin-stranger run --run <id> --npm <version>     # or the published npm bytes instead
```

The hosted job in `release-cut.yml` is a convenience that runs the same tool on a
runner the fleet owns when `KIN_STRANGER_RUNNER` names one. It carries
`continue-on-error: true` and can never redden a cut run, because a driver out of
limit or an offline runner is not a fact about the candidate. Whatever it does,
it writes a summary line naming the state, and `publish-stranger` keys on that
job's own `recorded` output rather than on its result, since `continue-on-error`
masks a failed job's result to success for everything downstream.

With the variable unset the cut still selects, arms and preflights, and the
`stranger-standby` job prints the exact local command with all three arms named
and raises a warning. The mint tags either way. What a missing `stranger.env`
costs is the claim, not the release: the mint's step summary carries a first
contact row reading `pending`, `release.yml` stamps the same statement onto the
release body behind the `<!-- kin-first-contact-proof -->` marker, and the
release still becomes GitHub Latest. A partial record is still refused rather
than accepted, because a record that overstates its own coverage is worse than
no record.

**A stranger record is linked to its candidate by one of two receipts, and both
are the release chain's own.** `stranger.env` names the archive sha256 the
stranger ran, and `scripts/check-release-proof-artifacts.mjs` accepts that
archive when it appears among the preflight legs for that commit, or among
`artifacts[].archive.sha256` in the `release-provenance.json` asset of the
release whose tag resolves to that commit. Two receipts rather than one because
there are two honest sets of bytes: the preflight judges the rc-build archives,
and `release.yml` rebuilds at the tag, so the archive a developer downloads is
never a preflight leg. With only the first link, the released-byte proof of any
release could never lift that release's own pending notice. The release receipt
is held to the same standard: its `kin.commit`, and every artifact's, must be
the candidate, so a release whose provenance describes another build refuses
rather than being passed over. An archive in neither receipt is still a stranger
that ran on some other build, and it is still refused.

The driver takes its credential from `KIN_STRANGER_ANTHROPIC_API_KEY`, exported
as `ANTHROPIC_API_KEY`. No harness change was needed: `driver_env_argv` unsets
that variable on exactly one branch, the local endpoint, and the endpoint
defaults to the account, so an exported key rides through and Claude Code
prefers it over `ANTHROPIC_AUTH_TOKEN`. The job refuses at the door when the
secret is empty rather than sending every request out unauthenticated and
discovering it hours later in a transcript that records only a server error.

## Tag admission (fail-closed checks, in order)

Before creating any tag, the single job refuses unless **all** hold:

1. **Trusted trigger or authorized break-glass actor.** Scheduled and
   `workflow_run` events use workflow code from protected default-branch
   history. Break glass uses only the typed `repository_dispatch` action
   `release_tag`. GitHub assigns that event the last commit and ref of the
   default branch and runs it only when the workflow exists on that branch.
   The job also requires `github.actor` in the allowlist
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
   `repos/<owner>/<repo>/commits/<sha>/check-runs`. A required-context guard and
   an advisory-evidence audit run. Every context in the
   **presence-required release-critical set**
   (`REQUIRED_CHECKS`) must be present and green. A SHA missing any of these is
   refused even if nothing failed (a SHA that never ran CI is refused, not passed
   vacuously). Required contexts are bound to the GitHub Actions App identity,
   so another check-writing App cannot satisfy one by copying its name. Every
   required non-DCO context must conclude `success`; `DCO Sign-off` alone may
   be `skipped` on merged `main` because PR-time DCO already gated the merge.
   This reviewed set is the complete release veto authority. A red or unfinished
   check outside it is announced in the workflow annotation and step summary,
   but it neither refuses nor delays the mint. If an advisory check becomes
   release-critical, add it to this reviewed set so that change is explicit and
   reviewable rather than granting every check writer an implicit veto.
   The presence-required set is:
   - `Check & Test (ubuntu-latest)`
   - `Check & Test (macos-latest)`
   - `DCO Sign-off`
   - `cargo-deny`
   - `gitleaks (full history)`
   - `Windows installer + vector release build`

   This reviewed list is the authority for release admission. The active `main`
   ruleset should carry the same contexts, but the mint does not read mutable
   ruleset configuration at runtime; keep the two declarations aligned through
   reviewed changes. The list need not mirror every CI context. It must name
   every context whose presence and green verdict are required to release.
6. **The prior release lane is settled.** No Release run may be queued or
   active, and the prior stable must have either a successful exact tag/SHA
   Release run or its attested terminal completion marker. This prevents GitHub
   concurrency from replacing a pending version without making Actions log
   retention part of durable release authority. The highest tag this compares
   against skips any tag carried by `scripts/abandoned-release-tags.json`; see
   [Abandoning a release tag](#abandoning-a-release-tag). A tag that is merely
   failing so far carries no record and still blocks its successor.
7. **Tag does not already exist.** Refuses if `refs/tags/<tag>` is present.

Only then does it mint the App token, create `refs/tags/<tag>` at the SHA, and
**post-verify** that the new ref points at the SHA. A run summary records the
tag, SHA, and actor.

An automatic mint may correctly decline while a prior release is still active
or unresolved. Such a decline writes a warning annotation, a titled summary,
and a named reason. The first three consecutive real declines remain green; the
fourth and every later consecutive decline fail visibly as a blocked lane.
`workflow_run` invocations whose entire mint job is skipped are controller noise,
not mint outcomes, and do not reset or increment that count. A completed mint
job that did not take the decline path resets it.

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

The issue compares the complete failing job/step set across attempts. A repeated
set is reported as a **repeated failure signature**, not as proof of a
deterministic root cause: external registries, notarization services, and runner
infrastructure can repeatedly fail at the same step. Logs and source diagnosis
decide whether to preserve the tag for a same-release rerun or land a source fix
and recut. Unreadable attempts are reported as indeterminate. A Release API 404
is reported as absence; any other API failure is reported as unknown state and
never rewritten as proof that no Release exists.

There is one exception, and only one: a tag the reviewed record has already
retired is reconciled instead of alerted. Before retrying or alerting, the
controller reads `scripts/abandoned-release-tags.json` from the run's own
default-branch commit and asks the same selector the mint asks. A tag that
record waives at exactly the commit the failed release ran gets no retry, no
issue, and a notice saying so, and that reconcile concludes success.

Every other outcome leaves the tag unrecorded and the alert armed, including a
record that cannot be read or is under-evidenced: an undiagnosed failure
still opens the issue and still fails the reconcile. See
[Abandoning a release tag](#abandoning-a-release-tag).

## Abandoning a release tag

Recovery stopping is not the end of the story. The rail serializes on the
highest `vX.Y.Z` tag being the finalized GitHub Latest release, which holds that
tag responsible for finishing. A tag whose artifacts can never be built cannot
finish, and on its own it holds the gate closed against every successor,
including the one that repairs whatever made it unbuildable.

`scripts/abandoned-release-tags.json` is the reviewed way out. It is the only
thing that waives the predicate for a tag, so a tag that is merely failing so far
keeps blocking, which is what the predicate is for. Each entry records the `tag`,
the exact `sha` it pointed at, a `reason`, the `superseded_by` tag, and the
`failed_release_run_id` that evidences it. Both the record and the selector that
reads it are loaded from protected `main`, never from the checked-out release
commit, which predates any abandonment it has to honour.

Three consumers read it through that selector: the mint refuses to create a tag
it names, drift resolution skips that tag when it ranks the highest release the
rail must wait on, and automatic recovery stands down for it rather than
retrying and alerting on a release nobody intends to finish.

**Operating rule: record the abandonment and leave the tag in place.**

Deleting an abandoned tag while the workspace version still equals it wedges both
rails, and nothing automatic recovers:

- the mint refuses, because the abandonment refusal reads the record and not the
  tag listing, so the version stays burned after its tag is gone (this is
  deliberate: a burned version must never be re-minted onto a different commit)
- drift resolution defers rather than proposing a bump, because it finds no base
  tag to measure from and hands the transition to the mint that is refusing

The only exit from that state is a hand-landed version bump. Delete an abandoned
tag only when a version bump is landing with it.

Two further properties worth knowing before editing the record:

- an entry applies only while it still describes the repository. It names the
  exact commit its tag pointed at, so a tag that has since moved refuses loudly
  rather than quietly waiving a different object than the one reviewed
- a malformed, unparsable, or under-evidenced entry fails the rail closed rather
  than degrading to an empty waiver set, and recovery decides through that same
  selector, so an entry that cannot waive the rail cannot quiet the alarm either

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
The one explicit pre-marker migration release, v0.3.6, also has to
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

On mint success the tag exists and `release.yml` has started. A break-glass
refusal or hard policy failure fails at the offending step with an `::error::`
line and creates nothing. Correct automatic declines follow the warning and
four-decline escalation behavior above; they are not successful mints.

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
   posture, but the App is currently installed **org-wide** (founder decision).
   See "Install scope and token narrowing" below for why that is still safe.
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
   - `KIN_RELEASE_BOT_APP_ID`: the App ID (numeric).
   - `KIN_RELEASE_BOT_PRIVATE_KEY`: the full PEM contents, including the
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
to the `kin` repository alone. The raw private key carries more authority than one
narrowed token, so it must exist only as a secret in the main-only
`release-tag` Environment and only default-branch-pinned trigger paths may
consume it.
Extending bot-mediated tagging to another repo is a deliberate act: replicate
this workflow and its protected Environment in that repo and widen or duplicate
the `repositories:` narrowing to name the new repo explicitly. Never drop the
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

## Registry dependency wave

`.github/workflows/kin-registry-release.yml` receives a typed
`kin-registry-release` dispatch from a registry publish, reconciles the full
pin set hourly, prepares the new Cargo pins on a credential-free runner, and
writes the admitted bytes to one pull request on
`automation/kin-registry-dependency-wave` through the release App. Every job
binds to the commit it checked out, `github.sha`, and proves it is protected
main's history with `scripts/verify-protected-main-history.py`: the commit must
be the tip of `main` or an ancestor of it, read through the compare API. A lane
landing while the receiver runs no longer refuses the wave; a force-pushed or
foreign ref still does. The wave's pull base is proven to be protected main at
or after the admitted base for the same reason, in the receiver, the attester
and the CI gate alike.

`.github/workflows/kin-registry-release-attest.yml` then binds the exact wave
head to a release-App attestation that the required CI gate revalidates.

The pull-request action rebases the wave onto main's current tip, so once
main has moved the head's tree is tip plus delta rather than policy plus
delta. The receiver's post-write check, the attester and the CI gate therefore
prove the head carries exactly the admitted delta instead of comparing trees:
its parent is protected main at or after the admitted base, main did not touch
the pin files in between, the delta read against that parent passes every
admission rule, and transplanting the head's pin files onto the admitted base
reproduces the admitted tree. With an unmoved main every clause is the old
equality.

`.github/workflows/kin-registry-wave-land.yml` lands the wave. It runs on the
wave branch's own CI completion, on a typed `kin-registry-wave-land`
repository dispatch (the manual kick, admitted from the captain and the
release App, which the receiver sends once after every wave it writes), and on
a sweep four times an hour as a fallback. `scripts/land-kin-registry-wave.py`
decides `land`, `wait` or `refuse`: one open first-party wave opened by the
release App with no auto-merge armed, one bot commit carrying the reserved
marker, a diff inside `Cargo.toml` and `Cargo.lock`, every check-run on the
head concluded and none failed over the full set (`per_page=100`, the listed
length asserted against `total_count`, the newest run per check name, skipped
and neutral green, the six ruleset contexts present), the pull mergeable, and
the attestation verified. A judgment re-reads the whole snapshot for a bounded
budget while the verdict is a transient wait (checks running, a cancelled
suite awaiting its rerun, an attestation on its way, GitHub still computing
mergeability, a re-pushed head), so one trigger outlasts the checks it waits
on. Only then does the land job mint the App token, squash-merge with the pull
title and body and never the marker line, and prove the squash is on `main`.
A failed check, a foreign commit, an off-scope file or an unreadable listing
refuses loudly; everything transient and an open hold wait quietly. A wave
whose pins a lane already carried onto main has nothing to merge and is left
for the receiver's next refresh, never squashed as an empty diff. GitHub's
own auto-merge is not the mechanism, because it merges on the six ruleset
contexts alone and the admission chain refuses any server-owned landing state
on the wave.

Kick one judgment by hand with:

```sh
gh api --method POST repos/firelock-ai/kin/dispatches \
  -f event_type=kin-registry-wave-land \
  -f 'client_payload[reason]=<why>'
```

The hold is the repository variable `KIN_MAIN_FROZEN`, the wave's equivalent
of the fleet's `kin_main_frozen` gate. Set it with
`gh variable set KIN_MAIN_FROZEN --repo firelock-ai/kin --body "<why>"` and
lift it with `gh variable delete KIN_MAIN_FROZEN --repo firelock-ai/kin`. Any
non-empty value holds every wave landing and is named in the judgment.
