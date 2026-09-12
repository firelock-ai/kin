#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Alarm on a parked release rail without needing any Claude credential.

release-sentinel.yml's agent-driven `patrol` job reads the release train's own hold
marker and re-arms disarmed pull requests, but it only runs when
`secrets.CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI` is wired, and even wired it has never
watched the specific handoff this script watches. `release-cut.yml` triggers on
`workflow_run` completions of RC Build, and that trigger is exactly the kind
docs/traps.md's "workflow_run trigger that fires after an upstream workflow completes"
entry already named as slow and sometimes silent: an occasion can simply never arrive.
Measured live on this repository: RC Build run 34485474934 concluded success for the
v0.7.10 candidate on `release/v0.7.10-candidate` at 2026-09-10T14:43:07Z, and the first
Release Cut run of ANY kind after it was not created until 2026-09-10T16:35:09Z, 112
minutes later, a `repository_dispatch` at 17:28:38Z reading as the actual recovery
(matching the remedy docs/traps.md already names: `release-cut.yml` has no
`workflow_dispatch` of its own, so re-firing it is a `repository_dispatch` of type
`release_cut`, not a `gh workflow run`). v0.7.9 sat parked the same way earlier the same
day. Nothing that depends on a Claude credential can be the ONLY thing watching for
this, because the credential itself can be the reason nothing is watching (see
`release-sentinel-credential-alarm.py`), so this check needs none.

A parked rail, for this script, is exactly what was measured: an RC Build run that
concluded `success` on a `release/v*` branch (matching `release-cut.yml`'s own `select`
job trigger filter, so a manual dispatch on some other branch is correctly never judged
a parked rail) with no Release Cut run of any kind created within
PARKED_RAIL_WINDOW_MINUTES of its conclusion. "Any kind" is deliberate: this checks for
a follow-on run EXISTING, not for proof that its `select` job actually decided
something, because the GitHub API gives no cheap way to prove a specific Release Cut
run was caused by a specific RC Build run's completion. A Release Cut run that gets
created within the window but then skips every job (the OTHER shape docs/traps.md's
entry documents, from 2026-09-06) reads CLEAR here; that is a narrower, real gap in this
specific check, left for a future patrol rather than silently claimed as covered.

Verdicts:

  CLEAR      no RC Build run needs following up (none qualify, or one already has a
             follow-on inside the window).
  PENDING    the newest qualifying RC Build run concluded less than
             PARKED_RAIL_WINDOW_MINUTES ago with no follow-on YET. Too soon to judge;
             not an alarm.
  PARKED     the window fully elapsed with no follow-on ever. Open or update the
             tracking issue and fail the job.
  RECOVERED  the window elapsed with nothing inside it, but a follow-on has since
             appeared later. The immediate problem resolved (by hand or by a later
             schedule tick); close the tracking issue rather than re-alarming forever
             on a candidate the rail has already moved past.

Only PARKED fails the job. Falsified with `--self-test`, fully offline: both RC Build
and Release Cut run lists are plain Python data, `now` is an explicit timestamp, and
`gh` is a self-test-only in-memory fake, so the state machine and its two negative
controls (branch prefix, conclusion) are graded without touching a real repository or
the real clock. Wired into `ci.yml`'s `fast-gate-lint` and `check` jobs alongside
`check-required-contexts.py --self-test`, for the reason the comment beside that one
gives: `bin/kin-precheck` enumerates guard scripts out of the `check` job by name, and
only `fast-gate-lint` runs on a pull request.
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

# The one named constant the window is measured against. Chosen to match
# release-cut.yml's own schedule fallback (cron "3,18,33,48 * * * *", every 15
# minutes): if that fallback tick is healthy, a stuck workflow_run occasion should
# still be covered by the next one inside this window, so 15 minutes is "give the
# system's own designed recovery path one full cycle", not an arbitrary guess.
PARKED_RAIL_WINDOW_MINUTES = 15

RC_BUILD_WORKFLOW_FILE = "rc-build.yml"
RELEASE_CUT_WORKFLOW_FILE = "release-cut.yml"

CLEAR = "CLEAR"
PENDING = "PENDING"
PARKED = "PARKED"
RECOVERED = "RECOVERED"

ALARM_TITLE = "Release rail is parked: RC Build has no follow-on Release Cut run"

# The alarm lives on firelock-ai/kin-infra beside every other repository's alarms,
# and the label passed as --label is how a reader tells whose each one is.
LABEL_COLOR = "5319E7"

# The run lookups above read THIS repository with the workflow token. The alarm
# repository is another, private repository that token cannot reach, so the calls
# that touch it swap in the issues-only App token the workflow minted, carried in
# this variable. Absent, the alarm calls use whatever GH_TOKEN the run has, which is
# right when the alarm repository is this one.
ALARM_TOKEN_ENV = "KIN_ALARM_TOKEN"


class Unreadable(Exception):
    """A `gh` call failed, or answered with a shape this script does not recognize."""


def gh(args, capture=True, env=None):
    """Run gh, refusing an empty answer rather than treating it as a zero (same idiom
    as acceptance_red_alarm.py and release-sentinel-credential-alarm.py: a gh call can
    go out unauthenticated and its 403 wears a quota costume)."""
    proc = subprocess.run(["gh"] + args, capture_output=capture, text=True, check=False, env=env)
    if proc.returncode != 0:
        raise Unreadable(
            "gh %s exited %d: %s" % (" ".join(args), proc.returncode, (proc.stderr or "").strip()[:400])
        )
    return proc.stdout


def alarm_env(base=None):
    """Pure. The environment for a gh call that touches the alarm repository: the
    caller's environment with GH_TOKEN replaced by the alarm token when one is set."""
    env = dict(os.environ if base is None else base)
    token = env.get(ALARM_TOKEN_ENV)
    if token:
        env["GH_TOKEN"] = token
    return env


def gh_alarm(args, capture=True):
    return gh(args, capture=capture, env=alarm_env())


def ensure_label(repo, label, gh_fn=gh):
    """Create the source-repository label on the alarm repository, idempotently.

    Created before the issue rather than assumed, because a create against a missing
    label fails, and an alarm that fails to file is the one outcome this script exists
    to prevent. `--force` makes an existing label a no-op.
    """
    gh_fn(["label", "create", label, "--repo", repo, "--force", "--color", LABEL_COLOR,
           "--description", "Alarms raised by the %s repository's workflows" % label])


def gh_json(args, gh_fn):
    out = gh_fn(args)
    if not out.strip():
        raise Unreadable("gh %s returned no bytes" % " ".join(args))
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise Unreadable("gh %s did not return JSON: %s" % (" ".join(args), exc))


def parse_iso8601(ts):
    """GitHub's REST API timestamps are UTC and always end in Z, e.g.
    '2026-09-10T14:43:07Z'. Naive strptime would silently accept a non-UTC-looking
    string too, so this is the one place that shape is enforced."""
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def fetch_rc_build_runs(repo, gh_fn):
    data = gh_json(
        ["api", "repos/%s/actions/workflows/%s/runs?event=workflow_dispatch&status=success&per_page=100"
         % (repo, RC_BUILD_WORKFLOW_FILE)],
        gh_fn,
    )
    runs = data.get("workflow_runs") if isinstance(data, dict) else None
    if runs is None:
        raise Unreadable("RC Build runs listing did not answer with a workflow_runs list")
    return runs


def fetch_release_cut_runs(repo, gh_fn):
    data = gh_json(
        ["api", "repos/%s/actions/workflows/%s/runs?per_page=100" % (repo, RELEASE_CUT_WORKFLOW_FILE)],
        gh_fn,
    )
    runs = data.get("workflow_runs") if isinstance(data, dict) else None
    if runs is None:
        raise Unreadable("Release Cut runs listing did not answer with a workflow_runs list")
    return runs


def select_newest_qualifying_rc_build(rc_build_runs):
    """release-cut.yml's own `select` job only reacts to an RC Build completion that is
    `event == 'workflow_dispatch'` on a branch `startsWith('release/v')`; a manual
    dispatch on any other branch was never going to get a Release Cut follow-on and
    must not be judged a parked rail. Restricted to `conclusion == 'success'` to match
    the ticket's own definition; a failed candidate build has a different, separate
    remediation (retry the build)."""
    candidates = [
        r for r in rc_build_runs
        if r.get("conclusion") == "success" and str(r.get("head_branch") or "").startswith("release/v")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda r: parse_iso8601(r["updated_at"]))


def classify_rc_build(rc_build, release_cut_runs, now):
    """Pure. `rc_build` carries at least 'updated_at' (its conclusion time) and
    'html_url'; `release_cut_runs` each carry at least 'created_at' and 'html_url';
    `now` is an aware UTC datetime. Returns (verdict, detail)."""
    concluded_at = parse_iso8601(rc_build["updated_at"])
    window = timedelta(minutes=PARKED_RAIL_WINDOW_MINUTES)
    window_end = concluded_at + window
    elapsed = now - concluded_at

    in_window = [
        r for r in release_cut_runs
        if concluded_at <= parse_iso8601(r["created_at"]) <= window_end
    ]
    if in_window:
        newest = max(in_window, key=lambda r: parse_iso8601(r["created_at"]))
        minutes = (parse_iso8601(newest["created_at"]) - concluded_at).total_seconds() / 60
        return CLEAR, (
            "a Release Cut run appeared %.1f minute(s) after RC Build concluded, inside "
            "the %d-minute window (%s)" % (minutes, PARKED_RAIL_WINDOW_MINUTES, newest.get("html_url", "?"))
        )

    if elapsed < window:
        return PENDING, (
            "only %.1f minute(s) have passed since RC Build concluded; the %d-minute "
            "window is not up yet" % (elapsed.total_seconds() / 60, PARKED_RAIL_WINDOW_MINUTES)
        )

    after_at_all = [r for r in release_cut_runs if parse_iso8601(r["created_at"]) > concluded_at]
    if after_at_all:
        # The FIRST one to appear after the window closed is what actually ended the
        # parked state, not whichever is newest right now; a run picked by max() here
        # would report the most recent tick's timestamp forever, no matter how long
        # ago the rail actually recovered.
        first = min(after_at_all, key=lambda r: parse_iso8601(r["created_at"]))
        minutes = (parse_iso8601(first["created_at"]) - concluded_at).total_seconds() / 60
        return RECOVERED, (
            "no Release Cut run appeared within %d minutes, but one appeared %.1f "
            "minute(s) later (%s); the rail has since moved"
            % (PARKED_RAIL_WINDOW_MINUTES, minutes, first.get("html_url", "?"))
        )

    return PARKED, (
        "%.1f minute(s) have passed since RC Build concluded with no follow-on Release "
        "Cut run at all" % (elapsed.total_seconds() / 60)
    )


def decide(rc_build_runs, release_cut_runs, now):
    """Returns (verdict, detail, rc_build_or_None). Only the single newest qualifying
    RC Build run is judged: once a newer candidate exists, an older one going
    unfollowed is moot, and re-alarming on it forever would be noise about a rail that
    has already moved on to the next candidate."""
    rc_build = select_newest_qualifying_rc_build(rc_build_runs)
    if rc_build is None:
        return CLEAR, "no RC Build run on a release/v* branch has concluded success yet", None
    verdict, detail = classify_rc_build(rc_build, release_cut_runs, now)
    return verdict, detail, rc_build


def find_issue(repo, gh_fn=gh):
    """Exact-title lookup, matching the sibling alarm scripts in this repository."""
    out = gh_fn(["issue", "list", "--repo", repo, "--state", "open", "--limit", "100",
                 "--json", "number,title"])
    rows = json.loads(out or "[]")
    for row in rows:
        if row.get("title") == ALARM_TITLE:
            return row.get("number")
    return None


def render_alarm_body(repo, rc_build, detail):
    lines = [
        "The release rail looks parked.",
        "",
        "RC Build run [%s](%s) concluded success on `%s`, and %s."
        % (rc_build.get("id"), rc_build.get("html_url", "?"), rc_build.get("head_branch", "?"), detail),
        "",
        "Release Cut has no `workflow_dispatch` trigger of its own (every arm resolves "
        "its workflow code from protected main, and a workflow_dispatch takes a ref, so "
        "it would let a branch select the code that runs beside the release App's key); "
        "the recovery is a `repository_dispatch`:",
        "",
        "```",
        "gh api repos/%s/dispatches -f event_type=release_cut" % repo,
        "```",
        "",
        "This closes on the next patrol tick once a Release Cut run shows up after the "
        "RC Build run named above, whether that is this command, the next schedule "
        "tick, or a workflow_run occasion that was just slow.",
    ]
    return "\n".join(lines) + "\n"


def run_alarm(repo, rc_build_runs, release_cut_runs, now, dry_run=False, gh_fn=gh,
              alarm_repo=None, label=None, alarm_gh_fn=None):
    """`repo` is the repository whose rail was read and is named in the body;
    `alarm_repo` is where the issue lives (defaulting to `repo`), `label` names the
    source repository on it, and `alarm_gh_fn` is the gh that can reach it."""
    alarm_repo = alarm_repo or repo
    alarm_gh_fn = alarm_gh_fn or gh_fn
    verdict, detail, rc_build = decide(rc_build_runs, release_cut_runs, now)
    subject = "RC Build %s" % rc_build.get("id") if rc_build else "no qualifying RC Build run"
    print("VERDICT %s (%s): %s" % (verdict, subject, detail))

    if dry_run:
        if verdict == PARKED:
            print("--- body ---")
            print(render_alarm_body(repo, rc_build, detail))
        return verdict

    existing = find_issue(alarm_repo, gh_fn=alarm_gh_fn)
    if verdict == PARKED:
        body = render_alarm_body(repo, rc_build, detail)
        if existing:
            alarm_gh_fn(["issue", "comment", str(existing), "--repo", alarm_repo, "--body", body])
            print("updated tracking issue #%s" % existing)
        else:
            create = ["issue", "create", "--repo", alarm_repo, "--title", ALARM_TITLE, "--body", body]
            if label:
                ensure_label(alarm_repo, label, gh_fn=alarm_gh_fn)
                create += ["--label", label]
            number = alarm_gh_fn(create)
            print("opened tracking issue %s" % number.strip())
    else:
        if existing:
            alarm_gh_fn(["issue", "close", str(existing), "--repo", alarm_repo, "--comment",
                         "The rail is no longer parked: %s" % detail])
            print("closed tracking issue #%s" % existing)
        else:
            print("nothing open to close")
    return verdict


# ─── Controls ───────────────────────────────────────────────────────────────
#
# The first two fixtures are the real, measured incident this check exists for:
# RC Build 34485474934 (v0.7.10) and the six real Release Cut runs read back from
# `gh api` on 2026-09-10 between 16:35:09Z and 18:05:20Z. Everything else is
# synthetic, built to isolate one behaviour each, including both negative controls a
# check like this must carry (see docs/traps.md's "checks that cannot fail" doctrine):
# a manual dispatch on a non-release branch, and a failed candidate build, must both
# read CLEAR rather than PARKED, or the filters that are supposed to exclude them are
# not actually excluding anything.

REAL_RC_BUILD_V0_7_10 = {
    "id": 34485474934,
    "conclusion": "success",
    "head_branch": "release/v0.7.10-candidate",
    "updated_at": "2026-09-10T14:43:07Z",
    "html_url": "https://github.com/firelock-ai/kin/actions/runs/34485474934",
}

# The real Release Cut runs observed after it, earliest first. The gap between
# 14:43:07Z and 16:35:09Z (the first of these) is 112 minutes, the actual parked
# window this ticket measured.
REAL_RELEASE_CUT_FOLLOWUPS = [
    {"id": 34503004278, "created_at": "2026-09-10T16:35:09Z", "html_url": "https://x/34503004278"},
    {"id": 34504140482, "created_at": "2026-09-10T16:46:25Z", "html_url": "https://x/34504140482"},
    {"id": 34508449033, "created_at": "2026-09-10T17:28:38Z", "html_url": "https://x/34508449033"},
    {"id": 34509491534, "created_at": "2026-09-10T17:38:53Z", "html_url": "https://x/34509491534"},
    {"id": 34510058702, "created_at": "2026-09-10T17:44:33Z", "html_url": "https://x/34510058702"},
    {"id": 34512168539, "created_at": "2026-09-10T18:05:20Z", "html_url": "https://x/34512168539"},
]


class _FakeGh:
    """Records every call and answers `issue list`/`issue create` from in-memory
    state, matching release-sentinel-credential-alarm.py's fake."""

    def __init__(self, existing_issue=None):
        self.calls = []
        self.next_number = 202
        self.open_issue = existing_issue
        self.closed_issue = None
        self.comments = []
        self.labels = []

    def __call__(self, args):
        self.calls.append(args)
        if args[0] == "label" and args[1] == "create":
            self.labels.append(args[2])
            return ""
        if args[0] == "issue" and args[1] == "list":
            rows = [{"number": self.open_issue, "title": ALARM_TITLE}] if self.open_issue else []
            return json.dumps(rows)
        if args[0] == "issue" and args[1] == "create":
            self.open_issue = self.next_number
            return str(self.next_number)
        if args[0] == "issue" and args[1] == "comment":
            self.comments.append(args[2])
            return ""
        if args[0] == "issue" and args[1] == "close":
            self.closed_issue = self.open_issue
            self.open_issue = None
            return ""
        raise AssertionError("unexpected gh call in self-test: %r" % (args,))


def self_test():
    failures = []

    def check(name, cond):
        print("CONTROL %s %s" % ("PASS" if cond else "FAIL", name))
        if not cond:
            failures.append(name)

    # THE REGRESSION, replayed on real data: nothing at all inside the window, judged
    # 32 minutes after RC Build concluded, must read PARKED.
    now_soon_after = parse_iso8601("2026-09-10T15:15:00Z")
    verdict, detail, rc_build = decide([REAL_RC_BUILD_V0_7_10], [], now_soon_after)
    check("THE REGRESSION: v0.7.10's RC Build with nothing following reads PARKED",
          verdict == PARKED)
    check("PARKED names the real RC Build run", rc_build is not None and rc_build["id"] == 34485474934)
    check("PARKED's detail names an elapsed time consistent with 32 minutes",
          "32" in detail or "31.9" in detail or "32.0" in detail)

    # Same real RC Build, judged now with the real follow-ups on record: the window
    # itself still saw nothing (112 minutes to the first), but a follow-on did show up
    # later, so this must read RECOVERED, not a permanent PARKED.
    now_much_later = parse_iso8601("2026-09-10T18:17:00Z")
    verdict, detail, rc_build = decide([REAL_RC_BUILD_V0_7_10], REAL_RELEASE_CUT_FOLLOWUPS, now_much_later)
    check("the same RC Build, judged after real follow-ups exist, reads RECOVERED",
          verdict == RECOVERED)
    check("RECOVERED names the ~112-minute gap", "112" in detail)

    # Synthetic CLEAR: a follow-on inside the window.
    t0 = parse_iso8601("2026-01-01T00:00:00Z")
    healthy_rc = {"id": 1, "conclusion": "success", "head_branch": "release/v1.0.0-candidate",
                  "updated_at": "2026-01-01T00:00:00Z", "html_url": "https://x/1"}
    healthy_followup = [{"id": 2, "created_at": "2026-01-01T00:05:00Z", "html_url": "https://x/2"}]
    verdict, detail, _ = decide([healthy_rc], healthy_followup, t0 + timedelta(minutes=20))
    check("a follow-on inside the window reads CLEAR", verdict == CLEAR)

    # Synthetic PENDING: too soon to tell, must not alarm on a totally fresh success.
    verdict, detail, _ = decide([healthy_rc], [], t0 + timedelta(minutes=5))
    check("a fresh RC Build with no follow-on YET reads PENDING, not PARKED", verdict == PENDING)

    # Boundary: just under the window is PENDING, at/over the window with nothing is PARKED.
    verdict, _, _ = decide([healthy_rc], [], t0 + timedelta(minutes=14, seconds=59))
    check("14:59 elapsed with nothing yet is still PENDING", verdict == PENDING)
    verdict, _, _ = decide([healthy_rc], [], t0 + timedelta(minutes=15))
    check("exactly 15:00 elapsed with nothing yet tips into PARKED", verdict == PARKED)

    # No qualifying RC Build run at all: CLEAR, not an error and not PARKED.
    verdict, detail, rc_build = decide([], [], t0)
    check("no RC Build runs at all reads CLEAR", verdict == CLEAR and rc_build is None)

    # Negative control: a manual dispatch on a non-release branch must never be judged,
    # even with no follow-on ever and the window long elapsed. Without this control the
    # branch-prefix filter could be silently absent and every fixture above would still
    # pass.
    off_branch_rc = {"id": 3, "conclusion": "success", "head_branch": "some-feature-branch",
                      "updated_at": "2026-01-01T00:00:00Z", "html_url": "https://x/3"}
    verdict, detail, rc_build = decide([off_branch_rc], [], t0 + timedelta(hours=5))
    check("a manual dispatch off a release/v* branch is excluded, reading CLEAR",
          verdict == CLEAR and rc_build is None)

    # Negative control: a failed candidate build must never be judged either.
    failed_rc = {"id": 4, "conclusion": "failure", "head_branch": "release/v1.0.1-candidate",
                 "updated_at": "2026-01-01T00:00:00Z", "html_url": "https://x/4"}
    verdict, detail, rc_build = decide([failed_rc], [], t0 + timedelta(hours=5))
    check("a failed RC Build is excluded, reading CLEAR", verdict == CLEAR and rc_build is None)

    # Superseded-candidate control: an older PARKED-shaped RC Build must not win over a
    # newer, healthy one. Only the newest qualifying run is ever judged.
    older_parked = {"id": 5, "conclusion": "success", "head_branch": "release/v1.0.0-candidate",
                    "updated_at": "2026-01-01T00:00:00Z", "html_url": "https://x/5"}
    newer_healthy = {"id": 6, "conclusion": "success", "head_branch": "release/v1.0.1-candidate",
                     "updated_at": "2026-01-01T01:00:00Z", "html_url": "https://x/6"}
    newer_followup = [{"id": 7, "created_at": "2026-01-01T01:03:00Z", "html_url": "https://x/7"}]
    verdict, detail, rc_build = decide(
        [older_parked, newer_healthy], newer_followup, t0 + timedelta(hours=5)
    )
    check("a superseded older RC Build never blocks judgment of the newer one",
          verdict == CLEAR and rc_build is not None and rc_build["id"] == 6)

    # run_alarm's issue-mutation branching, same shape as the credential alarm's own
    # controls: create on first PARKED, comment (never duplicate) on repeat PARKED,
    # close on the next non-PARKED verdict, no-op when nothing is open and nothing
    # needs closing.
    fake = _FakeGh(existing_issue=None)
    verdict = run_alarm("firelock-ai/kin", [REAL_RC_BUILD_V0_7_10], [], now_soon_after, gh_fn=fake)
    check("first PARKED creates an issue", fake.open_issue == fake.next_number and verdict == PARKED)
    check("first PARKED never closes", fake.closed_issue is None)

    fake2 = _FakeGh(existing_issue=888)
    run_alarm("firelock-ai/kin", [REAL_RC_BUILD_V0_7_10], [], now_soon_after, gh_fn=fake2)
    check("repeat PARKED comments rather than duplicating", fake2.open_issue == 888 and len(fake2.comments) == 1)
    check("repeat PARKED never calls issue create",
          [c for c in fake2.calls if c[:2] == ["issue", "create"]] == [])

    fake3 = _FakeGh(existing_issue=999)
    verdict = run_alarm("firelock-ai/kin", [REAL_RC_BUILD_V0_7_10], REAL_RELEASE_CUT_FOLLOWUPS,
                         now_much_later, gh_fn=fake3)
    check("RECOVERED closes the open issue", fake3.closed_issue == 999 and verdict == RECOVERED)

    fake4 = _FakeGh(existing_issue=None)
    verdict = run_alarm("firelock-ai/kin", [], [], t0, gh_fn=fake4)
    check("CLEAR with nothing open performs no mutation",
          [c for c in fake4.calls if c[1] in ("create", "comment", "close")] == [] and verdict == CLEAR)

    # The alarm repository is not the repository whose rail was read. Every issue
    # call goes to the alarm repository through the alarm gh, the run repository
    # stays in the body, the label is created there before the issue that carries
    # it, and the gh that read the runs never touches an issue.
    runs_gh = _FakeGh(existing_issue=None)
    alarm_gh = _FakeGh(existing_issue=None)
    verdict = run_alarm("firelock-ai/kin", [REAL_RC_BUILD_V0_7_10], [], now_soon_after,
                        gh_fn=runs_gh, alarm_repo="firelock-ai/kin-infra", label="kin",
                        alarm_gh_fn=alarm_gh)
    created = [c for c in alarm_gh.calls if c[:2] == ["issue", "create"]]
    check("a routed PARKED creates exactly one issue through the alarm gh",
          verdict == PARKED and len(created) == 1)
    check("the routed create lands on the alarm repository",
          created and created[0][2:4] == ["--repo", "firelock-ai/kin-infra"])
    check("the routed create carries the source label",
          created and "--label" in created[0] and created[0][created[0].index("--label") + 1] == "kin")
    check("the label is created on the alarm repository before the issue",
          alarm_gh.labels == ["kin"]
          and alarm_gh.calls.index(["label", "create", "kin", "--repo", "firelock-ai/kin-infra",
                                    "--force", "--color", LABEL_COLOR, "--description",
                                    "Alarms raised by the kin repository's workflows"])
          < alarm_gh.calls.index(created[0]))
    check("the routed body still names the repository whose rail was read",
          created and "repos/firelock-ai/kin/dispatches" in created[0][created[0].index("--body") + 1])
    check("the gh that reads the runs never touches an issue", runs_gh.calls == [])

    alarm_gh_repeat = _FakeGh(existing_issue=889)
    run_alarm("firelock-ai/kin", [REAL_RC_BUILD_V0_7_10], [], now_soon_after,
              gh_fn=runs_gh, alarm_repo="firelock-ai/kin-infra", label="kin",
              alarm_gh_fn=alarm_gh_repeat)
    check("a routed repeat PARKED comments on the alarm repository and never relabels",
          alarm_gh_repeat.labels == [] and len(alarm_gh_repeat.comments) == 1
          and [c for c in alarm_gh_repeat.calls if c[:2] == ["issue", "create"]] == []
          and all(c[c.index("--repo") + 1] == "firelock-ai/kin-infra"
                  for c in alarm_gh_repeat.calls if "--repo" in c))

    # The token routing the workflow relies on: with the alarm token set, the alarm
    # calls authenticate with it; without it, the environment passes through unchanged.
    routed = alarm_env({"GH_TOKEN": "workflow", ALARM_TOKEN_ENV: "app"})
    check("alarm_env swaps in the alarm token when one is set", routed["GH_TOKEN"] == "app")
    check("alarm_env keeps the rest of the environment", routed[ALARM_TOKEN_ENV] == "app")
    untouched = alarm_env({"GH_TOKEN": "workflow"})
    check("alarm_env leaves GH_TOKEN alone when no alarm token is set",
          untouched == {"GH_TOKEN": "workflow"})

    print("release-rail-parked-alarm: self-test %s"
          % ("PASSED" if not failures else "FAILED on %s" % ", ".join(failures)))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "firelock-ai/kin"),
                        help="the repository whose rail is read")
    parser.add_argument("--alarm-repo", default=None,
                        help="where the tracking issue lives; defaults to --repo. Its gh calls "
                             "authenticate with $%s when set" % ALARM_TOKEN_ENV)
    parser.add_argument("--label", default=None,
                        help="the source-repository label to put on a newly opened alarm; "
                             "created on the alarm repository first when given")
    parser.add_argument("--dry-run", action="store_true", help="judge and print, touch no issue")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.self_test:
        return self_test()

    try:
        rc_build_runs = fetch_rc_build_runs(args.repo, gh)
        release_cut_runs = fetch_release_cut_runs(args.repo, gh)
        verdict = run_alarm(args.repo, rc_build_runs, release_cut_runs,
                             datetime.now(timezone.utc), dry_run=args.dry_run,
                             alarm_repo=args.alarm_repo, label=args.label, alarm_gh_fn=gh_alarm)
    except Unreadable as exc:
        print("VERDICT UNREADABLE %s" % exc)
        return 2
    return 0 if verdict != PARKED else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
