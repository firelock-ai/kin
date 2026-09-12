#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Fail the Release Sentinel run loud when it has no credential to patrol with.

release-sentinel.yml's `preflight` job reads
`secrets.CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI` and, when it is absent, printed a
`::notice::` and exited 0 "on purpose", so the downstream `patrol` job simply skipped.
Run 34506462232 (2026-09-10T17:09:20Z) is exactly that shape: `Resolve sentinel
credential` succeeded, `Patrol the release rail` shows SKIPPED, and the run's own
conclusion reads `success`. A skipped step reads as green to anyone scanning the
workflow list, so the one workflow whose entire job is to notice a silent release rail
was itself silent about being unable to run, for as long as nobody happened to open the
run and read the grey job. That is the same shape the sentinel exists to catch elsewhere
in the rail, just aimed at the sentinel itself.

This script is what a new `credential-alarm` job in release-sentinel.yml calls right
after `preflight`. It does not change what `preflight` reports (still a silent,
value-never-printed presence check) or what gates `patrol` (still
`needs.preflight.outputs.enabled`). It changes what happens on the disabled branch: the
job that runs this script now fails the run and opens or updates a single, exact-titled
tracking issue rather than letting a quiet `::notice::` be the only record. On the
enabled branch it closes that issue if one is open, so activating the credential is what
clears the alarm rather than a separate manual step.

Verdicts:

  ALARM   no credential. Open or update the tracking issue, fail the job.
  CLEAR   a credential is present. Close the tracking issue if one is open, succeed.

Falsified with `--self-test`, offline: every `gh` call is a self-test-only in-memory
fake, so the state machine (open on first ALARM, comment rather than duplicate on a
second ALARM, close on the next CLEAR, no-op when already clear) is graded without
touching a real repository. Wired into `ci.yml`'s `fast-gate-lint` and `check` jobs
alongside `check-required-contexts.py --self-test`, for the reason the comment beside
that one gives: `bin/kin-precheck` enumerates guard scripts out of the `check` job by
name, and only `fast-gate-lint` runs on a pull request, so a self-test living in only
one of them is invisible to the other.
"""

import argparse
import json
import os
import subprocess
import sys

ALARM = "ALARM"
CLEAR = "CLEAR"

ALARM_TITLE = "Release Sentinel has no credential to patrol with"

# The alarm lives on firelock-ai/kin-infra beside every other repository's alarms,
# and the label passed as --label is how a reader tells whose each one is.
LABEL_COLOR = "5319E7"


class Unreadable(Exception):
    """A `gh` call failed or answered with nothing usable."""


def gh(args, capture=True):
    """Run gh, refusing an empty answer rather than treating it as a zero.

    A gh call can go out unauthenticated and its 403 wears a quota costume (see
    docs/traps.md's "A gh call can go out unauthenticated" entry), so an empty read is
    Unreadable here rather than "nothing found".
    """
    proc = subprocess.run(["gh"] + args, capture_output=capture, text=True, check=False)
    if proc.returncode != 0:
        raise Unreadable(
            "gh %s exited %d: %s" % (" ".join(args), proc.returncode, (proc.stderr or "").strip()[:400])
        )
    return proc.stdout


def find_issue(repo, gh_fn=gh):
    """Exact-title lookup, matching acceptance_red_alarm.py's find_issue.

    A search expression could widen into an unrelated issue, so the title is compared
    for equality rather than passed to GitHub's fuzzy issue search.
    """
    out = gh_fn(["issue", "list", "--repo", repo, "--state", "open", "--limit", "100",
                 "--json", "number,title"])
    rows = json.loads(out or "[]")
    for row in rows:
        if row.get("title") == ALARM_TITLE:
            return row.get("number")
    return None


def ensure_label(repo, label, gh_fn=gh):
    """Create the source-repository label on the alarm repository, idempotently.

    Created before the issue rather than assumed, because a create against a missing
    label fails, and an alarm that fails to file is the one outcome this script exists
    to prevent. `--force` makes an existing label a no-op.
    """
    gh_fn(["label", "create", label, "--repo", repo, "--force", "--color", LABEL_COLOR,
           "--description", "Alarms raised by the %s repository's workflows" % label])


def judge(enabled):
    """Pure. `enabled` is the exact string release-sentinel.yml's `preflight` job
    outputs: 'true' when the secret is present, anything else otherwise."""
    return CLEAR if enabled == "true" else ALARM


def render_alarm_body(run_url):
    lines = [
        "The Release Sentinel has no credential to patrol with.",
        "",
        "`secrets.CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI` is not set, so `patrol` in "
        "`.github/workflows/release-sentinel.yml` is skipped this run and the three "
        "agent duties (re-arming a disarmed green pull request, judging a held release "
        "train, drafting an abandonment for a structurally dead tag) did not run.",
        "",
        "- run: %s" % run_url,
        "",
        "Mint the credential and wire it, which closes this issue on the next scheduled run:",
        "",
        "```",
        "claude setup-token",
        "gh secret set CLAUDE_CODE_OAUTH_TOKEN_TROY_FIRELOCK_AI --org firelock-ai --visibility all",
        "```",
        "",
        "The mechanical patrol in the same workflow (`release-rail-parked-alarm.py`) needs "
        "no credential and keeps watching the RC-Build-to-Release-Cut handoff either way; "
        "this issue is only about the agent duties above being unable to run.",
    ]
    return "\n".join(lines) + "\n"


def run_alarm(repo, enabled, run_url, dry_run=False, gh_fn=gh, label=None):
    """`repo` is where the alarm issue lives (the alarm repository, not necessarily the
    repository whose sentinel this is); `label` names the source repository on it."""
    verdict = judge(enabled)
    print("VERDICT %s (preflight enabled=%r)" % (verdict, enabled))

    if dry_run:
        if verdict == ALARM:
            print("--- body ---")
            print(render_alarm_body(run_url))
        return verdict

    existing = find_issue(repo, gh_fn=gh_fn)
    if verdict == ALARM:
        body = render_alarm_body(run_url)
        if existing:
            gh_fn(["issue", "comment", str(existing), "--repo", repo, "--body", body])
            print("updated tracking issue #%s" % existing)
        else:
            create = ["issue", "create", "--repo", repo, "--title", ALARM_TITLE, "--body", body]
            if label:
                ensure_label(repo, label, gh_fn=gh_fn)
                create += ["--label", label]
            number = gh_fn(create)
            print("opened tracking issue %s" % number.strip())
    else:
        if existing:
            gh_fn([
                "issue", "close", str(existing), "--repo", repo, "--comment",
                "A credential is wired again, verified by %s. The agent patrol duties resume "
                "on the next scheduled run." % run_url,
            ])
            print("closed tracking issue #%s" % existing)
        else:
            print("nothing open to close")
    return verdict


# ─── Controls ───────────────────────────────────────────────────────────────
#
# Every `gh` call in self-test goes through _FakeGh, never a subprocess, so this is
# deterministic in a network-denied sandbox and exercises the actual open/comment/close
# branching rather than only the boolean judge.

class _FakeGh:
    """Records every call and answers `issue list`/`issue create` from in-memory state,
    so a control can assert both the final state and which mutation actually fired."""

    def __init__(self, existing_issue=None):
        self.calls = []
        self.next_number = 101
        self.open_issue = existing_issue  # None, or an int issue number
        self.closed_issue = None
        self.comments = []
        self.labels = []

    def __call__(self, args):
        self.calls.append(args)
        cmd = args[0] if args else ""
        if cmd == "label" and args[1] == "create":
            self.labels.append(args[2])
            return ""
        if cmd == "issue" and args[1] == "list":
            rows = [{"number": self.open_issue, "title": ALARM_TITLE}] if self.open_issue else []
            return json.dumps(rows)
        if cmd == "issue" and args[1] == "create":
            self.open_issue = self.next_number
            return str(self.next_number)
        if cmd == "issue" and args[1] == "comment":
            self.comments.append(args[2])
            return ""
        if cmd == "issue" and args[1] == "close":
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

    # judge() is the load-bearing boolean: this is the exact string comparison that
    # decides whether the job that calls this script fails or succeeds.
    check("judge('true') is CLEAR", judge("true") == CLEAR)
    check("judge('false') is ALARM", judge("false") == ALARM)
    check("judge('') is ALARM (an empty output reads as disabled, never as enabled)", judge("") == ALARM)
    check("judge(None) is ALARM", judge(None) == ALARM)

    # First ALARM with nothing open: creates exactly one issue, never a comment or close.
    fake = _FakeGh(existing_issue=None)
    verdict = run_alarm("firelock-ai/kin", "false", "https://example/runs/1", gh_fn=fake)
    check("first ALARM returns ALARM", verdict == ALARM)
    check("first ALARM creates an issue", fake.open_issue == fake.next_number)
    check("first ALARM never closes", fake.closed_issue is None)
    check("first ALARM posts no comment (nothing existed to comment on)", fake.comments == [])
    check("an unlabelled ALARM touches no label", fake.labels == [])

    # The alarm repository and the source label, as release-sentinel.yml passes them:
    # every call lands on the repository given, the label is created before the issue
    # that carries it, and the create is the only call that carries it.
    fake_labelled = _FakeGh(existing_issue=None)
    run_alarm("firelock-ai/kin-infra", "false", "https://example/runs/5",
              gh_fn=fake_labelled, label="kin")
    labelled_create = [c for c in fake_labelled.calls if c[:2] == ["issue", "create"]]
    check("a labelled ALARM creates exactly one issue", len(labelled_create) == 1)
    check("the labelled create lands on the alarm repository",
          labelled_create and labelled_create[0][2:4] == ["--repo", "firelock-ai/kin-infra"])
    check("the labelled create carries the source label",
          labelled_create and "--label" in labelled_create[0]
          and labelled_create[0][labelled_create[0].index("--label") + 1] == "kin")
    check("the label is created on the alarm repository before the issue",
          fake_labelled.labels == ["kin"]
          and fake_labelled.calls.index(["label", "create", "kin", "--repo", "firelock-ai/kin-infra",
                                         "--force", "--color", LABEL_COLOR, "--description",
                                         "Alarms raised by the kin repository's workflows"])
          < fake_labelled.calls.index(labelled_create[0]))

    fake_labelled_repeat = _FakeGh(existing_issue=556)
    run_alarm("firelock-ai/kin-infra", "false", "https://example/runs/6",
              gh_fn=fake_labelled_repeat, label="kin")
    check("a labelled repeat ALARM comments and never relabels or recreates",
          fake_labelled_repeat.labels == [] and len(fake_labelled_repeat.comments) == 1
          and [c for c in fake_labelled_repeat.calls if c[:2] == ["issue", "create"]] == [])

    # A second ALARM while one is already open: comments on it, creates no duplicate.
    fake2 = _FakeGh(existing_issue=555)
    verdict = run_alarm("firelock-ai/kin", "false", "https://example/runs/2", gh_fn=fake2)
    check("repeat ALARM returns ALARM", verdict == ALARM)
    check("repeat ALARM does not open a second issue", fake2.open_issue == 555)
    check("repeat ALARM comments on the existing issue rather than duplicating it",
          len(fake2.comments) == 1)
    create_calls = [c for c in fake2.calls if c[:2] == ["issue", "create"]]
    check("repeat ALARM never calls issue create", create_calls == [])

    # CLEAR with an issue open: closes it.
    fake3 = _FakeGh(existing_issue=777)
    verdict = run_alarm("firelock-ai/kin", "true", "https://example/runs/3", gh_fn=fake3)
    check("CLEAR with an open issue returns CLEAR", verdict == CLEAR)
    check("CLEAR closes the open issue", fake3.closed_issue == 777)
    check("CLEAR leaves nothing open afterward", fake3.open_issue is None)

    # CLEAR with nothing open: a true no-op, no gh mutation at all.
    fake4 = _FakeGh(existing_issue=None)
    verdict = run_alarm("firelock-ai/kin", "true", "https://example/runs/4", gh_fn=fake4)
    check("CLEAR with nothing open returns CLEAR", verdict == CLEAR)
    mutating_calls = [c for c in fake4.calls if c[1] in ("create", "comment", "close")]
    check("CLEAR with nothing open performs no mutation", mutating_calls == [])

    # THE REGRESSION this script exists to prevent: an absent credential must never
    # read as a job that quietly does nothing and succeeds. If a future edit reintroduces
    # "exit 0 regardless", this control catches it independent of anything gh-shaped.
    check(
        "THE REGRESSION: a missing credential never judges CLEAR",
        judge("false") != CLEAR and judge("") != CLEAR and judge(None) != CLEAR,
    )

    print("release-sentinel-credential-alarm: self-test %s"
          % ("PASSED" if not failures else "FAILED on %s" % ", ".join(failures)))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "firelock-ai/kin"))
    parser.add_argument("--enabled", default=None,
                         help="the exact string release-sentinel.yml's preflight job output; "
                              "'true' means a credential is present")
    parser.add_argument("--run-url", default="")
    parser.add_argument("--label", default=None,
                        help="the source-repository label to put on a newly opened alarm; "
                             "created on --repo first when given")
    parser.add_argument("--dry-run", action="store_true", help="judge and print, touch no issue")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.self_test:
        return self_test()
    if args.enabled is None:
        parser.error("--enabled is required unless --self-test")

    try:
        verdict = run_alarm(args.repo, args.enabled, args.run_url, dry_run=args.dry_run,
                            label=args.label)
    except Unreadable as exc:
        print("VERDICT UNREADABLE %s" % exc)
        return 2
    return 0 if verdict == CLEAR else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
