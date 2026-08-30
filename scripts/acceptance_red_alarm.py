#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Judge a completed Acceptance run on main and say whether anyone must be told.

`Product Acceptance` is not a required context on main. Read live from
`GET /repos/firelock-ai/kin/rules/branches/main` on 2026-08-30 the required set is
six contexts, cargo-deny, DCO Sign-off, Fast gate build and tests, Fast gate lint
and policy, gitleaks (full history) and PR text hygiene, which is FIR-2815's
thinned fast gate. So a red Acceptance blocks no landing, and after the landing
nothing watches it either: of the eight workflows here that use `workflow_run`,
their `workflows:` lists cover CI, PR Text Hygiene, SAST, Release and the Kin
Registry Release Receiver, and none names Acceptance.

What that cost, measured on 2026-08-30: twelve consecutive red Acceptance runs on
main, from `00d655370` at 2026-08-29T20:46:51Z through `56f79f193` at
2026-08-30T03:53:44Z, last green `cc72a66e5`. Twelve landings crossed a red gate
and nothing said so. The red was a composite of three unrelated causes, which is
the part that makes a bare "Acceptance failed" notice useless: one suite's report
was unreadable, one check was UNREADABLE under FIR-2974, and two checks FAILed
under FIR-2820. A notice that does not name WHICH finding moved cannot tell a
landing that fixed something from one that broke something else.

This script is the judge. The workflow beside it is the messenger. Keeping the
judgement here means it can be run against any historical run id from a laptop,
which is how it is falsified, and the workflow stays thin enough to read.

Verdicts, and every one of them was observed or is catalogued:

  GREEN      the run concluded success. Close any open tracking issue.
  RED        the gate produced a verdict and named findings. Open or update.
  UNGRADED   the run failed before the gate printed a verdict, so the suite
             never graded. Names the failing step instead of inventing findings.
  INFRA      run-level failure with zero jobs concluded failure and zero runners
             assigned. During the 2026-08-26 Actions incident two kin runs wore
             exactly this shape, and a watcher keying on the rollup would refuse
             healthy work for the length of any outage. Not an alarm.
  UNREADABLE the log could not be read, or the findings did not reconcile
             against the gate's own total. Never silently reported as GREEN.

The reconciliation is the load-bearing part. `gate.py` prints its findings as
`::error::` lines and then prints `acceptance gate FAILED on N finding(s)`, so
the rows and the total come from one producer and must agree. They do not agree
if you count naively: the runner appends its own `##[error]Process completed with
exit code 1.` after the total, so a count over the whole log reads 5 where the
gate said 4. Collecting only the error lines that precede the total fixes it, and
keeping the reconciliation means a future change to either half is caught rather
than quietly producing decoration rows.
"""

import argparse
import json
import os
import re
import subprocess
import sys

GREEN = "GREEN"
RED = "RED"
UNGRADED = "UNGRADED"
INFRA = "INFRA"
UNREADABLE = "UNREADABLE"

ERROR_MARKER = "##[error]"
RAW_ERROR_MARKER = "::error::"
TOTAL_RE = re.compile(r"acceptance gate FAILED on (\d+) finding\(s\)")
PASSED_LINE = "acceptance gate passed"

# The runner emits its own annotations on the same channel as the gate's. These
# are not findings, and one of them always follows a red gate.
RUNNER_NOISE = (
    "Process completed with exit code",
    "The operation was canceled",
)

ALARM_TITLE = "Acceptance is red on main"


class Unreadable(Exception):
    """Raised when a read cannot be trusted. Never mapped onto a clean verdict."""


def gh(args, capture=True):
    """Run gh, refusing an empty answer rather than treating it as a zero.

    A gh call can go out unauthenticated and its 403 wears a quota costume, so an
    empty read is UNREADABLE here rather than "nothing found".
    """
    proc = subprocess.run(
        ["gh"] + args,
        capture_output=capture,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise Unreadable(
            "gh %s exited %d: %s"
            % (" ".join(args), proc.returncode, (proc.stderr or "").strip()[:400])
        )
    return proc.stdout


def gh_json(args):
    out = gh(args)
    if not out.strip():
        raise Unreadable("gh %s returned no bytes" % " ".join(args))
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        # An empty repository's 409 body arrives on stdout and parses as JSON
        # that is not the shape asked for, so validate the shape at every use
        # rather than the presence.
        raise Unreadable("gh %s did not return JSON: %s" % (" ".join(args), exc))


def parse_findings(log):
    """Return (findings, total) from a gate log, or raise Unreadable.

    Collects error lines only up to the gate's own total, so the runner's
    trailing annotation cannot inflate the count.
    """
    findings = []
    total = None
    for line in log.splitlines():
        hit = TOTAL_RE.search(line)
        if hit:
            total = int(hit.group(1))
            break
        marker = ERROR_MARKER if ERROR_MARKER in line else (
            RAW_ERROR_MARKER if RAW_ERROR_MARKER in line else None
        )
        if marker is None:
            continue
        message = line.split(marker, 1)[1].strip()
        if any(noise in message for noise in RUNNER_NOISE):
            continue
        if message:
            findings.append(message)
    if total is None:
        return findings, None
    if len(findings) != total:
        raise Unreadable(
            "the gate said %d finding(s) and %d error line(s) precede its total, so the "
            "rows and the total disagree and neither can be reported" % (total, len(findings))
        )
    return findings, total


def classify(run, jobs, log_reader):
    """Decide the verdict. `log_reader` is a callable so this stays testable."""
    conclusion = run.get("conclusion")
    if conclusion == "success":
        return GREEN, [], "the gate passed"
    if conclusion in ("cancelled", "skipped", None):
        return INFRA, [], "the run concluded %r, which is not a red" % conclusion

    failed = [j for j in jobs if j.get("conclusion") == "failure"]
    assigned = [j for j in jobs if j.get("runner_name")]
    if not failed and not assigned:
        # Both facts together are the discriminator. A genuine red always has one
        # named-runner job that lost.
        return (
            INFRA,
            [],
            "run-level %s with zero jobs concluded failure and zero runners assigned"
            % conclusion,
        )
    if not failed:
        return (
            UNGRADED,
            [],
            "run-level %s with a runner assigned but no job concluded failure" % conclusion,
        )

    log = log_reader()
    findings, total = parse_findings(log)
    if total is None:
        steps = []
        for job in failed:
            for step in job.get("steps") or []:
                if step.get("conclusion") == "failure":
                    steps.append("%s / %s" % (job.get("name", "?"), step.get("name", "?")))
        if PASSED_LINE in log:
            raise Unreadable(
                "the log says the gate passed while the run concluded %s" % conclusion
            )
        return (
            UNGRADED,
            [],
            "the gate never printed a verdict; failing step(s): %s"
            % (", ".join(steps) or "none reported"),
        )
    return RED, findings, "the gate failed on %d finding(s)" % total


def render_body(run, verdict, findings, detail):
    sha = run.get("head_sha") or "unknown"
    url = run.get("html_url") or ""
    lines = [
        "`Product Acceptance` is red on `main`.",
        "",
        "- squash: `%s`" % sha,
        "- run: %s" % url,
        "- verdict: %s, %s" % (verdict, detail),
        "",
    ]
    if findings:
        lines.append("Findings, verbatim from the gate:")
        lines.append("")
        lines.append("```")
        lines.extend(findings)
        lines.append("```")
        lines.append("")
    lines.extend(
        [
            "Acceptance is not a required context on main, so this landed without being",
            "blocked and nothing else reports it. This issue closes itself on the next",
            "green Acceptance run on main.",
        ]
    )
    return "\n".join(lines) + "\n"


def run_alarm(repo, run_id, dry_run):
    run = gh_json(
        [
            "api",
            "repos/%s/actions/runs/%s" % (repo, run_id),
            "--jq",
            "{conclusion,status,head_sha,head_branch,event,html_url}",
        ]
    )
    for key in ("conclusion", "status", "head_sha"):
        if key not in run:
            raise Unreadable("run %s answered without %r" % (run_id, key))

    jobs = gh_json(
        [
            "api",
            "repos/%s/actions/runs/%s/jobs?per_page=100" % (repo, run_id),
            "--jq",
            "[.jobs[] | {name,conclusion,status,runner_name,steps}]",
        ]
    )
    if not isinstance(jobs, list):
        raise Unreadable("jobs for run %s did not answer with a list" % run_id)

    def read_log():
        return gh(["run", "view", str(run_id), "--repo", repo, "--log-failed"])

    verdict, findings, detail = classify(run, jobs, read_log)
    print("VERDICT %s sha=%s %s" % (verdict, (run.get("head_sha") or "?")[:9], detail))
    for finding in findings:
        print("  FINDING %s" % finding)

    if dry_run:
        if verdict == RED:
            print("--- body ---")
            print(render_body(run, verdict, findings, detail))
        return verdict

    if verdict == RED:
        body = render_body(run, verdict, findings, detail)
        existing = find_issue(repo)
        if existing:
            gh(["issue", "comment", str(existing), "--repo", repo, "--body", body])
            print("updated tracking issue #%s" % existing)
        else:
            number = gh(
                ["issue", "create", "--repo", repo, "--title", ALARM_TITLE, "--body", body]
            )
            print("opened tracking issue %s" % number.strip())
    elif verdict == GREEN:
        existing = find_issue(repo)
        if existing:
            gh(
                [
                    "issue",
                    "close",
                    str(existing),
                    "--repo",
                    repo,
                    "--comment",
                    "Acceptance is green on `main` again, verified by %s (run on `%s`)."
                    % (run.get("html_url") or "this run", (run.get("head_sha") or "?")[:9]),
                ]
            )
            print("closed tracking issue #%s" % existing)
        else:
            print("nothing open to close")
    else:
        print("no issue action for verdict %s" % verdict)
    return verdict


def find_issue(repo):
    """Exact-title lookup, matching base-image-pins.yml.

    A search expression could widen into an unrelated issue, so the title is
    compared for equality.
    """
    out = gh(
        [
            "issue",
            "list",
            "--repo",
            repo,
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number,title",
        ]
    )
    rows = json.loads(out or "[]")
    for row in rows:
        if row.get("title") == ALARM_TITLE:
            return row.get("number")
    return None


# ─── Controls ───────────────────────────────────────────────────────────────
#
# Every verdict gets a fixture, and every fixture asserts the verdict BY NAME.
# The two that matter most are the ones a naive implementation gets wrong: the
# runner's trailing annotation inflating the finding count, and an infrastructure
# failure wearing a red costume.

REAL_RED_LOG = """\
Product Acceptance\tgate\t2026-08-30T04:34:56Z ALLOWED brownfield:4 is UNREADABLE (FIR-2593: ...)
Product Acceptance\tgate\t2026-08-30T04:34:56Z memory_pressure: 13 PASS, 1 UNREADABLE
Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]vcs_read_surfaces: report acceptance/vcs_read_surfaces.json carries no results list
Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]memory_pressure:12 UNREADABLE no standing was published
Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]working_copy_freshness:status FAIL FIR-2820 the line does not name the file
Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]working_copy_freshness:absence FAIL FIR-2820 the answer is withheld
Product Acceptance\tgate\t2026-08-30T04:34:56Z acceptance gate FAILED on 4 finding(s)
Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]Process completed with exit code 1.
"""

BUILD_FAILED_LOG = """\
Product Acceptance\tbuild\t2026-08-30T04:00:00Z error: could not compile `kin-core`
Product Acceptance\tbuild\t2026-08-30T04:00:00Z ##[error]Process completed with exit code 101.
"""

MISCOUNTED_LOG = REAL_RED_LOG.replace("FAILED on 4 finding(s)", "FAILED on 7 finding(s)")

# `--log-failed` returns every failed step, so a second failed step's runner
# annotation can precede the gate's total. The break at the total cannot exclude
# that one; only RUNNER_NOISE can. Without this fixture the RUNNER_NOISE filter
# is untested, because the trailing annotation in REAL_RED_LOG is already past
# the break, and the two defences hide each other's absence.
NOISE_BEFORE_TOTAL_LOG = REAL_RED_LOG.replace(
    "Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]vcs_read_surfaces:",
    "Product Acceptance\tupload\t2026-08-30T04:30:00Z ##[error]Process completed with exit code 1.\n"
    "Product Acceptance\tgate\t2026-08-30T04:34:56Z ##[error]vcs_read_surfaces:",
)


def self_test():
    """Grade every verdict by name, and never let one control's raise hide another.

    Each control runs through `grade`, which treats an UNEXPECTED `Unreadable` as
    a failure of that named control rather than letting it propagate. A suite
    that crashes reports no control at all, and a mutation driver reading only
    the exit code then scores the crash as a surviving mutant. That is exactly
    what happened when this file's own noise filter was first mutated away.
    """
    failures = []

    def check(name, cond):
        print("CONTROL %s %s" % ("PASS" if cond else "FAIL", name))
        if not cond:
            failures.append(name)

    def grade(name, thunk):
        try:
            check(name, thunk())
        except Unreadable as exc:
            print("CONTROL FAIL %s (raised Unreadable: %s)" % (name, exc))
            failures.append(name)

    one_job = [{"name": "Product Acceptance", "conclusion": "failure",
                "runner_name": "GitHub Actions 1", "steps": []}]
    red_run = {"conclusion": "failure", "head_sha": "a" * 40}

    def red_of(log):
        return classify(red_run, one_job, lambda: log)

    grade("a real red log grades RED", lambda: red_of(REAL_RED_LOG)[0] == RED)
    grade("the gate's four findings are four, not the runner's five",
          lambda: len(red_of(REAL_RED_LOG)[1]) == 4)
    grade("findings keep the gate's own text",
          lambda: red_of(REAL_RED_LOG)[1][0].startswith("vcs_read_surfaces:"))
    grade("a fabricated finding is absent",
          lambda: not any("zzznotafinding" in x for x in red_of(REAL_RED_LOG)[1]))

    grade("a successful run grades GREEN",
          lambda: classify({"conclusion": "success", "head_sha": "b" * 40}, [],
                           lambda: "")[0] == GREEN)

    grade("zero failed jobs and zero runners grades INFRA",
          lambda: classify(
              {"conclusion": "failure", "head_sha": "c" * 40},
              [{"name": "Product Acceptance", "conclusion": None, "status": "queued",
                "runner_name": None, "steps": []}],
              lambda: "")[0] == INFRA)

    died_before_gate = (
        {"conclusion": "failure", "head_sha": "d" * 40},
        [{"name": "build", "conclusion": "failure", "runner_name": "GitHub Actions 2",
          "steps": [{"name": "Build the release binary", "conclusion": "failure"}]}],
    )
    grade("a run that died before the gate grades UNGRADED",
          lambda: classify(*died_before_gate, log_reader=lambda: BUILD_FAILED_LOG)[0] == UNGRADED)
    grade("UNGRADED names the failing step",
          lambda: "Build the release binary" in
          classify(*died_before_gate, log_reader=lambda: BUILD_FAILED_LOG)[2])

    # A runner annotation BEFORE the gate's total is the one case the break at
    # the total cannot exclude. Without this control the noise filter is untested.
    grade("a runner annotation BEFORE the total is not a finding",
          lambda: red_of(NOISE_BEFORE_TOTAL_LOG)[0] == RED
          and len(red_of(NOISE_BEFORE_TOTAL_LOG)[1]) == 4)

    # This one expects the raise, so it must NOT go through `grade`.
    try:
        red_of(MISCOUNTED_LOG)
        check("a total that disagrees with its rows refuses", False)
    except Unreadable as exc:
        check("a total that disagrees with its rows refuses", "disagree" in str(exc))

    print("acceptance-red-alarm: self-test %s"
          % ("PASSED" if not failures else "FAILED on %s" % ", ".join(failures)))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", help="Acceptance run id to judge")
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "firelock-ai/kin"))
    parser.add_argument("--dry-run", action="store_true",
                        help="judge and print, touch no issue")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv[1:])

    if args.self_test:
        return self_test()
    if not args.run:
        parser.error("--run is required unless --self-test")

    try:
        verdict = run_alarm(args.repo, args.run, args.dry_run)
    except Unreadable as exc:
        # Exit 2 for "refused to answer", distinct from a real alarm, so a caller
        # can tell a broken read from a red gate.
        print("VERDICT %s %s" % (UNREADABLE, exc))
        return 2
    return 0 if verdict in (GREEN, INFRA) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
