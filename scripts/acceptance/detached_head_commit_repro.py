#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove a repository converted at a detached Git HEAD can commit.

FIR-3012. `git clone` then `git checkout <rev>` leaves Git's HEAD detached, and
that is where a user stands after checking out a tag, a release sha or a bisect
point. A `kin init` there records a detached Kin workspace head, faithfully,
because `init.rs` maps a direct raw Git HEAD onto `WorkspaceHead::Detached`.
Every `kin commit` afterwards then died on

    HTTP 400: native repository commit requires a symbolic workspace HEAD

after paying the whole planning cost first, and a later `git switch -c` did not
repair it, because nothing re-reads Git's HEAD once the graph owns the head.

The fix advances the workspace's own head to the change it just made and moves
no ref, which is the shape `kin_model`'s `validate_head_base` already binds: a
detached head must equal its base, and a commit advances the base.

Five checks, two seeded repositories, ordered so the control runs first. A suite
that could only ever prove the new behaviour would pass just as well on a build
that routed every commit down the detached path, so the branch arm is not
decoration.

  branch_control   the control that must keep passing. A repository converted on
                   a branch commits, says which branch it published onto, and
                   the branch is where the change is. This is the arm a fix that
                   over-reached would break
  head_visible     `kin status` names the workspace head on the detached
                   repository BEFORE any commit. The ticket reported no HEAD
                   line at all, and a user who cannot see the head cannot see
                   the thing being refused
  detached_commits the defect itself. `kin commit` on the detached repository
                   succeeds, where it used to refuse
  head_advanced    the head moved to the change that commit made, read as two
                   different head lines rather than as prose, because no wording
                   can fake a head line changing
  no_branch_moved  no branch was invented on the author's behalf, and the branch
                   the conversion left behind is where it was

Exit status is 0 when every check passed, 1 when one failed, 2 when none failed
but one could not be read, and 3 when the run could not be set up. `--self-test`
drives every grader against the literal pre-fix output and the post-fix output
beside it, and needs no binary, so a grader that cannot fail is a failure here
rather than a silent pass in CI.
"""
from __future__ import print_function

import argparse
import functools
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-3012"

print = functools.partial(print, flush=True)

# The literal refusal this suite exists to keep gone. Matched as the sentence
# rather than as a status code, because a 400 is also what a dozen healthy
# refusals return and only this wording names the defect.
PRE_FIX_REFUSAL = (
    "Error: daemon native commit failed (HTTP 400 Bad Request):\n"
    "Core error: model error: invalid operation:\n"
    "native repository commit requires a symbolic workspace HEAD\n"
)

MODULE_FIRST = '"""A tiny ledger."""\n\n\ndef total(entries):\n    return sum(entries)\n'
MODULE_SECOND = (
    '"""A tiny ledger."""\n\n\ndef total(entries):\n    return sum(entries)\n\n\n'
    "def count(entries):\n    return len(entries)\n"
)
MODULE_THIRD = (
    '"""A tiny ledger."""\n\n\ndef total(entries):\n    return sum(entries)\n\n\n'
    "def count(entries):\n    return len(entries)\n\n\n"
    "def mean(entries):\n    return total(entries) / max(count(entries), 1)\n"
)
MODULE_EDIT = (
    '"""A tiny ledger."""\n\n\ndef total(entries):\n    return sum(entries)\n\n\n'
    "def count(entries):\n    return len(entries)\n\n\n"
    "def mean(entries):\n    return total(entries) / max(count(entries), 1)\n\n\n"
    "def spread(entries):\n    return max(entries) - min(entries)\n"
)


class Result(object):
    def __init__(self, cid, status, detail):
        self.id = cid
        self.status = status
        self.detail = detail


def run(cmd, cwd=None, env=None, timeout=900):
    process = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    try:
        out, err = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        out, err = process.communicate()
        return 124, out or "", err or ""
    return process.returncode, out or "", err or ""


# ── graders ──
#
# Pure functions, so --self-test can drive every one against the input that must
# produce the opposite verdict.

def head_line(text):
    """The `Head:` line `kin status` printed, or None when it printed none.

    None rather than "" so a caller cannot mistake output that never reached
    this line for a line that was blank. The ticket's report was that no such
    line exists, and that reading has to be expressible.
    """
    if not isinstance(text, str):
        return None
    for line in text.splitlines():
        if line.startswith("Head: "):
            return line
    return None


def grade_head_is_visible(status_text):
    """The head has to be readable before a refusal about it means anything."""
    line = head_line(status_text)
    if line is None:
        return (FAIL, "kin status printed no Head line, so the head cannot be seen")
    if line.strip() == "Head:":
        return (FAIL, "the Head line named nothing: %r" % line)
    return (PASS, "kin status named the head: %s" % line.strip())


def grade_commit_refused_the_old_way(commit_text):
    """Whether this output is the pre-fix refusal, named by its own sentence."""
    text = commit_text or ""
    return "requires a symbolic workspace HEAD" in text


def grade_detached_commit_landed(rc, commit_text):
    if grade_commit_refused_the_old_way(commit_text):
        return (FAIL, "the pre-fix refusal is still shipping: %s"
                % " ".join((commit_text or "").split())[-160:])
    if rc != 0:
        return (FAIL, "kin commit exited %s: %s"
                % (rc, " ".join((commit_text or "").split())[-160:]))
    if "Created semantic change" not in (commit_text or ""):
        return (UNREADABLE,
                "kin commit exited 0 but named no change, so nothing can be read from it")
    if "on branch" in commit_text:
        return (FAIL,
                "a detached commit named a branch, so a branch was invented: %s"
                % " ".join(commit_text.split())[:160])
    if "detached HEAD" not in commit_text:
        return (FAIL,
                "a detached commit did not say where it went: %s"
                % " ".join(commit_text.split())[:160])
    return (PASS, "the commit landed and named the detached head")


def grade_branch_commit_landed(rc, commit_text, branch):
    """The control's grader. A branch commit still names its branch.

    Deliberately not the negation of the one above. A build that routed every
    commit onto the detached path would satisfy "did not refuse", so this asks
    for the branch by name.
    """
    if rc != 0:
        return (FAIL, "kin commit exited %s: %s"
                % (rc, " ".join((commit_text or "").split())[-160:]))
    if "on branch '%s'" % branch not in (commit_text or ""):
        return (FAIL, "a commit on %s did not name it: %s"
                % (branch, " ".join((commit_text or "").split())[:160]))
    if "detached HEAD" in commit_text:
        return (FAIL, "a commit on a branch reported a detached head: %s"
                % " ".join(commit_text.split())[:160])
    return (PASS, "the commit landed on %s and said so" % branch)


def grade_head_advanced(before, after):
    """The check prose could never make: the head line has to have MOVED.

    Both readings are of the same surface in the same repository minutes apart,
    so a suite that only asserted the wording would pass on a product whose head
    never moves, which is the exact defect a detached commit would have if the
    head were left cloned.
    """
    if before is None or after is None:
        return (UNREADABLE, "one of the two status reads carried no Head line")
    if before == after:
        return (FAIL, "the head did not move across a commit; both read %s" % before.strip())
    if "detached" not in after:
        return (FAIL, "the head stopped being detached without anyone switching: %s"
                % after.strip())
    if "change " not in after:
        return (FAIL, "the head moved but names no change: %s" % after.strip())
    return (PASS, "the head moved from %r to %r" % (before.strip(), after.strip()))


BRANCH_ROW = re.compile(r"^\s*\*?\s*(refs/\S+)")


def branch_targets(branch_list_text):
    """Every branch the repository holds, as a set of ref names.

    None when the output carries no ref row at all, which is different from a
    repository with no branches: a failed command and an empty repository look
    identical once both are reduced to an empty set.
    """
    if not isinstance(branch_list_text, str) or not branch_list_text.strip():
        return None
    saw_row = False
    names = set()
    for line in branch_list_text.splitlines():
        match = BRANCH_ROW.match(line)
        if not match:
            continue
        saw_row = True
        names.add(match.group(1))
    if not saw_row:
        return None
    return names


def grade_no_branch_moved(before, after):
    if before is None or after is None:
        return (UNREADABLE, "kin branch list printed no ref row, so no branch could be read")
    added = sorted(after - before)
    if added:
        return (FAIL, "a detached commit invented branch(es) %s" % ", ".join(added))
    removed = sorted(before - after)
    if removed:
        return (FAIL, "a detached commit removed branch(es) %s" % ", ".join(removed))
    return (PASS, "the branch set held still at %s" % (sorted(after) or "none"))


def report_payload(results, label):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`; the gate calls `payload.get("results")`
    and refuses anything else with "carries no results list".
    """
    return {
        "label": label,
        "ticket": TICKET,
        "results": [
            {"id": r.id, "ticket": TICKET, "status": r.status, "detail": r.detail}
            for r in results
        ],
    }


# ── fixture ──

class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        # kin refuses to invent an author, which is correct. The run isolates
        # HOME so it cannot read the machine's identity, so it brings one.
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = detached-head-commit-repro\n"
                         "\temail = repro@example.invalid\n"
                         "[commit]\n\tgpgsign = false\n")
        self.env = dict(os.environ)
        self.env["HOME"] = self.home
        self.env["USERPROFILE"] = self.home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env["KIN_REGISTRY_PATH"] = os.path.join(self.home, "registry.toml")
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DAEMON_URL", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self._repos = {}

    def kin_run(self, repo, args, timeout=900):
        rc, out, err = run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args), rc))
        return rc, out, err

    def git(self, repo, args, timeout=300):
        rc, out, err = run(["git"] + args, cwd=repo, env=self.env, timeout=timeout)
        if rc != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), (err or out)[-300:]))
        return out

    def repo(self, name, detach):
        """A three-commit Git repository, converted with `kin init`.

        `detach` decides the one fact under test: whether Git's HEAD is on a
        branch or on a commit when the conversion happens. Everything else about
        the two repositories is identical, so a difference between the arms is
        that fact and not the fixture.
        """
        if name in self._repos:
            return self._repos[name]
        path = os.path.realpath(os.path.join(self.workdir, name))
        os.makedirs(path)
        self.git(path, ["init", "-q", "-b", "main", "."])
        # The fixture's own hooks path, so a machine-wide commit-msg hook cannot
        # decide whether this suite can build its input.
        self.git(path, ["config", "core.hooksPath", os.path.join(self.home, "no-hooks")])
        self.git(path, ["config", "user.email", "repro@example.invalid"])
        self.git(path, ["config", "user.name", "detached-head-commit-repro"])
        for body, message in ((MODULE_FIRST, "first"),
                              (MODULE_SECOND, "second"),
                              (MODULE_THIRD, "third")):
            self._write(path, "ledger/reporting.py", body)
            self.git(path, ["add", "-A"])
            self.git(path, ["commit", "-q", "-m", message])
        if detach:
            second = self.git(path, ["rev-parse", "HEAD~1"]).strip()
            self.git(path, ["checkout", "-q", second])
            # The fixture assertion. A detached arm that quietly stayed on a
            # branch would pass every grader below for the wrong reason.
            rc, _, _ = run(["git", "symbolic-ref", "-q", "HEAD"],
                           cwd=path, env=self.env, timeout=60)
            if rc == 0:
                raise RuntimeError("the detached fixture is still on a branch")
        rc, out, err = self.kin_run(path, ["init", "."])
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % ((err or out)[-400:]))
        self._repos[name] = path
        return path

    @staticmethod
    def _write(root, relative, body):
        target = os.path.join(root, relative)
        directory = os.path.dirname(target)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(target, "w") as handle:
            handle.write(body)

    def stop_daemons(self):
        for path in self._repos.values():
            run([self.kin, "daemon", "stop"], cwd=path, env=self.env, timeout=180)


# ── checks ──
#
# The two arms share one dict so a later check can read what an earlier one saw
# without running the fixture twice. Every entry is written by the check that
# measured it and read by name, never by position.
OBSERVED = {}


def check_branch_control(suite):
    repo = suite.repo("on-branch", detach=False)
    suite._write(repo, "ledger/reporting.py", MODULE_EDIT)
    rc, out, err = suite.kin_run(repo, ["commit", "-m", "add a spread helper"])
    status, detail = grade_branch_commit_landed(rc, (out or "") + (err or ""),
                                                "refs/heads/main")
    return Result("branch_control", status, detail)


def check_head_visible(suite):
    repo = suite.repo("detached", detach=True)
    rc, out, err = suite.kin_run(repo, ["status"])
    if rc != 0:
        return Result("head_visible", UNREADABLE,
                      "kin status exited %s: %s" % (rc, (err or out)[-200:]))
    OBSERVED["head_before"] = head_line(out)
    status, detail = grade_head_is_visible(out)
    return Result("head_visible", status, detail)


def check_detached_commits(suite):
    repo = suite.repo("detached", detach=True)
    rc, out, err = suite.kin_run(repo, ["branch", "list"])
    OBSERVED["branches_before"] = branch_targets(out) if rc == 0 else None
    suite._write(repo, "ledger/reporting.py", MODULE_EDIT)
    rc, out, err = suite.kin_run(repo, ["commit", "-m", "add a spread helper"])
    OBSERVED["commit_rc"] = rc
    OBSERVED["commit_text"] = (out or "") + (err or "")
    status, detail = grade_detached_commit_landed(rc, OBSERVED["commit_text"])
    return Result("detached_commits", status, detail)


def check_head_advanced(suite):
    if "commit_rc" not in OBSERVED:
        return Result("head_advanced", UNREADABLE,
                      "the commit check never ran, so there is no transition to read")
    if OBSERVED["commit_rc"] != 0:
        return Result("head_advanced", UNREADABLE,
                      "the commit did not land, so no head could have moved")
    repo = suite.repo("detached", detach=True)
    rc, out, err = suite.kin_run(repo, ["status"])
    if rc != 0:
        return Result("head_advanced", UNREADABLE,
                      "kin status exited %s: %s" % (rc, (err or out)[-200:]))
    OBSERVED["head_after"] = head_line(out)
    status, detail = grade_head_advanced(OBSERVED.get("head_before"),
                                         OBSERVED.get("head_after"))
    return Result("head_advanced", status, detail)


def check_no_branch_moved(suite):
    if OBSERVED.get("commit_rc") != 0:
        return Result("no_branch_moved", UNREADABLE,
                      "the commit did not land, so no branch could have moved")
    repo = suite.repo("detached", detach=True)
    rc, out, err = suite.kin_run(repo, ["branch", "list"])
    if rc != 0:
        return Result("no_branch_moved", UNREADABLE,
                      "kin branch list exited %s: %s" % (rc, (err or out)[-200:]))
    status, detail = grade_no_branch_moved(OBSERVED.get("branches_before"),
                                           branch_targets(out))
    return Result("no_branch_moved", status, detail)


CHECKS = (
    ("branch_control", check_branch_control),
    ("head_visible", check_head_visible),
    ("detached_commits", check_detached_commits),
    ("head_advanced", check_head_advanced),
    ("no_branch_moved", check_no_branch_moved),
)


# ── self-test ──

def self_test():
    problems = []

    def expect(what, got, want):
        if got != want:
            problems.append("%s: got %r, wanted %r" % (what, got, want))

    # head_line separates absent from blank from present.
    expect("a status with a head", head_line("Workspace: w\nHead: detached Commit abc\nTree: t"),
           "Head: detached Commit abc")
    expect("a status with no head line", head_line("Workspace: w\nTree: t"), None)
    expect("a non-string status", head_line(None), None)

    # The pre-fix refusal must be recognised, and an unrelated 400 must not be.
    if not grade_commit_refused_the_old_way(PRE_FIX_REFUSAL):
        problems.append("the pre-fix refusal was not recognised as itself")
    if grade_commit_refused_the_old_way(
            "Error: daemon native commit failed (HTTP 400 Bad Request):\n"
            "Core error: model error: invalid operation:\n"
            "native commit message must not be empty\n"):
        problems.append("an unrelated 400 was read as the pre-fix refusal")

    # The detached grader fails on the shipped defect and passes on the fix.
    expect("the pre-fix refusal fails",
           grade_detached_commit_landed(1, PRE_FIX_REFUSAL)[0], FAIL)
    expect("a detached commit passes",
           grade_detached_commit_landed(0,
               "Created semantic change 37cfc298 on a detached HEAD, which no branch names "
               "(3 entities, 1 relations, 1 artifacts)\nRecorded in Kin authority, not in git.\n"
               "The workspace head advanced to this change and no branch moved. "
               "`kin branch create <name>` puts it on a branch.")[0], PASS)
    # The mutation that matters: a fix that quietly put the change on an
    # invented branch would exit 0 and name a change, and only the branch
    # sentence tells the two apart. The fixture carries BOTH phrases on
    # purpose. Without the detached note, deleting the branch check leaves the
    # missing-note check to fail the same input one line later, for a different
    # reason, and the mutation survives while the arm still reads red. The
    # detail is asserted for the same reason: a red arm naming another
    # assertion is not this arm passing.
    invented = grade_detached_commit_landed(0,
        "Created semantic change 37cfc298 on branch 'refs/heads/detached-work' "
        "(3 entities, 1 relations, 1 artifacts)\n"
        "The workspace head advanced to this change and no branch moved.")
    expect("a commit that invented a branch fails", invented[0], FAIL)
    if "a branch was invented" not in invented[1]:
        problems.append("the invented-branch case failed for another reason: %r" % invented[1])
    # And the note's own check, with an input only it can catch: no branch
    # named and no note either.
    silent = grade_detached_commit_landed(0,
        "Created semantic change 37cfc298 (3 entities, 1 relations, 1 artifacts)")
    expect("a commit that said nothing about where it went fails", silent[0], FAIL)
    if "did not say where it went" not in silent[1]:
        problems.append("the silent-commit case failed for another reason: %r" % silent[1])
    # An exit 0 with no change named is unreadable, never a pass.
    expect("an empty success is unreadable",
           grade_detached_commit_landed(0, "")[0], UNREADABLE)

    # The control's grader asks for the branch by name, so a build that routed
    # every commit down the detached path breaks it.
    expect("a branch commit passes",
           grade_branch_commit_landed(0,
               "Created semantic change 37cfc298 on branch 'refs/heads/main' "
               "(3 entities, 1 relations, 1 artifacts)", "refs/heads/main")[0], PASS)
    expect("a branch commit routed onto the detached path fails",
           grade_branch_commit_landed(0,
               "Created semantic change 37cfc298 on a detached HEAD, which no branch names "
               "(3 entities, 1 relations, 1 artifacts)", "refs/heads/main")[0], FAIL)
    expect("a branch commit naming another branch fails",
           grade_branch_commit_landed(0,
               "Created semantic change 37cfc298 on branch 'refs/heads/other' "
               "(3 entities, 1 relations, 1 artifacts)", "refs/heads/main")[0], FAIL)

    # The head has to MOVE, and a head that stayed put is the defect this fix is
    # about, not a wording problem.
    # Both readings name a CHANGE, so the only thing wrong with this pair is
    # that they are equal. With an external-commit fixture the "names no
    # change" check catches it one line later and the equality check can be
    # deleted without the arm noticing.
    stuck = grade_head_advanced("Head: detached change 37cfc298",
                                "Head: detached change 37cfc298")
    expect("a head that never moved fails", stuck[0], FAIL)
    if "did not move" not in stuck[1]:
        problems.append("the stuck-head case failed for another reason: %r" % stuck[1])
    expect("a head that advanced to a change passes",
           grade_head_advanced("Head: detached Commit 9e7b7dd",
                               "Head: detached change 37cfc298")[0], PASS)
    expect("a head that silently became symbolic fails",
           grade_head_advanced("Head: detached Commit 9e7b7dd",
                               "Head: symbolic refs/heads/main")[0], FAIL)
    expect("a missing head reading is unreadable",
           grade_head_advanced(None, "Head: detached change 37cfc298")[0], UNREADABLE)

    # branch_targets separates "no branches" from "the command said nothing".
    expect("a branch listing", branch_targets("  refs/heads/main  change abc\n"),
           {"refs/heads/main"})
    expect("an empty listing is unreadable", branch_targets(""), None)
    expect("a listing with no ref row is unreadable",
           branch_targets("no branches yet\n"), None)
    expect("an unchanged branch set passes",
           grade_no_branch_moved({"refs/heads/main"}, {"refs/heads/main"})[0], PASS)
    expect("an invented branch fails",
           grade_no_branch_moved({"refs/heads/main"},
                                 {"refs/heads/main", "refs/heads/detached-work"})[0], FAIL)
    expect("an unreadable listing is unreadable",
           grade_no_branch_moved(None, {"refs/heads/main"})[0], UNREADABLE)

    # The report the gate reads, driven through the gate's own reader rather
    # than through a copy of its rules.
    payload = report_payload([Result("x", PASS, "ok")], "selftest")
    if not payload.get("results"):
        problems.append("the report carries no results list, which the gate refuses")
    if payload["results"][0]["status"] != PASS:
        problems.append("the report lost a row's status")

    for problem in problems:
        print("SELFTEST FAIL %s" % problem)
    print("detached-head-commit-repro self-test: %d problem(s)" % len(problems))
    return 1 if problems else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--daemon", default=None)
    parser.add_argument("--workdir", default=None)
    parser.add_argument("--label", default="local")
    parser.add_argument("--only", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("error: --kin (or KIN_BIN) is required", file=sys.stderr)
        return 3
    # Absolutized here, before anything reads it: every probe runs with `cwd` set
    # to a fixture repository, so a relative `--kin target/release/kin` would
    # validate from the caller's directory and fail from the fixture's.
    kin = os.path.abspath(args.kin)
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("error: %s is not an executable kin binary" % kin, file=sys.stderr)
        return 3

    daemon = os.path.abspath(args.daemon) if args.daemon else None
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        if os.path.isfile(beside) and os.access(beside, os.X_OK):
            daemon = beside

    selected = None
    if args.only:
        selected = {part.strip() for part in args.only.split(",") if part.strip()}

    workdir = args.workdir or tempfile.mkdtemp(prefix="detached-head-commit-")
    os.makedirs(workdir, exist_ok=True)
    suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)

    results = []
    try:
        for cid, fn in CHECKS:
            if selected is not None and cid not in selected:
                continue
            try:
                results.append(fn(suite))
            except Exception as exc:  # a crashed probe is UNREADABLE, never a verdict
                results.append(Result(cid, UNREADABLE, "the probe raised: %s" % exc))
    finally:
        suite.stop_daemons()
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    for res in results:
        print("CHECK %s %s %s %s" % (res.id, TICKET, res.status, res.detail))

    failed = [r for r in results if r.status == FAIL]
    unreadable = [r for r in results if r.status == UNREADABLE]
    print("detached-head-commit-repro: %d checks, %d passed, %d failed, %d unreadable (%s)"
          % (len(results), len(results) - len(failed) - len(unreadable),
             len(failed), len(unreadable), args.label))

    if args.json:
        with open(args.json, "w") as handle:
            json.dump(report_payload(results, args.label), handle, indent=2, sort_keys=True)

    if failed:
        return 1
    if unreadable:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
