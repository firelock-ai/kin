#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove the everyday read surfaces state the basis of the verdicts they give.

FIR-2961. The first stranger run with a version control arm ran the whole
everyday loop against a Python project with no Git anywhere, and two read
surfaces answered wrongly in a way a Git user would not accept.

  kin status   "Tree: 70fda9ae... (8 artifacts, matching its base change)"
               printed over a tracked file edited twenty-two seconds earlier,
               and repeated across seven more readings
  kin admit    "Admitted the complete exact tree; nothing changed."
               printed by a pass that moved the workspace tree hash from
               70fda9ae to c078181f and its generation from 5 to 6, both
               visible three lines apart in the same output

Neither verdict was wrong about the graph. `dirty` compares the admitted
workspace tree against the tree of the change it is based on, and it was right
both times. The admit wording compares two cardinalities, tracked artifacts and
entities, and both genuinely held still. What is wrong in both is the same
thing: a correct answer about the graph, stated as a claim about the working
copy, with nothing beside it saying what it rests on.

So this suite never grades the verdict. It grades whether the basis travels with
it, which is the property that separates a true sentence from a misleading one
here, and it grades both directions: a surface that qualifies every answer it
gives is as useless as one that qualifies none, so the all-clear has its own
check and must still arrive.

Seven checks, one seeded repository, run in order because the experiment is
destructive: each one sets up the next, and the last stops the daemon.

  basis        the `Tree:` line names when graph truth last caught up, rather
               than rendering a bare verdict a reader takes for a statement
               about the files on disk
  saw_the_edit the check an age could never make. A tracked file's body changes
               and the tree hash on the `Tree:` line must move, read as two
               hashes rather than as prose, because no wording can fake a hash
               moving. This is what read-after-admit buys and it is the only
               thing that settles the question
  content      `kin admit` over that content-only edit does not report
               "nothing changed"
  settled      the control: a second `kin admit` with nothing left to take gives
               an explicit all-clear, either the legacy "nothing changed" or the
               stronger verdict that the working copy was already admitted at a
               named time. Without this the others are satisfied by a product
               that hedges every sentence
  diff_scope   a workspace diff names what its entity and relation counts cannot
               show, rather than printing three zeroes that cannot move
  held_merge   a real conflicting merge is opened and `kin status` must name it.
               Kin holds a merge in an authority transaction rather than smearing
               conflict markers across the files, which is the better design and
               is exactly why the status line is the only place this can live:
               there is nothing on disk to see. `kin conflicts` is the positive
               control, and it is not decoration, because a fixture that never
               opened a merge must read UNREADABLE rather than FAIL. Runs before
               `unadmitted`, which stops the daemon both `kin merge` and
               `kin conflicts` need
  unadmitted   with the daemon stopped, the verdict names itself unmeasured
               instead of borrowing the clock of an older admission. A fresh
               marker beside no admission at all is the most convincing form of
               the defect, and its self-test row is the literal line the earlier
               fix would have printed

Exit status is 0 when every check passed, 1 when one failed, 2 when none failed
but one could not be read, and 3 when the run could not be set up. `--self-test`
drives every grader against the literal pre-fix output the stranger saw and the
post-fix output beside it, and needs no binary, so a grader that cannot fail is
a failure here rather than a silent pass in CI.
"""
from __future__ import print_function

import argparse
import functools
import importlib.util
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

TICKET = "FIR-2961"

print = functools.partial(print, flush=True)

# The tracked module the experiment edits. Its body changes and nothing else
# does: no file added, no file removed, no declaration added or deleted. That is
# the shape both defects need, because it is the one shape that moves no count.
TRACKED_MODULE = "ledger/reporting.py"

MODULE_BEFORE = '''"""Roll ledger entries up into totals."""


def total_by(entries, key):
    """Sum amounts under one key."""
    buckets = {}
    for entry in entries:
        buckets[entry[key]] = buckets.get(entry[key], 0) + entry["amount"]
    return buckets
'''

# Same declarations, same names, same count. Only the body moved, which is the
# edit that admits with both cardinalities standing still.
MODULE_AFTER = '''"""Roll ledger entries up into totals."""


def total_by(entries, key):
    """Sum amounts under one key, rounded to cents."""
    buckets = {}
    for entry in entries:
        buckets[entry[key]] = round(buckets.get(entry[key], 0) + entry["amount"], 2)
    return buckets
'''


# Same declaration, two different bodies. A merge of two different FILES is clean
# and would grade nothing, so both branches rewrite `total_by`.
MODULE_SIDELINE = '''"""Roll ledger entries up into totals."""


def total_by(entries, key):
    """Sum amounts under one key, in cents."""
    buckets = {}
    for entry in entries:
        buckets[entry[key]] = buckets.get(entry[key], 0) + int(entry["amount"] * 100)
    return buckets
'''

MODULE_MAINLINE = '''"""Roll ledger entries up into totals."""


def total_by(entries, key):
    """Sum amounts under one key, with a currency symbol."""
    buckets = {}
    for entry in entries:
        buckets[entry[key]] = "$%.2f" % (buckets.get(entry[key], 0) + entry["amount"])
    return buckets
'''


# A THIRD body, for `check_content` alone. Same declarations, same count, body
# only, like MODULE_AFTER; distinct from it so an edit reaches `kin admit` that no
# earlier status read has already taken.
MODULE_FOR_ADMIT = '''"""Roll ledger entries up into totals."""


def total_by(entries, key):
    """Sum amounts under one key, rounded to whole units."""
    buckets = {}
    for entry in entries:
        buckets[entry[key]] = round(buckets.get(entry[key], 0) + entry["amount"])
    return buckets
'''


def run(cmd, cwd=None, env=None, timeout=600):
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


def tree_line(text):
    """The `Tree:` line, or None when the output carries none.

    None is returned rather than an empty string so a caller cannot mistake an
    output that never reached this line for one whose line was blank.
    """
    for line in (text or "").splitlines():
        if line.startswith("Tree: "):
            return line
    return None


# A verdict with a basis says one of three things: when the admission was taken,
# that none is recorded, or that the record would not parse. A bare verdict says
# none of them. Anchored on the words each arm is obliged to carry rather than on
# the whole sentence, so a rewording that keeps the fact still passes.
BASIS_PATTERNS = (
    re.compile(r"as admitted \S+ ago"),
    re.compile(r"no complete admission"),
    re.compile(r"will not parse"),
)


def grade_tree_line_carries_its_basis(text):
    line = tree_line(text)
    if line is None:
        return UNREADABLE, "kin status printed no Tree: line"
    if "base change" not in line:
        return UNREADABLE, "the Tree: line names no base-change verdict: %s" % line
    for pattern in BASIS_PATTERNS:
        if pattern.search(line):
            return PASS, "the verdict carries its basis: %s" % line
    return FAIL, (
        "the Tree: line states a verdict about the working copy with nothing "
        "saying when graph truth last looked: %s" % line
    )


def tree_hash(text):
    """The tree hash off the `Tree:` line, or None when there is no such line."""
    line = tree_line(text)
    if line is None:
        return None
    parts = line.split()
    return parts[1] if len(parts) > 1 else None


def grade_status_saw_the_edit(before_text, after_text):
    """The check the age could never make.

    kin#1254 put the admission's age beside the verdict, which made the sentence
    honest without making it true: measured on macOS the clock reads `0s ago`
    inside the roughly two-second window before the ambient watcher catches up,
    and on a bind mount that window never closes. So this grades the only thing
    that settles it, which is whether the tree the verdict describes is the tree
    on disk. Read as two hashes rather than as prose, because no wording can fake
    a hash moving.
    """
    before = tree_hash(before_text)
    after = tree_hash(after_text)
    if before is None or after is None:
        return UNREADABLE, "kin status printed no Tree: line on one of the two reads"
    if before == after:
        return FAIL, (
            "kin status reports the same tree %s after a tracked file changed, so it "
            "answered from a graph that has not seen the edit" % before[:16]
        )
    return PASS, "the tree moved %s -> %s, so the answer was measured against the working copy" % (
        before[:16], after[:16])


def grade_verdict_without_an_admission_says_so(text):
    """With nothing watching, a verdict is not a verdict.

    The case this catches is the one an age cannot: with the daemon stopped, the
    old line read `matching its base change as admitted 0s ago` while the
    untracked line directly below it correctly said nothing had measured
    anything. A fresh marker beside no admission is the most convincing possible
    form of the defect.
    """
    line = tree_line(text)
    if line is None:
        return UNREADABLE, "kin status printed no Tree: line"
    if "not measured against the working copy" in line:
        return PASS, "the verdict names itself unmeasured: %s" % line
    for pattern in BASIS_PATTERNS:
        if pattern.search(line):
            return FAIL, (
                "with nothing admitting the working copy, the verdict still presents a "
                "basis as though one had: %s" % line
            )
    return FAIL, "the verdict states no basis at all: %s" % line


def grade_status_names_a_held_merge(text, conflicts_text):
    """A merge Kin is holding cannot be seen from the working copy at all.

    Kin holds a merge in an authority transaction rather than smearing conflict
    markers across the files, which is the better design and is exactly why the
    status line is the only place this can live: there is nothing on disk to see.
    `kin status` said nothing during a merge that had left seventy-six conflicts
    unresolved (FIR-2961).

    `conflicts_text` is the positive control, and it is not decoration: if
    `kin conflicts` does not report a merge either, the fixture never reached the
    state this grades and the answer is UNREADABLE rather than FAIL.
    """
    body = text or ""
    control = conflicts_text or ""
    if "in progress" not in control.lower() and "merging" not in control.lower():
        return UNREADABLE, (
            "kin conflicts reports no held merge, so the fixture never reached the state "
            "this check is about: %s" % control.strip()[:200]
        )
    if "Merge in progress:" in body:
        line = next(l for l in body.splitlines() if l.startswith("Merge in progress:"))
        return PASS, "kin status names the held merge: %s" % line
    return FAIL, (
        "kin conflicts reports a held merge and kin status says nothing about it, so a "
        "reader who walks away is told the tree is clean and current"
    )


def grade_diff_discloses_its_semantic_scope(text):
    """`Entities: +0 ~0 -0` on a workspace diff cannot move, so it must say so.

    No writer in the daemon puts an entity delta into the workspace semantic
    overlay: the admission seam publishes `WorkspaceSemanticDelta::default()`
    unconditionally, and the one other writer passes the authority entities as
    both the base and the desired side. A stranger checked that zero against a
    fully settled graph and concluded the semantic layer had skipped a rewritten
    function body.
    """
    body = text or ""
    if "Entities:" not in body:
        return UNREADABLE, "kin diff printed no Entities line"
    if "Semantic scope:" not in body:
        return FAIL, (
            "a workspace diff printed its entity and relation counts with nothing saying "
            "they cannot move"
        )
    return PASS, "the workspace diff names what its semantic counts cannot show"


def grade_admit_left_the_graph_holding_the_edit(before_text, after_text):
    """Whether the graph holds the edit once the pass is done, read as two hashes.

    This graded the admission's WORDING until it was measured. The wording cannot
    carry the property: `content` and `settled` print the identical sentence,
    "Admitted the complete exact tree; nothing changed", and only one of them is a
    defect, so no reading of that string separates the two states it grades.

    Worse, the sentence was a true statement about a pass that correctly admitted
    nothing. The daemon's watch loop drains its file watcher every 100ms and
    admits what it finds (`loop_runner.rs`, `run_loop_armed`), and it is armed
    before `.kin/daemon.port` is published, so a write races an explicit
    `kin admit` and the loop usually wins. Measured on kin 0.6.2 at 510be53f9,
    six repetitions per arm: admitting immediately reported the content change 6
    of 6, and waiting 1.0s or 3.0s reported nothing changed 6 of 6. A stat-keyed
    cache predicts the opposite, since a staleness window shrinks as an mtime
    ages, and a write preserving both size and mtime was still seen 6 of 6, so
    nothing on this path trusts stat.

    So the property is that the graph ends up holding the new bytes, whoever
    admitted them. Read as two hashes for the reason `grade_status_saw_the_edit`
    gives one check above: no wording can fake a hash moving.
    """
    before = tree_hash(before_text)
    after = tree_hash(after_text)
    if before is None or after is None:
        return UNREADABLE, "kin status printed no Tree: line on one of the two reads"
    if before == after:
        return FAIL, (
            "the tree is still %s after a tracked file was edited and admitted, so the "
            "graph does not hold the edit" % before[:16]
        )
    return PASS, (
        "the graph holds the edit: the tree moved %s -> %s across the write and its "
        "admission" % (before[:16], after[:16])
    )


def grade_admit_still_reports_a_true_no_op(text):
    body = text or ""
    admission = next(
        (line for line in body.splitlines()
         if line.startswith("Admitted the complete exact tree")),
        None,
    )
    if admission is None:
        return UNREADABLE, "kin admit printed no admission line: %s" % body.strip()[:200]
    if "content changed" in admission:
        return FAIL, (
            "a pass with nothing left to take reported a content change: %s"
            % admission
        )
    legacy_all_clear = "nothing changed" in admission
    based_all_clear = re.search(
        r"nothing was left to admit, because the working copy was already admitted at "
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
        admission,
    )
    if not legacy_all_clear and based_all_clear is None:
        return FAIL, (
            "a settled tree got no all-clear, so the surface now hedges every answer: %s"
            % admission
        )
    return PASS, "a settled tree still gets its all-clear: %s" % admission


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        # kin refuses to invent an author, which is correct and not an obstacle.
        # The run isolates HOME so it cannot read the machine's identity, so it
        # brings one of its own.
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = vcs-read-surfaces-repro\n"
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
        self._repo = None

    def kin_run(self, args, timeout=600):
        rc, out, err = run([self.kin] + args, cwd=self.repo(), env=self.env, timeout=timeout)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args), rc))
        return rc, out, err

    def repo(self):
        if self._repo:
            return self._repo
        path = os.path.realpath(os.path.join(self.workdir, "ledger"))
        os.makedirs(path)
        self._repo = path
        # `kin init` refuses a non-empty directory for a non-Git repository, on
        # the stated grounds that it will not derive authority from filesystem
        # contents nothing admitted. So the store comes first and the files are
        # written into it, which is also the order the stranger used.
        rc, out, err = run([self.kin, "init"], cwd=path, env=self.env, timeout=600)
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % ((err or out)[-400:]))
        self._write(path, TRACKED_MODULE, MODULE_BEFORE)
        self._write(path, "ledger/__init__.py", '"""A tiny expense ledger."""\n')
        rc, out, err = self.kin_run(["commit", "-m", "Report totals grouped by key"])
        if rc != 0:
            raise RuntimeError("the seeding commit failed: %s" % ((err or out)[-400:]))
        return path

    @staticmethod
    def _write(root, relative, body):
        target = os.path.join(root, relative)
        directory = os.path.dirname(target)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(target, "w") as handle:
            handle.write(body)

    def edit_tracked_module(self):
        self._write(self.repo(), TRACKED_MODULE, MODULE_AFTER)

    def write_tracked_module(self, body):
        self._write(self.repo(), TRACKED_MODULE, body)

    def status_text(self):
        rc, out, err = self.kin_run(["status"])
        return out if rc == 0 else (out + err)


class Result(object):
    def __init__(self, ident, status, detail):
        self.ident = ident
        self.status = status
        self.detail = detail


def check_basis(suite):
    status, detail = grade_tree_line_carries_its_basis(suite.status_text())
    return Result("basis", status, "%s %s" % (TICKET, detail))


def check_saw_the_edit(suite):
    before = suite.status_text()
    suite.edit_tracked_module()
    status, detail = grade_status_saw_the_edit(before, suite.status_text())
    return Result("saw_the_edit", status, "%s %s" % (TICKET, detail))


def check_held_merge(suite):
    """Open a real conflicting merge and ask kin status about it.

    Destructive and it runs late for that reason: it leaves the workspace holding
    a merge transaction, which nothing after it would survive.
    """
    steps = [
        ["commit", "-m", "settle before branching"],
        ["branch", "create", "sideline"],
        ["branch", "switch", "sideline"],
    ]
    for args in steps:
        rc, out, err = suite.kin_run(args)
        if rc != 0:
            return Result("held_merge", UNREADABLE,
                          "%s `kin %s` exited %s: %s"
                          % (TICKET, " ".join(args), rc, (err or out)[-200:]))
    # Same declaration, two different bodies, one on each branch. That is the
    # shape that conflicts; two different files would merge clean and grade
    # nothing.
    suite.write_tracked_module(MODULE_SIDELINE)
    rc, out, err = suite.kin_run(["commit", "-m", "round on the sideline"])
    if rc != 0:
        return Result("held_merge", UNREADABLE,
                      "%s the sideline commit failed: %s" % (TICKET, (err or out)[-200:]))
    for args in (["branch", "switch", "main"],):
        rc, out, err = suite.kin_run(args)
        if rc != 0:
            return Result("held_merge", UNREADABLE,
                          "%s switching back failed: %s" % (TICKET, (err or out)[-200:]))
    suite.write_tracked_module(MODULE_MAINLINE)
    rc, out, err = suite.kin_run(["commit", "-m", "round on main"])
    if rc != 0:
        return Result("held_merge", UNREADABLE,
                      "%s the mainline commit failed: %s" % (TICKET, (err or out)[-200:]))
    # kin merge exits 0 on a conflicted merge today (a separate finding), so the
    # exit code is not the signal here and kin conflicts is.
    suite.kin_run(["merge", "sideline"])
    _, conflicts_out, conflicts_err = suite.kin_run(["conflicts"])
    status, detail = grade_status_names_a_held_merge(
        suite.status_text(), conflicts_out or conflicts_err
    )
    return Result("held_merge", status, "%s %s" % (TICKET, detail))


def check_unadmitted(suite):
    rc, out, err = suite.kin_run(["daemon", "stop"])
    if rc != 0:
        return Result("unadmitted", UNREADABLE,
                      "%s the daemon would not stop: %s" % (TICKET, (err or out)[-200:]))
    status, detail = grade_verdict_without_an_admission_says_so(suite.status_text())
    return Result("unadmitted", status, "%s %s" % (TICKET, detail))


def check_diff_scope(suite):
    rc, out, err = suite.kin_run(["diff", "HEAD", "WORKSPACE"])
    if rc != 0:
        return Result("diff_scope", UNREADABLE,
                      "%s kin diff exited %s: %s" % (TICKET, rc, (err or out)[-200:]))
    status, detail = grade_diff_discloses_its_semantic_scope(out)
    return Result("diff_scope", status, "%s %s" % (TICKET, detail))


def check_content(suite):
    """`kin admit` over a content-only edit must not report a no-op.

    Makes its OWN edit, and that is the whole correction. Since kin#1258
    `kin status` admits before it reads, so `check_saw_the_edit` above does not
    merely observe the edit, it TAKES it: the tree hash moving is exactly how that
    check passes. By the time this one ran, there was nothing left to admit and
    `kin admit` correctly said so, which failed this check on every main
    Acceptance run after kin#1258 landed.

    The check that proves read-after-admit works was consuming the state the next
    check grades. A read that mutates has to be treated as a mutation when
    ordering an experiment around it.
    """
    before = suite.status_text()
    suite.write_tracked_module(MODULE_FOR_ADMIT)
    rc, out, err = suite.kin_run(["admit"])
    if rc != 0:
        return Result("content", UNREADABLE,
                      "%s kin admit exited %s: %s" % (TICKET, rc, (err or out)[-200:]))
    status, detail = grade_admit_left_the_graph_holding_the_edit(before, suite.status_text())
    return Result("content", status, "%s %s" % (TICKET, detail))


def check_settled(suite):
    rc, out, err = suite.kin_run(["admit"])
    if rc != 0:
        return Result("settled", UNREADABLE,
                      "%s the control's kin admit exited %s: %s" % (TICKET, rc, (err or out)[-200:]))
    status, detail = grade_admit_still_reports_a_true_no_op(out)
    return Result("settled", status, "%s %s" % (TICKET, detail))


# Order is load-bearing and the experiment is destructive, and since kin#1258
# every `kin status` in it is a MUTATION: status admits before it reads. So each
# check that grades an unadmitted state has to create that state itself, after
# the last status call, rather than inherit one from the check above.
# `basis` and `saw_the_edit` both read status and therefore both admit;
# `saw_the_edit` takes the edit it makes, which is exactly how it passes.
# `content` writes its own edit for that reason, `settled` re-admits the settled
# tree `content` left, `diff_scope` reads a workspace diff over it, and
# `unadmitted` stops the daemon, which nothing after it could survive.
CHECKS = (
    ("basis", check_basis),
    ("saw_the_edit", check_saw_the_edit),
    ("content", check_content),
    ("settled", check_settled),
    ("diff_scope", check_diff_scope),
    ("held_merge", check_held_merge),
    ("unadmitted", check_unadmitted),
)


def report_payload(results):
    # The key is `results` because that is the one `gate.py:load_report` reads.
    # This file shipped it as `checks`, so the gate refused the report with
    # "carries no results list" and none of the graders below was ever consulted
    # (FIR-2985, the same class as FIR-2929 in init_budget). The self-test proves
    # the join by handing this payload to the real loader rather than by naming
    # the key a second time, because a string written twice drifts the same way.
    return {
        "ticket": TICKET,
        "results": [
            {"id": result.ident, "status": result.status, "detail": result.detail}
            for result in results
        ],
    }


def absolute_binary(path):
    if not path:
        return None
    resolved = os.path.abspath(path)
    return resolved if os.path.exists(resolved) else path


# The literal output the stranger saw, and the output the fix produces beside it.
# Quoted rather than invented, because a grader driven only against text written
# by the same hand cannot tell you what the product says.
STATUS_BARE = (
    "Kin repository-v6 status\n"
    "Tree: 70fda9aeeb87e4686298ebe4c601f1efbe1b5d65ce4e1567c158b2aa2efc076a "
    "(8 artifacts, matching its base change)\n"
    "Untracked host content: none, measured 0s ago\n"
)
STATUS_WITH_AGE = (
    "Kin repository-v6 status\n"
    "Tree: 70fda9aeeb87e4686298ebe4c601f1efbe1b5d65ce4e1567c158b2aa2efc076a "
    "(8 artifacts, matching its base change as admitted 2m ago)\n"
    "Untracked host content: none, measured 0s ago\n"
)
STATUS_UNKNOWN_BASIS = (
    "Kin repository-v6 status\n"
    "Tree: 70fda9ae (8 artifacts, matching its base change as last admitted; this store "
    "records no complete admission, so how far behind the working copy that is is unknown, "
    "and `kin admit` takes what it holds)\n"
)
STATUS_NO_TREE = "Kin repository-v6 status\nRefs: 1, default refs/heads/main\n"
# The bare verdict pointed the other way. A `dirty` tree with no basis is the
# same defect and must not pass because the word changed.
STATUS_BARE_AHEAD = (
    "Kin repository-v6 status\n"
    "Tree: c078181f (8 artifacts, ahead of its base change)\n"
)

# The verdict shapes read-after-admit produces, and the one it replaces.
STATUS_UNMEASURED_VERDICT = (
    "Kin repository-v6 status\n"
    "Tree: 70fda9ae (8 artifacts, matching its base change as last admitted, not measured "
    "against the working copy: no daemon is running for this repository, so nothing admitted "
    "the working copy)\n"
)
# The trap this arm exists for: a marker as fresh as it gets, beside no
# admission at all. The old line looked exactly like this.
STATUS_FRESH_CLOCK_NO_PASS = (
    "Kin repository-v6 status\n"
    "Tree: 70fda9ae (8 artifacts, matching its base change as admitted 0s ago)\n"
    "Untracked host content: not measured; no daemon is running for this repository\n"
)

DIFF_WITHOUT_SCOPE = (
    "Kin repository-v6 diff\n"
    "Artifacts: +0 ~1 -0\n"
    "Entities: +0 ~0 -0\n"
    "Relations: +0 ~0 -0\n"
    "M  ledger/reporting.py -> ledger/reporting.py [ce183603] blob f53cc41c -> blob d712bc3d\n"
)
DIFF_WITH_SCOPE = DIFF_WITHOUT_SCOPE + (
    "Semantic scope: The head endpoint is the workspace, whose entities are its base change's "
    "plus a workspace semantic overlay that nothing writes an entity delta into, so the entity "
    "count above cannot move for work in the working copy however many artifacts or relations "
    "do; commit it and diff change to change to see entity movement.\n"
)
STATUS_WITH_MERGE = (
    "Kin repository-v6 status\n"
    "Merge in progress: refs/heads/sideline into refs/heads/main as merge transaction "
    "1f2f0ae2, 2 of 76 conflict(s) settled; `kin conflicts` lists what is outstanding, and "
    "nothing below describes it\n"
    "Tree: efcc91dc (11 artifacts, matching its base change as admitted 0s ago)\n"
)
# The literal shape the stranger saw: a held 76-conflict merge, and a status that
# reports the tree as current and says nothing else.
STATUS_SILENT_DURING_MERGE = (
    "Kin repository-v6 status\n"
    "Tree: efcc91dc (11 artifacts, matching its base change)\n"
)
CONFLICTS_HELD = (
    "Merging refs/heads/sideline into refs/heads/main is in progress as merge transaction "
    "1f2f0ae2 (2 of 76 conflict(s) settled)\n"
)
CONFLICTS_NONE = "No merge has opened on workspace 004e239e; there is nothing to resolve\n"

DIFF_NO_ENTITIES_LINE = "Kin repository-v6 diff\nArtifacts: +0 ~1 -0\n"

ADMIT_NO_OP_CLAIM = (
    "Admitted the complete exact tree; nothing changed. 8 tracked artifacts, 39 entities.\n"
    "Embeddings: 71 of 78 indexed; the remainder is queued for the background embed pass.\n"
)
ADMIT_ALREADY_CURRENT = (
    "Admitted the complete exact tree; nothing was left to admit, because the working copy was "
    "already admitted at 2026-08-30T21:32:59.447229962+00:00. 8 tracked artifacts, "
    "39 entities.\n"
)
ADMIT_ALREADY_CURRENT_WITHOUT_BASIS = (
    "Admitted the complete exact tree; nothing was left to admit. 8 tracked artifacts, "
    "39 entities.\n"
)
ADMIT_HEDGED = (
    "Admitted the complete exact tree; the working copy may already be current. "
    "8 tracked artifacts, 39 entities.\n"
)
ADMIT_CONTENT_MOVED = (
    "Admitted the complete exact tree; content changed, with no artifact or entity added "
    "or removed. 8 tracked artifacts, 39 entities.\n"
)
ADMIT_UNMEASURED = (
    "Admitted the complete exact tree. 8 tracked artifacts, 39 entities, and neither count "
    "moved; this daemon does not report whether content moved, so this is not a statement "
    "that the tree is unchanged.\n"
)
ADMIT_REFUSED = "Complete exact-tree admission failed: host entry changed\n"


def check_the_gate_reads_this_suites_report():
    """Hand this suite's own report to `gate.py`'s loader and require it back.

    FIR-2985. This file emitted its rows under `checks` while `gate.py`'s
    `load_report` reads `results`, so the gate refused the report with "carries
    no results list" and every grader above went ungraded from the moment the
    suite was wired in. The run stayed red, which is the good half, but it was
    red for a plumbing fault wearing a product failure's clothes.

    The same class had already been fixed once, in init_budget under FIR-2929,
    and `working_copy_freshness_repro.py` already carries this exact check. It
    is per-suite, which is precisely why the class came back here. This is that
    proven check copied, not a new invention.

    Asserting the literal key would write the string twice and drift the same
    way. Importing the real consumer cannot: if the gate stops reading
    `results`, or this file stops writing it, this goes red.

    Returns (cases_run, broken).
    """
    ran = 0
    broken = 0

    def expect(name, got, want):
        nonlocal ran, broken
        ran += 1
        ok = got == want
        if not ok:
            broken += 1
        print("SELFTEST %s %s expected=%s got=%s"
              % (name, "ok" if ok else "BROKEN", want, got))

    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        print("SELFTEST gate/beside BROKEN gate.py is not beside this file, "
              "so the report shape went unchecked")
        return 1, 1

    spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)

    scratch = tempfile.mkdtemp(prefix="vcs-read-surfaces-selftest-")
    try:
        rows = [Result(ident, UNREADABLE, "%s check raised: fabricated" % TICKET)
                for ident, _ in CHECKS]
        good = os.path.join(scratch, "good.json")
        with open(good, "w") as handle:
            json.dump(report_payload(rows), handle)
        try:
            loaded = gate.load_report(good)
            expect("gate/reads-every-row", sorted(loaded),
                   sorted(ident for ident, _ in CHECKS))
            expect("gate/reads-a-status", loaded[CHECKS[0][0]].get("status"), UNREADABLE)
        except Exception as exc:  # noqa: BLE001 - a refusal is the finding
            ran += 1
            broken += 1
            print("SELFTEST gate/reads-every-row BROKEN the gate refused this "
                  "suite's own report: %s" % exc)

        # CONTROL: the shape that shipped must still be refused, or the two
        # assertions above would pass over any payload at all.
        bad = os.path.join(scratch, "bad.json")
        with open(bad, "w") as handle:
            json.dump({"ticket": TICKET,
                       "checks": [{"id": ident, "status": UNREADABLE}
                                  for ident, _ in CHECKS]}, handle)
        try:
            gate.load_report(bad)
            refused = False
        except Exception:  # noqa: BLE001 - the refusal is what is wanted
            refused = True
        expect("gate/CONTROL-still-refuses-the-checks-shape", refused, True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return ran, broken


def self_test():
    """Drive every grader against a payload that must pass and one that must fail.

    Each row names the grader, the payload, and the verdict it is obliged to
    reach. A grader that answers PASS to everything and one that answers FAIL to
    everything both fail here, which is the only way this file is worth running.
    """
    cases = [
        ("basis/bare-clean", grade_tree_line_carries_its_basis, STATUS_BARE, FAIL),
        ("basis/bare-ahead", grade_tree_line_carries_its_basis, STATUS_BARE_AHEAD, FAIL),
        ("basis/with-age", grade_tree_line_carries_its_basis, STATUS_WITH_AGE, PASS),
        ("basis/unknown", grade_tree_line_carries_its_basis, STATUS_UNKNOWN_BASIS, PASS),
        ("basis/no-tree-line", grade_tree_line_carries_its_basis, STATUS_NO_TREE, UNREADABLE),
        # The arm the age could never reach. A fresh clock beside no admission is
        # the most convincing form of the defect, so it must FAIL here.
        ("unadmitted/fresh-clock-no-pass", grade_verdict_without_an_admission_says_so,
         STATUS_FRESH_CLOCK_NO_PASS, FAIL),
        ("unadmitted/named", grade_verdict_without_an_admission_says_so,
         STATUS_UNMEASURED_VERDICT, PASS),
        ("unadmitted/bare", grade_verdict_without_an_admission_says_so, STATUS_BARE, FAIL),
        ("unadmitted/no-tree-line", grade_verdict_without_an_admission_says_so,
         STATUS_NO_TREE, UNREADABLE),
        ("diffscope/absent", grade_diff_discloses_its_semantic_scope,
         DIFF_WITHOUT_SCOPE, FAIL),
        ("diffscope/present", grade_diff_discloses_its_semantic_scope, DIFF_WITH_SCOPE, PASS),
        ("diffscope/no-entities", grade_diff_discloses_its_semantic_scope,
         DIFF_NO_ENTITIES_LINE, UNREADABLE),
        # The grader takes a pair, so these rows carry a tuple. The UNREADABLE row
        # is the one that keeps this check honest: a silent status over a fixture
        # that never opened a merge is a setup failure, not a product defect, and
        # scoring it FAIL would make the check fire on its own broken fixture.
        ("heldmerge/silent", grade_status_names_a_held_merge,
         (STATUS_SILENT_DURING_MERGE, CONFLICTS_HELD), FAIL),
        ("heldmerge/named", grade_status_names_a_held_merge,
         (STATUS_WITH_MERGE, CONFLICTS_HELD), PASS),
        ("heldmerge/no-merge-opened", grade_status_names_a_held_merge,
         (STATUS_SILENT_DURING_MERGE, CONFLICTS_NONE), UNREADABLE),
        ("settled/no-op-claim", grade_admit_still_reports_a_true_no_op, ADMIT_NO_OP_CLAIM, PASS),
        ("settled/already-current", grade_admit_still_reports_a_true_no_op,
         ADMIT_ALREADY_CURRENT, PASS),
        ("settled/already-current-without-basis", grade_admit_still_reports_a_true_no_op,
         ADMIT_ALREADY_CURRENT_WITHOUT_BASIS, FAIL),
        ("settled/hedged", grade_admit_still_reports_a_true_no_op, ADMIT_HEDGED, FAIL),
        ("settled/moved", grade_admit_still_reports_a_true_no_op, ADMIT_CONTENT_MOVED, FAIL),
        ("settled/unmeasured", grade_admit_still_reports_a_true_no_op, ADMIT_UNMEASURED, FAIL),
        ("settled/refused", grade_admit_still_reports_a_true_no_op, ADMIT_REFUSED, UNREADABLE),
    ]
    # The two-hash grader takes a pair, so its rows carry a tuple and are unpacked
    # here. A grader that ignored one side would pass its own table, which is why
    # the moved and unmoved rows are both required.
    cases.extend([
        ("sawedit/moved", grade_status_saw_the_edit, (STATUS_BARE, STATUS_BARE_AHEAD), PASS),
        ("sawedit/unmoved", grade_status_saw_the_edit, (STATUS_BARE, STATUS_BARE), FAIL),
        ("sawedit/no-tree-line", grade_status_saw_the_edit,
         (STATUS_BARE, STATUS_NO_TREE), UNREADABLE),
        # `content` grades the same property one step later: the graph holding
        # the edit after the admission, rather than the admission's sentence.
        # The unmoved row is what keeps FIR-2961's original finding covered,
        # because it is the arm that reds when the graph does NOT hold the bytes.
        ("content/moved", grade_admit_left_the_graph_holding_the_edit,
         (STATUS_BARE, STATUS_BARE_AHEAD), PASS),
        ("content/unmoved", grade_admit_left_the_graph_holding_the_edit,
         (STATUS_BARE, STATUS_BARE), FAIL),
        ("content/no-tree-line", grade_admit_left_the_graph_holding_the_edit,
         (STATUS_BARE, STATUS_NO_TREE), UNREADABLE),
    ])
    failures = 0
    for name, grader, payload, expected in cases:
        got, detail = grader(*payload) if isinstance(payload, tuple) else grader(payload)
        ok = got == expected
        if not ok:
            failures += 1
        print("SELFTEST %s %s expected=%s got=%s %s"
              % (name, "ok" if ok else "BROKEN", expected, got, detail))
    gate_cases, gate_broken = check_the_gate_reads_this_suites_report()
    failures += gate_broken
    print("SELFTEST %d case(s), %d broken" % (len(cases) + gate_cases, failures))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN") or shutil.which("kin"))
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"))
    parser.add_argument("--json", dest="json_path")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    opts = parser.parse_args(argv)

    if opts.self_test:
        return self_test()

    if not opts.kin:
        print("SETUP no kin binary: pass --kin or set KIN_BIN")
        return 3
    opts.kin = absolute_binary(opts.kin)
    opts.daemon = absolute_binary(opts.daemon)

    workdir = tempfile.mkdtemp(prefix="vcs-read-surfaces-")
    suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose)
    try:
        results = []
        for ident, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a setup failure is not a verdict
                results.append(Result(ident, UNREADABLE, "%s check raised: %s" % (TICKET, error)))
        for result in results:
            print("CHECK %s %s %s %s" % (result.ident, TICKET, result.status, result.detail))
        asked = [ident for ident, _ in CHECKS]
        answered = [result.ident for result in results]
        # Written before the asked/answered guard, not after it. Four UNREADABLE
        # rows are a verdict the gate can name; a missing report is one it can
        # only refuse.
        if opts.json_path:
            directory = os.path.dirname(os.path.abspath(opts.json_path))
            if directory:
                try:
                    os.makedirs(directory)
                except OSError:
                    pass
            with open(opts.json_path, "w") as handle:
                json.dump(report_payload(results), handle, indent=2)
        if answered != asked:
            print("SETUP asked for %r and %r answered" % (asked, answered))
            return 3
        if any(result.status == FAIL for result in results):
            return 1
        if any(result.status == UNREADABLE for result in results):
            return 2
        return 0
    finally:
        try:
            if suite._repo:
                run([opts.kin, "daemon", "stop"], cwd=suite._repo, env=suite.env, timeout=180)
        except Exception:  # noqa: BLE001 - teardown must not change the verdict
            pass
        if not opts.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("kept fixtures under %s" % workdir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
