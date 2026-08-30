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

Six checks, one seeded repository, run in order because the experiment is
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
  settled      the control: a second `kin admit` with nothing left to take says
               "nothing changed" and says it plainly. Without this the others
               are satisfied by a product that hedges every sentence
  diff_scope   a workspace diff names what its entity and relation counts cannot
               show, rather than printing three zeroes that cannot move
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


def grade_admit_does_not_claim_a_no_op(text):
    body = text or ""
    if "Admitted the complete exact tree" not in body:
        return UNREADABLE, "kin admit printed no admission line: %s" % body.strip()[:200]
    if "nothing changed" in body:
        return FAIL, (
            "a pass over an edited tracked file reported nothing changed: %s"
            % body.strip().splitlines()[0]
        )
    if "content changed" not in body:
        return FAIL, (
            "the pass neither claimed a no-op nor named the content change: %s"
            % body.strip().splitlines()[0]
        )
    return PASS, "the pass named the content change: %s" % body.strip().splitlines()[0]


def grade_admit_still_reports_a_true_no_op(text):
    body = text or ""
    if "Admitted the complete exact tree" not in body:
        return UNREADABLE, "kin admit printed no admission line: %s" % body.strip()[:200]
    if "content changed" in body:
        return FAIL, (
            "a pass with nothing left to take reported a content change: %s"
            % body.strip().splitlines()[0]
        )
    if "nothing changed" not in body:
        return FAIL, (
            "a settled tree got no all-clear, so the surface now hedges every answer: %s"
            % body.strip().splitlines()[0]
        )
    return PASS, "a settled tree still gets its all-clear: %s" % body.strip().splitlines()[0]


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
    rc, out, err = suite.kin_run(["admit"])
    if rc != 0:
        return Result("content", UNREADABLE,
                      "%s kin admit exited %s: %s" % (TICKET, rc, (err or out)[-200:]))
    status, detail = grade_admit_does_not_claim_a_no_op(out)
    return Result("content", status, "%s %s" % (TICKET, detail))


def check_settled(suite):
    rc, out, err = suite.kin_run(["admit"])
    if rc != 0:
        return Result("settled", UNREADABLE,
                      "%s the control's kin admit exited %s: %s" % (TICKET, rc, (err or out)[-200:]))
    status, detail = grade_admit_still_reports_a_true_no_op(out)
    return Result("settled", status, "%s %s" % (TICKET, detail))


# Order is load-bearing and the experiment is destructive. `saw_the_edit` makes
# the edit the next two are about, `content` admits it, `settled` re-admits a
# settled tree, `diff_scope` reads a workspace diff over it, and `unadmitted`
# stops the daemon, which nothing after it could survive.
CHECKS = (
    ("basis", check_basis),
    ("saw_the_edit", check_saw_the_edit),
    ("content", check_content),
    ("settled", check_settled),
    ("diff_scope", check_diff_scope),
    ("unadmitted", check_unadmitted),
)


def report_payload(results):
    return {
        "ticket": TICKET,
        "checks": [
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
DIFF_NO_ENTITIES_LINE = "Kin repository-v6 diff\nArtifacts: +0 ~1 -0\n"

ADMIT_NO_OP_CLAIM = (
    "Admitted the complete exact tree; nothing changed. 8 tracked artifacts, 39 entities.\n"
    "Embeddings: 71 of 78 indexed; the remainder is queued for the background embed pass.\n"
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
        ("content/no-op-claim", grade_admit_does_not_claim_a_no_op, ADMIT_NO_OP_CLAIM, FAIL),
        ("content/moved", grade_admit_does_not_claim_a_no_op, ADMIT_CONTENT_MOVED, PASS),
        ("content/unmeasured", grade_admit_does_not_claim_a_no_op, ADMIT_UNMEASURED, FAIL),
        ("content/refused", grade_admit_does_not_claim_a_no_op, ADMIT_REFUSED, UNREADABLE),
        ("settled/no-op-claim", grade_admit_still_reports_a_true_no_op, ADMIT_NO_OP_CLAIM, PASS),
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
    ])
    failures = 0
    for name, grader, payload, expected in cases:
        got, detail = grader(*payload) if isinstance(payload, tuple) else grader(payload)
        ok = got == expected
        if not ok:
            failures += 1
        print("SELFTEST %s %s expected=%s got=%s %s"
              % (name, "ok" if ok else "BROKEN", expected, got, detail))
    print("SELFTEST %d case(s), %d broken" % (len(cases), failures))
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
