#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC

"""Prove a bulk artifact settle never overrides an entity decision inside it.

FIR-2958. The rc062a stranger run settled one entity `--theirs`, settled the rest
`--all-ours`, and was told every conflict was resolved:

    $ kin resolve --theirs 0ce7fbfa-...              # format_report
    Settled 1 conflict(s); ... has 1 of 76 conflict(s) settled
    $ kin resolve --all-ours --expect db9836e0...
    Settled 75 conflict(s); ... has 76 of 76 conflict(s) settled
    $ kin resolve --do-continue
    Merged refs/heads/pretty into refs/heads/main as change 5f3cd725...

Every line reported success and 1 + 75 = 76 reconciles. The merged file was the
`--ours` version, and the merge change recorded `Deltas: entities=1 relations=0
tree=0`: a tree delta of zero, meaning the source branch contributed no bytes at
all. The entity decision was recorded, reported settled, and discarded.

The mechanism is that a settled entity and a settled artifact land in two
independent maps, and only the artifact map becomes file bytes. Both decisions
were honoured, in different dimensions, and the one the reader sees won.

The rule this suite grades is the founder's ruling of 2026-08-30: entity beats
artifact, specific beats bulk. The artifact is re-taken from whichever side's
published bytes carry every entity decision inside that file, and where no side
carries all of them the merge refuses and names both decisions. Nothing is
synthesized, because kin has no textual line merge to build a third body from,
so a projection is a choice among sides this merge already bound.

Six checks over five repositories, run in order because two of them are
destructive: they publish the merge the earlier assertions are about. The first
four grade FIR-2958's precedence rule; the last two grade rc062j finding (2),
which is the same authority reporting conflicts that are not conflicts.

  precedence  the entity settled `--theirs` decides the bytes of the artifact
              holding it, even though a later `--all-ours` settled that artifact,
              and the published merge carries a nonzero tree delta
  bulk        the control on the same merge: `--all-ours` still owns every
              artifact no entity decision contradicts, so the rule is precedence
              and not "take theirs"
  refusal     two entities in one file settled to opposite sides have no
              publishable projection, so the merge refuses, names the file and
              both decisions, moves no ref, and leaves the resolutions parked
  uniform     the control that keeps the other three honest: an ordinary
              `--all-theirs` merge still publishes, with the source bytes on
              disk and a nonzero tree delta. Without it a product that refused
              every merge would satisfy the refusal check and lose nothing else.
  removals    one changed function parks no row saying a branch removed an
              identity it did not remove. Measured at 18 such rows of 22 before
              the fix, on this same fixture
  genuine     the control for `removals`: a real removal, still pointed at by
              the other side, is still reported. Without it a merge that dropped
              every relation row would satisfy `removals` and lose nothing else

Exit status is 0 when every check passed, 1 when one failed, 2 when one could not
be read, and 3 when the run could not be set up. `--self-test` exercises every
grader against a payload that must pass and one that must fail, and needs no
binary, so a grader that cannot fail is a failure here rather than a silent pass
in CI.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/merge_precedence_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script.
"""
from __future__ import print_function

import argparse
import functools
import json
import os
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET = "FIR-2958"
# The granularity checks are rc062j finding (2), a different ticket in the same
# merge authority, graded here rather than in a second suite because a second
# copy of this scaffolding is only ever wrong in a way that looks like a pass.
GRANULARITY_TICKET = "FIR-2960"

print = functools.partial(print, flush=True)

# One file whose two entities both conflict. `base` is edited to a DIFFERENT
# LENGTH on each branch, which moves `mate` to a different byte offset on each
# branch, so `mate` conflicts too while being semantically identical on both
# sides. That shape is the whole difficulty and it is what the stranger hit: a
# bulk settle records a decision about `mate` that only its byte offsets
# distinguish, and judging the merge on whole entity values would refuse a mix
# kin can project honestly. The two bodies must not be the same length.
BASE_LIB = b"pub fn base() {}\npub fn mate() {}\n"
OURS_LIB = b"pub fn base(count: u64) {}\npub fn mate() {}\n"
THEIRS_LIB = b"pub fn base(v: i32) {}\npub fn mate() {}\n"

# A second file neither entity decision covers, so the bulk settle has something
# to keep. Without it "the rule is precedence" and "the rule is take theirs" are
# the same observation.
BASE_SHARED = b"shared bytes\n"
OURS_SHARED = b"main shared\n"
THEIRS_SHARED = b"feature shared\n"

# The contradictory fixture: two entities in one file, both moved on both
# branches, so settling them to opposite sides leaves no side carrying both.
# The granularity fixtures, rc062j finding (2). Python, because a Rust
# `src/lib.rs` produces no module entity and no import edges, so it has nothing
# to strand. `summarize` is called from three sibling modules, so it carries real
# incoming edges, and both sides edit it to a DIFFERENT LENGTH, which is what
# moves `helper` below it to a different byte offset on each side.
GRAN_CORE_BASE = b"def summarize(rows):\n    return len(rows)\n\n\ndef helper(x):\n    return x + 1\n"
GRAN_CORE_OURS = b"def summarize(rows):\n    return len(rows) + 100\n\n\ndef helper(x):\n    return x + 1\n"
GRAN_CORE_THEIRS = b"def summarize(rows):\n    return len(rows) * 2\n\n\ndef helper(x):\n    return x + 1\n"


def _gran_module(name):
    return ("from pkg.core import summarize, helper\n\n\n"
            "def use_%s(rows):\n    return summarize(rows) + helper(1)\n" % name).encode()


GRAN_FILES = {"pkg/core.py": (GRAN_CORE_BASE, GRAN_CORE_OURS, GRAN_CORE_THEIRS)}
for _name in ("a", "b", "c"):
    _body = _gran_module(_name)
    GRAN_FILES["pkg/mod_%s.py" % _name] = (_body, _body, _body)

# The control fixture: one side genuinely REMOVES `helper` while the other side
# adds an edge to it. That endpoint is absent from one side, so its row is
# predictive rather than false, and it must survive. Without this check a merge
# that dropped every relation row would pass `removals` and lose nothing else.
GENUINE_CORE_BASE = GRAN_CORE_BASE
GENUINE_CORE_OURS = b"def summarize(rows):\n    return len(rows)\n"
GENUINE_CORE_THEIRS = GRAN_CORE_BASE
GENUINE_MOD_BASE = b"from pkg.core import summarize\n\n\ndef use_a(rows):\n    return summarize(rows)\n"
GENUINE_MOD_THEIRS = _gran_module("a")
GENUINE_FILES = {
    "pkg/core.py": (GENUINE_CORE_BASE, GENUINE_CORE_OURS, GENUINE_CORE_THEIRS),
    "pkg/mod_a.py": (GENUINE_MOD_BASE, GENUINE_MOD_BASE, GENUINE_MOD_THEIRS),
}

BASE_PAIR = b"pub fn alpha() {}\npub fn beta() {}\n"
OURS_PAIR = b"pub fn alpha(count: u64) {}\npub fn beta(count: u64) {}\n"
THEIRS_PAIR = b"pub fn alpha(v: i32) {}\npub fn beta(v: i32) {}\n"


def run(cmd, cwd=None, env=None, timeout=600, stdin=None):
    proc = subprocess.Popen(
        cmd, cwd=cwd, env=env,
        stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    try:
        out, err = proc.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out, err
    return proc.returncode, out, err


# -- graders ---------------------------------------------------------------
#
# Every grader takes parsed payloads or rendered text and returns (status,
# detail). Kept apart from the run so `--self-test` can hand each one an input
# that must pass and one that must fail, with no binary anywhere.


def merge_change_of(log_text):
    """The newest change's parents and delta counts, or None when unreadable.

    `Deltas:` and `Parents:` are `kin log`'s own lines. Reading both is what
    separates "the merge moved no bytes" from "this is not a merge at all":
    a one-parent change with tree=0 is an ordinary empty change and says
    nothing about this defect.
    """
    if not isinstance(log_text, str) or "change " not in log_text:
        return None
    parents = None
    deltas = None
    for line in log_text.splitlines():
        stripped = line.strip()
        if parents is None and stripped.startswith("Parents:"):
            parents = stripped[len("Parents:"):].split()
        if deltas is None and stripped.startswith("Deltas:"):
            fields = {}
            for token in stripped[len("Deltas:"):].split():
                key, sep, value = token.partition("=")
                if sep:
                    fields[key] = value
            deltas = fields
    if deltas is None:
        return None
    return {"parents": parents or [], "deltas": deltas}


def grade_merge_moved_the_tree(log_text):
    """A merge that took the source branch's entity has to move the tree.

    `tree=0` is the exact signature the stranger recorded: the merged tree is
    byte-identical to the target branch, so the source branch contributed
    nothing while all 76 conflicts read as settled.
    """
    read = merge_change_of(log_text)
    if read is None:
        return UNREADABLE, "the log carries no change with a Deltas line"
    if len(read["parents"]) != 2:
        return UNREADABLE, (
            "the newest change is not a merge, so its deltas say nothing: parents %r"
            % (read["parents"],)
        )
    tree = read["deltas"].get("tree")
    if tree is None:
        return UNREADABLE, "the Deltas line carries no tree count: %r" % (read["deltas"],)
    if tree == "0":
        return FAIL, (
            "the merge change records tree=0, so the source branch contributed no bytes "
            "while every conflict reported settled: %r" % (read["deltas"],)
        )
    return PASS, "the merge change records tree=%s beside parents %r" % (tree, read["parents"])


def grade_bytes(actual, expected, what):
    """What is on disk, against what the settled decisions say must be."""
    if actual is None:
        return UNREADABLE, "%s could not be read from disk" % (what,)
    if actual != expected:
        return FAIL, "%s holds %r, and the settled decisions say %r" % (what, actual, expected)
    return PASS, "%s holds %r" % (what, actual)


def grade_refusal_names_both_decisions(stderr, path, entity_names):
    """A refusal that does not name both decisions is the defect wearing a
    refusal costume: the caller still cannot see which two choices collided."""
    if not isinstance(stderr, str) or not stderr.strip():
        return UNREADABLE, "the refusal printed nothing at all"
    if path not in stderr:
        return FAIL, "the refusal does not name the file %s: %r" % (path, stderr[-400:])
    missing = [name for name in entity_names if name not in stderr]
    if missing:
        return FAIL, (
            "the refusal does not name the entity decision(s) %s: %r"
            % (", ".join(missing), stderr[-400:])
        )
    absent = [flag for flag in ("--theirs", "--ours") if flag not in stderr]
    if absent:
        return FAIL, (
            "the refusal does not name the %s side(s) that were chosen: %r"
            % (", ".join(absent), stderr[-400:])
        )
    return PASS, "the refusal names %s and both decisions" % (path,)


def grade_nothing_published(log_text, before_head):
    """A refused merge moves no ref. Reading the head back is the only proof;
    the refusal's own text cannot say what it did not do."""
    if not isinstance(log_text, str) or "change " not in log_text:
        return UNREADABLE, "the log could not be read back after the refusal"
    head = None
    for line in log_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("change "):
            head = stripped.split()[1]
            break
    if head is None:
        return UNREADABLE, "the log names no change at all"
    if head != before_head:
        return FAIL, "the refused merge still advanced the branch from %s to %s" % (
            before_head, head)
    return PASS, "the branch is still at %s" % (head,)


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.home = os.path.join(workdir, "home")
        os.makedirs(self.home)
        # kin refuses to invent an author, which is correct product behavior and
        # not an obstacle. The run isolates HOME so it cannot read the machine's
        # identity, so it brings one of its own.
        with open(os.path.join(self.home, ".gitconfig"), "w") as handle:
            handle.write("[user]\n\tname = merge-precedence-repro\n"
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

    def git(self, args, repo):
        base = ["git", "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=merge-precedence-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=repo, env=self.env)

    def kin_run(self, args, repo, timeout=600):
        rc, out, err = run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)
        if self.verbose:
            print("  $ kin %s -> rc=%s" % (" ".join(args), rc))
        return rc, out, err

    def repo(self, name, files):
        """A converted repository whose `main` and `feature` both moved `files`.

        `files` maps a relative path to its (base, ours, theirs) bodies. main is
        ours, feature is theirs, which is the orientation `kin merge feature`
        gives them.
        """
        if name in self._repos:
            return self._repos[name]
        path = os.path.realpath(os.path.join(self.workdir, name))
        os.makedirs(path)
        self.git(["init", "-q", "--initial-branch=main", "."], path)
        self._write(path, files, 0)
        self.git(["add", "-A"], path)
        rc, out, err = self.git(["commit", "-q", "-m", "base"], path)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % (err or out)[-300:])

        self.git(["switch", "-q", "-c", "feature"], path)
        self._write(path, files, 2)
        self.git(["add", "-A"], path)
        rc, out, err = self.git(["commit", "-q", "-m", "feature work"], path)
        if rc != 0:
            raise RuntimeError("git commit failed on feature: %s" % (err or out)[-300:])

        self.git(["switch", "-q", "main"], path)
        self._write(path, files, 1)
        self.git(["add", "-A"], path)
        rc, out, err = self.git(["commit", "-q", "-m", "main work"], path)
        if rc != 0:
            raise RuntimeError("git commit failed on main: %s" % (err or out)[-300:])

        rc, out, err = self.kin_run(["init", "."], path)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (path, (err or out)[-300:]))
        # `kin init` can leave a pending semantic overlay, and a merge refuses to
        # publish into a workspace holding one. It happens on the Python fixtures
        # and not on the Rust ones, so a builder that skipped this worked for
        # four checks and made the other two UNREADABLE. Not graded: a workspace
        # with nothing pending reports nothing to commit, which is the same clean
        # state under another name, and a merge that still refuses says so in the
        # check's own detail line.
        self.kin_run(["commit", "-m", "settle the post-init overlay"], path)
        self._repos[name] = path
        return path

    @staticmethod
    def _write(path, files, index):
        for rel, bodies in files.items():
            full = os.path.join(path, rel)
            parent = os.path.dirname(full)
            if parent and not os.path.isdir(parent):
                os.makedirs(parent)
            with open(full, "wb") as handle:
                handle.write(bodies[index])

    def read_bytes(self, repo, rel):
        try:
            with open(os.path.join(repo, rel), "rb") as handle:
                return handle.read()
        except (IOError, OSError):
            return None

    def conflicts(self, repo):
        rc, out, err = self.kin_run(["conflicts", "--json"], repo)
        if rc != 0:
            raise RuntimeError("kin conflicts --json failed: %s" % (err or out)[-300:])
        return json.loads(out)

    def entity_conflict(self, report, name):
        """The identity of the one parked entity conflict named `name`.

        `kin resolve` takes the uuid, and the listing labels an entity
        `<name> in <file>`. Asserting there is exactly one keeps a fixture that
        grew a second entity of that name from settling the wrong conflict.
        """
        prefix = "%s in " % name
        found = []
        for entry in (report.get("record") or {}).get("entries") or []:
            subject = entry.get("subject") or {}
            if subject.get("subject") != "entity":
                continue
            label = entry.get("label")
            if isinstance(label, str) and label.startswith(prefix):
                found.append(subject.get("entity"))
        if len(found) != 1:
            raise RuntimeError(
                "expected exactly one parked conflict named %s, found %r" % (name, found))
        return found[0]

    def head_change(self, repo):
        rc, out, err = self.kin_run(["log", "-n", "1"], repo)
        if rc != 0:
            raise RuntimeError("kin log failed: %s" % (err or out)[-300:])
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith("change "):
                return stripped.split()[1]
        raise RuntimeError("kin log named no change: %s" % out[-300:])


class Result(object):
    """One graded check.

    `ticket` defaults to this suite's own. It exists because the CHECK line and
    the detail string used to be able to disagree: the printer hardcoded the
    suite ticket while `_combine` wrote whichever ticket the check passed, so a
    granularity row announced FIR-2958 and then explained FIR-2960.
    """

    def __init__(self, ident, status, detail, ticket=None):
        self.ident = ident
        self.status = status
        self.detail = detail
        self.ticket = ticket or TICKET


MIXED_FILES = {
    "src/lib.rs": (BASE_LIB, OURS_LIB, THEIRS_LIB),
    "shared.txt": (BASE_SHARED, OURS_SHARED, THEIRS_SHARED),
}
PAIR_FILES = {"src/lib.rs": (BASE_PAIR, OURS_PAIR, THEIRS_PAIR)}


def _settle_the_mixed_merge(suite):
    """Do the stranger's three commands once, and cache what they produced."""
    if hasattr(suite, "_mixed"):
        return suite._mixed
    repo = suite.repo("mixed", MIXED_FILES)
    rc, out, err = suite.kin_run(["merge", "feature"], repo)
    # A conflicted merge is the state this suite is about, so a nonzero exit is
    # expected here and is not graded: FIR-2960 grades the exit code itself.
    del rc, out, err
    entity = suite.entity_conflict(suite.conflicts(repo), "base")
    rc, out, err = suite.kin_run(["resolve", "--theirs", entity], repo)
    if rc != 0:
        raise RuntimeError("settling the entity failed: %s" % (err or out)[-300:])
    rc, out, err = suite.kin_run(["resolve", "--all-ours"], repo)
    if rc != 0:
        raise RuntimeError("the bulk settle failed: %s" % (err or out)[-300:])
    rc, out, err = suite.kin_run(["resolve", "--continue"], repo)
    published = rc == 0
    log = suite.kin_run(["log", "-n", "1"], repo)[1] if published else ""
    suite._mixed = {"repo": repo, "published": published, "log": log,
                    "detail": (err or out)[-400:]}
    return suite._mixed


def check_precedence(suite):
    state = _settle_the_mixed_merge(suite)
    if not state["published"]:
        return Result("precedence", FAIL,
                      "%s the merge did not publish at all: %s" % (TICKET, state["detail"]))
    verdicts = [
        ("bytes", grade_bytes(suite.read_bytes(state["repo"], "src/lib.rs"),
                              THEIRS_LIB, "src/lib.rs")),
        ("tree", grade_merge_moved_the_tree(state["log"])),
    ]
    return _combine("precedence", verdicts)


def check_bulk(suite):
    state = _settle_the_mixed_merge(suite)
    if not state["published"]:
        return Result("bulk", UNREADABLE,
                      "%s the merge did not publish, so the bulk settle is ungraded" % TICKET)
    status, detail = grade_bytes(suite.read_bytes(state["repo"], "shared.txt"),
                                 OURS_SHARED, "shared.txt")
    return Result("bulk", status, "%s %s" % (TICKET, detail))


def check_refusal(suite):
    repo = suite.repo("pair", PAIR_FILES)
    before = suite.head_change(repo)
    suite.kin_run(["merge", "feature"], repo)
    report = suite.conflicts(repo)
    alpha = suite.entity_conflict(report, "alpha")
    beta = suite.entity_conflict(report, "beta")
    rc, out, err = suite.kin_run(["resolve", "--theirs", alpha], repo)
    if rc != 0:
        return Result("refusal", UNREADABLE,
                      "%s settling alpha failed: %s" % (TICKET, (err or out)[-300:]))
    rc, out, err = suite.kin_run(["resolve", "--ours", beta], repo)
    if rc != 0:
        return Result("refusal", UNREADABLE,
                      "%s settling beta failed: %s" % (TICKET, (err or out)[-300:]))
    rc, out, err = suite.kin_run(["resolve", "--all-ours"], repo)
    if rc != 0:
        return Result("refusal", UNREADABLE,
                      "%s the bulk settle failed: %s" % (TICKET, (err or out)[-300:]))
    rc, out, err = suite.kin_run(["resolve", "--continue"], repo)
    if rc == 0:
        return Result("refusal", FAIL,
                      "%s two contradictory settlements published anyway, with %r on disk"
                      % (TICKET, suite.read_bytes(repo, "src/lib.rs")))
    verdicts = [
        ("named", grade_refusal_names_both_decisions(err or out, "src/lib.rs",
                                                     ["alpha", "beta"])),
        ("head", grade_nothing_published(suite.kin_run(["log", "-n", "1"], repo)[1], before)),
    ]
    return _combine("refusal", verdicts)


def check_uniform(suite):
    """The control. A rule that refused every mixed merge, or took theirs
    always, would satisfy the three checks above and lose nothing else."""
    repo = suite.repo("uniform", MIXED_FILES)
    suite.kin_run(["merge", "feature"], repo)
    rc, out, err = suite.kin_run(["resolve", "--all-theirs"], repo)
    if rc != 0:
        return Result("uniform", UNREADABLE,
                      "%s the uniform settle failed: %s" % (TICKET, (err or out)[-300:]))
    rc, out, err = suite.kin_run(["resolve", "--continue"], repo)
    if rc != 0:
        return Result("uniform", FAIL,
                      "%s an ordinary uniform merge no longer publishes: %s"
                      % (TICKET, (err or out)[-300:]))
    verdicts = [
        ("lib", grade_bytes(suite.read_bytes(repo, "src/lib.rs"), THEIRS_LIB, "src/lib.rs")),
        ("shared", grade_bytes(suite.read_bytes(repo, "shared.txt"), THEIRS_SHARED,
                               "shared.txt")),
        ("tree", grade_merge_moved_the_tree(suite.kin_run(["log", "-n", "1"], repo)[1])),
    ]
    return _combine("uniform", verdicts)


ROW_ENTITY_CHANGED = '{"subject": {"subject": "entity"}, "divergence": {"divergence": "changed_both_sides"}}'
ROW_ARTIFACT_CHANGED = '{"subject": {"subject": "artifact"}, "divergence": {"divergence": "changed_both_sides"}}'
ROW_RELATION_DANGLING = '{"subject": {"subject": "relation"}, "divergence": {"divergence": "dangling_endpoint"}}'
ROW_RELATION_CHANGED = '{"subject": {"subject": "relation"}, "divergence": {"divergence": "changed_both_sides"}}'

def dangling_rows(conflicts_json_text):
    """Every parked conflict row whose divergence is a stranded endpoint.

    Returns None when the listing cannot be read or names no parked merge,
    because "no rows describing a removal" and "no merge at all" are the same
    empty list and only one of them is the property being graded.
    """
    if not isinstance(conflicts_json_text, str) or not conflicts_json_text.strip():
        return None
    try:
        payload = json.loads(conflicts_json_text)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    record = payload.get("record")
    if not isinstance(record, dict):
        return None
    entries = record.get("entries")
    if not isinstance(entries, list) or not entries:
        return None
    rows = []
    for entry in entries:
        divergence = (entry or {}).get("divergence")
        if isinstance(divergence, dict) and divergence.get("divergence") == "dangling_endpoint":
            rows.append(entry)
    return rows


def grade_no_false_removals(conflicts_json_text):
    """rc062j (2). One changed function must strand nothing.

    Every identity in this fixture survives whichever side settles, so a row
    saying one branch removed something is false on its face.
    """
    rows = dangling_rows(conflicts_json_text)
    if rows is None:
        return (UNREADABLE, "no readable parked merge to count rows in")
    if rows:
        return (FAIL, "%d row(s) describe a removal neither branch performed" % len(rows))
    return (PASS, "no row describes a removal neither branch performed")


def grade_reports_a_genuine_removal(conflicts_json_text):
    """The control. A real removal the other side still points at must be named."""
    rows = dangling_rows(conflicts_json_text)
    if rows is None:
        return (UNREADABLE, "no readable parked merge to count rows in")
    if not rows:
        return (FAIL, "a genuine stranded endpoint went unreported")
    return (PASS, "%d genuine stranded endpoint row(s) reported" % len(rows))


def grade_conflict_kinds(conflicts_json_text, forbidden):
    """The kinds of subject the parked listing names, and whether `forbidden`
    is among them. Read beside the row count so "zero removal rows" and "zero
    relation rows of any kind" stay distinguishable."""
    if not isinstance(conflicts_json_text, str) or not conflicts_json_text.strip():
        return (UNREADABLE, "no listing to read subject kinds from")
    try:
        payload = json.loads(conflicts_json_text)
        entries = (payload.get("record") or {}).get("entries") or []
    except (ValueError, AttributeError):
        return (UNREADABLE, "the listing did not parse")
    if not entries:
        return (UNREADABLE, "the listing names no parked merge")
    kinds = {}
    for entry in entries:
        kind = ((entry or {}).get("subject") or {}).get("subject")
        kinds[kind] = kinds.get(kind, 0) + 1
    if forbidden in kinds:
        return (FAIL, "the listing still carries %d %s row(s): %s"
                % (kinds[forbidden], forbidden, kinds))
    return (PASS, "subject kinds are %s" % kinds)


def check_removals(suite):
    """rc062j (2). One changed function, and no row claiming a removal.

    Measured before the fix on this exact fixture: 22 rows, of which 18 said one
    branch removed an identity the other still relates to, and every one of those
    identities is present on both sides.
    """
    repo = suite.repo("granularity", GRAN_FILES)
    suite.kin_run(["merge", "feature"], repo)
    listing = suite.kin_run(["conflicts", "--json"], repo)[1]
    return _combine("removals", [
        ("rows", grade_no_false_removals(listing)),
        ("kinds", grade_conflict_kinds(listing, "relation")),
    ], ticket=GRANULARITY_TICKET)


def check_genuine(suite):
    """The control for `removals`. A real removal must still be reported."""
    repo = suite.repo("genuine", GENUINE_FILES)
    suite.kin_run(["merge", "feature"], repo)
    listing = suite.kin_run(["conflicts", "--json"], repo)[1]
    return _combine("genuine", [
        ("rows", grade_reports_a_genuine_removal(listing)),
    ], ticket=GRANULARITY_TICKET)


def _combine(ident, verdicts, ticket=None):
    """Report every arm, never the first bad one, because knowing which arm
    broke is the whole value of grading several claims in one check.

    `ticket` defaults to this suite's own, and the granularity checks pass
    their own, so a detail line never cites a ticket the row is not about.
    """
    ticket = ticket or TICKET
    detail = "; ".join("%s %s %s" % (name, status, note) for name, (status, note) in verdicts)
    if any(status == FAIL for _, (status, _) in verdicts):
        return Result(ident, FAIL, detail, ticket=ticket)
    if any(status == UNREADABLE for _, (status, _) in verdicts):
        return Result(ident, UNREADABLE, detail, ticket=ticket)
    return Result(ident, PASS, detail, ticket=ticket)


# Ordered, and the order is load bearing: `precedence` publishes the merge
# `bulk` reads back.
CHECKS = [
    ("precedence", check_precedence),
    ("bulk", check_bulk),
    ("refusal", check_refusal),
    ("uniform", check_uniform),
    ("removals", check_removals),
    ("genuine", check_genuine),
]


# -- self-test fixtures ----------------------------------------------------
#
# One fixture per assertion. Two assertions that can both catch one input hide
# each other's absence, so every fixture below is caught by exactly one, and
# deleting that assertion is the only thing that turns this self-test red.

MERGE_LOG_MOVED = (
    "change 5f3cd725aa\n"
    "Author: repro <repro@example.invalid>\n"
    "Parents: 37b6e37b81 3b1d3eeeb7\n"
    "Deltas: entities=1 relations=0 tree=1 policy=false\n"
)
MERGE_LOG_TREE_ZERO = (
    "change 5f3cd725aa\n"
    "Parents: 37b6e37b81 3b1d3eeeb7\n"
    "Deltas: entities=1 relations=0 tree=0 policy=false\n"
)
# One parent, so the deltas are an ordinary change's and say nothing here. Only
# the parent-count arm can catch this.
LOG_NOT_A_MERGE = (
    "change 5f3cd725aa\n"
    "Parents: 37b6e37b81\n"
    "Deltas: entities=1 relations=0 tree=1 policy=false\n"
)
# Two parents and a Deltas line with no tree field, which only the missing-field
# arm can catch.
MERGE_LOG_NO_TREE = (
    "change 5f3cd725aa\n"
    "Parents: 37b6e37b81 3b1d3eeeb7\n"
    "Deltas: entities=1 relations=0 policy=false\n"
)
LOG_NO_DELTAS = "change 5f3cd725aa\nParents: 37b6e37b81 3b1d3eeeb7\n"

REFUSAL_FULL = (
    "Error: the recorded resolutions disagree about src/lib.rs: entity alpha (0ce7fbfa) was "
    "settled `--theirs`, entity beta (899c1130) was settled `--ours`, and artifact src/lib.rs "
    "(ce183603) was settled `--ours`, whose bytes do not carry 1 decision(s)"
)
# Names both decisions and never names the file, which only the path arm catches.
REFUSAL_NO_PATH = (
    "Error: the recorded resolutions disagree: entity alpha was settled `--theirs`, entity beta "
    "was settled `--ours`"
)
# Names the file and both flags and neither entity, which only the entity arm catches.
REFUSAL_NO_ENTITY = (
    "Error: the recorded resolutions disagree about src/lib.rs: something was settled "
    "`--theirs` and something else was settled `--ours`"
)
# Names the file and both entities and only one flag, which only the flag arm catches.
REFUSAL_NO_FLAGS = (
    "Error: the recorded resolutions disagree about src/lib.rs: alpha and beta were settled "
    "to opposite sides, one of them `--ours`"
)


def report_payload(results):
    """The report shape `scripts/acceptance/gate.py` reads.

    The key is `results` and not `checks`. That is not a style choice: the gate
    calls `payload.get("results")` and refuses anything else with "carries no
    results list". Two sibling suites shipped keyed `checks`, printed green CHECK
    lines, and produced a verdict the gate could not read. The self-test drives
    the gate's own loader over this payload rather than a copy of its rules.
    """
    return {"suite": "merge_precedence", "ticket": TICKET,
            "results": [{"id": r.ident, "ticket": r.ticket, "status": r.status,
                         "detail": r.detail} for r in results]}


def absolute_binary(path):
    """A binary path the fixtures can still find after they change directory.

    Every check runs the binary with `cwd=` a fixture repository, so a relative
    `--kin target/release/kin` resolves against that fixture rather than the
    caller's directory, and raises `[Errno 2] No such file or directory`. The
    workflow passes exactly that relative path.
    """
    return path and os.path.abspath(os.path.expanduser(path))


def self_test():
    graded = []
    failures = []

    def expect(label, got, want):
        graded.append(label)
        status = got[0]
        if status != want:
            failures.append("%s: wanted %s got %s (%s)" % (label, want, status, got[1]))

    expect("tree passes a merge that moved the tree",
           grade_merge_moved_the_tree(MERGE_LOG_MOVED), PASS)
    expect("tree fails the shipped tree=0 signature",
           grade_merge_moved_the_tree(MERGE_LOG_TREE_ZERO), FAIL)
    expect("tree cannot read a one-parent change",
           grade_merge_moved_the_tree(LOG_NOT_A_MERGE), UNREADABLE)
    expect("tree cannot read a Deltas line with no tree field",
           grade_merge_moved_the_tree(MERGE_LOG_NO_TREE), UNREADABLE)
    expect("tree cannot read a log with no Deltas line",
           grade_merge_moved_the_tree(LOG_NO_DELTAS), UNREADABLE)
    expect("tree cannot read something that is not a log",
           grade_merge_moved_the_tree("nope"), UNREADABLE)

    expect("bytes pass the body the decisions chose",
           grade_bytes(THEIRS_LIB, THEIRS_LIB, "src/lib.rs"), PASS)
    expect("bytes fail the body the decisions rejected",
           grade_bytes(OURS_LIB, THEIRS_LIB, "src/lib.rs"), FAIL)
    expect("bytes cannot read a file that is not there",
           grade_bytes(None, THEIRS_LIB, "src/lib.rs"), UNREADABLE)

    expect("refusal passes text naming the file and both decisions",
           grade_refusal_names_both_decisions(REFUSAL_FULL, "src/lib.rs", ["alpha", "beta"]),
           PASS)
    expect("refusal fails text that names no file",
           grade_refusal_names_both_decisions(REFUSAL_NO_PATH, "src/lib.rs", ["alpha", "beta"]),
           FAIL)
    expect("refusal fails text that names neither entity",
           grade_refusal_names_both_decisions(REFUSAL_NO_ENTITY, "src/lib.rs", ["alpha", "beta"]),
           FAIL)
    expect("refusal fails text that names only one side",
           grade_refusal_names_both_decisions(REFUSAL_NO_FLAGS, "src/lib.rs", ["alpha", "beta"]),
           FAIL)
    expect("refusal cannot read an empty stderr",
           grade_refusal_names_both_decisions("", "src/lib.rs", ["alpha"]), UNREADABLE)

    expect("head passes a branch that did not move",
           grade_nothing_published("change 37b6e37b81\n", "37b6e37b81"), PASS)
    expect("head fails a branch the refusal advanced",
           grade_nothing_published("change 5f3cd725aa\n", "37b6e37b81"), FAIL)
    expect("head cannot read something that is not a log",
           grade_nothing_published("nope", "37b6e37b81"), UNREADABLE)

    # The report shape, driven through the gate's own reader rather than through
    # a copy of its rules. A suite that runs, grades, prints green CHECK lines
    # and writes a report the gate cannot read has not passed.
    import importlib.util

    gate_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gate.py")
    if not os.path.exists(gate_path):
        failures.append("gate.py is not beside this file, so the report shape went unchecked")
    else:
        spec = importlib.util.spec_from_file_location("acceptance_gate", gate_path)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        scratch = tempfile.mkdtemp(prefix="merge-precedence-selftest-")
        try:
            rows = [Result(ident, UNREADABLE, "%s check raised: fabricated" % TICKET)
                    for ident, _ in CHECKS]
            good = os.path.join(scratch, "good.json")
            with open(good, "w") as handle:
                json.dump(report_payload(rows), handle)
            try:
                loaded = gate.load_report(good)
                expect("the gate reads every row this suite writes",
                       (sorted(loaded), "loaded"), sorted(ident for ident, _ in CHECKS))
                expect("the gate reads a status off each row",
                       (loaded[CHECKS[0][0]].get("status"), "row status"), UNREADABLE)
            except Exception as exc:  # noqa: BLE001 - a refusal is the finding
                failures.append("the gate refused this suite's own report: %s" % exc)

            # CONTROL: the shape that broke CI twice must still be refused, or
            # the two assertions above would pass over any payload at all.
            bad = os.path.join(scratch, "bad.json")
            with open(bad, "w") as handle:
                json.dump({"suite": "merge_precedence", "ticket": TICKET,
                           "checks": [{"id": ident, "status": UNREADABLE}
                                      for ident, _ in CHECKS]}, handle)
            try:
                gate.load_report(bad)
                refused = False
            except Exception:  # noqa: BLE001 - the refusal is what is wanted
                refused = True
            expect("CONTROL the gate still refuses the `checks`-keyed shape that broke CI",
                   (refused, "refused"), True)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    # rc062j (2). Every granularity grader gets an input that must pass and one
    # that must fail, so a grader that answers PASS over anything is caught here
    # rather than in CI with no binary to blame.
    clean = '{"record": {"entries": [%s, %s]}}' % (
        ROW_ENTITY_CHANGED, ROW_ARTIFACT_CHANGED)
    stranded = '{"record": {"entries": [%s, %s]}}' % (
        ROW_ENTITY_CHANGED, ROW_RELATION_DANGLING)
    expect("removals passes a listing with no stranded row",
           grade_no_false_removals(clean), PASS)
    expect("removals fails the shipped listing carrying stranded rows",
           grade_no_false_removals(stranded), FAIL)
    expect("removals cannot read an empty listing",
           grade_no_false_removals(""), UNREADABLE)
    expect("removals cannot read a listing with no parked merge",
           grade_no_false_removals('{"record": {"entries": []}}'), UNREADABLE)
    expect("removals cannot read text that is not json",
           grade_no_false_removals("nope"), UNREADABLE)

    expect("genuine passes a listing that reports a real stranded endpoint",
           grade_reports_a_genuine_removal(stranded), PASS)
    expect("genuine fails a listing that reports none",
           grade_reports_a_genuine_removal(clean), FAIL)
    expect("genuine cannot read an empty listing",
           grade_reports_a_genuine_removal(""), UNREADABLE)

    expect("kinds passes a listing carrying no relation row",
           grade_conflict_kinds(clean, "relation"), PASS)
    expect("kinds fails a listing that still carries one",
           grade_conflict_kinds(stranded, "relation"), FAIL)
    expect("kinds cannot read a listing with no parked merge",
           grade_conflict_kinds('{"record": {"entries": []}}', "relation"), UNREADABLE)
    # CONTROL: the two graders must not be the same reading. A relation row that
    # is NOT a stranded endpoint is fine by `removals` and named by `kinds`.
    plain_relation = '{"record": {"entries": [%s]}}' % ROW_RELATION_CHANGED
    expect("CONTROL removals accepts a relation row that strands nothing",
           grade_no_false_removals(plain_relation), PASS)
    expect("CONTROL kinds still names that same relation row",
           grade_conflict_kinds(plain_relation, "relation"), FAIL)

    expect("a relative kin path is absolutized by this suite",
           (os.path.isabs(absolute_binary("target/release/kin")), "isabs"), True)
    expect("and an absent binary stays absent rather than becoming the cwd",
           (absolute_binary(None), "absent"), None)

    for line in failures:
        print("SELFTEST FAIL %s" % line)
    # Counted, never written out. A hardcoded total drifts from the assertions
    # it claims to describe, and it drifts silently downward.
    print("self-test: %d grader assertions, %d failed" % (len(graded), len(failures)))
    if len(graded) != len(set(graded)):
        print("SELFTEST FAIL duplicate assertion labels, so one shadowed another")
        return 1
    if not graded:
        print("SELFTEST FAIL no grader assertion ran")
        return 1
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
    if not opts.daemon:
        beside = os.path.join(os.path.dirname(opts.kin), "kin-daemon")
        if os.path.isfile(beside) and os.access(beside, os.X_OK):
            opts.daemon = beside

    workdir = tempfile.mkdtemp(prefix="merge-precedence-")
    suite = Suite(opts.kin, workdir, daemon=opts.daemon, verbose=opts.verbose)
    try:
        results = []
        for ident, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a setup failure is not a verdict
                results.append(Result(ident, UNREADABLE, "%s check raised: %s" % (TICKET, error)))
        for result in results:
            print("CHECK %s %s %s %s" % (result.ident, result.ticket, result.status,
                                         result.detail))
        asked = [ident for ident, _ in CHECKS]
        answered = [result.ident for result in results]
        # Written before the asked/answered guard below, not after it. Four
        # UNREADABLE rows are a verdict the gate can name; a missing report is
        # one it can only refuse.
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
        for repo in suite._repos.values():
            try:
                run([opts.kin, "daemon", "stop"], cwd=repo, env=suite.env, timeout=180)
            except Exception:  # noqa: BLE001 - teardown must not change the verdict
                pass
        if not opts.keep:
            shutil.rmtree(workdir, ignore_errors=True)
        else:
            print("kept fixtures under %s" % workdir)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
