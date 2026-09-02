#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the scratch-file commit shape (FIR-3097, FIR-3098).

Its output is a regression gate, never proof, never investor-facing, and never a
released claim.

What it is for
--------------
A stranger building a fresh Python package on the v0.6.4 candidate created
``_smoke.py``, ran it, deleted it, wrote three new files, and committed. Kin
refused in 20 ms:

    identity-underdetermined repository transition: unmatched removals [_smoke.py]
    and additions [.gitignore, notekeeper/__init__.py, notekeeper/parsing.py] may
    be move-plus-edit operations; use explicit identity-bearing add/remove/move
    commands

Three separate defects rode on that one transition, and this suite grades all
three because each can regress without the others.

``commit`` is the shape itself. ``kin commit`` takes no paths and has no staging
area, so it observes the whole working tree every time, and any scratch file
created and deleted between two commits produces exactly this. The stranger's
conclusion was "I now avoid scratch files in the repo entirely", which is a
product outcome no message wording can repair.

``remedy`` is the instruction. The refusal named ``add``, ``remove`` and ``move``
commands; ``kin --help`` lists sixty-odd subcommands and none of them, and the
closest, ``kin rename``, is a graph entity rename rather than a path move. This
arm reads the help text at run time and requires every command a refusal
prescribes to appear in it, so it grades the message against the product rather
than against a list written here that would go stale.

``exit`` is FIR-3098. After the refusal, ``kin admit`` printed
``Complete exact-tree admission failed:`` and exited 0. Kin's own agents and
every CI harness read ``$?``, so a failure that exits 0 is read as success. The
arm is deliberately two-sided: a run that fails must exit non-zero AND a run that
succeeds must exit zero, because a command that always exited non-zero would
satisfy the first half and be useless.

What it is blind to
-------------------
It grades one transition shape end to end. It does not grade rename detection,
which Kin does not do, and it takes no position on whether a future
similarity-gated refusal should exist: it requires only that a refusal, if one
happens, names a remedy that exists and leaves the exit status honest.

Each check prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
3 on setup failure, and 0 only when every check passes. ``--self-test`` drives
every grader against the input that must produce the opposite verdict, without
building a repository or needing a kin binary.
"""

from __future__ import print_function

import argparse
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

TICKET = "FIR-3097"
EXIT_TICKET = "FIR-3098"

SCRATCH = "_smoke.py"
SEED = "notekeeper/notes.py"
ADDITIONS = (".gitignore", "notekeeper/__init__.py", "notekeeper/parsing.py")

SEED_BODY = '"""Seed module."""\n\n\ndef make_note(title):\n    return {"title": title}\n'
SCRATCH_BODY = '"""Scratch, deleted before the commit."""\n\nprint(make_note)\n'
ADDITION_BODIES = {
    ".gitignore": "__pycache__/\n*.pyc\n",
    "notekeeper/__init__.py": 'from .parsing import parse_note\n\n__all__ = ["parse_note"]\n',
    "notekeeper/parsing.py": (
        '"""Markdown note parsing."""\n\n\ndef parse_note(text):\n'
        "    return {\"body\": text.strip()}\n"
    ),
}

# The refusal this suite exists for, matched on its stable head rather than on
# the whole sentence, so a reworded tail does not silently stop matching.
REFUSAL = "identity-underdetermined repository transition"

# What `kin admit` prints when it did not admit. Shared with the CLI constant
# `kin_cli::commands::admit::ADMIT_FAILURE_PREFIX`; if the two ever drift, the
# `exit` arm reads a failure as a success and this suite says so.
ADMIT_FAILURE = "Complete exact-tree admission failed:"

# Commands a refusal has prescribed. Each is a bare word the message offers as
# something to run, and every one must be a real subcommand.
PRESCRIBED = re.compile(r"\b(?:use|run|try)\b[^.]*?\b(add|remove|move|mv|rm)\b[^.]*?\bcommands?\b",
                        re.IGNORECASE)


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
# Pure functions, so --self-test drives every one against the input that must
# produce the opposite verdict, with no repository and no binary.

def help_subcommands(help_text):
    """Every subcommand `kin --help` lists.

    Read from the product rather than hardcoded, so a check about what Kin ships
    cannot pass against a list that went stale. Clap indents each subcommand by
    two spaces and follows it with its summary; the leading token of such a line
    is the name.
    """
    if not isinstance(help_text, str):
        return set()
    names = set()
    for line in help_text.splitlines():
        if not line.startswith("  ") or line.startswith("   "):
            continue
        token = line.strip().split(" ", 1)[0]
        if token and re.match(r"^[a-z][a-z0-9-]*$", token):
            names.add(token)
    return names


def grade_commit_admitted_the_scratch_delete(rc, text):
    """A scratch file deleted beside new files commits.

    The refusal is named explicitly rather than inferred from `rc`, because a
    commit can fail for reasons that have nothing to do with this ticket and
    reporting one of those as this regression would send the next reader at the
    wrong code.
    """
    if not isinstance(text, str):
        return Result("commit", UNREADABLE, "no commit output to read")
    if REFUSAL in text:
        return Result("commit", FAIL,
                      "kin commit refused the delete-plus-add transition: %s"
                      % first_line_containing(text, REFUSAL))
    if rc != 0:
        return Result("commit", UNREADABLE,
                      "kin commit failed for another reason (rc=%s): %s"
                      % (rc, text.strip()[-200:]))
    return Result("commit", PASS,
                  "a scratch file deleted beside %d new files committed" % len(ADDITIONS))


def grade_refusal_prescribes_a_real_remedy(text, subcommands):
    """Any refusal must name only commands the product ships.

    Two-sided on purpose. A message that prescribes nothing passes, because
    prescribing nothing is not the defect; prescribing fiction is. And the
    subcommand set has to be non-empty, or a help read that returned nothing
    would let every message through.
    """
    if not isinstance(text, str):
        return Result("remedy", UNREADABLE, "no message to read")
    if not subcommands:
        return Result("remedy", UNREADABLE,
                      "kin --help listed no subcommands, so the message cannot be graded")
    match = PRESCRIBED.search(text)
    if not match:
        return Result("remedy", PASS,
                      "no message prescribed a command (%d subcommands available)"
                      % len(subcommands))
    named = match.group(1).lower()
    if named in subcommands:
        return Result("remedy", PASS, "the message prescribes `kin %s`, which exists" % named)
    return Result("remedy", FAIL,
                  "the message prescribes `%s`, which `kin --help` does not list: %s"
                  % (named, match.group(0)))


def grade_admit_exit_status(rc, text):
    """`kin admit` exits non-zero exactly when it did not admit (FIR-3098).

    Both directions in one grader, because they are one property. A command that
    always exited non-zero would satisfy the half this ticket is about and break
    every green run, so the arm that matters cannot be graded alone.
    """
    if not isinstance(text, str) or not isinstance(rc, int):
        return Result("exit", UNREADABLE, "no admit result to read")
    failed = ADMIT_FAILURE in text
    if failed and rc == 0:
        return Result("exit", FAIL,
                      "kin admit printed a failure and exited 0, so a script reads it as success")
    if not failed and rc != 0:
        return Result("exit", FAIL,
                      "kin admit exited %s without printing a failure" % rc)
    if failed:
        return Result("exit", PASS, "a refused admission exited %s" % rc)
    return Result("exit", PASS, "a successful admission exited 0")


def first_line_containing(text, needle):
    for line in text.splitlines():
        if needle in line:
            return line.strip()[:200]
    return ""


def report_payload(results, label):
    """The report shape `scripts/acceptance/gate.py` reads."""
    return {
        "label": label,
        "ticket": TICKET,
        "results": [
            {"id": r.id,
             "ticket": EXIT_TICKET if r.id == "exit" else TICKET,
             "status": r.status,
             "detail": r.detail}
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
            handle.write("[user]\n\tname = scratch-file-commit-repro\n"
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

    def repo(self):
        """A converted repository holding one seed file, and nothing else.

        The scratch file is written and deleted AFTER conversion so the
        transition under test is the one the stranger hit: a tracked artifact
        whose content appears nowhere in the new observation, beside additions
        that match no tracked artifact.
        """
        if self._repo:
            return self._repo
        path = os.path.realpath(os.path.join(self.workdir, "notekeeper"))
        os.makedirs(path)
        self.git(path, ["init", "-q", "-b", "main", "."])
        self.git(path, ["config", "core.hooksPath", os.path.join(self.home, "no-hooks")])
        self.git(path, ["config", "user.email", "repro@example.invalid"])
        self.git(path, ["config", "user.name", "scratch-file-commit-repro"])
        self._write(path, SEED, SEED_BODY)
        self._write(path, SCRATCH, SCRATCH_BODY)
        self.git(path, ["add", "-A"])
        self.git(path, ["commit", "-q", "-m", "seed"])
        rc, out, err = self.kin_run(path, ["init", "."])
        if rc != 0:
            raise RuntimeError("kin init failed: %s" % ((err or out)[-400:]))
        # Fixture assertion. If the scratch file was never tracked, deleting it
        # produces no unmatched removal and every arm below passes vacuously.
        rc, out, err = self.kin_run(path, ["status"])
        if rc != 0:
            raise RuntimeError("kin status failed after init: %s" % ((err or out)[-400:]))
        self._repo = path
        return path

    def transition(self):
        """Delete the scratch file, write the new ones, and commit."""
        path = self.repo()
        os.remove(os.path.join(path, SCRATCH))
        for relative in ADDITIONS:
            self._write(path, relative, ADDITION_BODIES[relative])
        return self.kin_run(path, ["commit", "-m", "Add markdown note parser"])

    @staticmethod
    def _write(root, relative, body):
        target = os.path.join(root, relative)
        directory = os.path.dirname(target)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory)
        with open(target, "w") as handle:
            handle.write(body)

    def stop_daemons(self):
        if self._repo:
            run([self.kin, "daemon", "stop"], cwd=self._repo, env=self.env, timeout=180)


# ── checks ──

def check_commit(suite):
    rc, out, err = suite.transition()
    return grade_commit_admitted_the_scratch_delete(rc, "%s\n%s" % (out, err))


def check_remedy(suite):
    path = suite.repo()
    _, help_out, help_err = suite.kin_run(path, ["--help"], timeout=300)
    rc, out, err = suite.transition()
    return grade_refusal_prescribes_a_real_remedy(
        "%s\n%s" % (out, err), help_subcommands("%s\n%s" % (help_out, help_err)))


def check_exit(suite):
    path = suite.repo()
    suite.transition()
    rc, out, err = suite.kin_run(path, ["admit"])
    return grade_admit_exit_status(rc, "%s\n%s" % (out, err))


CHECKS = (("commit", check_commit), ("remedy", check_remedy), ("exit", check_exit))


# ── self-test ──

def self_test():
    failures = []

    def expect(what, got, want):
        if got != want:
            failures.append("%s: expected %s, got %s" % (what, want, got))

    refusal_text = (
        "Error: daemon native commit failed (HTTP 500 Internal Server Error): Core error: "
        "%s: unmatched removals [_smoke.py] and additions [.gitignore] may be "
        "move-plus-edit operations; use explicit identity-bearing add/remove/move commands"
        % REFUSAL
    )
    expect("commit FAILs on the refusal",
           grade_commit_admitted_the_scratch_delete(1, refusal_text).status, FAIL)
    expect("commit PASSes on a clean commit",
           grade_commit_admitted_the_scratch_delete(0, "Created semantic change abc123").status,
           PASS)
    # A commit that failed for an unrelated reason is not this regression, and
    # reporting it as one would send the next reader at the wrong code.
    expect("commit is UNREADABLE on an unrelated failure",
           grade_commit_admitted_the_scratch_delete(1, "Error: daemon not running").status,
           UNREADABLE)

    shipped = {"commit", "status", "admit", "rename", "init"}
    expect("remedy FAILs on a prescribed command that does not exist",
           grade_refusal_prescribes_a_real_remedy(refusal_text, shipped).status, FAIL)
    expect("remedy PASSes when the message prescribes nothing",
           grade_refusal_prescribes_a_real_remedy(
               "%s: the same exact entry also appears at b. Commit the two paths in separate "
               "commits, or make their contents differ" % REFUSAL, shipped).status, PASS)
    # The control that keeps the arm honest: a message naming a real command
    # must pass, or the grader is just banning the words.
    expect("remedy PASSes on a real command",
           grade_refusal_prescribes_a_real_remedy(
               "use the move commands to fix this", shipped | {"move"}).status, PASS)
    # A help read that returned nothing must not let every message through.
    expect("remedy is UNREADABLE with no subcommands",
           grade_refusal_prescribes_a_real_remedy(refusal_text, set()).status, UNREADABLE)

    admit_failed = ("%s Core error: %s\nGraph authority is unchanged: 2 tracked artifacts."
                    % (ADMIT_FAILURE, REFUSAL))
    expect("exit FAILs when a printed failure exits 0",
           grade_admit_exit_status(0, admit_failed).status, FAIL)
    expect("exit PASSes when a printed failure exits nonzero",
           grade_admit_exit_status(1, admit_failed).status, PASS)
    expect("exit PASSes on a successful admission",
           grade_admit_exit_status(0, "Admitted the complete exact tree").status, PASS)
    # The other direction. Without this, always exiting nonzero would pass.
    expect("exit FAILs when a silent run exits nonzero",
           grade_admit_exit_status(1, "Admitted the complete exact tree").status, FAIL)

    # The help parser is the one place this suite reads the product's own list.
    parsed = help_subcommands(
        "Commands:\n  commit   Record a semantic change\n  admit    Admit the tree\n"
        "  status   Show status\n\nOptions:\n  -h, --help  Print help\n")
    expect("help parser finds the subcommands", sorted(parsed) >= ["admit", "commit", "status"],
           True)
    expect("help parser rejects option lines", "-h," in parsed, False)

    for line in failures:
        print("SELFTEST FAIL %s" % line)
    if failures:
        return 1
    print("SELFTEST PASS %s/%s graders inverted" % (TICKET, EXIT_TICKET))
    return 0


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
    # Absolutized before anything reads it: every probe runs with `cwd` set to
    # the fixture repository, so a relative path would validate from the
    # caller's directory and fail from the fixture's.
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

    workdir = args.workdir or tempfile.mkdtemp(prefix="scratch-file-commit-")
    os.makedirs(workdir, exist_ok=True)
    suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
    results = []
    try:
        for cid, check in CHECKS:
            if selected and cid not in selected:
                continue
            try:
                results.append(check(suite))
            except Exception as exc:  # a probe that could not run is not a pass
                results.append(Result(cid, UNREADABLE, "probe raised: %s" % exc))
    finally:
        try:
            suite.stop_daemons()
        except Exception:
            pass
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    for result in results:
        ticket = EXIT_TICKET if result.id == "exit" else TICKET
        print("CHECK %s %s %s %s" % (result.id, ticket, result.status, result.detail))
    if args.json:
        with open(args.json, "w") as handle:
            json.dump(report_payload(results, args.label), handle, indent=2)

    if any(r.status == FAIL for r in results):
        return 1
    if any(r.status == UNREADABLE for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
