#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for the eject archive round trip (FIR-2664).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
The rc0552n green stranger ran `kin eject` on 0.5.52, copied the archived
`kin/` back to `.kin` with `cp -r`, and lost `kin commit` for good: every
attempt answered `daemon native commit failed (HTTP 500 Internal Server
Error): Core error: exact eject journal ... has an invalid identity-bound
descriptor`. A finished eject had left its journal behind in the archived
`.kin` at the detach phase, the copy carried it along under fresh inodes, and
every projection open after that refused. The only exit the stranger found was
`rm -rf .kin/`. Then `kin init` refused the ejected repository over
`.git/hooks/docs.url`, a 34-byte URL gitoxide's init template writes and Git
never runs, which `kin eject` itself had put there.

Seven checks, each with its own control:

  archive   a finished eject leaves no journal in the archived `kin/`, while
            the same directory still carries the authority key
  copyback  `cp -R` of the archived `kin/` back to `.kin` commits again
  carried   a journal shaped exactly as 0.5.52 left it, planted into the
            archive and carried back by the copy, is retired on the next
            commit rather than refused
  refusal   a journal bound to nothing this store can verify is refused with
            the file and the remedy named, never as an HTTP 500, and the same
            store commits once the file is gone
  hook      `kin init` re-admits the ejected repository with gitoxide's
            `docs.url` in place, and still refuses an executable `pre-commit`
  author    a native commit is stamped with the repository's own Git identity
            at REPOSITORY scope, read back out of Git rather than written here,
            and a repository where no identity resolves refuses instead of
            inventing one
  author_global
            the same stamp when the only identity that exists is at GLOBAL
            scope, which is the scope the report that started this came from,
            with a local read asserted empty so the arm cannot quietly become a
            second repository-scope test

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (a fixture that never built, an eject
that printed no archive path, a crashed probe). Exit status is 1 when any check
FAILs, 2 when none fail but some are UNREADABLE, 0 only when every check passes,
3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/eject_journal_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script. Eject is Unix-only, so this suite is.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2664"

JOURNAL = "reconciliation/exact-eject-journal.json"
AUTHORITY_KEY = "reconciliation/authority.key"
# The domain separator kin-core prefixes before HMAC-SHA256 with the store's
# 32-byte authority key. A journal authenticates only under the key of the
# store it sits in, which is why a crafted one has to be keyed per fixture.
JOURNAL_PREFIX = b"kin.exact-eject-journal.v1\x00"
# The field order kin-core serializes, captured from the journal a 0.5.52 eject
# left in the rc0552n archive. serde re-encodes the struct in this order before
# checking the HMAC, so a crafted journal must encode in it too.
JOURNAL_FIELDS = (
    "schema", "transaction_id", "phase", "root_identity", "kin_control_identity",
    "control_identity", "namespace_parent_identity", "root_name", "archive_name",
    "archive_identity", "stage_parent_components", "stage_parent_identity",
    "stage_name", "stage_identity", "stage_seal", "archived_kin_name",
    "archived_git_name", "previous_git",
)
DOCS_URL = "https://git-scm.com/docs/githooks\n"
SHIPPED_REFUSAL = (
    "daemon native commit failed (HTTP 500 Internal Server Error): Core error: exact "
    "eject journal /work/notekeeper/.kin/reconciliation/exact-eject-journal.json has an "
    "invalid identity-bound descriptor"
)


def tail(text, limit=400):
    """The END of a command's output, which is where its error is."""
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def error_lines(text, limit=700):
    """The lines that state an error, ahead of the tail.

    A refused kin command prints environment warnings on the way in and its
    `Error:` sentence on the way out, and which of the two a bounded tail keeps
    depends on their lengths. The sentence is what a reader needs, so it leads.
    """
    lines = [line.strip() for line in (text or "").splitlines()
             if "Error" in line or "error:" in line or "refused" in line]
    stated = " | ".join(lines)
    if not stated:
        return tail(text, limit)
    return stated if len(stated) <= limit else stated[:limit] + "..."


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout


class Result(object):
    def __init__(self, check_id, title):
        self.id = check_id
        self.title = title
        self.asserts = []

    def ok(self, detail):
        self.asserts.append({"status": PASS, "detail": detail})

    def bad(self, detail):
        self.asserts.append({"status": FAIL, "detail": detail})

    def unknown(self, detail):
        self.asserts.append({"status": UNREADABLE, "detail": detail})

    @property
    def status(self):
        graded = [a for a in self.asserts if a["status"] in (PASS, FAIL, UNREADABLE)]
        if any(a["status"] == FAIL for a in graded):
            return FAIL
        if any(a["status"] == UNREADABLE for a in graded):
            return UNREADABLE
        if not graded:
            return UNREADABLE
        return PASS

    @property
    def detail(self):
        for wanted in (FAIL, UNREADABLE):
            for a in self.asserts:
                if a["status"] == wanted:
                    return a["detail"]
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


# ------------------------------------------------------------------- graders

def commit_landed(rc, out):
    """Whether `kin commit` recorded a change: exit 0 and the sentence it prints."""
    return rc == 0 and "Created semantic change" in out


def refusal_is_worded(out, journal_paths):
    """Whether a refused commit names the journal and the way out, in words.

    The shipped 0.5.52 text fails every clause that matters: it carries the path
    but sends the reader to the daemon with `HTTP 500 Internal Server Error` and
    `Core error`, and names no remedy. A refusal passes only when it names one
    of the journal's paths (the daemon may print the canonical form), tells the
    reader to remove the file, offers `kin init` as the rebuild, and never
    mentions the transport.
    """
    return (
        any(path in out for path in journal_paths)
        and "remove the file" in out
        and "kin init" in out
        and "HTTP 500" not in out
        and "Internal Server Error" not in out
        and "Core error" not in out
    )


def init_refused_over(out, name):
    """Whether `kin init` refused the repository over a hook of this name."""
    return "admission blocker" in out and "Git hook" in out and name in out


def native_change_author(out):
    """The `Author:` of the newest native change in `kin log`, or None.

    Scoped to `Origin: native` on purpose. Imported changes carry the author Git
    recorded, so a grader that took the first `Author:` line it saw would read an
    imported one and pass while a native commit was stamped by anybody.
    """
    for block in re.split(r"^change ", out, flags=re.M)[1:]:
        if not re.search(r"^Origin: native", block, re.M):
            continue
        match = re.search(r"^Author: (.+)$", block, re.M)
        if match:
            return match.group(1).strip()
    return None


def identity_refusal_is_worded(out):
    """Whether a commit with no resolvable identity refused, and said how to fix it.

    Both remedies are required. Kin resolves a Git identity or a Kin-specific
    `default_author`, so a refusal naming only one leaves a reader who set the
    other with nothing to do.
    """
    return ("no author identity" in out
            and "git config --global user.name" in out
            and "git config --global user.email" in out
            and "default_author" in out)


GRADERS = {
    "commit_landed": commit_landed,
    "refusal_is_worded": refusal_is_worded,
    "init_refused_over": init_refused_over,
    "native_change_author": native_change_author,
    "identity_refusal_is_worded": identity_refusal_is_worded,
}


# ------------------------------------------------------------------ crafting

def identity(path):
    st = os.stat(path)
    return {"device": st.st_dev, "inode": st.st_ino}


NOWHERE = {"device": 0, "inode": 0}


def craft_journal(key, root, archive, archived_kin, bound=True):
    """An authenticated detach-phase journal in the shape 0.5.52 wrote.

    `bound=True` binds it to the directories an eject of `root` into `archive`
    would have recorded, with the archived `kin/` as the `.kin` it was written
    for: the shape a copy carries back. `bound=False` binds every identity to
    nothing, the shape nothing can verify.
    """
    parent = os.path.dirname(root)
    ident = identity if bound else (lambda _path: dict(NOWHERE))
    journal = {
        "schema": 1,
        "transaction_id": str(uuid.uuid4()),
        "phase": "detach_pending",
        "root_identity": ident(root),
        "kin_control_identity": ident(archived_kin),
        "control_identity": ident(os.path.join(archived_kin, "reconciliation")),
        "namespace_parent_identity": ident(parent),
        "root_name": list(os.fsencode(os.path.basename(root))),
        "archive_name": list(os.fsencode(os.path.basename(archive))),
        "archive_identity": ident(archive),
        "stage_parent_components": [list(b".kin-eject-git-stage.gone"), list(b"worktree")],
        "stage_parent_identity": dict(NOWHERE),
        "stage_name": list(b".git"),
        "stage_identity": ident(os.path.join(root, ".git")) if bound else dict(NOWHERE),
        "stage_seal": {"digest": [0] * 32, "entry_count": 0, "multiply_linked_files": 0},
        "archived_kin_name": list(b"kin"),
        "archived_git_name": list(b"previous-git"),
        "previous_git": None,
    }
    assert tuple(journal) == JOURNAL_FIELDS
    encoded = json.dumps(journal, separators=(",", ":")).encode()
    mac = hmac.new(key, JOURNAL_PREFIX + encoded, hashlib.sha256).digest()
    return json.dumps({"journal": journal, "authentication": list(mac)},
                      separators=(",", ":")).encode()


def plant_journal(kin_dir, body):
    path = os.path.join(kin_dir, JOURNAL)
    with open(path, "wb") as handle:
        handle.write(body)
    os.chmod(path, 0o600)
    return path


def journal_paths(repo):
    """Both spellings of the journal path a daemon might print."""
    return sorted({
        os.path.join(repo, ".kin", JOURNAL),
        os.path.join(os.path.realpath(repo), ".kin", JOURNAL),
    })


# ------------------------------------------------------------------- fixtures

class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.kin_home = os.path.join(workdir, "kin-home-%d" % os.getpid())
        os.makedirs(self.kin_home, exist_ok=True)
        self.env = dict(os.environ)
        # A scratch KIN_HOME keeps this run off the fleet's stores and the
        # auto-embed opt-out keeps it off the GPU.
        self.env["KIN_HOME"] = self.kin_home
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        self.env.pop("KIN_MCP_REPO", None)
        self.env.pop("KIN_DIR", None)
        if daemon:
            self.env["KIN_DAEMON_BIN"] = daemon
        self.repos = {}
        self.commits = 0

    def log(self, line):
        if self.verbose:
            print("  " + line, flush=True)

    def git(self, args, cwd):
        base = ["git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def kin_run(self, args, repo, timeout=600):
        rc, out = run([self.kin] + args, cwd=repo, env=self.env, timeout=timeout)
        self.log("kin %s -> %d" % (" ".join(args), rc))
        return rc, out

    def kin_commit(self, repo, title):
        """A fresh file and a `kin commit` recording it."""
        self.commits += 1
        with open(os.path.join(repo, "note%d.py" % self.commits), "w") as handle:
            handle.write("def note%d():\n    return %d\n" % (self.commits, self.commits))
        # A commit needs a daemon, and a repository that was just ejected or
        # re-attached has none running; `kin graph status` starts one.
        self.kin_run(["graph", "status"], repo)
        return self.kin_run(["commit", "-m", title], repo)

    def daemon_stop(self, repo):
        if os.path.isdir(os.path.join(repo, ".kin")):
            self.kin_run(["daemon", "stop"], repo)

    def fresh_repo(self, name):
        """A one-file Git repository admitted through `kin init`, plus one
        commit through kin so the store has a workspace generation of its own.
        """
        repo = os.path.join(self.workdir, "trees", name)
        os.makedirs(repo)
        rc, out = self.git(["init", "-q", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed: %s" % tail(out))
        # Persisted, not `-c`: `kin commit` resolves its author from the
        # repository's own configuration and refuses to invent one.
        self.git(["config", "user.email", "repro@example.invalid"], repo)
        self.git(["config", "user.name", "kin-eject-journal-repro"], repo)
        with open(os.path.join(repo, "app.py"), "w") as handle:
            handle.write("def hello():\n    return 'hi'\n")
        self.git(["add", "--all"], repo)
        rc, out = self.git(["commit", "-q", "-m", "a python module"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed: %s" % tail(out))
        rc, out = self.kin_run(["init"], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (repo, tail(out)))
        rc, out = self.kin_commit(repo, "a commit before eject")
        if not commit_landed(rc, out):
            raise RuntimeError("the control commit before eject did not land (rc=%d): %s"
                               % (rc, tail(out)))
        return repo

    def eject(self, repo):
        """`kin eject --yes`, returning the archive path it printed."""
        rc, out = self.kin_run(["eject", "--yes"], repo, timeout=900)
        if rc != 0:
            raise RuntimeError("kin eject failed (rc=%d): %s" % (rc, tail(out)))
        match = re.search(r"^Recoverable eject archive: (.+)$", out, re.M)
        if not match:
            raise RuntimeError("kin eject printed no archive path: %s" % tail(out))
        archive = match.group(1).strip()
        if not os.path.isdir(os.path.join(archive, "kin")):
            raise RuntimeError("the archive %s carries no kin/" % archive)
        if os.path.isdir(os.path.join(repo, ".kin")):
            raise RuntimeError("eject left .kin in place at %s" % repo)
        return archive

    def ejected(self, name):
        """A repository ejected once: (repo, archive)."""
        if name not in self.repos:
            repo = self.fresh_repo(name)
            self.repos[name] = (repo, self.eject(repo))
        return self.repos[name]


def copy_back(archive, repo):
    """`cp -R <archive>/kin <repo>/.kin`, the stranger's own re-attach."""
    rc, out = run(["cp", "-R", os.path.join(archive, "kin"), os.path.join(repo, ".kin")])
    if rc != 0:
        raise RuntimeError("cp -R failed: %s" % tail(out))


# --------------------------------------------------------------------- checks

def check_archive(suite):
    """A finished eject retires its journal from the archived `kin/`."""
    result = Result("archive", "a finished eject leaves no journal in the archived kin/")
    repo, archive = suite.ejected("plain")
    journal = os.path.join(archive, "kin", JOURNAL)
    key = os.path.join(archive, "kin", AUTHORITY_KEY)
    if not os.path.isfile(key):
        result.unknown("the archived kin/ carries no %s, so the directory read is not the "
                       "store's control directory" % AUTHORITY_KEY)
        return result
    if os.path.exists(journal):
        result.bad("the archived kin/ still carries %s after a finished eject; a copy of "
                   "this archive would carry it back" % journal)
    else:
        result.ok("no journal beside %s" % key)
    return result


def check_copyback(suite):
    """The archived `kin/` copied back as `.kin` commits again."""
    result = Result("copyback", "cp -R of the archived kin/ back to .kin commits again")
    repo, archive = suite.ejected("plain")
    copy_back(archive, repo)
    rc, out = suite.kin_commit(repo, "a commit after the copy back")
    if commit_landed(rc, out):
        result.ok("the commit after cp -R landed")
    else:
        result.bad("the commit after cp -R did not land (rc=%d): %s" % (rc, error_lines(out)))
    return result


def check_carried(suite):
    """A 0.5.52-shaped journal carried back by the copy is retired, not refused."""
    result = Result("carried", "a journal a copied .kin carries in is retired when the "
                               "archive proves the eject finished")
    repo, archive = suite.ejected("carried")
    archived_kin = os.path.join(archive, "kin")
    with open(os.path.join(archived_kin, AUTHORITY_KEY), "rb") as handle:
        key = handle.read()
    if len(key) != 32:
        result.unknown("the authority key is %d bytes, not the 32 the journal HMAC uses"
                       % len(key))
        return result
    planted = plant_journal(archived_kin, craft_journal(key, repo, archive, archived_kin))
    copy_back(archive, repo)
    carried = os.path.join(repo, ".kin", JOURNAL)
    if not os.path.isfile(carried):
        result.unknown("the copy did not carry the planted journal to %s" % carried)
        return result
    rc, out = suite.kin_commit(repo, "a commit over a carried journal")
    if not commit_landed(rc, out):
        result.bad("the commit was refused over the carried journal (rc=%d): %s"
                   % (rc, error_lines(out)))
        return result
    if os.path.exists(carried):
        result.bad("the commit landed but the carried journal is still at %s" % carried)
        return result
    if not os.path.isfile(planted):
        result.bad("retiring the carried copy removed the archive's own journal at %s"
                   % planted)
        return result
    result.ok("the commit landed, the carried journal was retired, the archive is untouched")
    return result


def check_refusal(suite):
    """A journal bound to nothing is refused in words, and the store survives it."""
    result = Result("refusal", "a journal bound to nothing is refused with the file and "
                               "the remedy named, never as HTTP 500")
    repo = suite.fresh_repo("refused")
    kin_dir = os.path.join(repo, ".kin")
    with open(os.path.join(kin_dir, AUTHORITY_KEY), "rb") as handle:
        key = handle.read()
    nowhere = os.path.join(os.path.dirname(repo), ".kin-ejected-nowhere")
    planted = plant_journal(kin_dir, craft_journal(key, repo, nowhere, kin_dir, bound=False))
    rc, out = suite.kin_commit(repo, "a commit over an unverifiable journal")
    if rc == 0:
        result.bad("a journal bound to nothing was accepted and the commit landed: %s"
                   % tail(out))
        return result
    if refusal_is_worded(out, journal_paths(repo)):
        result.ok("refused in words, naming the file and the remedy")
    else:
        result.bad("the refusal does not name the file and the remedy in words: %s"
                   % error_lines(out))
        return result
    # The control: the store is intact, and the remedy the message gives works.
    os.remove(planted)
    rc, out = suite.kin_commit(repo, "a commit after the remedy")
    if commit_landed(rc, out):
        result.ok("the commit landed once the file was removed, as the message said")
    else:
        result.bad("the remedy the message gives did not work (rc=%d): %s"
                   % (rc, error_lines(out)))
    return result


def check_hook(suite):
    """`kin init` re-admits the ejected repository over `docs.url`, and still
    refuses an executable hook."""
    result = Result("hook", "kin init re-admits an ejected repository past gitoxide's "
                            "docs.url and still refuses a real hook")
    repo, _archive = suite.ejected("hooked")
    hooks = os.path.join(repo, ".git", "hooks")
    # Pinned into the repository's own configuration, so the surface kin reads
    # is this directory on every host. A machine whose global configuration
    # sets core.hooksPath makes .git/hooks inert, and kin rightly leaves a
    # host-scoped surface uncounted; without the pin both halves of this check
    # would pass on such a machine without reading the file they are about.
    rc, out = suite.git(["config", "core.hooksPath", hooks], repo)
    if rc != 0:
        result.unknown("could not pin core.hooksPath: %s" % tail(out))
        return result
    docs = os.path.join(hooks, "docs.url")
    if os.path.isfile(docs):
        provenance = "left by kin eject"
    else:
        # gitoxide stopped writing it; the rule under test is kin init's count,
        # so plant the file the template used to write and say so.
        os.makedirs(hooks, exist_ok=True)
        with open(docs, "w") as handle:
            handle.write(DOCS_URL)
        provenance = "planted, kin eject no longer writes one"
    rc, out = suite.kin_run(["init"], repo, timeout=900)
    if rc == 0:
        result.ok("kin init admitted the ejected repository with docs.url in place (%s)"
                  % provenance)
    else:
        result.bad("kin init refused the ejected repository with docs.url in place (%s), "
                   "rc=%d: %s" % (provenance, rc, error_lines(out)))
        return result
    # The control: a hook Git runs still blocks, and the refusal names it.
    suite.daemon_stop(repo)
    shutil.rmtree(os.path.join(repo, ".kin"))
    hook = os.path.join(hooks, "pre-commit")
    with open(hook, "w") as handle:
        handle.write("#!/bin/sh\nexit 0\n")
    os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    rc, out = suite.kin_run(["init"], repo, timeout=900)
    if rc != 0 and init_refused_over(out, "pre-commit"):
        result.ok("an executable pre-commit still blocks and is named")
    elif rc == 0:
        result.bad("an executable pre-commit hook no longer blocks kin init")
    else:
        result.bad("kin init refused but did not name the pre-commit hook: %s"
                   % error_lines(out))
    os.remove(hook)
    return result


def check_author(suite):
    """A native commit carries the repository's own Git identity, and nothing else.

    The rc061a brown stranger read `Author: Kin Isolation Probe
    <iso-probe@firelock.io>` out of `kin log`, concluded Kin had a built-in
    identity it substitutes for the repository's own, and filed it as a
    provenance leak that would stop a tag. It was the container's own global Git
    identity, set by the stranger image, and Kin had resolved it correctly. The
    resolution has unit tests; what nothing exercised was the whole path, binary
    to `kin log`, which is the only surface the report was ever going to read.
    So this asserts it end to end, and it asserts the identity read back out of
    Git rather than a constant written here, because a constant this file and the
    fixture both spell would agree with itself while the product stamped anybody.

    This arm pins REPOSITORY scope. The container's identity was global, and
    `check_author_global` covers that, because closing the class at one scope
    says nothing about the other.

    The second arm is the half that makes the first mean something: with no
    identity resolvable anywhere, the commit must refuse. A product that stamps
    the configured identity when there is one and invents one when there is not
    passes the first arm and is exactly the defect the report alleged.
    """
    result = Result("author", "a native commit carries the repository's configured Git "
                              "identity, and an unresolvable identity refuses")
    repo = suite.fresh_repo("author")

    configured = []
    for field in ("user.name", "user.email"):
        rc, out = suite.git(["config", "--get", field], repo)
        if rc != 0 or not out.strip():
            result.unknown("the fixture repository has no %s, so this run cannot compare what "
                           "kin stamped against what Git holds" % field)
            return result
        configured.append(out.strip())
    want = "%s <%s>" % (configured[0], configured[1])

    rc, out = suite.kin_run(["log"], repo)
    if rc != 0:
        result.unknown("kin log failed (rc=%d): %s" % (rc, error_lines(out)))
        return result
    stamped = native_change_author(out)
    if stamped is None:
        result.unknown("kin log printed no native change with an Author line: %s" % tail(out))
        return result
    if stamped != want:
        result.bad("the native change is stamped %r, but this repository's Git identity is %r; "
                   "kin substituted an identity nobody configured" % (stamped, want))
        return result

    # Nothing resolvable anywhere: the repository's own scope is unset and both
    # wider scopes are cut off, which is the only way to prove the refusal is
    # about the absence rather than about the host that happened to run this.
    empty_global = os.path.join(suite.workdir, "empty-global.gitconfig")
    with open(empty_global, "w") as handle:
        handle.write("")
    for field in ("user.name", "user.email"):
        suite.git(["config", "--unset", field], repo)
    stripped_env = dict(suite.env)
    stripped_env["GIT_CONFIG_NOSYSTEM"] = "1"
    stripped_env["GIT_CONFIG_GLOBAL"] = empty_global
    with open(os.path.join(repo, "unattributed.py"), "w") as handle:
        handle.write("def unattributed():\n    return 0\n")
    rc, out = run([suite.kin, "commit", "-m", "a change nobody can be named for"],
                  cwd=repo, env=stripped_env)
    suite.log("kin commit with no identity -> %d" % rc)
    if rc == 0:
        result.bad("kin committed with no resolvable identity anywhere (rc=0), so some value "
                   "stood in for a person: %s" % tail(out))
    elif not identity_refusal_is_worded(out):
        result.bad("kin refused the unattributable commit but did not name both remedies: %s"
                   % error_lines(out))
    else:
        result.ok("stamped %r, matching this repository's Git identity, and refused when "
                  "nothing was resolvable" % stamped)
    return result


def check_author_global(suite):
    """A native commit carries an identity that exists only at GLOBAL Git scope.

    Its sibling `author` sets the fixture identity at repository scope, which
    closes the class one scope away from where the report came from. The rc061a
    container carried no repository identity at all: its `requests` checkout had
    no `[user]` section and no `default_author`, and the name the stranger read
    out of `kin log` was the image's global one. A check that only ever sees a
    local identity would keep passing if global scope stopped resolving
    tomorrow, and a global scope that stopped resolving is exactly the shape of
    the defect that was alleged, because the next thing kin does is refuse.

    So this repository is given no local identity at all, and that is asserted
    rather than assumed: a local read must come back empty while the merged read
    returns the global value. Without that control the arm would silently become
    a second repository-scope test the first time something wrote a local
    identity into the fixture.
    """
    result = Result("author_global", "a native commit carries an identity that resolves only "
                                     "from global Git scope")
    repo = os.path.join(suite.workdir, "trees", "author-global")
    os.makedirs(repo)
    global_config = os.path.join(suite.workdir, "author-global.gitconfig")
    with open(global_config, "w") as handle:
        handle.write("[user]\n\tname = eject-repro-global\n\temail = global@example.invalid\n")
    env = dict(suite.env)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_CONFIG_GLOBAL"] = global_config

    def git(args):
        return run(["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false"] + args,
                   cwd=repo, env=env)

    rc, out = git(["init", "-q", "--initial-branch=main"])
    if rc != 0:
        result.unknown("git init failed: %s" % tail(out))
        return result

    # The control, before anything is measured: no local identity exists, and
    # the merged read still resolves, so what follows is global scope or
    # nothing.
    rc, local_name = git(["config", "--local", "--get", "user.name"])
    if local_name.strip():
        result.unknown("the fixture has a local user.name (%r), so this arm would be measuring "
                       "repository scope again rather than global" % local_name.strip())
        return result
    merged = []
    for field in ("user.name", "user.email"):
        rc, value = git(["config", "--get", field])
        if rc != 0 or not value.strip():
            result.unknown("global %s does not resolve in the fixture, so there is no global "
                           "identity for kin to find" % field)
            return result
        merged.append(value.strip())
    want = "%s <%s>" % (merged[0], merged[1])

    with open(os.path.join(repo, "app.py"), "w") as handle:
        handle.write("def hello():\n    return 'hi'\n")
    git(["add", "--all"])
    rc, out = git(["commit", "-q", "-m", "a python module"])
    if rc != 0:
        result.unknown("git commit failed under global-only identity: %s" % tail(out))
        return result

    rc, out = run([suite.kin, "init"], cwd=repo, env=env, timeout=900)
    if rc != 0:
        result.unknown("kin init failed: %s" % error_lines(out))
        return result
    run([suite.kin, "graph", "status"], cwd=repo, env=env)
    with open(os.path.join(repo, "note_global.py"), "w") as handle:
        handle.write("def note_global():\n    return 1\n")
    rc, out = run([suite.kin, "commit", "-m", "a change authored from global scope"],
                  cwd=repo, env=env)
    suite.log("kin commit under global-only identity -> %d" % rc)
    if not commit_landed(rc, out):
        result.unknown("the commit under a global-only identity did not land (rc=%d): %s"
                       % (rc, error_lines(out)))
        return result

    rc, out = run([suite.kin, "log"], cwd=repo, env=env)
    if rc != 0:
        result.unknown("kin log failed (rc=%d): %s" % (rc, error_lines(out)))
        return result
    stamped = native_change_author(out)
    if stamped is None:
        result.unknown("kin log printed no native change with an Author line: %s" % tail(out))
        return result
    if stamped != want:
        result.bad("the native change is stamped %r, but the only identity resolvable here is the "
                   "global %r; kin did not read global scope" % (stamped, want))
    else:
        result.ok("stamped %r from global scope alone, with no local identity present" % stamped)
    return result


CHECKS = [check_archive, check_copyback, check_carried, check_refusal, check_hook,
          check_author, check_author_global]
DECLARED = ("archive", "copyback", "carried", "refusal", "hook", "author", "author_global")


# ------------------------------------------------------------------ self-test

def self_test():
    """Falsify every grader against its own inverse, with no binary."""
    failures = []
    counted = [0]

    def expect(label, got, want):
        counted[0] += 1
        if got != want:
            failures.append("%s: got %r, wanted %r" % (label, got, want))

    expect("a landed commit", commit_landed(0, "Created semantic change abc on branch"), True)
    expect("a non-zero exit is not landed", commit_landed(1, "Created semantic change abc"), False)
    expect("nothing to commit is not landed", commit_landed(0, "nothing to commit"), False)

    paths = ["/r/.kin/reconciliation/exact-eject-journal.json",
             "/private/r/.kin/reconciliation/exact-eject-journal.json"]
    worded = ("Error: exact eject journal /r/.kin/reconciliation/exact-eject-journal.json is "
              "bound to a different repository or .kin directory than the one it was found in, "
              "so Kin will not replay the eject it records here. If that eject completed, the "
              "repository root holds an ordinary .git and /.kin-ejected-x holds kin/ and "
              "previous-git/, and this journal is a leftover: remove the file and rerun. To "
              "rebuild Kin from Git history instead, remove .kin/ and run `kin init`.")
    expect("a worded refusal passes", refusal_is_worded(worded, paths), True)
    expect("the canonical spelling of the path passes",
           refusal_is_worded(worded.replace("/r/", "/private/r/"), paths), True)
    # The exact text 0.5.52 shipped. It names the path and nothing else a
    # reader needs, and it must fail here or this suite guards nothing.
    expect("the shipped HTTP 500 fails",
           refusal_is_worded(SHIPPED_REFUSAL, ["/work/notekeeper/.kin/reconciliation/"
                                               "exact-eject-journal.json"]), False)
    expect("the remedy with the transport still showing fails",
           refusal_is_worded("HTTP 500: " + worded, paths), False)
    expect("a Core error prefix fails", refusal_is_worded("Core error: " + worded, paths), False)
    expect("the remedy about a different file fails",
           refusal_is_worded(worded, ["/elsewhere/exact-eject-journal.json"]), False)
    expect("a refusal with no remedy fails",
           refusal_is_worded("Error: exact eject journal " + paths[0] + " failed authentication",
                             paths), False)
    expect("a remedy without kin init fails",
           refusal_is_worded(worded.replace("kin init", "reinstall"), paths), False)

    refused = ("Error: admit exact reachable Git repository authority\n\nCaused by:\n    admit "
               "this Git repository: this Git repository has 1 admission blocker(s):\n      - "
               "Git hook /r/.git/hooks/pre-commit runs for this repository; move it aside")
    expect("a hook refusal names its hook", init_refused_over(refused, "pre-commit"), True)
    expect("a refusal over another hook is not this one",
           init_refused_over(refused, "docs.url"), False)
    expect("an admission is not a refusal",
           init_refused_over("admitted exact Git repository in 0.1s", "pre-commit"), False)

    # `kin log` in the shape rc061a read it: one native change above an imported
    # one. The imported line is the trap, because it carries an Author too, and a
    # grader that took the first one it saw would grade the wrong change.
    log = ("change aaa\n"
           "Author: Kin Isolation Probe <iso-probe@firelock.io>\n"
           "Date:   2026-08-28T12:10:43Z\n"
           "Origin: native\n"
           "\n"
           "change bbb\n"
           "Author: Nate Prewitt <nate.prewitt@gmail.com> 1787618757 -0600\n"
           "Date:   2026-08-25T00:45:57Z\n"
           "Origin: git commit 5460f467\n")
    expect("the native change's author is the one read",
           native_change_author(log), "Kin Isolation Probe <iso-probe@firelock.io>")
    expect("an imported change alone yields no native author",
           native_change_author("change bbb\n"
                                "Author: Nate Prewitt <nate.prewitt@gmail.com> 1 -0600\n"
                                "Origin: git commit 5460f467\n"), None)
    expect("a log with no Author line yields none",
           native_change_author("change aaa\nOrigin: native\n"), None)

    remedy = ("Error: kin has no author identity to record for this change.\n\n"
              "Authorship is provenance. A change attributed to nobody cannot support review "
              "attribution, blame, or audit, and it cannot be corrected later without rewriting "
              "history, so kin refuses to invent one.\n\n"
              "Set your Git identity:\n"
              "  git config --global user.name \"Your Name\"\n"
              "  git config --global user.email \"you@example.com\"\n"
              "Or set a Kin-specific author in .kin/config.toml:\n"
              "  default_author = \"Your Name <you@example.com>\"")
    expect("the identity refusal names both remedies",
           identity_refusal_is_worded(remedy), True)
    expect("a refusal naming only the Git remedy fails",
           identity_refusal_is_worded(remedy.split("Or set a Kin-specific")[0]), False)
    expect("a landed commit is not a refusal",
           identity_refusal_is_worded("Created semantic change abc on branch main"), False)

    # The crafted journal encodes in kin-core's field order and authenticates
    # under the key it was given, and a changed byte changes the tag.
    key = bytes(range(32))
    with tempfile.TemporaryDirectory() as scratch:
        root = os.path.join(scratch, "repo")
        archive = os.path.join(scratch, ".kin-ejected-x")
        kin = os.path.join(archive, "kin")
        for path in (os.path.join(root, ".git"), os.path.join(kin, "reconciliation")):
            os.makedirs(path)
        body = json.loads(craft_journal(key, root, archive, kin))
        expect("the journal keeps kin-core's field order", tuple(body["journal"]), JOURNAL_FIELDS)
        expect("the journal is at the detach phase", body["journal"]["phase"], "detach_pending")
        expect("the journal names the archived kin",
               body["journal"]["kin_control_identity"], identity(kin))
        encoded = json.dumps(body["journal"], separators=(",", ":")).encode()
        tag = hmac.new(key, JOURNAL_PREFIX + encoded, hashlib.sha256).digest()
        expect("the tag is the HMAC of the prefixed journal", bytes(body["authentication"]), tag)
        other = hmac.new(key, JOURNAL_PREFIX + encoded.replace(b"detach", b"Detach"),
                         hashlib.sha256).digest()
        expect("a changed journal changes the tag", other == tag, False)
        unbound = json.loads(craft_journal(key, root, archive, kin, bound=False))
        expect("an unbound journal names nothing", unbound["journal"]["root_identity"], NOWHERE)

    tail_cases = [("short", "short"), ("WARN noise " * 60 + "Error: the real cause", None)]
    for text, exact in tail_cases:
        got = tail(text, 40)
        if exact is not None and got != exact:
            failures.append("tail(%r) = %r, wanted %r" % (text, got, exact))
        if exact is None and not got.endswith("Error: the real cause"):
            failures.append("tail dropped the end of the output: %r" % got)

    grade_cases = [
        (PASS, [(PASS, "a")]),
        (FAIL, [(PASS, "a"), (FAIL, "b")]),
        (UNREADABLE, [(PASS, "a"), (UNREADABLE, "b")]),
        (FAIL, [(UNREADABLE, "a"), (FAIL, "b")]),
        (UNREADABLE, []),
    ]
    for want, entries in grade_cases:
        result = Result("t", "t")
        for status, detail in entries:
            result.asserts.append({"status": status, "detail": detail})
        if result.status != want:
            failures.append("Result.status(%s) = %s, wanted %s" % (entries, result.status, want))

    # The declared ids are the checks' own names, so a check added or renamed
    # without its declaration cannot answer under a name nobody asked for.
    expect("every declared id has a check",
           tuple(c.__name__.replace("check_", "") for c in CHECKS), DECLARED)

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    total = counted[0] + len(tail_cases) + len(grade_cases)
    print("kin-eject-journal-repro: self-test %d/%d cases" % (total - len(failures), total))
    return 1 if failures else 0


# ----------------------------------------------------------------------- main

def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"),
                        help="the kin binary under test")
    parser.add_argument("--daemon", default=os.environ.get("KIN_DAEMON_BIN"),
                        help="the kin-daemon beside it")
    parser.add_argument("--json", dest="json_path", default=None,
                        help="write the machine-readable report here, for scripts/acceptance/gate.py")
    parser.add_argument("--label", default=os.environ.get("KIN_ACCEPTANCE_LABEL"),
                        help="an opaque run label recorded in the report")
    parser.add_argument("--keep", action="store_true", help="keep the fixtures")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--self-test", action="store_true",
                        help="falsify this suite's graders and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()

    if not args.kin:
        print("kin-eject-journal-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    if os.name != "posix":
        print("kin-eject-journal-repro: kin eject is Unix-only, and so is this suite.")
        return 3
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-eject-journal-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-eject-journal-repro-")
    suite = None
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        results = []
        for check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(getattr(check, "__name__", "check").replace("check_", ""),
                                "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
        # A suite that graded fewer checks than it declares exits like a clean
        # pass unless it counts, so it counts: the ids that answered are the ids
        # declared, in order, or the run is a setup failure.
        answered = tuple(r.id for r in results)
        if answered != DECLARED:
            print("kin-eject-journal-repro: declared %s but %s answered" % (DECLARED, answered))
            return 3
        print("kin-eject-journal-repro: %d of %d declared checks answered"
              % (len(answered), len(DECLARED)))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-eject-journal-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        if args.json_path:
            payload = {
                "suite": "eject_journal_repro",
                "ticket": TICKET,
                "label": args.label,
                "kin": kin,
                "results": [
                    {"id": r.id, "ticket": TICKET, "title": r.title,
                     "status": r.status, "detail": r.detail, "asserts": r.asserts}
                    for r in results
                ],
            }
            directory = os.path.dirname(os.path.abspath(args.json_path))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(args.json_path, "w") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
        if failed:
            return 1
        if unreadable:
            return 2
        return 0
    finally:
        if suite is not None:
            trees = os.path.join(workdir, "trees")
            if os.path.isdir(trees):
                for name in os.listdir(trees):
                    suite.daemon_stop(os.path.join(trees, name))
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
