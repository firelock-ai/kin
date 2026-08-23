#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for KIN_HOME registry isolation (FIR-2467).

Its output is a regression gate, never proof, never investor-facing and never a
released claim. It shares the CHECK line format, the exit codes and the
`--self-test` discipline of its siblings in this directory, so a reader who
knows one knows all of them.

What it is for
--------------
KIN_HOME is the boundary that bounds store state, and the cross-repo registry is
store state. It did not used to behave that way. The registry file's parent
directory doubled as the machine-level supervisor directory, so keying the
supervisor on the real home kept the registry there too, and a daemon launched
under a scratch KIN_HOME read the operator's registry and pinned sibling
authority for every repository on the box.

That is an isolation leak in both directions. A fixture observes machine state
it cannot control and cannot reproduce, and the machine's repository set leaks
into an environment whose whole purpose was to be sealed.

The two homes this suite builds
-------------------------------
A throwaway HOME stands in for the operator's real home, and a separate
directory is the scratch KIN_HOME. Repositories are registered into one or the
other, then queried from the scratch home with KIN_REGISTRY_PATH deliberately
UNSET, because an explicit registry pin wins on both sides of this fix and a
probe that set one would be asking a question it could not fail.

The outsider is registered with KIN_REGISTRY_PATH pinned at the throwaway home's
registry rather than by leaning on HOME resolution, so the operator's own
registry is never a possible target of a write no matter how a platform resolves
its home directory.

Every check is paired with its control, because a build that had simply stopped
answering would pass the sealed half of every one of them.

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated (no output, a non-JSON payload, a field
this build does not define). A crashed probe is UNREADABLE, never a verdict.
Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/registry_home_isolation.py --kin target/release/kin

`--kin` may also come from KIN_BIN. The kin-daemon beside it is used when one
exists. No binary is built by this script.
"""

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
TICKET = "FIR-2467"

# The daemon names a sibling it could not pin with this line. It is the exact
# symptom FIR-2467 was filed on: a scratch-home daemon printing one of these for
# every repository on the operator's machine.
PIN_WARNING = "sibling repository authority could not be pinned at daemon startup"

REGISTRY_ID = re.compile(r'^\s*id\s*=\s*"([^"]+)"', re.M)
REGISTRY_PATH = re.compile(r'^\s*path\s*=\s*"([^"]+)"', re.M)
# Daemon logs carry ANSI escapes between a field name and its value, so a
# byte-level match for `repo_id=outsider` never fires on a coloured log.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def strip_ansi(text):
    return ANSI.sub("", text or "")


def tail(text, limit=400):
    """The END of a command's output, which is where its error is."""
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def run(cmd, cwd=None, env=None, timeout=600):
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout


def run_split(cmd, cwd=None, env=None, timeout=600):
    """Like `run`, with stderr kept apart from stdout.

    kin writes a correctness-relevant-override warning to stderr on every command
    this suite runs, because the suite pins the embedding backend. Merged into
    stdout that line sits in front of the JSON payload and no parser reaches it,
    which reads as an unreadable product rather than an unreadable probe.
    """
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    return proc.returncode, proc.stdout, proc.stderr


def registry_entries(path):
    """Every id-to-path pair a registry file names, or None when unreadable.

    None and the empty mapping are different answers. A registry that is missing
    or unparseable cannot ground a claim that something is absent from it, which
    is the whole claim this suite makes.
    """
    try:
        with open(path) as handle:
            text = handle.read()
    except (IOError, OSError):
        return None
    entries = {}
    for block in text.split("[[repos]]")[1:]:
        ids = REGISTRY_ID.findall(block)
        paths = REGISTRY_PATH.findall(block)
        if ids and paths:
            entries[ids[0]] = paths[0]
    return entries


def id_for_path(entries, path):
    """The id a registry gave one repository path, or None."""
    wanted = os.path.realpath(path)
    for repo_id, recorded in (entries or {}).items():
        if os.path.realpath(recorded) == wanted:
            return repo_id
    return None


def deps_ids(output):
    """Repo ids from `kin deps --all --json`, or None when it will not parse."""
    try:
        payload = json.loads(output)
    except ValueError:
        return None
    repositories = payload.get("repositories")
    if not isinstance(repositories, list):
        return None
    ids = set()
    for repo in repositories:
        # `kin.deps.v1` names the field `repo_id`. A payload that does not carry
        # it is a schema this probe does not understand, which is unreadable and
        # never an empty answer.
        if not isinstance(repo, dict) or "repo_id" not in repo:
            return None
        ids.add(str(repo["repo_id"]))
    return ids


def listed_ids(output):
    """Repo ids from the `kin registry list` text surface, or None.

    The empty-registry line is a readable answer meaning no repositories, which
    is not the same as a surface that could not be read at all.
    """
    text = strip_ansi(output or "")
    if "No registered repositories." in text:
        return set()
    if "Registered repositories:" not in text:
        return None
    ids = set()
    for line in text.splitlines():
        if not line.startswith("  ") or not line.strip():
            continue
        fields = line.split()
        if len(fields) >= 2 and fields[1].isdigit():
            ids.add(fields[0])
    return ids


class Result(object):
    def __init__(self, check_id, ticket, title):
        self.id = check_id
        self.ticket = ticket
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
        # Every passing assertion, not the last one. Each check grades the
        # sealed case AND its control, and a line naming only the control would
        # read as a pass for a suite that never probed the case it exists for.
        graded = [a["detail"] for a in self.asserts if a["status"] == PASS]
        return "; ".join(graded) if graded else "no assertion was reached"


# ---------------------------------------------------------------------- suite

class Suite(object):
    """Two homes, four repositories, and one question asked from the scratch one.

    `real_home` stands in for the operator's home directory and is where the
    outsider is registered. `scratch_home` is the KIN_HOME every probe runs
    under. Nothing in this suite ever writes to the machine's own home.
    """

    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.verbose = verbose
        self.real_home = os.path.join(workdir, "real-home-%d" % os.getpid())
        self.scratch_home = os.path.join(workdir, "kin-home-%d" % os.getpid())
        os.makedirs(os.path.join(self.real_home, ".kin"), exist_ok=True)
        os.makedirs(self.scratch_home, exist_ok=True)

        base = dict(os.environ)
        # A scratch KIN_HOME keeps this run off the fleet's stores and the
        # auto-embed opt-out keeps it off the GPU. Neither is a nicety: this
        # suite is meant to run on every pull request beside other work.
        base["KIN_DAEMON_AUTO_EMBED"] = "0"
        base["KIN_EMBED_BACKEND"] = "cpu"
        base["KIN_VFS_DISABLE"] = "1"
        base["HOME"] = self.real_home
        base.pop("KIN_MCP_REPO", None)
        base.pop("KIN_DIR", None)
        if daemon:
            base["KIN_DAEMON_BIN"] = daemon

        # The environment under test. KIN_REGISTRY_PATH is removed rather than
        # merely left alone: an inherited pin wins on both sides of this fix,
        # so a probe that kept one would be asking a question it could not fail.
        self.env = dict(base)
        self.env["KIN_HOME"] = self.scratch_home
        self.env.pop("KIN_REGISTRY_PATH", None)

        # The stand-in for the operator's home. The registry is named outright
        # here so the write lands in the throwaway home whatever a platform
        # believes the home directory is.
        self.real_registry = os.path.join(self.real_home, ".kin", "registry.toml")
        self.real_env = dict(base)
        self.real_env["KIN_HOME"] = os.path.join(self.real_home, ".kin")
        self.real_env["KIN_REGISTRY_PATH"] = self.real_registry

        self.scratch_registry = os.path.join(self.scratch_home, "registry.toml")
        self.repos = {}

    # -- fixture construction

    def git(self, args, cwd):
        base = ["git",
                "-c", "core.hooksPath=/dev/null",
                "-c", "user.email=repro@example.invalid",
                "-c", "user.name=kin-registry-isolation-repro",
                "-c", "commit.gpgsign=false"]
        return run(base + args, cwd=cwd, env=self.env)

    def fixture(self, name, env):
        """A small Python library, admitted through `kin init` under `env`.

        The repository is registered by the product's own registration path
        rather than by writing a registry file, so what this suite seals is the
        thing a real `kin init` produces.
        """
        if name in self.repos:
            return self.repos[name]
        repo = os.path.join(self.workdir, name)
        os.makedirs(os.path.join(repo, "pkg"), exist_ok=True)
        rc, out = self.git(["init", "--initial-branch=main"], repo)
        if rc != 0:
            raise RuntimeError("git init failed in %s: %s" % (repo, tail(out)))
        for index in range(3):
            with open(os.path.join(repo, "pkg", "module%d.py" % index), "w") as handle:
                handle.write(
                    "def handler%d(payload):\n"
                    "    \"\"\"Return the payload unchanged.\"\"\"\n"
                    "    return payload\n" % index
                )
        self.git(["add", "--all"], repo)
        rc, out = self.git(["commit", "-m", "a python library"], repo)
        if rc != 0:
            raise RuntimeError("git commit failed in %s: %s" % (repo, tail(out)))
        rc, out = run([self.kin, "init"], cwd=repo, env=env, timeout=900)
        if rc != 0:
            raise RuntimeError("kin init failed in %s: %s" % (repo, tail(out)))
        self.repos[name] = repo
        return repo

    def stop_daemon(self, repo, env):
        run([self.kin, "daemon", "stop"], cwd=repo, env=env, timeout=180)

    def unbind(self, repo, env):
        """Stop this repository's daemon, then take its `.kin` away.

        A registered repository whose store is gone is one whose authority
        cannot be pinned, which is what makes the daemon say so. The daemon is
        stopped first because a running worker holds the store it serves.
        """
        self.stop_daemon(repo, env)
        shutil.rmtree(os.path.join(repo, ".kin"), ignore_errors=True)

    def own_repos(self):
        """The repositories this run registered under the scratch KIN_HOME."""
        return [self.probe, self.roommate, self.stranger]

    def setup(self):
        """Build both homes and leave the registries in their final state."""
        self.probe = self.fixture("probe", self.env)
        self.roommate = self.fixture("roommate", self.env)
        self.stranger = self.fixture("stranger", self.env)
        self.outsider = self.fixture("outsider", self.real_env)
        self.unbind(self.stranger, self.env)
        self.unbind(self.outsider, self.real_env)
        self.stop_daemon(self.roommate, self.env)

    # -- probes

    def kin_run(self, args, repo=None, timeout=600):
        return run([self.kin] + args, cwd=repo or self.probe, env=self.env, timeout=timeout)

    def kin_run_split(self, args, repo=None, timeout=600):
        return run_split([self.kin] + args, cwd=repo or self.probe, env=self.env,
                         timeout=timeout)

    def daemon_log(self):
        return os.path.join(self.probe, ".kin", "daemon.log")

    def restart_probe_daemon(self):
        """A daemon that read the registry in its FINAL state, and only that.

        Authority pinning happens once, at daemon startup, so a worker started
        before the fixtures were finished would have read a different registry.
        The log is truncated between the stop and the start so what it holds is
        this startup's and not an earlier one's.
        """
        self.stop_daemon(self.probe, self.env)
        try:
            with open(self.daemon_log(), "w"):
                pass
        except (IOError, OSError):
            pass
        return self.kin_run(["graph", "status"])

    def read_daemon_log(self):
        try:
            with open(self.daemon_log(), errors="replace") as handle:
                return strip_ansi(handle.read())
        except (IOError, OSError):
            return None


# --------------------------------------------------------------------- checks

def homes(suite, res):
    """What this run registered where, or None when absence cannot be grounded.

    Returns `(own, foreign, paths)`: the ids this run registered under the
    scratch KIN_HOME, the id it registered only in the stand-in real home, and
    the id-to-path map both readings came from.

    The ids are resolved by repository PATH across both registry files rather
    than by set-differencing them, because on unfixed bytes the scratch home has
    no registry at all: every `kin init` landed in the real home, including the
    three that named the scratch one. Differencing the files there yields nothing
    to compare and the whole suite reports UNREADABLE, which fails the gate but
    never names the leak. Resolving by path states the defect instead: these are
    the repositories this run put in the scratch home, this is the one it did
    not, and here is a scratch-home surface naming it.
    """
    scratch = registry_entries(suite.scratch_registry)
    real = registry_entries(suite.real_registry)
    if scratch is None and real is None:
        res.unknown("neither registry could be read (%s, %s), so no claim about "
                    "what either names is grounded"
                    % (suite.scratch_registry, suite.real_registry))
        return None

    paths = {}
    for entries in (real or {}, scratch or {}):
        paths.update(entries)

    foreign_id = id_for_path(paths, suite.outsider)
    if foreign_id is None:
        res.unknown("no registry names an id for the outsider repository at %s, "
                    "so there is nothing for a scratch home to be sealed from"
                    % suite.outsider)
        return None

    own = {i for i in (id_for_path(paths, repo) for repo in suite.own_repos()) if i}
    if not own:
        res.unknown("no registry names an id for any repository this run "
                    "registered under the scratch KIN_HOME, so a sealed reading "
                    "would have nothing to be sealed around")
        return None
    return own, {foreign_id}, paths


def grade_view(res, surface, seen, own, foreign, roommate_id):
    """Grade one cross-repo surface's repo-id set against both homes."""
    if seen is None:
        res.unknown("%s could not be read as a repository listing" % surface)
        return
    leaked = seen & foreign
    if leaked:
        res.bad("%s under the scratch KIN_HOME names %d repository id(s) "
                "registered only in the operator's home: %s"
                % (surface, len(leaked), ", ".join(sorted(leaked))))
    else:
        stray = seen - set(own)
        if stray:
            res.bad("%s under the scratch KIN_HOME names %d repository id(s) this "
                    "run never registered anywhere: %s"
                    % (surface, len(stray), ", ".join(sorted(stray))))
        else:
            res.ok("%s named %d id(s), all of them this scratch home's own, and "
                   "none of the %d registered only in the operator's home"
                   % (surface, len(seen), len(foreign)))
    # The control. Without it, a surface that had simply stopped answering would
    # pass the sealed assertion above for the wrong reason.
    if roommate_id is None:
        res.unknown("no registry names an id for the roommate repository, so "
                    "this surface's control cannot be graded")
    elif roommate_id in seen:
        res.ok("control: the sibling registered in the SCRATCH home (%s) still "
               "resolves on the same surface" % roommate_id)
    else:
        res.bad("control: the sibling registered in the SCRATCH home (%s) does "
                "not resolve, so this surface is sealed by being empty rather "
                "than by honouring KIN_HOME" % roommate_id)


def check_0(suite):
    """`kin deps --all` under a scratch KIN_HOME sees only that home's repos."""
    res = Result("0", TICKET, "kin deps is bounded by KIN_HOME")
    both = homes(suite, res)
    if both is None:
        return res
    own, foreign, _paths = both
    rc, out, err = suite.kin_run_split(["deps", "--all", "--json"])
    if rc != 0:
        res.unknown("kin deps --all --json exited %d: %s" % (rc, tail(err or out)))
        return res
    grade_view(res, "kin deps --all --json", deps_ids(out), own, foreign,
               id_for_path(_paths, suite.roommate))
    return res


def check_1(suite):
    """`kin registry` is bounded by the same home as every other surface."""
    res = Result("1", TICKET, "kin registry is bounded by KIN_HOME")
    both = homes(suite, res)
    if both is None:
        return res
    own, foreign, _paths = both
    # `kin registry` with no subcommand IS the listing; `registry list` is not a
    # subcommand and exits 2. The first draft of this probe asked for one and got
    # UNREADABLE, which is that outcome working.
    rc, out, err = suite.kin_run_split(["registry"])
    if rc != 0:
        res.unknown("kin registry exited %d: %s" % (rc, tail(err or out)))
        return res
    grade_view(res, "kin registry", listed_ids(out), own, foreign,
               id_for_path(_paths, suite.roommate))
    return res


def check_2(suite):
    """A scratch-home daemon pins no authority for the operator's repositories.

    This is the reported symptom of FIR-2467 rather than a proxy for it: the
    fixture daemon's own log carried one pin warning per repository on the box.
    The control is a second unbindable repository registered in the SCRATCH
    home, which MUST produce that warning, so an absent warning above is a
    sealed daemon and not a daemon that stopped pinning anything.
    """
    res = Result("2", TICKET, "a scratch-home daemon pins no foreign authority")
    both = homes(suite, res)
    if both is None:
        return res
    _own, foreign, paths = both
    rc, out = suite.restart_probe_daemon()
    if rc != 0:
        res.unknown("the command that starts the probe daemon exited %d: %s"
                    % (rc, tail(out)))
        return res
    log = suite.read_daemon_log()
    if not log or not log.strip():
        res.unknown("the daemon log at %s is missing or empty, so what the "
                    "daemon pinned cannot be read" % suite.daemon_log())
        return res

    named = sorted(i for i in foreign if i in log) + \
        sorted(p for p in (paths.get(i) for i in foreign) if p and p in log)
    if named:
        res.bad("the daemon under the scratch KIN_HOME names %d repository "
                "registered only in the operator's home: %s"
                % (len(named), ", ".join(named[:4])))
    else:
        res.ok("the daemon log names none of the %d repository id(s) or path(s) "
               "registered only in the operator's home" % len(foreign))

    stranger_id = id_for_path(paths, suite.stranger)
    if stranger_id is None:
        res.unknown("no registry names an id for the stranger repository, so "
                    "this check's control cannot be graded")
    elif PIN_WARNING in log and stranger_id in log:
        res.ok("control: the unbindable sibling in the SCRATCH home (%s) still "
               "draws the pin warning, so this log can carry one" % stranger_id)
    else:
        res.unknown("control: the unbindable sibling in the SCRATCH home (%s) drew "
                    "no pin warning, so an absent warning above proves nothing "
                    "about isolation" % stranger_id)
    return res


def check_3(suite):
    """KIN_HOME moves the registry and still does NOT move the supervisor.

    The other half of the same seam, and the reason this fix is a split rather
    than a move. The supervisor is a machine-level singleton on purpose: one
    supervisor holds daemons from several managed homes, and following KIN_HOME
    would hide from a pinned session the daemons it shares the box with.
    """
    res = Result("3", TICKET, "the supervisor stays machine-level")
    rc, out = suite.kin_run(["graph", "status"])
    if rc != 0:
        res.unknown("kin graph status exited %d, so no daemon was started to "
                    "place a supervisor: %s" % (rc, tail(out)))
        return res

    marks = ("supervisor.pid", "supervisor.port", "supervisor.lock")
    real_dir = os.path.join(suite.real_home, ".kin")
    at_real = [m for m in marks if os.path.exists(os.path.join(real_dir, m))]
    at_scratch = [m for m in marks if os.path.exists(os.path.join(suite.scratch_home, m))]

    if not at_real and not at_scratch:
        res.unknown("no supervisor file appeared in either home, so where the "
                    "supervisor lives cannot be read from this run")
        return res
    if at_real:
        res.ok("the supervisor is in the real home at %s (%s)"
               % (real_dir, ", ".join(at_real)))
    else:
        res.bad("no supervisor file is in the real home at %s, so the supervisor "
                "did not stay machine-level" % real_dir)
    if at_scratch:
        res.bad("the supervisor followed KIN_HOME into %s (%s), which would hide "
                "from a pinned session the daemons it shares the box with"
                % (suite.scratch_home, ", ".join(at_scratch)))
    else:
        res.ok("no supervisor file followed KIN_HOME into %s" % suite.scratch_home)
    # The registry, unlike the supervisor, MUST have moved. Without this the
    # check would pass on a build where KIN_HOME moved nothing at all.
    if os.path.exists(suite.scratch_registry):
        res.ok("control: the registry did move with KIN_HOME, to %s"
               % suite.scratch_registry)
    else:
        res.bad("control: no registry exists at %s, so KIN_HOME moved the "
                "registry nowhere" % suite.scratch_registry)
    return res


CHECKS = [("0", check_0), ("1", check_1), ("2", check_2), ("3", check_3)]


# ------------------------------------------------------------------ self-test

def _grade(seen, scratch, foreign, roommate_id):
    res = Result("x", TICKET, "grader under test")
    grade_view(res, "surface", seen, scratch, foreign, roommate_id)
    return res.status


def _diagnosis(seen, scratch, foreign, roommate_id):
    """The status AND the words the grader used to reach it.

    Status alone cannot falsify this grader. A foreign id is by construction
    also an id the scratch home never registered, so the leak branch and the
    stray branch both FAIL on the same input and deleting either one leaves the
    verdict unchanged. What the operator is told is the part that differs, so
    that is what gets asserted.
    """
    res = Result("x", TICKET, "grader under test")
    grade_view(res, "surface", seen, scratch, foreign, roommate_id)
    return res.status, res.detail


def self_test():
    """Falsify every grader here, each case paired with its inverse.

    Needs no binary, no corpus and no daemon. A suite whose graders are never
    falsified is a suite that reports PASS for reasons nobody has checked.
    """
    cases = []

    def case(name, got, want):
        cases.append((name, got, want))

    listing = json.dumps({"schema": "kin.deps.v1",
                          "repositories": [{"repo_id": "a"}, {"repo_id": "b"}]})
    case("deps ids read", deps_ids(listing), {"a", "b"})
    case("a deps payload behind a log line is unreadable",
         deps_ids("WARN correctness-relevant override active\n" + listing), None)
    case("the pre-rename field name is not accepted",
         deps_ids(json.dumps({"repositories": [{"id": "a"}]})), None)
    case("deps empty reads empty",
         deps_ids(json.dumps({"schema": "x", "repositories": []})), set())
    case("deps non-json is unreadable", deps_ids("not json at all"), None)
    case("deps without repositories is unreadable",
         deps_ids(json.dumps({"schema": "x"})), None)
    case("deps row without a repo_id is unreadable",
         deps_ids(json.dumps({"repositories": [{"entities": 1}]})), None)

    text = "Registered repositories:\n  probe                 2 entities  (no deps)  11s ago\n"
    case("listing ids read", listed_ids(text), {"probe"})
    case("listing ids read through colour",
         listed_ids("Registered repositories:\n  \x1b[32mprobe\x1b[0m    42 entities\n"),
         {"probe"})
    case("empty listing reads empty",
         listed_ids("No registered repositories.\nhint: ..."), set())
    case("unrecognized listing is unreadable", listed_ids("something else"), None)

    case("ansi stripped", strip_ansi("\x1b[31mrepo_id\x1b[0m=x"), "repo_id=x")
    case("tail keeps the end", tail("abcdef", limit=3), "..." + "def")

    scratch = {"probe": "/w/probe", "roommate": "/w/roommate"}
    case("id for a known path", id_for_path(scratch, "/w/roommate"), "roommate")
    case("id for an unknown path", id_for_path(scratch, "/w/elsewhere"), None)
    case("id from an unreadable registry", id_for_path(None, "/w/roommate"), None)

    # The grader itself, both directions.
    case("a leaked foreign id FAILs",
         _grade({"probe", "roommate", "outsider"}, scratch, {"outsider"}, "roommate"),
         FAIL)
    case("a sealed view with its control PASSes",
         _grade({"probe", "roommate"}, scratch, {"outsider"}, "roommate"), PASS)
    case("a sealed view with no control FAILs",
         _grade({"probe"}, scratch, {"outsider"}, "roommate"), FAIL)
    case("an id from neither home FAILs",
         _grade({"probe", "roommate", "somebody-elses"}, scratch, {"outsider"}, "roommate"),
         FAIL)
    # Each failing branch is named by the diagnosis it prints, because both
    # branches FAIL on a leaked id and neither can be falsified by status.
    leak_status, leak_detail = _diagnosis(
        {"probe", "roommate", "outsider"}, scratch, {"outsider"}, "roommate")
    case("a leak is diagnosed as the operator's home",
         (leak_status, "registered only in the operator's home" in leak_detail,
          "outsider" in leak_detail),
         (FAIL, True, True))
    stray_status, stray_detail = _diagnosis(
        {"probe", "roommate", "somebody-elses"}, scratch, {"outsider"}, "roommate")
    case("an id from neither home is diagnosed as unregistered",
         (stray_status, "never registered anywhere" in stray_detail,
          "somebody-elses" in stray_detail),
         (FAIL, True, True))
    sealed_status, sealed_detail = _diagnosis(
        {"probe", "roommate"}, scratch, {"outsider"}, "roommate")
    case("a sealed view says so and names its control",
         (sealed_status, "none of the 1 registered only in the operator's home"
          in sealed_detail, "control:" in sealed_detail),
         (PASS, True, True))
    case("an unreadable surface is UNREADABLE",
         _grade(None, scratch, {"outsider"}, "roommate"), UNREADABLE)
    case("a control with no id is UNREADABLE",
         _grade({"probe"}, scratch, {"outsider"}, None), UNREADABLE)

    # The verdict ladder: FAIL outranks UNREADABLE outranks PASS, and a check
    # that graded nothing is never a pass.
    ladder = Result("y", TICKET, "ladder")
    case("nothing graded is UNREADABLE", ladder.status, UNREADABLE)
    ladder.ok("fine")
    case("only passes is PASS", ladder.status, PASS)
    ladder.unknown("cannot say")
    case("one unreadable outranks passes", ladder.status, UNREADABLE)
    ladder.bad("broken")
    case("one fail outranks everything", ladder.status, FAIL)
    case("detail names the failure", ladder.detail, "broken")

    joined = Result("z", TICKET, "detail")
    joined.ok("case sealed")
    joined.ok("control resolved")
    case("detail joins every passing assertion", joined.detail,
         "case sealed; control resolved")

    # The registry reader, against files rather than strings, because what it
    # actually has to survive is a real registry's shape.
    work = tempfile.mkdtemp(prefix="kin-registry-isolation-selftest-")
    try:
        good = os.path.join(work, "registry.toml")
        with open(good, "w") as handle:
            handle.write('[[repos]]\nid = "probe"\npath = "/w/probe"\nentities = 3\n\n'
                         '[[repos]]\nid = "roommate"\npath = "/w/roommate"\nentities = 4\n')
        case("registry entries read", registry_entries(good),
             {"probe": "/w/probe", "roommate": "/w/roommate"})
        empty = os.path.join(work, "empty.toml")
        with open(empty, "w") as handle:
            handle.write("repos = []\n")
        case("an empty registry reads empty", registry_entries(empty), {})
        case("a missing registry is unreadable",
             registry_entries(os.path.join(work, "absent.toml")), None)

        # `homes` must refuse to grade rather than pass, in each way it can be
        # ungrounded, and must ground itself on registered PATHS so the unfixed
        # shape (no scratch registry at all, every repo in the real home) still
        # names the leak instead of reporting UNREADABLE.
        class Fake(object):
            pass

        absent = os.path.join(work, "absent.toml")
        unfixed = os.path.join(work, "unfixed.toml")
        with open(unfixed, "w") as handle:
            handle.write('[[repos]]\nid = "probe"\npath = "/w/probe"\n\n'
                         '[[repos]]\nid = "roommate"\npath = "/w/roommate"\n\n'
                         '[[repos]]\nid = "stranger"\npath = "/w/stranger"\n\n'
                         '[[repos]]\nid = "outsider"\npath = "/w/outsider"\n')

        def fake(scratch_path, real_path):
            f = Fake()
            f.scratch_registry = scratch_path
            f.real_registry = real_path
            f.probe, f.roommate, f.stranger = "/w/probe", "/w/roommate", "/w/stranger"
            f.outsider = "/w/outsider"
            f.own_repos = lambda: [f.probe, f.roommate, f.stranger]
            return f

        res = Result("h", TICKET, "homes")
        case("neither registry readable refuses to grade",
             (homes(fake(absent, absent), res) is None, res.status), (True, UNREADABLE))

        res = Result("h", TICKET, "homes")
        case("no outsider anywhere refuses to grade",
             (homes(fake(good, absent), res) is None, res.status), (True, UNREADABLE))

        # Both registries as the product actually leaves them. Fixed: the three
        # scratch repos in the scratch home, the outsider alone in the real one.
        fixed_scratch = os.path.join(work, "fixed-scratch.toml")
        with open(fixed_scratch, "w") as handle:
            handle.write('[[repos]]\nid = "probe"\npath = "/w/probe"\n\n'
                         '[[repos]]\nid = "roommate"\npath = "/w/roommate"\n\n'
                         '[[repos]]\nid = "stranger"\npath = "/w/stranger"\n')
        fixed_real = os.path.join(work, "fixed-real.toml")
        with open(fixed_real, "w") as handle:
            handle.write('[[repos]]\nid = "outsider"\npath = "/w/outsider"\n')

        # An outsider and nothing else. Without the guard this grades every id
        # the surface names as stray and FAILs, which is a confident wrong
        # diagnosis: there is no scratch-home repository to be sealed around.
        res = Result("h", TICKET, "homes")
        case("an outsider with no scratch repos refuses to grade",
             (homes(fake(absent, fixed_real), res) is None, res.status),
             (True, UNREADABLE))

        # The unfixed shape: one registry, in the real home, holding everything.
        res = Result("h", TICKET, "homes")
        got = homes(fake(absent, unfixed), res)
        case("the unfixed shape still grounds a verdict",
             (got is not None and got[0] == {"probe", "roommate", "stranger"}
              and got[1] == {"outsider"}),
             True)
        # ...and grading it names the leak rather than shrugging at it.
        unfixed_status, unfixed_detail = _diagnosis(
            {"probe", "roommate", "stranger", "outsider"},
            {"probe", "roommate", "stranger"}, {"outsider"}, "roommate")
        case("the unfixed shape FAILs and names the outsider",
             (unfixed_status, "registered only in the operator's home" in unfixed_detail,
              "outsider" in unfixed_detail),
             (FAIL, True, True))

        # The fixed shape: two registries, the outsider only in the real one.
        res = Result("h", TICKET, "homes")
        got = homes(fake(fixed_scratch, fixed_real), res)
        case("the fixed shape grounds the same verdict",
             (got is not None and got[0] == {"probe", "roommate", "stranger"}
              and got[1] == {"outsider"}),
             True)
        sealed_status, sealed_text = _diagnosis(
            {"probe", "roommate", "stranger"}, {"probe", "roommate", "stranger"},
            {"outsider"}, "roommate")
        case("the fixed shape PASSes on the same grader",
             (sealed_status, "outsider" in sealed_text), (PASS, False))
    finally:
        shutil.rmtree(work, ignore_errors=True)

    bad = [(name, got, want) for name, got, want in cases if got != want]
    for name, got, want in bad:
        print("SELFTEST FAIL %s: got %r, wanted %r" % (name, got, want))
    print("kin-registry-isolation-repro: self-test %d/%d cases"
          % (len(cases) - len(bad), len(cases)))
    return 1 if bad else 0


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
        print("kin-registry-isolation-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command below runs with cwd inside a fixture in a
    # temp directory, and a relative path would resolve against that fixture
    # rather than against the checkout.
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-registry-isolation-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-registry-isolation-repro-")
    suite = None
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        try:
            suite.setup()
        except Exception as error:  # noqa: BLE001 - a fixture that will not build is setup
            print("kin-registry-isolation-repro: fixture setup failed: %s: %s"
                  % (type(error).__name__, error))
            return 3
        results = []
        for check_id, check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(check_id, TICKET, "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, result.ticket, result.status, result.detail))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-registry-isolation-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        if args.json_path:
            # The gate reads this rather than the exit code, because an exit
            # status is one lever with two settings and a check blocked on
            # something outside the change under review needs a third.
            payload = {
                "suite": "registry_home_isolation",
                "ticket": TICKET,
                "label": args.label,
                "kin": kin,
                "results": [
                    {"id": r.id, "ticket": r.ticket, "title": r.title,
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
        # Every daemon this suite started, stopped. A worker left running holds
        # a store open for whatever runs next in the same job.
        if suite is not None:
            for name, repo in suite.repos.items():
                env = suite.real_env if name == "outsider" else suite.env
                run([kin, "daemon", "stop"], cwd=repo, env=env, timeout=180)
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
