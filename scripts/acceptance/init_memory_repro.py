#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for what a brownfield conversion holds.

Its output is a regression gate, never proof, never investor-facing, and never a
released claim. The citable gates all live in the kin-ecosystem umbrella and
nothing here substitutes for any of them.

What it is for
--------------
A full-history psf/requests conversion measured 11.72 GiB of resident set inside
a 12 GiB container, hitting the cgroup limit 871 times, and the same corpus was
OOM-killed outright on the v0.5.47 candidate once a second store's daemon shared
the box. The cause was structural: a conversion proved its import plan by
rebuilding the whole plan from raw objects and comparing the two, six times over
one init, holding as many as four whole histories at once.

That class is invisible to every functional test in this workspace. A
re-derivation that materializes a second copy of history returns exactly the
same verdict as one that streams it, so nothing fails until a real repository
meets a real memory limit. This suite makes it visible in minutes, on a
synthetic fixture, against the local build.

What it measures, and what it does not
--------------------------------------
Peak resident set of one `kin init` over a synthetic deep history, against a
stated cap. Resident set is the number that decides whether a conversion runs on
a small machine, which is why it is the one asserted here.

RSS is also allocator-dependent and platform-dependent, so the cap is set to
catch a STEP CHANGE and not a trim: another whole copy of history is hundreds of
megabytes at this depth, while ordinary drift is tens. The measured number is
printed on every run, so drift is visible long before it is a failure. For an
allocator-exact figure that moves only when allocation moves, use the live-heap
guard instead:

    cargo test --release -p kin-core --test init_deep_history_heap_ceiling \\
        -- --ignored --nocapture

Each check prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

UNREADABLE is a distinct outcome from FAIL and is never reported as a pass: it
means the probe could not be evaluated, which here means no resident-set figure
could be read at all. A measurement that cannot be taken is not a measurement
that passed. Exit status is 1 when any check FAILs, 2 when none fail but some
are UNREADABLE, 0 only when every check passes, 3 on a setup error.

The binary under test
---------------------
    cargo build --release --locked --bin kin --bin kin-daemon
    python3 scripts/acceptance/init_memory_repro.py --kin target/release/kin

`--kin` may also come from KIN_BIN. A debug binary allocates differently and
will not meet the cap; the cap is a release-build number and the suite says so
rather than guessing which it was handed.
"""

from __future__ import print_function

import argparse
import functools
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile

print = functools.partial(print, flush=True)

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"
TICKET = "FIR-2539"

# Depth is the whole point: the structures this guards scale with commits
# multiplied by tree size, so a shallow fixture cannot price them. These
# numbers admit in about a minute against a release binary.
COMMITS = 256
MODULES = 8
ITEMS_PER_MODULE = 4

# Cap on peak resident set for admitting COMMITS commits, in MiB.
#
# Set from this suite's own falsification rather than from a target: measured
# on the pre-fix commit and on the fix, both release, both on the same host,
# with the two numbers quoted in the pull request that introduced the cap. It
# sits well above the post-fix figure and well below the pre-fix one, because
# what it exists to catch is another whole copy of history coming back, which
# is a step change and not a trim.
PEAK_RSS_CAP_MIB = 700


def tail(text, limit=400):
    """The END of a command's output, which is where its error is."""
    text = (text or "").strip()
    return text if len(text) <= limit else "..." + text[-limit:]


def run(cmd, cwd=None, env=None, timeout=1800):
    proc = subprocess.run(
        cmd, cwd=cwd, env=env, timeout=timeout,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    return proc.returncode, proc.stdout


def maxrss_bytes():
    """Peak resident set of every child reaped so far, in bytes.

    `ru_maxrss` is kilobytes on Linux and bytes on macOS, which is the kind of
    difference that turns a cap into a thousandfold false pass on one platform
    and a thousandfold false failure on the other. Normalising here, once, is
    cheaper than discovering it from a green run.
    """
    raw = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    if raw <= 0:
        return None
    return raw if sys.platform == "darwin" else raw * 1024


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
            for entry in self.asserts:
                if entry["status"] == wanted:
                    return entry["detail"]
        return self.asserts[-1]["detail"] if self.asserts else "no assertion graded"


def grade_peak(peak_bytes, cap_mib):
    """PASS under the cap, FAIL over it, UNREADABLE when nothing was measured.

    Split out as a pure function so `--self-test` can drive it against its own
    inverse without admitting a repository.
    """
    if peak_bytes is None:
        return UNREADABLE, "no resident-set figure could be read for the admission"
    mib = peak_bytes / 1024.0 / 1024.0
    if mib >= cap_mib:
        return FAIL, ("admitting %d commits peaked at %.1f MiB of resident set, at or over "
                      "the %d MiB cap; a phase is holding another copy of history rather "
                      "than streaming it" % (COMMITS, mib, cap_mib))
    return PASS, ("admitting %d commits peaked at %.1f MiB of resident set, under the "
                  "%d MiB cap" % (COMMITS, mib, cap_mib))


class Suite(object):
    def __init__(self, kin, workdir, daemon=None, verbose=False):
        self.kin = kin
        self.workdir = workdir
        self.daemon = daemon
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_DAEMON_DISABLE_LSP"] = "1"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        for leaked in ("KIN_MCP_REPO", "KIN_DIR"):
            self.env.pop(leaked, None)
        if self.daemon:
            self.env["KIN_DAEMON_BIN"] = self.daemon

    def git(self, repo, args):
        env = dict(self.env)
        env.update({
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_AUTHOR_NAME": "Kin Fixture",
            "GIT_AUTHOR_EMAIL": "fixture@firelock.ai",
            "GIT_COMMITTER_NAME": "Kin Fixture",
            "GIT_COMMITTER_EMAIL": "fixture@firelock.ai",
        })
        code, out = run(["git"] + list(args), cwd=repo, env=env)
        if code != 0:
            raise RuntimeError("git %s failed: %s" % (" ".join(args), tail(out)))

    def build_history(self):
        repo = os.path.join(self.workdir, "deep")
        os.makedirs(os.path.join(repo, "src"))
        self.git(repo, ["init", "--initial-branch=main"])
        self.git(repo, ["config", "user.name", "Kin Fixture"])
        self.git(repo, ["config", "user.email", "fixture@firelock.ai"])
        with open(os.path.join(repo, "Cargo.toml"), "w") as handle:
            handle.write("[package]\nname = \"fixture\"\n")
        for commit in range(COMMITS):
            # Every commit rewrites the whole module set, so each carries a full
            # tree delta and a fresh set of entities. A one-file edit per commit
            # would make the trees nearly free to hold, which is the opposite of
            # the shape this guard is about.
            for module in range(MODULES):
                body = []
                for item in range(ITEMS_PER_MODULE):
                    body.append(
                        "pub struct Item%d_%d_%d { pub field: u32 }\n"
                        "impl Item%d_%d_%d {\n"
                        "pub fn build() -> Self { Self { field: %d } }\n"
                        "pub fn read(&self) -> u32 { self.field }\n"
                        "}\n" % (module, item, commit, module, item, commit, commit)
                    )
                with open(os.path.join(repo, "src", "mod_%d.rs" % module), "w") as handle:
                    handle.write("".join(body))
            self.git(repo, ["add", "-A"])
            self.git(repo, ["commit", "-m", "commit %d" % commit])
        return repo


def check_0(suite):
    """Admitting a deep history stays under the resident-set cap."""
    result = Result("0", "deep-history admission stays under the resident-set cap")
    repo = suite.build_history()

    # Read AFTER the fixture is built, so git's own children are already folded
    # into the high-water mark and cannot be mistaken for the admission's.
    before = maxrss_bytes()
    code, out = run([suite.kin, "init", "--no-enrich"], cwd=repo, env=suite.env)
    after = maxrss_bytes()
    if code != 0:
        result.unknown("kin init exited %d, so no admission was measured: %s" % (code, tail(out)))
        return result
    if after is None or (before is not None and after <= before):
        result.unknown("the admission did not move the child resident-set high-water mark, "
                       "so the figure read back is some earlier child's")
        return result

    status, detail = grade_peak(after, PEAK_RSS_CAP_MIB)
    {PASS: result.ok, FAIL: result.bad, UNREADABLE: result.unknown}[status](detail)
    return result


CHECKS = [check_0]


def self_test():
    """Falsify this suite's grader against its own inverse."""
    failures = []
    cap = 100
    cases = [
        ("under the cap passes", 50 * 1024 * 1024, PASS),
        ("at the cap fails", 100 * 1024 * 1024, FAIL),
        ("over the cap fails", 400 * 1024 * 1024, FAIL),
        ("nothing measured is unreadable", None, UNREADABLE),
    ]
    for title, peak, wanted in cases:
        got, detail = grade_peak(peak, cap)
        if got != wanted:
            failures.append("%s: wanted %s, got %s (%s)" % (title, wanted, got, detail))
    # A cap that cannot fail is not a cap: prove the real one rejects a figure
    # the size of the defect this suite exists for.
    got, _ = grade_peak(1176 * 1024 * 1024, PEAK_RSS_CAP_MIB)
    if got != FAIL:
        failures.append("the shipped cap does not reject a pre-fix-sized peak")
    got, _ = grade_peak(515 * 1024 * 1024, PEAK_RSS_CAP_MIB)
    if got != PASS:
        failures.append("the shipped cap rejects a post-fix-sized peak")
    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    print("kin-init-memory-repro self-test: %d case(s), %d failure(s)"
          % (len(cases) + 2, len(failures)))
    return 1 if failures else 0


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
        print("kin-init-memory-repro: no kin binary. Pass --kin or set KIN_BIN.")
        return 3
    # Absolute, because every command below runs with cwd inside a fixture in a
    # temp directory, where a relative path resolves against the fixture.
    kin = os.path.abspath(os.path.expanduser(args.kin))
    if not os.path.isfile(kin) or not os.access(kin, os.X_OK):
        print("kin-init-memory-repro: %s is not an executable file" % kin)
        return 3
    daemon = args.daemon and os.path.abspath(os.path.expanduser(args.daemon))
    if not daemon:
        beside = os.path.join(os.path.dirname(kin), "kin-daemon")
        daemon = beside if os.path.isfile(beside) else None

    workdir = tempfile.mkdtemp(prefix="kin-init-memory-repro-")
    try:
        suite = Suite(kin, workdir, daemon=daemon, verbose=args.verbose)
        results = []
        for check in CHECKS:
            try:
                results.append(check(suite))
            except Exception as error:  # noqa: BLE001 - a crashed probe is UNREADABLE
                result = Result(getattr(check, "__name__", "check"), "probe crashed")
                result.unknown("%s: %s" % (type(error).__name__, error))
                results.append(result)
        for result in results:
            print("CHECK %s %s %s %s" % (result.id, TICKET, result.status, result.detail))
        failed = [r for r in results if r.status == FAIL]
        unreadable = [r for r in results if r.status == UNREADABLE]
        print("kin-init-memory-repro: %d checks, %d pass, %d FAIL, %d UNREADABLE"
              % (len(results), len(results) - len(failed) - len(unreadable),
                 len(failed), len(unreadable)))
        if args.json_path:
            payload = {
                "suite": "init_memory_repro",
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
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
