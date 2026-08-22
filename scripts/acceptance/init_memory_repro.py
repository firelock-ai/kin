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
It drives the live-heap guard in `crates/kin-core/tests/` and grades what that
guard prints. Live heap, through a counting global allocator, moves when and
only when the code allocates differently; resident set keeps counting pages that
were freed but not returned, so it is reproducible only within one allocator on
one platform.

Resident set was tried first and rejected on evidence, which is worth recording
because it looked like the obvious measurement. On this fixture the base commit
reports 1253.5 MiB of peak RSS and the fix reports 1324.5 MiB, so RSS ranks the
fix WORSE. Inside a 12 GiB container both builds report `memory.peak` exactly
equal to `memory.max`, so there the number is the ceiling rather than the demand.
A cap over either figure would have been a check that cannot fail, or worse, one
that fails the wrong way.

The graded figure is what proof 1 adds to the running peak. That phase
revalidates the whole import plan and keeps nothing, so anything it adds is a
second copy of history built to check the first, which is exactly the defect.
The total peak is graded too, as a coarse backstop: it is normally set by the
bootstrap transaction rather than by any proof, so it does NOT move when a proof
stops copying, and it must not be read as the class gate.

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
import re
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

# The in-tree guard this suite drives, and how long it may take. The build
# dominates; the admission itself is a couple of minutes.
GUARD_TEST = "init_deep_history_heap_ceiling"
GUARD_TIMEOUT_S = 3600


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


PROOF_LINE = re.compile(
    r"kin\.init\.source_proof_staged added (\d+) bytes to the peak, ceiling (\d+) MiB"
)
TOTAL_LINE = re.compile(
    r"peak live heap admitting (\d+) commits: (\d+) bytes .*backstop (\d+) MiB"
)


def read_guard_output(text):
    """Pull the two graded figures out of the guard's own printed lines.

    Returns (proof_bytes, proof_cap_mib, total_bytes, total_cap_mib), with None
    for anything the output did not carry. A missing figure is UNREADABLE
    downstream and never a pass: a guard that printed nothing measured nothing.
    """
    proof = PROOF_LINE.search(text or "")
    total = TOTAL_LINE.search(text or "")
    return (
        int(proof.group(1)) if proof else None,
        int(proof.group(2)) if proof else None,
        int(total.group(2)) if total else None,
        int(total.group(3)) if total else None,
    )


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


def grade_bytes(measured, cap_mib, what):
    """PASS under the cap, FAIL at or over it, UNREADABLE when nothing was read.

    Pure, so `--self-test` can drive it against its own inverse without
    admitting a repository. An absent figure is never a pass: a guard that
    printed no number measured nothing, and that is a different fact from a
    number under the cap.
    """
    if measured is None:
        return UNREADABLE, "the guard printed no %s figure, so nothing was graded" % what
    if cap_mib is None:
        return UNREADABLE, "the guard printed no ceiling for %s, so nothing was graded" % what
    mib = measured / 1024.0 / 1024.0
    if mib >= cap_mib:
        return FAIL, ("%s is %.1f MiB, at or over the %d MiB ceiling" % (what, mib, cap_mib))
    return PASS, ("%s is %.1f MiB, under the %d MiB ceiling" % (what, mib, cap_mib))


class Suite(object):
    """Runs the in-tree live-heap guard against the checkout under test.

    Deliberately thin. The fixture, the measurement and the ceilings all live in
    `crates/kin-core/tests/init_deep_history_heap_ceiling.rs`, beside the
    allocator that does the counting, so there is one definition of what the
    guard measures rather than a Rust one and a Python one drifting apart.
    """

    def __init__(self, repo_root, workdir, verbose=False):
        self.repo_root = repo_root
        self.workdir = workdir
        self.verbose = verbose
        self.env = dict(os.environ)
        self.env["KIN_HOME"] = os.path.join(workdir, "kin-home")
        self.env["KIN_DAEMON_AUTO_EMBED"] = "0"
        self.env["KIN_DAEMON_DISABLE_LSP"] = "1"
        self.env["KIN_EMBED_BACKEND"] = "cpu"
        self.env["KIN_VFS_DISABLE"] = "1"
        for leaked in ("KIN_MCP_REPO", "KIN_DIR"):
            self.env.pop(leaked, None)
        self._guard = None

    def guard_output(self):
        """Run the guard once and reuse it, so both checks grade one run."""
        if self._guard is None:
            self._guard = self._run_guard()
        return self._guard

    def _run_guard(self):
        # Release, because the ceilings are release numbers: optimization
        # changes which allocations happen, not merely how fast they run, so a
        # debug figure is not comparable and must not be graded against them.
        return run([
            "cargo", "test", "--release", "--locked",
            "-p", "kin-core", "--test", GUARD_TEST,
            "--", "--ignored", "--nocapture",
        ], cwd=self.repo_root, env=self.env, timeout=GUARD_TIMEOUT_S)


def check_0(suite):
    """Proving the import plan does not cost a copy of it."""
    result = Result("0", "proof 1 does not allocate a second history")
    code, out = suite.guard_output()
    proof, proof_cap, total, total_cap = read_guard_output(out)
    if proof is None and code != 0 and total is None:
        result.unknown("the guard produced no figures and exited %d: %s" % (code, tail(out)))
        return result
    status, detail = grade_bytes(proof, proof_cap, "proof 1 peak growth")
    {PASS: result.ok, FAIL: result.bad, UNREADABLE: result.unknown}[status](detail)
    return result


def check_1(suite):
    """Total peak live heap stays under its coarse backstop."""
    result = Result("1", "total admission peak stays under its backstop")
    code, out = suite.guard_output()
    _, _, total, total_cap = read_guard_output(out)
    if total is None and code != 0:
        result.unknown("the guard produced no total and exited %d: %s" % (code, tail(out)))
        return result
    status, detail = grade_bytes(total, total_cap, "total peak live heap")
    {PASS: result.ok, FAIL: result.bad, UNREADABLE: result.unknown}[status](detail)
    return result


CHECKS = [check_0, check_1]


def self_test():
    """Falsify this suite's graders against their own inverses."""
    failures = []
    cases = [
        ("under the ceiling passes", 50 * 1024 * 1024, 100, PASS),
        ("at the ceiling fails", 100 * 1024 * 1024, 100, FAIL),
        ("over the ceiling fails", 400 * 1024 * 1024, 100, FAIL),
        ("nothing measured is unreadable", None, 100, UNREADABLE),
        ("no ceiling is unreadable", 1, None, UNREADABLE),
    ]
    for title, measured, cap, wanted in cases:
        got, detail = grade_bytes(measured, cap, "probe")
        if got != wanted:
            failures.append("%s: wanted %s, got %s (%s)" % (title, wanted, got, detail))

    # The parser is the other half that can silently pass. Drive it against the
    # guard's real output shape, and against output that carries no figures at
    # all, which is what a crashed or renamed guard produces.
    good = ("peak live heap admitting 256 commits: 1043605740 bytes (995.3 MiB), "
            "backstop 1400 MiB\n"
            "kin.init.source_proof_staged added 0 bytes to the peak, ceiling 16 MiB\n")
    proof, proof_cap, total, total_cap = read_guard_output(good)
    if (proof, proof_cap, total, total_cap) != (0, 16, 1043605740, 1400):
        failures.append("parser misread the guard's own output: %r"
                        % ((proof, proof_cap, total, total_cap),))
    if read_guard_output("error: could not compile") != (None, None, None, None):
        failures.append("parser invented figures from output that carries none")
    if read_guard_output("") != (None, None, None, None):
        failures.append("parser invented figures from empty output")

    # A ceiling that cannot reject the defect is not a ceiling. Drive the real
    # pre-fix figure through the real pre-fix ceiling.
    got, _ = grade_bytes(88146432, 16, "proof 1 peak growth")
    if got != FAIL:
        failures.append("the shipped proof ceiling does not reject the pre-fix figure")
    got, _ = grade_bytes(0, 16, "proof 1 peak growth")
    if got != PASS:
        failures.append("the shipped proof ceiling rejects the post-fix figure")

    for failure in failures:
        print("SELFTEST FAIL %s" % failure)
    print("kin-init-memory-repro self-test: %d case(s), %d failure(s)"
          % (len(cases) + 5, len(failures)))
    return 1 if failures else 0


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", default=None,
                        help="the kin checkout under test (default: this file's repository)")
    parser.add_argument("--kin", default=None,
                        help="accepted and ignored; the guard builds from the checkout")
    parser.add_argument("--daemon", default=None,
                        help="accepted and ignored; the guard builds from the checkout")
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

    repo_root = args.repo_root or os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    repo_root = os.path.abspath(os.path.expanduser(repo_root))
    if not os.path.isfile(os.path.join(repo_root, "Cargo.toml")):
        print("kin-init-memory-repro: %s is not a cargo workspace root" % repo_root)
        return 3

    workdir = tempfile.mkdtemp(prefix="kin-init-memory-repro-")
    try:
        suite = Suite(repo_root, workdir, verbose=args.verbose)
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
                "repo_root": repo_root,
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
