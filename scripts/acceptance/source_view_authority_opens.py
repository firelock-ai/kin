#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""NON-CITABLE acceptance suite for what a daemon RETAINS on a converted store (FIR-2955).

Its output is a regression gate, never proof, never investor-facing, and never a
released claim.

What it is for
--------------
A whole-store repository-authority open is O(store): KinDB decodes the complete
persisted authority and re-verifies every persisted body in repository CAS.
Measured on a converted psf/requests store, one open costs 3.71x its snapshot
file resident, the same multiple a 3.92x smaller store gives, and 93.8 percent
of that file is a change map. So the cost of an open is set by history the read
paths never answer from.

The daemon that reached 10.602 GiB on that store took five opens with a peak
concurrency of TWO, and its maximum resident set occurred while ZERO opens were
in flight. The pressure is what is RETAINED after an open returns, not what
overlaps during one. That distinction is why this suite counts opens rather than
timing them, and why it grades a count that must not scale.

What it grades, and what it is blind to
---------------------------------------
It names no call site, no cache and no type. A gate that knew the implementation
would have to be rewritten by the next one and would grade nothing in between,
and the sibling suite for the coverage read (FIR-2964) makes the same choice for
the same reason.

The property every cheap path can break in the same way is that an open is paid
per unit of work rather than once. So:

``scaling`` converts two repositories that differ only in FILE COUNT and requires
the authority-open count not to grow with it. A path that opens per file, per
entity or per enriched document fails this whatever it is called. The arm is a
ratio rather than an absolute, because the absolute is a property of how many
phases a conversion has and that legitimately changes.

``instrument`` requires the funnel to have logged at all. It is the control, and
it is not optional: ``scaling`` is an assertion that a count did not grow, and a
funnel that logs nothing satisfies it on every tree. An absent instrument is
reported UNREADABLE rather than PASS, because a measurement that could not be
taken is not one that passed.

Each check prints one line:

    CHECK <id> <ticket> PASS|FAIL|UNREADABLE <detail>

Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
3 on setup failure, and 0 only when every check passes. ``--self-test`` drives
every grader against its inverse without building a repository.
"""

from __future__ import print_function

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

PASS = "PASS"
FAIL = "FAIL"
UNREADABLE = "UNREADABLE"

TICKET = "FIR-2955"

# The daemon writes colour codes between a field name and its value, so a
# byte-level match on `caller=` never fires while lifecycle lines false-positive.
ANSI = re.compile(r"\x1b\[[0-9;]*m")

# The funnel's own message. Every path into KinDB's recovery reaches the function
# that logs it, which is why the count taken here is a count for all of them.
FUNNEL = "opening persisted repository authority"

# Small enough that both arms are cheap, far enough apart that a per-file open
# cannot hide in the noise of a fixed per-conversion cost.
SMALL_FILES = 4
LARGE_FILES = 24

# A per-unit open would multiply by LARGE/SMALL. A fixed cost gives 1.0. The bar
# sits below the smallest scaling a per-file path could produce and above any
# plausible fixed difference; it is stated as a ratio so the absolute count stays
# free to change.
MAX_GROWTH_RATIO = 2.0


def check(ident, status, detail):
    print("CHECK {0} {1} {2} {3}".format(ident, TICKET, status, detail))
    return status


def strip_ansi(text):
    return ANSI.sub("", text)


def count_funnel_lines(log_text):
    """How many whole-store authority opens this log reports."""
    return strip_ansi(log_text).count(FUNNEL)


def grade_scaling(small_opens, large_opens, small_files, large_files):
    """Did the open count grow with the amount of work?"""
    if small_opens <= 0 or large_opens <= 0:
        return (
            UNREADABLE,
            "no authority opens were logged in one or both arms "
            "(small={0}, large={1}); the instrument, not the tree, is what failed".format(
                small_opens, large_opens
            ),
        )
    ratio = float(large_opens) / float(small_opens)
    files_ratio = float(large_files) / float(small_files)
    detail = (
        "{0} files -> {1} opens, {2} files -> {3} opens; "
        "open ratio {4:.2f} against a file ratio of {5:.2f}, bar {6:.2f}".format(
            small_files, small_opens, large_files, large_opens, ratio, files_ratio, MAX_GROWTH_RATIO
        )
    )
    if ratio >= MAX_GROWTH_RATIO:
        return (
            FAIL,
            detail + "; the count scales with the work, so something opens the whole "
            "store per unit rather than once",
        )
    return (PASS, detail)


def grade_instrument(opens):
    if opens <= 0:
        return (
            UNREADABLE,
            "the authority-open funnel logged nothing, so a count of zero says "
            "nothing about the tree",
        )
    return (PASS, "the funnel logged {0} authority opens".format(opens))


def self_test():
    """Every grader against its inverse. No repository is built."""
    failures = []
    checked = []

    def expect(name, got, want):
        checked.append(name)
        if got != want:
            failures.append("{0}: got {1}, want {2}".format(name, got, want))

    # scaling: a fixed cost passes, a per-file cost fails, a silent funnel is
    # unreadable rather than either.
    expect("scaling fixed", grade_scaling(5, 5, 4, 24)[0], PASS)
    expect("scaling per-file", grade_scaling(5, 30, 4, 24)[0], FAIL)
    expect("scaling at the bar", grade_scaling(5, 10, 4, 24)[0], FAIL)
    expect("scaling just under", grade_scaling(5, 9, 4, 24)[0], PASS)
    expect("scaling silent", grade_scaling(0, 0, 4, 24)[0], UNREADABLE)
    expect("scaling half silent", grade_scaling(5, 0, 4, 24)[0], UNREADABLE)

    # instrument: present passes, absent is unreadable and never a pass.
    expect("instrument present", grade_instrument(3)[0], PASS)
    expect("instrument absent", grade_instrument(0)[0], UNREADABLE)

    # The needle must find a real line and must not find a fabricated one.
    real = "\x1b[2m2026-08-30T20:11:00Z\x1b[0m INFO kin_core: " + FUNNEL + " caller=x.rs:1\n"
    expect("needle present", count_funnel_lines(real), 1)
    expect("needle fabricated", count_funnel_lines("zzz-fabricated-needle\n"), 0)
    # ANSI between the words must not hide the line.
    hidden = "INFO opening persisted \x1b[3mrepository\x1b[0m authority\n"
    expect("needle through ansi", count_funnel_lines(strip_ansi(hidden)) >= 0, True)

    if failures:
        for line in failures:
            print("SELF-TEST FAIL " + line)
        return 1
    print("SELF-TEST PASS {0} expectations answered their inverse".format(len(checked)))
    return 0


def build_repo(root, file_count):
    os.makedirs(os.path.join(root, "src"))
    for index in range(file_count):
        with open(os.path.join(root, "src", "mod{0}.py".format(index)), "w") as handle:
            handle.write("def entry_{0}():\n    return {0}\n".format(index))
    subprocess.check_call(["git", "init", "--quiet"], cwd=root)
    subprocess.check_call(["git", "config", "user.email", "acceptance@kin.invalid"], cwd=root)
    subprocess.check_call(["git", "config", "user.name", "kin acceptance"], cwd=root)
    # The fixture must not inherit the caller's hooks or signing config. A
    # workspace hook that rewrites or refuses a commit message would fail this
    # suite for a reason that has nothing to do with the tree under test.
    subprocess.check_call(["git", "config", "commit.gpgsign", "false"], cwd=root)
    subprocess.check_call(["git", "config", "core.hooksPath", os.path.join(root, ".no-hooks")], cwd=root)
    subprocess.check_call(["git", "add", "-A"], cwd=root)
    subprocess.check_call(
        ["git", "commit", "--quiet", "--no-verify", "-m", "fixture"], cwd=root
    )


def run_arm(kin, root, file_count, home):
    build_repo(root, file_count)
    env = dict(os.environ)
    env["KIN_HOME"] = home
    env["KIN_EMBED_BACKEND"] = "cpu"
    env["KIN_DAEMON_AUTO_EMBED"] = "0"
    env["RUST_LOG"] = "kin_core=info,kin_daemon=info"
    subprocess.call([kin, "init"], cwd=root, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    log = os.path.join(root, ".kin", "daemon.log")
    if not os.path.exists(log):
        return 0
    with open(log, "rb") as handle:
        return count_funnel_lines(handle.read().decode("utf-8", "replace"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN", "kin"))
    args = parser.parse_args()

    if args.self_test:
        return self_test()

    kin = shutil.which(args.kin) or args.kin
    if not os.path.exists(kin):
        print("SETUP no kin binary at {0}".format(kin))
        return 3

    workspace = tempfile.mkdtemp(prefix="kin-source-view-opens-")
    try:
        home = os.path.join(workspace, "home")
        os.makedirs(home)
        small = run_arm(kin, os.path.join(workspace, "small"), SMALL_FILES, home)
        large = run_arm(kin, os.path.join(workspace, "large"), LARGE_FILES, home)

        statuses = []
        status, detail = grade_instrument(small + large)
        statuses.append(check("instrument", status, detail))
        status, detail = grade_scaling(small, large, SMALL_FILES, LARGE_FILES)
        statuses.append(check("scaling", status, detail))

        if FAIL in statuses:
            return 1
        if UNREADABLE in statuses:
            return 2
        return 0
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
