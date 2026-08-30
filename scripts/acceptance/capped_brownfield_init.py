#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Convert psf/requests inside a memory-capped container and grade the kills.

Why a container
---------------
The other memory suites read `memory.max` through this process's own binding
cgroup, and a hosted runner has no cap, so `Acceptance` has never measured
anything at 16 GB on any runner: every one of them read a ceiling far above the
demand and passed. That is why this class was found by a stranger in a capped
container and by nothing in CI.

So this suite does not read the host's ceiling. It CREATES one, runs the
conversion inside a `docker --memory <cap>` container, and reads
`memory.max`, `memory.peak` and `memory.events` from that container's own
cgroup at the end. A run on a 64 GB host and a run on a 16 GB host therefore
grade the same thing, and the cap is printed beside every result so a reader
never has to infer which was measured.

What it grades
--------------
On a converted psf/requests store at the documented 16 GB minimum, the daemon
serving enrichment must not be killed by the memory limit.

    CHECK capped_init_no_oom_kill FIR-2988 PASS|FAIL|UNREADABLE <detail>
    CHECK capped_init_no_kill_line FIR-2988 PASS|FAIL|UNREADABLE <detail>

Two checks rather than one because they fail differently. The cgroup counter is
the fact; the product's own sentence is what a partner reads. A build that
stopped emitting the sentence while still dying would pass the second alone,
and a build that emitted it spuriously would pass the first alone.

`memory.peak` is reported but NOT graded. On the arm that produced this suite it
read 13.56 GiB against a 16.00 GiB cap, which is 2.44 GiB below the ceiling on a
run that was nonetheless killed by the cgroup's own OOM killer, so peak equal to
max is sufficient evidence of a cap kill and not necessary. The `oom_kill`
counter decides, because only the cgroup's OOM killer increments it.

Cost
----
About twelve minutes: a full clone of psf/requests, a conversion of its whole
history, and the enrichment pass that follows. Too heavy for the per-PR gate, so
it runs behind `--run`, which the preflight's host leg and the stranger both
pass. Without `--run` it prints what it would do and exits 0.

Falsification
-------------
Point `--archive` at a build predating the fix and the first check must FAIL
with `oom_kill 1`. That arm is what produced this suite rather than a thing
invented for it.

Exit status is 1 when any check FAILs, 2 when none fail but some are UNREADABLE,
0 only when every check passes, 3 on a setup error.
"""

from __future__ import print_function

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid

REPO = "https://github.com/psf/requests"
# Pinned so the corpus cannot move underneath the number. This is the revision
# the v0.6.2 stranger's brownfield arm converted.
REVISION = "5460f467b02e49471c0fd6cfc9ca0adab6351f98"
IMAGE_DEFAULT = "kin-stranger:1"
DEFAULT_CAP = "16g"
KILL_SENTENCE = "killed by the memory limit"
GIB = float(1 << 30)


EMITTED = []


def emit(check_id, status, detail):
    """Print one check line and record its status.

    The exit code is computed from this list rather than recomputed from the
    same inputs, because two readings of one fact drift: a check could print
    FAIL while the status arithmetic below read the value differently and
    returned 0. There is one reading and the tally is over it.
    """
    EMITTED.append(status)
    print("CHECK %s FIR-2988 %s %s" % (check_id, status, detail))


def run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def docker(name, script):
    return run(["docker", "exec", name, "bash", "-lc", script])


def read_cgroup(name):
    """The cap and the counters from INSIDE the container, never from the flag.

    A container's limits at the end are not the flags it was created with, and
    a workload can raise them, so the flag is recorded separately and compared
    rather than trusted.
    """
    out = docker(name, "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/memory.peak; "
                       "cat /sys/fs/cgroup/memory.events")
    if out.returncode != 0:
        return None
    lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
    read = {}
    for line in lines:
        parts = line.split()
        if len(parts) == 1 and parts[0].isdigit():
            read.setdefault("_numbers", []).append(int(parts[0]))
        elif len(parts) == 2 and parts[1].lstrip("-").isdigit():
            read[parts[0]] = int(parts[1])
    numbers = read.get("_numbers", [])
    if len(numbers) >= 2:
        read["memory.max"], read["memory.peak"] = numbers[0], numbers[1]
    return read


def main(argv):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", action="store_true",
                        help="actually run the twelve-minute conversion")
    parser.add_argument("--archive", default=os.environ.get("KIN_ARCHIVE"),
                        help="a kin-linux-*.tar.gz whose kin and kin-daemon are installed")
    parser.add_argument("--cap", default=os.environ.get("KIN_CAPPED_INIT_CAP", DEFAULT_CAP))
    parser.add_argument("--image", default=os.environ.get("KIN_CAPPED_INIT_IMAGE", IMAGE_DEFAULT))
    parser.add_argument("--keep", action="store_true",
                        help="leave the container after the run (default: leave it)")
    parser.add_argument("--json", dest="json_path", default=None)
    args = parser.parse_args(argv)

    if not args.run:
        print("capped_brownfield_init: not run. Pass --run to spend about twelve minutes "
              "converting psf/requests at %s inside a docker --memory %s container."
              % (REVISION[:12], args.cap))
        return 0
    if not args.archive or not os.path.isfile(args.archive):
        print("capped_brownfield_init: SETUP --archive must name a kin release archive", file=sys.stderr)
        return 3
    if run(["docker", "info"]).returncode != 0:
        print("capped_brownfield_init: SETUP docker is not available on this host", file=sys.stderr)
        return 3

    name = "kin-capped-init-%s" % uuid.uuid4().hex[:10]
    archive_dir = os.path.dirname(os.path.abspath(args.archive))
    archive_base = os.path.basename(args.archive)
    # Never --rm: it deletes the only record of why a capped run died, and exit
    # 137 cannot separate an OOM kill from any other kill.
    started = run(["docker", "run", "-d", "--name", name,
                   "--memory", args.cap, "--cpus", "5",
                   "-v", "%s:/dist:ro" % archive_dir,
                   args.image, "sleep", "infinity"])
    if started.returncode != 0:
        print("capped_brownfield_init: SETUP container would not start: %s"
              % started.stderr.strip(), file=sys.stderr)
        return 3

    result = {"cap_flag": args.cap, "revision": REVISION, "container": name}
    try:
        cap = read_cgroup(name)
        if not cap or "memory.max" not in cap:
            emit("capped_init_no_oom_kill", "UNREADABLE",
                 "the container's cgroup could not be read, so no cap was measured")
            emit("capped_init_no_kill_line", "UNREADABLE", "no run was made")
            return 2
        result["memory.max_at_start"] = cap["memory.max"]
        print("cap read from the container's cgroup: %d bytes (%.2f GiB), flag was %s"
              % (cap["memory.max"], cap["memory.max"] / GIB, args.cap))

        install = docker(name,
            "set -e; mkdir -p /work/dist && cp /dist/%s /work/dist/ && cd /work/dist && "
            "tar xzf %s && d=$(dirname $(find /work/dist -name kin -type f | head -1)) && "
            "mkdir -p /work/bin && cp $d/kin $d/kin-daemon /work/bin/ && "
            "chmod +x /work/bin/kin /work/bin/kin-daemon && ls -l /work/bin"
            % (archive_base, archive_base))
        if install.returncode != 0 or not docker(name, "test -x /work/bin/kin-daemon").returncode == 0:
            # Without kin-daemon beside kin, init SKIPS enrichment and exits 0
            # with a plausible peak, which is a null result wearing a pass.
            emit("capped_init_no_oom_kill", "UNREADABLE",
                 "kin-daemon is not beside kin in the container, so enrichment would be skipped "
                 "and this run would measure nothing")
            emit("capped_init_no_kill_line", "UNREADABLE", "no run was made")
            return 2
        version = docker(name, "/work/bin/kin --version").stdout.strip()
        result["kin_version"] = version
        print("binary under test: %s" % version)

        clone = docker(name, "rm -rf /work/req && git clone -q %s /work/req && "
                             "git -C /work/req checkout -q %s && git -C /work/req rev-parse HEAD"
                             % (REPO, REVISION))
        if clone.returncode != 0 or REVISION not in clone.stdout:
            emit("capped_init_no_oom_kill", "UNREADABLE",
                 "the corpus could not be cloned at %s" % REVISION[:12])
            emit("capped_init_no_kill_line", "UNREADABLE", "no run was made")
            return 2

        began = time.time()
        init = docker(name, "cd /work/req && timeout 2700 /work/bin/kin init 2>&1")
        result["init_rc"] = init.returncode
        result["init_wall_s"] = round(time.time() - began, 1)
        print("init rc=%d wall=%ss" % (init.returncode, result["init_wall_s"]))

        end = read_cgroup(name) or {}
        result.update({k: v for k, v in end.items() if not k.startswith("_")})
        peak = end.get("memory.peak")
        oom_kill = end.get("oom_kill")
        if peak is not None:
            print("memory.peak %d (%.2f GiB) against memory.max %d (%.2f GiB), reported not graded"
                  % (peak, peak / GIB, end.get("memory.max", 0), end.get("memory.max", 0) / GIB))

        if oom_kill is None:
            emit("capped_init_no_oom_kill", "UNREADABLE",
                 "memory.events carried no oom_kill field, so no kill count was read")
        elif oom_kill == 0:
            emit("capped_init_no_oom_kill", "PASS",
                 "oom_kill 0 under a %.2f GiB cap read from the cgroup" % (end.get("memory.max", 0) / GIB))
        else:
            emit("capped_init_no_oom_kill", "FAIL",
                 "oom_kill %d under a %.2f GiB cap read from the cgroup; peak %.2f GiB"
                 % (oom_kill, end.get("memory.max", 0) / GIB, (peak or 0) / GIB))

        text = init.stdout or ""
        if not text.strip():
            emit("capped_init_no_kill_line", "UNREADABLE", "init produced no output to read")
        elif KILL_SENTENCE in text:
            line = next((l.strip() for l in text.splitlines() if KILL_SENTENCE in l), KILL_SENTENCE)
            emit("capped_init_no_kill_line", "FAIL", line[:240])
        else:
            emit("capped_init_no_kill_line", "PASS",
                 "the product reported no daemon killed by the memory limit")
        result["init_tail"] = text[-4000:]
    finally:
        if args.json_path:
            with open(args.json_path, "w") as handle:
                json.dump(result, handle, indent=2, sort_keys=True)
        print("container %s left in place; remove it yourself once its evidence is read" % name)

    # Refuse a tally over the wrong number of checks. A suite that emitted one
    # line grades half of what it claims, and its exit code would not say so.
    if len(EMITTED) != 2:
        print("capped_brownfield_init: SETUP emitted %d check lines, expected 2"
              % len(EMITTED), file=sys.stderr)
        return 3
    if "FAIL" in EMITTED:
        return 1
    if "UNREADABLE" in EMITTED:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
