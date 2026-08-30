#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Grade whether a missing language server reaches the WARNING line, with a size.

What this class is
------------------
A missing or stale language server does not shrink what the graph knows exists.
It shrinks what the graph knows about how those things relate. Measured on a
five-file Python corpus, one arm with pyright reachable and one without, on
kin 0.6.3 at bf8453fad:

    entities                     12   both arms, identical
    entity-to-entity relations   13   without a server
                                 29   with one
    UsesType edges                0   without a server
                                 11   with one

So a whole relation kind is absent without a server, and a status page that
reads clean over that is a false all-clear. The stranger who found this
(FIR-2777) saw 99 relations become 354 on a restart that let the daemon see
pyright, which is the same effect at a different size.

Why the effect is not the number reported
-----------------------------------------
Those are DELTAS obtained by running the system twice. At runtime kin has one
of those runs. A warning saying "about 16 relations are missing" would be
extrapolating from a measurement it never took, wrong by an unknown amount on
any repository unlike the corpus. So the warning counts what IS AFFECTED, the
files in languages with no server, a number the coverage line already computes.

What it grades

    CHECK lsp_gap_reaches_warning_line FIR-2777 PASS|FAIL|UNREADABLE <detail>
    CHECK lsp_gap_names_affected_count FIR-2777 PASS|FAIL|UNREADABLE <detail>
    CHECK lsp_present_leaves_line_quiet FIR-2777 PASS|FAIL|UNREADABLE <detail>

Three rather than one because they fail differently, and the middle one is the
whole point. Demoting the sentence back under the coverage section reds the
first alone. Keeping the sentence on the warning line but dropping the count
reds the second alone. A build that warned when a server WAS present would red
the third alone.

Arm identity
------------
Neither arm's identity rests on silence. The no-server arm must carry the
product's own "no language server found" sentence; the server arm must carry a
server-produced relation kind that the other arm lacks entirely. An absence has
producers (a daemon that died, a corpus that parsed to nothing), and a run where
nothing happened would otherwise read as a correctly degraded arm.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TICKET = "FIR-2777"

CORPUS = {
    "pkg/__init__.py": "",
    "pkg/models.py": (
        "class User:\n"
        "    def __init__(self, name: str) -> None:\n"
        "        self.name = name\n\n"
        "    def greet(self) -> str:\n"
        '        return f"hello {self.name}"\n'
    ),
    "pkg/service.py": (
        "from pkg.models import User\n\n\n"
        "def make_user(name: str) -> User:\n"
        "    return User(name)\n\n\n"
        "def greet_user(user: User) -> str:\n"
        "    return user.greet()\n"
    ),
    "pkg/handlers.py": (
        "from pkg.service import greet_user, make_user\n\n\n"
        "def handle(name: str) -> str:\n"
        "    return greet_user(make_user(name))\n"
    ),
    "main.py": (
        "from pkg.handlers import handle\n\n\n"
        "def main() -> None:\n"
        '    print(handle("world"))\n'
    ),
}


def warning_lines(text):
    """The warning line and nothing else.

    Scoped deliberately: the same sentence appears indented under the coverage
    section, and a grader that searched the whole page could not tell a promoted
    warning from the detail that was already there.
    """
    return [line for line in text.splitlines() if line.startswith("⚠")]


def gap_reaches_warning_line(text):
    return any("no language server for" in line for line in warning_lines(text))


def gap_names_affected_count(text):
    import re

    for line in warning_lines(text):
        if "no language server for" not in line:
            continue
        if re.search(r"\(\d+ files?\)", line):
            return True
    return False


def line_is_quiet(text):
    return not any("no language server for" in line for line in warning_lines(text))


def arm_is_the_no_server_arm(text):
    return "no language server found" in text


def arm_is_the_server_arm(text):
    return "UsesType" in text and "no language server found" not in text


GRADERS = {
    "gap_reaches_warning_line": gap_reaches_warning_line,
    "gap_names_affected_count": gap_names_affected_count,
    "line_is_quiet": line_is_quiet,
    "arm_is_the_no_server_arm": arm_is_the_no_server_arm,
    "arm_is_the_server_arm": arm_is_the_server_arm,
}

# The shapes each grader must separate. The second and third are the two
# falsifications this suite exists to survive: demote the sentence, and drop the
# count while keeping the sentence. Each must red exactly one grader.
PROMOTED = (
    "Reference edge coverage (resolved edges / parsed sites):\n"
    "  python: 5 files, calls 5/7 (71%), imports 3/3 (100%), cross-file 11, intra-file 0 [partial]\n"
    "  cross-file reference and override edges unavailable for python: no language server found\n"
    "⚠ no language server for python (5 files); cross-file reference and override edges are "
    "absent for those files, so this graph is incomplete rather than clean\n"
    "⚠ 24 embeddings are still pending\n"
)
DEMOTED = (
    "Reference edge coverage (resolved edges / parsed sites):\n"
    "  python: 5 files, calls 5/7 (71%), imports 3/3 (100%), cross-file 11, intra-file 0 [partial]\n"
    "  cross-file reference and override edges unavailable for python: no language server found\n"
    "⚠ 24 embeddings are still pending\n"
)
NO_COUNT = (
    "  cross-file reference and override edges unavailable for python: no language server found\n"
    "⚠ no language server for python; cross-file reference and override edges are absent, so "
    "this graph is incomplete rather than clean\n"
)
SERVER_PRESENT = (
    "Entity-to-entity relation kinds: UsesType: 11, Calls: 6, References: 6, Imports: 4\n"
    "  python: 5 files, calls 6/7 (85%), imports 3/3 (100%), cross-file 15, intra-file 1 [partial]\n"
    "⚠ 24 embeddings are still pending\n"
)


def self_test():
    """Falsify every grader against the input that must flip it.

    A grader that cannot separate its two cases reports a clean product on a
    broken one. The demoted and no-count shapes are the mutations this suite is
    written to catch, and each must red exactly one grader rather than all of
    them, or a mutation is being caught by the wrong assertion.
    """
    cases = [
        ("gap_reaches_warning_line", True, PROMOTED),
        # The mutation that puts the sentence back under the coverage section.
        # The prose is still on the page, which is why a whole-page search
        # cannot grade this and the grader is scoped to warning lines.
        ("gap_reaches_warning_line", False, DEMOTED),
        ("gap_reaches_warning_line", True, NO_COUNT),
        ("gap_reaches_warning_line", False, SERVER_PRESENT),
        ("gap_names_affected_count", True, PROMOTED),
        # The mutation that keeps the warning and drops the size. It must red
        # the count grader ALONE, which is why the case above asserts the
        # warning-line grader still passes on this same text.
        ("gap_names_affected_count", False, NO_COUNT),
        ("gap_names_affected_count", False, DEMOTED),
        ("line_is_quiet", True, SERVER_PRESENT),
        ("line_is_quiet", False, PROMOTED),
        ("line_is_quiet", True, DEMOTED),
        ("arm_is_the_no_server_arm", True, PROMOTED),
        ("arm_is_the_no_server_arm", False, SERVER_PRESENT),
        ("arm_is_the_server_arm", True, SERVER_PRESENT),
        ("arm_is_the_server_arm", False, PROMOTED),
    ]
    failures = []
    for name, want, text in cases:
        got = GRADERS[name](text)
        if got != want:
            failures.append("%s(...) = %s, wanted %s" % (name, got, want))
    if failures:
        for line in failures:
            print("SELF-TEST FAIL %s" % line)
        return 1
    print("SELF-TEST PASS %d grader cases" % len(cases))
    return 0


def build_corpus(root):
    for rel, body in CORPUS.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    hooks = root.parent / "nohooks"
    hooks.mkdir(exist_ok=True)
    for args in (
        ["init", "-q", "--initial-branch=main"],
        ["config", "user.email", "acceptance@example.invalid"],
        ["config", "user.name", "acceptance"],
        ["config", "core.hooksPath", str(hooks)],
        ["add", "-A"],
        ["commit", "-q", "-m", "corpus"],
    ):
        subprocess.run(["git", "-C", str(root)] + args, check=True)


def run_arm(kin, tmp, name, path_value):
    home = tmp / ("home-" + name)
    work = tmp / ("work-" + name)
    home.mkdir()
    build_corpus(work)
    env = {
        "HOME": str(home),
        "KIN_HOME": str(home),
        "PATH": path_value,
        "KIN_EMBED_BACKEND": "cpu",
        "TERM": "dumb",
    }
    subprocess.run([kin, "init", "."], cwd=str(work), env=env,
                   capture_output=True, text=True)
    got = subprocess.run([kin, "graph", "status"], cwd=str(work), env=env,
                         capture_output=True, text=True)
    return got.stdout + got.stderr


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kin", default=os.environ.get("KIN_BIN"))
    parser.add_argument("--self-test", action="store_true", dest="self_test")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    if not args.kin or not Path(args.kin).exists():
        print("language-server-warning: no kin binary. Pass --kin or set KIN_BIN.")
        return 2
    kin = str(Path(args.kin).resolve())

    server = shutil.which("pyright-langserver") or shutil.which("pyright")
    results = []
    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw)
        a = run_arm(kin, tmp, "A", "/usr/bin:/bin")
        if not arm_is_the_no_server_arm(a):
            results.append(("lsp_gap_reaches_warning_line", "UNREADABLE",
                            "arm A carries no 'no language server found' sentence, so it is not "
                            "the no-server arm and nothing about it can be graded"))
            results.append(("lsp_gap_names_affected_count", "UNREADABLE", "arm A unidentified"))
        else:
            results.append((
                "lsp_gap_reaches_warning_line",
                "PASS" if gap_reaches_warning_line(a) else "FAIL",
                "warning lines: %s" % (warning_lines(a) or "none"),
            ))
            results.append((
                "lsp_gap_names_affected_count",
                "PASS" if gap_names_affected_count(a) else "FAIL",
                "the warning must carry the affected file count, never an estimate",
            ))

        if not server:
            results.append(("lsp_present_leaves_line_quiet", "UNREADABLE",
                            "no pyright on this host, so the server arm cannot be built"))
        else:
            server_dir = str(Path(server).parent)
            b = run_arm(kin, tmp, "B", server_dir + ":/usr/bin:/bin")
            if not arm_is_the_server_arm(b):
                results.append(("lsp_present_leaves_line_quiet", "UNREADABLE",
                                "arm B shows no server-produced relation kind, so it is not the "
                                "server arm"))
            else:
                results.append((
                    "lsp_present_leaves_line_quiet",
                    "PASS" if line_is_quiet(b) else "FAIL",
                    "a graph with a server must not carry the gap warning",
                ))

    failed = 0
    for check_id, status, detail in results:
        print("CHECK %s %s %s %s" % (check_id, TICKET, status, detail))
        if status != "PASS":
            failed += 1
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
