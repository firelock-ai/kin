#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Falsify check-store-size-figures.py against mutants of the real page.

Every probe below breaks docs/store-size.md one way and requires the guard to
fail NAMING THE RIGHT RULE. A probe that goes red for some other reason is
recorded as a failure here, because a guard that refuses everything is not a
guard, it is a wish, and it looks identical to a working one from the outside.

Two controls run first and must PASS, and they are the reason this file exists
rather than a comment claiming the guard works:

  [control 1] the real page, unmutated, must be clean. A guard that rejects the
              page it ships beside would be reverted within a day, and every
              probe below would still "pass".

  [control 2] the du-side total is moved further from the walk-side total, with
              the parts and shares kept self-consistent. The guard must stay
              GREEN. This is the design property under test: it never reconciles
              a du figure against a walk figure, because there is no conversion
              between allocated blocks and logical bytes, and a human trying to
              reconcile them by eye is what put a wrong number on that page for
              a month. A guard that went red here would be doing the very thing
              this one refuses to do.

Usage: falsify-store-size-figures.py
Exit 0 when every control passed and every probe was refused by name.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GUARD = REPO_ROOT / "scripts" / "check-store-size-figures.py"
PAGE = REPO_ROOT / "docs" / "store-size.md"


def run_guard(page: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(GUARD), "--page", str(page)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode, result.stdout + result.stderr


def rules_fired(output: str) -> set[str]:
    fired = set()
    for line in output.splitlines():
        marker = "store-size: ["
        if line.startswith(marker):
            fired.add(line[len(marker) : line.index("]")])
    return fired


def mutate(text: str, old: str, new: str) -> str:
    count = text.count(old)
    if count != 1:
        raise SystemExit(
            f"falsify: the anchor {old!r} appears {count} time(s) in the page, so this "
            "probe would plant something other than what it describes. Re-anchor it "
            "against the current page rather than loosening the count."
        )
    return text.replace(old, new)


# Each probe is (label, old, new, the rule that must fire).
#
# The stamp anchors are written out in full rather than pattern-matched: a probe
# whose anchor has drifted must stop this script, not silently plant nothing and
# report that the guard let it through.
PROBES: list[tuple[str, str, str, str]] = [
    (
        "the ripgrep row loses its version and date",
        "| 122.7x | v0.7.2, 2026-09-07 |",
        "| 122.7x |  |",
        "V2",
    ),
    (
        "the ripgrep row is stamped with a version but no date",
        "| 122.7x | v0.7.2, 2026-09-07 |",
        "| 122.7x | v0.7.2 |",
        "V2",
    ),
    (
        "the ripgrep row is stamped with a date but no version",
        "| 122.7x | v0.7.2, 2026-09-07 |",
        "| 122.7x | 2026-09-07 |",
        "V2",
    ),
    (
        "a row invents its own excuse instead of a stamp",
        "| 122.7x | v0.7.2, 2026-09-07 |",
        "| 122.7x | current |",
        "V2",
    ),
    (
        "the Measured table loses its stamp column",
        "| Ratio | Version, date |",
        "| Ratio |",
        "V1",
    ),
    (
        "the breakdown table's introducing paragraph loses its stamp",
        "ripgrep at 2,261 commits under v0.7.2 (measured 2026-09-07 at `e89fff89`),",
        "ripgrep at 2,261 commits,",
        "V3",
    ),
    (
        "a prose paragraph states a size with no stamp",
        "here (v0.7.2, 2026-09-07), above the 703.9 MiB",
        "here, above the 703.9 MiB",
        "V4",
    ),
    (
        "the breakdown table stops declaring how it was measured",
        "| Part of `.kin/` | Size (by `du`) | Share |",
        "| Part of `.kin/` | Size | Share |",
        "M1",
    ),
    (
        "the Measured table stops declaring how it was measured",
        "Measured with the walk described above,",
        "Measured on stores as they stand,",
        "M1",
    ),
    (
        "the breakdown loses the total that makes its parts checkable",
        "| total (by `du`) | 754.2 MiB | 100% |\n",
        "",
        "M2",
    ),
    (
        "a breakdown part no longer sums to the table's own total",
        "| `kindb/<repo>/snapshots` (the graph snapshot) | 592.9 MiB | 78.6% |",
        "| `kindb/<repo>/snapshots` (the graph snapshot) | 492.9 MiB | 78.6% |",
        "M2",
    ),
    (
        "a breakdown size becomes a bound nothing can add",
        "| everything else | about 7 MiB | 1.0% |",
        "| everything else | under 8 MiB | 1.0% |",
        "M2",
    ),
    (
        "a breakdown share stops reconciling against that table's own total",
        "| `kindb/<repo>/source-blobs` (admitted bodies) | 154.0 MiB | 20.4% |",
        "| `kindb/<repo>/source-blobs` (admitted bodies) | 154.0 MiB | 30.4% |",
        "M3",
    ),
    (
        "a share becomes a word instead of a percentage",
        "| everything else | about 7 MiB | 1.0% |",
        "| everything else | about 7 MiB | rounding |",
        "M3",
    ),
    (
        "the paragraph naming both methods together is deleted",
        "This breakdown is measured by `du`, which counts allocated disk blocks rather\n"
        "than the logical file bytes this page's own walk sums, so it totals 754.2 MiB\n"
        "here (v0.7.2, 2026-09-07), above the 703.9 MiB `kin init` itself prints. The\n"
        "two methods measure different things and are not meant to be added across\n"
        "columns; a table like this one, left unlabeled, is what put a wrong number on\n"
        "this page the first time.\n\n",
        "",
        "M4",
    ),
    (
        "a third table publishes sizes under rules nobody declared",
        "## Where to see it\n",
        "## Another store\n\n"
        "| Thing | Size |\n"
        "| --- | --- |\n"
        "| some other store | 12.5 MiB |\n\n"
        "## Where to see it\n",
        "P1",
    ),
]

# The parts and shares move together so the du side stays self-consistent while
# its total moves 6 MiB further from the walk-side 703.9 MiB the page also
# prints. Nothing here is a claim about any real store; it exists to prove the
# guard does not compare across methods.
CONTROL_CROSS_METHOD: list[tuple[str, str]] = [
    (
        "| `kindb/<repo>/snapshots` (the graph snapshot) | 592.9 MiB | 78.6% |",
        "| `kindb/<repo>/snapshots` (the graph snapshot) | 592.9 MiB | 78.0% |",
    ),
    (
        "| `kindb/<repo>/source-blobs` (admitted bodies) | 154.0 MiB | 20.4% |",
        "| `kindb/<repo>/source-blobs` (admitted bodies) | 154.0 MiB | 20.3% |",
    ),
    (
        "| everything else | about 7 MiB | 1.0% |",
        "| everything else | about 13 MiB | 1.7% |",
    ),
    (
        "| total (by `du`) | 754.2 MiB | 100% |",
        "| total (by `du`) | 760.2 MiB | 100% |",
    ),
]


def main() -> int:
    if not PAGE.is_file():
        print(f"falsify: {PAGE} is not a file", file=sys.stderr)
        return 1
    original = PAGE.read_text(encoding="utf-8")
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="store-size-falsify-") as directory:
        scratch = Path(directory) / "store-size.md"

        scratch.write_text(original, encoding="utf-8")
        code, output = run_guard(scratch)
        if code == 0:
            print("falsify: [control 1/2] the real page is clean: PASS")
        else:
            failures.append("control 1: the real page does not pass its own guard")
            print("falsify: [control 1/2] the real page is clean: FAIL")
            print(output)

        moved = original
        for old, new in CONTROL_CROSS_METHOD:
            moved = mutate(moved, old, new)
        scratch.write_text(moved, encoding="utf-8")
        code, output = run_guard(scratch)
        if code == 0:
            print(
                "falsify: [control 2/2] a self-consistent du total 6 MiB further from "
                "the walk total stays clean: PASS"
            )
        else:
            failures.append(
                "control 2: the guard went red comparing a du figure against a walk "
                f"figure, which is the mistake it exists to refuse. Rules: "
                f"{sorted(rules_fired(output))}"
            )
            print("falsify: [control 2/2] cross-method refusal: FAIL")
            print(output)

        for index, (label, old, new, expected) in enumerate(PROBES, start=1):
            scratch.write_text(mutate(original, old, new), encoding="utf-8")
            code, output = run_guard(scratch)
            fired = rules_fired(output)
            if code == 0:
                failures.append(f"probe {index} ({label}) was let through")
                print(f"falsify: [{index}/{len(PROBES)}] {label}: LET THROUGH")
            elif expected not in fired:
                failures.append(
                    f"probe {index} ({label}) went red on {sorted(fired)} rather than "
                    f"{expected}, so the guard refused it for the wrong reason"
                )
                print(
                    f"falsify: [{index}/{len(PROBES)}] {label}: WRONG RULE "
                    f"{sorted(fired)}"
                )
            else:
                print(
                    f"falsify: [{index}/{len(PROBES)}] {label}: refused by {expected}"
                )

    if failures:
        print("", file=sys.stderr)
        for failure in failures:
            print(f"falsify: {failure}", file=sys.stderr)
        print(
            f"falsify: {len(failures)} of {len(PROBES) + 2} case(s) did not hold",
            file=sys.stderr,
        )
        return 1
    print(f"falsify: 2 controls held and {len(PROBES)} probes were refused by name")
    return 0


if __name__ == "__main__":
    sys.exit(main())
