#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Refuse a store-size figure that does not say which Kin produced it, or how.

docs/store-size.md published a ripgrep store size that was wrong by 1.74x for
about a month, and the launch post carried the wrong number outward. Two
independent defects made it, and neither was an arithmetic slip:

  Version vintage. The figures were measured at workspace version 0.5.6, at
  least a dozen releases before v0.7.2, and the graph snapshot alone roughly
  doubled across that span. Nothing on the page said which version produced
  any number, so a stale figure was indistinguishable from a current one.

  Mixed methods. The breakdown was measured with `du`, which counts allocated
  disk blocks, while the total came from Kin's own logical-byte walk. The two
  halves therefore could not add up, and no amount of re-checking the
  arithmetic would ever have found it, because the arithmetic was not the
  error. A reader who "verified" that page was adding numbers that were never
  comparable.

## The design choice this guard makes

It never reconciles across methods, and it refuses an undeclared one.

Reconciling is exactly what a human wrongly did for a month, and no tolerance
can do it correctly: there is no fixed conversion between allocated blocks and
logical bytes, because the gap depends on block size, file count and the size
distribution of the files. Pick 2% and the correct page goes red on a real
7.1% method gap. Pick 10% and the original 10.3% defect walks through. The two
cases are not separable by magnitude, which is the whole reason a careful
reader could not tell them apart either.

So every size figure must name its method, the arithmetic is checked only
WITHIN one declared method, and a page that publishes two methods must have a
paragraph where both are named together. An undeclared method is a failure,
not something this guard tries to resolve.

## What it refuses

  P1  the page is missing one of the two tables this guard knows about, or
      carries a third table with size figures in it. A new table is a decision
      about provenance, so it stops here until somebody makes it.
  V1  the Measured table has no version column. Its rows are independent
      measurements of different repositories, so one stamp per table would
      let a stale row hide behind a fresh one.
  V2  a Measured row whose stamp is neither `vX.Y.Z` plus an ISO date nor the
      exact literal `synthetic fixture`.
  V3  the breakdown table's introducing paragraph carries no version and date.
      That table is one measurement split into parts, so one stamp covers it.
  V4  a paragraph outside any table that states a KiB, MiB or GiB size without
      a version and a date beside it.
  M1  a table whose size columns declare no measurement method, or more than
      one. The method is read from the size column headers and the table's
      introducing paragraph, and the vocabulary is closed on purpose: a third
      method has to be taught to this guard before it can be published.
  M2  a breakdown table with no total row, a size cell this guard cannot read
      as a value, or part rows that do not sum to the total row. This is
      within-method arithmetic, which is the only arithmetic that means
      anything here.
  M3  a breakdown share that does not reconcile against that table's OWN
      total. The original page's shares reconciled against a sum it never
      printed, which is how the reader could tell nobody had checked them.
  M4  the page declares more than one method and no paragraph names them all
      together. That paragraph is where the reader is told not to add across
      them, and its absence is what made the first mistake invisible.
  C1  a size figure this guard did not account for. A parser that quietly
      stops finding figures reports the same green a clean page reports, so
      every figure in the file must land in something that was graded.

Usage: check-store-size-figures.py [--page <path>]
Exit 0 when the page is clean, 1 when any rule above fires.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PAGE = REPO_ROOT / "docs" / "store-size.md"

# A Kin release, and the day a figure was read. Both, or the figure is not
# safe to read as current.
VERSION_RE = re.compile(r"\bv\d+\.\d+\.\d+\b")
DATE_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")

# The units Kin's own walk prints. KB and MB are deliberately not here: on this
# page they describe Git-side and fixture-side facts rather than a Kin store.
SIZE_RE = re.compile(r"(?<![\d.])(\d+(?:\.\d+)?)\s+(KiB|MiB|GiB)\b")

# A size cell this guard will sum. Anything else is refused rather than
# guessed at, because a bound ("under 1 MiB") cannot be added to anything.
EXACT_CELL_RE = re.compile(r"^(\d+(?:\.\d+)?)\s+(KiB|MiB|GiB)$")
APPROX_CELL_RE = re.compile(r"^(?:about|roughly|~)\s*(\d+(?:\.\d+)?)\s+(KiB|MiB|GiB)$")

SHARE_CELL_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*%$")

# The closed method vocabulary. `du` counts allocated disk blocks; the walk
# sums logical file bytes. Teaching this guard a third one is a deliberate
# edit, which is the point.
METHODS = {
    "du": re.compile(r"\bdu\b"),
    "walk": re.compile(r"\bwalks?\b"),
}

UNIT_BYTES = {"KiB": 1024.0, "MiB": 1024.0**2, "GiB": 1024.0**3}

# The only stamp a row may carry instead of a version and a date. It is a
# closed literal rather than free text, and every use is printed, so the
# exemption can never be invisible in a CI log.
FIXTURE_STAMP = "synthetic fixture"

# The two tables this page publishes, keyed by the first cell of the header
# row. BREAKDOWN is one store split into parts, so it carries one stamp and a
# total row; MEASURED is many independent measurements, so it carries a stamp
# column.
BREAKDOWN_KEY = "Part of"
MEASURED_KEY = "Repository"


@dataclass
class Table:
    kind: str
    header: list[str]
    rows: list[list[str]]
    start_line: int
    intro: str


@dataclass
class Block:
    lines: list[str]
    start_line: int

    @property
    def text(self) -> str:
        return "\n".join(self.lines)

    @property
    def is_table(self) -> bool:
        return bool(self.lines) and all(ln.lstrip().startswith("|") for ln in self.lines)


def split_blocks(text: str) -> list[Block]:
    """Split the page into blank-line separated blocks, keeping line numbers."""
    blocks: list[Block] = []
    current: list[str] = []
    start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip():
            if not current:
                start = number
            current.append(line)
        elif current:
            blocks.append(Block(current, start))
            current = []
    if current:
        blocks.append(Block(current, start))
    return blocks


def split_row(line: str) -> list[str]:
    stripped = line.strip()
    if stripped.startswith("|"):
        stripped = stripped[1:]
    if stripped.endswith("|"):
        stripped = stripped[:-1]
    return [cell.strip() for cell in stripped.split("|")]


def plain(cell: str) -> str:
    """Strip the markdown a cell may wear, so a value can be read out of it."""
    return cell.replace("`", "").replace("**", "").replace("*", "").strip()


def to_bytes(value: float, unit: str) -> float:
    return value * UNIT_BYTES[unit]


class Report:
    def __init__(self) -> None:
        self.failures: list[tuple[str, str]] = []
        self.notes: list[str] = []

    def fail(self, rule: str, message: str) -> None:
        self.failures.append((rule, message))

    def note(self, message: str) -> None:
        self.notes.append(message)


def collect_tables(blocks: list[Block], report: Report) -> dict[str, Table]:
    """Find the two known tables, and refuse any third one carrying sizes."""
    tables: dict[str, Table] = {}
    for index, block in enumerate(blocks):
        if not block.is_table:
            continue
        rows = [split_row(line) for line in block.lines]
        if len(rows) < 3:
            continue
        header = rows[0]
        body = [row for row in rows[2:] if row]
        first = plain(header[0])
        intro = ""
        for previous in reversed(blocks[:index]):
            if not previous.is_table:
                intro = previous.text
                break
        if first.startswith(BREAKDOWN_KEY):
            kind = "breakdown"
        elif first.startswith(MEASURED_KEY):
            kind = "measured"
        elif any(SIZE_RE.search(cell) for row in rows for cell in row):
            report.fail(
                "P1",
                f"line {block.start_line}: a table headed {first!r} publishes size "
                "figures and this guard knows nothing about its provenance rules; "
                f"teach it, or head the table {BREAKDOWN_KEY!r} or {MEASURED_KEY!r}",
            )
            continue
        else:
            continue
        if kind in tables:
            report.fail(
                "P1",
                f"line {block.start_line}: a second {kind} table; this guard grades "
                "one of each and would silently leave the other ungraded",
            )
            continue
        tables[kind] = Table(kind, header, body, block.start_line, intro)
    for kind in ("breakdown", "measured"):
        if kind not in tables:
            report.fail(
                "P1",
                f"the {kind} table is missing; a page this guard cannot find its "
                "tables in must not report the same green a clean page reports",
            )
    return tables


def size_columns(table: Table) -> list[int]:
    """Header cells that carry a size, which are the ones needing a method."""
    columns = []
    for index, cell in enumerate(table.header):
        text = plain(cell).lower()
        if "size" in text or "store" in text:
            columns.append(index)
    return columns


def check_methods(tables: dict[str, Table], report: Report) -> set[str]:
    """Rule M1: exactly one declared method per table, from a closed set."""
    declared: set[str] = set()
    for kind, table in tables.items():
        columns = size_columns(table)
        if not columns:
            report.fail(
                "M1",
                f"line {table.start_line}: the {kind} table has no size column this "
                "guard can identify, so nothing about it is being graded",
            )
            continue
        haystack = " ".join(table.header[i] for i in columns) + "\n" + table.intro
        found = {name for name, pattern in METHODS.items() if pattern.search(haystack)}
        if not found:
            report.fail(
                "M1",
                f"line {table.start_line}: the {kind} table's size columns declare no "
                f"measurement method; name one of {sorted(METHODS)} in the size column "
                "header or in the paragraph introducing the table",
            )
        elif len(found) > 1:
            report.fail(
                "M1",
                f"line {table.start_line}: the {kind} table's size columns declare "
                f"{sorted(found)} at once; one table measures one way, or its rows "
                "cannot be compared with each other",
            )
        else:
            declared |= found
    return declared


def check_version_stamps(tables: dict[str, Table], report: Report) -> None:
    """Rules V1 to V3: every published figure says which Kin produced it."""
    measured = tables.get("measured")
    if measured is not None:
        stamp_column = None
        for index, cell in enumerate(measured.header):
            if "version" in plain(cell).lower():
                stamp_column = index
                break
        if stamp_column is None:
            report.fail(
                "V1",
                f"line {measured.start_line}: the Measured table has no version "
                "column; its rows are independent measurements, so one stamp for the "
                "table would let a stale row hide behind a fresh one",
            )
        else:
            for offset, row in enumerate(measured.rows, start=measured.start_line + 2):
                subject = plain(row[0]) if row else "?"
                cell = plain(row[stamp_column]) if stamp_column < len(row) else ""
                if cell == FIXTURE_STAMP:
                    report.note(
                        f"line {offset}: {subject!r} is stamped {FIXTURE_STAMP!r} "
                        "rather than with a version and a date, so nothing here can "
                        "tell you whether it is current"
                    )
                    continue
                if not (VERSION_RE.search(cell) and DATE_RE.search(cell)):
                    report.fail(
                        "V2",
                        f"line {offset}: {subject!r} carries the stamp {cell!r}, which "
                        "is neither a vX.Y.Z with an ISO date nor the literal "
                        f"{FIXTURE_STAMP!r}",
                    )

    breakdown = tables.get("breakdown")
    if breakdown is not None:
        intro = breakdown.intro
        if not (VERSION_RE.search(intro) and DATE_RE.search(intro)):
            report.fail(
                "V3",
                f"line {breakdown.start_line}: the paragraph introducing the breakdown "
                "table carries no version and date, and it is the only stamp that "
                "table has",
            )


def check_prose_stamps(blocks: list[Block], report: Report) -> int:
    """Rule V4: a size in prose is a published figure and carries its stamp."""
    graded = 0
    for block in blocks:
        if block.is_table or not SIZE_RE.search(block.text):
            continue
        graded += 1
        if VERSION_RE.search(block.text) and DATE_RE.search(block.text):
            continue
        figures = ", ".join(
            f"{value} {unit}" for value, unit in SIZE_RE.findall(block.text)
        )
        report.fail(
            "V4",
            f"line {block.start_line}: this paragraph states {figures} with no version "
            "and date beside it; an unstamped figure is indistinguishable from a "
            "stale one, which is how the ripgrep number survived a dozen releases",
        )
    return graded


def read_size_cell(cell: str) -> tuple[float, str, bool] | None:
    text = plain(cell)
    match = EXACT_CELL_RE.match(text)
    if match:
        return float(match.group(1)), match.group(2), False
    match = APPROX_CELL_RE.match(text)
    if match:
        return float(match.group(1)), match.group(2), True
    return None


def check_breakdown_arithmetic(tables: dict[str, Table], report: Report) -> int:
    """Rules M2 and M3: within-method arithmetic, and only within-method."""
    table = tables.get("breakdown")
    if table is None:
        return 0
    columns = size_columns(table)
    if not columns:
        return 0
    size_column = columns[0]
    share_column = None
    for index, cell in enumerate(table.header):
        if "share" in plain(cell).lower():
            share_column = index
            break

    total_row = None
    parts: list[tuple[int, str, float, str, bool]] = []
    for offset, row in enumerate(table.rows, start=table.start_line + 2):
        if size_column >= len(row):
            report.fail("M2", f"line {offset}: this row has no size cell")
            continue
        subject = plain(row[0])
        parsed = read_size_cell(row[size_column])
        if parsed is None:
            report.fail(
                "M2",
                f"line {offset}: the size cell {plain(row[size_column])!r} for "
                f"{subject!r} is not a value this guard will sum; write it as "
                "'N MiB' or 'about N MiB', because a bound cannot be added to "
                "anything",
            )
            continue
        value, unit, approximate = parsed
        if subject.lower().startswith("total"):
            if total_row is not None:
                report.fail("M2", f"line {offset}: a second total row")
                continue
            total_row = (offset, subject, value, unit, approximate)
        else:
            parts.append((offset, subject, value, unit, approximate))

    if total_row is None:
        report.fail(
            "M2",
            f"line {table.start_line}: the breakdown table states no total of its own. "
            "That is the defect this guard exists for: the parts were measured one way "
            "and the only total on the page was measured another, so they could never "
            "add up and nobody could see why",
        )
        return len(parts)
    if not parts:
        report.fail("M2", f"line {table.start_line}: the breakdown table has no parts")
        return 0

    total_bytes = to_bytes(total_row[2], total_row[3])
    summed = sum(to_bytes(value, unit) for _, _, value, unit, _ in parts)
    # A one-decimal figure rounds within half of the last place; a row written
    # as "about N" is fuzzy by its own admission and gets the wider of half a
    # unit or a tenth of itself.
    tolerance = to_bytes(0.05, total_row[3])
    for _, _, value, unit, approximate in parts:
        slack = max(0.5, 0.1 * value) if approximate else 0.05
        tolerance += to_bytes(slack, unit)
    if abs(summed - total_bytes) > tolerance:
        listed = " + ".join(f"{value} {unit}" for _, _, value, unit, _ in parts)
        report.fail(
            "M2",
            f"line {total_row[0]}: the parts sum to {summed / UNIT_BYTES[total_row[3]]:.1f} "
            f"{total_row[3]} ({listed}) against a stated total of {total_row[2]} "
            f"{total_row[3]}, past the {tolerance / UNIT_BYTES[total_row[3]]:.2f} "
            f"{total_row[3]} these rows' own rounding allows",
        )

    if share_column is None:
        report.fail(
            "M3",
            f"line {table.start_line}: the breakdown table has no share column, so its "
            "shares cannot be reconciled against its own total",
        )
        return len(parts)
    for offset, subject, value, unit, approximate in parts + [total_row]:
        if share_column >= len(table.rows[offset - table.start_line - 2]):
            report.fail("M3", f"line {offset}: {subject!r} has no share cell")
            continue
        cell = plain(table.rows[offset - table.start_line - 2][share_column])
        match = SHARE_CELL_RE.match(cell)
        if match is None:
            report.fail(
                "M3",
                f"line {offset}: the share cell {cell!r} for {subject!r} is not a "
                "percentage, so nothing about it can be checked",
            )
            continue
        stated = float(match.group(1))
        actual = to_bytes(value, unit) / total_bytes * 100.0
        slack = 0.35 if approximate else 0.15
        if abs(stated - actual) > slack:
            report.fail(
                "M3",
                f"line {offset}: {subject!r} states {stated}% but is {actual:.2f}% of "
                f"this table's own {total_row[2]} {total_row[3]} total",
            )
    return len(parts)


def check_method_declaration(
    blocks: list[Block], declared: set[str], report: Report
) -> None:
    """Rule M4: two methods on one page need a paragraph naming both."""
    if len(declared) < 2:
        return
    for block in blocks:
        if block.is_table:
            continue
        if all(METHODS[name].search(block.text) for name in declared):
            return
    report.fail(
        "M4",
        f"this page publishes figures under {sorted(declared)} and no paragraph names "
        "them together. That paragraph is where a reader is told the two are not "
        "comparable, and its absence is what let a du-measured breakdown sit under a "
        "walk-measured total for a month",
    )


def check_coverage(
    text: str, tables: dict[str, Table], prose_blocks: int, report: Report
) -> None:
    """Rule C1: every size figure in the file landed in something graded."""
    total = len(SIZE_RE.findall(text))
    accounted = prose_blocks_figures(text)
    for table in tables.values():
        for row in table.rows:
            accounted += sum(len(SIZE_RE.findall(cell)) for cell in row)
        accounted += sum(len(SIZE_RE.findall(cell)) for cell in table.header)
    if accounted != total:
        report.fail(
            "C1",
            f"the page holds {total} size figure(s) and this guard accounted for "
            f"{accounted}; a figure nothing grades is exactly the shape that put a "
            "wrong number on this page",
        )
    else:
        report.note(
            f"graded {total} size figure(s) across {len(tables)} table(s) and "
            f"{prose_blocks} prose paragraph(s)"
        )


def prose_blocks_figures(text: str) -> int:
    return sum(
        len(SIZE_RE.findall(block.text))
        for block in split_blocks(text)
        if not block.is_table
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--page", type=Path, default=DEFAULT_PAGE)
    args = parser.parse_args()

    if not args.page.is_file():
        print(f"::error title=Store-size page missing::{args.page} is not a file")
        return 1
    text = args.page.read_text(encoding="utf-8")
    blocks = split_blocks(text)
    report = Report()

    tables = collect_tables(blocks, report)
    declared = check_methods(tables, report)
    check_version_stamps(tables, report)
    prose_graded = check_prose_stamps(blocks, report)
    check_breakdown_arithmetic(tables, report)
    check_method_declaration(blocks, declared, report)
    check_coverage(text, tables, prose_graded, report)

    for note in report.notes:
        print(f"store-size: {note}")
    if not report.failures:
        print(f"store-size: {args.page} is clean")
        return 0
    annotate = bool(os.environ.get("GITHUB_ACTIONS"))
    for rule, message in report.failures:
        print(f"store-size: [{rule}] {message}")
        if annotate:
            print(f"::error title=Store-size figure guard {rule}::{message}")
    print(
        f"store-size: {len(report.failures)} rule(s) fired on {args.page}",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
