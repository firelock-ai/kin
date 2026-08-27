#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Decide which workspace packages a diff can possibly have broken.

The admission core builds and tests on the pull request's own clock, so it
cannot afford the whole workspace on every diff and it cannot afford to be
clever about it either. A test selector that narrows too far is the worst kind
of check: it exits 0 having graded nothing, and it reads exactly like a clean
pass. Everything below is arranged so that the failure mode is running too much
rather than running too little.

## What it prints

Either the single argument `--workspace`, or one `-p <package>` argument per
line for the changed packages and everything in the workspace that depends on
them. Nothing else goes to stdout; the reasoning goes to stderr so a caller can
read the decision without parsing it.

## When it refuses to narrow

Every one of these prints `--workspace`, and each is a case where narrowing
would be a guess:

  no changed paths at all      a push or a merge-group build, where there is no
                               base to diff against. Also the shape a failed
                               diff produces, and those two must not be told
                               apart by guessing.
  a path outside every crate   Cargo.lock, the root manifest, .cargo/, .config/,
                               .github/, scripts/. A lockfile move can change
                               any crate's dependency versions, so no closure
                               over source ownership can bound it.
  a path in no known package   a new crate directory the metadata does not yet
                               carry, or a layout this script does not model.
  a closure covering most of   narrowing to nine tenths of the workspace costs
  the workspace                a longer command line and buys nothing.

## The reverse closure, and why it is the point

Changing a leaf crate can only break that leaf. Changing a crate other crates
depend on breaks them, and they are where the failure shows up. So the selected
set is the changed packages plus their reverse-dependency closure over workspace
members, computed from `cargo metadata`, which is the same graph cargo builds
from rather than a directory-name heuristic.

## What the caller still owes

This script chooses a set. It cannot tell whether the set ran. The caller has to
assert the test LISTING is non-empty before the run, because a filter matching
nothing prints the same `test result: ok` a clean pass prints, with `running 0
tests` the only tell. That assertion lives in the workflow beside the run, not
here, because only the caller knows which run it just made.

## Usage

  cargo metadata --no-deps --format-version 1 > meta.json
  scripts/changed-crate-scope.py meta.json < changed-paths.txt
  scripts/changed-crate-scope.py --self-test
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import PurePosixPath

# Above this share of the workspace, narrowing is not worth the command line.
WHOLE_WORKSPACE_SHARE = 0.6

# Paths that can reach any crate, so no closure over source ownership bounds
# them. A lockfile move is the sharp one: it changes resolved dependency
# versions for packages whose own files never moved.
UNBOUNDED_PREFIXES = (
    "Cargo.lock",
    "Cargo.toml",
    ".cargo/",
    ".config/",
    ".github/",
    "rust-toolchain",
    "scripts/",
)

WORKSPACE = ["--workspace"]


def load_members(metadata, root):
    """Map each workspace member to its directory and its workspace deps."""

    members = {}
    ids = {package["id"]: package["name"] for package in metadata["packages"]}
    wanted = {ids[member] for member in metadata["workspace_members"] if member in ids}
    for package in metadata["packages"]:
        name = package["name"]
        if name not in wanted:
            continue
        manifest = PurePosixPath(package["manifest_path"].replace(os.sep, "/"))
        try:
            directory = manifest.parent.relative_to(root)
        except ValueError:
            # A member outside the workspace root is a shape this script does
            # not model, and modelling it wrongly is worse than declining to.
            return None
        members[name] = {
            "dir": str(directory),
            "deps": {dep["name"] for dep in package.get("dependencies", [])},
        }
    for entry in members.values():
        entry["deps"] &= set(members)
    return members


def owning_package(path, members):
    """Longest directory prefix wins, so a nested crate beats its parent."""

    best = None
    for name, entry in members.items():
        directory = entry["dir"]
        if path == directory or path.startswith(directory + "/"):
            if best is None or len(directory) > len(members[best]["dir"]):
                best = name
    return best


def reverse_closure(seeds, members):
    """Everything that depends on a seed, transitively."""

    selected = set(seeds)
    changed = True
    while changed:
        changed = False
        for name, entry in members.items():
            if name in selected:
                continue
            if entry["deps"] & selected:
                selected.add(name)
                changed = True
    return selected


def scope(paths, members, note=lambda _: None):
    """Return (arguments, rule). The rule name is not decoration.

    Several rules widen to the whole workspace, and more than one of them
    accepts the same input: with `Cargo.lock` removed from UNBOUNDED_PREFIXES
    the unknown-path rule still widens it, so deleting that entry left the
    behaviour correct and every control green. Two rules that can both catch one
    input hide each other's absence, so the caller and the controls read WHICH
    rule fired rather than only what it returned.
    """

    if members is None:
        note("workspace layout is not one this script models")
        return WORKSPACE, "unmodelled"
    paths = [path.strip() for path in paths if path.strip()]
    if not paths:
        note("no changed paths, which is a push, a merge group, or a failed diff")
        return WORKSPACE, "no-paths"

    seeds = set()
    for path in paths:
        if any(path == prefix or path.startswith(prefix) for prefix in UNBOUNDED_PREFIXES):
            note(f"{path} can reach any crate")
            return WORKSPACE, "unbounded"
        owner = owning_package(path, members)
        if owner is None:
            note(f"{path} belongs to no known package")
            return WORKSPACE, "unknown-path"
        seeds.add(owner)

    selected = reverse_closure(seeds, members)
    if len(selected) >= max(1, int(len(members) * WHOLE_WORKSPACE_SHARE)):
        note(
            f"{len(selected)} of {len(members)} packages selected, which is most "
            "of the workspace"
        )
        return WORKSPACE, "most-of-workspace"

    note(
        f"changed {sorted(seeds)}; with reverse dependents that is "
        f"{len(selected)} of {len(members)} packages"
    )
    args = [argument for name in sorted(selected) for argument in ("-p", name)]
    return args, "narrowed"


# ─── Controls ───────────────────────────────────────────────────────────────

FIXTURE = {
    "leaf": {"dir": "crates/leaf", "deps": set()},
    "middle": {"dir": "crates/middle", "deps": {"leaf"}},
    "top": {"dir": "crates/top", "deps": {"middle"}},
    "aside": {"dir": "crates/aside", "deps": set()},
    "nested": {"dir": "crates/leaf/nested", "deps": set()},
    "spare1": {"dir": "crates/spare1", "deps": set()},
    "spare2": {"dir": "crates/spare2", "deps": set()},
    "spare3": {"dir": "crates/spare3", "deps": set()},
}


def run_controls():
    """Each rule, and the case that must NOT trigger it.

    A selector is only ever wrong in a way that looks like a passing run, so
    every arm below is paired: the input that must widen to the workspace, and
    the input that must not. Without the second half a selector that always
    answers `--workspace` passes every one of these.
    """

    def check(label, paths, expected, rule):
        got, fired = scope(paths, FIXTURE)
        if got != expected:
            raise AssertionError(f"{label}: expected {expected}, got {got}")
        if fired != rule:
            raise AssertionError(
                f"{label}: widened by rule '{fired}', expected '{rule}'. A rule "
                "another rule already covers is a defence whose removal nothing "
                "would notice"
            )

    # Widening, one case per rule.
    check("empty diff widens", [], WORKSPACE, "no-paths")
    check("lockfile widens", ["Cargo.lock"], WORKSPACE, "unbounded")
    check("workflow widens", [".github/workflows/ci.yml"], WORKSPACE, "unbounded")
    check("quarantine config widens", [".config/nextest.toml"], WORKSPACE, "unbounded")
    check("unknown path widens", ["docs/thing.md"], WORKSPACE, "unknown-path")

    # A closure covering most of the workspace widens. Its own control is the
    # transitive case further down, where the identical change over a bigger
    # workspace narrows instead, so this rule is shown to key on the SHARE
    # rather than on the change.
    small = {
        "leaf": {"dir": "crates/leaf", "deps": set()},
        "middle": {"dir": "crates/middle", "deps": {"leaf"}},
        "top": {"dir": "crates/top", "deps": {"middle"}},
    }
    if scope(["crates/leaf/src/a.rs"], small) != (WORKSPACE, "most-of-workspace"):
        raise AssertionError("a closure covering the whole workspace must widen")

    # Every unbounded path, written out rather than iterated. Two attempts got
    # this wrong before it worked. Controlling only `Cargo.lock` and `.github/`
    # left the rest free, because the unknown-path rule widened them anyway.
    # Looping over UNBOUNDED_PREFIXES was worse: deleting an entry deletes the
    # control with it, so the self-test passed with one fewer element every
    # time. The list below is the ratchet, deliberately a second copy, and a
    # prefix leaving the tuple has to be a deliberate edit here too.
    for probe in (
        "Cargo.lock",
        "Cargo.toml",
        ".cargo/config.toml",
        ".config/nextest.toml",
        ".github/workflows/ci.yml",
        "rust-toolchain.toml",
        "scripts/check-quarantine.py",
    ):
        got, fired = scope([probe], FIXTURE)
        if (got, fired) != (WORKSPACE, "unbounded"):
            raise AssertionError(
                f"{probe} must widen by the unbounded rule, got {got} by "
                f"'{fired}'. Its prefix left UNBOUNDED_PREFIXES, and the "
                "unknown-path rule widening it anyway is luck, not a defence"
            )

    # Not widening. Without these, a selector that always widens passes above.
    check(
        "a leaf change selects only its own package",
        ["crates/aside/src/a.rs"],
        ["-p", "aside"],
        "narrowed",
    )
    check(
        "a middle change selects its reverse dependents",
        ["crates/middle/src/a.rs"],
        ["-p", "middle", "-p", "top"],
        "narrowed",
    )
    check(
        "a nested crate is not attributed to its parent directory",
        ["crates/leaf/nested/src/a.rs"],
        ["-p", "nested"],
        "narrowed",
    )
    check(
        "two changes union rather than replace",
        ["crates/aside/src/a.rs", "crates/spare1/src/b.rs"],
        ["-p", "aside", "-p", "spare1"],
        "narrowed",
    )

    # The closure must be transitive, not one hop. leaf -> middle -> top, and
    # `leaf` is only kept out of the widening rule by a workspace large enough.
    big = dict(FIXTURE)
    for extra in range(9):
        big[f"filler{extra}"] = {"dir": f"crates/filler{extra}", "deps": set()}
    got, _ = scope(["crates/leaf/src/a.rs"], big)
    if got != ["-p", "leaf", "-p", "middle", "-p", "top"]:
        raise AssertionError(f"transitive closure is not transitive: {got}")

    # A member the metadata cannot place must widen rather than be guessed at.
    if scope(["crates/aside/src/a.rs"], None) != (WORKSPACE, "unmodelled"):
        raise AssertionError("an unmodelled layout must widen to the workspace")

    print(
        f"changed-crate-scope: {12 + 7} controls passed, "
        "each naming the rule that fired"
    )


def main(argv):
    if len(argv) > 1 and argv[1] == "--self-test":
        run_controls()
        return 0
    run_controls_quietly()
    if len(argv) < 2:
        raise AssertionError("usage: changed-crate-scope.py <cargo-metadata.json>")
    metadata = json.loads(open(argv[1], encoding="utf-8").read())
    root = PurePosixPath(metadata["workspace_root"].replace(os.sep, "/"))
    members = load_members(metadata, root)
    selection, rule = scope(
        sys.stdin.read().splitlines(),
        members,
        note=lambda why: print(f"changed-crate-scope: {why}", file=sys.stderr),
    )
    print(f"changed-crate-scope: rule={rule}", file=sys.stderr)
    for argument in selection:
        print(argument)
    return 0


def run_controls_quietly():
    import contextlib
    import io

    with contextlib.redirect_stdout(io.StringIO()):
        run_controls()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except AssertionError as error:
        sys.exit(f"changed-crate-scope: {error}")
