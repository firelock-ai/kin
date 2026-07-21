#!/usr/bin/env python3
"""Falsify the Zero File-Search guards against a poisoned tree.

A guard that has never been shown to fail proves nothing. A guard shown to
fail at ONE location proves only that it works at that location: it cannot
distinguish "the guard enforces" from "the guard enforces here". That
distinction is not academic. A desync in the checker's comment and brace
tracking once left roughly a third of the largest answer module unscanned,
and a single-point falsification passed the whole time, because the probe
was planted inside the region that still worked.

So this poisons every module the guard claims to enforce, at several points
each including end-of-file, and requires the guard to fail and to name the
offending file every time.

The enforced-module list is read from the guard itself rather than restated
here. A module added to the guard's coverage is falsified automatically, and
this harness cannot quietly fall behind what the guard claims to cover.

Usage: falsify-zero-file-search.py <tree_root>
"""
import importlib.util
import json
import os
import subprocess
import sys

POISON = "fn __falsification_probe(p: &str) -> String { std::fs::read_to_string(p).unwrap() }"
CMD_DIR = "crates/kin-cli/src/commands"


def load_guard(root):
    path = os.path.join(root, "scripts", "verify-zero-file-search.py")
    spec = importlib.util.spec_from_file_location("zfs_guard", path)
    module = importlib.util.module_from_spec(spec)
    argv = sys.argv
    sys.argv = ["verify-zero-file-search.py", root]
    try:
        spec.loader.exec_module(module)
    except SystemExit:
        # The guard runs main() on import and exits; we only want its constants.
        pass
    finally:
        sys.argv = argv
    return module


def whole_file_exempt(root):
    """Files the allowlist exempts entirely, which the guard therefore never
    scans. Excluding them here is correct, but it must be visible: an
    exemption that silently cancels a module's enforcement is exactly the kind
    of gap this harness exists to surface."""
    path = os.path.join(root, "scripts", "zero-file-search-allowlist.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {e["file"] for e in data.get("allowlist", []) if not e.get("allow_match")}


def production_end(lines):
    """Index of the first column-0 `#[cfg(test)]`, or len(lines).

    Deliberately a plain textual marker rather than the guard's own lexer. If
    this harness chose its probe sites using the parser it is testing, a
    parser that mistakenly believes it is inside a test module would steer
    every probe into the region it still scans, and the bug would hide from
    the check built to catch it.
    """
    for i, line in enumerate(lines):
        if line.startswith("#[cfg(test)]"):
            return i
    return len(lines)


def probe_sites(lines):
    """(label, insert-after index) pairs spanning the production region."""
    end = production_end(lines)
    sites = [("eof", len(lines))]
    if end >= 8:
        for label, idx in (("quarter", end // 4), ("half", end // 2), ("last-prod", end - 1)):
            # Snap back to a blank line so the probe cannot land inside a
            # multi-line string or a block comment, where the guard is right
            # to ignore it.
            j = idx
            while j > 0 and lines[j].strip():
                j -= 1
            sites.append((label, j if j > 0 else idx))
    return sites


def shell_guard_modules(root):
    """The answer modules the shell guard lists, read from the script itself.

    Read rather than restated for the same reason as the Python list: a
    harness that keeps its own copy of what it is supposed to cover will
    eventually cover something else.
    """
    path = os.path.join(root, "scripts", "zero_file_search_guard.sh")
    modules, collecting = set(), False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("authority_files=("):
                collecting = True
                continue
            if collecting:
                if line.strip() == ")":
                    break
                entry = line.strip().strip('"')
                if entry.startswith("$cmd_dir/"):
                    modules.add(entry.split("/")[-1])
    return modules


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    root = os.path.abspath(sys.argv[1])
    guard = load_guard(root)
    exempt = whole_file_exempt(root)
    shell_modules = shell_guard_modules(root)

    enforced, skipped = [], []
    cmd_dir = os.path.join(root, CMD_DIR)
    for name in sorted(os.listdir(cmd_dir)):
        if name not in guard.QUERY_COMMANDS and name not in shell_modules:
            continue
        rel = f"{CMD_DIR}/{name}"
        python_scans = name in guard.QUERY_COMMANDS and rel not in exempt
        shell_scans = name in shell_modules
        if python_scans or shell_scans:
            enforced.append((rel, python_scans, shell_scans))
        else:
            skipped.append(rel)

    if skipped:
        print("Not falsifiable — the allowlist exempts these answer modules entirely,")
        print("so the guard never scans them despite their being listed as query commands:")
        for rel in skipped:
            print(f"  - {rel}")
        print()

    if not enforced:
        print("::error::no enforced answer modules to falsify")
        return 1

    py_guard = os.path.join(root, "scripts", "verify-zero-file-search.py")
    sh_guard = os.path.join(root, "scripts", "zero_file_search_guard.sh")

    print(f"Falsifying {len(enforced)} answer modules at up to 4 sites each")
    print("  py = Python checker, sh = shell guard, - = module not in that guard's scope\n")
    failures = []
    for rel, python_scans, shell_scans in enforced:
        path = os.path.join(root, rel)
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        marks = []
        try:
            for label, idx in probe_sites(lines):
                poisoned = lines[:idx] + [POISON] + lines[idx:]
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(poisoned))
                cell = []
                for tag, scans, cmd in (
                    ("py", python_scans, [sys.executable, py_guard, root]),
                    ("sh", shell_scans, ["bash", sh_guard, root]),
                ):
                    if not scans:
                        cell.append("-")
                        continue
                    code, out = run(cmd)
                    if code == 0:
                        failures.append(f"{rel} @ {label}: {tag} guard PASSED on a poisoned tree")
                        cell.append("BLIND")
                    elif os.path.basename(rel) not in out:
                        failures.append(f"{rel} @ {label}: {tag} guard failed but never named the file")
                        cell.append("UNNAMED")
                    else:
                        cell.append("ok")
                marks.append(f"{label}=py:{cell[0]}/sh:{cell[1]}")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print(f"  {os.path.basename(rel):24} {'  '.join(marks)}")

    if failures:
        print()
        for f in failures:
            print(f"::error::falsification failed — {f}")
        return 1

    print("\nEvery enforced answer module fails its guards when poisoned, at every site.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
