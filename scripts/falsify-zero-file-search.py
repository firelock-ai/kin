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

Coverage can also be lost from the other end, by an exemption growing rather
than a pattern missing, and that direction is the quieter one: the summary line
and the exit status of an over-wide exemption are identical to a clean run. Two
probes below attack it directly. One plants a brace inside a literal or a
comment in an allowlisted function body, the spelling a brace counter without
lexical awareness reads as an unclosed body before excusing the rest of the
file. The other pays for a real filesystem probe with a rename in test code the
guard never reads, which is what a pin counted over the raw file will accept.

The widest exemption of all is a whole file, and it has no falsification history
by construction: nothing is scanned there, so no probe can fail. A module
narrowed out of that state is probed across its production region here, and a
body exemption reground onto a pin is probed inside the body it used to excuse.

Which lines count as production is itself a policy decision, and the tracker
that made it keyed on the literal string `mod tests`. The cfg probes exercise
each spelling separately, including the ones that mention `test` and still
compile in production, and each carries a control the scan must always report so
a silent guard cannot pass for a correctly excluded item.

Every probe asks whether the SCAN reported the file, not whether the tool exited
nonzero. An allowlist error also exits nonzero and also prints the path it
complains about, and that failure mode is exactly the one that masks the scan.

The enforced-module list is read from the guard itself rather than restated
here. A module added to the guard's coverage is falsified automatically, and
this harness cannot quietly fall behind what the guard claims to cover.

Usage: falsify-zero-file-search.py <tree_root>
"""
import importlib.util
import json
import os
import re
import subprocess
import sys

POISON = "fn __falsification_probe(p: &str) -> String { std::fs::read_to_string(p).unwrap() }"
METADATA_POISON = (
    "fn __metadata_falsification_probe(p: &std::path::Path) -> bool { "
    "p.metadata().is_ok() }"
)
DENY_SET_PROBES = [
    (
        "Path::try_exists",
        "fn __try_exists_falsification_probe(p: &std::path::Path) -> bool { "
        "p.try_exists().unwrap_or(false) }",
    ),
    (
        "Path::is_symlink",
        "fn __is_symlink_falsification_probe(p: &std::path::Path) -> bool { "
        "p.is_symlink() }",
    ),
    (
        "raw-search subprocess",
        "fn __command_falsification_probe() -> bool { "
        "std::process::Command::new(\"rg\").arg(\"needle\").output().is_ok() }",
    ),
    (
        "aliased raw-search subprocess",
        "fn __aliased_command_falsification_probe() -> bool {\n"
        "    use std::process::Command as SearchProcess;\n"
        "    SearchProcess::new(\"find\").arg(\".\").output().is_ok()\n"
        "}",
    ),
    (
        "grouped std command alias",
        "fn __grouped_std_command_falsification_probe() -> bool {\n"
        "    use std::process::{Command as SearchProcess};\n"
        "    SearchProcess::new(\"rg\").arg(\"needle\").output().is_ok()\n"
        "}",
    ),
    (
        "multiline std use-tree alias",
        "fn __multiline_std_command_falsification_probe() -> bool {\n"
        "    use std::{\n"
        "        process::{Command as SearchProcess},\n"
        "    };\n"
        "    SearchProcess::new(\"grep\").arg(\"needle\").output().is_ok()\n"
        "}",
    ),
    (
        "grouped tokio command alias",
        "async fn __grouped_tokio_command_falsification_probe() -> bool {\n"
        "    use tokio::process::{Command as SearchProcess};\n"
        "    SearchProcess::new(\"find\").arg(\".\").output().await.is_ok()\n"
        "}",
    ),
    (
        "multiline tokio use-tree alias",
        "async fn __multiline_tokio_command_falsification_probe() -> bool {\n"
        "    use tokio::{\n"
        "        process::{Command as SearchProcess},\n"
        "    };\n"
        "    SearchProcess::new(\"git\").arg(\"grep\").output().await.is_ok()\n"
        "}",
    ),
    (
        "multiline git-grep subprocess",
        "fn __multiline_command_falsification_probe() -> bool {\n"
        "    std::process::Command::new(\"git\")\n"
        "        .arg(\"grep\")\n"
        "        .arg(\"needle\")\n"
        "        .output()\n"
        "        .is_ok()\n"
        "}",
    ),
]
CMD_DIR = "crates/kin-cli/src/commands"

# (module, one function the allowlist exempts by name). Each pair is probed
# inside that body, immediately after it, and at end of file.
DAEMON_FN_SCOPED = [
    ("crates/kin-daemon/src/api.rs", "ensure_loopback_token"),
]

# Braces that are not structure. Each is planted inside an exempt function body,
# where a brace counter without lexical awareness reads the opener as the body's
# and never finds its close, so the exemption silently runs to end of file and
# the guard passes on a poisoned tree. That is the failure this file exists to
# make impossible to reintroduce: the guard's OTHER brace counter was hardened
# against exactly these spellings, and the one that resolves exemptions was not.
BRACE_DESYNC_VARIANTS = [
    ("string", '    let _template = "{";'),
    ("char", "    let _brace = '{';"),
    ("line-cmt", "    // the { case is handled upstream"),
    ("block-cmt", "    /* { */"),
    ("raw-str", '    let _raw = r#"{"#;'),
    ("byte-str", '    let _bytes = b"{\\"schema\\":\\"partial";'),
]
PROBE_MARKER = "__falsification_probe"

# (module, counted pin) for the slack probe below. A count declared over the raw
# file is a budget the scan never audits: occurrences in test modules and
# comments are counted but can never be masked, so deleting one from a test
# releases room for a genuine filesystem probe in a scanned path with the
# declared number unchanged.
COUNTED_PIN_SLACK = [
    ("crates/kin-daemon/src/repository_commit.rs", ".metadata()"),
]
SLACK_PROBE = (
    "fn __slack_falsification_probe(p: &std::path::Path) -> bool {\n"
    "    p.metadata().map(|m| m.len() > 0).unwrap_or(false)\n"
    "}"
)
# A rename inside a test module: routine, invisible to the guard, and the offset
# that used to pay for the probe above.
SLACK_TEST_REPLACEMENT = ".authority_metadata()"

# Modules that were exempt as whole files and are now scanned around pinned
# expressions. A whole-file exemption is the widest gap the policy can have and
# the quietest: the guard's summary line and exit status are identical whether
# the file is a boundary end to end or has grown a raw source read since anyone
# looked. Narrowing one is only worth as much as the proof that the file is
# actually scanned now, so each is probed across its production region.
NARROWED_MODULES = ["crates/kin-daemon-spawn/src/lib.rs"]

# (module, function, pinned expression) for bodies that were exempt by name and
# are now covered by a pin on the primitive instead. The pin masks two `.exists()`
# calls; the twenty-four lines around them must be scanned again, which is the
# whole difference between the two grains. Poison goes just inside the body, on a
# line that is not the pinned one.
REGROUND_PINS = [
    ("crates/kin-daemon/src/daemon.rs", "repository_root_missing", ".exists()"),
    ("crates/kin-daemon/src/daemon.rs", "classify_control_plane", ".exists()"),
]

# The cfg tracker decides which items are production code, and it decided it by
# naming convention: the attribute line armed and disarmed in the same iteration,
# so only a following literal `mod tests` kept the exclusion alive. Every entry
# here is a spelling that decision got wrong or could get wrong, and the marker
# is placed in the violating line's own text so the guard's report distinguishes
# them. `expect` is the set of markers the scan must report; every probe also
# carries a control the scan must always report, so "the guard stayed silent
# because it is broken" cannot pass as "the item was correctly excluded".
TRACKER_CONTROL = "__tracker_control_path"


def tracker_read(marker):
    return f"    let _ = std::fs::read_to_string({marker}).unwrap();"


TRACKER_PROBES = [
    (
        "cfg(test) fn",
        "#[cfg(test)]\nfn __tracker_gated_fn() {\n"
        + tracker_read("__tracker_cfg_test_fn")
        + "\n}",
        [("__tracker_cfg_test_fn", False)],
    ),
    (
        "cfg(test) mod, unconventional name",
        "#[cfg(test)]\nmod __tracker_ingest_cas_tests {\n    fn probe() {\n"
        + tracker_read("__tracker_cfg_test_mod")
        + "\n    }\n}",
        [("__tracker_cfg_test_mod", False)],
    ),
    (
        "cfg(all(test, unix))",
        "#[cfg(all(test, unix))]\nfn __tracker_all_gated() {\n"
        + tracker_read("__tracker_cfg_all_test")
        + "\n}",
        [("__tracker_cfg_all_test", False)],
    ),
    (
        "cfg(any(unix, test)) stays scanned",
        "#[cfg(any(unix, test))]\nfn __tracker_any_gated() {\n"
        + tracker_read("__tracker_cfg_any_test")
        + "\n}",
        [("__tracker_cfg_any_test", True)],
    ),
    (
        "cfg(not(test)) stays scanned",
        "#[cfg(not(test))]\nfn __tracker_not_gated() {\n"
        + tracker_read("__tracker_cfg_not_test")
        + "\n}",
        [("__tracker_cfg_not_test", True)],
    ),
    (
        "cfg_attr(not(test), ..) gates nothing",
        "#[cfg_attr(not(test), allow(dead_code))]\nfn __tracker_cfg_attr() {\n"
        + tracker_read("__tracker_cfg_attr_test")
        + "\n}",
        [("__tracker_cfg_attr_test", True)],
    ),
    (
        "#[test] fn",
        "#[test]\nfn __tracker_test_attr() {\n"
        + tracker_read("__tracker_test_attribute")
        + "\n}",
        [("__tracker_test_attribute", False)],
    ),
    (
        "#[tokio::test] fn",
        '#[tokio::test(flavor = "multi_thread")]\nasync fn __tracker_tokio_test() {\n'
        + tracker_read("__tracker_tokio_attribute")
        + "\n}",
        [("__tracker_tokio_attribute", False)],
    ),
    (
        "exclusion ends at the gated item",
        "#[cfg(test)]\nmod __tracker_bounded {\n    fn probe() {\n"
        + tracker_read("__tracker_inside_bound")
        + "\n    }\n}\nfn __tracker_next_item() {\n"
        + tracker_read("__tracker_after_bound")
        + "\n}",
        [("__tracker_inside_bound", False), ("__tracker_after_bound", True)],
    ),
    (
        "a literal brace cannot widen the exclusion",
        "#[cfg(test)]\nfn __tracker_brace_gated() {\n"
        + '    let _template = "{";\n'
        + tracker_read("__tracker_inside_brace")
        + "\n}\nfn __tracker_after_brace() {\n"
        + tracker_read("__tracker_after_brace_probe")
        + "\n}",
        [("__tracker_inside_brace", False), ("__tracker_after_brace_probe", True)],
    ),
    (
        "a gated struct field excludes nothing",
        "struct __TrackerFields {\n    #[cfg(test)]\n    probe: bool,\n}\n"
        + "fn __tracker_after_field() {\n"
        + tracker_read("__tracker_after_field_probe")
        + "\n}",
        [("__tracker_after_field_probe", True)],
    ),
    (
        "cfg(test) macro_rules",
        "#[cfg(test)]\nmacro_rules! __tracker_gated_macro {\n    () => {\n"
        + tracker_read("__tracker_inside_macro")
        + "\n    };\n}\nfn __tracker_after_macro() {\n"
        + tracker_read("__tracker_after_macro_probe")
        + "\n}",
        [("__tracker_inside_macro", False), ("__tracker_after_macro_probe", True)],
    ),
]


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


def allowlist_entries(root):
    path = os.path.join(root, "scripts", "zero-file-search-allowlist.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f).get("allowlist", [])


def whole_file_exempt(root):
    """Files the allowlist exempts entirely, which the guard therefore never
    scans. Excluding them here is correct, but it must be visible: an
    exemption that silently cancels a module's enforcement is exactly the kind
    of gap this harness exists to surface.

    An entry carrying either kind of pin is not whole-file exempt: expression
    pins and function-body pins both leave the rest of the file scanned."""
    return {
        e["file"]
        for e in allowlist_entries(root)
        if not e.get("allow_match") and not e.get("allow_fn")
    }


def pinned_allowlist(root):
    """Return {file: {expression: expected occurrence count}}.

    A pin is a bare string, meaning exactly one occurrence, or an object
    carrying its own count for an expression that legitimately recurs. The
    count is what makes a recurring pin falsifiable, so this harness reads it
    rather than assuming one site per pin."""
    pinned = {}
    for entry in allowlist_entries(root):
        matches = entry.get("allow_match")
        if not matches:
            continue
        pinned[entry["file"]] = {
            (m if isinstance(m, str) else m["expr"]): (
                1 if isinstance(m, str) else m.get("count", 1)
            )
            for m in matches
        }
    return pinned


def exempt_fn_names(root):
    """Return {file: {function name, ...}} for every `allow_fn` entry."""
    names = {}
    for entry in allowlist_entries(root):
        fns = entry.get("allow_fn")
        if not fns:
            continue
        names[entry["file"]] = {f if isinstance(f, str) else f["fn"] for f in fns}
    return names


def scanned_pin_counts(guard, root, rel, fn_names, pins):
    """Occurrences of each pin in the text the guard actually scans.

    A declared count is a claim about scanned code, not about the file, so this
    precondition is measured the same way. It uses the guard's own projection
    deliberately: the falsification below poisons sites located textually, and
    stays independent of the guard's parser, but the setup check is asking
    whether the ALLOWLIST still matches the tree, which is the guard's own
    question. A raw-file count here would have declared drift on every pin whose
    expression also appears in a test module or a comment.
    """
    with open(os.path.join(root, rel), "r", encoding="utf-8") as f:
        lines = f.readlines()
    return guard.count_pins_in_scan(lines, guard.lex_lines(lines), fn_names, pins)


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


def test_module_start(lines):
    """Index of the column-0 `mod tests` declaration, or None.

    `production_end` deliberately stops at the first column-0 `#[cfg(test)]`,
    which is conservative for siting probes but is NOT the test module: a
    `#[cfg(test)]` helper function can sit hundreds of lines above the module,
    and the guard scans that helper's body. A probe that needs an occurrence the
    guard genuinely never reads has to key on the module itself, and on the same
    marker the guard's own tracker keys on.
    """
    for i, line in enumerate(lines):
        if line.startswith("mod tests"):
            return i
    return None


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


def shell_guard_modules(root, flag="--list-enforced"):
    """The answer modules the shell guard names, asked OF the shell guard.

    This used to parse an `authority_files=(...)` array out of the script. That
    array is gone: FIR-2282 made the command surface opt-out, so the guard
    derives its modules from the shared allowlist and there is no literal list
    left to read. Asking it directly is better anyway, for the reason the array
    was read rather than restated in the first place. A harness that keeps its
    own copy of what it is supposed to cover will eventually cover something
    else.

    `--list-enforced` rather than `--list-scanned` on purpose: the enforced list
    excludes modules whose declared boundary pins the shell guard defers to the
    Python checker. Poisoning one of those would fail for the wrong reason.
    """
    guard = os.path.join(root, "scripts", "zero_file_search_guard.sh")
    result = subprocess.run(
        ["bash", guard, flag, root], capture_output=True, text=True
    )
    if result.returncode != 0:
        raise SystemExit(
            f"::error::the shell guard refused to enumerate its modules "
            f"({flag}, rc={result.returncode}): {result.stderr.strip()[:300]}"
        )
    modules = {line.strip() for line in result.stdout.split("\n") if line.strip()}
    if not modules:
        # The control. An empty set would silently make every module below
        # "not in the shell guard's scope" and the harness would report a clean
        # sheet over nothing, which is the failure mode it exists to catch.
        raise SystemExit("::error::the shell guard enumerated zero answer modules")
    return modules


# Every declaration shape the guard's FN_DECL accepts, with the indentation
# captured so a body's closing brace can be found by matching it.
FN_DECL_PREFIX = (
    r"^(\s*)(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:unsafe\s+)?(?:extern\s+(?:\"[^\"]*\"\s+)?)?fn\s+"
)


def fn_body_span(lines, name):
    """(declaration index, closing-brace index) for a named function, or None.

    Located textually, by the indentation of the declaration and the first line
    that is exactly that indentation followed by `}`. Deliberately not the
    guard's own brace-depth parser: a harness that sited its probes with the
    parser under test would put both of them wherever that parser believed the
    body was, and a body it mislocated would never be probed at all.
    `cargo fmt --check` runs in the same CI job, so the closing brace of a
    function is reliably indented to match its declaration.

    The declaration prefix mirrors the guard's FN_DECL shape by shape, including
    `const`, `unsafe`, `extern`, and a parenthesised visibility with a space in
    it, which `pub\\S*` could not match. Failure here is loud rather than silent,
    but a probe that disables itself proves nothing either.
    """
    pattern = re.compile(FN_DECL_PREFIX + re.escape(name) + r"\s*[(<]")
    for idx, line in enumerate(lines):
        m = pattern.match(line)
        if not m:
            continue
        closer = m.group(1) + "}"
        for end in range(idx + 1, len(lines)):
            if lines[end].rstrip() == closer:
                return idx, end
    return None


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout + result.stderr


def scan_reported(out, rel):
    """Whether the Python guard's SCAN reported this file.

    A nonzero exit is not evidence the scan ran, and neither is the file's name
    appearing in the output: an allowlist error also exits nonzero and also
    prints the path it is complaining about. Only the scan prints the
    `[VIOLATION] <path>` header, so that is what a probe has to look for. This
    matters because the two failure modes read identically from outside and one
    of them masks the other: a stale pin once reported itself while ten real
    violations in a newly covered crate went unmentioned, and a probe satisfied
    by "exit code was 1 and the basename appeared" would have called that a pass.
    """
    return f"[VIOLATION] {rel}" in out


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    # This harness REWRITES source files in place: it plants a probe, runs the
    # guards, and restores the original in a `finally`. Two refusals guard the
    # target, because the damage from a wrong one is done before any verdict
    # exists, and both exit 2 so a refusal can never be read as a verdict.
    #
    # An empty argument is the one that actually happened. A caller built the
    # path with `poisoned=$(cat <file>)`, the file did not exist, `cat` failed,
    # and the empty string reached here looking exactly like a path. Argument
    # COUNT is 2 either way, and `os.path.abspath("")` is the current working
    # directory, so the harness poisoned the live checkout instead of a copy.
    # It restored everything and exited 0; a killed run would have left a probe
    # in real source. An empty value that looks exactly like a valid one is the
    # shape to refuse, not to survive.
    if not sys.argv[1].strip():
        print(
            "falsify-zero-file-search: refusing an empty root. os.path.abspath('') is the "
            "current working directory, so an empty argument would poison whatever tree you "
            "are standing in. Pass the copy explicitly.",
            file=sys.stderr,
        )
        return 2
    root = os.path.abspath(sys.argv[1])
    # A git working tree is never a legitimate target. Every caller copies
    # `crates` and `scripts` into a scratch directory first, which carries no
    # `.git`, so this separates the intended target from the one mistake that
    # costs real source. `.git` is a directory in a clone and a file in a
    # worktree, so test existence rather than directory-ness.
    if os.path.exists(os.path.join(root, ".git")):
        print(
            f"falsify-zero-file-search: refusing {root}: it is a git working tree and this "
            "harness rewrites source files in place. Copy `crates` and `scripts` into a "
            "scratch directory and pass that, which is what CI does.",
            file=sys.stderr,
        )
        return 2
    guard = load_guard(root)
    exempt = whole_file_exempt(root)
    shell_modules = shell_guard_modules(root)

    # Which modules each guard grades, asked of each guard rather than assumed.
    # The command surface is opt-out since FIR-2282, so "scanned" is now the
    # default and the interesting set is what remains after the allowlist.
    policies = guard.load_allowlist()[0]
    python_modules = guard.command_modules_scanned(policies)

    enforced, skipped = [], []
    cmd_dir = os.path.join(root, CMD_DIR)
    for name in sorted(os.listdir(cmd_dir)):
        if name not in python_modules and name not in shell_modules:
            continue
        rel = f"{CMD_DIR}/{name}"
        python_scans = name in python_modules and rel not in exempt
        shell_scans = name in shell_modules
        if python_scans or shell_scans:
            enforced.append((rel, python_scans, shell_scans))
        else:
            skipped.append(rel)

    if skipped:
        print("Not falsifiable — the allowlist exempts these answer modules entirely,")
        print("so neither guard scans them despite their being command modules:")
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
                    named = (
                        scan_reported(out, rel)
                        if tag == "py"
                        else os.path.basename(rel) in out
                    )
                    if code == 0:
                        failures.append(f"{rel} @ {label}: {tag} guard PASSED on a poisoned tree")
                        cell.append("BLIND")
                    elif not named:
                        failures.append(
                            f"{rel} @ {label}: {tag} guard failed but its scan never "
                            "reported the file"
                        )
                        cell.append("UNNAMED")
                    else:
                        cell.append("ok")
                marks.append(f"{label}=py:{cell[0]}/sh:{cell[1]}")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print(f"  {os.path.basename(rel):24} {'  '.join(marks)}")

    # A module that was whole-file exempt has no falsification history at all:
    # nothing was ever scanned there, so no probe could fail. Prove the narrowed
    # policy across the production region, at the same four sites the answer
    # modules get, and require the SCAN to report it rather than settling for a
    # nonzero exit.
    for rel in NARROWED_MODULES:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            failures.append(f"{rel}: narrowed-module falsification target is missing")
            continue
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        marks = []
        try:
            for label, idx in probe_sites(lines):
                poisoned = lines[:idx] + [POISON] + lines[idx:]
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(poisoned))
                code, out = run([sys.executable, py_guard, root])
                if code == 0:
                    failures.append(
                        f"{rel} @ {label}: guard PASSED on a poisoned tree that was "
                        "whole-file exempt before this policy was narrowed"
                    )
                    marks.append(f"{label}=BLIND")
                elif not scan_reported(out, rel):
                    failures.append(
                        f"{rel} @ {label}: guard failed but the scan never reported "
                        "the file"
                    )
                    marks.append(f"{label}=UNNAMED")
                else:
                    marks.append(f"{label}=ok")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print(f"  narrowed {os.path.basename(rel):15} {'  '.join(marks)}")

    # A pin on a primitive replaced two function-body exemptions. The bodies are
    # scanned again, which is the only reason the trade is worth making, so
    # poison each one on a line that is not the pinned one and require the report.
    # An exemption that had regressed to whole-body would swallow this silently.
    for rel, fn_name, pin in REGROUND_PINS:
        path = os.path.join(root, rel)
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        span = fn_body_span(lines, fn_name)
        if span is None:
            failures.append(f"{rel}: could not locate {fn_name} to falsify")
            continue
        if pin not in "\n".join(lines[span[0] : span[1] + 1]):
            failures.append(
                f"{rel}: {fn_name} no longer contains the pinned {pin!r}, so the "
                "reground pin no longer covers it"
            )
            continue
        try:
            poisoned = lines[: span[0] + 1] + [POISON] + lines[span[0] + 1 :]
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(poisoned))
            code, out = run([sys.executable, py_guard, root])
            mark = "ok"
            if code == 0 or not scan_reported(out, rel):
                failures.append(
                    f"{rel}: poison inside {fn_name} was not reported, so that body "
                    "is still exempt in whole rather than covered by a pin"
                )
                mark = "BLIND"
            print(f"  reground pin {fn_name:26} {mark}")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)

    # Which items are production code is a policy decision, and the tracker used
    # to make it by naming convention. Each probe below is one cfg spelling, with
    # a control the scan must always report so silence cannot pass for exclusion.
    #
    # Every probe's markers are unique, so the whole table is planted in one run
    # and each expectation read out of the same output. That is one guard run
    # instead of eleven, which matters because the guard walks every crate and
    # this harness already runs it well over a hundred times. The cost of batching
    # is attribution: an over-wide exclusion in one snippet would surface as a
    # missing marker in a later one. So a batch that fails is replayed one probe
    # at a time, which localises it exactly, and only a failing run pays for that.
    tracker_rel = f"{CMD_DIR}/search.rs"
    tracker_path = os.path.join(root, tracker_rel)
    with open(tracker_path, "r", encoding="utf-8") as f:
        tracker_original = f.read()
    control = (
        "fn __tracker_control() {\n"
        f"    let _ = std::fs::read_to_string({TRACKER_CONTROL}).unwrap();\n"
        "}"
    )

    def tracker_verdicts(probes):
        """Plant `probes` together and return {label: mark} for the one run."""
        body = "".join(f"\n{snippet}\n" for _, snippet, _ in probes)
        with open(tracker_path, "w", encoding="utf-8") as handle:
            handle.write(tracker_original + body + "\n" + control + "\n")
        code, out = run([sys.executable, py_guard, root])
        if code == 0 or TRACKER_CONTROL not in out:
            return {label: "NOCONTROL" for label, _, _ in probes}
        verdicts = {}
        for label, _, expectations in probes:
            mark = "ok"
            for marker, want_reported in expectations:
                if want_reported and marker not in out:
                    mark = "MISSED"
                elif not want_reported and marker in out:
                    mark = "SPURIOUS"
            verdicts[label] = mark
        return verdicts

    EXPLAIN = {
        "NOCONTROL": "the control probe was not reported, so the run proves "
        "nothing about the gated items",
        "MISSED": "an item that is production code was not reported",
        "SPURIOUS": "an item that exists only in a test build was reported as "
        "production",
    }
    try:
        verdicts = tracker_verdicts(TRACKER_PROBES)
        if any(mark != "ok" for mark in verdicts.values()):
            verdicts = {}
            for probe in TRACKER_PROBES:
                verdicts.update(tracker_verdicts([probe]))
        for label, _, _ in TRACKER_PROBES:
            mark = verdicts[label]
            if mark != "ok":
                failures.append(f"tracker probe {label!r}: {EXPLAIN[mark]}")
            print(f"  cfg tracker {label:38} {mark}")
    finally:
        with open(tracker_path, "w", encoding="utf-8") as f:
            f.write(tracker_original)

    # An expression pin must exempt only its own bytes, not the entire source
    # line. Poison every pinned line while retaining the allowed expression on
    # that same line. The historical `if allow_match in line: continue` bug
    # passed this mutation because the poison inherited the neighboring
    # exemption; the hardened guard must name every affected file.
    pinned = pinned_allowlist(root)
    fn_scoped = exempt_fn_names(root)
    originals = {}
    setup_failed = False
    try:
        for rel, matches in pinned.items():
            path = os.path.join(root, rel)
            with open(path, "r", encoding="utf-8") as f:
                original = f.read()
            originals[path] = original
            lines = original.split("\n")
            counts = scanned_pin_counts(
                guard, root, rel, fn_scoped.get(rel, set()), matches
            )
            poisoned_lines = set()
            for match, want in matches.items():
                found = counts.get(match, 0)
                if found != want:
                    failures.append(
                        f"{rel}: pinned expression {match!r} occurs "
                        f"{found} times in scanned code (want {want})"
                    )
                    setup_failed = True
                    continue
                # Every site a recurring pin covers, not just the first: an
                # exemption that masked one line and dropped the rest would
                # pass a single-site probe.
                poisoned_lines.update(
                    idx for idx, line in enumerate(lines) if match in line
                )
            for idx in poisoned_lines:
                lines[idx] = f"{POISON} {lines[idx]}"
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(lines))

        if not setup_failed:
            code, out = run([sys.executable, py_guard, root])
            if code == 0:
                failures.append(
                    "Python guard PASSED when poison shared every pinned allowlist line"
                )
            else:
                for rel in pinned:
                    if not scan_reported(out, rel):
                        failures.append(
                            f"{rel}: Python same-line falsification failed but "
                            "the scan never reported the file"
                        )
            print(
                "  pinned same-line poison   "
                + ("py:ok" if code != 0 else "py:BLIND")
            )
    finally:
        for path, original in originals.items():
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)

    # The shell guard has its own pinned allowlist. Its locate expression is
    # also present in the shared JSON policy, so use that one representative
    # line to prove the dependency-free guard masks rather than drops it.
    shell_same_line_rel = f"{CMD_DIR}/locate.rs"
    shell_matches = list(pinned.get(shell_same_line_rel, {}))
    shell_path = os.path.join(root, shell_same_line_rel)
    if len(shell_matches) != 1:
        failures.append(
            f"{shell_same_line_rel}: expected exactly one shared shell pin"
        )
    else:
        with open(shell_path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        locations = [
            idx for idx, line in enumerate(lines) if shell_matches[0] in line
        ]
        try:
            if len(locations) != 1:
                failures.append(
                    f"{shell_same_line_rel}: shell pin occurs {len(locations)} "
                    "times (want exactly 1)"
                )
            else:
                idx = locations[0]
                lines[idx] = f"{POISON} {lines[idx]}"
                with open(shell_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(lines))
                code, out = run(["bash", sh_guard, root])
                if code == 0:
                    failures.append(
                        "shell guard PASSED when poison shared its pinned locate line"
                    )
                elif os.path.basename(shell_same_line_rel) not in out:
                    failures.append(
                        f"{shell_same_line_rel}: shell same-line falsification "
                        "failed but never named the file"
                    )
                print(
                    "  shell same-line poison    "
                    + ("sh:ok" if code != 0 else "sh:BLIND")
                )
        finally:
            with open(shell_path, "w", encoding="utf-8") as f:
                f.write(original)

    # Function-body exemptions need falsifying from both sides. Poison inside
    # an exempt body must NOT be reported, or the exemption does not work;
    # poison just past its closing brace must be, or the exemption is really a
    # whole-file one wearing a function's name. The daemon RPC surface is where
    # this matters: it was a directory-level exemption with a six-handler
    # rescue covering a sixtieth of the file, so "the guard names api.rs" is a
    # claim that has to be demonstrated rather than assumed.
    for rel, exempt_fn in DAEMON_FN_SCOPED:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            failures.append(f"{rel}: fn-scoped falsification target is missing")
            continue
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        span = fn_body_span(lines, exempt_fn)
        if span is None:
            failures.append(
                f"{rel}: could not locate the body of {exempt_fn} to falsify"
            )
            continue
        start, end = span
        base = os.path.basename(rel)
        marks = []
        try:
            for label, idx, want_named in (
                ("inside-exempt-fn", start + 1, False),
                ("after-exempt-fn", end + 1, True),
                ("eof", len(lines), True),
            ):
                poisoned = lines[:idx] + [POISON] + lines[idx:]
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(poisoned))
                code, out = run([sys.executable, py_guard, root])
                named = scan_reported(out, rel)
                if want_named and not named:
                    failures.append(
                        f"{rel} @ {label}: guard did not name the file on a "
                        "poisoned scanned region"
                    )
                    marks.append(f"{label}=BLIND")
                elif not want_named and named:
                    failures.append(
                        f"{rel} @ {label}: guard named the file for poison inside "
                        f"the exempt body of {exempt_fn}, so the exemption is not "
                        "scoped to it"
                    )
                    marks.append(f"{label}=UNSCOPED")
                elif want_named and code == 0:
                    failures.append(
                        f"{rel} @ {label}: guard PASSED on a poisoned tree"
                    )
                    marks.append(f"{label}=BLIND")
                else:
                    marks.append(f"{label}=ok")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print(f"  {base:24} {'  '.join(marks)}")

    # Placement is not the whole property. The probe above never edits the
    # exempt body, so it cannot see the body's BOUNDARY move. Plant a brace that
    # is not structure inside the exempt body and the standard probe at end of
    # file, and require the guard to still report the probe. A brace counter
    # reading raw lines takes the literal's `{` for the body's, never finds its
    # close, and returns a range ending at the last line: everything after the
    # declaration is excused, the summary line is byte-identical to a clean run,
    # and the guard exits 0 on a working-tree scan planted in the RPC surface.
    # The daemon crate already carries this spelling in a byte string, so the
    # material for the bypass exists in the tree, not only in theory.
    for rel, exempt_fn in DAEMON_FN_SCOPED:
        path = os.path.join(root, rel)
        if not os.path.isfile(path):
            failures.append(f"{rel}: brace-desync falsification target is missing")
            continue
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        span = fn_body_span(lines, exempt_fn)
        if span is None:
            failures.append(
                f"{rel}: could not locate the body of {exempt_fn} to falsify"
            )
            continue
        start = span[0]
        marks = []
        try:
            for label, brace_line in BRACE_DESYNC_VARIANTS:
                poisoned = (
                    lines[: start + 1]
                    + [brace_line]
                    + lines[start + 1 :]
                    + [POISON]
                )
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(poisoned))
                code, out = run([sys.executable, py_guard, root])
                if code == 0:
                    failures.append(
                        f"{rel}: a {label} brace inside {exempt_fn} extended that "
                        "exemption and the guard PASSED on a poisoned tree"
                    )
                    marks.append(f"{label}=BLIND")
                elif PROBE_MARKER not in out:
                    failures.append(
                        f"{rel}: a {label} brace inside {exempt_fn} hid the "
                        "end-of-file probe; the guard failed for another reason"
                    )
                    marks.append(f"{label}=HIDDEN")
                else:
                    marks.append(f"{label}=ok")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print(f"  brace desync in {exempt_fn:9} {'  '.join(marks)}")

    # A counted pin has to be a budget over scanned code rather than over the
    # file. Plant the offset that proves the difference: rename one occurrence
    # inside the test module, which is a routine refactor the guard never reads,
    # and add a genuine filesystem probe to a scanned path. Counted over the raw
    # file the two net out, the declared number still validates, and a real
    # Path::metadata probe rides into a planning path behind a green guard.
    # Counted over scanned code the pin comes up short, is dropped rather than
    # applied, and every line it claimed is reported beside the pin error.
    for rel, pin in COUNTED_PIN_SLACK:
        path = os.path.join(root, rel)
        want = pinned.get(rel, {}).get(pin)
        if want is None:
            failures.append(f"{rel}: no counted pin {pin!r} to probe for slack")
            continue
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        tests_at = test_module_start(lines)
        test_sites = (
            [i for i in range(tests_at, len(lines)) if pin in lines[i]]
            if tests_at is not None
            else []
        )
        insert_at = dict(probe_sites(lines)).get("half")
        if not test_sites or insert_at is None:
            failures.append(
                f"{rel}: {pin!r} no longer occurs in the test module, so the "
                "counted-pin slack probe cannot run"
            )
            continue
        poisoned = list(lines)
        poisoned[test_sites[0]] = poisoned[test_sites[0]].replace(
            pin, SLACK_TEST_REPLACEMENT, 1
        )
        poisoned = (
            poisoned[:insert_at] + SLACK_PROBE.split("\n") + poisoned[insert_at:]
        )
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("\n".join(poisoned))
            code, out = run([sys.executable, py_guard, root])
            mark = "ok"
            if code == 0:
                failures.append(
                    f"{rel}: a test-module rename paid for a real filesystem probe "
                    f"and the {pin!r} pin still validated"
                )
                mark = "BLIND"
            else:
                for want_text in (
                    f"[VIOLATION] {rel}",
                    f"allow_match {pin!r}",
                    f"(want {want})",
                ):
                    if want_text not in out:
                        failures.append(
                            f"{rel}: counted-pin slack was caught but the output "
                            f"never showed {want_text!r}"
                        )
                        mark = "UNNAMED"
            print(f"  counted-pin slack        {os.path.basename(rel)}={mark}")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)

    # The broad probe above proves coverage across every claimed module, but
    # one representative read primitive cannot prove the deny sets themselves
    # stay complete. In particular, Path::metadata is a bare method call: it
    # has no `std::fs::` prefix, so a guard that only watches module-qualified
    # metadata calls misses it. Exercise that spelling explicitly in a module
    # covered by both guards, once in the middle of production code and once at
    # EOF so test-module span handling cannot hide either location.
    metadata_rel = f"{CMD_DIR}/search.rs"
    metadata_scope = next(
        (entry for entry in enforced if entry[0] == metadata_rel), None
    )
    if metadata_scope is None or not all(metadata_scope[1:]):
        failures.append(
            f"{metadata_rel}: bare metadata regression needs coverage from both guards"
        )
    else:
        path = os.path.join(root, metadata_rel)
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        lines = original.split("\n")
        marks = []
        try:
            for label, idx in probe_sites(lines):
                if label not in ("half", "eof"):
                    continue
                poisoned = lines[:idx] + [METADATA_POISON] + lines[idx:]
                with open(path, "w", encoding="utf-8") as f:
                    f.write("\n".join(poisoned))
                cell = []
                for tag, cmd in (
                    ("py", [sys.executable, py_guard, root]),
                    ("sh", ["bash", sh_guard, root]),
                ):
                    code, out = run(cmd)
                    if code == 0:
                        failures.append(
                            f"{metadata_rel} @ {label}: {tag} guard PASSED "
                            "on bare Path::metadata"
                        )
                        cell.append("BLIND")
                    elif not (
                        scan_reported(out, metadata_rel)
                        if tag == "py"
                        else os.path.basename(metadata_rel) in out
                    ):
                        failures.append(
                            f"{metadata_rel} @ {label}: {tag} guard failed but "
                            "never reported the file"
                        )
                        cell.append("UNNAMED")
                    else:
                        cell.append("ok")
                marks.append(f"{label}=py:{cell[0]}/sh:{cell[1]}")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)
        print(
            f"  bare Path::metadata      {'  '.join(marks)}"
        )

    # Deny-set breadth is itself a release boundary. Exercise the standard
    # fallible existence and symlink probes plus direct and multiline raw-search
    # subprocess builders. Banning Command::new in answer modules makes the
    # multiline case independent of how executable/argument strings are laid
    # out, and prevents a dynamically selected executable from bypassing a
    # literal-name scanner.
    deny_rel = f"{CMD_DIR}/search.rs"
    deny_scope = next((entry for entry in enforced if entry[0] == deny_rel), None)
    if deny_scope is None or not all(deny_scope[1:]):
        failures.append(
            f"{deny_rel}: deny-set falsification needs coverage from both guards"
        )
    else:
        path = os.path.join(root, deny_rel)
        with open(path, "r", encoding="utf-8") as f:
            original = f.read()
        base_lines = original.split("\n")
        try:
            for probe_name, probe in DENY_SET_PROBES:
                marks = []
                for label, idx in probe_sites(base_lines):
                    if label not in ("half", "eof"):
                        continue
                    poisoned = base_lines[:idx] + probe.split("\n") + base_lines[idx:]
                    with open(path, "w", encoding="utf-8") as f:
                        f.write("\n".join(poisoned))
                    cell = []
                    for tag, cmd in (
                        ("py", [sys.executable, py_guard, root]),
                        ("sh", ["bash", sh_guard, root]),
                    ):
                        code, out = run(cmd)
                        if code == 0:
                            failures.append(
                                f"{deny_rel} @ {label}: {tag} guard PASSED on {probe_name}"
                            )
                            cell.append("BLIND")
                        elif not (
                            scan_reported(out, deny_rel)
                            if tag == "py"
                            else os.path.basename(deny_rel) in out
                        ):
                            failures.append(
                                f"{deny_rel} @ {label}: {tag} guard failed on "
                                f"{probe_name} but never reported the file"
                            )
                            cell.append("UNNAMED")
                        else:
                            cell.append("ok")
                    marks.append(f"{label}=py:{cell[0]}/sh:{cell[1]}")
                print(f"  {probe_name:<27} {'  '.join(marks)}")
        finally:
            with open(path, "w", encoding="utf-8") as f:
                f.write(original)

    if failures:
        print()
        for f in failures:
            print(f"::error::falsification failed — {f}")
        return 1

    print("\nEvery enforced answer module fails its guards when poisoned, at every site.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
