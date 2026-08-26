#!/usr/bin/env python3
"""Refuse a test that decides by the runner's environment instead of by the code.

FIR-2714 removed one instance. This is what stops the next, and the distinction
between an alarm and a prevention is the whole point.

A test that resolves a home through `home_dir`, `shell_rc`, `shell_path_rcs` or
`rc_write_plan` without `#[serial]` passes on a quiet laptop, lands green, and
ejects a merge-queue entry weeks later from inside a `merge_group` run that marks
no pull request. That is what happened to kin#1141 and kin#1142 on 2026-08-26.
A serial test is only serialised against other serial tests, so an unpinned one
runs beside the sixty-odd siblings that point `HOME` at a tempdir, and reads
whichever home the scheduler leaves in place between two calls.

Two rules, and the second exists because the first alone would have shipped a
guard carrying the exact gap that bit the lane writing it.

RULE ONE. A test that resolves a home through a real call site is `#[serial]`.
`unix_home_dir_still_resolves_exactly_what_base_dirs_reports` is allowlisted by
name, because comparing against the real home is its contract.

RULE TWO. A test that drives the PowerShell arm unsets `PROFILE`. Tests calling
the parameterized `_in` variants take a home, so rule one does not reach them,
and they still read `PROFILE`: `shell_rc_in` prefers it over the home it is
handed. Taking a home as a parameter stops the home being the only input; it
does not make it the only input. Both checks added in kin#1144 had this and
passed anyway, because nothing in the module and nothing on that host sets it.

## Scope

The file set is DISCOVERED rather than pinned, because the class follows the
call sites and a pinned list goes stale the day a test moves modules. Eight
files under `crates/` reach these functions today and `git grep` finds them the
same way this walk does. A pinned list would have been a check that stops being
able to fail the moment somebody adds a ninth.

## Three things make the scan answer correctly, and each was a mistake first

It blanks string literals as well as comments. A doc comment saying
`shell_rc("powershell")` and an assertion message naming `home_dir` both match a
naive scan, and a false regex hit is the same match as a real one. The first
version of this reported three non-serial readers when the answer was one.

It requires a word boundary on both sides of a call site, so `resolve_home_dir(`
is not `home_dir(` and `shell_rc_in(` is not `shell_rc(`.

It walks braces for a test's body. Slicing to the next `#[test]` swallows the
following test's doc comment, which is precisely how the mention got counted.

## Controls, and why these ones

Three run before any file is read, and all three can fail in both directions.

The blanker self-test runs against a fixture carried here rather than against
whatever the tree happens to contain. The scratch version of this guard drew its
negative control from the file under test, which is fine for one file and
vacuous for every file that does not happen to contain the chosen string: the
check silently stops running rather than failing. A fixture cannot go vacuous.

The recogniser self-test asserts the scan still reports a known offender and
still stays quiet on its pinned twin. A guard that has lost the ability to say
yes is green on every tree, and nothing else here would notice.

The discovery control asserts the walk found files at all and found the module
this class is known to live in. A walk that matches nothing reports a clean tree.

A file that discovery selected and the parser found no test in is reported as
unscannable rather than passing, because "no offenders" and "no tests parsed"
are the same exit code otherwise.
"""

import re
import sys
from pathlib import Path

FNS = ("rc_write_plan", "shell_rc", "shell_path_rcs", "home_dir")
PARAMETERIZED = ("rc_write_plan_in", "shell_rc_in", "shell_path_rcs_in")
ALLOWED = {"unix_home_dir_still_resolves_exactly_what_base_dirs_reports"}
ROOTS = ("crates",)
# The module the class is known to live in. Discovery has to keep finding it, or
# the walk has stopped reaching the code this guard exists for.
DISCOVERY_ANCHOR = "crates/kin-cli/src/commands/setup.rs"

# A fixture, not a needle drawn from the tree. Every line of it is load-bearing:
# a comment mention, a literal mention, and one real call site, so the blanker
# is proved to erase the first two and keep the third.
BLANKER_FIXTURE = '''
// a doc comment naming home_dir( and shell_rc("powershell")
fn probe() {
    let script = "#!/bin/sh\\nhome_dir(\\n";
    let real = home_dir();
    assert!(real.is_some(), "home_dir( failed");
}
'''
BLANKER_MUST_VANISH = ("#!/bin/sh", 'shell_rc("powershell")')
BLANKER_MUST_SURVIVE = "home_dir("

# The recogniser self-test. The first must be reported under both rules and the
# second under neither, from one pass of the same code that reads the tree.
RECOGNISER_FIXTURE = '''
    #[test]
    fn an_offender_reads_the_home_and_drives_powershell() {
        let plan = rc_write_plan("powershell").unwrap();
        assert_eq!(plan.len(), 1);
    }

    #[test]
    #[serial]
    fn a_pinned_twin_reads_the_home_and_drives_powershell() {
        let _profile = EnvVarGuard::unset("PROFILE");
        let plan = rc_write_plan("powershell").unwrap();
        assert_eq!(plan.len(), 1);
    }
'''
RECOGNISER_OFFENDER = "an_offender_reads_the_home_and_drives_powershell"
RECOGNISER_TWIN = "a_pinned_twin_reads_the_home_and_drives_powershell"


def blank(text):
    """Replace comment and string-literal bytes with spaces, preserving offsets."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = j if j > 0 else n
            out.append(" " * (j - i))
            i = j
        elif text[i] == '"':
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == '"':
                    break
                j += 1
            j = min(j, n - 1)
            out.append(" " * (j - i + 1))
            i = j + 1
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def body_after(text, idx):
    """The brace-matched block that starts at the first { at or after idx."""
    start = text.find("{", idx)
    if start < 0:
        return ""
    depth, j = 0, start
    while j < len(text):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start : j + 1]
        j += 1
    return text[start:]


CALL = {fn: re.compile(r"(?<![A-Za-z0-9_])" + fn + r"\(") for fn in FNS}
PARAM_CALL = {fn: re.compile(r"(?<![A-Za-z0-9_])" + fn + r"\(") for fn in PARAMETERIZED}
TEST_FN = re.compile(r"((?:[ \t]*#\[[^\]]*\][ \t]*\n)+)[ \t]*fn (\w+)\(\)")


def scan(raw):
    """Return (home offenders, profile offenders, tests seen) for one source."""
    code = blank(raw)
    if len(code) != len(raw):
        raise AssertionError("blanker changed the length; offsets are untrustworthy")

    unpinned_home, unpinned_profile, seen = [], [], 0
    for m in TEST_FN.finditer(code):
        attrs, name = m.group(1), m.group(2)
        if "#[test]" not in attrs:
            continue
        seen += 1
        body = body_after(code, m.end())
        raw_body = raw[m.end() : m.end() + len(body)]
        serial = "#[serial]" in attrs

        calls = [fn for fn, pat in CALL.items() if pat.search(body)]
        if calls and not serial and name not in ALLOWED:
            unpinned_home.append((name, calls))

        reaches = calls or [fn for fn, pat in PARAM_CALL.items() if pat.search(body)]
        if (
            '"powershell"' in raw_body
            and reaches
            and 'EnvVarGuard::unset("PROFILE")' not in raw_body
        ):
            unpinned_profile.append(name)
    return unpinned_home, unpinned_profile, seen


def run_controls():
    """Every control, before a single tree file is read. Raises on any failure."""
    blanked = blank(BLANKER_FIXTURE)
    if len(blanked) != len(BLANKER_FIXTURE):
        raise AssertionError("blanker control: length changed, offsets are untrustworthy")
    for needle in BLANKER_MUST_VANISH:
        if needle in blanked:
            raise AssertionError(
                f"blanker control: {needle!r} survived blanking, so the scan would "
                "count comments and string literals as call sites"
            )
    if not re.search(r"(?<![A-Za-z0-9_])home_dir\(", blanked):
        raise AssertionError(
            f"blanker control: {BLANKER_MUST_SURVIVE!r} did not survive blanking, so "
            "the scan would count nothing and report every tree clean"
        )

    home, profile, seen = scan(RECOGNISER_FIXTURE)
    if seen != 2:
        raise AssertionError(
            f"recogniser control: parsed {seen} of 2 fixture tests, so the walk has "
            "stopped finding test bodies and would report every tree clean"
        )
    if [n for n, _ in home] != [RECOGNISER_OFFENDER]:
        raise AssertionError(
            "recogniser control: rule one no longer names exactly the known "
            f"offender; it named {[n for n, _ in home]}"
        )
    if profile != [RECOGNISER_OFFENDER]:
        raise AssertionError(
            "recogniser control: rule two no longer names exactly the known "
            f"offender; it named {profile}"
        )
    if RECOGNISER_TWIN in [n for n, _ in home] or RECOGNISER_TWIN in profile:
        raise AssertionError(
            "recogniser control: the pinned twin was reported, so this guard would "
            "refuse a correctly isolated test"
        )


def discover(root):
    """Every Rust source under ROOTS whose CODE reaches one of the call sites."""
    found = []
    for top in ROOTS:
        for path in sorted((root / top).rglob("*.rs")):
            code = blank(path.read_text(encoding="utf-8", errors="replace"))
            if any(pat.search(code) for pat in CALL.values()):
                found.append(path)
    return found


def main(argv):
    root = Path(argv[1]) if len(argv) > 1 else Path.cwd()
    run_controls()

    files = discover(root)
    relative = [str(p.relative_to(root)) for p in files]
    if not files:
        raise AssertionError(
            "discovery control: no file under "
            f"{'/, '.join(ROOTS)}/ reaches these call sites, so this run graded "
            "nothing. Either the walk is broken or the functions were renamed; "
            "fix this guard before trusting it"
        )
    if DISCOVERY_ANCHOR not in relative:
        raise AssertionError(
            f"discovery control: {DISCOVERY_ANCHOR} is not in the discovered set, so "
            "the walk no longer reaches the module this class is known to live in"
        )

    home_hits, profile_hits, unscannable = [], [], []
    for path, rel in zip(files, relative):
        home, profile, seen = scan(path.read_text(encoding="utf-8", errors="replace"))
        if seen == 0:
            unscannable.append(rel)
        home_hits.extend((rel, name, calls) for name, calls in home)
        profile_hits.extend((rel, name) for name in profile)

    for rel, name, calls in home_hits:
        print(f"{rel}: {name} resolves a home via {', '.join(calls)} and is not #[serial]")
    for rel, name in profile_hits:
        print(f"{rel}: {name} drives the powershell arm without unsetting PROFILE")
    for rel in unscannable:
        print(f"{rel}: reaches these call sites and this guard parsed no #[test] in it")

    if home_hits:
        print(
            f"\n{len(home_hits)} test(s) resolve a home without #[serial]. Such a test "
            "passes on a quiet machine, lands, and ejects a merge-queue entry later "
            "from inside a merge_group run that marks no pull request. Add #[serial] "
            "and point HOME at a tempdir, or add the test to ALLOWED in this guard if "
            "reading the real home is its contract."
        )
    if profile_hits:
        print(
            f"\n{len(profile_hits)} test(s) drive the powershell arm without pinning "
            "PROFILE. shell_rc_in prefers PROFILE over the home it is handed, so on a "
            "runner that sets it the plan correctly leaves the home and any assertion "
            'about the home is wrong rather than flaky. Add EnvVarGuard::unset("PROFILE") '
            "and #[serial]. Taking a home as a parameter does NOT exempt a test from "
            "this: the home stops being the only input, it does not become the only one."
        )
    if unscannable:
        print(
            f"\n{len(unscannable)} file(s) reach these call sites and yielded no parsed "
            "test. That is not a pass: it is this guard failing to read them. Either "
            "the test shape changed or the parser broke; fix this guard."
        )

    if not (home_hits or profile_hits or unscannable):
        print(
            f"{len(files)} file(s) reach a home resolver; every test in them that does "
            "is #[serial], and every one driving the powershell arm pins PROFILE"
        )
        return 0
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except AssertionError as error:
        sys.exit(f"check-home-reader-tests: {error}")
