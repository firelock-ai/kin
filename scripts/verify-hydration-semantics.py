#!/usr/bin/env python3
"""Hydration replay-semantics guard.

Kin's deep history is not a stored fact. It is a projection re-authored at
ingest by the hydration replay algorithm, so the bytes persisted for a change
are a function of the code in this guard's manifest. A merge change's
`entity_deltas`/`relation_deltas` are discarded and recomputed from the
all-parent runtime baseline, which means an edit to any of those functions
silently changes what Kin reports about the past.

`HYDRATION_SEMANTICS_VERSION` is the declared dial for that class of change,
but nothing mechanically couples the two: the constant sat at 3 across the
releases that shipped the replay rewrite, and the hydration checkpoint was
invalidated only incidentally by an unrelated parser-version bump.

This guard supplies the missing coupling. It digests each guarded function's
source and compares it against the digest recorded in the manifest. Any edit
fails CI until a human updates the manifest entry, and updating that entry puts
the recorded `hydration_semantics_version` in front of them. The guard also
asserts the manifest's recorded version still equals the live constant, so the
two cannot drift apart unnoticed.

A digest is deliberately NOT a "bump the version on every edit" rule. Most
edits to these functions (a rename, a perf refactor) do not change replay
semantics, and forcing a bump on each one trains the reflex this guard exists
to prevent. What it forces is an explicit, reviewed decision.

Usage: verify-hydration-semantics.py [repo_root]

The optional repo_root selects the tree to scan (default: the repo containing
this script). The manifest always travels with the script — it is the policy,
not a property of the tree under test — which lets CI point the guard at a
deliberately poisoned copy and assert that it fails.
"""
import hashlib
import json
import os
import re
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KIN_ROOT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(SCRIPT_DIR)
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "hydration-semantics-manifest.json")

# Every entry names an accountable owner and says why the function is part of
# the replay-semantics surface, so the guarded set cannot grow or shrink
# without a stated reason.
REQUIRED_FIELDS = ("file", "function", "digest", "reason", "owner")

# The file and constant that declare the dial this manifest is pinned to.
VERSION_FILE = "crates/kin-cli/src/commands/init/history_checkpoint.rs"
VERSION_CONST = "HYDRATION_SEMANTICS_VERSION"

# Applied with `.match(code, line_start)`, which anchors at the offset; a
# leading `^` would only ever match at position zero without re.MULTILINE.
FN_START = re.compile(
    r"(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:async\s+)?(?:unsafe\s+)?"
    r"(?:extern\s+\"[^\"]*\"\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b"
)

# Matched with an explicit `pos` rather than against a slice: these run at every
# character of a multi-hundred-KB file, and slicing would copy the whole
# remainder each time, making the scan quadratic.
RAW_STRING_START = re.compile(r'(?:b)?r(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\.|[^\\'])'")


def fail(message):
    print(f"::error::{message}")


def strip_to_code(text):
    """Blank out comments and literal contents, preserving length and newlines.

    Brace matching must not be fooled by a `{` inside a string or a comment.
    Returning a same-length buffer lets the caller index straight back into the
    original source, so the digest is taken over the real bytes rather than
    this stripped view.
    """
    out = list(text)
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        # Line comment.
        if c == "/" and nxt == "/":
            while i < n and text[i] != "\n":
                out[i] = " "
                i += 1
            continue

        # Block comment (Rust nests them).
        if c == "/" and nxt == "*":
            depth = 0
            while i < n:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth += 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth -= 1
                    out[i] = out[i + 1] = " "
                    i += 2
                    if depth == 0:
                        break
                    continue
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue

        # Raw string: r"..." / r#"..."# / br#"..."#
        m = RAW_STRING_START.match(text, i)
        if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            hashes = m.group(1)
            terminator = '"' + hashes
            start = m.end()
            end = text.find(terminator, start)
            end = n if end == -1 else end + len(terminator)
            for j in range(i, end):
                if text[j] != "\n":
                    out[j] = " "
            i = end
            continue

        # Normal string.
        if c == '"':
            out[i] = " "
            i += 1
            while i < n:
                if text[i] == "\\":
                    if text[i] != "\n":
                        out[i] = " "
                    if i + 1 < n and text[i + 1] != "\n":
                        out[i + 1] = " "
                    i += 2
                    continue
                if text[i] == '"':
                    out[i] = " "
                    i += 1
                    break
                if text[i] != "\n":
                    out[i] = " "
                i += 1
            continue

        # Char literal, but not a lifetime (`'a`) — only a real `'x'`/`'\n'`.
        if c == "'":
            m = CHAR_LITERAL.match(text, i)
            if m:
                for j in range(i, m.end()):
                    out[j] = " "
                i = m.end()
                continue

        i += 1
    return "".join(out)


# Several guarded functions share one (large) file; strip it once per tree.
_STRIP_CACHE = {}


def _stripped(source):
    key = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if key not in _STRIP_CACHE:
        _STRIP_CACHE[key] = strip_to_code(source)
    return _STRIP_CACHE[key]


def extract_function(source, name):
    """Return the exact source text of top-level `fn name`, or None.

    Anchored at column zero: these are all free functions in the guarded
    modules, and refusing to match an indented definition keeps the guard from
    silently latching onto a same-named helper nested in a test module.
    """
    code = _stripped(source)
    matches = []
    for line_match in re.finditer(r"^.*$", code, re.MULTILINE):
        line_start = line_match.start()
        m = FN_START.match(code, line_start)
        if m and m.group("name") == name:
            matches.append(line_start)

    if len(matches) != 1:
        return None, len(matches)

    start = matches[0]
    brace = code.find("{", start)
    if brace == -1:
        return None, 1

    depth = 0
    for i in range(brace, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start : i + 1], 1
    return None, 1


def digest_of(text):
    """SHA-256 over the function source, normalized for line endings and
    trailing whitespace only. Everything else — every token, every brace — is
    load-bearing, because it is what re-authors history."""
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    normalized = "\n".join(lines).strip() + "\n"
    return "sha256:" + hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def load_manifest():
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        fail(f"cannot load hydration semantics manifest {MANIFEST_PATH}: {e}")
        sys.exit(1)


def live_version(errors):
    path = os.path.join(KIN_ROOT, VERSION_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
    except Exception as e:
        errors.append(f"cannot read {VERSION_FILE}: {e}")
        return None
    m = re.search(
        rf"^\s*(?:pub(?:\([^)]*\))?\s+)?const\s+{VERSION_CONST}\s*:\s*u32\s*=\s*(\d+)\s*;",
        source,
        re.MULTILINE,
    )
    if not m:
        errors.append(
            f"{VERSION_FILE} no longer declares `const {VERSION_CONST}: u32`; "
            "this guard pins the manifest to that constant and cannot verify it"
        )
        return None
    return int(m.group(1))


def main():
    manifest = load_manifest()
    entries = manifest.get("guarded", [])
    errors = []

    if not entries:
        fail("hydration semantics manifest lists no guarded functions")
        return 1

    recorded_version = manifest.get("hydration_semantics_version")
    actual_version = live_version(errors)
    if recorded_version is None:
        errors.append("manifest is missing `hydration_semantics_version`")
    elif actual_version is not None and recorded_version != actual_version:
        errors.append(
            f"{VERSION_CONST} is {actual_version} but the manifest records "
            f"{recorded_version}. The dial and the pinned replay surface must move "
            "together: update `hydration_semantics_version` in "
            "scripts/hydration-semantics-manifest.json"
        )

    sources = {}
    for index, entry in enumerate(entries):
        missing = [f for f in REQUIRED_FIELDS if not entry.get(f)]
        if missing:
            errors.append(f"guarded[{index}] is missing required field(s): {', '.join(missing)}")
            continue

        rel_path = entry["file"]
        name = entry["function"]
        abs_path = os.path.join(KIN_ROOT, rel_path)

        if rel_path not in sources:
            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    sources[rel_path] = f.read()
            except Exception as e:
                errors.append(f"cannot read {rel_path} (guarding `{name}`): {e}")
                sources[rel_path] = None
        source = sources[rel_path]
        if source is None:
            continue

        text, found = extract_function(source, name)
        if text is None:
            if found == 0:
                errors.append(
                    f"`{name}` no longer exists as a top-level fn in {rel_path}. If the "
                    "replay surface moved or was renamed, update "
                    "scripts/hydration-semantics-manifest.json to point at its new home"
                )
            elif found > 1:
                errors.append(
                    f"`{name}` matches {found} top-level definitions in {rel_path}; "
                    "the guard cannot tell which one authors history"
                )
            else:
                errors.append(f"cannot delimit the body of `{name}` in {rel_path}")
            continue

        actual = digest_of(text)
        if actual != entry["digest"]:
            errors.append(
                f"`{name}` in {rel_path} changed.\n"
                f"    recorded: {entry['digest']}\n"
                f"    actual:   {actual}\n"
                "    This function re-authors persisted history. Decide whether the change "
                "alters replay semantics for ALREADY-INGESTED repositories:\n"
                f"      - if it does, bump {VERSION_CONST} in {VERSION_FILE} and set the "
                "manifest's `hydration_semantics_version` to match;\n"
                "      - either way, record the new digest in "
                "scripts/hydration-semantics-manifest.json.\n"
                "    Regenerate digests with: "
                "python3 scripts/verify-hydration-semantics.py --write"
            )

    if errors:
        print(f"Hydration replay-semantics guard FAILED ({len(errors)} problem(s)):\n")
        for e in errors:
            fail(e)
        return 1

    print(
        f"Hydration replay-semantics guard passed: {len(entries)} guarded function(s) "
        f"match the manifest at {VERSION_CONST}={recorded_version}."
    )
    return 0


def write_digests():
    """Rewrite the manifest's digests and version from the current tree.

    Deliberately a separate, explicit invocation: it exists so updating a
    pinned digest is a decision the author records, never something the guard
    does for them on the way past.
    """
    manifest = load_manifest()
    errors = []
    version = live_version(errors)
    if errors:
        for e in errors:
            fail(e)
        return 1
    manifest["hydration_semantics_version"] = version

    for entry in manifest.get("guarded", []):
        path = os.path.join(KIN_ROOT, entry["file"])
        with open(path, "r", encoding="utf-8") as f:
            source = f.read()
        text, found = extract_function(source, entry["function"])
        if text is None:
            fail(f"cannot extract `{entry['function']}` from {entry['file']} (matches: {found})")
            return 1
        entry["digest"] = digest_of(text)

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"Rewrote {MANIFEST_PATH} at {VERSION_CONST}={version}.")
    return 0


if __name__ == "__main__":
    if "--write" in sys.argv:
        sys.argv = [a for a in sys.argv if a != "--write"]
        KIN_ROOT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(SCRIPT_DIR)
        sys.exit(write_digests())
    sys.exit(main())
