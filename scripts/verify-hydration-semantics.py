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

Given the base branch's manifest, the guard also holds each version number to
one meaning. Two changes cut from one base can each move the replay surface
and each claim the next number, and each passes alone. A merge that keeps both
passes too, with two meanings under one number, so a store stamped with it
would claim a replay it never ran. Against a base, a head that changes the
pinned surface must record a higher version than the base does. A change that
leaves replay semantics alone (a rename, a comment, a refactor) may keep the
base's number when `same_epoch_changes` records it: each entry names the
guarded function or file, the exact digest it now has, and why replay is
unchanged, so a later edit to the same function is not excused by it.

Usage: verify-hydration-semantics.py [repo_root] [--base-manifest PATH | --base-ref REF]
       verify-hydration-semantics.py [repo_root] --write

The optional repo_root selects the tree to scan (default: the repo containing
this script). The manifest always travels with the script — it is the policy,
not a property of the tree under test — which lets CI point the guard at a
deliberately poisoned copy and assert that it fails. `--base-ref` reads the
base manifest from git at REF, beside this script's own path; a base that
predates the manifest has nothing to compare and is reported, not failed.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

# Flags that take the next argument as their value, so the repository root is
# the first argument that is neither a flag nor a flag's value.
VALUE_FLAGS = ("--base-manifest", "--base-ref")


def positional_args(argv):
    positional = []
    skip = False
    for arg in argv:
        if skip:
            skip = False
        elif arg in VALUE_FLAGS:
            skip = True
        elif not arg.startswith("--"):
            positional.append(arg)
    return positional


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_POSITIONAL = positional_args(sys.argv[1:])
KIN_ROOT = os.path.abspath(_POSITIONAL[0]) if _POSITIONAL else os.path.dirname(SCRIPT_DIR)
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "hydration-semantics-manifest.json")
MANIFEST_NAME = os.path.basename(MANIFEST_PATH)

# What a same-epoch entry records for a guarded function or file that the head
# no longer pins at all.
REMOVED = "removed"

# Every entry names an accountable owner and says why the function is part of
# the replay-semantics surface, so the guarded set cannot grow or shrink
# without a stated reason.
REQUIRED_FIELDS = ("file", "function", "digest", "reason", "owner")

# The file and constant that declare the dial this manifest is pinned to.
VERSION_FILE = "crates/kin-index/src/history.rs"
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


def verify_guarded_files(manifest, errors, refresh=False):
    """Exact source pins for dedicated authoring modules with method bodies."""
    entries = manifest.get("guarded_files", [])
    if not isinstance(entries, list):
        errors.append("guarded_files must be an array")
        return 0
    seen = set()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(field), str) or not entry[field].strip()
            for field in ("file", "digest", "reason", "owner")
        ):
            errors.append(f"guarded_files[{index}] has missing/malformed required fields")
            continue
        relative = entry["file"]
        if (os.path.isabs(relative) or "\\" in relative or "\0" in relative
                or any(part in ("", ".", "..") for part in relative.split("/"))):
            errors.append(f"guarded_files[{index}] has malformed repository-relative path")
            continue
        if relative in seen:
            errors.append(f"duplicate guarded file path: {relative}")
            continue
        seen.add(relative)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", entry["digest"]):
            errors.append(f"guarded file {relative} has malformed SHA-256 digest")
            continue
        path = os.path.join(KIN_ROOT, relative)
        if os.path.commonpath([os.path.realpath(KIN_ROOT), os.path.realpath(path)]) != os.path.realpath(KIN_ROOT):
            errors.append(f"guarded file {relative} resolves outside repository")
            continue
        try:
            with open(path, "rb") as source:
                actual = "sha256:" + hashlib.sha256(source.read()).hexdigest()
        except OSError as error:
            errors.append(f"cannot read guarded file {relative}: {error}")
            continue
        if refresh:
            entry["digest"] = actual
        elif actual != entry["digest"]:
            errors.append(f"guarded source file {relative} changed: recorded {entry['digest']}, actual {actual}. Decide whether replay semantics changed and explicitly update the version/digest; no migration is implied.")
    return len(entries)


def pinned_surface(manifest):
    """Every pin in a manifest, keyed by (file, function), with its digest.

    A whole-file pin is keyed with no function. Malformed entries are skipped
    here: the digest checks report them against the head, and a base that
    carried one can only make the comparison stricter.
    """
    surface = {}
    for entry in manifest.get("guarded", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("file"), str) and isinstance(entry.get("function"), str):
            surface[(entry["file"], entry["function"])] = entry.get("digest")
    for entry in manifest.get("guarded_files", []) or []:
        if isinstance(entry, dict) and isinstance(entry.get("file"), str):
            surface[(entry["file"], None)] = entry.get("digest")
    return surface


def surface_label(key):
    path, function = key
    return f"`{function}` in {path}" if function else f"guarded file {path}"


def same_epoch_excuses(manifest, errors):
    """The `same_epoch_changes` entries, keyed like `pinned_surface`."""
    entries = manifest.get("same_epoch_changes", [])
    if not isinstance(entries, list):
        errors.append("same_epoch_changes must be an array")
        return {}
    excuses = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict) or any(
            not isinstance(entry.get(field), str) or not entry[field].strip()
            for field in ("file", "digest", "reason")
        ) or ("function" in entry and (not isinstance(entry["function"], str) or not entry["function"].strip())):
            errors.append(
                f"same_epoch_changes[{index}] needs a file, the exact digest it excuses (or "
                f'"{REMOVED}") and a reason, and a function name when it excuses a function'
            )
            continue
        excuses[(entry["file"], entry.get("function"))] = entry["digest"]
    return excuses


def compare_with_base(manifest, base, base_label, errors):
    """Hold the head's version to one meaning against the base's manifest."""
    head_version = manifest.get("hydration_semantics_version")
    base_version = base.get("hydration_semantics_version")
    if not isinstance(base_version, int):
        errors.append(f"the manifest at {base_label} records no integer `hydration_semantics_version` to compare against")
        return
    if not isinstance(head_version, int):
        return
    if head_version < base_version:
        errors.append(
            f"{VERSION_CONST} is {head_version}, below the {base_version} that {base_label} "
            "already records. A store stamped with the higher number would read as current "
            "under a replay older than the one it ran; take a number above the base's."
        )
        return
    excuses = same_epoch_excuses(manifest, errors)
    if head_version > base_version:
        return
    head = pinned_surface(manifest)
    prior = pinned_surface(base)
    changed = sorted(
        (key for key in head.keys() | prior.keys() if head.get(key) != prior.get(key)),
        key=lambda key: (key[0], key[1] or ""),
    )
    unexcused = [key for key in changed if excuses.get(key) != head.get(key, REMOVED)]
    if not unexcused:
        return
    listing = "\n".join(f"      - {surface_label(key)}" for key in unexcused)
    template = json.dumps(
        [
            {
                "file": key[0],
                **({"function": key[1]} if key[1] else {}),
                "digest": head.get(key, REMOVED),
                "reason": "why replay semantics are unchanged",
            }
            for key in unexcused
        ],
        indent=2,
    )
    errors.append(
        f"{VERSION_CONST} stays at {head_version}, the number {base_label} already records, "
        "but the replay surface pinned under it changed:\n"
        f"{listing}\n"
        "    A version names one replay. Two changes that each took the next number from one "
        "base collide here, and a merge that keeps both must move one of them up.\n"
        f"      - if replay semantics changed, set {VERSION_CONST} and "
        f"`hydration_semantics_version` above {base_version};\n"
        "      - if they did not, record each entry under `same_epoch_changes` in "
        f"scripts/{MANIFEST_NAME}:\n{template}"
    )


def read_base_manifest(path=None, ref=None):
    """Load the base manifest from a file or from git at `ref`.

    Returns (manifest or None, label, error or None). A git base that has no
    manifest at this path predates the guard, which leaves nothing to compare.
    """
    if path is not None:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f), f"the base manifest {path}", None
        except Exception as e:
            return None, path, f"cannot load base manifest {path}: {e}"
    label = f"the base {ref}"
    prefix = subprocess.run(
        ["git", "-C", SCRIPT_DIR, "rev-parse", "--show-prefix"],
        capture_output=True,
        text=True,
    )
    if prefix.returncode != 0:
        return None, label, f"cannot locate this script in git to read {label}: {prefix.stderr.strip()}"
    commit = subprocess.run(
        ["git", "-C", SCRIPT_DIR, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    if commit.returncode != 0:
        return None, label, f"{ref} does not name a commit here, so the version cannot be compared with its base"
    blob = f"{commit.stdout.strip()}:{prefix.stdout.strip()}{MANIFEST_NAME}"
    exists = subprocess.run(
        ["git", "-C", SCRIPT_DIR, "cat-file", "-e", blob], capture_output=True, text=True
    )
    if exists.returncode != 0:
        return None, label, None
    shown = subprocess.run(["git", "-C", SCRIPT_DIR, "show", blob], capture_output=True, text=True)
    if shown.returncode != 0:
        return None, label, f"cannot read the manifest at {ref}: {shown.stderr.strip()}"
    try:
        return json.loads(shown.stdout), label, None
    except ValueError as e:
        return None, label, f"the manifest at {ref} is not JSON: {e}"


def main(base_manifest=None, base_ref=None):
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

    file_count = verify_guarded_files(manifest, errors)

    compared = ""
    if base_manifest is not None or base_ref is not None:
        base, base_label, base_error = read_base_manifest(base_manifest, base_ref)
        if base_error:
            errors.append(base_error)
        elif base is None:
            compared = f" {base_label} has no manifest, so there is no earlier version to hold it above."
        else:
            compare_with_base(manifest, base, base_label, errors)
            compared = (
                f" Against {base_label}, at {base.get('hydration_semantics_version')}, "
                "the version names one replay."
            )
    else:
        same_epoch_excuses(manifest, errors)

    if errors:
        print(f"Hydration replay-semantics guard FAILED ({len(errors)} problem(s)):\n")
        for e in errors:
            fail(e)
        return 1

    print(
        f"Hydration replay-semantics guard passed: {len(entries)} guarded function(s) "
        f"and {file_count} guarded file(s) match the manifest at {VERSION_CONST}={recorded_version}."
        + compared
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

    verify_guarded_files(manifest, errors, refresh=True)
    if errors:
        for error in errors:
            fail(error)
        return 1

    # A same-epoch entry excuses one exact digest. One that no longer matches
    # what the tree pins can never excuse anything again, so it goes.
    if isinstance(manifest.get("same_epoch_changes"), list):
        surface = pinned_surface(manifest)
        manifest["same_epoch_changes"] = [
            entry
            for entry in manifest["same_epoch_changes"]
            if isinstance(entry, dict)
            and entry.get("digest") == surface.get((entry.get("file"), entry.get("function")), REMOVED)
        ]

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"Rewrote {MANIFEST_PATH} at {VERSION_CONST}={version}.")
    return 0


def flag_value(argv, flag):
    if flag not in argv:
        return None
    index = argv.index(flag)
    if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
        fail(f"{flag} needs a value")
        sys.exit(2)
    return argv[index + 1]


if __name__ == "__main__":
    arguments = sys.argv[1:]
    known = {"--write", *VALUE_FLAGS}
    unknown = [arg for arg in arguments if arg.startswith("--") and arg not in known]
    if unknown or len(positional_args(arguments)) > 1:
        fail(f"unrecognized arguments: {' '.join(unknown or positional_args(arguments)[1:])}")
        sys.exit(2)
    base_manifest = flag_value(arguments, "--base-manifest")
    base_ref = flag_value(arguments, "--base-ref")
    if base_manifest is not None and base_ref is not None:
        fail("pass --base-manifest or --base-ref, not both")
        sys.exit(2)
    if "--write" in arguments:
        if base_manifest is not None or base_ref is not None:
            fail("--write records the tree as it is and compares with no base")
            sys.exit(2)
        sys.exit(write_digests())
    sys.exit(main(base_manifest, base_ref))
