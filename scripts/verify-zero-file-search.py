#!/usr/bin/env python3
"""Zero File-Search Authority guard.

Kin answers locate/search/context/trace/review/xref/rename queries from
graph-owned truth, never by consulting raw filesystem contents. This guard
fails when a raw filesystem read, existence, or traversal primitive appears in
an answer path outside the justified allowlist.

Usage: verify-zero-file-search.py [repo_root]

The optional repo_root selects the tree to scan (default: the repo containing
this script). The allowlist always travels with the script — it is the policy,
not a property of the tree under test — which lets CI point the guard at a
deliberately poisoned copy and assert that it fails.

Allowlist validation never short-circuits the scan. A stale pin used to abort
before the walk began, so CI reported the pin errors and nothing else: on one
change two stale pins hid ten real violations in a newly covered crate. The
gate still failed closed, but a red allowlist stopped being a measure of the
work left. The scan now always runs to completion, an unvalidated pin masks
nothing so the lines it claimed are reported like any other, and allowlist
errors are printed after the scan with both feeding the exit status.
"""
import os
import sys
import json
import re
from datetime import date

# Resolve paths relative to kin repo root
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
KIN_ROOT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.dirname(SCRIPT_DIR)
ALLOWLIST_PATH = os.path.join(SCRIPT_DIR, "zero-file-search-allowlist.json")

# Every allowlist entry must carry these so each exemption has an accountable
# owner and a date by which it is re-justified or removed.
REQUIRED_FIELDS = ("file", "reason", "owner", "expiration")


class Policy:
    """What the allowlist exempts inside one file.

    `whole_file` skips the file outright. Otherwise the file is scanned and only
    the validated pins are excused: `matches` masks exact expressions and `fns`
    skips named function bodies. A pin that failed validation never reaches
    here, so the lines it claimed are reported like any other.
    """

    __slots__ = ("whole_file", "matches", "fns")

    def __init__(self):
        self.whole_file = False
        self.matches = set()
        self.fns = set()


def parse_pin(item, key):
    """Normalize one pin into (value, expected_count).

    A bare string means "occurs exactly once", which is the right default: it
    proves the pin names one specific site rather than a shape that repeats.
    The object form declares a count, for the cases where exactly-once cannot
    be expressed: a cfg-gated pair of same-named functions, or a boundary
    expression that legitimately recurs. The count is enforced exactly, so a
    new occurrence still fails the guard and has to be re-justified.
    """
    if isinstance(item, str):
        if not item or "\n" in item:
            raise ValueError("want a non-empty single-line string")
        return item, 1
    if not isinstance(item, dict):
        raise ValueError("want a string or an object")
    unknown = set(item) - {key, "count"}
    if unknown:
        raise ValueError(f"unknown field(s): {', '.join(sorted(unknown))}")
    value = item.get(key)
    if not isinstance(value, str) or not value or "\n" in value:
        raise ValueError(f"'{key}' must be a non-empty single-line string")
    count = item.get("count", 1)
    if not isinstance(count, int) or isinstance(count, bool) or count < 1:
        raise ValueError("'count' must be a positive integer")
    return value, count


def parse_pin_list(raw, key):
    """Normalize a pin list into {value: count}, raising on any malformation."""
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"want a non-empty list of {key} pins")
    pins = {}
    for item in raw:
        value, count = parse_pin(item, key)
        if value in pins:
            raise ValueError(f"repeats the pin {value!r}")
        pins[value] = count
    return pins


def load_allowlist():
    """Load and validate the allowlist, returning ({file: Policy}, errors).

    Errors are returned rather than raised so the caller can complete the scan
    first. Nothing here exits.

    Each entry must declare file, reason, owner, and an ISO `expiration` date,
    and must name a path that actually exists. Missing fields, malformed dates,
    past-due exemptions, and entries for deleted files all fail the guard, so
    exemptions cannot silently accumulate, outlive their justification, or sit
    dormant waiting to auto-exempt a file that gets recreated under the same
    path.

    `allow_match` and `allow_fn` are optional and compose. `allow_match` lists
    exact source expressions that are exempt within that file, mirroring
    `allow_for` in scripts/zero_file_search_guard.sh; the scanner masks only
    those bytes and still checks the rest of the line, so a second primitive
    beside the allowed one cannot inherit the exemption. `allow_fn` names
    function bodies that are an IO boundary in whole, which is how a mixed
    file keeps every other line scanned even when it both answers queries and
    serves package registries and writes its own auth token. Each pin's
    occurrence count is enforced exactly, and counted over the text the scan
    actually reads rather than the raw file, so a pin can only ever license
    sites the guard would otherwise report.

    When neither is present the whole file is exempt, which is only appropriate
    for files that are an IO boundary end to end.

    A pin whose count does not match is dropped rather than applied, so the
    scan reports the lines that pin claimed and the true scope stays visible.
    An expired or malformed expiration is an accountability failure rather than
    a scope question, so it is reported while the exemption still applies.
    """
    errors = []
    try:
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        errors.append(f"  could not load allowlist from {ALLOWLIST_PATH}: {e}")
        return {}, errors

    entries = data.get("allowlist", [])
    policies = {}
    today = date.today()

    for i, item in enumerate(entries):
        missing = [k for k in REQUIRED_FIELDS if not item.get(k)]
        if missing:
            errors.append(
                f"  entry #{i} ({item.get('file', '?')}) missing required "
                f"field(s): {', '.join(missing)}"
            )
            continue

        source_path = os.path.join(KIN_ROOT, item["file"])
        if not os.path.exists(source_path):
            errors.append(
                f"  entry {item['file']} names a path that does not exist "
                f"(owner: {item['owner']}) — remove the stale exemption; leaving "
                f"it would silently exempt any file later recreated at that path"
            )
            continue

        if item["file"] in policies:
            errors.append(
                f"  entry {item['file']} is duplicated — one file must have "
                "exactly one allowlist policy"
            )
            continue

        policy = Policy()
        policies[item["file"]] = policy

        raw_matches = item.get("allow_match")
        raw_fns = item.get("allow_fn")
        policy.whole_file = raw_matches is None and raw_fns is None

        lines = None
        lexed = None
        if not policy.whole_file:
            try:
                with open(source_path, "r", encoding="utf-8") as source_file:
                    lines = source_file.readlines()
            except OSError as error:
                errors.append(f"  entry {item['file']} could not be read: {error}")
            else:
                lexed = lex_lines(lines)

        if policy.whole_file and not scan_reaches(item["file"]):
            errors.append(
                f"  entry {item['file']} exempts the whole file, but the scan "
                f"never reaches that path (owner: {item['owner']}), so the "
                "exemption grants nothing and only records a claim nothing "
                "enforces. Remove it, or pin the boundary, which forces the "
                "file to be scanned around the pins"
            )

        # `allow_fn` is validated first because the bodies it excuses decide
        # which lines the scan reads, and those lines are what `allow_match`
        # counts have to be measured against.
        if raw_fns is not None and lexed is not None:
            try:
                bodies = find_fn_body_ranges(lines, None, lexed)
                scanned = {index for index, _ in scannable_lines(lexed)}
                for name, want in parse_pin_list(raw_fns, "fn").items():
                    found = len(bodies.get(name, ()))
                    if found != want:
                        errors.append(
                            f"  entry {item['file']} allow_fn {name!r} resolves to "
                            f"{found} function bodies (want {want})"
                        )
                        continue
                    if not any(
                        index in scanned
                        for lo, hi in bodies[name]
                        for index in range(lo, hi + 1)
                    ):
                        errors.append(
                            f"  entry {item['file']} allow_fn {name!r} names a body "
                            "the scan never reads, so the exemption excuses "
                            "nothing. A test-gated or otherwise unscanned "
                            "function needs no entry. Remove it"
                        )
                        continue
                    policy.fns.add(name)
            except ValueError as error:
                errors.append(f"  entry {item['file']} has an invalid allow_fn: {error}")

        if raw_matches is not None and lexed is not None:
            try:
                pins = parse_pin_list(raw_matches, "expr")
            except ValueError as error:
                errors.append(f"  entry {item['file']} has an invalid allow_match: {error}")
            else:
                counts = count_pins_in_scan(lines, lexed, policy.fns, pins)
                for expression, want in pins.items():
                    found = counts[expression]
                    if found != want:
                        errors.append(
                            f"  entry {item['file']} allow_match {expression!r} "
                            f"occurs {found} times in scanned code (want {want})"
                        )
                        continue
                    policy.matches.add(expression)

        try:
            exp_date = date.fromisoformat(item["expiration"])
        except ValueError:
            errors.append(
                f"  entry {item['file']} has invalid expiration "
                f"'{item['expiration']}' (want YYYY-MM-DD)"
            )
            continue
        if exp_date < today:
            errors.append(
                f"  entry {item['file']} exemption expired {item['expiration']} "
                f"(owner: {item['owner']}) — re-justify or remove"
            )

    return policies, errors


BOUNDARY_DIRS = [
    # kin-daemon is deliberately absent. It used to be exempt as a directory,
    # which exempted the RPC surface every agent and CLI reaches Kin through,
    # and a six-handler opt-in rescued roughly a sixtieth of api.rs. The crate
    # is now scanned by default and its boundary IO is declared per file in
    # scripts/zero-file-search-allowlist.json, so a new daemon module, a new
    # query handler above all, is covered the moment it is added.
    "crates/kin-migrate/",
    "crates/kin-index/",
    "crates/kin-registry/",
    "crates/kin-buildinfo/",
    "crates/kin-projection/",
    "crates/kin-reconcile/",
    # kin-core is a mixed crate: it carries the semantic repo's config, layout,
    # init, projection, ingestion, and git-history boundary IO — all legitimate
    # input/output boundaries — but it must not be broadly exempted, or an
    # answer-authority raw-filesystem path (like the retired text_refs source
    # scan that backed `kin refs`/`kin rename`) could hide there again.
    # Enumerate the boundary files explicitly so every other kin-core file,
    # including any newly added one, is scanned by default.
    "crates/kin-core/src/assistant.rs",
    "crates/kin-core/src/assistant_sync.rs",
    "crates/kin-core/src/config.rs",
    # The Windows half of the same config writer. It is the identical boundary
    # as config.rs, split out because publishing a file atomically shares no
    # code between the two platforms, and it answers no query: every call here
    # writes or proves the repository's own config file at a path the caller
    # already validated, never resolves one by searching.
    "crates/kin-core/src/config/windows.rs",
    "crates/kin-core/src/dependencies.rs",
    "crates/kin-core/src/env_registry.rs",
    "crates/kin-core/src/federation.rs",
    "crates/kin-core/src/git_init.rs",
    "crates/kin-core/src/init.rs",
    # Init's own staging directories, and nothing else. It runs before any
    # graph exists, on paths init itself minted, and its whole output is
    # whether a directory this process created still needs removing. It
    # answers no locate/search/context/trace/review/xref query, and the
    # directory it enumerates is the repository's parent, never repository
    # content.
    "crates/kin-core/src/init_staging.rs",
    "crates/kin-core/src/layout.rs",
    "crates/kin-core/src/lib.rs",
    "crates/kin-core/src/manifest.rs",
    "crates/kin-core/src/ref_view.rs",
    "crates/kin-core/src/registry.rs",
    "crates/kin-core/src/shims.rs",
    "crates/kin-core/src/sync_state.rs",
    "crates/kin-core/src/tree.rs",
    # kin-git is scanned by default because it also carries answer-adjacent
    # logic (co-change, blame-style history) that must come from graph truth.
    # These four modules are the Git format boundary itself: capturing a Git
    # repository, reporting what would stop one being admitted, proving a
    # checkout matches its committed seed before admission, and materializing
    # graph-owned history back out as Git. Reading a Git repository from disk is
    # the entire point of an import boundary, and none of these modules answers
    # a locate/search/context/trace/review/xref query. Enumerated file by file
    # so every other kin-git module, including any newly added one, keeps being
    # scanned.
    "crates/kin-git/src/lossless.rs",
    # Runs before any graph exists, on the source Git repository, and produces
    # only refusals. Nothing it reads reaches a query answer, and its whole
    # output is a list of reasons admission cannot start.
    "crates/kin-git/src/admission_blockers.rs",
    "crates/kin-git/src/preflight.rs",
    "crates/kin-git/src/repository_export.rs",
    "crates/kin-runtime/",
    "crates/kin-parser/",
    "crates/kin-ranking/src/ltr.rs",
    "crates/kin-cli/src/daemon_client.rs",
    "crates/kin-cli/src/profile.rs",
    "crates/kin-cli/src/main.rs",
    "crates/kin-cli/src/backend.rs"
]

QUERY_COMMANDS = {
    "locate.rs",
    "search.rs",
    "trace.rs",
    "trace_data_flow.rs",
    "xref.rs",
    "review.rs",
    "ref_lookup.rs",
    # refs answers incoming-reference queries purely from graph relation edges;
    # scanning it keeps that authority path free of any raw source-tree walk.
    "refs.rs",
    # Context-pack assembly is an answer authority, not an IO boundary.
    "context.rs",
    # rename derives its edit plan — the answer — from the graph's entity and
    # reference relations, so it is an authority path even though applying the
    # plan later writes files.
    "rename.rs",
    # deps answers a cross-repo dependency query. Whether it may answer it from
    # manifests instead of the spine is an open decision; scanning it keeps the
    # question visible instead of silent.
    "deps.rs",
    # Read-only analyses that answer from graph relations, history, and health
    # records. None of them should need the working tree to produce an answer.
    "blame.rs",
    "impact.rs",
    "dead_code.rs",
    "overview.rs",
    # health reports on the local install and graph state. Environment probes
    # here are a diagnostic boundary, but repo-content reads would not be.
    "health.rs",
    # `kin graph validate`/`inspect`/`stats` report on graph integrity itself.
    # A validation surface that decides its answer from the working tree states
    # the filesystem's opinion of the graph rather than the graph's own, which
    # is how the orphan count came to be computed by probing each entity's
    # file_origin with `.exists()`. Orphan status now resolves against the
    # graph-owned exact tree, and scanning this module is what keeps it there.
    "graph.rs",
    # The same graph data, rendered. A visualization that reads the tree would
    # draw a picture of the projection while claiming to draw the graph.
    "graph_viz.rs",
    # Co-change answers from graph-owned CoChanges relations; the Git-format
    # boundary that captures them lives in kin-git, not here.
    "cochange.rs",
    # History answers from recorded commits, not from re-reading the tree.
    "history.rs",
    # `kin mcp` is how agents reach Kin. It is a launcher today and carries no
    # filesystem primitive at all, which is exactly why it belongs here: the
    # agent-facing entry point should never become the one answer surface that
    # nothing was watching.
    "mcp.rs",
    # `kin spec list`/`show` answer from graph-owned specs. The module was
    # outside this set for as long as it answered by reading .kin/specs/*.json,
    # so the guard reported the invariant holding over a surface that was
    # breaking it. Coverage is half the fix: without the module scanned, a
    # later reader could reintroduce the sidecar read and CI would stay green.
    "spec.rs"
}

# Matches a free or method function declaration, including the visibility,
# constness, asyncness, unsafety and ABI a declaration may carry. `pub(crate)`
# was missing for as long as function scoping existed, and every miss was a
# silent one in both directions: a `pub(crate)` handler named for scoping was
# never found, and a `pub(crate)` body an allowlist entry means to excuse would
# not resolve. The ABI string is optional inside `extern`, because bare
# `extern fn` is valid Rust and defaults to "C".
FN_DECL = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?(?:async\s+)?"
    r"(?:unsafe\s+)?(?:extern\s+(?:\"[^\"]*\"\s+)?)?fn\s+([A-Za-z0-9_]+)\s*[(<]"
)


def is_test_file(rel_path):
    # Skip standalone test directories. Anchored to whole path segments: a
    # substring test skipped any module whose name merely contained `test_`,
    # so a `latest_authority.rs` would have been dropped from the scan
    # entirely, and now that the daemon crate is scanned by default that would
    # be silent loss of a new module rather than an exemption it already had.
    segments = rel_path.split("/")
    if (
        "tests" in segments
        or any(segment.startswith("test_") for segment in segments)
        or rel_path.endswith("_test.rs")
    ):
        return True
    # Skip ingestion/migration/projection boundary directories/files
    for bdir in BOUNDARY_DIRS:
        if rel_path.startswith(bdir) or rel_path == bdir:
            return True

    # For CLI commands, only scan query commands
    if "crates/kin-cli/src/commands/" in rel_path:
        filename = os.path.basename(rel_path)
        if filename not in QUERY_COMMANDS:
            return True

    return False


def scan_reaches(rel_path):
    """Whether the walk would scan this path absent any allowlist policy.

    A pinned entry answers yes by construction: naming spans in a file forces it
    to be scanned even inside a boundary directory. A whole-file entry for a path
    the walk skips anyway answers no, and such an entry is inert. Eight of them
    had accumulated on command modules outside the query set and on a file
    already enumerated as a boundary, each reading like an enforced boundary
    declaration while granting exactly nothing. Deciding this from the same walk
    predicate the scan uses is what keeps the two from drifting: add a module to
    QUERY_COMMANDS and its dormant whole-file exemption would begin to matter,
    which is when it has to be re-justified rather than silently inherited.
    """
    return rel_path.startswith("crates/") and not is_test_file(rel_path)


# Patterns to scan.
#
# The first group is the raw filesystem read / existence / traversal primitive
# set shared with scripts/zero_file_search_guard.sh. Answering a semantic query
# by probing the working tree is the violation the rule exists to stop, and it
# does not require the `std::fs::` prefix to happen: `path.exists()`,
# `path.try_exists()`, `File::open`, a bare `read_dir(`, or a `WalkDir`
# traversal all read the tree just as directly. Spawning a subprocess is also
# denied in answer modules: otherwise `rg`, `grep`, `find`, or a multiline
# `git grep` builder can replace the semantic authority behind the guard's
# back.
#
# Writes and directory creation ARE denied here, unlike in the shell guard,
# because the module-qualified patterns below match all of `std::fs::` and the
# named `fs::` calls include the mutating ones. Materialization is a projection
# boundary rather than answer-by-search, so a write in an answer module is not
# the violation this rule exists to stop. It is still a claim worth stating out
# loud, and stating it means an explicit allowlist pin naming the boundary
# rather than a pattern that never looked.
PATTERNS = [
    (re.compile(r'\.is_file\(\)'), "filesystem existence probe (is_file)"),
    (re.compile(r'\.is_dir\(\)'), "filesystem existence probe (is_dir)"),
    (re.compile(r'\.exists\(\)'), "filesystem existence probe (exists)"),
    (re.compile(r'\.try_exists\(\)'), "filesystem existence probe (try_exists)"),
    (re.compile(r'\.is_symlink\(\)'), "filesystem existence probe (is_symlink)"),
    (re.compile(r'\.canonicalize\(\)'), "filesystem path resolution (canonicalize)"),
    (re.compile(r'\.metadata\(\)'), "filesystem metadata probe"),
    (re.compile(r'\bsymlink_metadata\b'), "filesystem metadata probe"),
    (re.compile(r'\bread_link\b'), "filesystem symlink read"),
    (re.compile(r'\bFile::open\b'), "raw file handle open"),
    (re.compile(r'\bread_dir\('), "directory traversal (read_dir)"),
    (re.compile(r'\bWalkDir\b|\bwalkdir::'), "directory traversal (walkdir)"),
    (re.compile(r'\bglob::glob\b'), "filesystem glob"),
    # `process::` catches direct paths and grouped/multiline use trees such as
    # `use std::{process::{Command as SearchProcess}}`; `process as` catches a
    # namespace alias before it can hide a later `Alias::Command::new` call.
    # Bare Command::new covers an imported, unaliased constructor.
    (re.compile(r'\bCommand::new\s*\(|\bprocess\s*(?:::|\bas\b)'), "subprocess execution in answer authority"),
    (re.compile(r'\bstd::fs::[a-zA-Z0-9_]+'), "std::fs API usage"),
    (re.compile(r'(?<![_a-z])fs::(read|read_to_string|read_dir|metadata|write|copy|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all)\b'), "fs API usage"),
]


class LexState:
    """Carries lexical context across line boundaries.

    Block comments, string literals and raw strings all span lines in Rust, so
    a line cannot be classified in isolation.
    """

    __slots__ = ("block_depth", "string", "raw_hashes")

    def __init__(self):
        self.block_depth = 0
        self.string = None
        self.raw_hashes = 0


# `r"`, `r#"`, `br##"`, `b"` -- the raw and byte string openers.
RAW_OPEN = re.compile(r'(b?)r(#*)"|b"')
IDENT_CHAR = re.compile(r"[A-Za-z0-9_]")


def split_code(line, st):
    """Split one line into (structure, code), advancing the lexer state.

    `structure` is the line with comments removed AND every literal's contents
    blanked out. Brace depth and keyword detection read this, so a `{` inside a
    string, or the word `mod tests` inside one, cannot move the parser.

    `code` is the line with comments removed but literals intact. The violation
    patterns read this, because some of them legitimately match literal text --
    `Command::new("git")` is only recognisable with the string still in place.

    Splitting the two is the whole point: structure tracking must ignore
    literals, and pattern matching must not.
    """
    structure = []
    code = []
    i, n = 0, len(line)

    while i < n:
        ch = line[i]

        if st.block_depth > 0:
            # Rust block comments nest, so `/*` inside one opens another level.
            if line.startswith("/*", i):
                st.block_depth += 1
                i += 2
            elif line.startswith("*/", i):
                st.block_depth -= 1
                i += 2
            else:
                i += 1
            continue

        if st.string == "raw":
            if ch == '"' and line[i + 1 : i + 1 + st.raw_hashes] == "#" * st.raw_hashes:
                code.append(line[i : i + 1 + st.raw_hashes])
                i += 1 + st.raw_hashes
                st.string = None
            else:
                code.append(ch)
                i += 1
            continue

        if st.string == "normal":
            if ch == "\\":
                code.append(line[i : i + 2])
                i += 2
            elif ch == '"':
                code.append(ch)
                i += 1
                st.string = None
            else:
                code.append(ch)
                i += 1
            continue

        if line.startswith("//", i):
            break

        if line.startswith("/*", i):
            st.block_depth = 1
            i += 2
            continue

        # A raw or byte string opener, but only where it starts a token --
        # otherwise the `r` ending an identifier would be mistaken for one.
        if ch in "rb" and not (i and IDENT_CHAR.match(line[i - 1])):
            m = RAW_OPEN.match(line, i)
            if m:
                code.append(m.group(0))
                st.string = "raw" if "r" in m.group(0) else "normal"
                st.raw_hashes = len(m.group(2) or "")
                i = m.end()
                continue

        if ch == '"':
            code.append(ch)
            st.string = "normal"
            i += 1
            continue

        if ch == "'":
            # A char literal, or a lifetime. `'a'` is a literal; `'static` is
            # not, and consuming it as one would swallow the rest of the line.
            if line.startswith("\\", i + 1):
                j = i + 2
                while j < n and line[j] != "'":
                    j += 1
                code.append(line[i : j + 1])
                i = j + 1
            elif i + 2 < n and line[i + 2] == "'":
                code.append(line[i : i + 3])
                i += 3
            else:
                structure.append(ch)
                code.append(ch)
                i += 1
            continue

        structure.append(ch)
        code.append(ch)
        i += 1

    return "".join(structure), "".join(code)


def lex_lines(lines):
    """Return [(structure, code), ...]: one lexer pass over a whole file.

    Everything that needs a file's lexical form shares this pass: brace depth
    for function bodies, the scan's own structure tracking, and the projection
    allowlist counts are measured against. The three cannot disagree about
    where a string literal ends.
    """
    lex = LexState()
    return [split_code(line, lex) for line in lines]


# The declaration as it survives comment and literal stripping. `structure`
# drops the ABI string from `extern "C" fn`, so FN_DECL is matched against the
# raw line and this against the stripped one: the raw match reads the shape, and
# this confirms the shape is code rather than prose.
FN_IN_STRUCTURE = re.compile(r"\bfn\s+([A-Za-z0-9_]+)")


def find_fn_body_ranges(lines, fn_names=None, lexed=None):
    """Return {name: [(first_line, last_line), ...]} for function bodies.

    Line numbers are inclusive and 0-based, and bounds are tracked by brace
    depth from the function's opening brace to its matching close. With
    `fn_names` only those names are collected; without it, every declaration is,
    which is what validation counts.

    Depth is counted on the lexically stripped `structure`, never on the raw
    line. Braces inside string literals, char literals, raw strings, and
    comments used to count, and the failure direction was silent
    over-exemption: one `{` that never closed walked the range to `len(lines)`,
    so a body's exemption covered every line after its declaration while the
    summary line and the exit status stayed identical to a clean run. `scan_file`
    already read `structure` for exactly this reason. This counter did not, and
    it is the one function scoping resolves exemptions with, which is the whole
    of an `allow_fn` entry's meaning.

    A declaration only counts if it survives the strip. `fn foo() {` inside a
    block comment or a raw string is prose, and counting it as a body measured
    the exact-count property over non-code.

    A body whose closing brace is never found is dropped rather than returned as
    a range reaching end of file. Dropping is the loud direction: an `allow_fn`
    pin then resolves to zero bodies and fails validation, and the scan applies
    no exemption at all, so the file is reported in full.
    """
    if lexed is None:
        lexed = lex_lines(lines)
    found = {}
    n = len(lines)
    i = 0
    while i < n:
        m = FN_DECL.match(lines[i])
        if not m or (fn_names is not None and m.group(1) not in fn_names):
            i += 1
            continue
        in_code = FN_IN_STRUCTURE.search(lexed[i][0])
        if in_code is None or in_code.group(1) != m.group(1):
            i += 1
            continue

        depth = 0
        started = False
        closed = False
        bodyless = False
        nesting = 0
        j = i
        while j < n:
            structure = lexed[j][0]
            if not started:
                # A declaration with no body, a trait method or an `extern`
                # signature ending in `;`, is skipped. Brace counting alone
                # would find no opening brace and run the "body" to end of
                # file, so a name that matched such a signature would exempt
                # everything after it. The terminating `;` is only recognised
                # outside parentheses and brackets, so a `[u8; 32]` parameter is
                # not mistaken for one.
                stop = -1
                for pos, ch in enumerate(structure):
                    if ch in "([":
                        nesting += 1
                    elif ch in ")]":
                        nesting -= 1
                    elif ch == "{" and nesting <= 0:
                        break
                    elif ch == ";" and nesting <= 0:
                        stop = pos
                        break
                if stop >= 0:
                    bodyless = True
                    break
            opens = structure.count("{")
            closes = structure.count("}")
            if opens > 0:
                started = True
            if started:
                depth += opens - closes
                if depth <= 0:
                    closed = True
                    break
            j += 1

        if bodyless:
            i = j + 1
            continue
        if not closed:
            # Malformed input rather than a body. Resume at the next line so
            # every other declaration in the file still resolves and reports.
            i += 1
            continue
        found.setdefault(m.group(1), []).append((i, j))
        i = j + 1
    return found


# The leading path of an attribute, with the whitespace Rust permits around the
# `::` separators. `#[test]`, `#[tokio::test]` and `#[cfg(...)]` are all read
# from this one shape.
ATTR_PATH = re.compile(r"^#\s*\[\s*([A-Za-z0-9_]+(?:\s*::\s*[A-Za-z0-9_]+)*)")

# An item head an attribute can gate, whose extent the tracker can bound by
# brace matching or a terminating `;`. Modifiers may repeat and appear in any
# order, so they are matched as a run rather than as a fixed sequence.
# Deliberately a closed set: a construct this does not recognise -- a gated
# struct field, enum variant, match arm, or statement -- has no bound this
# tracker can trust, and the safe answer there is to keep scanning.
#
# `macro_rules!` sits outside the word-boundary group on purpose. A trailing
# `\b` asserts a word character follows, and `!` is not one, so listing it
# among the keywords produced an alternative that could never match while
# reading as though it did. The failure was the safe direction, and no
# cfg-gated macro exists in the tree today, but a closed set that silently
# omits one of its own members is the same defect this tracker was rewritten
# to remove: a policy decision made by an accident of spelling.
ITEM_HEAD = re.compile(
    r"^(?:(?:pub(?:\s*\([^)]*\))?|default|unsafe|async|const|extern(?:\s+\"[^\"]*\")?)\s+)*"
    r"(?:(?:mod|fn|impl|struct|enum|union|trait|type|use|const|static)\b"
    r"|macro_rules\s*!)"
)


def split_predicates(inner):
    """Split a cfg predicate list on its top-level commas."""
    parts, depth, current = [], 0, []
    for ch in inner:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
            continue
        current.append(ch)
    if "".join(current).strip():
        parts.append("".join(current))
    return [p.strip() for p in parts if p.strip()]


CFG_CALL = re.compile(r"^([A-Za-z0-9_]+)\s*\((.*)\)$", re.S)


def predicate_is_test_only(predicate):
    """Whether a cfg predicate can only hold in a test build.

    Evaluated rather than pattern-matched, because the tree carries predicates
    that mention `test` and still compile in production. `all(...)` is test-only
    when any member is, since every member must hold. `any(...)` only when every
    member is, since one suffices: `cfg(any(unix, test))` is live on unix in a
    release build, and excluding it would stop scanning production code. `not(..)`
    is never treated as test-only, and neither is any other predicate, so an
    unrecognised spelling keeps its item scanned.
    """
    predicate = predicate.strip()
    call = CFG_CALL.match(predicate)
    if call:
        operator, inner = call.group(1).strip(), call.group(2)
        members = split_predicates(inner)
        if operator == "all":
            return any(predicate_is_test_only(m) for m in members)
        if operator == "any":
            return bool(members) and all(predicate_is_test_only(m) for m in members)
        return False
    return predicate == "test"


def attribute_extent(lexed, start):
    """(last_line, text, trailing) for the attribute opening on line `start`.

    Bracket-matched over the lexically stripped text, so an attribute spanning
    lines is read whole and a `]` inside a string literal cannot close it early.
    `trailing` is whatever follows the closing bracket on its line, which is how
    a one-line `#[cfg(test)] use std::fs;` is recognised.
    """
    depth = 0
    parts = []
    for j in range(start, len(lexed)):
        structure = lexed[j][0]
        begin = structure.index("#") if j == start else 0
        for k in range(begin, len(structure)):
            ch = structure[k]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    parts.append(structure[begin : k + 1])
                    return j, "".join(parts), structure[k + 1 :]
        parts.append(structure[begin:])
    return None, "".join(parts), ""


def is_test_gate(text):
    """Whether an attribute removes its item from every non-test build.

    Two shapes qualify. A `test` attribute path -- `#[test]`, `#[tokio::test]`
    -- marks an item rustc only emits under `--test`. A `cfg` whose predicate is
    test-only gates the item's existence outright. `cfg_attr` never qualifies: it
    applies an attribute conditionally and leaves the item itself compiled.
    """
    m = ATTR_PATH.match(text)
    if not m:
        return False
    path = re.sub(r"\s+", "", m.group(1))
    if path == "test" or path.endswith("::test"):
        return True
    if path != "cfg":
        return False
    open_paren = text.find("(", m.end())
    if open_paren < 0:
        return False
    depth = 0
    for k in range(open_paren, len(text)):
        if text[k] == "(":
            depth += 1
        elif text[k] == ")":
            depth -= 1
            if depth == 0:
                return predicate_is_test_only(text[open_paren + 1 : k])
    return False


def item_span(lexed, start):
    """(start, last_line) for the item beginning on line `start`, or None.

    Bounded the same way a function body is: brace depth from the item's opening
    brace to its matching close, or a terminating `;` outside parentheses and
    brackets for a declaration that has no block. Counted on the lexically
    stripped text so a brace inside a literal or a comment cannot move the bound.
    An item whose close is never found returns None, which drops the exclusion
    and keeps the lines scanned rather than excusing everything below it.
    """
    depth = 0
    started = False
    nesting = 0
    for j in range(start, len(lexed)):
        structure = lexed[j][0]
        if not started:
            for ch in structure:
                if ch in "([":
                    nesting += 1
                elif ch in ")]":
                    nesting -= 1
                elif ch == "{" and nesting <= 0:
                    break
                elif ch == ";" and nesting <= 0:
                    return start, j
        opens = structure.count("{")
        closes = structure.count("}")
        if opens:
            started = True
        if started:
            depth += opens - closes
            if depth <= 0:
                return start, j
    return None


def test_gated_ranges(lexed):
    """Inclusive line ranges holding items that exist only in a test build.

    The tracker this replaces armed on the attribute line and disarmed on the
    same iteration, because an attribute carries no brace and the guard's
    disarm condition is `brace_depth <= armed_depth`. What kept it working at
    all was the literal string `mod tests` on the following line re-arming it,
    so exclusion was decided by a naming convention: `#[cfg(test)] mod
    ingest_cas_tests` and every `#[cfg(test)] fn` were scanned as production.
    The failure direction was safe, but over-reporting manufactures allowlist
    entries, and an exemption that exists to silence a false positive is
    indistinguishable later from one that licenses real boundary IO.

    Attribute runs are read whole and the item they gate is bounded explicitly,
    so exclusion follows from the cfg predicate rather than from a name. A gated
    construct whose extent cannot be bounded, and an attribute run that gates
    nothing recognisable, both stay scanned.
    """
    ranges = []
    n = len(lexed)
    i = 0
    while i < n:
        if not lexed[i][0].strip().startswith("#["):
            i += 1
            continue

        block_start = i
        gated = False
        item_start = None
        j = i
        while j < n:
            structure = lexed[j][0]
            stripped = structure.strip()
            if not stripped:
                j += 1
                continue
            if not stripped.startswith("#["):
                item_start = j
                break
            last_line, text, trailing = attribute_extent(lexed, j)
            if last_line is None:
                break
            if is_test_gate(text):
                gated = True
            if trailing.strip():
                item_start = last_line
                break
            j = last_line + 1

        span = None
        if gated and item_start is not None:
            head = lexed[item_start][0].strip()
            if item_start != block_start:
                candidate = head
            else:
                # The item shares the attribute's line, so only what follows the
                # closing bracket is the item.
                candidate = attribute_extent(lexed, item_start)[2].strip()
            if ITEM_HEAD.match(candidate):
                span = item_span(lexed, item_start)

        if span is None:
            i = block_start + 1
            continue
        ranges.append((block_start, span[1]))
        i = span[1] + 1
    return ranges


def scannable_lines(lexed):
    """Yield (index, code) for every line the scan reads, index 0-based.

    Test-only items are skipped here rather than in the caller so that allowlist
    pin counts and the scan itself are measured over exactly the same text. A
    count taken over the raw file measured a superset: test and commented-out
    occurrences counted toward a pin's budget without ever being sites the pin
    could license, and removing one from a test then silently released budget for
    a real filesystem probe in a scanned path.
    """
    excluded = set()
    for lo, hi in test_gated_ranges(lexed):
        excluded.update(range(lo, hi + 1))
    for idx, (_structure, code) in enumerate(lexed):
        if idx in excluded:
            continue
        yield idx, code


def mask_pins(line, pins):
    """Blank every pinned expression out of one line, returning (line, hits).

    Only the exact, count-validated boundary expression is masked. The remainder
    of the line stays authoritative: a second filesystem read beside an allowed
    one must still fail rather than inheriting a whole-line exemption.

    Longest first, so a pin that is a substring of another cannot mask the
    shorter one's bytes out from under it and leave the longer pin unmatched,
    which also makes the result independent of set iteration order. Counting and
    scanning both go through here, so a pin can never be counted at a site the
    scan would not have masked.
    """
    hits = {}
    if not pins:
        return line, hits
    for pin in sorted(pins, key=len, reverse=True):
        offset = line.find(pin)
        while offset >= 0:
            line = line[:offset] + (" " * len(pin)) + line[offset + len(pin) :]
            hits[pin] = hits.get(pin, 0) + 1
            offset = line.find(pin, offset + len(pin))
    return line, hits


def exempt_body_ranges(lines, exempt_fn_names, lexed):
    """Line ranges the allowlist declares to be a boundary in whole.

    Function scoping is an opt-out, not an opt-in. Every line is scanned except
    these, so a handler added to a mixed file is covered without anyone
    remembering to list it.
    """
    ranges = []
    if exempt_fn_names:
        for spans in find_fn_body_ranges(lines, exempt_fn_names, lexed).values():
            ranges.extend(spans)
    return ranges


def count_pins_in_scan(lines, lexed, exempt_fn_names, pins):
    """Count each pin at the sites the scan would actually mask.

    The scan reads neither test modules nor comments, and never reads a body
    `allow_fn` excused, so a count taken over the raw file measures a superset
    of what the pin licenses. That difference is not cosmetic, it is budget: a
    `.metadata()` pin declaring 19 while the scan read only 6 of those sites
    carried thirteen occurrences of slack, so deleting one from a test module
    could be offset by adding a genuine filesystem probe to a scanned planning
    path with the declared count unchanged and the guard green.
    """
    ranges = exempt_body_ranges(lines, exempt_fn_names, lexed)
    counts = {pin: 0 for pin in pins}
    for idx, code in scannable_lines(lexed):
        if any(lo <= idx <= hi for lo, hi in ranges):
            continue
        for pin, hits in mask_pins(code, pins)[1].items():
            counts[pin] += hits
    return counts


def scan_file(filepath, rel_path, exempt_fn_names=None, allowed_matches=None):
    violations = []

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # Comments and literals are removed lexically rather than by substring
    # search. A `//` or `/*` inside a string literal used to truncate the line
    # or latch block-comment mode on to EOF, desynchronising brace depth so the
    # scanner believed it had entered `mod tests` and quietly stopped enforcing
    # for the rest of the file.
    lexed = lex_lines(lines)
    ranges = exempt_body_ranges(lines, exempt_fn_names, lexed)

    for idx, line in scannable_lines(lexed):
        if any(lo <= idx <= hi for lo, hi in ranges):
            continue

        scan_line = mask_pins(line, allowed_matches)[0]

        # Scan for patterns. A line can match several primitives at once
        # (`std::fs::read_dir` is both an fs call and a traversal); report the
        # line once with every primitive it tripped, so the violation count
        # tracks offending lines rather than pattern hits.
        descs = [desc for pattern, desc in PATTERNS if pattern.search(scan_line)]
        if descs:
            violations.append((idx + 1, line.strip(), ", ".join(dict.fromkeys(descs))))

    return violations


def main():
    policies, allowlist_errors = load_allowlist()
    total_violations = 0
    scanned = 0
    whole_file_exempt = 0
    fn_scoped = 0

    # Walk crates directory
    crates_dir = os.path.join(KIN_ROOT, "crates")
    if not os.path.exists(crates_dir):
        print(f"Error: crates directory not found at {crates_dir}")
        if allowlist_errors:
            report_allowlist_errors(allowlist_errors)
        sys.exit(1)

    for root, _, files in os.walk(crates_dir):
        for file in sorted(files):
            if not file.endswith(".rs"):
                continue

            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, KIN_ROOT)

            policy = policies.get(rel_path)

            # A whole-file exemption skips the scan entirely; a pinned or
            # function-scoped one still scans everything it did not pin.
            if policy is not None and policy.whole_file:
                whole_file_exempt += 1
                continue

            # An allowlisted file is scanned even inside a boundary directory:
            # naming it is a statement about which spans are boundary IO, not a
            # request to stop looking at the rest.
            if policy is None and is_test_file(rel_path):
                continue

            exempt_fns = policy.fns if policy else None
            allowed_matches = policy.matches if policy else None
            if exempt_fns:
                fn_scoped += 1
            scanned += 1

            violations = scan_file(filepath, rel_path, exempt_fns, allowed_matches)
            if violations:
                print(f"\n[VIOLATION] {rel_path} contains forbidden filesystem access:")
                for line_num, content, desc in violations:
                    print(f"  Line {line_num:4d}: {content} ({desc})")
                total_violations += len(violations)

    print(
        f"\nScanned {scanned} source files "
        f"({fn_scoped} with function-scoped exemptions, "
        f"{whole_file_exempt} exempt whole-file)."
    )

    if total_violations > 0:
        print(f"Verification FAILED: Found {total_violations} zero-file-search violations.")
    if allowlist_errors:
        report_allowlist_errors(allowlist_errors)
    if total_violations or allowlist_errors:
        sys.exit(1)

    print("Verification PASSED: Zero File-Search Invariant holds.")
    sys.exit(0)


def report_allowlist_errors(errors):
    """Print allowlist errors after the scan.

    Deliberately last. These used to abort before the walk, so a stale pin
    reported itself and hid every violation behind it.
    """
    print("\nAllowlist validation FAILED:")
    print("\n".join(errors))


if __name__ == "__main__":
    main()
