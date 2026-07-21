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


def load_allowlist():
    """Load and validate the allowlist, returning {file: allowed_matches}.

    Each entry must declare file, reason, owner, and an ISO `expiration` date,
    and must name a path that actually exists. Missing fields, malformed dates,
    past-due exemptions, and entries for deleted files all fail the guard, so
    exemptions cannot silently accumulate, outlive their justification, or sit
    dormant waiting to auto-exempt a file that gets recreated under the same
    path.

    `allow_match` is optional. When present it lists exact substrings that are
    exempt within that file, mirroring `allow_for` in
    scripts/zero_file_search_guard.sh: the exemption is pinned to the known
    lines, so a new or different filesystem primitive in the same file still
    trips the guard. When absent the whole file is exempt, which is only
    appropriate for files that are an IO boundary end to end.
    """
    try:
        with open(ALLOWLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading allowlist from {ALLOWLIST_PATH}: {e}")
        sys.exit(1)

    entries = data.get("allowlist", [])
    errors = []
    files = {}
    today = date.today()

    for i, item in enumerate(entries):
        missing = [k for k in REQUIRED_FIELDS if not item.get(k)]
        if missing:
            errors.append(
                f"  entry #{i} ({item.get('file', '?')}) missing required "
                f"field(s): {', '.join(missing)}"
            )
            continue

        if not os.path.exists(os.path.join(KIN_ROOT, item["file"])):
            errors.append(
                f"  entry {item['file']} names a path that does not exist "
                f"(owner: {item['owner']}) — remove the stale exemption; leaving "
                f"it would silently exempt any file later recreated at that path"
            )
            continue

        matches = item.get("allow_match")
        if matches is not None and (
            not isinstance(matches, list)
            or not matches
            or not all(isinstance(m, str) and m for m in matches)
        ):
            errors.append(
                f"  entry {item['file']} has an invalid allow_match "
                f"(want a non-empty list of non-empty strings)"
            )
            continue
        files[item["file"]] = set(matches) if matches else None

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

    if errors:
        print("Allowlist validation FAILED:")
        print("\n".join(errors))
        sys.exit(1)

    return files


BOUNDARY_DIRS = [
    "crates/kin-daemon/",
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
    "crates/kin-core/src/dependencies.rs",
    "crates/kin-core/src/env_registry.rs",
    "crates/kin-core/src/federation.rs",
    "crates/kin-core/src/init.rs",
    "crates/kin-core/src/layout.rs",
    "crates/kin-core/src/lib.rs",
    "crates/kin-core/src/manifest.rs",
    "crates/kin-core/src/ref_view.rs",
    "crates/kin-core/src/registry.rs",
    "crates/kin-core/src/shims.rs",
    "crates/kin-core/src/sync_state.rs",
    "crates/kin-core/src/tree.rs",
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
    "health.rs"
}

# Query/answer authority handlers that live inside an otherwise IO-boundary
# crate (the daemon serves package registries, persists snapshots, and writes
# auth tokens — all legitimate boundary IO). These files are scanned
# function-scoped: only the named handler bodies are checked, so the boundary
# IO elsewhere in the same file is not falsely flagged, while a raw filesystem
# read sneaking into a query answer path still fails the guard.
DAEMON_QUERY_HANDLERS = {
    "crates/kin-daemon/src/api.rs": {
        "locate",
        "search",
        "context",
        "trace",
        "impact",
        "review",
    },
}

# Matches a (possibly `pub`/`async`) free or method function declaration.
FN_DECL = re.compile(r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)\s*[(<]")


def is_test_file(rel_path):
    # Skip standalone test directories
    if "tests/" in rel_path or "test_" in rel_path or rel_path.endswith("_test.rs"):
        return True
    # Skip ingestion/migration/daemon boundary directories/files
    for bdir in BOUNDARY_DIRS:
        if rel_path.startswith(bdir) or rel_path == bdir:
            return True

    # For CLI commands, only scan query commands
    if "crates/kin-cli/src/commands/" in rel_path:
        filename = os.path.basename(rel_path)
        if filename not in QUERY_COMMANDS:
            return True

    return False


# Patterns to scan.
#
# The first group is the raw filesystem read / existence / traversal primitive
# set shared with scripts/zero_file_search_guard.sh. Answering a semantic query
# by probing the working tree is the violation the rule exists to stop, and it
# does not require the `std::fs::` prefix to happen: `path.exists()`,
# `File::open`, a bare `read_dir(`, or a `WalkDir` traversal all read the tree
# just as directly. Writes and directory creation stay out of the deny set —
# materialization is a projection boundary, not answer-by-search.
PATTERNS = [
    (re.compile(r'\.is_file\(\)'), "filesystem existence probe (is_file)"),
    (re.compile(r'\.is_dir\(\)'), "filesystem existence probe (is_dir)"),
    (re.compile(r'\.exists\(\)'), "filesystem existence probe (exists)"),
    (re.compile(r'\.canonicalize\(\)'), "filesystem path resolution (canonicalize)"),
    (re.compile(r'\bsymlink_metadata\b'), "filesystem metadata probe"),
    (re.compile(r'\bread_link\b'), "filesystem symlink read"),
    (re.compile(r'\bFile::open\b'), "raw file handle open"),
    (re.compile(r'\bread_dir\('), "directory traversal (read_dir)"),
    (re.compile(r'\bWalkDir\b|\bwalkdir::'), "directory traversal (walkdir)"),
    (re.compile(r'\bglob::glob\b'), "filesystem glob"),
    (re.compile(r'\bstd::fs::[a-zA-Z0-9_]+'), "std::fs API usage"),
    (re.compile(r'(?<![_a-z])fs::(read|read_to_string|read_dir|metadata|write|copy|create_dir|create_dir_all|remove_file|remove_dir|remove_dir_all)\b'), "fs API usage"),
    (re.compile(r'Command::new\("git"\).*?"grep"'), "git grep subprocess usage")
]


def find_fn_body_ranges(lines, fn_names):
    """Return inclusive 0-based line ranges for the bodies of the named
    functions. Body bounds are tracked by brace depth from the function's
    opening brace to its matching close."""
    ranges = []
    n = len(lines)
    i = 0
    while i < n:
        m = FN_DECL.match(lines[i])
        if m and m.group(1) in fn_names:
            depth = 0
            started = False
            j = i
            while j < n:
                opens = lines[j].count("{")
                closes = lines[j].count("}")
                if opens > 0:
                    started = True
                if started:
                    depth += opens - closes
                    if depth <= 0:
                        break
                j += 1
            ranges.append((i, j))
            i = j + 1
        else:
            i += 1
    return ranges


def scan_file(filepath, rel_path, query_fn_names=None, allowed_matches=None):
    violations = []

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    # When scanning a mixed boundary file, restrict violations to the bodies of
    # the designated query handlers.
    allowed_ranges = (
        find_fn_body_ranges(lines, query_fn_names) if query_fn_names else None
    )

    in_block_comment = False
    in_test_module = False
    brace_depth = 0
    test_module_brace_depth = -1

    for idx, line in enumerate(lines, 1):
        stripped = line.strip()

        # Track block comments
        if "/*" in stripped:
            in_block_comment = True
        if in_block_comment:
            if "*/" in stripped:
                in_block_comment = False
            continue

        # Ignore single line comments
        if stripped.startswith("//"):
            continue

        # Remove trailing comments
        if "//" in line:
            line = line.split("//")[0]
            stripped = line.strip()

        # Track test module to ignore test code inside source files
        if "mod tests" in stripped or "#[cfg(test)]" in stripped:
            in_test_module = True
            test_module_brace_depth = brace_depth

        # Track brace depth
        brace_depth += stripped.count("{") - stripped.count("}")

        if in_test_module and brace_depth <= test_module_brace_depth:
            in_test_module = False
            test_module_brace_depth = -1

        if in_test_module:
            continue

        # Skip attributes like #[test]
        if stripped.startswith("#[test]"):
            continue

        # When function-scoped, only flag lines inside a designated handler body.
        if allowed_ranges is not None and not any(
            lo <= (idx - 1) <= hi for lo, hi in allowed_ranges
        ):
            continue

        # Lines pinned by an `allow_match` exemption are a justified IO
        # boundary. Anything else in the same file still trips the guard.
        if allowed_matches and any(m in line for m in allowed_matches):
            continue

        # Scan for patterns. A line can match several primitives at once
        # (`std::fs::read_dir` is both an fs call and a traversal); report the
        # line once with every primitive it tripped, so the violation count
        # tracks offending lines rather than pattern hits.
        descs = [desc for pattern, desc in PATTERNS if pattern.search(line)]
        if descs:
            violations.append((idx, line.strip(), ", ".join(dict.fromkeys(descs))))

    return violations


def main():
    allowlist = load_allowlist()
    total_violations = 0

    # Walk crates directory
    crates_dir = os.path.join(KIN_ROOT, "crates")
    if not os.path.exists(crates_dir):
        print(f"Error: crates directory not found at {crates_dir}")
        sys.exit(1)

    for root, _, files in os.walk(crates_dir):
        for file in files:
            if not file.endswith(".rs"):
                continue

            filepath = os.path.join(root, file)
            rel_path = os.path.relpath(filepath, KIN_ROOT)

            # Whole-file exemptions (an `allow_match`-less entry) skip the scan
            # entirely; pinned exemptions still scan, minus their named lines.
            allowed_matches = None
            if rel_path in allowlist:
                allowed_matches = allowlist[rel_path]
                if allowed_matches is None:
                    continue

            # Query handlers inside boundary crates are scanned function-scoped;
            # they bypass the boundary skip so their answer paths are covered.
            query_fns = DAEMON_QUERY_HANDLERS.get(rel_path)
            if query_fns is None and allowed_matches is None and is_test_file(rel_path):
                continue

            violations = scan_file(filepath, rel_path, query_fns, allowed_matches)
            if violations:
                print(f"\n[VIOLATION] {rel_path} contains forbidden filesystem access:")
                for line_num, content, desc in violations:
                    print(f"  Line {line_num:4d}: {content} ({desc})")
                total_violations += len(violations)

    if total_violations > 0:
        print(f"\nVerification FAILED: Found {total_violations} zero-file-search violations.")
        sys.exit(1)

    print("Verification PASSED: Zero File-Search Invariant holds.")
    sys.exit(0)


if __name__ == "__main__":
    main()
