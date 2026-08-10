#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
"""Regenerate crates/kin-core/src/env_registry_generated.rs.

The locate / ranking / semantic-locate pipeline reads a few hundred `KIN_*`
tuning knobs through typed helper wrappers (`locate_env_f32`, `locate_env_usize`,
`locate_env_bool`, `rank_env_f32`, `semloc_env_f32`, ...). The *kind* and
*default* of each knob live at the call site, so this script lifts them straight
from the source to keep the registry honest and complete. Hand-curated
operational / safety / correctness variables live in `env_registry.rs`; this
file only covers the auto-extractable tuning knobs.

Run from anywhere:  python3 scripts/gen_env_registry.py
"""

import os
import re
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRATES = os.path.join(ROOT, "crates")
OUT = os.path.join(CRATES, "kin-core", "src", "env_registry_generated.rs")

# Timeout/budget bound knobs (`0` = unbounded). These read through the shared
# `env_ms_bound` / `env_secs_bound_f64` helpers rather than the plain typed
# helpers, so they are hand-curated in env_registry.rs (OPERATIONAL) and excluded
# here to avoid a duplicate, mis-typed entry.
BOUND_KNOBS = {
    "KIN_LOCATE_MULTIHOP_TIMEOUT_MS",
    "KIN_LOCATE_RERANK_LATENCY_BUDGET_MS",
    "KIN_LOCATE_TOTAL_TIMEOUT_SECS",
    "KIN_LOCATE_PHASE_ENTITY_DISCOVERY_SECS",
    "KIN_LOCATE_PHASE_ENTITY_RESOLUTION_SECS",
    "KIN_LOCATE_PHASE_MULTIHOP_SECS",
    "KIN_LOCATE_PHASE_TEXT_SEARCH_SECS",
    "KIN_LOCATE_PHASE_SOURCE_TEXT_SECS",
    "KIN_LOCATE_PHASE_SCORING_SECS",
}
KIND_MAP = {
    "f32": "NonNegF32",
    "usize": "Usize",
    "bool": "Bool",
    "usize_set": "UsizeSet",
    "duration_secs": "Secs",
}
# Non-literal defaults rendered as readable prose for the doc.
DYN = {
    "profile.multihop_timeout_ms()": "profile-dependent (200/500/1000 ms)",
    "profile.multihop_frontier_limit()": "profile-dependent (50/100/200)",
    "profile_max_depth": "profile-dependent",
    "default_seed_limit": "repo-size adaptive (5 or 8)",
    "usize::MAX": "unbounded",
    "[]": "(none)",
    "default_artifact_hops": "context-dependent",
    "retention_floor_pct.min(0.08)": "adaptive (<= 0.08)",
    "support_floor_pct.min(0.15)": "adaptive (<= 0.15)",
    "base.max_chars": "snippet-config default",
    "base.max_lines": "snippet-config default",
    "base.max_symbols_per_file": "snippet-config default",
    "tracked_term_limit * 3": "3x tracked-term limit",
}
# Compile-time / build-info variables that are not runtime env reads.
BUILD_INFO = {
    "KIN_BUILD_BRANCH",
    "KIN_BUILD_DIRTY",
    "KIN_BUILD_GIT_SHA",
    "KIN_BUILD_TIME",
    "KIN_BUILD_VERSION",
    "KIN_RELEASE_PUBLIC_KEY",
    "KIN_SUPERVISOR_REEXECED_FOR_MTIME",
}

HELPER_RE = re.compile(
    r'\b([a-z_][a-z0-9_]*env[a-z0-9_]*|rank_env_f32|semloc_env_f32'
    r"|cochange_env_usize|duration_from_env_secs)"
    r'\(\s*"(KIN_[A-Z0-9_]+)"\s*',
    re.S,
)


def default_arg(text, start):
    """Return the helper's default argument, or None when it takes no default.

    `start` is the offset just past the variable-name literal, so the helper's
    own opening paren is already consumed and the scan begins at depth 1.

    This tracks bracket depth and skips string literals rather than matching to
    the first close paren. A default that is itself a call, such as
    `quality.cross_encoder_default(ce_model_cached)`, closes an inner paren
    before the helper's own, so stopping at the first one lifts a syntactically
    incomplete expression into the published default column.
    """
    if start >= len(text) or text[start] != ",":
        return None
    i = start + 1
    depth = 1
    while i < len(text):
        c = text[i]
        if c == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
        i += 1
    return None


def kind_from_fn(fn):
    f = fn.lower()
    if "usize_set" in f or "_set" in f:
        return "usize_set"
    if "f32" in f or "f64" in f or "float" in f:
        return "f32"
    if "usize" in f or "u64" in f or "u32" in f:
        return "usize"
    if "bool" in f or "flag" in f or "truthy" in f:
        return "bool"
    if "secs" in f or "duration" in f:
        return "duration_secs"
    return None


def walk_rs():
    for base, _dirs, files in os.walk(CRATES):
        if os.sep + "tests" + os.sep in base + os.sep:
            continue
        for name in files:
            if name.endswith(".rs") and not name.endswith("_test.rs"):
                yield os.path.join(base, name)


def build_catalog():
    catalog = {}
    for path in walk_rs():
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        for m in HELPER_RE.finditer(text):
            fn, name = m.group(1), m.group(2)
            default = (default_arg(text, m.end()) or "").strip()
            default = default.split("\n")[0].strip().rstrip(",").strip()
            if len(default) > 60:
                default = default[:60]
            e = catalog.setdefault(name, {"kind": None, "default": None})
            k = kind_from_fn(fn)
            if k and not e["kind"]:
                e["kind"] = k
            if default and e["default"] is None:
                e["default"] = default
    for b in BUILD_INFO:
        catalog.pop(b, None)
    return catalog


def pretty_default(d):
    if d is None:
        return ""
    d = d.strip()
    if d in DYN:
        return DYN[d]
    if d.endswith(")") and "(" in d:
        # A call expression has no single literal value to publish, so it is
        # described rather than printed. This used to key off a trailing `(`,
        # which only ever appeared because the extractor cut the argument at
        # its first close paren; a default whose own call took an argument
        # therefore missed this branch and leaked a broken expression into the
        # published default column.
        return DYN.get(d, "context-dependent")
    if re.match(r"^-?[0-9.]+$", d):
        return d
    if d in ("true", "false"):
        return d
    if re.match(r"^[0-9]+usize$", d):
        return d.replace("usize", "")
    return d


def summary(name):
    if name.startswith("KIN_RANK_"):
        fam, strip = "ranking", "rank"
    elif name.startswith("KIN_SEMLOC_"):
        fam, strip = "semantic-locate", "semloc"
    else:
        fam, strip = "locate", "locate"
    toks = name[len("KIN_"):].lower().replace("_", " ").split()
    if toks and toks[0] == strip:
        toks = toks[1:]
    return f"{fam} tuning knob: {' '.join(toks)}".rstrip()


def rs_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main():
    catalog = build_catalog()
    rows = []
    for name in sorted(catalog):
        e = catalog[name]
        if not name.startswith(("KIN_LOCATE_", "KIN_RANK_", "KIN_SEMLOC_")):
            continue
        if name in BOUND_KNOBS:
            continue  # bound knobs are hand-curated in env_registry.rs
        if not e["kind"]:
            continue  # direct-read vars are hand-curated in env_registry.rs
        kind = KIND_MAP.get(e["kind"])
        if not kind:
            continue
        rows.append((name, kind, pretty_default(e["default"]), summary(name)))

    out = [
        "// @generated by scripts/gen_env_registry.py — DO NOT EDIT BY HAND.",
        "// Source of truth: the locate/ranking/semantic-locate env read sites in",
        "// kin-cli (locate.rs), kin-ranking, and kin-daemon (api.rs semloc).",
        "// Regenerate after adding/removing a tuning knob; the doc-drift test guards",
        "// the rendered reference. Kind/default are lifted directly from each call site.",
        "",
        "use super::{EnvVarSpec, Kind, Sensitivity};",
        "",
        "/// Auto-extracted locate/ranking tuning knobs. All are correctness-relevant:",
        "/// each shifts retrieval fusion, thresholds, or ranking output.",
        "#[rustfmt::skip]",
        "pub const GENERATED_KNOBS: &[EnvVarSpec] = &[",
    ]
    for name, kind, default, summ in rows:
        out.append(
            f"    EnvVarSpec {{ name: {rs_str(name)}, kind: Kind::{kind}, "
            f"default: {rs_str(default)}, sensitivity: Sensitivity::Correctness, "
            f"summary: {rs_str(summ)} }},"
        )
    out.append("];")
    out.append("")
    with open(OUT, "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"wrote {os.path.relpath(OUT, ROOT)} with {len(rows)} knobs")
    print("kinds:", dict(Counter(r[1] for r in rows)))


if __name__ == "__main__":
    main()
