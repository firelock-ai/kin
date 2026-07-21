#!/usr/bin/env bash
# Zero File-Search Authority guard.
#
# Kin answers locate/search/context/trace/review/xref queries from graph-owned
# truth, never by consulting raw filesystem contents. This guard fails if a raw
# filesystem read, existence, or traversal primitive appears in an answer path
# outside the justified allowlist. The allowlist covers only explicit
# input/output boundaries that are not the semantic answer: telemetry consent,
# the paging-cursor cache, the offline debug-dump reader, and the benchmark
# task-input boundary. Filesystem writes and directory creation are
# materialization, not answer-by-search, and are intentionally not denied.
#
# This is the narrow half of a two-guard pair, both run by CI:
#
#   scripts/verify-zero-file-search.py   walks every crate, shares this deny
#                                        set, and carries the owned, dated,
#                                        existence-validated allowlist
#   scripts/zero_file_search_guard.sh    this file — a dependency-free check on
#                                        the core answer modules, driven by the
#                                        kin-cli unit test as well as by CI
#
# Keep the deny sets in step. Coverage beyond these modules belongs in the
# Python checker rather than being duplicated here.
#
# Usage: zero_file_search_guard.sh [repo_root]
# Exit: 0 when the answer paths are graph-clean, 1 on the first violation.
set -euo pipefail

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cmd_dir="crates/kin-cli/src/commands"

# Answer-authority modules that must resolve results from graph truth alone.
authority_files=(
  "$cmd_dir/locate.rs"
  "$cmd_dir/locate_cursor.rs"
  "$cmd_dir/locate_debug.rs"
  "$cmd_dir/contextbench_locate.rs"
  "$cmd_dir/search.rs"
  "$cmd_dir/context.rs"
  "$cmd_dir/trace.rs"
  "$cmd_dir/trace_data_flow.rs"
  "$cmd_dir/review.rs"
  "$cmd_dir/xref.rs"
)

# Raw filesystem read / existence / traversal primitives.
deny_re='\.is_file\(\)|\.is_dir\(\)|\.exists\(\)|\.canonicalize\(\)|symlink_metadata|read_link|std::fs::(read|read_to_string|read_dir|metadata|File)|[^_a-z]fs::(read|read_to_string|read_dir|metadata)|File::open|read_dir\(|WalkDir|walkdir::|glob::glob'

# Per-file justified allowlist (input/output boundaries, not the answer). A new
# or different primitive in the same file still trips the guard.
allow_for() {
  case "$1" in
    locate.rs)             printf '%s' 'consent_marker_path' ;;
    locate_cursor.rs)      printf '%s' 'std::fs::read_to_string(&path)' ;;
    locate_debug.rs)       printf '%s' 'std::fs::read_to_string(path)' ;;
    contextbench_locate.rs) printf '%s' 'std::fs::read_to_string(&task_file)' ;;
    *)                     printf '%s' '' ;;
  esac
}

# First and last line of the inline `#[cfg(test)]` test module, so test-only
# filesystem IO is never mistaken for an answer-path leak. Prints a span past
# the end of the file when there is no such module.
#
# The span is bounded at both ends deliberately. Skipping from the test module
# to end-of-file instead left everything after it unscanned — in the largest
# answer module that was a third of the file, and a raw read appended at the
# end passed the guard untouched. Production code after a test module is
# unusual but perfectly legal, and "unusual" is precisely where a leak survives.
test_module_span() {
  # A `#[cfg(test)]` attribute attaches to the next real item; intervening
  # lines are only other attributes, comments, or blanks. The test module is
  # the first `#[cfg(test)]` whose next real item is a `mod` (a `#[cfg(test)]`
  # on a plain `fn` is a test helper amid production code and is not a boundary).
  # The module ends at the first `}` in column zero at or after it. Counting
  # braces instead would need to know which ones sit inside a string or a
  # comment, and a scanner that guesses at that desynchronises and silently
  # swallows the rest of the file. `cargo fmt --check` runs in the same job, so
  # a top-level item's closing brace is reliably unindented.
  #
  # If no such line exists the span runs to end of file, which is the old
  # blind behaviour — but scripts/falsify-zero-file-search.py plants a probe at
  # end of file in every listed module, so that case fails CI rather than
  # quietly disabling the guard.
  awk '
    !found && /^[[:space:]]*#\[cfg\(test\)\]/ { cfg=NR; watching=1; next }
    watching && !found {
      if ($0 ~ /^[[:space:]]*(#|\/\/|$)/) next
      if ($0 ~ /^[[:space:]]*mod /) { found=1; start=cfg }
      else { watching=0; next }
    }
    found && NR > start && /^\}[[:space:]]*$/ { print start, NR; done=1; exit }
    END { if (!done) print (found ? start : NR + 1), NR + 1 }
  ' "$1"
}

violations=()
for rel in "${authority_files[@]}"; do
  file="$repo_root/$rel"
  [[ -f "$file" ]] || continue
  base="$(basename "$rel")"
  allow="$(allow_for "$base")"
  read -r test_start test_end <<<"$(test_module_span "$file")"

  # Everything outside the test module, before it and after it alike, with the
  # original line numbers preserved.
  region="$(awk -v s="$test_start" -v e="$test_end" \
    'NR < s || NR > e { print NR ":" $0 }' "$file")"
  hits="$(printf '%s\n' "$region" | grep -E "$deny_re" || true)"
  [[ -n "$hits" ]] || continue
  if [[ -n "$allow" ]]; then
    hits="$(printf '%s\n' "$hits" | grep -vF "$allow" || true)"
  fi
  [[ -n "$hits" ]] || continue
  while IFS= read -r hit; do
    [[ -n "$hit" ]] && violations+=("$rel:$hit")
  done <<< "$hits"
done

if ((${#violations[@]} > 0)); then
  echo "Zero File-Search guard FAILED: raw filesystem access in answer paths:" >&2
  printf '  %s\n' "${violations[@]}" >&2
  echo >&2
  echo "Answer paths must resolve from graph truth. If this is a genuine" >&2
  echo "input/output boundary (not the semantic answer), add it to allow_for." >&2
  exit 1
fi

echo "Zero File-Search guard passed: answer paths are graph-clean."
