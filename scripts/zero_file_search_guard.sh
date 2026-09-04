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
#        zero_file_search_guard.sh --list-scanned [repo_root]
# Exit: 0 when the answer paths are graph-clean, 1 on the first violation.
set -euo pipefail

# Two lists, two meanings, and the difference matters.
#
#   --list-scanned   every answer module, deferred ones included. This is the
#                    notion of an answer module the Python checker's
#                    `check_guard_seam` compares against, because a deferred
#                    file is still an answer module; it is simply graded by the
#                    other guard.
#   --list-enforced  the modules THIS guard actually runs its deny set over.
#                    scripts/falsify-zero-file-search.py poisons these, and
#                    poisoning a deferred one would fail for the wrong reason.
list_only=0
if [[ "${1:-}" == "--list-scanned" ]]; then
  list_only=1
  shift
elif [[ "${1:-}" == "--list-enforced" ]]; then
  list_only=2
  shift
fi

repo_root="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cmd_dir="crates/kin-cli/src/commands"
allowlist="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/zero-file-search-allowlist.json"

# Answer-authority modules, DERIVED rather than listed.
#
# This was a hardcoded array of ten module names, and that was the FIR-2282
# defect: an opt-in list on a surface of 107 modules, so a new command with a
# raw filesystem fallback was outside the guard on the day it was written. It
# was also the second such list. The Python checker kept its own, they covered
# different sets, and nothing compared them, so `contextbench_locate.rs`,
# `locate_cursor.rs` and `locate_debug.rs` were answer modules here and did not
# exist over there.
#
# So: every module in the directory is an answer module, minus the ones the
# shared allowlist exempts whole-file. That is the same list
# `command_modules_scanned` builds in the Python checker, and its
# `check_guard_seam` runs `--list-scanned` and fails when the two differ, so the
# drift that produced this ticket cannot recur silently.
#
# A whole-file exemption is an entry with no `allow_match` and no `allow_fn`.
# Read with awk rather than a JSON parser because this guard stays dependency
# free, and the allowlist is machine-written with one key per line. The parse
# carries its own control below: a run that resolves zero modules refuses
# instead of reporting a clean sheet over nothing.
allowlist_files() {
  # $2 selects which kind: "whole" for entries with no pins, "pinned" for the
  # rest. Both are read from the same entries in one pass so they cannot
  # disagree about which bucket a file is in.
  awk -v want="$2" '
    /^    \{/                    { file=""; pinned=0; next }
    /"file":/                    { if (match($0, /crates\/[^"]*/)) file=substr($0, RSTART, RLENGTH) }
    /"allow_match"|"allow_fn"/   { pinned=1 }
    /^    \}/                    {
      if (file != "" && ((want == "whole" && pinned == 0) || (want == "pinned" && pinned == 1)))
        print file
      file=""; pinned=0
    }
  ' "$1"
}

exempt=" $(allowlist_files "$allowlist" whole | tr '\n' ' ') "

# Files whose exemptions are expression pins or function bodies. This guard
# cannot express those without a JSON parser it deliberately does not have, so
# it DEFERS them to the Python checker, which grades them in full.
#
# Deferring rather than exempting, and counted out loud below, because a silent
# skip is the defect this ticket exists to remove. A deferred file is still an
# answer module: it appears in `--list-scanned`, the seam check compares it, and
# the Python checker reports every line of it. What this guard gives up is only
# its second opinion, and only where a boundary has already been declared and
# reviewed.
pinned=" $(allowlist_files "$allowlist" pinned | tr '\n' ' ') "

# The test-file rule, stated to match `is_test_file` in the Python checker
# exactly: a `test_` prefix or a `_test.rs` suffix. Both spellings, because the
# checker skips both and the seam check compares the resulting sets.
#
# `test_subprocess.rs` is why the prefix half is here and it was found by that
# seam check on its first run, not by reading. It is `#[cfg(test)] pub(crate)
# mod test_subprocess;` in commands/mod.rs, so it does not exist in a production
# build, and this guard would have scanned it while the checker skipped it.
authority_files=()
while IFS= read -r path; do
  rel="${path#"$repo_root"/}"
  base="${rel##*/}"
  case "$base" in test_*) continue ;; *_test.rs) continue ;; esac
  [[ "$exempt" == *" $rel "* ]] && continue
  authority_files+=("$rel")
done < <(find "$repo_root/$cmd_dir" -maxdepth 1 -name '*.rs' -type f | sort)

# The control. A glob that matched nothing, or an allowlist parse that swallowed
# every module, would otherwise print "answer paths are graph-clean" over an
# empty set, which is the exact failure mode this ticket is about.
if ((${#authority_files[@]} < 10)); then
  echo "Zero File-Search guard REFUSES: resolved only ${#authority_files[@]} answer" >&2
  echo "module(s) under $cmd_dir. That is fewer than this repository has ever had," >&2
  echo "so the enumeration is broken rather than the tree being clean." >&2
  exit 1
fi

if ((list_only == 1)); then
  printf '%s\n' "${authority_files[@]##*/}"
  exit 0
fi

# Raw filesystem read / existence / traversal primitives. Subprocess creation
# is denied wholesale in answer modules so dynamic or multiline rg/grep/find/
# git-grep builders cannot bypass a line-local executable-name pattern.
#
# The filesystem half matches the MODULE, not the item name. It used to read
# `std::fs::(read|read_to_string|read_dir|metadata|File)`, an enumeration of
# five functions, and `OpenOptions` was in neither that alternation nor the
# Python checker's: a read written with the builder shape passed both guards
# green in `locate.rs`, the flagship answer module. Naming five items out of a
# module is always one item behind, and `std::fs::exists` stabilising in 1.81
# would have been the next miss. `std::fs` on its own is complete over that
# module forever, and it costs nothing here because none of the ten answer
# modules imports it.
#
# This guard has no parser, so it cannot do what the Python checker does and
# learn a file's bindings from its own `use` trees. It does not have to: you
# cannot bind an fs name without a `use` line, and a `use` line always names
# the module. So the type names below are belt to the namespace reach's braces,
# and the two together close the same class the checker closes with a parser.
deny_re='\.is_file\(\)|\.is_dir\(\)|\.exists\(\)|\.try_exists\(\)|\.is_symlink\(\)|\.canonicalize\(\)|\.metadata\(\)|symlink_metadata|read_link|Command::new[[:space:]]*\(|process[[:space:]]*(::|as([[:space:]]|$))|(std|core)::fs|std::os::(unix|windows|wasi)::fs|(tokio|async_std|smol)::fs|(fs_err|fs2|fs_extra|filetime|walkdir)::|[^_a-z]fs::[a-zA-Z_]|File::(open|create|create_new|options)|OpenOptions|DirBuilder|DirEntry|ReadDir|read_dir\(|WalkDir|glob::glob'

# Per-file justified allowlist (input/output boundaries, not the answer). A new
# or different primitive in the same file still trips the guard.
#
# One expression PER LINE, and more than one per file is allowed. It used to be
# a single string, which was not a policy decision, it was the shape the deny
# set happened to need: nothing else was reported, so nothing else had to be
# declared. Widening the deny set from five enumerated `std::fs` functions to
# the module surfaced the cursor cache's own write and delete in
# `locate_cursor.rs`, two boundary calls sitting one line apart from a read that
# was declared, invisible for as long as the guard only watched five names.
# Each expression is still counted and must occur exactly once.
allow_for() {
  case "$1" in
    locate.rs)
      printf '%s\n' 'let marker_present = tel::consent_marker_path(layout.root()).exists();'
      ;;
    locate_cursor.rs)
      # The paging-cursor cache, read, written and cleared. It holds a locate
      # continuation token, never repository content, and no locate result is
      # derived from it: a miss restarts paging rather than answering.
      printf '%s\n' 'std::fs::read_to_string(&path)' \
                    'let _ = std::fs::write(&path, cursor);' \
                    'let _ = std::fs::remove_file(&path);'
      ;;
    locate_debug.rs)
      printf '%s\n' 'std::fs::read_to_string(path)'
      ;;
    resolve.rs)
      # Explicit bounded merge input, submitted once and persisted in CAS.
      printf '%s\n' 'let input = std::fs::File::open(source)'
      ;;
    contextbench_locate.rs)
      printf '%s\n' 'std::fs::read_to_string(&task_file)'
      ;;
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

enforced_files=()
for rel in "${authority_files[@]}"; do
  if [[ "$pinned" == *" $rel "* ]] && [[ -z "$(allow_for "${rel##*/}")" ]]; then
    continue
  fi
  enforced_files+=("$rel")
done

if ((list_only == 2)); then
  printf '%s\n' "${enforced_files[@]##*/}"
  exit 0
fi

violations=()
deferred=$(( ${#authority_files[@]} - ${#enforced_files[@]} ))
for rel in "${authority_files[@]}"; do
  file="$repo_root/$rel"
  [[ -f "$file" ]] || continue
  base="$(basename "$rel")"
  # Declared boundaries this guard cannot express, deferred to the Python
  # checker. A file `allow_for` covers is NOT deferred: those pins are this
  # guard's own and predate the shared list, and dropping them would quietly
  # narrow coverage of the four core answer modules while this change claims to
  # widen it.
  if [[ "$pinned" == *" $rel "* ]] && [[ -z "$(allow_for "$base")" ]]; then
    continue
  fi
  read -r test_start test_end <<<"$(test_module_span "$file")"

  # Read into an array rather than a single string. `while read` rather than
  # `mapfile`, because the CI image and this fleet's macOS boxes do not agree on
  # bash 4.
  allow_list=()
  while IFS= read -r allow_expr; do
    [[ -n "$allow_expr" ]] && allow_list+=("$allow_expr")
  done < <(allow_for "$base")

  # Everything outside the test module, before it and after it alike, with the
  # original line numbers preserved.
  # Everything outside the test module, plus the single-statement items a
  # `#[cfg(test)]` gates on its own.
  #
  # The second half was found by widening this guard's coverage, not by reading:
  # `setup_ledger.rs` carries `#[cfg(test)]` on line 25 and `use std::fs;` on 26,
  # a test-only import of a production-looking module. `test_module_span` only
  # recognises a `#[cfg(test)]` whose next item is a `mod`, so it walked past
  # this one to the real test module at 768 and reported line 26 as a production
  # filesystem import. The Python checker's cfg tracker already excluded it, so
  # the two guards disagreed about one line of one file.
  #
  # Only a one-line statement is dropped, never an item with a body. A gated
  # `fn` or `mod` keeps being scanned, which over-reports rather than
  # under-reports, and over-reporting is the direction a reviewer can see.
  # Comments are stripped, because this guard had no lexer and the deny set is
  # full of ordinary words. Measured: `// we deliberately avoid OpenOptions
  # here`, `// the process as a whole is graph-owned` and a trailing
  # `// OpenOptions is not used` each redden a REQUIRED context, in any of the
  # 57 modules FIR-2282 newly covers, while the Python checker correctly ignores
  # all three. A guard that fails on prose trains people to write around it.
  #
  # The stripper tracks double-quoted strings so a `//` inside a literal cannot
  # truncate the code after it, and it carries block-comment state across lines.
  # Every way it can be wrong is a FALSE POSITIVE: a char literal holding a quote
  # leaves it believing it is inside a string, so it stops stripping and reports
  # more, and a string spanning lines resets at the newline, where the only thing
  # it could then hide is text inside a literal, which is not code. It never
  # strips something it should have scanned.
  region="$(awk -v s="$test_start" -v e="$test_end" '
    function strip(line,   i, n, ch, nx, out, in_str, esc) {
      n = length(line); out = ""
      for (i = 1; i <= n; i++) {
        ch = substr(line, i, 1); nx = substr(line, i + 1, 1)
        if (in_block) { if (ch == "*" && nx == "/") { in_block = 0; i++ } ; continue }
        if (in_str) {
          out = out ch
          if (esc) esc = 0
          else if (ch == "\\") esc = 1
          else if (ch == "\"") in_str = 0
          continue
        }
        if (ch == "\"") { in_str = 1; out = out ch; continue }
        if (ch == "/" && nx == "/") break
        if (ch == "/" && nx == "*") { in_block = 1; i++; continue }
        out = out ch
      }
      return out
    }
    NR >= s && NR <= e                              { next }
    /^[[:space:]]*#\[cfg\(test\)\][[:space:]]*$/ { gate = 1; next }
    gate && /^[[:space:]]*(\/\/|$)/                 { next }
    gate {
      gate = 0
      if ($0 !~ /^[[:space:]]*mod / && $0 ~ /;[[:space:]]*$/) next
    }
                                                    { print NR ":" strip($0) }
  ' "$file")"
  scan_region="$region"

  # An empty array is unbound under `set -u` on bash 3.2, so expand it guarded.
  pin_failed=0
  for allow in ${allow_list[@]+"${allow_list[@]}"}; do
    allow_hits="$(grep -F -o -- "$allow" "$file" || true)"
    allow_count=0
    if [[ -n "$allow_hits" ]]; then
      allow_count="$(printf '%s\n' "$allow_hits" | wc -l | tr -d '[:space:]')"
    fi
    if [[ "$allow_count" -ne 1 ]]; then
      violations+=(
        "$rel: allowlist expression occurs $allow_count times (want exactly 1): $allow"
      )
      pin_failed=1
      continue
    fi
    scan_region="$(printf '%s\n' "$scan_region" | awk -v needle="$allow" '
      {
        pos = index($0, needle)
        if (pos > 0) {
          $0 = substr($0, 1, pos - 1) substr($0, pos + length(needle))
        }
        print
      }
    ')"
  done
  [[ "$pin_failed" -eq 0 ]] || continue

  hits="$(printf '%s\n' "$scan_region" | grep -E "$deny_re" || true)"
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

echo "Zero File-Search guard passed: ${#authority_files[@]} answer modules are graph-clean" \
     "($deferred with declared boundary pins deferred to verify-zero-file-search.py)."
