#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v rg >/dev/null 2>&1; then
  echo "runtime boundary guard requires ripgrep (rg)" >&2
  exit 1
fi

allowed_files=(
  "crates/kin-cli/src/backend.rs"
  "crates/kin-cli/src/commands/init.rs"
  "crates/kin-daemon/src/api.rs"
  # kin-db defines SnapshotManager here, so this file IS the runtime internal the
  # rule protects. It moved into crates/ on 2026-09-11; while kin-db was a registry
  # dependency the scan never reached its source at all.
  "crates/kin-db/src/storage/snapshot.rs"
  "crates/kin-daemon/src/state.rs"
  "crates/kin-migrate/src/executor.rs"
)

allowed_session_registry_files=(
  "crates/kin-mcp/src/server.rs"
  "crates/kin-mcp/src/session.rs"
  "crates/kin-mcp/src/handlers/mod.rs"
  "crates/kin-mcp/src/handlers/sessions.rs"
  # Declared only under #[cfg(test)] in handlers/mod.rs. These fixtures own
  # isolated registries to prove external scopes cannot acquire local locks.
  "crates/kin-mcp/src/handlers/external_symbols_tests.rs"
)

is_allowed() {
  local file="$1"
  for allowed in "${allowed_files[@]}"; do
    if [[ "$file" == "$allowed" ]]; then
      return 0
    fi
  done
  return 1
}

unexpected_hits=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  if [[ "$file" == crates/*/tests/* ]]; then
    continue
  fi
  if ! is_allowed "$file"; then
    unexpected_hits+=("$file:$line")
  fi
done < <(rg -n 'SnapshotManager::open\(' "$repo_root/crates" -g '*.rs')

if ((${#unexpected_hits[@]} > 0)); then
  echo "Unexpected direct SnapshotManager::open usage outside runtime internals:" >&2
  printf '  %s\n' "${unexpected_hits[@]}" >&2
  exit 1
fi

unexpected_graph_loads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_graph_loads+=("$file:$line")
done < <(rg -n 'load_stdio_graph\(' "$repo_root/crates" -g '*.rs')

if ((${#unexpected_graph_loads[@]} > 0)); then
  echo "Unexpected local MCP graph bootstrap outside the start path:" >&2
  printf '  %s\n' "${unexpected_graph_loads[@]}" >&2
  exit 1
fi

unexpected_cli_search_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_search_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|ReadIndex::load|with_extension\("kidx"\)' "$repo_root/crates/kin-cli/src/commands/search.rs" -g '*.rs')

if ((${#unexpected_cli_search_reads[@]} > 0)); then
  echo "Unexpected local graph/read-index access in kin search product path:" >&2
  printf '  %s\n' "${unexpected_cli_search_reads[@]}" >&2
  exit 1
fi

unexpected_cli_support_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_support_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/support.rs" -g '*.rs')

if ((${#unexpected_cli_support_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin support product path:" >&2
  printf '  %s\n' "${unexpected_cli_support_reads[@]}" >&2
  exit 1
fi

unexpected_cli_context_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_context_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/context.rs" -g '*.rs')

if ((${#unexpected_cli_context_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin context product path:" >&2
  printf '  %s\n' "${unexpected_cli_context_reads[@]}" >&2
  exit 1
fi

unexpected_cli_trace_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_trace_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/trace.rs" -g '*.rs')

if ((${#unexpected_cli_trace_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin trace product path:" >&2
  printf '  %s\n' "${unexpected_cli_trace_reads[@]}" >&2
  exit 1
fi

unexpected_cli_impact_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_impact_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/impact.rs" -g '*.rs')

if ((${#unexpected_cli_impact_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin impact product path:" >&2
  printf '  %s\n' "${unexpected_cli_impact_reads[@]}" >&2
  exit 1
fi

unexpected_cli_review_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_review_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/review.rs" -g '*.rs')

if ((${#unexpected_cli_review_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin review product path:" >&2
  printf '  %s\n' "${unexpected_cli_review_reads[@]}" >&2
  exit 1
fi

unexpected_cli_embed_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_embed_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/embed.rs" -g '*.rs')

if ((${#unexpected_cli_embed_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin embed product path:" >&2
  printf '  %s\n' "${unexpected_cli_embed_reads[@]}" >&2
  exit 1
fi

unexpected_cli_blame_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_blame_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path|SnapshotManager::save_graph' "$repo_root/crates/kin-cli/src/commands/blame.rs" -g '*.rs')

if ((${#unexpected_cli_blame_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin blame product path:" >&2
  printf '  %s\n' "${unexpected_cli_blame_reads[@]}" >&2
  exit 1
fi

unexpected_cli_history_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_history_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first|open_kindb_snapshot|SnapshotManager::open|kindb_snapshot_path|SnapshotManager::save_graph' "$repo_root/crates/kin-cli/src/commands/history.rs" -g '*.rs')

if ((${#unexpected_cli_history_reads[@]} > 0)); then
  echo "Unexpected local graph access in kin history product path:" >&2
  printf '  %s\n' "${unexpected_cli_history_reads[@]}" >&2
  exit 1
fi

for command_file in status work note overview graph dead_code refs xref verify commit diff log audit approvals security branch checkout rename session_workspace; do
  # Every guarded command must still exist. A silently absent file would make
  # its rule pass by scanning nothing, so a rename has to be reflected here.
  if [[ ! -f "$repo_root/crates/kin-cli/src/commands/${command_file}.rs" ]]; then
    echo "Guarded command path crates/kin-cli/src/commands/${command_file}.rs is missing:" >&2
    echo "  update this list when a command module is renamed or removed" >&2
    exit 1
  fi
  unexpected_cli_command_graph_reads=()
  while IFS=: read -r file line _; do
    [[ -z "$file" ]] && continue
    file="${file#"$repo_root/"}"
    unexpected_cli_command_graph_reads+=("$file:$line")
  done < <(rg -n 'open_snapshot_daemon_first|require_daemon_graph_mutations|ReadIndex::load|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/${command_file}.rs" -g '*.rs')

  if ((${#unexpected_cli_command_graph_reads[@]} > 0)); then
    echo "Unexpected local graph access in kin ${command_file} product path:" >&2
    printf '  %s\n' "${unexpected_cli_command_graph_reads[@]}" >&2
    exit 1
  fi
done

unexpected_ref_lookup_saves=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_ref_lookup_saves+=("$file:$line")
done < <(rg -n 'SnapshotManager::save_graph|kindb_snapshot_path' "$repo_root/crates/kin-cli/src/commands/ref_lookup.rs" -g '*.rs')

if ((${#unexpected_ref_lookup_saves[@]} > 0)); then
  echo "Unexpected local graph persistence in ref lookup helpers:" >&2
  printf '  %s\n' "${unexpected_ref_lookup_saves[@]}" >&2
  exit 1
fi

unexpected_cli_verify_writes=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_verify_writes+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first\(|snap\.save\(\?\)' "$repo_root/crates/kin-cli/src/commands/verify.rs" -g '*.rs')

if ((${#unexpected_cli_verify_writes[@]} > 0)); then
  echo "Unexpected local graph write access in kin verify product path:" >&2
  printf '  %s\n' "${unexpected_cli_verify_writes[@]}" >&2
  exit 1
fi

unexpected_cli_writable_graph_opens=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  case "$file" in
    crates/kin-cli/src/commands/import.rs)
      ;;
    *)
      unexpected_cli_writable_graph_opens+=("$file:$line")
      ;;
  esac
done < <(rg -n 'open_snapshot_daemon_first\(' "$repo_root/crates/kin-cli/src/commands" -g '*.rs')

if ((${#unexpected_cli_writable_graph_opens[@]} > 0)); then
  echo "Unexpected writable CLI graph opens outside remaining import/reconcile migration paths:" >&2
  printf '  %s\n' "${unexpected_cli_writable_graph_opens[@]}" >&2
  exit 1
fi

unexpected_cli_daemon_bootstrap_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  unexpected_cli_daemon_bootstrap_reads+=("$file:$line")
done < <(rg -n 'open_snapshot_daemon_first_read_only\(' "$repo_root/crates/kin-cli/src/commands" -g '*.rs')

if ((${#unexpected_cli_daemon_bootstrap_reads[@]} > 0)); then
  echo "Unexpected daemon-bootstrap graph hydration in CLI product command path:" >&2
  printf '  %s\n' "${unexpected_cli_daemon_bootstrap_reads[@]}" >&2
  exit 1
fi

unexpected_cli_admin_bootstrap_reads=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  case "$file" in
    crates/kin-cli/src/commands/push.rs|\
    crates/kin-cli/src/commands/pull.rs|\
    crates/kin-cli/src/commands/remote.rs|\
    crates/kin-cli/src/commands/native_sync.rs|\
    crates/kin-cli/src/commands/git.rs|\
    crates/kin-cli/src/commands/release.rs|\
    crates/kin-cli/src/commands/merge.rs|\
    crates/kin-cli/src/commands/resolve.rs|\
    crates/kin-cli/src/commands/locate_debug.rs)
      ;;
    *)
      unexpected_cli_admin_bootstrap_reads+=("$file:$line")
      ;;
  esac
done < <(rg -n 'open_snapshot_explicit_admin_read_only\(' "$repo_root/crates/kin-cli/src/commands" -g '*.rs')

if ((${#unexpected_cli_admin_bootstrap_reads[@]} > 0)); then
  echo "Unexpected explicit-admin graph hydration outside declared legacy admin/debug/sync commands:" >&2
  printf '  %s\n' "${unexpected_cli_admin_bootstrap_reads[@]}" >&2
  exit 1
fi

# Direct local storage reads from a command module.
#
# The scan above governs `open_snapshot_explicit_admin_read_only`, which carries
# its own daemon-first authority order and env gate. `open_snapshot_local` is the
# raw local open underneath it, and a command calling it directly gets neither
# unless it arranges them itself. `graph_viz.rs` does arrange them, at
# `resolve_payload`: daemon first, then `daemon_bootstrap_admin_allowed()`, then a
# refusal. It is the one command allowed to, and it is named here so the next one
# has to be a decision rather than an omission.
#
# This scan exists because the allowlist above lost its `graph_viz.rs` entry when
# that file stopped calling the wrapper, which left its new direct call ungoverned
# by anything in this script.
unexpected_cli_direct_local_opens=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  case "$file" in
    crates/kin-cli/src/commands/graph_viz.rs)
      ;;
    *)
      unexpected_cli_direct_local_opens+=("$file:$line")
      ;;
  esac
done < <(rg -n 'open_snapshot_local\(' "$repo_root/crates/kin-cli/src/commands" -g '*.rs')

if ((${#unexpected_cli_direct_local_opens[@]} > 0)); then
  echo "Unexpected direct local graph open in a CLI command; route it through the daemon, or add the file here with the authority order it implements:" >&2
  printf '  %s\n' "${unexpected_cli_direct_local_opens[@]}" >&2
  exit 1
fi

unexpected_session_registry_hits=()
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  case " ${allowed_session_registry_files[*]} " in
    *" $file "*) ;;
    *)
      unexpected_session_registry_hits+=("$file:$line")
      ;;
  esac
done < <(rg -n 'SessionRegistry::new\(' "$repo_root/crates/kin-mcp/src" -g '*.rs')

if ((${#unexpected_session_registry_hits[@]} > 0)); then
  echo "Unexpected SessionRegistry instantiation outside runtime fallback sites:" >&2
  printf '  %s\n' "${unexpected_session_registry_hits[@]}" >&2
  exit 1
fi

if rg -n 'tokio::spawn' "$repo_root/crates/kin-mcp/src/handlers/sessions.rs" -g '*.rs' >/dev/null; then
  echo "Unexpected fire-and-forget session delegation in kin-mcp session handlers:" >&2
  rg -n 'tokio::spawn' "$repo_root/crates/kin-mcp/src/handlers/sessions.rs" -g '*.rs' >&2
  exit 1
fi

# The re-derivation commit is the one place a binding-history lineage may start
# part way through a store's operation log, so the upgrade module is its only
# caller. An HTTP, MCP or hosted route, or any other command, reaching it would
# let a request qualify state no re-derivation produced. kin-db defines it,
# kin-index implements the verifier it takes, and the upgrade calls it.
#
# The upgrade module reaches it from two entry points, and only two. `kin
# upgrade` is one. The other is `requalify_at_daemon_start`, which a daemon
# runs as it starts on a store whose workspace carries no checked binding
# history, so that nobody has to run `kin upgrade` by hand. It is the same plan,
# verifier, compare-and-swap and payment, run where the command runs them:
# holding the repository's runtime authority, before any state is open, never
# from a request. Only the daemon's startup module may name that entry point,
# and nothing outside the upgrade module may name the commit or its verifier.
unexpected_rederivation_hits=()
rederivation_caller_seen=0
while IFS=: read -r file line text; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  case "$file" in
    crates/kin-cli/src/commands/upgrade.rs)
      # The positive control counts the commit itself, not the verifier
      # type beside it, so renaming the commit fails this rule.
      if [[ "$text" == *commit_rederived_repository_transaction* ]]; then
        rederivation_caller_seen=1
      fi
      ;;
    crates/kin-db/src/storage/repository.rs | \
      crates/kin-db/src/storage/binding_history.rs | \
      crates/kin-db/src/storage/binding_history_tests.rs | \
      crates/kin-db/src/storage/derivation_ledger_tests.rs | \
      crates/kin-index/src/binding_history.rs) ;;
    # A test target, never a runtime path. The upgrade's store tests drive the
    # commit with the real verifier to show that a certificate bound to the
    # current bytes, with no derivation behind it, pays nothing.
    crates/kin-cli/tests/store_upgrade.rs) ;;
    *)
      unexpected_rederivation_hits+=("$file:$line")
      ;;
  esac
done < <(rg -n 'commit_rederived_repository_transaction|RederivationBindingHistoryVerifier|RederivationVerifier\b' "$repo_root/crates" -g '*.rs')

if ((${#unexpected_rederivation_hits[@]} > 0)); then
  echo "Unexpected use of the re-derivation commit or its verifier outside kin upgrade:" >&2
  printf '  %s\n' "${unexpected_rederivation_hits[@]}" >&2
  exit 1
fi
# The positive control: a rename that moved the caller would otherwise leave
# this rule scanning for names nothing uses and passing on nothing.
if ((rederivation_caller_seen == 0)); then
  echo "kin upgrade no longer names the re-derivation commit in crates/kin-cli/src/commands/upgrade.rs:" >&2
  echo "  update this rule when the caller or the API is renamed" >&2
  exit 1
fi

# The daemon-start entry point runs the same re-derivation commit, so it has
# exactly one runtime caller: the daemon's startup, before it opens state.
unexpected_startup_requalification_hits=()
startup_requalification_caller_seen=0
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  file="${file#"$repo_root/"}"
  case "$file" in
    crates/kin-cli/src/commands/upgrade.rs) ;;
    crates/kin-daemon/src/startup_requalification.rs)
      startup_requalification_caller_seen=1
      ;;
    # Test targets drive it directly against fixture stores.
    crates/kin-cli/tests/store_upgrade.rs) ;;
    *)
      unexpected_startup_requalification_hits+=("$file:$line")
      ;;
  esac
done < <(rg -n 'requalify_at_daemon_start' "$repo_root/crates" -g '*.rs')

if ((${#unexpected_startup_requalification_hits[@]} > 0)); then
  echo "Unexpected caller of the daemon-start re-qualification outside the daemon's startup:" >&2
  printf '  %s\n' "${unexpected_startup_requalification_hits[@]}" >&2
  exit 1
fi
if ((startup_requalification_caller_seen == 0)); then
  echo "the daemon's startup no longer names requalify_at_daemon_start in crates/kin-daemon/src/startup_requalification.rs:" >&2
  echo "  update this rule when the caller or the entry point is renamed" >&2
  exit 1
fi

echo "Runtime guardrails check passed."
