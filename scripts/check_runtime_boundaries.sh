#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

allowed_files=(
  "crates/kin-cli/src/backend.rs"
  "crates/kin-cli/src/commands/init.rs"
  "crates/kin-daemon/src/api.rs"
  "crates/kin-daemon/src/state.rs"
  "crates/kin-migrate/src/executor.rs"
)

allowed_session_registry_files=(
  "crates/kin-mcp/src/server.rs"
  "crates/kin-mcp/src/session.rs"
  "crates/kin-mcp/src/handlers/mod.rs"
  "crates/kin-mcp/src/handlers/sessions.rs"
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

for command_file in status work note overview graph dead_code refs xref verify commit diff log audit approvals security branch checkout rename with exec session_workspace open shell; do
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
    crates/kin-cli/src/commands/graph_viz.rs|\
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

echo "Runtime guardrails check passed."
