#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

allowed_files=(
  "crates/kin-cli/src/backend.rs"
  "crates/kin-daemon/src/state.rs"
  "crates/kin-mcp/src/graph_loader.rs"
  "crates/kin-migrate/src/executor.rs"
)

allowed_graph_load_files=(
  "crates/kin-cli/src/commands/mcp.rs"
  "crates/kin-mcp/src/graph_loader.rs"
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
  case " ${allowed_graph_load_files[*]} " in
    *" $file "*) ;;
    *)
      unexpected_graph_loads+=("$file:$line")
      ;;
  esac
done < <(rg -n 'load_stdio_graph\(' "$repo_root/crates" -g '*.rs')

if ((${#unexpected_graph_loads[@]} > 0)); then
  echo "Unexpected local MCP graph bootstrap outside the start path:" >&2
  printf '  %s\n' "${unexpected_graph_loads[@]}" >&2
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
