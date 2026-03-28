#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

patterns=(
  '\.\./kinlab'
  'kinlab\.git'
  'pnpm --filter @kinlab'
  '@kinlab/control-plane'
  '@kinlab/web'
  'kinlab-control-plane'
  'kinlab-web'
  'cargo install --git .*kinlab'
)

hits=()
for pattern in "${patterns[@]}"; do
  while IFS=: read -r file line _; do
    [[ -z "$file" ]] && continue
    file="${file#"$repo_root/"}"
    hits+=("$file:$line:$pattern")
  done < <(rg -n "$pattern" "$repo_root" \
    -g '!target/**' \
    -g '!.git/**' \
    -g '!scripts/check_private_repo_coupling.sh' \
    -g '!Cargo.lock' \
    -g '!pnpm-lock.yaml' || true)
done

if ((${#hits[@]} > 0)); then
  echo "Private KinLab source/build/orchestration references are not allowed in public kin:" >&2
  printf '  %s\n' "${hits[@]}" >&2
  exit 1
fi

echo "Private repo coupling check passed."
