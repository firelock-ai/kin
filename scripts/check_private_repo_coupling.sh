#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v rg >/dev/null 2>&1; then
  echo "private repo coupling guard requires ripgrep (rg)" >&2
  exit 1
fi

# ripgrep anchors a glob containing a slash to the working directory rather than
# to the path it is told to search, so searching an absolute repo root from any
# other directory silently stops matching every exclusion below, and the guard
# then reports its own pattern list as coupling. Searching '.' from the repo
# root is what makes the exclusions mean what they read as.
cd "$repo_root"

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
    file="${file#./}"
    hits+=("$file:$line:$pattern")
  done < <(rg -n "$pattern" . \
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
