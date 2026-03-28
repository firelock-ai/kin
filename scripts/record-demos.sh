#!/usr/bin/env bash
# Record terminal demo GIFs for Kin README.
# Requires: asciinema, agg, and a 'kin' binary on PATH or at KIN_BINARY.
#
# Usage:
#   ./scripts/record-demos.sh            # record all demos
#   ./scripts/record-demos.sh git-interop # record one demo
#
# Output goes to .github/demos/*.gif

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORKSPACE_ROOT="$(cd "$REPO_ROOT/.." && pwd)"
DEFAULT_KIN_BINARY="$REPO_ROOT/target/release/kin"
if [[ -n "${KIN_BINARY:-}" ]]; then
  KIN="$KIN_BINARY"
elif [[ -x "$DEFAULT_KIN_BINARY" ]]; then
  KIN="$DEFAULT_KIN_BINARY"
else
  KIN="kin"
fi
OUT_DIR="$REPO_ROOT/.github/demos"
CAST_DIR="$(mktemp -d)"
SANDBOX="$(mktemp -d)"

mkdir -p "$OUT_DIR"

AGG_OPTS=(--font-size 16 --cols 90 --rows 28 --speed 1.5 --theme monokai)

cleanup() {
  rm -rf "$CAST_DIR" "$SANDBOX"
}
trap cleanup EXIT

# Helper: create a realistic sample project in a temp dir
create_sample_project() {
  local dir="$1"
  rm -rf "$dir"
  mkdir -p "$dir" && cd "$dir"
  git init -b main --quiet

  cat > server.js << 'JS'
const http = require('http');
const { parseUrl, formatResponse } = require('./utils');

function handleRequest(req, res) {
  const route = parseUrl(req.url);
  if (route === '/health') {
    res.writeHead(200);
    res.end(formatResponse({ status: 'ok' }));
  } else if (route === '/api/users') {
    res.writeHead(200);
    res.end(formatResponse({ users: [] }));
  } else {
    res.writeHead(404);
    res.end('Not found');
  }
}

const server = http.createServer(handleRequest);
server.listen(3000, () => console.log('Listening on :3000'));
JS

  cat > utils.js << 'JS'
function parseUrl(url) {
  return url.split('?')[0];
}

function formatResponse(data) {
  return JSON.stringify(data, null, 2);
}

module.exports = { parseUrl, formatResponse };
JS

  git add -A && git commit -m "initial server" --quiet
}

clone_repo_for_demo() {
  local source_repo="$1"
  local target_dir="$2"
  rm -rf "$target_dir"
  git clone --local --quiet "$source_repo" "$target_dir"
}

materialize_kin_state() {
  local repo_dir="$1"
  (
    cd "$repo_dir"
    "$KIN" init . >/dev/null
    "$KIN" git import . >/dev/null
    "$KIN" commit -m "materialize semantic state" >/dev/null
  )
}

record_git_vs_kin_repo() {
  local demo_key="$1"
  local title="$2"
  local source_repo="$3"
  local git_def_cmd="$4"
  local git_refs_cmd="$5"
  local trace_symbol="$6"
  local impact_symbol="$7"

  local proj="$SANDBOX/$demo_key"
  local cast="$CAST_DIR/$demo_key.cast"
  local runner="$CAST_DIR/$demo_key.sh"
  local escaped_kin
  escaped_kin="$(printf '%q' "$KIN")"

  clone_repo_for_demo "$source_repo" "$proj"
  materialize_kin_state "$proj"

  cat > "$runner" <<EOF
#!/usr/bin/env bash
set -euo pipefail

KIN=$escaped_kin

run_demo_command() {
  local cmd="\$1"
  local pre_sleep="\${2:-0.5}"
  local post_sleep="\${3:-2}"
  echo "\$ \$cmd"
  sleep "\$pre_sleep"
  eval "\$cmd"
  sleep "\$post_sleep"
  echo ""
}

echo "# Git vs Kin: $title"
sleep 1.5
echo "# Same repo. Same question. Different substrate."
sleep 1.5
echo ""

run_demo_command '$git_def_cmd' 0.5 2
run_demo_command '$git_refs_cmd' 0.5 2.5
run_demo_command "\$KIN trace $trace_symbol" 0.5 3
run_demo_command "\$KIN impact $impact_symbol" 0.5 3
EOF

  chmod +x "$runner"

  (
    cd "$proj"
    asciinema rec --overwrite --cols 90 --rows 28 --command "bash '$runner'" "$cast"
  )

  agg "${AGG_OPTS[@]}" "$cast" "$OUT_DIR/$demo_key.gif"
  echo "Wrote $OUT_DIR/$demo_key.gif"
}

# ---------------------------------------------------------------------------
# Demo: Git Interop (brownfield adoption)
# ---------------------------------------------------------------------------
record_git_interop() {
  local proj="$SANDBOX/my-project"
  create_sample_project "$proj"
  cd "$proj"

  local cast="$CAST_DIR/git-interop.cast"

  asciinema rec --overwrite --cols 90 --rows 28 --command "bash -c '
    set -e
    KIN=\"$KIN\"

    echo \"# Adopt Kin on an existing Git repo\"
    sleep 1.5

    echo \"\$ kin init .\"
    sleep 0.5
    \$KIN init .
    sleep 1

    echo \"\"
    echo \"\$ kin git import .\"
    sleep 0.5
    \$KIN git import .
    sleep 1

    echo \"\"
    echo \"\$ kin commit -m \\\"materialize semantic state\\\"\"
    sleep 0.5
    \$KIN commit -m \"materialize semantic state\"
    sleep 1.5

    echo \"\"
    echo \"\$ kin status\"
    sleep 0.5
    \$KIN status
    sleep 1.5

    echo \"\"
    echo \"\$ kin trace handleRequest\"
    sleep 0.5
    \$KIN trace handleRequest
    sleep 3
  '" "$cast"

  agg "${AGG_OPTS[@]}" "$cast" "$OUT_DIR/git-interop.gif"
  echo "Wrote $OUT_DIR/git-interop.gif"
}

# ---------------------------------------------------------------------------
# Demo: Overview + Trace (semantic exploration)
# ---------------------------------------------------------------------------
record_explore() {
  local proj="$SANDBOX/explore-project"
  create_sample_project "$proj"
  cd "$proj"
  $KIN init . >/dev/null 2>&1
  $KIN git import . >/dev/null 2>&1
  $KIN commit -m "init" >/dev/null 2>&1

  local cast="$CAST_DIR/explore.cast"

  asciinema rec --overwrite --cols 90 --rows 28 --command "bash -c '
    set -e
    KIN=\"$KIN\"

    echo \"\$ kin overview\"
    sleep 0.5
    \$KIN overview
    sleep 2

    echo \"\"
    echo \"\$ kin trace handleRequest\"
    sleep 0.5
    \$KIN trace handleRequest
    sleep 2

    echo \"\"
    echo \"\$ kin trace parseUrl\"
    sleep 0.5
    \$KIN trace parseUrl
    sleep 2

    echo \"\"
    echo \"\$ kin impact handleRequest\"
    sleep 0.5
    \$KIN impact handleRequest
    sleep 3
  '" "$cast"

  agg "${AGG_OPTS[@]}" "$cast" "$OUT_DIR/explore.gif"
  echo "Wrote $OUT_DIR/explore.gif"
}

# ---------------------------------------------------------------------------
# Demo: MCP Setup (npx auto-init)
# ---------------------------------------------------------------------------
record_mcp_setup() {
  local proj="$SANDBOX/mcp-project"
  create_sample_project "$proj"
  cd "$proj"

  local cast="$CAST_DIR/mcp-setup.cast"

  asciinema rec --overwrite --cols 90 --rows 28 --command "bash -c '
    set -e

    echo \"# Zero-config MCP setup for Claude Code, Codex, or Gemini CLI\"
    sleep 1.5

    echo \"\$ claude mcp add kin -- npx -y kin-mcp\"
    sleep 1
    echo \"Added stdio MCP server kin with command: npx -y kin-mcp\"
    echo \"\"
    sleep 1.5

    echo \"# That is it. The wrapper auto-downloads the Kin binary,\"
    echo \"# auto-initializes .kin/ if missing, and starts the MCP server.\"
    echo \"# Your assistant now has semantic code understanding.\"
    sleep 3
  '" "$cast"

  agg "${AGG_OPTS[@]}" "$cast" "$OUT_DIR/mcp-setup.gif"
  echo "Wrote $OUT_DIR/mcp-setup.gif"
}

# ---------------------------------------------------------------------------
# Demo: Full workflow (hero GIF)
# ---------------------------------------------------------------------------
record_full() {
  local proj="$SANDBOX/full-demo"
  create_sample_project "$proj"
  cd "$proj"

  local cast="$CAST_DIR/full-demo.cast"

  asciinema rec --overwrite --cols 90 --rows 28 --command "bash -c '
    set -e
    KIN=\"$KIN\"

    echo \"# Kin: semantic system of record for software\"
    sleep 2

    echo \"\$ kin init .\"
    sleep 0.5
    \$KIN init .
    sleep 1

    echo \"\"
    echo \"\$ kin git import .\"
    sleep 0.5
    \$KIN git import .
    sleep 1

    echo \"\"
    echo \"\$ kin commit -m \\\"materialize semantic state\\\"\"
    sleep 0.5
    \$KIN commit -m \"materialize semantic state\"
    sleep 1.5

    echo \"\"
    echo \"\$ kin status\"
    sleep 0.5
    \$KIN status
    sleep 1.5

    echo \"\"
    echo \"\$ kin overview\"
    sleep 0.5
    \$KIN overview
    sleep 2

    echo \"\"
    echo \"\$ kin trace handleRequest\"
    sleep 0.5
    \$KIN trace handleRequest
    sleep 2

    echo \"\"
    echo \"\$ kin trace parseUrl\"
    sleep 0.5
    \$KIN trace parseUrl
    sleep 2

    echo \"\"
    echo \"\$ kin impact handleRequest\"
    sleep 0.5
    \$KIN impact handleRequest
    sleep 3
  '" "$cast"

  agg "${AGG_OPTS[@]}" "$cast" "$OUT_DIR/full-demo.gif"
  echo "Wrote $OUT_DIR/full-demo.gif"
}

record_git_vs_kin_kin() {
  record_git_vs_kin_repo \
    "git-vs-kin-kin" \
    "kin" \
    "$WORKSPACE_ROOT/kin" \
    'git grep -n "fn derive_target_dir" -- crates/kin-cli/src/commands/clone.rs' \
    'git grep -n "derive_target_dir(" -- crates | sed -n "1,20p"' \
    "derive_target_dir" \
    "derive_target_dir"
}

record_git_vs_kin_kin_db() {
  record_git_vs_kin_repo \
    "git-vs-kin-kin-db" \
    "kin-db" \
    "$WORKSPACE_ROOT/kin-db" \
    'git grep -n "fn merge_hot_into_cold" -- crates/kin-db/src/storage/tiered.rs' \
    'git grep -n "merge_hot_into_cold(" -- . | sed -n "1,20p"' \
    "merge_hot_into_cold" \
    "merge_hot_into_cold"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "${1:-all}" in
  git-interop) record_git_interop ;;
  explore)     record_explore ;;
  mcp-setup)   record_mcp_setup ;;
  full)        record_full ;;
  git-vs-kin-kin)    record_git_vs_kin_kin ;;
  git-vs-kin-kin-db) record_git_vs_kin_kin_db ;;
  git-vs-kin-all)
    record_git_vs_kin_kin
    record_git_vs_kin_kin_db
    ;;
  all)
    record_git_interop
    record_explore
    record_mcp_setup
    record_full
    record_git_vs_kin_kin
    record_git_vs_kin_kin_db
    ;;
  *)
    echo "Usage: $0 {all|git-interop|explore|mcp-setup|full|git-vs-kin-kin|git-vs-kin-kin-db|git-vs-kin-all}"
    exit 1
    ;;
esac

echo "All demos written to $OUT_DIR/"
