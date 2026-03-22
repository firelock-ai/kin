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

KIN="${KIN_BINARY:-kin}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
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

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "${1:-all}" in
  git-interop) record_git_interop ;;
  explore)     record_explore ;;
  mcp-setup)   record_mcp_setup ;;
  full)        record_full ;;
  all)
    record_git_interop
    record_explore
    record_mcp_setup
    record_full
    ;;
  *)
    echo "Usage: $0 {all|git-interop|explore|mcp-setup|full}"
    exit 1
    ;;
esac

echo "All demos written to $OUT_DIR/"
