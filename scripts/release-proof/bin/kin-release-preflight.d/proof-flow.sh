#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# One leg of the local release preflight: kin's Install Proof, run against a
# release-shaped archive on this machine. The step bodies are the workflow's own
# (kin/.github/workflows/install-proof.yml), in the workflow's order, under the
# runner contract the proof depends on (RUNNER_OS/ARCH/TEMP, GITHUB_ENV/PATH,
# an ambient PSModulePath, a fresh HOME). The publish-fetch surface is the one
# thing not exercised: nothing here downloads from get.kinlab.dev, verifies an
# attestation, or binds a tag. That is why the result is DEV-LOCAL and never
# citable.
#
# Runs on the host (macOS or Linux) and unchanged inside a Linux container. The
# driver is bin/kin-release-preflight; this file is not meant to be run by hand.
#
# Contract (environment):
#   PF_ROOT             leg root (created); HOME, KIN_HOME, temp, probe live under it
#   PF_ARCHIVE          the release-shaped kin-<os>-<arch>.tar.gz to install
#   PF_TOOLS            dir holding install.sh, validate.mjs and, when present,
#                       check-glibc-floor.mjs and kin-magic-repro
#   PF_LEG              leg name for the result
#   PF_RUNNER_OS        macOS | Linux         PF_RUNNER_ARCH  ARM64 | X64
#   PF_SETUP_SHELL      zsh | bash            (what kin setup is told)
#   PF_EXPECTED_COMMIT  40-hex the binaries must report (may be empty)
#   PF_EXPECTED_LOCK_SHA sha256 of that commit's Cargo.lock (may be empty)
#   PF_ALLOW_DIRTY      1 waives the clean-source assertions
#   PF_HF_HOME          Hugging Face cache the embedder may use (persisted)
#   PF_EMBED_SECONDS    kin embed --max-seconds (default 300, the workflow's)
#   PF_EMBED_BACKEND    when set, exported as KIN_EMBED_BACKEND (cpu forces the CPU path)
#   PF_PYTHON           exact tomllib-capable Python executable (default python3)
#   PF_SETTLE_SECONDS   settle budget (default 180, the workflow's)
#   PF_QUIESCE_SECONDS  kin status --wait-quiesce (default 60, the workflow's)
#   PF_GLIBC_FLOOR      1 runs check-glibc-floor.mjs on kin-vfs and the shim
#   PF_MAGIC_REPRO      1 runs kin-magic-repro against the installed binaries
#   PF_EMULATED         1 marks a leg running under CPU emulation: the daemon-
#                       runtime probe steps are skipped because they are
#                       structurally unable to pass under an interpreter
#   PF_EXPORT_DIR       when set, logs/captures/result are copied here on exit
#   PF_HOST_APPS        comma list of clients this host detects by an installed
#                       application outside HOME (cursor, windsurf, antigravity),
#                       which no HOME isolation can hide from kin setup
#
# Exit status: 0 leg PASS, 1 leg FAIL, 2 leg UNREADABLE (nothing failed but
# something could not be judged), 3 the flow itself could not start.
set -uo pipefail

: "${PF_ROOT:?PF_ROOT is required}"
: "${PF_ARCHIVE:?PF_ARCHIVE is required}"
: "${PF_TOOLS:?PF_TOOLS is required}"
PF_LEG="${PF_LEG:-leg}"
PF_RUNNER_OS="${PF_RUNNER_OS:-}"
PF_RUNNER_ARCH="${PF_RUNNER_ARCH:-}"
PF_SETUP_SHELL="${PF_SETUP_SHELL:-}"
PF_EXPECTED_COMMIT="${PF_EXPECTED_COMMIT:-}"
PF_EXPECTED_LOCK_SHA="${PF_EXPECTED_LOCK_SHA:-}"
PF_ALLOW_DIRTY="${PF_ALLOW_DIRTY:-0}"
PF_HF_HOME="${PF_HF_HOME:-}"
PF_EMBED_SECONDS="${PF_EMBED_SECONDS:-300}"
PF_EMBED_BACKEND="${PF_EMBED_BACKEND:-}"
PF_PYTHON="${PF_PYTHON:-python3}"
PF_SETTLE_SECONDS="${PF_SETTLE_SECONDS:-180}"
PF_QUIESCE_SECONDS="${PF_QUIESCE_SECONDS:-60}"
PF_GLIBC_FLOOR="${PF_GLIBC_FLOOR:-0}"
PF_MAGIC_REPRO="${PF_MAGIC_REPRO:-0}"
PF_EMULATED="${PF_EMULATED:-0}"
PF_EXPORT_DIR="${PF_EXPORT_DIR:-}"
PF_HOST_APPS="${PF_HOST_APPS:-}"
if [ -z "$PF_HOST_APPS" ] && [ -d /Applications ]; then
  apps=""
  [ -e "/Applications/Cursor.app" ] && apps="$apps,cursor"
  [ -e "/Applications/Windsurf.app" ] && apps="$apps,windsurf"
  { [ -e "/Applications/Antigravity.app" ] || [ -e "/Applications/Antigravity IDE.app" ]; } && apps="$apps,antigravity"
  PF_HOST_APPS="${apps#,}"
fi

if [ -z "$PF_RUNNER_OS" ]; then
  case "$(uname -s)" in Darwin) PF_RUNNER_OS=macOS ;; Linux) PF_RUNNER_OS=Linux ;; *) PF_RUNNER_OS="$(uname -s)" ;; esac
fi
if [ -z "$PF_RUNNER_ARCH" ]; then
  case "$(uname -m)" in arm64|aarch64) PF_RUNNER_ARCH=ARM64 ;; x86_64|amd64) PF_RUNNER_ARCH=X64 ;; *) PF_RUNNER_ARCH="$(uname -m)" ;; esac
fi
if [ -z "$PF_SETUP_SHELL" ]; then
  case "$PF_RUNNER_OS" in macOS) PF_SETUP_SHELL=zsh ;; *) PF_SETUP_SHELL=bash ;; esac
fi

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }
say() { printf '[%s] proof-flow(%s): %s\n' "$(ts)" "$PF_LEG" "$*"; }

for tool in node git tar; do
  command -v "$tool" >/dev/null 2>&1 || { say "REFUSED: $tool is not on PATH"; exit 3; }
done
[ -x "$PF_PYTHON" ] || command -v "$PF_PYTHON" >/dev/null 2>&1 || {
  say "REFUSED: configured Python is not executable: $PF_PYTHON"; exit 3;
}
"$PF_PYTHON" -c 'import tomllib' >/dev/null 2>&1 || {
  say "REFUSED: configured Python cannot import tomllib: $PF_PYTHON"; exit 3;
}
[ -f "$PF_ARCHIVE" ] || { say "REFUSED: archive not found: $PF_ARCHIVE"; exit 3; }
[ -f "$PF_TOOLS/install.sh" ] || { say "REFUSED: $PF_TOOLS/install.sh missing"; exit 3; }
[ -f "$PF_TOOLS/validate.mjs" ] || { say "REFUSED: $PF_TOOLS/validate.mjs missing"; exit 3; }

mkdir -p "$PF_ROOT" || exit 3
PF_ROOT="$(cd "$PF_ROOT" && pwd -P)"
LOGS="$PF_ROOT/logs"
export HOME="$PF_ROOT/home"
export RUNNER_TEMP="$PF_ROOT/temp"
WORKSPACE="$PF_ROOT/w"
PROBE="$WORKSPACE/kin-install-proof"
CAPTURES="$RUNNER_TEMP/kin-proof-captures"
mkdir -p "$LOGS" "$HOME" "$RUNNER_TEMP" "$WORKSPACE" "$CAPTURES" || exit 3

# The runner contract the workflow's step bodies rely on. PSModulePath is set
# the way a hosted image that ships PowerShell exports it into every Unix step;
# a shell-detection defect once hid behind exactly that marker, so the leg
# reproduces it rather than running cleaner than CI. Steps that unset it do so
# themselves, per step, as the workflow does.
export CI=true
export GITHUB_ACTIONS=true
export RUNNER_OS="$PF_RUNNER_OS"
export RUNNER_ARCH="$PF_RUNNER_ARCH"
export GITHUB_WORKSPACE="$WORKSPACE"
export GITHUB_ENV="$PF_ROOT/github_env"
export GITHUB_PATH="$PF_ROOT/github_path"
: > "$GITHUB_ENV"; : > "$GITHUB_PATH"
case "$PF_RUNNER_OS" in
  macOS) export PSModulePath="$HOME/.local/share/powershell/Modules:/usr/local/share/powershell/Modules:/usr/local/microsoft/powershell/7/Modules" ;;
  *)     export PSModulePath="/home/runner/.local/share/powershell/Modules:/usr/local/share/powershell/Modules:/opt/microsoft/powershell/7/Modules" ;;
esac
export PROOF_SHELL="$PF_SETUP_SHELL"
if [ -n "$PF_HF_HOME" ]; then
  mkdir -p "$PF_HF_HOME" || exit 3
  export HF_HOME="$PF_HF_HOME"
fi
# Nothing from the operator's shell may leak into the flow: no daemon
# coordinates, no VFS interposition, no KIN_HOME pin pointing elsewhere.
unset KIN_HOME KIN_DIR KIN_MANAGED_BIN KIN_NO_PROVISION KIN_LAUNCHER_ADOPT KIN_MCP_REPO
unset KIN_SESSION KIN_SESSION_ID KIN_SESSION_DIR KIN_DAEMON_URL KIN_DAEMON_AUTH_TOKEN
unset KIN_REPO_ID KIN_REPO_IDS KIN_PRIMARY_REPO_ID KIN_DAEMON_BIN KIN_DAEMON_AUTO_EMBED
unset KIN_VFS_DISABLE KIN_NO_VFS KIN_VFS_WORKSPACE KIN_VFS_WORKSPACE_ALIASES KIN_VFS_SOCK KIN_VFS_PIPE
unset KIN_VFS_CANARY KIN_VFS_INTERPOSE_ACTIVE KIN_VFS_LAST_DIR _KIN_VFS_LAST_DIR
unset KIN_SOURCE_ROOT KIN_ORIGINAL_PATH KIN_DISCOVERY_MODE KIN_CONTENT_MODE
unset DYLD_INSERT_LIBRARIES LD_PRELOAD GIT_CONFIG_GLOBAL GIT_CONFIG_SYSTEM XDG_CONFIG_HOME
if [ -n "$PF_EMBED_BACKEND" ]; then
  # The override is announced by kin as a WARN on stderr at every start, and the
  # workflow captures `kin status --json` with 2>&1, so the announcement would
  # land inside a JSON capture and read as an unparsable status. The override is
  # this leg's own doing, so its announcement is turned off with it.
  export KIN_EMBED_BACKEND="$PF_EMBED_BACKEND"
  export KIN_ENV_VALIDATION=off
fi
# No other Kin install may answer to `kin` before the one this leg installs.
PATH="$(printf '%s' "$PATH" | tr ':' '\n' | command grep -v -e '/\.kin/bin$' -e '^$' | paste -sd: -)"
export PATH

# --------------------------------------------------------------- bookkeeping
STEP_N=0
STEPS_TSV="$PF_ROOT/steps.tsv"
: > "$STEPS_TSV"
STOP=0
sha256_of() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else sha256sum "$1" | cut -d' ' -f1; fi
}
apply_runner_files() {
  # The Actions contract: lines appended to GITHUB_PATH become PATH prefixes for
  # later steps, and KEY=VALUE lines in GITHUB_ENV become their environment.
  local line
  if [ -s "$GITHUB_PATH" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      case ":$PATH:" in *":$line:"*) ;; *) PATH="$line:$PATH" ;; esac
    done < "$GITHUB_PATH"
    export PATH
    : > "$GITHUB_PATH"
  fi
  if [ -s "$GITHUB_ENV" ]; then
    while IFS= read -r line; do
      case "$line" in
        [A-Za-z_]*=*) export "$line" ;;
      esac
    done < "$GITHUB_ENV"
    : > "$GITHUB_ENV"
  fi
}
run_step() { # <slug> <critical 0|1> <workdir> <function>
  local slug="$1" critical="$2" wd="$3" fn="$4" log rc t0 t1
  STEP_N=$((STEP_N + 1))
  log="$LOGS/$(printf '%02d' "$STEP_N")-$slug.log"
  if [ "$STOP" = 1 ]; then
    printf 'not run: an earlier critical step failed\n' > "$log"
    printf '%s\t%s\t%s\t%s\n' "$slug" "skipped" "0" "$log" >> "$STEPS_TSV"
    say "step $slug: skipped (earlier critical step failed)"
    return 0
  fi
  say "step $slug"
  t0=$(date +%s)
  ( set -euo pipefail; cd "$wd" && "$fn" ) > "$log" 2>&1
  rc=$?
  t1=$(date +%s)
  apply_runner_files
  printf '%s\t%s\t%s\t%s\n' "$slug" "$rc" "$((t1 - t0))" "$log" >> "$STEPS_TSV"
  case "$rc" in
    0)  say "step $slug: ok ($((t1 - t0))s)" ;;
    99) say "step $slug: UNREADABLE ($((t1 - t0))s)"; tail -n 6 "$log" | sed 's/^/      /' ;;
    *)  say "step $slug: FAIL rc=$rc ($((t1 - t0))s)"; tail -n 12 "$log" | sed 's/^/      /'
        [ "$critical" = 1 ] && STOP=1 ;;
  esac
  return 0
}

# ------------------------------------------------------------------- cleanup
stop_daemons() {
  # kin daemon stop --all skips daemons whose home it cannot see, so pid files
  # and a path-anchored pgrep close the gap. Everything this leg started lives
  # under PF_ROOT, which is what makes the pgrep safe.
  local pid pidfile
  if [ -d "$PROBE" ] && [ -x "$HOME/.kin/bin/kin" ]; then
    ( cd "$PROBE" && "$HOME/.kin/bin/kin" daemon stop --all --json ) >> "$LOGS/daemon-stop.log" 2>&1 || true
  fi
  # Only a path that is unmistakably this leg's may anchor a kill sweep.
  case "/$PF_ROOT/" in
    */kpf/*|*/preflight/*)
      if command -v pgrep >/dev/null 2>&1; then
        while IFS= read -r pid; do
          [ -n "$pid" ] || continue
          [ "$pid" = "$$" ] && continue
          kill "$pid" 2>/dev/null || true
        done < <(pgrep -f -- "$PF_ROOT/" 2>/dev/null || true)
      fi
      ;;
  esac
  for pidfile in "$PROBE"/.kin/daemon.pid "$PF_ROOT"/repro/*/.kin/daemon.pid; do
    [ -f "$pidfile" ] || continue
    pid="$(tr -d '[:space:]' < "$pidfile" 2>/dev/null)"
    case "$pid" in ''|*[!0-9]*) continue ;; esac
    kill "$pid" 2>/dev/null || true
  done
}
snapshot_captures() {
  # The captures are the evidence the assertions were read from; keep a copy
  # beside the logs so the installed tree and probe repo can be discarded.
  if [ -d "$CAPTURES" ]; then
    mkdir -p "$PF_ROOT/captures"
    cp -R "$CAPTURES"/. "$PF_ROOT/captures/" 2>/dev/null || true
  fi
  if [ -f "$PROBE/.agents/mcp_config.json" ]; then
    mkdir -p "$PF_ROOT/captures/.agents"
    cp "$PROBE/.agents/mcp_config.json" "$PF_ROOT/captures/.agents/" 2>/dev/null || true
  fi
  return 0
}
export_results() {
  snapshot_captures
  [ -n "$PF_EXPORT_DIR" ] || return 0
  mkdir -p "$PF_EXPORT_DIR" || return 0
  cp -R "$LOGS" "$PF_EXPORT_DIR/" 2>/dev/null || true
  [ -d "$PF_ROOT/captures" ] && cp -R "$PF_ROOT/captures" "$PF_EXPORT_DIR/" 2>/dev/null
  local f
  for f in result.json steps.tsv validate.json repro.json repro.log archive.env; do
    [ -f "$PF_ROOT/$f" ] && cp "$PF_ROOT/$f" "$PF_EXPORT_DIR/" 2>/dev/null
  done
  return 0
}
FINAL_RC=3
on_exit() {
  stop_daemons
  export_results
  exit "$FINAL_RC"
}
trap on_exit EXIT
trap 'say "interrupted"; FINAL_RC=130; exit 130' INT TERM

# ------------------------------------------------------------- 1. the archive
ARCHIVE_NAME="$(basename "$PF_ARCHIVE")"
ARCHIVE_SHA=""
CONTENT_ROOT=""
ARTIFACT_NAME="${ARCHIVE_NAME%.tar.gz}"
case "$PF_RUNNER_OS" in
  Linux) SHIM_NAME="libkin_vfs_shim.so" ;;
  macOS) SHIM_NAME="libkin_vfs_shim.dylib" ;;
  *) SHIM_NAME="" ;;
esac
case "$PF_RUNNER_OS/$PF_RUNNER_ARCH" in
  Linux/X64) HOST_TARGET="linux-x86_64" ;;
  Linux/ARM64) HOST_TARGET="linux-aarch64" ;;
  macOS/X64) HOST_TARGET="macos-x86_64" ;;
  macOS/ARM64) HOST_TARGET="macos-aarch64" ;;
  *) HOST_TARGET="" ;;
esac
KIN_VERSION_LINE=""
DAEMON_VERSION_LINE=""
INSTALL_VERSION=""
STAMP_SHA=""

step_stage_archive() {
  ARCHIVE_SHA="$(sha256_of "$PF_ARCHIVE")"
  echo "archive: $PF_ARCHIVE"
  echo "archive sha256: $ARCHIVE_SHA"
  local extract="$PF_ROOT/archive"
  rm -rf "$extract"; mkdir -p "$extract"
  tar -xzf "$PF_ARCHIVE" -C "$extract"
  local root
  root="$(find "$extract" -mindepth 1 -maxdepth 1 -type d -name 'kin-*' | head -1)"
  [ -n "$root" ] || { echo "archive has no kin-* content root" >&2; exit 1; }
  CONTENT_ROOT="$root"
  echo "content root: $CONTENT_ROOT"
  for required in kin kin-daemon; do
    [ -f "$CONTENT_ROOT/$required" ] || { echo "$required missing from $ARCHIVE_NAME" >&2; exit 1; }
  done
  ls -la "$CONTENT_ROOT"
  # The archive under test must be the one this host can run: a Linux archive
  # reaches this script only inside a Linux container.
  case "$ARTIFACT_NAME" in
    kin-"$HOST_TARGET") ;;
    *) echo "archive $ARTIFACT_NAME is not the host target kin-$HOST_TARGET; this leg cannot execute it" >&2; exit 1 ;;
  esac
  chmod +x "$CONTENT_ROOT/kin" "$CONTENT_ROOT/kin-daemon"
  KIN_VERSION_LINE="$("$CONTENT_ROOT/kin" --version 2>&1 | tail -1)"
  DAEMON_VERSION_LINE="$("$CONTENT_ROOT/kin-daemon" --version 2>&1 | tail -1)"
  echo "kin --version: $KIN_VERSION_LINE"
  echo "kin-daemon --version: $DAEMON_VERSION_LINE"
  echo "kin sha256: $(sha256_of "$CONTENT_ROOT/kin")"
  echo "kin-daemon sha256: $(sha256_of "$CONTENT_ROOT/kin-daemon")"
  [ -f "$CONTENT_ROOT/kin-vfs" ] && echo "kin-vfs sha256: $(sha256_of "$CONTENT_ROOT/kin-vfs")"
  [ -n "$SHIM_NAME" ] && [ -f "$CONTENT_ROOT/$SHIM_NAME" ] && echo "$SHIM_NAME sha256: $(sha256_of "$CONTENT_ROOT/$SHIM_NAME")"
  local kin_sha daemon_sha
  kin_sha="$(printf '%s\n' "$KIN_VERSION_LINE" | sed -n 's/.*(\([0-9a-f]\{40\}\).*/\1/p')"
  daemon_sha="$(printf '%s\n' "$DAEMON_VERSION_LINE" | sed -n 's/.*(\([0-9a-f]\{40\}\).*/\1/p')"
  if [ -z "$kin_sha" ] || [ -z "$daemon_sha" ]; then
    echo "a version line carries no full build SHA: '$KIN_VERSION_LINE' / '$DAEMON_VERSION_LINE'" >&2; exit 1
  fi
  if [ "$kin_sha" != "$daemon_sha" ]; then
    echo "STAMP MISMATCH: kin names $kin_sha but kin-daemon names $daemon_sha; refusing to judge a mixed pair" >&2; exit 1
  fi
  STAMP_SHA="$kin_sha"
  INSTALL_VERSION="$(printf '%s\n' "$KIN_VERSION_LINE" | awk '{print $2}')"
  case "$INSTALL_VERSION" in [0-9]*) ;; *) echo "could not read a version out of '$KIN_VERSION_LINE'" >&2; exit 1 ;; esac
  # A file:// release mirror for the real installer: <base>/download/v<ver>/<archive>
  # and its shasum sidecar, exactly the layout get.kinlab.dev's installer fetches.
  local stub="$PF_ROOT/stub/download/v$INSTALL_VERSION"
  rm -rf "$PF_ROOT/stub"; mkdir -p "$stub"
  cp "$PF_ARCHIVE" "$stub/$ARCHIVE_NAME"
  printf '%s  %s\n' "$ARCHIVE_SHA" "$ARCHIVE_NAME" > "$stub/$ARCHIVE_NAME.sha256"
  echo "install mirror: $PF_ROOT/stub (version $INSTALL_VERSION)"
  {
    printf 'archive=%s\narchive_sha256=%s\ncontent_root=%s\nkin_version_line=%s\ndaemon_version_line=%s\nstamp_sha=%s\ninstall_version=%s\n' \
      "$PF_ARCHIVE" "$ARCHIVE_SHA" "$CONTENT_ROOT" "$KIN_VERSION_LINE" "$DAEMON_VERSION_LINE" "$STAMP_SHA" "$INSTALL_VERSION"
  } > "$PF_ROOT/archive.env"
}
run_step stage-archive 1 "$PF_ROOT" step_stage_archive
if [ -f "$PF_ROOT/archive.env" ]; then
  # Re-read the values the subshell resolved.
  ARCHIVE_SHA="$(sed -n 's/^archive_sha256=//p' "$PF_ROOT/archive.env")"
  CONTENT_ROOT="$(sed -n 's/^content_root=//p' "$PF_ROOT/archive.env")"
  KIN_VERSION_LINE="$(sed -n 's/^kin_version_line=//p' "$PF_ROOT/archive.env")"
  DAEMON_VERSION_LINE="$(sed -n 's/^daemon_version_line=//p' "$PF_ROOT/archive.env")"
  STAMP_SHA="$(sed -n 's/^stamp_sha=//p' "$PF_ROOT/archive.env")"
  INSTALL_VERSION="$(sed -n 's/^install_version=//p' "$PF_ROOT/archive.env")"
fi
if [ -z "$PF_EXPECTED_COMMIT" ] && [ -n "$STAMP_SHA" ]; then
  PF_EXPECTED_COMMIT="$STAMP_SHA"
  say "expected commit not supplied; using the binaries' own stamp $STAMP_SHA (both agree)"
fi

# --------------------------------------------------------- 2. glibc floor guard
step_glibc_floor() {
  if [ ! -f "$PF_TOOLS/check-glibc-floor.mjs" ]; then
    echo "check-glibc-floor.mjs is absent from the tools staged for this run (the kin ref under test predates the floor guard); the floor cannot be judged" >&2
    exit 99
  fi
  if [ ! -f "$CONTENT_ROOT/kin-vfs" ] || [ ! -f "$CONTENT_ROOT/$SHIM_NAME" ]; then
    echo "archive carries no kin-vfs or $SHIM_NAME to check" >&2
    exit 1
  fi
  node "$PF_TOOLS/check-glibc-floor.mjs" "$CONTENT_ROOT/kin-vfs" "$CONTENT_ROOT/$SHIM_NAME"
}
if [ "$PF_GLIBC_FLOOR" = 1 ] && [ "$PF_RUNNER_OS" = Linux ]; then
  run_step glibc-floor 0 "$PF_ROOT" step_glibc_floor
fi

# ------------------------------------------------------- 3. Public install (Unix)
step_install() {
  # The repo's own installer, pointed at the local mirror. KIN_NO_SETUP binds
  # to sh, as the workflow's comment insists, and the version is pinned so the
  # installer never asks GitHub which release is latest.
  export KIN_BASE_URL="file://$PF_ROOT/stub"
  export KIN_VERSION="$INSTALL_VERSION"
  export KIN_NO_SETUP=1
  sh "$PF_TOOLS/install.sh"
  echo "$HOME/.kin/bin" >> "$GITHUB_PATH"
}
run_step install 1 "$PF_ROOT" step_install

# ---------------------------------------- 4. Verify binaries installed + runnable
step_verify_binaries() {
  kin_version_line="$(kin --version)"
  daemon_version_line="$(kin-daemon --version)"
  printf '%s\n' "$kin_version_line" | tee kin-version.txt
  printf '%s\n' "$daemon_version_line" | tee kin-daemon-version.txt

  RUNNER_OS="$RUNNER_OS" node <<'NODE'
  const fs = require("fs");
  const os = require("os");
  const path = require("path");
  const { execFileSync } = require("child_process");

  const executable = process.env.RUNNER_OS === "Windows" ? "kin.exe" : "kin";
  const installedKin = path.join(os.homedir(), ".kin", "bin", executable);
  if (!fs.statSync(installedKin).isFile()) {
    throw new Error(`public installer did not create a regular Kin launcher at ${installedKin}`);
  }
  const directVersion = execFileSync(installedKin, ["--version"], { encoding: "utf8" }).trim();
  const pathVersion = fs.readFileSync("kin-version.txt", "utf8").trim();
  if (directVersion !== pathVersion) {
    throw new Error(`PATH selected ${pathVersion}, but the installed launcher reports ${directVersion}`);
  }
  fs.writeFileSync("installed-kin-command.txt", `${installedKin}\n`);
NODE

  # The tag/attestation/provenance half of this step is the publish-fetch
  # surface and is not run locally. What stands in for it: the expected version
  # is what the archive's own kin reports, and the expected commit and lock
  # sha256 were resolved by the driver from the source under test.
  installed_version="$(printf '%s\n' "$kin_version_line" | awk '{print $2}')"
  installed_daemon_version="$(printf '%s\n' "$daemon_version_line" | awk '{print $2}')"
  expected_version="$INSTALL_VERSION"
  if [ "$installed_version" != "$expected_version" ]; then
    echo "installed kin $installed_version, expected $expected_version" >&2
    exit 1
  fi
  if [ "$installed_daemon_version" != "$expected_version" ]; then
    echo "installed kin-daemon $installed_daemon_version, expected $expected_version" >&2
    exit 1
  fi
  printf '%s\n' "$expected_version" > expected-version.txt
  printf '%s\n' "$PF_EXPECTED_COMMIT" > expected-commit.txt
  printf '%s\n' "$PF_EXPECTED_LOCK_SHA" > expected-lock-sha.txt
  echo "expected commit: ${PF_EXPECTED_COMMIT:-<unresolved>}"
  echo "expected Cargo.lock sha256: ${PF_EXPECTED_LOCK_SHA:-<unresolved>}"
}
run_step verify-binaries 1 "$WORKSPACE" step_verify_binaries

# The installed kin-vfs and shim must be the archive's own bytes. This is the
# component half of the same workflow step, kept apart so a projection the
# installer refused to keep (a loader that cannot start it) reads as its own
# failure instead of stopping the leg before the flow has said anything else.
step_vfs_components() {
  CONTENT_ROOT="$CONTENT_ROOT" \
  INSTALLED_VFS="$HOME/.kin/bin/kin-vfs" \
  INSTALLED_SHIM="$HOME/.kin/lib/$SHIM_NAME" \
  SHIM_NAME="$SHIM_NAME" node <<'NODE'
  const crypto = require("crypto");
  const fs = require("fs");
  const path = require("path");

  const fail = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const sha256Bytes = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
  const components = [
    { name: "kin-vfs", installed: process.env.INSTALLED_VFS },
    { name: process.env.SHIM_NAME, installed: process.env.INSTALLED_SHIM },
  ].map((component) => {
    const archived = path.join(process.env.CONTENT_ROOT, component.name);
    fail(fs.existsSync(component.installed),
      `installed ${component.name} is missing at ${component.installed} (the installer did not keep it, or the archive never carried it)`);
    const installedBytes = fs.readFileSync(component.installed);
    const archivedBytes = fs.readFileSync(archived);
    fail(installedBytes.equals(archivedBytes),
      `installed ${component.name} differs from the attested public archive`);
    return { name: component.name, installed_path: component.installed, sha256: sha256Bytes(installedBytes) };
  });
  for (const component of components) console.log(`${component.name}: ${component.sha256} (${component.installed_path})`);
NODE
}
run_step vfs-components 0 "$WORKSPACE" step_vfs_components

# ------------------------------- 5. First-run repository, daemon, and setup proof
step_first_run() {
  case "$PROOF_SHELL" in
    bash)
      unset PSModulePath PSVersionTable
      export SHELL=/bin/bash
      printf 'SHELL=%s\n' "$SHELL" >> "$GITHUB_ENV"
      ;;
    zsh)
      unset PSModulePath PSVersionTable
      export SHELL=/bin/zsh
      printf 'SHELL=%s\n' "$SHELL" >> "$GITHUB_ENV"
      ;;
    powershell)
      ;;
    *) echo "unsupported install-proof setup shell: $PROOF_SHELL" >&2; exit 1 ;;
  esac

  mkdir -p kin-install-proof && cd kin-install-proof
  git init -q && git config user.email ci@firelock.ai && git config user.name ci
  printf 'def hello():\n    return 42\n' > probe.py
  git add -A && git commit -qm "probe"
  captures="$RUNNER_TEMP/kin-proof-captures"
  mkdir -p "$captures"
  init_status=0
  kin init > "$captures/kin-init.txt" 2>&1 || init_status=$?
  cat "$captures/kin-init.txt"
  if [ "$init_status" -ne 0 ]; then exit "$init_status"; fi
  kin status > "$captures/kin-status.txt" 2>&1
  cat "$captures/kin-status.txt"
  kin status --json > "$captures/kin-status.json" 2>&1
  cat "$captures/kin-status.json"
  kin bench-meta --json > "$captures/kin-build-meta.json"
  cat "$captures/kin-build-meta.json"
  proof_base_path="$PATH"
  fake_agent_bin="$RUNNER_TEMP/kin-proof-agent-bin"
  mkdir -p "$fake_agent_bin"
  for agent in claude cursor codex gemini windsurf agy; do
    if [ "$RUNNER_OS" = "Windows" ]; then
      cp "$(command -v kin)" "$fake_agent_bin/$agent.exe"
    else
      printf '#!/bin/sh\nexit 0\n' > "$fake_agent_bin/$agent"
      chmod +x "$fake_agent_bin/$agent"
    fi
  done
  export PATH="$fake_agent_bin:$proof_base_path"
  printf '%s\n' "$fake_agent_bin" >> "$GITHUB_PATH"

  antigravity_legacy="$HOME/.gemini/antigravity-ide/mcp_config.json"
  mkdir -p "$(dirname "$antigravity_legacy")"
  ANTIGRAVITY_LEGACY="$antigravity_legacy" node <<'NODE'
  const fs = require("fs");
  const path = require("path");
  const config = {
    userPolicy: "preserve",
    mcpServers: {
      kin: {
        command: "/stale/kin",
        args: ["mcp", "start"],
        cwd: fs.realpathSync(process.cwd()),
        env: { USER_POLICY: "preserve" },
      },
    },
  };
  fs.writeFileSync(process.env.ANTIGRAVITY_LEGACY, `${JSON.stringify(config, null, 2)}\n`);
NODE

  # Never pipe setup, for the reason `kin status` above is not piped. Setup
  # leaves a long-lived child behind in an admitted repository, and that child
  # inherits the write end of the pipe and holds it until it idles out, so
  # `tee` blocks reading a pipe nobody will close even though setup itself has
  # finished and printed everything it will print. The workflow's Windows leg
  # measured that wait twice on v0.5.49, at 1805 s and 1868 s, which is the
  # 1800 s daemon idle window plus startup and shutdown slack. Redirecting ends
  # the wait whatever the child turns out to be, because nothing waits on a
  # file. Setup's own exit status is captured rather than left to `set -e` so a
  # failure still reaches the log instead of aborting before the `cat`.
  setup_status=0
  kin setup --no-interactive --intent agent --shell "$PROOF_SHELL" \
    > "$captures/kin-setup.txt" 2>&1 || setup_status=$?
  cat "$captures/kin-setup.txt"
  if [ "$setup_status" -ne 0 ]; then exit "$setup_status"; fi

  CODEX_CONFIG="$HOME/.codex/config.toml" PROOF_CAPTURES="$captures" "$PF_PYTHON" - <<'PY'
import json
import os
import pathlib
import tomllib

config = pathlib.Path(os.environ["CODEX_CONFIG"])
with config.open("rb") as handle:
    entry = tomllib.load(handle)["mcp_servers"]["kin"]
pathlib.Path(os.environ["PROOF_CAPTURES"], "kin-codex-config.json").write_text(
    json.dumps({"mcpServers": {"kin": entry}}, indent=2) + "\n",
    encoding="utf-8",
)
PY

  primary_home="$HOME"
  claude_fallback_home="$RUNNER_TEMP/kin-proof-claude-fallback-home"
  claude_fallback_bin="$RUNNER_TEMP/kin-proof-claude-fallback-bin"
  mkdir -p "$claude_fallback_home/.claude"
  mkdir -p "$claude_fallback_bin"
  printf '{}\n' > "$claude_fallback_home/.claude/config.json"
  if [ "$RUNNER_OS" = "Windows" ]; then
    cp "$(command -v kin)" "$claude_fallback_bin/claude.exe"
  else
    printf '#!/bin/sh\nexit 0\n' > "$claude_fallback_bin/claude"
    chmod +x "$claude_fallback_bin/claude"
  fi
  claude_fallback_path="$claude_fallback_bin:$primary_home/.kin/bin:/usr/bin:/bin"
  # Unpiped for the same reason as the setup above, and it cost the same: this
  # second setup left the child that held the second pipe for its own full idle
  # window.
  fallback_setup_status=0
  HOME="$claude_fallback_home" USERPROFILE="$claude_fallback_home" \
  KIN_HOME="$primary_home/.kin" PATH="$claude_fallback_path" \
    kin setup --no-interactive --intent agent --shell "$PROOF_SHELL" \
    > "$captures/kin-claude-fallback-setup.txt" 2>&1 || fallback_setup_status=$?
  cat "$captures/kin-claude-fallback-setup.txt"
  if [ "$fallback_setup_status" -ne 0 ]; then exit "$fallback_setup_status"; fi
  if [ -e "$claude_fallback_home/.claude.json" ]; then
    echo "Claude fallback proof unexpectedly wrote the primary ~/.claude.json path" >&2
    exit 1
  fi
  cp "$claude_fallback_home/.claude/config.json" "$captures/kin-claude-fallback-config.json"
  HOME="$claude_fallback_home" USERPROFILE="$claude_fallback_home" \
  KIN_HOME="$primary_home/.kin" PATH="$claude_fallback_path" \
    kin setup status --json > "$captures/kin-claude-fallback-health.json"
  HOME="$claude_fallback_home" USERPROFILE="$claude_fallback_home" \
  KIN_HOME="$primary_home/.kin" PATH="$claude_fallback_path" \
    kin doctor --json > "$captures/kin-claude-fallback-doctor.json"
}
run_step first-run 1 "$WORKSPACE" step_first_run

# ------------------------------------------ 6. Graph query and MCP tool-call proof
step_graph_query_mcp() {
  captures="$RUNNER_TEMP/kin-proof-captures"
  mkdir -p "$captures"
  kin search hello --json > "$captures/kin-search.json"
  cat "$captures/kin-search.json"
  kin locate hello --json --explain --max-files 5 > "$captures/kin-locate.json"
  cat "$captures/kin-locate.json"

  daemon_port="$(tr -d '[:space:]' < .kin/daemon.port)"
  case "$daemon_port" in
    ''|*[!0-9]*)
      echo "installed daemon published an invalid port: $daemon_port" >&2
      exit 1
      ;;
  esac
  DAEMON_PORT="$daemon_port" node <<'NODE' > "$captures/kin-daemon-health.json"
  const http = require("http");
  const request = http.get(
    `http://127.0.0.1:${process.env.DAEMON_PORT}/health`,
    (response) => {
      const chunks = [];
      response.on("data", (chunk) => chunks.push(chunk));
      response.on("end", () => {
        const body = Buffer.concat(chunks);
        if (response.statusCode !== 200) {
          console.error(`daemon health returned HTTP ${response.statusCode}: ${body}`);
          process.exitCode = 1;
          return;
        }
        process.stdout.write(body);
      });
    }
  );
  request.setTimeout(30000, () => {
    request.destroy(new Error("daemon health request exceeded 30 seconds"));
  });
  request.on("error", (error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
NODE
  cat "$captures/kin-daemon-health.json"
  kin setup status --json | tee "$captures/kin-health.json"
  kin doctor --json | tee "$captures/kin-doctor.json"

  PROOF_CAPTURES="$captures" node <<'NODE'
  const fs = require("fs");
  const path = require("path");
  const { execFileSync, spawn, spawnSync } = require("child_process");

  const captures = process.env.PROOF_CAPTURES;

  const resolver = process.platform === "win32"
    ? ["where.exe", ["kin"]]
    : ["sh", ["-c", "command -v kin"]];
  const resolved = execFileSync(resolver[0], resolver[1], { encoding: "utf8" })
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find(Boolean);
  if (!resolved) throw new Error("could not resolve the installed Kin binary");
  const kinBinary = fs.realpathSync(resolved);
  const installDir = path.dirname(kinBinary);
  const normalizePath = (value) => {
    let normalized;
    try {
      normalized = fs.realpathSync(value);
    } catch {
      normalized = path.resolve(value);
    }
    return process.platform === "win32" ? normalized.toLowerCase() : normalized;
  };
  const proofEnv = { ...process.env };
  delete proofEnv.KIN_DAEMON_BIN;
  const pathKey = Object.keys(proofEnv).find((key) => key.toUpperCase() === "PATH") ?? "PATH";
  proofEnv[pathKey] = (proofEnv[pathKey] ?? "")
    .split(path.delimiter)
    .filter((entry) => entry && normalizePath(entry) !== normalizePath(installDir))
    .join(path.delimiter);
  if ((proofEnv[pathKey] ?? "")
    .split(path.delimiter)
    .some((entry) => entry && normalizePath(entry) === normalizePath(installDir))) {
    throw new Error("PATH-free MCP proof still contains the Kin install directory");
  }

  const stopDaemons = (phase) => {
    const stopped = spawnSync(
      kinBinary,
      ["daemon", "stop", "--all", "--json"],
      {
        cwd: process.cwd(),
        env: proofEnv,
        encoding: "utf8",
        timeout: 60_000,
      },
    );
    fs.appendFileSync(
      path.join(captures, "kin-mcp-daemon-stop.txt"),
      `${phase}: status=${stopped.status}\n${stopped.stdout ?? ""}${stopped.stderr ?? ""}\n`,
    );
    if (stopped.error || stopped.status !== 0) {
      throw new Error(
        `${phase}: failed to stop installed daemons: ${stopped.error ?? stopped.stderr}`,
      );
    }
  };

  stopDaemons("before MCP startup");

  const requests = [
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    { jsonrpc: "2.0", method: "notifications/initialized", params: {} },
    { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} },
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "semantic_search",
        arguments: { query: "hello", compact: true, limit: 5 },
      },
    },
  ];

  const configPath = path.join(process.cwd(), ".agents", "mcp_config.json");
  const entry = JSON.parse(fs.readFileSync(configPath, "utf8"))?.mcpServers?.kin;
  if (!entry || typeof entry.command !== "string" || !Array.isArray(entry.args) || typeof entry.cwd !== "string") {
    throw new Error(`${configPath}: captured MCP launch entry is missing`);
  }
  const stripVerbatim = (p) => (typeof p === "string" && p.startsWith("\\\\?\\") ? p.slice(4) : p);
  const child = spawn(entry.command, entry.args, {
    cwd: stripVerbatim(entry.cwd),
    env: { ...proofEnv, ...(entry.env ?? {}) },
    stdio: ["pipe", "pipe", "pipe"],
  });
  let stdout = "";
  let stderr = "";
  let lineBuffer = "";
  let revivalRequested = false;
  let settled = false;
  const finish = (error) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    fs.writeFileSync(path.join(captures, "kin-mcp-out.jsonl"), stdout);
    fs.writeFileSync(path.join(captures, "kin-mcp-err.txt"), stderr);
    if (error) {
      if (!child.killed) child.kill("SIGKILL");
      console.error(error);
      console.error(stderr);
      process.exit(1);
    }
  };
  const timer = setTimeout(() => {
    child.kill("SIGKILL");
    finish(new Error("installed MCP startup/revival proof did not exit within 120 seconds"));
  }, 120_000);
  const validateSearch = (message, label) => {
    if (!message?.result || message.error || message.result.isError === true) {
      throw new Error(`${label} failed: ${JSON.stringify(message ?? null)}`);
    }
    const rendered = JSON.stringify(message.result);
    if (!rendered.includes("hello") || !rendered.includes("probe.py")) {
      throw new Error(`${label} did not return the seeded hello entity`);
    }
  };
  child.stdout.on("data", (chunk) => {
    const text = chunk.toString();
    stdout += text;
    lineBuffer += text;
    const lines = lineBuffer.split(/\r?\n/);
    lineBuffer = lines.pop() ?? "";
    try {
      for (const line of lines) {
        if (!line.trim().startsWith("{")) continue;
        const message = JSON.parse(line);
        if (message.id === 3 && !revivalRequested) {
          validateSearch(message, "initial MCP semantic_search");
          stopDaemons("between MCP calls");
          revivalRequested = true;
          child.stdin.write(`${JSON.stringify({
            jsonrpc: "2.0",
            id: 4,
            method: "tools/call",
            params: {
              name: "semantic_search",
              arguments: { query: "hello", compact: true, limit: 5 },
            },
          })}\n`);
        } else if (message.id === 4) {
          validateSearch(message, "revived MCP semantic_search");
          child.stdin.end();
        }
      }
    } catch (error) {
      finish(error);
    }
  });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("error", finish);
  child.on("close", (code) => {
    if (code !== 0) {
      finish(new Error(`installed MCP server exited ${code}`));
      return;
    }
    try {
      const messages = stdout
        .split(/\r?\n/)
        .filter((line) => line.trim().startsWith("{"))
        .map((line) => JSON.parse(line));
      const byId = new Map(messages.filter((message) => message.id != null).map((message) => [message.id, message]));
      if (!byId.get(1)?.result) throw new Error("MCP initialize response missing");
      if (!JSON.stringify(byId.get(2)?.result ?? {}).includes("semantic_search")) {
        throw new Error("MCP tools/list omitted semantic_search");
      }
      validateSearch(byId.get(3), "initial MCP semantic_search");
      if (!revivalRequested) throw new Error("MCP daemon revival was not exercised");
      validateSearch(byId.get(4), "revived MCP semantic_search");
      finish();
    } catch (error) {
      finish(error);
    }
  });
  child.stdin.write(`${requests.map((request) => JSON.stringify(request)).join("\n")}\n`);
NODE
}
if [ "$PF_EMULATED" = 1 ]; then
  say "step graph-query-mcp: SKIPPED (emulated leg; daemon-runtime behavior binds on real runners)"
else
  run_step graph-query-mcp 0 "$PROBE" step_graph_query_mcp
fi

# ------------------------------------------------ 7. Graph-backed VFS projection proof
step_vfs_projection() {
  captures="$RUNNER_TEMP/kin-proof-captures"
  mkdir -p "$captures"
  probe_bin="$RUNNER_TEMP/vfs-open-probe"
  cc -O2 -Wall -Wextra -Werror -x c -o "$probe_bin" - <<'C'
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fputs("usage: vfs-open-probe <path>\n", stderr);
        return 2;
    }

    struct stat stdout_stat;
    if (fstat(STDOUT_FILENO, &stdout_stat) != 0) {
        perror("fstat(stdout)");
        return 3;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 4;
    }

    char buffer[4096];
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("read");
            close(fd);
            return 5;
        }
        for (ssize_t written = 0; written < count;) {
            ssize_t step = write(STDOUT_FILENO, buffer + written, (size_t)(count - written));
            if (step < 0 && errno == EINTR) {
                continue;
            }
            if (step <= 0) {
                perror("write");
                close(fd);
                return 6;
            }
            written += step;
        }
    }

    if (close(fd) != 0) {
        perror("close");
        return 7;
    }
    return 0;
}
C

  vfs_pid=""
  cleanup_vfs() {
    cleanup_status=0
    chmod u+rw probe.py || cleanup_status=1
    if [ -n "$vfs_pid" ]; then
      kin-vfs stop --workspace . >> "$captures/kin-vfs-daemon.log" 2>&1 || cleanup_status=1
      stopped=false
      for _ in $(seq 1 150); do
        process_state="$(ps -o stat= -p "$vfs_pid" 2>/dev/null || true)"
        process_state="$(printf '%s' "$process_state" | tr -d '[:space:]')"
        if [ -z "$process_state" ] || printf '%s\n' "$process_state" | grep -q 'Z'; then
          stopped=true
          break
        fi
        sleep 0.1
      done
      if [ "$stopped" != true ]; then
        cat "$captures/kin-vfs-daemon.log" >&2
        echo "installed kin-vfs daemon did not stop cleanly" >&2
        kill "$vfs_pid" 2>/dev/null || true
        sleep 1
        kill -9 "$vfs_pid" 2>/dev/null || true
        wait "$vfs_pid" 2>/dev/null || true
        cleanup_status=1
      else
        wait_status=0
        wait "$vfs_pid" || wait_status=$?
        case "$wait_status" in
          0|143) ;;
          *)
            echo "installed kin-vfs daemon exited with unexpected status $wait_status" >&2
            cleanup_status=1
            ;;
        esac
      fi
      vfs_pid=""
    fi
    if [ -S .kin/vfs.sock ]; then
      echo "installed kin-vfs socket remained after shutdown" >&2
      cleanup_status=1
    fi
    test -r probe.py || cleanup_status=1
    return "$cleanup_status"
  }
  on_vfs_signal() {
    signal_status="$1"
    trap - EXIT INT TERM
    cleanup_vfs || true
    exit "$signal_status"
  }
  trap 'cleanup_vfs || true' EXIT
  trap 'on_vfs_signal 130' INT
  trap 'on_vfs_signal 143' TERM

  kin-vfs start --workspace . > "$captures/kin-vfs-daemon.log" 2>&1 &
  vfs_pid=$!
  socket_ready=false
  for _ in $(seq 1 150); do
    if [ -S .kin/vfs.sock ]; then
      socket_ready=true
      break
    fi
    if ! kill -0 "$vfs_pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  if [ "$socket_ready" != true ]; then
    cat "$captures/kin-vfs-daemon.log" >&2
    echo "installed kin-vfs daemon did not bind its socket" >&2
    exit 1
  fi

  chmod 000 probe.py
  set +e
  "$probe_bin" "$PWD/probe.py" > "$captures/vfs-negative.txt" 2>&1
  negative_status=$?
  set -e
  if [ "$negative_status" -ne 4 ]; then
    cat "$captures/vfs-negative.txt" >&2
    echo "negative control failed before the expected raw-disk open denial (status $negative_status)" >&2
    exit 1
  fi
  if ! grep -Eq '^open: (Permission denied|Operation not permitted)$' "$captures/vfs-negative.txt"; then
    cat "$captures/vfs-negative.txt" >&2
    echo "negative control did not fail with the expected raw-disk permission error" >&2
    exit 1
  fi

  KIN_VFS_STRICT=1 kin-vfs exec --workspace . -- \
    "$probe_bin" "$PWD/probe.py" \
    > "$captures/vfs-graph-read.txt" 2> "$captures/vfs-graph-read.stderr.txt"
  printf 'def hello():\n    return 42\n' > "$captures/vfs-expected.txt"
  if ! cmp -s "$captures/vfs-expected.txt" "$captures/vfs-graph-read.txt"; then
    cmp -l "$captures/vfs-expected.txt" "$captures/vfs-graph-read.txt" >&2 || true
    echo "installed VFS did not return the exact graph-owned probe.py bytes" >&2
    exit 1
  fi

  trap - EXIT
  cleanup_vfs
  trap - INT TERM
}
if [ "$PF_EMULATED" = 1 ]; then
  say "step vfs-projection: SKIPPED (emulated leg; the projection is served by the kin-vfs daemon through the preload shim, daemon-runtime that binds on real runners)"
else
  run_step vfs-projection 0 "$PROBE" step_vfs_projection
fi

# ------------------------------------- 8. Unix embedding and semantic retrieval proof
step_embedding_retrieval() {
  case "$PROOF_SHELL" in
    bash)
      unset PSModulePath PSVersionTable
      export SHELL=/bin/bash
      ;;
    zsh)
      unset PSModulePath PSVersionTable
      export SHELL=/bin/zsh
      ;;
    *) echo "unsupported Unix install-proof shell: $PROOF_SHELL" >&2; exit 1 ;;
  esac
  captures="$RUNNER_TEMP/kin-proof-captures"
  mkdir -p "$captures"
  kin embed --max-seconds "$PF_EMBED_SECONDS" --json | tee "$captures/kin-embed.json"

  PROOF_CAPTURES="$captures" PF_SETTLE_SECONDS="$PF_SETTLE_SECONDS" node <<'NODE'
  const fs = require("fs");
  const path = require("path");
  const { execFileSync } = require("child_process");

  const captures = process.env.PROOF_CAPTURES;
  const budgetMs = Number(process.env.PF_SETTLE_SECONDS || 180) * 1000;
  const pollSeconds = 1;
  const log = [];
  const record = (line) => {
    log.push(line);
    console.log(line);
  };
  const flush = () => {
    fs.writeFileSync(
      path.join(captures, "kin-embedding-settle.txt"),
      `${log.join("\n")}\n`,
    );
  };

  const fingerprint = (status) => {
    const enrichment = status.semantic_enrichment ?? {};
    const coverage = status.embedding_coverage ?? {};
    return JSON.stringify({
      repository_generation: status.repository?.generation,
      workspace_generation: status.workspace?.generation,
      authority_generation: enrichment.authority_generation,
      enrichment_workspace_generation: enrichment.workspace_generation,
      entity_count: enrichment.entity_count,
      relation_count: enrichment.relation_count,
      semantic_change_count: enrichment.semantic_change_count,
      coverage_state: coverage.state,
      coverage_reason: coverage.reason,
      indexed: coverage.indexed,
      pending: coverage.pending,
      total: coverage.total,
    });
  };

  const deadline = Date.now() + budgetMs;
  let previous = null;
  let last = "no status read completed";
  let reads = 0;
  let settled = false;
  while (Date.now() < deadline) {
    reads += 1;
    let status;
    try {
      status = JSON.parse(
        execFileSync("kin", ["status", "--json"], { encoding: "utf8", timeout: 120_000 }),
      );
    } catch (error) {
      last = `kin status --json failed: ${error.message}`;
      previous = null;
      execFileSync("sleep", [String(pollSeconds)]);
      continue;
    }
    const current = fingerprint(status);
    last = current;
    const coverage = status.embedding_coverage ?? {};
    const drained =
      coverage.state === "observed" &&
      coverage.total > 0 &&
      coverage.pending === 0 &&
      coverage.indexed === coverage.total;
    if (drained && current === previous) {
      record(`settled after ${reads} reads: ${current}`);
      settled = true;
      break;
    }
    previous = current;
    execFileSync("sleep", [String(pollSeconds)]);
  }
  if (!settled) {
    record(`did not settle within ${budgetMs / 1000}s over ${reads} reads: ${last}`);
    flush();
    console.log(
      `::error::the store never settled: ${last}. ` +
      "Embedding coverage must reach observed with pending 0 and indexed equal to total, " +
      "and two consecutive reads must agree that nothing new was admitted between them.",
    );
    process.exit(1);
  }
  flush();
NODE

  settle_probe="$(kin status --help 2>&1 || true)"
  case "$settle_probe" in
    *--wait-quiesce*)
      printf 'bounded settle (kin status --wait-quiesce %s)\n' "$PF_QUIESCE_SECONDS" \
        | tee "$captures/kin-status-settle-mode.txt"
      kin status --json --wait-quiesce "$PF_QUIESCE_SECONDS" | tee "$captures/kin-embedded-status.json"
      ;;
    *)
      printf 'single sample (installed kin has no --wait-quiesce)\n' \
        | tee "$captures/kin-status-settle-mode.txt" >&2
      kin status --json | tee "$captures/kin-embedded-status.json"
      ;;
  esac
  kin setup status --json | tee "$captures/kin-embedded-health.json"
  kin doctor --json | tee "$captures/kin-embedded-doctor.json"
  kin search hello --semantic --json | tee "$captures/kin-semantic-search.json"
  kin locate hello --json --explain --max-files 5 | tee "$captures/kin-semantic-locate.json"
}
if [ "$PF_EMULATED" = 1 ]; then
  say "step embedding-retrieval: SKIPPED (emulated leg; daemon-runtime behavior binds on real runners)"
else
  run_step embedding-retrieval 0 "$PROBE" step_embedding_retrieval
fi

# ------------------------------- 9. Restore captured proof reports into the repo
step_restore_captures() {
  captures="$RUNNER_TEMP/kin-proof-captures"
  destination="$PWD/kin-install-proof"
  if [ ! -d "$captures" ]; then
    echo "no proof captures were taken"
    exit 0
  fi
  if [ ! -d "$destination" ]; then
    echo "no proof repository exists to restore captures into"
    exit 0
  fi
  restored=0
  while IFS= read -r capture; do
    [ -n "$capture" ] || continue
    cp "$captures/$capture" "$destination/$capture"
    restored=$((restored + 1))
  done < <(ls -1 "$captures")
  echo "restored $restored proof capture(s) into the proof repository"
}
# The restore and the validator run whatever happened before them, as the
# workflow's always() steps do; a leg that died early still hands over what it
# captured, and the assertions on missing captures read UNREADABLE beside the
# step that failed.
STOP_SAVED=$STOP
STOP=0
run_step restore-captures 0 "$WORKSPACE" step_restore_captures

# ------------------------------------------ 10. Validate installed capability proof
step_validate() {
  PF_CAPTURES="$PWD" \
  PF_HOME="$HOME" \
  PF_INSTALLED_KIN="$(cat ../installed-kin-command.txt 2>/dev/null || true)" \
  PF_EXPECTED_COMMIT="$PF_EXPECTED_COMMIT" \
  PF_EXPECTED_LOCK_SHA="$PF_EXPECTED_LOCK_SHA" \
  PF_RUNNER_OS="$RUNNER_OS" \
  PF_ALLOW_DIRTY="$PF_ALLOW_DIRTY" \
  PF_HOST_APPS="$PF_HOST_APPS" \
  PF_RESULT_JSON="$PF_ROOT/validate.json" \
    node "$PF_TOOLS/validate.mjs"
}
if [ -d "$PROBE" ]; then
  run_step validate 0 "$PROBE" step_validate
else
  say "validate: no probe repository exists; nothing to validate"
fi
STOP=$STOP_SAVED

# ------------------------------------------------------- 11. daemons off, then repro
say "stopping the leg's daemons"
stop_daemons

step_magic_repro() {
  if [ ! -f "$PF_TOOLS/kin-magic-repro" ]; then
    echo "kin-magic-repro is absent from the tools staged for this run" >&2
    exit 99
  fi
  [ -x "$PF_PYTHON" ] || command -v "$PF_PYTHON" >/dev/null 2>&1 || { echo "Python is required for kin-magic-repro" >&2; exit 99; }
  mkdir -p "$PF_ROOT/repro"
  # The suite mints kin commits in its fixtures, and kin refuses a commit with no
  # configured author rather than inventing one. A developer host carries a
  # global Git identity; this fresh HOME does not, so give it one here, after
  # the install proof ran without it exactly as a hosted runner does.
  git config --global user.name "kin-release-preflight"
  git config --global user.email "preflight@firelock.invalid"
  "$PF_PYTHON" "$PF_TOOLS/kin-magic-repro" \
    --kin "$HOME/.kin/bin/kin" --daemon "$HOME/.kin/bin/kin-daemon" \
    --workdir "$PF_ROOT/repro" --json "$PF_ROOT/repro.json" \
    --label "preflight-$PF_LEG" --verbose 2>&1 | tee "$PF_ROOT/repro.log"
  # The suite's own status is what decides; tee's is not.
  return "${PIPESTATUS[0]}"
}
if [ "$PF_MAGIC_REPRO" = 1 ] && [ -x "$HOME/.kin/bin/kin" ] && [ -x "$HOME/.kin/bin/kin-daemon" ]; then
  run_step magic-repro 0 "$PF_ROOT" step_magic_repro
  stop_daemons
fi

# ------------------------------------------------------------------ 12. result
PF_ROOT="$PF_ROOT" PF_LEG="$PF_LEG" STEPS_TSV="$STEPS_TSV" ARCHIVE_ENV="$PF_ROOT/archive.env" \
PF_RUNNER_OS="$PF_RUNNER_OS" PF_RUNNER_ARCH="$PF_RUNNER_ARCH" PF_EXPECTED_COMMIT="$PF_EXPECTED_COMMIT" \
PF_EXPECTED_LOCK_SHA="$PF_EXPECTED_LOCK_SHA" PF_ALLOW_DIRTY="$PF_ALLOW_DIRTY" \
node - <<'NODE'
const fs = require("fs");
const path = require("path");
const root = process.env.PF_ROOT;
const readMaybe = (file) => (fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "");
const lastLines = (text, n) => text.split(/\r?\n/).map((l) => l.trimEnd()).filter(Boolean).slice(-n);
const failingLine = (text) => {
  const lines = text.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const named = [...lines].reverse().find((l) => /^(Error:|::error::|STAMP MISMATCH|installed |negative control|kin init|the store never settled)/.test(l));
  return named ?? lines[lines.length - 1] ?? "";
};
const steps = readMaybe(process.env.STEPS_TSV).split("\n").filter(Boolean).map((line) => {
  const [slug, rc, seconds, log] = line.split("\t");
  const status = rc === "skipped" ? "SKIPPED" : rc === "0" ? "PASS" : rc === "99" ? "UNREADABLE" : "FAIL";
  const text = readMaybe(log);
  return {
    step: slug, status, exit: rc === "skipped" ? null : Number(rc), seconds: Number(seconds), log,
    failing: status === "PASS" || status === "SKIPPED" ? "" : failingLine(text),
    tail: status === "PASS" ? [] : lastLines(text, 8),
  };
});
const archiveEnv = Object.fromEntries(readMaybe(process.env.ARCHIVE_ENV).split("\n").filter(Boolean).map((l) => {
  const i = l.indexOf("="); return [l.slice(0, i), l.slice(i + 1)];
}));
let validate = null;
if (fs.existsSync(path.join(root, "validate.json"))) validate = JSON.parse(fs.readFileSync(path.join(root, "validate.json"), "utf8"));
let repro = null;
const reproStep = steps.find((s) => s.step === "magic-repro") ?? null;
if (reproStep && !fs.existsSync(path.join(root, "repro.json"))) {
  repro = { version: null, counts: { PASS: 0, FAIL: 0, UNREADABLE: 0 }, total: 0, checks: [],
    verdict: "UNREADABLE", note: `the suite wrote no repro.json (${reproStep.status}: ${reproStep.failing || "no detail"})` };
}
if (fs.existsSync(path.join(root, "repro.json"))) {
  const r = JSON.parse(fs.readFileSync(path.join(root, "repro.json"), "utf8"));
  const counts = { PASS: 0, FAIL: 0, UNREADABLE: 0 };
  for (const row of r.results ?? []) counts[row.status] = (counts[row.status] ?? 0) + 1;
  repro = {
    version: r.version, counts, total: (r.results ?? []).length,
    checks: (r.results ?? []).map((row) => ({ id: row.id, ticket: row.ticket, status: row.status, detail: row.detail })),
    verdict: counts.FAIL > 0 ? "FAIL" : counts.UNREADABLE > 0 || (r.results ?? []).length === 0 ? "UNREADABLE" : "PASS",
  };
}
// The leg verdict: the flow steps and the ported assertions. The magic repro
// is reported beside it, not inside it, so each answers for itself.
// The validate step's own exit is the tally of its assertions, which are
// listed individually below, so it is not counted a second time as a step.
const flowSteps = steps.filter((s) => s.step !== "magic-repro" && s.step !== "validate");
const failing = [];
for (const s of flowSteps) if (s.status === "FAIL") failing.push({ kind: "step", name: s.step, message: s.failing });
for (const a of validate?.assertions ?? []) if (a.status === "FAIL") failing.push({ kind: "assertion", name: a.name, message: a.message });
const unreadable = [];
for (const s of flowSteps) if (s.status === "UNREADABLE") unreadable.push({ kind: "step", name: s.step, message: s.failing });
for (const a of validate?.assertions ?? []) if (a.status === "UNREADABLE") unreadable.push({ kind: "assertion", name: a.name, message: a.message });
if (!validate && !flowSteps.some((s) => s.status === "FAIL")) unreadable.push({ kind: "assertion", name: "validate", message: "the validator never ran" });
const waived = (validate?.assertions ?? []).filter((a) => /^WAIVED/.test(a.message ?? "")).map((a) => ({ name: a.name, message: a.message }));
const verdict = failing.length > 0 ? "FAIL" : unreadable.length > 0 ? "UNREADABLE" : "PASS";
const glibc = steps.find((s) => s.step === "glibc-floor") ?? null;
const result = {
  schema: "kin.release-preflight.leg.v1",
  leg: process.env.PF_LEG,
  citable: false,
  runner_os: process.env.PF_RUNNER_OS,
  runner_arch: process.env.PF_RUNNER_ARCH,
  archive: { path: archiveEnv.archive ?? null, sha256: archiveEnv.archive_sha256 ?? null },
  binaries: {
    kin: { version_line: archiveEnv.kin_version_line ?? null },
    kin_daemon: { version_line: archiveEnv.daemon_version_line ?? null },
    stamp_sha: archiveEnv.stamp_sha ?? null,
    version: archiveEnv.install_version ?? null,
  },
  expected: { commit: process.env.PF_EXPECTED_COMMIT || null, lock_sha256: process.env.PF_EXPECTED_LOCK_SHA || null, allow_dirty: process.env.PF_ALLOW_DIRTY === "1" },
  steps,
  glibc_floor: glibc ? { status: glibc.status, detail: glibc.status === "PASS" ? lastLines(readMaybe(glibc.log), 2).join(" | ") : glibc.failing } : null,
  assertions: validate,
  magic_repro: repro,
  failing,
  unreadable,
  waived,
  verdict,
};
fs.writeFileSync(path.join(root, "result.json"), `${JSON.stringify(result, null, 2)}\n`);
console.log(`proof-flow(${result.leg}): verdict ${verdict}` +
  (failing.length ? `; first failure: ${failing[0].kind} ${failing[0].name}: ${failing[0].message}` : "") +
  (repro ? `; magic-repro ${repro.counts.PASS} pass, ${repro.counts.FAIL} fail, ${repro.counts.UNREADABLE} unreadable` : ""));
process.exit(verdict === "PASS" ? 0 : verdict === "FAIL" ? 1 : 2);
NODE
FINAL_RC=$?
exit "$FINAL_RC"
