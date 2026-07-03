// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use console::style;
use dialoguer::MultiSelect;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write as _};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Embedded shell hooks (from kin-vfs/shell/)
// ---------------------------------------------------------------------------

const ZSH_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs zsh integration — auto-activates the VFS overlay when entering
# a Kin workspace (any directory tree containing .kin/).
#
# Installed by: kin setup

_kin_vfs_find_workspace() {
    local dir="$1"
    while [[ "$dir" != "/" ]]; do
        if [[ -d "$dir/.kin" ]]; then
            printf '%s' "$dir"
            return 0
        fi
        dir="${dir:h}"
    done
    if [[ -d "/.kin" ]]; then
        printf '%s' "/"
        return 0
    fi
    return 1
}

_kin_vfs_shim_path() {
    local lib
    local kin_lib="$HOME/.kin/lib"
    case "$(uname -s)" in
        Darwin) lib="$kin_lib/libkin_vfs_shim.dylib" ;;
        Linux)  lib="$kin_lib/libkin_vfs_shim.so" ;;
        *)      lib="" ;;
    esac
    # Validate the shim exists AND is non-empty. A 0-byte dylib causes
    # macOS to kill every process before main() via DYLD_INSERT_LIBRARIES.
    [[ -f "$lib" && -s "$lib" ]] && printf '%s' "$lib"
}

_kin_vfs_clear_preload() {
    unset DYLD_INSERT_LIBRARIES LD_PRELOAD
}

_kin_vfs_refresh_preload() {
    local shim
    shim="$(_kin_vfs_shim_path)"
    if [[ -z "$shim" ]]; then
        _kin_vfs_clear_preload
        return
    fi
    case "$(uname -s)" in
        Darwin)
            export DYLD_INSERT_LIBRARIES="$shim"
            unset LD_PRELOAD
            ;;
        Linux)
            export LD_PRELOAD="$shim"
            unset DYLD_INSERT_LIBRARIES
            ;;
        *)
            _kin_vfs_clear_preload
            ;;
    esac
}

_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"
    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"
    if [[ ! -S "$sock" ]]; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" &>/dev/null &!
            local attempts=0
            while [[ ! -S "$sock" ]] && (( attempts < 10 )); do
                sleep 0.1
                (( attempts++ ))
            done
        fi
    fi
    # Auto-register workspace for NFS mount discovery
    if command -v kin-vfs >/dev/null 2>&1; then
        kin-vfs workspaces add --path "$ws" &>/dev/null 2>&1 || true
    fi
    _kin_vfs_refresh_preload
}

_kin_vfs_deactivate() {
    unset KIN_VFS_WORKSPACE KIN_VFS_SOCK
    _kin_vfs_clear_preload
}

_kin_vfs_chpwd() {
    local ws
    ws="$(_kin_vfs_find_workspace "$PWD")"
    if [[ -n "$ws" ]]; then
        if [[ "$ws" != "${KIN_VFS_WORKSPACE:-}" ]]; then
            _kin_vfs_activate "$ws"
        else
            _kin_vfs_refresh_preload
        fi
    else
        if [[ -n "${KIN_VFS_WORKSPACE:-}" ]]; then
            _kin_vfs_deactivate
        else
            _kin_vfs_clear_preload
        fi
    fi
}

# Kin-family control-plane binaries must not be injected with the shim.
# External tools (editors, builds) keep the shim via the global env var.
_kin_vfs_exec_without_preload() {
    DYLD_INSERT_LIBRARIES= LD_PRELOAD= command "$@"
}

kin() { _kin_vfs_exec_without_preload kin "$@"; }
kin-real() { _kin_vfs_exec_without_preload kin-real "$@"; }
kin-daemon() { _kin_vfs_exec_without_preload kin-daemon "$@"; }
kin-mcp() { _kin_vfs_exec_without_preload kin-mcp "$@"; }
kin-vfs() { _kin_vfs_exec_without_preload kin-vfs "$@"; }
kin-bench-prep() { _kin_vfs_exec_without_preload kin-bench-prep "$@"; }
kin-bench-eval() { _kin_vfs_exec_without_preload kin-bench-eval "$@"; }
kin-bench-target() { _kin_vfs_exec_without_preload kin-bench-target "$@"; }

autoload -Uz add-zsh-hook
add-zsh-hook chpwd _kin_vfs_chpwd
_kin_vfs_chpwd
"#;

const BASH_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs bash integration — auto-activates the VFS overlay when entering
# a Kin workspace (any directory tree containing .kin/).
#
# Installed by: kin setup

_kin_vfs_find_workspace() {
    local dir="$1"
    while [ "$dir" != "/" ]; do
        if [ -d "$dir/.kin" ]; then
            printf '%s' "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    if [ -d "/.kin" ]; then
        printf '%s' "/"
        return 0
    fi
    return 1
}

_kin_vfs_shim_path() {
    local lib
    local kin_lib="$HOME/.kin/lib"
    case "$(uname -s)" in
        Darwin) lib="$kin_lib/libkin_vfs_shim.dylib" ;;
        Linux)  lib="$kin_lib/libkin_vfs_shim.so" ;;
        *)      lib="" ;;
    esac
    # -s checks non-empty: a 0-byte dylib kills all processes via DYLD.
    [ -f "$lib" ] && [ -s "$lib" ] && printf '%s' "$lib"
}

_kin_vfs_clear_preload() {
    unset DYLD_INSERT_LIBRARIES LD_PRELOAD
}

_kin_vfs_refresh_preload() {
    local shim
    shim="$(_kin_vfs_shim_path)"
    if [ -z "$shim" ]; then
        _kin_vfs_clear_preload
        return
    fi
    case "$(uname -s)" in
        Darwin)
            export DYLD_INSERT_LIBRARIES="$shim"
            unset LD_PRELOAD
            ;;
        Linux)
            export LD_PRELOAD="$shim"
            unset DYLD_INSERT_LIBRARIES
            ;;
        *)
            _kin_vfs_clear_preload
            ;;
    esac
}

_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"
    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"
    if [ ! -S "$sock" ]; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" >/dev/null 2>&1 &
            disown 2>/dev/null
            local attempts=0
            while [ ! -S "$sock" ] && [ "$attempts" -lt 10 ]; do
                sleep 0.1
                attempts=$((attempts + 1))
            done
        fi
    fi
    # Auto-register workspace for NFS mount discovery
    if command -v kin-vfs >/dev/null 2>&1; then
        kin-vfs workspaces add --path "$ws" &>/dev/null 2>&1 || true
    fi
    _kin_vfs_refresh_preload
}

_kin_vfs_deactivate() {
    unset KIN_VFS_WORKSPACE KIN_VFS_SOCK
    _kin_vfs_clear_preload
}

_kin_vfs_prompt_command() {
    if [ "$PWD" = "${_KIN_VFS_LAST_DIR:-}" ]; then return; fi
    _KIN_VFS_LAST_DIR="$PWD"
    local ws
    ws="$(_kin_vfs_find_workspace "$PWD")"
    if [ -n "$ws" ]; then
        if [ "$ws" != "${KIN_VFS_WORKSPACE:-}" ]; then
            _kin_vfs_activate "$ws"
        else
            _kin_vfs_refresh_preload
        fi
    else
        if [ -n "${KIN_VFS_WORKSPACE:-}" ]; then
            _kin_vfs_deactivate
        else
            _kin_vfs_clear_preload
        fi
    fi
}

# Kin-family control-plane binaries must not be injected with the shim.
# External tools (editors, builds) keep the shim via the global env var.
_kin_vfs_exec_without_preload() {
    DYLD_INSERT_LIBRARIES= LD_PRELOAD= command "$@"
}

kin() { _kin_vfs_exec_without_preload kin "$@"; }
kin-real() { _kin_vfs_exec_without_preload kin-real "$@"; }
kin-daemon() { _kin_vfs_exec_without_preload kin-daemon "$@"; }
kin-mcp() { _kin_vfs_exec_without_preload kin-mcp "$@"; }
kin-vfs() { _kin_vfs_exec_without_preload kin-vfs "$@"; }
kin-bench-prep() { _kin_vfs_exec_without_preload kin-bench-prep "$@"; }
kin-bench-eval() { _kin_vfs_exec_without_preload kin-bench-eval "$@"; }
kin-bench-target() { _kin_vfs_exec_without_preload kin-bench-target "$@"; }

if [ -z "$PROMPT_COMMAND" ]; then
    PROMPT_COMMAND="_kin_vfs_prompt_command"
else
    PROMPT_COMMAND="_kin_vfs_prompt_command;$PROMPT_COMMAND"
fi
_KIN_VFS_LAST_DIR=""
_kin_vfs_prompt_command
"#;

const POWERSHELL_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs shell integration for PowerShell
# Installed by: kin setup

$script:KinVfsActive = $false
$script:KinVfsWorkspace = ""

function Find-KinWorkspace {
    param([string]$StartDir)
    $dir = $StartDir
    while ($dir -and $dir -ne [System.IO.Path]::GetPathRoot($dir)) {
        if (Test-Path (Join-Path $dir ".kin")) { return $dir }
        $dir = Split-Path $dir -Parent
    }
    return $null
}

function Enable-KinVfs {
    param([string]$Workspace)
    $pipe = "\\.\pipe\kin-vfs-$([System.IO.Path]::GetFileName($Workspace))"
    $daemonCmd = Get-Command "kin-vfs" -ErrorAction SilentlyContinue
    if ($daemonCmd) {
        $pipeExists = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*kin-vfs*" }
        if (-not $pipeExists) {
            Start-Process -FilePath "kin-vfs" -ArgumentList "start", "--workspace", $Workspace -WindowStyle Hidden
            $retries = 0
            while ($retries -lt 10) {
                Start-Sleep -Milliseconds 50
                $pipeExists = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*kin-vfs*" }
                if ($pipeExists) { break }
                $retries++
            }
        }
    }
    $env:KIN_VFS_WORKSPACE = $Workspace
    $env:KIN_VFS_PIPE = $pipe
    $script:KinVfsActive = $true
    $script:KinVfsWorkspace = $Workspace
}

function Disable-KinVfs {
    Remove-Item Env:\KIN_VFS_WORKSPACE -ErrorAction SilentlyContinue
    Remove-Item Env:\KIN_VFS_PIPE -ErrorAction SilentlyContinue
    $script:KinVfsActive = $false
    $script:KinVfsWorkspace = ""
}

function Invoke-KinVfsLocationCheck {
    $ws = Find-KinWorkspace -StartDir $PWD.Path
    if ($ws) {
        if ($script:KinVfsWorkspace -ne $ws) { Enable-KinVfs -Workspace $ws }
    } else {
        if ($script:KinVfsActive) { Disable-KinVfs }
    }
}

if (-not (Get-Variable -Name KinVfsOriginalPrompt -Scope Script -ErrorAction SilentlyContinue)) {
    $script:KinVfsOriginalPrompt = $function:prompt
}
function prompt { Invoke-KinVfsLocationCheck; & $script:KinVfsOriginalPrompt }
Invoke-KinVfsLocationCheck
"#;

const FISH_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs shell integration for fish
# Installed by: kin setup

set -g _KIN_VFS_WORKSPACE ""

function _kin_vfs_find_workspace
    set -l dir $argv[1]
    while test "$dir" != "/"
        if test -d "$dir/.kin"
            echo $dir
            return 0
        end
        set dir (dirname $dir)
    end
    return 1
end

function _kin_vfs_activate
    set -l ws $argv[1]
    set -l sock "$ws/.kin/vfs.sock"
    set -gx KIN_VFS_WORKSPACE $ws
    set -gx KIN_VFS_SOCK $sock

    if not test -S $sock
        if command -sq kin-vfs
            kin-vfs start --workspace $ws &>/dev/null &
            disown
            set -l attempts 0
            while not test -S $sock; and test $attempts -lt 10
                sleep 0.1
                set attempts (math $attempts + 1)
            end
        end
    end

    if command -sq kin-vfs
        kin-vfs workspaces add --path $ws &>/dev/null 2>&1 &
        disown
    end

    set -l shim "$HOME/.kin/lib/libkin_vfs_shim"
    switch (uname -s)
        case Darwin
            set shim "$shim.dylib"
            # -s checks non-empty: a 0-byte dylib kills all processes via DYLD.
            if test -f $shim -a -s $shim
                set -gx DYLD_INSERT_LIBRARIES $shim
            end
        case Linux
            set shim "$shim.so"
            if test -f $shim -a -s $shim
                set -gx LD_PRELOAD $shim
            end
    end
end

function _kin_vfs_deactivate
    set -e KIN_VFS_WORKSPACE
    set -e KIN_VFS_SOCK
    set -e DYLD_INSERT_LIBRARIES
    set -e LD_PRELOAD
    set -g _KIN_VFS_WORKSPACE ""
end

# kin is a graph tool — never inject VFS shim into its process.
function kin --wraps=kin --description 'Run kin without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin $argv
end

function _kin_vfs_chpwd --on-variable PWD
    set -l ws (_kin_vfs_find_workspace $PWD)
    if test -n "$ws"
        if test "$_KIN_VFS_WORKSPACE" != "$ws"
            _kin_vfs_activate $ws
            set -g _KIN_VFS_WORKSPACE $ws
        end
    else
        if test -n "$_KIN_VFS_WORKSPACE"
            _kin_vfs_deactivate
        end
    end
end

# Run once on source
_kin_vfs_chpwd
"#;

// ---------------------------------------------------------------------------
// Wizard options (from CLI flags for non-interactive use)
// ---------------------------------------------------------------------------

pub struct WizardOptions {
    /// Deprecated — Kin is always native mode now. Kept for CLI compat.
    pub mode: Option<String>,
    pub shell: Option<String>,
    pub auto_daemon: bool,
    pub no_interactive: bool,
    /// First-run intent, when provided non-interactively (or to preselect the
    /// interactive menu): one of `local`, `agent`, `editor`, `hosted`,
    /// `advanced`. When absent, interactive runs ask and non-interactive runs
    /// default to `agent` (the smallest path to value).
    pub intent: Option<String>,
}

/// First-run intent — what the user wants out of Kin. Each intent maps to a
/// [`SetupPlan`] of concrete actions; the wizard asks for the intent rather
/// than a bag of independent toggles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupIntent {
    /// CLI development on this machine: shell hook + auto-daemon, no MCP config.
    LocalOnly,
    /// The agent wedge: write the agent-default MCP config to detected AI
    /// clients + auto-daemon. The smallest path to value.
    AgentOnly,
    /// Local-only plus a pointer to the kin-editor VS Code extension.
    Editor,
    /// Hosted / KinLab — not yet a first-run flow (honest gap).
    Hosted,
    /// Expose the granular toggles (shell, per-client MCP, daemon).
    Advanced,
}

impl SetupIntent {
    fn from_flag(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "local" | "local-only" | "cli" => Some(Self::LocalOnly),
            "agent" | "agent-only" | "mcp" => Some(Self::AgentOnly),
            "editor" | "vscode" => Some(Self::Editor),
            "hosted" | "kinlab" | "cloud" => Some(Self::Hosted),
            "advanced" | "manual" => Some(Self::Advanced),
            _ => None,
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::LocalOnly => "Local-only (CLI development)",
            Self::AgentOnly => "AI agents (the wedge)",
            Self::Editor => "Editor (VS Code + kin-editor)",
            Self::Hosted => "Hosted / KinLab (coming soon)",
            Self::Advanced => "Advanced / manual (all toggles)",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::LocalOnly => "shell integration + auto-daemon; no AI client config",
            Self::AgentOnly => "configure Kin's MCP server for detected AI clients + auto-daemon",
            Self::Editor => "local-only, plus how to install the kin-editor extension",
            Self::Hosted => "connect to a KinLab workspace (no first-run flow yet)",
            Self::Advanced => "choose shell, per-client MCP, and daemon options yourself",
        }
    }
}

/// The full setup model an intent maps to. Every interactive and
/// non-interactive path produces one of these and then applies it, so behaviour
/// stays identical regardless of how the answers were collected.
struct SetupPlan {
    install_shell_hook: bool,
    configure_mcp: bool,
    /// Which detected AI clients to configure (indices into
    /// [`detect_ai_assistants`]). Empty unless `configure_mcp` is true.
    mcp_assistant_indices: Vec<usize>,
    inject_discovery_reminders: bool,
    auto_daemon: bool,
    show_editor_hint: bool,
    show_hosted_hint: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .context("could not determine home directory")
}

pub(crate) fn kin_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".kin"))
}

pub(crate) fn shim_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkin_vfs_shim.dylib"
    } else if cfg!(target_os = "windows") {
        "kin_vfs_shim.dll"
    } else {
        "libkin_vfs_shim.so"
    }
}

/// True when `path` is a shim we can actually inject: it exists and is
/// non-empty. A 0-byte file — e.g. a shim an earlier self-copy truncated — is
/// not a usable source; returning it would let a repair re-copy the corruption.
fn is_usable_shim(path: &Path) -> bool {
    fs::metadata(path)
        .map(|meta| meta.is_file() && meta.len() > 0)
        .unwrap_or(false)
}

/// Whether two paths resolve to the same file on disk (after following symlinks
/// and normalizing `..`). Both must exist; a non-existent path is never "same".
fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// Outcome of a guarded shim copy.
#[derive(Debug, PartialEq, Eq)]
enum ShimCopy {
    /// Source and destination are the same file — nothing copied.
    Skipped,
    /// Source was copied to the destination.
    Copied,
}

/// Copy `src` to `dest`, skipping when they are the same file.
///
/// `fs::copy` truncates the destination before reading the source, so copying a
/// file onto itself zeroes it out — the root cause of the "0-byte shim" that
/// crashes every injected process. Both the setup flow and the doctor repair go
/// through this guard so neither can truncate the shim.
fn copy_shim(src: &Path, dest: &Path) -> Result<ShimCopy> {
    if same_file(src, dest) {
        return Ok(ShimCopy::Skipped);
    }
    fs::copy(src, dest).with_context(|| format!("failed to copy shim to {}", dest.display()))?;
    Ok(ShimCopy::Copied)
}

fn find_shim() -> Option<PathBuf> {
    let name = shim_filename();

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if is_usable_shim(&candidate) {
                return Some(candidate);
            }
            let lib_candidate = dir.join("../lib").join(name);
            if is_usable_shim(&lib_candidate) {
                return Some(lib_candidate);
            }
        }
    }

    if let Ok(cargo_home) = env::var("CARGO_HOME") {
        let candidate = PathBuf::from(&cargo_home).join("lib").join(name);
        if is_usable_shim(&candidate) {
            return Some(candidate);
        }
    }

    let cwd_candidate = PathBuf::from("target/release").join(name);
    if is_usable_shim(&cwd_candidate) {
        return Some(cwd_candidate);
    }

    let cwd_debug = PathBuf::from("target/debug").join(name);
    if is_usable_shim(&cwd_debug) {
        return Some(cwd_debug);
    }

    None
}

pub(crate) fn detect_shell() -> &'static str {
    if env::var("PSModulePath").is_ok() || env::var("PSVersionTable").is_ok() {
        return "powershell";
    }
    if let Ok(shell) = env::var("SHELL") {
        if shell.ends_with("/zsh") || shell.ends_with("/zsh-5") {
            return "zsh";
        }
        if shell.ends_with("/bash") {
            return "bash";
        }
        if shell.ends_with("/fish") {
            return "fish";
        }
    }
    "zsh"
}

pub(crate) fn shell_rc(shell: &str) -> Result<PathBuf> {
    let home = home_dir()?;
    match shell {
        "zsh" => Ok(home.join(".zshrc")),
        "bash" => Ok(home.join(".bashrc")),
        "fish" => Ok(home.join(".config/fish/config.fish")),
        "powershell" => {
            if let Ok(profile) = env::var("PROFILE") {
                Ok(PathBuf::from(profile))
            } else if cfg!(target_os = "windows") {
                Ok(home.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1"))
            } else {
                Ok(home.join(".config/powershell/Microsoft.PowerShell_profile.ps1"))
            }
        }
        _ => Ok(home.join(".zshrc")),
    }
}

pub(crate) fn hook_filename(shell: &str) -> &'static str {
    match shell {
        "bash" => "kin-vfs.bash",
        "fish" => "kin-vfs.fish",
        "powershell" => "kin-vfs.ps1",
        _ => "kin-vfs.zsh",
    }
}

fn hook_content(shell: &str) -> &'static str {
    match shell {
        "bash" => BASH_HOOK,
        "fish" => FISH_HOOK,
        "powershell" => POWERSHELL_HOOK,
        _ => ZSH_HOOK,
    }
}

pub(crate) fn check_binary_in_path(name: &str) -> Option<PathBuf> {
    which::which(name).ok()
}

fn is_tty() -> bool {
    io::stdin().is_terminal()
}

fn prompt_line(prompt: &str, default: &str, interactive: bool) -> String {
    if !interactive {
        return default.to_string();
    }
    print!("{prompt}");
    let _ = io::stdout().flush();
    let mut buf = String::new();
    if io::stdin().lock().read_line(&mut buf).is_ok() {
        let trimmed = buf.trim();
        if trimmed.is_empty() {
            default.to_string()
        } else {
            trimmed.to_string()
        }
    } else {
        default.to_string()
    }
}

fn prompt_yn(prompt: &str, default_yes: bool, interactive: bool) -> bool {
    if !interactive {
        return default_yes;
    }
    let hint = if default_yes { "[Y/n]" } else { "[y/N]" };
    let input = prompt_line(&format!("{prompt} {hint} "), "", interactive);
    match input.to_lowercase().as_str() {
        "y" | "yes" => true,
        "n" | "no" => false,
        _ => default_yes,
    }
}

// ---------------------------------------------------------------------------
// AI assistant MCP configuration
// ---------------------------------------------------------------------------

/// The MCP server entry we inject for Kin.
///
/// Prefers an absolute path to the `kin` binary (resolved from the current
/// executable) so the entry works in agent processes that do not inherit the
/// user's PATH.
///
/// The entry starts the MCP server in single-repo mode: `kin mcp start`
/// resolves the repo from the agent's working directory (or from
/// `KIN_DAEMON_URL` when a session launch pinned one), so each agent session
/// binds to the daemon of the repository it is actually working in.
fn kin_mcp_entry() -> serde_json::Value {
    // Try to resolve an absolute path from the running executable.  The
    // installed binary lives alongside the other kin-* binaries, so
    // current_exe() gives us the right directory.
    let command = if let Ok(exe) = env::current_exe() {
        // current_exe may be e.g. /Users/foo/.cargo/bin/kin — use it directly.
        exe.to_string_lossy().into_owned()
    } else {
        // Fallback: bare name relying on PATH (previous behaviour).
        "kin".to_string()
    };
    serde_json::json!({
        "command": command,
        "args": ["mcp", "start"],
        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    })
}

/// Describes an AI assistant we can auto-configure.
struct AiAssistant {
    name: &'static str,
    detected: bool,
    install_hint: &'static str,
}

// Assistant index constants — keep in sync with detect_ai_assistants() order.
const IDX_CLAUDE_CODE: usize = 0;
const IDX_CURSOR: usize = 1;
const IDX_CODEX: usize = 2;
const IDX_GEMINI: usize = 3;
const IDX_WINDSURF: usize = 4;

/// Detect installed AI assistants eligible for MCP auto-configuration.
///
/// Detection heuristics per client:
/// - Claude Code: `claude` binary on PATH
/// - Cursor: `cursor` binary on PATH, or `/Applications/Cursor.app`
/// - Codex CLI: `codex` binary on PATH
/// - Gemini CLI: `gemini` binary on PATH, or `~/.gemini` directory
/// - Windsurf: `windsurf` binary on PATH, or `/Applications/Windsurf.app`
fn detect_ai_assistants() -> Vec<AiAssistant> {
    let claude_detected = check_binary_in_path("claude").is_some();
    let cursor_detected = check_binary_in_path("cursor").is_some()
        || PathBuf::from("/Applications/Cursor.app").exists();
    let codex_detected = check_binary_in_path("codex").is_some();
    let gemini_detected = check_binary_in_path("gemini").is_some()
        || home_dir()
            .map(|h| h.join(".gemini").exists())
            .unwrap_or(false);
    let windsurf_detected = check_binary_in_path("windsurf").is_some()
        || PathBuf::from("/Applications/Windsurf.app").exists();

    vec![
        AiAssistant {
            name: "Claude Code",
            detected: claude_detected,
            install_hint: "install from claude.ai/download",
        },
        AiAssistant {
            name: "Cursor",
            detected: cursor_detected,
            install_hint: "install from cursor.com",
        },
        AiAssistant {
            name: "Codex CLI",
            detected: codex_detected,
            install_hint: "install from github.com/openai/codex",
        },
        AiAssistant {
            name: "Gemini CLI",
            detected: gemini_detected,
            install_hint: "install via: npm install -g @google/gemini-cli",
        },
        AiAssistant {
            name: "Windsurf",
            detected: windsurf_detected,
            install_hint: "install from windsurf.com",
        },
    ]
}

/// Merge the "kin" MCP server entry into an existing JSON config file.
/// Creates the file if it doesn't exist.
fn merge_mcp_config(path: &PathBuf) -> Result<()> {
    let mut root: serde_json::Value = if path.exists() {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        serde_json::from_str(&content).with_context(|| {
            format!(
                "existing file {} is not valid JSON — refusing to overwrite it. \
                 Fix or remove the file and try again.",
                path.display()
            )
        })?
    } else {
        serde_json::json!({})
    };

    // Ensure root is an object
    if !root.is_object() {
        root = serde_json::json!({});
    }

    // Ensure mcpServers key exists as an object
    if !root.get("mcpServers").is_some_and(|v| v.is_object()) {
        root["mcpServers"] = serde_json::json!({});
    }

    // Insert/overwrite the "kin" entry
    root["mcpServers"]["kin"] = kin_mcp_entry();

    // Write back with pretty formatting
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let formatted =
        serde_json::to_string_pretty(&root).context("failed to serialize MCP config")?;
    fs::write(path, formatted).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(())
}

/// Configure MCP for Claude Code.
fn configure_claude_code() -> Result<PathBuf> {
    let home = home_dir()?;

    // Prefer ~/.claude.json; also check ~/.claude/config.json
    let primary = home.join(".claude.json");
    let alt = home.join(".claude").join("config.json");

    let target = if alt.exists() && !primary.exists() {
        alt
    } else {
        primary
    };

    merge_mcp_config(&target)?;
    Ok(target)
}

/// Configure MCP for Cursor (global config).
fn configure_cursor() -> Result<PathBuf> {
    let home = home_dir()?;
    let target = home.join(".cursor").join("mcp.json");
    merge_mcp_config(&target)?;
    Ok(target)
}

/// Configure MCP for Codex CLI.
fn configure_codex() -> Result<PathBuf> {
    let home = home_dir()?;
    // Codex uses ~/.codex/mcp.json
    let target = home.join(".codex").join("mcp.json");
    merge_mcp_config(&target)?;
    Ok(target)
}

/// Configure MCP for Gemini CLI.
///
/// Gemini CLI persists MCP servers in `~/.gemini/settings.json` under the
/// top-level `mcpServers` key (same shape as other agents: `command` + `args`).
fn configure_gemini_cli() -> Result<PathBuf> {
    let home = home_dir()?;
    let target = home.join(".gemini").join("settings.json");
    merge_mcp_config(&target)?;
    Ok(target)
}

/// Configure MCP for Windsurf.
///
/// Windsurf reads its MCP server list from `~/.codeium/windsurf/mcp_config.json`.
fn configure_windsurf() -> Result<PathBuf> {
    let home = home_dir()?;
    let target = home
        .join(".codeium")
        .join("windsurf")
        .join("mcp_config.json");
    merge_mcp_config(&target)?;
    Ok(target)
}

// ---------------------------------------------------------------------------
// Discovery reminder injection
// ---------------------------------------------------------------------------

/// Kin-first discovery reminder appended to agent instruction files.
///
/// Tells the agent to lead with Kin's semantic tools (`semantic_locate`,
/// `get_context_pack`, `trace_data_flow`) instead of grep/read loops.
const KIN_DISCOVERY_REMINDER: &str = r#"
## Kin-first discovery (added by `kin setup`)

When exploring a Kin repository, always start with Kin's semantic MCP tools
before falling back to grep or raw file reads:

1. `semantic_locate`    — find symbols, functions, types by semantic meaning
2. `get_context_pack`  — get a structured context bundle for a file or symbol
3. `trace_data_flow`   — trace data lineage and cross-file dependencies

These tools operate on the graph-native substrate and return richer, more
accurate results than filesystem heuristics. Use them first.
"#;

/// Append the Kin-first discovery reminder to an agent instruction file
/// (e.g. `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`).
///
/// Idempotent: skips if the marker is already present.
fn inject_discovery_reminder(path: &PathBuf) -> Result<()> {
    const MARKER: &str = "## Kin-first discovery (added by `kin setup`)";

    let existing = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    if existing.contains(MARKER) {
        return Ok(());
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }

    let mut content = existing;
    if !content.ends_with('\n') && !content.is_empty() {
        content.push('\n');
    }
    content.push_str(KIN_DISCOVERY_REMINDER);

    fs::write(path, &content).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(())
}

/// Check if a given MCP config file already has the "kin" server entry.
fn has_kin_mcp_config(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    let Ok(root) = serde_json::from_str::<serde_json::Value>(&content) else {
        return false;
    };
    root.get("mcpServers").and_then(|s| s.get("kin")).is_some()
}

// ---------------------------------------------------------------------------
// Shell hook installation
// ---------------------------------------------------------------------------

/// The `source <hook>` line Kin adds to a shell rc file (`.` for PowerShell).
fn rc_source_line(shell_name: &str, hook_file: &Path) -> String {
    if shell_name == "powershell" {
        format!(". {}", hook_file.display())
    } else {
        format!("source {}", hook_file.display())
    }
}

/// The exact block Kin appends to a shell rc file (comment + source line). This
/// is the slice Kin owns; the install ledger fingerprints it so uninstall can
/// excise precisely it.
fn rc_integration_block(source_line: &str) -> String {
    format!("\n# kin-vfs shell integration\n{source_line}\n")
}

fn install_shell_hook(shell_name: &str) -> Result<(PathBuf, String)> {
    let kin_home = kin_dir()?;
    let shell_dir = kin_home.join("shell");
    let lib_dir = kin_home.join("lib");

    fs::create_dir_all(&shell_dir).context("failed to create ~/.kin/shell/")?;
    fs::create_dir_all(&lib_dir).context("failed to create ~/.kin/lib/")?;

    let hook_file = shell_dir.join(hook_filename(shell_name));
    fs::write(&hook_file, hook_content(shell_name))
        .with_context(|| format!("failed to write {}", hook_file.display()))?;
    println!("  Wrote shell hook: {}", hook_file.display());

    if let Some(shim_path) = find_shim() {
        let dest = lib_dir.join(shim_filename());
        // On the standard install layout the shim already lives at ~/.kin/lib
        // and `find_shim` resolves the source via ~/.kin/bin/../lib — i.e. the
        // source and destination are the SAME FILE. `copy_shim` no-ops that case
        // so the shim is never truncated onto itself.
        match copy_shim(&shim_path, &dest)? {
            ShimCopy::Skipped => {
                println!("  VFS shim already in place: {}", dest.display());
            }
            ShimCopy::Copied => {
                println!(
                    "  Copied VFS shim: {} -> {}",
                    shim_path.display(),
                    dest.display()
                );
            }
        }
    } else {
        println!("  VFS shim not found. Build it with:");
        println!("    cargo build --release -p kin-vfs-shim");
    }

    let source_line = rc_source_line(shell_name, &hook_file);

    let rc_path = shell_rc(shell_name)?;
    let already_installed = if rc_path.exists() {
        fs::read_to_string(&rc_path)
            .map(|c| c.contains("kin-vfs"))
            .unwrap_or(false)
    } else {
        false
    };

    if already_installed {
        println!(
            "  Shell rc already sources kin-vfs hook: {}",
            rc_path.display()
        );
    } else {
        let mut rc_content = if rc_path.exists() {
            fs::read_to_string(&rc_path)?
        } else {
            String::new()
        };
        if !rc_content.ends_with('\n') && !rc_content.is_empty() {
            rc_content.push('\n');
        }
        rc_content.push_str(&rc_integration_block(&source_line));
        fs::write(&rc_path, &rc_content)
            .with_context(|| format!("failed to update {}", rc_path.display()))?;
        println!("  Appended to {}", rc_path.display());
    }

    Ok((hook_file, source_line))
}

/// Reinstall the shell hook + rc source line for the detected shell.
///
/// Used by `kin doctor --fix` to repair the `shell_path` check. Returns the
/// hook file path it wrote.
pub(crate) fn reinstall_shell_hook() -> Result<PathBuf> {
    let shell_name = detect_shell();
    let (hook_file, _source_line) = install_shell_hook(shell_name)?;
    Ok(hook_file)
}

/// Re-source a usable VFS shim into `~/.kin/lib`.
///
/// Used by `kin doctor --fix` to repair the `vfs_projection` check when the
/// installed shim is missing or was truncated to 0 bytes. Returns the
/// destination path when a usable shim was installed, or `None` when no usable
/// source shim exists anywhere — in that case the bytes cannot be reconstructed
/// locally and the caller directs the user to reinstall.
pub(crate) fn reinstall_vfs_shim() -> Result<Option<PathBuf>> {
    let lib_dir = kin_dir()?.join("lib");
    fs::create_dir_all(&lib_dir).context("failed to create ~/.kin/lib/")?;
    let dest = lib_dir.join(shim_filename());

    // `find_shim` only returns non-empty candidates, so a truncated shim is
    // never re-selected as the source. `copy_shim` no-ops if the usable shim
    // already is the destination.
    let Some(shim_path) = find_shim() else {
        return Ok(None);
    };
    copy_shim(&shim_path, &dest)?;
    Ok(Some(dest))
}

/// Re-merge the kin MCP server entry (with the agent-default profile) into the
/// config files of every AI client that already has a config present.
///
/// Used by `kin doctor --fix` to repair `mcp_client_*` checks. Returns the
/// paths that were re-merged.
pub(crate) fn remerge_existing_mcp_configs() -> Vec<PathBuf> {
    let mut repaired = Vec::new();
    for (_id, _label, path) in crate::commands::health::mcp_client_config_paths() {
        if path.exists() && merge_mcp_config(&path).is_ok() {
            repaired.push(path);
        }
    }
    repaired
}

// ---------------------------------------------------------------------------
// Auto-daemon config
// ---------------------------------------------------------------------------

fn write_auto_daemon_config(enabled: bool) -> Result<()> {
    let kin_home = kin_dir()?;
    let config_dir = kin_home.join("config");
    fs::create_dir_all(&config_dir).context("failed to create ~/.kin/config/")?;
    let config_path = config_dir.join("setup.toml");
    let content = format!("# Generated by: kin setup\n[daemon]\nauto_start = {enabled}\n");
    fs::write(&config_path, content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `kin setup` — interactive wizard (or non-interactive with flags)
// ---------------------------------------------------------------------------

pub async fn run_wizard(opts: WizardOptions) -> Result<()> {
    let interactive = !opts.no_interactive && is_tty();

    println!();
    println!("Welcome to Kin setup. Let's get you to value in a few questions.");
    println!();

    let assistants = detect_ai_assistants();
    let intent = resolve_intent(&opts, interactive);

    println!();
    println!(
        "Plan: {} — {}",
        style(intent.title()).bold(),
        intent.description()
    );
    println!();

    let shell_name = opts.shell.as_deref().unwrap_or_else(|| detect_shell());
    let plan = build_plan(intent, &opts, &assistants, shell_name, interactive)?;

    let configured_assistants = apply_plan(&plan, &assistants, shell_name).await?;

    print_intent_followups(&plan);

    // The final checklist is the real first-run health engine — not a parallel
    // set of hardcoded probes. Every line below reflects probed state.
    println!();
    println!("=== Health checklist ===");
    println!();
    let report = crate::commands::health::run_health_checks().await;
    print_human_report(&report);

    print_next_steps(intent, plan.install_shell_hook, &configured_assistants);

    Ok(())
}

/// Decide the first-run intent: explicit flag, else interactive menu, else the
/// non-interactive default (`AgentOnly`, the smallest path to value).
fn resolve_intent(opts: &WizardOptions, interactive: bool) -> SetupIntent {
    if let Some(flag) = opts.intent.as_deref() {
        if let Some(intent) = SetupIntent::from_flag(flag) {
            return intent;
        }
        println!(
            "  {} unrecognized --intent '{}'; falling back to a prompt/default",
            style("!").yellow(),
            flag
        );
    }

    if !interactive {
        return SetupIntent::AgentOnly;
    }

    let intents = [
        SetupIntent::AgentOnly,
        SetupIntent::LocalOnly,
        SetupIntent::Editor,
        SetupIntent::Hosted,
        SetupIntent::Advanced,
    ];
    let items: Vec<String> = intents
        .iter()
        .map(|i| format!("{:<34} {}", i.title(), i.description()))
        .collect();

    println!("What do you want Kin for?");
    match dialoguer::Select::new().items(&items).default(0).interact() {
        Ok(idx) => intents[idx],
        Err(_) => SetupIntent::AgentOnly,
    }
}

/// Map an intent to the concrete [`SetupPlan`]. The Advanced intent re-exposes
/// the granular toggles; the rest apply opinionated, platform-safe defaults.
fn build_plan(
    intent: SetupIntent,
    opts: &WizardOptions,
    assistants: &[AiAssistant],
    shell_name: &str,
    interactive: bool,
) -> Result<SetupPlan> {
    let all_detected: Vec<usize> = assistants
        .iter()
        .enumerate()
        .filter(|(_, a)| a.detected)
        .map(|(i, _)| i)
        .collect();

    let plan = match intent {
        SetupIntent::LocalOnly => SetupPlan {
            install_shell_hook: true,
            configure_mcp: false,
            mcp_assistant_indices: Vec::new(),
            inject_discovery_reminders: false,
            auto_daemon: true,
            show_editor_hint: false,
            show_hosted_hint: false,
        },
        SetupIntent::AgentOnly => SetupPlan {
            install_shell_hook: true,
            configure_mcp: true,
            mcp_assistant_indices: all_detected,
            inject_discovery_reminders: true,
            auto_daemon: true,
            show_editor_hint: false,
            show_hosted_hint: false,
        },
        SetupIntent::Editor => SetupPlan {
            install_shell_hook: true,
            configure_mcp: false,
            mcp_assistant_indices: Vec::new(),
            inject_discovery_reminders: false,
            auto_daemon: true,
            show_editor_hint: true,
            show_hosted_hint: false,
        },
        SetupIntent::Hosted => SetupPlan {
            install_shell_hook: true,
            configure_mcp: false,
            mcp_assistant_indices: Vec::new(),
            inject_discovery_reminders: false,
            auto_daemon: true,
            show_editor_hint: false,
            show_hosted_hint: true,
        },
        SetupIntent::Advanced => {
            build_advanced_plan(opts, assistants, shell_name, interactive, &all_detected)
        }
    };

    // The `--auto-daemon` flag and `--shell` are honored across every intent so
    // scripts can still steer behaviour without selecting Advanced.
    Ok(SetupPlan {
        auto_daemon: plan.auto_daemon || opts.auto_daemon,
        ..plan
    })
}

/// Granular toggles for the Advanced intent. Non-interactive Advanced reuses the
/// same defaults as the other intents (shell on, all detected clients, daemon
/// on) so scripted Advanced is predictable.
fn build_advanced_plan(
    opts: &WizardOptions,
    assistants: &[AiAssistant],
    shell_name: &str,
    interactive: bool,
    all_detected: &[usize],
) -> SetupPlan {
    let install_shell_hook = prompt_yn(
        &format!(
            "Install shell integration to {}?",
            shell_rc(shell_name)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| shell_name.to_string())
        ),
        true,
        interactive,
    );

    let mcp_assistant_indices = if interactive {
        let items: Vec<String> = assistants
            .iter()
            .map(|a| {
                let status = if a.detected {
                    "installed"
                } else {
                    "not detected"
                };
                format!("{:<14} [{}]", a.name, status)
            })
            .collect();
        let defaults: Vec<bool> = assistants.iter().map(|a| a.detected).collect();
        println!("Configure Kin's MCP server for which AI clients?");
        MultiSelect::new()
            .items(&items)
            .defaults(&defaults)
            .interact()
            .unwrap_or_else(|_| all_detected.to_vec())
    } else {
        all_detected.to_vec()
    };

    let auto_daemon = if opts.auto_daemon {
        true
    } else {
        prompt_yn(
            "Auto-start kin-daemon when entering Kin workspaces?",
            true,
            interactive,
        )
    };

    let configure_mcp = !mcp_assistant_indices.is_empty();
    SetupPlan {
        install_shell_hook,
        configure_mcp,
        mcp_assistant_indices,
        inject_discovery_reminders: configure_mcp,
        auto_daemon,
        show_editor_hint: false,
        show_hosted_hint: false,
    }
}

/// Apply a [`SetupPlan`]: install the shell hook, write MCP configs, inject
/// discovery reminders, and persist the daemon config. Existing config is
/// detected and the user is told what changes before it is touched.
async fn apply_plan(
    plan: &SetupPlan,
    assistants: &[AiAssistant],
    shell_name: &str,
) -> Result<Vec<(String, Option<PathBuf>)>> {
    // Shell integration.
    if plan.install_shell_hook {
        let rc_path = shell_rc(shell_name)?;
        let already = rc_path.exists()
            && std::fs::read_to_string(&rc_path)
                .map(|c| c.contains("kin-vfs"))
                .unwrap_or(false);
        if already {
            println!(
                "Shell integration: {} already sources the kin-vfs hook — refreshing the hook file in place, leaving your rc untouched.",
                rc_path.display()
            );
        } else {
            println!(
                "Shell integration: adding one `source` line to {}.",
                rc_path.display()
            );
        }
        install_shell_hook(shell_name)?;
        if cfg!(target_os = "windows") {
            println!(
                "  {} On Windows the VFS shim/ProjFS is an optional feature and is not \
                 shell-auto-injected — the PowerShell hook only manages env state.",
                style("!").yellow()
            );
        }
        println!("  Shell integration installed.");
    } else {
        println!("Shell integration: skipped.");
    }
    println!();

    // AI client MCP configuration.
    let mut configured_assistants: Vec<(String, Option<PathBuf>)> = Vec::new();
    if plan.configure_mcp {
        println!("AI client MCP configuration:");
        for idx in &plan.mcp_assistant_indices {
            let Some(a) = assistants.get(*idx) else {
                continue;
            };
            let existing_path = mcp_config_path_for_index(*idx);
            if let Some(p) = &existing_path {
                if has_kin_mcp_config(p) {
                    println!(
                        "  {} {} already has a kin MCP entry at {} — re-merging to the agent-default profile (other servers untouched).",
                        style("→").cyan(),
                        a.name,
                        p.display()
                    );
                } else if p.exists() {
                    println!(
                        "  {} {} has a config at {} — merging the kin server entry in (other servers untouched).",
                        style("→").cyan(),
                        a.name,
                        p.display()
                    );
                }
            }
            let result = configure_assistant_by_index(*idx);
            match result {
                Some(Ok(path)) => {
                    println!(
                        "  {} {} configured ({})",
                        style("✓").green(),
                        a.name,
                        path.display()
                    );
                    configured_assistants.push((a.name.to_string(), Some(path)));
                }
                Some(Err(e)) => {
                    println!(
                        "  {} {} configuration failed: {e}",
                        style("✗").red(),
                        a.name
                    );
                    configured_assistants.push((a.name.to_string(), None));
                }
                None => {}
            }
        }
        for a in assistants.iter().filter(|a| !a.detected) {
            println!(
                "  {} {} not detected — {}",
                style("→").cyan(),
                a.name,
                a.install_hint
            );
        }
        println!();
    }

    // Agent discovery reminders.
    if plan.inject_discovery_reminders {
        println!("Agent discovery reminders:");
        let home = home_dir()?;
        for (label, path) in [
            ("Claude Code", home.join(".claude").join("CLAUDE.md")),
            ("Codex CLI", home.join(".codex").join("AGENTS.md")),
        ] {
            match inject_discovery_reminder(&path) {
                Ok(()) => println!(
                    "  {} {label} discovery reminder ensured ({})",
                    style("✓").green(),
                    path.display()
                ),
                Err(e) => println!("  {} {label} reminder failed: {e}", style("!").yellow()),
            }
        }
        println!();
    }

    // Daemon auto-start config.
    write_auto_daemon_config(plan.auto_daemon)?;
    println!(
        "Daemon auto-start: {}.",
        if plan.auto_daemon {
            "enabled"
        } else {
            "disabled"
        }
    );

    // Record what we wrote into the install ledger so `kin doctor` can verify it
    // and `kin setup uninstall` can remove exactly it.
    record_setup_ledger(plan, shell_name);

    Ok(configured_assistants)
}

/// Stable ledger id for an AI-client index, matching the ids used by
/// [`crate::commands::health::mcp_client_config_paths`].
fn client_id_for_index(idx: usize) -> &'static str {
    match idx {
        IDX_CLAUDE_CODE => "claude",
        IDX_CURSOR => "cursor",
        IDX_CODEX => "codex",
        IDX_GEMINI => "gemini",
        IDX_WINDSURF => "windsurf",
        _ => "unknown",
    }
}

/// Read the `mcpServers.kin` sub-value from a client config, if present.
fn read_kin_mcp_entry(path: &Path) -> Option<serde_json::Value> {
    let content = fs::read_to_string(path).ok()?;
    let root: serde_json::Value = serde_json::from_str(&content).ok()?;
    root.get("mcpServers")?.get("kin").cloned()
}

/// Record everything the applied [`SetupPlan`] wrote into the install ledger.
///
/// Re-derives each artifact from final on-disk state and upserts it, preserving
/// original install timestamps across idempotent re-runs. Ledger failures are
/// non-fatal: setup already succeeded, so a ledger write error is a warning, not
/// a setup failure.
fn record_setup_ledger(plan: &SetupPlan, shell_name: &str) {
    use crate::commands::setup_ledger::{ArtifactKind, LedgerEntry, SetupLedger};

    let Ok(ledger_path) = crate::commands::setup_ledger::ledger_path() else {
        return;
    };
    let mut ledger = SetupLedger::load(&ledger_path).unwrap_or_default();

    if plan.install_shell_hook {
        if let Ok(kin_home) = kin_dir() {
            // Shell hook file — a whole file Kin owns.
            let hook_file = kin_home.join("shell").join(hook_filename(shell_name));
            ledger.record(LedgerEntry::whole_file(
                ArtifactKind::ShellHook,
                shell_name,
                hook_file.clone(),
                hook_content(shell_name).as_bytes(),
            ));

            // VFS shim — a whole file, recorded only when a usable one landed.
            let shim = kin_home.join("lib").join(shim_filename());
            if let Ok(bytes) = fs::read(&shim) {
                if !bytes.is_empty() {
                    ledger.record(LedgerEntry::whole_file(
                        ArtifactKind::VfsShim,
                        "shim",
                        shim,
                        &bytes,
                    ));
                }
            }

            // rc source-line block — an appended marker, recorded only when it
            // is actually present in the rc (i.e. we appended it this run or a
            // prior one).
            if let Ok(rc_path) = shell_rc(shell_name) {
                let block = rc_integration_block(&rc_source_line(shell_name, &hook_file));
                let present = fs::read_to_string(&rc_path)
                    .map(|c| c.contains(&block))
                    .unwrap_or(false);
                if present {
                    ledger.record(LedgerEntry::appended(
                        ArtifactKind::ShellRcLine,
                        shell_name,
                        rc_path,
                        block,
                    ));
                }
            }
        }
    }

    if plan.configure_mcp {
        for idx in &plan.mcp_assistant_indices {
            let Some(path) = mcp_config_path_for_index(*idx) else {
                continue;
            };
            if let Some(kin_entry) = read_kin_mcp_entry(&path) {
                ledger.record(LedgerEntry::mcp(
                    client_id_for_index(*idx),
                    path,
                    &kin_entry,
                ));
            }
        }
    }

    if plan.inject_discovery_reminders {
        if let Ok(home) = home_dir() {
            for (target, path) in [
                ("claude-md", home.join(".claude").join("CLAUDE.md")),
                ("codex-agents", home.join(".codex").join("AGENTS.md")),
            ] {
                let present = fs::read_to_string(&path)
                    .map(|c| c.contains(KIN_DISCOVERY_REMINDER))
                    .unwrap_or(false);
                if present {
                    ledger.record(LedgerEntry::appended(
                        ArtifactKind::DiscoveryReminder,
                        target,
                        path,
                        KIN_DISCOVERY_REMINDER,
                    ));
                }
            }
        }
    }

    // Daemon auto-start config — always written by apply_plan.
    if let Ok(kin_home) = kin_dir() {
        let cfg = kin_home.join("config").join("setup.toml");
        if let Ok(bytes) = fs::read(&cfg) {
            ledger.record(LedgerEntry::whole_file(
                ArtifactKind::DaemonConfig,
                "daemon",
                cfg,
                &bytes,
            ));
        }
    }

    if let Err(e) = ledger.save(&ledger_path) {
        println!(
            "  {} could not write install ledger: {e}",
            style("!").yellow()
        );
    }
}

/// The MCP config path an assistant index writes to, if any.
fn mcp_config_path_for_index(idx: usize) -> Option<PathBuf> {
    let home = home_dir().ok()?;
    match idx {
        IDX_CLAUDE_CODE => {
            let primary = home.join(".claude.json");
            let alt = home.join(".claude").join("config.json");
            Some(if alt.exists() && !primary.exists() {
                alt
            } else {
                primary
            })
        }
        IDX_CURSOR => Some(home.join(".cursor").join("mcp.json")),
        IDX_CODEX => Some(home.join(".codex").join("mcp.json")),
        IDX_GEMINI => Some(home.join(".gemini").join("settings.json")),
        IDX_WINDSURF => Some(
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
        ),
        _ => None,
    }
}

/// Run the matching `configure_*` for an assistant index.
fn configure_assistant_by_index(idx: usize) -> Option<Result<PathBuf>> {
    match idx {
        IDX_CLAUDE_CODE => Some(configure_claude_code()),
        IDX_CURSOR => Some(configure_cursor()),
        IDX_CODEX => Some(configure_codex()),
        IDX_GEMINI => Some(configure_gemini_cli()),
        IDX_WINDSURF => Some(configure_windsurf()),
        _ => None,
    }
}

/// Intent-specific guidance shown before the health checklist, driven by the
/// applied [`SetupPlan`].
fn print_intent_followups(plan: &SetupPlan) {
    if plan.show_editor_hint {
        println!();
        println!("Editor extension:");
        println!(
            "  {} Install the kin-editor VS Code extension for the entity explorer,",
            style("→").cyan()
        );
        println!("    semantic search, and trace surfaces. See the kin-editor README.");
    }
    if plan.show_hosted_hint {
        println!();
        println!("Hosted / KinLab:");
        println!(
            "  {} Hosted connect is not a first-run flow yet. There is no public",
            style("!").yellow()
        );
        println!("    `kin login`/connect command shipped. This is coming soon —");
        println!("    your local setup above is fully functional in the meantime.");
    }
}

/// Closing next-steps block, tailored to the chosen intent.
fn print_next_steps(
    intent: SetupIntent,
    installed_shell: bool,
    configured_assistants: &[(String, Option<PathBuf>)],
) {
    println!();
    if installed_shell {
        println!("Open a new shell session to load the shell hook.");
        println!();
    }
    println!("Next steps:");
    println!("  kin init             -- initialize a Kin repository in the current directory");
    println!("  kin setup status     -- show what's installed");
    println!("  kin setup doctor     -- run health checks (use --fix to repair)");
    println!("  kin setup ledger     -- show what setup wrote + verify it on disk");
    println!("  kin setup uninstall  -- remove exactly what setup wrote (ledger-verified)");

    let configured_any = configured_assistants.iter().any(|(_, p)| p.is_some());
    if matches!(intent, SetupIntent::AgentOnly | SetupIntent::Advanced) && configured_any {
        println!();
        println!("Try this next prompt in your AI agent:");
        println!();
        println!("  Use Kin to explore this codebase: run semantic_locate to find the");
        println!("  main entry point, then get_context_pack on that file.");
    }
    println!();
}

// ---------------------------------------------------------------------------
// `kin setup status`
// ---------------------------------------------------------------------------

pub async fn status(json: bool) -> Result<()> {
    let report = crate::commands::health::run_health_checks().await;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    print_human_report(&report);
    Ok(())
}

/// Map a status to a short human label for the text table.
fn status_label(status: &crate::commands::health::HealthStatus) -> &'static str {
    use crate::commands::health::HealthStatus;
    match status {
        HealthStatus::Healthy => "ok",
        HealthStatus::Missing => "MISSING",
        HealthStatus::Stale => "STALE",
        HealthStatus::Misconfigured => "MISCONFIGURED",
        HealthStatus::Unsupported => "n/a",
    }
}

/// Render a [`HealthReport`] as the human-readable table used by
/// `kin setup status` and `kin doctor`.
fn print_human_report(report: &crate::commands::health::HealthReport) {
    use crate::commands::health::HealthStatus;
    println!("Platform: {}", report.platform);
    println!();
    for check in &report.checks {
        let mark = match check.status {
            HealthStatus::Healthy => style("✓").green(),
            HealthStatus::Missing | HealthStatus::Misconfigured => style("✗").red(),
            HealthStatus::Stale => style("!").yellow(),
            HealthStatus::Unsupported => style("→").cyan(),
        };
        println!(
            "  {mark} {:<26} {:<14} {}",
            check.label,
            status_label(&check.status),
            check.detail
        );
        if let Some(note) = &check.platform_note {
            println!("      note: {note}");
        }
        if !matches!(check.status, HealthStatus::Healthy) {
            if let Some(fix) = &check.manual_fix {
                println!("      fix:  {fix}");
            }
        }
    }
    println!();
    let summary = report.summary();
    println!(
        "Summary: {} passed, {} need attention, {} not applicable.",
        style(summary.passed).green(),
        if summary.attention > 0 {
            style(summary.attention).red()
        } else {
            style(summary.attention).dim()
        },
        style(summary.skipped).dim(),
    );
    if report.healthy {
        println!(
            "{} First-run ready — no component is missing or misconfigured.",
            style("✓").green()
        );
    } else {
        println!(
            "{} Some checks need attention. Run `kin doctor --fix` to apply safe repairs.",
            style("✗").red()
        );
    }
}

// ---------------------------------------------------------------------------
// `kin setup doctor`
// ---------------------------------------------------------------------------

pub async fn doctor(fix: bool, json: bool) -> Result<()> {
    let report = crate::commands::health::run_health_checks().await;

    if !fix {
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_human_report(&report);
        }
        return Ok(());
    }

    // Apply only the safe, fixable repairs. Each maps to a check id family.
    println!("Applying safe repairs...");
    println!();
    let mut applied: Vec<String> = Vec::new();

    let shell_needs_fix = report.checks.iter().any(|c| {
        c.id == "shell_path"
            && c.fixable
            && !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
    });
    if shell_needs_fix {
        match reinstall_shell_hook() {
            Ok(path) => {
                applied.push(format!("reinstalled shell hook ({})", path.display()));
            }
            Err(e) => println!("  {} shell hook reinstall failed: {e}", style("✗").red()),
        }
    }

    let mcp_needs_fix = report.checks.iter().any(|c| {
        c.id.starts_with("mcp_client_")
            && c.fixable
            && !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
    });
    if mcp_needs_fix {
        let repaired = remerge_existing_mcp_configs();
        for path in repaired {
            applied.push(format!("re-merged MCP config ({})", path.display()));
        }
    }

    // Re-source the VFS shim when it is missing or was truncated to 0 bytes.
    let vfs_needs_fix = report.checks.iter().any(|c| {
        c.id == "vfs_projection"
            && c.fixable
            && !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
    });
    if vfs_needs_fix {
        match reinstall_vfs_shim() {
            Ok(Some(dest)) => applied.push(format!("reinstalled VFS shim ({})", dest.display())),
            Ok(None) => println!(
                "  {} no usable VFS shim found to reinstall — re-run the installer \
                 (curl -fsSL https://get.kinlab.dev/install | sh)",
                style("✗").red()
            ),
            Err(e) => println!("  {} VFS shim reinstall failed: {e}", style("✗").red()),
        }
    }

    // Start the repo daemon if we're inside a Kin repo and it isn't running.
    let daemon_needs_fix = report.checks.iter().any(|c| {
        c.id == "daemon_running"
            && c.fixable
            && !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
    });
    if daemon_needs_fix {
        match start_repo_daemon().await {
            Ok(Some(url)) => applied.push(format!("started kin-daemon ({url})")),
            Ok(None) => {}
            Err(e) => println!("  {} kin-daemon start failed: {e}", style("✗").red()),
        }
    }

    // Ensure the config directory scaffold exists (idempotent).
    if let Ok(kin_home) = kin_dir() {
        let config_dir = kin_home.join("config");
        if !config_dir.exists() && fs::create_dir_all(&config_dir).is_ok() {
            applied.push(format!("created config dir ({})", config_dir.display()));
        }
    }

    // Clean orphaned daemon PID/port files across registered repos.
    let cleaned = cleanup_stale_daemons();
    if cleaned > 0 {
        applied.push(format!("cleaned {cleaned} stale daemon(s)"));
    }

    if applied.is_empty() {
        println!("  Nothing to repair automatically.");
    } else {
        for line in &applied {
            println!("  {} {line}", style("✓").green());
        }
    }
    println!();

    // Re-run the checks to report the post-fix state.
    let after = crate::commands::health::run_health_checks().await;
    if json {
        println!("{}", serde_json::to_string_pretty(&after)?);
        return Ok(());
    }
    println!("Re-running checks...");
    println!();
    print_human_report(&after);

    let still_manual: Vec<&crate::commands::health::HealthCheck> = after
        .checks
        .iter()
        .filter(|c| {
            !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
                && c.manual_fix.is_some()
        })
        .collect();
    if !still_manual.is_empty() {
        println!();
        println!("Still needs manual steps:");
        for check in still_manual {
            if let Some(fix) = &check.manual_fix {
                println!("  - {}: {fix}", check.label);
            }
        }
    }

    Ok(())
}

/// Start the daemon for the repo containing the current directory, if any.
///
/// Returns `Ok(Some(url))` when a daemon is now reachable, `Ok(None)` when the
/// current directory is not inside a Kin repository (nothing to start), or an
/// error if the daemon could not be started.
async fn start_repo_daemon() -> Result<Option<String>> {
    let cwd = env::current_dir().unwrap_or_default();
    let Some(layout) = kin_core::KinLayout::discover(&cwd) else {
        return Ok(None);
    };
    let url = crate::daemon_client::ensure_daemon_running(layout.root()).await?;
    Ok(Some(url))
}

/// Scan all registered repos for stale daemon PID/port files and clean them up.
/// Returns the number of stale daemons cleaned.
fn cleanup_stale_daemons() -> usize {
    let mut cleaned = 0;
    if let Ok(registry) = kin_core::registry::KinRegistry::load() {
        for repo in &registry.repos {
            let kin_root = repo.path.join(".kin");
            if !kin_root.exists() {
                continue;
            }
            // daemon_is_up() cleans stale files as a side effect
            let _ = crate::daemon_client::daemon_is_up(&kin_root);
            // Also check for orphaned port files without a PID file
            let has_port = kin_root.join("daemon.port").exists();
            let has_pid = kin_root.join("daemon.pid").exists();
            if has_port && !has_pid {
                let _ = std::fs::remove_file(kin_root.join("daemon.port"));
                cleaned += 1;
            }
        }
    }
    cleaned
}

// ---------------------------------------------------------------------------
// `kin setup ledger` and `kin setup uninstall`
// ---------------------------------------------------------------------------

/// Show the install ledger and each entry's verification state against disk.
pub fn ledger_status(json: bool) -> Result<()> {
    use crate::commands::setup_ledger::{ledger_path, verify_ledger, EntryState};

    let path = ledger_path()?;
    let verifications = verify_ledger(&path)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&verifications)?);
        return Ok(());
    }

    if verifications.is_empty() {
        println!("No install ledger at {}.", path.display());
        println!("Run `kin setup` to configure Kin and record what it writes.");
        return Ok(());
    }

    println!("Install ledger: {}", path.display());
    println!();
    for v in &verifications {
        let mark = match v.state {
            EntryState::Verified => style("✓").green(),
            EntryState::Modified => style("!").yellow(),
            EntryState::Removed => style("✗").red(),
        };
        println!("  {mark} {:<16} {}", v.entry.target, v.detail);
        println!("      path: {}", v.entry.path.display());
    }
    println!();

    let verified = verifications
        .iter()
        .filter(|v| matches!(v.state, EntryState::Verified))
        .count();
    let modified = verifications
        .iter()
        .filter(|v| matches!(v.state, EntryState::Modified))
        .count();
    let removed = verifications
        .iter()
        .filter(|v| matches!(v.state, EntryState::Removed))
        .count();
    println!(
        "{} artifact(s) tracked: {} verified, {} modified, {} removed.",
        verifications.len(),
        style(verified).green(),
        if modified > 0 {
            style(modified).yellow()
        } else {
            style(modified).dim()
        },
        if removed > 0 {
            style(removed).red()
        } else {
            style(removed).dim()
        },
    );
    Ok(())
}

/// Remove exactly what `kin setup` recorded in the install ledger.
///
/// Ledger-verified: an artifact modified since install is left in place (unless
/// `--force`) so a user's own edits are never clobbered. `--dry-run` reports
/// what would be removed without touching disk.
pub fn uninstall(dry_run: bool, force: bool, json: bool) -> Result<()> {
    use crate::commands::setup_ledger::{ledger_path, run_uninstall, RemovalAction};

    let path = ledger_path()?;
    let outcomes = run_uninstall(&path, dry_run, force)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&outcomes)?);
        return Ok(());
    }

    if outcomes.is_empty() {
        println!("No install ledger found — nothing recorded to uninstall.");
        println!("(The ledger is written by `kin setup`; run it first if you expected entries.)");
        return Ok(());
    }

    if dry_run {
        println!("Dry run — no changes will be written.");
    } else {
        println!("Uninstalling Kin-written artifacts (ledger-verified)...");
    }
    println!();
    for o in &outcomes {
        let mark = match o.action {
            RemovalAction::Removed => style("✓").green(),
            RemovalAction::SkippedModified => style("!").yellow(),
            RemovalAction::AlreadyAbsent => style("→").cyan(),
            RemovalAction::Failed => style("✗").red(),
        };
        println!("  {mark} {}", o.detail);
    }
    println!();

    let removed = outcomes
        .iter()
        .filter(|o| matches!(o.action, RemovalAction::Removed))
        .count();
    let skipped = outcomes
        .iter()
        .filter(|o| matches!(o.action, RemovalAction::SkippedModified))
        .count();
    let failed = outcomes
        .iter()
        .filter(|o| matches!(o.action, RemovalAction::Failed))
        .count();

    if dry_run {
        println!("Would remove {removed}, skip {skipped} (modified since install).");
    } else {
        println!("Removed {removed}, skipped {skipped} (modified since install), {failed} failed.");
        if skipped > 0 {
            println!("Re-run with --force to remove entries modified since install.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> WizardOptions {
        WizardOptions {
            mode: None,
            shell: Some("zsh".to_string()),
            auto_daemon: false,
            no_interactive: true,
            intent: None,
        }
    }

    #[test]
    fn is_usable_shim_requires_a_nonempty_file() {
        let tmp = tempfile::tempdir().unwrap();
        let empty = tmp.path().join("empty.dylib");
        fs::write(&empty, b"").unwrap();
        let full = tmp.path().join("full.dylib");
        fs::write(&full, b"real bytes").unwrap();
        let missing = tmp.path().join("missing.dylib");

        assert!(!is_usable_shim(&empty), "0-byte shim must not be usable");
        assert!(is_usable_shim(&full));
        assert!(!is_usable_shim(&missing));
    }

    #[test]
    fn same_file_detects_the_bin_dotdot_lib_aliasing() {
        let tmp = tempfile::tempdir().unwrap();
        let lib = tmp.path().join("lib");
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&lib).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let dest = lib.join(shim_filename());
        fs::write(&dest, b"shim").unwrap();

        // The exact path find_shim produces on the standard install layout.
        let aliased = bin.join("..").join("lib").join(shim_filename());
        assert!(same_file(&aliased, &dest));

        let other = lib.join("other.dylib");
        fs::write(&other, b"x").unwrap();
        assert!(!same_file(&other, &dest));
    }

    #[test]
    fn copy_shim_skips_self_copy_and_preserves_bytes() {
        // Regression: `kin setup` copied the shim onto itself (bin/../lib aliases
        // lib) and fs::copy truncated it to 0 bytes. The guard must no-op and
        // leave the bytes intact.
        let tmp = tempfile::tempdir().unwrap();
        let lib = tmp.path().join("lib");
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&lib).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let dest = lib.join(shim_filename());
        fs::write(&dest, b"REAL_SHIM_BYTES").unwrap();
        let aliased_src = bin.join("..").join("lib").join(shim_filename());

        assert_eq!(copy_shim(&aliased_src, &dest).unwrap(), ShimCopy::Skipped);
        assert_eq!(fs::read(&dest).unwrap(), b"REAL_SHIM_BYTES");
    }

    #[test]
    fn copy_shim_copies_a_distinct_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source.dylib");
        fs::write(&src, b"SOURCE_BYTES").unwrap();
        let dest = tmp.path().join("lib").join(shim_filename());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();

        assert_eq!(copy_shim(&src, &dest).unwrap(), ShimCopy::Copied);
        assert_eq!(fs::read(&dest).unwrap(), b"SOURCE_BYTES");
    }

    #[test]
    fn zsh_hook_clears_stale_preload_state() {
        assert!(ZSH_HOOK.contains("_kin_vfs_clear_preload"));
        assert!(ZSH_HOOK.contains("_kin_vfs_refresh_preload"));
        assert!(ZSH_HOOK.contains("else\n            _kin_vfs_refresh_preload"));
    }

    #[test]
    fn bash_hook_clears_stale_preload_state() {
        assert!(BASH_HOOK.contains("_kin_vfs_clear_preload"));
        assert!(BASH_HOOK.contains("_kin_vfs_refresh_preload"));
        assert!(BASH_HOOK.contains("else\n            _kin_vfs_refresh_preload"));
    }

    #[test]
    fn intent_flag_parses_aliases() {
        assert_eq!(
            SetupIntent::from_flag("local"),
            Some(SetupIntent::LocalOnly)
        );
        assert_eq!(SetupIntent::from_flag("CLI"), Some(SetupIntent::LocalOnly));
        assert_eq!(
            SetupIntent::from_flag("agent"),
            Some(SetupIntent::AgentOnly)
        );
        assert_eq!(SetupIntent::from_flag("mcp"), Some(SetupIntent::AgentOnly));
        assert_eq!(SetupIntent::from_flag("editor"), Some(SetupIntent::Editor));
        assert_eq!(SetupIntent::from_flag("hosted"), Some(SetupIntent::Hosted));
        assert_eq!(SetupIntent::from_flag("kinlab"), Some(SetupIntent::Hosted));
        assert_eq!(
            SetupIntent::from_flag("advanced"),
            Some(SetupIntent::Advanced)
        );
        assert_eq!(SetupIntent::from_flag("nonsense"), None);
    }

    #[test]
    fn non_interactive_defaults_to_agent_intent() {
        assert_eq!(resolve_intent(&opts(), false), SetupIntent::AgentOnly);
    }

    #[test]
    fn intent_flag_overrides_default() {
        let mut o = opts();
        o.intent = Some("local".to_string());
        assert_eq!(resolve_intent(&o, false), SetupIntent::LocalOnly);
    }

    #[test]
    fn agent_intent_configures_mcp_and_daemon() {
        let assistants = detect_ai_assistants();
        let plan = build_plan(SetupIntent::AgentOnly, &opts(), &assistants, "zsh", false).unwrap();
        assert!(plan.configure_mcp);
        assert!(plan.install_shell_hook);
        assert!(plan.inject_discovery_reminders);
        assert!(plan.auto_daemon);
        assert!(!plan.show_hosted_hint);
    }

    #[test]
    fn local_intent_skips_mcp_keeps_shell_and_daemon() {
        let assistants = detect_ai_assistants();
        let plan = build_plan(SetupIntent::LocalOnly, &opts(), &assistants, "zsh", false).unwrap();
        assert!(!plan.configure_mcp);
        assert!(plan.mcp_assistant_indices.is_empty());
        assert!(!plan.inject_discovery_reminders);
        assert!(plan.install_shell_hook);
        assert!(plan.auto_daemon);
    }

    #[test]
    fn editor_intent_shows_editor_hint_no_mcp() {
        let assistants = detect_ai_assistants();
        let plan = build_plan(SetupIntent::Editor, &opts(), &assistants, "zsh", false).unwrap();
        assert!(plan.show_editor_hint);
        assert!(!plan.configure_mcp);
        assert!(plan.install_shell_hook);
    }

    #[test]
    fn hosted_intent_shows_hosted_hint_no_mcp() {
        let assistants = detect_ai_assistants();
        let plan = build_plan(SetupIntent::Hosted, &opts(), &assistants, "zsh", false).unwrap();
        assert!(plan.show_hosted_hint);
        assert!(!plan.configure_mcp);
        assert!(!plan.show_editor_hint);
    }

    #[test]
    fn auto_daemon_flag_forces_daemon_on_every_intent() {
        let assistants = detect_ai_assistants();
        let mut o = opts();
        o.auto_daemon = true;
        let plan = build_plan(SetupIntent::Editor, &o, &assistants, "zsh", false).unwrap();
        assert!(plan.auto_daemon);
    }

    #[test]
    fn merge_mcp_config_refuses_to_overwrite_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"this is not json {{{").unwrap();

        let original = std::fs::read(&path).unwrap();
        let err = merge_mcp_config(&path).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("not valid JSON"),
            "expected 'not valid JSON' in error, got: {msg}"
        );
        assert!(
            msg.contains("refusing to overwrite"),
            "expected 'refusing to overwrite' in error, got: {msg}"
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            original,
            "corrupt file must not be modified"
        );
    }

    #[test]
    fn merge_mcp_config_merges_into_valid_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"existingKey": true}"#).unwrap();

        merge_mcp_config(&path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(val["existingKey"], true, "existing keys must be preserved");
        assert!(
            val["mcpServers"]["kin"].is_object(),
            "kin entry must be added"
        );
    }
}
