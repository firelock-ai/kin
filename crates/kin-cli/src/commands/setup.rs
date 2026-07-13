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
    local kin_home="${KIN_HOME:-${KIN_DIR:-$HOME/.kin}}"
    local kin_lib="$kin_home/lib"
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
    local kin_home="${KIN_HOME:-${KIN_DIR:-$HOME/.kin}}"
    local kin_lib="$kin_home/lib"
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

    set -l kin_home "$HOME/.kin"
    if set -q KIN_DIR
        set kin_home $KIN_DIR
    end
    if set -q KIN_HOME
        set kin_home $KIN_HOME
    end
    set -l shim "$kin_home/lib/libkin_vfs_shim"
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
    for key in ["KIN_HOME", "KIN_DIR"] {
        if let Some(value) = env::var_os(key) {
            if !value.is_empty() {
                return Ok(PathBuf::from(value));
            }
        }
    }
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
fn copy_shim(
    install_lock: &crate::commands::update::InstallRootLock,
    src: &Path,
    dest: &Path,
) -> Result<ShimCopy> {
    let expected_parent = install_lock.root().join("lib");
    let actual_parent = dest
        .parent()
        .context("VFS shim destination has no parent")?
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", dest.display()))?;
    if actual_parent != expected_parent {
        anyhow::bail!(
            "refusing VFS shim write outside managed lib directory {}: {}",
            expected_parent.display(),
            dest.display()
        );
    }
    if let Ok(metadata) = fs::symlink_metadata(dest) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!(
                "refusing non-regular VFS shim destination {}",
                dest.display()
            );
        }
    }
    if same_file(src, dest) {
        return Ok(ShimCopy::Skipped);
    }
    let bytes = fs::read(src).with_context(|| format!("failed to read shim {}", src.display()))?;
    crate::commands::update::write_managed_component_atomically(install_lock, dest, &bytes)
        .with_context(|| format!("failed to copy shim to {}", dest.display()))?;
    Ok(ShimCopy::Copied)
}

fn find_shim() -> Option<PathBuf> {
    let name = shim_filename();

    if let Ok(kin_home) = kin_dir() {
        let candidate = kin_home.join("lib").join(name);
        if is_usable_shim(&candidate) {
            return Some(candidate);
        }
    }

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

/// Restore the shim at `dest` from the first usable source in `sources` (a
/// source is usable when it exists and is non-empty). Returns the dest path when
/// a source was copied, or `None` when no usable local source exists — the
/// caller then escalates (download) or prints a manual step. Explicit sources
/// keep the copy logic unit-testable without a real `$HOME`.
fn restore_shim_from_sources(
    install_lock: &crate::commands::update::InstallRootLock,
    dest: &Path,
    sources: &[PathBuf],
) -> Result<Option<PathBuf>> {
    for src in sources {
        if is_usable_shim(src) {
            copy_shim(install_lock, src, dest)?;
            return Ok(Some(dest.to_path_buf()));
        }
    }
    Ok(None)
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
/// Prefers the managed launcher and then the PATH-visible launcher so upgrades
/// do not strand client configs on a versioned Cellar or build-directory path.
/// The running executable is only a fallback when no stable launcher exists.
///
/// The entry starts the MCP server in single-repo mode. Most clients launch it
/// from the active workspace, so `kin mcp start` resolves that working
/// directory (or `KIN_DAEMON_URL` when a session pinned one). New global client
/// entries are cwd-free, while an existing cwd is preserved as user-owned
/// launch policy. A client-supported workspace config may pin its repository.
fn kin_mcp_entry() -> serde_json::Value {
    kin_mcp_entry_with_cwd(None)
}

fn kin_mcp_entry_with_cwd(cwd: Option<&Path>) -> serde_json::Value {
    kin_mcp_entry_for_command(preferred_kin_mcp_launcher(), cwd)
}

pub(crate) fn preferred_kin_mcp_launcher() -> String {
    let managed = kin_dir()
        .ok()
        .map(|home| home.join("bin").join(kin_launcher_filename()));
    select_kin_mcp_launcher(
        managed,
        check_binary_in_path("kin"),
        env::current_exe().ok(),
    )
}

fn kin_mcp_entry_for_command(command: String, cwd: Option<&Path>) -> serde_json::Value {
    let mut entry = serde_json::json!({
        "command": command,
        "args": ["mcp", "start"],
        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    });
    if let Some(cwd) = cwd {
        entry["cwd"] = serde_json::Value::String(cwd.to_string_lossy().into_owned());
    }
    entry
}

fn kin_launcher_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "kin.exe"
    } else {
        "kin"
    }
}

fn is_usable_kin_launcher(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn select_kin_mcp_launcher(
    managed: Option<PathBuf>,
    path_launcher: Option<PathBuf>,
    current_exe: Option<PathBuf>,
) -> String {
    let current_dir = env::current_dir().ok();
    managed
        .into_iter()
        .chain(path_launcher)
        .chain(current_exe)
        .filter_map(|candidate| {
            if candidate.is_absolute() {
                Some(candidate)
            } else {
                current_dir.as_ref().map(|cwd| cwd.join(candidate))
            }
        })
        .find(|candidate| is_usable_kin_launcher(candidate))
        .map(|candidate| candidate.to_string_lossy().into_owned())
        .unwrap_or_else(|| "kin".to_string())
}

/// Describes an AI assistant we can auto-configure.
struct AiAssistant {
    name: &'static str,
    detected: bool,
    install_hint: &'static str,
}

#[derive(Debug, Default)]
struct AssistantConfigOutcome {
    configured: Vec<(&'static str, PathBuf)>,
    errors: Vec<String>,
}

impl AssistantConfigOutcome {
    fn failed(error: impl Into<String>) -> Self {
        Self {
            configured: Vec::new(),
            errors: vec![error.into()],
        }
    }

    fn from_single(target: &'static str, result: Result<PathBuf>) -> Self {
        match result {
            Ok(path) => Self {
                configured: vec![(target, path)],
                errors: Vec::new(),
            },
            Err(error) => Self::failed(error.to_string()),
        }
    }

    fn attempt(
        &mut self,
        target: &'static str,
        path: PathBuf,
        configure: impl FnOnce(&PathBuf) -> Result<()>,
    ) {
        match configure(&path) {
            Ok(()) => self.configured.push((target, path)),
            Err(error) => self.errors.push(format!("{}: {error}", path.display())),
        }
    }
}

// Assistant index constants — keep in sync with detect_ai_assistants() order.
const IDX_CLAUDE_CODE: usize = 0;
const IDX_CURSOR: usize = 1;
const IDX_CODEX: usize = 2;
const IDX_ANTIGRAVITY: usize = 3;
const IDX_WINDSURF: usize = 4;

/// Detect installed AI assistants eligible for MCP auto-configuration.
///
/// Detection heuristics per client:
/// - Claude Code: `claude` binary on PATH
/// - Cursor: `cursor` binary on PATH, or `/Applications/Cursor.app`
/// - Codex CLI: `codex` binary on PATH
/// - Google Antigravity: `agy`/`agy-ide` on PATH, their default install
///   locations, or the Antigravity/Antigravity IDE macOS applications
/// - Windsurf: `windsurf` binary on PATH, or `/Applications/Windsurf.app`
fn detect_ai_assistants() -> Vec<AiAssistant> {
    let claude_detected = check_binary_in_path("claude").is_some();
    let cursor_detected = check_binary_in_path("cursor").is_some()
        || PathBuf::from("/Applications/Cursor.app").exists();
    let codex_detected = is_codex_detected();
    let antigravity_detected = is_antigravity_detected();
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
            name: "Google Antigravity",
            detected: antigravity_detected,
            install_hint: "install from antigravity.google/download",
        },
        AiAssistant {
            name: "Windsurf",
            detected: windsurf_detected,
            install_hint: "install from windsurf.com",
        },
    ]
}

/// Detect Google Antigravity without treating the retired Gemini CLI or a
/// generic `~/.gemini` directory as an installed current client.
///
/// The CLI installer places `agy` at `~/.local/bin/agy` by default, which may
/// not be on PATH until the user opens a new shell. The IDE can expose
/// `agy-ide`, and the two macOS application bundles are also valid installed
/// surfaces even when neither launcher is on PATH.
fn antigravity_detected_at(
    home: Option<&Path>,
    applications_dir: &Path,
    binary_on_path: impl Fn(&str) -> bool,
) -> bool {
    if binary_on_path("agy") || binary_on_path("agy-ide") {
        return true;
    }

    if home.is_some_and(|home| {
        home.join(".local").join("bin").join("agy").exists()
            || home
                .join(".antigravity-ide")
                .join("antigravity-ide")
                .join("bin")
                .join("agy-ide")
                .exists()
    }) {
        return true;
    }

    ["Antigravity.app", "Antigravity IDE.app"]
        .iter()
        .any(|name| applications_dir.join(name).exists())
}

pub(crate) fn is_antigravity_detected() -> bool {
    let home = home_dir().ok();
    antigravity_detected_at(home.as_deref(), Path::new("/Applications"), |name| {
        check_binary_in_path(name).is_some()
    })
}

pub(crate) fn is_codex_detected() -> bool {
    check_binary_in_path("codex").is_some()
}

/// Merge the "kin" MCP server entry into an existing JSON config file.
/// Creates the file if it doesn't exist.
fn merge_mcp_config(path: &PathBuf) -> Result<()> {
    merge_mcp_config_entry(path, kin_mcp_entry())
}

fn merge_mcp_config_with_cwd(path: &PathBuf, cwd: &Path) -> Result<()> {
    merge_mcp_config_entry(path, kin_mcp_entry_with_cwd(Some(cwd)))
}

/// Atomically replace setup-managed state while retaining the permissions of
/// an existing file. A symlinked path keeps the symlink and replaces its target
/// instead of silently turning the symlink into a regular file.
fn write_config_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    write_config_atomically_with(path, bytes, |temp, destination| {
        temp.persist(destination)
            .map(|_| ())
            .map_err(|error| error.error)
    })
}

fn write_config_atomically_with(
    path: &Path,
    bytes: &[u8],
    persist: impl FnOnce(tempfile::NamedTempFile, &Path) -> io::Result<()>,
) -> Result<()> {
    let destination = match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            path.canonicalize().with_context(|| {
                format!(
                    "client config symlink {} does not resolve to a writable file",
                    path.display()
                )
            })?
        }
        Ok(_) => path.to_path_buf(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => path.to_path_buf(),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect client config {}", path.display()))
        }
    };
    let parent = destination
        .parent()
        .context("client config path has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create directory {}", parent.display()))?;

    let existing_permissions = match fs::metadata(&destination) {
        Ok(metadata) => Some(metadata.permissions()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read permissions for client config {}",
                    destination.display()
                )
            })
        }
    };

    let mut temp = tempfile::Builder::new()
        .prefix(kin_index::REPO_LOCAL_MCP_CONFIG_TEMP_PREFIX)
        .tempfile_in(parent)
        .with_context(|| format!("failed to stage client config in {}", parent.display()))?;
    temp.write_all(bytes)
        .with_context(|| format!("failed to stage client config {}", destination.display()))?;
    temp.as_file_mut()
        .sync_all()
        .with_context(|| format!("failed to sync client config {}", destination.display()))?;
    if let Some(permissions) = existing_permissions {
        temp.as_file()
            .set_permissions(permissions)
            .with_context(|| {
                format!(
                    "failed to preserve permissions for client config {}",
                    destination.display()
                )
            })?;
    }

    persist(temp, &destination).with_context(|| {
        format!(
            "failed to atomically replace client config {}",
            destination.display()
        )
    })
}

fn merge_mcp_config_entry(path: &PathBuf, kin_entry: serde_json::Value) -> Result<()> {
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

    // A syntactically valid but structurally incompatible config is still user
    // data. Refuse to replace it rather than silently converting it into an
    // object and discarding the original value.
    if !root.is_object() {
        anyhow::bail!(
            "existing file {} has a non-object JSON root — refusing to overwrite it",
            path.display()
        );
    }

    if root
        .get("mcpServers")
        .is_some_and(|value| !value.is_object())
    {
        anyhow::bail!(
            "existing file {} has a non-object mcpServers value — refusing to overwrite it",
            path.display()
        );
    }
    if root.get("mcpServers").is_none() {
        root["mcpServers"] = serde_json::json!({});
    }

    let desired = kin_entry
        .as_object()
        .context("generated Kin MCP entry is not a JSON object")?;
    let servers = root["mcpServers"]
        .as_object_mut()
        .expect("mcpServers was validated as an object");
    if servers
        .get("kin")
        .is_some_and(|existing| !existing.is_object())
    {
        anyhow::bail!(
            "existing file {} has a non-object mcpServers.kin value — refusing to overwrite it",
            path.display()
        );
    }
    let kin_entry_preexisted = servers.contains_key("kin");
    let existing = servers
        .entry("kin".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let existing = existing
        .as_object_mut()
        .expect("Kin MCP entry was validated as an object");

    // Kin owns its launcher fields, but not client-side policy such as
    // `disabled`, `disabledTools`, approval controls, or future extension keys.
    // Preserve those user-owned fields across idempotent setup/doctor repairs.
    for key in ["command", "args"] {
        if let Some(value) = desired.get(key) {
            existing.insert(key.to_string(), value.clone());
        }
    }
    match desired.get("cwd") {
        Some(value) => {
            existing.insert("cwd".to_string(), value.clone());
        }
        // A cwd on a pre-existing entry is user-owned policy unless ownership
        // can be proven. This merge has no such proof, so preserve it. Newly
        // created global entries start without cwd.
        None if kin_entry_preexisted => {}
        None => {
            existing.remove("cwd");
        }
    }

    let desired_env = desired
        .get("env")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .unwrap_or_default();
    if existing
        .get("env")
        .is_some_and(|existing_env| !existing_env.is_object())
    {
        anyhow::bail!(
            "existing file {} has a non-object mcpServers.kin.env value — refusing to overwrite it",
            path.display()
        );
    }
    let env = existing
        .entry("env".to_string())
        .or_insert_with(|| serde_json::json!({}));
    let env = env
        .as_object_mut()
        .expect("Kin MCP env was validated as an object");
    for (key, value) in desired_env {
        env.insert(key, value);
    }

    // Write back with pretty formatting
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    let formatted =
        serde_json::to_string_pretty(&root).context("failed to serialize MCP config")?;
    write_config_atomically(path, formatted.as_bytes())?;

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

/// Merge the "kin" MCP server entry into a TOML MCP config (Codex CLI's
/// `~/.codex/config.toml`). Creates the file if it doesn't exist.
///
/// Codex reads MCP servers from `[mcp_servers.<name>]` tables in
/// `config.toml` — it does not read an `mcp.json`. Uses a format-preserving
/// TOML edit so unrelated keys, tables, and comments in the user's config are
/// left untouched.
fn merge_mcp_config_toml(path: &PathBuf, cwd: Option<&Path>) -> Result<()> {
    use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table};

    let mut doc: DocumentMut = if path.exists() {
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        content.parse().with_context(|| {
            format!(
                "existing file {} is not valid TOML — refusing to overwrite it. \
                 Fix or remove the file and try again.",
                path.display()
            )
        })?
    } else {
        DocumentMut::new()
    };

    // Ensure mcp_servers is a standard table we can nest [mcp_servers.kin]
    // under, preserving any existing server entries (including ones written
    // as an inline `mcp_servers = { ... }` value).
    if !matches!(doc.get("mcp_servers"), Some(Item::Table(_))) {
        let mut servers = match doc.remove("mcp_servers") {
            Some(item) => match item.into_table() {
                Ok(table) => table,
                Err(item) => match item.into_value() {
                    Ok(toml_edit::Value::InlineTable(inline)) => inline.into_table(),
                    _ => anyhow::bail!(
                        "existing file {} has an incompatible mcp_servers value — refusing to overwrite it",
                        path.display()
                    ),
                },
            },
            None => Table::new(),
        };
        servers.set_implicit(true);
        doc.insert("mcp_servers", Item::Table(servers));
    }

    // Build the kin entry from the same source of truth as the JSON configs.
    let entry = kin_mcp_entry();
    let command = entry
        .get("command")
        .and_then(|c| c.as_str())
        .unwrap_or("kin")
        .to_string();

    let kin_servers = doc["mcp_servers"]
        .as_table_mut()
        .expect("mcp_servers was normalized to a table");
    let existing_kin = kin_servers.remove("kin");
    let kin_entry_preexisted = existing_kin.is_some();
    let kin_table = match existing_kin {
        Some(item) => match item.into_table() {
            Ok(table) => table,
            Err(item) => match item.into_value() {
                Ok(toml_edit::Value::InlineTable(inline)) => inline.into_table(),
                _ => anyhow::bail!(
                    "existing file {} has an incompatible mcp_servers.kin value — refusing to overwrite it",
                    path.display()
                ),
            },
        },
        None => Table::new(),
    };
    kin_servers.insert("kin", Item::Table(kin_table));
    let kin = doc["mcp_servers"]["kin"]
        .as_table_mut()
        .expect("Kin MCP config was validated as a table");
    kin.insert("command", value(command));
    let mut args = Array::new();
    args.push("mcp");
    args.push("start");
    kin.insert("args", value(args));
    if let Some(cwd) = cwd {
        kin.insert("cwd", value(cwd.to_string_lossy().into_owned()));
    } else if !kin_entry_preexisted {
        // New global entries inherit the client launch directory. Preserve cwd
        // on a pre-existing entry as user-owned launch policy.
        kin.remove("cwd");
    }
    match kin.get_mut("env") {
        Some(Item::Value(toml_edit::Value::InlineTable(env))) => {
            env.insert("KIN_MCP_TOOL_PROFILE", "agent-default".into());
        }
        Some(Item::Table(env)) => {
            env.insert("KIN_MCP_TOOL_PROFILE", value("agent-default"));
        }
        None => {
            let mut env = InlineTable::new();
            env.insert("KIN_MCP_TOOL_PROFILE", "agent-default".into());
            kin.insert("env", value(env));
        }
        Some(_) => anyhow::bail!(
            "existing file {} has an incompatible mcp_servers.kin.env value — refusing to overwrite it",
            path.display()
        ),
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    write_config_atomically(path, doc.to_string().as_bytes())?;

    Ok(())
}

/// Configure MCP for Codex CLI.
///
/// Codex reads MCP servers from `~/.codex/config.toml` (`[mcp_servers.<name>]`
/// tables with `command`/`args`/`env`), not from an `mcp.json` file. Codex
/// 0.144.1 does not reliably load project-local MCP tables, so Kin keeps one
/// global entry. New entries omit cwd and resolve the active launch directory;
/// existing cwd policy is preserved so umbrella-launched clients can remain
/// explicitly bound to their intended repository.
fn configure_codex() -> Result<PathBuf> {
    let home = home_dir()?;
    configure_codex_at(&home)
}

fn configure_codex_at(home: &Path) -> Result<PathBuf> {
    let target = home.join(".codex").join("config.toml");
    merge_mcp_config_toml(&target, None)?;
    Ok(target)
}

/// Configure MCP for Google Antigravity.
///
/// Google Antigravity IDE and CLI share the official
/// global MCP file at `~/.gemini/config/mcp_config.json`, while current clients
/// also load `.agents/mcp_config.json` from the active workspace. Kin writes a
/// cwd-free global fallback and, when setup runs in a Kin repo, a repo-scoped
/// workspace entry. A pre-existing global cwd is preserved as user policy.
/// Existing retired Gemini CLI settings remain a compatibility target but are
/// never created for a new install.
fn configure_antigravity_at(home: &Path, repo_root: Option<&Path>) -> AssistantConfigOutcome {
    let mut outcome = AssistantConfigOutcome::default();
    let primary = home.join(".gemini").join("config").join("mcp_config.json");
    outcome.attempt("antigravity", primary, |path| merge_mcp_config(path));

    if let Some(repo_root) = repo_root {
        let workspace = repo_root.join(kin_index::REPO_LOCAL_MCP_CONFIG_PATH);
        outcome.attempt("antigravity_workspace", workspace, |path| {
            validate_workspace_mcp_destination(repo_root, path)?;
            ensure_workspace_mcp_git_excluded(repo_root)?;
            merge_mcp_config_with_cwd(path, repo_root)
        });
    }

    let legacy = home.join(".gemini").join("settings.json");
    if legacy.exists() {
        outcome.attempt("gemini", legacy, |path| merge_mcp_config(path));
    }
    outcome
}

fn configure_antigravity() -> AssistantConfigOutcome {
    let home = match home_dir() {
        Ok(home) => home,
        Err(error) => return AssistantConfigOutcome::failed(error.to_string()),
    };
    let repo_root = discover_setup_repo_root().ok();
    configure_antigravity_at(&home, repo_root.as_deref())
}

fn discover_setup_repo_root_from(start: &Path) -> Option<PathBuf> {
    // Setup needs a durable filesystem root for a global client config. Ignore
    // a session-scoped KIN_DAEMON_URL so it cannot turn an arbitrary cwd into
    // a synthetic layout that will be stale in the next client process.
    kin_core::KinLayout::discover_with_daemon_url(start, None)
        .map(|layout| layout.working_dir().to_path_buf())
}

fn discover_setup_repo_root() -> Result<PathBuf> {
    let current_dir = env::current_dir().context("could not determine the current directory")?;
    discover_setup_repo_root_from(&current_dir).with_context(|| {
        format!(
            "Google Antigravity workspace MCP setup needs a Kin repository cwd, but none was found from {}. The safe global fallback remains available; run `kin init` in the target repository to complete workspace setup.",
            current_dir.display()
        )
    })
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
///
/// Understands both JSON configs (`mcpServers.kin`) and TOML configs such as
/// Codex's `config.toml` (`mcp_servers.kin`).
fn has_kin_mcp_config(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        let Ok(root) = toml::from_str::<toml::Value>(&content) else {
            return false;
        };
        return root.get("mcp_servers").and_then(|s| s.get("kin")).is_some();
    }
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

fn shell_path_separator() -> &'static str {
    if cfg!(target_os = "windows") {
        ";"
    } else {
        ":"
    }
}

fn rc_path_line(shell_name: &str, bin_dir: &Path) -> String {
    match shell_name {
        "fish" => format!("fish_add_path {}", bin_dir.display()),
        "powershell" => {
            format!(
                "$env:PATH = \"{}{}$env:PATH\"",
                bin_dir.display(),
                shell_path_separator()
            )
        }
        _ => format!("export PATH=\"{}:$PATH\"", bin_dir.display()),
    }
}

fn rc_path_block(shell_name: &str, bin_dir: &Path) -> String {
    format!("\n# Kin\n{}\n", rc_path_line(shell_name, bin_dir))
}

fn rc_declares_kin_bin(content: &str, bin_dir: &Path) -> bool {
    let bin = bin_dir.to_string_lossy();
    content.contains(bin.as_ref()) || content.contains(".kin/bin") || content.contains("kin/bin")
}

fn install_shell_hook(shell_name: &str) -> Result<(PathBuf, String)> {
    let requested_home = kin_dir()?;
    let install_lock = crate::commands::update::InstallRootLock::acquire(&requested_home)?;
    // Preserve the configured spelling in shell snippets (notably macOS
    // /var -> /private/var aliases) while the lock validates the canonical root.
    let kin_home = &requested_home;
    let bin_dir = kin_home.join("bin");
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
        match copy_shim(&install_lock, &shim_path, &dest)? {
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
    let mut rc_content = if rc_path.exists() {
        fs::read_to_string(&rc_path)?
    } else {
        String::new()
    };
    let hook_installed = rc_content.contains("kin-vfs");
    let path_installed = rc_declares_kin_bin(&rc_content, &bin_dir);

    if hook_installed {
        println!(
            "  Shell rc already sources kin-vfs hook: {}",
            rc_path.display()
        );
    } else {
        if !rc_content.ends_with('\n') && !rc_content.is_empty() {
            rc_content.push('\n');
        }
        rc_content.push_str(&rc_integration_block(&source_line));
        println!("  Appended to {}", rc_path.display());
    }

    if path_installed {
        println!("  Shell rc already adds {} to PATH", bin_dir.display());
    } else {
        if !rc_content.ends_with('\n') && !rc_content.is_empty() {
            rc_content.push('\n');
        }
        rc_content.push_str(&rc_path_block(shell_name, &bin_dir));
        println!(
            "  Added {} to PATH for new shell sessions",
            bin_dir.display()
        );
    }

    if !hook_installed || !path_installed {
        if let Some(parent) = rc_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::write(&rc_path, &rc_content)
            .with_context(|| format!("failed to update {}", rc_path.display()))?;
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
    let requested_home = kin_dir()?;
    let install_lock = crate::commands::update::InstallRootLock::acquire(&requested_home)?;
    let lib_dir = install_lock.root().join("lib");
    let dest = lib_dir.join(shim_filename());

    // `find_shim` only returns non-empty candidates, so a truncated shim is
    // never re-selected as the source. `restore_shim_from_sources` copies the
    // first usable one and `copy_shim` no-ops if that source already is the
    // destination.
    let sources: Vec<PathBuf> = find_shim().into_iter().collect();
    restore_shim_from_sources(&install_lock, &dest, &sources)
}

/// Re-merge the kin MCP server entry (with the agent-default profile) into the
/// config files of every AI client that already has a config present.
///
/// Used by `kin doctor --fix` to repair `mcp_client_*` checks. Returns the
/// paths that were re-merged.
pub(crate) fn remerge_existing_mcp_configs() -> Vec<PathBuf> {
    let outcome = remerge_existing_mcp_configs_detailed();
    for error in outcome.errors {
        eprintln!("WARNING: could not refresh a Kin MCP entry: {error}");
    }
    outcome.repaired
}

/// Strict updater-facing MCP repair result. Unlike the historical convenience
/// wrapper, this preserves every per-client failure so the self-updater can
/// retain its durable repair marker until all intended merges succeed.
#[derive(Debug, Default)]
pub(crate) struct McpRemergeOutcome {
    pub(crate) repaired: Vec<PathBuf>,
    pub(crate) errors: Vec<String>,
}

pub(crate) fn remerge_existing_mcp_configs_detailed() -> McpRemergeOutcome {
    let repo_root = discover_setup_repo_root().ok();
    remerge_mcp_config_paths(
        crate::commands::health::mcp_client_config_paths(),
        is_antigravity_detected(),
        is_codex_detected(),
        repo_root.as_deref(),
    )
}

fn remerge_mcp_config_paths(
    configs: Vec<(&'static str, &'static str, PathBuf)>,
    antigravity_detected: bool,
    codex_detected: bool,
    repo_root: Option<&Path>,
) -> McpRemergeOutcome {
    let mut outcome = McpRemergeOutcome::default();
    for (id, label, path) in configs {
        // Detected clients with no config are real missing setup artifacts.
        // New global Codex/Antigravity entries are cwd-free and safe to create
        // from any directory; existing cwd policy is preserved. The workspace
        // Antigravity target additionally needs a discovered Kin repository.
        let detected_client = (matches!(id, "antigravity" | "antigravity_workspace")
            && antigravity_detected)
            || (id == "codex" && codex_detected);
        let can_create = id != "antigravity_workspace" || repo_root.is_some();
        let should_merge = path.exists() || detected_client && can_create;
        if !should_merge {
            continue;
        }
        // Codex's config.toml is TOML; every other client config is JSON.
        let merged = if id == "antigravity_workspace" {
            let Some(repo_root) = repo_root else {
                continue;
            };
            merge_mcp_config_with_cwd(&path, repo_root)
        } else if id == "codex" {
            merge_mcp_config_toml(&path, None)
        } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            merge_mcp_config_toml(&path, None)
        } else {
            merge_mcp_config(&path)
        };
        match merged {
            Ok(()) => outcome.repaired.push(path),
            Err(error) => outcome
                .errors
                .push(format!("{label} at {}: {error:#}", path.display())),
        }
    }
    outcome
}

// ---------------------------------------------------------------------------
// Setup runtime config
// ---------------------------------------------------------------------------

fn write_setup_runtime_config(auto_daemon: bool, auto_configure_repo_clients: bool) -> Result<()> {
    let kin_home = kin_dir()?;
    let config_dir = kin_home.join("config");
    fs::create_dir_all(&config_dir).context("failed to create ~/.kin/config/")?;
    let config_path = config_dir.join("setup.toml");
    let content = format!(
        "# Generated by: kin setup\n[daemon]\nauto_start = {auto_daemon}\n\n[mcp]\nauto_configure_repo_clients = {auto_configure_repo_clients}\n"
    );
    fs::write(&config_path, content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

fn auto_configure_repo_clients_enabled_at(kin_home: &Path) -> bool {
    let path = kin_home.join("config").join("setup.toml");
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    toml::from_str::<toml::Value>(&content)
        .ok()
        .and_then(|root| {
            root.get("mcp")?
                .get("auto_configure_repo_clients")?
                .as_bool()
        })
        .unwrap_or(false)
}

fn auto_configure_repo_clients_enabled() -> bool {
    kin_dir()
        .ok()
        .is_some_and(|kin_home| auto_configure_repo_clients_enabled_at(&kin_home))
}

/// Complete repo-scoped MCP setup as part of `kin init` when the earlier
/// first-run wizard selected AI-agent integration. Antigravity supports an
/// official workspace-local config; writing it here makes the installer-first
/// (`setup` then `init`) path self-healing without pinning a global launcher.
pub(crate) fn auto_configure_repo_clients_for_init(repo_root: &Path) -> Result<Vec<PathBuf>> {
    auto_configure_repo_clients_for_init_with_state(
        repo_root,
        auto_configure_repo_clients_enabled(),
        is_antigravity_detected(),
    )
}

fn auto_configure_repo_clients_for_init_with_state(
    repo_root: &Path,
    enabled: bool,
    antigravity_detected: bool,
) -> Result<Vec<PathBuf>> {
    if !enabled || !antigravity_detected {
        return Ok(Vec::new());
    }

    let absolute_repo_root = if repo_root.is_absolute() {
        repo_root.to_path_buf()
    } else {
        env::current_dir()
            .context("could not determine the current directory for repo-scoped MCP setup")?
            .join(repo_root)
    };
    let repo_root = absolute_repo_root
        .canonicalize()
        .unwrap_or(absolute_repo_root);
    let path = repo_root.join(kin_index::REPO_LOCAL_MCP_CONFIG_PATH);
    validate_workspace_mcp_destination(&repo_root, &path)?;
    ensure_workspace_mcp_git_excluded(&repo_root)?;
    merge_mcp_config_with_cwd(&path, &repo_root)?;
    if let Err(error) = record_mcp_targets_in_ledger(&[("antigravity_workspace", path.clone())]) {
        tracing::warn!(%error, "repo-scoped MCP config succeeded but ledger update failed");
        eprintln!(
            "  warning: repo-scoped MCP config was written, but its install ledger entry failed: {error}"
        );
    }
    Ok(vec![path])
}

const WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS: &[&str] =
    &["/.agents/mcp_config.json", "/.agents/.kin-mcp-config-*"];

fn validate_workspace_mcp_destination(repo_root: &Path, path: &Path) -> Result<()> {
    let canonical_repo = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());

    if let Some(parent) = path.parent() {
        if let Ok(canonical_parent) = parent.canonicalize() {
            if let Ok(relative_parent) = canonical_parent.strip_prefix(&canonical_repo) {
                if relative_parent != Path::new(".agents") {
                    anyhow::bail!(
                        "workspace MCP config parent {} resolves to graph-admissible repo path {}; replace the in-repo symlink before setup",
                        parent.display(),
                        relative_parent.display()
                    );
                }
            }
        }
    }

    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        let target = path.canonicalize().with_context(|| {
            format!(
                "workspace MCP config symlink {} does not resolve",
                path.display()
            )
        })?;
        if let Ok(relative_target) = target.strip_prefix(&canonical_repo) {
            if kin_index::should_index_repo_relative_path(relative_target) {
                anyhow::bail!(
                    "workspace MCP config {} resolves to graph-admissible repo path {}; use a checkout-local or external target",
                    path.display(),
                    relative_target.display()
                );
            }
        }
    }

    Ok(())
}

fn ensure_workspace_mcp_git_excluded(repo_root: &Path) -> Result<Option<PathBuf>> {
    let dot_git = repo_root.join(".git");
    let metadata = match fs::metadata(&dot_git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", dot_git.display()))
        }
    };

    let git_dir = if metadata.is_dir() {
        dot_git
    } else if metadata.is_file() {
        let pointer = fs::read_to_string(&dot_git).with_context(|| {
            format!("failed to read Git directory pointer {}", dot_git.display())
        })?;
        let target = pointer
            .trim()
            .strip_prefix("gitdir:")
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .with_context(|| format!("invalid Git directory pointer {}", dot_git.display()))?;
        let target = PathBuf::from(target);
        if target.is_absolute() {
            target
        } else {
            repo_root.join(target)
        }
    } else {
        return Ok(None);
    };

    let common_dir_pointer = git_dir.join("commondir");
    let common_dir = match fs::read_to_string(&common_dir_pointer) {
        Ok(pointer) => {
            let target = PathBuf::from(pointer.trim());
            if target.is_absolute() {
                target
            } else {
                git_dir.join(target)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => git_dir,
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to read Git common-directory pointer {}",
                    common_dir_pointer.display()
                )
            })
        }
    };

    let exclude = common_dir.join("info").join("exclude");
    let content = match fs::read_to_string(&exclude) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to read Git exclude {}", exclude.display()))
        }
    };
    // Git applies the last matching rule. Remove only Kin's exact positive
    // rules, preserve every user-authored byte, then append ours at EOF so a
    // preceding negation cannot expose checkout-local state.
    let mut updated: String = content
        .split_inclusive('\n')
        .filter(|line| {
            let trimmed = line.trim();
            !WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS.contains(&trimmed)
                && trimmed != kin_index::REPO_LOCAL_MCP_CONFIG_PATH
        })
        .collect();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    for pattern in WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS {
        updated.push_str(pattern);
        updated.push('\n');
    }
    if updated != content {
        write_config_atomically(&exclude, updated.as_bytes())?;
    }
    Ok(Some(exclude))
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
    let mut configured_mcp_targets: Vec<(&'static str, PathBuf)> = Vec::new();
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
            let Some(outcome) = configure_assistant_by_index(*idx) else {
                continue;
            };
            let primary_path = outcome.configured.first().map(|(_, path)| path.clone());
            if let Some(path) = &primary_path {
                for (target, configured_path) in &outcome.configured {
                    println!(
                        "  {} {} configured [{}] ({})",
                        style("✓").green(),
                        a.name,
                        target,
                        configured_path.display()
                    );
                }
                configured_assistants.push((a.name.to_string(), Some(path.clone())));
                configured_mcp_targets.extend(outcome.configured);
            } else {
                configured_assistants.push((a.name.to_string(), None));
            }
            for error in outcome.errors {
                println!(
                    "  {} {} configuration failed: {error}",
                    style("✗").red(),
                    a.name
                );
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
    write_setup_runtime_config(plan.auto_daemon, plan.configure_mcp)?;
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
    record_setup_ledger(plan, shell_name, &configured_mcp_targets);

    Ok(configured_assistants)
}

/// Read the kin MCP server sub-value from a client config, if present.
///
/// Handles both JSON configs (`mcpServers.kin`) and TOML configs such as
/// Codex's `config.toml` (`mcp_servers.kin`), normalizing the entry to JSON
/// for the install ledger.
fn read_kin_mcp_entry(path: &Path) -> Option<serde_json::Value> {
    let content = fs::read_to_string(path).ok()?;
    if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        let root: toml::Value = toml::from_str(&content).ok()?;
        let entry = root.get("mcp_servers")?.get("kin")?;
        return serde_json::to_value(entry).ok();
    }
    let root: serde_json::Value = serde_json::from_str(&content).ok()?;
    root.get("mcpServers")?.get("kin").cloned()
}

/// Record everything the applied [`SetupPlan`] wrote into the install ledger.
///
/// Re-derives each artifact from final on-disk state and upserts it, preserving
/// original install timestamps across idempotent re-runs. Ledger failures are
/// non-fatal: setup already succeeded, so a ledger write error is a warning, not
/// a setup failure.
fn record_setup_ledger(
    plan: &SetupPlan,
    shell_name: &str,
    configured_mcp_targets: &[(&'static str, PathBuf)],
) {
    use crate::commands::setup_ledger::{ArtifactKind, LedgerEntry, SetupLedger};

    let Ok(ledger_path) = crate::commands::setup_ledger::ledger_path() else {
        return;
    };
    let mut ledger = match SetupLedger::load(&ledger_path) {
        Ok(ledger) => ledger,
        Err(error) => {
            println!(
                "  {} could not load install ledger without risking existing records: {error}",
                style("!").yellow()
            );
            return;
        }
    };

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
                        rc_path.clone(),
                        block,
                    ));
                }

                let bin_dir = kin_home.join("bin");
                let path_block = rc_path_block(shell_name, &bin_dir);
                let path_present = fs::read_to_string(&rc_path)
                    .map(|c| c.contains(&path_block))
                    .unwrap_or(false);
                if path_present {
                    ledger.record(LedgerEntry::appended(
                        ArtifactKind::ShellPathLine,
                        format!("{shell_name}-path"),
                        rc_path,
                        path_block,
                    ));
                }
            }
        }
    }

    if plan.configure_mcp {
        for (target, path) in configured_mcp_targets {
            if let Some(kin_entry) = read_kin_mcp_entry(path) {
                ledger.record(LedgerEntry::mcp(*target, path.clone(), &kin_entry));
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

fn record_mcp_targets_in_ledger(targets: &[(&'static str, PathBuf)]) -> Result<()> {
    use crate::commands::setup_ledger::{LedgerEntry, SetupLedger};

    let ledger_path = crate::commands::setup_ledger::ledger_path()?;
    let mut ledger = SetupLedger::load(&ledger_path)?;
    for (target, path) in targets {
        let kin_entry = read_kin_mcp_entry(path).with_context(|| {
            format!(
                "configured MCP target {} has no readable Kin entry",
                path.display()
            )
        })?;
        ledger.record(LedgerEntry::mcp(*target, path.clone(), &kin_entry));
    }
    ledger.save(&ledger_path)
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
        IDX_CODEX => Some(home.join(".codex").join("config.toml")),
        IDX_ANTIGRAVITY => Some(home.join(".gemini").join("config").join("mcp_config.json")),
        IDX_WINDSURF => Some(
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
        ),
        _ => None,
    }
}

/// Run the matching `configure_*` for an assistant index. Each target records
/// success independently so a later target failure can never make the install
/// ledger claim a config slice this setup invocation did not write.
fn configure_assistant_by_index(idx: usize) -> Option<AssistantConfigOutcome> {
    match idx {
        IDX_CLAUDE_CODE => Some(AssistantConfigOutcome::from_single(
            "claude",
            configure_claude_code(),
        )),
        IDX_CURSOR => Some(AssistantConfigOutcome::from_single(
            "cursor",
            configure_cursor(),
        )),
        IDX_CODEX => Some(AssistantConfigOutcome::from_single(
            "codex",
            configure_codex(),
        )),
        IDX_ANTIGRAVITY => Some(configure_antigravity()),
        IDX_WINDSURF => Some(AssistantConfigOutcome::from_single(
            "windsurf",
            configure_windsurf(),
        )),
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

    // Repair the VFS shim when it is missing, truncated to 0 bytes, or corrupt.
    // Try a local copy first; a standalone binary (no sibling shim, no ledger
    // source) has none, so fall back to downloading the shim from the release
    // that matches THIS binary's version. Only if both fail do we print a manual
    // step — and never one that points back at `kin doctor --fix` (FIR-1409).
    let vfs_needs_fix = report.checks.iter().any(|c| {
        c.id == "vfs_projection"
            && c.fixable
            && !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
    });
    if vfs_needs_fix {
        match reinstall_vfs_shim() {
            Ok(Some(dest)) => applied.push(format!(
                "reinstalled VFS shim from a local copy ({})",
                dest.display()
            )),
            Ok(None) => {
                // No local shim source. Fetch the shim from the matching release.
                println!(
                    "  No local VFS shim found; fetching it from the v{} release...",
                    env!("CARGO_PKG_VERSION")
                );
                match crate::commands::update::download_shim_for_current_version().await {
                    Ok(dest) => applied.push(format!(
                        "downloaded the VFS shim from the v{} release ({})",
                        env!("CARGO_PKG_VERSION"),
                        dest.display()
                    )),
                    Err(e) => {
                        println!(
                            "  {} could not restore the VFS shim automatically: {e}",
                            style("✗").red()
                        );
                        println!(
                            "      reinstall kin to restore it: \
                             curl -fsSL https://get.kinlab.dev/install | sh"
                        );
                    }
                }
            }
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
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};

    struct EnvGuard {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = env::var_os(key);
            env::set_var(key, value.as_ref());
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = env::var_os(key);
            env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => env::set_var(self.key, value),
                None => env::remove_var(self.key),
            }
        }
    }

    fn opts() -> WizardOptions {
        WizardOptions {
            mode: None,
            shell: Some("zsh".to_string()),
            auto_daemon: false,
            no_interactive: true,
            intent: None,
        }
    }

    fn write_executable(path: &Path) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"launcher").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    #[test]
    fn mcp_launcher_prefers_managed_path_over_versioned_current_exe() {
        let dir = tempfile::tempdir().unwrap();
        let managed = dir.path().join("home/.kin/bin/kin");
        let path_launcher = dir.path().join("opt/homebrew/bin/kin");
        let cellar_current = dir.path().join("opt/homebrew/Cellar/kin/0.2.21/bin/kin");
        for path in [&managed, &path_launcher, &cellar_current] {
            write_executable(path);
        }

        let command = select_kin_mcp_launcher(
            Some(managed.clone()),
            Some(path_launcher),
            Some(cellar_current.clone()),
        );
        let entry = kin_mcp_entry_for_command(command, None);

        assert_eq!(entry["command"], managed.to_string_lossy().as_ref());
        assert_ne!(entry["command"], cellar_current.to_string_lossy().as_ref());
        assert!(Path::new(entry["command"].as_str().unwrap()).is_absolute());
    }

    #[test]
    fn mcp_launcher_prefers_path_launcher_over_target_current_exe() {
        let dir = tempfile::tempdir().unwrap();
        let missing_managed = dir.path().join("home/.kin/bin/kin");
        let path_launcher = dir.path().join("opt/homebrew/bin/kin");
        let target_current = dir.path().join("checkout/target/release/kin");
        for path in [&path_launcher, &target_current] {
            write_executable(path);
        }

        let command = select_kin_mcp_launcher(
            Some(missing_managed),
            Some(path_launcher.clone()),
            Some(target_current.clone()),
        );
        let entry = kin_mcp_entry_for_command(command, None);

        assert_eq!(entry["command"], path_launcher.to_string_lossy().as_ref());
        assert_ne!(entry["command"], target_current.to_string_lossy().as_ref());
        assert!(Path::new(entry["command"].as_str().unwrap()).is_absolute());
    }

    #[cfg(unix)]
    #[test]
    fn mcp_launcher_keeps_stable_symlink_instead_of_cellar_target() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let cellar_target = dir.path().join("opt/homebrew/Cellar/kin/0.2.21/bin/kin");
        let stable_launcher = dir.path().join("opt/homebrew/bin/kin");
        write_executable(&cellar_target);
        fs::create_dir_all(stable_launcher.parent().unwrap()).unwrap();
        symlink(&cellar_target, &stable_launcher).unwrap();

        let command = select_kin_mcp_launcher(
            None,
            Some(stable_launcher.clone()),
            Some(cellar_target.clone()),
        );

        assert_eq!(command, stable_launcher.to_string_lossy());
        assert_ne!(command, cellar_target.to_string_lossy());
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
    fn restore_shim_repairs_a_zeroed_shim_from_a_usable_source() {
        // FIR-1409 repair path: a deliberately-zeroed shim + a usable source is
        // restored to the real bytes.
        let tmp = tempfile::tempdir().unwrap();
        let install_lock = crate::commands::update::InstallRootLock::acquire(tmp.path()).unwrap();
        let source = tmp.path().join("source-shim");
        fs::write(&source, b"\xCF\xFA\xED\xFEreal-shim-bytes").unwrap();
        let dest = tmp.path().join("lib").join(shim_filename());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, b"").unwrap(); // the 0-byte crash hazard

        let restored =
            restore_shim_from_sources(&install_lock, &dest, std::slice::from_ref(&source)).unwrap();
        assert_eq!(restored.as_deref(), Some(dest.as_path()));
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"\xCF\xFA\xED\xFEreal-shim-bytes",
            "dest must hold the source bytes after repair"
        );
    }

    #[test]
    fn restore_shim_reports_none_when_no_usable_source_exists() {
        // FIR-1409 honest path: with no usable source, the repair reports None
        // (so the caller escalates / prints a manual step) and never fabricates
        // content over the zeroed shim.
        let tmp = tempfile::tempdir().unwrap();
        let install_lock = crate::commands::update::InstallRootLock::acquire(tmp.path()).unwrap();
        let empty = tmp.path().join("empty-source");
        fs::write(&empty, b"").unwrap();
        let missing = tmp.path().join("missing-source");
        let dest = tmp.path().join("lib").join(shim_filename());
        fs::write(&dest, b"").unwrap();

        let restored = restore_shim_from_sources(&install_lock, &dest, &[empty, missing]).unwrap();
        assert!(restored.is_none(), "no usable source must yield None");
        assert_eq!(
            fs::metadata(&dest).unwrap().len(),
            0,
            "dest must stay untouched when there is nothing to copy"
        );
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
        let install_lock = crate::commands::update::InstallRootLock::acquire(tmp.path()).unwrap();
        let lib = tmp.path().join("lib");
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&lib).unwrap();
        fs::create_dir_all(&bin).unwrap();
        let dest = lib.join(shim_filename());
        fs::write(&dest, b"REAL_SHIM_BYTES").unwrap();
        let aliased_src = bin.join("..").join("lib").join(shim_filename());

        assert_eq!(
            copy_shim(&install_lock, &aliased_src, &dest).unwrap(),
            ShimCopy::Skipped
        );
        assert_eq!(fs::read(&dest).unwrap(), b"REAL_SHIM_BYTES");
    }

    #[test]
    fn copy_shim_copies_a_distinct_source() {
        let tmp = tempfile::tempdir().unwrap();
        let install_lock = crate::commands::update::InstallRootLock::acquire(tmp.path()).unwrap();
        let src = tmp.path().join("source.dylib");
        fs::write(&src, b"SOURCE_BYTES").unwrap();
        let dest = tmp.path().join("lib").join(shim_filename());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();

        assert_eq!(
            copy_shim(&install_lock, &src, &dest).unwrap(),
            ShimCopy::Copied
        );
        assert_eq!(fs::read(&dest).unwrap(), b"SOURCE_BYTES");
    }

    #[test]
    #[serial]
    fn find_shim_checks_managed_kin_home_lib() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let shim = kin_home.join("lib").join(shim_filename());
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&shim, b"MANAGED_SHIM").unwrap();

        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvGuard::remove("KIN_DIR");

        assert_eq!(find_shim().as_deref(), Some(shim.as_path()));
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
    fn shell_hooks_respect_custom_kin_home() {
        let posix_home = r#"${KIN_HOME:-${KIN_DIR:-$HOME/.kin}}"#;
        assert!(ZSH_HOOK.contains(posix_home));
        assert!(BASH_HOOK.contains(posix_home));
        assert!(FISH_HOOK.contains("if set -q KIN_DIR"));
        assert!(FISH_HOOK.contains("if set -q KIN_HOME"));
        assert!(FISH_HOOK.contains("\"$kin_home/lib/libkin_vfs_shim\""));
    }

    #[test]
    fn rc_path_line_uses_shell_appropriate_syntax() {
        let bin = Path::new("/tmp/kin-home/bin");
        assert_eq!(
            rc_path_line("zsh", bin),
            "export PATH=\"/tmp/kin-home/bin:$PATH\""
        );
        assert_eq!(
            rc_path_line("bash", bin),
            "export PATH=\"/tmp/kin-home/bin:$PATH\""
        );
        assert_eq!(rc_path_line("fish", bin), "fish_add_path /tmp/kin-home/bin");
        assert!(rc_path_line("powershell", bin).contains("$env:PATH"));
    }

    #[test]
    #[serial]
    fn kin_dir_honors_kin_home_before_kin_dir() {
        let _kin_home = EnvGuard::remove("KIN_HOME");
        let _kin_dir = EnvGuard::remove("KIN_DIR");
        let fallback = PathBuf::from("/tmp/kin-dir-only");
        let preferred = PathBuf::from("/tmp/kin-home-preferred");

        env::set_var("KIN_DIR", &fallback);
        assert_eq!(kin_dir().unwrap(), fallback);

        env::set_var("KIN_HOME", &preferred);
        assert_eq!(kin_dir().unwrap(), preferred);
    }

    #[test]
    #[serial]
    fn install_shell_hook_adds_path_and_hook_blocks_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(&home).unwrap();

        let _home = EnvGuard::set("HOME", &home);
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvGuard::remove("KIN_DIR");
        let _path = EnvGuard::set("PATH", "/usr/bin");

        install_shell_hook("zsh").unwrap();
        install_shell_hook("zsh").unwrap();

        let rc = fs::read_to_string(home.join(".zshrc")).unwrap();
        let path_line = rc_path_line("zsh", &kin_home.join("bin"));

        assert_eq!(
            rc.matches("kin-vfs.zsh").count(),
            1,
            "setup must not duplicate the shell hook source line"
        );
        assert_eq!(
            rc.matches(&path_line).count(),
            1,
            "setup must not duplicate the Kin PATH line"
        );
        assert!(
            fs::read_to_string(kin_home.join("shell").join("kin-vfs.zsh"))
                .unwrap()
                .contains(r#"${KIN_HOME:-${KIN_DIR:-$HOME/.kin}}"#),
            "installed hook must resolve the active Kin home"
        );
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
    fn antigravity_detection_recognizes_current_cli_names_only() {
        let tmp = tempfile::tempdir().unwrap();

        assert!(antigravity_detected_at(
            Some(tmp.path()),
            tmp.path(),
            |name| name == "agy"
        ));
        assert!(antigravity_detected_at(
            Some(tmp.path()),
            tmp.path(),
            |name| name == "agy-ide"
        ));
        assert!(
            !antigravity_detected_at(Some(tmp.path()), tmp.path(), |name| name == "gemini"),
            "the retired Gemini CLI must not masquerade as Antigravity"
        );
    }

    #[test]
    fn antigravity_detection_recognizes_default_cli_and_macos_app_locations() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let applications = tmp.path().join("Applications");
        fs::create_dir_all(home.join(".local").join("bin")).unwrap();
        fs::write(home.join(".local").join("bin").join("agy"), b"binary").unwrap();

        assert!(antigravity_detected_at(Some(&home), &applications, |_| {
            false
        }));

        fs::remove_file(home.join(".local").join("bin").join("agy")).unwrap();
        fs::create_dir_all(applications.join("Antigravity IDE.app")).unwrap();
        assert!(antigravity_detected_at(Some(&home), &applications, |_| {
            false
        }));
    }

    #[test]
    fn configure_antigravity_writes_global_and_workspace_configs_without_losing_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let legacy = home.join(".gemini").join("settings.json");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        fs::write(
            &legacy,
            r#"{"theme":"dark","mcpServers":{"other":{"command":"other"}}}"#,
        )
        .unwrap();

        let primary = home.join(".gemini").join("config").join("mcp_config.json");
        fs::create_dir_all(primary.parent().unwrap()).unwrap();
        fs::write(
            &primary,
            r#"{"userSetting":true,"mcpServers":{"other":{"command":"other"},"kin":{"command":"old","args":["old"],"cwd":"/stale/repo","disabled":true,"disabledTools":["semantic_locate"],"futurePolicy":"keep","env":{"KEEP_ME":"yes"}}}}"#,
        )
        .unwrap();

        let outcome = configure_antigravity_at(&home, Some(&repo));
        assert!(outcome.errors.is_empty(), "errors: {:?}", outcome.errors);
        let workspace = repo.join(".agents").join("mcp_config.json");
        assert_eq!(
            outcome.configured,
            vec![
                ("antigravity", primary.clone()),
                ("antigravity_workspace", workspace.clone()),
                ("gemini", legacy.clone()),
            ]
        );

        let primary_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&primary).unwrap()).unwrap();
        let kin = &primary_json["mcpServers"]["kin"];
        assert!(
            kin["command"]
                .as_str()
                .is_some_and(|command| !command.is_empty()),
            "Antigravity stdio config must name a Kin executable"
        );
        assert_eq!(kin["args"], serde_json::json!(["mcp", "start"]));
        assert_eq!(kin["env"]["KIN_MCP_TOOL_PROFILE"], "agent-default");
        assert_eq!(kin["cwd"], "/stale/repo");
        assert_eq!(kin["disabled"], true);
        assert_eq!(kin["disabledTools"], serde_json::json!(["semantic_locate"]));
        assert_eq!(kin["futurePolicy"], "keep");
        assert_eq!(kin["env"]["KEEP_ME"], "yes");
        assert_eq!(primary_json["userSetting"], true);
        assert_eq!(primary_json["mcpServers"]["other"]["command"], "other");

        let workspace_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&workspace).unwrap()).unwrap();
        assert_eq!(
            workspace_json["mcpServers"]["kin"]["cwd"],
            repo.to_string_lossy().as_ref()
        );

        let legacy_json: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&legacy).unwrap()).unwrap();
        assert_eq!(legacy_json["theme"], "dark");
        assert_eq!(legacy_json["mcpServers"]["other"]["command"], "other");
        assert!(legacy_json["mcpServers"]["kin"].is_object());
        assert!(legacy_json["mcpServers"]["kin"].get("cwd").is_none());
    }

    #[test]
    fn configure_antigravity_before_init_creates_only_a_safe_global_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let repo = tmp.path().join("repo");
        let outcome = configure_antigravity_at(&home, None);
        let primary = home.join(".gemini").join("config").join("mcp_config.json");

        assert!(outcome.errors.is_empty(), "errors: {:?}", outcome.errors);
        assert_eq!(outcome.configured, vec![("antigravity", primary.clone())]);
        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&primary).unwrap()).unwrap();
        assert!(root["mcpServers"]["kin"].get("cwd").is_none());
        assert!(!home.join(".gemini").join("settings.json").exists());
        assert!(!repo.join(".agents").join("mcp_config.json").exists());
    }

    #[test]
    fn workspace_mcp_git_exclude_uses_common_dir_and_is_idempotent() {
        use std::process::Command;

        let tmp = tempfile::tempdir().unwrap();
        let main = tmp.path().join("main");
        let linked = tmp.path().join("linked");

        let run_git = |cwd: &Path, args: &[&str]| {
            let output = Command::new("git")
                .args(args)
                .current_dir(cwd)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {args:?} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };

        fs::create_dir_all(&main).unwrap();
        run_git(&main, &["init"]);
        run_git(&main, &["config", "user.email", "kin-tests@example.com"]);
        run_git(&main, &["config", "user.name", "Kin Tests"]);
        fs::write(main.join("README.md"), "seed\n").unwrap();
        run_git(&main, &["add", "README.md"]);
        run_git(&main, &["commit", "-m", "seed"]);

        let output = Command::new("git")
            .args(["worktree", "add", "--detach"])
            .arg(&linked)
            .current_dir(&main)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let common_exclude = main.join(".git/info/exclude");
        let mut original = fs::read_to_string(&common_exclude).unwrap_or_default();
        original.push_str("\nkeep.local\n!/.agents/mcp_config.json\n!/.agents/*\n");
        fs::write(&common_exclude, &original).unwrap();

        let first = ensure_workspace_mcp_git_excluded(&linked)
            .unwrap()
            .expect("linked worktree should resolve a Git exclude");
        let second = ensure_workspace_mcp_git_excluded(&linked).unwrap().unwrap();
        assert_eq!(first, second);

        fs::create_dir_all(linked.join(".agents")).unwrap();
        fs::write(linked.join(kin_index::REPO_LOCAL_MCP_CONFIG_PATH), "{}").unwrap();
        let check = Command::new("git")
            .args(["check-ignore", "-q", "--"])
            .arg(kin_index::REPO_LOCAL_MCP_CONFIG_PATH)
            .current_dir(&linked)
            .status()
            .unwrap();
        assert!(check.success(), "workspace MCP config is not Git-ignored");

        let content = fs::read_to_string(common_exclude).unwrap();
        assert!(content.contains("keep.local"));
        for pattern in WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS {
            assert_eq!(
                content
                    .lines()
                    .filter(|line| line.trim() == *pattern)
                    .count(),
                1
            );
        }
        assert!(
            content.rfind("/.agents/mcp_config.json").unwrap()
                > content.rfind("!/.agents/mcp_config.json").unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_mcp_rejects_graph_admissible_in_repo_symlink_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let home = tmp.path().join("home");
        fs::create_dir_all(repo.join(".agents")).unwrap();
        fs::create_dir_all(repo.join("config")).unwrap();
        let target = repo.join("config/local-mcp.json");
        fs::write(&target, "keep\n").unwrap();
        symlink(&target, repo.join(kin_index::REPO_LOCAL_MCP_CONFIG_PATH)).unwrap();

        let outcome = configure_antigravity_at(&home, Some(&repo));

        assert!(outcome
            .errors
            .iter()
            .any(|error| error.contains("graph-admissible repo path")));
        assert_eq!(fs::read_to_string(target).unwrap(), "keep\n");
    }

    #[test]
    #[serial]
    fn init_auto_configures_workspace_antigravity_and_records_the_success() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);

        write_setup_runtime_config(false, true).unwrap();
        assert!(auto_configure_repo_clients_enabled_at(&kin_home));

        let configured =
            auto_configure_repo_clients_for_init_with_state(&repo, true, true).unwrap();
        let canonical_repo = repo.canonicalize().unwrap();
        let workspace = canonical_repo.join(".agents").join("mcp_config.json");
        assert_eq!(configured, vec![workspace.clone()]);

        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&workspace).unwrap()).unwrap();
        assert_eq!(
            root["mcpServers"]["kin"]["cwd"],
            canonical_repo.to_string_lossy().as_ref()
        );

        let ledger_path = crate::commands::setup_ledger::ledger_path().unwrap();
        let ledger = crate::commands::setup_ledger::SetupLedger::load(&ledger_path).unwrap();
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].target, "antigravity_workspace");
        assert_eq!(ledger.entries[0].path, workspace);
    }

    #[test]
    #[serial]
    fn antigravity_ledger_records_only_targets_that_were_written() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(&repo).unwrap();
        fs::write(repo.join(".agents"), "blocks workspace directory").unwrap();
        let _kin_home = EnvGuard::set("KIN_HOME", &kin_home);

        let outcome = configure_antigravity_at(&home, Some(&repo));
        assert_eq!(outcome.configured.len(), 1);
        assert_eq!(outcome.configured[0].0, "antigravity");
        assert_eq!(outcome.errors.len(), 1);

        record_mcp_targets_in_ledger(&outcome.configured).unwrap();
        let ledger_path = crate::commands::setup_ledger::ledger_path().unwrap();
        let ledger = crate::commands::setup_ledger::SetupLedger::load(&ledger_path).unwrap();
        assert_eq!(ledger.entries.len(), 1);
        assert_eq!(ledger.entries[0].target, "antigravity");
        assert!(ledger
            .entries
            .iter()
            .all(|entry| entry.target != "antigravity_workspace"));
    }

    #[test]
    fn antigravity_cwd_is_discovered_from_the_kin_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("repo");
        let nested = repo.join("src").join("nested");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        fs::create_dir_all(&nested).unwrap();

        assert_eq!(discover_setup_repo_root_from(&nested), Some(repo));
    }

    #[test]
    fn doctor_remerge_creates_safe_global_config_for_detected_antigravity() {
        let tmp = tempfile::tempdir().unwrap();
        let primary = tmp
            .path()
            .join(".gemini")
            .join("config")
            .join("mcp_config.json");
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repaired = remerge_mcp_config_paths(
            vec![("antigravity", "Google Antigravity", primary.clone())],
            true,
            false,
            Some(&repo),
        );

        assert_eq!(repaired.repaired, vec![primary.clone()]);
        assert!(has_kin_mcp_config(&primary));
        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&primary).unwrap()).unwrap();
        assert!(root["mcpServers"]["kin"].get("cwd").is_none());
    }

    #[test]
    fn doctor_remerge_preserves_user_owned_cwd_in_existing_codex_config() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(".codex").join("config.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            "model = \"o3\"\n[mcp_servers.kin]\ncommand = \"kin\"\nargs = [\"mcp\", \"start\"]\ncwd = \"/stale/repo\"\nenv = { KIN_MCP_TOOL_PROFILE = \"agent-default\" }\n",
        )
        .unwrap();
        let repo = tmp.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();

        let repaired = remerge_mcp_config_paths(
            vec![("codex", "Codex CLI", path.clone())],
            false,
            true,
            Some(&repo),
        );

        assert_eq!(repaired.repaired, vec![path.clone()]);
        let root: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(root["model"].as_str(), Some("o3"));
        assert_eq!(
            root["mcp_servers"]["kin"]["cwd"].as_str(),
            Some("/stale/repo")
        );
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

    #[test]
    fn merge_mcp_config_refuses_incompatible_existing_kin_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"mcpServers":{"kin":"user-owned-value"}}"#).unwrap();
        let original = std::fs::read(&path).unwrap();

        let error = merge_mcp_config(&path).unwrap_err().to_string();

        assert!(error.contains("non-object mcpServers.kin"));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn atomic_config_failure_leaves_original_bytes_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let original = b"{\"keep\":true}\n";
        fs::write(&path, original).unwrap();

        let error = write_config_atomically_with(&path, b"replacement", |_temp, _destination| {
            Err(io::Error::other("forced persist failure"))
        })
        .unwrap_err()
        .to_string();

        assert!(error.contains("atomically replace"));
        assert_eq!(fs::read(&path).unwrap(), original);
        let sibling_names: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(sibling_names, vec![OsString::from("config.json")]);
    }

    #[cfg(unix)]
    #[test]
    fn json_config_atomic_replace_preserves_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"existingKey":true}"#).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        merge_mcp_config(&path).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(root["mcpServers"]["kin"].is_object());
    }

    #[test]
    fn merge_mcp_config_toml_refuses_to_overwrite_corrupt_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"this is not toml [[[").unwrap();

        let original = std::fs::read(&path).unwrap();
        let err = merge_mcp_config_toml(&path, None).unwrap_err();
        let msg = err.to_string();

        assert!(
            msg.contains("not valid TOML"),
            "expected 'not valid TOML' in error, got: {msg}"
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

    #[cfg(unix)]
    #[test]
    fn toml_config_atomic_replace_preserves_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "model = \"o3\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        merge_mcp_config_toml(&path, None).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let root: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(root["mcp_servers"]["kin"].is_table());
        assert!(root["mcp_servers"]["kin"].get("cwd").is_none());
    }

    #[test]
    fn new_global_codex_entry_omits_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let path = configure_codex_at(&home).unwrap();

        let root: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        assert!(root["mcp_servers"]["kin"].get("cwd").is_none());
    }

    #[test]
    fn configure_codex_preserves_existing_cwd_and_other_user_policy() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let path = home.join(".codex").join("config.toml");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "# user settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"other-server\"\n\n[mcp_servers.kin]\ncommand = \"old\"\nargs = [\"old\"]\ncwd = \"/stale/repo\"\ndisabled = true\nfuture_policy = \"keep\"\nenv = { KEEP_ME = \"yes\", KIN_MCP_TOOL_PROFILE = \"old\" }\n",
        )
        .unwrap();

        assert_eq!(configure_codex_at(&home).unwrap(), path);

        let content = std::fs::read_to_string(&path).unwrap();
        let root: toml::Value = toml::from_str(&content).unwrap();
        assert_eq!(
            root.get("model").and_then(|v| v.as_str()),
            Some("o3"),
            "unrelated keys must be preserved"
        );
        assert!(
            content.contains("# user settings"),
            "comments must be preserved"
        );
        assert_eq!(
            root["mcp_servers"]["other"]["command"].as_str(),
            Some("other-server"),
            "other MCP servers must be preserved"
        );
        let kin = &root["mcp_servers"]["kin"];
        assert!(kin.get("command").is_some(), "kin entry must be added");
        assert_eq!(
            kin["args"].as_array().map(|a| a.len()),
            Some(2),
            "kin args must be [mcp, start]"
        );
        assert_eq!(kin["cwd"].as_str(), Some("/stale/repo"));
        assert_eq!(kin["disabled"].as_bool(), Some(true));
        assert_eq!(kin["future_policy"].as_str(), Some("keep"));
        assert_eq!(kin["env"]["KEEP_ME"].as_str(), Some("yes"));
        assert_eq!(
            kin["env"]["KIN_MCP_TOOL_PROFILE"].as_str(),
            Some("agent-default"),
            "agent-default profile must be set"
        );
    }

    #[test]
    fn merge_mcp_config_toml_creates_missing_file_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(".codex").join("config.toml");
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();

        merge_mcp_config_toml(&path, Some(&repo)).unwrap();
        merge_mcp_config_toml(&path, Some(&repo)).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let root: toml::Value = toml::from_str(&content).unwrap();
        assert!(
            root["mcp_servers"]["kin"].get("command").is_some(),
            "kin entry must exist"
        );
        assert_eq!(
            content.matches("[mcp_servers.kin]").count(),
            1,
            "re-running must not duplicate the kin table"
        );
        assert!(
            has_kin_mcp_config(&path),
            "TOML-aware config check must see the entry"
        );
        let ledger_entry = read_kin_mcp_entry(&path).expect("ledger read must parse TOML");
        assert_eq!(
            ledger_entry["env"]["KIN_MCP_TOOL_PROFILE"], "agent-default",
            "ledger entry must normalize the TOML entry to JSON"
        );
        assert_eq!(ledger_entry["cwd"], repo.to_string_lossy().as_ref());
    }

    #[test]
    fn merge_mcp_config_toml_preserves_inline_cwd_and_other_user_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "mcp_servers = { other = { command = \"other\" }, kin = { command = \"old\", args = [\"old\"], cwd = \"/stale/repo\", disabled = true, future_policy = \"keep\", env = { KEEP_ME = \"yes\" } } }\n",
        )
        .unwrap();

        merge_mcp_config_toml(&path, None).unwrap();

        let root: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let kin = &root["mcp_servers"]["kin"];
        assert_eq!(kin["cwd"].as_str(), Some("/stale/repo"));
        assert_eq!(kin["disabled"].as_bool(), Some(true));
        assert_eq!(kin["future_policy"].as_str(), Some("keep"));
        assert_eq!(kin["env"]["KEEP_ME"].as_str(), Some("yes"));
        assert_eq!(
            kin["env"]["KIN_MCP_TOOL_PROFILE"].as_str(),
            Some("agent-default")
        );
        assert_eq!(
            root["mcp_servers"]["other"]["command"].as_str(),
            Some("other")
        );
    }
}
