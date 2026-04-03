// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use console::style;
use dialoguer::MultiSelect;
use std::env;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Write as _};
use std::path::PathBuf;

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
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn home_dir() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .context("could not determine home directory")
}

fn kin_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".kin"))
}

fn shim_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkin_vfs_shim.dylib"
    } else if cfg!(target_os = "windows") {
        "kin_vfs_shim.dll"
    } else {
        "libkin_vfs_shim.so"
    }
}

fn find_shim() -> Option<PathBuf> {
    let name = shim_filename();

    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
            let lib_candidate = dir.join("../lib").join(name);
            if lib_candidate.exists() {
                return Some(lib_candidate);
            }
        }
    }

    if let Ok(cargo_home) = env::var("CARGO_HOME") {
        let candidate = PathBuf::from(&cargo_home).join("lib").join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    let cwd_candidate = PathBuf::from("target/release").join(name);
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    let cwd_debug = PathBuf::from("target/debug").join(name);
    if cwd_debug.exists() {
        return Some(cwd_debug);
    }

    None
}

fn detect_shell() -> &'static str {
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

fn shell_rc(shell: &str) -> Result<PathBuf> {
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

fn hook_filename(shell: &str) -> &'static str {
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

fn check_binary_in_path(name: &str) -> Option<PathBuf> {
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
fn kin_mcp_entry() -> serde_json::Value {
    serde_json::json!({
        "command": "kin",
        "args": ["mcp", "start", "--global"]
    })
}

/// Describes an AI assistant we can auto-configure.
struct AiAssistant {
    name: &'static str,
    detected: bool,
    install_hint: &'static str,
}

fn detect_ai_assistants() -> Vec<AiAssistant> {
    let claude_detected = check_binary_in_path("claude").is_some();
    let cursor_detected = check_binary_in_path("cursor").is_some()
        || PathBuf::from("/Applications/Cursor.app").exists();
    let codex_detected = check_binary_in_path("codex").is_some();

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
    ]
}

/// Read a JSON file, or return an empty object if it doesn't exist / is invalid.
fn read_json_file(path: &PathBuf) -> serde_json::Value {
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                return val;
            }
        }
    }
    serde_json::json!({})
}

/// Merge the "kin" MCP server entry into an existing JSON config file.
/// Creates the file if it doesn't exist.
fn merge_mcp_config(path: &PathBuf) -> Result<()> {
    let mut root = read_json_file(path);

    // Ensure root is an object
    if !root.is_object() {
        root = serde_json::json!({});
    }

    // Ensure mcpServers key exists as an object
    if !root.get("mcpServers").map_or(false, |v| v.is_object()) {
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

/// Check if a given MCP config file already has the "kin" server entry.
fn has_kin_mcp_config(path: &PathBuf) -> bool {
    if !path.exists() {
        return false;
    }
    let root = read_json_file(path);
    root.get("mcpServers").and_then(|s| s.get("kin")).is_some()
}

// ---------------------------------------------------------------------------
// Shell hook installation
// ---------------------------------------------------------------------------

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
        fs::copy(&shim_path, &dest)
            .with_context(|| format!("failed to copy shim to {}", dest.display()))?;
        println!(
            "  Copied VFS shim: {} -> {}",
            shim_path.display(),
            dest.display()
        );
    } else {
        println!("  VFS shim not found. Build it with:");
        println!("    cargo build --release -p kin-vfs-shim");
    }

    let source_line = if shell_name == "powershell" {
        format!(". {}", hook_file.display())
    } else {
        format!("source {}", hook_file.display())
    };

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
        rc_content.push_str(&format!("\n# kin-vfs shell integration\n{source_line}\n"));
        fs::write(&rc_path, &rc_content)
            .with_context(|| format!("failed to update {}", rc_path.display()))?;
        println!("  Appended to {}", rc_path.display());
    }

    Ok((hook_file, source_line))
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

    // Step 1: Welcome
    println!();
    println!("Welcome to Kin setup. Let's configure your environment.");
    println!();

    // Step 2: Shell detection + hook install
    let shell_name = opts.shell.as_deref().unwrap_or_else(|| detect_shell());

    println!("Detected shell: {shell_name}");
    let install_shell = prompt_yn(
        &format!(
            "Install shell integration to {}?",
            shell_rc(shell_name)?.display()
        ),
        true,
        interactive,
    );

    if install_shell {
        install_shell_hook(shell_name)?;
        println!("  Shell integration installed.");
    } else {
        println!("  Skipped shell integration.");
    }
    println!();

    // Step 4: AI Assistants — MCP auto-configuration
    println!("AI Assistants (MCP configuration):");
    println!();

    let assistants = detect_ai_assistants();
    let mut configured_assistants: Vec<(String, Option<PathBuf>)> = Vec::new();

    if interactive {
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

        // Default: select all detected assistants
        let defaults: Vec<bool> = assistants.iter().map(|a| a.detected).collect();

        let selections = MultiSelect::new()
            .items(&items)
            .defaults(&defaults)
            .interact()
            .unwrap_or_else(|_| {
                // Fallback: select all detected
                assistants
                    .iter()
                    .enumerate()
                    .filter(|(_, a)| a.detected)
                    .map(|(i, _)| i)
                    .collect()
            });

        for idx in &selections {
            let a = &assistants[*idx];
            match *idx {
                0 => match configure_claude_code() {
                    Ok(path) => configured_assistants.push((a.name.to_string(), Some(path))),
                    Err(e) => {
                        println!(
                            "  {} Claude Code configuration failed: {e}",
                            style("✗").red()
                        );
                        configured_assistants.push((a.name.to_string(), None));
                    }
                },
                1 => match configure_cursor() {
                    Ok(path) => configured_assistants.push((a.name.to_string(), Some(path))),
                    Err(e) => {
                        println!("  {} Cursor configuration failed: {e}", style("✗").red());
                        configured_assistants.push((a.name.to_string(), None));
                    }
                },
                2 => match configure_codex() {
                    Ok(path) => configured_assistants.push((a.name.to_string(), Some(path))),
                    Err(e) => {
                        println!("  {} Codex CLI configuration failed: {e}", style("✗").red());
                        configured_assistants.push((a.name.to_string(), None));
                    }
                },
                _ => {}
            }
        }

        // Report on non-selected but not-detected assistants
        for (i, a) in assistants.iter().enumerate() {
            if !selections.contains(&i) && !a.detected {
                println!(
                    "  {} {} not detected — {}",
                    style("→").cyan(),
                    a.name,
                    a.install_hint
                );
            }
        }
    } else {
        // Non-interactive: auto-configure all detected assistants
        for (i, a) in assistants.iter().enumerate() {
            if a.detected {
                let result = match i {
                    0 => configure_claude_code(),
                    1 => configure_cursor(),
                    2 => configure_codex(),
                    _ => continue,
                };
                match result {
                    Ok(path) => configured_assistants.push((a.name.to_string(), Some(path))),
                    Err(e) => {
                        println!(
                            "  {} {} configuration failed: {e}",
                            style("✗").red(),
                            a.name,
                        );
                        configured_assistants.push((a.name.to_string(), None));
                    }
                }
            } else {
                println!(
                    "  {} {} not detected — {}",
                    style("→").cyan(),
                    a.name,
                    a.install_hint
                );
            }
        }
    }

    for (name, path) in &configured_assistants {
        if let Some(p) = path {
            println!(
                "  {} {} configured (wrote {})",
                style("✓").green(),
                name,
                p.display()
            );
        }
    }
    println!();

    // Step 5: Active Kin surfaces
    println!("Active Kin surfaces:");
    println!();
    println!("  kin-vfs    -- transparent filesystem projection for native mode");
    println!("  kin-mcp    -- bundled MCP server (run `kin mcp start`)");
    println!("  kin-editor -- lightweight VS Code extension surface");
    println!();

    // Step 6: Daemon configuration
    let auto_daemon = if opts.auto_daemon {
        true
    } else {
        prompt_yn(
            "Auto-start kin-daemon when entering Kin workspaces?",
            true,
            interactive,
        )
    };
    write_auto_daemon_config(auto_daemon)?;
    println!(
        "  Daemon auto-start: {}",
        if auto_daemon { "enabled" } else { "disabled" }
    );
    println!();

    // Step 7: Verify installation
    println!("Verifying installation...");

    let kin_home = kin_dir()?;

    // kin binary
    println!(
        "  {} kin binary working (v{})",
        style("✓").green(),
        env!("CARGO_PKG_VERSION")
    );

    // Shell hook
    let hook_path = kin_home.join("shell").join(hook_filename(shell_name));
    if install_shell && hook_path.exists() {
        println!("  {} Shell hook installed", style("✓").green());
    } else if install_shell {
        println!(
            "  {} Shell hook not found at {}",
            style("✗").red(),
            hook_path.display()
        );
    } else {
        println!("  {} Shell hook skipped", style("!").yellow());
    }

    // VFS shim
    let shim_path = kin_home.join("lib").join(shim_filename());
    if shim_path.exists() {
        println!("  {} VFS shim found", style("✓").green());
    } else {
        println!(
            "  {} VFS shim not found (build with: cargo build --release -p kin-vfs-shim)",
            style("!").yellow()
        );
    }

    // AI assistant MCP configs
    for (name, path) in &configured_assistants {
        if let Some(p) = path {
            if has_kin_mcp_config(p) {
                println!("  {} {} MCP configured", style("✓").green(), name);
            } else {
                println!(
                    "  {} {} MCP config written but verification failed",
                    style("!").yellow(),
                    name
                );
            }
        }
    }

    // kin-vfs daemon
    if check_binary_in_path("kin-vfs").is_some() {
        println!("  {} kin-vfs daemon in PATH", style("✓").green());
    } else {
        println!(
            "  {} kin-vfs daemon not in PATH (native mode requires kin-vfs)",
            style("!").yellow()
        );
    }

    // kin-daemon connectivity
    let daemon_up = kin_core::KinLayout::discover(&std::env::current_dir().unwrap_or_default())
        .and_then(|layout| crate::daemon_client::daemon_is_up(layout.root()))
        .is_some();
    if daemon_up {
        println!("  {} kin-daemon reachable", style("✓").green());
    } else {
        println!(
            "  {} kin-daemon not running (will auto-start on next command)",
            style("!").yellow()
        );
    }

    println!();

    // Step 8: Summary
    println!("=== Setup complete ===");
    println!();
    println!(
        "  Shell integration: {}",
        if install_shell {
            "installed"
        } else {
            "skipped"
        }
    );
    println!(
        "  Daemon auto-start: {}",
        if auto_daemon { "yes" } else { "no" }
    );
    for (name, path) in &configured_assistants {
        let status = if path.is_some() {
            "configured"
        } else {
            "failed"
        };
        println!("  {:<19}{}", format!("{}:", name), status);
    }
    println!();

    if install_shell {
        println!("Open a new shell session to load the shell hook.");
        println!();
    }

    println!("Next steps:");
    println!("  kin init             -- initialize a Kin repository in the current directory");
    println!("  kin setup status     -- show what's installed");
    println!("  kin setup doctor     -- run health checks");
    println!();

    Ok(())
}

// ---------------------------------------------------------------------------
// `kin setup status`
// ---------------------------------------------------------------------------

pub async fn status() -> Result<()> {
    let kin_home = kin_dir()?;
    let shell_name = detect_shell();

    let kin_version = env!("CARGO_PKG_VERSION");
    if let Ok(exe) = env::current_exe() {
        println!("kin binary:    v{kin_version} ({})", exe.display());
    } else {
        println!("kin binary:    v{kin_version}");
    }

    match check_binary_in_path("kin-daemon") {
        Some(p) => println!("kin-daemon:    found ({})", p.display()),
        None => println!("kin-daemon:    not found in PATH"),
    }

    match check_binary_in_path("kin-vfs") {
        Some(p) => println!("kin-vfs:       found ({})", p.display()),
        None => println!("kin-vfs:       not found in PATH"),
    }

    let shim_path = kin_home.join("lib").join(shim_filename());
    if shim_path.exists() {
        println!("VFS shim:      installed ({})", shim_path.display());
    } else {
        println!("VFS shim:      not installed");
    }

    let hook_path = kin_home.join("shell").join(hook_filename(shell_name));
    if hook_path.exists() {
        println!("Shell hook:    installed ({})", hook_path.display());
    } else {
        println!("Shell hook:    not installed");
    }

    let rc_path = shell_rc(shell_name)?;
    let rc_sourced = if rc_path.exists() {
        fs::read_to_string(&rc_path)
            .map(|c| c.contains("kin-vfs"))
            .unwrap_or(false)
    } else {
        false
    };
    if rc_sourced {
        println!("Shell rc:      configured ({})", rc_path.display());
    } else {
        println!("Shell rc:      not configured");
    }

    println!("kin-mcp:       bundled (run `kin mcp start`)");
    println!("kin-editor:    extension surface (see kin README)");
    let config_path = kin_home.join("config/setup.toml");
    if config_path.exists() {
        let content = fs::read_to_string(&config_path).unwrap_or_default();
        if content.contains("auto_start = true") {
            println!("Auto-daemon:   enabled");
        } else {
            println!("Auto-daemon:   disabled");
        }
    } else {
        println!("Auto-daemon:   not configured");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// `kin setup doctor`
// ---------------------------------------------------------------------------

pub async fn doctor() -> Result<()> {
    let kin_home = kin_dir()?;
    let shell_name = detect_shell();
    let mut all_ok = true;

    print!("kin binary .............. ");
    println!("ok (v{})", env!("CARGO_PKG_VERSION"));

    print!("kin-vfs daemon .......... ");
    if check_binary_in_path("kin-vfs").is_some() {
        println!("ok");
    } else {
        println!("MISSING");
        all_ok = false;
    }

    print!("VFS shim library ........ ");
    let shim_path = kin_home.join("lib").join(shim_filename());
    let shim_size = shim_path.metadata().map(|m| m.len()).unwrap_or(0);
    if shim_path.exists() && shim_size > 0 {
        println!("ok ({} bytes)", shim_size);
    } else if shim_path.exists() && shim_size == 0 {
        println!("BROKEN (0 bytes — will crash all processes via DYLD)");
        eprintln!("  fix: rm {:?} && kin setup install", shim_path);
        all_ok = false;
    } else {
        println!("MISSING");
        all_ok = false;
    }

    print!("Shell hook ({shell_name}) ........ ");
    let hook_installed = kin_home
        .join("shell")
        .join(hook_filename(shell_name))
        .exists();
    if hook_installed {
        println!("ok");
    } else {
        println!("MISSING (run: kin setup)");
        all_ok = false;
    }

    print!("kin-daemon ................. ");
    if let Some(layout) =
        kin_core::KinLayout::discover(&std::env::current_dir().unwrap_or_default())
    {
        match crate::daemon_client::daemon_is_up(layout.root()) {
            Some(port) => println!("ok (port {})", port),
            None => {
                println!("NOT RUNNING (will auto-start on next command)");
            }
        }
    } else {
        println!("SKIPPED (not in a kin repo)");
    }

    // Check for orphaned daemons across all registered repos
    print!("Stale daemon cleanup ....... ");
    let cleaned = cleanup_stale_daemons();
    if cleaned > 0 {
        println!("cleaned {} stale daemon(s)", cleaned);
    } else {
        println!("ok (no stale daemons)");
    }

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed. Run `kin setup` to install missing components.");
    }

    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{BASH_HOOK, ZSH_HOOK};

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
}
