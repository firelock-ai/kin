// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use std::env;
use std::fs;
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
# Installed by: kin setup shell
#
# Environment variables set when inside a workspace:
#   KIN_VFS_WORKSPACE  — absolute path to the workspace root
#   KIN_VFS_SOCK       — path to the daemon Unix socket
#   DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux) — VFS shim library

# ---------------------------------------------------------------------------
# Walk up from a directory to find the nearest .kin/ marker.
# Prints the workspace root (parent of .kin/) or nothing.
# ---------------------------------------------------------------------------
_kin_vfs_find_workspace() {
    local dir="$1"
    while [[ "$dir" != "/" ]]; do
        if [[ -d "$dir/.kin" ]]; then
            printf '%s' "$dir"
            return 0
        fi
        dir="${dir:h}"  # zsh dirname — parent directory
    done
    # Check root just in case
    if [[ -d "/.kin" ]]; then
        printf '%s' "/"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Resolve the path to the VFS shim library for the current platform.
# Returns empty string if not found.
# ---------------------------------------------------------------------------
_kin_vfs_shim_path() {
    local lib
    local kin_lib="$HOME/.kin/lib"
    case "$(uname -s)" in
        Darwin) lib="$kin_lib/libkin_vfs_shim.dylib" ;;
        Linux)  lib="$kin_lib/libkin_vfs_shim.so" ;;
        *)      lib="" ;;
    esac
    [[ -f "$lib" ]] && printf '%s' "$lib"
}

# ---------------------------------------------------------------------------
# Enter a kin workspace: start daemon if needed, set env.
# ---------------------------------------------------------------------------
_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"

    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"

    # Auto-start the daemon if the socket does not exist.
    if [[ ! -S "$sock" ]]; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" &>/dev/null &!
            # Give the daemon a moment to bind the socket.
            local attempts=0
            while [[ ! -S "$sock" ]] && (( attempts < 10 )); do
                sleep 0.1
                (( attempts++ ))
            done
        fi
    fi

    # Set the LD_PRELOAD / DYLD_INSERT_LIBRARIES shim.
    local shim
    shim="$(_kin_vfs_shim_path)"
    if [[ -n "$shim" ]]; then
        case "$(uname -s)" in
            Darwin) export DYLD_INSERT_LIBRARIES="$shim" ;;
            Linux)  export LD_PRELOAD="$shim" ;;
        esac
    fi
}

# ---------------------------------------------------------------------------
# Leave a kin workspace: unset all VFS env vars.
# ---------------------------------------------------------------------------
_kin_vfs_deactivate() {
    unset KIN_VFS_WORKSPACE
    unset KIN_VFS_SOCK
    unset DYLD_INSERT_LIBRARIES
    unset LD_PRELOAD
}

# ---------------------------------------------------------------------------
# chpwd hook — runs every time the working directory changes.
# ---------------------------------------------------------------------------
_kin_vfs_chpwd() {
    local ws
    ws="$(_kin_vfs_find_workspace "$PWD")"

    if [[ -n "$ws" ]]; then
        # Inside a workspace. Only re-activate if we switched workspaces.
        if [[ "$ws" != "${KIN_VFS_WORKSPACE:-}" ]]; then
            _kin_vfs_activate "$ws"
        fi
    else
        # Outside any workspace. Deactivate if we were previously inside one.
        if [[ -n "${KIN_VFS_WORKSPACE:-}" ]]; then
            _kin_vfs_deactivate
        fi
    fi
}

# Register the hook.
autoload -Uz add-zsh-hook
add-zsh-hook chpwd _kin_vfs_chpwd

# Run once on source so the current directory is handled immediately.
_kin_vfs_chpwd
"#;

const BASH_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs bash integration — auto-activates the VFS overlay when entering
# a Kin workspace (any directory tree containing .kin/).
#
# Installed by: kin setup shell
#
# Environment variables set when inside a workspace:
#   KIN_VFS_WORKSPACE  — absolute path to the workspace root
#   KIN_VFS_SOCK       — path to the daemon Unix socket
#   DYLD_INSERT_LIBRARIES (macOS) or LD_PRELOAD (Linux) — VFS shim library

# ---------------------------------------------------------------------------
# Walk up from a directory to find the nearest .kin/ marker.
# Prints the workspace root (parent of .kin/) or nothing.
# ---------------------------------------------------------------------------
_kin_vfs_find_workspace() {
    local dir="$1"
    while [ "$dir" != "/" ]; do
        if [ -d "$dir/.kin" ]; then
            printf '%s' "$dir"
            return 0
        fi
        dir="$(dirname "$dir")"
    done
    # Check root just in case
    if [ -d "/.kin" ]; then
        printf '%s' "/"
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Resolve the path to the VFS shim library for the current platform.
# Returns empty string if not found.
# ---------------------------------------------------------------------------
_kin_vfs_shim_path() {
    local lib
    local kin_lib="$HOME/.kin/lib"
    case "$(uname -s)" in
        Darwin) lib="$kin_lib/libkin_vfs_shim.dylib" ;;
        Linux)  lib="$kin_lib/libkin_vfs_shim.so" ;;
        *)      lib="" ;;
    esac
    [ -f "$lib" ] && printf '%s' "$lib"
}

# ---------------------------------------------------------------------------
# Enter a kin workspace: start daemon if needed, set env.
# ---------------------------------------------------------------------------
_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"

    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"

    # Auto-start the daemon if the socket does not exist.
    if [ ! -S "$sock" ]; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" >/dev/null 2>&1 &
            disown 2>/dev/null
            # Give the daemon a moment to bind the socket.
            local attempts=0
            while [ ! -S "$sock" ] && [ "$attempts" -lt 10 ]; do
                sleep 0.1
                attempts=$((attempts + 1))
            done
        fi
    fi

    # Set the LD_PRELOAD / DYLD_INSERT_LIBRARIES shim.
    local shim
    shim="$(_kin_vfs_shim_path)"
    if [ -n "$shim" ]; then
        case "$(uname -s)" in
            Darwin) export DYLD_INSERT_LIBRARIES="$shim" ;;
            Linux)  export LD_PRELOAD="$shim" ;;
        esac
    fi
}

# ---------------------------------------------------------------------------
# Leave a kin workspace: unset all VFS env vars.
# ---------------------------------------------------------------------------
_kin_vfs_deactivate() {
    unset KIN_VFS_WORKSPACE
    unset KIN_VFS_SOCK
    unset DYLD_INSERT_LIBRARIES
    unset LD_PRELOAD
}

# ---------------------------------------------------------------------------
# PROMPT_COMMAND hook — detect directory changes by comparing to last dir.
# ---------------------------------------------------------------------------
_kin_vfs_prompt_command() {
    # Only run when the directory has actually changed.
    if [ "$PWD" = "${_KIN_VFS_LAST_DIR:-}" ]; then
        return
    fi
    _KIN_VFS_LAST_DIR="$PWD"

    local ws
    ws="$(_kin_vfs_find_workspace "$PWD")"

    if [ -n "$ws" ]; then
        # Inside a workspace. Only re-activate if we switched workspaces.
        if [ "$ws" != "${KIN_VFS_WORKSPACE:-}" ]; then
            _kin_vfs_activate "$ws"
        fi
    else
        # Outside any workspace. Deactivate if we were previously inside one.
        if [ -n "${KIN_VFS_WORKSPACE:-}" ]; then
            _kin_vfs_deactivate
        fi
    fi
}

# Append our hook to PROMPT_COMMAND (preserve any existing hooks).
if [ -z "$PROMPT_COMMAND" ]; then
    PROMPT_COMMAND="_kin_vfs_prompt_command"
else
    PROMPT_COMMAND="_kin_vfs_prompt_command;$PROMPT_COMMAND"
fi

# Run once on source so the current directory is handled immediately.
_KIN_VFS_LAST_DIR=""
_kin_vfs_prompt_command
"#;

const POWERSHELL_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs shell integration for PowerShell
# Installed by: kin setup shell
#
# When you cd into a directory containing .kin/, the VFS daemon is
# auto-started and the ProjFS provider is activated. When you leave,
# it deactivates.

$script:KinVfsActive = $false
$script:KinVfsWorkspace = ""

function Find-KinWorkspace {
    param([string]$StartDir)
    $dir = $StartDir
    while ($dir -and $dir -ne [System.IO.Path]::GetPathRoot($dir)) {
        if (Test-Path (Join-Path $dir ".kin")) {
            return $dir
        }
        $dir = Split-Path $dir -Parent
    }
    return $null
}

function Enable-KinVfs {
    param([string]$Workspace)
    $sock = Join-Path $Workspace ".kin\vfs.sock"
    $pipe = "\\.\pipe\kin-vfs-$([System.IO.Path]::GetFileName($Workspace))"

    # Auto-start daemon if not running.
    $daemonCmd = Get-Command "kin-vfs" -ErrorAction SilentlyContinue
    if ($daemonCmd) {
        # Check if daemon is reachable via named pipe.
        $pipeExists = [System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -like "*kin-vfs*" }
        if (-not $pipeExists) {
            Start-Process -FilePath "kin-vfs" -ArgumentList "start", "--workspace", $Workspace -WindowStyle Hidden
            # Brief wait for daemon startup.
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
        if ($script:KinVfsWorkspace -ne $ws) {
            Enable-KinVfs -Workspace $ws
        }
    }
    else {
        if ($script:KinVfsActive) {
            Disable-KinVfs
        }
    }
}

# Override the default prompt to check directory on every command.
# Preserve the user's existing prompt function.
if (-not (Get-Variable -Name KinVfsOriginalPrompt -Scope Script -ErrorAction SilentlyContinue)) {
    $script:KinVfsOriginalPrompt = $function:prompt
}

function prompt {
    Invoke-KinVfsLocationCheck
    & $script:KinVfsOriginalPrompt
}

# Run once on source to handle current directory.
Invoke-KinVfsLocationCheck
"#;

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

/// Platform-specific shim library filename.
fn shim_filename() -> &'static str {
    if cfg!(target_os = "macos") {
        "libkin_vfs_shim.dylib"
    } else if cfg!(target_os = "windows") {
        "kin_vfs_shim.dll"
    } else {
        "libkin_vfs_shim.so"
    }
}

/// Search common locations for the VFS shim library.
fn find_shim() -> Option<PathBuf> {
    let name = shim_filename();

    // 1. Same directory as the running `kin` binary.
    if let Ok(exe) = env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
            // Also check a sibling lib/ directory.
            let lib_candidate = dir.join("../lib").join(name);
            if lib_candidate.exists() {
                return Some(lib_candidate);
            }
        }
    }

    // 2. $CARGO_HOME/bin/../lib/
    if let Ok(cargo_home) = env::var("CARGO_HOME") {
        let candidate = PathBuf::from(&cargo_home).join("lib").join(name);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    // 3. Current directory's target/release/
    let cwd_candidate = PathBuf::from("target/release").join(name);
    if cwd_candidate.exists() {
        return Some(cwd_candidate);
    }

    // 4. Current directory's target/debug/
    let cwd_debug = PathBuf::from("target/debug").join(name);
    if cwd_debug.exists() {
        return Some(cwd_debug);
    }

    None
}

/// Detect which shell the user is running.
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
    }
    "zsh" // default on macOS
}

/// Return the shell rc file path.
fn shell_rc(shell: &str) -> Result<PathBuf> {
    let home = home_dir()?;
    match shell {
        "zsh" => Ok(home.join(".zshrc")),
        "bash" => Ok(home.join(".bashrc")),
        "powershell" => {
            // PowerShell $PROFILE — best-effort guess.
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
        "powershell" => "kin-vfs.ps1",
        _ => "kin-vfs.zsh",
    }
}

fn hook_content(shell: &str) -> &'static str {
    match shell {
        "bash" => BASH_HOOK,
        "powershell" => POWERSHELL_HOOK,
        _ => ZSH_HOOK,
    }
}

fn check_binary_in_path(name: &str) -> Option<PathBuf> {
    which::which(name).ok()
}

// ---------------------------------------------------------------------------
// `kin setup shell`
// ---------------------------------------------------------------------------

pub async fn shell() -> Result<()> {
    let shell = detect_shell();
    println!("Detected shell: {shell}");

    let kin_home = kin_dir()?;
    let shell_dir = kin_home.join("shell");
    let lib_dir = kin_home.join("lib");

    // Create directories.
    fs::create_dir_all(&shell_dir).context("failed to create ~/.kin/shell/")?;
    fs::create_dir_all(&lib_dir).context("failed to create ~/.kin/lib/")?;
    println!("  Created ~/.kin/shell/ and ~/.kin/lib/");

    // Write the shell hook.
    let hook_file = shell_dir.join(hook_filename(shell));
    fs::write(&hook_file, hook_content(shell))
        .with_context(|| format!("failed to write {}", hook_file.display()))?;
    println!("  Wrote shell hook: {}", hook_file.display());

    // Find and copy the VFS shim.
    if let Some(shim_path) = find_shim() {
        let dest = lib_dir.join(shim_filename());
        fs::copy(&shim_path, &dest)
            .with_context(|| format!("failed to copy shim to {}", dest.display()))?;
        println!("  Copied VFS shim: {} -> {}", shim_path.display(), dest.display());
    } else {
        println!("  VFS shim not found. Build it with:");
        println!("    cargo build --release -p kin-vfs-shim");
        println!("  Then re-run: kin setup shell");
    }

    // Append source line to shell rc.
    let rc_path = shell_rc(shell)?;
    let source_line = if shell == "powershell" {
        format!(". {}", hook_file.display())
    } else {
        format!("source {}", hook_file.display())
    };

    let already_installed = if rc_path.exists() {
        let contents = fs::read_to_string(&rc_path)?;
        contents.contains("kin-vfs")
    } else {
        false
    };

    if already_installed {
        println!("  Shell rc already sources kin-vfs hook: {}", rc_path.display());
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
        fs::write(&rc_path, rc_content)
            .with_context(|| format!("failed to update {}", rc_path.display()))?;
        println!("  Appended to {}", rc_path.display());
    }

    println!();
    println!("Shell integration installed. Restart your shell or run:");
    println!("  {source_line}");

    Ok(())
}

// ---------------------------------------------------------------------------
// `kin setup status`
// ---------------------------------------------------------------------------

pub async fn status() -> Result<()> {
    let kin_home = kin_dir()?;
    let shell_name = detect_shell();

    // kin binary
    let kin_version = env!("CARGO_PKG_VERSION");
    if let Ok(exe) = env::current_exe() {
        println!("kin binary:    v{kin_version} ({})", exe.display());
    } else {
        println!("kin binary:    v{kin_version}");
    }

    // kin-daemon
    match check_binary_in_path("kin-daemon") {
        Some(p) => println!("kin-daemon:    found ({})", p.display()),
        None => println!("kin-daemon:    not found in PATH"),
    }

    // kin-vfs
    match check_binary_in_path("kin-vfs") {
        Some(p) => println!("kin-vfs:       found ({})", p.display()),
        None => println!("kin-vfs:       not found in PATH"),
    }

    // VFS shim
    let shim_path = kin_home.join("lib").join(shim_filename());
    if shim_path.exists() {
        println!("VFS shim:      installed ({})", shim_path.display());
    } else {
        println!("VFS shim:      not installed");
    }

    // Shell hook
    let hook_path = kin_home.join("shell").join(hook_filename(shell_name));
    if hook_path.exists() {
        println!("Shell hook:    installed ({})", hook_path.display());
    } else {
        println!("Shell hook:    not installed");
    }

    // Shell rc
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

    Ok(())
}

// ---------------------------------------------------------------------------
// `kin setup doctor`
// ---------------------------------------------------------------------------

pub async fn doctor() -> Result<()> {
    let kin_home = kin_dir()?;
    let shell_name = detect_shell();
    let mut all_ok = true;

    // 1. kin binary
    print!("kin binary .............. ");
    println!("ok (v{})", env!("CARGO_PKG_VERSION"));

    // 2. kin-vfs-daemon
    print!("kin-vfs daemon .......... ");
    if check_binary_in_path("kin-vfs").is_some() {
        println!("ok");
    } else {
        println!("MISSING");
        all_ok = false;
    }

    // 3. VFS shim library
    print!("VFS shim library ........ ");
    let shim_installed = kin_home.join("lib").join(shim_filename()).exists();
    if shim_installed {
        println!("ok");
    } else {
        println!("MISSING");
        all_ok = false;
    }

    // 4. Shell hook
    print!("Shell hook ({shell_name}) ........ ");
    let hook_installed = kin_home.join("shell").join(hook_filename(shell_name)).exists();
    if hook_installed {
        println!("ok");
    } else {
        println!("MISSING (run: kin setup shell)");
        all_ok = false;
    }

    // 5. kin-daemon reachable
    print!("kin-daemon (localhost:4219) ");
    match try_connect_daemon().await {
        true => println!("ok"),
        false => {
            println!("UNREACHABLE");
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        println!("All checks passed.");
    } else {
        println!("Some checks failed. Run `kin setup shell` to install missing components.");
    }

    Ok(())
}

async fn try_connect_daemon() -> bool {
    tokio::net::TcpStream::connect("127.0.0.1:4219")
        .await
        .is_ok()
}

// ---------------------------------------------------------------------------
// Interactive wizard: `kin setup` (no subcommand)
// ---------------------------------------------------------------------------

pub struct WizardOptions {
    pub mode: Option<String>,
    pub shell: Option<String>,
    pub auto_daemon: bool,
    pub no_interactive: bool,
}

pub async fn run_wizard(opts: WizardOptions) -> Result<()> {
    use console::style;
    use dialoguer::{Confirm, MultiSelect, Select};

    let is_tty = atty::is(atty::Stream::Stdin);
    let interactive = is_tty && !opts.no_interactive;

    // ── Header ────────────────────────────────────────────────────────
    println!();
    println!(
        "  {}",
        style("Kin Setup").bold().cyan()
    );
    println!(
        "  {}",
        style("Configure your semantic development environment").dim()
    );
    println!();

    // ── Step 1: Mode selection ────────────────────────────────────────
    let mode = if let Some(ref m) = opts.mode {
        m.clone()
    } else if interactive {
        let modes = vec![
            "Native         —  graph is truth, files are projections (full Kin experience)",
            "Compatibility  —  files on disk, Kin indexes alongside (safe for existing projects)",
        ];
        let selection = Select::new()
            .with_prompt(format!("  {}", style("Which mode?").bold()))
            .items(&modes)
            .default(0)
            .interact()?;
        match selection {
            0 => "native".to_string(),
            _ => "compatibility".to_string(),
        }
    } else {
        "compatibility".to_string()
    };

    println!(
        "  {} {}",
        style("Mode:").bold(),
        style(&mode).green()
    );

    if mode == "compatibility" {
        println!();
        println!("  {}", style("Note: Compatibility mode keeps files on disk alongside the graph.").dim());
        println!("  {}", style("You will NOT get:").yellow());
        println!("    {} Zero-duplication storage (files + blob store both use disk)", style("·").dim());
        println!("    {} Instant branch switching (graph swap vs file checkout)", style("·").dim());
        println!("    {} Process-scoped projections (different tools see different views)", style("·").dim());
        println!("    {} Semantic-only materialization (only touched files exist on disk)", style("·").dim());
        println!();
        println!("  {}", style("You CAN switch to native anytime: kin mode preset native").dim());
    } else {
        println!();
        println!("  {}", style("Native mode: the graph is your source of truth.").dim());
        println!("  {}", style("Files are served on demand from the blob store — zero duplication.").dim());
    }
    println!();

    // ── Step 2: Shell integration ─────────────────────────────────────
    let shell_name = opts.shell.as_deref().unwrap_or_else(|| detect_shell());

    let install_shell = if interactive {
        Confirm::new()
            .with_prompt(format!(
                "  {} Install shell integration for {}?",
                style("Shell:").bold(),
                style(shell_name).cyan()
            ))
            .default(true)
            .interact()?
    } else {
        true
    };

    if install_shell {
        let kin_home = kin_dir()?;
        let shell_dir = kin_home.join("shell");
        let lib_dir = kin_home.join("lib");
        fs::create_dir_all(&shell_dir)?;
        fs::create_dir_all(&lib_dir)?;

        // Write hook
        let hook_file = shell_dir.join(hook_filename(shell_name));
        fs::write(&hook_file, hook_content(shell_name))?;

        // Copy shim if found
        if let Some(shim_src) = find_shim() {
            let dest = lib_dir.join(shim_filename());
            fs::copy(&shim_src, &dest)?;
            println!(
                "  {} VFS shim installed",
                style("  ✓").green()
            );
        } else {
            println!(
                "  {} VFS shim not found — build with: cargo build --release -p kin-vfs-shim",
                style("  !").yellow()
            );
        }

        // Append to shell rc
        let rc_path = shell_rc(shell_name)?;
        let source_line = if shell_name == "powershell" {
            format!(". {}", hook_file.display())
        } else {
            format!("source {}", hook_file.display())
        };

        let already = rc_path
            .exists()
            .then(|| fs::read_to_string(&rc_path).ok())
            .flatten()
            .map(|c| c.contains("kin-vfs"))
            .unwrap_or(false);

        if !already {
            let mut content = if rc_path.exists() {
                fs::read_to_string(&rc_path)?
            } else {
                String::new()
            };
            if !content.ends_with('\n') && !content.is_empty() {
                content.push('\n');
            }
            content.push_str(&format!("\n# Kin shell integration\n{source_line}\n"));
            fs::write(&rc_path, content)?;
        }

        println!(
            "  {} Shell hook installed for {}",
            style("  ✓").green(),
            style(shell_name).cyan()
        );
    }
    println!();

    // ── Step 3: Additional tools ──────────────────────────────────────
    let tools = vec![
        ("kin-pilot", "AI agent shell — semantic-first coding agent (Codex fork)"),
        ("kin-code", "Editor shell — VS Code with native graph support"),
        ("kinlab", "Hosted collaboration — semantic review, org search, activity feeds"),
    ];

    let installed_tools: Vec<usize> = if interactive {
        let labels: Vec<String> = tools
            .iter()
            .map(|(name, desc)| {
                let available = check_binary_in_path(name).is_some();
                let tag = if available {
                    style("installed").green().to_string()
                } else {
                    style("not installed").dim().to_string()
                };
                format!("{} — {} [{}]", style(name).bold(), desc, tag)
            })
            .collect();

        println!(
            "  {}",
            style("Additional tools (space to toggle, enter to confirm):").bold()
        );
        MultiSelect::new()
            .items(&labels)
            .interact()?
    } else {
        Vec::new()
    };

    for idx in &installed_tools {
        let (name, _desc) = tools[*idx];
        if check_binary_in_path(name).is_some() {
            println!(
                "  {} {} already installed",
                style("  ✓").green(),
                name
            );
        } else {
            println!(
                "  {} {} — install from: https://github.com/firelock-ai/{}",
                style("  →").cyan(),
                name,
                name
            );
        }
    }
    if !installed_tools.is_empty() {
        println!();
    }

    // ── Step 4: Daemon auto-start ─────────────────────────────────────
    let auto_daemon = if opts.auto_daemon {
        true
    } else if interactive {
        Confirm::new()
            .with_prompt(format!(
                "  {} Auto-start kin-daemon when entering workspaces?",
                style("Daemon:").bold()
            ))
            .default(true)
            .interact()?
    } else {
        true
    };

    if auto_daemon {
        println!(
            "  {} Daemon auto-start enabled",
            style("  ✓").green()
        );
    }
    println!();

    // ── Step 5: Write global config ───────────────────────────────────
    let kin_home = kin_dir()?;
    let config_path = kin_home.join("config.toml");
    let compat_warning = if mode == "compatibility" {
        r#"
# NOTE: You are running in compatibility mode.
# This means files exist on disk AND in the graph — doubling storage.
# You will not get:
#   - Zero-duplication storage (blob store serves files directly)
#   - Instant branch switching (graph pointer swap, no file checkout)
#   - Process-scoped projections (editors, agents, and build tools see tailored views)
#   - Semantic-only materialization (only modified files touch disk)
#
# Switch to native mode anytime:
#   kin mode preset native
"#
    } else {
        r#"
# Native mode: the graph is the source of truth.
# Files are served on demand via kin-vfs from the content-addressed blob store.
# No file duplication — the blob store IS your files.
"#
    };

    let config_content = format!(
        r#"# Kin global configuration
# Generated by: kin setup
#
# Docs: https://github.com/firelock-ai/kin

[defaults]
mode = "{mode}"{compat_warning}
auto_daemon = {auto_daemon}
"#
    );
    fs::create_dir_all(&kin_home)?;
    fs::write(&config_path, config_content)?;

    // ── Summary ───────────────────────────────────────────────────────
    println!("  {}", style("Setup complete!").bold().green());
    println!();
    println!("  {}", style("What's configured:").bold());
    println!("    Mode:          {}", style(&mode).cyan());
    println!("    Shell:         {}", style(shell_name).cyan());
    println!("    Auto-daemon:   {}", if auto_daemon { style("yes").green() } else { style("no").dim() });
    println!("    Config:        {}", style(config_path.display()).dim());
    println!();
    println!(
        "  {} Restart your shell, then run {} in any Git repo to get started.",
        style("→").cyan(),
        style("kin init").bold()
    );
    println!();

    Ok(())
}
