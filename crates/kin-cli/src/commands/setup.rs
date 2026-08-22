// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use console::style;
use dialoguer::MultiSelect;
use fs2::FileExt;
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read as _, Seek as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::commands::language_servers;

// ---------------------------------------------------------------------------
// Embedded shell hooks (from kin-vfs/shell/)
// ---------------------------------------------------------------------------

const ZSH_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs zsh integration — auto-activates the VFS overlay when entering
# a Kin repository (a directory whose .kin/ carries a repository manifest).
#
# Installed by: kin setup

_kin_vfs_disabled() {
    case "${KIN_VFS_DISABLE:-}" in
        1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]) return 0 ;;
        *) return 1 ;;
    esac
}

_kin_vfs_logical_dir() {
    local dir="${1:a}"
    [[ -d "$dir" ]] || return 1
    printf '%s' "$dir"
}

_kin_vfs_physical_dir() {
    local dir="${1:A}"
    [[ -d "$dir" ]] || return 1
    printf '%s' "$dir"
}

_kin_vfs_path_within() {
    local path="$1"
    local root="$2"
    [[ "$path" == "$root" || "$root" == "/" ]] && return 0
    case "$path" in
        "$root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# A `.kin` directory names a repository only when it carries the manifest
# `kin init` writes there. The managed toolchain home ($KIN_HOME, default
# $HOME/.kin) is a real `.kin` directory too, holding bin/, lib/, shell/ and
# config/, so a walk that asks only whether `.kin` is a directory binds $HOME
# itself as a projection root, and every path under it then belongs to a
# projection no daemon serves. The kin-vfs shim admits a root on this same
# file, so both halves answer the containment question the same way.
_kin_vfs_is_repository() {
    [[ -f "$1/.kin/manifest.json" ]]
}

_kin_vfs_scan_path() {
    local dir="$1"
    local boundary="$2"
    while true; do
        # A Kin marker is authority only when it is a real local directory
        # holding a repository manifest. During a session it may win over a
        # same-directory .git marker only at the exact validated session root.
        if [[ -e "$dir/.kin" || -L "$dir/.kin" ]]; then
            [[ -d "$dir/.kin" && ! -L "$dir/.kin" ]] || return 1
            if _kin_vfs_is_repository "$dir"; then
                if [[ -n "$boundary" && "$dir" != "$boundary" ]]; then
                    return 1
                fi
                printf '%s' "$dir"
                return 0
            fi
        fi
        # Files, directories, and even broken symlinks are Git boundaries.
        if [[ -e "$dir/.git" || -L "$dir/.git" ]]; then
            return 1
        fi
        if [[ -n "$boundary" && "$dir" == "$boundary" ]]; then
            return 1
        fi
        [[ "$dir" != "/" ]] || return 1
        dir="${dir:h}"
    done
}

_kin_vfs_find_workspace() {
    _kin_vfs_disabled && return 1

    local logical physical
    local session_logical="" session_physical=""
    local logical_workspace physical_workspace logical_workspace_physical
    logical="$(_kin_vfs_logical_dir "$1")" || return 1
    physical="$(_kin_vfs_physical_dir "$1")" || return 1

    if [[ -n "${KIN_SESSION_DIR:-}" ]]; then
        [[ "$KIN_SESSION_DIR" == /* ]] || return 1
        session_logical="$(_kin_vfs_logical_dir "$KIN_SESSION_DIR")" || return 1
        session_physical="$(_kin_vfs_physical_dir "$KIN_SESSION_DIR")" || return 1
        _kin_vfs_path_within "$logical" "$session_logical" || return 1
        _kin_vfs_path_within "$physical" "$session_physical" || return 1
    fi

    logical_workspace="$(_kin_vfs_scan_path "$logical" "$session_logical")" || return 1
    physical_workspace="$(_kin_vfs_scan_path "$physical" "$session_physical")" || return 1
    logical_workspace_physical="$(_kin_vfs_physical_dir "$logical_workspace")" || return 1
    [[ "$logical_workspace_physical" == "$physical_workspace" ]] || return 1

    if [[ -n "$session_logical" ]]; then
        [[ "$logical_workspace" == "$session_logical" ]] || return 1
        [[ "$physical_workspace" == "$session_physical" ]] || return 1
    fi

    printf '%s' "$physical_workspace"
}

_kin_vfs_shim_path() {
    local lib
    local kin_home="${KIN_HOME:-$HOME/.kin}"
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

# A socket file outlives the daemon that bound it, so only a connect
# answered by a listener proves one is behind it. `kin-vfs status` exits 0
# for a stale socket too; its Status line carries the verdict.
_kin_vfs_daemon_listening() {
    local out
    out="$(kin-vfs status --workspace "$1" 2>/dev/null)" || return 1
    case "$out" in
        *"Status:"*"running"*) return 0 ;;
        *) return 1 ;;
    esac
}

_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"
    unset KIN_VFS_WORKSPACE_ALIASES KIN_VFS_PIPE
    unset KIN_VFS_CANARY KIN_VFS_INTERPOSE_ACTIVE KIN_VFS_LAST_DIR
    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"
    # -S is only a pre-filter (nothing to probe without a socket); the
    # listener probe decides. `kin-vfs start` connects first and unlinks a
    # stale socket itself before binding fresh.
    if [[ ! -S "$sock" ]] || ! _kin_vfs_daemon_listening "$ws"; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" &>/dev/null &!
            local attempts=0
            while (( attempts < 10 )); do
                if [[ -S "$sock" ]] && _kin_vfs_daemon_listening "$ws"; then
                    break
                fi
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
    unset KIN_VFS_WORKSPACE KIN_VFS_WORKSPACE_ALIASES
    unset KIN_VFS_SOCK KIN_VFS_PIPE
    unset KIN_VFS_CANARY KIN_VFS_INTERPOSE_ACTIVE KIN_VFS_LAST_DIR
    _kin_vfs_clear_preload
}

_kin_vfs_chpwd() {
    local ws
    if _kin_vfs_disabled; then
        _kin_vfs_deactivate
        return
    fi
    ws="$(_kin_vfs_find_workspace "$PWD")"
    if [[ -n "$ws" ]]; then
        if [[ "$ws" != "${KIN_VFS_WORKSPACE:-}" ||
              -n "${KIN_VFS_WORKSPACE_ALIASES:-}" ||
              "${KIN_VFS_SOCK:-}" != "$ws/.kin/vfs.sock" ||
              -n "${KIN_VFS_PIPE:-}" ]]; then
            _kin_vfs_activate "$ws"
        else
            _kin_vfs_refresh_preload
        fi
    else
        _kin_vfs_deactivate
    fi
}

# Kin-family control-plane binaries must not be injected with the shim.
# External tools (editors, builds) keep the shim via the global env var.
#
# Every wrapper clears the preload variables inline and depends on no other
# function. A consumer that replays these definitions into another shell
# carries the whole exclusion with them, so the wrapper cannot resolve to a
# missing helper.
_kin_vfs_exec_without_preload() {
    DYLD_INSERT_LIBRARIES= LD_PRELOAD= command "$@"
}

kin() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin "$@"; }
kin-real() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-real "$@"; }
kin-daemon() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-daemon "$@"; }
kin-mcp() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-mcp "$@"; }
kin-vfs() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-vfs "$@"; }
kin-bench-prep() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-bench-prep "$@"; }
kin-bench-eval() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-bench-eval "$@"; }
kin-bench-target() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-bench-target "$@"; }

autoload -Uz add-zsh-hook
add-zsh-hook chpwd _kin_vfs_chpwd
_kin_vfs_chpwd
"#;

const BASH_HOOK: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Firelock, LLC
#
# kin-vfs bash integration — auto-activates the VFS overlay when entering
# a Kin repository (a directory whose .kin/ carries a repository manifest).
#
# Installed by: kin setup

_kin_vfs_disabled() {
    case "${KIN_VFS_DISABLE:-}" in
        1|[Tt][Rr][Uu][Ee]|[Yy][Ee][Ss]|[Oo][Nn]) return 0 ;;
        *) return 1 ;;
    esac
}

_kin_vfs_logical_dir() {
    (
        unset CDPATH
        builtin cd -L -- "$1" 2>/dev/null || return 1
        builtin pwd -L
    )
}

_kin_vfs_physical_dir() {
    (
        unset CDPATH
        builtin cd -P -- "$1" 2>/dev/null || return 1
        builtin pwd -P
    )
}

_kin_vfs_path_within() {
    local path="$1"
    local root="$2"
    [ "$path" = "$root" ] && return 0
    [ "$root" = "/" ] && return 0
    case "$path" in
        "$root"/*) return 0 ;;
        *) return 1 ;;
    esac
}

# A `.kin` directory names a repository only when it carries the manifest
# `kin init` writes there. The managed toolchain home ($KIN_HOME, default
# $HOME/.kin) is a real `.kin` directory too, holding bin/, lib/, shell/ and
# config/, so a walk that asks only whether `.kin` is a directory binds $HOME
# itself as a projection root, and every path under it then belongs to a
# projection no daemon serves. The kin-vfs shim admits a root on this same
# file, so both halves answer the containment question the same way.
_kin_vfs_is_repository() {
    [ -f "$1/.kin/manifest.json" ]
}

_kin_vfs_scan_path() {
    local dir="$1"
    local boundary="$2"
    while :; do
        # A Kin marker is authority only when it is a real local directory
        # holding a repository manifest. During a session it may win over a
        # same-directory .git marker only at the exact validated session root.
        if [ -e "$dir/.kin" ] || [ -L "$dir/.kin" ]; then
            [ -d "$dir/.kin" ] && [ ! -L "$dir/.kin" ] || return 1
            if _kin_vfs_is_repository "$dir"; then
                if [ -n "$boundary" ] && [ "$dir" != "$boundary" ]; then
                    return 1
                fi
                printf '%s' "$dir"
                return 0
            fi
        fi
        # Files, directories, and even broken symlinks are Git boundaries.
        if [ -e "$dir/.git" ] || [ -L "$dir/.git" ]; then
            return 1
        fi
        if [ -n "$boundary" ] && [ "$dir" = "$boundary" ]; then
            return 1
        fi
        [ "$dir" != "/" ] || return 1
        dir="${dir%/*}"
        [ -n "$dir" ] || dir="/"
    done
}

_kin_vfs_find_workspace() {
    _kin_vfs_disabled && return 1

    local logical physical
    local session_logical="" session_physical=""
    local logical_workspace physical_workspace logical_workspace_physical
    logical="$(_kin_vfs_logical_dir "$1")" || return 1
    physical="$(_kin_vfs_physical_dir "$1")" || return 1

    if [ -n "${KIN_SESSION_DIR:-}" ]; then
        case "$KIN_SESSION_DIR" in
            /*) ;;
            *) return 1 ;;
        esac
        session_logical="$(_kin_vfs_logical_dir "$KIN_SESSION_DIR")" || return 1
        session_physical="$(_kin_vfs_physical_dir "$KIN_SESSION_DIR")" || return 1
        _kin_vfs_path_within "$logical" "$session_logical" || return 1
        _kin_vfs_path_within "$physical" "$session_physical" || return 1
    fi

    logical_workspace="$(_kin_vfs_scan_path "$logical" "$session_logical")" || return 1
    physical_workspace="$(_kin_vfs_scan_path "$physical" "$session_physical")" || return 1
    logical_workspace_physical="$(_kin_vfs_physical_dir "$logical_workspace")" || return 1
    [ "$logical_workspace_physical" = "$physical_workspace" ] || return 1

    if [ -n "$session_logical" ]; then
        [ "$logical_workspace" = "$session_logical" ] || return 1
        [ "$physical_workspace" = "$session_physical" ] || return 1
    fi

    printf '%s' "$physical_workspace"
}

_kin_vfs_shim_path() {
    local lib
    local kin_home="${KIN_HOME:-$HOME/.kin}"
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

# A socket file outlives the daemon that bound it, so only a connect
# answered by a listener proves one is behind it. `kin-vfs status` exits 0
# for a stale socket too; its Status line carries the verdict.
_kin_vfs_daemon_listening() {
    local out
    out="$(kin-vfs status --workspace "$1" 2>/dev/null)" || return 1
    case "$out" in
        *"Status:"*"running"*) return 0 ;;
        *) return 1 ;;
    esac
}

_kin_vfs_activate() {
    local ws="$1"
    local sock="$ws/.kin/vfs.sock"
    unset KIN_VFS_WORKSPACE_ALIASES KIN_VFS_PIPE
    unset KIN_VFS_CANARY KIN_VFS_INTERPOSE_ACTIVE KIN_VFS_LAST_DIR
    export KIN_VFS_WORKSPACE="$ws"
    export KIN_VFS_SOCK="$sock"
    # -S is only a pre-filter (nothing to probe without a socket); the
    # listener probe decides. `kin-vfs start` connects first and unlinks a
    # stale socket itself before binding fresh.
    if [ ! -S "$sock" ] || ! _kin_vfs_daemon_listening "$ws"; then
        if command -v kin-vfs >/dev/null 2>&1; then
            kin-vfs start --workspace "$ws" >/dev/null 2>&1 &
            disown 2>/dev/null
            local attempts=0
            while [ "$attempts" -lt 10 ]; do
                if [ -S "$sock" ] && _kin_vfs_daemon_listening "$ws"; then
                    break
                fi
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
    unset KIN_VFS_WORKSPACE KIN_VFS_WORKSPACE_ALIASES
    unset KIN_VFS_SOCK KIN_VFS_PIPE
    unset KIN_VFS_CANARY KIN_VFS_INTERPOSE_ACTIVE KIN_VFS_LAST_DIR
    _kin_vfs_clear_preload
}

_kin_vfs_prompt_command() {
    _KIN_VFS_LAST_DIR="$PWD"
    local ws
    if _kin_vfs_disabled; then
        _kin_vfs_deactivate
        return
    fi
    ws="$(_kin_vfs_find_workspace "$PWD")"
    if [ -n "$ws" ]; then
        if [ "$ws" != "${KIN_VFS_WORKSPACE:-}" ] ||
           [ -n "${KIN_VFS_WORKSPACE_ALIASES:-}" ] ||
           [ "${KIN_VFS_SOCK:-}" != "$ws/.kin/vfs.sock" ] ||
           [ -n "${KIN_VFS_PIPE:-}" ]; then
            _kin_vfs_activate "$ws"
        else
            _kin_vfs_refresh_preload
        fi
    else
        _kin_vfs_deactivate
    fi
}

# Kin-family control-plane binaries must not be injected with the shim.
# External tools (editors, builds) keep the shim via the global env var.
#
# Every wrapper clears the preload variables inline and depends on no other
# function. A consumer that replays these definitions into another shell
# carries the whole exclusion with them, so the wrapper cannot resolve to a
# missing helper.
_kin_vfs_exec_without_preload() {
    DYLD_INSERT_LIBRARIES= LD_PRELOAD= command "$@"
}

kin() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin "$@"; }
kin-real() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-real "$@"; }
kin-daemon() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-daemon "$@"; }
kin-mcp() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-mcp "$@"; }
kin-vfs() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-vfs "$@"; }
kin-bench-prep() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-bench-prep "$@"; }
kin-bench-eval() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-bench-eval "$@"; }
kin-bench-target() { DYLD_INSERT_LIBRARIES= LD_PRELOAD= command kin-bench-target "$@"; }

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
$script:KinVfsPathComparison = if ([int][System.IO.Path]::DirectorySeparatorChar -eq 92) {
    [System.StringComparison]::OrdinalIgnoreCase
} else {
    [System.StringComparison]::Ordinal
}

function Test-KinVfsDisabled {
    if ([string]::IsNullOrWhiteSpace($env:KIN_VFS_DISABLE)) {
        return $false
    }
    return @("1", "true", "yes", "on") -contains $env:KIN_VFS_DISABLE.Trim().ToLowerInvariant()
}

function Normalize-KinLogicalDirectory {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathRooted($Path)) {
        return $null
    }
    try {
        $full = [System.IO.Path]::GetFullPath($Path)
        if (-not [System.IO.Directory]::Exists($full)) {
            return $null
        }
        $root = [System.IO.Path]::GetPathRoot($full)
        if (-not $full.Equals($root, $script:KinVfsPathComparison)) {
            $full = $full.TrimEnd([char[]]@([char]47, [char]92))
        }
        return $full
    } catch {
        return $null
    }
}

function Resolve-KinPhysicalDirectory {
    param([string]$Path)
    $logical = Normalize-KinLogicalDirectory -Path $Path
    if (-not $logical) {
        return $null
    }

    try {
        $root = [System.IO.Path]::GetPathRoot($logical)
        $current = $root
        $remainder = $logical.Substring($root.Length)
        $separators = [char[]]@(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        )
        $parts = $remainder.Split(
            $separators,
            [System.StringSplitOptions]::RemoveEmptyEntries
        )

        foreach ($part in $parts) {
            $candidate = [System.IO.Path]::Combine($current, $part)
            $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
            if (-not $item.PSIsContainer) {
                return $null
            }
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                # ResolveLinkTarget(true) resolves the complete remaining link
                # chain. Older runtimes without it fail closed on reparse paths.
                if ($item.PSObject.Methods.Name -notcontains "ResolveLinkTarget") {
                    return $null
                }
                $item = $item.ResolveLinkTarget($true)
                if (-not $item -or -not $item.PSIsContainer) {
                    return $null
                }
            }
            $current = [System.IO.Path]::GetFullPath($item.FullName)
        }
        return Normalize-KinLogicalDirectory -Path $current
    } catch {
        return $null
    }
}

function Test-KinPathEqual {
    param([string]$Left, [string]$Right)
    return $Left.Equals($Right, $script:KinVfsPathComparison)
}

function Test-KinPathWithin {
    param([string]$Path, [string]$Root)
    if ((Test-KinPathEqual -Left $Path -Right $Root) -or
        (Test-KinPathEqual -Left $Root -Right ([System.IO.Path]::GetPathRoot($Root)))) {
        return $true
    }
    $prefix = $Root + [System.IO.Path]::DirectorySeparatorChar
    return $Path.StartsWith($prefix, $script:KinVfsPathComparison)
}

function Test-KinMarkerExists {
    param([string]$Path)
    try {
        $null = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return $true
    } catch [System.Management.Automation.ItemNotFoundException] {
        return $false
    } catch {
        # An unreadable marker is still an authority boundary.
        return $true
    }
}

# A `.kin` directory names a repository only when it carries the manifest
# `kin init` writes there. The managed toolchain home ($KIN_HOME, default
# $HOME/.kin) is a real `.kin` directory too, holding bin/, lib/, shell/ and
# config/, so a walk that asks only whether `.kin` is a directory binds the
# home directory itself as a projection root, and every path under it then
# belongs to a projection no daemon serves. The kin-vfs shim admits a root on
# this same file, so both halves answer the containment question the same way.
function Test-KinRepository {
    param([string]$Path)
    try {
        return [System.IO.File]::Exists((Join-Path (Join-Path $Path ".kin") "manifest.json"))
    } catch {
        return $false
    }
}

function Find-KinWorkspaceOnPath {
    param([string]$StartDir, [string]$Boundary)
    $dir = $StartDir
    while ($dir) {
        $kinMarker = Join-Path $dir ".kin"
        if (Test-KinMarkerExists -Path $kinMarker) {
            try {
                $kinItem = Get-Item -LiteralPath $kinMarker -Force -ErrorAction Stop
            } catch {
                return $null
            }
            if (-not $kinItem.PSIsContainer -or
                (($kinItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)) {
                return $null
            }
            if (Test-KinRepository -Path $dir) {
                if ($Boundary -and -not (Test-KinPathEqual -Left $dir -Right $Boundary)) {
                    return $null
                }
                return $dir
            }
        }
        if (Test-KinMarkerExists -Path (Join-Path $dir ".git")) {
            return $null
        }
        if ($Boundary -and (Test-KinPathEqual -Left $dir -Right $Boundary)) {
            return $null
        }
        $parent = [System.IO.Directory]::GetParent($dir)
        if (-not $parent) {
            return $null
        }
        $dir = $parent.FullName
    }
    return $null
}

function Find-KinWorkspace {
    param([string]$StartDir)
    if (Test-KinVfsDisabled) {
        return $null
    }

    $logical = Normalize-KinLogicalDirectory -Path $StartDir
    $physical = Resolve-KinPhysicalDirectory -Path $StartDir
    if (-not $logical -or -not $physical) {
        return $null
    }

    $sessionLogical = $null
    $sessionPhysical = $null
    if (-not [string]::IsNullOrWhiteSpace($env:KIN_SESSION_DIR)) {
        $sessionLogical = Normalize-KinLogicalDirectory -Path $env:KIN_SESSION_DIR
        $sessionPhysical = Resolve-KinPhysicalDirectory -Path $env:KIN_SESSION_DIR
        if (-not $sessionLogical -or -not $sessionPhysical) {
            return $null
        }
        if (-not (Test-KinPathWithin -Path $logical -Root $sessionLogical) -or
            -not (Test-KinPathWithin -Path $physical -Root $sessionPhysical)) {
            return $null
        }
    }

    $logicalWorkspace = Find-KinWorkspaceOnPath -StartDir $logical -Boundary $sessionLogical
    $physicalWorkspace = Find-KinWorkspaceOnPath -StartDir $physical -Boundary $sessionPhysical
    if (-not $logicalWorkspace -or -not $physicalWorkspace) {
        return $null
    }
    $logicalWorkspacePhysical = Resolve-KinPhysicalDirectory -Path $logicalWorkspace
    if (-not $logicalWorkspacePhysical -or
        -not (Test-KinPathEqual -Left $logicalWorkspacePhysical -Right $physicalWorkspace)) {
        return $null
    }
    if ($sessionLogical -and
        (-not (Test-KinPathEqual -Left $logicalWorkspace -Right $sessionLogical) -or
         -not (Test-KinPathEqual -Left $physicalWorkspace -Right $sessionPhysical))) {
        return $null
    }
    return $physicalWorkspace
}

function Enable-KinVfs {
    param([string]$Workspace)
    $pipe = "\\.\pipe\kin-vfs-$([System.IO.Path]::GetFileName($Workspace))"
    Disable-KinVfs
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
    foreach ($name in @(
        "KIN_VFS_WORKSPACE",
        "KIN_VFS_WORKSPACE_ALIASES",
        "KIN_VFS_SOCK",
        "KIN_VFS_PIPE",
        "KIN_VFS_CANARY",
        "KIN_VFS_INTERPOSE_ACTIVE",
        "KIN_VFS_LAST_DIR",
        "DYLD_INSERT_LIBRARIES",
        "LD_PRELOAD"
    )) {
        Remove-Item "Env:\$name" -ErrorAction SilentlyContinue
    }
    $script:KinVfsActive = $false
    $script:KinVfsWorkspace = ""
}

function Invoke-KinVfsLocationCheck {
    if (Test-KinVfsDisabled) {
        Disable-KinVfs
        return
    }
    $ws = Find-KinWorkspace -StartDir $PWD.Path
    if ($ws) {
        $expectedPipe = "\\.\pipe\kin-vfs-$([System.IO.Path]::GetFileName($ws))"
        if (-not (Test-KinPathEqual -Left $script:KinVfsWorkspace -Right $ws) -or
            $env:KIN_VFS_WORKSPACE_ALIASES -or
            $env:KIN_VFS_SOCK -or
            $env:KIN_VFS_PIPE -ne $expectedPipe) {
            Enable-KinVfs -Workspace $ws
        }
    } else {
        Disable-KinVfs
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

function _kin_vfs_disabled
    if not set -q KIN_VFS_DISABLE
        return 1
    end
    switch (string lower -- (string trim -- "$KIN_VFS_DISABLE"))
        case 1 true yes on
            return 0
    end
    return 1
end

function _kin_vfs_logical_dir
    set -l candidate $argv[1]
    string match -qr '^/' -- "$candidate"; or return 1
    set -l normalized (path normalize -- "$candidate" 2>/dev/null); or return 1
    test -d "$normalized"; or return 1
    printf '%s' "$normalized"
end

function _kin_vfs_physical_dir
    set -l candidate $argv[1]
    string match -qr '^/' -- "$candidate"; or return 1
    set -l resolved (path resolve -- "$candidate" 2>/dev/null); or return 1
    test -d "$resolved"; or return 1
    printf '%s' "$resolved"
end

function _kin_vfs_path_within
    set -l candidate $argv[1]
    set -l root $argv[2]
    if test "$candidate" = "$root"; or test "$root" = /
        return 0
    end
    set -l prefix "$root/"
    set -l prefix_length (string length -- "$prefix")
    test (string sub -s 1 -l "$prefix_length" -- "$candidate") = "$prefix"
end

# A `.kin` directory names a repository only when it carries the manifest
# `kin init` writes there. The managed toolchain home ($KIN_HOME, default
# $HOME/.kin) is a real `.kin` directory too, holding bin/, lib/, shell/ and
# config/, so a walk that asks only whether `.kin` is a directory binds $HOME
# itself as a projection root, and every path under it then belongs to a
# projection no daemon serves. The kin-vfs shim admits a root on this same
# file, so both halves answer the containment question the same way.
function _kin_vfs_is_repository
    test -f "$argv[1]/.kin/manifest.json"
end

function _kin_vfs_scan_path
    set -l dir $argv[1]
    set -l boundary $argv[2]
    while true
        if test -e "$dir/.kin"; or test -L "$dir/.kin"
            test -d "$dir/.kin"; and not test -L "$dir/.kin"; or return 1
            if _kin_vfs_is_repository "$dir"
                if test -n "$boundary"; and test "$dir" != "$boundary"
                    return 1
                end
                printf '%s' "$dir"
                return 0
            end
        end
        if test -e "$dir/.git"; or test -L "$dir/.git"
            return 1
        end
        if test -n "$boundary"; and test "$dir" = "$boundary"
            return 1
        end
        test "$dir" != /; or return 1
        set dir (path dirname -- "$dir")
    end
end

function _kin_vfs_find_workspace
    _kin_vfs_disabled; and return 1

    set -l logical (_kin_vfs_logical_dir "$argv[1]")
    test -n "$logical"; or return 1
    set -l physical (_kin_vfs_physical_dir "$argv[1]")
    test -n "$physical"; or return 1
    set -l session_logical ""
    set -l session_physical ""

    if set -q KIN_SESSION_DIR; and test -n "$KIN_SESSION_DIR"
        string match -qr '^/' -- "$KIN_SESSION_DIR"; or return 1
        set session_logical (_kin_vfs_logical_dir "$KIN_SESSION_DIR")
        test -n "$session_logical"; or return 1
        set session_physical (_kin_vfs_physical_dir "$KIN_SESSION_DIR")
        test -n "$session_physical"; or return 1
        _kin_vfs_path_within "$logical" "$session_logical"; or return 1
        _kin_vfs_path_within "$physical" "$session_physical"; or return 1
    end

    set -l logical_workspace (_kin_vfs_scan_path "$logical" "$session_logical")
    test -n "$logical_workspace"; or return 1
    set -l physical_workspace (_kin_vfs_scan_path "$physical" "$session_physical")
    test -n "$physical_workspace"; or return 1
    set -l logical_workspace_physical (_kin_vfs_physical_dir "$logical_workspace")
    test -n "$logical_workspace_physical"; or return 1
    test "$logical_workspace_physical" = "$physical_workspace"; or return 1

    if test -n "$session_logical"
        test "$logical_workspace" = "$session_logical"; or return 1
        test "$physical_workspace" = "$session_physical"; or return 1
    end

    printf '%s' "$physical_workspace"
end

# A socket file outlives the daemon that bound it, so only a connect
# answered by a listener proves one is behind it. `kin-vfs status` exits 0
# for a stale socket too; its Status line carries the verdict.
function _kin_vfs_daemon_listening
    set -l out (kin-vfs status --workspace $argv[1] 2>/dev/null)
    or return 1
    string match -q '*Status:*running*' -- "$out"
end

function _kin_vfs_activate
    set -l ws $argv[1]
    set -l sock "$ws/.kin/vfs.sock"
    set -e KIN_VFS_WORKSPACE_ALIASES
    set -e KIN_VFS_PIPE
    set -e KIN_VFS_CANARY
    set -e KIN_VFS_INTERPOSE_ACTIVE
    set -e KIN_VFS_LAST_DIR
    set -gx KIN_VFS_WORKSPACE $ws
    set -gx KIN_VFS_SOCK $sock

    # -S is only a pre-filter (nothing to probe without a socket); the
    # listener probe decides. `kin-vfs start` connects first and unlinks a
    # stale socket itself before binding fresh.
    if not test -S $sock; or not _kin_vfs_daemon_listening $ws
        if command -sq kin-vfs
            kin-vfs start --workspace $ws &>/dev/null &
            disown
            set -l attempts 0
            while test $attempts -lt 10
                if test -S $sock; and _kin_vfs_daemon_listening $ws
                    break
                end
                sleep 0.1
                set attempts (math $attempts + 1)
            end
        end
    end

    if command -sq kin-vfs
        kin-vfs workspaces add --path $ws &>/dev/null 2>&1 &
        disown
    end

    set -e DYLD_INSERT_LIBRARIES
    set -e LD_PRELOAD
    set -l kin_home "$HOME/.kin"
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
    set -e KIN_VFS_WORKSPACE_ALIASES
    set -e KIN_VFS_SOCK
    set -e KIN_VFS_PIPE
    set -e KIN_VFS_CANARY
    set -e KIN_VFS_INTERPOSE_ACTIVE
    set -e KIN_VFS_LAST_DIR
    set -e DYLD_INSERT_LIBRARIES
    set -e LD_PRELOAD
    set -g _KIN_VFS_WORKSPACE ""
end

# Kin-family control-plane binaries must not be injected with the shim.
# External tools (editors, builds) keep the shim via the global env var.
# The set covers the same binaries the zsh and bash hooks wrap.
function kin --wraps=kin --description 'Run kin without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin $argv
end

function kin-real --wraps=kin-real --description 'Run kin-real without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-real $argv
end

function kin-daemon --wraps=kin-daemon --description 'Run kin-daemon without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-daemon $argv
end

function kin-mcp --wraps=kin-mcp --description 'Run kin-mcp without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-mcp $argv
end

function kin-vfs --wraps=kin-vfs --description 'Run kin-vfs without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-vfs $argv
end

function kin-bench-prep --wraps=kin-bench-prep --description 'Run kin-bench-prep without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-bench-prep $argv
end

function kin-bench-eval --wraps=kin-bench-eval --description 'Run kin-bench-eval without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-bench-eval $argv
end

function kin-bench-target --wraps=kin-bench-target --description 'Run kin-bench-target without VFS shim'
    set -lx DYLD_INSERT_LIBRARIES
    set -lx LD_PRELOAD
    command kin-bench-target $argv
end

function _kin_vfs_chpwd --on-variable PWD
    if _kin_vfs_disabled
        _kin_vfs_deactivate
        return
    end

    set -l ws (_kin_vfs_find_workspace "$PWD")
    if test -n "$ws"
        if test "$_KIN_VFS_WORKSPACE" != "$ws"; or \
           set -q KIN_VFS_WORKSPACE_ALIASES; or \
           not set -q KIN_VFS_SOCK; or \
           test "$KIN_VFS_SOCK" != "$ws/.kin/vfs.sock"; or \
           set -q KIN_VFS_PIPE
            _kin_vfs_activate "$ws"
            set -g _KIN_VFS_WORKSPACE $ws
        end
    else
        _kin_vfs_deactivate
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
    /// Skip the per-client MCP round trip that proves a written config can
    /// actually reach Kin. For a scripted install with no repository yet, where
    /// there is nothing for a tool call to answer about. The skip is printed
    /// per client rather than silently dropping the section.
    pub skip_mcp_check: bool,
    /// Install the language servers Kin enriches with, without asking.
    ///
    /// Needed because the install is a network download into a shared prefix.
    /// Without it an interactive run asks and a scripted one prints the command
    /// and changes nothing.
    pub install_language_servers: bool,
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
    /// Local setup plus the real KinLab sign-in state and the commands that
    /// change it.
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
            Self::Hosted => "Hosted / KinLab (connect this machine)",
            Self::Advanced => "Advanced / manual (all toggles)",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Self::LocalOnly => "shell integration + auto-daemon; no AI client config",
            Self::AgentOnly => "configure Kin's MCP server for detected AI clients + auto-daemon",
            Self::Editor => "local-only, plus how to install the kin-editor extension",
            Self::Hosted => {
                "local setup, plus the sign-in state and commands for a KinLab workspace"
            }
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

/// The home directory every setup artifact is written relative to.
///
/// `directories::BaseDirs::new()` resolves a Windows home only when
/// `FOLDERID_Profile`, `FOLDERID_RoamingAppData` **and** `FOLDERID_LocalAppData`
/// all resolve — each of them existence-verified, because the crate passes
/// `dwFlags = 0` — and it never reads `USERPROFILE`. A profile root carrying no
/// `AppData` subtree therefore collapses the whole constructor to `None`, and
/// setup aborts with "could not determine home directory" before writing
/// anything. That is not hypothetical: it is exactly how the public install
/// proof's isolated-home leg fails on `windows-latest`, where the isolated
/// profile is a bare directory.
///
/// So on Windows the profile root the environment explicitly names wins, then
/// the profile-only known-folder lookup, and the AppData-requiring constructor
/// is only the last resort. Preferring the explicit name is also what keeps an
/// isolated home *isolated*: a lookup that answers from the machine's own known
/// folders would quietly resolve the real profile instead of the override, so a
/// caller that believed it had redirected the home would be writing to the
/// user's real one.
///
/// Unix is deliberately untouched and stays on `BaseDirs`, which already reads
/// `HOME` first and falls back to the passwd database.
pub(crate) fn home_dir() -> Result<PathBuf> {
    resolve_home_dir(
        cfg!(windows),
        |key| env::var_os(key),
        || directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
        || directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
    )
    .context("could not determine home directory")
}

/// The platform-conditional policy behind [`home_dir`], with the platform, the
/// environment, and both OS lookups taken as arguments.
///
/// The Windows arm is a runtime branch rather than a `#[cfg]` block on purpose:
/// gated behind `cfg`, it would be compiled — and therefore tested — only on
/// the one platform this fleet has no host for, which is how the defect above
/// survived to a release proof. As written it is compiled and exercised on
/// every host, and it reads nothing ambient, so a test states the whole
/// environment it is asserting against.
///
/// `known_profile_root` is the profile-only lookup (`FOLDERID_Profile` on
/// Windows); `base_dirs_home` is the stricter `BaseDirs` constructor.
///
/// Visible to the crate because the Hugging Face cache probe in
/// `crate::retrieval_profile` mirrors the same layout and must resolve the home
/// the same way. A second resolver there is what produced the `HOME`-only
/// lookup that never matched on Windows.
pub(crate) fn resolve_home_dir(
    windows: bool,
    var_os: impl Fn(&str) -> Option<OsString>,
    known_profile_root: impl FnOnce() -> Option<PathBuf>,
    base_dirs_home: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    if windows {
        // An empty value is not a home; every Windows tool that reads this
        // name treats it the same as unset.
        if let Some(profile) = var_os("USERPROFILE").filter(|value| !value.is_empty()) {
            return Some(PathBuf::from(profile));
        }
        return known_profile_root().or_else(base_dirs_home);
    }
    base_dirs_home()
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
fn copy_shim(src: &Path, dest: &Path) -> Result<ShimCopy> {
    if same_file(src, dest) {
        return Ok(ShimCopy::Skipped);
    }
    fs::copy(src, dest).with_context(|| format!("failed to copy shim to {}", dest.display()))?;
    Ok(ShimCopy::Copied)
}

pub(crate) fn find_shim() -> Option<PathBuf> {
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
fn restore_shim_from_sources(dest: &Path, sources: &[PathBuf]) -> Result<Option<PathBuf>> {
    for src in sources {
        if is_usable_shim(src) {
            copy_shim(src, dest)?;
            return Ok(Some(dest.to_path_buf()));
        }
    }
    Ok(None)
}

/// Whether the environment carries PowerShell's markers.
///
/// `PSModulePath` is machine-scoped: the Windows installer sets it for every
/// process, PowerShell exports it to its children on every platform, and hosted
/// CI images that merely ship `pwsh` export it into shells that are not
/// PowerShell at all. It therefore proves PowerShell is present, not that this
/// process is running under it.
fn powershell_environment_markers() -> bool {
    env::var_os("PSModulePath").is_some() || env::var_os("PSVersionTable").is_some()
}

pub(crate) fn detect_shell() -> &'static str {
    // On Windows PowerShell is the shell Kin configures and its markers are the
    // reliable signal. `SHELL` there is set by whatever POSIX layer (Git Bash,
    // MSYS) launched the process and does not name the shell a user configures
    // Kin for, so it must not outrank them.
    if cfg!(target_os = "windows") && powershell_environment_markers() {
        return "powershell";
    }

    // Everywhere else `SHELL` names the user's own shell and outranks the
    // PowerShell markers, which on Unix say only that PowerShell exists on the
    // machine. Reading the markers first detected bash and zsh operators as
    // PowerShell, wrote the hook to a profile their shell never loads, and then
    // reported the shell integration they were actually using as misconfigured.
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

    // No POSIX shell named itself. The markers are the remaining evidence, so
    // `pwsh` on Unix is still detected whenever `SHELL` cannot answer.
    if powershell_environment_markers() {
        return "powershell";
    }

    fallback_shell()
}

/// The shell to configure when nothing in the environment names one.
///
/// `SHELL` is unset in containers, cron, and most non-login invocations, which
/// is exactly where first-run happens. A flat default of zsh then wrote the hook
/// and the PATH line into a `.zshrc` on hosts with no zsh installed, reported
/// that as shell integration installed, and disagreed with the installer, which
/// had already chosen `.bashrc` for the same install. Choose a shell the host
/// actually has, in the platform's own order of preference, so the two agree.
fn fallback_shell() -> &'static str {
    // On Windows the PowerShell markers above are the signal Kin acts on, and a
    // Git-for-Windows PATH routinely carries a bash that is not the shell anyone
    // configures Kin for. Leave that platform on its historical default.
    if cfg!(target_os = "windows") {
        return "zsh";
    }

    let ordered: [&'static str; 3] = if cfg!(target_os = "macos") {
        ["zsh", "bash", "fish"]
    } else {
        ["bash", "zsh", "fish"]
    };
    ordered
        .into_iter()
        .find(|shell| check_binary_in_path(shell).is_some())
        .unwrap_or(ordered[0])
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

/// The files bash reads for a login shell, in the order bash reads them.
///
/// bash runs the FIRST of these that it can read and none of the rest, and
/// `.bashrc` is not among them at all: a login bash reads `.bashrc` only when
/// one of these files sources it. So a PATH line written to `.bashrc` alone is
/// invisible to `bash -lc`, to an ssh login, and to a macOS Terminal tab, which
/// opens a login shell by default.
const BASH_LOGIN_RCS: [&str; 3] = [".bash_profile", ".bash_login", ".profile"];

/// What Kin seeds a `.bash_profile` with when it has to create one.
///
/// A home with none of [`BASH_LOGIN_RCS`] gives a login bash no user file to
/// read, so Kin creating `.bash_profile` is what puts the PATH line somewhere a
/// login shell will find it. Pairing it with the conventional source line keeps
/// an interactive login shell equivalent to an interactive non-login one, which
/// is what a bash user expects of a home that has both files.
///
/// The interactivity guard is deliberate and is the same rule [`shell_rc`]
/// follows for zsh. `.bashrc` carries the projection hook, which activates the
/// VFS overlay on entry, and `bash -lc` is a login shell that is not
/// interactive, so an unguarded source line here would inject the shim into
/// every scripted login shell.
///
/// Kin writes this only into a file it creates. An existing `.bash_profile`,
/// `.bash_login` or `.profile` keeps whatever semantics its owner gave it and
/// receives nothing but the PATH block.
const BASH_PROFILE_SEED: &str = "\
# Created by kin setup.
#
# A login bash reads .bash_profile, .bash_login or .profile, the first one only,
# and never .bashrc, so Kin's PATH line below has to live here. Sourcing
# ~/.bashrc keeps an interactive login shell equivalent to an interactive
# non-login one; the guard keeps it out of `bash -lc`, which is not interactive.
case $- in
    *i*) [ -f \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\" ;;
esac
";

/// The login file bash will actually read in `home`.
///
/// Mirrors bash's own resolution: first existing wins. When none exists there is
/// nothing to append to, and `.bash_profile` is the file to create, because it
/// is the one bash looks at first and the one that belongs to bash alone.
/// `.profile` is shared with `sh` and every other POSIX shell, so Kin never
/// conjures that one.
fn bash_login_rc_in(home: &Path) -> PathBuf {
    BASH_LOGIN_RCS
        .iter()
        .map(|name| home.join(name))
        .find(|path| path.exists())
        .unwrap_or_else(|| home.join(BASH_LOGIN_RCS[0]))
}

/// Every file this shell's PATH line belongs in, which is not always the one its
/// hook belongs in, and for bash is not one file.
///
/// zsh reads `.zshenv` on every launch and `.zshrc` only when the shell is
/// interactive, so a PATH line written to `.zshrc` alone leaves `kin` unfindable
/// in a script, a Makefile, a `sh -c` from an editor, a launchd or systemd job,
/// or an agent shelling out. Those are exactly the callers a semantic repo
/// substrate is meant to serve.
///
/// bash splits the same way along a different seam. `.bashrc` serves an
/// interactive non-login shell and nothing else, so the PATH line needs a second
/// home in the file a login shell reads, chosen by [`bash_login_rc_in`]. Both
/// get it: dropping it from `.bashrc` would take `kin` away from the terminal
/// that opens a non-login shell, which is most of Linux.
///
/// The hook must not move with either. Sourcing the projection hook from
/// `.zshenv` or from a bash login file would inject the shim into every
/// non-interactive shell, which is the opposite of what the hook's own exclusion
/// wrappers exist for, so [`shell_rc`] keeps the hook in the interactive file and
/// this decides the PATH line separately.
///
/// fish and PowerShell read one file for both, so this returns [`shell_rc`] for
/// them, and the arms below mirror that function's exactly, including its
/// treatment of an unrecognized shell as zsh.
pub(crate) fn shell_path_rcs(shell: &str) -> Result<Vec<PathBuf>> {
    let home = home_dir()?;
    Ok(match shell {
        "bash" => vec![home.join(".bashrc"), bash_login_rc_in(&home)],
        "fish" | "powershell" => vec![shell_rc(shell)?],
        _ => vec![home.join(".zshenv")],
    })
}

pub(crate) fn hook_filename(shell: &str) -> &'static str {
    match shell {
        "bash" => "kin-vfs.bash",
        "fish" => "kin-vfs.fish",
        "powershell" => "kin-vfs.ps1",
        _ => "kin-vfs.zsh",
    }
}

pub(crate) fn hook_content(shell: &str) -> &'static str {
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

/// Exact public npm wrapper topology accepted by setup health.
///
/// Keep these values shared with the health parser rather than accepting an
/// arbitrary package spec or executable that merely happens to proxy Kin.
pub(crate) const CANONICAL_NPM_MCP_COMMAND: &str = "npx";
pub(crate) const CANONICAL_NPM_MCP_PACKAGE: &str = "@kinlab/kin";

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
fn kin_mcp_entry() -> Result<serde_json::Value> {
    let command = configured_mcp_launcher()?;
    Ok(serde_json::json!({
        "command": command,
        "args": ["mcp", "start"],
        "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
    }))
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
const IDX_ANTIGRAVITY: usize = 5;

/// The Claude Code CLI filename, by platform.
fn claude_cli_filename() -> &'static str {
    if cfg!(windows) {
        "claude.exe"
    } else {
        "claude"
    }
}

/// Whether Claude Code itself has left evidence of an install in `home`.
///
/// Every other client gets a filesystem fallback beside its PATH probe, so a
/// client installed outside the current `PATH` is still configured. Claude Code
/// had only the PATH probe, which is why it alone was skipped when its CLI
/// lives somewhere the invoking shell does not export — the native installer
/// drops it in `~/.local/bin`, which login shells add but non-login and CI
/// shells frequently do not.
///
/// The bare `~/.claude` directory never counts: `kin setup` creates it to
/// write the discovery reminder, so trusting it would let a previous setup
/// run manufacture its own evidence of an install that never happened.
/// `~/.claude.json` is accepted even though `configure_claude_code` can
/// create it, because non-interactive runs only configure clients this
/// detection already admitted; the remaining self-evidence path is an
/// operator explicitly selecting an undetected client in the advanced
/// picker, which is a deliberate override rather than manufactured
/// detection, and an uninstall excises Kin's key but leaves the file.
fn claude_code_install_evidence(home: &Path) -> bool {
    home.join(".claude.json").exists()
        || home.join(".claude").join("settings.json").exists()
        || home.join(".claude").join("config.json").exists()
        || home
            .join(".local")
            .join("bin")
            .join(claude_cli_filename())
            .exists()
}

/// Detect installed AI assistants eligible for MCP auto-configuration.
///
/// Detection heuristics per client:
/// - Claude Code: `claude` binary on PATH, or Claude Code's own state/config
///   files, or the native installer's `~/.local/bin/claude`
/// - Cursor: `cursor` binary on PATH, or `/Applications/Cursor.app`
/// - Codex CLI: `codex` binary on PATH
/// - Gemini CLI: `gemini` binary on PATH, or `~/.gemini` directory
/// - Windsurf: `windsurf` binary on PATH, or `/Applications/Windsurf.app`
fn detect_ai_assistants() -> Vec<AiAssistant> {
    let claude_detected = check_binary_in_path("claude").is_some()
        || home_dir()
            .map(|home| claude_code_install_evidence(&home))
            .unwrap_or(false);
    let cursor_detected = check_binary_in_path("cursor").is_some()
        || PathBuf::from("/Applications/Cursor.app").exists();
    let codex_detected = check_binary_in_path("codex").is_some();
    let gemini_detected = check_binary_in_path("gemini").is_some()
        || home_dir()
            .map(|h| h.join(".gemini").exists())
            .unwrap_or(false);
    let windsurf_detected = check_binary_in_path("windsurf").is_some()
        || PathBuf::from("/Applications/Windsurf.app").exists();
    let antigravity_detected = check_binary_in_path("agy").is_some()
        || check_binary_in_path("agy-ide").is_some()
        || PathBuf::from("/Applications/Antigravity.app").exists()
        || PathBuf::from("/Applications/Antigravity IDE.app").exists()
        || home_dir()
            .map(|home| home.join(".gemini").join("antigravity").exists())
            .unwrap_or(false);

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
        AiAssistant {
            name: "Google Antigravity",
            detected: antigravity_detected,
            install_hint: "install Google Antigravity",
        },
    ]
}

/// What setup may claim after writing one client's MCP config.
///
/// "Configured" is a statement about a client that is on this machine. Setup
/// writes for a client it did not detect only when an operator picked one in the
/// advanced picker, and saying "configured" there reports an install that does
/// not exist: the only new thing on disk is the config file Kin just created.
fn client_write_summary(name: &str, detected: bool, path: &Path) -> String {
    if detected {
        format!("{name} configured ({})", path.display())
    } else {
        format!(
            "{name} pre-configured for a client that is not installed ({})",
            path.display()
        )
    }
}

/// Names of the AI clients setup detects on this machine.
///
/// `kin doctor` reads this rather than keeping its own rule, because the two
/// answered differently in the same minute: doctor said "no AI client config
/// files detected, nothing to configure" from the absence of config files, and
/// `kin setup` then found a client and configured it. A config file is evidence
/// a client was configured, not evidence one is installed.
pub(crate) fn detected_ai_client_names() -> Vec<&'static str> {
    detect_ai_assistants()
        .into_iter()
        .filter(|assistant| assistant.detected)
        .map(|assistant| assistant.name)
        .collect()
}

/// Merge the "kin" MCP server entry into an existing JSON config file.
/// Creates the file if it doesn't exist.
fn merge_mcp_config(path: &PathBuf, target_id: &str) -> Result<()> {
    let topology = McpTopologyLock::acquire()?;
    merge_mcp_config_with_topology(path, target_id, &topology)
}

fn merge_mcp_config_with_topology(
    path: &PathBuf,
    target_id: &str,
    _topology: &McpTopologyLock,
) -> Result<()> {
    let lock = ConfigLock::acquire(path)?;
    let original = lock.original_bytes(path)?;
    let mut root: serde_json::Value = if let Some(content) = original.as_deref() {
        serde_json::from_slice(content).with_context(|| {
            format!(
                "existing file {} is not valid JSON — refusing to overwrite it. \
                 Fix or remove the file and try again.",
                path.display()
            )
        })?
    } else {
        serde_json::json!({})
    };

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

    let desired = kin_mcp_entry()?;
    let desired = desired
        .as_object()
        .context("generated Kin MCP entry is not an object")?;
    let servers = root["mcpServers"]
        .as_object_mut()
        .expect("mcpServers was validated as an object");
    if servers.get("kin").is_some_and(|value| !value.is_object()) {
        anyhow::bail!(
            "existing file {} has a non-object mcpServers.kin value — refusing to overwrite it",
            path.display()
        );
    }
    let entry_preexisted = servers.contains_key("kin");
    let entry = servers
        .entry("kin".to_string())
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .expect("Kin MCP entry was validated as an object");
    for key in ["command", "args"] {
        if let Some(value) = desired.get(key) {
            entry.insert(key.to_string(), value.clone());
        }
    }
    if !entry_preexisted {
        entry.remove("cwd");
    }
    if entry.get("env").is_some_and(|value| !value.is_object()) {
        anyhow::bail!(
            "existing file {} has a non-object mcpServers.kin.env value — refusing to overwrite it",
            path.display()
        );
    }
    let env = entry
        .entry("env".to_string())
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .expect("Kin MCP env was validated as an object");
    if let Some(desired_env) = desired.get("env").and_then(serde_json::Value::as_object) {
        for (key, value) in desired_env {
            env.insert(key.clone(), value.clone());
        }
    }
    let owned_entry = root["mcpServers"]["kin"].clone();
    let formatted = serde_json::to_vec_pretty(&root).context("failed to serialize MCP config")?;
    lock.write_guarded(path, &formatted, original.as_deref())?;
    record_mcp_entry_in_ledger(target_id, path, &owned_entry)
}

fn record_mcp_entry_in_ledger(
    target_id: &str,
    path: &Path,
    entry: &serde_json::Value,
) -> Result<()> {
    use crate::commands::setup_ledger::{ledger_path, LedgerEntry, SetupLedger};

    let ledger_path = ledger_path()?;
    SetupLedger::update(&ledger_path, |ledger| {
        ledger.record(LedgerEntry::mcp(
            target_id.to_string(),
            path.to_path_buf(),
            entry,
        ));
        Ok(())
    })
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

    merge_mcp_config(&target, "claude")?;
    Ok(target)
}

/// Configure MCP for Cursor (global config).
fn configure_cursor() -> Result<PathBuf> {
    let home = home_dir()?;
    let target = home.join(".cursor").join("mcp.json");
    merge_mcp_config(&target, "cursor")?;
    Ok(target)
}

/// Merge the "kin" MCP server entry into a TOML MCP config (Codex CLI's
/// `~/.codex/config.toml`). Creates the file if it doesn't exist.
///
/// Codex reads MCP servers from `[mcp_servers.<name>]` tables in
/// `config.toml` — it does not read an `mcp.json`. Uses a format-preserving
/// TOML edit so unrelated keys, tables, and comments in the user's config are
/// left untouched.
fn merge_mcp_config_toml(path: &PathBuf, repo_root: &Path) -> Result<()> {
    let topology = McpTopologyLock::acquire()?;
    merge_mcp_config_toml_with_topology(path, repo_root, &topology)
}

fn merge_mcp_config_toml_with_topology(
    path: &PathBuf,
    repo_root: &Path,
    _topology: &McpTopologyLock,
) -> Result<()> {
    let lock = ConfigLock::acquire(path)?;
    let entry = kin_mcp_entry()?;
    let command = entry
        .get("command")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("kin");
    merge_mcp_config_toml_locked(path, repo_root, &lock, "codex", command)
}

fn merge_mcp_config_toml_locked(
    path: &PathBuf,
    repo_root: &Path,
    lock: &ConfigLock,
    target_id: &str,
    command: &str,
) -> Result<()> {
    use toml_edit::{value, Array, DocumentMut, InlineTable, Item, Table};

    let repo_root = canonical_initialized_repo(repo_root).with_context(|| {
        format!(
            "Codex MCP binding requires an initialized Kin repository: {}",
            repo_root.display()
        )
    })?;
    let original = lock.original_bytes(path)?;
    let mut doc: DocumentMut = if let Some(content) = original.as_deref() {
        std::str::from_utf8(content)
            .with_context(|| format!("existing file {} is not UTF-8", path.display()))?
            .parse()
            .with_context(|| {
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

    let servers = doc["mcp_servers"]
        .as_table_mut()
        .expect("mcp_servers was normalized to a table");
    let existing = servers.remove("kin");
    let entry_preexisted = existing.is_some();
    let kin = match existing {
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
    servers.insert("kin", Item::Table(kin));
    let kin = doc["mcp_servers"]["kin"]
        .as_table_mut()
        .expect("Kin MCP entry was validated as a table");
    kin.insert("command", value(command));
    let mut args = Array::new();
    args.push("mcp");
    args.push("start");
    args.push("--repo");
    args.push(repo_root.to_string_lossy().into_owned());
    kin.insert("args", value(args));
    if !entry_preexisted {
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

    let formatted = doc.to_string();
    lock.write_guarded(path, formatted.as_bytes(), original.as_deref())?;
    let owned_entry = read_kin_mcp_entry_from_bytes(path, formatted.as_bytes())
        .context("generated Codex MCP entry is missing")?;
    record_mcp_entry_in_ledger(target_id, path, &owned_entry)
}

/// Configure MCP for Codex CLI.
///
/// Codex reads MCP servers from `~/.codex/config.toml` (`[mcp_servers.<name>]`
/// tables with `command`/`args`/`env`), not from an `mcp.json` file.
fn configure_codex() -> Result<PathBuf> {
    let home = home_dir()?;
    let target = home.join(".codex").join("config.toml");
    let cwd = env::current_dir().context("could not determine the current directory")?;
    let repo_root = crate::commands::managed_config_scope::discover_repo_root()
        .and_then(|root| root.canonicalize().ok())
        .with_context(|| {
            format!(
                "Codex MCP setup requires an initialized Kin repository; run `kin init` in the target repository and re-run `kin setup` from it (current directory: {})",
                cwd.display()
            )
        })?;
    merge_mcp_config_toml(&target, &repo_root)?;
    Ok(target)
}

/// Configure MCP for Gemini CLI.
///
/// Gemini CLI persists MCP servers in `~/.gemini/settings.json` under the
/// top-level `mcpServers` key (same shape as other agents: `command` + `args`).
fn configure_gemini_cli() -> Result<PathBuf> {
    let home = home_dir()?;
    let target = home.join(".gemini").join("settings.json");
    merge_mcp_config(&target, "gemini")?;
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
    merge_mcp_config(&target, "windsurf")?;
    Ok(target)
}

fn current_initialized_setup_repo(client: &str) -> Result<PathBuf> {
    let cwd = env::current_dir().context("could not determine the current directory")?;
    crate::commands::managed_config_scope::discover_repo_root()
        .and_then(|root| root.canonicalize().ok())
        .and_then(|root| canonical_initialized_repo(&root))
        .with_context(|| {
            format!(
                "{client} MCP setup requires an initialized Kin repository; run `kin init` in the target repository and re-run `kin setup` from it (current directory: {})",
                cwd.display()
            )
        })
}

/// Configure current Antigravity's global MCP authority and the exact
/// checkout-local workspace binding in one topology transaction. The older
/// antigravity-ide path is touched only when it already contains a Kin entry.
fn configure_antigravity() -> Result<PathBuf> {
    let home = home_dir()?;
    let repo_root = current_initialized_setup_repo("Antigravity")?;
    let global = home.join(".gemini").join("config").join("mcp_config.json");
    let legacy = home
        .join(".gemini")
        .join("antigravity-ide")
        .join("mcp_config.json");
    let workspace = repo_root.join(".agents").join("mcp_config.json");
    let topology = McpTopologyLock::acquire()?;
    ensure_workspace_mcp_git_excluded(&repo_root)?.with_context(|| {
        format!(
            "Antigravity workspace binding requires trusted Git authority at {}",
            repo_root.display()
        )
    })?;

    let mut targets = vec![
        McpRepairTarget {
            id: "antigravity".to_string(),
            path: global.clone(),
            repo_root: Some(repo_root.clone()),
            captured_config_sha256: "0".repeat(64),
        },
        McpRepairTarget {
            id: "antigravity_workspace".to_string(),
            path: workspace,
            repo_root: Some(repo_root.clone()),
            captured_config_sha256: "0".repeat(64),
        },
    ];
    if legacy.exists() && has_kin_mcp_config(&legacy) {
        targets.push(McpRepairTarget {
            id: "antigravity".to_string(),
            path: legacy,
            repo_root: Some(repo_root),
            captured_config_sha256: "0".repeat(64),
        });
    }
    let paths = targets
        .iter()
        .map(|target| target.path.clone())
        .collect::<Vec<_>>();
    let mut locks = ConfigLock::acquire_many(&paths)?;
    let command = configured_mcp_launcher()?;
    for (target, lock) in targets.iter().zip(&mut locks) {
        merge_json_mcp_target_locked(target, &command, lock)?;
        lock.refresh_locked_state()?;
    }
    drop(topology);
    Ok(global)
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

/// Heading the reminder is recognized by, and the line setup names before it
/// appends anything to a user's global instruction file.
const KIN_DISCOVERY_MARKER: &str = "## Kin-first discovery (added by `kin setup`)";

/// Whether an instruction file already carries Kin's reminder heading.
fn discovery_reminder_marker_present(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|content| content.contains(KIN_DISCOVERY_MARKER))
        .unwrap_or(false)
}

/// Append the Kin-first discovery reminder to an agent instruction file
/// (e.g. `~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`).
///
/// Idempotent: skips if the marker is already present.
fn inject_discovery_reminder(path: &PathBuf) -> Result<()> {
    let existing = if path.exists() {
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?
    } else {
        String::new()
    };

    if existing.contains(KIN_DISCOVERY_MARKER) {
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

/// One agent instruction file setup can append the Kin-first discovery reminder
/// to, paired with the client whose MCP registration makes that directive true.
struct DiscoveryReminderTarget {
    /// Assistant index whose MCP registration the directive depends on.
    client: usize,
    /// Human label used in setup output.
    label: &'static str,
    /// Stable ledger target id for the appended block.
    ledger_target: &'static str,
    path: PathBuf,
}

/// The instruction files setup can write, in output order.
fn discovery_reminder_targets(home: &Path) -> Vec<DiscoveryReminderTarget> {
    vec![
        DiscoveryReminderTarget {
            client: IDX_CLAUDE_CODE,
            label: "Claude Code",
            ledger_target: "claude-md",
            path: home.join(".claude").join("CLAUDE.md"),
        },
        DiscoveryReminderTarget {
            client: IDX_CODEX,
            label: "Codex CLI",
            ledger_target: "codex-agents",
            path: home.join(".codex").join("AGENTS.md"),
        },
    ]
}

/// Whether Kin's discovery reminder is already appended to an instruction file.
fn discovery_reminder_present(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|content| content.contains(KIN_DISCOVERY_REMINDER))
        .unwrap_or(false)
}

/// Append the Kin-first discovery reminder to each instruction file whose client
/// this run registered, and report what was written as `(ledger target, path)`.
///
/// The reminder is a standing behavioral directive: it tells the agent to reach
/// for Kin's semantic MCP tools before grep or raw file reads, in every
/// repository, for every session. That instruction is only true for a client
/// whose MCP server is actually registered, so each file is gated on its own
/// client appearing in `registered_clients`. Writing it for an unregistered
/// client aims the agent at tools that are not wired, and every call it makes
/// fails.
///
/// `home` is taken by argument rather than resolved here so this is exercisable
/// without mutating the process environment that the rest of the suite reads.
fn apply_discovery_reminders(
    home: &Path,
    registered_clients: &[usize],
) -> Vec<(&'static str, PathBuf)> {
    let mut written = Vec::new();
    for target in discovery_reminder_targets(home) {
        let DiscoveryReminderTarget {
            client,
            label,
            ledger_target,
            path,
        } = target;
        if !registered_clients.contains(&client) {
            if discovery_reminder_present(&path) {
                println!(
                    "  {} {label} reminder is present at {} but Kin's MCP server is not \
                     registered for it — `kin setup uninstall` removes it when a setup run \
                     recorded it; an unrecorded reminder stays until removed by hand",
                    style("!").yellow(),
                    path.display()
                );
            } else {
                println!(
                    "  {} {label} reminder skipped — Kin's MCP server was not registered for it",
                    style("→").cyan()
                );
            }
            continue;
        }
        if !discovery_reminder_marker_present(&path) {
            println!(
                "  {} {label}: appending the \"{KIN_DISCOVERY_MARKER}\" block to {}, a global \
                 instruction file every {label} session on this host reads",
                style("→").cyan(),
                path.display()
            );
        }
        match inject_discovery_reminder(&path) {
            Ok(()) => {
                println!(
                    "  {} {label} discovery reminder ensured ({})",
                    style("✓").green(),
                    path.display()
                );
                written.push((ledger_target, path));
            }
            Err(e) => println!("  {} {label} reminder failed: {e}", style("!").yellow()),
        }
    }
    written
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

/// Whether this `kin` is the binary the published installer placed in
/// `~/.kin/bin`, rather than one built from a source checkout.
fn is_managed_install(exe: Option<&Path>, kin_home: &Path) -> bool {
    let Some(exe_dir) = exe.and_then(Path::parent) else {
        return false;
    };
    let managed_bin = kin_home.join("bin");
    match (exe_dir.canonicalize(), managed_bin.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => exe_dir == managed_bin,
    }
}

/// Headline and command to print when the projection shim is missing.
///
/// A cargo target is the right remedy only for someone running a `kin` they
/// built from this source tree. A user who installed through the published
/// one-liner has neither a checkout nor cargo, so naming a cargo build sends
/// them to a command they cannot run; the installer that ships the shim is
/// their route back, and it is the same remedy `kin doctor` already gives.
fn missing_shim_guidance(exe: Option<&Path>, kin_home: &Path) -> (&'static str, &'static str) {
    if is_managed_install(exe, kin_home) {
        (
            "VFS shim not found. Reinstall Kin to restore it:",
            crate::daemon_client::KIN_INSTALL_COMMAND,
        )
    } else {
        (
            "VFS shim not found. Build it with:",
            "cargo build --release -p kin-vfs-shim",
        )
    }
}

fn install_shell_hook(shell_name: &str) -> Result<(PathBuf, String)> {
    let kin_home = kin_dir()?;
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
        let (headline, command) =
            missing_shim_guidance(env::current_exe().ok().as_deref(), &kin_home);
        println!("  {headline}");
        println!("    {command}");
    }

    let source_line = rc_source_line(shell_name, &hook_file);

    for target in rc_write_plan(shell_name)? {
        let rc_path = target.path.as_path();
        let existed = rc_path.exists();
        let rc_content = if existed {
            fs::read_to_string(rc_path)?
        } else {
            // A file Kin creates from nothing may owe the user something before
            // Kin's own blocks. A `.bash_profile` that exists only because Kin
            // wrote it still has to behave like one a bash user would recognize.
            target.seed_when_absent.unwrap_or_default().to_string()
        };

        let update = plan_rc_update(
            &rc_content,
            shell_name,
            &source_line,
            rc_path,
            &bin_dir,
            bin_dir.is_dir(),
            target.blocks,
        );
        for line in update.already_present.iter().chain(&update.skipped) {
            println!("{line}");
        }
        if !update.applied.is_empty() {
            if let Some(parent) = rc_path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::write(rc_path, &update.content)
                .with_context(|| format!("failed to update {}", rc_path.display()))?;
            if !existed && target.seed_when_absent.is_some() {
                println!(
                    "  Created {}, which is the file a bash login shell reads; \
                     it sources ~/.bashrc when the shell is interactive",
                    rc_path.display()
                );
            }
            for line in &update.applied {
                println!("{line}");
            }
        }
    }

    Ok((hook_file, source_line))
}

/// The files this shell's integration is written to, and what each one carries.
///
/// One entry for a shell that reads a single file for both. Two for zsh, whose
/// PATH line belongs in `.zshenv` so a non-interactive shell can find `kin` at
/// all while the hook stays in `.zshrc` so the shim is not injected into one.
/// Two for bash along a different seam: `.bashrc` carries both, because it is
/// the file an interactive non-login shell reads, and the login file carries the
/// PATH line a second time, because bash reads one or the other and never both
/// unless the login file says so.
fn rc_write_plan(shell_name: &str) -> Result<Vec<RcTarget>> {
    let hook_rc = shell_rc(shell_name)?;
    let mut plan = vec![RcTarget {
        path: hook_rc.clone(),
        blocks: RcBlocks::HookOnly,
        seed_when_absent: None,
    }];
    for path_rc in shell_path_rcs(shell_name)? {
        if path_rc == hook_rc {
            plan[0].blocks = RcBlocks::HookAndPath;
            continue;
        }
        // Only a file Kin creates from nothing gets a seed, and `.bash_profile`
        // is the only one Kin ever creates: an existing login file keeps the
        // semantics its owner gave it, and `.profile` belongs to every POSIX
        // shell rather than to bash.
        let creates_bash_profile = shell_name == "bash"
            && path_rc.file_name().and_then(|name| name.to_str()) == Some(BASH_LOGIN_RCS[0]);
        plan.push(RcTarget {
            path: path_rc,
            blocks: RcBlocks::PathOnly,
            seed_when_absent: creates_bash_profile.then_some(BASH_PROFILE_SEED),
        });
    }
    Ok(plan)
}

/// One file setup writes to, what it is responsible for, and what Kin owes it
/// if Kin is the one bringing it into existence.
#[derive(Clone, Debug)]
struct RcTarget {
    path: PathBuf,
    blocks: RcBlocks,
    /// Content to start the file with when it does not exist yet. `None` for a
    /// file whose absence needs nothing but Kin's own blocks. Never applied to a
    /// file that already exists, so no user's semantics are rewritten.
    seed_when_absent: Option<&'static str>,
}

/// Which of the two blocks one rc file is responsible for.
///
/// A shell whose PATH line and hook line share a file gets both from one plan.
/// zsh does not: its hook belongs in `.zshrc` and its PATH line in `.zshenv`,
/// and a plan that wrote both to either file would leave the invariant broken in
/// one direction or the other.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RcBlocks {
    HookAndPath,
    HookOnly,
    PathOnly,
}

impl RcBlocks {
    fn carries_hook(self) -> bool {
        matches!(self, RcBlocks::HookAndPath | RcBlocks::HookOnly)
    }

    fn carries_path(self) -> bool {
        matches!(self, RcBlocks::HookAndPath | RcBlocks::PathOnly)
    }
}

/// The rc file Kin wants on disk, split from what it may say about it.
///
/// `applied` is non-empty exactly when a write is needed, and every line in it
/// describes rc state that exists only once that write lands. Keeping the two
/// apart is what stops setup announcing "Appended to ~/.zshrc" and then failing
/// the run out from under the claim.
#[derive(Debug)]
struct RcUpdate {
    content: String,
    applied: Vec<String>,
    already_present: Vec<String>,
    /// Lines this run chose not to write, and why. A repair that silently
    /// declines to act reads exactly like one that acted.
    skipped: Vec<String>,
}

fn plan_rc_update(
    existing: &str,
    shell_name: &str,
    source_line: &str,
    rc_path: &Path,
    bin_dir: &Path,
    bin_dir_present: bool,
    blocks: RcBlocks,
) -> RcUpdate {
    let mut content = existing.to_string();
    let mut applied = Vec::new();
    let mut already_present = Vec::new();
    let mut skipped = Vec::new();

    let append = |content: &mut String, block: &str| {
        if !content.ends_with('\n') && !content.is_empty() {
            content.push('\n');
        }
        content.push_str(block);
    };

    if blocks.carries_hook() {
        if existing.contains("kin-vfs") {
            already_present.push(format!(
                "  Shell rc already sources kin-vfs hook: {}",
                rc_path.display()
            ));
        } else {
            append(&mut content, &rc_integration_block(source_line));
            applied.push(format!("  Appended to {}", rc_path.display()));
        }
    }

    if !blocks.carries_path() {
        // Nothing to say: this file is not where this shell's PATH line lives.
    } else if rc_declares_kin_bin(existing, bin_dir) {
        already_present.push(format!(
            "  Shell rc already adds {} to PATH",
            bin_dir.display()
        ));
    } else if !bin_dir_present {
        // Only the launcher-provisioned layout populates ~/.kin/bin. An archive
        // or Homebrew install puts the binaries elsewhere, and writing the
        // export anyway left the user's rc pointing at a directory this install
        // never created, which nobody reading that rc later can tell from an
        // install that went missing.
        skipped.push(format!(
            "  Skipped the PATH line: {} does not exist, and this install put nothing there",
            bin_dir.display()
        ));
    } else {
        append(&mut content, &rc_path_block(shell_name, bin_dir));
        applied.push(format!(
            "  Added {} to PATH in {} for new shell sessions",
            bin_dir.display(),
            rc_path.display()
        ));
    }

    RcUpdate {
        content,
        applied,
        already_present,
        skipped,
    }
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
    // never re-selected as the source. `restore_shim_from_sources` copies the
    // first usable one and `copy_shim` no-ops if that source already is the
    // destination.
    let sources: Vec<PathBuf> = find_shim().into_iter().collect();
    restore_shim_from_sources(&dest, &sources)
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

#[derive(Debug, Default)]
pub(crate) struct McpRemergeOutcome {
    pub(crate) repaired: Vec<PathBuf>,
    pub(crate) errors: Vec<String>,
}

/// One exact MCP repair obligation captured before an updater transaction.
/// Paths are absolute so a later retry never derives authority from its cwd.
#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRepairTarget {
    pub(crate) id: String,
    pub(crate) path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) repo_root: Option<PathBuf>,
    /// SHA-256 of the complete config bytes captured under the topology and
    /// target locks. Repair refuses a stale binding unless the current Kin
    /// entry already matches the desired managed generation.
    pub(crate) captured_config_sha256: String,
}

/// Global MCP topology authority. Every Kin writer acquires this before any
/// per-target ConfigLock and before the setup-ledger lock. The updater captures
/// and later recaptures/extends its target inventory under this authority, so
/// a newly configured target cannot fall outside marker finalization.
pub(crate) struct McpTopologyLock {
    _lock: ConfigLock,
}

impl McpTopologyLock {
    pub(crate) fn acquire() -> Result<Self> {
        let path = kin_dir()?.join("mcp-topology.guard");
        Self::acquire_path(&path)
    }

    pub(crate) fn acquire_for_ledger(ledger_path: &Path) -> Result<Self> {
        let config = ledger_path
            .parent()
            .context("setup ledger has no config directory")?;
        let kin_home = config
            .parent()
            .context("setup ledger config directory has no Kin home")?;
        let path = kin_home.join("mcp-topology.guard");
        Self::acquire_path(&path)
    }

    fn acquire_path(path: &Path) -> Result<Self> {
        Ok(Self {
            _lock: ConfigLock::acquire_nofollow(path)?,
        })
    }
}

fn mcp_target_supported(id: &str) -> bool {
    matches!(
        id,
        "claude"
            | "cursor"
            | "codex"
            | "antigravity"
            | "antigravity_workspace"
            | "gemini"
            | "windsurf"
    )
}

fn workspace_root_for_mcp_path(path: &Path) -> Option<PathBuf> {
    let agents = path.parent()?;
    (agents.file_name().and_then(|name| name.to_str()) == Some(".agents")
        && path.file_name().and_then(|name| name.to_str()) == Some("mcp_config.json"))
    .then(|| agents.parent().map(Path::to_path_buf))
    .flatten()
}

const WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS: [&str; 2] = [
    "/.agents/mcp_config.json",
    "/.agents/.mcp_config.json.kin-update.lock",
];

/// Persist checkout-local Antigravity config and its permanent lock as local
/// Git exclusions in the repository's common Git directory. Linked worktrees
/// share this file, so resolving `commondir` is required for idempotency.
#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceGitAuthority {
    repo_root: PathBuf,
    git_dir: PathBuf,
    common_dir: PathBuf,
    info_dir: PathBuf,
    exclude: PathBuf,
}

fn read_single_git_pointer(path: &Path, label: &str) -> Result<String> {
    const MAX_GIT_POINTER_BYTES: u64 = 4096;

    let before = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {label} {}", path.display()))?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > MAX_GIT_POINTER_BYTES
    {
        anyhow::bail!(
            "{label} must be a bounded regular non-symlink file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if before.nlink() != 1 {
            anyhow::bail!("{label} must not be hard linked: {}", path.display());
        }
    }
    let mut file = fs::File::open(path)
        .with_context(|| format!("failed to open {label} {}", path.display()))?;
    let _opened = file.metadata()?;
    #[cfg(unix)]
    if ConfigFileIdentity::from_metadata(&before) != ConfigFileIdentity::from_metadata(&_opened) {
        anyhow::bail!("{label} changed while it was opened: {}", path.display());
    }
    #[cfg(windows)]
    let opened_identity = ConfigFileIdentity::from_open_file(&file)?;
    #[cfg(windows)]
    if visible_config_file_identity_nofollow(path)? != opened_identity {
        anyhow::bail!("{label} changed while it was opened: {}", path.display());
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(MAX_GIT_POINTER_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_GIT_POINTER_BYTES || bytes.contains(&0) {
        anyhow::bail!("{label} is oversized or contains NUL: {}", path.display());
    }
    let after = fs::symlink_metadata(path)?;
    if after.file_type().is_symlink() || !after.is_file() {
        anyhow::bail!("{label} changed type while it was read: {}", path.display());
    }
    #[cfg(unix)]
    if ConfigFileIdentity::from_metadata(&before) != ConfigFileIdentity::from_metadata(&after) {
        anyhow::bail!("{label} changed while it was read: {}", path.display());
    }
    #[cfg(windows)]
    if visible_config_file_identity_nofollow(path)? != opened_identity {
        anyhow::bail!("{label} changed while it was read: {}", path.display());
    }
    let text = std::str::from_utf8(&bytes)
        .with_context(|| format!("{label} is not UTF-8: {}", path.display()))?;
    let value = text.trim_end_matches(['\r', '\n']);
    if value.is_empty() || value.trim() != value || value.contains('\r') || value.contains('\n') {
        anyhow::bail!(
            "{label} must contain exactly one non-empty line: {}",
            path.display()
        );
    }
    Ok(value.to_string())
}

const SETUP_GIT_AUTHORITY_TIMEOUT: Duration = Duration::from_secs(15);
const SETUP_GIT_AUTHORITY_CAPTURE_LIMIT: u64 = 4 * 1024 * 1024;

enum SetupGitDeadlineStart {
    Immediate,
    #[cfg(all(test, unix))]
    AfterParseablePid {
        marker: PathBuf,
        readiness_timeout: Duration,
    },
}

fn git_authority_output(repo_root: &Path, args: &[&str]) -> Result<String> {
    let host_path = kin_core::shims::unshimmed_path();
    git_authority_output_with_policy(
        repo_root,
        args,
        &host_path,
        SETUP_GIT_AUTHORITY_TIMEOUT,
        SETUP_GIT_AUTHORITY_CAPTURE_LIMIT,
    )
}

fn git_authority_output_with_policy(
    repo_root: &Path,
    args: &[&str],
    host_path: &str,
    timeout: Duration,
    capture_limit: u64,
) -> Result<String> {
    let resolution_cwd =
        std::env::current_dir().context("capture host Git resolution directory for setup")?;
    git_authority_output_with_resolution_policy(
        repo_root,
        args,
        host_path,
        &resolution_cwd,
        timeout,
        capture_limit,
    )
}

fn git_authority_output_with_resolution_policy(
    repo_root: &Path,
    args: &[&str],
    host_path: &str,
    resolution_cwd: &Path,
    timeout: Duration,
    capture_limit: u64,
) -> Result<String> {
    git_authority_output_with_resolution_policy_from(
        repo_root,
        args,
        host_path,
        resolution_cwd,
        timeout,
        capture_limit,
        SetupGitDeadlineStart::Immediate,
    )
}

#[cfg(all(test, unix))]
fn git_authority_output_with_policy_after_parseable_pid_ready(
    repo_root: &Path,
    args: &[&str],
    host_path: &str,
    readiness_marker: &Path,
    timeout: Duration,
    capture_limit: u64,
) -> Result<String> {
    let resolution_cwd =
        std::env::current_dir().context("capture host Git resolution directory for setup")?;
    git_authority_output_with_resolution_policy_from(
        repo_root,
        args,
        host_path,
        &resolution_cwd,
        timeout,
        capture_limit,
        SetupGitDeadlineStart::AfterParseablePid {
            marker: readiness_marker.to_path_buf(),
            readiness_timeout: Duration::from_secs(5),
        },
    )
}

fn git_authority_output_with_resolution_policy_from(
    repo_root: &Path,
    args: &[&str],
    host_path: &str,
    resolution_cwd: &Path,
    timeout: Duration,
    capture_limit: u64,
    deadline_start: SetupGitDeadlineStart,
) -> Result<String> {
    let repo_root = repo_root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize repository {}", repo_root.display()))?;
    let host_path = absolute_setup_host_search_path(host_path, resolution_cwd)?;
    let git = which::which_in("git", Some(&host_path), resolution_cwd)
        .context("host Git is required to validate workspace MCP authority")?;
    let git = if git.is_absolute() {
        git
    } else {
        resolution_cwd.join(git)
    };
    let mut command = Command::new(git);
    command
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(&repo_root)
        .args(args);
    run_git_authority_command(
        command,
        args,
        &host_path,
        timeout,
        capture_limit,
        deadline_start,
    )
}

fn absolute_setup_host_search_path(
    host_path: impl AsRef<OsStr>,
    resolution_cwd: &Path,
) -> Result<OsString> {
    let entries = std::env::split_paths(host_path.as_ref())
        .map(|entry| {
            if entry.is_absolute() {
                entry
            } else {
                resolution_cwd.join(entry)
            }
        })
        .collect::<Vec<_>>();
    std::env::join_paths(entries).with_context(|| {
        format!(
            "normalize host Git PATH against {} for setup",
            resolution_cwd.display()
        )
    })
}

fn run_git_authority_command(
    mut command: Command,
    args: &[&str],
    host_path: &OsStr,
    timeout: Duration,
    capture_limit: u64,
    deadline_start: SetupGitDeadlineStart,
) -> Result<String> {
    let label = format!("Git workspace authority query {args:?}");
    finalize_setup_git_authority_process(&mut command, host_path);
    let output = match deadline_start {
        SetupGitDeadlineStart::Immediate => {
            crate::daemon_client::probe_process::output_finalized_with_timeout_and_limit(
                command,
                &label,
                timeout,
                capture_limit,
            )
        }
        #[cfg(all(test, unix))]
        SetupGitDeadlineStart::AfterParseablePid {
            marker,
            readiness_timeout,
        } => crate::daemon_client::probe_process::
            output_finalized_with_timeout_and_limit_after_parseable_pid_ready(
                command,
                &label,
                &marker,
                readiness_timeout,
                timeout,
                capture_limit,
            ),
    }
    .with_context(|| format!("failed to run host Git authority query {args:?}"))?;
    if !output.status.success() {
        anyhow::bail!(
            "git {:?} rejected workspace authority: {}",
            args,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    String::from_utf8(output.stdout).context("git authority output is not UTF-8")
}

/// Apply the complete Git/Kin/VFS/loader authority boundary immediately
/// before bounded spawn. The bounded helper may only attach stdio afterward.
fn finalize_setup_git_authority_process(command: &mut Command, host_path: &OsStr) {
    finalize_setup_git_authority_process_with_ambient(
        command,
        host_path,
        std::env::vars_os().map(|(key, _)| key),
    );
}

fn finalize_setup_git_authority_process_with_ambient(
    command: &mut Command,
    host_path: &OsStr,
    ambient_keys: impl IntoIterator<Item = std::ffi::OsString>,
) {
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_setup_git_authority_env(key))
        .collect::<Vec<_>>();
    for key in ambient_keys
        .into_iter()
        .filter(|key| is_setup_git_authority_env(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command
        .env("PATH", host_path)
        .env("KIN_VFS_DISABLE", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_CONFIG_GLOBAL", kin_git::empty_global_git_config());
}

fn is_setup_git_authority_env(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    setup_git_env_name_starts_with(&label, "GIT_")
        || setup_git_env_name_starts_with(&label, "KIN_")
        || setup_git_env_name_starts_with(&label, "_KIN_")
        || setup_git_env_name_starts_with(&label, "DYLD_")
        || setup_git_env_name_starts_with(&label, "LD_")
}

#[cfg(windows)]
fn setup_git_env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
}

#[cfg(not(windows))]
fn setup_git_env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual.starts_with(expected)
}

fn canonical_git_output_path(repo_root: &Path, output: &str, label: &str) -> Result<PathBuf> {
    let value = output.trim();
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        anyhow::bail!("git returned invalid {label} authority");
    }
    let path = PathBuf::from(value);
    let path = if path.is_absolute() {
        path
    } else {
        repo_root.join(path)
    };
    path.canonicalize()
        .with_context(|| format!("failed to canonicalize git {label} {}", path.display()))
}

fn resolve_workspace_git_authority(repo_root: &Path) -> Result<Option<WorkspaceGitAuthority>> {
    let repo_root = repo_root
        .canonicalize()
        .with_context(|| format!("failed to canonicalize repository {}", repo_root.display()))?;
    let dot_git = repo_root.join(".git");
    let dot_git_metadata = match fs::symlink_metadata(&dot_git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", dot_git.display()))
        }
    };
    if dot_git_metadata.file_type().is_symlink() {
        anyhow::bail!(
            "repository .git authority must not be a symlink: {}",
            dot_git.display()
        );
    }

    let (git_dir, common_dir) = if dot_git_metadata.is_dir() {
        let git_dir = dot_git.canonicalize()?;
        if git_dir != repo_root.join(".git") {
            anyhow::bail!("main-worktree .git authority escaped the canonical repository root");
        }
        (git_dir.clone(), git_dir)
    } else if dot_git_metadata.is_file() {
        let pointer = read_single_git_pointer(&dot_git, "linked-worktree .git pointer")?;
        let target = pointer
            .strip_prefix("gitdir:")
            .map(str::trim)
            .filter(|target| !target.is_empty())
            .context("linked-worktree .git pointer lacks gitdir authority")?;
        let target = PathBuf::from(target);
        let target = if target.is_absolute() {
            target
        } else {
            repo_root.join(target)
        };
        let target_metadata = fs::symlink_metadata(&target).with_context(|| {
            format!(
                "failed to inspect linked-worktree gitdir {}",
                target.display()
            )
        })?;
        if target_metadata.file_type().is_symlink() || !target_metadata.is_dir() {
            anyhow::bail!("linked-worktree gitdir must be a non-symlink directory");
        }
        let git_dir = target.canonicalize()?;
        let commondir_pointer = git_dir.join("commondir");
        let commondir =
            read_single_git_pointer(&commondir_pointer, "linked-worktree commondir pointer")?;
        let commondir = PathBuf::from(commondir);
        if commondir.is_absolute() {
            anyhow::bail!("linked-worktree commondir authority must be relative");
        }
        let common_target = git_dir.join(commondir);
        let common_metadata = fs::symlink_metadata(&common_target)?;
        if common_metadata.file_type().is_symlink() || !common_metadata.is_dir() {
            anyhow::bail!("linked-worktree common Git directory must be a non-symlink directory");
        }
        let common_dir = common_target.canonicalize()?;
        let worktrees = common_dir.join("worktrees");
        let relative = git_dir.strip_prefix(&worktrees).with_context(|| {
            format!(
                "linked-worktree gitdir {} is outside trusted common worktrees {}",
                git_dir.display(),
                worktrees.display()
            )
        })?;
        let mut components = relative.components();
        if !matches!(components.next(), Some(std::path::Component::Normal(_)))
            || components.next().is_some()
        {
            anyhow::bail!("linked-worktree gitdir must occupy exactly one common worktree slot");
        }
        let reverse = git_dir.join("gitdir");
        let reverse = read_single_git_pointer(&reverse, "linked-worktree gitdir backpointer")?;
        let reverse = reverse
            .strip_prefix("gitdir:")
            .map(str::trim)
            .unwrap_or(&reverse);
        let reverse = PathBuf::from(reverse);
        let reverse = if reverse.is_absolute() {
            reverse
        } else {
            git_dir.join(reverse)
        };
        if reverse.canonicalize()? != dot_git.canonicalize()? {
            anyhow::bail!("linked-worktree gitdir backpointer does not name repository .git");
        }
        (git_dir, common_dir)
    } else {
        anyhow::bail!("repository .git authority is neither a directory nor regular pointer file");
    };

    for (name, directory) in [("objects", true), ("refs", true), ("HEAD", false)] {
        let path = common_dir.join(name);
        let metadata = fs::symlink_metadata(&path)
            .with_context(|| format!("missing common Git authority marker {}", path.display()))?;
        if metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
        {
            anyhow::bail!("common Git authority marker is unsafe: {}", path.display());
        }
    }

    let shown_root = canonical_git_output_path(
        &repo_root,
        &git_authority_output(&repo_root, &["rev-parse", "--show-toplevel"])?,
        "worktree root",
    )?;
    let shown_git_dir = canonical_git_output_path(
        &repo_root,
        &git_authority_output(&repo_root, &["rev-parse", "--absolute-git-dir"])?,
        "gitdir",
    )?;
    let shown_common = canonical_git_output_path(
        &repo_root,
        &git_authority_output(&repo_root, &["rev-parse", "--git-common-dir"])?,
        "common directory",
    )?;
    if shown_root != repo_root || shown_git_dir != git_dir || shown_common != common_dir {
        anyhow::bail!("Git command authority disagrees with structurally validated worktree state");
    }
    let worktrees = git_authority_output(&repo_root, &["worktree", "list", "--porcelain"])?;
    let listed = worktrees
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .filter_map(|path| Path::new(path).canonicalize().ok())
        .any(|path| path == repo_root);
    if !listed {
        anyhow::bail!("Git worktree authority does not list the canonical repository root");
    }

    let info_dir = common_dir.join("info");
    let info_metadata = fs::symlink_metadata(&info_dir)
        .with_context(|| format!("missing common Git info directory {}", info_dir.display()))?;
    if info_metadata.file_type().is_symlink() || !info_metadata.is_dir() {
        anyhow::bail!("common Git info authority must be a non-symlink directory");
    }
    let info_dir = info_dir.canonicalize()?;
    if info_dir.parent() != Some(common_dir.as_path()) {
        anyhow::bail!("common Git info authority escaped its validated directory");
    }
    let exclude = info_dir.join("exclude");
    if let Ok(metadata) = fs::symlink_metadata(&exclude) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!("common Git exclude authority must be a regular non-symlink file");
        }
    }
    Ok(Some(WorkspaceGitAuthority {
        repo_root,
        git_dir,
        common_dir,
        info_dir,
        exclude,
    }))
}

fn ensure_workspace_mcp_git_excluded(repo_root: &Path) -> Result<Option<PathBuf>> {
    let Some(authority) = resolve_workspace_git_authority(repo_root)? else {
        return Ok(None);
    };
    let lock = ConfigLock::acquire(&authority.exclude)?;
    if resolve_workspace_git_authority(repo_root)?.as_ref() != Some(&authority) {
        anyhow::bail!("workspace Git authority changed while Kin acquired its exclude lock");
    }
    let exclude = authority.exclude.clone();
    let original = lock.original_bytes(&exclude)?;
    let content = match original.as_deref() {
        Some(bytes) => std::str::from_utf8(bytes)
            .with_context(|| format!("Git exclude {} is not UTF-8", exclude.display()))?,
        None => "",
    };
    let mut updated: String = content
        .split_inclusive('\n')
        .filter(|line| {
            let line = line.trim();
            !WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS.contains(&line)
                && line != ".agents/mcp_config.json"
                && line != ".agents/.mcp_config.json.kin-update.lock"
        })
        .collect();
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    for pattern in WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS {
        updated.push_str(pattern);
        updated.push('\n');
    }
    lock.write_guarded(&exclude, updated.as_bytes(), original.as_deref())?;
    if resolve_workspace_git_authority(repo_root)?.as_ref() != Some(&authority) {
        anyhow::bail!("workspace Git authority changed during exclude reconciliation");
    }
    Ok(Some(exclude))
}

fn canonical_initialized_repo(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    canonical.join(".kin").is_dir().then_some(canonical)
}

fn allowed_static_mcp_target_paths(id: &str) -> Result<Vec<PathBuf>> {
    let home = home_dir()?;
    let candidates = match id {
        // Claude has used both locations. Setup deliberately prefers the
        // primary unless only the legacy nested config already exists.
        "claude" => vec![
            home.join(".claude.json"),
            home.join(".claude").join("config.json"),
        ],
        "cursor" => vec![home.join(".cursor").join("mcp.json")],
        "codex" => vec![home.join(".codex").join("config.toml")],
        "gemini" => vec![home.join(".gemini").join("settings.json")],
        "windsurf" => vec![home
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json")],
        "antigravity" => vec![
            home.join(".gemini").join("config").join("mcp_config.json"),
            home.join(".gemini")
                .join("antigravity-ide")
                .join("mcp_config.json"),
        ],
        "antigravity_workspace" => Vec::new(),
        _ => anyhow::bail!("unsupported managed MCP target '{id}'"),
    };
    let mut allowed = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let parent = candidate
            .parent()
            .context("managed MCP candidate has no parent")?;
        match parent.canonicalize() {
            Ok(parent) => allowed.push(
                parent.join(
                    candidate
                        .file_name()
                        .context("managed MCP candidate has no file name")?,
                ),
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to canonicalize allowed MCP config parent {}",
                        parent.display()
                    )
                })
            }
        }
    }
    Ok(allowed)
}

fn validate_static_mcp_target_path(id: &str, path: &Path) -> Result<()> {
    let allowed = allowed_static_mcp_target_paths(id)?;
    if !allowed.iter().any(|candidate| candidate == path) {
        anyhow::bail!(
            "managed MCP target '{}' is not an allowed canonical config path for client '{}'; refusing arbitrary path authority",
            path.display(),
            id
        );
    }
    Ok(())
}

pub(crate) fn normalize_mcp_repair_targets(
    targets: impl IntoIterator<Item = McpRepairTarget>,
) -> Result<Vec<McpRepairTarget>> {
    let mut dedup = std::collections::BTreeMap::new();
    for mut target in targets {
        if !mcp_target_supported(&target.id) {
            anyhow::bail!("unsupported managed MCP target '{}'", target.id);
        }
        if !target.path.is_absolute() {
            anyhow::bail!(
                "managed MCP target path is not absolute: {}",
                target.path.display()
            );
        }
        target.path = ConfigLock::normalized_path_with_existing_parent(&target.path)?;
        if target.captured_config_sha256.len() != 64
            || !target
                .captured_config_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            anyhow::bail!(
                "managed MCP target '{}' has an invalid captured config SHA-256",
                target.id
            );
        }
        if target.id == "antigravity_workspace" {
            let root = target
                .repo_root
                .take()
                .or_else(|| workspace_root_for_mcp_path(&target.path))
                .context("workspace MCP target is missing its repository root")?;
            let root = canonical_initialized_repo(&root)
                .context("workspace MCP target repository is not an initialized Kin repository")?;
            if target.path != root.join(".agents").join("mcp_config.json") {
                anyhow::bail!(
                    "workspace MCP target {} does not match repository {}",
                    target.path.display(),
                    root.display()
                );
            }
            target.repo_root = Some(root);
        } else {
            validate_static_mcp_target_path(&target.id, &target.path)?;
            if target.id == "codex" || target.id == "antigravity" {
                let repo_root = target
                    .repo_root
                    .as_deref()
                    .map(|root| {
                        canonical_initialized_repo(root).with_context(|| {
                            format!(
                                "{} MCP repository is not an initialized path: {}",
                                target.id,
                                root.display()
                            )
                        })
                    })
                    .transpose()?
                    .with_context(|| {
                        format!(
                            "{} MCP target {} has no exact initialized repository binding; run `kin setup` from the intended initialized repository before updating",
                            target.id,
                            target.path.display()
                        )
                    })?;
                target.repo_root = Some(repo_root);
            } else {
                if target.repo_root.is_some() {
                    anyhow::bail!(
                        "non-workspace MCP target '{}' carried a repository root",
                        target.id
                    );
                }
            }
        }

        let key = target.path.clone();
        match dedup.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(target);
            }
            std::collections::btree_map::Entry::Occupied(entry) => {
                let existing: &McpRepairTarget = entry.get();
                if existing != &target {
                    anyhow::bail!(
                        "one canonical MCP config path is assigned conflicting repair authority: {}",
                        target.path.display()
                    );
                }
            }
        }
    }
    Ok(dedup.into_values().collect())
}

fn codex_repo_from_entry_bytes(content: &[u8]) -> Result<Option<PathBuf>> {
    let text = std::str::from_utf8(content).context("Codex MCP config is not UTF-8")?;
    let root: toml::Value = toml::from_str(text).context("Codex MCP config is not valid TOML")?;
    let Some(entry) = root
        .get("mcp_servers")
        .and_then(|servers| servers.get("kin"))
    else {
        return Ok(None);
    };

    let cwd = match entry.get("cwd") {
        Some(value) => {
            let value = value
                .as_str()
                .context("Codex MCP kin cwd must be a string")?;
            let cwd = PathBuf::from(value);
            if !cwd.is_absolute() {
                anyhow::bail!(
                    "Codex MCP kin cwd must be absolute to provide repository authority: {}",
                    cwd.display()
                );
            }
            Some(cwd)
        }
        None => None,
    };

    let mut repo_arg = None;
    if let Some(value) = entry.get("args") {
        let args = value
            .as_array()
            .context("Codex MCP kin args must be an array")?;
        for (index, value) in args.iter().enumerate() {
            let Some(argument) = value.as_str() else {
                continue;
            };
            let candidate = if argument == "--repo" {
                Some(
                    args.get(index + 1)
                        .and_then(toml::Value::as_str)
                        .context("Codex MCP kin --repo is missing its path value")?,
                )
            } else {
                argument.strip_prefix("--repo=")
            };
            let Some(candidate) = candidate else {
                continue;
            };
            if repo_arg.is_some() {
                anyhow::bail!("Codex MCP kin entry contains duplicate --repo arguments");
            }
            if candidate.is_empty() {
                anyhow::bail!("Codex MCP kin --repo path must not be empty");
            }
            repo_arg = Some(PathBuf::from(candidate));
        }
    }

    let candidate = match repo_arg {
        Some(repo) if repo.is_absolute() => repo,
        Some(repo) => cwd
            .as_ref()
            .with_context(|| {
                format!(
                    "relative Codex MCP --repo '{}' requires an absolute entry cwd",
                    repo.display()
                )
            })?
            .join(repo),
        None => match cwd {
            Some(cwd) => cwd,
            None => return Ok(None),
        },
    };
    Ok(canonical_initialized_repo(&candidate))
}

pub(crate) fn codex_entry_has_exact_repo_binding(
    content: &[u8],
    expected_repo: &Path,
) -> Result<bool> {
    let text = std::str::from_utf8(content).context("Codex MCP config is not UTF-8")?;
    let root: toml::Value = toml::from_str(text).context("Codex MCP config is not valid TOML")?;
    let Some(entry) = root
        .get("mcp_servers")
        .and_then(|servers| servers.get("kin"))
    else {
        return Ok(false);
    };
    let Some(args) = entry.get("args").and_then(toml::Value::as_array) else {
        return Ok(false);
    };
    let native_binding = args.len() == 4
        && args[0].as_str() == Some("mcp")
        && args[1].as_str() == Some("start")
        && args[2].as_str() == Some("--repo")
        && args[3].as_str().is_some();
    let canonical_npm_binding = args.len() == 6
        && args[0].as_str() == Some("-y")
        && args[1].as_str() == Some(CANONICAL_NPM_MCP_PACKAGE)
        && args[2].as_str() == Some("mcp")
        && args[3].as_str() == Some("start")
        && args[4].as_str() == Some("--repo")
        && args[5].as_str().is_some();
    if !native_binding && !canonical_npm_binding {
        return Ok(false);
    }
    // `configure_codex` writes the *canonicalized* working directory, and the
    // parsed `--repo` path is normalized through `canonical_initialized_repo`.
    // The expected repository is supplied by the health surface via
    // `current_health_repo`, which does not canonicalize, so normalize it the
    // same way before comparing. Otherwise a correctly written binding is
    // rejected wherever a raw path differs from its canonical form — notably
    // Windows `\\?\` verbatim prefixes and symlinked home directories. Compare
    // canonical repository identity, not raw path strings.
    let actual = codex_repo_from_entry_bytes(content)?;
    Ok(match canonical_initialized_repo(expected_repo) {
        Some(expected) => actual == Some(expected),
        None => false,
    })
}

fn json_mcp_repo_from_entry_bytes(content: &[u8], client: &str) -> Result<Option<PathBuf>> {
    let root: serde_json::Value = serde_json::from_slice(content)
        .with_context(|| format!("{client} MCP config is invalid JSON"))?;
    let Some(entry) = root
        .get("mcpServers")
        .and_then(|servers| servers.get("kin"))
    else {
        return Ok(None);
    };
    let cwd = match entry.get("cwd") {
        Some(value) => {
            let value = value
                .as_str()
                .with_context(|| format!("{client} MCP kin cwd must be a string"))?;
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                anyhow::bail!("{client} MCP kin cwd must be absolute");
            }
            Some(path)
        }
        None => None,
    };
    let mut repo_arg = None;
    if let Some(args) = entry.get("args") {
        let args = args
            .as_array()
            .with_context(|| format!("{client} MCP kin args must be an array"))?;
        for (index, argument) in args.iter().enumerate() {
            let Some(argument) = argument.as_str() else {
                continue;
            };
            let candidate = if argument == "--repo" {
                Some(
                    args.get(index + 1)
                        .and_then(serde_json::Value::as_str)
                        .with_context(|| format!("{client} MCP kin --repo lacks a path"))?,
                )
            } else {
                argument.strip_prefix("--repo=")
            };
            let Some(candidate) = candidate else {
                continue;
            };
            if repo_arg.replace(PathBuf::from(candidate)).is_some() {
                anyhow::bail!("{client} MCP kin entry contains duplicate --repo arguments");
            }
        }
    }
    let candidate = match repo_arg {
        Some(repo) if repo.is_absolute() => repo,
        Some(repo) => cwd
            .as_ref()
            .with_context(|| format!("relative {client} --repo requires an absolute cwd"))?
            .join(repo),
        None => match cwd {
            Some(cwd) => cwd,
            None => return Ok(None),
        },
    };
    Ok(canonical_initialized_repo(&candidate))
}

/// The repository a written kin MCP entry is bound to, read out of the entry.
///
/// Only the clients whose contract carries `--repo` have one. For the rest the
/// answer is None, which is the honest reading: their binding names no
/// repository, so there is nothing about it that depends on where setup ran.
pub(crate) fn mcp_entry_repo_argument(entry: &serde_json::Value) -> Option<PathBuf> {
    let args = entry.get("args")?.as_array()?;
    let flag = args
        .iter()
        .position(|argument| argument.as_str() == Some("--repo"))?;
    let repo = PathBuf::from(args.get(flag + 1)?.as_str()?);
    repo.is_absolute().then_some(repo)
}

/// The repository the kin MCP entry in this config file is bound to.
pub(crate) fn bound_repo_for_mcp_config(path: &Path) -> Option<PathBuf> {
    let bytes = fs::read(path).ok()?;
    let entry = read_kin_mcp_entry_from_bytes(path, &bytes)?;
    mcp_entry_repo_argument(&entry)
}

/// Capture only MCP configs Kin already owns, plus exact workspace targets
/// persisted in the setup ledger. Update never creates a new client config.
pub(crate) fn current_mcp_repair_targets() -> Result<Vec<McpRepairTarget>> {
    let topology = McpTopologyLock::acquire()?;
    current_mcp_repair_targets_with_topology(&topology)
}

pub(crate) fn current_mcp_repair_targets_with_topology(
    topology: &McpTopologyLock,
) -> Result<Vec<McpRepairTarget>> {
    current_mcp_repair_targets_excluding_with_topology(topology, &std::collections::BTreeSet::new())
}

fn current_mcp_repair_targets_excluding_with_topology(
    _topology: &McpTopologyLock,
    excluded_paths: &std::collections::BTreeSet<PathBuf>,
) -> Result<Vec<McpRepairTarget>> {
    use crate::commands::setup_ledger::{ArtifactKind, SetupLedger};

    let mut targets = Vec::new();
    let mut paths = crate::commands::health::mcp_client_config_paths();
    if let Ok(home) = home_dir() {
        paths.push((
            "antigravity",
            "Google Antigravity legacy",
            home.join(".gemini")
                .join("antigravity-ide")
                .join("mcp_config.json"),
        ));
    }
    for (id, _label, path) in paths {
        if let Some(target) = capture_mcp_repair_target_excluding(id, path, excluded_paths)? {
            targets.push(target);
        }
    }

    let ledger = SetupLedger::load(&crate::commands::setup_ledger::ledger_path()?)?;
    for entry in ledger
        .entries
        .into_iter()
        .filter(|entry| entry.kind == ArtifactKind::McpConfig)
    {
        if let Some(target) =
            capture_mcp_repair_target_excluding(&entry.target, entry.path, excluded_paths)?
        {
            targets.push(target);
        }
    }
    normalize_mcp_repair_targets(targets)
}

fn capture_mcp_repair_target_excluding(
    id: &str,
    path: PathBuf,
    excluded_paths: &std::collections::BTreeSet<PathBuf>,
) -> Result<Option<McpRepairTarget>> {
    match fs::symlink_metadata(&path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect MCP config {}", path.display()))
        }
    }
    let path = ConfigLock::normalized_path_with_existing_parent(&path)?;
    if excluded_paths.contains(&path) {
        return Ok(None);
    }
    let lock = ConfigLock::acquire(&path)?;
    let Some(bytes) = lock.original_bytes(&path)? else {
        return Ok(None);
    };
    if read_kin_mcp_entry_from_bytes(&path, &bytes).is_none() {
        return Ok(None);
    }
    let repo_root = match id {
        "antigravity_workspace" => workspace_root_for_mcp_path(&path),
        "antigravity" => json_mcp_repo_from_entry_bytes(&bytes, "Antigravity")?,
        "codex" => codex_repo_from_entry_bytes(&bytes)?,
        _ => None,
    };
    Ok(Some(McpRepairTarget {
        id: id.to_string(),
        path,
        repo_root,
        captured_config_sha256: crate::commands::setup_ledger::sha256_hex(&bytes),
    }))
}

/// Spell a launcher path the way its platform spells it, so what setup records
/// can be compared against the launcher the installer wrote.
///
/// `Path::join` appends the platform separator and never touches what it was
/// handed, so a `KIN_HOME` that arrived with forward slashes, which is how MSYS
/// bash and every shell like it spells `$HOME` on Windows, produces
/// `C:/Users/u/.kin\bin\kin.exe`. Windows opens that happily and no reader can
/// compare it against the `C:\Users\u\.kin\bin\kin.exe` the installer wrote,
/// which is why the release install proof reported the MCP entry malformed
/// against a launcher that was sitting right there. A forward slash is not a
/// legal character in a Windows filename, so rewriting it loses nothing.
///
/// The platform is an argument rather than read from `env::consts::OS` for the
/// reason [`resolve_home_dir`] gives for the same choice: read ambiently, the
/// Windows arm could only ever run on the one platform this fleet has no host
/// for, and a test written on macOS would take the Unix arm and prove nothing
/// while looking like it did.
fn launcher_spelling_for(path: &str, os: &str) -> String {
    if os == "windows" {
        path.replace('/', "\\")
    } else {
        path.to_string()
    }
}

fn launcher_spelling(path: &Path) -> String {
    launcher_spelling_for(&path.to_string_lossy(), env::consts::OS)
}

pub(crate) fn managed_mcp_launcher() -> Result<String> {
    let name = if cfg!(windows) { "kin.exe" } else { "kin" };
    let path = kin_dir()?.join("bin").join(name);
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("managed Kin launcher is missing at {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "managed Kin launcher must be a regular non-symlink file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            anyhow::bail!("managed Kin launcher is not executable: {}", path.display());
        }
    }
    Ok(launcher_spelling(&path))
}

/// Resolve the stable launcher that ordinary setup, health, and doctor must
/// agree on for the installation channel currently running Kin.
///
/// Managed curl/npm installs own `$KIN_HOME/bin/kin`, so that stable path wins
/// when present. Homebrew and manual installs do not create it; for those
/// channels, prefer the `kin` path on PATH only when it resolves to this exact
/// running executable, then fall back to `current_exe`. The updater keeps using
/// [`managed_mcp_launcher`] directly after it has installed managed bytes.
pub(crate) fn configured_mcp_launcher() -> Result<String> {
    if let Ok(managed) = managed_mcp_launcher() {
        return Ok(managed);
    }

    let current = env::current_exe().context("could not resolve the running Kin executable")?;
    validate_running_mcp_launcher(&current)?;
    if let Ok(path_candidate) = which::which(if cfg!(windows) { "kin.exe" } else { "kin" }) {
        let candidate_target = fs::canonicalize(&path_candidate).ok();
        let current_target = fs::canonicalize(&current).ok();
        if candidate_target.is_some() && candidate_target == current_target {
            validate_running_mcp_launcher(&path_candidate)?;
            return Ok(launcher_spelling(&path_candidate));
        }
    }
    Ok(launcher_spelling(&current))
}

fn validate_running_mcp_launcher(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!("Kin MCP launcher is not absolute: {}", path.display());
    }
    let metadata = fs::metadata(path)
        .with_context(|| format!("Kin MCP launcher is unavailable at {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("Kin MCP launcher is not a file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            anyhow::bail!("Kin MCP launcher is not executable: {}", path.display());
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
enum InjectedConfigObjectDrift {
    Bytes(fs::File, Vec<u8>),
    Mode(fs::File, u32),
}

#[cfg(all(test, windows))]
#[derive(Clone, Copy)]
enum InjectedWindowsStageDrift {
    Dacl,
    SupportedSacl,
    UnsupportedSaclCrash,
}

#[cfg(all(test, unix))]
enum InjectedPrivateDirectoryStage {
    FailAfterMkdir,
    FailAfterRepair,
    PublishUnsafeWinner,
    SubstituteWithSymlink(PathBuf),
}

#[cfg(test)]
thread_local! {
    static FAIL_CONFIG_DIRECTORY_SYNC_UNDER: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static INJECT_CONFIG_DIRECTORY_EEXIST_AT: std::cell::RefCell<Option<PathBuf>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static INJECT_CONFIG_AUTHORITY_DRIFT_AT_PHASE:
        std::cell::RefCell<Option<(&'static str, PathBuf, u32)>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static INJECT_CONFIG_OBJECT_DRIFT_AT_PHASE:
        std::cell::RefCell<Option<(&'static str, InjectedConfigObjectDrift)>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(windows)]
    static INJECT_WINDOWS_STAGE_DRIFT_AT_PHASE:
        std::cell::RefCell<Option<(&'static str, InjectedWindowsStageDrift)>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static INJECT_PRIVATE_DIRECTORY_STAGE_AT:
        std::cell::RefCell<Option<(PathBuf, InjectedPrivateDirectoryStage)>> =
        const { std::cell::RefCell::new(None) };
    #[cfg(unix)]
    static INJECTED_PRIVATE_DIRECTORY_WINNER_IDENTITY:
        std::cell::RefCell<Option<ConfigFileIdentity>> = const {
            std::cell::RefCell::new(None)
        };
}

#[cfg(test)]
pub(crate) fn reset_config_transaction_acquire_count() {
    CONFIG_TRANSACTION_ACQUIRE_COUNT.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn config_transaction_acquire_count() -> usize {
    CONFIG_TRANSACTION_ACQUIRE_COUNT.with(std::cell::Cell::get)
}

#[cfg(all(test, unix))]
pub(crate) fn inject_config_directory_sync_failure_under(root: Option<&Path>) {
    FAIL_CONFIG_DIRECTORY_SYNC_UNDER.with(|configured| {
        *configured.borrow_mut() =
            root.map(|path| path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
    });
}

#[cfg(all(test, unix))]
fn inject_config_directory_eexist_at(path: Option<&Path>) {
    INJECT_CONFIG_DIRECTORY_EEXIST_AT.with(|configured| {
        *configured.borrow_mut() = path.map(Path::to_path_buf);
    });
}

#[cfg(all(test, unix))]
fn maybe_inject_config_directory_eexist(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let inject = INJECT_CONFIG_DIRECTORY_EEXIST_AT.with(|configured| {
        if configured.borrow().as_deref() == Some(path) {
            configured.borrow_mut().take();
            true
        } else {
            false
        }
    });
    if inject {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o777))?;
    }
    Ok(())
}

#[cfg(all(not(test), unix))]
fn maybe_inject_config_directory_eexist(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
fn inject_private_directory_stage_at(
    path: Option<&Path>,
    injection: Option<InjectedPrivateDirectoryStage>,
) {
    INJECT_PRIVATE_DIRECTORY_STAGE_AT.with(|configured| {
        *configured.borrow_mut() = path
            .zip(injection)
            .map(|(path, injection)| (path.to_path_buf(), injection));
    });
    INJECTED_PRIVATE_DIRECTORY_WINNER_IDENTITY.with(|identity| {
        identity.borrow_mut().take();
    });
}

#[cfg(all(test, unix))]
fn take_injected_private_directory_winner_identity() -> Option<ConfigFileIdentity> {
    INJECTED_PRIVATE_DIRECTORY_WINNER_IDENTITY.with(|identity| identity.borrow_mut().take())
}

#[cfg(all(test, unix))]
fn maybe_inject_private_directory_stage(
    phase: &'static str,
    parent: &fs::File,
    stage_name: &str,
    final_name: &std::ffi::OsStr,
    final_path: &Path,
) -> Result<()> {
    let should_take = INJECT_PRIVATE_DIRECTORY_STAGE_AT.with(|configured| {
        let configured = configured.borrow();
        configured.as_ref().is_some_and(|(path, injection)| {
            path == final_path
                && matches!(
                    (phase, injection),
                    ("after_mkdir", InjectedPrivateDirectoryStage::FailAfterMkdir)
                        | (
                            "before_repair",
                            InjectedPrivateDirectoryStage::SubstituteWithSymlink(_)
                        )
                        | (
                            "after_repair",
                            InjectedPrivateDirectoryStage::FailAfterRepair
                        )
                        | (
                            "before_publish",
                            InjectedPrivateDirectoryStage::PublishUnsafeWinner
                        )
                )
        })
    });
    if !should_take {
        return Ok(());
    }
    let (_, injection) = INJECT_PRIVATE_DIRECTORY_STAGE_AT
        .with(|configured| configured.borrow_mut().take())
        .context("private-directory stage injection disappeared")?;
    match injection {
        InjectedPrivateDirectoryStage::FailAfterMkdir => {
            anyhow::bail!("injected crash after private-directory staged mkdir")
        }
        InjectedPrivateDirectoryStage::FailAfterRepair => {
            anyhow::bail!("injected crash after private-directory staged repair")
        }
        InjectedPrivateDirectoryStage::PublishUnsafeWinner => {
            rustix::fs::mkdirat(parent, final_name, rustix::fs::Mode::from_raw_mode(0o777))?;
            let fd = rustix::fs::openat(
                parent,
                final_name,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            let winner = fs::File::from(fd);
            rustix::fs::fchmod(&winner, rustix::fs::Mode::from_raw_mode(0o777))?;
            let sentinel = rustix::fs::openat(
                &winner,
                "sentinel",
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )?;
            let mut sentinel = fs::File::from(sentinel);
            sentinel.write_all(b"raced winner must survive")?;
            sentinel.sync_all()?;
            winner.sync_all()?;
            let identity = ConfigFileIdentity::from_metadata(&winner.metadata()?);
            INJECTED_PRIVATE_DIRECTORY_WINNER_IDENTITY.with(|configured| {
                *configured.borrow_mut() = Some(identity);
            });
            Ok(())
        }
        InjectedPrivateDirectoryStage::SubstituteWithSymlink(target) => {
            rustix::fs::unlinkat(parent, stage_name, rustix::fs::AtFlags::REMOVEDIR)?;
            rustix::fs::symlinkat(&target, parent, stage_name)?;
            Ok(())
        }
    }
}

#[cfg(all(not(test), unix))]
fn maybe_inject_private_directory_stage(
    _phase: &'static str,
    _parent: &fs::File,
    _stage_name: &str,
    _final_name: &std::ffi::OsStr,
    _final_path: &Path,
) -> Result<()> {
    Ok(())
}

#[cfg(all(test, unix))]
fn inject_config_authority_drift_at_phase(phase: Option<(&'static str, &Path, u32)>) {
    INJECT_CONFIG_AUTHORITY_DRIFT_AT_PHASE.with(|configured| {
        *configured.borrow_mut() =
            phase.map(|(phase, path, mode)| (phase, path.to_path_buf(), mode));
    });
}

#[cfg(all(test, unix))]
fn inject_config_object_drift_at_phase(phase: Option<(&'static str, InjectedConfigObjectDrift)>) {
    INJECT_CONFIG_OBJECT_DRIFT_AT_PHASE.with(|configured| {
        *configured.borrow_mut() = phase;
    });
}

#[cfg(all(test, windows))]
fn inject_windows_stage_drift_at_phase(phase: Option<(&'static str, InjectedWindowsStageDrift)>) {
    INJECT_WINDOWS_STAGE_DRIFT_AT_PHASE.with(|configured| {
        *configured.borrow_mut() = phase;
    });
}

#[cfg(all(test, windows))]
fn maybe_inject_windows_stage_drift(phase: &'static str, staged: &fs::File) -> Result<()> {
    let drift = INJECT_WINDOWS_STAGE_DRIFT_AT_PHASE.with(|configured| {
        let matches = configured
            .borrow()
            .as_ref()
            .is_some_and(|(configured_phase, _)| *configured_phase == phase);
        matches.then(|| configured.borrow_mut().take()).flatten()
    });
    match drift {
        Some((_, InjectedWindowsStageDrift::Dacl)) => {
            super::update::windows_update::inject_test_managed_file_dacl_drift(staged)
        }
        Some((_, InjectedWindowsStageDrift::SupportedSacl)) => {
            super::update::windows_update::inject_test_managed_file_supported_sacl_drift(staged)
        }
        Some((_, InjectedWindowsStageDrift::UnsupportedSaclCrash)) => anyhow::bail!(
            "unsupported-SACL crash injection reached the ordinary live drift resolver"
        ),
        None => Ok(()),
    }
}

#[cfg(all(not(test), windows))]
fn maybe_inject_windows_stage_drift(_phase: &'static str, _staged: &fs::File) -> Result<()> {
    Ok(())
}

#[cfg(all(test, windows))]
fn maybe_inject_windows_stage_crash(phase: &'static str, staged: &fs::File) -> Result<bool> {
    let inject = INJECT_WINDOWS_STAGE_DRIFT_AT_PHASE.with(|configured| {
        let matches = configured
            .borrow()
            .as_ref()
            .is_some_and(|(configured_phase, drift)| {
                *configured_phase == phase
                    && matches!(drift, InjectedWindowsStageDrift::UnsupportedSaclCrash)
            });
        matches.then(|| configured.borrow_mut().take()).flatten()
    });
    if inject.is_none() {
        return Ok(false);
    }
    super::update::windows_update::inject_test_managed_file_unsupported_sacl(staged)?;
    Ok(true)
}

#[cfg(all(not(test), windows))]
fn maybe_inject_windows_stage_crash(_phase: &'static str, _staged: &fs::File) -> Result<bool> {
    Ok(false)
}

#[cfg(all(test, unix))]
fn maybe_inject_config_authority_drift(phase: &'static str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    let configured = INJECT_CONFIG_AUTHORITY_DRIFT_AT_PHASE.with(|configured| {
        let matches = configured
            .borrow()
            .as_ref()
            .is_some_and(|(configured_phase, _, _)| *configured_phase == phase);
        matches.then(|| configured.borrow_mut().take()).flatten()
    });
    if let Some((_, path, mode)) = configured {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    let object_drift = INJECT_CONFIG_OBJECT_DRIFT_AT_PHASE.with(|configured| {
        let matches = configured
            .borrow()
            .as_ref()
            .is_some_and(|(configured_phase, _)| *configured_phase == phase);
        matches.then(|| configured.borrow_mut().take()).flatten()
    });
    match object_drift {
        Some((_, InjectedConfigObjectDrift::Bytes(mut file, bytes))) => {
            file.set_len(0)?;
            file.rewind()?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        Some((_, InjectedConfigObjectDrift::Mode(file, mode))) => {
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_raw_mode(mode as _))?;
            file.sync_all()?;
        }
        None => {}
    }
    Ok(())
}

#[cfg(all(not(test), unix))]
fn maybe_inject_config_authority_drift(_phase: &'static str) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn config_directory_sync_injected(path: &Path) -> bool {
    #[cfg(test)]
    {
        let observed = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        return FAIL_CONFIG_DIRECTORY_SYNC_UNDER.with(|configured| {
            configured
                .borrow()
                .as_ref()
                .is_some_and(|root| observed.starts_with(root))
        });
    }
    #[cfg(not(test))]
    {
        let _ = path;
        false
    }
}

fn shared_config_lock_path(path: &Path) -> Result<PathBuf> {
    let parent = path.parent().context("MCP config path has no parent")?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("MCP config path has no UTF-8 file name")?;
    Ok(parent.join(format!(".{name}.kin-update.lock")))
}

// Name a managed config's recovery journal and object vault after the durable
// sidecar pathname that identifies the config, never after the sidecar object's
// device and inode. The operating system recycles a device+inode pair as soon
// as the sidecar is unlinked, so an identity-derived name cannot tell "this
// config" apart from "an unrelated config whose sidecar inherited a freed
// inode": both hash to one journal and one vault, so the later config reads the
// earlier config's recovery record and sweeps the earlier config's staged
// objects out of the shared vault. A pathname is not recycled, so distinct
// configs always get distinct journals, and one config keeps its journal across
// a sidecar that is deleted and recreated. Callers pass the normalized sidecar
// path that `ConfigLock::plan_with_policy` resolved.
fn config_transaction_subject_key(sidecar_path: &Path) -> String {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(b"KIN_CONFIG_TXN_SUBJECT_V1\0");
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        let bytes = sidecar_path.as_os_str().as_bytes();
        encoded.extend_from_slice(b"unix\0");
        encoded.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        encoded.extend_from_slice(bytes);
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        let units = sidecar_path.as_os_str().encode_wide().collect::<Vec<_>>();
        encoded.extend_from_slice(b"windows\0");
        encoded.extend_from_slice(&(units.len() as u64).to_le_bytes());
        for unit in units {
            encoded.extend_from_slice(&unit.to_le_bytes());
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let lossy = sidecar_path.to_string_lossy();
        encoded.extend_from_slice(b"unsupported\0");
        encoded.extend_from_slice(&(lossy.len() as u64).to_le_bytes());
        encoded.extend_from_slice(lossy.as_bytes());
    }
    crate::commands::setup_ledger::sha256_hex(&encoded)
}

struct ConfigTransactionAuthority {
    file: fs::File,
    path: PathBuf,
    identity: ConfigFileIdentity,
    subject_identity: ConfigFileIdentity,
    #[cfg(unix)]
    root: fs::File,
    #[cfg(unix)]
    root_path: PathBuf,
    #[cfg(unix)]
    root_identity: ConfigFileIdentity,
    #[cfg(unix)]
    vault: fs::File,
    #[cfg(unix)]
    vault_path: PathBuf,
    #[cfg(unix)]
    vault_identity: ConfigFileIdentity,
}

#[cfg(test)]
thread_local! {
    static CONFIG_TRANSACTION_ACQUIRE_COUNT: std::cell::Cell<usize> = const {
        std::cell::Cell::new(0)
    };
}

#[cfg(test)]
fn lexically_normalize_test_path(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                }
            }
            std::path::Component::Normal(part) => normalized.push(part),
        }
    }
    normalized
}

#[cfg(test)]
fn canonicalize_nearest_existing_test_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let normalized = lexically_normalize_test_path(&absolute);
    let mut ancestor = normalized.clone();
    let mut missing_suffix = Vec::new();
    loop {
        if let Ok(mut canonical) = ancestor.canonicalize() {
            for component in missing_suffix.iter().rev() {
                canonical.push(component);
            }
            return canonical;
        }
        let Some(name) = ancestor.file_name().map(ToOwned::to_owned) else {
            return normalized;
        };
        missing_suffix.push(name);
        if !ancestor.pop() {
            return normalized;
        }
    }
}

#[cfg(test)]
fn config_transaction_test_kin_home(subject_path: &Path) -> PathBuf {
    let temp = env::temp_dir()
        .canonicalize()
        .unwrap_or_else(|_| env::temp_dir());
    let normalized = canonicalize_nearest_existing_test_path(subject_path);
    let fixture_root = normalized
        .strip_prefix(&temp)
        .ok()
        .and_then(|relative| relative.components().next())
        .map(|component| temp.join(component.as_os_str()))
        .filter(|candidate| candidate != &normalized && candidate.is_dir());
    let fixture_scope = fixture_root
        .as_deref()
        .unwrap_or(&normalized)
        .to_string_lossy()
        .into_owned();
    let digest = crate::commands::setup_ledger::sha256_hex(fixture_scope.as_bytes());
    let name = format!(".kin-config-transaction-tests-{}", &digest[..24]);
    // A tempfile fixture already gives this test exclusive directory
    // authority. Keep its transaction home beneath that fixture so parallel
    // setup tests do not all serialize on the process-wide temporary parent.
    // A subject directly beneath TMPDIR cannot contain its own authority, so
    // retain the sibling fallback for that shape.
    fixture_root
        .map(|root| root.join(&name))
        .unwrap_or_else(|| temp.join(name.trim_start_matches('.')))
}

impl ConfigTransactionAuthority {
    fn acquire(subject_identity: &ConfigFileIdentity, subject_path: &Path) -> Result<Self> {
        #[cfg(test)]
        CONFIG_TRANSACTION_ACQUIRE_COUNT.with(|count| count.set(count.get() + 1));
        #[cfg(not(test))]
        let kin_home = kin_dir()?;
        #[cfg(test)]
        let kin_home = config_transaction_test_kin_home(subject_path);
        #[cfg(unix)]
        let kin_home_authority = create_config_directory_all_durable(&kin_home, true)
            .with_context(|| format!("failed to create {}", kin_home.display()))?;
        #[cfg(unix)]
        let kin_home = kin_home_authority.path.clone();
        #[cfg(not(unix))]
        fs::create_dir_all(&kin_home)
            .with_context(|| format!("failed to create {}", kin_home.display()))?;
        #[cfg(unix)]
        validate_kin_home_namespace(&kin_home_authority)?;
        #[cfg(windows)]
        let root = super::update::windows_update::ensure_private_temp_container(
            &kin_home,
            "config-transactions",
        )?;
        #[cfg(not(windows))]
        let root = kin_home.join("config-transactions");
        #[cfg(unix)]
        let (transaction_root, transaction_root_identity) = {
            let kin_home_handle = kin_home_authority.file.try_clone()?;
            let kin_home_identity = kin_home_authority.identity.clone();
            let root_name = "config-transactions";
            let (root_handle, _, identity) = open_or_create_private_unix_directory_at(
                &kin_home_handle,
                &kin_home,
                std::ffi::OsStr::new(root_name),
                &root,
            )
            .with_context(|| {
                format!(
                    "failed to create managed config transaction root {}",
                    root.display()
                )
            })?;
            ensure_config_parent_binding(&kin_home, &kin_home_handle, &kin_home_identity)?;
            (root_handle, identity)
        };
        #[cfg(all(not(unix), not(windows)))]
        fs::create_dir_all(&root)?;
        #[cfg(not(unix))]
        let root = root.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize managed config transaction root {}",
                root.display()
            )
        })?;
        let key = config_transaction_subject_key(subject_path);
        #[cfg(unix)]
        let (vault, vault_path, vault_identity) = {
            let vault_name = format!("{key}.objects");
            let vault_path = root.join(&vault_name);
            let (vault, _, identity) = open_or_create_private_unix_directory_at(
                &transaction_root,
                &root,
                std::ffi::OsStr::new(&vault_name),
                &vault_path,
            )
            .with_context(|| {
                format!("failed to create managed config object vault {vault_name}")
            })?;
            (vault, vault_path, identity)
        };
        let guard_name = format!("{key}.guard");
        let path = root.join(&guard_name);
        #[cfg(all(not(unix), not(windows)))]
        let mut options = fs::OpenOptions::new();
        #[cfg(all(not(unix), not(windows)))]
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        let (file, metadata) = {
            let flags = rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC;
            let (fd, created) = match rustix::fs::openat(
                &transaction_root,
                guard_name.as_str(),
                flags | rustix::fs::OFlags::CREATE | rustix::fs::OFlags::EXCL,
                rustix::fs::Mode::from_raw_mode(0o600),
            ) {
                Ok(fd) => (fd, true),
                Err(rustix::io::Errno::EXIST) => (
                    rustix::fs::openat(
                        &transaction_root,
                        guard_name.as_str(),
                        flags,
                        rustix::fs::Mode::empty(),
                    )?,
                    false,
                ),
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create managed config transaction authority {}",
                            path.display()
                        )
                    })
                }
            };
            let file = fs::File::from(fd);
            let metadata = validate_private_unix_file(&path, &file, created)?;
            let identity = ConfigFileIdentity::from_metadata(&metadata);
            ensure_config_binding_at(
                &transaction_root,
                &guard_name,
                &identity,
                "managed config transaction authority",
            )?;
            if created {
                sync_config_parent(&transaction_root)?;
            }
            (file, metadata)
        };
        #[cfg(all(not(unix), not(windows)))]
        let file = options.open(&path).with_context(|| {
            format!(
                "failed to open managed config transaction authority {}",
                path.display()
            )
        })?;
        #[cfg(windows)]
        let file = super::update::windows_update::open_or_create_current_user_private_file(&path)?;
        #[cfg(not(unix))]
        let metadata = validate_regular_config_file(&path, &file, true)?;
        #[cfg(windows)]
        let _ = &metadata;
        #[cfg(unix)]
        let identity = ConfigFileIdentity::from_metadata(&metadata);
        #[cfg(windows)]
        let identity = ConfigFileIdentity::from_open_file(&file)?;
        lock_file_exclusive_bounded(
            &file,
            &format!("managed config transaction authority {}", path.display()),
        )?;
        #[cfg(unix)]
        {
            let visible_root = open_config_parent_nofollow(&root)?;
            let visible_identity = ConfigFileIdentity::from_metadata(&visible_root.metadata()?);
            if visible_identity != transaction_root_identity {
                anyhow::bail!(
                    "managed config transaction root changed while Kin waited: {}",
                    root.display()
                );
            }
            ensure_config_binding_at(
                &transaction_root,
                &guard_name,
                &identity,
                "managed config transaction authority",
            )?;
        }
        #[cfg(not(unix))]
        let named = fs::symlink_metadata(&path)?;
        #[cfg(windows)]
        let named_identity = visible_config_file_identity_nofollow(&path)?;
        #[cfg(all(not(unix), not(windows)))]
        let named_identity = ConfigFileIdentity {};
        #[cfg(not(unix))]
        if named.file_type().is_symlink() || named_identity != identity {
            anyhow::bail!(
                "managed config transaction authority changed while Kin waited: {}",
                path.display()
            );
        }
        Ok(Self {
            file,
            path,
            identity,
            subject_identity: subject_identity.clone(),
            #[cfg(unix)]
            root: transaction_root,
            #[cfg(unix)]
            root_path: root,
            #[cfg(unix)]
            root_identity: transaction_root_identity,
            #[cfg(unix)]
            vault,
            #[cfg(unix)]
            vault_path,
            #[cfg(unix)]
            vault_identity,
        })
    }

    fn revalidate(&self) -> Result<()> {
        #[cfg(unix)]
        {
            let held_root = validate_private_unix_directory(&self.root_path, &self.root, false)?;
            let visible_root = open_config_parent_nofollow(&self.root_path)?;
            let visible_root_identity =
                validate_private_unix_directory(&self.root_path, &visible_root, false)?;
            if held_root != self.root_identity || visible_root_identity != self.root_identity {
                anyhow::bail!(
                    "managed config transaction root authority changed: {}",
                    self.root_path.display()
                );
            }
            let guard_metadata = validate_private_unix_file(&self.path, &self.file, false)?;
            let guard_identity = ConfigFileIdentity::from_metadata(&guard_metadata);
            let guard_name = self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .context("managed config transaction guard name is not UTF-8")?;
            if guard_identity != self.identity {
                anyhow::bail!(
                    "managed config transaction authority changed: {}",
                    self.path.display()
                );
            }
            ensure_config_binding_at(
                &self.root,
                guard_name,
                &self.identity,
                "managed config transaction authority",
            )?;

            let vault_identity =
                validate_private_unix_directory(&self.vault_path, &self.vault, false)?;
            let vault_name = self
                .vault_path
                .file_name()
                .and_then(|name| name.to_str())
                .context("managed config object vault name is not UTF-8")?;
            let named_vault = rustix::fs::statat(
                &self.root,
                vault_name,
                rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
            )?;
            if vault_identity != self.vault_identity
                || named_vault.st_dev as u64 != self.vault_identity.device
                || named_vault.st_ino as u64 != self.vault_identity.inode
                || rustix::fs::FileType::from_raw_mode(named_vault.st_mode)
                    != rustix::fs::FileType::Directory
            {
                anyhow::bail!(
                    "managed config object vault authority changed: {}",
                    self.vault_path.display()
                );
            }
        }
        #[cfg(not(unix))]
        {
            let named = fs::symlink_metadata(&self.path)?;
            #[cfg(windows)]
            let opened_identity = ConfigFileIdentity::from_open_file(&self.file)?;
            #[cfg(windows)]
            let named_identity = visible_config_file_identity_nofollow(&self.path)?;
            #[cfg(all(not(unix), not(windows)))]
            let opened_identity = ConfigFileIdentity {};
            #[cfg(all(not(unix), not(windows)))]
            let named_identity = ConfigFileIdentity {};
            if named.file_type().is_symlink()
                || opened_identity != self.identity
                || named_identity != self.identity
            {
                anyhow::bail!(
                    "managed config transaction authority changed: {}",
                    self.path.display()
                );
            }
            #[cfg(windows)]
            super::update::windows_update::validate_current_user_private_file(&self.file)?;
        }
        Ok(())
    }
}

#[derive(
    Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize,
)]
struct ConfigFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    volume: u64,
    #[cfg(windows)]
    index: super::update::WindowsFileId,
}

impl ConfigFileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }

    #[cfg(windows)]
    fn from_open_file(file: &fs::File) -> Result<Self> {
        let (volume, index) = super::update::windows_update::managed_object_identity(file, false)?;
        Ok(Self { volume, index })
    }
}

#[cfg(unix)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct UnixConfigMetadata {
    xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    acl: Vec<u8>,
    flags: Option<u32>,
}

#[cfg(unix)]
impl UnixConfigMetadata {
    fn fingerprint(&self) -> String {
        let mut encoded = Vec::new();
        encoded.extend_from_slice(b"KIN_UNIX_CONFIG_METADATA_V1\0");
        match self.flags {
            Some(flags) => {
                encoded.push(1);
                encoded.extend_from_slice(&flags.to_le_bytes());
            }
            None => encoded.push(0),
        }
        encoded.extend_from_slice(&(self.acl.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&self.acl);
        encoded.extend_from_slice(&(self.xattrs.len() as u64).to_le_bytes());
        for (name, value) in &self.xattrs {
            encoded.extend_from_slice(&(name.len() as u64).to_le_bytes());
            encoded.extend_from_slice(name);
            encoded.extend_from_slice(&(value.len() as u64).to_le_bytes());
            encoded.extend_from_slice(value);
        }
        crate::commands::setup_ledger::sha256_hex(&encoded)
    }

    fn grants_extended_private_access(&self) -> bool {
        !self.acl.is_empty()
            || self.xattrs.iter().any(|(name, _)| {
                name.as_slice() == b"system.posix_acl_access"
                    || name.as_slice() == b"system.posix_acl_default"
                    || name.as_slice() == b"system.nfs4_acl"
                    || name.as_slice() == b"system.richacl"
            })
    }
}

#[cfg(target_os = "macos")]
fn macos_acl_has_deny_entry(acl: &[u8]) -> Result<bool> {
    Ok(macos_acl_entries(acl)?
        .iter()
        .any(|(disposition, _)| disposition == "deny"))
}

#[cfg(target_os = "macos")]
fn macos_acl_entries(acl: &[u8]) -> Result<Vec<(String, Vec<String>)>> {
    let text = std::str::from_utf8(acl).context("managed config ACL text is not UTF-8")?;
    let mut saw_header = false;
    let mut saw_entry = false;
    let mut entries = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if line.starts_with("!#acl") {
            if line != "!#acl 1" || saw_header || saw_entry {
                anyhow::bail!("managed config ACL has an invalid header");
            }
            saw_header = true;
            continue;
        }
        if !saw_header {
            anyhow::bail!("managed config ACL entry precedes its version header");
        }
        let mut fields = line.rsplitn(3, ':');
        let permissions = fields
            .next()
            .filter(|field| !field.is_empty())
            .context("managed config ACL entry has no permission field")?;
        let disposition_and_flags = fields
            .next()
            .filter(|field| !field.is_empty())
            .context("managed config ACL entry has no disposition field")?;
        let _subject = fields
            .next()
            .filter(|field| !field.is_empty())
            .context("managed config ACL entry has no subject field")?;
        if permissions.split(',').any(str::is_empty) {
            anyhow::bail!("managed config ACL entry contains an empty permission");
        }
        let disposition = disposition_and_flags
            .split(',')
            .next()
            .filter(|value| *value == "allow" || *value == "deny")
            .context("managed config ACL entry has an unknown disposition")?;
        entries.push((
            disposition.to_string(),
            permissions.split(',').map(str::to_string).collect(),
        ));
        saw_entry = true;
    }
    if !acl.is_empty() && (!saw_header || !saw_entry) {
        anyhow::bail!("managed config ACL contains no entries");
    }
    Ok(entries)
}

#[cfg(target_os = "macos")]
fn validate_macos_directory_namespace_acl(acl: &[u8], label: &str) -> Result<()> {
    for (disposition, permissions) in macos_acl_entries(acl)? {
        if disposition == "allow"
            && permissions.iter().any(|permission| {
                matches!(
                    permission.as_str(),
                    "write"
                        | "append"
                        | "add_file"
                        | "add_subdirectory"
                        | "delete"
                        | "delete_child"
                        | "writesecurity"
                        | "chown"
                )
            })
        {
            anyhow::bail!("{label} carries extended namespace authority");
        }
        // A standard macOS home directory carries `everyone deny delete`.
        // That protects the retained home entry and does not block anchored
        // child creation, replacement, or removal. Every other deny right is
        // rejected because it can make the transaction incomplete or
        // platform-dependent.
        if disposition == "deny"
            && permissions
                .iter()
                .any(|permission| permission.as_str() != "delete")
        {
            anyhow::bail!("{label} carries a deny ACL that blocks child namespace operations");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_metadata_for_transaction(
    metadata: &UnixConfigMetadata,
    label: &str,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        const SF_NOUNLINK: u32 = 0x0010_0000;
        let blocking = libc::UF_IMMUTABLE
            | libc::UF_APPEND
            | libc::SF_IMMUTABLE
            | libc::SF_APPEND
            | SF_NOUNLINK;
        if metadata.flags.is_some_and(|flags| flags & blocking != 0) {
            anyhow::bail!("{label} carries namespace-blocking BSD flags");
        }
        if macos_acl_has_deny_entry(&metadata.acl)? {
            anyhow::bail!("{label} carries a deny ACL that cannot be safely transacted");
        }
    }
    #[cfg(target_os = "linux")]
    if metadata
        .flags
        .is_some_and(|flags| flags & (0x10 | 0x20) != 0)
    {
        anyhow::bail!("{label} carries immutable/append inode flags");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_directory_namespace_metadata(
    metadata: &UnixConfigMetadata,
    label: &str,
) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        // SF_NOUNLINK protects the directory entry itself. Kin neither
        // renames nor unlinks retained namespace anchors, and the flag does
        // not prevent anchored child creation/removal. Immutable and append
        // flags do block those child namespace operations.
        let blocking = libc::UF_IMMUTABLE | libc::UF_APPEND | libc::SF_IMMUTABLE | libc::SF_APPEND;
        if metadata.flags.is_some_and(|flags| flags & blocking != 0) {
            anyhow::bail!("{label} carries child-namespace-blocking BSD flags");
        }
        validate_macos_directory_namespace_acl(&metadata.acl, label)?;
    }
    #[cfg(target_os = "linux")]
    if metadata
        .flags
        .is_some_and(|flags| flags & (0x10 | 0x20) != 0)
    {
        anyhow::bail!("{label} carries immutable/append inode flags");
    }
    Ok(())
}

#[cfg(unix)]
fn unix_xattr_call_unsupported(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ENOTSUP) || error.raw_os_error() == Some(libc::EOPNOTSUPP)
}

#[cfg(unix)]
fn unix_config_xattrs(file: &fs::File) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    const MAX_XATTR_BYTES: usize = 4 * 1024 * 1024;
    const MAX_XATTRS: usize = 1024;
    let fd = file.as_raw_fd();
    let list_size = unsafe {
        #[cfg(target_os = "macos")]
        {
            libc::flistxattr(fd, std::ptr::null_mut(), 0, 0)
        }
        #[cfg(not(target_os = "macos"))]
        {
            libc::flistxattr(fd, std::ptr::null_mut(), 0)
        }
    };
    if list_size < 0 {
        let error = io::Error::last_os_error();
        return Err(error).context("failed to size managed config xattr list");
    }
    let list_size = usize::try_from(list_size).context("managed config xattr list overflow")?;
    if list_size > MAX_XATTR_BYTES {
        anyhow::bail!("managed config xattr name list exceeds the 4 MiB safety bound");
    }
    let mut names = vec![0_u8; list_size];
    if list_size != 0 {
        let listed = unsafe {
            #[cfg(target_os = "macos")]
            {
                libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len(), 0)
            }
            #[cfg(not(target_os = "macos"))]
            {
                libc::flistxattr(fd, names.as_mut_ptr().cast(), names.len())
            }
        };
        if listed < 0 {
            return Err(io::Error::last_os_error())
                .context("failed to read managed config xattr list");
        }
        names.truncate(
            usize::try_from(listed).context("managed config xattr list length overflow")?,
        );
    }
    let mut entries = Vec::new();
    let mut aggregate_bytes = list_size;
    for raw_name in names
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        if entries.len() >= MAX_XATTRS {
            anyhow::bail!("managed config has more than 1024 extended attributes");
        }
        let name = CString::new(raw_name).context("managed config xattr name contains NUL")?;
        let value_size = unsafe {
            #[cfg(target_os = "macos")]
            {
                libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0)
            }
            #[cfg(not(target_os = "macos"))]
            {
                libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0)
            }
        };
        if value_size < 0 {
            return Err(io::Error::last_os_error()).with_context(|| {
                format!(
                    "failed to size managed config xattr {:?}",
                    String::from_utf8_lossy(raw_name)
                )
            });
        }
        let value_size =
            usize::try_from(value_size).context("managed config xattr value overflow")?;
        if value_size > MAX_XATTR_BYTES {
            anyhow::bail!("managed config xattr value exceeds the 4 MiB safety bound");
        }
        aggregate_bytes = aggregate_bytes
            .checked_add(raw_name.len())
            .and_then(|total| total.checked_add(value_size))
            .context("managed config aggregate xattr size overflow")?;
        if aggregate_bytes > 16 * 1024 * 1024 {
            anyhow::bail!(
                "managed config aggregate xattr metadata exceeds the 16 MiB safety bound"
            );
        }
        let mut value = vec![0_u8; value_size];
        if value_size != 0 {
            let read = unsafe {
                #[cfg(target_os = "macos")]
                {
                    libc::fgetxattr(
                        fd,
                        name.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                        0,
                        0,
                    )
                }
                #[cfg(not(target_os = "macos"))]
                {
                    libc::fgetxattr(fd, name.as_ptr(), value.as_mut_ptr().cast(), value.len())
                }
            };
            if read < 0 {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed to read managed config xattr {:?}",
                        String::from_utf8_lossy(raw_name)
                    )
                });
            }
            value.truncate(
                usize::try_from(read).context("managed config xattr read length overflow")?,
            );
        }
        entries.push((raw_name.to_vec(), value));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(entries)
}

#[cfg(target_os = "macos")]
fn macos_config_acl(file: &fs::File) -> Result<Vec<u8>> {
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, acl_type: libc::c_int) -> *mut libc::c_void;
        fn acl_to_text(acl: *mut libc::c_void, len: *mut libc::ssize_t) -> *mut libc::c_char;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) };
    if acl.is_null() {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(Vec::new());
        }
        return Err(error).context("failed to read managed config ACL");
    }
    let mut len = 0;
    let text = unsafe { acl_to_text(acl, &mut len) };
    if text.is_null() {
        unsafe {
            acl_free(acl);
        }
        return Err(io::Error::last_os_error()).context("failed to serialize managed config ACL");
    }
    let result = if len < 0 {
        Err(anyhow::anyhow!("managed config ACL length is negative"))
    } else {
        match usize::try_from(len) {
            Ok(len) => Ok(unsafe { std::slice::from_raw_parts(text.cast::<u8>(), len) }.to_vec()),
            Err(error) => {
                Err(anyhow::Error::new(error).context("managed config ACL length overflow"))
            }
        }
    };
    unsafe {
        acl_free(text.cast());
        acl_free(acl);
    }
    result
}

#[cfg(unix)]
fn unix_config_flags(file: &fs::File) -> Result<Option<u32>> {
    #[cfg(target_os = "macos")]
    {
        let stat = rustix::fs::fstat(file)?;
        return Ok(Some(stat.st_flags));
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd as _;
        let mut flags: libc::c_int = 0;
        if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } == 0 {
            return Ok(Some(u32::try_from(flags).context(
                "managed config inode flags cannot be represented as u32",
            )?));
        }
        let error = io::Error::last_os_error();
        if unix_xattr_call_unsupported(&error)
            || matches!(
                error.raw_os_error(),
                Some(libc::ENOTTY) | Some(libc::EINVAL)
            )
        {
            return Ok(None);
        }
        return Err(error).context("failed to read managed config inode flags");
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = file;
        Ok(None)
    }
}

#[cfg(unix)]
fn unix_config_metadata(file: &fs::File) -> Result<UnixConfigMetadata> {
    Ok(UnixConfigMetadata {
        xattrs: unix_config_xattrs(file)?,
        #[cfg(target_os = "macos")]
        acl: macos_config_acl(file)?,
        #[cfg(not(target_os = "macos"))]
        acl: Vec::new(),
        flags: unix_config_flags(file)?,
    })
}

#[cfg(unix)]
fn unix_set_xattr(file: &fs::File, name: &[u8], value: &[u8]) -> Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let name = CString::new(name).context("managed config xattr name contains NUL")?;
    let result = unsafe {
        #[cfg(target_os = "macos")]
        {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
                0,
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                value.as_ptr().cast(),
                value.len(),
                0,
            )
        }
    };
    if result != 0 {
        return Err(io::Error::last_os_error()).context("failed to copy managed config xattr");
    }
    Ok(())
}

#[cfg(unix)]
fn unix_remove_xattr(file: &fs::File, name: &[u8]) -> Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;

    let name = CString::new(name).context("managed config xattr name contains NUL")?;
    let result = unsafe {
        #[cfg(target_os = "macos")]
        {
            libc::fremovexattr(file.as_raw_fd(), name.as_ptr(), 0)
        }
        #[cfg(not(target_os = "macos"))]
        {
            libc::fremovexattr(file.as_raw_fd(), name.as_ptr())
        }
    };
    if result != 0 {
        let error = io::Error::last_os_error();
        #[cfg(target_os = "macos")]
        let missing = error.raw_os_error() == Some(libc::ENOATTR);
        #[cfg(not(target_os = "macos"))]
        let missing = error.raw_os_error() == Some(libc::ENODATA);
        if missing || unix_xattr_call_unsupported(&error) {
            return Ok(());
        }
        return Err(error).context("failed to remove managed config xattr");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clear_macos_extended_acl(file: &fs::File) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    unsafe extern "C" {
        fn acl_init(count: libc::c_int) -> *mut libc::c_void;
        fn acl_set_fd_np(
            fd: libc::c_int,
            acl: *mut libc::c_void,
            acl_type: libc::c_int,
        ) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
    let acl = unsafe { acl_init(0) };
    if acl.is_null() {
        return Err(io::Error::last_os_error()).context("failed to allocate empty Kin ACL");
    }
    let applied = unsafe { acl_set_fd_np(file.as_raw_fd(), acl, ACL_TYPE_EXTENDED) };
    unsafe {
        acl_free(acl);
    }
    if applied != 0 {
        return Err(io::Error::last_os_error()).context("failed to clear inherited Kin ACL");
    }
    Ok(())
}

#[cfg(unix)]
fn clear_product_owned_unix_acl(file: &fs::File) -> Result<()> {
    #[cfg(target_os = "macos")]
    clear_macos_extended_acl(file)?;
    #[cfg(target_os = "linux")]
    {
        unix_remove_xattr(file, b"system.posix_acl_access")?;
        unix_remove_xattr(file, b"system.posix_acl_default")?;
        unix_remove_xattr(file, b"system.nfs4_acl")?;
        unix_remove_xattr(file, b"system.richacl")?;
    }
    let metadata = unix_config_metadata(file)?;
    if metadata.grants_extended_private_access() {
        anyhow::bail!("product-owned Kin object retained an extended access ACL");
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_unix_directory(
    path: &Path,
    directory: &fs::File,
    newly_created: bool,
) -> Result<ConfigFileIdentity> {
    if newly_created {
        rustix::fs::fchmod(directory, rustix::fs::Mode::from_raw_mode(0o700))?;
        clear_product_owned_unix_acl(directory)?;
        directory.sync_all()?;
    }
    let stat = rustix::fs::fstat(directory)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_uid != unsafe { libc::geteuid() }
        || (stat.st_mode as u32 & 0o7777) != 0o700
    {
        anyhow::bail!(
            "managed private directory must be a current-user directory with mode 0700: {}",
            path.display()
        );
    }
    let extended = unix_config_metadata(directory)?;
    if extended.grants_extended_private_access() {
        anyhow::bail!(
            "managed private directory has an extended access ACL: {}",
            path.display()
        );
    }
    validate_unix_metadata_for_transaction(&extended, "managed private directory")?;
    Ok(ConfigFileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

#[cfg(unix)]
fn repair_restrictive_umask_on_new_private_directory(
    parent: &fs::File,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<ConfigFileIdentity> {
    let created_stat = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if rustix::fs::FileType::from_raw_mode(created_stat.st_mode) != rustix::fs::FileType::Directory
        || created_stat.st_uid != unsafe { libc::geteuid() }
    {
        anyhow::bail!(
            "new private directory changed before restrictive-umask repair: {}",
            display.display()
        );
    }
    let identity = ConfigFileIdentity {
        device: created_stat.st_dev as u64,
        inode: created_stat.st_ino as u64,
    };
    // mkdirat honors the process umask and can therefore create mode 000. This
    // is an unpublished random staging name beneath a locked, anchored parent;
    // EEXIST winners at the final name never enter this repair path.
    if created_stat.st_mode as u32 & 0o7777 != 0o700 {
        #[cfg(target_os = "linux")]
        {
            use std::ffi::CString;
            use std::os::fd::AsRawFd as _;
            use std::os::unix::ffi::OsStrExt as _;

            let name =
                CString::new(name.as_bytes()).context("new private directory name contains NUL")?;
            // fchmodat2 is syscall 452 on Kin's supported Linux x86_64 and
            // aarch64 targets. libc does not expose SYS_fchmodat2 on every
            // supported architecture, so keep the number local and fail loud
            // with ENOSYS on an older kernel rather than following a symlink.
            const LINUX_SYS_FCHMODAT2: libc::c_long = 452;
            let result = unsafe {
                libc::syscall(
                    LINUX_SYS_FCHMODAT2,
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    0o700 as libc::mode_t,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error()).with_context(|| {
                    format!(
                        "failed exact no-follow restrictive-umask repair for {}",
                        display.display()
                    )
                });
            }
        }
        #[cfg(not(target_os = "linux"))]
        rustix::fs::chmodat(
            parent,
            name,
            rustix::fs::Mode::from_raw_mode(0o700),
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )?;
    }
    let repaired = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
    if repaired.st_dev as u64 != identity.device
        || repaired.st_ino as u64 != identity.inode
        || rustix::fs::FileType::from_raw_mode(repaired.st_mode) != rustix::fs::FileType::Directory
        || repaired.st_uid != unsafe { libc::geteuid() }
        || repaired.st_mode as u32 & 0o7777 != 0o700
    {
        anyhow::bail!(
            "new private directory changed during restrictive-umask repair: {}",
            display.display()
        );
    }
    Ok(identity)
}

#[cfg(unix)]
const PRIVATE_DIRECTORY_STAGE_PREFIX: &str = ".kin-private-directory-stage-";

#[cfg(unix)]
const PRIVATE_DIRECTORY_STAGE_SUFFIX: &str = ".tmp";

#[cfg(unix)]
fn private_directory_stage_uuid(name: &str) -> Option<&str> {
    name.strip_prefix(PRIVATE_DIRECTORY_STAGE_PREFIX)
        .and_then(|name| name.strip_suffix(PRIVATE_DIRECTORY_STAGE_SUFFIX))
        .filter(|uuid| uuid::Uuid::parse_str(uuid).is_ok())
}

#[cfg(unix)]
fn lock_private_directory_parent(parent: &fs::File, display: &Path) -> Result<fs::File> {
    let expected = config_parent_identity(parent)?;
    let fd = rustix::fs::openat(
        parent,
        ".",
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?;
    let guard = fs::File::from(fd);
    if config_parent_identity(&guard)? != expected {
        anyhow::bail!(
            "private-directory parent changed before staging: {}",
            display.display()
        );
    }
    lock_file_exclusive_bounded(
        &guard,
        &format!("private-directory parent {}", display.display()),
    )?;
    if config_parent_identity(parent)? != expected || config_parent_identity(&guard)? != expected {
        anyhow::bail!(
            "private-directory parent changed while Kin waited: {}",
            display.display()
        );
    }
    Ok(guard)
}

#[cfg(unix)]
fn cleanup_orphaned_private_directory_stages(parent: &fs::File, display: &Path) -> Result<()> {
    const MAX_ORPHAN_STAGES: usize = 64;

    let mut entries = rustix::fs::Dir::read_from(parent).with_context(|| {
        format!(
            "failed to enumerate private-directory parent {}",
            display.display()
        )
    })?;
    let mut owned = Vec::new();
    for entry in &mut entries {
        let entry = entry.with_context(|| {
            format!(
                "failed to read private-directory parent {}",
                display.display()
            )
        })?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let Ok(name) = std::str::from_utf8(bytes) else {
            continue;
        };
        if private_directory_stage_uuid(name).is_none() {
            continue;
        }
        if owned.len() == MAX_ORPHAN_STAGES {
            anyhow::bail!(
                "private-directory parent has more than {MAX_ORPHAN_STAGES} Kin staging residues: {}",
                display.display()
            );
        }
        let stat = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
            || stat.st_uid != unsafe { libc::geteuid() }
        {
            anyhow::bail!(
                "Kin private-directory staging residue has unsafe authority and was retained: {}",
                display.join(name).display()
            );
        }
        owned.push(name.to_string());
    }
    if owned.is_empty() {
        return Ok(());
    }
    for name in &owned {
        rustix::fs::unlinkat(parent, name.as_str(), rustix::fs::AtFlags::REMOVEDIR).with_context(
            || {
                format!(
                    "Kin private-directory staging residue is not an empty owned directory and was retained: {}",
                    display.join(name).display()
                )
            },
        )?;
    }
    sync_config_parent(parent)
}

#[cfg(unix)]
fn ensure_private_directory_binding_at(
    parent: &fs::File,
    name: &std::ffi::OsStr,
    identity: &ConfigFileIdentity,
    label: &str,
) -> Result<()> {
    let stat = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .with_context(|| format!("{label} disappeared"))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_dev as u64 != identity.device
        || stat.st_ino as u64 != identity.inode
    {
        anyhow::bail!("{label} changed object identity");
    }
    Ok(())
}

#[cfg(unix)]
fn open_existing_private_unix_directory_at(
    parent: &fs::File,
    name: &std::ffi::OsStr,
    display: &Path,
) -> Result<(fs::File, ConfigFileIdentity)> {
    let fd = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("failed to anchor private directory {}", display.display()))?;
    let directory = fs::File::from(fd);
    let identity = validate_private_unix_directory(display, &directory, false)?;
    ensure_private_directory_binding_at(parent, name, &identity, "managed private directory")?;
    Ok((directory, identity))
}

#[cfg(unix)]
fn open_or_create_private_unix_directory_at(
    parent: &fs::File,
    parent_display: &Path,
    final_name: &std::ffi::OsStr,
    final_display: &Path,
) -> Result<(fs::File, bool, ConfigFileIdentity)> {
    let _parent_guard = lock_private_directory_parent(parent, parent_display)?;
    cleanup_orphaned_private_directory_stages(parent, parent_display)?;

    match rustix::fs::statat(parent, final_name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            let (directory, identity) =
                open_existing_private_unix_directory_at(parent, final_name, final_display)?;
            return Ok((directory, false, identity));
        }
        Err(rustix::io::Errno::NOENT) => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect private directory {}",
                    final_display.display()
                )
            })
        }
    }

    let stage_name = (0..8)
        .find_map(|attempt| {
            let name = format!(
                "{PRIVATE_DIRECTORY_STAGE_PREFIX}{}{PRIVATE_DIRECTORY_STAGE_SUFFIX}",
                uuid::Uuid::new_v4()
            );
            match rustix::fs::mkdirat(
                parent,
                name.as_str(),
                rustix::fs::Mode::from_raw_mode(0o700),
            ) {
                Ok(()) => Some(Ok(name)),
                Err(rustix::io::Errno::EXIST) if attempt + 1 < 8 => None,
                Err(error) => Some(Err(error)),
            }
        })
        .context("failed to allocate a unique private-directory staging name")?
        .with_context(|| {
            format!(
                "failed to create private-directory stage for {}",
                final_display.display()
            )
        })?;

    maybe_inject_private_directory_stage(
        "after_mkdir",
        parent,
        &stage_name,
        final_name,
        final_display,
    )?;
    maybe_inject_private_directory_stage(
        "before_repair",
        parent,
        &stage_name,
        final_name,
        final_display,
    )?;
    let created_identity = repair_restrictive_umask_on_new_private_directory(
        parent,
        std::ffi::OsStr::new(&stage_name),
        &parent_display.join(&stage_name),
    )?;
    maybe_inject_private_directory_stage(
        "after_repair",
        parent,
        &stage_name,
        final_name,
        final_display,
    )?;

    let fd = rustix::fs::openat(
        parent,
        stage_name.as_str(),
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| {
        format!(
            "failed to anchor private-directory stage for {}",
            final_display.display()
        )
    })?;
    let staged = fs::File::from(fd);
    if ConfigFileIdentity::from_metadata(&staged.metadata()?) != created_identity {
        anyhow::bail!(
            "private-directory stage changed before anchored validation: {}",
            final_display.display()
        );
    }
    let staged_identity = validate_private_unix_directory(final_display, &staged, true)?;
    if staged_identity != created_identity {
        anyhow::bail!(
            "private-directory stage changed during anchored validation: {}",
            final_display.display()
        );
    }
    ensure_private_directory_binding_at(
        parent,
        std::ffi::OsStr::new(&stage_name),
        &staged_identity,
        "managed private-directory stage",
    )?;
    sync_config_parent(&staged)?;
    sync_config_parent(parent)?;
    maybe_inject_private_directory_stage(
        "before_publish",
        parent,
        &stage_name,
        final_name,
        final_display,
    )?;

    match rustix::fs::renameat_with(
        parent,
        stage_name.as_str(),
        parent,
        final_name,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            if config_directory_sync_injected(final_display) {
                anyhow::bail!(
                    "injected durable config directory sync failure at {}",
                    final_display.display()
                );
            }
            sync_config_parent(parent)?;
            ensure_private_directory_binding_at(
                parent,
                final_name,
                &staged_identity,
                "published managed private directory",
            )?;
            Ok((staged, true, staged_identity))
        }
        Err(rustix::io::Errno::EXIST) => {
            ensure_private_directory_binding_at(
                parent,
                std::ffi::OsStr::new(&stage_name),
                &staged_identity,
                "unpublished managed private-directory stage",
            )?;
            rustix::fs::unlinkat(parent, stage_name.as_str(), rustix::fs::AtFlags::REMOVEDIR)?;
            sync_config_parent(parent)?;
            let (directory, identity) =
                open_existing_private_unix_directory_at(parent, final_name, final_display)?;
            Ok((directory, false, identity))
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to publish private directory {} without replacement",
                final_display.display()
            )
        }),
    }
}

#[cfg(unix)]
fn validate_kin_home_namespace(authority: &DurableConfigDirectory) -> Result<()> {
    if authority.final_created {
        rustix::fs::fchmod(&authority.file, rustix::fs::Mode::from_raw_mode(0o700))?;
        clear_product_owned_unix_acl(&authority.file)?;
        authority.file.sync_all()?;
    }
    let stat = rustix::fs::fstat(&authority.file)?;
    let metadata = unix_config_metadata(&authority.file)?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
        || stat.st_uid != unsafe { libc::geteuid() }
        || stat.st_mode as u32 & 0o022 != 0
        || metadata.grants_extended_private_access()
    {
        anyhow::bail!(
            "Kin home must be a current-user directory without group/other write or extended ACL authority: {}",
            authority.path.display()
        );
    }
    validate_unix_directory_namespace_metadata(&metadata, "Kin home")?;
    if config_parent_identity(&authority.file)? != authority.identity {
        anyhow::bail!("Kin home handle changed identity");
    }
    let visible = open_config_parent_nofollow(&authority.path)?;
    if config_parent_identity(&visible)? != authority.identity {
        anyhow::bail!(
            "Kin home namespace binding changed: {}",
            authority.path.display()
        );
    }
    let parent_path = authority
        .path
        .parent()
        .context("Kin home has no namespace parent")?
        .canonicalize()?;
    let parent = open_config_parent_nofollow(&parent_path)?;
    let parent_stat = rustix::fs::fstat(&parent)?;
    let parent_extended = unix_config_metadata(&parent)?;
    if parent_stat.st_mode as u32 & 0o022 != 0 && parent_stat.st_mode as u32 & 0o1000 == 0 {
        anyhow::bail!(
            "Kin-home parent permits untrusted namespace replacement: {}",
            parent_path.display()
        );
    }
    #[cfg(not(target_os = "macos"))]
    if parent_extended.grants_extended_private_access() {
        anyhow::bail!(
            "Kin-home parent carries extended namespace authority: {}",
            parent_path.display()
        );
    }
    validate_unix_directory_namespace_metadata(&parent_extended, "Kin-home parent")?;
    Ok(())
}

#[cfg(unix)]
fn validate_private_unix_file(
    path: &Path,
    file: &fs::File,
    newly_created: bool,
) -> Result<fs::Metadata> {
    if newly_created {
        rustix::fs::fchmod(file, rustix::fs::Mode::from_raw_mode(0o600))?;
        clear_product_owned_unix_acl(file)?;
        file.sync_all()?;
    }
    let metadata = validate_regular_config_file(path, file, true)?;
    let extended = unix_config_metadata(file)?;
    if extended.grants_extended_private_access() {
        anyhow::bail!(
            "managed private file has an extended access ACL: {}",
            path.display()
        );
    }
    validate_unix_metadata_for_transaction(&extended, "managed private file")?;
    Ok(metadata)
}

#[cfg(unix)]
fn apply_unix_config_metadata(
    source: &fs::File,
    destination: &fs::File,
    expected: &ObservedConfigFile,
) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    #[cfg(not(target_os = "macos"))]
    let _ = source;

    validate_unix_metadata_for_transaction(&expected.metadata, "managed config")?;

    // Ownership and mode changes can rewrite ACL masks, clear set-id bits, or
    // invalidate capability xattrs. Apply them before copying extended
    // metadata so the final equality check describes the committed object.
    rustix::fs::fchown(
        destination,
        None,
        Some(rustix::fs::Gid::from_raw(expected.gid)),
    )
    .context("failed to preserve managed config group on staged replacement")?;
    rustix::fs::fchmod(
        destination,
        rustix::fs::Mode::from_raw_mode(expected.mode as _),
    )
    .context("failed to preserve full managed config mode on staged replacement")?;

    #[cfg(target_os = "macos")]
    if unsafe {
        libc::fcopyfile(
            source.as_raw_fd(),
            destination.as_raw_fd(),
            std::ptr::null_mut(),
            libc::COPYFILE_ACL | libc::COPYFILE_XATTR,
        )
    } != 0
    {
        return Err(io::Error::last_os_error())
            .context("failed to copy managed config ACL/xattrs to staged replacement");
    }

    let destination_xattrs = unix_config_xattrs(destination)?;
    for (name, _) in destination_xattrs {
        if !expected
            .metadata
            .xattrs
            .iter()
            .any(|(expected_name, _)| expected_name == &name)
        {
            unix_remove_xattr(destination, &name)?;
        }
    }
    for (name, value) in &expected.metadata.xattrs {
        unix_set_xattr(destination, name, value)?;
    }

    #[cfg(target_os = "macos")]
    if let Some(flags) = expected.metadata.flags {
        if unsafe { libc::fchflags(destination.as_raw_fd(), flags) } != 0 {
            return Err(io::Error::last_os_error())
                .context("failed to preserve managed config BSD flags");
        }
    }
    #[cfg(target_os = "linux")]
    if let Some(flags) = expected.metadata.flags {
        let flags = libc::c_int::try_from(flags)
            .context("managed config inode flags cannot be represented as c_int")?;
        if unsafe { libc::ioctl(destination.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) } != 0 {
            return Err(io::Error::last_os_error())
                .context("failed to preserve managed config inode flags");
        }
    }
    destination.sync_all()?;
    let actual = unix_config_metadata(destination)?;
    if actual != expected.metadata {
        anyhow::bail!(
            "staged managed config metadata does not exactly match the retained original"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn sanitize_owned_unix_stage_for_cleanup(stage: &fs::File) -> Result<()> {
    use std::os::fd::AsRawFd as _;

    #[cfg(target_os = "macos")]
    if unsafe { libc::fchflags(stage.as_raw_fd(), 0) } != 0 {
        return Err(io::Error::last_os_error())
            .context("failed to clear namespace-blocking flags from owned Kin stage");
    }
    #[cfg(target_os = "linux")]
    {
        let flags: libc::c_int = 0;
        if unsafe { libc::ioctl(stage.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) } != 0 {
            let error = io::Error::last_os_error();
            if !unix_xattr_call_unsupported(&error)
                && !matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTTY) | Some(libc::EINVAL)
                )
            {
                return Err(error)
                    .context("failed to clear namespace-blocking flags from owned Kin stage");
            }
        }
    }
    clear_product_owned_unix_acl(stage)?;
    rustix::fs::fchmod(stage, rustix::fs::Mode::from_raw_mode(0o600))?;
    stage.sync_all()?;
    Ok(())
}

#[derive(Debug)]
struct ObservedConfigFile {
    bytes: Vec<u8>,
    identity: ConfigFileIdentity,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    metadata: UnixConfigMetadata,
    #[cfg(windows)]
    security: String,
    #[cfg(windows)]
    full_sacl: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct RecordedConfigObject {
    identity: ConfigFileIdentity,
    sha256: String,
    len: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
    #[cfg(unix)]
    metadata_sha256: String,
    #[cfg(windows)]
    security: String,
    #[cfg(windows)]
    full_sacl: Option<String>,
}

impl RecordedConfigObject {
    fn from_observed(observed: &ObservedConfigFile) -> Self {
        Self {
            identity: observed.identity.clone(),
            sha256: crate::commands::setup_ledger::sha256_hex(&observed.bytes),
            len: observed.bytes.len() as u64,
            #[cfg(unix)]
            mode: observed.mode,
            #[cfg(unix)]
            uid: observed.uid,
            #[cfg(unix)]
            gid: observed.gid,
            #[cfg(unix)]
            metadata_sha256: observed.metadata.fingerprint(),
            #[cfg(windows)]
            security: observed.security.clone(),
            #[cfg(windows)]
            full_sacl: observed.full_sacl.clone(),
        }
    }

    fn matches(&self, observed: &ObservedConfigFile) -> bool {
        self.identity == observed.identity
            && self.len == observed.bytes.len() as u64
            && self.sha256 == crate::commands::setup_ledger::sha256_hex(&observed.bytes)
            && {
                #[cfg(unix)]
                {
                    self.mode == observed.mode
                        && self.uid == observed.uid
                        && self.gid == observed.gid
                        && self.metadata_sha256 == observed.metadata.fingerprint()
                }
                #[cfg(not(unix))]
                {
                    #[cfg(windows)]
                    {
                        self.security == observed.security && self.full_sacl == observed.full_sacl
                    }
                    #[cfg(not(windows))]
                    {
                        true
                    }
                }
            }
    }

    #[cfg(unix)]
    fn same_identity(&self, observed: &ObservedConfigFile) -> bool {
        self.identity == observed.identity
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigTransactionOperation {
    Write,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigTransactionPhase {
    Prepared,
    NamespaceCommitted,
    RollbackApplied,
    CommitComplete,
    RollbackComplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigTransactionOutcome {
    Committed,
    RolledBack,
}

#[cfg(any(unix, windows))]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigParentIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    namespace: u64,
    #[cfg(windows)]
    file: super::update::WindowsFileId,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigTransactionRecord {
    schema_version: u32,
    sidecar: ConfigFileIdentity,
    destination: PathBuf,
    destination_name: String,
    operation: ConfigTransactionOperation,
    phase: ConfigTransactionPhase,
    private: bool,
    staged_name: Option<String>,
    retained_name: Option<String>,
    original: Option<RecordedConfigObject>,
    replacement: Option<RecordedConfigObject>,
    #[cfg(any(unix, windows))]
    parent: ConfigParentIdentity,
    #[cfg(unix)]
    vault: ConfigFileIdentity,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct ConfigTransactionEnvelope {
    magic: String,
    frame_schema: u32,
    sequence: u64,
    payload_len: u64,
    payload_sha256: String,
    payload: ConfigTransactionRecord,
}

const CONFIG_TRANSACTION_SCHEMA_VERSION: u32 = 6;
const CONFIG_TRANSACTION_WAL_MAGIC: &str = "KIN_CONFIG_TXN_WAL";
const CONFIG_TRANSACTION_WAL_FRAME_SCHEMA: u32 = 1;
const CONFIG_TRANSACTION_WAL_COMMIT_PREFIX: &str = "KIN_CONFIG_TXN_COMMIT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigTransactionSyncPoint {
    Envelope,
    Commit,
}

#[cfg(test)]
thread_local! {
    static FAIL_CONFIG_TRANSACTION_SYNC_AT:
        std::cell::RefCell<Option<ConfigTransactionSyncPoint>> = const {
            std::cell::RefCell::new(None)
        };
}

#[cfg(test)]
fn inject_config_transaction_sync_failure_at(point: Option<ConfigTransactionSyncPoint>) {
    FAIL_CONFIG_TRANSACTION_SYNC_AT.with(|configured| *configured.borrow_mut() = point);
}

fn config_transaction_sync_injected(point: ConfigTransactionSyncPoint) -> bool {
    #[cfg(test)]
    {
        return FAIL_CONFIG_TRANSACTION_SYNC_AT.with(|configured| {
            if configured.borrow().as_ref() == Some(&point) {
                configured.borrow_mut().take();
                true
            } else {
                false
            }
        });
    }
    #[cfg(not(test))]
    {
        let _ = point;
        false
    }
}

fn sync_config_transaction_wal(
    lock_file: &fs::File,
    point: ConfigTransactionSyncPoint,
) -> Result<()> {
    if config_transaction_sync_injected(point) {
        anyhow::bail!("injected managed config WAL {point:?} sync failure");
    }
    lock_file
        .sync_all()
        .with_context(|| format!("failed to sync managed config recovery {point:?}"))
}

#[derive(Debug)]
struct ConfigTransactionWalState {
    latest: Option<ConfigTransactionRecord>,
    committed_len: usize,
    next_sequence: u64,
    uncommitted_tail_sha256: Option<String>,
}

struct ConfigTransactionCommit {
    sequence: u64,
    envelope_len: u64,
    envelope_sha256: String,
}

fn validate_regular_config_file(
    path: &Path,
    file: &fs::File,
    private: bool,
) -> Result<fs::Metadata> {
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("managed config is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            anyhow::bail!("managed config has multiple hard links: {}", path.display());
        }
        if metadata.uid() != unsafe { libc::geteuid() } {
            anyhow::bail!(
                "managed config is not owned by the current user: {}",
                path.display()
            );
        }
        if private && metadata.permissions().mode() & 0o7777 != 0o600 {
            anyhow::bail!(
                "managed private file must have mode 0600: {}",
                path.display()
            );
        }
    }
    #[cfg(windows)]
    {
        use std::mem::zeroed;
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
            FILE_ATTRIBUTE_REPARSE_POINT,
        };

        // `Metadata::is_file` describes the target when a reparse point was
        // followed. Config authority instead comes from the exact handle opened
        // with FILE_FLAG_OPEN_REPARSE_POINT, so reject every final-component
        // reparse point and hard link by handle attributes.
        // SAFETY: zero is a valid initializer for this output structure and the
        // file owns a live Windows handle for the duration of the call.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
        if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!("failed to inspect managed config handle {}", path.display())
            });
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!("managed config is a reparse point: {}", path.display());
        }
        if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            anyhow::bail!("managed config is a directory: {}", path.display());
        }
        if info.nNumberOfLinks != 1 {
            anyhow::bail!("managed config has multiple hard links: {}", path.display());
        }
        if private {
            super::update::windows_update::validate_current_user_private_file(file)?;
        }
    }
    Ok(metadata)
}

#[cfg(windows)]
fn visible_config_file_identity_nofollow(path: &Path) -> Result<ConfigFileIdentity> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| {
            format!(
                "failed to open visible managed config authority {}",
                path.display()
            )
        })?;
    validate_regular_config_file(path, &file, false)?;
    ConfigFileIdentity::from_open_file(&file)
}

fn read_config_file_nofollow(path: &Path, private: bool) -> Result<Option<ObservedConfigFile>> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to open managed config without following links: {}",
                    path.display()
                )
            })
        }
    };
    observe_open_config_file(path, &mut file, private).map(Some)
}

fn observe_open_config_file(
    path: &Path,
    file: &mut fs::File,
    private: bool,
) -> Result<ObservedConfigFile> {
    #[cfg(unix)]
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    file.seek(io::SeekFrom::Start(0))
        .with_context(|| format!("failed to rewind {}", path.display()))?;
    let metadata = validate_regular_config_file(path, file, private)?;
    #[cfg(windows)]
    let _ = &metadata;
    #[cfg(unix)]
    let identity = ConfigFileIdentity::from_metadata(&metadata);
    #[cfg(windows)]
    let identity = ConfigFileIdentity::from_open_file(file)?;
    #[cfg(unix)]
    let initial_mode = metadata.permissions().mode() & 0o7777;
    #[cfg(unix)]
    let initial_uid = metadata.uid();
    #[cfg(unix)]
    let initial_gid = metadata.gid();
    #[cfg(unix)]
    let initial_stability = (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        initial_mode,
        initial_uid,
        initial_gid,
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    );
    #[cfg(unix)]
    let initial_extended = unix_config_metadata(file)?;
    #[cfg(unix)]
    if private && initial_extended.grants_extended_private_access() {
        anyhow::bail!(
            "managed private file has an extended ACL that can bypass mode 0600: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    let initial_security = super::update::windows_update::managed_file_metadata_fingerprint(file)?;
    let mut first_bytes = Vec::new();
    file.read_to_end(&mut first_bytes)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let middle_metadata = validate_regular_config_file(path, file, private)?;
    #[cfg(windows)]
    let _ = &middle_metadata;
    #[cfg(unix)]
    let middle_stability = (
        middle_metadata.dev(),
        middle_metadata.ino(),
        middle_metadata.len(),
        middle_metadata.permissions().mode() & 0o7777,
        middle_metadata.uid(),
        middle_metadata.gid(),
        middle_metadata.mtime(),
        middle_metadata.mtime_nsec(),
        middle_metadata.ctime(),
        middle_metadata.ctime_nsec(),
    );
    #[cfg(unix)]
    let middle_extended = unix_config_metadata(file)?;
    file.seek(io::SeekFrom::Start(0))
        .with_context(|| format!("failed to rewind {} for stable reread", path.display()))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to reread {}", path.display()))?;
    let final_metadata = validate_regular_config_file(path, file, private)?;
    #[cfg(unix)]
    let final_identity = ConfigFileIdentity::from_metadata(&final_metadata);
    #[cfg(windows)]
    let final_identity = ConfigFileIdentity::from_open_file(file)?;
    #[cfg(unix)]
    let final_stability = (
        final_metadata.dev(),
        final_metadata.ino(),
        final_metadata.len(),
        final_metadata.permissions().mode() & 0o7777,
        final_metadata.uid(),
        final_metadata.gid(),
        final_metadata.mtime(),
        final_metadata.mtime_nsec(),
        final_metadata.ctime(),
        final_metadata.ctime_nsec(),
    );
    #[cfg(unix)]
    let final_extended = unix_config_metadata(file)?;
    #[cfg(windows)]
    let final_security = super::update::windows_update::managed_file_metadata_fingerprint(file)?;
    if first_bytes != bytes
        || final_identity != identity
        || final_metadata.len() != bytes.len() as u64
        || {
            #[cfg(unix)]
            {
                initial_stability != middle_stability
                    || middle_stability != final_stability
                    || initial_extended != middle_extended
                    || middle_extended != final_extended
            }
            #[cfg(windows)]
            {
                initial_security != final_security
            }
            #[cfg(all(not(unix), not(windows)))]
            {
                false
            }
        }
    {
        anyhow::bail!(
            "managed config changed while it was read: {}",
            path.display()
        );
    }
    Ok(ObservedConfigFile {
        bytes,
        identity,
        #[cfg(unix)]
        mode: final_metadata.permissions().mode() & 0o7777,
        #[cfg(unix)]
        uid: final_metadata.uid(),
        #[cfg(unix)]
        gid: final_metadata.gid(),
        #[cfg(unix)]
        metadata: final_extended,
        #[cfg(windows)]
        security: final_security,
        #[cfg(windows)]
        full_sacl: None,
    })
}

#[cfg(windows)]
fn observe_open_config_file_with_full_sacl(
    path: &Path,
    file: &mut fs::File,
    private: bool,
    strict_sacl: bool,
) -> Result<ObservedConfigFile> {
    if !strict_sacl {
        return observe_open_config_file(path, file, private);
    }
    let initial = super::update::windows_update::managed_file_full_sacl_fingerprint(file)
        .with_context(|| {
            format!(
                "failed to capture full SACL authority for {}",
                path.display()
            )
        })?;
    let mut observed = observe_open_config_file(path, file, private)?;
    let final_fingerprint = super::update::windows_update::managed_file_full_sacl_fingerprint(file)
        .with_context(|| {
            format!(
                "failed to recapture full SACL authority for {}",
                path.display()
            )
        })?;
    if final_fingerprint != initial {
        anyhow::bail!(
            "managed config full SACL changed while it was read: {}",
            path.display()
        );
    }
    observed.full_sacl = Some(final_fingerprint);
    Ok(observed)
}

fn complete_wal_line(bytes: &[u8], offset: usize) -> Option<(&[u8], usize)> {
    let relative_end = bytes
        .get(offset..)?
        .iter()
        .position(|byte| *byte == b'\n')?;
    let end = offset + relative_end;
    Some((&bytes[offset..end], end + 1))
}

fn parse_config_transaction_commit(line: &[u8]) -> Option<ConfigTransactionCommit> {
    let line = std::str::from_utf8(line).ok()?;
    let mut fields = line.split(' ');
    if fields.next()? != CONFIG_TRANSACTION_WAL_COMMIT_PREFIX {
        return None;
    }
    let sequence = fields.next()?.parse().ok()?;
    let envelope_len = fields.next()?.parse().ok()?;
    let envelope_sha256 = fields.next()?;
    if fields.next().is_some()
        || envelope_sha256.len() != 64
        || !envelope_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(ConfigTransactionCommit {
        sequence,
        envelope_len,
        envelope_sha256: envelope_sha256.to_string(),
    })
}

fn suffix_contains_config_transaction_commit(bytes: &[u8], mut offset: usize) -> bool {
    while let Some((line, next)) = complete_wal_line(bytes, offset) {
        if parse_config_transaction_commit(line).is_some() {
            return true;
        }
        offset = next;
    }
    false
}

fn uncommitted_config_transaction_tail(
    bytes: &[u8],
    committed_len: usize,
    next_sequence: u64,
    latest: Option<ConfigTransactionRecord>,
) -> ConfigTransactionWalState {
    ConfigTransactionWalState {
        latest,
        committed_len,
        next_sequence,
        uncommitted_tail_sha256: Some(crate::commands::setup_ledger::sha256_hex(
            &bytes[committed_len..],
        )),
    }
}

fn parse_config_transaction_wal(bytes: &[u8]) -> Result<ConfigTransactionWalState> {
    let mut latest = None;
    let mut committed_len = 0_usize;
    let mut offset = 0_usize;
    let mut expected_sequence = 1_u64;
    while offset < bytes.len() {
        let envelope_start = offset;
        let Some((envelope_bytes, after_envelope)) = complete_wal_line(bytes, offset) else {
            return Ok(uncommitted_config_transaction_tail(
                bytes,
                committed_len,
                expected_sequence,
                latest,
            ));
        };
        if parse_config_transaction_commit(envelope_bytes).is_some() {
            anyhow::bail!(
                "managed config recovery WAL has an orphan commit trailer where envelope sequence {} was required",
                expected_sequence
            );
        }
        let envelope = match serde_json::from_slice::<ConfigTransactionEnvelope>(envelope_bytes) {
            Ok(envelope) => envelope,
            Err(error) => {
                if suffix_contains_config_transaction_commit(bytes, after_envelope) {
                    return Err(error).context(
                        "managed config recovery WAL has corrupt non-final or committed envelope",
                    );
                }
                return Ok(uncommitted_config_transaction_tail(
                    bytes,
                    committed_len,
                    expected_sequence,
                    latest,
                ));
            }
        };
        let Some((commit_bytes, after_commit)) = complete_wal_line(bytes, after_envelope) else {
            return Ok(uncommitted_config_transaction_tail(
                bytes,
                committed_len,
                expected_sequence,
                latest,
            ));
        };
        let Some(commit) = parse_config_transaction_commit(commit_bytes) else {
            anyhow::bail!(
                "managed config recovery WAL has an invalid or ambiguous complete commit trailer at sequence {}",
                expected_sequence
            );
        };
        let envelope_digest = crate::commands::setup_ledger::sha256_hex(envelope_bytes);
        if commit.sequence != expected_sequence
            || commit.envelope_len != envelope_bytes.len() as u64
            || commit.envelope_sha256 != envelope_digest
        {
            anyhow::bail!(
                "managed config recovery WAL committed trailer mismatch at sequence {}",
                expected_sequence
            );
        }
        if envelope.magic != CONFIG_TRANSACTION_WAL_MAGIC
            || envelope.frame_schema != CONFIG_TRANSACTION_WAL_FRAME_SCHEMA
            || envelope.sequence != expected_sequence
        {
            anyhow::bail!(
                "managed config recovery WAL committed envelope authority is invalid at sequence {}",
                expected_sequence
            );
        }
        let payload = serde_json::to_vec(&envelope.payload)
            .context("failed to canonicalize managed config recovery transaction")?;
        if envelope.payload_len != payload.len() as u64 {
            anyhow::bail!(
                "managed config recovery WAL committed payload length mismatch at sequence {}",
                envelope.sequence
            );
        }
        let payload_digest = crate::commands::setup_ledger::sha256_hex(&payload);
        if payload_digest != envelope.payload_sha256 {
            anyhow::bail!(
                "managed config recovery WAL committed payload checksum mismatch at sequence {}",
                envelope.sequence
            );
        }
        if envelope.payload.schema_version != CONFIG_TRANSACTION_SCHEMA_VERSION {
            anyhow::bail!(
                "managed config recovery transaction has unsupported schema version {}",
                envelope.payload.schema_version
            );
        }
        latest = Some(envelope.payload);
        committed_len = after_commit;
        offset = after_commit;
        expected_sequence += 1;
        debug_assert!(committed_len > envelope_start);
    }
    Ok(ConfigTransactionWalState {
        latest,
        committed_len,
        next_sequence: expected_sequence,
        uncommitted_tail_sha256: None,
    })
}

fn read_config_transaction(lock_file: &fs::File) -> Result<Option<ConfigTransactionRecord>> {
    let mut reader = lock_file;
    reader.seek(io::SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    Ok(parse_config_transaction_wal(&bytes)?.latest)
}

fn write_config_transaction(lock_file: &fs::File, record: &ConfigTransactionRecord) -> Result<()> {
    let payload = serde_json::to_vec(record)
        .context("failed to serialize managed config recovery transaction")?;
    let mut reader = lock_file;
    reader.seek(io::SeekFrom::Start(0))?;
    let mut existing = Vec::new();
    reader.read_to_end(&mut existing)?;
    let wal = parse_config_transaction_wal(&existing)?;
    if let Some(tail_sha256) = wal.uncommitted_tail_sha256.as_deref() {
        let tail_len = existing.len() - wal.committed_len;
        eprintln!(
            "warning: repairing uncommitted managed config WAL suffix: bytes={tail_len} sha256={tail_sha256}"
        );
        lock_file
            .set_len(wal.committed_len as u64)
            .context("failed to discard uncommitted managed config recovery WAL suffix")?;
        lock_file
            .sync_all()
            .context("failed to sync repaired managed config recovery WAL tail")?;
    }
    let envelope = ConfigTransactionEnvelope {
        magic: CONFIG_TRANSACTION_WAL_MAGIC.to_string(),
        frame_schema: CONFIG_TRANSACTION_WAL_FRAME_SCHEMA,
        sequence: wal.next_sequence,
        payload_len: payload.len() as u64,
        payload_sha256: crate::commands::setup_ledger::sha256_hex(&payload),
        payload: record.clone(),
    };
    let envelope_bytes = serde_json::to_vec(&envelope)
        .context("failed to serialize managed config recovery envelope")?;
    let mut writer = lock_file;
    writer.seek(io::SeekFrom::End(0))?;
    writer
        .write_all(&envelope_bytes)
        .context("failed to append managed config recovery envelope")?;
    writer
        .write_all(b"\n")
        .context("failed to terminate managed config recovery envelope")?;
    sync_config_transaction_wal(lock_file, ConfigTransactionSyncPoint::Envelope)?;
    let envelope_sha256 = crate::commands::setup_ledger::sha256_hex(&envelope_bytes);
    let commit = format!(
        "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} {} {} {envelope_sha256}\n",
        envelope.sequence,
        envelope_bytes.len()
    );
    writer
        .write_all(commit.as_bytes())
        .context("failed to append managed config recovery commit trailer")?;
    sync_config_transaction_wal(lock_file, ConfigTransactionSyncPoint::Commit)
}

fn complete_config_transaction(
    lock_file: &fs::File,
    record: &mut ConfigTransactionRecord,
    outcome: ConfigTransactionOutcome,
) -> Result<()> {
    record.phase = match outcome {
        ConfigTransactionOutcome::Committed => ConfigTransactionPhase::CommitComplete,
        ConfigTransactionOutcome::RolledBack => ConfigTransactionPhase::RollbackComplete,
    };
    write_config_transaction(lock_file, record)
}

// Retire a fully resolved recovery journal by truncating it back to empty. A
// terminal record is not evidence of pending work, so keeping it only grows the
// journal without bound and leaves a resolved transaction replayable forever.
// Retirement is the completion step: once the owning operation has finished
// consulting the record, the transaction stops existing on disk. A still-open
// transaction (non-terminal latest record) is preserved untouched so durable
// crash recovery is unaffected.
fn retire_resolved_config_transaction_wal(lock_file: &fs::File) -> Result<()> {
    match read_config_transaction(lock_file)? {
        Some(record)
            if matches!(
                record.phase,
                ConfigTransactionPhase::CommitComplete | ConfigTransactionPhase::RollbackComplete
            ) =>
        {
            lock_file
                .set_len(0)
                .context("failed to retire resolved managed config recovery journal")?;
            lock_file
                .sync_all()
                .context("failed to sync retired managed config recovery journal")
        }
        _ => Ok(()),
    }
}

// Settle a guarded operation: after the operation itself has finished reading
// the journal, retire it if it reached a terminal outcome. A failed operation
// keeps its own error; a successful operation surfaces any retirement failure.
fn settle_config_transaction_after(lock_file: &fs::File, outcome: Result<()>) -> Result<()> {
    let retired = retire_resolved_config_transaction_wal(lock_file);
    match outcome {
        Ok(()) => retired,
        Err(error) => Err(error),
    }
}

fn complete_recovered_config_transaction(
    lock_file: &fs::File,
    record: &ConfigTransactionRecord,
    outcome: ConfigTransactionOutcome,
) -> Result<()> {
    let mut completed = record.clone();
    complete_config_transaction(lock_file, &mut completed, outcome)
}

#[cfg(unix)]
fn open_config_parent_nofollow(parent: &Path) -> Result<fs::File> {
    let fd = rustix::fs::open(
        parent,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::DIRECTORY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| {
        format!(
            "failed to anchor managed config parent {}",
            parent.display()
        )
    })?;
    Ok(fs::File::from(fd))
}

#[cfg(unix)]
#[derive(Debug)]
struct DurableConfigDirectory {
    path: PathBuf,
    file: fs::File,
    identity: ConfigParentIdentity,
    final_created: bool,
}

#[cfg(unix)]
fn create_config_directory_all_durable(
    path: &Path,
    private_chain: bool,
) -> Result<DurableConfigDirectory> {
    let mut cursor = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path.to_path_buf()
    };
    let mut missing = Vec::new();
    let anchor = loop {
        match fs::symlink_metadata(&cursor) {
            Ok(_) => {
                let canonical = cursor.canonicalize().with_context(|| {
                    format!(
                        "failed to canonicalize existing ancestor {}",
                        cursor.display()
                    )
                })?;
                let handle = open_config_parent_nofollow(&canonical)?;
                break (canonical, handle);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                let component = match cursor.components().next_back() {
                    Some(std::path::Component::Normal(component)) => component,
                    Some(std::path::Component::CurDir | std::path::Component::ParentDir) => {
                        anyhow::bail!(
                            "missing config directory suffix contains a non-normal component: {}",
                            cursor.display()
                        )
                    }
                    _ => anyhow::bail!(
                        "missing config directory has no final component: {}",
                        cursor.display()
                    ),
                };
                missing.push(component.to_os_string());
                let parent = cursor
                    .parent()
                    .context("missing config directory has no parent")?;
                cursor = if parent.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    parent.to_path_buf()
                };
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect config directory ancestor {}",
                        cursor.display()
                    )
                })
            }
        }
    };

    let (mut display, mut parent) = anchor;
    if private_chain {
        let stat = rustix::fs::fstat(&parent)?;
        let extended = unix_config_metadata(&parent)?;
        #[cfg(target_os = "macos")]
        let grants_extended_private_access = false;
        #[cfg(not(target_os = "macos"))]
        let grants_extended_private_access = extended.grants_extended_private_access();
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::Directory
            || (stat.st_mode as u32 & 0o022 != 0 && stat.st_mode as u32 & 0o1000 == 0)
            || grants_extended_private_access
        {
            anyhow::bail!(
                "existing Kin-home ancestor permits unsafe namespace replacement: {}",
                display.display()
            );
        }
        validate_unix_directory_namespace_metadata(&extended, "Kin-home ancestor")?;
    }
    let mut final_created = false;
    for (index, component) in missing.iter().rev().enumerate() {
        let child_display = display.join(component);
        maybe_inject_config_directory_eexist(&child_display)?;
        let (child, created) = if private_chain {
            let (child, created, _) = open_or_create_private_unix_directory_at(
                &parent,
                &display,
                component.as_os_str(),
                &child_display,
            )?;
            (child, created)
        } else {
            let created = match rustix::fs::mkdirat(
                &parent,
                component.as_os_str(),
                rustix::fs::Mode::from_raw_mode(0o777),
            ) {
                Ok(()) => true,
                Err(rustix::io::Errno::EXIST) => false,
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!(
                            "failed to create anchored config directory {}",
                            child_display.display()
                        )
                    })
                }
            };
            if created {
                if config_directory_sync_injected(&child_display) {
                    anyhow::bail!(
                        "injected durable config directory sync failure at {}",
                        child_display.display()
                    );
                }
                // Persist the new directory entry before any later fallible open.
                sync_config_parent(&parent)?;
            }
            let fd = rustix::fs::openat(
                &parent,
                component.as_os_str(),
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )?;
            let child = fs::File::from(fd);
            if created {
                sync_config_parent(&child)?;
            }
            (child, created)
        };
        display.push(component);
        parent = child;
        if index + 1 == missing.len() {
            final_created = created;
        }
    }
    let identity = config_parent_identity(&parent)?;
    let visible = open_config_parent_nofollow(&display)?;
    if config_parent_identity(&visible)? != identity {
        anyhow::bail!(
            "durably created config directory changed before authority return: {}",
            display.display()
        );
    }
    Ok(DurableConfigDirectory {
        path: display,
        file: parent,
        identity,
        final_created,
    })
}

#[cfg(unix)]
fn config_parent_identity(parent: &fs::File) -> Result<ConfigParentIdentity> {
    let stat = rustix::fs::fstat(parent)?;
    Ok(ConfigParentIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    })
}

#[cfg(unix)]
fn ensure_config_parent_binding(
    parent_path: &Path,
    parent: &fs::File,
    expected: &ConfigParentIdentity,
) -> Result<()> {
    if &config_parent_identity(parent)? != expected {
        anyhow::bail!("anchored managed config parent changed identity");
    }
    let current = open_config_parent_nofollow(parent_path).with_context(|| {
        format!(
            "failed to reopen canonical managed config parent {}",
            parent_path.display()
        )
    })?;
    if config_parent_identity(&current)? != *expected {
        anyhow::bail!(
            "canonical managed config parent binding changed: {}",
            parent_path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn open_observed_config_at(
    parent: &fs::File,
    name: &str,
    display: &Path,
    private: bool,
) -> Result<Option<(fs::File, ObservedConfigFile)>> {
    let before = match rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        Err(rustix::io::Errno::NOENT) => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to inspect anchored config {}", display.display())
            })
        }
    };
    if rustix::fs::FileType::from_raw_mode(before.st_mode) != rustix::fs::FileType::RegularFile {
        anyhow::bail!(
            "anchored managed config is not a regular file: {}",
            display.display()
        );
    }
    let fd = rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .with_context(|| format!("failed to open anchored config {}", display.display()))?;
    let mut file = fs::File::from(fd);
    let observed = observe_open_config_file(display, &mut file, private)?;
    let opened = rustix::fs::fstat(&file)?;
    if opened.st_dev != before.st_dev || opened.st_ino != before.st_ino {
        anyhow::bail!(
            "managed config changed while its anchored handle was opened: {}",
            display.display()
        );
    }
    Ok(Some((file, observed)))
}

#[derive(Debug)]
struct QuarantinedConfig {
    name: String,
    file: fs::File,
    observed: ObservedConfigFile,
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsStagedLocation {
    Staged,
    Canonical,
    DispositionApplied,
}

#[cfg(unix)]
fn sync_config_parent(parent: &fs::File) -> Result<()> {
    rustix::fs::fsync(parent).context("failed to sync anchored managed config parent")
}

#[cfg(unix)]
fn ensure_config_binding_at(
    parent: &fs::File,
    name: &str,
    identity: &ConfigFileIdentity,
    label: &str,
) -> Result<()> {
    let stat = rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW)
        .with_context(|| format!("{label} disappeared"))?;
    if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
        || stat.st_dev as u64 != identity.device
        || stat.st_ino as u64 != identity.inode
    {
        anyhow::bail!("{label} changed object identity");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_config_absent_at(parent: &fs::File, name: &str, label: &str) -> Result<()> {
    match rustix::fs::statat(parent, name, rustix::fs::AtFlags::SYMLINK_NOFOLLOW) {
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Ok(_) => anyhow::bail!("{label} unexpectedly remains visible"),
        Err(error) => Err(error).with_context(|| format!("failed to prove {label} absent")),
    }
}

#[cfg(unix)]
fn quarantine_config_at(
    parent: &fs::File,
    vault: &fs::File,
    destination_name: &str,
    destination: &Path,
    file: fs::File,
    observed: ObservedConfigFile,
    quarantine_name: String,
) -> Result<QuarantinedConfig> {
    rustix::fs::renameat_with(
        parent,
        destination_name,
        vault,
        quarantine_name.as_str(),
        rustix::fs::RenameFlags::NOREPLACE,
    )
    .with_context(|| {
        format!(
            "failed to quarantine managed config {} as {}",
            destination.display(),
            quarantine_name
        )
    })?;
    Ok(QuarantinedConfig {
        name: quarantine_name,
        file,
        observed,
    })
}

#[cfg(unix)]
fn cleanup_uncommitted_unix_stage(
    transaction: &ConfigTransactionAuthority,
    parent: &fs::File,
    source_name: &str,
    source_path: &Path,
    staged: &fs::File,
) -> Result<()> {
    let stat = rustix::fs::fstat(staged)?;
    let expected_identity = ConfigFileIdentity {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
    };
    ensure_config_binding_at(
        &transaction.vault,
        source_name,
        &expected_identity,
        "uncommitted managed config staging file",
    )?;
    sanitize_owned_unix_stage_for_cleanup(staged)?;
    ensure_config_binding_at(
        &transaction.vault,
        source_name,
        &expected_identity,
        "sanitized uncommitted managed config staging file",
    )?;
    rustix::fs::unlinkat(
        &transaction.vault,
        source_name,
        rustix::fs::AtFlags::empty(),
    )
    .with_context(|| {
        format!(
            "failed to remove exact owned stage {}",
            source_path.display()
        )
    })?;
    let vault_sync = sync_config_parent(&transaction.vault);
    let parent_sync = sync_config_parent(parent);
    vault_sync?;
    parent_sync
}

#[cfg(unix)]
fn cleanup_unjournaled_unix_stages(
    transaction: &ConfigTransactionAuthority,
    destination: &Path,
) -> Result<()> {
    transaction.revalidate()?;
    let file_name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("managed config destination name is not UTF-8")?;
    let prefix = format!(".{file_name}.kin-update-");
    let suffix = ".tmp";
    let mut entries = rustix::fs::Dir::read_from(&transaction.vault)
        .context("failed to enumerate managed config object vault")?;
    let mut removed = false;
    for entry in &mut entries {
        let entry = entry.context("failed to read managed config object vault entry")?;
        let bytes = entry.file_name().to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::str::from_utf8(bytes)
            .context("managed config object vault contains a non-UTF-8 entry")?;
        let Some(uuid) = name
            .strip_prefix(&prefix)
            .and_then(|name| name.strip_suffix(suffix))
        else {
            continue;
        };
        if uuid::Uuid::parse_str(uuid).is_err() {
            continue;
        }
        let fd = rustix::fs::openat(
            &transaction.vault,
            name,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .with_context(|| {
            format!(
                "failed to retain exact unjournaled managed config stage {}",
                transaction.vault_path.join(name).display()
            )
        })?;
        let staged = fs::File::from(fd);
        let stat = rustix::fs::fstat(&staged)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_nlink != 1
        {
            anyhow::bail!(
                "unjournaled managed config stage has unsafe authority and was retained: {}",
                transaction.vault_path.join(name).display()
            );
        }
        let identity = ConfigFileIdentity {
            device: stat.st_dev as u64,
            inode: stat.st_ino as u64,
        };
        ensure_config_binding_at(
            &transaction.vault,
            name,
            &identity,
            "unjournaled managed config staging file",
        )?;
        sanitize_owned_unix_stage_for_cleanup(&staged)?;
        ensure_config_binding_at(
            &transaction.vault,
            name,
            &identity,
            "sanitized unjournaled managed config staging file",
        )?;
        rustix::fs::unlinkat(&transaction.vault, name, rustix::fs::AtFlags::empty()).with_context(
            || {
                format!(
                    "failed to remove guarded unjournaled managed config stage {}",
                    transaction.vault_path.join(name).display()
                )
            },
        )?;
        eprintln!(
            "warning: removed guarded unjournaled managed config stage {} (device={} inode={})",
            transaction.vault_path.join(name).display(),
            stat.st_dev,
            stat.st_ino
        );
        removed = true;
    }
    if removed {
        sync_config_parent(&transaction.vault)?;
    }
    transaction.revalidate()
}

#[cfg(unix)]
fn restore_vault_config_at(
    transaction: &ConfigTransactionAuthority,
    parent: &fs::File,
    destination_name: &str,
    destination: &Path,
    retained_name: &str,
    private: bool,
) -> Result<bool> {
    let retained_path = transaction.vault_path.join(retained_name);
    let (_, observed) =
        open_observed_config_at(&transaction.vault, retained_name, &retained_path, private)?
            .with_context(|| {
                format!(
                    "vaulted managed config disappeared during restoration: {}",
                    retained_path.display()
                )
            })?;
    ensure_config_binding_at(
        &transaction.vault,
        retained_name,
        &observed.identity,
        "vaulted managed config",
    )?;
    match rustix::fs::renameat_with(
        &transaction.vault,
        retained_name,
        parent,
        destination_name,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => {
            sync_config_parent(&transaction.vault)?;
            sync_config_parent(parent)?;
            ensure_config_binding_at(
                parent,
                destination_name,
                &observed.identity,
                "restored managed config",
            )?;
            Ok(true)
        }
        Err(rustix::io::Errno::EXIST) => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to restore vaulted config to {}; retained as {}",
                destination.display(),
                retained_path.display()
            )
        }),
    }
}

#[cfg(unix)]
fn dispose_quarantined_config_at(
    parent: &fs::File,
    quarantine: &mut QuarantinedConfig,
    private: bool,
) -> Result<()> {
    let opened = rustix::fs::fstat(&quarantine.file)?;
    if opened.st_dev as u64 != quarantine.observed.identity.device
        || opened.st_ino as u64 != quarantine.observed.identity.inode
    {
        anyhow::bail!("quarantined managed config handle changed identity");
    }
    ensure_config_binding_at(
        parent,
        &quarantine.name,
        &quarantine.observed.identity,
        "quarantined managed config",
    )?;
    let quarantine_path = PathBuf::from(&quarantine.name);
    let reobserved = observe_open_config_file(&quarantine_path, &mut quarantine.file, private)?;
    if !observed_config_matches(Some(&reobserved), Some(&quarantine.observed)) {
        anyhow::bail!("quarantined managed config accrued concurrent edits; exact object retained");
    }
    rustix::fs::unlinkat(
        parent,
        quarantine.name.as_str(),
        rustix::fs::AtFlags::empty(),
    )
    .context("failed to unlink exact quarantined managed config")?;
    sync_config_parent(parent)
}

fn validate_config_transaction_record(
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<()> {
    if record.schema_version != CONFIG_TRANSACTION_SCHEMA_VERSION {
        anyhow::bail!(
            "unsupported managed config recovery schema {} (expected {})",
            record.schema_version,
            CONFIG_TRANSACTION_SCHEMA_VERSION
        );
    }
    if record.private != private {
        anyhow::bail!(
            "managed config recovery policy mismatch: record private={}, lock private={private}",
            record.private
        );
    }
    let current_destination_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("managed config recovery target name is not UTF-8")?;
    if current_destination_name.is_empty() || record.destination_name.is_empty() {
        anyhow::bail!("managed config recovery has an empty final-component authority");
    }
    let mut destination_components = Path::new(&record.destination_name).components();
    if !matches!(
        (destination_components.next(), destination_components.next()),
        (Some(std::path::Component::Normal(_)), None)
    ) {
        anyhow::bail!(
            "managed config recovery final-component authority is not one normal component"
        );
    }
    let destination_name = record.destination_name.as_str();
    for transaction_name in [
        record.staged_name.as_deref(),
        record.retained_name.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let retained_path = Path::new(transaction_name);
        if retained_path.components().count() != 1
            || !matches!(
                retained_path.components().next(),
                Some(std::path::Component::Normal(_))
            )
            || (!transaction_name.starts_with(&format!(".{destination_name}.kin-update-"))
                && !transaction_name.starts_with(&format!(".{destination_name}.kin-quarantine-")))
        {
            anyhow::bail!(
                "managed config recovery name is outside its target namespace: {transaction_name}"
            );
        }
    }
    match record.operation {
        ConfigTransactionOperation::Write if record.replacement.is_none() => {
            anyhow::bail!("managed config write recovery record has no replacement authority")
        }
        ConfigTransactionOperation::Remove
            if record.original.is_none() || record.replacement.is_some() =>
        {
            anyhow::bail!("managed config removal recovery record is inconsistent")
        }
        _ => {}
    }
    #[cfg(windows)]
    validate_windows_config_transaction_full_sacl_authority(record)?;
    Ok(())
}

#[cfg(windows)]
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(windows)]
fn require_windows_recorded_full_sacl<'a>(
    object: &'a RecordedConfigObject,
    label: &str,
) -> Result<&'a str> {
    let fingerprint = object
        .full_sacl
        .as_deref()
        .with_context(|| format!("schema-v6 Windows {label} lost full-SACL authority"))?;
    if !is_lowercase_sha256(fingerprint) {
        anyhow::bail!(
            "schema-v6 Windows {label} full-SACL authority is not a lowercase SHA-256 fingerprint"
        );
    }
    Ok(fingerprint)
}

#[cfg(windows)]
fn validate_windows_config_transaction_full_sacl_authority(
    record: &ConfigTransactionRecord,
) -> Result<()> {
    match record.operation {
        ConfigTransactionOperation::Write => {
            let replacement = record
                .replacement
                .as_ref()
                .context("schema-v6 Windows write lost replacement authority")?;
            if let Some(original) = record.original.as_ref() {
                require_windows_recorded_full_sacl(original, "write original")?;
                require_windows_recorded_full_sacl(replacement, "write replacement")?;
            } else if replacement.full_sacl.is_some() {
                anyhow::bail!(
                    "schema-v6 Windows create replacement must not claim inherited full-SACL authority"
                );
            }
        }
        ConfigTransactionOperation::Remove => {
            let original = record
                .original
                .as_ref()
                .context("schema-v6 Windows removal lost original authority")?;
            require_windows_recorded_full_sacl(original, "removal original")?;
        }
    }
    Ok(())
}

#[cfg(any(unix, windows))]
fn recorded_config_recovery_path(
    transaction: &ConfigTransactionAuthority,
    requested_path: &Path,
    record: &ConfigTransactionRecord,
) -> Result<PathBuf> {
    let parent = requested_path
        .parent()
        .context("managed config recovery target has no parent")?;
    let recorded_path = parent.join(&record.destination_name);
    let recorded_sidecar = shared_config_lock_path(&recorded_path)?;
    let file = open_config_sidecar_identity_shared(&recorded_sidecar)?;
    let metadata = validate_regular_config_file(&recorded_sidecar, &file, true)?;
    if metadata.len() != 0 {
        anyhow::bail!(
            "recorded managed config sidecar is not empty: {}",
            recorded_sidecar.display()
        );
    }
    #[cfg(unix)]
    let opened_identity = ConfigFileIdentity::from_metadata(&metadata);
    #[cfg(windows)]
    let opened_identity = {
        let _ = &metadata;
        ConfigFileIdentity::from_open_file(&file)?
    };
    let named = fs::symlink_metadata(&recorded_sidecar).with_context(|| {
        format!(
            "recorded managed config sidecar disappeared: {}",
            recorded_sidecar.display()
        )
    })?;
    #[cfg(unix)]
    let named_identity = ConfigFileIdentity::from_metadata(&named);
    #[cfg(windows)]
    let named_identity = visible_config_file_identity_nofollow(&recorded_sidecar)?;
    if named.file_type().is_symlink()
        || named_identity != opened_identity
        || opened_identity != record.sidecar
        || opened_identity != transaction.subject_identity
    {
        anyhow::bail!(
            "recorded managed config final component no longer owns its durable sidecar: {}",
            recorded_path.display()
        );
    }
    Ok(recorded_path)
}

#[cfg(unix)]
fn open_recovery_object_at(
    parent: &fs::File,
    name: &str,
    destination: &Path,
    private: bool,
) -> Result<Option<(fs::File, ObservedConfigFile)>> {
    open_observed_config_at(parent, name, &destination.with_file_name(name), private)
}

#[cfg(unix)]
fn recover_unix_terminal_config_transaction(
    transaction: &ConfigTransactionAuthority,
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<()> {
    let _ = path;
    let Some(retained_name) = record.retained_name.as_deref() else {
        return Ok(());
    };
    let Some((file, observed)) = open_observed_config_at(
        &transaction.vault,
        retained_name,
        &transaction.vault_path.join(retained_name),
        private,
    )?
    else {
        return Ok(());
    };
    let expected = match (record.phase, record.operation, record.original.as_ref()) {
        (
            ConfigTransactionPhase::CommitComplete,
            ConfigTransactionOperation::Write,
            Some(original),
        ) => original,
        (
            ConfigTransactionPhase::CommitComplete,
            ConfigTransactionOperation::Write,
            None,
        ) => record
            .replacement
            .as_ref()
            .context("completed create lost replacement authority")?,
        (
            ConfigTransactionPhase::CommitComplete,
            ConfigTransactionOperation::Remove,
            _,
        ) => record
            .original
            .as_ref()
            .context("completed removal lost original authority")?,
        (
            ConfigTransactionPhase::RollbackComplete,
            ConfigTransactionOperation::Write,
            _,
        ) => record
            .replacement
            .as_ref()
            .context("rolled-back write lost replacement authority")?,
        (
            ConfigTransactionPhase::RollbackComplete,
            ConfigTransactionOperation::Remove,
            _,
        ) => anyhow::bail!(
            "rolled-back managed config removal still has a quarantine object; preserved for manual reconciliation"
        ),
        _ => anyhow::bail!("managed config terminal recovery received a non-terminal phase"),
    };
    if !expected.matches(&observed) {
        anyhow::bail!(
            "completed managed config transaction has changed or unknown residue {retained_name}; preserved for manual reconciliation"
        );
    }
    let mut residue = QuarantinedConfig {
        name: retained_name.to_string(),
        file,
        observed,
    };
    dispose_quarantined_config_at(&transaction.vault, &mut residue, private)?;
    sync_config_parent(&transaction.vault)?;
    transaction.revalidate()
}

#[cfg(unix)]
fn terminalize_unix_durable_transition(
    transaction: &ConfigTransactionAuthority,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<Option<ConfigTransactionOutcome>> {
    let outcome = match record.phase {
        ConfigTransactionPhase::NamespaceCommitted => ConfigTransactionOutcome::Committed,
        ConfigTransactionPhase::RollbackApplied => ConfigTransactionOutcome::RolledBack,
        ConfigTransactionPhase::Prepared
        | ConfigTransactionPhase::CommitComplete
        | ConfigTransactionPhase::RollbackComplete => return Ok(None),
    };
    let retained = match record.retained_name.as_deref() {
        Some(name) => open_observed_config_at(
            &transaction.vault,
            name,
            &transaction.vault_path.join(name),
            private,
        )?,
        None => None,
    };
    if let Some((file, observed)) = retained {
        let expected = match (record.phase, record.operation) {
            (
                ConfigTransactionPhase::NamespaceCommitted,
                ConfigTransactionOperation::Write | ConfigTransactionOperation::Remove,
            ) => record.original.as_ref(),
            (ConfigTransactionPhase::RollbackApplied, ConfigTransactionOperation::Write) => {
                record.replacement.as_ref()
            }
            (ConfigTransactionPhase::RollbackApplied, ConfigTransactionOperation::Remove) => None,
            _ => unreachable!("non-durable phases returned above"),
        };
        let Some(expected) = expected else {
            anyhow::bail!(
                "durable managed config transaction has unexpected owned residue {}; preserved for manual reconciliation",
                record
                    .retained_name
                    .as_deref()
                    .unwrap_or("<missing retained name>")
            );
        };
        if !expected.matches(&observed) {
            anyhow::bail!(
                "durable managed config transaction has changed owned residue {}; preserved for manual reconciliation",
                record
                    .retained_name
                    .as_deref()
                    .unwrap_or("<missing retained name>")
            );
        }
        let mut residue = QuarantinedConfig {
            name: record
                .retained_name
                .clone()
                .context("durable managed config transaction lost retained name")?,
            file,
            observed,
        };
        dispose_quarantined_config_at(&transaction.vault, &mut residue, private)?;
        sync_config_parent(&transaction.vault)?;
        transaction.revalidate()?;
    }
    complete_recovered_config_transaction(&transaction.file, record, outcome)?;
    Ok(Some(outcome))
}

#[cfg(unix)]
fn resolve_unix_committed_transaction_after_error(
    transaction: &ConfigTransactionAuthority,
    path: &Path,
    private: bool,
    error: anyhow::Error,
) -> Result<()> {
    let resolution = (|| -> Result<()> {
        let durable = read_config_transaction(&transaction.file)?
            .context("committed managed config transaction lost durable WAL authority")?;
        match durable.phase {
            ConfigTransactionPhase::NamespaceCommitted => {
                match terminalize_unix_durable_transition(transaction, private, &durable)? {
                    Some(ConfigTransactionOutcome::Committed) => Ok(()),
                    _ => anyhow::bail!(
                        "committed managed config transaction resolved to a non-commit outcome"
                    ),
                }
            }
            ConfigTransactionPhase::CommitComplete => {
                recover_unix_terminal_config_transaction(transaction, path, private, &durable)
            }
            phase => anyhow::bail!(
                "committed managed config transaction regressed to unexpected durable phase {phase:?}"
            ),
        }
    })();
    match resolution {
        Ok(()) => Ok(()),
        Err(resolution) => Err(error.context(format!(
            "committed managed config operation could not finish exact owned-residue recovery: {resolution:#}"
        ))),
    }
}

#[cfg(unix)]
fn recover_unix_config_transaction(
    transaction: &ConfigTransactionAuthority,
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<()> {
    let lock_file = &transaction.file;
    validate_config_transaction_record(path, private, record)?;
    transaction.revalidate()?;
    if record.sidecar != transaction.subject_identity {
        anyhow::bail!(
            "managed config recovery sidecar authority does not match the journal recorded for this config"
        );
    }
    let recovery_path = recorded_config_recovery_path(transaction, path, record)?;
    let path = recovery_path.as_path();
    if record.vault != transaction.vault_identity {
        anyhow::bail!("managed config recovery vault authority does not match its durable record");
    }
    let parent_path = path.parent().context("managed config has no parent")?;
    let destination_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("managed config file name is not UTF-8")?;
    let parent = open_config_parent_nofollow(parent_path)?;
    ensure_config_parent_binding(parent_path, &parent, &record.parent)?;
    if matches!(
        record.phase,
        ConfigTransactionPhase::CommitComplete | ConfigTransactionPhase::RollbackComplete
    ) {
        return recover_unix_terminal_config_transaction(transaction, path, private, record);
    }
    if terminalize_unix_durable_transition(transaction, private, record)?.is_some() {
        return Ok(());
    }
    if record.operation == ConfigTransactionOperation::Write
        && record.phase == ConfigTransactionPhase::Prepared
    {
        let mut rollback = record.clone();
        return match rollback_failed_unix_write(transaction, &parent, path, private, &mut rollback)?
        {
            FailedWriteResolution::RolledBack => Ok(()),
            FailedWriteResolution::Committed => anyhow::bail!(
                "prepared managed config transaction was incorrectly classified committed"
            ),
        };
    }
    let canonical = open_recovery_object_at(&parent, destination_name, path, private)?;
    match record.operation {
        ConfigTransactionOperation::Write => {
            unreachable!("prepared writes are resolved before canonical removal recovery")
        }
        ConfigTransactionOperation::Remove => {
            let original = record
                .original
                .as_ref()
                .context("remove recovery lost original authority")?;
            let retained_name = record
                .retained_name
                .as_deref()
                .context("remove recovery lost quarantine name")?;
            let retained = open_observed_config_at(
                &transaction.vault,
                retained_name,
                &transaction.vault_path.join(retained_name),
                private,
            )?;
            debug_assert_eq!(record.phase, ConfigTransactionPhase::Prepared);
            match (canonical, retained) {
                    (None, Some((_, quarantined))) if original.same_identity(&quarantined) => {
                        ensure_config_parent_binding(parent_path, &parent, &record.parent)?;
                        rustix::fs::renameat_with(
                            &transaction.vault,
                            retained_name,
                            &parent,
                            destination_name,
                            rustix::fs::RenameFlags::NOREPLACE,
                        )?;
                        sync_config_parent(&parent)?;
                        sync_config_parent(&transaction.vault)?;
                        ensure_config_parent_binding(parent_path, &parent, &record.parent)?;
                        let mut rollback = record.clone();
                        rollback.phase = ConfigTransactionPhase::RollbackApplied;
                        write_config_transaction(lock_file, &rollback)?;
                        complete_config_transaction(
                            lock_file,
                            &mut rollback,
                            ConfigTransactionOutcome::RolledBack,
                        )
                    }
                    (Some((_, current)), None) if original.same_identity(&current) => {
                        ensure_config_parent_binding(parent_path, &parent, &record.parent)?;
                        let mut rollback = record.clone();
                        rollback.phase = ConfigTransactionPhase::RollbackApplied;
                        write_config_transaction(lock_file, &rollback)?;
                        complete_config_transaction(
                            lock_file,
                            &mut rollback,
                            ConfigTransactionOutcome::RolledBack,
                        )
                    }
                    _ => anyhow::bail!(
                        "prepared managed config removal has ambiguous recovery state; exact objects retained"
                    ),
            }
        }
    }
}

#[cfg(any(unix, windows))]
enum FailedWriteResolution {
    RolledBack,
    Committed,
}

#[cfg(unix)]
fn rollback_failed_unix_write(
    transaction: &ConfigTransactionAuthority,
    parent: &fs::File,
    path: &Path,
    private: bool,
    record: &mut ConfigTransactionRecord,
) -> Result<FailedWriteResolution> {
    let lock_file = &transaction.file;
    if let Some(outcome) = terminalize_unix_durable_transition(transaction, private, record)? {
        return Ok(match outcome {
            ConfigTransactionOutcome::Committed => FailedWriteResolution::Committed,
            ConfigTransactionOutcome::RolledBack => FailedWriteResolution::RolledBack,
        });
    }
    let parent_path = path
        .parent()
        .context("managed config rollback has no parent")?;
    ensure_config_parent_binding(parent_path, parent, &record.parent)?;
    let destination_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("managed config rollback target name is not UTF-8")?;
    let retained_name = record
        .retained_name
        .as_deref()
        .context("managed config rollback lost retained name")?
        .to_string();
    let replacement = record
        .replacement
        .as_ref()
        .context("managed config rollback lost replacement authority")?;
    let canonical = open_recovery_object_at(parent, destination_name, path, private)?;
    let retained = open_observed_config_at(
        &transaction.vault,
        &retained_name,
        &transaction.vault_path.join(&retained_name),
        private,
    )?;

    if record.phase == ConfigTransactionPhase::Prepared && retained.is_none() {
        let transition_never_started = match (record.original.as_ref(), canonical.as_ref()) {
            (Some(original), Some((_, current))) => original.same_identity(current),
            (None, None) => true,
            _ => false,
        };
        if transition_never_started {
            // The Prepared frame may have reached the file cache even when
            // its sync reported an error. The caller then disposes the stage
            // because durable ownership was not established. A later acquire
            // must recognize that exact pre-transition inventory as a safely
            // aborted write instead of wedging the config forever.
            record.phase = ConfigTransactionPhase::RollbackApplied;
            write_config_transaction(lock_file, record)?;
            ensure_config_parent_binding(parent_path, parent, &record.parent)?;
            complete_config_transaction(lock_file, record, ConfigTransactionOutcome::RolledBack)?;
            return Ok(FailedWriteResolution::RolledBack);
        }
    }

    let staged = match record.original.as_ref() {
        Some(original) => match (canonical, retained) {
            (Some((_, installed)), Some((_, old)))
                if replacement.matches(&installed) && original.same_identity(&old) =>
            {
                ensure_config_binding_at(
                    parent,
                    destination_name,
                    &installed.identity,
                    "failed-write replacement",
                )?;
                ensure_config_binding_at(
                    &transaction.vault,
                    retained_name.as_str(),
                    &old.identity,
                    "failed-write retained old config",
                )?;
                rustix::fs::renameat_with(
                    parent,
                    destination_name,
                    &transaction.vault,
                    retained_name.as_str(),
                    rustix::fs::RenameFlags::EXCHANGE,
                )?;
                sync_config_parent(parent)?;
                sync_config_parent(&transaction.vault)?;
                ensure_config_parent_binding(parent_path, parent, &record.parent)?;
                let restored = open_recovery_object_at(
                    parent,
                    destination_name,
                    path,
                    private,
                )?
                .context("old config disappeared during failed-write rollback")?;
                if !original.same_identity(&restored.1) {
                    anyhow::bail!(
                        "failed-write rollback did not restore the exact old config identity"
                    );
                }
                open_observed_config_at(
                    &transaction.vault,
                    &retained_name,
                    &transaction.vault_path.join(&retained_name),
                    private,
                )?
                    .context("replacement disappeared during failed-write rollback")?
            }
            (Some((_, current)), Some(staged))
                if original.same_identity(&current) && replacement.matches(&staged.1) =>
            {
                staged
            }
            (Some(_), Some(staged))
                if record.phase == ConfigTransactionPhase::Prepared
                    && replacement.matches(&staged.1) =>
            {
                // EXCHANGE/NOREPLACE never applied. Preserve the collider.
                staged
            }
            _ => anyhow::bail!(
                "failed managed config write has ambiguous rollback authority; WAL and objects retained"
            ),
        },
        None => match (canonical, retained) {
            (Some((_, installed)), None) if replacement.matches(&installed) => {
                rustix::fs::renameat_with(
                    parent,
                    destination_name,
                    &transaction.vault,
                    retained_name.as_str(),
                    rustix::fs::RenameFlags::NOREPLACE,
                )?;
                sync_config_parent(parent)?;
                sync_config_parent(&transaction.vault)?;
                ensure_config_parent_binding(parent_path, parent, &record.parent)?;
                open_observed_config_at(
                    &transaction.vault,
                    &retained_name,
                    &transaction.vault_path.join(&retained_name),
                    private,
                )?
                    .context("created replacement disappeared during failed-write rollback")?
            }
            (_, Some(staged)) if replacement.matches(&staged.1) => staged,
            _ => anyhow::bail!(
                "failed managed config create has ambiguous rollback authority; WAL and objects retained"
            ),
        },
    };

    if !replacement.matches(&staged.1) {
        anyhow::bail!("failed-write rollback staging authority changed; object retained");
    }
    record.phase = ConfigTransactionPhase::RollbackApplied;
    write_config_transaction(lock_file, record)?;
    ensure_config_parent_binding(parent_path, parent, &record.parent)?;
    let mut staged = QuarantinedConfig {
        name: retained_name,
        file: staged.0,
        observed: staged.1,
    };
    dispose_quarantined_config_at(&transaction.vault, &mut staged, private)?;
    sync_config_parent(&transaction.vault)?;
    ensure_config_parent_binding(parent_path, parent, &record.parent)?;
    complete_config_transaction(lock_file, record, ConfigTransactionOutcome::RolledBack)?;
    Ok(FailedWriteResolution::RolledBack)
}

#[cfg(unix)]
fn finish_unix_removal_rollback(
    transaction: &ConfigTransactionAuthority,
    parent_path: &Path,
    parent: &fs::File,
    record: &mut ConfigTransactionRecord,
) -> Result<()> {
    let lock_file = &transaction.file;
    ensure_config_parent_binding(parent_path, parent, &record.parent)?;
    record.phase = ConfigTransactionPhase::RollbackApplied;
    write_config_transaction(lock_file, record)?;
    ensure_config_parent_binding(parent_path, parent, &record.parent)?;
    complete_config_transaction(lock_file, record, ConfigTransactionOutcome::RolledBack)
}

#[cfg(unix)]
fn resolve_failed_unix_removal(
    transaction: &ConfigTransactionAuthority,
    parent_path: &Path,
    parent: &fs::File,
    path: &Path,
    private: bool,
    destination_name: &str,
    retained_name: &str,
    record: &mut ConfigTransactionRecord,
    disposition_may_have_applied: bool,
    error: anyhow::Error,
) -> Result<()> {
    let lock_file = &transaction.file;
    let original = record
        .original
        .as_ref()
        .context("failed removal recovery lost original authority")?;
    let canonical = open_recovery_object_at(parent, destination_name, path, private)?;
    let retained = open_observed_config_at(
        &transaction.vault,
        retained_name,
        &transaction.vault_path.join(retained_name),
        private,
    )?;
    match (canonical, retained) {
        (None, Some((_, quarantined))) if original.same_identity(&quarantined) => {
            match restore_vault_config_at(
                transaction,
                parent,
                destination_name,
                path,
                retained_name,
                private,
            ) {
                Ok(true) => {
                    finish_unix_removal_rollback(transaction, parent_path, parent, record)?;
                    Err(error.context("managed config removal failed and was rolled back exactly"))
                }
                Ok(false) => Err(error.context(format!(
                    "managed config removal failed; quarantine retained as {retained_name} because the destination is occupied"
                ))),
                Err(restore) => Err(error.context(format!(
                    "managed config removal failed; quarantine retained as {retained_name}: {restore:#}"
                ))),
            }
        }
        (Some((_, current)), None) if original.same_identity(&current) => {
            finish_unix_removal_rollback(transaction, parent_path, parent, record)?;
            Err(error.context("managed config removal failed after its exact rollback completed"))
        }
        (None, None) if disposition_may_have_applied => {
            // Unlink crossed the irreversible boundary. The prior durable
            // NamespaceCommitted frame remains sufficient recovery authority
            // even if appending its terminal tombstone reports a sync error.
            ensure_config_parent_binding(parent_path, parent, &record.parent)?;
            let _ = complete_config_transaction(
                lock_file,
                record,
                ConfigTransactionOutcome::Committed,
            );
            Ok(())
        }
        _ => Err(error.context(
            "managed config removal failed with ambiguous canonical/quarantine authority; WAL and objects retained",
        )),
    }
}

#[cfg(windows)]
fn open_windows_recovery_handle(path: &Path, strict_sacl: bool) -> Result<Option<fs::File>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    }
    let file =
        super::update::windows_update::open_managed_config_for_exact_inventory(path, strict_sacl)?;
    Ok(Some(file))
}

#[cfg(windows)]
fn open_windows_recovery_object(
    path: &Path,
    private: bool,
    strict_sacl: bool,
) -> Result<Option<(fs::File, ObservedConfigFile)>> {
    let Some(mut file) = open_windows_recovery_handle(path, strict_sacl)? else {
        return Ok(None);
    };
    let observed = observe_open_config_file_with_full_sacl(path, &mut file, private, strict_sacl)?;
    super::update::windows_update::revalidate_managed_file_path(path, &file, private, strict_sacl)?;
    Ok(Some((file, observed)))
}

#[cfg(windows)]
fn open_windows_terminal_observation_object(
    path: &Path,
    private: bool,
    strict_sacl: bool,
) -> Result<Option<(fs::File, ObservedConfigFile)>> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    }
    let mut file = super::update::windows_update::open_managed_config_for_terminal_observation(
        path,
        strict_sacl,
    )?;
    let observed = observe_open_config_file_with_full_sacl(path, &mut file, private, strict_sacl)?;
    super::update::windows_update::revalidate_managed_file_path(path, &file, private, strict_sacl)?;
    Ok(Some((file, observed)))
}

#[cfg(windows)]
fn strict_windows_full_sacl<'a>(
    expected: &'a RecordedConfigObject,
    label: &str,
) -> Result<&'a str> {
    expected
        .full_sacl
        .as_deref()
        .with_context(|| format!("{label} lacks persisted schema-v6 full-SACL authority"))
}

#[cfg(windows)]
fn rename_windows_config_exact(
    file: &fs::File,
    destination: &Path,
    private: bool,
    expected_full_sacl: Option<&str>,
) -> Result<()> {
    if let Some(expected_full_sacl) = expected_full_sacl {
        super::update::windows_update::require_managed_file_full_sacl_fingerprint(
            file,
            expected_full_sacl,
        )
        .context("managed config full SACL changed immediately before exact rename")?;
    }
    if private {
        super::update::windows_update::rename_private_file_handle_exact(file, destination, false)
    } else {
        super::update::windows_update::rename_managed_file_handle_exact(file, destination, false)
    }
}

#[cfg(windows)]
fn dispose_windows_config_exact(
    file: &fs::File,
    path: &Path,
    private: bool,
    label: &str,
) -> Result<()> {
    if private {
        super::update::windows_update::dispose_private_file_handle_exact(file, path, label)
    } else {
        super::update::windows_update::dispose_managed_file_handle_exact(file, label)
    }
}

#[cfg(windows)]
fn mark_windows_recorded_config_for_disposition(
    file: &fs::File,
    path: &Path,
    private: bool,
    label: &str,
    expected: &RecordedConfigObject,
    strict_sacl: bool,
) -> Result<()> {
    super::update::windows_update::revalidate_managed_file_path(path, &file, private, strict_sacl)?;
    let mut reader = file.try_clone()?;
    let observed =
        observe_open_config_file_with_full_sacl(path, &mut reader, private, strict_sacl)?;
    if !expected.matches(&observed) {
        anyhow::bail!("{label} changed immediately before disposition; exact object retained");
    }
    if strict_sacl {
        super::update::windows_update::require_managed_file_full_sacl_fingerprint(
            file,
            strict_windows_full_sacl(expected, label)?,
        )?;
    }
    dispose_windows_config_exact(file, path, private, label)
}

#[cfg(windows)]
fn finish_windows_disposition(file: fs::File, path: &Path, label: &str) -> Result<()> {
    // Exact rename/disposition handles are opened with WRITE_THROUGH. Flush
    // the delete-pending file object, close every owned handle, and prove the
    // transaction-owned pathname is absent before terminalizing the WAL.
    let sync = file
        .sync_all()
        .with_context(|| format!("failed to flush disposed exact {label}"));
    drop(file);
    sync?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!(
            "disposed exact {label} is still visible at {}; terminal WAL was not written",
            path.display()
        ),
        Err(error) => {
            Err(error).with_context(|| format!("failed to verify exact {label} disposition"))
        }
    }
}

#[cfg(windows)]
fn dispose_windows_recorded_config_owned(
    file: fs::File,
    path: &Path,
    private: bool,
    label: &str,
    expected: &RecordedConfigObject,
    strict_sacl: bool,
) -> Result<()> {
    mark_windows_recorded_config_for_disposition(
        &file,
        path,
        private,
        label,
        expected,
        strict_sacl,
    )?;
    finish_windows_disposition(file, path, label)
}

#[cfg(windows)]
fn dispose_windows_terminal_residue(
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    label: &str,
    expected: &RecordedConfigObject,
    strict_sacl: bool,
) -> Result<()> {
    let Some((file, observed)) = open_windows_recovery_object(path, private, strict_sacl)? else {
        return Ok(());
    };
    if !expected.matches(&observed) {
        anyhow::bail!(
            "completed managed config transaction has changed or unknown residue {}; preserved for manual reconciliation",
            path.display()
        );
    }
    dispose_windows_recorded_config_owned(file, path, private, label, expected, strict_sacl)?;
    parent.revalidate_visible()
}

#[cfg(windows)]
fn recover_windows_terminal_config_transaction(
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<()> {
    validate_config_transaction_record(path, private, record)?;
    let strict_sacl = record.original.is_some();
    let (namespace, file) = parent.identity();
    if record.parent.namespace != namespace || record.parent.file != file {
        anyhow::bail!(
            "completed Windows managed config transaction parent differs from durable namespace authority; journal and residue retained"
        );
    }
    parent.revalidate_visible()?;
    let staged_path = record
        .staged_name
        .as_deref()
        .map(|name| path.with_file_name(name));
    let retained_path = record
        .retained_name
        .as_deref()
        .map(|name| path.with_file_name(name));
    match (record.phase, record.operation) {
        (ConfigTransactionPhase::CommitComplete, ConfigTransactionOperation::Write) => {
            if let Some(staged_path) = staged_path.as_deref() {
                dispose_windows_terminal_residue(
                    parent,
                    staged_path,
                    private,
                    "completed managed config staging residue",
                    record
                        .replacement
                        .as_ref()
                        .context("completed Windows write lost replacement authority")?,
                    strict_sacl,
                )?;
            }
            if let (Some(retained_path), Some(original)) =
                (retained_path.as_deref(), record.original.as_ref())
            {
                dispose_windows_terminal_residue(
                    parent,
                    retained_path,
                    private,
                    "completed managed config quarantine residue",
                    original,
                    strict_sacl,
                )?;
            }
        }
        (ConfigTransactionPhase::RollbackComplete, ConfigTransactionOperation::Write) => {
            if let Some(staged_path) = staged_path.as_deref() {
                dispose_windows_terminal_residue(
                    &parent,
                    staged_path,
                    private,
                    "rolled-back managed config staging residue",
                    record
                        .replacement
                        .as_ref()
                        .context("rolled-back Windows write lost replacement authority")?,
                    strict_sacl,
                )?;
            }
            if let Some(retained_path) = retained_path.as_deref() {
                if open_windows_recovery_object(retained_path, private, strict_sacl)?.is_some() {
                    anyhow::bail!(
                        "rolled-back Windows managed config write still has quarantine residue {}; preserved for manual reconciliation",
                        retained_path.display()
                    );
                }
            }
        }
        (ConfigTransactionPhase::CommitComplete, ConfigTransactionOperation::Remove) => {
            if let Some(retained_path) = retained_path.as_deref() {
                dispose_windows_terminal_residue(
                    &parent,
                    retained_path,
                    private,
                    "completed managed config removal residue",
                    record
                        .original
                        .as_ref()
                        .context("completed Windows removal lost original authority")?,
                    strict_sacl,
                )?;
            }
        }
        (ConfigTransactionPhase::RollbackComplete, ConfigTransactionOperation::Remove) => {
            if let Some(retained_path) = retained_path.as_deref() {
                if open_windows_recovery_object(retained_path, private, strict_sacl)?.is_some() {
                    anyhow::bail!(
                        "rolled-back Windows managed config removal still has quarantine residue {}; preserved for manual reconciliation",
                        retained_path.display()
                    );
                }
            }
        }
        _ => anyhow::bail!("Windows terminal recovery received a non-terminal phase"),
    }
    parent.revalidate_visible()
}

#[cfg(windows)]
fn terminalize_windows_durable_transition(
    lock_file: &fs::File,
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<Option<ConfigTransactionOutcome>> {
    validate_config_transaction_record(path, private, record)?;
    let strict_sacl = record.original.is_some();
    let outcome = match record.phase {
        ConfigTransactionPhase::NamespaceCommitted => ConfigTransactionOutcome::Committed,
        ConfigTransactionPhase::RollbackApplied => ConfigTransactionOutcome::RolledBack,
        ConfigTransactionPhase::Prepared
        | ConfigTransactionPhase::CommitComplete
        | ConfigTransactionPhase::RollbackComplete => return Ok(None),
    };
    let (namespace, file) = parent.identity();
    if record.parent.namespace != namespace || record.parent.file != file {
        anyhow::bail!(
            "Windows managed config durable transition parent differs from recorded namespace authority"
        );
    }
    parent.revalidate_visible()?;
    let staged_path = record
        .staged_name
        .as_deref()
        .map(|name| path.with_file_name(name));
    let retained_path = record
        .retained_name
        .as_deref()
        .map(|name| path.with_file_name(name));
    let staged = match staged_path.as_deref() {
        Some(path) => open_windows_recovery_object(path, private, strict_sacl)?,
        None => None,
    };
    let retained = if retained_path == staged_path {
        None
    } else {
        match retained_path.as_deref() {
            Some(path) => open_windows_recovery_object(path, private, strict_sacl)?,
            None => None,
        }
    };
    let canonical = open_windows_terminal_observation_object(path, private, strict_sacl)?;

    match (record.phase, record.operation) {
        (ConfigTransactionPhase::NamespaceCommitted, ConfigTransactionOperation::Write) => {
            let replacement = record
                .replacement
                .as_ref()
                .context("committed Windows write lost replacement authority")?;
            if !matches!(
                canonical.as_ref(),
                Some((_, observed)) if replacement.matches(observed)
            ) {
                anyhow::bail!(
                    "committed Windows managed config replacement changed before terminal WAL"
                );
            }
            if staged.is_some() {
                anyhow::bail!(
                    "committed Windows managed config write has unexpected staging residue; preserved for manual reconciliation"
                );
            }
            match (record.original.as_ref(), retained) {
                (Some(expected), Some((file, observed))) if expected.matches(&observed) => {
                    dispose_windows_recorded_config_owned(
                        file,
                        retained_path
                            .as_deref()
                            .context("committed Windows write lost quarantine path")?,
                        private,
                        "committed Windows managed config quarantine",
                        expected,
                        strict_sacl,
                    )?;
                }
                (Some(_), Some(_)) | (None, Some(_)) => anyhow::bail!(
                    "committed Windows managed config write has changed or unknown owned residue; preserved for manual reconciliation"
                ),
                (_, None) => {}
            }
        }
        (ConfigTransactionPhase::NamespaceCommitted, ConfigTransactionOperation::Remove) => {
            if canonical.is_some() {
                anyhow::bail!(
                    "committed Windows managed config removal destination reappeared before terminal WAL"
                );
            }
            if staged.is_some() {
                anyhow::bail!(
                    "committed Windows managed config removal has unexpected staging residue; preserved for manual reconciliation"
                );
            }
            match retained {
                Some((file, observed)) => {
                    let expected = record
                        .original
                        .as_ref()
                        .context("committed Windows removal lost original authority")?;
                    if !expected.matches(&observed) {
                        anyhow::bail!(
                            "committed Windows managed config removal has changed owned residue; preserved for manual reconciliation"
                        );
                    }
                    dispose_windows_recorded_config_owned(
                        file,
                        retained_path
                            .as_deref()
                            .context("committed Windows removal lost quarantine path")?,
                        private,
                        "committed Windows managed config removal quarantine",
                        expected,
                        strict_sacl,
                    )?;
                }
                None => {}
            }
        }
        (ConfigTransactionPhase::RollbackApplied, ConfigTransactionOperation::Write) => {
            match (record.original.as_ref(), canonical.as_ref()) {
                (Some(original), Some((_, observed))) if original.matches(observed) => {}
                (None, None) => {}
                _ => anyhow::bail!(
                    "rolled-back Windows managed config canonical authority changed before terminal WAL"
                ),
            }
            if retained.is_some() {
                anyhow::bail!(
                    "rolled-back Windows managed config write has unexpected quarantine residue; preserved for manual reconciliation"
                );
            }
            if let Some((file, observed)) = staged {
                let expected = record
                    .replacement
                    .as_ref()
                    .context("rolled-back Windows write lost replacement authority")?;
                if !expected.matches(&observed) {
                    anyhow::bail!(
                        "rolled-back Windows managed config write has changed staging residue; preserved for manual reconciliation"
                    );
                }
                dispose_windows_recorded_config_owned(
                    file,
                    staged_path
                        .as_deref()
                        .context("rolled-back Windows write lost staging path")?,
                    private,
                    "rolled-back Windows managed config replacement",
                    expected,
                    strict_sacl,
                )?;
            }
        }
        (ConfigTransactionPhase::RollbackApplied, ConfigTransactionOperation::Remove) => {
            let original = record
                .original
                .as_ref()
                .context("rolled-back Windows removal lost original authority")?;
            if !matches!(
                canonical.as_ref(),
                Some((_, observed)) if original.matches(observed)
            ) {
                anyhow::bail!(
                    "rolled-back Windows managed config removal authority changed before terminal WAL"
                );
            }
            if staged.is_some() || retained.is_some() {
                anyhow::bail!(
                    "rolled-back Windows managed config removal still has owned residue; preserved for manual reconciliation"
                );
            }
        }
        _ => unreachable!("non-durable phases returned above"),
    }
    validate_windows_terminal_authority(parent, path, private, record)?;
    parent.revalidate_visible()?;
    complete_recovered_config_transaction(lock_file, record, outcome)?;
    Ok(Some(outcome))
}

#[cfg(windows)]
fn resolve_windows_committed_transaction_after_error(
    lock_file: &fs::File,
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    error: anyhow::Error,
) -> Result<()> {
    let resolution = (|| -> Result<()> {
        let durable = read_config_transaction(lock_file)?
            .context("committed Windows managed config transaction lost durable WAL authority")?;
        match durable.phase {
            ConfigTransactionPhase::NamespaceCommitted => {
                match terminalize_windows_durable_transition(
                    lock_file, parent, path, private, &durable,
                )? {
                    Some(ConfigTransactionOutcome::Committed) => Ok(()),
                    _ => anyhow::bail!(
                        "committed Windows managed config transaction resolved to a non-commit outcome"
                    ),
                }
            }
            ConfigTransactionPhase::CommitComplete => {
                recover_windows_terminal_config_transaction(parent, path, private, &durable)
            }
            phase => anyhow::bail!(
                "committed Windows managed config transaction regressed to unexpected durable phase {phase:?}"
            ),
        }
    })();
    match resolution {
        Ok(()) => Ok(()),
        Err(resolution) => Err(error.context(format!(
            "committed Windows managed config operation could not finish exact owned-residue recovery: {resolution:#}"
        ))),
    }
}

#[cfg(windows)]
fn recover_windows_config_transaction(
    transaction: &ConfigTransactionAuthority,
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<()> {
    let lock_file = &transaction.file;
    validate_config_transaction_record(path, private, record)?;
    transaction.revalidate()?;
    if record.sidecar != transaction.subject_identity {
        anyhow::bail!(
            "Windows managed config recovery sidecar authority does not match the journal recorded for this config"
        );
    }
    let recovery_path = recorded_config_recovery_path(transaction, path, record)?;
    let path = recovery_path.as_path();
    let parent_path = path.parent().context("managed config has no parent")?;
    let parent = super::update::windows_update::WindowsParentGuard::open(parent_path)?;
    let (namespace, file) = parent.identity();
    if record.parent.namespace != namespace || record.parent.file != file {
        anyhow::bail!(
            "visible managed config parent differs from durable transaction authority; journal retained"
        );
    }
    parent.revalidate_visible()?;
    if matches!(
        record.phase,
        ConfigTransactionPhase::CommitComplete | ConfigTransactionPhase::RollbackComplete
    ) {
        return recover_windows_terminal_config_transaction(&parent, path, private, record);
    }
    if terminalize_windows_durable_transition(lock_file, &parent, path, private, record)?.is_some()
    {
        return Ok(());
    }
    if record.operation == ConfigTransactionOperation::Write
        && record.phase == ConfigTransactionPhase::Prepared
    {
        let mut rollback = record.clone();
        return match rollback_failed_windows_write(
            lock_file,
            &parent,
            path,
            private,
            &mut rollback,
        )? {
            FailedWriteResolution::RolledBack => Ok(()),
            FailedWriteResolution::Committed => anyhow::bail!(
                "prepared Windows managed config transaction was incorrectly classified committed"
            ),
        };
    }
    let strict_sacl = record.original.is_some();
    let canonical = open_windows_recovery_object(path, private, strict_sacl)?;
    let retained_path = record
        .retained_name
        .as_deref()
        .map(|name| path.with_file_name(name));
    let retained = match retained_path.as_deref() {
        Some(path) => open_windows_recovery_object(path, private, strict_sacl)?,
        None => None,
    };

    match record.operation {
        ConfigTransactionOperation::Write => {
            unreachable!("prepared Windows writes are resolved before removal recovery")
        }
        ConfigTransactionOperation::Remove => {
            let original = record
                .original
                .as_ref()
                .context("Windows removal recovery lost original authority")?;
            debug_assert_eq!(record.phase, ConfigTransactionPhase::Prepared);
            match (canonical, retained) {
                (None, Some((old_file, old))) if original.matches(&old) => {
                    rename_windows_config_exact(
                        &old_file,
                        path,
                        private,
                        Some(strict_windows_full_sacl(original, "removal original")?),
                    )?;
                    super::update::windows_update::revalidate_managed_file_path(
                        path,
                        &old_file,
                        private,
                        strict_sacl,
                    )?;
                    parent.revalidate_visible()?;
                    let mut rollback = record.clone();
                    rollback.phase = ConfigTransactionPhase::RollbackApplied;
                    write_config_transaction(lock_file, &rollback)?;
                    complete_windows_config_transaction(
                        lock_file,
                        &parent,
                        path,
                        private,
                        &mut rollback,
                        ConfigTransactionOutcome::RolledBack,
                    )
                }
                (Some((_, current)), None) if original.matches(&current) => {
                    parent.revalidate_visible()?;
                    let mut rollback = record.clone();
                    rollback.phase = ConfigTransactionPhase::RollbackApplied;
                    write_config_transaction(lock_file, &rollback)?;
                    complete_windows_config_transaction(
                        lock_file,
                        &parent,
                        path,
                        private,
                        &mut rollback,
                        ConfigTransactionOutcome::RolledBack,
                    )
                }
                _ => anyhow::bail!(
                    "prepared Windows managed config removal has ambiguous object authority; journal retained"
                ),
            }
        }
    }
}

#[cfg(windows)]
fn require_windows_path_absent(path: &Path, label: &str) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("{label} remains visible at {}", path.display()),
        Err(error) => Err(error)
            .with_context(|| format!("failed to prove {label} absent at {}", path.display())),
    }
}

#[cfg(windows)]
fn validate_windows_terminal_authority(
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    record: &ConfigTransactionRecord,
) -> Result<()> {
    let strict_sacl = record.original.is_some();
    parent.revalidate_visible()?;
    let canonical = open_windows_terminal_observation_object(path, private, strict_sacl)?;
    match (record.phase, record.operation) {
        (ConfigTransactionPhase::NamespaceCommitted, ConfigTransactionOperation::Write) => {
            let replacement = record
                .replacement
                .as_ref()
                .context("committed Windows write lost replacement authority")?;
            if !matches!(
                canonical.as_ref(),
                Some((_, observed)) if replacement.matches(observed)
            ) {
                anyhow::bail!(
                    "committed Windows replacement changed immediately before terminal WAL"
                );
            }
        }
        (ConfigTransactionPhase::NamespaceCommitted, ConfigTransactionOperation::Remove) => {
            if canonical.is_some() {
                anyhow::bail!(
                    "removed Windows managed config reappeared immediately before terminal WAL"
                );
            }
        }
        (ConfigTransactionPhase::RollbackApplied, ConfigTransactionOperation::Write) => {
            match (record.original.as_ref(), canonical.as_ref()) {
                (Some(original), Some((_, observed))) if original.matches(observed) => {}
                (None, None) => {}
                _ => anyhow::bail!(
                    "rolled-back Windows write changed immediately before terminal WAL"
                ),
            }
        }
        (ConfigTransactionPhase::RollbackApplied, ConfigTransactionOperation::Remove) => {
            let original = record
                .original
                .as_ref()
                .context("rolled-back Windows removal lost original authority")?;
            if !matches!(
                canonical.as_ref(),
                Some((_, observed)) if original.matches(observed)
            ) {
                anyhow::bail!(
                    "rolled-back Windows removal changed immediately before terminal WAL"
                );
            }
        }
        _ => anyhow::bail!("Windows terminal authority check received a non-durable phase"),
    }
    let mut residue_paths = Vec::new();
    if let Some(name) = record.staged_name.as_deref() {
        residue_paths.push(path.with_file_name(name));
    }
    if let Some(name) = record.retained_name.as_deref() {
        let retained = path.with_file_name(name);
        if !residue_paths.contains(&retained) {
            residue_paths.push(retained);
        }
    }
    for residue in residue_paths {
        require_windows_path_absent(&residue, "owned Windows transaction residue")?;
    }
    parent.revalidate_visible()
}

#[cfg(windows)]
fn complete_windows_config_transaction(
    lock_file: &fs::File,
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    record: &mut ConfigTransactionRecord,
    outcome: ConfigTransactionOutcome,
) -> Result<()> {
    validate_config_transaction_record(path, private, record)?;
    validate_windows_terminal_authority(parent, path, private, record)?;
    complete_config_transaction(lock_file, record, outcome)
}

#[cfg(windows)]
fn resolve_failed_windows_write_with_retained_handles(
    lock_file: &fs::File,
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    staged_path: &Path,
    private: bool,
    record: &mut ConfigTransactionRecord,
    staged: &mut Option<fs::File>,
    staged_location: &mut WindowsStagedLocation,
    quarantine: &mut Option<QuarantinedConfig>,
) -> Result<FailedWriteResolution> {
    validate_config_transaction_record(path, private, record)?;
    let strict_sacl = record.original.is_some();
    let replacement = record
        .replacement
        .clone()
        .context("Windows exact-handle resolver lost replacement authority")?;
    let retained_path = record
        .retained_name
        .as_deref()
        .map(|name| path.with_file_name(name));

    match record.phase {
        ConfigTransactionPhase::Prepared => {
            if staged.is_none() {
                // A crash or failure during the durable handoff closes the
                // permanently armed file object and removes the stage. The
                // caller can still hold the exact original with delete sharing
                // denied, so reopening the canonical path is both unnecessary
                // and expected to fail. Prove rollback from the retained
                // handle plus WAL authority and terminalize it directly.
                require_windows_path_absent(
                    staged_path,
                    "prepared Windows handoff stage after armed-handle failure",
                )?;
                match record.original.as_ref() {
                    Some(original) => {
                        let old = quarantine.as_mut().context(
                            "prepared Windows handoff rollback lost retained original handle",
                        )?;
                        if old.name != record.destination_name {
                            anyhow::bail!(
                                "prepared Windows handoff original has unknown retained-handle location"
                            );
                        }
                        let observed = observe_open_config_file_with_full_sacl(
                            path,
                            &mut old.file,
                            private,
                            strict_sacl,
                        )?;
                        if !original.matches(&observed) {
                            anyhow::bail!(
                                "prepared Windows handoff original changed; retained exact handle and WAL"
                            );
                        }
                        super::update::windows_update::revalidate_managed_file_path(
                            path,
                            &old.file,
                            private,
                            strict_sacl,
                        )?;
                    }
                    None => {
                        if quarantine.is_some() {
                            anyhow::bail!(
                                "prepared Windows handoff create unexpectedly retained an original"
                            );
                        }
                        require_windows_path_absent(
                            path,
                            "prepared Windows handoff create canonical slot",
                        )?;
                    }
                }
                parent.revalidate_visible()?;
                record.phase = ConfigTransactionPhase::RollbackApplied;
                write_config_transaction(lock_file, record)?;
                complete_windows_config_transaction(
                    lock_file,
                    parent,
                    path,
                    private,
                    record,
                    ConfigTransactionOutcome::RolledBack,
                )?;
                return Ok(FailedWriteResolution::RolledBack);
            }
            // Inventory retained-handle locations before touching either
            // object. Stage policy is deliberately not consulted until the
            // exact original has been restored to (or absence proven at) the
            // canonical slot.
            let staged_file = staged
                .as_mut()
                .context("Windows exact-handle rollback lost staged replacement")?;
            if *staged_location == WindowsStagedLocation::DispositionApplied {
                anyhow::bail!("prepared Windows write already applied replacement disposition");
            }
            match (record.original.as_ref(), quarantine.as_ref()) {
                (Some(_), Some(old))
                    if old.name == record.destination_name
                        || record.retained_name.as_deref() == Some(old.name.as_str()) => {}
                (Some(_), Some(_)) => {
                    anyhow::bail!("prepared Windows original has unknown retained-handle location")
                }
                (Some(_), None) => {
                    anyhow::bail!("prepared Windows rollback lost retained original handle")
                }
                (None, Some(_)) => {
                    anyhow::bail!("prepared Windows create unexpectedly retained an old object")
                }
                (None, None) => {}
            }

            if *staged_location == WindowsStagedLocation::Canonical {
                // This is a product-owned CREATE_NEW handle. Move that exact
                // object out of canonical without reopening it and without a
                // DACL/SACL policy check that could strand the original behind
                // a drifted replacement.
                super::update::windows_update::rename_managed_file_handle_exact(
                    staged_file,
                    staged_path,
                    false,
                )?;
                *staged_location = WindowsStagedLocation::Staged;
            }

            match record.original.as_ref() {
                Some(original) => {
                    let old = quarantine
                        .as_mut()
                        .context("prepared Windows rollback lost retained original handle")?;
                    let old_path = path.with_file_name(&old.name);
                    let old_observed = observe_open_config_file_with_full_sacl(
                        &old_path,
                        &mut old.file,
                        private,
                        strict_sacl,
                    )?;
                    if !original.matches(&old_observed) {
                        anyhow::bail!(
                            "prepared Windows original changed; retained exact handles and WAL"
                        );
                    }
                    if old.name != record.destination_name {
                        rename_windows_config_exact(
                            &old.file,
                            path,
                            private,
                            Some(strict_windows_full_sacl(original, "replacement original")?),
                        )?;
                        old.name = record.destination_name.clone();
                    }
                    super::update::windows_update::revalidate_managed_file_path(
                        path,
                        &old.file,
                        private,
                        strict_sacl,
                    )?;
                    let restored = observe_open_config_file_with_full_sacl(
                        path,
                        &mut old.file,
                        private,
                        strict_sacl,
                    )?;
                    if !original.matches(&restored) {
                        anyhow::bail!(
                            "prepared Windows original changed after exact restoration; retained handles and WAL"
                        );
                    }
                }
                None => require_windows_path_absent(
                    path,
                    "prepared Windows create canonical slot after replacement relocation",
                )?,
            }
            parent.revalidate_visible()?;
            record.phase = ConfigTransactionPhase::RollbackApplied;
            write_config_transaction(lock_file, record)?;

            // RollbackApplied now protects the canonical original/absence.
            // Only after that durable boundary may a drifted replacement be
            // validated and, if still exact, disposed.
            let staged_file = staged
                .as_mut()
                .context("Windows rollback lost replacement before validation")?;
            let staged_observed = observe_open_config_file_with_full_sacl(
                staged_path,
                staged_file,
                private,
                strict_sacl,
            )?;
            if !replacement.matches(&staged_observed) {
                anyhow::bail!(
                    "rolled-back Windows replacement changed; original was restored and suspect residue plus WAL were retained"
                );
            }
            mark_windows_recorded_config_for_disposition(
                staged_file,
                staged_path,
                private,
                "rolled-back Windows managed config replacement",
                &replacement,
                strict_sacl,
            )?;
            *staged_location = WindowsStagedLocation::DispositionApplied;
            let staged_file = staged
                .take()
                .context("Windows rollback lost delete-pending replacement")?;
            finish_windows_disposition(
                staged_file,
                staged_path,
                "rolled-back Windows managed config replacement",
            )?;
            parent.revalidate_visible()?;
            complete_windows_config_transaction(
                lock_file,
                parent,
                path,
                private,
                record,
                ConfigTransactionOutcome::RolledBack,
            )?;
            Ok(FailedWriteResolution::RolledBack)
        }
        ConfigTransactionPhase::NamespaceCommitted => {
            if *staged_location != WindowsStagedLocation::Canonical {
                anyhow::bail!(
                    "committed Windows write lost its exact canonical replacement handle"
                );
            }
            let staged_file = staged
                .as_mut()
                .context("committed Windows write lost replacement handle")?;
            let installed =
                observe_open_config_file_with_full_sacl(path, staged_file, private, strict_sacl)?;
            if !replacement.matches(&installed) {
                anyhow::bail!(
                    "committed Windows replacement changed before terminalization; WAL retained"
                );
            }
            super::update::windows_update::revalidate_managed_file_path(
                path,
                staged_file,
                private,
                strict_sacl,
            )?;

            if let Some(original) = record.original.as_ref() {
                if let Some(old) = quarantine.as_mut() {
                    let retained_path = retained_path
                        .as_deref()
                        .context("committed Windows write lost quarantine path")?;
                    if old.name
                        != record
                            .retained_name
                            .as_deref()
                            .context("committed Windows write lost quarantine name")?
                    {
                        anyhow::bail!(
                            "committed Windows original has unknown retained-handle location"
                        );
                    }
                    mark_windows_recorded_config_for_disposition(
                        &old.file,
                        retained_path,
                        private,
                        "committed Windows managed config quarantine",
                        original,
                        strict_sacl,
                    )?;
                    let old = quarantine
                        .take()
                        .context("committed Windows write lost delete-pending original")?;
                    finish_windows_disposition(
                        old.file,
                        retained_path,
                        "committed Windows managed config quarantine",
                    )?;
                } else if let Some(retained_path) = retained_path.as_deref() {
                    require_windows_path_absent(
                        retained_path,
                        "committed Windows quarantine without its retained exact handle",
                    )?;
                }
            }
            parent.revalidate_visible()?;
            complete_windows_config_transaction(
                lock_file,
                parent,
                path,
                private,
                record,
                ConfigTransactionOutcome::Committed,
            )?;
            Ok(FailedWriteResolution::Committed)
        }
        ConfigTransactionPhase::RollbackApplied => {
            if let Some(old) = quarantine.as_ref() {
                if record.original.is_some() && old.name != record.destination_name {
                    anyhow::bail!("rolled-back Windows original is not held at the canonical slot");
                }
            }
            if let Some(staged_file) = staged.as_ref() {
                if *staged_location != WindowsStagedLocation::Staged {
                    anyhow::bail!(
                        "rolled-back Windows replacement has unknown retained-handle location"
                    );
                }
                mark_windows_recorded_config_for_disposition(
                    staged_file,
                    staged_path,
                    private,
                    "rolled-back Windows managed config replacement",
                    &replacement,
                    strict_sacl,
                )?;
                *staged_location = WindowsStagedLocation::DispositionApplied;
                let staged_file = staged
                    .take()
                    .context("rolled-back Windows write lost delete-pending replacement")?;
                finish_windows_disposition(
                    staged_file,
                    staged_path,
                    "rolled-back Windows managed config replacement",
                )?;
            } else {
                require_windows_path_absent(
                    staged_path,
                    "rolled-back Windows staging residue without its retained exact handle",
                )?;
            }
            parent.revalidate_visible()?;
            complete_windows_config_transaction(
                lock_file,
                parent,
                path,
                private,
                record,
                ConfigTransactionOutcome::RolledBack,
            )?;
            Ok(FailedWriteResolution::RolledBack)
        }
        ConfigTransactionPhase::CommitComplete => Ok(FailedWriteResolution::Committed),
        ConfigTransactionPhase::RollbackComplete => Ok(FailedWriteResolution::RolledBack),
    }
}

#[cfg(windows)]
fn rollback_failed_windows_write(
    lock_file: &fs::File,
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    private: bool,
    record: &mut ConfigTransactionRecord,
) -> Result<FailedWriteResolution> {
    let strict_sacl = record.original.is_some();
    if let Some(outcome) =
        terminalize_windows_durable_transition(lock_file, parent, path, private, record)?
    {
        return Ok(match outcome {
            ConfigTransactionOutcome::Committed => FailedWriteResolution::Committed,
            ConfigTransactionOutcome::RolledBack => FailedWriteResolution::RolledBack,
        });
    }
    let replacement = record
        .replacement
        .clone()
        .context("Windows rollback lost replacement authority")?;
    let staged_path = record
        .staged_name
        .as_deref()
        .map(|name| path.with_file_name(name))
        .context("Windows rollback lost staging path")?;
    let retained_path = record
        .retained_name
        .as_deref()
        .map(|name| path.with_file_name(name));
    // Inventory only exact-handle identities first. In particular, do not
    // validate replacement DACL/SACL policy before relocating a canonical
    // stage and restoring the original.
    let canonical = open_windows_recovery_handle(path, strict_sacl)?;
    let staged = open_windows_recovery_handle(&staged_path, strict_sacl)?;
    let retained = match retained_path.as_deref() {
        Some(path) => open_windows_recovery_handle(path, strict_sacl)?,
        None => None,
    };

    if record.phase == ConfigTransactionPhase::Prepared && staged.is_none() && retained.is_none() {
        let transition_never_started = match (record.original.as_ref(), canonical.as_ref()) {
            (Some(original), Some(current)) => {
                original.identity == ConfigFileIdentity::from_open_file(current)?
            }
            (None, None) => true,
            _ => false,
        };
        if transition_never_started {
            if let (Some(original), Some(mut current)) = (record.original.as_ref(), canonical) {
                let observed = observe_open_config_file_with_full_sacl(
                    path,
                    &mut current,
                    private,
                    strict_sacl,
                )?;
                if !original.matches(&observed) {
                    anyhow::bail!(
                        "pre-transition Windows original changed; WAL retained without a rollback claim"
                    );
                }
            }
            // A complete Prepared frame can remain readable after its sync
            // reports failure, or after an armed pre-Prepared stage closes.
            // Record the exact pre-transition inventory as rolled back so a
            // subsequent acquire is not permanently blocked by the journal.
            record.phase = ConfigTransactionPhase::RollbackApplied;
            write_config_transaction(lock_file, record)?;
            parent.revalidate_visible()?;
            complete_windows_config_transaction(
                lock_file,
                parent,
                path,
                private,
                record,
                ConfigTransactionOutcome::RolledBack,
            )?;
            return Ok(FailedWriteResolution::RolledBack);
        }
    }

    let canonical_is_replacement = canonical
        .as_ref()
        .map(|file| {
            Ok::<bool, anyhow::Error>(
                replacement.identity == ConfigFileIdentity::from_open_file(file)?,
            )
        })
        .transpose()?
        .unwrap_or(false);
    let staged_is_replacement = staged
        .as_ref()
        .map(|file| {
            Ok::<bool, anyhow::Error>(
                replacement.identity == ConfigFileIdentity::from_open_file(file)?,
            )
        })
        .transpose()?
        .unwrap_or(false);

    let mut staged_authority;
    let original = record.original.clone();
    if let Some(original) = original.as_ref() {
        let canonical_is_original = canonical
            .as_ref()
            .map(|file| {
                Ok::<bool, anyhow::Error>(
                    original.identity == ConfigFileIdentity::from_open_file(file)?,
                )
            })
            .transpose()?
            .unwrap_or(false);
        let retained_is_original = retained
            .as_ref()
            .map(|file| {
                Ok::<bool, anyhow::Error>(
                    original.identity == ConfigFileIdentity::from_open_file(file)?,
                )
            })
            .transpose()?
            .unwrap_or(false);

        let (mut old_file, old_path, old_needs_restore) =
            match (canonical, staged, retained) {
                (Some(new_file), None, Some(old_file))
                    if canonical_is_replacement && retained_is_original =>
                {
                    super::update::windows_update::rename_managed_file_handle_exact(
                        &new_file,
                        &staged_path,
                        false,
                    )?;
                    staged_authority = new_file;
                    (
                        old_file,
                        retained_path
                            .clone()
                            .context("Windows rollback lost retained original path")?,
                        true,
                    )
                }
                (None, Some(new_file), Some(old_file))
                    if staged_is_replacement && retained_is_original =>
                {
                    staged_authority = new_file;
                    (
                        old_file,
                        retained_path
                            .clone()
                            .context("Windows rollback lost retained original path")?,
                        true,
                    )
                }
                (Some(old_file), Some(new_file), None)
                    if canonical_is_original && staged_is_replacement =>
                {
                    staged_authority = new_file;
                    (old_file, path.to_path_buf(), false)
                }
                _ => anyhow::bail!(
                    "failed Windows managed config write has ambiguous rollback identities; WAL and objects retained"
                ),
            };

        let old_observed = observe_open_config_file_with_full_sacl(
            &old_path,
            &mut old_file,
            private,
            strict_sacl,
        )?;
        if !original.matches(&old_observed) {
            anyhow::bail!(
                "failed Windows managed config original changed before exact restoration; WAL and objects retained"
            );
        }
        if old_needs_restore {
            rename_windows_config_exact(
                &old_file,
                path,
                private,
                Some(strict_windows_full_sacl(original, "replacement original")?),
            )?;
        }
        super::update::windows_update::revalidate_managed_file_path(
            path,
            &old_file,
            private,
            strict_sacl,
        )?;
        let restored =
            observe_open_config_file_with_full_sacl(path, &mut old_file, private, strict_sacl)?;
        if !original.matches(&restored) {
            anyhow::bail!(
                "failed Windows managed config original changed after exact restoration; WAL and objects retained"
            );
        }
    } else {
        match (canonical, staged, retained) {
            (Some(new_file), None, None) if canonical_is_replacement => {
                super::update::windows_update::rename_managed_file_handle_exact(
                    &new_file,
                    &staged_path,
                    false,
                )?;
                staged_authority = new_file;
            }
            (None, Some(new_file), None) if staged_is_replacement => {
                staged_authority = new_file;
            }
            _ => anyhow::bail!(
                "failed Windows managed config create has ambiguous rollback identities; WAL and objects retained"
            ),
        }
        require_windows_path_absent(
            path,
            "failed Windows managed config create canonical slot after stage relocation",
        )?;
    }

    parent.revalidate_visible()?;
    record.phase = ConfigTransactionPhase::RollbackApplied;
    write_config_transaction(lock_file, record)?;
    let staged_observed = observe_open_config_file_with_full_sacl(
        &staged_path,
        &mut staged_authority,
        private,
        strict_sacl,
    )?;
    if !replacement.matches(&staged_observed) {
        anyhow::bail!(
            "rolled-back Windows replacement changed; original was restored and suspect residue plus WAL were retained"
        );
    }
    dispose_windows_recorded_config_owned(
        staged_authority,
        &staged_path,
        private,
        "rolled-back Windows managed config replacement",
        &replacement,
        strict_sacl,
    )?;
    parent.revalidate_visible()?;
    complete_windows_config_transaction(
        lock_file,
        parent,
        path,
        private,
        record,
        ConfigTransactionOutcome::RolledBack,
    )?;
    Ok(FailedWriteResolution::RolledBack)
}

#[cfg(windows)]
fn finish_windows_removal_rollback(
    lock_file: &fs::File,
    parent: &super::update::windows_update::WindowsParentGuard,
    path: &Path,
    quarantine_path: &Path,
    private: bool,
    quarantined: &mut QuarantinedConfig,
    record: &mut ConfigTransactionRecord,
    error: anyhow::Error,
) -> Result<()> {
    let original = record
        .original
        .as_ref()
        .context("Windows removal rollback lost original authority")?;
    let mut reader = quarantined.file.try_clone()?;
    let observed =
        observe_open_config_file_with_full_sacl(quarantine_path, &mut reader, private, true)?;
    if !original.matches(&observed) {
        anyhow::bail!(
            "Windows removal rollback quarantine changed; exact object and WAL retained: {error:#}"
        );
    }
    rename_windows_config_exact(
        &quarantined.file,
        path,
        private,
        Some(strict_windows_full_sacl(original, "removal original")?),
    )?;
    quarantined.name = record.destination_name.clone();
    super::update::windows_update::revalidate_managed_file_path(
        path,
        &quarantined.file,
        private,
        true,
    )?;
    quarantined.file.sync_all()?;
    parent.revalidate_visible()?;
    record.phase = ConfigTransactionPhase::RollbackApplied;
    write_config_transaction(lock_file, record)?;
    parent.revalidate_visible()?;
    complete_windows_config_transaction(
        lock_file,
        parent,
        path,
        private,
        record,
        ConfigTransactionOutcome::RolledBack,
    )?;
    Err(error.context("Windows managed config removal failed and was rolled back exactly"))
}

pub(crate) fn read_private_file_nofollow(path: &Path) -> Result<Option<Vec<u8>>> {
    read_config_file_nofollow(path, true).map(|observed| observed.map(|observed| observed.bytes))
}

fn lock_file_exclusive_bounded(file: &fs::File, label: &str) -> Result<()> {
    const ATTEMPTS: usize = 200;
    for attempt in 0..ATTEMPTS {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock && attempt + 1 < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                anyhow::bail!("timed out waiting for {label} after 5 seconds")
            }
            Err(error) => return Err(error).with_context(|| format!("failed to lock {label}")),
        }
    }
    unreachable!("bounded config-lock retry loop always returns")
}

#[cfg(not(windows))]
fn open_config_sidecar(path: &Path, create: bool) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options
        .open(path)
        .with_context(|| format!("failed to open managed config lock {}", path.display()))
}

#[cfg(windows)]
fn open_config_sidecar(path: &Path, create: bool) -> Result<fs::File> {
    if create {
        super::update::windows_update::open_or_create_current_user_private_file(path)
    } else {
        super::update::windows_update::open_current_user_private_file_existing(path)
    }
    .with_context(|| format!("failed to open managed config lock {}", path.display()))
}

#[cfg(not(windows))]
fn open_or_create_config_sidecar(path: &Path) -> Result<(fs::File, bool)> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    match options.open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            open_config_sidecar(path, false).map(|file| (file, false))
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to create managed config lock {}", path.display())),
    }
}

#[cfg(windows)]
fn open_or_create_config_sidecar(path: &Path) -> Result<(fs::File, bool)> {
    super::update::windows_update::open_or_create_current_user_private_file_with_status(path)
        .with_context(|| format!("failed to open managed config lock {}", path.display()))
}

fn open_config_sidecar_identity_shared(path: &Path) -> Result<fs::File> {
    #[cfg(windows)]
    {
        return super::update::windows_update::open_current_user_private_file_existing_shared(path)
            .with_context(|| {
                format!(
                    "failed to open recorded managed config sidecar {}",
                    path.display()
                )
            });
    }
    #[cfg(not(windows))]
    {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        options.open(path).with_context(|| {
            format!(
                "failed to open recorded managed config sidecar {}",
                path.display()
            )
        })
    }
}

struct ConfigLockPlan {
    path: PathBuf,
    lock_path: PathBuf,
    lock_identity: ConfigFileIdentity,
    private: bool,
    #[cfg(unix)]
    parent: DurableConfigDirectory,
}

#[cfg(unix)]
impl ConfigLockPlan {
    fn revalidate_parent(&self) -> Result<()> {
        if config_parent_identity(&self.parent.file)? != self.parent.identity {
            anyhow::bail!("retained managed config parent handle changed identity");
        }
        let visible = open_config_parent_nofollow(&self.parent.path)?;
        if config_parent_identity(&visible)? != self.parent.identity {
            anyhow::bail!(
                "managed config parent binding changed: {}",
                self.parent.path.display()
            );
        }
        Ok(())
    }
}

fn observed_config_matches(
    left: Option<&ObservedConfigFile>,
    right: Option<&ObservedConfigFile>,
) -> bool {
    observed_config_matches_inner(left, right, false)
}

#[cfg(windows)]
fn observed_config_matches_pre_strict_baseline(
    left: Option<&ObservedConfigFile>,
    right: Option<&ObservedConfigFile>,
) -> bool {
    observed_config_matches_inner(left, right, true)
}

fn observed_config_matches_inner(
    left: Option<&ObservedConfigFile>,
    right: Option<&ObservedConfigFile>,
    ignore_windows_full_sacl: bool,
) -> bool {
    #[cfg(not(windows))]
    let _ = ignore_windows_full_sacl;
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.identity == right.identity && left.bytes == right.bytes && {
                #[cfg(unix)]
                {
                    left.mode == right.mode
                        && left.uid == right.uid
                        && left.gid == right.gid
                        && left.metadata == right.metadata
                }
                #[cfg(windows)]
                {
                    left.security == right.security
                        && (ignore_windows_full_sacl || left.full_sacl == right.full_sacl)
                }
                #[cfg(all(not(unix), not(windows)))]
                {
                    true
                }
            }
        }
        _ => false,
    }
}

/// Persistent sidecar authority shared by setup, doctor repair, updater repair,
/// and the setup ledger. The sidecar is deliberately retained: deleting a lock
/// file would let a later writer lock a different inode while an earlier writer
/// still holds the old one.
pub(crate) struct ConfigLock {
    transaction: ConfigTransactionAuthority,
    file: fs::File,
    path: PathBuf,
    lock_path: PathBuf,
    original: Option<ObservedConfigFile>,
    private: bool,
    lock_identity: ConfigFileIdentity,
    #[cfg(unix)]
    parent: fs::File,
    #[cfg(unix)]
    parent_path: PathBuf,
    #[cfg(unix)]
    parent_identity: ConfigParentIdentity,
}

impl ConfigLock {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        Self::acquire_with_policy(path, false)
    }

    pub(crate) fn acquire_nofollow(path: &Path) -> Result<Self> {
        Self::acquire_with_policy(path, true)
    }

    pub(crate) fn acquire_many(paths: &[PathBuf]) -> Result<Vec<Self>> {
        let plans = paths
            .iter()
            .map(|path| Self::plan_with_policy(path, false))
            .collect::<Result<Vec<_>>>()?;
        let requested = plans
            .iter()
            .map(|plan| plan.path.clone())
            .collect::<Vec<_>>();
        let acquired = Self::acquire_plans(plans)?;
        let mut by_path = acquired
            .into_iter()
            .map(|lock| (lock.path.clone(), lock))
            .collect::<std::collections::BTreeMap<_, _>>();
        requested
            .into_iter()
            .map(|path| {
                by_path.remove(&path).with_context(|| {
                    format!(
                        "identity-ordered config acquisition lost requested target {}",
                        path.display()
                    )
                })
            })
            .collect()
    }

    /// Preflight a mixed set of public/private managed paths through their
    /// durable sidecars and reject identity aliases before any WAL guard is
    /// acquired. Callers that must preserve a higher-level lock hierarchy use
    /// this before acquiring the individual authorities.
    pub(crate) fn preflight_distinct(paths: &[(PathBuf, bool)]) -> Result<()> {
        let mut plans = paths
            .iter()
            .map(|(path, private)| Self::plan_with_policy(path, *private))
            .collect::<Result<Vec<_>>>()?;
        Self::sort_and_reject_duplicate_plans(&mut plans)
    }

    /// Resolve a managed config to the exact path spelling used by its shared
    /// sidecar lock. Multi-target writers sort these paths before locking so
    /// every setup/updater/uninstall flow has one global lock order.
    pub(crate) fn normalized_path(path: &Path) -> Result<PathBuf> {
        #[cfg(unix)]
        {
            return Self::normalized_path_with_parent_authority(path)
                .map(|(normalized, _)| normalized);
        }
        #[cfg(not(unix))]
        {
            let parent = path.parent().context("managed config path has no parent")?;
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
            Self::normalized_path_with_existing_parent(path)
        }
    }

    #[cfg(unix)]
    fn normalized_path_with_parent_authority(
        path: &Path,
    ) -> Result<(PathBuf, DurableConfigDirectory)> {
        let parent = path.parent().context("managed config path has no parent")?;
        let authority = create_config_directory_all_durable(parent, false)
            .with_context(|| format!("failed to create {}", parent.display()))?;
        let file_name = path
            .file_name()
            .context("managed config path has no file name")?;
        let candidate = authority.path.join(file_name);
        let normalized = Self::normalized_path_with_existing_parent(&candidate)?;
        let normalized_parent = normalized
            .parent()
            .context("normalized managed config path has no parent")?;
        if normalized_parent != authority.path {
            anyhow::bail!("managed config normalization escaped its retained parent authority");
        }
        let visible = open_config_parent_nofollow(&authority.path)?;
        if config_parent_identity(&visible)? != authority.identity
            || config_parent_identity(&authority.file)? != authority.identity
        {
            anyhow::bail!(
                "managed config parent changed during durable normalization: {}",
                authority.path.display()
            );
        }
        Ok((normalized, authority))
    }

    pub(crate) fn normalized_path_with_existing_parent(path: &Path) -> Result<PathBuf> {
        let parent = path.parent().context("managed config path has no parent")?;
        let parent = parent.canonicalize().with_context(|| {
            format!(
                "failed to canonicalize managed config parent {}",
                parent.display()
            )
        })?;
        let file_name = path
            .file_name()
            .context("managed config path has no file name")?;
        let candidate = parent.join(file_name);
        #[cfg(windows)]
        if let Some(stored_name) =
            super::update::windows_update::managed_file_stored_final_component(&candidate)?
        {
            let requested = file_name.to_string_lossy();
            let stored = stored_name.to_string_lossy();
            if requested != stored && !requested.eq_ignore_ascii_case(&stored) {
                anyhow::bail!(
                    "managed config target {} uses an alternate short/alias final component; retry with the durable long spelling {} so restart recovery cannot lose its sidecar authority",
                    candidate.display(),
                    stored
                );
            }
            return Ok(parent.join(stored_name));
        }
        Ok(candidate)
    }

    fn acquire_with_policy(path: &Path, private: bool) -> Result<Self> {
        let plan = Self::plan_with_policy(path, private)?;
        Self::acquire_plans(vec![plan])?
            .pop()
            .context("single managed config lock plan produced no lock")
    }

    fn plan_with_policy(path: &Path, private: bool) -> Result<ConfigLockPlan> {
        crate::commands::managed_config_scope::guard_managed_path(path);
        #[cfg(unix)]
        let (path, parent) = Self::normalized_path_with_parent_authority(path)?;
        #[cfg(not(unix))]
        let path = Self::normalized_path(path)?;
        let lock_path = shared_config_lock_path(&path)?;
        if fs::symlink_metadata(&lock_path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            anyhow::bail!("managed config lock is a symlink: {}", lock_path.display());
        }
        let (file, sidecar_created) = open_or_create_config_sidecar(&lock_path)?;
        // The reserved sidecar is authority, not caller data. Validate the
        // exact no-follow handle and its visible binding before changing its
        // permissions or syncing it. In particular, never chmod a same-user
        // hard-linked victim that was moved onto the sidecar name.
        let initial_metadata = validate_regular_config_file(&lock_path, &file, false)?;
        if initial_metadata.len() != 0 {
            anyhow::bail!(
                "managed config sidecar is not empty: {}",
                lock_path.display()
            );
        }
        #[cfg(unix)]
        let initial_identity = ConfigFileIdentity::from_metadata(&initial_metadata);
        #[cfg(windows)]
        let initial_identity = {
            let _ = &initial_metadata;
            ConfigFileIdentity::from_open_file(&file)?
        };
        let initial_named = fs::symlink_metadata(&lock_path).with_context(|| {
            format!(
                "managed config sidecar disappeared during prevalidation: {}",
                lock_path.display()
            )
        })?;
        #[cfg(unix)]
        let initial_named_identity = ConfigFileIdentity::from_metadata(&initial_named);
        #[cfg(windows)]
        let initial_named_identity = visible_config_file_identity_nofollow(&lock_path)?;
        if initial_named.file_type().is_symlink() || initial_named_identity != initial_identity {
            anyhow::bail!(
                "managed config sidecar changed during prevalidation: {}",
                lock_path.display()
            );
        }
        #[cfg(unix)]
        validate_private_unix_file(&lock_path, &file, sidecar_created)?;
        #[cfg(windows)]
        let _ = sidecar_created;
        file.sync_all()
            .context("failed to sync durable managed config sidecar")?;
        #[cfg(unix)]
        {
            let sidecar_parent = lock_path
                .parent()
                .context("managed config sidecar has no parent")?;
            let parent = open_config_parent_nofollow(sidecar_parent)?;
            sync_config_parent(&parent)?;
        }
        #[cfg(windows)]
        {
            let sidecar_parent = lock_path
                .parent()
                .context("Windows managed config sidecar has no parent")?;
            let parent = super::update::windows_update::WindowsParentGuard::open(sidecar_parent)?;
            parent.revalidate_visible()?;
        }
        #[cfg(unix)]
        let metadata = validate_private_unix_file(&lock_path, &file, false)?;
        #[cfg(not(unix))]
        let metadata = validate_regular_config_file(&lock_path, &file, true)?;
        #[cfg(unix)]
        let lock_identity = ConfigFileIdentity::from_metadata(&metadata);
        #[cfg(windows)]
        let lock_identity = {
            let _ = &metadata;
            ConfigFileIdentity::from_open_file(&file)?
        };
        if lock_identity != initial_identity {
            anyhow::bail!(
                "managed config sidecar identity changed while making it durable: {}",
                lock_path.display()
            );
        }
        let durable_named = fs::symlink_metadata(&lock_path).with_context(|| {
            format!(
                "managed config sidecar disappeared while making it durable: {}",
                lock_path.display()
            )
        })?;
        #[cfg(unix)]
        let durable_named_identity = ConfigFileIdentity::from_metadata(&durable_named);
        #[cfg(windows)]
        let durable_named_identity = visible_config_file_identity_nofollow(&lock_path)?;
        if durable_named.file_type().is_symlink() || durable_named_identity != lock_identity {
            anyhow::bail!(
                "managed config sidecar changed while making it durable: {}",
                lock_path.display()
            );
        }
        drop(file);
        let reopened = open_config_sidecar(&lock_path, false)?;
        #[cfg(unix)]
        let reopened_metadata = validate_private_unix_file(&lock_path, &reopened, false)?;
        #[cfg(not(unix))]
        let reopened_metadata = validate_regular_config_file(&lock_path, &reopened, true)?;
        #[cfg(unix)]
        let reopened_identity = ConfigFileIdentity::from_metadata(&reopened_metadata);
        #[cfg(windows)]
        let reopened_identity = {
            let _ = &reopened_metadata;
            ConfigFileIdentity::from_open_file(&reopened)?
        };
        if reopened_identity != lock_identity {
            anyhow::bail!(
                "managed config sidecar changed after durable creation: {}",
                lock_path.display()
            );
        }
        Ok(ConfigLockPlan {
            path,
            lock_path,
            lock_identity,
            private,
            #[cfg(unix)]
            parent,
        })
    }

    fn sort_and_reject_duplicate_plans(plans: &mut [ConfigLockPlan]) -> Result<()> {
        plans.sort_by(|left, right| left.lock_identity.cmp(&right.lock_identity));
        if let Some(duplicate) = plans
            .windows(2)
            .find(|pair| pair[0].lock_identity == pair[1].lock_identity)
        {
            anyhow::bail!(
                "managed config targets {} and {} resolve to the same sidecar object; alias ambiguity refused before locking",
                duplicate[0].path.display(),
                duplicate[1].path.display()
            );
        }
        Ok(())
    }

    fn acquire_plans(mut plans: Vec<ConfigLockPlan>) -> Result<Vec<Self>> {
        Self::sort_and_reject_duplicate_plans(&mut plans)?;

        // Acquire every subject-keyed WAL guard first in one deterministic
        // order. Only after all guards are held do we reacquire and lock the
        // adjacent sidecars in the same order.
        let mut guarded = Vec::with_capacity(plans.len());
        for plan in plans {
            #[cfg(unix)]
            plan.revalidate_parent()?;
            let transaction =
                ConfigTransactionAuthority::acquire(&plan.lock_identity, &plan.lock_path)?;
            #[cfg(unix)]
            plan.revalidate_parent()?;
            guarded.push((plan, transaction));
        }

        let mut locks = Vec::with_capacity(guarded.len());
        for (plan, transaction) in guarded {
            #[cfg(unix)]
            plan.revalidate_parent()?;
            let file = open_config_sidecar(&plan.lock_path, false)?;
            #[cfg(unix)]
            let metadata = validate_private_unix_file(&plan.lock_path, &file, false)?;
            #[cfg(not(unix))]
            let metadata = validate_regular_config_file(&plan.lock_path, &file, true)?;
            #[cfg(unix)]
            let opened_identity = ConfigFileIdentity::from_metadata(&metadata);
            #[cfg(windows)]
            let opened_identity = {
                let _ = &metadata;
                ConfigFileIdentity::from_open_file(&file)?
            };
            if opened_identity != plan.lock_identity {
                anyhow::bail!(
                    "managed config sidecar identity changed before lock acquisition: {}",
                    plan.lock_path.display()
                );
            }
            #[cfg(unix)]
            plan.revalidate_parent()?;
            lock_file_exclusive_bounded(
                &file,
                &format!("managed config sidecar {}", plan.lock_path.display()),
            )?;
            let named = fs::symlink_metadata(&plan.lock_path).with_context(|| {
                format!(
                    "managed config lock disappeared: {}",
                    plan.lock_path.display()
                )
            })?;
            #[cfg(unix)]
            let named_identity = ConfigFileIdentity::from_metadata(&named);
            #[cfg(windows)]
            let named_identity = visible_config_file_identity_nofollow(&plan.lock_path)?;
            if named.file_type().is_symlink()
                || named_identity != plan.lock_identity
                || transaction.subject_identity != plan.lock_identity
            {
                anyhow::bail!(
                    "managed config lock changed while Kin waited: {}",
                    plan.lock_path.display()
                );
            }
            if let Some(record) = read_config_transaction(&transaction.file)? {
                #[cfg(unix)]
                recover_unix_config_transaction(&transaction, &plan.path, plan.private, &record)
                    .with_context(|| {
                        format!(
                            "failed to recover interrupted managed config transaction for {}",
                            plan.path.display()
                        )
                    })?;
                #[cfg(windows)]
                recover_windows_config_transaction(&transaction, &plan.path, plan.private, &record)
                    .with_context(|| {
                        format!(
                            "failed to recover interrupted managed config transaction for {}",
                            plan.path.display()
                        )
                    })?;
                #[cfg(all(not(unix), not(windows)))]
                anyhow::bail!(
                    "managed config recovery transaction requires an unsupported platform: {}",
                    plan.path.display()
                );
                // Recovery has resolved the interrupted transaction to a
                // terminal outcome and has finished reading its record, so the
                // transaction is complete: retire the journal instead of
                // leaving a resolved record for the next acquisition to reread.
                #[cfg(any(unix, windows))]
                retire_resolved_config_transaction_wal(&transaction.file).with_context(|| {
                    format!(
                        "failed to retire recovered managed config transaction for {}",
                        plan.path.display()
                    )
                })?;
            }
            #[cfg(unix)]
            cleanup_unjournaled_unix_stages(&transaction, &plan.path)?;
            let original = read_config_file_nofollow(&plan.path, plan.private)?;
            locks.push(Self {
                transaction,
                file,
                path: plan.path,
                lock_path: plan.lock_path,
                original,
                private: plan.private,
                lock_identity: plan.lock_identity,
                #[cfg(unix)]
                parent_identity: plan.parent.identity,
                #[cfg(unix)]
                parent_path: plan.parent.path,
                #[cfg(unix)]
                parent: plan.parent.file,
            });
        }
        Ok(locks)
    }

    fn revalidate_lock(&self) -> Result<()> {
        self.transaction.revalidate()?;
        #[cfg(unix)]
        {
            if config_parent_identity(&self.parent)? != self.parent_identity {
                anyhow::bail!("retained managed config parent handle changed identity");
            }
            let visible_parent = open_config_parent_nofollow(&self.parent_path)?;
            if config_parent_identity(&visible_parent)? != self.parent_identity {
                anyhow::bail!(
                    "managed config parent binding changed: {}",
                    self.parent_path.display()
                );
            }
        }
        #[cfg(unix)]
        let metadata = validate_private_unix_file(&self.lock_path, &self.file, false)?;
        #[cfg(windows)]
        super::update::windows_update::validate_current_user_private_file(&self.file)?;
        let named = fs::symlink_metadata(&self.lock_path)?;
        #[cfg(unix)]
        let opened_identity = ConfigFileIdentity::from_metadata(&metadata);
        #[cfg(windows)]
        let opened_identity = ConfigFileIdentity::from_open_file(&self.file)?;
        #[cfg(unix)]
        let named_identity = ConfigFileIdentity::from_metadata(&named);
        #[cfg(windows)]
        let named_identity = visible_config_file_identity_nofollow(&self.lock_path)?;
        if named.file_type().is_symlink()
            || opened_identity != self.lock_identity
            || named_identity != self.lock_identity
        {
            anyhow::bail!(
                "managed config lock authority changed: {}",
                self.lock_path.display()
            );
        }
        Ok(())
    }

    /// Return whether `path` resolves to the same persistent sidecar object as
    /// this held lock. This is identity-based so bind-mounted parents and
    /// case/long-name aliases cannot bypass reserved-authority checks.
    pub(crate) fn protects_alias(&self, path: &Path) -> Result<bool> {
        self.revalidate_lock()?;
        let candidate = Self::normalized_path_with_existing_parent(path)?;
        let candidate_sidecar = shared_config_lock_path(&candidate)?;
        if candidate_sidecar == self.lock_path {
            return Ok(true);
        }
        match fs::symlink_metadata(&candidate_sidecar) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect candidate managed config sidecar {}",
                        candidate_sidecar.display()
                    )
                })
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "candidate managed config sidecar is a symlink: {}",
                    candidate_sidecar.display()
                )
            }
            Ok(_) => {}
        }
        let candidate_file = open_config_sidecar_identity_shared(&candidate_sidecar)?;
        #[cfg(unix)]
        let metadata = validate_private_unix_file(&candidate_sidecar, &candidate_file, false)?;
        #[cfg(not(unix))]
        let metadata = validate_regular_config_file(&candidate_sidecar, &candidate_file, true)?;
        if metadata.len() != 0 {
            anyhow::bail!(
                "candidate managed config sidecar is not empty: {}",
                candidate_sidecar.display()
            );
        }
        #[cfg(unix)]
        let candidate_identity = ConfigFileIdentity::from_metadata(&metadata);
        #[cfg(windows)]
        let candidate_identity = {
            let _ = &metadata;
            ConfigFileIdentity::from_open_file(&candidate_file)?
        };
        #[cfg(all(not(unix), not(windows)))]
        let candidate_identity = ConfigFileIdentity {};
        Ok(candidate_identity == self.lock_identity)
    }

    pub(crate) fn original_bytes(&self, path: &Path) -> Result<Option<Vec<u8>>> {
        self.ensure_path(path)?;
        self.revalidate_lock()?;
        Ok(self
            .original
            .as_ref()
            .map(|observed| observed.bytes.clone()))
    }

    /// Advance the held lock's CAS baseline after one successful mutation.
    /// This is used by uninstall when multiple ledger slices share one file
    /// (for example the shell hook and PATH blocks in `.zshrc`). The persistent
    /// sidecar remains locked across the entire chain.
    pub(crate) fn refresh_locked_state(&mut self) -> Result<()> {
        self.revalidate_lock()?;
        self.original = read_config_file_nofollow(&self.path, self.private)?;
        Ok(())
    }

    fn ensure_path(&self, path: &Path) -> Result<()> {
        if !self.protects_alias(path)? {
            anyhow::bail!(
                "managed config lock for {} cannot mutate {}",
                self.path.display(),
                path.display()
            );
        }
        Ok(())
    }

    pub(crate) fn write_guarded(
        &self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&[u8]>,
    ) -> Result<()> {
        self.write_guarded_with_policy(path, bytes, expected, self.private)
    }

    pub(crate) fn write_private_guarded(
        &self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&[u8]>,
    ) -> Result<()> {
        self.write_guarded_with_policy(path, bytes, expected, true)
    }

    fn write_guarded_with_policy(
        &self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&[u8]>,
        private: bool,
    ) -> Result<()> {
        self.write_guarded_with_policy_and_hook(path, bytes, expected, private, || Ok(()))
    }

    fn write_guarded_with_policy_and_hook<B>(
        &self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&[u8]>,
        private: bool,
        before_destination_transition: B,
    ) -> Result<()>
    where
        B: FnOnce() -> Result<()>,
    {
        let outcome = self.write_guarded_transaction(
            path,
            bytes,
            expected,
            private,
            before_destination_transition,
        );
        settle_config_transaction_after(&self.transaction.file, outcome)
    }

    fn write_guarded_transaction<B>(
        &self,
        path: &Path,
        bytes: &[u8],
        expected: Option<&[u8]>,
        private: bool,
        before_destination_transition: B,
    ) -> Result<()>
    where
        B: FnOnce() -> Result<()>,
    {
        self.ensure_path(path)?;
        self.revalidate_lock()?;
        if self
            .original
            .as_ref()
            .map(|observed| observed.bytes.as_slice())
            != expected
        {
            anyhow::bail!(
                "managed config expectation does not match locked state: {}",
                path.display()
            );
        }
        let current = read_config_file_nofollow(&self.path, private)?;
        if !observed_config_matches(current.as_ref(), self.original.as_ref()) {
            anyhow::bail!(
                "managed config changed during locked update: {}",
                path.display()
            );
        }
        if expected == Some(bytes) {
            return Ok(());
        }
        let parent = self.path.parent().context("managed config has no parent")?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .context("managed config file name is not UTF-8")?;
        let temp_name = format!(".{file_name}.kin-update-{}.tmp", uuid::Uuid::new_v4());
        #[cfg(unix)]
        let temp = self.transaction.vault_path.join(&temp_name);
        #[cfg(not(unix))]
        let temp = parent.join(&temp_name);
        #[cfg(unix)]
        let parent_handle = self.parent.try_clone()?;
        #[cfg(windows)]
        let parent_guard = super::update::windows_update::WindowsParentGuard::open(parent)?;
        #[cfg(all(not(unix), not(windows)))]
        let mut options = {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            options
        };
        #[cfg(unix)]
        if rustix::fs::fstat(&parent_handle)?.st_dev
            != rustix::fs::fstat(&self.transaction.vault)?.st_dev
        {
            anyhow::bail!(
                "managed config parent and private object vault are on different devices; refusing staging before creating residue"
            );
        }
        #[cfg(unix)]
        {
            if let Some(original) = self.original.as_ref() {
                validate_unix_metadata_for_transaction(&original.metadata, "managed config")?;
            }
            let parent_metadata = unix_config_metadata(&parent_handle)?;
            validate_unix_directory_namespace_metadata(
                &parent_metadata,
                "managed config parent directory",
            )?;
        }
        #[cfg(unix)]
        let final_mode = if private {
            0o600
        } else {
            self.original
                .as_ref()
                .map_or(0o600, |observed| observed.mode)
        };
        #[cfg(unix)]
        let mut staged = {
            let fd = rustix::fs::openat(
                &self.transaction.vault,
                temp_name.as_str(),
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_raw_mode(0o600),
            )
            .with_context(|| {
                format!(
                    "failed to create private-vault staging file {}",
                    temp.display()
                )
            })?;
            fs::File::from(fd)
        };
        #[cfg(all(not(unix), not(windows)))]
        let mut staged = options
            .open(&temp)
            .with_context(|| format!("failed to create {}", temp.display()))?;
        #[cfg(windows)]
        let mut staged = Some(if private {
            super::update::windows_update::create_current_user_private_staged_file(
                &temp,
                self.original.is_some(),
            )
            .with_context(|| format!("failed to create {}", temp.display()))?
        } else {
            super::update::windows_update::create_managed_config_staged_file(
                &temp,
                self.original.is_some(),
            )
            .with_context(|| format!("failed to create {}", temp.display()))?
        });
        // Arm exact cleanup immediately after CREATE. Every fallible
        // validation and identity probe below runs inside the cleanup envelope.
        let mut staged_committed = false;
        #[cfg(any(unix, windows))]
        let mut namespace_phase_sync_failed = false;
        #[cfg(unix)]
        let mut unix_authority_boundary_failed = false;
        #[cfg(windows)]
        let mut windows_staged_location = WindowsStagedLocation::Staged;
        #[cfg(windows)]
        let mut windows_quarantine: Option<QuarantinedConfig> = None;
        let result = (|| -> Result<()> {
            #[cfg(unix)]
            {
                clear_product_owned_unix_acl(&staged)?;
                validate_regular_config_file(&temp, &staged, true)?;
            }
            #[cfg(windows)]
            validate_regular_config_file(
                &temp,
                staged
                    .as_ref()
                    .context("Windows staging handle is missing")?,
                private,
            )?;
            #[cfg(not(windows))]
            {
                staged.write_all(bytes)?;
                staged.sync_all()?;
            }
            #[cfg(windows)]
            {
                let staged_file = staged
                    .as_mut()
                    .context("Windows staging handle disappeared before write")?;
                staged_file.write_all(bytes)?;
                staged_file.sync_all()?;
            }
            self.revalidate_lock()?;

            #[cfg(unix)]
            let final_current =
                open_observed_config_at(&parent_handle, file_name, &self.path, private)?;
            #[cfg(windows)]
            let final_current = if self.original.is_some() {
                let mut file =
                    super::update::windows_update::open_managed_config_for_exact_quarantine(
                        &self.path, true,
                    )?;
                let observed =
                    observe_open_config_file_with_full_sacl(&self.path, &mut file, private, true)?;
                Some((file, observed))
            } else {
                None
            };
            #[cfg(all(not(unix), not(windows)))]
            let final_current = read_config_file_nofollow(&self.path, private)?;
            #[cfg(any(unix, windows))]
            let final_observed = final_current.as_ref().map(|(_, observed)| observed);
            #[cfg(all(not(unix), not(windows)))]
            let final_observed = final_current.as_ref();
            #[cfg(windows)]
            let final_matches_original =
                observed_config_matches_pre_strict_baseline(final_observed, self.original.as_ref());
            #[cfg(not(windows))]
            let final_matches_original =
                observed_config_matches(final_observed, self.original.as_ref());
            if !final_matches_original {
                anyhow::bail!(
                    "managed config changed before quarantine: {}",
                    path.display()
                );
            }
            #[cfg(unix)]
            let staged_observed = {
                if let Some((source, observed)) = final_current.as_ref() {
                    apply_unix_config_metadata(source, &staged, observed)?;
                } else {
                    rustix::fs::fchmod(&staged, rustix::fs::Mode::from_raw_mode(final_mode as _))?;
                    clear_product_owned_unix_acl(&staged)?;
                    staged.sync_all()?;
                }
                let observed = observe_open_config_file(&temp, &mut staged, private)?;
                if observed.bytes != bytes {
                    anyhow::bail!(
                        "staged managed config bytes changed before transaction preparation"
                    );
                }
                if let Some((_, original)) = final_current.as_ref() {
                    if observed.mode != original.mode
                        || observed.uid != original.uid
                        || observed.gid != original.gid
                        || observed.metadata != original.metadata
                    {
                        anyhow::bail!(
                            "staged managed config metadata does not exactly match the retained original"
                        );
                    }
                }
                observed
            };
            #[cfg(unix)]
            let staged_identity = staged_observed.identity.clone();
            #[cfg(unix)]
            let staged_record = RecordedConfigObject::from_observed(&staged_observed);
            #[cfg(windows)]
            {
                windows_quarantine = final_current.map(|(file, observed)| QuarantinedConfig {
                    name: file_name.to_string(),
                    file,
                    observed,
                });
            }

            before_destination_transition()?;
            self.revalidate_lock()?;
            #[cfg(unix)]
            let platform_result: Result<()> = (|| {
                let parent_identity = config_parent_identity(&parent_handle)?;
                ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                ensure_config_binding_at(
                    &self.transaction.vault,
                    &temp_name,
                    &staged_identity,
                    "managed config staging file",
                )?;
                let replacement = staged_record.clone();
                sync_config_parent(&self.transaction.vault)?;
                let mut transaction = ConfigTransactionRecord {
                    schema_version: CONFIG_TRANSACTION_SCHEMA_VERSION,
                    sidecar: self.lock_identity.clone(),
                    destination: self.path.clone(),
                    destination_name: file_name.to_string(),
                    operation: ConfigTransactionOperation::Write,
                    phase: ConfigTransactionPhase::Prepared,
                    private,
                    staged_name: Some(temp_name.clone()),
                    retained_name: Some(temp_name.clone()),
                    original: final_current
                        .as_ref()
                        .map(|(_, observed)| RecordedConfigObject::from_observed(observed)),
                    replacement: Some(replacement.clone()),
                    parent: parent_identity.clone(),
                    vault: self.transaction.vault_identity.clone(),
                };
                self.revalidate_lock()?;
                write_config_transaction(&self.transaction.file, &transaction)?;
                // From this point the durable transaction, not the outer
                // best-effort cleanup, owns the staging pathname.
                staged_committed = true;

                if final_current.is_some() {
                    rustix::fs::renameat_with(
                        &self.transaction.vault,
                        temp_name.as_str(),
                        &parent_handle,
                        file_name,
                        rustix::fs::RenameFlags::EXCHANGE,
                    )
                    .context("failed to atomically exchange managed config")?;
                } else {
                    rustix::fs::renameat_with(
                        &self.transaction.vault,
                        temp_name.as_str(),
                        &parent_handle,
                        file_name,
                        rustix::fs::RenameFlags::NOREPLACE,
                    )
                    .context("failed to commit new managed config without replacement")?;
                }
                if config_directory_sync_injected(parent) {
                    anyhow::bail!(
                        "injected client config directory sync failure after namespace transition"
                    );
                }
                sync_config_parent(&parent_handle)?;
                sync_config_parent(&self.transaction.vault)?;
                ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                let (_, installed) =
                    open_observed_config_at(&parent_handle, file_name, &self.path, private)?
                        .context("managed config disappeared after namespace transition")?;
                if !replacement.matches(&installed) {
                    anyhow::bail!(
                        "managed config failed exact post-commit readback; recovery evidence retained: {}",
                        path.display()
                    );
                }

                if let Some((old_file, expected_old)) = final_current {
                    let retained = open_observed_config_at(
                        &self.transaction.vault,
                        &temp_name,
                        &self.transaction.vault_path.join(&temp_name),
                        private,
                    )?
                    .context("retained old config disappeared after atomic exchange")?;
                    let old_record = transaction
                        .original
                        .as_ref()
                        .context("managed config exchange lost original authority")?;
                    if !old_record.matches(&retained.1) {
                        // The destination raced after final validation, or a
                        // pre-existing writable fd changed the old object.
                        // Restore that exact object only while canonical still
                        // names Kin's known staged replacement.
                        ensure_config_binding_at(
                            &parent_handle,
                            file_name,
                            &staged_identity,
                            "installed managed config",
                        )?;
                        ensure_config_binding_at(
                            &self.transaction.vault,
                            &temp_name,
                            &retained.1.identity,
                            "retained raced managed config",
                        )?;
                        ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                        rustix::fs::renameat_with(
                            &parent_handle,
                            file_name,
                            &self.transaction.vault,
                            temp_name.as_str(),
                            rustix::fs::RenameFlags::EXCHANGE,
                        )?;
                        sync_config_parent(&parent_handle)?;
                        sync_config_parent(&self.transaction.vault)?;
                        ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                        let (_, restored) = open_observed_config_at(
                            &parent_handle,
                            file_name,
                            &self.path,
                            private,
                        )?
                        .context("raced managed config disappeared during exchange rollback")?;
                        if restored.identity != retained.1.identity {
                            anyhow::bail!(
                                "raced managed config could not be restored exactly; recovery record retained"
                            );
                        }
                        let staged_after_rollback = open_observed_config_at(
                            &self.transaction.vault,
                            &temp_name,
                            &self.transaction.vault_path.join(&temp_name),
                            private,
                        )?
                        .context("staged replacement disappeared during exchange rollback")?;
                        if !replacement.matches(&staged_after_rollback.1) {
                            anyhow::bail!(
                                "staged replacement changed during exchange rollback; recovery record retained"
                            );
                        }
                        let mut staged_after_rollback = QuarantinedConfig {
                            name: temp_name.clone(),
                            file: staged_after_rollback.0,
                            observed: staged_after_rollback.1,
                        };
                        let rollback_boundary = (|| -> Result<ObservedConfigFile> {
                            maybe_inject_config_authority_drift("write-rollback-applied")?;
                            self.revalidate_lock()?;
                            ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                            let (_, boundary_restored) = open_observed_config_at(
                                &parent_handle,
                                file_name,
                                &self.path,
                                private,
                            )?
                            .context(
                                "restored raced managed config disappeared at durable rollback boundary",
                            )?;
                            if !observed_config_matches(Some(&boundary_restored), Some(&retained.1))
                            {
                                anyhow::bail!(
                                    "restored raced managed config changed at durable rollback boundary"
                                );
                            }
                            let boundary_staged = observe_open_config_file(
                                &self.transaction.vault_path.join(&temp_name),
                                &mut staged_after_rollback.file,
                                private,
                            )?;
                            if !replacement.matches(&boundary_staged) {
                                anyhow::bail!(
                                    "rolled-back managed config replacement changed at durable rollback boundary"
                                );
                            }
                            ensure_config_binding_at(
                                &self.transaction.vault,
                                &temp_name,
                                &boundary_staged.identity,
                                "rolled-back managed config replacement",
                            )?;
                            Ok(boundary_restored)
                        })();
                        let boundary_restored = match rollback_boundary {
                            Ok(observed) => observed,
                            Err(error) => {
                                unix_authority_boundary_failed = true;
                                return Err(error.context(
                                    "managed config authority changed before durable RollbackApplied",
                                ));
                            }
                        };
                        transaction.phase = ConfigTransactionPhase::RollbackApplied;
                        write_config_transaction(&self.transaction.file, &transaction)?;
                        dispose_quarantined_config_at(
                            &self.transaction.vault,
                            &mut staged_after_rollback,
                            private,
                        )?;
                        let terminal_boundary = (|| -> Result<()> {
                            self.revalidate_lock()?;
                            ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                            let (_, terminal_restored) = open_observed_config_at(
                                &parent_handle,
                                file_name,
                                &self.path,
                                private,
                            )?
                            .context(
                                "restored raced managed config disappeared at terminal rollback boundary",
                            )?;
                            if !observed_config_matches(
                                Some(&terminal_restored),
                                Some(&boundary_restored),
                            ) {
                                anyhow::bail!(
                                    "restored raced managed config changed at terminal rollback boundary"
                                );
                            }
                            ensure_config_absent_at(
                                &self.transaction.vault,
                                &temp_name,
                                "disposed rolled-back managed config replacement",
                            )
                        })();
                        if let Err(error) = terminal_boundary {
                            unix_authority_boundary_failed = true;
                            return Err(error.context(
                                "managed config authority changed before terminal rollback WAL",
                            ));
                        }
                        complete_config_transaction(
                            &self.transaction.file,
                            &mut transaction,
                            ConfigTransactionOutcome::RolledBack,
                        )?;
                        anyhow::bail!(
                            "managed config changed at the atomic exchange boundary; raced object was restored"
                        );
                    }
                    let mut old = QuarantinedConfig {
                        name: temp_name.clone(),
                        file: old_file,
                        observed: expected_old,
                    };
                    let namespace_boundary = (|| -> Result<()> {
                        maybe_inject_config_authority_drift("write-namespace-committed")?;
                        self.revalidate_lock()?;
                        ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                        let (_, boundary_installed) = open_observed_config_at(
                            &parent_handle,
                            file_name,
                            &self.path,
                            private,
                        )?
                        .context(
                            "installed managed config disappeared at durable commit boundary",
                        )?;
                        if !replacement.matches(&boundary_installed) {
                            anyhow::bail!(
                                "installed managed config changed at durable commit boundary"
                            );
                        }
                        let boundary_old = observe_open_config_file(
                            &self.transaction.vault_path.join(&temp_name),
                            &mut old.file,
                            private,
                        )?;
                        if !old_record.matches(&boundary_old) {
                            anyhow::bail!(
                                "retained managed config original changed at durable commit boundary"
                            );
                        }
                        ensure_config_binding_at(
                            &self.transaction.vault,
                            &temp_name,
                            &boundary_old.identity,
                            "retained original at durable commit boundary",
                        )
                    })();
                    if let Err(error) = namespace_boundary {
                        unix_authority_boundary_failed = true;
                        return Err(error.context(
                            "managed config authority changed before durable NamespaceCommitted",
                        ));
                    }
                    transaction.phase = ConfigTransactionPhase::NamespaceCommitted;
                    if let Err(error) =
                        write_config_transaction(&self.transaction.file, &transaction)
                    {
                        namespace_phase_sync_failed = true;
                        return Err(error.context(
                            "managed config NamespaceCommitted WAL sync is ambiguous; exact recovery evidence retained for restart",
                        ));
                    }
                    dispose_quarantined_config_at(&self.transaction.vault, &mut old, private)?;
                    ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                } else {
                    let namespace_boundary = (|| -> Result<()> {
                        maybe_inject_config_authority_drift("write-namespace-committed")?;
                        self.revalidate_lock()?;
                        ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                        let (_, boundary_installed) = open_observed_config_at(
                            &parent_handle,
                            file_name,
                            &self.path,
                            private,
                        )?
                        .context("created managed config disappeared at durable commit boundary")?;
                        if !replacement.matches(&boundary_installed) {
                            anyhow::bail!(
                                "created managed config changed at durable commit boundary"
                            );
                        }
                        ensure_config_absent_at(
                            &self.transaction.vault,
                            &temp_name,
                            "moved managed config staging file",
                        )
                    })();
                    if let Err(error) = namespace_boundary {
                        unix_authority_boundary_failed = true;
                        return Err(error.context(
                            "managed config authority changed before durable NamespaceCommitted",
                        ));
                    }
                    transaction.phase = ConfigTransactionPhase::NamespaceCommitted;
                    if let Err(error) =
                        write_config_transaction(&self.transaction.file, &transaction)
                    {
                        namespace_phase_sync_failed = true;
                        return Err(error.context(
                            "managed config NamespaceCommitted WAL sync is ambiguous; exact recovery evidence retained for restart",
                        ));
                    }
                }
                let terminal_boundary = (|| -> Result<()> {
                    self.revalidate_lock()?;
                    ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                    let (_, terminal_installed) =
                        open_observed_config_at(&parent_handle, file_name, &self.path, private)?
                            .context(
                                "installed managed config disappeared at terminal commit boundary",
                            )?;
                    if !replacement.matches(&terminal_installed) {
                        anyhow::bail!(
                            "installed managed config changed at terminal commit boundary"
                        );
                    }
                    ensure_config_absent_at(
                        &self.transaction.vault,
                        &temp_name,
                        "disposed managed config original",
                    )
                })();
                if let Err(error) = terminal_boundary {
                    unix_authority_boundary_failed = true;
                    return Err(error
                        .context("managed config authority changed before terminal commit WAL"));
                }
                complete_config_transaction(
                    &self.transaction.file,
                    &mut transaction,
                    ConfigTransactionOutcome::Committed,
                )?;
                return Ok(());
            })();

            #[cfg(windows)]
            let platform_result: Result<()> = (|| {
                let strict_sacl = windows_quarantine.is_some();
                parent_guard.revalidate_visible()?;
                if let Some(source) = windows_quarantine.as_ref() {
                    super::update::windows_update::copy_managed_file_metadata(
                        &source.file,
                        staged
                            .as_ref()
                            .context("Windows staging handle disappeared before metadata copy")?,
                    )?;
                }
                let staged_observed = observe_open_config_file_with_full_sacl(
                    &temp,
                    staged
                        .as_mut()
                        .context("Windows staging handle disappeared before observation")?,
                    private,
                    strict_sacl,
                )?;
                let replacement = RecordedConfigObject::from_observed(&staged_observed);
                let quarantine_name = windows_quarantine
                    .as_ref()
                    .map(|_| format!(".{file_name}.kin-quarantine-{}", uuid::Uuid::new_v4()));
                let (namespace, parent_file) = parent_guard.identity();
                let mut transaction = ConfigTransactionRecord {
                    schema_version: CONFIG_TRANSACTION_SCHEMA_VERSION,
                    sidecar: self.lock_identity.clone(),
                    destination: self.path.clone(),
                    destination_name: file_name.to_string(),
                    operation: ConfigTransactionOperation::Write,
                    phase: ConfigTransactionPhase::Prepared,
                    private,
                    staged_name: Some(temp_name.clone()),
                    retained_name: quarantine_name.clone(),
                    original: windows_quarantine
                        .as_ref()
                        .map(|old| RecordedConfigObject::from_observed(&old.observed)),
                    replacement: Some(replacement.clone()),
                    parent: ConfigParentIdentity {
                        namespace,
                        file: parent_file,
                    },
                };
                if strict_sacl {
                    super::update::windows_update::validate_managed_file_full_sacl(
                        staged
                            .as_ref()
                            .context("Windows staging handle disappeared before Prepared")?,
                    )?;
                    super::update::windows_update::validate_managed_file_full_sacl(
                        &windows_quarantine
                            .as_ref()
                            .context("Windows replacement lost source authority before Prepared")?
                            .file,
                    )?;
                }
                self.revalidate_lock()?;
                write_config_transaction(&self.transaction.file, &transaction)?;
                // The durable Prepared frame owns recovery from this point,
                // including any crash during the two-file-object handoff.
                staged_committed = true;
                let armed = staged
                    .take()
                    .context("Windows staging handle disappeared after Prepared WAL")?;
                let durable = super::update::windows_update::disarm_staged_file_delete_on_close(
                    armed,
                    &temp,
                    private,
                    strict_sacl,
                )?;
                staged = Some(durable);

                maybe_inject_windows_stage_drift(
                    "before-old-quarantine",
                    staged.as_ref().context(
                        "Windows staging handle disappeared before first drift boundary",
                    )?,
                )?;
                let staged_before_namespace = observe_open_config_file_with_full_sacl(
                    &temp,
                    staged.as_mut().context(
                        "Windows staging handle disappeared before first namespace mutation",
                    )?,
                    private,
                    strict_sacl,
                )?;
                if !replacement.matches(&staged_before_namespace) {
                    anyhow::bail!(
                        "Windows replacement changed immediately before first namespace mutation"
                    );
                }
                if let (Some(old), Some(original)) =
                    (windows_quarantine.as_mut(), transaction.original.as_ref())
                {
                    let original_before_namespace = observe_open_config_file_with_full_sacl(
                        &self.path,
                        &mut old.file,
                        private,
                        strict_sacl,
                    )?;
                    if !original.matches(&original_before_namespace) {
                        anyhow::bail!(
                            "Windows original changed immediately before first namespace mutation"
                        );
                    }
                }

                if let Some(old) = windows_quarantine.as_mut() {
                    let name = quarantine_name
                        .clone()
                        .context("Windows write transaction lost quarantine name")?;
                    let quarantine_path = parent.join(&name);
                    rename_windows_config_exact(
                        &old.file,
                        &quarantine_path,
                        private,
                        transaction
                            .original
                            .as_ref()
                            .map(|original| {
                                strict_windows_full_sacl(original, "replacement original")
                            })
                            .transpose()?,
                    )?;
                    // Record the new exact-handle location immediately after
                    // the namespace transition, before any fallible check.
                    old.name = name;
                    super::update::windows_update::revalidate_managed_file_path(
                        &quarantine_path,
                        &old.file,
                        private,
                        strict_sacl,
                    )?;
                    parent_guard.revalidate_visible()?;
                }
                if maybe_inject_windows_stage_crash(
                    "after-old-quarantine-before-stage-commit",
                    staged.as_ref().context(
                        "Windows staging handle disappeared before crash-recovery injection",
                    )?,
                )? {
                    namespace_phase_sync_failed = true;
                    anyhow::bail!(
                        "injected crash after old quarantine with an unsupported replacement SACL"
                    );
                }
                maybe_inject_windows_stage_drift(
                    "after-old-quarantine-before-stage-commit",
                    staged.as_ref().context(
                        "Windows staging handle disappeared before post-quarantine drift boundary",
                    )?,
                )?;
                let staged_before_commit = observe_open_config_file_with_full_sacl(
                    &temp,
                    staged
                        .as_mut()
                        .context("Windows staging handle disappeared before exact commit")?,
                    private,
                    strict_sacl,
                )?;
                if !replacement.matches(&staged_before_commit) {
                    anyhow::bail!(
                        "Windows replacement changed after old quarantine and before exact commit"
                    );
                }
                if let (Some(old), Some(original)) =
                    (windows_quarantine.as_mut(), transaction.original.as_ref())
                {
                    let quarantine_path = parent.join(&old.name);
                    let original_before_commit = observe_open_config_file_with_full_sacl(
                        &quarantine_path,
                        &mut old.file,
                        private,
                        strict_sacl,
                    )?;
                    if !original.matches(&original_before_commit) {
                        anyhow::bail!(
                            "Windows original changed after quarantine and before replacement commit"
                        );
                    }
                }
                let staged_file = staged
                    .as_ref()
                    .context("Windows staging handle disappeared before exact commit")?;
                rename_windows_config_exact(
                    staged_file,
                    &self.path,
                    private,
                    replacement.full_sacl.as_deref(),
                )
                .context("failed to commit managed config; durable recovery authority retained")?;
                windows_staged_location = WindowsStagedLocation::Canonical;
                super::update::windows_update::revalidate_managed_file_path(
                    &self.path,
                    staged
                        .as_ref()
                        .context("Windows staging handle disappeared after exact commit")?,
                    private,
                    strict_sacl,
                )?;
                parent_guard.revalidate_visible()?;
                validate_regular_config_file(
                    &self.path,
                    staged
                        .as_ref()
                        .context("Windows staging handle disappeared before validation")?,
                    private,
                )?;
                staged
                    .as_ref()
                    .context("Windows staging handle disappeared before flush")?
                    .sync_all()?;
                let installed = observe_open_config_file_with_full_sacl(
                    &self.path,
                    staged
                        .as_mut()
                        .context("Windows installed handle disappeared after exact commit")?,
                    private,
                    strict_sacl,
                )?;
                if !replacement.matches(&installed) {
                    anyhow::bail!(
                        "managed config failed exact post-commit readback; durable recovery evidence retained: {}",
                        path.display()
                    );
                }
                if let Some(quarantined) = windows_quarantine.as_mut() {
                    let quarantine_path = parent.join(&quarantined.name);
                    super::update::windows_update::revalidate_managed_file_path(
                        &quarantine_path,
                        &quarantined.file,
                        private,
                        strict_sacl,
                    )?;
                    let reobserved = observe_open_config_file_with_full_sacl(
                        &quarantine_path,
                        &mut quarantined.file,
                        private,
                        strict_sacl,
                    )?;
                    if !observed_config_matches(Some(&reobserved), Some(&quarantined.observed)) {
                        anyhow::bail!(
                            "retained old managed config accrued concurrent edits; exact-handle rollback required"
                        );
                    }
                }

                transaction.phase = ConfigTransactionPhase::NamespaceCommitted;
                if let Err(error) = write_config_transaction(&self.transaction.file, &transaction) {
                    namespace_phase_sync_failed = true;
                    return Err(error.context(
                        "Windows managed config NamespaceCommitted WAL sync is ambiguous; exact recovery evidence retained for restart",
                    ));
                }

                if let Some(quarantined) = windows_quarantine.as_ref() {
                    let quarantine_path = parent.join(&quarantined.name);
                    super::update::windows_update::revalidate_managed_file_path(
                        &quarantine_path,
                        &quarantined.file,
                        private,
                        strict_sacl,
                    )?;
                    let original = transaction
                        .original
                        .as_ref()
                        .context("Windows write transaction lost original authority")?;
                    mark_windows_recorded_config_for_disposition(
                        &quarantined.file,
                        &quarantine_path,
                        private,
                        "quarantined managed config",
                        original,
                        strict_sacl,
                    )?;
                    let quarantined = windows_quarantine
                        .take()
                        .context("Windows write lost delete-pending quarantine")?;
                    finish_windows_disposition(
                        quarantined.file,
                        &quarantine_path,
                        "quarantined managed config",
                    )?;
                    parent_guard.revalidate_visible()?;
                }
                let staged_file = staged
                    .as_ref()
                    .context("Windows installed handle disappeared before terminal validation")?;
                super::update::windows_update::revalidate_managed_file_path(
                    &self.path,
                    staged_file,
                    private,
                    strict_sacl,
                )?;
                let mut final_reader = staged_file.try_clone()?;
                let installed_before_terminal = observe_open_config_file_with_full_sacl(
                    &self.path,
                    &mut final_reader,
                    private,
                    strict_sacl,
                )?;
                if !replacement.matches(&installed_before_terminal) {
                    anyhow::bail!(
                        "managed config changed before terminal commit; terminal WAL was not written"
                    );
                }
                parent_guard.revalidate_visible()?;
                complete_windows_config_transaction(
                    &self.transaction.file,
                    &parent_guard,
                    &self.path,
                    private,
                    &mut transaction,
                    ConfigTransactionOutcome::Committed,
                )?;
                drop(staged.take());
                return Ok(());
            })();

            #[cfg(all(not(unix), not(windows)))]
            let platform_result: Result<()> = (|| {
                replace_config_file(&temp, &self.path, final_current.is_some())?;
                staged_committed = true;
                let installed = read_config_file_nofollow(&self.path, private)?
                    .context("managed config disappeared after atomic replacement")?;
                if installed.bytes != bytes {
                    anyhow::bail!(
                        "managed config failed post-replacement readback: {}",
                        path.display()
                    );
                }
                Ok(())
            })();
            platform_result
        })();
        if let Err(error) = result {
            #[cfg(windows)]
            {
                if staged_committed {
                    if namespace_phase_sync_failed {
                        return Err(error);
                    }
                    let mut transaction = read_config_transaction(&self.transaction.file)?
                        .context("failed Windows write lost durable recovery transaction")?;
                    if transaction.operation == ConfigTransactionOperation::Write
                        && !matches!(
                            transaction.phase,
                            ConfigTransactionPhase::CommitComplete
                                | ConfigTransactionPhase::RollbackComplete
                        )
                    {
                        return match resolve_failed_windows_write_with_retained_handles(
                            &self.transaction.file,
                            &parent_guard,
                            &self.path,
                            &temp,
                            private,
                            &mut transaction,
                            &mut staged,
                            &mut windows_staged_location,
                            &mut windows_quarantine,
                        ) {
                            Ok(FailedWriteResolution::RolledBack) => Err(error.context(
                                "Windows managed config write failed after transition and was rolled back",
                            )),
                            Ok(FailedWriteResolution::Committed) => Ok(()),
                            Err(rollback) => Err(error.context(format!(
                                "Windows managed config write failed after transition; rollback evidence retained: {rollback:#}"
                            ))),
                        };
                    }
                    if transaction.phase == ConfigTransactionPhase::CommitComplete {
                        return Ok(());
                    }
                    if transaction.phase == ConfigTransactionPhase::RollbackComplete {
                        return Err(error.context(
                            "Windows managed config write failed and its rollback completed",
                        ));
                    }
                    return Err(error);
                }
                let cleanup = (|| -> Result<()> {
                    let staged_file = staged
                        .as_ref()
                        .context("Windows staging handle disappeared before exact cleanup")?;
                    dispose_windows_config_exact(
                        staged_file,
                        &temp,
                        private,
                        "partial managed config staging file",
                    )?;
                    windows_staged_location = WindowsStagedLocation::DispositionApplied;
                    let staged_file = staged
                        .take()
                        .context("Windows staging handle disappeared after disposition")?;
                    finish_windows_disposition(
                        staged_file,
                        &temp,
                        "partial managed config staging file",
                    )
                })();
                return match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(error.context(format!(
                        "exact staging cleanup also failed; object retained at {}: {cleanup:#}",
                        temp.display()
                    ))),
                };
            }
            #[cfg(unix)]
            if staged_committed {
                if namespace_phase_sync_failed || unix_authority_boundary_failed {
                    return Err(error);
                }
                if let Err(authority) = self.revalidate_lock() {
                    return Err(error.context(format!(
                        "managed config write failed after authority drift; durable WAL and exact objects retained: {authority:#}"
                    )));
                }
                let mut transaction = read_config_transaction(&self.transaction.file)?
                    .context("failed write lost durable recovery transaction")?;
                if transaction.operation == ConfigTransactionOperation::Write
                    && !matches!(
                        transaction.phase,
                        ConfigTransactionPhase::CommitComplete
                            | ConfigTransactionPhase::RollbackComplete
                    )
                {
                    return match rollback_failed_unix_write(
                        &self.transaction,
                        &parent_handle,
                        &self.path,
                        private,
                        &mut transaction,
                    ) {
                        Ok(FailedWriteResolution::RolledBack) => Err(error.context(
                            "managed config write failed after transition and was rolled back",
                        )),
                        Ok(FailedWriteResolution::Committed) => Ok(()),
                        Err(rollback) => Err(error.context(format!(
                            "managed config write failed after transition; rollback evidence retained: {rollback:#}"
                        ))),
                    };
                }
                return match transaction.phase {
                    ConfigTransactionPhase::CommitComplete => Ok(()),
                    ConfigTransactionPhase::RollbackComplete => {
                        Err(error.context("managed config write failed and its rollback completed"))
                    }
                    _ => Err(error),
                };
            }
            #[cfg(unix)]
            if !staged_committed {
                let cleanup = cleanup_uncommitted_unix_stage(
                    &self.transaction,
                    &parent_handle,
                    &temp_name,
                    &temp,
                    &staged,
                );
                if let Err(cleanup) = cleanup {
                    return Err(error.context(format!(
                        "exact staging cleanup also failed; object retained at {}: {cleanup:#}",
                        temp.display()
                    )));
                }
            }
            #[cfg(all(not(unix), not(windows)))]
            if !staged_committed {
                let _ = fs::remove_file(&temp);
            }
            #[cfg(not(windows))]
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn remove_guarded(&self, path: &Path, expected: Option<&[u8]>) -> Result<()> {
        self.remove_guarded_with_hook(path, expected, || Ok(()))
    }

    fn remove_guarded_with_hook<B>(
        &self,
        path: &Path,
        expected: Option<&[u8]>,
        before_quarantine: B,
    ) -> Result<()>
    where
        B: FnOnce() -> Result<()>,
    {
        let outcome = self.remove_guarded_transaction(path, expected, before_quarantine);
        settle_config_transaction_after(&self.transaction.file, outcome)
    }

    fn remove_guarded_transaction<B>(
        &self,
        path: &Path,
        expected: Option<&[u8]>,
        before_quarantine: B,
    ) -> Result<()>
    where
        B: FnOnce() -> Result<()>,
    {
        self.ensure_path(path)?;
        self.revalidate_lock()?;
        if self
            .original
            .as_ref()
            .map(|observed| observed.bytes.as_slice())
            != expected
        {
            anyhow::bail!(
                "managed config expectation does not match locked state: {}",
                path.display()
            );
        }
        let current = read_config_file_nofollow(&self.path, self.private)?;
        if !observed_config_matches(current.as_ref(), self.original.as_ref()) {
            anyhow::bail!(
                "managed config changed during locked removal: {}",
                path.display()
            );
        }
        if current.is_none() {
            return Ok(());
        }

        let parent = self.path.parent().context("managed config has no parent")?;
        let file_name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .context("managed config file name is not UTF-8")?;

        #[cfg(unix)]
        let platform_result: Result<()> = (|| {
            let parent_handle = self.parent.try_clone()?;
            let parent_identity = config_parent_identity(&parent_handle)?;
            let final_current =
                open_observed_config_at(&parent_handle, file_name, &self.path, self.private)?;
            let final_observed = final_current.as_ref().map(|(_, observed)| observed);
            if !observed_config_matches(final_observed, self.original.as_ref()) {
                anyhow::bail!(
                    "managed config changed before removal quarantine: {}",
                    path.display()
                );
            }
            before_quarantine()?;
            self.revalidate_lock()?;
            ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
            let (file, observed) =
                final_current.context("managed config disappeared before removal quarantine")?;
            ensure_config_binding_at(
                &parent_handle,
                file_name,
                &observed.identity,
                "managed config removal target",
            )?;
            let quarantine_name = format!(".{file_name}.kin-quarantine-{}", uuid::Uuid::new_v4());
            if rustix::fs::fstat(&parent_handle)?.st_dev
                != rustix::fs::fstat(&self.transaction.vault)?.st_dev
            {
                anyhow::bail!(
                    "managed config parent and private object vault are on different devices; refusing non-atomic removal"
                );
            }
            let mut transaction = ConfigTransactionRecord {
                schema_version: CONFIG_TRANSACTION_SCHEMA_VERSION,
                sidecar: self.lock_identity.clone(),
                destination: self.path.clone(),
                destination_name: file_name.to_string(),
                operation: ConfigTransactionOperation::Remove,
                phase: ConfigTransactionPhase::Prepared,
                private: self.private,
                staged_name: None,
                retained_name: Some(quarantine_name.clone()),
                original: Some(RecordedConfigObject::from_observed(&observed)),
                replacement: None,
                parent: parent_identity.clone(),
                vault: self.transaction.vault_identity.clone(),
            };
            self.revalidate_lock()?;
            write_config_transaction(&self.transaction.file, &transaction)?;
            let mut quarantined = quarantine_config_at(
                &parent_handle,
                &self.transaction.vault,
                file_name,
                &self.path,
                file,
                observed,
                quarantine_name.clone(),
            )?;

            let precommit = (|| -> Result<()> {
                if config_directory_sync_injected(parent) {
                    anyhow::bail!(
                        "injected client config directory sync failure after removal quarantine"
                    );
                }
                sync_config_parent(&parent_handle)?;
                sync_config_parent(&self.transaction.vault)?;
                ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                ensure_config_binding_at(
                    &self.transaction.vault,
                    &quarantine_name,
                    &quarantined.observed.identity,
                    "removal quarantine",
                )?;
                let reobserved = observe_open_config_file(
                    &self.transaction.vault_path.join(&quarantine_name),
                    &mut quarantined.file,
                    self.private,
                )?;
                if !observed_config_matches(Some(&reobserved), Some(&quarantined.observed)) {
                    anyhow::bail!("managed config changed at the removal quarantine boundary");
                }
                Ok(())
            })();
            if let Err(error) = precommit {
                return resolve_failed_unix_removal(
                    &self.transaction,
                    parent,
                    &parent_handle,
                    &self.path,
                    self.private,
                    file_name,
                    &quarantine_name,
                    &mut transaction,
                    false,
                    error,
                );
            }

            let namespace_boundary = (|| -> Result<()> {
                maybe_inject_config_authority_drift("remove-namespace-committed")?;
                self.revalidate_lock()?;
                ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
                ensure_config_absent_at(
                    &parent_handle,
                    file_name,
                    "quarantined managed config destination",
                )?;
                let boundary_quarantine = observe_open_config_file(
                    &self.transaction.vault_path.join(&quarantine_name),
                    &mut quarantined.file,
                    self.private,
                )?;
                if !transaction
                    .original
                    .as_ref()
                    .context("removal transaction lost original boundary authority")?
                    .matches(&boundary_quarantine)
                {
                    anyhow::bail!("removal quarantine changed at durable commit boundary");
                }
                ensure_config_binding_at(
                    &self.transaction.vault,
                    &quarantine_name,
                    &boundary_quarantine.identity,
                    "removal quarantine at durable commit boundary",
                )
            })();
            if let Err(error) = namespace_boundary {
                return Err(error.context(
                    "managed config authority changed before removal NamespaceCommitted",
                ));
            }
            transaction.phase = ConfigTransactionPhase::NamespaceCommitted;
            if let Err(error) = write_config_transaction(&self.transaction.file, &transaction) {
                return Err(error.context(
                    "managed config removal NamespaceCommitted WAL sync is ambiguous; exact quarantine retained for restart",
                ));
            }
            if let Err(error) = dispose_quarantined_config_at(
                &self.transaction.vault,
                &mut quarantined,
                self.private,
            ) {
                return resolve_unix_committed_transaction_after_error(
                    &self.transaction,
                    &self.path,
                    self.private,
                    error,
                );
            }
            ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
            self.revalidate_lock()?;
            ensure_config_parent_binding(parent, &parent_handle, &parent_identity)?;
            ensure_config_absent_at(
                &parent_handle,
                file_name,
                "committed removed managed config destination",
            )?;
            ensure_config_absent_at(
                &self.transaction.vault,
                &quarantine_name,
                "disposed managed config removal quarantine",
            )?;
            if let Err(error) = complete_config_transaction(
                &self.transaction.file,
                &mut transaction,
                ConfigTransactionOutcome::Committed,
            ) {
                return resolve_unix_committed_transaction_after_error(
                    &self.transaction,
                    &self.path,
                    self.private,
                    error,
                );
            }
            return Ok(());
        })();

        #[cfg(windows)]
        let platform_result: Result<()> = (|| {
            let parent_guard = super::update::windows_update::WindowsParentGuard::open(parent)?;
            let mut file = super::update::windows_update::open_managed_config_for_exact_quarantine(
                &self.path, true,
            )?;
            let observed =
                observe_open_config_file_with_full_sacl(&self.path, &mut file, self.private, true)?;
            if !observed_config_matches_pre_strict_baseline(Some(&observed), self.original.as_ref())
            {
                anyhow::bail!(
                    "managed config changed before removal quarantine: {}",
                    path.display()
                );
            }
            super::update::windows_update::revalidate_managed_file_path(
                &self.path,
                &file,
                self.private,
                true,
            )?;
            let mut quarantined = QuarantinedConfig {
                name: file_name.to_string(),
                file,
                observed,
            };
            before_quarantine()?;
            self.revalidate_lock()?;
            parent_guard.revalidate_visible()?;
            let quarantine_name = format!(".{file_name}.kin-quarantine-{}", uuid::Uuid::new_v4());
            let quarantine_path = parent.join(&quarantine_name);
            let (namespace, parent_file) = parent_guard.identity();
            let mut transaction = ConfigTransactionRecord {
                schema_version: CONFIG_TRANSACTION_SCHEMA_VERSION,
                sidecar: self.lock_identity.clone(),
                destination: self.path.clone(),
                destination_name: file_name.to_string(),
                operation: ConfigTransactionOperation::Remove,
                phase: ConfigTransactionPhase::Prepared,
                private: self.private,
                staged_name: None,
                retained_name: Some(quarantine_name),
                original: Some(RecordedConfigObject::from_observed(&quarantined.observed)),
                replacement: None,
                parent: ConfigParentIdentity {
                    namespace,
                    file: parent_file,
                },
            };
            super::update::windows_update::validate_managed_file_full_sacl(&quarantined.file)
                .context("managed config full SACL changed before removal Prepared WAL")?;
            self.revalidate_lock()?;
            write_config_transaction(&self.transaction.file, &transaction)?;
            rename_windows_config_exact(
                &quarantined.file,
                &quarantine_path,
                self.private,
                Some(strict_windows_full_sacl(
                    transaction
                        .original
                        .as_ref()
                        .context("Windows removal transaction lost original authority")?,
                    "removal original",
                )?),
            )?;
            quarantined.name = transaction
                .retained_name
                .clone()
                .context("Windows removal transaction lost quarantine name")?;
            let quarantine_validation = (|| -> Result<()> {
                super::update::windows_update::revalidate_managed_file_path(
                    &quarantine_path,
                    &quarantined.file,
                    self.private,
                    true,
                )?;
                parent_guard.revalidate_visible()?;
                let reobserved = observe_open_config_file_with_full_sacl(
                    &quarantine_path,
                    &mut quarantined.file,
                    self.private,
                    true,
                )?;
                if !observed_config_matches(Some(&reobserved), Some(&quarantined.observed)) {
                    anyhow::bail!("managed config changed at removal quarantine boundary");
                }
                Ok(())
            })();
            if let Err(error) = quarantine_validation {
                return finish_windows_removal_rollback(
                    &self.transaction.file,
                    &parent_guard,
                    &self.path,
                    &quarantine_path,
                    self.private,
                    &mut quarantined,
                    &mut transaction,
                    error,
                );
            }
            transaction.phase = ConfigTransactionPhase::NamespaceCommitted;
            if let Err(error) = write_config_transaction(&self.transaction.file, &transaction) {
                return Err(error.context(
                    "Windows managed config removal NamespaceCommitted WAL sync is ambiguous; exact quarantine retained for restart",
                ));
            }
            let original = transaction
                .original
                .as_ref()
                .context("Windows removal transaction lost original authority")?
                .clone();
            if let Err(error) = mark_windows_recorded_config_for_disposition(
                &quarantined.file,
                &quarantine_path,
                self.private,
                "quarantined managed config",
                &original,
                true,
            ) {
                return Err(error.context(
                    "committed Windows removal retained its exact quarantine handle before disposition; restart recovery remains required",
                ));
            }
            if let Err(error) = finish_windows_disposition(
                quarantined.file,
                &quarantine_path,
                "quarantined managed config",
            ) {
                return resolve_windows_committed_transaction_after_error(
                    &self.transaction.file,
                    &parent_guard,
                    &self.path,
                    self.private,
                    error,
                );
            }
            if let Err(error) = parent_guard.revalidate_visible() {
                return resolve_windows_committed_transaction_after_error(
                    &self.transaction.file,
                    &parent_guard,
                    &self.path,
                    self.private,
                    error,
                );
            }
            if let Err(error) = complete_windows_config_transaction(
                &self.transaction.file,
                &parent_guard,
                &self.path,
                self.private,
                &mut transaction,
                ConfigTransactionOutcome::Committed,
            ) {
                return resolve_windows_committed_transaction_after_error(
                    &self.transaction.file,
                    &parent_guard,
                    &self.path,
                    self.private,
                    error,
                );
            }
            return Ok(());
        })();

        #[cfg(all(not(unix), not(windows)))]
        let platform_result: Result<()> = (|| {
            before_quarantine()?;
            fs::remove_file(&self.path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            Ok(())
        })();
        platform_result
    }
}

#[cfg(all(not(unix), not(windows)))]
fn replace_config_file(staged: &Path, destination: &Path, _destination_exists: bool) -> Result<()> {
    fs::rename(staged, destination)
        .with_context(|| format!("failed to atomically replace {}", destination.display()))
}

fn merge_json_mcp_target_locked(
    target: &McpRepairTarget,
    command: &str,
    lock: &ConfigLock,
) -> Result<()> {
    let original = lock.original_bytes(&target.path)?;
    let mut root: serde_json::Value = match original.as_deref() {
        Some(bytes) => serde_json::from_slice(bytes).with_context(|| {
            format!(
                "existing file {} is not valid JSON; refusing to overwrite it",
                target.path.display()
            )
        })?,
        None => serde_json::json!({}),
    };
    let root_object = root
        .as_object_mut()
        .context("existing MCP JSON config is not an object")?;
    if root_object
        .get("mcpServers")
        .is_some_and(|value| !value.is_object())
    {
        anyhow::bail!("existing mcpServers value is not an object");
    }
    let servers = root_object
        .entry("mcpServers")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .expect("mcpServers was validated as an object");
    if servers.get("kin").is_some_and(|value| !value.is_object()) {
        anyhow::bail!("existing mcpServers.kin value is not an object");
    }
    let entry_preexisted = servers.contains_key("kin");
    let entry = servers
        .entry("kin")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .expect("Kin MCP entry was validated as an object");
    entry.insert(
        "command".to_string(),
        serde_json::Value::String(command.to_string()),
    );
    let args = match target.repo_root.as_deref() {
        Some(repo_root) => {
            serde_json::json!(["mcp", "start", "--repo", repo_root.to_string_lossy()])
        }
        None => serde_json::json!(["mcp", "start"]),
    };
    entry.insert("args".to_string(), args);
    if let Some(repo_root) = target.repo_root.as_deref() {
        if target.id == "antigravity_workspace" || (target.id == "antigravity" && !entry_preexisted)
        {
            entry.insert(
                "cwd".to_string(),
                serde_json::Value::String(repo_root.to_string_lossy().into_owned()),
            );
        }
    }
    if entry.get("env").is_some_and(|value| !value.is_object()) {
        anyhow::bail!("existing Kin MCP env value is not an object");
    }
    let env = entry
        .entry("env")
        .or_insert_with(|| serde_json::json!({}))
        .as_object_mut()
        .expect("Kin MCP env was validated as an object");
    env.insert(
        "KIN_MCP_TOOL_PROFILE".to_string(),
        serde_json::Value::String("agent-default".to_string()),
    );
    let owned_entry = root["mcpServers"]["kin"].clone();
    let formatted = serde_json::to_vec_pretty(&root)?;
    lock.write_guarded(&target.path, &formatted, original.as_deref())?;
    record_mcp_entry_in_ledger(&target.id, &target.path, &owned_entry)
}

fn merge_codex_mcp_target_locked(
    target: &McpRepairTarget,
    command: &str,
    lock: &ConfigLock,
) -> Result<()> {
    let repo_root = target
        .repo_root
        .as_deref()
        .context("cannot determine an initialized Kin repository for the Codex MCP binding")?;
    merge_mcp_config_toml_locked(&target.path, repo_root, lock, &target.id, command)
}

fn remerge_mcp_targets_with_launcher(
    targets: &[McpRepairTarget],
    launcher: impl FnOnce() -> Result<String>,
    launcher_label: &str,
) -> McpRemergeOutcome {
    let _topology = match McpTopologyLock::acquire() {
        Ok(topology) => topology,
        Err(error) => {
            return McpRemergeOutcome {
                errors: vec![format!("could not lock MCP topology: {error:#}")],
                ..Default::default()
            }
        }
    };
    let targets = match normalize_mcp_repair_targets(targets.iter().cloned()) {
        Ok(targets) if !targets.is_empty() => targets,
        Ok(_) => {
            return McpRemergeOutcome {
                errors: vec!["MCP repair manifest is empty".to_string()],
                ..Default::default()
            }
        }
        Err(error) => {
            return McpRemergeOutcome {
                errors: vec![format!("invalid MCP repair manifest: {error:#}")],
                ..Default::default()
            }
        }
    };
    let command = match launcher() {
        Ok(command) => command,
        Err(error) => {
            return McpRemergeOutcome {
                errors: vec![format!(
                    "{launcher_label} launcher is unavailable: {error:#}"
                )],
                ..Default::default()
            }
        }
    };

    for target in &targets {
        if target.id == "antigravity_workspace" {
            let Some(repo_root) = target.repo_root.as_deref() else {
                return McpRemergeOutcome {
                    errors: vec![format!(
                        "workspace MCP target {} has no repository root",
                        target.path.display()
                    )],
                    ..Default::default()
                };
            };
            if let Err(error) = ensure_workspace_mcp_git_excluded(repo_root) {
                return McpRemergeOutcome {
                    errors: vec![format!(
                        "could not prepare workspace MCP target {}: {error:#}",
                        target.path.display()
                    )],
                    ..Default::default()
                };
            }
        }
    }
    let target_paths = targets
        .iter()
        .map(|target| target.path.clone())
        .collect::<Vec<_>>();
    let mut locks = match ConfigLock::acquire_many(&target_paths) {
        Ok(locks) => locks,
        Err(error) => {
            return McpRemergeOutcome {
                errors: vec![format!(
                    "could not acquire identity-ordered MCP config locks: {error:#}"
                )],
                ..Default::default()
            }
        }
    };

    let mut outcome = McpRemergeOutcome::default();
    for (target, lock) in targets.into_iter().zip(&mut locks) {
        let result = if target.id == "codex" {
            merge_codex_mcp_target_locked(&target, &command, lock)
        } else {
            merge_json_mcp_target_locked(&target, &command, lock)
        };
        match result {
            Ok(()) => outcome.repaired.push(target.path),
            Err(error) => outcome.errors.push(format!(
                "{} at {}: {error:#}",
                target.id,
                target.path.display()
            )),
        }
    }
    outcome
}

/// Repair an updater's exact target manifest while retaining every target
/// lock until the ledger fingerprints are verified and the caller atomically
/// clears its durable marker. This closes the window where a normal setup
/// writer could change a just-repaired config between verification and clear.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn remerge_mcp_targets_exact_with_finalizer(
    targets: &[McpRepairTarget],
    finalizer: impl FnOnce() -> Result<()>,
) -> Result<Vec<PathBuf>> {
    let topology = McpTopologyLock::acquire()?;
    remerge_mcp_targets_exact_with_topology_and_finalizer(targets, &topology, finalizer)
}

pub(crate) fn remerge_mcp_targets_exact_with_topology_and_finalizer(
    targets: &[McpRepairTarget],
    topology: &McpTopologyLock,
    finalizer: impl FnOnce() -> Result<()>,
) -> Result<Vec<PathBuf>> {
    let mut targets = normalize_mcp_repair_targets(targets.iter().cloned())?;
    if targets.is_empty() {
        anyhow::bail!("MCP repair manifest is empty");
    }
    // A crash can release the topology guard after the marker is persisted.
    // Recapture under the new guard and include paths configured since the
    // journal snapshot. Existing marker paths retain their captured binding,
    // so a stale A -> B rebind still fails its precondition instead of being
    // silently refreshed to broader authority.
    let captured_paths = targets
        .iter()
        .map(|target| target.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for current in current_mcp_repair_targets_excluding_with_topology(topology, &captured_paths)? {
        targets.push(current);
    }
    targets = normalize_mcp_repair_targets(targets)?;
    targets.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.id.cmp(&right.id))
    });
    if targets.windows(2).any(|pair| pair[0].path == pair[1].path) {
        anyhow::bail!("MCP repair manifest assigns one config path to multiple clients");
    }
    for target in &targets {
        if target.id == "antigravity_workspace" {
            ensure_workspace_mcp_git_excluded(
                target
                    .repo_root
                    .as_deref()
                    .context("workspace MCP repair target has no repository root")?,
            )?;
        }
    }
    let target_paths = targets
        .iter()
        .map(|target| target.path.clone())
        .collect::<Vec<_>>();
    let mut locks = ConfigLock::acquire_many(&target_paths)?;
    let command = managed_mcp_launcher()?;
    // Validate every capture precondition before writing the first target. A
    // concurrent/user rebind (especially Codex repo A -> B) therefore retains
    // the marker and all configs rather than partially replaying stale state.
    for (target, lock) in targets.iter().zip(&locks) {
        validate_mcp_repair_precondition(target, lock, &command)?;
    }
    let mut repaired = Vec::with_capacity(targets.len());
    for (target, lock) in targets.iter().zip(&mut locks) {
        if target.id == "codex" {
            merge_codex_mcp_target_locked(target, &command, lock)?;
        } else {
            merge_json_mcp_target_locked(target, &command, lock)?;
        }
        lock.refresh_locked_state()?;
        repaired.push(target.path.clone());
    }
    if !mcp_repair_targets_ledger_verified_with_locks(&targets, &locks)? {
        anyhow::bail!("MCP config repair completed but setup-ledger fingerprints are not verified");
    }
    finalizer()?;
    Ok(repaired)
}

fn validate_mcp_repair_precondition(
    target: &McpRepairTarget,
    lock: &ConfigLock,
    command: &str,
) -> Result<()> {
    let bytes = lock
        .original_bytes(&target.path)?
        .with_context(|| format!("captured MCP config disappeared: {}", target.path.display()))?;
    let digest = crate::commands::setup_ledger::sha256_hex(&bytes);
    if digest == target.captured_config_sha256 {
        return Ok(());
    }
    let current = read_kin_mcp_entry_from_bytes(&target.path, &bytes).with_context(|| {
        format!(
            "captured Kin MCP entry disappeared from {}",
            target.path.display()
        )
    })?;
    if mcp_entry_matches_repair_target(&current, target, command) {
        return Ok(());
    }
    anyhow::bail!(
        "MCP config {} changed after updater capture; stale repair authority was refused and the durable marker was retained",
        target.path.display()
    )
}

fn mcp_entry_matches_repair_target(
    entry: &serde_json::Value,
    target: &McpRepairTarget,
    command: &str,
) -> bool {
    if entry.get("command").and_then(serde_json::Value::as_str) != Some(command)
        || entry
            .get("env")
            .and_then(|env| env.get("KIN_MCP_TOOL_PROFILE"))
            .and_then(serde_json::Value::as_str)
            != Some("agent-default")
    {
        return false;
    }
    let expected_args = match target.repo_root.as_deref() {
        Some(repo_root) => {
            serde_json::json!(["mcp", "start", "--repo", repo_root.to_string_lossy()])
        }
        None => serde_json::json!(["mcp", "start"]),
    };
    if entry.get("args") != Some(&expected_args) {
        return false;
    }
    match target.repo_root.as_deref() {
        Some(repo_root) if target.id == "antigravity_workspace" => {
            entry.get("cwd").and_then(serde_json::Value::as_str)
                == Some(repo_root.to_string_lossy().as_ref())
        }
        _ => true,
    }
}

pub(crate) fn remerge_existing_mcp_configs_detailed() -> McpRemergeOutcome {
    match current_mcp_repair_targets() {
        Ok(targets) if !targets.is_empty() => remerge_mcp_targets_with_launcher(
            &targets,
            configured_mcp_launcher,
            "configured installation",
        ),
        Ok(_) => McpRemergeOutcome::default(),
        Err(error) => McpRemergeOutcome {
            errors: vec![format!("could not capture MCP targets: {error:#}")],
            ..Default::default()
        },
    }
}

#[cfg(all(test, unix))]
pub(crate) fn mcp_repair_targets_ledger_verified(targets: &[McpRepairTarget]) -> Result<bool> {
    let mut targets = normalize_mcp_repair_targets(targets.iter().cloned())?;
    if targets.is_empty() {
        return Ok(false);
    }
    targets.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.id.cmp(&right.id))
    });
    let target_paths = targets
        .iter()
        .map(|target| target.path.clone())
        .collect::<Vec<_>>();
    let locks = ConfigLock::acquire_many(&target_paths)?;
    mcp_repair_targets_ledger_verified_with_locks(&targets, &locks)
}

fn mcp_repair_targets_ledger_verified_with_locks(
    targets: &[McpRepairTarget],
    locks: &[ConfigLock],
) -> Result<bool> {
    use crate::commands::setup_ledger::{
        verify_entry_locked, ArtifactKind, EntryState, SetupLedger,
    };

    if targets.is_empty() || targets.len() != locks.len() {
        return Ok(false);
    }
    let ledger = SetupLedger::load(&crate::commands::setup_ledger::ledger_path()?)?;
    for (target, lock) in targets.iter().zip(locks) {
        let Some(entry) = ledger.entries.iter().find(|entry| {
            entry.kind == ArtifactKind::McpConfig
                && entry.target == target.id
                && entry.path == target.path
        }) else {
            return Ok(false);
        };
        if verify_entry_locked(entry, lock)?.state != EntryState::Verified {
            return Ok(false);
        }
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Auto-daemon config
// ---------------------------------------------------------------------------

/// Record the daemon auto-start choice in `~/.kin/config/setup.toml`.
///
/// A read-modify-write rather than a rewrite. This file used to hold one
/// setting and was replaced wholesale on every `kin setup` run, which was
/// harmless while it was the only writer. It now also carries the recorded
/// projection mode, and a rewrite would have discarded that mode the next time
/// anyone ran setup, silently returning the machine to the fallback order.
fn write_auto_daemon_config(enabled: bool) -> Result<()> {
    let kin_home = kin_dir()?;
    let config_dir = kin_home.join("config");
    fs::create_dir_all(&config_dir).context("failed to create ~/.kin/config/")?;
    let config_path = config_dir.join("setup.toml");
    let body = fs::read_to_string(&config_path).unwrap_or_default();
    let content = crate::commands::projection::config_set(
        &body,
        "daemon",
        "auto_start",
        toml::Value::Boolean(enabled),
    )?;
    fs::write(&config_path, content)
        .with_context(|| format!("failed to write {}", config_path.display()))?;
    Ok(())
}

/// Choose the projection this host should use, prove the choice, and record it.
///
/// Setup is where a machine's projection is decided, because it is the one
/// moment a person is present and the one moment Kin knows what this host can
/// actually run. The choice is made from probes that execute the driver rather
/// than from paths that would tell setup what it hoped to hear, and what setup
/// picked is printed with the evidence, including the modes it could not use
/// and why. Recording it is what lets `kin doctor` later say that a configured
/// projection is not working, which it cannot say about a mode nobody chose.
/// The one honest recording decision setup can make, extracted so a test can
/// hold it still: a recording claims the mode RUNS, setup engages nothing, and
/// the shim is the only mode in force by mere installation. A mode an earlier
/// `kin vfs on` recorded is kept even when it is a mount mode, because the
/// chooser fed it in and it was recorded at a moment it actually engaged.
pub(crate) fn projection_mode_to_record(
    already: Option<crate::commands::projection::ProjectionMode>,
    chosen: crate::commands::projection::ProjectionMode,
    shim_available: bool,
) -> Option<crate::commands::projection::ProjectionMode> {
    use crate::commands::projection::ProjectionMode;
    if already == Some(chosen) {
        return Some(chosen);
    }
    if chosen == ProjectionMode::Shim {
        return Some(ProjectionMode::Shim);
    }
    shim_available.then_some(ProjectionMode::Shim)
}

fn record_projection_choice() -> Result<()> {
    use crate::commands::projection;

    let kin_home = kin_dir()?;
    let exe = std::env::current_exe().ok();
    let driver = projection::probe_driver(&kin_home, exe.as_deref());
    let shim = projection::probe_shim(&kin_home);
    let modes = projection::probe_modes(&driver, &shim);
    let (_, chosen) = projection::choose_mode(None, projection::recorded_mode(&kin_home), &modes);

    println!("Filesystem projection:");
    for probe in &modes {
        let mark = if probe.available {
            style("✓").green()
        } else {
            style("✗").red()
        };
        println!("  {mark} {:<5} {}", probe.mode.as_str(), probe.evidence);
    }
    if modes.iter().any(|probe| probe.available) {
        // A recorded mode is a claim that this host RUNS it, and setup engages
        // nothing: the shim is the one mode in force the moment it is
        // installed, because it injects per process and needs no server and no
        // mount. Recording a mount mode here is what made every fresh macOS
        // and Windows install read `projection_mode=misconfigured` in `kin
        // doctor` (the v0.5.41 release install proof failed on exactly that),
        // since the chooser preferred nfs or projfs and nothing had mounted
        // them. So setup records the shim when it is available and prints the
        // preferred mount mode as the upgrade path; `kin vfs on` records that
        // mode itself at the moment it actually engages. A mode an earlier
        // `kin vfs on` already recorded is kept: the chooser fed it in, and
        // overwriting a deliberate choice with the shim would un-configure a
        // machine that was configured on purpose.
        let already = projection::recorded_mode(&kin_home);
        let shim_available = modes
            .iter()
            .any(|probe| probe.mode == projection::ProjectionMode::Shim && probe.available);
        let to_record = projection_mode_to_record(already, chosen, shim_available);
        match to_record {
            Some(mode) => {
                projection::record_mode(&kin_home, mode)?;
                println!("  Using {mode}: {}", mode.description());
                if mode == chosen {
                    println!("  Change it with `kin vfs on --mode <shim|nfs|fuse>`.");
                } else {
                    println!(
                        "  {chosen} is available: engage it with `kin vfs on --mode {chosen}`,                          which records it once it is actually running."
                    );
                }
            }
            None => {
                println!(
                    "  {chosen} is available but needs `kin vfs on --mode {chosen}` to engage;                      nothing is recorded until a projection is actually running."
                );
            }
        }
    } else {
        // Nothing is recorded when nothing works. A recorded mode is a claim
        // that this host runs it, and `kin doctor` reads a recording that does
        // not run as a defect. Writing one here would manufacture that defect
        // on a machine the installer deliberately shipped without projection.
        println!(
            "  No projection is available on this host. The CLI and daemon answer from the graph \
             without one."
        );
    }
    println!();
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

    let configured_assistants =
        apply_plan(&plan, &assistants, shell_name, !opts.skip_mcp_check).await?;

    print_intent_followups(&plan, interactive);

    // Language servers are what turn Kin's cross-file answers from bare-name
    // matches into resolved ones, and setup is the one moment a person is
    // present to consent to the download. Skipping this step is what shipped
    // before: the adapter was wired, no server was installed, the daemon logged
    // the failed start at debug level, and every cross-file call fell back to
    // matching names.
    provision_language_servers_in_wizard(&opts, interactive).await;

    report_notification_identity(interactive);

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

/// Offer the missing language servers during first-run setup.
///
/// Interactive runs ask per install command with the download disclosed.
/// Non-interactive runs print the command and change nothing unless
/// `--install-language-servers` was passed, because an unattended install
/// should never spend a user's bandwidth on a prefix they share with the rest
/// of their toolchain.
async fn provision_language_servers_in_wizard(opts: &WizardOptions, interactive: bool) {
    let missing = language_servers::missing_enrichable_languages();
    if missing.is_empty() {
        return;
    }
    println!();
    println!("Language servers (cross-file reference edges):");
    let consent = language_servers::InstallConsent::resolve(
        opts.install_language_servers,
        interactive && !opts.install_language_servers,
    );
    let outcome = apply_language_server_provisioning(&missing, consent).await;
    for line in &outcome.applied {
        println!("  {} {line}", style("✓").green());
    }
    outcome.print_unfinished();
}

/// Get the notification identity working, and say so when it cannot be.
///
/// Three things have to be true for a notification to arrive as Kin: the bundle
/// has to exist, macOS has to know about it, and the user has to have allowed
/// it. Setup is where all three are settled, because it is the one moment a
/// person is present. When the first is not true, the remaining two cannot be
/// fixed here, so the gap is reported instead of silently skipped.
fn report_notification_identity(interactive: bool) {
    if !cfg!(target_os = "macos") {
        return;
    }
    let Ok(notifier) = kin_notify::Notifier::new() else {
        return;
    };
    if let Some(degradation) = notifier.status().degradation() {
        println!();
        println!("  {} {degradation}", style("!").yellow());
        return;
    }
    // The managed installer registers what it writes; a channel that installs
    // into its own prefix, such as a Homebrew formula, cannot, so setup does it
    // for whichever copy is actually resolved. It is not worth failing setup
    // over, but a silent failure would leave the authorization step below
    // asking about a bundle macOS does not know.
    if let Err(error) = notifier.register_with_launch_services() {
        println!("  {} {error:#}", style("!").yellow());
    }
    request_notification_authorization(interactive);
}

/// Ask macOS for permission to post notifications, once, from the one place a
/// person is definitely present.
///
/// This is deliberately confined to interactive setup. macOS records a
/// dismissed authorization prompt as a permanent denial, and an app denied that
/// way is not listed in System Settings, so there is no supported way to undo
/// it. A prompt raised by a background job at 3am would therefore burn the
/// bundle identity with nobody there to answer, which is why nothing else in
/// Kin ever requests authorization.
///
/// Never fails setup: an unavailable or declined notifier only costs the nicer
/// sender identity, and the router still delivers through its fallback.
fn request_notification_authorization(interactive: bool) {
    if !cfg!(target_os = "macos") || !interactive {
        return;
    }
    let Ok(notifier) = kin_notify::Notifier::new() else {
        return;
    };
    // Resolved rather than assumed: a channel that cannot write to the home
    // directory installs its bundle beside the binary, and that copy holds the
    // same identity the authorization decision is recorded against.
    let Some(executable) = notifier.resolve_notifier() else {
        return;
    };

    // Only ask when the decision has not already been made; re-running setup
    // must not nag, and macOS answers from the stored decision anyway.
    let already_decided = std::process::Command::new(&executable)
        .arg("--status")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| !String::from_utf8_lossy(&out.stdout).contains("not_determined"))
        .unwrap_or(true);
    if already_decided {
        return;
    }

    println!();
    println!("  macOS will ask whether Kin may send you notifications.");
    println!("  These are update and health alerts; Kin posts nothing else.");
    let granted = std::process::Command::new(&executable)
        .arg("--request-authorization")
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if granted {
        println!("  {} Notifications will arrive as Kin", style("✓").green());
    } else {
        println!(
            "  {} Notifications declined; Kin will stay quiet",
            style("·").dim()
        );
    }
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
    verify_mcp_round_trip: bool,
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
    // Assistant indices whose MCP server this run actually registered. Gates the
    // discovery reminders below so a directive is never written for a client
    // Kin did not wire up.
    let mut registered_clients: Vec<usize> = Vec::new();
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
                        "  {} {}",
                        style("✓").green(),
                        client_write_summary(a.name, a.detected, &path)
                    );
                    // Which repository a client ends up bound to is decided by
                    // the directory this ran in, and nothing said so. A later
                    // run from a different directory rebound the client
                    // silently, and the only visible consequence was a health
                    // report calling a fresh, successful setup drifted. Name
                    // the repository where the choice is actually made.
                    if let Some(repo) = bound_repo_for_mcp_config(&path) {
                        println!("      bound to repository {}", repo.display());
                    }
                    registered_clients.push(*idx);
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

        // Writing the entry is not the same as the entry working. A recorded
        // launcher that no longer exists, or a server that cannot hold a
        // handshake, leaves a config file that reads as perfectly valid while
        // every call the agent makes fails, and setup used to report that as a
        // configured client. Launch each entry the way its client would and
        // report what one real tool call answered.
        let registered: Vec<(String, PathBuf)> = configured_assistants
            .iter()
            .filter_map(|(name, path)| path.clone().map(|path| (name.clone(), path)))
            .collect();
        let proofs = crate::commands::setup_verify::prove_registered_clients(
            &registered,
            verify_mcp_round_trip,
        );
        crate::commands::setup_verify::print_proofs(&proofs);
    }

    // Agent discovery reminders.
    //
    // The reminder is a standing behavioral directive: it tells the agent to
    // reach for Kin's semantic MCP tools before grep or raw file reads, in every
    // repository, for every session. That instruction is only true for a client
    // whose MCP server is actually registered, so each instruction file is gated
    // on its own client's registration succeeding this run. Writing it for an
    // unregistered client aims the agent at tools that are not wired, and every
    // call it makes fails.
    let mut written_reminders: Vec<(&'static str, PathBuf)> = Vec::new();
    if plan.inject_discovery_reminders {
        println!("Agent discovery reminders:");
        written_reminders = apply_discovery_reminders(&home_dir()?, &registered_clients);
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

    println!();
    if let Err(e) = record_projection_choice() {
        println!(
            "  {} could not settle the projection mode: {e}",
            style("!").yellow()
        );
    }

    // Record what we wrote into the install ledger so `kin doctor` can verify it
    // and `kin setup uninstall` can remove exactly it.
    record_setup_ledger(plan, shell_name, &written_reminders);

    Ok(configured_assistants)
}

/// Read the kin MCP server sub-value from a client config, if present.
///
/// Handles both JSON configs (`mcpServers.kin`) and TOML configs such as
/// Codex's `config.toml` (`mcp_servers.kin`), normalizing the entry to JSON
/// for the install ledger.
pub(crate) fn read_kin_mcp_entry_from_bytes(
    path: &Path,
    content: &[u8],
) -> Option<serde_json::Value> {
    if path.extension().and_then(|e| e.to_str()) == Some("toml") {
        let root: toml::Value = toml::from_str(std::str::from_utf8(content).ok()?).ok()?;
        let entry = root.get("mcp_servers")?.get("kin")?;
        return serde_json::to_value(entry).ok();
    }
    let root: serde_json::Value = serde_json::from_slice(content).ok()?;
    root.get("mcpServers")?.get("kin").cloned()
}

#[cfg(test)]
fn read_kin_mcp_entry(path: &Path) -> Option<serde_json::Value> {
    let content = fs::read(path).ok()?;
    read_kin_mcp_entry_from_bytes(path, &content)
}

/// Record everything the applied [`SetupPlan`] wrote into the install ledger.
///
/// Re-derives each artifact from final on-disk state and upserts it, preserving
/// original install timestamps across idempotent re-runs. Ledger failures are
/// non-fatal: setup already succeeded, so a ledger write error is a warning, not
/// a setup failure.
///
/// `written_reminders` carries the instruction files this run actually appended
/// to, as `(ledger target, path)`. Only those are recorded, so the ledger never
/// claims an artifact the registration gate declined to write. Entries recorded
/// by an earlier run survive regardless: [`SetupLedger::record`] upserts and
/// never prunes, so `kin setup uninstall` can still remove a reminder appended
/// before that gate existed.
fn record_setup_ledger(
    plan: &SetupPlan,
    shell_name: &str,
    written_reminders: &[(&'static str, PathBuf)],
) {
    use crate::commands::setup_ledger::{ArtifactKind, LedgerEntry, SetupLedger};

    let Ok(ledger_path) = crate::commands::setup_ledger::ledger_path() else {
        return;
    };
    let update = SetupLedger::update(&ledger_path, |ledger| {
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

                    // The PATH line is recorded against every file it was
                    // actually written to, which for zsh is `.zshenv` rather
                    // than the file carrying the hook and for bash is the login
                    // file as well as `.bashrc`. Recording it against the hook's
                    // file alone would leave uninstall excising a block from one
                    // file while the real ones stayed behind. The entries share
                    // a target name and differ by path, which is what the
                    // ledger's `(kind, target, path)` identity is for.
                    for path_rc in shell_path_rcs(shell_name).unwrap_or_default() {
                        let bin_dir = kin_home.join("bin");
                        let path_block = rc_path_block(shell_name, &bin_dir);
                        let path_present = fs::read_to_string(&path_rc)
                            .map(|c| c.contains(&path_block))
                            .unwrap_or(false);
                        if path_present {
                            ledger.record(LedgerEntry::appended(
                                ArtifactKind::ShellPathLine,
                                format!("{shell_name}-path"),
                                path_rc,
                                path_block,
                            ));
                        }
                    }
                }
            }
        }

        if plan.inject_discovery_reminders {
            for (target, path) in written_reminders {
                if discovery_reminder_present(path) {
                    ledger.record(LedgerEntry::appended(
                        ArtifactKind::DiscoveryReminder,
                        *target,
                        path.clone(),
                        KIN_DISCOVERY_REMINDER,
                    ));
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

        Ok(())
    });
    if let Err(e) = update {
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
        IDX_CODEX => Some(home.join(".codex").join("config.toml")),
        IDX_GEMINI => Some(home.join(".gemini").join("settings.json")),
        IDX_WINDSURF => Some(
            home.join(".codeium")
                .join("windsurf")
                .join("mcp_config.json"),
        ),
        IDX_ANTIGRAVITY => Some(home.join(".gemini").join("config").join("mcp_config.json")),
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
        IDX_ANTIGRAVITY => Some(configure_antigravity()),
        _ => None,
    }
}

/// Intent-specific guidance shown before the health checklist, driven by the
/// applied [`SetupPlan`].
fn print_intent_followups(plan: &SetupPlan, interactive: bool) {
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
        let base_url = super::auth::hosted_base_url(None);
        match super::auth::hosted_credential_state(&base_url, interactive) {
            Ok(state) => {
                for line in hosted_followup_lines(&base_url, &state) {
                    println!("  {} {}", style("→").cyan(), line);
                }
            }
            Err(error) => {
                println!(
                    "  {} could not read the stored KinLab credential for {base_url}: {error}",
                    style("!").yellow()
                );
                println!("    `kin auth status` reports the same state directly.");
            }
        }
    }
}

/// Hosted follow-ups, rendered from what this machine actually knows about a
/// KinLab identity. Kept separate from printing so the wording is testable
/// without touching a credential store.
fn hosted_followup_lines(
    base_url: &str,
    state: &super::auth::HostedCredentialState,
) -> Vec<String> {
    match state {
        super::auth::HostedCredentialState::Ready {
            user_email,
            expires_at,
        } => vec![
            format!("Signed in to {base_url} as {user_email} (credential expires {expires_at})."),
            "`kin auth whoami` confirms the account the workspace sees.".to_string(),
            "Add a native remote with `kin remote add <name> <url>`, then `kin push`.".to_string(),
        ],
        super::auth::HostedCredentialState::Locked => vec![
            format!("A stored credential for {base_url} is encrypted on this machine."),
            "`kin auth status` unlocks and reports it; `kin auth login` replaces it.".to_string(),
        ],
        super::auth::HostedCredentialState::Absent => vec![
            format!("Not signed in to {base_url}."),
            "`kin auth login` connects this machine, then `kin remote add <name> <url>`."
                .to_string(),
            "Another workspace: `kin auth login --base-url <url>`, or set KINLAB_URL.".to_string(),
        ],
        super::auth::HostedCredentialState::AbsentKeyringNotRead => vec![
            format!("No stored credential file for {base_url} on this machine."),
            "This run cannot answer a keychain prompt, so the platform keyring was not read; \
             `kin auth status` reports a keyring-stored credential."
                .to_string(),
            "`kin auth login` connects this machine, then `kin remote add <name> <url>`."
                .to_string(),
        ],
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
        HealthStatus::Pending => "PENDING",
        HealthStatus::Degraded => "DEGRADED",
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
            HealthStatus::Missing | HealthStatus::Misconfigured | HealthStatus::Degraded => {
                style("✗").red()
            }
            HealthStatus::Stale => style("!").yellow(),
            HealthStatus::Pending => style("…").yellow(),
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
    let readiness = readiness_line(report);
    let mark = if readiness.ready {
        style("✓").green()
    } else if readiness.severe {
        style("✗").red()
    } else {
        style("!").yellow()
    };
    println!("{mark} {}", readiness.sentence);
}

/// The closing readiness line, and how loudly to print it.
struct ReadinessLine {
    /// Whether the run may claim readiness at all.
    ready: bool,
    /// Whether the rows needing attention include a real failure rather than
    /// expected first-run work. Only the mark depends on it.
    severe: bool,
    sentence: String,
}

/// Compose the closing line from the rows the table just printed.
///
/// It used to be read off `report.healthy` alone, which asks a narrower
/// question than the table answers: `healthy` gates on Missing and
/// Misconfigured, so a container run whose `Reference edge coverage` row read
/// PENDING for want of a language server closed with "First-run ready" one line
/// under its own "4 need attention" tally, and the repair that would have
/// closed that row had failed in the same output (FIR-2547). The row knew; the
/// summary did not read it. A reader who trusts the last line is entitled to
/// have it agree with the rows above it, so claiming readiness now requires
/// that nothing at all needs attention, and the line names what does.
fn readiness_line(report: &crate::commands::health::HealthReport) -> ReadinessLine {
    use crate::commands::health::HealthStatus;

    /// How many rows the line names before it counts the rest.
    const NAMED: usize = 4;

    let summary = report.summary();
    let waiting: Vec<&crate::commands::health::HealthCheck> = report
        .checks
        .iter()
        .filter(|check| {
            !matches!(
                check.status,
                HealthStatus::Healthy | HealthStatus::Unsupported
            )
        })
        .collect();
    if report.healthy && summary.attention == 0 && waiting.is_empty() {
        return ReadinessLine {
            ready: true,
            severe: false,
            sentence: "First-run ready — no component is missing or misconfigured.".to_string(),
        };
    }
    let severe = !report.healthy
        || waiting.iter().any(|check| {
            matches!(
                check.status,
                HealthStatus::Missing | HealthStatus::Misconfigured | HealthStatus::Degraded
            )
        });
    let mut labels: Vec<String> = waiting
        .iter()
        .take(NAMED)
        .map(|check| check.label.clone())
        .collect();
    if waiting.len() > NAMED {
        labels.push(format!("and {} more", waiting.len() - NAMED));
    }
    let advice = if waiting.iter().any(|check| check.fixable) {
        "Run `kin doctor --fix` to apply safe repairs."
    } else {
        "Each row above carries the fix it needs."
    };
    let sentence = if waiting.len() == 1 {
        format!("1 check needs attention: {}. {advice}", labels.join(", "))
    } else {
        format!(
            "{} checks need attention: {}. {advice}",
            waiting.len(),
            labels.join(", ")
        )
    };
    ReadinessLine {
        ready: false,
        severe,
        sentence,
    }
}

/// A repair `kin doctor --fix` attempted and could not complete.
struct UnfinishedRepair {
    /// What Kin was trying to do, in the operator's terms.
    what: String,
    /// Why it did not happen, in the failing tool's own words where there were
    /// any to keep.
    reason: String,
    /// The commands that close it by hand.
    remediation: Vec<String>,
    /// Whether the operator asked for this repair by name.
    ///
    /// Only these set the exit code. `--fix` also runs a set of best-effort
    /// convergence repairs nobody asked for individually, and `kin update` runs
    /// `kin setup doctor --fix` unattended as the last step of its chain
    /// (`update::ChainStep::RepairConfigs`), where a VFS shim that could not be
    /// re-downloaded on an offline host must not report an installed release as
    /// a failed update. A requested repair is the opposite case: the operator
    /// typed `--install-language-servers` or answered the prompt, and silence
    /// about its failure is the defect FIR-2547 records.
    requested: bool,
}

/// Print what could not be repaired, with the commands that close it.
fn print_unfinished_repairs(unfinished: &[UnfinishedRepair]) {
    if unfinished.is_empty() {
        return;
    }
    println!();
    println!("Repairs that did not complete:");
    for repair in unfinished {
        println!("  {} {}: {}", style("✗").red(), repair.what, repair.reason);
        for line in &repair.remediation {
            println!("      {line}");
        }
    }
}

/// The exit verdict for a `--fix` run.
///
/// Non-zero when a repair the operator asked for did not happen. The run has
/// already printed what failed and what closes it; this is the half a script
/// can read, and the half whose absence let a run that installed nothing close
/// under a green tick.
fn fix_verdict(unfinished: &[UnfinishedRepair]) -> Result<()> {
    let requested: Vec<&UnfinishedRepair> = unfinished
        .iter()
        .filter(|repair| repair.requested)
        .collect();
    if requested.is_empty() {
        return Ok(());
    }
    let names = requested
        .iter()
        .map(|repair| repair.what.clone())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "{} requested repair{} did not complete: {names}",
        requested.len(),
        if requested.len() == 1 { "" } else { "s" }
    )
}

/// Provision the language servers behind Kin's cross-file reference edges, and
/// report each one in the operator's own words.
///
/// Shared by the wizard and by `kin doctor --fix` so a person gets the same
/// disclosure, the same prompt, and the same restart advice on both paths. The
/// returned lines are the "what was applied" list both surfaces already print;
/// anything not applied is printed here instead, because a declined or failed
/// install is a fact the operator needs and an empty applied-list is not.
/// Ask a running daemon to re-probe and re-enrich after a server was installed.
///
/// Readiness taken once latches: a daemon that probed before the install would
/// keep reporting that language unavailable for the rest of its life, and that
/// stale answer is an input under an agent-facing verdict. The sweep route
/// re-probes at its start, so one call refreshes the verdict and produces the
/// edges the new server can finally resolve.
///
/// Returns whether a daemon was actually poked, so the caller can fall back to
/// telling the user to restart when there was none.
async fn refresh_running_daemon_after_install(cwd: &std::path::Path) -> bool {
    let Some(layout) = kin_core::KinLayout::discover(cwd) else {
        return false;
    };
    let Some(url) = crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await else {
        return false;
    };
    // For_layout, not from_base_url: the latter resolves the bearer token from
    // the process working directory, which is the silent-wrong-target class
    // that made kin init's conversion phase 401 on runners.
    let Ok(client) = crate::daemon_client::DaemonClient::from_base_url_for_layout(&url, &layout)
    else {
        return false;
    };
    match client.queue_lsp_sweep().await {
        Ok(_) => {
            println!(
                "  {} asked the running daemon to re-check its language servers and enrich again",
                style("✓").green()
            );
            true
        }
        Err(_) => false,
    }
}

/// What one provisioning pass applied, and what it could not.
#[derive(Default)]
struct ProvisioningOutcome {
    applied: Vec<String>,
    unfinished: Vec<UnfinishedRepair>,
}

impl ProvisioningOutcome {
    /// Print the remedies for what did not happen, for surfaces with no
    /// closing block of their own.
    fn print_unfinished(&self) {
        for repair in &self.unfinished {
            for line in &repair.remediation {
                println!("      {line}");
            }
        }
    }
}

async fn apply_language_server_provisioning(
    missing: &[kin_model::LanguageId],
    consent: language_servers::InstallConsent,
) -> ProvisioningOutcome {
    use language_servers::{InstallConsent, InstallOutcome};

    if missing.is_empty() {
        return ProvisioningOutcome::default();
    }

    if consent == InstallConsent::Withheld {
        // Nobody to ask and no flag. Say what is missing and what closes it,
        // and change nothing. Printing the command is the whole value here: the
        // gap was already reported, the command was not.
        println!(
            "  {} no language server for {}; cross-file reference edges are unavailable for {}",
            style("!").yellow(),
            missing
                .iter()
                .map(|language| language.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            if missing.len() == 1 { "it" } else { "them" }
        );
        for command in language_servers::install_commands_for(missing) {
            println!("      {command}");
        }
        println!(
            "      or re-run with --install-language-servers to have Kin run {}",
            if missing.len() == 1 { "it" } else { "them" }
        );
        return ProvisioningOutcome::default();
    }

    let reports = language_servers::provision(
        missing,
        consent,
        |recipe| recipe.installed(),
        |recipe| recipe.installer_available(),
        |recipe| {
            println!();
            println!(
                "  Kin can enrich {} with cross-file reference edges, but its language server is \
                 not installed.",
                recipe.language
            );
            println!("    Command:    {}", recipe.command_line());
            println!("    This will:  {}", recipe.disclosure);
            prompt_yn("  Install it now?", false, true)
        },
        language_servers::run_install,
    );

    let mut applied = Vec::new();
    let mut unfinished: Vec<UnfinishedRepair> = Vec::new();
    let mut installed_any = false;
    for report in reports {
        let recipe = language_servers::recipe_for(report.language);
        match report.outcome {
            InstallOutcome::AlreadyPresent => {}
            InstallOutcome::Installed { command } => {
                installed_any = true;
                applied.push(format!(
                    "installed the {} language server (`{command}`)",
                    report.language
                ));
            }
            // A zero exit that left the binary unreachable is reported as the
            // gap it still is. Counting it as applied is how a closed-looking
            // row keeps an open gap.
            InstallOutcome::RanButStillMissing { command } => {
                println!(
                    "  {} `{command}` succeeded but no {} server is on PATH",
                    style("✗").red(),
                    report.language
                );
                unfinished.push(UnfinishedRepair {
                    what: format!("install the {} language server", report.language),
                    reason: format!(
                        "`{command}` reported success and no {} server is on PATH",
                        report.language
                    ),
                    remediation: recipe
                        .map(language_servers::unreachable_after_install_remediation)
                        .unwrap_or_default(),
                    requested: true,
                });
            }
            InstallOutcome::Failed { command, reason } => {
                println!(
                    "  {} could not install the {} language server: {reason}",
                    style("✗").red(),
                    report.language
                );
                let remediation = recipe
                    .map(|recipe| language_servers::install_failure_remediation(recipe, &reason))
                    .unwrap_or_else(|| {
                        vec![format!(
                            "run `{command}` yourself to see the installer's own error"
                        )]
                    });
                unfinished.push(UnfinishedRepair {
                    what: format!("install the {} language server", report.language),
                    reason,
                    remediation,
                    requested: true,
                });
            }
            InstallOutcome::Declined { command } => println!(
                "  {} skipped the {} language server; run `{command}` to install it later",
                style("-").dim(),
                report.language
            ),
            InstallOutcome::NoInstaller { program, command } => {
                println!(
                    "  {} `{program}` is not installed, so Kin cannot run `{command}` to \
                     provision the {} language server",
                    style("✗").red(),
                    report.language
                );
                unfinished.push(UnfinishedRepair {
                    what: format!("install the {} language server", report.language),
                    reason: format!("`{program}` is not installed on this host"),
                    remediation: vec![format!("install `{program}`, then run `{command}`")],
                    // Consent was never asked for here, so only the flag makes
                    // this a repair the operator requested.
                    requested: consent == InstallConsent::Granted,
                });
            }
        }
    }

    // An install that lands a binary the server cannot run is not a completed
    // install. `RanButStillMissing` above already refuses to count a zero exit
    // that left nothing on PATH; this is its sibling, a zero exit that left
    // something on PATH which cannot start. Both are the same mistake: counting
    // a command's exit code as the outcome an operator cares about.
    //
    // Probed rather than looked up, because binary presence is exactly what
    // cannot tell these apart, and this is the surface where the wrong answer
    // ends the interaction with the user believing they are done.
    if installed_any {
        use kin_core::reference_coverage::LanguageServerReadiness;
        let cwd = std::env::current_dir().unwrap_or_default();
        let readiness = language_servers::probe_language_server_readiness(&cwd).await;
        let mut unusable = false;
        for language in missing {
            if let Some(LanguageServerReadiness::Unusable { reason }) = readiness.get(language) {
                unusable = true;
                applied.retain(|line| !line.contains(&language.to_string()));
                println!(
                    "  {} the {language} language server installed but did not start: {reason}",
                    style("✗").red(),
                );
                unfinished.push(UnfinishedRepair {
                    what: format!("install a working {language} language server"),
                    reason: format!("the server installed and refused to start: {reason}"),
                    remediation: vec![format!(
                        "the binary is on PATH and cannot serve {language}; the server's own \
                         message above names what it could not find"
                    )],
                    requested: true,
                });
            }
        }
        if !unusable {
            // Poke the sweep the daemon already exposes, rather than only
            // telling the user to restart. That one route re-probes readiness
            // AND re-enriches, which is exactly what someone wants after
            // installing a server, and it is why no dedicated route is needed.
            //
            // Best effort by design: outside a repository, or with no daemon
            // running, there is nothing holding a stale verdict to refresh, and
            // the restart advice below still covers a daemon this process
            // cannot reach.
            let refreshed = refresh_running_daemon_after_install(&cwd).await;
            if !refreshed {
                println!("  {}", language_servers::RESTART_AFTER_INSTALL);
            }
        }
    }
    ProvisioningOutcome {
        applied,
        unfinished,
    }
}

// ---------------------------------------------------------------------------
// `kin setup doctor`
// ---------------------------------------------------------------------------

/// What one `doctor` run observed before deciding whether to install a language
/// server.
///
/// Every field is a fact the run already measured rather than a probe this rule
/// performs, so [`decide_language_server_request`] is testable with no daemon,
/// no repository and no host. That split is the fix for FIR-2502: the gate used
/// to decide in the same breath it acted, and every branch that decided "no"
/// acted by falling through, which at a terminal is indistinguishable from an
/// install that worked. Two strangers on v0.5.43 read that silence as success
/// and converted large repositories with no enrichment at all.
pub(crate) struct LanguageServerRequest {
    /// `--install-language-servers` was typed.
    pub(crate) requested: bool,
    /// `--fix` was typed, so this run is allowed to change the host.
    pub(crate) fixing: bool,
    /// A Kin repository was discovered from the working directory.
    ///
    /// Read with `KinLayout::discover`, the same test the health report itself
    /// uses to decide `NotInRepository`, so the two cannot drift apart without
    /// the shared function changing under both.
    pub(crate) in_repository: bool,
    /// The `reference_edge_coverage` row's status, absent when the report
    /// carried no such row.
    pub(crate) coverage_status: Option<crate::commands::health::HealthStatus>,
    /// Languages this build enriches whose server is absent from this HOST.
    ///
    /// Host-scoped rather than repository-scoped, because that is what
    /// [`language_servers::missing_enrichable_languages`] measures and what an
    /// install would actually change. The gate above it is repository-scoped,
    /// and every message below keeps the two apart on purpose.
    pub(crate) missing_on_host: Vec<kin_model::LanguageId>,
}

/// What the run should do about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LanguageServerDecision {
    /// Install servers for these languages, subject to consent.
    Install(Vec<kin_model::LanguageId>),
    /// Install nothing, and print these lines so the no-op is legible.
    Explain(Vec<String>),
    /// Install nothing and print nothing, because nobody asked.
    Silent,
}

/// Render a language list the way an operator reads it.
fn language_list(languages: &[kin_model::LanguageId]) -> String {
    languages
        .iter()
        .map(|language| language.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// What this host holds, phrased for the end of a sentence.
///
/// Stated from the measurement rather than from the repository, because the
/// install is host-wide and a reader who is told "nothing is missing" has to be
/// able to trust that about the machine, not about the directory they happen to
/// be standing in.
fn host_language_server_state(missing_on_host: &[kin_model::LanguageId]) -> String {
    if missing_on_host.is_empty() {
        "this host already has a server for every one".to_string()
    } else {
        format!(
            "this host is missing a server for {}",
            language_list(missing_on_host)
        )
    }
}

/// Decide what a run does about `--install-language-servers`, and say so.
///
/// Every message this returns is true in the state that produced it, and none
/// of them names a cause the run did not observe. The two facts that are easy
/// to conflate are kept apart everywhere: servers install per HOST, and the gap
/// that asks for them is measured per REPOSITORY.
pub(crate) fn decide_language_server_request(
    request: &LanguageServerRequest,
) -> LanguageServerDecision {
    use crate::commands::health::HealthStatus;

    // Pending and Stale are exactly the two states the coverage row takes when
    // a language-server gap was actually OBSERVED. Every other state either
    // read the graph and found nothing to close, or never read it at all, and
    // spending a user's bandwidth off the back of an unread row is the prompt
    // this gate exists to refuse.
    let gap_observed = matches!(
        request.coverage_status,
        Some(HealthStatus::Pending | HealthStatus::Stale)
    );

    if !request.fixing {
        // Installing downloads packages into a shared prefix, so it belongs
        // behind `--fix` with every other repair. What it does not get to do is
        // stay quiet about that: the flag was simply dead here before, and
        // `kin doctor --install-language-servers` printed an ordinary report
        // and exited 0 having installed nothing.
        if !request.requested {
            return LanguageServerDecision::Silent;
        }
        return LanguageServerDecision::Explain(vec![
            "Nothing installed. `--install-language-servers` only runs under `--fix`.".to_string(),
            "Run `kin doctor --fix --install-language-servers` to install them.".to_string(),
        ]);
    }

    if gap_observed && !request.missing_on_host.is_empty() {
        return LanguageServerDecision::Install(request.missing_on_host.clone());
    }

    // Nothing is going to be installed. Explain that only to a run that asked
    // for it. A bare `--fix` never raised the subject, and a line about a repair
    // nobody requested is noise on every healthy install.
    if !request.requested {
        return LanguageServerDecision::Silent;
    }

    if !request.in_repository {
        return LanguageServerDecision::Explain(vec![
            "Nothing installed. This directory is not inside a Kin repository, and Kin measures \
             the language-server gap per repository even though the servers install per host."
                .to_string(),
            format!(
                "Run `kin doctor --fix --install-language-servers` from a Kin repository. It \
                 checks {}, and {}.",
                language_list(&language_servers::enrichable_languages()),
                host_language_server_state(&request.missing_on_host)
            ),
        ]);
    }

    if request.missing_on_host.is_empty() {
        let mut lines = vec![format!(
            "Nothing to install. Every language this build enriches already has a server on this \
             host: {}.",
            language_list(&language_servers::enrichable_languages())
        )];
        if gap_observed {
            // The row is unhealthy for a reason no install closes. Saying which
            // way round it is matters: the reader came here to fix the gap, and
            // the gap is real, so sending them to the row that named it is the
            // only useful thing this run can do.
            lines.push(
                "This repository still reports a reference-edge gap, so read the Reference edge \
                 coverage row for what it names."
                    .to_string(),
            );
        }
        return LanguageServerDecision::Explain(lines);
    }

    // In a repository, servers missing from the host, and no gap to close. The
    // two ways that happens read differently and are kept apart, because only
    // one of them means the graph was actually consulted.
    if matches!(request.coverage_status, Some(HealthStatus::Healthy)) {
        let mut lines = vec![
            "Nothing to install. This repository's graph reports no reference-edge gap, and that \
             gap is what the install closes."
                .to_string(),
            format!(
                "This host is still missing a server for {}. Install by hand, or run this again \
                 from a repository whose Reference edge coverage row names the gap:",
                language_list(&request.missing_on_host)
            ),
        ];
        for command in language_servers::install_commands_for(&request.missing_on_host) {
            lines.push(format!("  {command}"));
        }
        return LanguageServerDecision::Explain(lines);
    }

    // The row exists and reports something other than a verdict from a graph it
    // read. `Unsupported` is the reachable one, and it is always phrased "n/a"
    // by the health check, so naming it as unread is the row's own claim rather
    // than a guess about a cause this run never saw.
    let headline = if matches!(request.coverage_status, Some(HealthStatus::Unsupported)) {
        "Nothing to install. Kin could not measure this repository's reference-edge coverage, so \
         it saw no gap to close."
    } else {
        "Nothing to install. This repository's Reference edge coverage row does not report a \
         language-server gap."
    };
    LanguageServerDecision::Explain(vec![
        headline.to_string(),
        format!(
            "Read that row above for what it does report. {}.",
            host_language_server_state(&request.missing_on_host)
        ),
    ])
}

/// Print an [`LanguageServerDecision::Explain`], and nothing otherwise.
///
/// Written to stderr on purpose. `kin doctor --json` promises a parseable
/// report on stdout, and a notice about a request that did nothing is a
/// diagnostic, not part of the report. Sending it to stdout would make the fix
/// for a silent no-op the cause of an unparseable one.
fn print_language_server_decision(decision: &LanguageServerDecision) {
    if let LanguageServerDecision::Explain(lines) = decision {
        for line in lines {
            eprintln!("{line}");
        }
    }
}

/// Read the facts this run measured about a language-server install request.
fn observe_language_server_request(
    fix: bool,
    install_language_servers: bool,
    report: &crate::commands::health::HealthReport,
) -> LanguageServerRequest {
    let cwd = env::current_dir().unwrap_or_default();
    LanguageServerRequest {
        requested: install_language_servers,
        fixing: fix,
        in_repository: kin_core::KinLayout::discover(&cwd).is_some(),
        coverage_status: report
            .checks
            .iter()
            .find(|check| check.id == "reference_edge_coverage")
            .map(|check| check.status.clone()),
        missing_on_host: language_servers::missing_enrichable_languages(),
    }
}

pub async fn doctor(fix: bool, install_language_servers: bool, json: bool) -> Result<()> {
    let report = crate::commands::health::run_health_checks().await;

    // Decided once, before the report is printed, so the one rule that governs
    // `--install-language-servers` sees the same facts on both sides of the
    // `--fix` branch. Skipped entirely when neither flag is present, so a plain
    // `kin doctor` still probes nothing it does not need (FIR-2502).
    let language_server_decision = if fix || install_language_servers {
        decide_language_server_request(&observe_language_server_request(
            fix,
            install_language_servers,
            &report,
        ))
    } else {
        LanguageServerDecision::Silent
    };

    if !fix {
        if json {
            println!("{}", serde_json::to_string_pretty(&report)?);
        } else {
            print_human_report(&report);
        }
        // Printed last, so a human reads it under the report rather than above
        // it. Before this, the flag was dead on this path: bound at the
        // signature, first read well past this return, and so a scripted
        // `kin doctor --install-language-servers` exited 0 having installed
        // nothing and said nothing.
        return Ok(());
    }

    // Apply only the safe, fixable repairs. Each maps to a check id family.
    println!("Applying safe repairs...");
    println!();
    let mut applied: Vec<String> = Vec::new();
    // Every repair below that fails records itself here, so the run closes
    // with what it could not do and the commands that close it, rather than
    // with a summary that never read its own attempts (FIR-2547).
    let mut unfinished: Vec<UnfinishedRepair> = Vec::new();

    let registry_needs_fix = report.checks.iter().any(|c| {
        c.id == "registry_authority"
            && c.fixable
            && !matches!(c.status, crate::commands::health::HealthStatus::Healthy)
    });
    if registry_needs_fix {
        match kin_core::registry::repair_registry_authority_permissions() {
            Ok(paths) => {
                for path in paths {
                    applied.push(format!(
                        "repaired registry authority permissions to 0600 ({})",
                        path.display()
                    ));
                }
            }
            Err(e) => {
                let reason = e.to_string();
                println!(
                    "  {} registry permission repair refused: {reason}",
                    style("✗").red()
                );
                unfinished.push(UnfinishedRepair {
                    what: "repair the registry authority permissions".to_string(),
                    reason,
                    remediation: vec![
                        "fix the owner and mode of the path named above, then run `kin doctor \
                         --fix` again"
                            .to_string(),
                    ],
                    requested: false,
                });
            }
        }
    }

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
            Err(e) => {
                let reason = e.to_string();
                println!(
                    "  {} shell hook reinstall failed: {reason}",
                    style("✗").red()
                );
                unfinished.push(UnfinishedRepair {
                    what: "reinstall the shell hook".to_string(),
                    reason,
                    remediation: vec![
                        "run `kin setup` to write the shell hook, or add Kin's bin directory to \
                         PATH by hand"
                            .to_string(),
                    ],
                    requested: false,
                });
            }
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
    // step — and never one that points back at `kin doctor --fix`.
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
                        let reason = e.to_string();
                        println!(
                            "  {} could not restore the VFS shim automatically: {reason}",
                            style("✗").red()
                        );
                        println!(
                            "      reinstall kin to restore it: \
                             curl -fsSL https://get.kinlab.dev/install | sh"
                        );
                        unfinished.push(UnfinishedRepair {
                            what: "restore the VFS shim".to_string(),
                            reason,
                            remediation: vec!["reinstall kin to restore it: curl -fsSL \
                                 https://get.kinlab.dev/install | sh"
                                .to_string()],
                            requested: false,
                        });
                    }
                }
            }
            Err(e) => {
                let reason = e.to_string();
                println!("  {} VFS shim reinstall failed: {reason}", style("✗").red());
                unfinished.push(UnfinishedRepair {
                    what: "reinstall the VFS shim".to_string(),
                    reason,
                    remediation: vec![
                        "reinstall kin to restore it: curl -fsSL https://get.kinlab.dev/install \
                         | sh"
                            .to_string(),
                    ],
                    requested: false,
                });
            }
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
            Err(e) => {
                let reason = e.to_string();
                println!("  {} kin-daemon start failed: {reason}", style("✗").red());
                unfinished.push(UnfinishedRepair {
                    what: "start the repository daemon".to_string(),
                    reason,
                    remediation: vec![
                        "run `kin status` in the repository to see the daemon's own error"
                            .to_string(),
                    ],
                    requested: false,
                });
            }
        }
    }

    // Install the language servers this build enriches with, when the operator
    // asked for it. Deliberately NOT part of the unconditional "safe repairs"
    // set above: every other repair here writes a file Kin already owns, while
    // this one downloads packages into a shared global prefix. `--fix` alone
    // prints the command; `--fix --install-language-servers` runs it, and an
    // interactive `--fix` asks.
    //
    // The gate itself, and the words for every state it declines to install in,
    // live in `decide_language_server_request` above. Both silent paths this
    // replaces (an `if` with no `else`, and an `if missing.is_empty()` whose
    // body was a comment) reported a no-op exactly the way a success reports
    // itself, which is FIR-2502.
    match &language_server_decision {
        LanguageServerDecision::Install(missing) => {
            let consent = language_servers::InstallConsent::resolve(
                install_language_servers,
                !install_language_servers && is_tty(),
            );
            let outcome = apply_language_server_provisioning(missing, consent).await;
            applied.extend(outcome.applied);
            unfinished.extend(outcome.unfinished);
        }
        LanguageServerDecision::Explain(_) | LanguageServerDecision::Silent => {
            print_language_server_decision(&language_server_decision);
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
    match cleanup_stale_daemons() {
        Ok(cleaned) if cleaned > 0 => {
            applied.push(format!("cleaned {cleaned} stale daemon(s)"));
        }
        Ok(_) => {}
        Err(e) => {
            let reason = e.to_string();
            println!(
                "  {} stale-daemon cleanup refused registry authority: {reason}",
                style("✗").red()
            );
            unfinished.push(UnfinishedRepair {
                what: "clean stale daemon records".to_string(),
                reason,
                remediation: vec![
                    "run `kin registry authority --fix` to repair the registry, then run `kin \
                     doctor --fix` again"
                        .to_string(),
                ],
                requested: false,
            });
        }
    }

    if applied.is_empty() {
        // "Nothing to repair automatically" belongs to a run that found nothing
        // to do. A run that attempted four repairs and failed all four printed
        // it directly under its own four failure lines (FIR-2512), which is the
        // same defect as the closing line that could not read its rows.
        if unfinished.is_empty() {
            println!("  Nothing to repair automatically.");
        } else {
            println!(
                "  {} nothing was repaired; {} repair{} did not complete, listed below.",
                style("✗").red(),
                unfinished.len(),
                if unfinished.len() == 1 { "" } else { "s" }
            );
        }
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
        // The verdict still applies: a JSON caller reads the exit code, and a
        // repair that did not happen is exactly what it would otherwise have to
        // infer from a report that cannot see the attempt.
        return fix_verdict(&unfinished);
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

    print_unfinished_repairs(&unfinished);

    fix_verdict(&unfinished)
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
fn cleanup_stale_daemons() -> Result<usize> {
    let mut cleaned = 0;
    let registry = kin_core::registry::KinRegistry::load()
        .map_err(|e| anyhow::anyhow!("failed to load registry: {e}"))?;
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
            if crate::daemon_client::remove_orphaned_daemon_port(&kin_root) {
                cleaned += 1;
            }
        }
    }
    Ok(cleaned)
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
#[derive(Debug, Clone, serde::Serialize)]
struct FullUninstallAction {
    kind: String,
    path: PathBuf,
    action: String,
    detail: String,
}

impl FullUninstallAction {
    fn new(kind: &str, path: impl Into<PathBuf>, action: &str, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            path: path.into(),
            action: action.to_string(),
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Clone)]
struct ValidatedInstallRoot {
    requested: PathBuf,
    path: PathBuf,
    exists: bool,
    identity: Option<InstallRootIdentity>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InstallRootIdentity {
    volume_or_device: u64,
    file_index_or_inode: u64,
}

#[cfg(unix)]
fn install_root_identity(path: &Path) -> Result<InstallRootIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect install root identity {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        anyhow::bail!(
            "install root is not a real non-symlink directory: {}",
            path.display()
        );
    }
    Ok(InstallRootIdentity {
        volume_or_device: metadata.dev(),
        file_index_or_inode: metadata.ino(),
    })
}

#[cfg(windows)]
fn install_root_identity(path: &Path) -> Result<InstallRootIdentity> {
    use std::mem::zeroed;
    use std::os::windows::fs::OpenOptionsExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };

    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .with_context(|| format!("failed to open install root identity {}", path.display()))?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("failed to inspect install root handle {}", path.display()));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
    {
        anyhow::bail!(
            "install root is not a real non-reparse directory: {}",
            path.display()
        );
    }
    Ok(InstallRootIdentity {
        volume_or_device: u64::from(info.dwVolumeSerialNumber),
        file_index_or_inode: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    })
}

#[cfg(not(any(unix, windows)))]
fn install_root_identity(path: &Path) -> Result<InstallRootIdentity> {
    let _ = path;
    anyhow::bail!("full uninstall root identity is unsupported on this platform")
}

fn normalize_install_root(path: &Path) -> Result<(PathBuf, bool)> {
    if !path.is_absolute() {
        anyhow::bail!(
            "full uninstall requires an absolute KIN_HOME, got {}",
            path.display()
        );
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                anyhow::bail!(
                    "refusing full uninstall through symlink install root {}",
                    path.display()
                );
            }
            if !metadata.is_dir() {
                anyhow::bail!(
                    "refusing full uninstall because KIN_HOME is not a directory: {}",
                    path.display()
                );
            }
            Ok((
                path.canonicalize().with_context(|| {
                    format!("failed to resolve Kin install root {}", path.display())
                })?,
                true,
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().context("KIN_HOME has no parent directory")?;
            let name = path
                .file_name()
                .context("KIN_HOME has no final path component")?;
            let parent = parent.canonicalize().with_context(|| {
                format!(
                    "failed to resolve parent of absent Kin install root {}",
                    path.display()
                )
            })?;
            Ok((parent.join(name), false))
        }
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect Kin install root {}", path.display())),
    }
}

fn valid_launcher_version_stamp(root: &Path) -> bool {
    let Ok(bin) = fs::symlink_metadata(root.join("bin")) else {
        return false;
    };
    if bin.file_type().is_symlink() || !bin.is_dir() {
        return false;
    }
    let path = root.join("bin/.kinlab-kin-version");
    let Ok(Some(observed)) = read_config_file_nofollow(&path, false) else {
        return false;
    };
    let Ok(version) = std::str::from_utf8(&observed.bytes) else {
        return false;
    };
    semver::Version::parse(version.trim().trim_start_matches('v')).is_ok()
}

fn valid_setup_ledger_marker(root: &Path) -> bool {
    let Ok(config) = fs::symlink_metadata(root.join("config")) else {
        return false;
    };
    if config.file_type().is_symlink() || !config.is_dir() {
        return false;
    }
    let path = root.join("config/setup-ledger.json");
    crate::commands::setup_ledger::SetupLedger::load(&path)
        .map(|ledger| !ledger.entries.is_empty())
        .unwrap_or(false)
}

fn incomplete_full_uninstall_artifacts(root: &Path) -> Result<Vec<PathBuf>> {
    let parent = root.parent().context("Kin install root has no parent")?;
    let mut artifacts = Vec::new();
    for entry in fs::read_dir(parent).with_context(|| {
        format!(
            "failed to inspect {} for incomplete Kin uninstall state",
            parent.display()
        )
    })? {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let token = name
            .strip_prefix(".kin-uninstall-retired-")
            .or_else(|| name.strip_prefix(".kin-uninstall-delete-"))
            .or_else(|| name.strip_prefix(".kin-uninstall-incomplete-"));
        let Some(token) = token else {
            continue;
        };
        if uuid::Uuid::parse_str(token).is_ok_and(|id| {
            id.get_version() == Some(uuid::Version::Random) && id.hyphenated().to_string() == token
        }) {
            artifacts.push(entry.path());
        }
    }
    Ok(artifacts)
}

fn validate_full_uninstall_root_at(
    requested: &Path,
    user_home: &Path,
    current_exe: Option<&Path>,
) -> Result<ValidatedInstallRoot> {
    let (root, exists) = normalize_install_root(requested)?;
    let canonical_home = user_home
        .canonicalize()
        .with_context(|| format!("failed to resolve user home {}", user_home.display()))?;

    // Removing the home directory or one of its ancestors is never a valid Kin
    // uninstall, regardless of a hostile or accidental KIN_HOME override.
    if canonical_home.starts_with(&root) {
        anyhow::bail!(
            "refusing full uninstall because KIN_HOME {} is the user home or one of its ancestors",
            root.display()
        );
    }

    let default_root = canonical_home.join(".kin");

    // A custom KIN_HOME has no enforceable ownership boundary: arbitrary user
    // data can be placed below an otherwise Kin-looking `lib/`, `state/`, or
    // `packages/` directory and is indistinguishable from runtime data. Never
    // authorize recursive deletion there. The ledger-scoped uninstall remains
    // available, followed by explicit operator review of the custom root.
    if root != default_root {
        anyhow::bail!(
            "refusing recursive full uninstall for custom KIN_HOME {}; run `kin setup uninstall` for ledger-owned artifacts, then review and remove that custom directory explicitly",
            root.display()
        );
    }

    let incomplete = incomplete_full_uninstall_artifacts(&root)?;
    if !incomplete.is_empty() {
        anyhow::bail!(
            "full uninstall is incomplete: retired managed state remains: {}; refusing to report fully_removed",
            incomplete
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if !exists {
        return Ok(ValidatedInstallRoot {
            requested: requested.to_path_buf(),
            path: root,
            exists: false,
            identity: None,
        });
    }
    let root_identity = install_root_identity(&root)?;

    let active_binary_is_managed = current_exe
        .and_then(|path| path.canonicalize().ok())
        .is_some_and(|path| {
            path.parent()
                .and_then(Path::parent)
                .is_some_and(|parent| parent == root)
                && path
                    .file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| matches!(name, "kin" | "kin.exe"))
        });
    // A path with a Kin-looking name is not ownership. Accept only an
    // authenticated running Kin executable inside this root, the launcher's
    // validated semantic-version stamp, or a valid non-empty setup ledger read
    // through the no-follow/private-file authority path.
    let has_strong_managed_proof = active_binary_is_managed
        || valid_launcher_version_stamp(&root)
        || valid_setup_ledger_marker(&root);
    if !has_strong_managed_proof {
        anyhow::bail!(
            "refusing to recursively remove KIN_HOME {}; no strong managed-install ownership proof was found",
            root.display()
        );
    }

    if install_root_identity(&root)? != root_identity {
        anyhow::bail!(
            "KIN_HOME {} changed while managed-install ownership was being validated",
            root.display()
        );
    }

    Ok(ValidatedInstallRoot {
        requested: requested.to_path_buf(),
        identity: Some(root_identity),
        path: root,
        exists: true,
    })
}

fn validate_full_uninstall_root() -> Result<ValidatedInstallRoot> {
    let requested = kin_dir()?;
    let home = home_dir()?;
    let current_exe = env::current_exe().ok();
    validate_full_uninstall_root_at(&requested, &home, current_exe.as_deref())
}

fn legacy_shell_path_targets(home: &Path) -> Vec<(String, PathBuf)> {
    let mut targets = std::collections::BTreeSet::new();
    targets.insert(("zsh".to_string(), home.join(".zshrc")));
    // zsh's PATH line lives here, so an uninstall that swept only `.zshrc`
    // would leave the export behind pointing at a directory it had removed.
    targets.insert(("zsh".to_string(), home.join(".zshenv")));
    targets.insert(("bash".to_string(), home.join(".bashrc")));
    // bash's PATH line also lives in whichever login file bash reads, and which
    // one that is depends on what existed when setup ran. An uninstall that
    // swept only `.bashrc` would leave the export behind in the file a login
    // shell is the one reading, so all three candidates are swept. Sweeping a
    // file Kin never wrote to costs nothing: the cleanup removes only exact
    // occurrences of Kin's own block and skips a file carrying none.
    for name in BASH_LOGIN_RCS {
        targets.insert(("bash".to_string(), home.join(name)));
    }
    targets.insert(("fish".to_string(), home.join(".config/fish/config.fish")));
    targets.insert((
        "powershell".to_string(),
        home.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1"),
    ));
    targets.insert((
        "powershell".to_string(),
        home.join(".config/powershell/Microsoft.PowerShell_profile.ps1"),
    ));
    if let Some(profile) = env::var_os("PROFILE").filter(|value| !value.is_empty()) {
        targets.insert(("powershell".to_string(), PathBuf::from(profile)));
    }
    targets.into_iter().collect()
}

fn cleanup_legacy_shell_path_blocks(
    home: &Path,
    install_root: &Path,
    dry_run: bool,
) -> Result<Vec<FullUninstallAction>> {
    let bin_dir = install_root.join("bin");
    let mut actions = Vec::new();
    for (shell, path) in legacy_shell_path_targets(home) {
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect shell config {}", path.display()))
            }
            Ok(metadata) if metadata.file_type().is_symlink() => {
                anyhow::bail!(
                    "refusing legacy PATH cleanup through symlink shell config {}",
                    path.display()
                )
            }
            Ok(metadata) if !metadata.is_file() => continue,
            Ok(_) => {}
        }

        let block = rc_path_block(&shell, &bin_dir);
        let lock = if dry_run {
            None
        } else {
            Some(ConfigLock::acquire(&path)?)
        };
        let original = match &lock {
            Some(lock) => lock.original_bytes(&path)?,
            None => read_config_file_nofollow(&path, false)?.map(|observed| observed.bytes),
        };
        let Some(original) = original else {
            continue;
        };
        let content = std::str::from_utf8(&original)
            .with_context(|| format!("shell config {} is not UTF-8", path.display()))?;
        let occurrences = content.matches(&block).count();
        if occurrences == 0 {
            continue;
        }
        if !dry_run {
            let stripped = content.replace(&block, "");
            lock.as_ref()
                .context("legacy shell cleanup lost its config lock")?
                .write_guarded(&path, stripped.as_bytes(), Some(&original))?;
        }
        actions.push(FullUninstallAction::new(
            "legacy_shell_path",
            path.clone(),
            if dry_run { "would_remove" } else { "removed" },
            format!(
                "{} {} exact legacy Kin PATH block{}",
                if dry_run { "would remove" } else { "removed" },
                occurrences,
                if occurrences == 1 { "" } else { "s" }
            ),
        ));
    }
    Ok(actions)
}

fn ledger_blocks_full_uninstall(
    outcomes: &[crate::commands::setup_ledger::RemovalOutcome],
) -> usize {
    use crate::commands::setup_ledger::RemovalAction;
    outcomes
        .iter()
        .filter(|outcome| {
            matches!(
                outcome.action,
                RemovalAction::SkippedModified | RemovalAction::Failed
            )
        })
        .count()
}

#[cfg(not(windows))]
fn remove_full_install_root_with_hooks<F, R>(
    root: &ValidatedInstallRoot,
    dry_run: bool,
    install_lock: Option<&crate::commands::update::InstallRootLock>,
    before_retire: F,
    after_retire: R,
) -> Result<FullUninstallAction>
where
    F: FnOnce() -> Result<()>,
    R: FnOnce(&Path) -> Result<()>,
{
    if !root.exists {
        if !dry_run && fs::symlink_metadata(&root.path).is_ok() {
            anyhow::bail!(
                "Kin install root {} appeared after absent-root validation; re-run uninstall so it can be validated and locked",
                root.path.display()
            );
        }
        return Ok(FullUninstallAction::new(
            "install_root",
            &root.path,
            "already_absent",
            "managed Kin install root is already absent",
        ));
    }
    if dry_run {
        return Ok(FullUninstallAction::new(
            "install_root",
            &root.path,
            "would_remove",
            "would recursively remove the validated managed Kin install root",
        ));
    }
    let expected = root
        .identity
        .context("validated install root lost its identity before removal")?;
    let lock = install_lock.context("full uninstall lost install-mutation authority")?;
    if lock.root() != root.path {
        anyhow::bail!(
            "install authority {} does not match validated root {}",
            lock.root().display(),
            root.path.display()
        );
    }
    if install_root_identity(&root.path)? != expected {
        anyhow::bail!(
            "Kin install root identity changed after validation; refusing removal of {}",
            root.path.display()
        );
    }
    before_retire()?;
    let retired = lock.retire_for_uninstall()?;
    if install_root_identity(retired.path())? != expected {
        anyhow::bail!(
            "atomically retired Kin install root has the wrong identity; preserving {}",
            retired.path().display()
        );
    }
    after_retire(retired.path()).with_context(|| {
        format!(
            "post-retirement uninstall fence failed; preserving {}",
            retired.path().display()
        )
    })?;
    retired
        .remove()
        .context("failed to remove the descriptor-pinned atomically retired Kin install root")?;
    if fs::symlink_metadata(&root.path).is_ok() {
        anyhow::bail!(
            "the original Kin install root was removed, but {} was recreated concurrently and was retained",
            root.path.display()
        );
    }
    Ok(FullUninstallAction::new(
        "install_root",
        &root.path,
        "removed",
        "removed the complete managed Kin install root",
    ))
}

#[cfg(windows)]
fn cleanup_windows_user_path(root: &Path, requested_root: &Path) -> Result<()> {
    let script = r#"$ErrorActionPreference = 'Stop'
$bins = @(
    [IO.Path]::GetFullPath([IO.Path]::Combine($env:KIN_UNINSTALL_ROOT, 'bin')).TrimEnd([char[]]@([char]47, [char]92)).ToLowerInvariant()
    [IO.Path]::GetFullPath([IO.Path]::Combine($env:KIN_UNINSTALL_PATH_ROOT, 'bin')).TrimEnd([char[]]@([char]47, [char]92)).ToLowerInvariant()
) | Select-Object -Unique
$current = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($null -ne $current) {
    $kept = @($current -split ';' | Where-Object {
        if ([string]::IsNullOrWhiteSpace($_)) { return $true }
        $candidate = $_.Trim().Trim('"')
        try { $candidate = [IO.Path]::GetFullPath($candidate) } catch {}
        $bins -notcontains $candidate.TrimEnd([char[]]@([char]47, [char]92)).ToLowerInvariant()
    })
    [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
}
"#;
    let status = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .env("KIN_UNINSTALL_ROOT", root)
        .env("KIN_UNINSTALL_PATH_ROOT", requested_root)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .status()
        .context("failed to run exact Windows user-PATH cleanup")?;
    if !status.success() {
        anyhow::bail!(
            "Windows user-PATH cleanup failed with status {}; full uninstall is not complete",
            status
        );
    }
    Ok(())
}

#[cfg(windows)]
fn move_windows_install_root(from: &Path, to: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let encode = |path: &Path| -> Result<Vec<u16>> {
        let mut encoded = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            anyhow::bail!(
                "Windows uninstall path contains an interior NUL: {}",
                path.display()
            );
        }
        encoded.push(0);
        Ok(encoded)
    };
    let from_wide = encode(from)?;
    let to_wide = encode(to)?;
    if unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), MOVEFILE_WRITE_THROUGH) } == 0 {
        return Err(io::Error::last_os_error()).with_context(|| {
            format!(
                "failed to atomically retire Kin install root {} to {}",
                from.display(),
                to.display()
            )
        });
    }
    Ok(())
}

#[cfg(windows)]
fn current_windows_process_creation_time() -> Result<u64> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetProcessTimes};

    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error())
            .context("failed to capture the uninstalling Windows process incarnation");
    }
    Ok(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
}

#[cfg(windows)]
fn wait_for_windows_uninstall_helper_ready(
    child: &mut std::process::Child,
    ready_path: &Path,
    ready_nonce: &str,
    log_path: &Path,
) -> Result<()> {
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        match fs::read_to_string(ready_path) {
            Ok(observed) if observed == ready_nonce => return Ok(()),
            Ok(observed) => anyhow::bail!(
                "deferred Windows uninstall helper published an invalid ready handshake: {observed:?}"
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read deferred Windows uninstall helper handshake {}",
                        ready_path.display()
                    )
                })
            }
        }
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect deferred Windows uninstall helper startup")?
        {
            let detail = fs::read_to_string(log_path)
                .unwrap_or_else(|_| "helper did not publish a diagnostic log".to_string());
            anyhow::bail!(
                "deferred Windows uninstall helper exited before its incarnation-safe handoff ({status}): {detail}"
            );
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for deferred Windows uninstall helper to pin the parent process incarnation"
            );
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[cfg(windows)]
fn retire_windows_install_root(
    root: &ValidatedInstallRoot,
    retired: &Path,
    expected: InstallRootIdentity,
) -> Result<()> {
    match fs::symlink_metadata(retired) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect Windows uninstall retirement path {}",
                    retired.display()
                )
            })
        }
        Ok(_) => anyhow::bail!(
            "refusing to replace existing Windows uninstall retirement path {}",
            retired.display()
        ),
    }
    if install_root_identity(&root.path)? != expected {
        anyhow::bail!(
            "Kin install root identity changed before atomic retirement; refusing removal of {}",
            root.path.display()
        );
    }
    move_windows_install_root(&root.path, retired)?;
    if install_root_identity(retired)? != expected {
        anyhow::bail!(
            "atomically retired Kin install root has the wrong identity; preserving {}",
            retired.display()
        );
    }
    Ok(())
}

#[cfg(all(test, windows))]
const WINDOWS_UNINSTALL_PARENT_CREATION_OVERRIDE: &str =
    "KIN_INTERNAL_TEST_UNINSTALL_PARENT_CREATED_100NS";
#[cfg(all(test, windows))]
const WINDOWS_UNINSTALL_HELPER_RELEASE: &str = "KIN_INTERNAL_TEST_UNINSTALL_HELPER_RELEASE";

#[cfg(windows)]
fn remove_full_install_root(
    root: &ValidatedInstallRoot,
    dry_run: bool,
    install_lock: Option<&crate::commands::update::InstallRootLock>,
) -> Result<FullUninstallAction> {
    if !root.exists {
        if !dry_run {
            cleanup_windows_user_path(&root.path, &root.requested)?;
            if fs::symlink_metadata(&root.path).is_ok() {
                anyhow::bail!(
                    "Kin install root {} appeared after absent-root validation; re-run uninstall so it can be validated and locked",
                    root.path.display()
                );
            }
        }
        return Ok(FullUninstallAction::new(
            "install_root",
            &root.path,
            if dry_run {
                "would_clean_path"
            } else {
                "already_absent"
            },
            if dry_run {
                "install root is absent; would remove the exact installer-owned user-PATH segment"
            } else {
                "managed Kin install root is absent and the exact installer-owned user-PATH segment was removed; the inert current-user install-authority sidecar remains for race-safe future installs"
            },
        ));
    }
    if dry_run {
        return Ok(FullUninstallAction::new(
            "install_root",
            &root.path,
            "would_schedule",
            "would remove the exact Kin user-PATH segment and schedule the validated install root for deletion after this process exits; the inert current-user install-authority sidecar would remain for race-safe future installs",
        ));
    }

    let expected = root
        .identity
        .context("validated install root lost its identity before Windows removal")?;
    if install_root_identity(&root.path)? != expected {
        anyhow::bail!(
            "Kin install root identity changed after validation; refusing removal of {}",
            root.path.display()
        );
    }
    let lock = install_lock.context("full uninstall lost install-mutation authority")?;
    if lock.root() != root.path {
        anyhow::bail!(
            "install authority {} does not match validated root {}",
            lock.root().display(),
            root.path.display()
        );
    }

    // Windows does not permit a running executable to unlink itself. A
    // no-profile PowerShell helper opens this process, validates its creation
    // time, and publishes a ready handshake while that incarnation is still
    // alive. It then waits on the pinned process handle before deleting the
    // image. Atomically retire the validated root while install authority is
    // still held, then let the helper delete only that private sibling. A
    // replacement install at the public pathname is therefore never followed.
    let token = uuid::Uuid::new_v4();
    let script_path = env::temp_dir().join(format!("kin-uninstall-{token}.ps1"));
    let log_path = env::temp_dir().join(format!("kin-uninstall-{token}.log"));
    let ready_path = env::temp_dir().join(format!("kin-uninstall-{token}.ready"));
    let ready_publishing_path =
        env::temp_dir().join(format!("kin-uninstall-{token}.ready.publishing"));
    let ready_nonce = uuid::Uuid::new_v4().to_string();
    let parent_creation_time = current_windows_process_creation_time()?;
    let install_authority_path =
        crate::commands::update::windows_install_authority_path(&root.path)?;
    #[cfg(test)]
    let parent_creation_time = match env::var_os(WINDOWS_UNINSTALL_PARENT_CREATION_OVERRIDE) {
        Some(override_value) => override_value
            .to_string_lossy()
            .parse::<u64>()
            .context("invalid Windows uninstall parent-creation test override")?,
        None => parent_creation_time,
    };
    let retired_path = root
        .path
        .parent()
        .context("Kin install root has no parent")?
        .join(format!(".kin-uninstall-retired-{token}"));
    let incomplete_marker = root
        .path
        .parent()
        .context("Kin install root has no parent")?
        .join(format!(".kin-uninstall-incomplete-{token}"));
    let script = r#"$ErrorActionPreference = 'Stop'
$log = $env:KIN_UNINSTALL_LOG
$ready = $env:KIN_UNINSTALL_READY
$readyPublishing = $env:KIN_UNINSTALL_READY_PUBLISHING
$authority = $env:KIN_UNINSTALL_AUTHORITY
$parentHandle = $null
$authorityStream = $null
$authorityLocked = $false
try {
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class KinUninstallIdentity {
    [StructLayout(LayoutKind.Sequential)]
    struct FILETIME { public uint Low; public uint High; }
    [StructLayout(LayoutKind.Sequential)]
    struct BY_HANDLE_FILE_INFORMATION {
        public uint Attributes; public FILETIME Creation; public FILETIME Access;
        public FILETIME Write; public uint Volume; public uint SizeHigh;
        public uint SizeLow; public uint Links; public uint IndexHigh;
        public uint IndexLow;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct FILE_DISPOSITION_INFO {
        [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFileW(string path, uint access, uint share,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle handle,
        out BY_HANDLE_FILE_INFORMATION info);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetFileInformationByHandle(SafeFileHandle handle,
        int informationClass, ref FILE_DISPOSITION_INFO information, uint size);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, uint processId);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetProcessTimes(SafeWaitHandle handle, out FILETIME creation,
        out FILETIME exit, out FILETIME kernel, out FILETIME user);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern uint WaitForSingleObject(SafeWaitHandle handle, uint milliseconds);
    static string ReadHandle(SafeFileHandle handle) {
        BY_HANDLE_FILE_INFORMATION info;
        if (!GetFileInformationByHandle(handle, out info))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        if ((info.Attributes & 0x400) != 0 || (info.Attributes & 0x10) == 0)
            throw new InvalidOperationException("retired root is not a real non-reparse directory");
        ulong index = ((ulong)info.IndexHigh << 32) | info.IndexLow;
        return ((ulong)info.Volume).ToString() + ":" + index.ToString();
    }
    public static string Read(string path) {
        const uint FILE_SHARE_READ=1, FILE_SHARE_WRITE=2, FILE_SHARE_DELETE=4;
        const uint OPEN_EXISTING=3, BACKUP_SEMANTICS=0x02000000, OPEN_REPARSE=0x00200000;
        using (var handle = CreateFileW(path, 0,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, IntPtr.Zero,
            OPEN_EXISTING, BACKUP_SEMANTICS|OPEN_REPARSE, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            return ReadHandle(handle);
        }
    }
    public static SafeFileHandle Lock(string path, string expected) {
        const uint FILE_READ_ATTRIBUTES=0x80, DELETE=0x00010000;
        const uint FILE_SHARE_READ=1, FILE_SHARE_WRITE=2;
        const uint OPEN_EXISTING=3, BACKUP_SEMANTICS=0x02000000, OPEN_REPARSE=0x00200000;
        var handle = CreateFileW(path, FILE_READ_ATTRIBUTES|DELETE,
            FILE_SHARE_READ|FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING,
            BACKUP_SEMANTICS|OPEN_REPARSE, IntPtr.Zero);
        if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            if (ReadHandle(handle) != expected)
                throw new InvalidOperationException("retired root identity changed while acquiring deletion lock");
            return handle;
        } catch { handle.Dispose(); throw; }
    }
    public static string ReadLocked(SafeFileHandle handle) { return ReadHandle(handle); }
    public static SafeWaitHandle LockParent(uint processId, ulong expectedCreation) {
        const uint SYNCHRONIZE=0x00100000, QUERY_LIMITED_INFORMATION=0x1000;
        var raw = OpenProcess(SYNCHRONIZE|QUERY_LIMITED_INFORMATION, false, processId);
        if (raw == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        var handle = new SafeWaitHandle(raw, true);
        try {
            FILETIME creation, exit, kernel, user;
            if (!GetProcessTimes(handle, out creation, out exit, out kernel, out user))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            ulong observed = ((ulong)creation.High << 32) | creation.Low;
            if (observed != expectedCreation)
                throw new InvalidOperationException("uninstall parent process incarnation changed before helper handoff");
            return handle;
        } catch { handle.Dispose(); throw; }
    }
    public static void WaitForParentExit(SafeWaitHandle handle) {
        const uint WAIT_OBJECT_0=0, WAIT_TIMEOUT=258;
        uint result = WaitForSingleObject(handle, 300000);
        if (result == WAIT_TIMEOUT)
            throw new TimeoutException("timed out waiting for uninstall parent process incarnation");
        if (result != WAIT_OBJECT_0)
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
    public static void DeleteLocked(SafeFileHandle handle, string expected) {
        if (ReadHandle(handle) != expected)
            throw new InvalidOperationException("retired root identity changed before handle-bound deletion");
        const int FileDispositionInfo = 4;
        var disposition = new FILE_DISPOSITION_INFO { DeleteFile = true };
        if (!SetFileInformationByHandle(handle, FileDispositionInfo, ref disposition,
            (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO))))
            throw new Win32Exception(Marshal.GetLastWin32Error());
    }
}
'@
$installRoot = [IO.Path]::GetFullPath($env:KIN_UNINSTALL_ROOT)
$requestedInstallRoot = [IO.Path]::GetFullPath($env:KIN_UNINSTALL_PATH_ROOT)
$bins = @(
    [IO.Path]::GetFullPath([IO.Path]::Combine($installRoot, 'bin')).TrimEnd([char[]]@([char]47, [char]92)).ToLowerInvariant()
    [IO.Path]::GetFullPath([IO.Path]::Combine($requestedInstallRoot, 'bin')).TrimEnd([char[]]@([char]47, [char]92)).ToLowerInvariant()
) | Select-Object -Unique
$pidToWait = [int]$env:KIN_UNINSTALL_PID
$expectedParentCreation = [UInt64]$env:KIN_UNINSTALL_PARENT_CREATED_100NS
$retired = [IO.Path]::GetFullPath($env:KIN_UNINSTALL_RETIRED)
$incompleteMarker = [IO.Path]::GetFullPath($env:KIN_UNINSTALL_INCOMPLETE_MARKER)
$expectedIdentity = $env:KIN_UNINSTALL_EXPECTED_IDENTITY
$parentHandle = [KinUninstallIdentity]::LockParent($pidToWait, $expectedParentCreation)
$readyBytes = [Text.Encoding]::UTF8.GetBytes($env:KIN_UNINSTALL_READY_NONCE)
$readyStream = [IO.File]::Open($readyPublishing, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
try {
    $readyStream.Write($readyBytes, 0, $readyBytes.Length)
    $readyStream.Flush($true)
} finally {
    $readyStream.Dispose()
}
[IO.File]::Move($readyPublishing, $ready)
[KinUninstallIdentity]::WaitForParentExit($parentHandle)
    $authorityDeadline = [DateTime]::UtcNow.AddMinutes(5)
    while (-not $authorityLocked) {
        try {
            if ($null -eq $authorityStream) {
                $authorityStream = [IO.File]::Open($authority, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::ReadWrite)
            }
            $authorityStream.Lock(0, [Int64]::MaxValue)
            $authorityLocked = $true
        } catch {
            if ($null -ne $authorityStream) {
                $authorityStream.Dispose()
                $authorityStream = $null
            }
            if ([DateTime]::UtcNow -ge $authorityDeadline) {
                throw "timed out acquiring Kin install authority for deferred uninstall cleanup: $_"
            }
            Start-Sleep -Milliseconds 25
        }
    }
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($null -ne $current) {
        $kept = @($current -split ';' | Where-Object {
            if ([string]::IsNullOrWhiteSpace($_)) { return $true }
            $candidate = $_.Trim().Trim('"')
            try { $candidate = [IO.Path]::GetFullPath($candidate) } catch {}
            $bins -notcontains $candidate.TrimEnd([char[]]@([char]47, [char]92)).ToLowerInvariant()
        })
        [Environment]::SetEnvironmentVariable('Path', ($kept -join ';'), 'User')
    }
    if (-not (Test-Path -LiteralPath $retired)) {
        throw "retired Kin root disappeared before identity-bound cleanup; retaining incomplete marker $incompleteMarker"
    }
    if ([KinUninstallIdentity]::Read($retired) -ne $expectedIdentity) {
        throw "retired Kin root identity changed; preserving $retired"
    }
    $deleteRoot = [IO.Path]::Combine([IO.Path]::GetDirectoryName($retired), ('.kin-uninstall-delete-' + [Guid]::NewGuid().ToString()))
    [IO.Directory]::Move($retired, $deleteRoot)
    if ([KinUninstallIdentity]::Read($deleteRoot) -ne $expectedIdentity) {
        throw "retired Kin root changed during private deletion rename; preserving $deleteRoot"
    }
    $guard = [KinUninstallIdentity]::Lock($deleteRoot, $expectedIdentity)
    try {
        Get-ChildItem -LiteralPath $deleteRoot -Force | Remove-Item -Recurse -Force
        if ([KinUninstallIdentity]::ReadLocked($guard) -ne $expectedIdentity) {
            throw "retired Kin root identity changed while descriptor-locked; preserving $deleteRoot"
        }
        # Delete disposition targets this verified open directory handle. No
        # pathname replacement can redirect final removal to another tree.
        [KinUninstallIdentity]::DeleteLocked($guard, $expectedIdentity)
    } finally {
        $guard.Dispose()
    }
    Remove-Item -LiteralPath $incompleteMarker -Force
    Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
} catch {
    $_ | Out-File -LiteralPath $log -Encoding utf8
} finally {
    if ($null -ne $authorityStream) { $authorityStream.Dispose() }
    if ($null -ne $parentHandle) { $parentHandle.Dispose() }
    [IO.File]::Delete($readyPublishing)
    Remove-Item -LiteralPath $ready -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $PSCommandPath -Force -ErrorAction SilentlyContinue
}
"#;
    #[cfg(test)]
    let script = script.replace(
        "    $current = [Environment]::GetEnvironmentVariable('Path', 'User')",
        r#"    $testRelease = $env:KIN_INTERNAL_TEST_UNINSTALL_HELPER_RELEASE
    if (-not [string]::IsNullOrEmpty($testRelease)) {
        $testReleaseDeadline = [DateTime]::UtcNow.AddSeconds(300)
        while (-not (Test-Path -LiteralPath $testRelease -PathType Leaf)) {
            if ([DateTime]::UtcNow -ge $testReleaseDeadline) {
                throw "timed out waiting for the native-test deferred-cleanup release"
            }
            Start-Sleep -Milliseconds 25
        }
    }
    $current = [Environment]::GetEnvironmentVariable('Path', 'User')"#,
    );
    fs::write(&script_path, script).with_context(|| {
        format!(
            "failed to write deferred Windows uninstall helper {}",
            script_path.display()
        )
    })?;
    let marker_result = (|| -> Result<()> {
        let mut marker = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&incomplete_marker)
            .with_context(|| {
                format!(
                    "failed to create durable uninstall marker {}",
                    incomplete_marker.display()
                )
            })?;
        marker.write_all(b"kin-uninstall-incomplete-v1\n")?;
        marker.sync_all()?;
        Ok(())
    })();
    if let Err(error) = marker_result {
        let _ = fs::remove_file(&script_path);
        let _ = fs::remove_file(&ready_path);
        let _ = fs::remove_file(&ready_publishing_path);
        let _ = fs::remove_file(&incomplete_marker);
        return Err(error);
    }
    if let Err(error) = retire_windows_install_root(root, &retired_path, expected) {
        let _ = fs::remove_file(&script_path);
        let _ = fs::remove_file(&ready_path);
        let _ = fs::remove_file(&ready_publishing_path);
        let _ = fs::remove_file(&incomplete_marker);
        return Err(error);
    }
    if let Err(error) = crate::commands::daemon::verify_install_owned_processes_absent(&root.path)
        .and_then(|_| crate::commands::daemon::verify_install_owned_processes_absent(&retired_path))
    {
        let _ = fs::remove_file(&script_path);
        let _ = fs::remove_file(&ready_path);
        let _ = fs::remove_file(&ready_publishing_path);
        return Err(error).context(format!(
            "post-retirement process fence failed; preserving {}",
            retired_path.display()
        ));
    }
    let child = Command::new("powershell.exe")
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-WindowStyle",
            "Hidden",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&script_path)
        .env("KIN_UNINSTALL_ROOT", &root.path)
        .env("KIN_UNINSTALL_PATH_ROOT", &root.requested)
        .env("KIN_UNINSTALL_PID", std::process::id().to_string())
        .env(
            "KIN_UNINSTALL_PARENT_CREATED_100NS",
            parent_creation_time.to_string(),
        )
        .env("KIN_UNINSTALL_LOG", &log_path)
        .env("KIN_UNINSTALL_READY", &ready_path)
        .env("KIN_UNINSTALL_READY_PUBLISHING", &ready_publishing_path)
        .env("KIN_UNINSTALL_READY_NONCE", &ready_nonce)
        .env("KIN_UNINSTALL_AUTHORITY", &install_authority_path)
        .env("KIN_UNINSTALL_RETIRED", &retired_path)
        .env("KIN_UNINSTALL_INCOMPLETE_MARKER", &incomplete_marker)
        .env(
            "KIN_UNINSTALL_EXPECTED_IDENTITY",
            format!(
                "{}:{}",
                expected.volume_or_device, expected.file_index_or_inode
            ),
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let mut child = match child {
        Ok(child) => child,
        Err(spawn_error) => {
            let rollback = move_windows_install_root(&retired_path, &root.path);
            let _ = fs::remove_file(&script_path);
            let _ = fs::remove_file(&ready_path);
            let _ = fs::remove_file(&ready_publishing_path);
            match rollback {
                Ok(()) => {
                    let _ = fs::remove_file(&incomplete_marker);
                    return Err(spawn_error).with_context(|| {
                    format!(
                        "failed to launch deferred Windows uninstall helper {}; atomically restored {}",
                        script_path.display(),
                        root.path.display()
                    )
                    });
                }
                Err(rollback_error) => anyhow::bail!(
                    "failed to launch deferred Windows uninstall helper {}: {}; the validated install root is preserved at {}, but restoring its public path also failed: {:#}",
                    script_path.display(),
                    spawn_error,
                    retired_path.display(),
                    rollback_error
                ),
            }
        }
    };
    if let Err(handoff_error) =
        wait_for_windows_uninstall_helper_ready(&mut child, &ready_path, &ready_nonce, &log_path)
    {
        let _ = child.kill();
        let _ = child.wait();
        let rollback = move_windows_install_root(&retired_path, &root.path);
        let _ = fs::remove_file(&script_path);
        let _ = fs::remove_file(&ready_path);
        let _ = fs::remove_file(&ready_publishing_path);
        let _ = fs::remove_file(&log_path);
        match rollback {
            Ok(()) => {
                let _ = fs::remove_file(&incomplete_marker);
                return Err(handoff_error).context(format!(
                    "deferred Windows uninstall helper did not complete its incarnation-safe handoff; atomically restored {}",
                    root.path.display()
                ));
            }
            Err(rollback_error) => anyhow::bail!(
                "deferred Windows uninstall helper did not complete its incarnation-safe handoff: {handoff_error:#}; the validated install root is preserved at {}, but restoring its public path also failed: {rollback_error:#}",
                retired_path.display()
            ),
        }
    }
    drop(child);
    Ok(FullUninstallAction::new(
        "install_root",
        &root.path,
        "scheduled",
        format!(
            "scheduled current-user PATH cleanup and complete install-root deletion after process exit; the inert current-user install-authority sidecar remains for race-safe future installs; failures are recorded at {}",
            log_path.display()
        ),
    ))
}

pub async fn uninstall(all: bool, dry_run: bool, force: bool, json: bool) -> Result<()> {
    use crate::commands::setup_ledger::{ledger_path, run_uninstall, RemovalAction};

    let install_root = if all {
        Some(validate_full_uninstall_root()?)
    } else {
        None
    };
    let install_lock = match install_root.as_ref() {
        Some(root) if root.exists && !dry_run => Some(
            crate::commands::update::InstallRootLock::acquire_existing_waiting(&root.path)
                .context("full uninstall could not acquire exclusive install-mutation authority")?,
        ),
        _ => None,
    };
    let daemon_fence = match install_root.as_ref() {
        Some(root) if root.exists && !dry_run => Some(
            crate::commands::daemon::stop_all_for_uninstall(&root.path)
                .await
                .context("full uninstall refused because not every Kin daemon could be stopped")?,
        ),
        Some(_) if !dry_run => {
            crate::commands::daemon::stop_all_quiet()
                .await
                .context("full uninstall refused because not every Kin daemon could be stopped")?;
            crate::commands::daemon::verify_install_owned_processes_absent(
                &install_root
                    .as_ref()
                    .context("full uninstall root disappeared")?
                    .path,
            )?;
            None
        }
        _ => None,
    };

    let path = ledger_path()?;
    let outcomes = run_uninstall(&path, dry_run, force)?;
    let blocked = ledger_blocks_full_uninstall(&outcomes);
    let mut full_actions = Vec::new();
    if let Some(root) = &install_root {
        if blocked == 0 {
            full_actions.extend(cleanup_legacy_shell_path_blocks(
                &home_dir()?,
                &root.path,
                dry_run,
            )?);
            if root.requested != root.path {
                full_actions.extend(cleanup_legacy_shell_path_blocks(
                    &home_dir()?,
                    &root.requested,
                    dry_run,
                )?);
            }
            if let Some(fence) = daemon_fence.as_ref() {
                fence.verify_quiescent(&root.path).context(
                    "full uninstall refused because a managed daemon restarted before root retirement",
                )?;
            }
            #[cfg(not(windows))]
            let install_root_action = remove_full_install_root_with_hooks(
                root,
                dry_run,
                install_lock.as_ref(),
                || Ok(()),
                |retired| {
                    if let Some(fence) = daemon_fence.as_ref() {
                        // Retirement is the executable admission fence: after
                        // this rename no new supervisor or worker can be
                        // spawned from the managed public path. Scan both the
                        // historical argv path and the retired executable path
                        // before descriptor-bound deletion.
                        fence.verify_quiescent(&root.path)?;
                        fence.verify_quiescent(retired)?;
                    }
                    Ok(())
                },
            )?;
            #[cfg(windows)]
            let install_root_action =
                remove_full_install_root(root, dry_run, install_lock.as_ref())?;
            full_actions.push(install_root_action);
        } else {
            full_actions.push(FullUninstallAction::new(
                "install_root",
                &root.path,
                "blocked",
                format!(
                    "retained the install root because {blocked} ledger entr{} still require{} reconciliation",
                    if blocked == 1 { "y" } else { "ies" },
                    if blocked == 1 { "s" } else { "" }
                ),
            ));
        }
    }

    if json {
        if all {
            let fully_removed = !dry_run
                && full_actions.iter().any(|action| {
                    action.kind == "install_root"
                        && matches!(action.action.as_str(), "removed" | "already_absent")
                });
            let payload = serde_json::json!({
                "schema": "kin.setup-uninstall.v2",
                "scope": "all",
                "dry_run": dry_run,
                "ledger": outcomes,
                "full_install": full_actions,
                "fully_removed": fully_removed,
                "retained_coordination_metadata": if cfg!(windows) {
                    serde_json::json!([{
                        "kind": "windows_install_authority",
                        "reason": "persistent current-user-only sidecar prevents split install authority across crashes, aliases, and concurrent future installs"
                    }])
                } else {
                    serde_json::json!([])
                },
            });
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&outcomes)?);
        }
        if blocked > 0 && all && !dry_run {
            anyhow::bail!(
                "full uninstall retained KIN_HOME because {blocked} ledger entries were modified or failed removal; review them and re-run with --force only if those Kin-owned slices should be removed"
            );
        }
        return Ok(());
    }

    if outcomes.is_empty() {
        if all {
            println!("No install ledger found — continuing with full managed-install cleanup.");
        } else {
            println!("No install ledger found — nothing recorded to uninstall.");
            println!(
                "(The ledger is written by `kin setup`; run it first if you expected entries.)"
            );
            return Ok(());
        }
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
    if all {
        for action in &full_actions {
            println!("  {}", action.detail);
        }
        if blocked > 0 && !dry_run {
            anyhow::bail!(
                "full uninstall retained KIN_HOME because {blocked} ledger entries were modified or failed removal; review them and re-run with --force only if those Kin-owned slices should be removed"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::projection_mode_to_record;
    use super::{fix_verdict, readiness_line, UnfinishedRepair};
    use crate::commands::health::{HealthCheck, HealthReport, HealthStatus};
    use kin_model::LanguageId;

    fn check(id: &str, label: &str, status: HealthStatus) -> HealthCheck {
        HealthCheck {
            id: id.to_string(),
            label: label.to_string(),
            status,
            detail: String::new(),
            platform_note: None,
            fixable: false,
            manual_fix: None,
        }
    }

    /// The state the container run was actually in: `healthy` true, because
    /// nothing was Missing or Misconfigured, while the coverage row read
    /// PENDING because no language server was found and the repair meant to
    /// install one had just failed. The closing line said "First-run ready"
    /// under its own "4 need attention" tally (FIR-2547).
    #[test]
    fn a_pending_row_keeps_the_summary_from_claiming_first_run_ready() {
        let report = HealthReport {
            platform: "linux".to_string(),
            checks: vec![
                check("kin_binary", "Kin binary", HealthStatus::Healthy),
                check(
                    "reference_edge_coverage",
                    "Reference edge coverage",
                    HealthStatus::Pending,
                ),
            ],
            healthy: true,
        };
        let line = readiness_line(&report);
        assert!(
            !line.ready,
            "a report holding a row that needs attention must not claim readiness, got: {}",
            line.sentence
        );
        assert!(
            !line.sentence.contains("First-run ready"),
            "a row that knows no language server was found must not close under a claim that \
             nothing is missing: {}",
            line.sentence
        );
        assert!(
            line.sentence.contains("Reference edge coverage"),
            "the line has to name the row it is refusing on: {}",
            line.sentence
        );
        assert!(
            !line.severe,
            "pending work is not a failure, so the mark stays short of red: {}",
            line.sentence
        );
    }

    /// Positive control: a report with nothing needing attention still reads
    /// ready, or the line would refuse every correct install.
    #[test]
    fn a_report_with_nothing_waiting_still_reads_first_run_ready() {
        let report = HealthReport {
            platform: "linux".to_string(),
            checks: vec![
                check("kin_binary", "Kin binary", HealthStatus::Healthy),
                check(
                    "vfs_projection",
                    "VFS projection",
                    HealthStatus::Unsupported,
                ),
            ],
            healthy: true,
        };
        let line = readiness_line(&report);
        assert!(line.ready, "{}", line.sentence);
        assert!(
            line.sentence.contains("First-run ready"),
            "{}",
            line.sentence
        );
    }

    /// A real failure keeps the red mark and the repair route.
    #[test]
    fn a_missing_row_reads_as_severe_and_names_the_repair() {
        let mut missing = check("shell_path", "Shell PATH", HealthStatus::Missing);
        missing.fixable = true;
        let report = HealthReport {
            platform: "linux".to_string(),
            checks: vec![
                check("kin_binary", "Kin binary", HealthStatus::Healthy),
                missing,
            ],
            healthy: false,
        };
        let line = readiness_line(&report);
        assert!(!line.ready, "{}", line.sentence);
        assert!(line.severe, "{}", line.sentence);
        assert!(line.sentence.contains("Shell PATH"), "{}", line.sentence);
        assert!(
            line.sentence.contains("kin doctor --fix"),
            "{}",
            line.sentence
        );
    }

    /// A repair the operator asked for and Kin could not make ends the run
    /// non-zero. The run this comes from installed nothing and exited 0.
    #[test]
    fn a_requested_repair_that_did_not_complete_fails_the_run() {
        let requested = UnfinishedRepair {
            what: "install the python language server".to_string(),
            reason: "`npm install -g pyright` exited with 243: npm error code EACCES".to_string(),
            remediation: vec!["npm config set prefix \"$HOME/.npm-global\"".to_string()],
            requested: true,
        };
        let error = fix_verdict(std::slice::from_ref(&requested))
            .expect_err("a requested repair that did not happen must not exit 0");
        let text = error.to_string();
        assert!(
            text.contains("install the python language server"),
            "{text}"
        );

        // Two controls. Nothing unfinished is a clean run, and a best-effort
        // convergence repair reports itself without failing the run, because
        // `kin update` runs `kin setup doctor --fix` unattended as its last
        // step and an offline shim fetch must not report the release as a
        // failed update.
        assert!(fix_verdict(&[]).is_ok());
        let unrequested = UnfinishedRepair {
            what: "restore the VFS shim".to_string(),
            reason: "the release asset could not be fetched".to_string(),
            remediation: Vec::new(),
            requested: false,
        };
        assert!(fix_verdict(std::slice::from_ref(&unrequested)).is_ok());
    }

    /// FIR-2293, from the artifact the Windows install proof captured. The
    /// proof runs the config writers with `KIN_HOME="$primary_home/.kin"`, and
    /// MSYS bash spells `$HOME` as `C:/Users/runneradmin`, so `KIN_HOME`
    /// reaches the process forward-slashed. `Path::join` then appended
    /// backslashes and setup recorded `C:/Users/runneradmin/.kin\bin\kin.exe`
    /// as the MCP command against an installed launcher of
    /// `C:\Users\runneradmin\.kin\bin\kin.exe`. Windows opens both, so nothing
    /// broke until a reader tried to compare them, and then the proof called
    /// the entry malformed against a launcher sitting right where it said.
    ///
    /// Nothing exotic reaches this: a Windows user whose `KIN_HOME` came from
    /// any shell that spells paths with forward slashes got the same entry.
    #[test]
    fn a_windows_launcher_is_recorded_the_way_windows_spells_it() {
        assert_eq!(
            super::launcher_spelling_for("C:/Users/runneradmin/.kin\\bin\\kin.exe", "windows"),
            "C:\\Users\\runneradmin\\.kin\\bin\\kin.exe"
        );
        // A path that is already canonical comes back byte-identical, so the
        // rewrite is idempotent and a correct entry is never turned into a
        // different one on the next setup run.
        assert_eq!(
            super::launcher_spelling_for("C:\\Users\\runneradmin\\.kin\\bin\\kin.exe", "windows"),
            "C:\\Users\\runneradmin\\.kin\\bin\\kin.exe"
        );
        // Unix keeps every byte it was handed. The forward slash is the
        // separator there, and rewriting one would break every path recorded
        // on the platforms this leg already gates.
        assert_eq!(
            super::launcher_spelling_for("/Users/runner/.kin/bin/kin", "macos"),
            "/Users/runner/.kin/bin/kin"
        );
        assert_eq!(
            super::launcher_spelling_for("/home/u/.kin/bin/kin", "linux"),
            "/home/u/.kin/bin/kin"
        );
    }

    /// Setup must never record a mount mode it did not engage. The v0.5.41
    /// release install proof failed on all three non-Linux legs because a
    /// fresh install recorded nfs (macOS) or projfs (Windows) with nothing
    /// mounted, and doctor read the recording as misconfigured.
    #[test]
    fn setup_records_the_shim_when_the_chooser_prefers_an_unengaged_mount() {
        use crate::commands::projection::ProjectionMode;
        assert_eq!(
            projection_mode_to_record(None, ProjectionMode::Nfs, true),
            Some(ProjectionMode::Shim)
        );
        assert_eq!(
            projection_mode_to_record(None, ProjectionMode::ProjFs, true),
            Some(ProjectionMode::Shim)
        );
        assert_eq!(
            projection_mode_to_record(None, ProjectionMode::Fuse, true),
            Some(ProjectionMode::Shim)
        );
    }

    /// With no shim installed there is nothing setup can honestly claim runs,
    /// so nothing is recorded and doctor stays clean on a projection-less host.
    #[test]
    fn setup_records_nothing_when_no_mode_is_in_force() {
        use crate::commands::projection::ProjectionMode;
        assert_eq!(
            projection_mode_to_record(None, ProjectionMode::Nfs, false),
            None
        );
        assert_eq!(
            projection_mode_to_record(None, ProjectionMode::ProjFs, false),
            None
        );
    }

    /// The shim is in force by installation alone, so choosing it records it.
    #[test]
    fn setup_records_the_shim_when_the_shim_is_chosen() {
        use crate::commands::projection::ProjectionMode;
        assert_eq!(
            projection_mode_to_record(None, ProjectionMode::Shim, true),
            Some(ProjectionMode::Shim)
        );
    }

    /// A mode an earlier `kin vfs on` engaged and recorded is preserved: the
    /// chooser feeds the recording back in, and setup keeping it is what lets
    /// a deliberately configured machine survive a setup re-run.
    #[test]
    fn setup_keeps_a_previously_engaged_recording() {
        use crate::commands::projection::ProjectionMode;
        assert_eq!(
            projection_mode_to_record(Some(ProjectionMode::Nfs), ProjectionMode::Nfs, true),
            Some(ProjectionMode::Nfs)
        );
        assert_eq!(
            projection_mode_to_record(Some(ProjectionMode::ProjFs), ProjectionMode::ProjFs, false),
            Some(ProjectionMode::ProjFs)
        );
    }

    use super::*;
    use crate::commands::setup_ledger::ArtifactKind;
    use kin_core::test_env::EnvVarGuard;
    use serial_test::serial;

    fn opts() -> WizardOptions {
        WizardOptions {
            mode: None,
            shell: Some("zsh".to_string()),
            auto_daemon: false,
            no_interactive: true,
            intent: None,
            skip_mcp_check: false,
            install_language_servers: false,
        }
    }

    fn configured_command_env(command: &Command, key: &str) -> Option<Option<std::ffi::OsString>> {
        command
            .get_envs()
            .find(|(candidate, _)| *candidate == OsStr::new(key))
            .map(|(_, value)| value.map(OsStr::to_os_string))
    }

    /// The install proof's isolated Windows home, verbatim: `USERPROFILE` names
    /// a directory that exists but carries no `AppData` subtree, so the
    /// AppData-requiring `BaseDirs` constructor collapses to `None`. That
    /// `None` used to be the entire answer, and `kin setup` aborted with "could
    /// not determine home directory" before writing a single artifact.
    #[test]
    fn windows_home_resolves_an_isolated_profile_with_no_app_data_subtree() {
        let isolated = PathBuf::from(r"D:\a\_temp\kin-proof-claude-fallback-home");

        let resolved = resolve_home_dir(
            true,
            |key| (key == "USERPROFILE").then(|| isolated.as_os_str().to_os_string()),
            // Whichever known-folder lookup the bare profile defeats, the
            // resolution must not depend on it.
            || None,
            || None,
        );

        assert_eq!(
            resolved.as_deref(),
            Some(isolated.as_path()),
            "a Windows profile root with no AppData subtree must still resolve"
        );
    }

    /// The explicitly named profile beats whatever the machine's own known
    /// folders report. Losing that ordering does not fail loudly: setup would
    /// succeed against the real profile while the caller believed it had
    /// redirected the home, which both writes where it must not and turns the
    /// isolated leg of the install proof into a test of nothing.
    #[test]
    fn windows_home_prefers_the_named_profile_over_the_machine_profile() {
        let isolated = PathBuf::from(r"D:\a\_temp\kin-proof-claude-fallback-home");
        let machine = PathBuf::from(r"C:\Users\runneradmin");

        let resolved = resolve_home_dir(
            true,
            |key| (key == "USERPROFILE").then(|| isolated.as_os_str().to_os_string()),
            || Some(machine.clone()),
            || Some(machine.clone()),
        );

        assert_eq!(
            resolved.as_deref(),
            Some(isolated.as_path()),
            "an explicit USERPROFILE must outrank the machine's known folders"
        );
    }

    /// Without a usable `USERPROFILE`, Windows falls through the profile-only
    /// lookup and only then to the stricter constructor — and still reports
    /// `None` when nothing resolves, so a genuinely homeless environment keeps
    /// failing loudly instead of inventing a path.
    #[test]
    fn windows_home_falls_through_profile_root_then_base_dirs() {
        let profile = PathBuf::from(r"C:\Users\runneradmin");
        let base_dirs = PathBuf::from(r"C:\Users\stricter");

        for unusable in [None, Some(OsString::new())] {
            let resolved = resolve_home_dir(
                true,
                |_| unusable.clone(),
                || Some(profile.clone()),
                || Some(base_dirs.clone()),
            );
            assert_eq!(
                resolved.as_deref(),
                Some(profile.as_path()),
                "an unset or empty USERPROFILE must fall through to the profile lookup"
            );
        }

        assert_eq!(
            resolve_home_dir(true, |_| None, || None, || Some(base_dirs.clone())).as_deref(),
            Some(base_dirs.as_path()),
            "the stricter constructor is still the last resort, not a removed step"
        );
        assert_eq!(
            resolve_home_dir(true, |_| None, || None, || None),
            None,
            "no resolvable home must stay an error rather than a guess"
        );
    }

    /// Unix keeps exactly the resolution it had — the `BaseDirs` answer
    /// verbatim, including its `None`. `USERPROFILE` is a Windows name and must
    /// not become a Unix input, and the profile-only lookup must not run there.
    #[test]
    fn unix_home_resolution_is_untouched_by_the_windows_arm() {
        let base_dirs = PathBuf::from("/Users/runner");
        let stray = PathBuf::from("/tmp/kin-proof-claude-fallback-home");

        assert_eq!(
            resolve_home_dir(
                false,
                |_| Some(stray.as_os_str().to_os_string()),
                || Some(stray.clone()),
                || Some(base_dirs.clone()),
            )
            .as_deref(),
            Some(base_dirs.as_path()),
            "Unix must ignore both Windows sources"
        );
        assert_eq!(
            resolve_home_dir(
                false,
                |_| Some(stray.as_os_str().to_os_string()),
                || Some(stray.clone()),
                || None,
            ),
            None,
            "Unix must keep failing exactly where BaseDirs fails"
        );
    }

    /// The wiring, not just the policy: on this platform `home_dir` is still
    /// the `BaseDirs` expression it was before the Windows arm existed.
    ///
    /// Both sides read the real environment, so the read is taken inside the
    /// mutation domain — otherwise a neighbouring test's scoped `HOME` could
    /// land between the two calls and fail this on a lie.
    #[cfg(unix)]
    #[test]
    fn unix_home_dir_still_resolves_exactly_what_base_dirs_reports() {
        let _domain = EnvVarGuard::new();

        assert_eq!(
            home_dir().ok(),
            directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf())
        );
    }

    #[test]
    fn setup_git_authority_finalizer_scrubs_ambient_and_explicit_authority() {
        let explicit = [
            "GIT_DIR",
            "KIN_SESSION",
            "_KIN_VFS_LAST_DIR",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ];
        let ambient = [
            "GIT_WORK_TREE",
            "KIN_SOURCE_ROOT",
            "_KIN_TEST_AUTHORITY",
            "DYLD_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
        ];
        let mut command = Command::new("git");
        for key in explicit {
            command.env(key, "poison");
        }

        finalize_setup_git_authority_process_with_ambient(
            &mut command,
            OsStr::new("trusted-host-path"),
            ambient.into_iter().map(OsString::from),
        );

        for key in explicit.into_iter().chain(ambient) {
            assert_eq!(
                configured_command_env(&command, key),
                Some(None),
                "{key} retained authority"
            );
        }
        assert_eq!(
            configured_command_env(&command, "PATH"),
            Some(Some(OsString::from("trusted-host-path")))
        );
        assert_eq!(
            configured_command_env(&command, "KIN_VFS_DISABLE"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(
            configured_command_env(&command, "GIT_CONFIG_NOSYSTEM"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(
            configured_command_env(&command, "GIT_NO_REPLACE_OBJECTS"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(
            configured_command_env(&command, "GIT_OPTIONAL_LOCKS"),
            Some(Some(OsString::from("0")))
        );
    }

    /// `kin setup` shells out to Git through this boundary, so the global
    /// config it binds has to be a path Git can actually open. Binding the
    /// reserved Windows device name `NUL` made Git fail with
    /// `fatal: unable to access 'NUL': Invalid argument` on a real Windows
    /// host, which failed setup rather than isolating it.
    #[test]
    fn setup_git_boundary_binds_an_openable_empty_global_config() {
        let mut command = Command::new("git");
        finalize_setup_git_authority_process_with_ambient(
            &mut command,
            OsStr::new("trusted-host-path"),
            std::iter::empty(),
        );

        let bound = configured_command_env(&command, "GIT_CONFIG_GLOBAL")
            .flatten()
            .expect("the setup Git boundary bound a global config");
        assert_eq!(
            bound,
            kin_git::empty_global_git_config(),
            "the setup Git boundary stopped routing through the shared helper"
        );
        assert!(
            Path::new(&bound).is_absolute(),
            "bound global Git config {bound:?} is a bare name, not an absolute path"
        );
    }

    #[cfg(unix)]
    fn write_setup_fake_git(bin: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        fs::create_dir_all(bin).unwrap();
        let git = bin.join("git");
        fs::write(&git, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&git).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&git, permissions).unwrap();
        git
    }

    #[cfg(unix)]
    fn fixture_process_is_live(pid: u32) -> bool {
        let system = sysinfo::System::new_all();
        system
            .process(sysinfo::Pid::from_u32(pid))
            .is_some_and(|process| {
                !matches!(
                    process.status(),
                    sysinfo::ProcessStatus::Dead | sysinfo::ProcessStatus::Zombie
                )
            })
    }

    #[cfg(unix)]
    #[test]
    fn setup_git_authority_uses_resolved_host_git_with_closed_stdin() {
        let fixture = tempfile::tempdir().unwrap();
        let bin = fixture.path().join("host-bin");
        write_setup_fake_git(
            &bin,
            r#"
if IFS= read -r ignored; then
    echo "stdin remained readable" >&2
    exit 90
fi
printf 'path=%s\n' "$PATH"
printf 'vfs=%s\n' "$KIN_VFS_DISABLE"
printf 'nosystem=%s\n' "$GIT_CONFIG_NOSYSTEM"
printf 'global=%s\n' "$GIT_CONFIG_GLOBAL"
printf 'args=%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5"
"#,
        );
        let host_path = bin.to_string_lossy();

        let output = git_authority_output_with_policy(
            fixture.path(),
            &["rev-parse", "HEAD"],
            &host_path,
            Duration::from_secs(2),
            16 * 1024,
        )
        .unwrap();

        assert!(output.contains(&format!("path={host_path}\n")), "{output}");
        assert!(output.contains("vfs=1\n"), "{output}");
        assert!(output.contains("nosystem=1\n"), "{output}");
        assert!(output.contains("global=/dev/null\n"), "{output}");
        assert!(
            output.contains(&format!(
                "args=--no-replace-objects|-C|{}|rev-parse|HEAD",
                fixture.path().canonicalize().unwrap().display()
            )),
            "{output}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn setup_git_relative_host_path_cannot_rebind_under_repository_cwd() {
        let fixture = tempfile::tempdir().unwrap();
        let resolution_root = fixture.path().join("resolution");
        let repo_root = fixture.path().join("repository");
        write_setup_fake_git(&resolution_root.join("bin"), "printf trusted");
        write_setup_fake_git(&repo_root.join("bin"), "printf hostile");

        let output = git_authority_output_with_resolution_policy(
            &repo_root,
            &["rev-parse", "HEAD"],
            "bin",
            &resolution_root,
            Duration::from_secs(2),
            16 * 1024,
        )
        .unwrap();

        assert_eq!(output, "trusted");
    }

    #[cfg(unix)]
    #[test]
    fn setup_git_authority_rejects_runaway_output_and_reaps_descendants() {
        let fixture = tempfile::tempdir().unwrap();
        let bin = fixture.path().join("host-bin");
        write_setup_fake_git(
            &bin,
            r#"
/bin/sleep 30 &
descendant_pid="$!"
printf '%s\n' "$descendant_pid" > "${0%/*}/descendant.pid.staged"
/bin/mv "${0%/*}/descendant.pid.staged" "${0%/*}/descendant.pid"
chunk='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
while :; do
    printf '%s' "$chunk"
done
"#,
        );
        let marker = bin.join("descendant.pid");
        let error = git_authority_output_with_policy_after_parseable_pid_ready(
            fixture.path(),
            &["rev-parse", "HEAD"],
            &bin.to_string_lossy(),
            &marker,
            Duration::from_secs(5),
            4 * 1024,
        )
        .expect_err("runaway Git output must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("exceeded the 4096-byte"), "{message}");
        assert!(message.contains("cleanup=ok"), "{message}");

        let pid = fs::read_to_string(marker)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(
            !fixture_process_is_live(pid),
            "runaway Git descendant {pid} survived bounded return"
        );
    }

    #[cfg(unix)]
    #[test]
    fn setup_git_authority_times_out_and_reaps_descendants() {
        let fixture = tempfile::tempdir().unwrap();
        let bin = fixture.path().join("host-bin");
        write_setup_fake_git(
            &bin,
            r#"
/bin/sleep 30 &
descendant_pid="$!"
printf '%s\n' "$descendant_pid" > "${0%/*}/descendant.pid.staged"
/bin/mv "${0%/*}/descendant.pid.staged" "${0%/*}/descendant.pid"
wait
"#,
        );
        let marker = bin.join("descendant.pid");
        let error = git_authority_output_with_policy_after_parseable_pid_ready(
            fixture.path(),
            &["worktree", "list", "--porcelain"],
            &bin.to_string_lossy(),
            &marker,
            Duration::from_millis(200),
            16 * 1024,
        )
        .expect_err("hung Git authority query must time out");
        let message = format!("{error:#}");
        assert!(message.contains("timed out after 200ms"), "{message}");
        assert!(message.contains("cleanup=ok"), "{message}");

        let pid = fs::read_to_string(marker)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(
            !fixture_process_is_live(pid),
            "timed-out Git descendant {pid} survived bounded return"
        );
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
        // Repair path: a deliberately-zeroed shim + a usable source is
        // restored to the real bytes.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source-shim");
        fs::write(&source, b"\xCF\xFA\xED\xFEreal-shim-bytes").unwrap();
        let dest = tmp.path().join("lib").join(shim_filename());
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        fs::write(&dest, b"").unwrap(); // the 0-byte crash hazard

        let restored = restore_shim_from_sources(&dest, std::slice::from_ref(&source)).unwrap();
        assert_eq!(restored.as_deref(), Some(dest.as_path()));
        assert_eq!(
            fs::read(&dest).unwrap(),
            b"\xCF\xFA\xED\xFEreal-shim-bytes",
            "dest must hold the source bytes after repair"
        );
    }

    #[test]
    fn restore_shim_reports_none_when_no_usable_source_exists() {
        // Honest path: with no usable source, the repair reports None
        // (so the caller escalates / prints a manual step) and never fabricates
        // content over the zeroed shim.
        let tmp = tempfile::tempdir().unwrap();
        let empty = tmp.path().join("empty-source");
        fs::write(&empty, b"").unwrap();
        let missing = tmp.path().join("missing-source");
        let dest = tmp.path().join("dest-shim");
        fs::write(&dest, b"").unwrap();

        let restored = restore_shim_from_sources(&dest, &[empty, missing]).unwrap();
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
    #[serial]
    fn find_shim_checks_managed_kin_home_lib() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let shim = kin_home.join("lib").join(shim_filename());
        fs::create_dir_all(shim.parent().unwrap()).unwrap();
        fs::write(&shim, b"MANAGED_SHIM").unwrap();

        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");

        assert_eq!(find_shim().as_deref(), Some(shim.as_path()));
    }

    /// The repair `kin doctor --fix` actually runs, against the install shape an
    /// archive or Homebrew user has: no `~/.kin/bin`, and `kin` resolved from
    /// somewhere else. It appended the PATH export anyway, so the rc named a
    /// directory that did not exist before the repair or after it.
    #[test]
    #[serial]
    fn the_shell_repair_neither_invents_a_bin_directory_nor_points_at_one() {
        let tmp = tempfile::tempdir().unwrap();
        let archive_home = tmp.path().join("archive-home");
        let managed_home = tmp.path().join("managed-home");
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(&archive_home).unwrap();
        fs::create_dir_all(&managed_home).unwrap();

        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        let bin_dir = kin_home.join("bin");

        {
            let _home = EnvVarGuard::set("HOME", &archive_home);
            install_shell_hook("bash").unwrap();
        }
        let rc = fs::read_to_string(archive_home.join(".bashrc")).unwrap();
        assert!(
            rc.contains("kin-vfs"),
            "the hook source line is the repair and must still land: {rc}"
        );
        assert!(
            !rc.contains(&bin_dir.display().to_string()),
            "a repair may not write a PATH reference to a directory it did not install: {rc}"
        );
        assert!(
            !bin_dir.exists(),
            "the repair must not conjure {} either",
            bin_dir.display()
        );

        // Falsification: on the launcher-provisioned layout, where the binaries
        // really are under ~/.kin/bin, the same repair still writes the line.
        fs::create_dir_all(&bin_dir).unwrap();
        {
            let _home = EnvVarGuard::set("HOME", &managed_home);
            install_shell_hook("bash").unwrap();
        }
        let managed_rc = fs::read_to_string(managed_home.join(".bashrc")).unwrap();
        assert!(
            managed_rc.contains(&bin_dir.display().to_string()),
            "a provisioned bin directory must still reach PATH: {managed_rc}"
        );
    }

    /// The defect a bash user hits in the first ten minutes. `kin setup` wrote
    /// the PATH line only to `.bashrc`, which a login shell never reads, so on a
    /// fresh install `bash -lc` could not find `kin` at all. FIR-2596.
    ///
    /// This drives the real writer against a throwaway home and then asks a real
    /// `bash -lc` what its PATH carries. The assertion is on the install's own
    /// bin directory rather than on which `kin` wins, because a login shell runs
    /// `/etc/profile` first and macOS's `path_helper` puts the system
    /// directories back in front; on a host that already has a `kin` in
    /// `/usr/local/bin`, asserting on the winner would measure the operator's
    /// machine instead of this install.
    ///
    /// The falsification is the second half: delete the login file the fix
    /// writes, leaving exactly the pre-fix layout of `.bashrc` and nothing else,
    /// and the same probe loses the directory again.
    #[test]
    #[serial]
    #[cfg(unix)]
    fn a_bash_login_shell_finds_kin_after_setup() {
        use std::os::unix::fs::PermissionsExt;

        if !Path::new("/bin/bash").is_file() {
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let bin_dir = kin_home.join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        // The binary the launcher-provisioned layout puts in ~/.kin/bin. Only
        // where it sits matters here; the probe asks what PATH carries.
        let stub = bin_dir.join("kin");
        fs::write(&stub, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        {
            let _home = EnvVarGuard::set("HOME", &home);
            install_shell_hook("bash").unwrap();
        }

        // One probe, three facts: what PATH the login shell carries, whether
        // `kin` resolves there, and whether the projection hook was sourced into
        // it. The last one is why the seed's interactivity guard exists, so it
        // is asserted rather than assumed.
        let probe = || {
            let out = std::process::Command::new("/bin/bash")
                .arg("-lc")
                .arg(concat!(
                    r#"printf 'KFR_PATH=%s\n' "$PATH""#,
                    "\n",
                    r#"if command -v kin > /dev/null 2>&1; then printf 'KFR_KIN=%s\n' "$(command -v kin)"; else printf 'KFR_KIN=none\n'; fi"#,
                    "\n",
                    r#"if declare -F _kin_vfs_prompt_command > /dev/null 2>&1; then printf 'KFR_HOOK=yes\n'; else printf 'KFR_HOOK=no\n'; fi"#,
                ))
                .env("HOME", &home)
                .env("PATH", "/usr/bin:/bin")
                .env_remove("KIN_HOME")
                .env_remove("KIN_DIR")
                .env_remove("BASH_ENV")
                .current_dir(&home)
                .output()
                .expect("could not run /bin/bash -lc");
            assert!(
                out.status.success(),
                "the probe shell itself failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let field = |name: &str| -> String {
                text.lines()
                    .find_map(|line| line.strip_prefix(name))
                    .unwrap_or_else(|| panic!("the probe printed no {name} line: {text}"))
                    .trim()
                    .to_string()
            };
            (field("KFR_PATH="), field("KFR_KIN="), field("KFR_HOOK="))
        };
        let carries_bin = |path: &str| path.split(':').any(|entry| Path::new(entry) == bin_dir);

        let (after, resolved, hook) = probe();
        assert!(
            carries_bin(&after),
            "a bash login shell does not carry {} on its PATH, so `bash -lc` \
             cannot find kin on a fresh install: {after}",
            bin_dir.display()
        );
        assert_eq!(
            Path::new(&resolved).parent(),
            Some(bin_dir.as_path()),
            "`bash -lc 'command -v kin'` did not resolve into this install: {resolved}"
        );
        assert_eq!(
            hook, "no",
            "the projection hook reached a non-interactive login shell, which is \
             what the seed's `case $- in *i*)` guard exists to prevent: every \
             `bash -lc` would activate the VFS overlay"
        );

        // Falsification for the guard itself: drop it from the created file and
        // the hook fires in the same non-interactive login shell.
        let seeded = fs::read_to_string(home.join(".bash_profile")).unwrap();
        assert!(seeded.contains("case $- in"), "{seeded}");
        let unguarded = seeded
            .lines()
            .filter(|line| !line.starts_with("case $- in") && !line.starts_with("esac"))
            .map(|line| {
                if line.trim_start().starts_with("*i*)") {
                    "[ -f \"$HOME/.bashrc\" ] && . \"$HOME/.bashrc\"".to_string()
                } else {
                    line.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(home.join(".bash_profile"), format!("{unguarded}\n")).unwrap();
        let (_, _, mutant_hook) = probe();
        assert_eq!(
            mutant_hook, "yes",
            "removing the guard did not let the hook through, so the assertion \
             above cannot fail and proves nothing about the guard"
        );

        // Falsification for the PATH line: the pre-fix layout, `.bashrc` and
        // nothing else.
        fs::remove_file(home.join(".bash_profile")).unwrap();
        assert!(
            home.join(".bashrc").exists(),
            "the falsification has to leave the pre-fix file in place"
        );
        let (without, _, _) = probe();
        assert!(
            !carries_bin(&without),
            "with the login file gone the login shell still carries {}, so this \
             check cannot fail and is not evidence: {without}",
            bin_dir.display()
        );
    }

    /// An existing login file belongs to whoever wrote it. Kin appends its PATH
    /// block there and nothing else: no seed, no source line, no reordering of
    /// what was already in it.
    #[test]
    #[serial]
    fn an_existing_bash_login_file_keeps_its_own_semantics() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        let bin_dir = kin_home.join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let mine = "# mine\nexport EDITOR=vi\n";
        fs::write(home.join(".bash_profile"), mine).unwrap();

        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        {
            let _home = EnvVarGuard::set("HOME", &home);
            install_shell_hook("bash").unwrap();
        }

        let profile = fs::read_to_string(home.join(".bash_profile")).unwrap();
        assert_eq!(
            profile,
            format!("{mine}{}", rc_path_block("bash", &bin_dir)),
            "an existing login file keeps its owner's bytes exactly and gains \
             nothing but Kin's own block: {profile}"
        );
        assert!(
            profile.contains(&rc_path_line("bash", &bin_dir)),
            "the PATH line still has to reach the file a login shell reads: {profile}"
        );
        assert!(
            !profile.contains("Created by kin setup"),
            "the seed is for a file Kin creates, never for one it found: {profile}"
        );
        assert!(
            !profile.contains("kin-vfs"),
            "the projection hook belongs in the interactive file only; a login \
             file carrying it would inject the shim into every `bash -lc`: {profile}"
        );

        // The hook's own file is untouched by any of that.
        let bashrc = fs::read_to_string(home.join(".bashrc")).unwrap();
        assert!(bashrc.contains("kin-vfs"), "{bashrc}");
        assert!(
            bashrc.contains(&rc_path_line("bash", &bin_dir)),
            "an interactive non-login bash reads only `.bashrc`, so the PATH line \
             stays here too: {bashrc}"
        );
    }

    /// A second `kin setup` run must not append a second export to either file.
    #[test]
    #[serial]
    fn a_second_bash_setup_run_appends_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(kin_home.join("bin")).unwrap();

        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        let _home = EnvVarGuard::set("HOME", &home);

        install_shell_hook("bash").unwrap();
        let first: Vec<String> = [".bashrc", ".bash_profile"]
            .iter()
            .map(|name| fs::read_to_string(home.join(name)).unwrap())
            .collect();
        install_shell_hook("bash").unwrap();
        let second: Vec<String> = [".bashrc", ".bash_profile"]
            .iter()
            .map(|name| fs::read_to_string(home.join(name)).unwrap())
            .collect();

        assert_eq!(first, second, "a re-run rewrote the rc files");
    }

    /// Uninstall can only excise what setup recorded, so every file the bash
    /// PATH line lands in has to reach the ledger. Recording only `.bashrc`
    /// would leave the export behind in the file a login shell is the one
    /// reading, pointing at a directory the same run had just removed.
    #[test]
    #[serial]
    fn the_ledger_records_both_files_the_bash_path_line_lands_in() {
        use crate::commands::setup_ledger::{ledger_path, ArtifactKind, SetupLedger};

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::create_dir_all(kin_home.join("config")).unwrap();

        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        let _home = EnvVarGuard::set("HOME", &home);

        install_shell_hook("bash").unwrap();
        let plan = SetupPlan {
            install_shell_hook: true,
            configure_mcp: false,
            mcp_assistant_indices: Vec::new(),
            inject_discovery_reminders: false,
            auto_daemon: false,
            show_editor_hint: false,
            show_hosted_hint: false,
        };
        record_setup_ledger(&plan, "bash", &[]);

        let ledger = SetupLedger::load(&ledger_path().unwrap()).unwrap();
        let recorded: Vec<&std::path::PathBuf> = ledger
            .entries
            .iter()
            .filter(|entry| entry.kind == ArtifactKind::ShellPathLine)
            .map(|entry| &entry.path)
            .collect();
        assert!(
            recorded.contains(&&home.join(".bash_profile")),
            "the login file carrying the PATH line is unrecorded, so uninstall \
             cannot remove it: {recorded:?}"
        );
        assert!(
            recorded.contains(&&home.join(".bashrc")),
            "the interactive file's PATH line stopped being recorded: {recorded:?}"
        );
    }

    /// Setup wrote `~/.claude.json` and a global `~/.claude/CLAUDE.md` block and
    /// called it "Claude Code configured". "Configured" is a claim about a
    /// client that is installed; for one that is not, the only new thing is the
    /// file Kin just wrote, and the line has to say so.
    #[test]
    fn an_absent_client_is_never_reported_as_configured() {
        let path = Path::new("/home/u/.claude.json");

        let installed = client_write_summary("Claude Code", true, path);
        assert_eq!(installed, "Claude Code configured (/home/u/.claude.json)");

        // Falsification: same client, same path, detection flipped.
        let absent = client_write_summary("Claude Code", false, path);
        assert!(
            absent.contains("pre-configured for a client that is not installed"),
            "an absent client must be named as absent: {absent}"
        );
        assert!(
            !absent.contains("Claude Code configured"),
            "no wording may read as a configured install: {absent}"
        );
        assert!(
            absent.contains("/home/u/.claude.json"),
            "the file that was written is still named: {absent}"
        );
    }

    /// The reminder is a standing directive in a file every future session of
    /// that client reads, so setup names the file and the block before it
    /// appends, not only after.
    #[test]
    fn the_discovery_reminder_marker_is_the_heading_the_block_carries() {
        assert!(
            KIN_DISCOVERY_REMINDER.contains(KIN_DISCOVERY_MARKER),
            "the announced heading must be the one the block actually carries"
        );

        let tmp = tempfile::tempdir().unwrap();
        let instructions = tmp.path().join("CLAUDE.md");
        assert!(!discovery_reminder_marker_present(&instructions));
        inject_discovery_reminder(&instructions).unwrap();
        assert!(
            discovery_reminder_marker_present(&instructions),
            "a written reminder must be recognized, so the announcement fires once"
        );
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

    /// Build the `.kin` a real repository carries: the directory plus the
    /// manifest `kin init` writes into it. The hooks admit a projection root
    /// only on that manifest, so a fixture that creates the directory alone is
    /// the managed toolchain home's shape rather than a repository's.
    #[cfg(unix)]
    fn seed_repository_marker(root: &Path) {
        fs::create_dir_all(root.join(".kin")).unwrap();
        fs::write(
            root.join(".kin").join("manifest.json"),
            b"{\"repo_id\":\"00000000-0000-4000-8000-000000000000\"}",
        )
        .unwrap();
    }

    /// FIR-2300 contract: a socket inode outlives the daemon that bound it, so
    /// `-S` may appear only as a pre-filter. Both the decision to start a
    /// daemon and the readiness poll must go through the
    /// `_kin_vfs_daemon_listening` connect probe.
    fn daemon_guard_liveness_error(shell: &str, hook: &str) -> Option<String> {
        let (probe_def, start_guard, poll_guard, old_start_guard, old_poll) = match shell {
            "zsh" => (
                "_kin_vfs_daemon_listening() {",
                "if [[ ! -S \"$sock\" ]] || ! _kin_vfs_daemon_listening \"$ws\"; then",
                "if [[ -S \"$sock\" ]] && _kin_vfs_daemon_listening \"$ws\"; then",
                "if [[ ! -S \"$sock\" ]]; then",
                "while [[ ! -S \"$sock\" ]]",
            ),
            "bash" => (
                "_kin_vfs_daemon_listening() {",
                "if [ ! -S \"$sock\" ] || ! _kin_vfs_daemon_listening \"$ws\"; then",
                "if [ -S \"$sock\" ] && _kin_vfs_daemon_listening \"$ws\"; then",
                "if [ ! -S \"$sock\" ]; then",
                "while [ ! -S \"$sock\" ]",
            ),
            "fish" => (
                "function _kin_vfs_daemon_listening",
                "if not test -S $sock; or not _kin_vfs_daemon_listening $ws",
                "if test -S $sock; and _kin_vfs_daemon_listening $ws",
                "if not test -S $sock\n",
                "while not test -S $sock",
            ),
            other => return Some(format!("no liveness contract defined for shell {other}")),
        };
        if !hook.contains(probe_def) {
            return Some(format!(
                "{shell} hook defines no _kin_vfs_daemon_listening probe"
            ));
        }
        if !hook.contains("kin-vfs status --workspace") {
            return Some(format!(
                "{shell} probe does not connect through `kin-vfs status --workspace`"
            ));
        }
        if !hook.contains(start_guard) {
            return Some(format!(
                "{shell} start decision is not probe-gated: missing `{start_guard}`"
            ));
        }
        if !hook.contains(poll_guard) {
            return Some(format!(
                "{shell} readiness poll is not probe-gated: missing `{poll_guard}`"
            ));
        }
        if hook.contains(old_start_guard) {
            return Some(format!(
                "{shell} still decides on the socket-file test `{}`",
                old_start_guard.trim_end()
            ));
        }
        if hook.contains(old_poll) {
            return Some(format!(
                "{shell} still polls readiness with the socket-file test `{old_poll}`"
            ));
        }
        None
    }

    #[test]
    fn hook_daemon_guards_are_liveness_based() {
        for (shell, hook) in [("zsh", ZSH_HOOK), ("bash", BASH_HOOK), ("fish", FISH_HOOK)] {
            if let Some(err) = daemon_guard_liveness_error(shell, hook) {
                panic!("FIR-2300 regression: {err}");
            }
        }
    }

    #[test]
    fn powershell_hook_probes_the_live_pipe_namespace_not_a_file_marker() {
        // Windows named pipes vanish with the process that serves them, so
        // enumerating \\.\pipe\ is already a listener check; a stale-inode
        // state is unrepresentable there. Pin the probe to the live namespace
        // so the guard never regresses toward a file marker.
        assert!(POWERSHELL_HOOK.contains(r#"[System.IO.Directory]::GetFiles("\\.\pipe\")"#));
        assert!(!POWERSHELL_HOOK.contains("vfs.sock"));
    }

    /// Controls proving `hook_daemon_guards_are_liveness_based` can fail: the
    /// exact guards the hooks shipped before FIR-2300 must be rejected in
    /// every shell, and each late rule must be reachable on its own.
    #[test]
    fn liveness_guard_contract_rejects_the_pre_fir2300_guards() {
        let old_zsh = r#"
_kin_vfs_activate() {
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
}
"#;
        let old_bash = r#"
_kin_vfs_activate() {
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
}
"#;
        let old_fish = r#"
function _kin_vfs_activate
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
end
"#;
        for (shell, old_hook) in [("zsh", old_zsh), ("bash", old_bash), ("fish", old_fish)] {
            assert!(
                daemon_guard_liveness_error(shell, old_hook).is_some(),
                "{shell}: the pre-FIR-2300 socket-file guard passed the liveness \
                 contract, so the contract test cannot fail"
            );
        }

        // A hook that adopts the probe for the start decision but keeps a
        // lingering file-test poll must fail on the poll rule specifically.
        let probe_but_old_poll = r#"
_kin_vfs_daemon_listening() {
    out="$(kin-vfs status --workspace "$1" 2>/dev/null)" || return 1
}
if [[ ! -S "$sock" ]] || ! _kin_vfs_daemon_listening "$ws"; then
    if [[ -S "$sock" ]] && _kin_vfs_daemon_listening "$ws"; then
        :
    fi
    while [[ ! -S "$sock" ]] && (( attempts < 10 )); do
        sleep 0.1
    done
fi
"#;
        let err = daemon_guard_liveness_error("zsh", probe_but_old_poll)
            .expect("a lingering socket-file poll must fail the contract");
        assert!(
            err.contains("still polls readiness"),
            "wrong rule fired for the lingering poll control: {err}"
        );
    }

    /// Runs each POSIX hook in a real shell against a stub `kin-vfs` and a
    /// workspace holding a genuinely stale socket inode (bound, then dropped),
    /// proving the guard decides on a listener rather than the socket file.
    ///
    /// The shim export is asserted in every scenario, including the one where
    /// no daemon ever answers: per the authority contract, unreachable
    /// authority must surface as EIO from the shim, never as silent raw-disk
    /// reads, so the shell only ever decides whether to START a daemon and
    /// never whether the preload applies.
    /// How long a scenario waits for a start the hook launched detached.
    ///
    /// Only how long a run that is going to fail spends proving it: the wait
    /// below returns the instant the line lands, so a passing scenario never
    /// spends this. Sized against a runner where the whole probe shell took ten
    /// seconds rather than the three a quiet box takes.
    #[cfg(unix)]
    const DETACHED_START_BOUND: Duration = Duration::from_secs(30);

    /// Start lines the stub has recorded so far.
    #[cfg(unix)]
    fn recorded_starts(start_log: &Path) -> usize {
        fs::read_to_string(start_log)
            .map(|log| log.lines().count())
            .unwrap_or(0)
    }

    /// Wait for the starts a scenario expects, and return what the log holds.
    ///
    /// Every hook launches `kin-vfs start` detached, zsh with `&!` and the
    /// others with a plain `&`, and none of them waits for it. `Command::output`
    /// waits for the probe shell alone, so reading the log the moment it returns
    /// reads a side effect of a process nothing synchronised with: on a loaded
    /// host the shell's ten bounded retries expire and it exits before the
    /// disowned grandchild has appended its line (FIR-2573).
    ///
    /// So wait on the observable rather than on the shell. This returns as soon
    /// as the expected count is there and hands the count back either way, so
    /// the caller's assertion still names the scenario and prints the call log.
    /// A scenario expecting no start has nothing to wait for and is read
    /// directly: a start that has not landed yet cannot fail that assertion, so
    /// it has never been the flaky direction.
    #[cfg(unix)]
    fn starts_recorded_within_bound(start_log: &Path, expected: usize) -> usize {
        let deadline = std::time::Instant::now() + DETACHED_START_BOUND;
        loop {
            let starts = recorded_starts(start_log);
            if starts >= expected || std::time::Instant::now() >= deadline {
                return starts;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[cfg(unix)]
    #[test]
    fn hook_liveness_guard_starts_on_stale_sockets_and_keeps_the_shim_unconditional() {
        use std::os::unix::fs::PermissionsExt;

        let fixture = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(fixture.path()).unwrap();

        let ws = root.join("workspace");
        seed_repository_marker(&ws);
        // A real stale socket: bind a listener, then drop it. The inode stays
        // behind, which is exactly the state `-S` misreads as a live daemon.
        let sock = ws.join(".kin/vfs.sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
        assert!(sock.exists(), "stale socket fixture was not left behind");

        let kin_home = root.join("kin-home");
        let lib = kin_home.join("lib");
        fs::create_dir_all(&lib).unwrap();
        fs::write(lib.join("libkin_vfs_shim.dylib"), b"SHIM").unwrap();
        fs::write(lib.join("libkin_vfs_shim.so"), b"SHIM").unwrap();

        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let stub = bin.join("kin-vfs");
        // Mirrors the real CLI's exit contract: `status` exits 0 whether or
        // not a daemon listens; only the Status line differs.
        fs::write(
            &stub,
            r#"#!/bin/sh
printf '%s\n' "$*" >> "$STUB_CALLS"
case "$1" in
status)
    mode="$STUB_STATUS_MODE"
    if [ "$mode" = follow_start ]; then
        if [ -s "$STUB_START_LOG" ]; then mode=running; else mode=stale; fi
    fi
    echo "Workspace: $3"
    echo "Socket:    $3/.kin/vfs.sock"
    if [ "$mode" = running ]; then
        echo "Status:    running (PID 12345), healthy"
    else
        echo "Status:    stopped (stale socket)"
    fi
    exit 0
    ;;
start)
    printf 'start %s\n' "$3" >> "$STUB_START_LOG"
    exit 0
    ;;
esac
exit 0
"#,
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();

        let hooks_dir = root.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let posix_probe = r#"
source "$KIN_TEST_HOOK" || { echo SOURCE_FAILED >&2; exit 97; }
printf 'WORKSPACE=[%s]\n' "${KIN_VFS_WORKSPACE-}"
printf 'DYLD=[%s]\n' "${DYLD_INSERT_LIBRARIES-}"
printf 'LD=[%s]\n' "${LD_PRELOAD-}"
"#;
        let fish_probe = r#"
source $KIN_TEST_HOOK; or begin; echo SOURCE_FAILED >&2; exit 97; end
printf 'WORKSPACE=[%s]\n' "$KIN_VFS_WORKSPACE"
printf 'DYLD=[%s]\n' "$DYLD_INSERT_LIBRARIES"
printf 'LD=[%s]\n' "$LD_PRELOAD"
"#;

        let fish_path = [
            "/opt/homebrew/bin/fish",
            "/usr/local/bin/fish",
            "/usr/bin/fish",
            "/bin/fish",
        ]
        .into_iter()
        .find(|p| Path::new(p).is_file());

        let mut shells: Vec<(&str, &str, &str, &[&str], &str)> = vec![
            (
                "/bin/bash",
                "kin-vfs.bash",
                BASH_HOOK,
                &["--noprofile", "--norc"][..],
                posix_probe,
            ),
            (
                "/bin/zsh",
                "kin-vfs.zsh",
                ZSH_HOOK,
                &["-f"][..],
                posix_probe,
            ),
        ];
        if let Some(fish) = fish_path {
            shells.push((fish, "kin-vfs.fish", FISH_HOOK, &[][..], fish_probe));
        }

        let scenarios = [
            ("running", 0usize, "a live listener must not be restarted"),
            (
                "follow_start",
                1usize,
                "a stale socket must trigger exactly one daemon start \
                 (the pre-FIR-2300 -S guard started none)",
            ),
            (
                "stale",
                1usize,
                "a daemon that never answers still gets one bounded start attempt",
            ),
        ];

        for (shell, hook_name, hook, flags, probe) in shells {
            if !Path::new(shell).is_file() {
                continue;
            }
            let hook_path = hooks_dir.join(hook_name);
            fs::write(&hook_path, hook).unwrap();

            for (mode, expected_starts, why) in scenarios {
                let run = root.join(format!("run-{mode}-{hook_name}"));
                fs::create_dir_all(&run).unwrap();
                let calls = run.join("calls.log");
                let start_log = run.join("start.log");

                let output = std::process::Command::new(shell)
                    .args(flags)
                    .arg("-c")
                    .arg(probe)
                    .current_dir(&ws)
                    .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
                    .env("HOME", &root)
                    .env("KIN_HOME", &kin_home)
                    .env("KIN_TEST_HOOK", &hook_path)
                    .env("STUB_STATUS_MODE", mode)
                    .env("STUB_CALLS", &calls)
                    .env("STUB_START_LOG", &start_log)
                    .env_remove("KIN_DIR")
                    .env_remove("KIN_SESSION_DIR")
                    .env_remove("KIN_VFS_DISABLE")
                    .env_remove("KIN_VFS_STRICT")
                    .env_remove("KIN_VFS_WORKSPACE")
                    .env_remove("KIN_VFS_SOCK")
                    .env_remove("DYLD_INSERT_LIBRARIES")
                    .env_remove("LD_PRELOAD")
                    .output()
                    .unwrap();

                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    output.status.success(),
                    "{hook_name}/{mode}: probe shell failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
                );

                let starts = if expected_starts == 0 {
                    recorded_starts(&start_log)
                } else {
                    starts_recorded_within_bound(&start_log, expected_starts)
                };
                let calls_text = fs::read_to_string(&calls).unwrap_or_default();
                assert_eq!(
                    starts, expected_starts,
                    "{hook_name}/{mode}: {why}\ncalls:\n{calls_text}\nstdout:\n{stdout}"
                );

                assert!(
                    calls_text.contains(&format!("status --workspace {}", ws.display())),
                    "{hook_name}/{mode}: the guard never probed the daemon\ncalls:\n{calls_text}"
                );

                assert!(
                    stdout.contains(&format!("WORKSPACE=[{}]", ws.display())),
                    "{hook_name}/{mode}: workspace not activated\nstdout:\n{stdout}"
                );

                let expected_preload = if cfg!(target_os = "macos") {
                    Some(format!(
                        "DYLD=[{}]",
                        lib.join("libkin_vfs_shim.dylib").display()
                    ))
                } else if cfg!(target_os = "linux") {
                    Some(format!("LD=[{}]", lib.join("libkin_vfs_shim.so").display()))
                } else {
                    None
                };
                if let Some(expected) = &expected_preload {
                    assert!(
                        stdout.contains(expected),
                        "{hook_name}/{mode}: shim preload missing or gated on daemon \
                         liveness\nstdout:\n{stdout}\nstderr:\n{stderr}"
                    );
                }
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_installed_hooks_enforce_canonical_git_and_session_boundaries() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().join("root with spaces");
        fs::create_dir(&root_path).unwrap();
        let root_path = fs::canonicalize(root_path).unwrap();
        seed_repository_marker(&root_path);

        let nested_git = root_path.join("linked-worktree");
        let nested_start = nested_git.join("src/deep");
        fs::create_dir_all(&nested_start).unwrap();
        fs::write(
            nested_git.join(".git"),
            "gitdir: ../repo/.git/worktrees/linked-worktree\n",
        )
        .unwrap();

        let nested_kin = root_path.join("kin-workspace");
        let local_start = nested_kin.join("src/deep");
        seed_repository_marker(&nested_kin);
        fs::create_dir_all(nested_kin.join(".git")).unwrap();
        fs::create_dir_all(&local_start).unwrap();

        let session_plain = root_path.join("runs/session-plain");
        let session_plain_start = session_plain.join("src/deep");
        fs::create_dir_all(&session_plain_start).unwrap();

        let session_repo = root_path.join("runs/session-repo");
        let session_repo_start = session_repo.join("src/deep");
        seed_repository_marker(&session_repo);
        fs::create_dir_all(session_repo.join(".git")).unwrap();
        fs::create_dir_all(&session_repo_start).unwrap();
        let normalized_session_repo = root_path.join("runs/../runs/session-repo");

        let nested_session = root_path.join("runs/session-with-nested-repo");
        let nested_session_repo = nested_session.join("nested");
        let nested_session_start = nested_session_repo.join("src/deep");
        seed_repository_marker(&nested_session_repo);
        fs::create_dir_all(&nested_session_start).unwrap();

        let aliased_session_target = root_path.join("runs/session-alias-target");
        let aliased_session_target_start = aliased_session_target.join("src/deep");
        seed_repository_marker(&aliased_session_target);
        fs::create_dir_all(aliased_session_target.join(".git")).unwrap();
        fs::create_dir_all(&aliased_session_target_start).unwrap();
        let aliased_session = root_path.join("session-alias");
        symlink(&aliased_session_target, &aliased_session).unwrap();
        let aliased_session_start = aliased_session.join("src/deep");

        let escape_link = session_plain.join("escape");
        symlink(&nested_git, &escape_link).unwrap();
        let escape_start = escape_link.join("src/deep");

        let physical_git_container = root_path.join("logical-container");
        fs::create_dir(&physical_git_container).unwrap();
        let physical_git_link = physical_git_container.join("deep-link");
        symlink(&nested_start, &physical_git_link).unwrap();

        let symlink_kin_root = root_path.join("symlink-kin-marker");
        fs::create_dir(&symlink_kin_root).unwrap();
        symlink(root_path.join(".kin"), symlink_kin_root.join(".kin")).unwrap();

        let hooks = root_path.join("hooks");
        fs::create_dir(&hooks).unwrap();
        let probe = r#"
fail() {
    printf 'hook assertion failed: %s\n' "$1" >&2
    exit 1
}
expect_none() {
    if _kin_vfs_find_workspace "$1" >/dev/null; then
        fail "$2 unexpectedly resolved"
    fi
}
expect_workspace() {
    local observed
    observed="$(_kin_vfs_find_workspace "$1")" || fail "$3 did not resolve"
    [ "$observed" = "$2" ] || fail "$3 resolved $observed instead of $2"
}

export KIN_VFS_WORKSPACE=/stale/workspace
export KIN_VFS_WORKSPACE_ALIASES=/stale/alias
export KIN_VFS_SOCK=/stale/socket
export KIN_VFS_PIPE=/stale/pipe
export KIN_VFS_CANARY=stale
export KIN_VFS_INTERPOSE_ACTIVE=1
export KIN_VFS_LAST_DIR=/stale/last
export DYLD_INSERT_LIBRARIES=/stale/preload.dylib
export LD_PRELOAD=/stale/preload.so
source "$1" || fail "source"

[ -z "${KIN_VFS_WORKSPACE+x}" ] || fail "disabled hook retained workspace"
[ -z "${KIN_VFS_WORKSPACE_ALIASES+x}" ] || fail "disabled hook retained aliases"
[ -z "${KIN_VFS_SOCK+x}" ] || fail "disabled hook retained socket"
[ -z "${KIN_VFS_PIPE+x}" ] || fail "disabled hook retained pipe"
[ -z "${KIN_VFS_CANARY+x}" ] || fail "disabled hook retained canary"
[ -z "${KIN_VFS_INTERPOSE_ACTIVE+x}" ] || fail "disabled hook retained interpose state"
[ -z "${KIN_VFS_LAST_DIR+x}" ] || fail "disabled hook retained last-dir authority"
[ -z "${DYLD_INSERT_LIBRARIES+x}" ] || fail "disabled hook retained DYLD preload"
[ -z "${LD_PRELOAD+x}" ] || fail "disabled hook retained LD preload"
[ "$KIN_VFS_DISABLE" = 1 ] || fail "hook cleared disable policy"
expect_none "$TEST_LOCAL_START" "disabled local repo"

unset KIN_VFS_DISABLE
export KIN_SESSION_DIR="$TEST_SESSION_PLAIN"
export KIN_VFS_WORKSPACE=/stale/workspace
export KIN_VFS_WORKSPACE_ALIASES=/stale/alias
export KIN_VFS_SOCK=/stale/socket
export KIN_VFS_PIPE=/stale/pipe
export DYLD_INSERT_LIBRARIES=/stale/preload.dylib
export LD_PRELOAD=/stale/preload.so
if type _kin_vfs_prompt_command >/dev/null 2>&1; then
    _kin_vfs_prompt_command
else
    _kin_vfs_chpwd
fi
[ -z "${KIN_VFS_WORKSPACE+x}" ] || fail "no-match retained workspace"
[ -z "${KIN_VFS_WORKSPACE_ALIASES+x}" ] || fail "no-match retained aliases"
[ -z "${KIN_VFS_SOCK+x}" ] || fail "no-match retained socket"
[ -z "${KIN_VFS_PIPE+x}" ] || fail "no-match retained pipe"
[ -z "${DYLD_INSERT_LIBRARIES+x}" ] || fail "no-match retained DYLD preload"
[ -z "${LD_PRELOAD+x}" ] || fail "no-match retained LD preload"

unset KIN_SESSION_DIR
expect_none "$TEST_NESTED_GIT_START" "nearer Git boundary"
expect_none "$TEST_PHYSICAL_GIT_LINK" "physical Git boundary"
expect_none "$TEST_SYMLINK_KIN" "symlinked Kin marker"
expect_workspace "$TEST_LOCAL_START" "$TEST_LOCAL_ROOT" "local Kin repo"

export KIN_SESSION_DIR="$TEST_SESSION_PLAIN"
expect_none "$TEST_SESSION_PLAIN_START" "plain session"
expect_none "$TEST_LOCAL_START" "cwd outside active session"
expect_none "$TEST_ESCAPE_START" "session symlink escape"

export KIN_SESSION_DIR=relative/session
expect_none "$TEST_LOCAL_START" "relative session boundary"
export KIN_SESSION_DIR="$TEST_MISSING_SESSION"
expect_none "$TEST_LOCAL_START" "missing session boundary"

export KIN_SESSION_DIR="$TEST_NORMALIZED_SESSION_REPO"
expect_workspace "$TEST_SESSION_REPO_START" "$TEST_SESSION_REPO" "normalized session root"

export KIN_SESSION_DIR="$TEST_NESTED_SESSION"
expect_none "$TEST_NESTED_SESSION_START" "nested Kin marker inside session"

export KIN_SESSION_DIR="$TEST_ALIASED_SESSION"
expect_workspace "$TEST_ALIASED_SESSION_START" "$TEST_ALIASED_SESSION_PHYSICAL" \
    "safe lexical session alias"
"#;

        for (shell, hook_name, hook, flags) in [
            (
                "/bin/bash",
                "kin-vfs.bash",
                BASH_HOOK,
                &["--noprofile", "--norc"][..],
            ),
            ("/bin/zsh", "kin-vfs.zsh", ZSH_HOOK, &["-f"][..]),
        ] {
            if !Path::new(shell).is_file() {
                continue;
            }
            let hook_path = hooks.join(hook_name);
            fs::write(&hook_path, hook).unwrap();
            let output = std::process::Command::new(shell)
                .args(flags)
                .arg("-c")
                .arg(probe)
                .arg("kin-setup-git-boundary-test")
                .arg(&hook_path)
                .current_dir(&session_plain_start)
                .env("PATH", "/usr/bin:/bin")
                .env("KIN_HOME", root_path.join("kin-home"))
                .env_remove("KIN_DIR")
                .env("KIN_SESSION_DIR", &session_plain)
                .env("KIN_VFS_DISABLE", "1")
                .env_remove("DYLD_INSERT_LIBRARIES")
                .env_remove("LD_PRELOAD")
                .env("TEST_NESTED_GIT_START", &nested_start)
                .env("TEST_LOCAL_START", &local_start)
                .env("TEST_LOCAL_ROOT", &nested_kin)
                .env("TEST_SESSION_PLAIN", &session_plain)
                .env("TEST_SESSION_PLAIN_START", &session_plain_start)
                .env("TEST_MISSING_SESSION", root_path.join("missing-session"))
                .env("TEST_SESSION_REPO", &session_repo)
                .env("TEST_SESSION_REPO_START", &session_repo_start)
                .env("TEST_NORMALIZED_SESSION_REPO", &normalized_session_repo)
                .env("TEST_NESTED_SESSION", &nested_session)
                .env("TEST_NESTED_SESSION_START", &nested_session_start)
                .env("TEST_ALIASED_SESSION", &aliased_session)
                .env("TEST_ALIASED_SESSION_START", &aliased_session_start)
                .env("TEST_ALIASED_SESSION_PHYSICAL", &aliased_session_target)
                .env("TEST_ESCAPE_START", &escape_start)
                .env("TEST_PHYSICAL_GIT_LINK", &physical_git_link)
                .env("TEST_SYMLINK_KIN", &symlink_kin_root)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{hook_name} crossed a Git or session boundary\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// FIR-2552: the managed toolchain home is `.kin`-shaped, so a hook that
    /// admits a projection root on the directory alone binds `$HOME` itself.
    /// On the released 0.5.45 bytes that made every path under `$HOME` answer
    /// EIO, because the shim owned a root no daemon served. The hook must walk
    /// past the toolchain home, and must still bind a real repository under it.
    ///
    /// Driven through the installed hook in the real shell rather than through
    /// `_kin_vfs_scan_path` alone, because what broke the container was the
    /// variable the hook exported on source, not a helper's return code.
    #[cfg(unix)]
    #[test]
    fn unix_installed_hooks_leave_a_toolchain_shaped_home_unbound() {
        let root = tempfile::tempdir().unwrap();
        let home = fs::canonicalize(root.path()).unwrap().join("home");
        fs::create_dir_all(&home).unwrap();

        // The managed toolchain home, in the shape `kin setup` provisions:
        // a real `.kin` directory carrying bin/, lib/, shell/, config/ and
        // registry.toml, and never a repository manifest.
        let kin_home = home.join(".kin");
        for dir in ["bin", "lib", "shell", "config"] {
            fs::create_dir_all(kin_home.join(dir)).unwrap();
        }
        fs::write(kin_home.join("registry.toml"), b"# managed toolchain\n").unwrap();
        let shim_name = if cfg!(target_os = "macos") {
            "libkin_vfs_shim.dylib"
        } else {
            "libkin_vfs_shim.so"
        };
        let shim = kin_home.join("lib").join(shim_name);
        fs::write(&shim, b"\x7fELF not a real object, only non-empty\n").unwrap();

        // A real repository under that home, and a plain directory under it.
        let repo = home.join("demo-repo");
        let repo_start = repo.join("src/deep");
        fs::create_dir_all(&repo_start).unwrap();
        seed_repository_marker(&repo);
        let plain = home.join("plain/sub");
        fs::create_dir_all(&plain).unwrap();

        let hooks = home.join("hooks");
        fs::create_dir_all(&hooks).unwrap();

        let posix_probe = r#"
source "$KIN_TEST_HOOK" || { echo SOURCE_FAILED >&2; exit 97; }
printf 'WORKSPACE=[%s]\n' "${KIN_VFS_WORKSPACE-}"
printf 'DYLD=[%s]\n' "${DYLD_INSERT_LIBRARIES-}"
printf 'LD=[%s]\n' "${LD_PRELOAD-}"
"#;
        let fish_probe = r#"
source $KIN_TEST_HOOK; or begin; echo SOURCE_FAILED >&2; exit 97; end
printf 'WORKSPACE=[%s]\n' "$KIN_VFS_WORKSPACE"
printf 'DYLD=[%s]\n' "$DYLD_INSERT_LIBRARIES"
printf 'LD=[%s]\n' "$LD_PRELOAD"
"#;
        let fish_path = [
            "/opt/homebrew/bin/fish",
            "/usr/local/bin/fish",
            "/usr/bin/fish",
            "/bin/fish",
        ]
        .into_iter()
        .find(|candidate| Path::new(candidate).is_file());

        let mut shells: Vec<(&str, &str, &str, &[&str], &str)> = vec![
            (
                "/bin/bash",
                "kin-vfs.bash",
                BASH_HOOK,
                &["--noprofile", "--norc"][..],
                posix_probe,
            ),
            (
                "/bin/zsh",
                "kin-vfs.zsh",
                ZSH_HOOK,
                &["-f"][..],
                posix_probe,
            ),
        ];
        if let Some(fish) = fish_path {
            shells.push((fish, "kin-vfs.fish", FISH_HOOK, &[][..], fish_probe));
        }

        // (working directory, the root the hook must bind, why)
        let cases: [(&Path, Option<&Path>, &str); 4] = [
            (
                home.as_path(),
                None,
                "the managed toolchain home is not a repository and must never be bound",
            ),
            (
                plain.as_path(),
                None,
                "a plain directory under the toolchain home walks past it and binds nothing",
            ),
            (
                repo.as_path(),
                Some(repo.as_path()),
                "a repository under the toolchain home still binds",
            ),
            (
                repo_start.as_path(),
                Some(repo.as_path()),
                "a directory inside that repository binds the repository, not the home",
            ),
        ];

        let mut shells_run = 0;
        for (shell, hook_name, hook, flags, probe) in shells {
            if !Path::new(shell).is_file() {
                continue;
            }
            shells_run += 1;
            let hook_path = hooks.join(hook_name);
            fs::write(&hook_path, hook).unwrap();

            for (cwd, expected, why) in cases {
                let output = std::process::Command::new(shell)
                    .args(flags)
                    .arg("-c")
                    .arg(probe)
                    .current_dir(cwd)
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &home)
                    .env("KIN_HOME", &kin_home)
                    .env("KIN_TEST_HOOK", &hook_path)
                    .env_remove("KIN_DIR")
                    .env_remove("KIN_SESSION_DIR")
                    .env_remove("KIN_VFS_DISABLE")
                    .env_remove("KIN_VFS_WORKSPACE")
                    .env_remove("KIN_VFS_SOCK")
                    .env_remove("DYLD_INSERT_LIBRARIES")
                    .env_remove("LD_PRELOAD")
                    .output()
                    .unwrap();
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    output.status.success(),
                    "{hook_name} at {}: probe shell failed\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    cwd.display()
                );

                let expected_line = match expected {
                    Some(root) => format!("WORKSPACE=[{}]", root.display()),
                    None => "WORKSPACE=[]".to_string(),
                };
                assert!(
                    stdout.contains(&expected_line),
                    "{hook_name} at {}: {why}\nexpected {expected_line}\nstdout:\n{stdout}",
                    cwd.display()
                );

                // The preload follows the binding: nothing bound means nothing
                // injected, so a home that is not a repository leaves every
                // process in it on raw disk rather than under an unserved root.
                let preload_line = if cfg!(target_os = "macos") {
                    format!("DYLD=[{}]", shim.display())
                } else {
                    format!("LD=[{}]", shim.display())
                };
                let empty_preload = if cfg!(target_os = "macos") {
                    "DYLD=[]"
                } else {
                    "LD=[]"
                };
                if expected.is_some() {
                    assert!(
                        stdout.contains(&preload_line),
                        "{hook_name} at {}: a bound repository must still inject the shim\
                         \nstdout:\n{stdout}",
                        cwd.display()
                    );
                } else {
                    assert!(
                        stdout.contains(empty_preload),
                        "{hook_name} at {}: an unbound directory must not inject the shim\
                         \nstdout:\n{stdout}",
                        cwd.display()
                    );
                }
            }
        }
        assert!(
            shells_run > 0,
            "no POSIX shell was available, so this test proved nothing"
        );
    }

    /// The text contract, so the four installed hooks cannot drift apart and so
    /// the one this fleet has no host for is covered too. PowerShell is checked
    /// here or nowhere.
    #[test]
    fn every_installed_hook_admits_a_root_only_on_the_repository_manifest() {
        // (shell, hook, the predicate it must carry, the pre-fix adjacency it
        // must no longer carry: the bare `.kin`-is-a-directory admission)
        let contracts: [(&str, &str, &str, &str); 4] = [
            (
                "zsh",
                ZSH_HOOK,
                "_kin_vfs_is_repository() {\n    [[ -f \"$1/.kin/manifest.json\" ]]\n}",
                "[[ -d \"$dir/.kin\" && ! -L \"$dir/.kin\" ]] || return 1\n            if [[ -n \"$boundary\"",
            ),
            (
                "bash",
                BASH_HOOK,
                "_kin_vfs_is_repository() {\n    [ -f \"$1/.kin/manifest.json\" ]\n}",
                "[ -d \"$dir/.kin\" ] && [ ! -L \"$dir/.kin\" ] || return 1\n            if [ -n \"$boundary\"",
            ),
            (
                "fish",
                FISH_HOOK,
                "function _kin_vfs_is_repository\n    test -f \"$argv[1]/.kin/manifest.json\"\nend",
                "test -d \"$dir/.kin\"; and not test -L \"$dir/.kin\"; or return 1\n            if test -n \"$boundary\"",
            ),
            (
                "powershell",
                POWERSHELL_HOOK,
                "[System.IO.File]::Exists((Join-Path (Join-Path $Path \".kin\") \"manifest.json\"))",
                "-ne 0)) {\n                return $null\n            }\n            if ($Boundary",
            ),
        ];
        for (shell, hook, predicate, pre_fix) in contracts {
            assert!(
                hook.contains(predicate),
                "the {shell} hook carries no repository-manifest predicate; \
                 a `.kin` directory alone admits the managed toolchain home as a \
                 projection root (FIR-2552)"
            );
            assert!(
                !hook.contains(pre_fix),
                "the {shell} hook still admits a root straight off the `.kin` directory test, \
                 so the toolchain home binds again (FIR-2552)"
            );
        }
    }

    /// The Kin-family binaries every shell hook must exclude from the shim.
    const SHIM_EXCLUDED_BINARIES: [&str; 8] = [
        "kin",
        "kin-real",
        "kin-daemon",
        "kin-mcp",
        "kin-vfs",
        "kin-bench-prep",
        "kin-bench-eval",
        "kin-bench-target",
    ];

    #[test]
    fn posix_shim_exclusion_wrappers_depend_on_no_other_function() {
        for (shell, source) in [("zsh", ZSH_HOOK), ("bash", BASH_HOOK)] {
            for binary in SHIM_EXCLUDED_BINARIES {
                let wrapper = format!(
                    "{binary}() {{ DYLD_INSERT_LIBRARIES= LD_PRELOAD= command {binary} \"$@\"; }}"
                );
                assert!(
                    source.contains(&wrapper),
                    "{shell} hook does not define a self-sufficient wrapper for {binary}; \
                     a wrapper that delegates to a helper breaks whenever a consumer \
                     replays only public functions"
                );
            }

            for binary in SHIM_EXCLUDED_BINARIES {
                let delegating = format!("{binary}() {{ _kin_vfs_exec_without_preload ");
                assert!(
                    !source.contains(&delegating),
                    "{shell} hook wrapper for {binary} still delegates to a private helper"
                );
            }
        }
    }

    #[test]
    fn fish_hook_excludes_the_same_binaries_as_the_posix_hooks() {
        for binary in SHIM_EXCLUDED_BINARIES {
            let definition = format!("function {binary} --wraps={binary} ");
            assert!(
                FISH_HOOK.contains(&definition),
                "fish hook leaves {binary} running with the VFS shim injected, \
                 contradicting the exclusion the zsh and bash hooks enforce"
            );
            let body = format!("command {binary} $argv");
            assert!(
                FISH_HOOK.contains(&body),
                "fish hook wrapper for {binary} does not exec the real binary"
            );
        }
    }

    /// Replays only the public wrappers into a fresh shell, the way a consumer
    /// that snapshots exported functions and drops underscore-prefixed private
    /// ones does, then runs each wrapper against a stub binary.
    ///
    /// Before the wrappers inlined the exclusion this exited 127 with
    /// `command not found: _kin_vfs_exec_without_preload`, leaving `kin`
    /// unrunnable in any such shell.
    #[test]
    fn wrappers_survive_a_consumer_that_replays_only_public_functions() {
        let fixture = tempfile::tempdir().unwrap();
        let bin = fixture.path().join("bin");
        fs::create_dir_all(&bin).unwrap();

        for binary in SHIM_EXCLUDED_BINARIES {
            let stub = bin.join(binary);
            // An unset variable and an empty one both mean "no shim injected",
            // and macOS strips DYLD_* when exec'ing a protected system binary,
            // so collapse the two into one observable value.
            fs::write(
                &stub,
                "#!/bin/sh\n\
                 echo \"ran $(basename \"$0\") dyld=[${DYLD_INSERT_LIBRARIES-}] \
                 ld=[${LD_PRELOAD-}]\"\n",
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&stub, fs::Permissions::from_mode(0o755)).unwrap();
            }
        }

        for (shell, hook_name, hook, flags) in [
            (
                "/bin/bash",
                "kin-vfs.bash",
                BASH_HOOK,
                &["--noprofile", "--norc"][..],
            ),
            ("/bin/zsh", "kin-vfs.zsh", ZSH_HOOK, &["-f"][..]),
        ] {
            if !Path::new(shell).exists() {
                continue;
            }

            let hook_path = fixture.path().join(hook_name);
            fs::write(&hook_path, hook).unwrap();

            // Keep only the public wrapper definitions, exactly the subset a
            // function-replaying consumer carries forward.
            let mut replay = String::new();
            for line in hook.lines() {
                for binary in SHIM_EXCLUDED_BINARIES {
                    if line.starts_with(&format!("{binary}() {{")) {
                        replay.push_str(line);
                        replay.push('\n');
                    }
                }
            }
            assert!(
                !replay.is_empty(),
                "{shell}: no public wrapper definitions were captured for replay"
            );

            let mut script = String::from("set -u\n");
            script.push_str(&format!("PATH={}:$PATH\n", bin.display()));
            script.push_str("export DYLD_INSERT_LIBRARIES=/stale/preload.dylib\n");
            script.push_str("export LD_PRELOAD=/stale/preload.so\n");
            script.push_str(&replay);
            for binary in SHIM_EXCLUDED_BINARIES {
                script.push_str(&format!("{binary} --version || exit 127\n"));
            }

            let script_path = fixture.path().join(format!("{hook_name}.replay"));
            fs::write(&script_path, &script).unwrap();

            let output = Command::new(shell)
                .args(flags)
                .arg(&script_path)
                .output()
                .unwrap_or_else(|e| panic!("{shell}: failed to run replay script: {e}"));

            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                output.status.success(),
                "{shell}: replayed wrappers failed (status {:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
                output.status.code()
            );
            assert!(
                !stderr.contains("_kin_vfs_exec_without_preload"),
                "{shell}: replayed wrapper resolved to a missing private helper\nstderr:\n{stderr}"
            );

            for binary in SHIM_EXCLUDED_BINARIES {
                assert!(
                    stdout.contains(&format!("ran {binary} dyld=[] ld=[]")),
                    "{shell}: wrapper for {binary} did not run with both preload \
                     variables cleared\nstdout:\n{stdout}\nstderr:\n{stderr}"
                );
            }
        }
    }

    #[test]
    fn every_installed_hook_carries_the_same_fail_closed_boundary_contract() {
        let cases = [
            ("bash", BASH_HOOK, "logical_workspace", "physical_workspace"),
            ("zsh", ZSH_HOOK, "logical_workspace", "physical_workspace"),
            ("fish", FISH_HOOK, "logical_workspace", "physical_workspace"),
            (
                "powershell",
                POWERSHELL_HOOK,
                "logicalWorkspace",
                "physicalWorkspace",
            ),
        ];

        for (shell, source, logical_workspace, physical_workspace) in cases {
            for required in [
                "KIN_SESSION_DIR",
                "KIN_VFS_DISABLE",
                ".git",
                ".kin",
                "KIN_VFS_WORKSPACE",
                "KIN_VFS_WORKSPACE_ALIASES",
                "KIN_VFS_SOCK",
                "KIN_VFS_PIPE",
                "DYLD_INSERT_LIBRARIES",
                "LD_PRELOAD",
                logical_workspace,
                physical_workspace,
            ] {
                assert!(
                    source.contains(required),
                    "{shell} hook is missing boundary/state contract token {required}"
                );
            }
            assert!(
                !source.contains("KIN_DIR"),
                "{shell} hook retained the pre-release KIN_DIR compatibility alias"
            );
        }
    }

    #[test]
    fn shell_hooks_use_only_the_canonical_kin_home_override() {
        let posix_home = r#"${KIN_HOME:-$HOME/.kin}"#;
        assert!(ZSH_HOOK.contains(posix_home));
        assert!(BASH_HOOK.contains(posix_home));
        assert!(FISH_HOOK.contains("if set -q KIN_HOME"));
        assert!(FISH_HOOK.contains("\"$kin_home/lib/libkin_vfs_shim\""));
        assert!(!ZSH_HOOK.contains("KIN_DIR"));
        assert!(!BASH_HOOK.contains("KIN_DIR"));
        assert!(!FISH_HOOK.contains("KIN_DIR"));
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
        let mut home = EnvVarGuard::unset("KIN_HOME").without("KIN_DIR");
        let fallback = PathBuf::from("/tmp/kin-dir-only");
        let preferred = PathBuf::from("/tmp/kin-home-preferred");

        home.apply("KIN_DIR", Some(&fallback));
        assert_eq!(kin_dir().unwrap(), fallback);

        home.apply("KIN_HOME", Some(&preferred));
        assert_eq!(kin_dir().unwrap(), preferred);
    }

    #[test]
    #[serial]
    fn detect_shell_prefers_the_named_shell_over_ambient_powershell_markers() {
        let mut shell_env = EnvVarGuard::unset("SHELL")
            .without("PSModulePath")
            .without("PSVersionTable");

        // A hosted image that merely ships pwsh exports PSModulePath into every
        // process, including a bash one. The shell is still bash.
        shell_env.apply("PSModulePath", Some("/opt/microsoft/powershell/7/Modules"));
        shell_env.apply("SHELL", Some("/bin/bash"));
        if cfg!(target_os = "windows") {
            assert_eq!(detect_shell(), "powershell");
        } else {
            assert_eq!(detect_shell(), "bash");
        }

        shell_env.apply("SHELL", Some("/bin/zsh"));
        if cfg!(target_os = "windows") {
            assert_eq!(detect_shell(), "powershell");
        } else {
            assert_eq!(detect_shell(), "zsh");
        }
    }

    #[test]
    #[serial]
    fn detect_shell_uses_powershell_markers_when_no_posix_shell_names_itself() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        // Pin the host evidence the nothing-named-itself fallback reads, so this
        // test stays about the markers on every platform.
        write_stub_shell(&bin, "zsh");
        let _path = EnvVarGuard::set("PATH", &bin);

        let mut shell_env = EnvVarGuard::unset("SHELL")
            .without("PSModulePath")
            .without("PSVersionTable");

        assert_eq!(detect_shell(), "zsh");

        shell_env.apply("PSModulePath", Some("/opt/microsoft/powershell/7/Modules"));
        assert_eq!(detect_shell(), "powershell");

        // An unrecognized login shell is not an answer either, so the markers
        // still decide.
        shell_env.apply("SHELL", Some("/usr/bin/false"));
        assert_eq!(detect_shell(), "powershell");
    }

    fn write_stub_shell(bin: &Path, name: &str) {
        fs::create_dir_all(bin).unwrap();
        let shell = bin.join(name);
        fs::write(&shell, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mut permissions = fs::metadata(&shell).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&shell, permissions).unwrap();
        }
    }

    /// `SHELL` is unset in containers, cron, and most non-login invocations —
    /// exactly where first-run happens. Measured on ubuntu:24.04, a flat zsh
    /// default wrote the hook into a `.zshrc` on a host with no zsh, while the
    /// installer had already chosen `.bashrc` for the same install.
    #[test]
    #[serial]
    #[cfg(unix)]
    fn detect_shell_falls_back_to_a_shell_the_host_actually_has() {
        let tmp = tempfile::tempdir().unwrap();
        let bin = tmp.path().join("bin");
        fs::create_dir_all(&bin).unwrap();

        let _shell_env = EnvVarGuard::unset("SHELL")
            .without("PSModulePath")
            .without("PSVersionTable");
        let _path = EnvVarGuard::set("PATH", &bin);

        write_stub_shell(&bin, "bash");
        assert_eq!(
            detect_shell(),
            "bash",
            "a host carrying only bash must be configured as bash"
        );

        fs::remove_file(bin.join("bash")).unwrap();
        write_stub_shell(&bin, "zsh");
        assert_eq!(
            detect_shell(),
            "zsh",
            "a host carrying only zsh must be configured as zsh"
        );

        // Both present: the platform's own preference decides, and it is the
        // same one the installer applies when it picks an rc file.
        write_stub_shell(&bin, "bash");
        let expected = if cfg!(target_os = "macos") {
            "zsh"
        } else {
            "bash"
        };
        assert_eq!(detect_shell(), expected);

        // No shell resolvable at all still yields the platform default rather
        // than failing setup.
        fs::remove_file(bin.join("bash")).unwrap();
        fs::remove_file(bin.join("zsh")).unwrap();
        assert_eq!(
            detect_shell(),
            if cfg!(target_os = "macos") {
                "zsh"
            } else {
                "bash"
            }
        );
    }

    /// A curl-installed user has neither a checkout nor cargo, so naming a cargo
    /// target as the remedy sends them to a command they cannot run.
    #[test]
    fn missing_shim_guidance_routes_managed_installs_to_the_installer() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let managed_bin = kin_home.join("bin");
        fs::create_dir_all(&managed_bin).unwrap();

        let (headline, command) = missing_shim_guidance(Some(&managed_bin.join("kin")), &kin_home);
        assert_eq!(command, crate::daemon_client::KIN_INSTALL_COMMAND);
        assert!(
            !headline.contains("cargo") && !command.contains("cargo"),
            "a managed install must never be told to build the shim: {headline} / {command}"
        );
    }

    #[test]
    fn missing_shim_guidance_keeps_the_cargo_build_for_source_checkouts() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        let checkout_bin = tmp.path().join("checkout").join("target").join("release");
        fs::create_dir_all(&checkout_bin).unwrap();

        let (_headline, command) =
            missing_shim_guidance(Some(&checkout_bin.join("kin")), &kin_home);
        assert_eq!(command, "cargo build --release -p kin-vfs-shim");
    }

    #[test]
    fn missing_shim_guidance_without_a_resolvable_exe_does_not_claim_a_managed_install() {
        let tmp = tempfile::tempdir().unwrap();
        let kin_home = tmp.path().join("kin-home");
        let (_headline, command) = missing_shim_guidance(None, &kin_home);
        assert_eq!(command, "cargo build --release -p kin-vfs-shim");
    }

    /// `applied` is the exact set of claims that become true only when the rc
    /// write lands, so an rc that already carries both blocks must produce none
    /// — there is no write, and nothing to announce.
    #[test]
    fn plan_rc_update_announces_only_what_a_write_would_change() {
        let rc_path = Path::new("/home/u/.zshrc");
        let bin_dir = Path::new("/home/u/.kin/bin");
        let source_line = "source /home/u/.kin/shell/kin-vfs.zsh";

        let fresh = plan_rc_update(
            "",
            "bash",
            source_line,
            rc_path,
            bin_dir,
            true,
            RcBlocks::HookAndPath,
        );
        assert_eq!(fresh.applied.len(), 2, "{:?}", fresh.applied);
        assert!(fresh.already_present.is_empty());
        assert!(fresh.content.contains(source_line));
        assert!(fresh.content.contains(&rc_path_line("bash", bin_dir)));

        let settled = plan_rc_update(
            &fresh.content,
            "bash",
            source_line,
            rc_path,
            bin_dir,
            true,
            RcBlocks::HookAndPath,
        );
        assert!(
            settled.applied.is_empty(),
            "nothing is written on a second run, so nothing may be claimed: {:?}",
            settled.applied
        );
        assert_eq!(settled.already_present.len(), 2);
        assert_eq!(settled.content, fresh.content);
    }

    /// A repair may not write a reference to something it did not install.
    /// `kin doctor --fix` appended `export PATH="$HOME/.kin/bin:$PATH"` to a
    /// `.bashrc` on an archive install, and `~/.kin/bin` did not exist before
    /// that line or after it; only the launcher-provisioned layout populates it.
    #[test]
    fn plan_rc_update_writes_no_path_line_for_a_directory_this_install_never_made() {
        let rc_path = Path::new("/home/u/.bashrc");
        let bin_dir = Path::new("/home/u/.kin/bin");
        let source_line = "source /home/u/.kin/shell/kin-vfs.bash";

        let absent = plan_rc_update(
            "",
            "bash",
            source_line,
            rc_path,
            bin_dir,
            false,
            RcBlocks::HookAndPath,
        );
        assert!(
            !absent.content.contains(".kin/bin"),
            "no PATH line may reference a directory that does not exist: {}",
            absent.content
        );
        assert_eq!(absent.applied.len(), 1, "{:?}", absent.applied);
        assert!(
            absent.applied.iter().all(|line| !line.contains("PATH")),
            "a skipped write may not be claimed: {:?}",
            absent.applied
        );
        assert_eq!(absent.skipped.len(), 1, "{:?}", absent.skipped);
        assert!(
            absent.skipped[0].contains("does not exist")
                && absent.skipped[0].contains("/home/u/.kin/bin"),
            "the skip must name the directory and the reason: {:?}",
            absent.skipped
        );

        // Falsification: the same rc on the layout that does populate the
        // directory still gets the line, so this is not a blanket removal.
        let present = plan_rc_update(
            "",
            "bash",
            source_line,
            rc_path,
            bin_dir,
            true,
            RcBlocks::HookAndPath,
        );
        assert!(
            present.content.contains(&rc_path_line("bash", bin_dir)),
            "a provisioned ~/.kin/bin still earns its PATH line: {}",
            present.content
        );
        assert!(present.skipped.is_empty(), "{:?}", present.skipped);
    }

    #[test]
    fn plan_rc_update_claims_only_the_half_that_is_missing() {
        let rc_path = Path::new("/home/u/.bashrc");
        let bin_dir = Path::new("/home/u/.kin/bin");
        let source_line = "source /home/u/.kin/shell/kin-vfs.bash";

        let hook_only = format!("{}\n", rc_integration_block(source_line));
        let update = plan_rc_update(
            &hook_only,
            "bash",
            source_line,
            rc_path,
            bin_dir,
            true,
            RcBlocks::HookAndPath,
        );
        assert_eq!(update.applied.len(), 1, "{:?}", update.applied);
        assert!(update.applied[0].contains("PATH"));
        assert_eq!(update.already_present.len(), 1);
        assert!(update.already_present[0].contains("already sources"));
    }

    /// zsh reads `.zshenv` on every launch and `.zshrc` only when the shell is
    /// interactive, so the two blocks go to two files: the PATH line where a
    /// script, a Makefile or an agent shelling out will read it, and the hook
    /// where it will not be injected into one.
    #[test]
    fn zsh_writes_its_path_line_where_a_non_interactive_shell_reads_it() {
        let plan = rc_write_plan("zsh").unwrap();
        assert_eq!(plan.len(), 2, "{plan:?}");

        let hook = plan
            .iter()
            .find(|target| target.blocks == RcBlocks::HookOnly)
            .expect("zsh writes a hook-only file");
        assert_eq!(
            hook.path.file_name().and_then(|name| name.to_str()),
            Some(".zshrc"),
            "the hook moved out of the interactive file, which would inject the \
             shim into every non-interactive shell"
        );

        let path = plan
            .iter()
            .find(|target| target.blocks == RcBlocks::PathOnly)
            .expect("zsh writes a path-only file");
        assert_eq!(
            path.path.file_name().and_then(|name| name.to_str()),
            Some(".zshenv"),
            "the PATH line is back in a file only an interactive zsh reads, so a \
             script or an agent cannot find kin at all"
        );
        assert!(
            path.seed_when_absent.is_none(),
            "zsh's `.zshenv` needs nothing but Kin's own block: {path:?}"
        );
    }

    /// fish and PowerShell read one file for both, and splitting them there
    /// would write a second block nothing reads.
    #[test]
    fn a_shell_that_reads_one_file_still_gets_one_plan() {
        for shell in ["fish", "powershell"] {
            let plan = rc_write_plan(shell).unwrap();
            assert_eq!(plan.len(), 1, "{shell}: {plan:?}");
            assert_eq!(plan[0].blocks, RcBlocks::HookAndPath, "{shell}");
            assert_eq!(plan[0].path, shell_rc(shell).unwrap(), "{shell}");
            assert!(plan[0].seed_when_absent.is_none(), "{shell}");
        }
    }

    /// bash reads `.bashrc` only for an interactive non-login shell. A login
    /// shell reads `.bash_profile`, `.bash_login` or `.profile`, the first one
    /// only, and never `.bashrc` unless one of them sources it, so a PATH line
    /// written to `.bashrc` alone is invisible to `bash -lc`, to an ssh login and
    /// to a macOS Terminal tab. This is FIR-2596.
    #[test]
    #[serial]
    fn bash_writes_its_path_line_where_a_login_shell_reads_it() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);

        let plan = rc_write_plan("bash").unwrap();
        assert_eq!(plan.len(), 2, "{plan:?}");

        let interactive = plan
            .iter()
            .find(|target| target.path == home.join(".bashrc"))
            .expect("bash still writes to the file an interactive shell reads");
        assert_eq!(
            interactive.blocks,
            RcBlocks::HookAndPath,
            "dropping the PATH line from `.bashrc` would take kin away from every \
             terminal that opens a non-login shell: {interactive:?}"
        );

        let login = plan
            .iter()
            .find(|target| target.path == home.join(".bash_profile"))
            .expect("a home with no login file gets `.bash_profile`");
        assert_eq!(
            login.blocks,
            RcBlocks::PathOnly,
            "the projection hook must not reach a login file, where `bash -lc` \
             would source it: {login:?}"
        );
        assert_eq!(
            login.seed_when_absent,
            Some(BASH_PROFILE_SEED),
            "a `.bash_profile` Kin creates has to pair with `.bashrc` the way a \
             bash user expects: {login:?}"
        );
    }

    /// Which login file bash reads is decided by what exists, first one wins, so
    /// Kin has to append to that one rather than to a file bash will skip.
    #[test]
    #[serial]
    fn the_bash_login_file_follows_bash_own_resolution_order() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();

        assert_eq!(
            bash_login_rc_in(&home),
            home.join(".bash_profile"),
            "with none of the three present there is nothing to append to, and \
             `.bash_profile` is the one bash looks at first"
        );

        fs::write(home.join(".profile"), "# mine\n").unwrap();
        assert_eq!(bash_login_rc_in(&home), home.join(".profile"));

        fs::write(home.join(".bash_login"), "# mine\n").unwrap();
        assert_eq!(
            bash_login_rc_in(&home),
            home.join(".bash_login"),
            "`.bash_login` outranks `.profile` in bash's own order"
        );

        fs::write(home.join(".bash_profile"), "# mine\n").unwrap();
        assert_eq!(
            bash_login_rc_in(&home),
            home.join(".bash_profile"),
            "`.bash_profile` outranks both, and appending anywhere else would \
             write to a file this login shell never opens"
        );

        // The seed is for a file Kin creates. This one exists, so the plan must
        // not offer to rewrite what its owner put there.
        let _home_guard = EnvVarGuard::set("HOME", &home);
        let login = rc_write_plan("bash")
            .unwrap()
            .into_iter()
            .find(|target| target.blocks == RcBlocks::PathOnly)
            .expect("bash writes a path-only login file");
        assert_eq!(login.path, home.join(".bash_profile"));
    }

    /// Each half of the plan writes its own block and nothing else. Without
    /// this, a two-file shell would get the hook in both files or the PATH line
    /// in neither, and the second failure looks exactly like the bug being
    /// fixed.
    #[test]
    fn each_half_of_a_split_plan_writes_only_its_own_block() {
        let bin_dir = Path::new("/home/u/.kin/bin");
        let source_line = "source /home/u/.kin/shell/kin-vfs.zsh";

        let hook_rc = Path::new("/home/u/.zshrc");
        let hook = plan_rc_update(
            "",
            "zsh",
            source_line,
            hook_rc,
            bin_dir,
            true,
            RcBlocks::HookOnly,
        );
        assert!(hook.content.contains(source_line));
        assert!(
            !hook.content.contains(&rc_path_line("zsh", bin_dir)),
            "the interactive file took the PATH line as well: {}",
            hook.content
        );
        assert_eq!(hook.applied.len(), 1, "{:?}", hook.applied);

        let path_rc = Path::new("/home/u/.zshenv");
        let path = plan_rc_update(
            "",
            "zsh",
            source_line,
            path_rc,
            bin_dir,
            true,
            RcBlocks::PathOnly,
        );
        assert!(path.content.contains(&rc_path_line("zsh", bin_dir)));
        assert!(
            !path.content.contains(source_line),
            "the always-read file took the hook, which injects the shim into \
             every non-interactive shell: {}",
            path.content
        );
        assert_eq!(path.applied.len(), 1, "{:?}", path.applied);
    }

    /// A PATH-only file that is missing the line is the whole defect, so the
    /// plan must announce a write for it even when the hook file is already
    /// settled. It also must stay quiet once the line is there, or every setup
    /// run appends another export.
    #[test]
    fn the_path_only_half_settles_after_one_write() {
        let bin_dir = Path::new("/home/u/.kin/bin");
        let source_line = "source /home/u/.kin/shell/kin-vfs.zsh";
        let path_rc = Path::new("/home/u/.zshenv");

        let first = plan_rc_update(
            "",
            "zsh",
            source_line,
            path_rc,
            bin_dir,
            true,
            RcBlocks::PathOnly,
        );
        assert_eq!(first.applied.len(), 1, "{:?}", first.applied);

        let second = plan_rc_update(
            &first.content,
            "zsh",
            source_line,
            path_rc,
            bin_dir,
            true,
            RcBlocks::PathOnly,
        );
        assert!(second.applied.is_empty(), "{:?}", second.applied);
        assert_eq!(second.content, first.content);
    }

    /// Uninstall has to sweep the file the PATH line was actually written to.
    /// Sweeping only `.zshrc` would leave an export behind pointing at a
    /// directory the same run had just removed.
    #[test]
    fn uninstall_sweeps_the_file_zsh_reads_on_every_launch() {
        let home = Path::new("/home/u");
        let targets = legacy_shell_path_targets(home);
        assert!(
            targets
                .iter()
                .any(|(shell, path)| shell == "zsh" && path == &home.join(".zshenv")),
            "{targets:?}"
        );
        assert!(
            targets
                .iter()
                .any(|(shell, path)| shell == "zsh" && path == &home.join(".zshrc")),
            "{targets:?}"
        );
    }

    /// Same rule for bash, whose PATH line lands in whichever login file bash
    /// reads. Which one that was depends on what existed when setup ran, so
    /// uninstall sweeps all three candidates; the cleanup removes only exact
    /// occurrences of Kin's own block, so a file Kin never wrote to costs
    /// nothing.
    #[test]
    fn uninstall_sweeps_the_files_a_bash_login_shell_reads() {
        let home = Path::new("/home/u");
        let targets = legacy_shell_path_targets(home);
        for name in BASH_LOGIN_RCS {
            assert!(
                targets
                    .iter()
                    .any(|(shell, path)| shell == "bash" && path == &home.join(name)),
                "{name} is unswept, so an uninstall leaves the export behind in \
                 the file a login shell reads: {targets:?}"
            );
        }
        assert!(
            targets
                .iter()
                .any(|(shell, path)| shell == "bash" && path == &home.join(".bashrc")),
            "{targets:?}"
        );
    }

    #[test]
    fn full_uninstall_root_rejects_home_and_unrecognized_custom_data() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();

        let home_error = validate_full_uninstall_root_at(&home, &home, None).unwrap_err();
        assert!(
            home_error.to_string().contains("user home"),
            "unexpected refusal: {home_error:#}"
        );

        let broad = tmp.path().join("tools");
        fs::create_dir_all(broad.join("bin")).unwrap();
        fs::write(broad.join("bin/kin"), b"binary").unwrap();
        fs::write(broad.join("other-product-data"), b"keep").unwrap();
        let broad_error =
            validate_full_uninstall_root_at(&broad, &home, Some(&broad.join("bin/kin")))
                .unwrap_err();
        assert!(
            broad_error.to_string().contains("custom KIN_HOME"),
            "unexpected refusal: {broad_error:#}"
        );

        let misleading_name = tmp.path().join("working");
        fs::create_dir_all(misleading_name.join("bin")).unwrap();
        fs::write(misleading_name.join("bin/kin"), b"binary").unwrap();
        fs::write(misleading_name.join("user-notes.txt"), b"keep").unwrap();
        let misleading_error = validate_full_uninstall_root_at(
            &misleading_name,
            &home,
            Some(&misleading_name.join("bin/kin")),
        )
        .unwrap_err();
        assert!(
            misleading_error.to_string().contains("custom KIN_HOME"),
            "a directory name containing 'kin' must not bypass ownership checks: {misleading_error:#}"
        );

        let managed = tmp.path().join("kin-home");
        fs::create_dir_all(managed.join("bin")).unwrap();
        fs::write(managed.join("bin/kin"), b"binary").unwrap();
        fs::create_dir_all(managed.join("lib")).unwrap();
        fs::write(managed.join("lib/unrelated-user-notes.txt"), b"keep").unwrap();
        let managed_error =
            validate_full_uninstall_root_at(&managed, &home, Some(&managed.join("bin/kin")))
                .unwrap_err();
        assert!(managed_error.to_string().contains("custom KIN_HOME"));
        assert_eq!(
            fs::read(managed.join("lib/unrelated-user-notes.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn full_uninstall_absent_root_never_hides_a_retired_tree() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();
        let retired = home.join(format!(".kin-uninstall-retired-{}", uuid::Uuid::new_v4()));
        let deleting = home.join(format!(".kin-uninstall-delete-{}", uuid::Uuid::new_v4()));
        let incomplete = home.join(format!(
            ".kin-uninstall-incomplete-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(retired.join("bin")).unwrap();
        fs::write(retired.join("bin/kin"), b"still here").unwrap();
        fs::create_dir_all(deleting.join("bin")).unwrap();
        fs::write(deleting.join("bin/kin"), b"also here").unwrap();
        fs::write(&incomplete, b"journal").unwrap();

        let error = validate_full_uninstall_root_at(&home.join(".kin"), &home, None).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("retired managed state"), "{message}");
        assert!(
            message.contains("refusing to report fully_removed"),
            "{message}"
        );
        assert_eq!(fs::read(retired.join("bin/kin")).unwrap(), b"still here");
        assert_eq!(fs::read(deleting.join("bin/kin")).unwrap(), b"also here");
        assert_eq!(fs::read(&incomplete).unwrap(), b"journal");

        fs::create_dir_all(home.join(".kin/bin")).unwrap();
        fs::write(home.join(".kin/bin/kin"), b"new install").unwrap();
        let recreated = validate_full_uninstall_root_at(
            &home.join(".kin"),
            &home,
            Some(&home.join(".kin/bin/kin")),
        )
        .unwrap_err();
        assert!(
            format!("{recreated:#}").contains("retired managed state"),
            "a recreated public install must not hide prior residual state: {recreated:#}"
        );
    }

    #[cfg(windows)]
    const WINDOWS_FULL_UNINSTALL_CHILD_MODE: &str = "KIN_INTERNAL_TEST_FULL_UNINSTALL_CHILD_MODE";
    #[cfg(windows)]
    const WINDOWS_FULL_UNINSTALL_CHILD_ROOT: &str = "KIN_INTERNAL_TEST_FULL_UNINSTALL_CHILD_ROOT";
    #[cfg(windows)]
    const WINDOWS_FULL_UNINSTALL_CHILD_RESULT: &str =
        "KIN_INTERNAL_TEST_FULL_UNINSTALL_CHILD_RESULT";

    #[cfg(windows)]
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    struct WindowsFullUninstallChildResult {
        retired: PathBuf,
        incomplete_marker: PathBuf,
        helper_script: PathBuf,
        helper_ready: PathBuf,
        helper_ready_publishing: PathBuf,
        helper_log: PathBuf,
        parked_original: Option<PathBuf>,
    }

    #[cfg(windows)]
    fn only_windows_uninstall_artifact(parent: &Path, prefix: &str) -> Result<PathBuf> {
        let matches = fs::read_dir(parent)?
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(prefix))
            })
            .collect::<Vec<_>>();
        anyhow::ensure!(
            matches.len() == 1,
            "expected one {prefix} artifact below {}, found {matches:?}",
            parent.display()
        );
        Ok(matches.into_iter().next().expect("length checked above"))
    }

    #[cfg(windows)]
    fn windows_user_path() -> Result<Option<String>> {
        let snapshot_dir = tempfile::tempdir()?;
        let snapshot = snapshot_dir.path().join("user-path.bin");
        let script = r#"$ErrorActionPreference = 'Stop'
$value = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($null -eq $value) {
    [IO.File]::WriteAllBytes($env:KIN_TEST_PATH_SNAPSHOT, [byte[]]@(0))
} else {
    $body = [Text.Encoding]::UTF8.GetBytes($value)
    $payload = New-Object byte[] ($body.Length + 1)
    $payload[0] = 1
    [Array]::Copy($body, 0, $payload, 1, $body.Length)
    [IO.File]::WriteAllBytes($env:KIN_TEST_PATH_SNAPSHOT, $payload)
}
"#;
        let output = Command::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                script,
            ])
            .env("KIN_TEST_PATH_SNAPSHOT", &snapshot)
            .stdin(std::process::Stdio::null())
            .output()
            .context("failed to snapshot the Windows User PATH for native uninstall proof")?;
        anyhow::ensure!(
            output.status.success(),
            "failed to snapshot the Windows User PATH: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = fs::read(&snapshot)?;
        match bytes.split_first() {
            Some((&0, [])) => Ok(None),
            Some((&1, body)) => Ok(Some(String::from_utf8(body.to_vec())?)),
            _ => anyhow::bail!("Windows User PATH snapshot had an invalid encoding marker"),
        }
    }

    #[cfg(windows)]
    fn set_windows_user_path(value: Option<&str>) -> Result<()> {
        let script = r#"$ErrorActionPreference = 'Stop'
$value = if ($env:KIN_TEST_PATH_PRESENT -eq '1') { $env:KIN_TEST_PATH_VALUE } else { $null }
[Environment]::SetEnvironmentVariable('Path', $value, 'User')
"#;
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ]);
        match value {
            Some(value) => {
                command
                    .env("KIN_TEST_PATH_PRESENT", "1")
                    .env("KIN_TEST_PATH_VALUE", value);
            }
            None => {
                command.env("KIN_TEST_PATH_PRESENT", "0");
            }
        }
        let output = command
            .stdin(std::process::Stdio::null())
            .output()
            .context("failed to set the Windows User PATH for native uninstall proof")?;
        anyhow::ensure!(
            output.status.success(),
            "failed to set the Windows User PATH: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }

    #[cfg(windows)]
    struct WindowsUserPathRestore {
        original: Option<String>,
        armed: bool,
    }

    #[cfg(windows)]
    impl WindowsUserPathRestore {
        fn capture() -> Result<Self> {
            Ok(Self {
                original: windows_user_path()?,
                armed: true,
            })
        }

        fn restore(&mut self) -> Result<()> {
            set_windows_user_path(self.original.as_deref())?;
            self.armed = false;
            Ok(())
        }
    }

    #[cfg(windows)]
    impl Drop for WindowsUserPathRestore {
        fn drop(&mut self) {
            if self.armed {
                if let Err(error) = set_windows_user_path(self.original.as_deref()) {
                    eprintln!(
                        "failed to restore the Windows User PATH after uninstall test: {error:#}"
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    fn windows_full_uninstall_child(mode: &str) -> Result<()> {
        let root = PathBuf::from(
            env::var_os(WINDOWS_FULL_UNINSTALL_CHILD_ROOT)
                .context("native uninstall child root was not provided")?,
        );
        let result_path = PathBuf::from(
            env::var_os(WINDOWS_FULL_UNINSTALL_CHILD_RESULT)
                .context("native uninstall child result path was not provided")?,
        );
        let home = root
            .parent()
            .context("native uninstall child root has no home parent")?;
        let validated = validate_full_uninstall_root_at(&root, home, None)?;
        let lock = crate::commands::update::InstallRootLock::acquire_existing_waiting(&root)?;
        if mode == "parent-incarnation-mismatch" {
            let _parent_creation_override =
                EnvVarGuard::set(WINDOWS_UNINSTALL_PARENT_CREATION_OVERRIDE, "0");
            let error = remove_full_install_root(&validated, false, Some(&lock))
                .expect_err("a mismatched parent incarnation must fail the helper handoff");
            let message = format!("{error:#}");
            anyhow::ensure!(
                message.contains("incarnation-safe handoff")
                    && message.contains("atomically restored"),
                "parent-incarnation mismatch produced an unexpected error: {message}"
            );
            anyhow::ensure!(
                install_root_identity(&root)?
                    == validated
                        .identity
                        .context("mismatch fixture lost validated identity")?,
                "failed parent handoff did not restore the original root incarnation"
            );
            anyhow::ensure!(
                !fs::read_dir(home)?
                    .filter_map(std::result::Result::ok)
                    .any(|entry| entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".kin-uninstall-"))),
                "failed parent handoff left an uninstall retirement artifact"
            );
            fs::write(&result_path, message)?;
            return Ok(());
        }
        let outcome = remove_full_install_root(&validated, false, Some(&lock))?;
        anyhow::ensure!(
            outcome.action == "scheduled",
            "native Windows uninstall did not schedule deferred deletion: {outcome:?}"
        );

        // The helper waits for this exact test process, so every artifact is
        // stable and observable until this child writes its result and exits.
        let retired = only_windows_uninstall_artifact(home, ".kin-uninstall-retired-")?;
        let incomplete_marker =
            only_windows_uninstall_artifact(home, ".kin-uninstall-incomplete-")?;
        let token = incomplete_marker
            .file_name()
            .and_then(OsStr::to_str)
            .and_then(|name| name.strip_prefix(".kin-uninstall-incomplete-"))
            .context("native uninstall marker did not carry its helper token")?;
        let helper_script = env::temp_dir().join(format!("kin-uninstall-{token}.ps1"));
        let helper_ready = env::temp_dir().join(format!("kin-uninstall-{token}.ready"));
        let helper_ready_publishing =
            env::temp_dir().join(format!("kin-uninstall-{token}.ready.publishing"));
        let helper_log = env::temp_dir().join(format!("kin-uninstall-{token}.log"));
        anyhow::ensure!(
            retired.is_dir(),
            "validated root was not atomically retired"
        );
        anyhow::ensure!(
            incomplete_marker.is_file(),
            "deferred uninstall did not publish its durable incomplete marker"
        );
        anyhow::ensure!(
            helper_script.is_file(),
            "deferred uninstall helper script was not published"
        );
        anyhow::ensure!(
            fs::read_to_string(&helper_ready)
                .is_ok_and(|nonce| uuid::Uuid::parse_str(&nonce).is_ok()),
            "deferred uninstall helper did not publish a valid incarnation-safe ready handshake"
        );

        let parked_original = if mode == "identity-mismatch" {
            let parked = home.join("parked-original-install-root");
            move_windows_install_root(&retired, &parked)?;
            fs::create_dir_all(&retired)?;
            fs::write(
                retired.join("replacement.txt"),
                b"replacement at retired pathname must survive",
            )?;
            Some(parked)
        } else {
            anyhow::ensure!(
                mode == "success",
                "unknown native uninstall child mode {mode}"
            );
            None
        };

        // Recreate the public pathname before the helper is allowed to run.
        // A correct deferred delete remains bound to the retired incarnation.
        fs::create_dir_all(&root)?;
        fs::write(
            root.join("replacement.txt"),
            b"public path replacement must survive",
        )?;

        let result = WindowsFullUninstallChildResult {
            retired,
            incomplete_marker,
            helper_script,
            helper_ready,
            helper_ready_publishing,
            helper_log,
            parked_original,
        };
        fs::write(&result_path, serde_json::to_vec(&result)?)?;
        Ok(())
    }

    /// What a Windows deferred-uninstall poll observed.
    ///
    /// `Failed` reports state that can never become `Satisfied`. Polling past it
    /// only spends the remaining timeout and reprints the same terminal reason.
    #[cfg(windows)]
    enum WindowsWaitState {
        Satisfied,
        Pending,
        Failed(String),
    }

    #[cfg(windows)]
    fn wait_for_windows_condition(
        label: &str,
        timeout: Duration,
        mut condition: impl FnMut() -> WindowsWaitState,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            match condition() {
                WindowsWaitState::Satisfied => return Ok(()),
                WindowsWaitState::Failed(detail) => {
                    anyhow::bail!("{label} failed before its deadline: {detail}")
                }
                WindowsWaitState::Pending => {}
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for {label}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// Run a test child that launches the production detached uninstall helper.
    ///
    /// The helper outlives the child by design. `Command::output` captures
    /// through pipes, and `CreateProcess` hands every inheritable handle a
    /// process holds to the process it spawns, so the child's pipe ends reach
    /// the helper even though the helper's own stdio is the null device.
    /// Reading those pipes to end-of-file therefore waits for the helper, not
    /// for the child, while the helper waits for state this process publishes
    /// only after the child has been reaped. Capturing into files instead keeps
    /// the wait bound to the child's own lifetime.
    #[cfg(windows)]
    fn run_uninstall_test_child(
        command: &mut Command,
        capture_root: &Path,
        tag: &str,
    ) -> Result<std::process::Output> {
        let stdout_path = capture_root.join(format!("{tag}-child-stdout.log"));
        let stderr_path = capture_root.join(format!("{tag}-child-stderr.log"));
        let stdout = fs::File::create(&stdout_path).with_context(|| {
            format!(
                "failed to create uninstall child stdout capture {}",
                stdout_path.display()
            )
        })?;
        let stderr = fs::File::create(&stderr_path).with_context(|| {
            format!(
                "failed to create uninstall child stderr capture {}",
                stderr_path.display()
            )
        })?;
        let status = command
            .stdout(std::process::Stdio::from(stdout))
            .stderr(std::process::Stdio::from(stderr))
            .status()
            .context("failed to run the native Windows uninstall test child")?;
        Ok(std::process::Output {
            status,
            stdout: fs::read(&stdout_path).with_context(|| {
                format!(
                    "failed to read uninstall child stdout capture {}",
                    stdout_path.display()
                )
            })?,
            stderr: fs::read(&stderr_path).with_context(|| {
                format!(
                    "failed to read uninstall child stderr capture {}",
                    stderr_path.display()
                )
            })?,
        })
    }

    #[cfg(windows)]
    fn run_windows_full_uninstall_child(
        mode: &str,
        root: &Path,
        result_path: &Path,
        helper_release: Option<&Path>,
    ) -> Result<WindowsFullUninstallChildResult> {
        let test_name =
            "commands::setup::tests::native_full_uninstall_runtime_executes_retirement_and_user_path_cleanup";
        let mut command = Command::new(env::current_exe()?);
        command
            .args([test_name, "--exact", "--nocapture"])
            .env(WINDOWS_FULL_UNINSTALL_CHILD_MODE, mode)
            .env(WINDOWS_FULL_UNINSTALL_CHILD_ROOT, root)
            .env(WINDOWS_FULL_UNINSTALL_CHILD_RESULT, result_path)
            .stdin(std::process::Stdio::null());
        match helper_release {
            Some(path) => {
                command.env(WINDOWS_UNINSTALL_HELPER_RELEASE, path);
            }
            None => {
                command.env_remove(WINDOWS_UNINSTALL_HELPER_RELEASE);
            }
        }
        let capture_root = result_path
            .parent()
            .context("native uninstall child result path has no parent")?;
        let output = run_uninstall_test_child(&mut command, capture_root, mode)?;
        if !output.status.success() {
            // If the child failed after launching the production helper, let
            // that helper finish before the caller restores the real User
            // PATH. The isolated home makes this marker lookup exact; no
            // unrelated uninstall helper is observed or waited on.
            let home = root
                .parent()
                .context("native uninstall child root has no home parent")?;
            if let Ok(marker) = only_windows_uninstall_artifact(home, ".kin-uninstall-incomplete-")
            {
                if let Some(token) = marker
                    .file_name()
                    .and_then(OsStr::to_str)
                    .and_then(|name| name.strip_prefix(".kin-uninstall-incomplete-"))
                {
                    let helper_script = env::temp_dir().join(format!("kin-uninstall-{token}.ps1"));
                    wait_for_windows_condition(
                        "failed child uninstall helper to exit before PATH restoration",
                        Duration::from_secs(45),
                        || {
                            if helper_script.exists() {
                                WindowsWaitState::Pending
                            } else {
                                WindowsWaitState::Satisfied
                            }
                        },
                    )?;
                }
            }
            anyhow::bail!(
                "native Windows uninstall child failed ({mode}):\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(serde_json::from_slice(&fs::read(result_path)?)?)
    }

    #[cfg(windows)]
    fn run_windows_parent_incarnation_mismatch_child(
        root: &Path,
        result_path: &Path,
    ) -> Result<String> {
        let test_name =
            "commands::setup::tests::native_full_uninstall_runtime_executes_retirement_and_user_path_cleanup";
        let mut command = Command::new(env::current_exe()?);
        command
            .args([test_name, "--exact", "--nocapture"])
            .env(
                WINDOWS_FULL_UNINSTALL_CHILD_MODE,
                "parent-incarnation-mismatch",
            )
            .env(WINDOWS_FULL_UNINSTALL_CHILD_ROOT, root)
            .env(WINDOWS_FULL_UNINSTALL_CHILD_RESULT, result_path)
            .stdin(std::process::Stdio::null());
        let capture_root = result_path
            .parent()
            .context("parent-incarnation mismatch result path has no parent")?;
        let output =
            run_uninstall_test_child(&mut command, capture_root, "parent-incarnation-mismatch")?;
        anyhow::ensure!(
            output.status.success(),
            "parent-incarnation mismatch child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(fs::read_to_string(result_path)?)
    }

    #[cfg(windows)]
    fn windows_path_fixture(root: &Path) -> (String, String) {
        let parent = root.parent().expect("fixture root has a parent");
        let keep_before = parent.join("keep-before");
        let keep_similar = parent.join(".kin-neighbor").join("bin");
        let keep_after = parent.join("keep-after");
        (
            format!(
                "{};\"{}\";{};{}",
                keep_before.display(),
                root.join("bin").display(),
                keep_similar.display(),
                keep_after.display()
            ),
            format!(
                "{};{};{}",
                keep_before.display(),
                keep_similar.display(),
                keep_after.display()
            ),
        )
    }

    #[cfg(windows)]
    fn prepare_windows_managed_root(root: &Path) -> Result<InstallRootIdentity> {
        fs::create_dir_all(root.join("bin"))?;
        fs::write(root.join("bin/.kinlab-kin-version"), b"0.4.6\n")?;
        fs::write(root.join("bin/original.txt"), b"exact original incarnation")?;
        install_root_identity(root)
    }

    #[cfg(windows)]
    fn exercise_windows_full_uninstall_runtime() -> Result<()> {
        let fixture = tempfile::tempdir()?;

        // First drive the synchronous absent-root cleanup itself. The exact
        // root and requested-root entries disappear while a lookalike remains.
        let direct_root = fixture.path().join("direct").join(".kin");
        let requested_root = fixture.path().join("direct-requested").join(".kin");
        let keep_before = fixture.path().join("direct-keep-before");
        let keep_similar = fixture
            .path()
            .join("direct")
            .join(".kin-neighbor")
            .join("bin");
        let keep_after = fixture.path().join("direct-keep-after");
        let direct_seed = format!(
            "{};{};{};{};{}",
            keep_before.display(),
            direct_root.join("bin").display(),
            keep_similar.display(),
            requested_root.join("bin").display(),
            keep_after.display()
        );
        let direct_expected = format!(
            "{};{};{}",
            keep_before.display(),
            keep_similar.display(),
            keep_after.display()
        );
        set_windows_user_path(Some(&direct_seed))?;
        cleanup_windows_user_path(&direct_root, &requested_root)?;
        anyhow::ensure!(
            windows_user_path()?.as_deref() == Some(direct_expected.as_str()),
            "synchronous Windows User PATH cleanup was not exact"
        );

        // Present the helper with the current PID but the wrong creation
        // identity. It must reject the reusable PID immediately, exit without
        // publishing readiness, and let the parent atomically restore the
        // original root rather than waiting on that process number.
        let handoff_home = fixture.path().join("handoff-mismatch").join("home");
        let handoff_root = handoff_home.join(".kin");
        fs::create_dir_all(&handoff_home)?;
        let handoff_identity = prepare_windows_managed_root(&handoff_root)?;
        let handoff_result_path = fixture.path().join("handoff-mismatch-result.txt");
        let handoff_error =
            run_windows_parent_incarnation_mismatch_child(&handoff_root, &handoff_result_path)?;
        anyhow::ensure!(
            handoff_error.contains("parent process incarnation changed"),
            "helper did not explain its parent-incarnation refusal: {handoff_error}"
        );
        anyhow::ensure!(
            install_root_identity(&handoff_root)? == handoff_identity,
            "parent-incarnation refusal did not preserve the original install root"
        );

        let success_home = fixture.path().join("success").join("home");
        let success_root = success_home.join(".kin");
        fs::create_dir_all(&success_home)?;
        let original_identity = prepare_windows_managed_root(&success_root)?;
        let (success_seed, success_expected_path) = windows_path_fixture(&success_root);
        set_windows_user_path(Some(&success_seed))?;
        let success_result_path = fixture.path().join("success-result.json");
        let success_helper_release = fixture.path().join("success-helper-release");
        let success = run_windows_full_uninstall_child(
            "success",
            &success_root,
            &success_result_path,
            Some(&success_helper_release),
        )?;
        let reinstall_error = crate::commands::update::InstallRootLock::acquire(&success_root)
            .err()
            .context("a reinstall must not enter while deferred uninstall cleanup is pending")?;
        let reinstall_message = format!("{reinstall_error:#}");
        anyhow::ensure!(
            reinstall_message.contains("install mutation is already active")
                || reinstall_message.contains("prior Windows Kin uninstall")
                || reinstall_message.contains("install authority"),
            "pending uninstall rejected reinstall for an unexpected reason: {reinstall_message}"
        );
        fs::write(&success_helper_release, b"continue\n")?;
        wait_for_windows_condition(
            "successful deferred uninstall",
            Duration::from_secs(120),
            || {
                // A journalled helper error is terminal: the helper writes its
                // log on the way out, so no later poll can clear it. An empty
                // log is the same journal still being written, so keep polling
                // rather than reporting a terminal error with no text in it.
                if success.helper_log.is_file() {
                    let log_content = fs::read_to_string(&success.helper_log).unwrap_or_default();
                    if log_content.trim().is_empty() {
                        return WindowsWaitState::Pending;
                    }
                    return WindowsWaitState::Failed(format!(
                        "the deferred uninstall helper journalled a terminal error to {}:\n{}",
                        success.helper_log.display(),
                        log_content.trim_end()
                    ));
                }
                // The helper removes its own script last, so its absence is what
                // proves the teardown ran to completion rather than catching the
                // helper part-way through it.
                if !success.incomplete_marker.exists()
                    && !success.retired.exists()
                    && !success.helper_ready.exists()
                    && !success.helper_ready_publishing.exists()
                    && !success.helper_script.exists()
                {
                    WindowsWaitState::Satisfied
                } else {
                    WindowsWaitState::Pending
                }
            },
        )?;
        let post_cleanup_lock = crate::commands::update::InstallRootLock::acquire(&success_root)
            .context("reinstall authority did not recover after deferred uninstall cleanup")?;
        drop(post_cleanup_lock);
        anyhow::ensure!(
            !success.helper_log.exists(),
            "successful deferred uninstall unexpectedly left {}",
            success.helper_log.display()
        );
        anyhow::ensure!(
            fs::read(success_root.join("replacement.txt"))?
                == b"public path replacement must survive",
            "deferred delete followed the public install pathname replacement"
        );
        anyhow::ensure!(
            install_root_identity(&success_root)? != original_identity,
            "the public replacement retained the deleted root's identity"
        );
        anyhow::ensure!(
            !fs::read_dir(&success_home)?
                .filter_map(std::result::Result::ok)
                .any(|entry| {
                    entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".kin-uninstall-delete-"))
                }),
            "successful deferred uninstall left its private delete incarnation"
        );
        anyhow::ensure!(
            windows_user_path()?.as_deref() == Some(success_expected_path.as_str()),
            "deferred helper did not remove only the exact Kin User PATH entry"
        );

        let failure_home = fixture.path().join("failure").join("home");
        let failure_root = failure_home.join(".kin");
        fs::create_dir_all(&failure_home)?;
        let failure_identity = prepare_windows_managed_root(&failure_root)?;
        let (failure_seed, failure_expected_path) = windows_path_fixture(&failure_root);
        set_windows_user_path(Some(&failure_seed))?;
        let failure_result_path = fixture.path().join("failure-result.json");
        let failure = run_windows_full_uninstall_child(
            "identity-mismatch",
            &failure_root,
            &failure_result_path,
            None,
        )?;
        wait_for_windows_condition(
            "failed deferred uninstall journal",
            Duration::from_secs(120),
            || {
                // The helper journals its refusal inside `catch` and only then
                // clears the handshake artifacts in `finally`, removing its own
                // script last. Waiting for the journal alone would observe the
                // helper mid-teardown; waiting for the script to disappear
                // proves the whole teardown ran.
                if failure.helper_log.is_file() && !failure.helper_script.exists() {
                    WindowsWaitState::Satisfied
                } else {
                    WindowsWaitState::Pending
                }
            },
        )?;
        anyhow::ensure!(
            !failure.helper_ready.exists(),
            "failed deferred uninstall retained its helper ready handshake"
        );
        anyhow::ensure!(
            !failure.helper_ready_publishing.exists(),
            "failed deferred uninstall retained its partial helper ready handshake"
        );
        anyhow::ensure!(
            failure.incomplete_marker.is_file(),
            "failed deferred uninstall cleared its durable incomplete marker"
        );
        anyhow::ensure!(
            fs::read(failure.retired.join("replacement.txt"))?
                == b"replacement at retired pathname must survive",
            "identity-mismatched retired-path replacement was deleted"
        );
        anyhow::ensure!(
            fs::read(failure_root.join("replacement.txt"))?
                == b"public path replacement must survive",
            "failed deferred delete followed the public install pathname replacement"
        );
        let parked_original = failure
            .parked_original
            .as_deref()
            .context("identity-mismatch fixture did not park the original root")?;
        anyhow::ensure!(
            install_root_identity(parked_original)? == failure_identity,
            "failed helper did not preserve the exact original root incarnation"
        );
        let failure_log = fs::read_to_string(&failure.helper_log)?;
        anyhow::ensure!(
            failure_log.contains("identity changed"),
            "failed helper log did not explain its identity refusal: {failure_log}"
        );
        anyhow::ensure!(
            windows_user_path()?.as_deref() == Some(failure_expected_path.as_str()),
            "failed deferred helper did not apply exact User PATH cleanup before journaling"
        );
        fs::remove_file(&failure.helper_log)?;
        Ok(())
    }

    /// This test must run on a native Windows host. Its child process executes
    /// the production MoveFileEx retirement and then exits so the production
    /// PowerShell helper can perform identity-bound deferred deletion.
    #[cfg(windows)]
    #[test]
    #[serial]
    fn native_full_uninstall_runtime_executes_retirement_and_user_path_cleanup() -> Result<()> {
        if let Some(mode) = env::var_os(WINDOWS_FULL_UNINSTALL_CHILD_MODE) {
            return windows_full_uninstall_child(&mode.to_string_lossy());
        }

        let mut path_restore = WindowsUserPathRestore::capture()?;
        let exercise = exercise_windows_full_uninstall_runtime();
        let restore = path_restore.restore();
        match (exercise, restore) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(restore_error)) => Err(restore_error),
            (Err(error), Err(restore_error)) => anyhow::bail!(
                "native uninstall proof failed: {error:#}; restoring the original Windows User PATH also failed: {restore_error:#}"
            ),
        }
    }

    #[cfg(unix)]
    #[test]
    fn full_uninstall_rejects_symlink_binary_as_custom_root_ownership() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = tmp.path().join("tools");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("lib")).unwrap();
        fs::write(root.join("lib/notes.txt"), b"unrelated user library data").unwrap();
        std::os::unix::fs::symlink("/usr/bin/true", root.join("bin/kin")).unwrap();
        fs::create_dir_all(&home).unwrap();

        let error = validate_full_uninstall_root_at(&root, &home, None).unwrap_err();
        assert!(
            error.to_string().contains("custom KIN_HOME"),
            "unexpected refusal: {error:#}"
        );
        assert_eq!(
            fs::read(root.join("lib/notes.txt")).unwrap(),
            b"unrelated user library data"
        );
    }

    #[test]
    #[serial]
    fn full_uninstall_legacy_path_cleanup_is_exact_and_dry_run_is_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let install_root = home.join(".kin");
        fs::create_dir_all(&home).unwrap();
        let _profile = EnvVarGuard::unset("PROFILE");

        let zsh = home.join(".zshrc");
        let bash = home.join(".bashrc");
        let block = rc_path_block("zsh", &install_root.join("bin"));
        fs::write(&zsh, format!("export KEEP=1\n{block}alias k='kin'\n")).unwrap();
        fs::write(&bash, format!("# user heading\n{block}{block}")).unwrap();
        let before_zsh = fs::read(&zsh).unwrap();
        let before_bash = fs::read(&bash).unwrap();

        let dry = cleanup_legacy_shell_path_blocks(&home, &install_root, true).unwrap();
        assert_eq!(dry.len(), 2);
        assert_eq!(fs::read(&zsh).unwrap(), before_zsh);
        assert_eq!(fs::read(&bash).unwrap(), before_bash);
        let dry_entries = fs::read_dir(&home).unwrap().count();
        assert_eq!(
            dry_entries, 2,
            "dry-run must not create persistent config-lock sidecars"
        );

        let removed = cleanup_legacy_shell_path_blocks(&home, &install_root, false).unwrap();
        assert_eq!(removed.len(), 2);
        let zsh_after = fs::read_to_string(&zsh).unwrap();
        let bash_after = fs::read_to_string(&bash).unwrap();
        assert_eq!(zsh_after, "export KEEP=1\nalias k='kin'\n");
        assert_eq!(bash_after, "# user heading\n");
    }

    /// The bash login file is swept too, and the sweep is exact there as well.
    /// A user's own PATH export in the same file is not Kin's to remove, and
    /// telling the two apart is the whole reason the cleanup matches the block
    /// rather than the directory name.
    #[test]
    #[serial]
    fn the_bash_login_sweep_removes_only_the_block_kin_wrote() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let install_root = home.join(".kin");
        fs::create_dir_all(&home).unwrap();
        let _profile = EnvVarGuard::unset("PROFILE");

        let block = rc_path_block("bash", &install_root.join("bin"));
        let mine = "# user heading\nexport PATH=\"$HOME/bin:$PATH\"\n";
        let login = home.join(".bash_profile");
        fs::write(&login, format!("{mine}{block}")).unwrap();

        let removed = cleanup_legacy_shell_path_blocks(&home, &install_root, false).unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(
            fs::read_to_string(&login).unwrap(),
            mine,
            "the sweep took something that was not Kin's block"
        );
    }

    #[test]
    #[cfg(not(windows))]
    fn full_uninstall_removes_only_the_validated_install_root() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = home.join(".kin");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/kin"), b"binary").unwrap();
        let keep = home.join("keep.txt");
        fs::write(&keep, b"user data").unwrap();

        let validated =
            validate_full_uninstall_root_at(&root, &home, Some(&root.join("bin/kin"))).unwrap();
        let lock =
            crate::commands::update::InstallRootLock::acquire_existing_waiting(&root).unwrap();
        let outcome = remove_full_install_root_with_hooks(
            &validated,
            false,
            Some(&lock),
            || Ok(()),
            |_| Ok(()),
        )
        .unwrap();
        assert_eq!(outcome.action, "removed");
        assert!(!root.exists());
        assert_eq!(fs::read(&keep).unwrap(), b"user data");
    }

    #[cfg(unix)]
    #[test]
    fn full_uninstall_never_deletes_an_ordinary_directory_replacement() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = home.join(".kin");
        let parked = home.join("validated-root-moved-away");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/kin"), b"binary").unwrap();

        let validated =
            validate_full_uninstall_root_at(&root, &home, Some(&root.join("bin/kin"))).unwrap();
        let lock =
            crate::commands::update::InstallRootLock::acquire_existing_waiting(&root).unwrap();
        let error = remove_full_install_root_with_hooks(
            &validated,
            false,
            Some(&lock),
            || {
                fs::rename(&root, &parked).unwrap();
                fs::create_dir_all(&root).unwrap();
                fs::write(root.join("unrelated.txt"), b"must survive").unwrap();
                Ok(())
            },
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(
            error.to_string().contains("binding")
                || error.to_string().contains("changed")
                || error.to_string().contains("missing"),
            "unexpected refusal: {error:#}"
        );
        assert_eq!(
            fs::read(root.join("unrelated.txt")).unwrap(),
            b"must survive"
        );
        assert!(parked.exists(), "the validated original must be preserved");
    }

    #[cfg(unix)]
    #[test]
    fn full_uninstall_retired_path_replacement_is_never_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = home.join(".kin");
        let parked = home.join("retired-original-moved-away");
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/kin"), b"binary").unwrap();

        let validated =
            validate_full_uninstall_root_at(&root, &home, Some(&root.join("bin/kin"))).unwrap();
        let lock =
            crate::commands::update::InstallRootLock::acquire_existing_waiting(&root).unwrap();
        let error = remove_full_install_root_with_hooks(
            &validated,
            false,
            Some(&lock),
            || Ok(()),
            |retired| {
                fs::rename(retired, &parked).unwrap();
                fs::create_dir_all(retired).unwrap();
                fs::write(retired.join("unrelated.txt"), b"must survive").unwrap();
                Ok(())
            },
        )
        .unwrap_err();

        assert!(
            format!("{error:#}").contains("binding changed"),
            "unexpected refusal: {error:#}"
        );
        let replacement = fs::read_dir(&home)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .find(|path| path.join("unrelated.txt").is_file())
            .expect("retired-path replacement must be preserved");
        assert_eq!(
            fs::read(replacement.join("unrelated.txt")).unwrap(),
            b"must survive"
        );
        assert!(
            parked.exists(),
            "the descriptor-pinned original remains parked"
        );
    }

    #[cfg(unix)]
    #[test]
    fn full_uninstall_retires_public_executable_before_final_fence() {
        use std::os::unix::fs::PermissionsExt as _;

        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let root = home.join(".kin");
        let daemon = root.join("bin/kin-daemon");
        fs::create_dir_all(daemon.parent().unwrap()).unwrap();
        fs::write(&daemon, b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(&daemon).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&daemon, permissions).unwrap();
        fs::write(root.join("bin/kin"), b"binary").unwrap();

        let validated =
            validate_full_uninstall_root_at(&root, &home, Some(&root.join("bin/kin"))).unwrap();
        let lock =
            crate::commands::update::InstallRootLock::acquire_existing_waiting(&root).unwrap();
        let outcome = remove_full_install_root_with_hooks(
            &validated,
            false,
            Some(&lock),
            || Ok(()),
            |retired| {
                assert!(!root.exists(), "public executable root was not retired");
                assert!(retired.join("bin/kin-daemon").is_file());
                let error = Command::new(&daemon).status().unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::NotFound);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(outcome.action, "removed");
    }

    #[test]
    #[serial]
    fn install_shell_hook_adds_path_and_hook_blocks_idempotently() {
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        let kin_home = tmp.path().join("kin-home");
        fs::create_dir_all(&home).unwrap();
        // The PATH line is written for the layout that populates ~/.kin/bin, so
        // that is the layout this idempotence contract is about.
        fs::create_dir_all(kin_home.join("bin")).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _kin_dir = EnvVarGuard::unset("KIN_DIR");
        let _path = EnvVarGuard::set("PATH", "/usr/bin");

        install_shell_hook("zsh").unwrap();
        install_shell_hook("zsh").unwrap();

        let rc = fs::read_to_string(home.join(".zshrc")).unwrap();
        let env_path = home.join(".zshenv");
        let env_rc = fs::read_to_string(&env_path).unwrap_or_else(|error| {
            panic!(
                "setup wrote no {}, so a non-interactive zsh has no PATH line to \
                 read: {error}",
                env_path.display()
            )
        });
        let path_line = rc_path_line("zsh", &kin_home.join("bin"));

        assert_eq!(
            rc.matches("kin-vfs.zsh").count(),
            1,
            "setup must not duplicate the shell hook source line"
        );
        assert_eq!(
            env_rc.matches(&path_line).count(),
            1,
            "setup must write the Kin PATH line to the file every zsh reads, exactly once"
        );
        assert_eq!(
            rc.matches(&path_line).count(),
            0,
            "the PATH line stayed in the interactive-only file, where a script \
             or an agent cannot see it"
        );
        assert_eq!(
            env_rc.matches("kin-vfs.zsh").count(),
            0,
            "the hook reached the file every zsh reads, which injects the shim \
             into every non-interactive shell"
        );
        assert!(
            fs::read_to_string(kin_home.join("shell").join("kin-vfs.zsh"))
                .unwrap()
                .contains(r#"${KIN_HOME:-$HOME/.kin}"#),
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

    /// The hosted surface is where a first-time caller learns whether they can
    /// connect at all. `kin auth login` ships, so no hosted wording may say a
    /// connect command is missing or still on the way.
    #[test]
    fn hosted_followups_never_deny_the_shipped_connect_command() {
        let states = [
            super::super::auth::HostedCredentialState::Absent,
            super::super::auth::HostedCredentialState::AbsentKeyringNotRead,
            super::super::auth::HostedCredentialState::Locked,
            super::super::auth::HostedCredentialState::Ready {
                user_email: "dev@example.com".to_string(),
                expires_at: "2026-12-31T00:00:00Z".to_string(),
            },
        ];
        for state in states {
            let rendered = hosted_followup_lines("https://kinlab.example", &state).join("\n");
            let lowered = rendered.to_lowercase();
            for denial in [
                "coming soon",
                "no public",
                "not a first-run flow",
                "no first-run flow",
            ] {
                assert!(
                    !lowered.contains(denial),
                    "hosted wording for {state:?} must not deny a shipped command: {rendered}"
                );
            }
            assert!(
                rendered.contains("kin auth"),
                "hosted wording for {state:?} must name a real auth command: {rendered}"
            );
        }
    }

    /// Each state answers the only question the caller has: am I connected, and
    /// what do I type next.
    #[test]
    fn hosted_followups_report_the_state_this_machine_is_in() {
        let absent = hosted_followup_lines(
            "https://kinlab.example",
            &super::super::auth::HostedCredentialState::Absent,
        )
        .join("\n");
        assert!(
            absent.contains("https://kinlab.example") && absent.contains("kin auth login"),
            "a machine with no credential must be told where it is not signed in and how: {absent}"
        );

        let locked = hosted_followup_lines(
            "https://kinlab.example",
            &super::super::auth::HostedCredentialState::Locked,
        )
        .join("\n");
        assert!(
            locked.contains("kin auth status"),
            "a locked credential must name the command that unlocks it: {locked}"
        );

        let ready = hosted_followup_lines(
            "https://kinlab.example",
            &super::super::auth::HostedCredentialState::Ready {
                user_email: "dev@example.com".to_string(),
                expires_at: "2026-12-31T00:00:00Z".to_string(),
            },
        )
        .join("\n");
        assert!(
            ready.contains("dev@example.com") && ready.contains("2026-12-31T00:00:00Z"),
            "a signed-in machine must be told which identity and until when: {ready}"
        );
    }

    /// A run that cannot answer a keychain prompt does not read the keyring, so
    /// it does not know whether this machine is signed in. Saying it is not
    /// would be false on the default install, where the keyring is where a
    /// credential lands.
    #[test]
    fn hosted_followups_do_not_claim_signed_out_when_the_keyring_went_unread() {
        let unread = hosted_followup_lines(
            "https://kinlab.example",
            &super::super::auth::HostedCredentialState::AbsentKeyringNotRead,
        )
        .join("\n");
        assert!(
            !unread.to_lowercase().contains("not signed in"),
            "an unread keyring cannot support a signed-out claim: {unread}"
        );
        assert!(
            unread.contains("kin auth status"),
            "the report must name the command that does read the keyring: {unread}"
        );

        let read = hosted_followup_lines(
            "https://kinlab.example",
            &super::super::auth::HostedCredentialState::Absent,
        )
        .join("\n");
        assert!(
            read.to_lowercase().contains("not signed in"),
            "a probe that did read the keyring states the machine is signed out: {read}"
        );
    }

    /// The intent menu is read before anything runs, so its own line cannot
    /// promise less than the command surface delivers.
    #[test]
    fn hosted_intent_menu_entry_does_not_deny_the_connect_command() {
        let entry = format!(
            "{} {}",
            SetupIntent::Hosted.title(),
            SetupIntent::Hosted.description()
        )
        .to_lowercase();
        for denial in ["coming soon", "no first-run flow yet", "not yet"] {
            assert!(
                !entry.contains(denial),
                "hosted menu entry must not deny a shipped command: {entry}"
            );
        }
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
    #[serial]
    fn merge_mcp_config_refuses_to_overwrite_corrupt_json() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let path = dir.path().join("config.json");
        std::fs::write(&path, b"this is not json {{{").unwrap();

        let original = std::fs::read(&path).unwrap();
        let err = merge_mcp_config(&path, "cursor").unwrap_err();
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
    #[serial]
    fn merge_mcp_config_merges_into_valid_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let path = dir.path().join("config.json");
        std::fs::write(&path, r#"{"existingKey": true}"#).unwrap();

        merge_mcp_config(&path, "cursor").unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(val["existingKey"], true, "existing keys must be preserved");
        assert!(
            val["mcpServers"]["kin"].is_object(),
            "kin entry must be added"
        );
    }

    #[test]
    #[serial]
    fn claude_writer_uses_fallback_only_while_primary_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        let fallback = home.join(".claude/config.json");
        let primary = home.join(".claude.json");
        fs::create_dir_all(fallback.parent().unwrap()).unwrap();
        fs::write(&fallback, b"{}\n").unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);

        assert_eq!(configure_claude_code().unwrap(), fallback);
        assert!(!primary.exists());
        let fallback_entry = read_kin_mcp_entry(&fallback).unwrap();
        assert_eq!(
            fallback_entry["command"].as_str(),
            env::current_exe().unwrap().to_str()
        );
        assert_eq!(fallback_entry["args"], serde_json::json!(["mcp", "start"]));
        assert_eq!(
            fallback_entry["env"]["KIN_MCP_TOOL_PROFILE"],
            "agent-default"
        );

        fs::write(&primary, b"{}\n").unwrap();
        assert_eq!(configure_claude_code().unwrap(), primary);
        assert!(read_kin_mcp_entry(&primary).is_some());
    }

    /// A temp home plus the ledger path a test drives directly.
    fn reminder_fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        (dir, home)
    }

    /// The Kin-first directive is a standing instruction to prefer Kin's MCP
    /// tools over grep and raw file reads, in every repository, for every
    /// session. Writing it for a client whose MCP server setup never registered
    /// points that agent at tools which are not wired.
    ///
    /// Models the reported first-install shape: Cursor registers, Claude Code
    /// does not, and the run still reaches the reminder step. Against the
    /// pre-fix code — an unconditional loop over both instruction files — this
    /// fails on the `.claude/CLAUDE.md` assertion.
    #[test]
    fn discovery_reminder_is_withheld_from_a_client_kin_did_not_register() {
        let (_dir, home) = reminder_fixture();

        let written = apply_discovery_reminders(&home, &[IDX_CURSOR]);

        assert!(
            written.is_empty(),
            "nothing may be reported as written, so the ledger cannot claim it either"
        );
        assert!(
            !home.join(".claude").join("CLAUDE.md").exists(),
            "a directive to prefer Kin's MCP tools must not be written for a client \
             whose MCP server was never registered"
        );
        assert!(
            !home.join(".codex").join("AGENTS.md").exists(),
            "the same gate must hold for Codex"
        );
    }

    /// The other half of the gate: once a client is registered the directive is
    /// true for it, so it is written and reported for the ledger to track.
    #[test]
    fn discovery_reminder_follows_a_successful_registration() {
        let (_dir, home) = reminder_fixture();

        let written = apply_discovery_reminders(&home, &[IDX_CLAUDE_CODE]);

        assert_eq!(
            written,
            vec![("claude-md", home.join(".claude").join("CLAUDE.md"))],
            "only the registered client's reminder is written and reported"
        );
        assert!(discovery_reminder_present(
            &home.join(".claude").join("CLAUDE.md")
        ));
        assert!(
            !home.join(".codex").join("AGENTS.md").exists(),
            "an unregistered sibling stays untouched in the same run"
        );
    }

    /// Each instruction file is gated on its own client, not on any client
    /// having been registered.
    #[test]
    fn each_instruction_file_is_gated_on_its_own_client() {
        let (_dir, home) = reminder_fixture();

        let written = apply_discovery_reminders(&home, &[IDX_CODEX]);

        assert_eq!(
            written
                .iter()
                .map(|(target, _)| *target)
                .collect::<Vec<_>>(),
            vec!["codex-agents"]
        );
        assert!(discovery_reminder_present(
            &home.join(".codex").join("AGENTS.md")
        ));
        assert!(!discovery_reminder_present(
            &home.join(".claude").join("CLAUDE.md")
        ));
    }

    /// Re-running setup must not append the block twice.
    #[test]
    fn discovery_reminder_injection_is_idempotent() {
        let (_dir, home) = reminder_fixture();
        let claude_md = home.join(".claude").join("CLAUDE.md");

        apply_discovery_reminders(&home, &[IDX_CLAUDE_CODE]);
        let once = fs::read_to_string(&claude_md).unwrap();
        apply_discovery_reminders(&home, &[IDX_CLAUDE_CODE]);

        assert_eq!(fs::read_to_string(&claude_md).unwrap(), once);
    }

    /// A reminder appended by a Kin that predates the gate stays removable:
    /// uninstall excises exactly the recorded block and leaves the user's own
    /// text alone.
    #[test]
    fn uninstall_excises_a_reminder_left_by_an_earlier_run() {
        use crate::commands::setup_ledger::{uninstall_entry, LedgerEntry};

        let (_dir, home) = reminder_fixture();
        let claude_md = home.join(".claude").join("CLAUDE.md");
        apply_discovery_reminders(&home, &[IDX_CLAUDE_CODE]);
        let user_text = "# My own instructions\n\nKeep this.\n";
        let with_user = format!("{user_text}{}", fs::read_to_string(&claude_md).unwrap());
        fs::write(&claude_md, &with_user).unwrap();

        let entry = LedgerEntry::appended(
            ArtifactKind::DiscoveryReminder,
            "claude-md",
            claude_md.clone(),
            KIN_DISCOVERY_REMINDER,
        );
        uninstall_entry(&entry, false, false);

        let after = fs::read_to_string(&claude_md).unwrap();
        assert!(
            !after.contains(KIN_DISCOVERY_REMINDER),
            "uninstall must remove the reminder block"
        );
        assert!(
            after.contains("Keep this."),
            "the user's own text must survive"
        );
    }

    /// Claude Code was the only client detected by PATH alone. Its own state
    /// file is install evidence, so a CLI outside the invoking shell's PATH —
    /// the native installer's `~/.local/bin` in a non-login shell — is still
    /// configured rather than silently skipped.
    #[test]
    fn claude_code_state_file_counts_as_install_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        fs::create_dir_all(&home).unwrap();
        assert!(!claude_code_install_evidence(&home));

        fs::write(home.join(".claude.json"), b"{}\n").unwrap();
        assert!(claude_code_install_evidence(&home));
    }

    #[test]
    fn claude_code_native_install_path_counts_as_install_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let bin = home.join(".local").join("bin");
        fs::create_dir_all(&bin).unwrap();
        assert!(!claude_code_install_evidence(&home));

        fs::write(bin.join(claude_cli_filename()), b"#!/bin/sh\n").unwrap();
        assert!(claude_code_install_evidence(&home));
    }

    /// Detection must not be satisfiable by Kin's own output. `kin setup`
    /// creates `~/.claude/CLAUDE.md` itself, so counting the directory would let
    /// one run manufacture evidence of an install that never happened — and the
    /// next run would register a client the user does not have.
    #[test]
    fn kin_written_claude_directory_is_not_install_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let claude = home.join(".claude");
        fs::create_dir_all(&claude).unwrap();
        fs::write(claude.join("CLAUDE.md"), KIN_DISCOVERY_REMINDER).unwrap();

        assert!(
            !claude_code_install_evidence(&home),
            "Kin's own discovery reminder must never read as a Claude Code install"
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn non_managed_install_setup_health_and_doctor_repair_converge() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        fs::create_dir_all(&home).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _scan_root =
            EnvVarGuard::set(crate::commands::managed_config_scope::SCAN_ROOT_ENV, &home);

        assert!(
            !kin_home.join("bin/kin").exists(),
            "fixture must model Homebrew/manual install without a managed launcher"
        );
        let config = configure_cursor().unwrap();
        let expected = configured_mcp_launcher().unwrap();
        let entry = read_kin_mcp_entry(&config).unwrap();
        assert_eq!(entry["command"].as_str(), Some(expected.as_str()));
        let (status, detail) = crate::commands::health::evaluate_mcp_client(&config, "cursor");
        assert!(
            matches!(status, crate::commands::health::HealthStatus::Healthy),
            "setup output must be accepted by status: {detail}"
        );

        let mut root: serde_json::Value =
            serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
        root["mcpServers"]["kin"]["command"] = serde_json::json!("/stale/kin");
        fs::write(&config, serde_json::to_vec_pretty(&root).unwrap()).unwrap();
        let (status, _) = crate::commands::health::evaluate_mcp_client(&config, "cursor");
        assert!(matches!(
            status,
            crate::commands::health::HealthStatus::Misconfigured
        ));

        let outcome = remerge_existing_mcp_configs_detailed();
        assert!(outcome.errors.is_empty(), "{:?}", outcome.errors);
        assert!(outcome
            .repaired
            .contains(&ConfigLock::normalized_path(&config).unwrap()));
        let (status, detail) = crate::commands::health::evaluate_mcp_client(&config, "cursor");
        assert!(
            matches!(status, crate::commands::health::HealthStatus::Healthy),
            "doctor repair must converge: {detail}"
        );
        assert_eq!(
            read_kin_mcp_entry(&config).unwrap()["command"].as_str(),
            Some(expected.as_str())
        );
    }

    #[test]
    #[serial]
    fn merge_mcp_config_toml_refuses_to_overwrite_corrupt_toml() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, b"this is not toml [[[").unwrap();

        let original = std::fs::read(&path).unwrap();
        let err = merge_mcp_config_toml(&path, &repo).unwrap_err();
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

    #[test]
    #[serial]
    fn merge_mcp_config_toml_preserves_existing_codex_config() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "# user settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"other-server\"\n",
        )
        .unwrap();

        merge_mcp_config_toml(&path, &repo).unwrap();

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
            Some(4),
            "kin args must include an exact --repo binding"
        );
        assert_eq!(kin["args"][3].as_str(), repo.to_str());
        assert_eq!(
            kin["env"]["KIN_MCP_TOOL_PROFILE"].as_str(),
            Some("agent-default"),
            "agent-default profile must be set"
        );
    }

    #[test]
    #[serial]
    fn merge_mcp_config_toml_creates_missing_file_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let path = dir.path().join(".codex").join("config.toml");

        merge_mcp_config_toml(&path, &repo).unwrap();
        merge_mcp_config_toml(&path, &repo).unwrap();

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
    }

    #[test]
    #[serial]
    fn codex_merge_preserves_table_env_cwd_and_user_policy() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            format!(
                "[mcp_servers.kin]\ncommand = \"old\"\nargs = [\"mcp\", \"start\"]\ncwd = {:?}\ndisabled = true\n\n[mcp_servers.kin.env]\nUSER_POLICY = \"keep\"\n",
                repo.to_string_lossy()
            ),
        )
        .unwrap();

        merge_mcp_config_toml(&path, &repo).unwrap();
        let root: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let kin = &root["mcp_servers"]["kin"];
        assert_eq!(kin["cwd"].as_str(), repo.to_str());
        assert_eq!(kin["disabled"].as_bool(), Some(true));
        assert_eq!(kin["env"]["USER_POLICY"].as_str(), Some("keep"));
        assert_eq!(
            kin["env"]["KIN_MCP_TOOL_PROFILE"].as_str(),
            Some("agent-default")
        );
        assert_eq!(kin["args"][3].as_str(), repo.to_str());
    }

    #[test]
    #[serial]
    fn structurally_incompatible_configs_fail_closed_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let json = dir.path().join("config.json");
        let json_bytes = br#"{"mcpServers":{"kin":{"env":"user-owned"}}}"#;
        fs::write(&json, json_bytes).unwrap();
        assert!(merge_mcp_config(&json, "cursor").is_err());
        assert_eq!(fs::read(json).unwrap(), json_bytes);

        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let toml = dir.path().join("config.toml");
        let toml_bytes = b"mcp_servers = 7\n";
        fs::write(&toml, toml_bytes).unwrap();
        assert!(merge_mcp_config_toml(&toml, &repo).is_err());
        assert_eq!(fs::read(toml).unwrap(), toml_bytes);
    }

    #[test]
    #[serial]
    fn canonical_aliases_cannot_self_deadlock_or_cross_client_authority() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let client = home.join(".cursor");
        fs::create_dir_all(&client).unwrap();
        let config = client.join("mcp.json");
        fs::write(&config, b"{}").unwrap();
        let alias = client.join("..").join(".cursor").join("mcp.json");
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", dir.path().join("kin-home"));
        let digest = crate::commands::setup_ledger::sha256_hex(b"{}");
        let cursor = McpRepairTarget {
            id: "cursor".to_string(),
            path: config.clone(),
            repo_root: None,
            captured_config_sha256: digest.clone(),
        };
        let exact_alias = McpRepairTarget {
            path: alias.clone(),
            ..cursor.clone()
        };
        let deduplicated = normalize_mcp_repair_targets([cursor.clone(), exact_alias]).unwrap();
        assert_eq!(deduplicated.len(), 1);
        assert_eq!(
            deduplicated[0].path,
            ConfigLock::normalized_path_with_existing_parent(&config).unwrap()
        );

        let conflicting = McpRepairTarget {
            id: "gemini".to_string(),
            path: alias,
            repo_root: None,
            captured_config_sha256: digest,
        };
        let error = normalize_mcp_repair_targets([cursor, conflicting])
            .expect_err("one canonical path cannot acquire two client identities");
        assert!(format!("{error:#}").contains("not an allowed canonical config path"));
    }

    #[test]
    #[serial]
    fn acquire_many_restores_caller_order_after_identity_ordered_locking() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a.json");
        let second = dir.path().join("b.json");
        let first_plan = ConfigLock::plan_with_policy(&first, false).unwrap();
        let second_plan = ConfigLock::plan_with_policy(&second, false).unwrap();
        assert_ne!(first_plan.lock_identity, second_plan.lock_identity);

        // Deliberately request the reverse of identity order. The internal
        // acquisition must still use identity order, but callers must receive
        // locks mapped back to their own target order.
        let requested = if first_plan.lock_identity < second_plan.lock_identity {
            vec![second.clone(), first.clone()]
        } else {
            vec![first.clone(), second.clone()]
        };
        CONFIG_TRANSACTION_ACQUIRE_COUNT.with(|count| count.set(0));
        let locks = ConfigLock::acquire_many(&requested).unwrap();
        assert_eq!(
            locks
                .iter()
                .map(|lock| lock.path.clone())
                .collect::<Vec<_>>(),
            requested
                .iter()
                .map(|path| ConfigLock::normalized_path(path).unwrap())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            CONFIG_TRANSACTION_ACQUIRE_COUNT.with(std::cell::Cell::get),
            2
        );
        for (lock, requested_path) in locks.iter().zip(&requested) {
            lock.ensure_path(requested_path).unwrap();
        }
    }

    #[test]
    #[serial]
    fn acquire_many_rejects_duplicate_sidecar_identity_before_any_guard() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"{}\n").unwrap();
        let alias = dir.path().join(".").join("config.json");

        CONFIG_TRANSACTION_ACQUIRE_COUNT.with(|count| count.set(0));
        let error = match ConfigLock::acquire_many(&[config.clone(), alias]) {
            Ok(_) => panic!("one sidecar identity cannot authorize two requested targets"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("same sidecar object"));
        assert_eq!(
            CONFIG_TRANSACTION_ACQUIRE_COUNT.with(std::cell::Cell::get),
            0,
            "duplicate authority must be rejected before any WAL guard acquisition"
        );
        assert_eq!(fs::read(config).unwrap(), b"{}\n");
    }

    #[cfg(unix)]
    #[test]
    fn durable_config_directory_creation_handles_three_missing_levels() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("first/second/third");

        create_config_directory_all_durable(&nested, false).unwrap();
        create_config_directory_all_durable(&nested, false).unwrap();

        assert!(nested.is_dir());
        assert!(dir.path().join("first").is_dir());
        assert!(dir.path().join("first/second").is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn durable_config_directory_creation_rejects_non_normal_missing_suffix_before_mkdir() {
        let dir = tempfile::tempdir().unwrap();
        let first_missing = dir.path().join("missing");
        let ambiguous = first_missing.join("child/../target");

        let error = create_config_directory_all_durable(&ambiguous, false)
            .expect_err("a missing suffix containing ParentDir must be refused");

        assert!(format!("{error:#}").contains("non-normal component"));
        assert!(
            !first_missing.exists(),
            "suffix validation must finish before the first mkdir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn durable_config_directory_creation_allows_aliases_inside_existing_parent() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing");
        fs::create_dir_all(existing.join("child")).unwrap();
        let aliased_parent = existing.join("child/..");
        let nested = aliased_parent.join("first/second");

        let authority = create_config_directory_all_durable(&nested, false).unwrap();

        assert_eq!(
            authority.path,
            existing.canonicalize().unwrap().join("first/second")
        );
        assert!(authority.path.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_chain_rejects_an_unsafe_eexist_race_before_deeper_mkdir() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().canonicalize().unwrap();
        let raced = parent.join("raced");
        let nested = raced.join("deeper/final");
        inject_config_directory_eexist_at(Some(&raced));

        let error = create_config_directory_all_durable(&nested, true)
            .expect_err("an unsafe EEXIST winner must not become Kin-home authority");
        inject_config_directory_eexist_at(None);

        assert!(format!("{error:#}").contains("mode 0700"));
        assert_eq!(
            fs::symlink_metadata(&raced).unwrap().permissions().mode() & 0o7777,
            0o777,
            "an existing raced directory must never be silently repaired"
        );
        assert!(
            !raced.join("deeper").exists(),
            "unsafe authority must be rejected before deeper descendants"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_chain_repairs_only_new_entries_under_restrictive_umask() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        const WORKER_PATH: &str = "KIN_TEST_RESTRICTIVE_PRIVATE_CHAIN_PATH";
        if let Some(path) = std::env::var_os(WORKER_PATH) {
            unsafe {
                libc::umask(0o777);
            }
            let nested = PathBuf::from(path).join("first/second");
            let authority = create_config_directory_all_durable(&nested, true).unwrap();
            for path in [
                authority.path.clone(),
                authority.path.parent().unwrap().to_path_buf(),
            ] {
                assert_eq!(
                    fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777,
                    0o700
                );
            }
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::setup::tests::private_directory_chain_repairs_only_new_entries_under_restrictive_umask",
                "--nocapture",
            ])
            .env(WORKER_PATH, dir.path());
        let output = crate::commands::test_subprocess::output_with_timeout(
            command,
            "restrictive private-directory chain worker",
            crate::commands::test_subprocess::DEFAULT_TEST_SUBPROCESS_TIMEOUT,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "restrictive-umask worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    #[test]
    fn restrictive_umask_keeps_transaction_root_vault_and_guard_private() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::process::Command;

        const WORKER_ROOT: &str = "KIN_TEST_RESTRICTIVE_TRANSACTION_ROOT";
        if let Some(root) = std::env::var_os(WORKER_ROOT) {
            let root = PathBuf::from(root);
            let subject = root.join("subject");
            fs::write(&subject, b"subject").unwrap();
            let subject_identity =
                ConfigFileIdentity::from_metadata(&fs::metadata(&subject).unwrap());
            unsafe {
                libc::umask(0o777);
            }
            let transaction =
                ConfigTransactionAuthority::acquire(&subject_identity, &subject).unwrap();
            let kin_home = config_transaction_test_kin_home(&subject)
                .canonicalize()
                .unwrap();
            let transaction_root = kin_home.join("config-transactions");
            let subject_key = config_transaction_subject_key(&subject);
            let vault = transaction_root.join(format!("{subject_key}.objects"));
            let guard = transaction_root.join(format!("{subject_key}.guard"));
            for directory in [&kin_home, &transaction_root, &vault] {
                assert_eq!(
                    fs::symlink_metadata(directory)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    0o700,
                    "unexpected private-directory mode at {}",
                    directory.display()
                );
                assert!(private_directory_stage_paths(directory).is_empty());
            }
            assert_eq!(
                fs::symlink_metadata(&guard).unwrap().permissions().mode() & 0o7777,
                0o600
            );
            assert_eq!(transaction.root_path, transaction_root);
            assert_eq!(transaction.vault_path, vault);
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::setup::tests::restrictive_umask_keeps_transaction_root_vault_and_guard_private",
                "--nocapture",
            ])
            .env(WORKER_ROOT, dir.path())
            .env("TMPDIR", dir.path());
        let output = crate::commands::test_subprocess::output_with_timeout(
            command,
            "restrictive transaction-directory worker",
            crate::commands::test_subprocess::DEFAULT_TEST_SUBPROCESS_TIMEOUT,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "restrictive transaction worker output: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(unix)]
    fn private_directory_stage_paths(parent: &Path) -> Vec<PathBuf> {
        fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| private_directory_stage_uuid(name).is_some())
            })
            .collect()
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_retry_cleans_crash_after_staged_mkdir() {
        let dir = tempfile::tempdir().unwrap();
        let parent_path = dir.path().canonicalize().unwrap();
        let parent = open_config_parent_nofollow(&parent_path).unwrap();
        let final_path = parent_path.join("private");
        inject_private_directory_stage_at(
            Some(&final_path),
            Some(InjectedPrivateDirectoryStage::FailAfterMkdir),
        );

        let error = open_or_create_private_unix_directory_at(
            &parent,
            &parent_path,
            std::ffi::OsStr::new("private"),
            &final_path,
        )
        .expect_err("the injected crash boundary must retain only the unpublished stage");

        assert!(format!("{error:#}").contains("after private-directory staged mkdir"));
        assert!(!final_path.exists());
        assert_eq!(private_directory_stage_paths(&parent_path).len(), 1);
        let (_, created, _) = open_or_create_private_unix_directory_at(
            &parent,
            &parent_path,
            std::ffi::OsStr::new("private"),
            &final_path,
        )
        .unwrap();
        assert!(created);
        assert!(final_path.is_dir());
        assert!(private_directory_stage_paths(&parent_path).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_retry_cleans_crash_after_staged_repair() {
        let dir = tempfile::tempdir().unwrap();
        let parent_path = dir.path().canonicalize().unwrap();
        let parent = open_config_parent_nofollow(&parent_path).unwrap();
        let final_path = parent_path.join("private");
        inject_private_directory_stage_at(
            Some(&final_path),
            Some(InjectedPrivateDirectoryStage::FailAfterRepair),
        );

        let error = open_or_create_private_unix_directory_at(
            &parent,
            &parent_path,
            std::ffi::OsStr::new("private"),
            &final_path,
        )
        .expect_err("the injected crash boundary must retain only the unpublished stage");

        assert!(format!("{error:#}").contains("after private-directory staged repair"));
        assert!(!final_path.exists());
        assert_eq!(private_directory_stage_paths(&parent_path).len(), 1);
        let (_, created, _) = open_or_create_private_unix_directory_at(
            &parent,
            &parent_path,
            std::ffi::OsStr::new("private"),
            &final_path,
        )
        .unwrap();
        assert!(created);
        assert!(final_path.is_dir());
        assert!(private_directory_stage_paths(&parent_path).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_stage_symlink_substitution_never_mutates_target() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let parent_path = dir.path().canonicalize().unwrap();
        let parent = open_config_parent_nofollow(&parent_path).unwrap();
        let final_path = parent_path.join("private");
        let sentinel = parent_path.join("sentinel");
        fs::write(&sentinel, b"must survive unchanged").unwrap();
        fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o640)).unwrap();
        let original_mode = fs::metadata(&sentinel).unwrap().permissions().mode() & 0o7777;
        inject_private_directory_stage_at(
            Some(&final_path),
            Some(InjectedPrivateDirectoryStage::SubstituteWithSymlink(
                sentinel.clone(),
            )),
        );

        let error = open_or_create_private_unix_directory_at(
            &parent,
            &parent_path,
            std::ffi::OsStr::new("private"),
            &final_path,
        )
        .expect_err("a substituted staging symlink must be rejected before chmod");

        assert!(format!("{error:#}").contains("changed before restrictive-umask repair"));
        assert!(!final_path.exists());
        assert_eq!(fs::read(&sentinel).unwrap(), b"must survive unchanged");
        assert_eq!(
            fs::metadata(&sentinel).unwrap().permissions().mode() & 0o7777,
            original_mode
        );
        let residues = private_directory_stage_paths(&parent_path);
        assert_eq!(residues.len(), 1);
        assert!(fs::symlink_metadata(&residues[0])
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_file(&residues[0]).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_noreplace_rejects_unsafe_raced_winner_without_repair() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let parent_path = dir.path().canonicalize().unwrap();
        let parent = open_config_parent_nofollow(&parent_path).unwrap();
        let final_path = parent_path.join("private");
        inject_private_directory_stage_at(
            Some(&final_path),
            Some(InjectedPrivateDirectoryStage::PublishUnsafeWinner),
        );

        let error = open_or_create_private_unix_directory_at(
            &parent,
            &parent_path,
            std::ffi::OsStr::new("private"),
            &final_path,
        )
        .expect_err("an unsafe final-name winner must fail after NOREPLACE");

        let injected_identity = take_injected_private_directory_winner_identity()
            .expect("the exact injected winner identity must be retained for comparison");
        assert!(format!("{error:#}").contains("mode 0700"));
        assert_eq!(
            ConfigFileIdentity::from_metadata(&fs::symlink_metadata(&final_path).unwrap()),
            injected_identity,
            "NOREPLACE must retain the exact raced winner"
        );
        assert_eq!(
            fs::symlink_metadata(&final_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777,
            "the raced EEXIST winner must never be repaired"
        );
        assert_eq!(
            fs::read(final_path.join("sentinel")).unwrap(),
            b"raced winner must survive"
        );
        assert!(
            private_directory_stage_paths(&parent_path).is_empty(),
            "only the exact Kin-owned unpublished stage may be removed"
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_parent_lock_preserves_live_cooperative_stage() {
        let dir = tempfile::tempdir().unwrap();
        let parent_path = dir.path().canonicalize().unwrap();
        let holder_parent_path = parent_path.clone();
        let holder_parent = open_config_parent_nofollow(&holder_parent_path).unwrap();
        let stage_name = format!(
            "{PRIVATE_DIRECTORY_STAGE_PREFIX}{}{PRIVATE_DIRECTORY_STAGE_SUFFIX}",
            uuid::Uuid::new_v4()
        );
        let holder_stage_name = stage_name.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let holder = std::thread::spawn(move || {
            let guard = lock_private_directory_parent(&holder_parent, &holder_parent_path).unwrap();
            rustix::fs::mkdirat(
                &holder_parent,
                holder_stage_name.as_str(),
                rustix::fs::Mode::from_raw_mode(0o700),
            )
            .unwrap();
            sync_config_parent(&holder_parent).unwrap();
            ready_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        ready_rx.recv().unwrap();

        let creator_parent_path = parent_path.clone();
        let creator_parent = open_config_parent_nofollow(&creator_parent_path).unwrap();
        let final_path = creator_parent_path.join("private");
        let creator_final_path = final_path.clone();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let creator = std::thread::spawn(move || {
            done_tx
                .send(open_or_create_private_unix_directory_at(
                    &creator_parent,
                    &creator_parent_path,
                    std::ffi::OsStr::new("private"),
                    &creator_final_path,
                ))
                .unwrap();
        });
        assert!(matches!(
            done_rx.recv_timeout(std::time::Duration::from_millis(150)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(parent_path.join(&stage_name).is_dir());
        release_tx.send(()).unwrap();
        done_rx.recv().unwrap().unwrap();
        holder.join().unwrap();
        creator.join().unwrap();

        assert!(final_path.is_dir());
        assert!(private_directory_stage_paths(&parent_path).is_empty());
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn durable_config_directory_creation_propagates_sync_failure() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first");
        let nested = first.join("second/third");
        inject_config_directory_sync_failure_under(Some(dir.path()));
        let error = create_config_directory_all_durable(&nested, false)
            .expect_err("an ancestor sync failure must stop the durable mkdir chain");
        inject_config_directory_sync_failure_under(None);

        assert!(format!("{error:#}").contains("injected durable config directory sync failure"));
        assert!(first.is_dir(), "the failed mkdir remains visible for retry");
        assert!(!first.join("second").exists());
        create_config_directory_all_durable(&nested, false).unwrap();
        assert!(nested.is_dir());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn existing_sidecar_with_extended_acl_is_rejected_without_mutation() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        let sidecar = shared_config_lock_path(&config).unwrap();
        fs::write(&sidecar, b"").unwrap();
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&sidecar)
            .status()
            .unwrap()
            .success());

        let error = match ConfigLock::plan_with_policy(&config, false) {
            Ok(_) => panic!("an existing sidecar ACL must never be silently cleared"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("extended access ACL"));
        assert!(!unix_config_metadata(&fs::File::open(&sidecar).unwrap())
            .unwrap()
            .acl
            .is_empty());
        let _ = std::process::Command::new("chmod")
            .arg("-N")
            .arg(&sidecar)
            .status();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn held_sidecar_revalidation_rejects_acl_drift_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        assert!(std::process::Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(&lock.lock_path)
            .status()
            .unwrap()
            .success());

        let error = lock
            .write_guarded(&config, b"replacement\n", Some(b"original\n"))
            .expect_err("sidecar ACL drift must invalidate the held authority");
        assert!(format!("{error:#}").contains("extended access ACL"));
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
        let _ = std::process::Command::new("chmod")
            .arg("-N")
            .arg(&lock.lock_path)
            .status();
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_unavailable_se_security_privilege_fails_before_wal_or_namespace_change() {
        struct ResetPrivilegeInjection;
        impl Drop for ResetPrivilegeInjection {
            fn drop(&mut self) {
                super::super::update::windows_update::inject_se_security_privilege_unavailable(
                    false,
                );
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        fs::write(&path, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&path).unwrap();
        super::super::update::windows_update::inject_se_security_privilege_unavailable(true);
        let _reset = ResetPrivilegeInjection;
        let error = lock
            .write_guarded(&path, b"replacement\n", Some(b"original\n"))
            .expect_err("strict replacement must fail when SeSecurityPrivilege is unavailable");

        assert!(format!("{error:#}").contains("SeSecurityPrivilege"));
        assert_eq!(fs::read(&path).unwrap(), b"original\n");
        assert_eq!(lock.transaction.file.metadata().unwrap().len(), 0);
        assert!(
            lock.lock_path.is_file(),
            "the persistent lock sidecar is expected and must remain"
        );
        let residue = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.rsplit_once(".kin-update-")
                    .and_then(|(_, suffix)| suffix.strip_suffix(".tmp"))
                    .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
                    || name
                        .rsplit_once(".kin-quarantine-")
                        .is_some_and(|(_, suffix)| uuid::Uuid::parse_str(suffix).is_ok())
            })
            .collect::<Vec<_>>();
        assert!(
            residue.is_empty(),
            "unexpected pre-WAL residue: {residue:?}"
        );
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_config_lock_round_trips_public_and_private_files() {
        let dir = tempfile::tempdir().unwrap();
        let public = dir.path().join("config.json");
        fs::write(&public, b"public original\n").unwrap();
        let mut public_lock = ConfigLock::acquire(&public).unwrap();
        public_lock
            .write_guarded(&public, b"public replacement\n", Some(b"public original\n"))
            .unwrap();
        assert_eq!(fs::read(&public).unwrap(), b"public replacement\n");
        public_lock.refresh_locked_state().unwrap();
        public_lock
            .remove_guarded(&public, Some(b"public replacement\n"))
            .unwrap();
        assert!(!public.exists());

        let private = dir.path().join("private-marker.json");
        let mut private_lock = ConfigLock::acquire_nofollow(&private).unwrap();
        private_lock
            .write_private_guarded(&private, b"private marker\n", None)
            .unwrap();
        assert_eq!(
            read_private_file_nofollow(&private).unwrap().unwrap(),
            b"private marker\n"
        );
        private_lock.refresh_locked_state().unwrap();
        private_lock
            .remove_guarded(&private, Some(b"private marker\n"))
            .unwrap();
        assert!(!private.exists());
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_prepared_handoff_failure_deletes_stage_and_rolls_back_from_wal() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        super::super::update::windows_update::inject_staged_file_disarm_failure(true);
        lock.write_guarded(&config, b"replacement\n", Some(b"original\n"))
            .expect_err("handoff failure must not publish the replacement");
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
        let residue = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.rsplit_once(".kin-update-")
                    .and_then(|(_, suffix)| suffix.strip_suffix(".tmp"))
                    .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
            })
            .collect::<Vec<_>>();
        assert!(
            residue.is_empty(),
            "failed handoff leaked a named stage: {residue:?}"
        );
        assert!(
            read_config_transaction(&lock.transaction.file)
                .unwrap()
                .is_none(),
            "a handoff rollback that reached a terminal outcome must retire its journal"
        );
        assert_eq!(lock.transaction.file.metadata().unwrap().len(), 0);
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_file_id_info_is_stable_across_handles_and_rename() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("identity-original.tmp");
        let renamed = dir.path().join("identity-renamed.tmp");
        let distinct = dir.path().join("identity-distinct.tmp");
        let first = super::super::update::windows_update::create_managed_config_staged_file(
            &original, false,
        )
        .unwrap();
        let first = super::super::update::windows_update::disarm_staged_file_delete_on_close(
            first, &original, false, false,
        )
        .unwrap();
        let second = fs::File::open(&original).unwrap();
        let first_identity =
            super::super::update::windows_update::managed_object_identity(&first, false).unwrap();
        let second_identity =
            super::super::update::windows_update::managed_object_identity(&second, false).unwrap();
        assert_eq!(first_identity, second_identity);
        assert_ne!(first_identity.0, 0);
        assert_ne!(
            first_identity.1,
            super::super::update::WindowsFileId::zero()
        );

        super::super::update::windows_update::rename_managed_file_handle_exact(
            &first, &renamed, false,
        )
        .unwrap();
        assert_eq!(
            super::super::update::windows_update::managed_object_identity(&first, false).unwrap(),
            first_identity
        );

        let other = super::super::update::windows_update::create_managed_config_staged_file(
            &distinct, false,
        )
        .unwrap();
        let other_identity =
            super::super::update::windows_update::managed_object_identity(&other, false).unwrap();
        assert_ne!(first_identity, other_identity);
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_created_file_validation_failures_leave_no_named_residue() {
        use super::super::update::windows_update::{
            inject_created_file_validation_failure, CreatedFileValidationFailure,
        };

        let dir = tempfile::tempdir().unwrap();
        let private_identity = dir.path().join("private-identity.tmp");
        inject_created_file_validation_failure(Some(CreatedFileValidationFailure::Identity));
        assert!(
            super::super::update::windows_update::create_current_user_private_staged_file(
                &private_identity,
                false,
            )
            .is_err()
        );
        assert!(!private_identity.exists());

        let private_security = dir.path().join("private-security.tmp");
        inject_created_file_validation_failure(Some(CreatedFileValidationFailure::Security));
        assert!(
            super::super::update::windows_update::create_current_user_private_staged_file(
                &private_security,
                false,
            )
            .is_err()
        );
        assert!(!private_security.exists());

        let public_identity = dir.path().join("public-identity.tmp");
        inject_created_file_validation_failure(Some(CreatedFileValidationFailure::Identity));
        assert!(
            super::super::update::windows_update::create_managed_config_staged_file(
                &public_identity,
                false,
            )
            .is_err()
        );
        assert!(!public_identity.exists());
        inject_created_file_validation_failure(None);
    }

    #[test]
    #[serial]
    fn codex_relative_repo_binding_uses_entry_cwd_not_process_cwd() {
        let dir = tempfile::tempdir().unwrap();
        let repo_a = dir.path().join("repo-a");
        fs::create_dir_all(repo_a.join(".kin")).unwrap();
        let repo_a = repo_a.canonicalize().unwrap();
        assert_ne!(env::current_dir().unwrap().canonicalize().unwrap(), repo_a);
        let content = format!(
            "[mcp_servers.kin]\ncommand = \"/managed/kin\"\nargs = [\"mcp\", \"start\", \"--repo\", \".\"]\ncwd = {:?}\n",
            repo_a.to_string_lossy()
        );

        let resolved = codex_repo_from_entry_bytes(content.as_bytes())
            .unwrap()
            .expect("relative --repo must resolve from the entry cwd");

        assert_eq!(resolved, repo_a);
    }

    #[test]
    fn codex_binding_matches_expected_repo_regardless_of_path_form() {
        // Regression: `configure_codex` writes the canonicalized repository
        // path, but the health surface supplies the expected repo via
        // `current_health_repo`, which does not canonicalize. Comparing the two
        // by raw path equality wrongly reports a correct binding as
        // misconfigured wherever the raw path differs from its canonical form —
        // this is what failed every Windows install-proof leg (the `\\?\`
        // verbatim prefix that `canonicalize` adds) while Unix passed. The
        // comparison must normalize both sides to canonical repository identity.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let canonical = repo.canonicalize().unwrap();

        // Exactly what `configure_codex` writes: an absolute, canonicalized
        // `--repo` path.
        let content = format!(
            "[mcp_servers.kin]\ncommand = \"/managed/kin\"\nargs = [\"mcp\", \"start\", \"--repo\", {:?}]\n",
            canonical.to_string_lossy()
        );

        // The same repository named through a non-canonical but equivalent
        // path, standing in for the Windows `\\?\`/symlink divergence.
        let non_canonical = canonical.join("..").join(canonical.file_name().unwrap());
        assert_ne!(non_canonical, canonical);
        assert!(
            codex_entry_has_exact_repo_binding(content.as_bytes(), &non_canonical).unwrap(),
            "a canonically written binding must match its repository named through a non-canonical path"
        );

        // A genuinely different repository must still be refused.
        let other = dir.path().join("other");
        fs::create_dir_all(other.join(".kin")).unwrap();
        assert!(
            !codex_entry_has_exact_repo_binding(content.as_bytes(), &other).unwrap(),
            "a binding for one repository must not satisfy a different repository"
        );

        let npm_content = format!(
            "[mcp_servers.kin]\ncommand = \"npx\"\nargs = [\"-y\", \"@kinlab/kin\", \"mcp\", \"start\", \"--repo\", {:?}]\n",
            canonical.to_string_lossy()
        );
        assert!(
            codex_entry_has_exact_repo_binding(npm_content.as_bytes(), &non_canonical).unwrap(),
            "the canonical npm wrapper must retain the same exact repository identity"
        );
        assert!(
            !codex_entry_has_exact_repo_binding(npm_content.as_bytes(), &other).unwrap(),
            "the canonical npm wrapper must not weaken repository binding"
        );
    }

    #[test]
    fn codex_repo_binding_rejects_duplicate_or_ambiguous_relative_authority() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        let repo = repo.canonicalize().unwrap();
        let duplicate = format!(
            "[mcp_servers.kin]\nargs = [\"mcp\", \"start\", \"--repo\", \".\", \"--repo={}\"]\ncwd = {:?}\n",
            repo.display(),
            repo.to_string_lossy()
        );
        let error = codex_repo_from_entry_bytes(duplicate.as_bytes())
            .expect_err("duplicate --repo arguments are ambiguous");
        assert!(format!("{error:#}").contains("duplicate --repo"));

        let relative_cwd =
            b"[mcp_servers.kin]\nargs = [\"mcp\", \"start\", \"--repo\", \".\"]\ncwd = \"relative/repo\"\n";
        let error = codex_repo_from_entry_bytes(relative_cwd)
            .expect_err("a relative entry cwd cannot provide authority");
        assert!(format!("{error:#}").contains("cwd must be absolute"));

        let missing_cwd = b"[mcp_servers.kin]\nargs = [\"mcp\", \"start\", \"--repo\", \".\"]\n";
        let error = codex_repo_from_entry_bytes(missing_cwd)
            .expect_err("a relative --repo without cwd cannot provide authority");
        assert!(format!("{error:#}").contains("requires an absolute entry cwd"));
    }

    fn wal_test_record(phase: ConfigTransactionPhase) -> ConfigTransactionRecord {
        let identity = ConfigFileIdentity {
            #[cfg(unix)]
            device: 11,
            #[cfg(unix)]
            inode: 12,
            #[cfg(windows)]
            volume: 11,
            #[cfg(windows)]
            index: super::super::update::WindowsFileId::from_bytes([12; 16]),
        };
        ConfigTransactionRecord {
            schema_version: CONFIG_TRANSACTION_SCHEMA_VERSION,
            sidecar: identity.clone(),
            destination: PathBuf::from("/tmp/config.json"),
            destination_name: "config.json".to_string(),
            operation: ConfigTransactionOperation::Write,
            phase,
            private: false,
            staged_name: Some(".config.json.kin-update-test".to_string()),
            retained_name: Some(".config.json.kin-update-test".to_string()),
            original: None,
            replacement: Some(RecordedConfigObject {
                identity,
                sha256: crate::commands::setup_ledger::sha256_hex(b"replacement\n"),
                len: b"replacement\n".len() as u64,
                #[cfg(unix)]
                mode: 0o600,
                #[cfg(unix)]
                uid: unsafe { libc::geteuid() },
                #[cfg(unix)]
                gid: unsafe { libc::getegid() },
                #[cfg(unix)]
                metadata_sha256: crate::commands::setup_ledger::sha256_hex(b"test-unix-metadata"),
                #[cfg(windows)]
                security: "test-security".to_string(),
                #[cfg(windows)]
                full_sacl: None,
            }),
            parent: ConfigParentIdentity {
                #[cfg(unix)]
                device: 21,
                #[cfg(unix)]
                inode: 22,
                #[cfg(windows)]
                namespace: 21,
                #[cfg(windows)]
                file: super::super::update::WindowsFileId::from_bytes([22; 16]),
            },
            #[cfg(unix)]
            vault: ConfigFileIdentity {
                device: 31,
                inode: 32,
            },
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_acl_parser_distinguishes_allow_deny_and_malformed_entries() {
        let allow = b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:allow:read\n";
        assert!(!macos_acl_has_deny_entry(allow).unwrap());

        let deny =
            b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:deny:delete,delete_child\n";
        assert!(macos_acl_has_deny_entry(deny).unwrap());

        let inherited_deny =
            b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:deny,file_inherit:delete\n";
        assert!(macos_acl_has_deny_entry(inherited_deny).unwrap());

        for malformed in [
            b"!#acl 2\n".as_slice(),
            b"!#acl 1\n".as_slice(),
            b"0: subject:allow:read\n".as_slice(),
            b"!#acl 1\n0: subject:maybe:read\n".as_slice(),
        ] {
            assert!(macos_acl_has_deny_entry(malformed).is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_namespace_acl_accepts_protective_home_delete_deny_only() {
        let standard_home =
            b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:deny:delete\n";
        validate_macos_directory_namespace_acl(standard_home, "home").unwrap();

        let read_only_allow =
            b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:allow:read\n";
        validate_macos_directory_namespace_acl(read_only_allow, "home").unwrap();

        let namespace_grant =
            b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:allow:add_file\n";
        assert!(validate_macos_directory_namespace_acl(namespace_grant, "home").is_err());

        let child_deny =
            b"!#acl 1\n0: ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB:everyone:deny:delete_child\n";
        assert!(validate_macos_directory_namespace_acl(child_deny, "home").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn macos_current_home_namespace_acl_is_transactable() {
        let home = directories::BaseDirs::new()
            .unwrap()
            .home_dir()
            .to_path_buf();
        let handle = open_config_parent_nofollow(&home).unwrap();
        let acl = macos_config_acl(&handle).unwrap();
        validate_macos_directory_namespace_acl(&acl, "current home").unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[serial]
    fn guarded_config_write_preserves_full_unix_metadata() {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        let original_bytes = b"original metadata\n";
        let replacement_bytes = b"replacement metadata\n";
        fs::write(&config, original_bytes).unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o1640)).unwrap();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config)
            .unwrap();
        unix_set_xattr(&file, b"com.firelock.kin-metadata-test", b"preserve-me").unwrap();
        assert_eq!(
            unsafe { libc::fchflags(file.as_raw_fd(), libc::UF_NODUMP) },
            0
        );
        file.sync_all().unwrap();
        let before = observe_open_config_file(&config, &mut file, false).unwrap();
        drop(file);

        let lock = ConfigLock::acquire(&config).unwrap();
        lock.write_guarded(&config, replacement_bytes, Some(original_bytes))
            .unwrap();
        let after = read_config_file_nofollow(&config, false).unwrap().unwrap();

        assert_eq!(after.bytes, replacement_bytes);
        assert_eq!(after.mode, before.mode);
        assert_eq!(after.uid, before.uid);
        assert_eq!(after.gid, before.gid);
        assert_eq!(after.metadata, before.metadata);
        assert_ne!(after.identity, before.identity);
    }

    fn wal_test_envelope(record: &ConfigTransactionRecord, sequence: u64) -> Vec<u8> {
        let payload = serde_json::to_vec(record).unwrap();
        serde_json::to_vec(&ConfigTransactionEnvelope {
            magic: CONFIG_TRANSACTION_WAL_MAGIC.to_string(),
            frame_schema: CONFIG_TRANSACTION_WAL_FRAME_SCHEMA,
            sequence,
            payload_len: payload.len() as u64,
            payload_sha256: crate::commands::setup_ledger::sha256_hex(&payload),
            payload: record.clone(),
        })
        .unwrap()
    }

    fn wal_test_pair(record: &ConfigTransactionRecord, sequence: u64) -> Vec<u8> {
        let envelope = wal_test_envelope(record, sequence);
        let mut pair = envelope.clone();
        pair.push(b'\n');
        pair.extend_from_slice(
            format!(
                "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} {sequence} {} {}\n",
                envelope.len(),
                crate::commands::setup_ledger::sha256_hex(&envelope)
            )
            .as_bytes(),
        );
        pair
    }

    #[test]
    fn config_transaction_record_rejects_non_normal_destination_components() {
        for invalid in ["", ".", "..", "nested/config.json", "/config.json"] {
            let mut record = wal_test_record(ConfigTransactionPhase::Prepared);
            record.destination_name = invalid.to_string();
            let error =
                validate_config_transaction_record(Path::new("/tmp/config.json"), false, &record)
                    .expect_err("recovery authority must be exactly one normal component");
            assert!(
                format!("{error:#}").contains("final-component authority"),
                "unexpected validation error for {invalid:?}: {error:#}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_schema_v6_full_sacl_authority_is_validated_for_every_phase() {
        let phases = [
            ConfigTransactionPhase::Prepared,
            ConfigTransactionPhase::NamespaceCommitted,
            ConfigTransactionPhase::RollbackApplied,
            ConfigTransactionPhase::CommitComplete,
            ConfigTransactionPhase::RollbackComplete,
        ];
        for phase in phases {
            let mut existing_write = wal_test_record(phase);
            let mut original = existing_write.replacement.clone().unwrap();
            original.full_sacl = Some("a".repeat(64));
            existing_write.original = Some(original);
            existing_write.replacement.as_mut().unwrap().full_sacl = Some("b".repeat(64));
            validate_config_transaction_record(
                Path::new("/tmp/config.json"),
                false,
                &existing_write,
            )
            .unwrap();

            for (label, mutate) in [
                ("missing original full SACL", 0_u8),
                ("missing replacement full SACL", 1_u8),
                ("uppercase replacement full SACL", 2_u8),
            ] {
                let mut invalid = existing_write.clone();
                match mutate {
                    0 => invalid.original.as_mut().unwrap().full_sacl = None,
                    1 => invalid.replacement.as_mut().unwrap().full_sacl = None,
                    2 => invalid.replacement.as_mut().unwrap().full_sacl = Some("B".repeat(64)),
                    _ => unreachable!(),
                }
                assert!(
                    validate_config_transaction_record(
                        Path::new("/tmp/config.json"),
                        false,
                        &invalid,
                    )
                    .is_err(),
                    "{label} was accepted in {phase:?}"
                );
            }

            let create = wal_test_record(phase);
            validate_config_transaction_record(Path::new("/tmp/config.json"), false, &create)
                .unwrap();
            let mut invalid_create = create.clone();
            invalid_create.replacement.as_mut().unwrap().full_sacl = Some("c".repeat(64));
            assert!(
                validate_config_transaction_record(
                    Path::new("/tmp/config.json"),
                    false,
                    &invalid_create,
                )
                .is_err(),
                "create full-SACL authority was accepted in {phase:?}"
            );

            let mut removal = existing_write.clone();
            removal.operation = ConfigTransactionOperation::Remove;
            removal.replacement = None;
            validate_config_transaction_record(Path::new("/tmp/config.json"), false, &removal)
                .unwrap();
            removal.original.as_mut().unwrap().full_sacl = Some("short".to_string());
            assert!(
                validate_config_transaction_record(Path::new("/tmp/config.json"), false, &removal,)
                    .is_err(),
                "invalid removal full-SACL authority was accepted in {phase:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_stage_drift_restores_original_before_retaining_suspect_residue() {
        struct ResetWindowsStageDrift;
        impl Drop for ResetWindowsStageDrift {
            fn drop(&mut self) {
                inject_windows_stage_drift_at_phase(None);
            }
        }

        for (phase, drift) in [
            ("before-old-quarantine", InjectedWindowsStageDrift::Dacl),
            (
                "before-old-quarantine",
                InjectedWindowsStageDrift::SupportedSacl,
            ),
            (
                "after-old-quarantine-before-stage-commit",
                InjectedWindowsStageDrift::Dacl,
            ),
            (
                "after-old-quarantine-before-stage-commit",
                InjectedWindowsStageDrift::SupportedSacl,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let config = dir.path().join("config.json");
            fs::write(&config, b"original\n").unwrap();
            let lock = ConfigLock::acquire(&config).unwrap();
            inject_windows_stage_drift_at_phase(Some((phase, drift)));
            let _reset = ResetWindowsStageDrift;

            let error = lock
                .write_guarded(&config, b"replacement\n", Some(b"original\n"))
                .expect_err("stage authority drift must retain recovery evidence");
            let diagnostic = format!("{error:#}");
            assert!(
                diagnostic.contains("original was restored")
                    || diagnostic.contains("suspect residue"),
                "unexpected {phase} drift diagnostic: {diagnostic}"
            );
            assert_eq!(fs::read(&config).unwrap(), b"original\n");
            let durable = read_config_transaction(&lock.transaction.file)
                .unwrap()
                .expect("drift recovery must retain a durable WAL");
            assert_eq!(durable.phase, ConfigTransactionPhase::RollbackApplied);
            assert!(!matches!(
                durable.phase,
                ConfigTransactionPhase::CommitComplete | ConfigTransactionPhase::RollbackComplete
            ));
            let residues = fs::read_dir(dir.path())
                .unwrap()
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .filter(|name| {
                    name.rsplit_once(".kin-update-")
                        .and_then(|(_, suffix)| suffix.strip_suffix(".tmp"))
                        .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
                })
                .collect::<Vec<_>>();
            assert_eq!(
                residues.len(),
                1,
                "{phase} drift must retain exactly one suspect stage: {residues:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    #[serial]
    fn windows_restart_recovery_restores_original_before_rejecting_unsupported_stage_sacl() {
        struct ResetWindowsStageDrift;
        impl Drop for ResetWindowsStageDrift {
            fn drop(&mut self) {
                inject_windows_stage_drift_at_phase(None);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let wal_path = lock.transaction.path.clone();
        inject_windows_stage_drift_at_phase(Some((
            "after-old-quarantine-before-stage-commit",
            InjectedWindowsStageDrift::UnsupportedSaclCrash,
        )));
        let _reset = ResetWindowsStageDrift;

        let crash = lock
            .write_guarded(&config, b"replacement\n", Some(b"original\n"))
            .expect_err("post-quarantine crash injection must preserve durable recovery state");
        assert!(
            format!("{crash:#}").contains("injected crash after old quarantine"),
            "unexpected crash diagnostic: {crash:#}"
        );
        assert!(
            !config.exists(),
            "the simulated crash point must leave the original quarantined"
        );
        drop(lock);

        let recovery = match ConfigLock::acquire(&config) {
            Ok(_) => {
                panic!("unsupported replacement SACL must fail after exact original restoration")
            }
            Err(error) => error,
        };
        let diagnostic = format!("{recovery:#}");
        assert!(
            diagnostic.contains("unsupported"),
            "unexpected restart recovery diagnostic: {diagnostic}"
        );
        assert_eq!(fs::read(&config).unwrap(), b"original\n");

        let wal = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&wal_path)
            .unwrap();
        let durable = read_config_transaction(&wal)
            .unwrap()
            .expect("failed replacement validation must retain the durable WAL");
        assert_eq!(durable.phase, ConfigTransactionPhase::RollbackApplied);
        let residues = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| {
                name.rsplit_once(".kin-update-")
                    .and_then(|(_, suffix)| suffix.strip_suffix(".tmp"))
                    .is_some_and(|suffix| uuid::Uuid::parse_str(suffix).is_ok())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            residues.len(),
            1,
            "suspect stage must remain exact: {residues:?}"
        );
    }

    // A managed config's journal belongs to the config, not to whichever object
    // currently occupies its sidecar name. Renaming a sidecar onto a different
    // target slot must not carry the journal with it, and the config whose
    // sidecar was taken must refuse to proceed against a replacement object it
    // never recorded.
    #[test]
    #[serial]
    fn a_renamed_sidecar_cannot_carry_a_journal_to_a_different_target_slot() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let original_path = dir_path.join("original.json");
        let redirected_path = dir_path.join("redirected.json");
        fs::write(&original_path, b"owner-data\n").unwrap();

        let lock = ConfigLock::acquire(&original_path).unwrap();
        let mut record = wal_test_record(ConfigTransactionPhase::CommitComplete);
        record.sidecar = lock.lock_identity.clone();
        record.destination = original_path.clone();
        record.destination_name = "original.json".to_string();
        record.staged_name = None;
        record.retained_name = None;
        #[cfg(unix)]
        {
            let parent = open_config_parent_nofollow(&dir_path).unwrap();
            let stat = rustix::fs::fstat(&parent).unwrap();
            record.parent = ConfigParentIdentity {
                device: stat.st_dev as u64,
                inode: stat.st_ino as u64,
            };
            record.vault = lock.transaction.vault_identity.clone();
        }
        #[cfg(windows)]
        {
            let parent =
                super::super::update::windows_update::WindowsParentGuard::open(&dir_path).unwrap();
            let (namespace, file) = parent.identity();
            record.parent = ConfigParentIdentity { namespace, file };
        }
        write_config_transaction(&lock.transaction.file, &record).unwrap();
        let original_sidecar = lock.lock_path.clone();
        let redirected_sidecar = shared_config_lock_path(&redirected_path).unwrap();
        drop(lock);

        // The renamed sidecar keeps its device+inode, which is the same
        // aliasing input the kernel hands a later config when it recycles a
        // freed inode. The redirected target must see its own empty journal.
        fs::rename(&original_sidecar, &redirected_sidecar).unwrap();
        let redirected = ConfigLock::acquire(&redirected_path)
            .expect("a renamed sidecar must not redirect another config's recovery authority");
        assert!(
            read_config_transaction(&redirected.transaction.file)
                .unwrap()
                .is_none(),
            "the redirected target inherited a journal that belongs to another config"
        );
        drop(redirected);
        assert_eq!(fs::read(&original_path).unwrap(), b"owner-data\n");
        assert!(!redirected_path.exists());

        // The victim's journal stayed with the victim, so its next acquisition
        // detects that the recorded sidecar is no longer the sidecar in place.
        let error = match ConfigLock::acquire(&original_path) {
            Ok(_) => panic!("a config whose sidecar was taken must not silently proceed"),
            Err(error) => error,
        };
        assert!(
            format!("{error:#}").contains("does not match the journal recorded for this config"),
            "unexpected stolen-sidecar error: {error:#}"
        );
        assert_eq!(fs::read(&original_path).unwrap(), b"owner-data\n");

        let cleanup_identity = record.sidecar.clone();
        let cleanup =
            ConfigTransactionAuthority::acquire(&cleanup_identity, &original_sidecar).unwrap();
        cleanup.file.set_len(0).unwrap();
        cleanup.file.sync_all().unwrap();
    }

    #[test]
    fn config_transaction_wal_accepts_only_committed_pairs() {
        let record = wal_test_record(ConfigTransactionPhase::Prepared);
        let pair = wal_test_pair(&record, 1);
        let parsed = parse_config_transaction_wal(&pair).unwrap();
        assert_eq!(parsed.latest, Some(record));
        assert_eq!(parsed.committed_len, pair.len());
        assert_eq!(parsed.next_sequence, 2);
        assert!(parsed.uncommitted_tail_sha256.is_none());
    }

    #[test]
    fn config_transaction_test_authority_is_fixture_scoped_and_stable() {
        let fixture_a = tempfile::tempdir().unwrap();
        let fixture_b = tempfile::tempdir().unwrap();
        let identity = wal_test_record(ConfigTransactionPhase::Prepared).sidecar;
        let subject_a = fixture_a.path().join("first.lock");
        let subject_b = fixture_b.path().join("first.lock");
        let fixture_a_root = fixture_a.path().canonicalize().unwrap();
        let fixture_b_root = fixture_b.path().canonicalize().unwrap();
        assert_eq!(
            config_transaction_test_kin_home(&subject_a).parent(),
            Some(fixture_a_root.as_path()),
            "parallel transaction fixtures must not share the system temporary parent"
        );
        assert_eq!(
            config_transaction_test_kin_home(&subject_b).parent(),
            Some(fixture_b_root.as_path()),
            "each transaction fixture must own its recovery namespace"
        );

        let authority_a = ConfigTransactionAuthority::acquire(&identity, &subject_a).unwrap();
        let authority_a_path = authority_a.path.clone();
        let mut record = wal_test_record(ConfigTransactionPhase::Prepared);
        record.sidecar = identity.clone();
        write_config_transaction(&authority_a.file, &record).unwrap();
        drop(authority_a);

        let authority_b = ConfigTransactionAuthority::acquire(&identity, &subject_b).unwrap();
        assert_ne!(authority_b.path, authority_a_path);
        assert!(read_config_transaction(&authority_b.file)
            .unwrap()
            .is_none());
        drop(authority_b);

        // The same subject must reach the same journal so an interrupted
        // transaction stays recoverable across acquisitions.
        let reacquired = ConfigTransactionAuthority::acquire(&identity, &subject_a).unwrap();
        assert_eq!(reacquired.path, authority_a_path);
        assert_eq!(
            read_config_transaction(&reacquired.file).unwrap(),
            Some(record)
        );
        reacquired.file.set_len(0).unwrap();
        reacquired.file.sync_all().unwrap();
    }

    // Falsify the (device, inode) key. Genuine inode recycling cannot be forced
    // from a test — the kernel decides when a freed inode is handed out again,
    // and the sidecar validator rejects hard links (nlink != 1), so two live
    // names cannot stand in for one recycled object either. The collision is
    // therefore constructed at the key-derivation boundary: two managed configs
    // are handed one identical sidecar identity, which is exactly the state a
    // config inherits when it is given a recycled inode. Both subjects share one
    // test vault root here, so nothing but the key itself can separate them.
    #[test]
    fn a_recycled_sidecar_identity_does_not_alias_two_configs() {
        let fixture = tempfile::tempdir().unwrap();
        let recycled = wal_test_record(ConfigTransactionPhase::Prepared).sidecar;
        let first = fixture.path().join(".first.json.kin-update.lock");
        let second = fixture.path().join(".second.json.kin-update.lock");
        assert_eq!(
            config_transaction_test_kin_home(&first),
            config_transaction_test_kin_home(&second),
            "both subjects must share one vault root or the fixture, not the key, is the isolation"
        );
        assert_ne!(
            config_transaction_subject_key(&first),
            config_transaction_subject_key(&second),
            "two configs that share a recycled sidecar identity must not share a subject key"
        );

        let first_authority = ConfigTransactionAuthority::acquire(&recycled, &first).unwrap();
        let first_guard = first_authority.path.clone();
        #[cfg(unix)]
        let first_vault = first_authority.vault_path.clone();
        let mut interrupted = wal_test_record(ConfigTransactionPhase::Prepared);
        interrupted.sidecar = recycled.clone();
        interrupted.destination = fixture.path().join("first.json");
        interrupted.destination_name = "first.json".to_string();
        write_config_transaction(&first_authority.file, &interrupted).unwrap();
        drop(first_authority);

        let second_authority = ConfigTransactionAuthority::acquire(&recycled, &second).unwrap();
        assert_ne!(
            second_authority.path, first_guard,
            "the second config inherited the first config's recovery journal"
        );
        #[cfg(unix)]
        assert_ne!(
            second_authority.vault_path, first_vault,
            "the second config inherited the first config's staged-object vault"
        );
        assert!(
            read_config_transaction(&second_authority.file)
                .unwrap()
                .is_none(),
            "a config that inherited a recycled sidecar identity must start with no transaction"
        );
        drop(second_authority);

        let reacquired = ConfigTransactionAuthority::acquire(&recycled, &first).unwrap();
        assert_eq!(reacquired.path, first_guard);
        assert_eq!(
            read_config_transaction(&reacquired.file).unwrap(),
            Some(interrupted),
            "the first config lost the interrupted transaction it still owns"
        );
        reacquired.file.set_len(0).unwrap();
        reacquired.file.sync_all().unwrap();
    }

    #[test]
    fn config_transaction_subject_key_distinguishes_every_distinct_subject() {
        let root = Path::new("/home/user/.config");
        let sibling = Path::new("/home/user/.config2");
        let subject = root.join(".a.json.kin-update.lock");
        let neighbour = root.join(".b.json.kin-update.lock");
        let namesake = sibling.join(".a.json.kin-update.lock");
        assert_ne!(
            config_transaction_subject_key(&subject),
            config_transaction_subject_key(&neighbour)
        );
        assert_ne!(
            config_transaction_subject_key(&subject),
            config_transaction_subject_key(&namesake)
        );
        // Length prefixing keeps a component boundary from being spelled away.
        assert_ne!(
            config_transaction_subject_key(Path::new("/home/user/ab")),
            config_transaction_subject_key(Path::new("/home/user/a/b"))
        );
        let restated = PathBuf::from("/home/user/.config/.a.json.kin-update.lock");
        assert_eq!(
            config_transaction_subject_key(&subject),
            config_transaction_subject_key(&restated),
            "one subject must keep one key so its journal survives a restart"
        );
    }

    // Completion must retire the journal, not append a terminal record that is
    // never pruned: an append-only journal grows without bound and keeps a
    // finished transaction replayable forever.
    #[test]
    #[serial]
    fn a_resolved_config_transaction_retires_its_journal() {
        let dir = tempfile::tempdir().unwrap();
        let dir_path = dir.path().canonicalize().unwrap();
        let config = dir_path.join("config.json");
        fs::write(&config, b"original\n").unwrap();

        let lock = ConfigLock::acquire(&config).unwrap();
        lock.write_guarded(&config, b"replacement\n", Some(b"original\n"))
            .unwrap();
        assert_eq!(fs::read(&config).unwrap(), b"replacement\n");
        assert_eq!(
            lock.transaction.file.metadata().unwrap().len(),
            0,
            "a committed transaction must not leave a replayable record behind"
        );
        assert!(read_config_transaction(&lock.transaction.file)
            .unwrap()
            .is_none());
        drop(lock);

        let lock = ConfigLock::acquire(&config).unwrap();
        lock.remove_guarded(&config, Some(b"replacement\n"))
            .unwrap();
        assert!(!config.exists());
        assert_eq!(
            lock.transaction.file.metadata().unwrap().len(),
            0,
            "a completed removal must not leave a replayable record behind"
        );
    }

    #[test]
    fn retirement_keeps_a_transaction_that_is_still_open() {
        let fixture = tempfile::tempdir().unwrap();
        let identity = wal_test_record(ConfigTransactionPhase::Prepared).sidecar;
        let subject = fixture.path().join(".config.json.kin-update.lock");
        let authority = ConfigTransactionAuthority::acquire(&identity, &subject).unwrap();

        let interrupted = wal_test_record(ConfigTransactionPhase::Prepared);
        write_config_transaction(&authority.file, &interrupted).unwrap();
        let open_len = authority.file.metadata().unwrap().len();
        retire_resolved_config_transaction_wal(&authority.file).unwrap();
        assert_eq!(
            read_config_transaction(&authority.file).unwrap(),
            Some(interrupted),
            "retirement must not discard a transaction that is still open"
        );

        let resolved = wal_test_record(ConfigTransactionPhase::CommitComplete);
        write_config_transaction(&authority.file, &resolved).unwrap();
        assert!(
            authority.file.metadata().unwrap().len() > open_len,
            "terminal records are appended, so only retirement can bound the journal"
        );
        retire_resolved_config_transaction_wal(&authority.file).unwrap();
        assert_eq!(authority.file.metadata().unwrap().len(), 0);
        assert!(read_config_transaction(&authority.file).unwrap().is_none());
    }

    #[test]
    #[serial]
    fn config_transaction_test_authority_normalizes_relative_nonexistent_paths() {
        let current = env::current_dir().unwrap();
        let fixture = tempfile::Builder::new()
            .prefix("kin-config-relative-")
            .tempdir_in(&current)
            .unwrap();
        let fixture_name = fixture.path().strip_prefix(&current).unwrap();
        let relative = PathBuf::from(".")
            .join(fixture_name)
            .join("missing")
            .join("..")
            .join("renamed.lock");
        let absolute = fixture.path().join("renamed.lock");

        assert!(!absolute.exists());
        assert_eq!(
            canonicalize_nearest_existing_test_path(&relative),
            canonicalize_nearest_existing_test_path(&absolute)
        );
        assert_eq!(
            config_transaction_test_kin_home(&relative),
            config_transaction_test_kin_home(&absolute)
        );
    }

    #[test]
    #[serial]
    fn config_transaction_wal_ignores_newline_terminated_torn_envelope() {
        let record = wal_test_record(ConfigTransactionPhase::Prepared);
        let committed = wal_test_pair(&record, 1);
        let mut bytes = committed.clone();
        bytes.extend_from_slice(br#"{"magic":"KIN_CONFIG_TXN_WAL","frame_schema":1"#);
        bytes.push(b'\n');

        let parsed = parse_config_transaction_wal(&bytes).unwrap();
        assert_eq!(parsed.latest, Some(record));
        assert_eq!(parsed.committed_len, committed.len());
        assert!(parsed.uncommitted_tail_sha256.is_some());
    }

    #[test]
    fn config_transaction_wal_ignores_only_a_non_newline_torn_commit_trailer() {
        let first = wal_test_record(ConfigTransactionPhase::Prepared);
        let second = wal_test_record(ConfigTransactionPhase::NamespaceCommitted);
        let committed = wal_test_pair(&first, 1);
        let envelope = wal_test_envelope(&second, 2);
        let mut bytes = committed.clone();
        bytes.extend_from_slice(&envelope);
        bytes.push(b'\n');
        bytes.extend_from_slice(b"KIN_CONFIG_TXN_COM");
        let parsed = parse_config_transaction_wal(&bytes).unwrap();
        assert_eq!(parsed.latest, Some(first));
        assert_eq!(parsed.committed_len, committed.len());
        assert!(parsed.uncommitted_tail_sha256.is_some());
    }

    #[test]
    fn config_transaction_wal_rejects_a_complete_invalid_commit_trailer() {
        let record = wal_test_record(ConfigTransactionPhase::Prepared);
        let envelope = wal_test_envelope(&record, 1);
        let mut bytes = envelope;
        bytes.extend_from_slice(b"\nnot-a-commit\n");
        let error = parse_config_transaction_wal(&bytes).unwrap_err();
        assert!(format!("{error:#}").contains("invalid or ambiguous complete commit trailer"));
    }

    #[test]
    fn config_transaction_wal_rejects_an_orphan_commit_trailer() {
        let bytes = format!(
            "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} 1 1 {}\n",
            "0".repeat(64)
        );
        let error = parse_config_transaction_wal(bytes.as_bytes()).unwrap_err();
        assert!(format!("{error:#}").contains("orphan commit trailer"));
    }

    #[test]
    fn config_transaction_wal_rejects_a_mismatched_commit_trailer() {
        let record = wal_test_record(ConfigTransactionPhase::Prepared);
        let envelope = wal_test_envelope(&record, 1);
        let digest = crate::commands::setup_ledger::sha256_hex(&envelope);
        for trailer in [
            format!(
                "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} 1 {} {}\n",
                envelope.len(),
                "0".repeat(64)
            ),
            format!(
                "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} 1 {} {digest}\n",
                envelope.len() + 1
            ),
            format!(
                "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} 2 {} {digest}\n",
                envelope.len()
            ),
        ] {
            let mut bytes = envelope.clone();
            bytes.push(b'\n');
            bytes.extend_from_slice(trailer.as_bytes());
            let error = parse_config_transaction_wal(&bytes).unwrap_err();
            assert!(format!("{error:#}").contains("committed trailer mismatch"));
        }
    }

    #[test]
    fn config_transaction_wal_rejects_corruption_before_a_later_commit() {
        let record = wal_test_record(ConfigTransactionPhase::Prepared);
        let mut bytes = wal_test_pair(&record, 1);
        bytes.extend_from_slice(b"{not-json}\n");
        bytes.extend_from_slice(
            format!(
                "{CONFIG_TRANSACTION_WAL_COMMIT_PREFIX} 2 1 {}\n",
                "0".repeat(64)
            )
            .as_bytes(),
        );
        let error = parse_config_transaction_wal(&bytes).unwrap_err();
        assert!(format!("{error:#}").contains("corrupt non-final or committed envelope"));
    }

    #[test]
    fn config_transaction_wal_rejects_a_corrupt_committed_envelope() {
        let record = wal_test_record(ConfigTransactionPhase::Prepared);
        let mut bytes = wal_test_pair(&record, 1);
        bytes[0] = b'[';
        let error = parse_config_transaction_wal(&bytes).unwrap_err();
        assert!(format!("{error:#}").contains("corrupt non-final or committed envelope"));
    }

    #[test]
    fn config_transaction_wal_repairs_uncommitted_suffix_before_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.guard");
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let first = wal_test_record(ConfigTransactionPhase::Prepared);
        let second = wal_test_record(ConfigTransactionPhase::NamespaceCommitted);
        let mut bytes = wal_test_pair(&first, 1);
        bytes.extend_from_slice(b"{\"torn\":true}\n");
        (&file).write_all(&bytes).unwrap();
        file.sync_all().unwrap();

        write_config_transaction(&file, &second).unwrap();
        let parsed = read_config_transaction(&file).unwrap().unwrap();
        assert_eq!(parsed, second);
        let contents = fs::read(&path).unwrap();
        let state = parse_config_transaction_wal(&contents).unwrap();
        assert_eq!(state.next_sequence, 3);
        assert!(state.uncommitted_tail_sha256.is_none());
    }

    #[test]
    fn config_transaction_wal_sync_failpoints_never_authorize_an_uncommitted_envelope() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("transaction.guard");
        let file = fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        let record = wal_test_record(ConfigTransactionPhase::Prepared);

        inject_config_transaction_sync_failure_at(Some(ConfigTransactionSyncPoint::Envelope));
        assert!(write_config_transaction(&file, &record).is_err());
        assert!(read_config_transaction(&file).unwrap().is_none());

        write_config_transaction(&file, &record).unwrap();
        let committed = wal_test_record(ConfigTransactionPhase::NamespaceCommitted);
        inject_config_transaction_sync_failure_at(Some(ConfigTransactionSyncPoint::Commit));
        assert!(write_config_transaction(&file, &committed).is_err());
        assert_eq!(read_config_transaction(&file).unwrap(), Some(committed));
        inject_config_transaction_sync_failure_at(None);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn guarded_config_write_restores_raced_replacement_after_final_validation() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        let original = b"original config";
        let replacement = b"editor replacement";
        fs::write(&config, original).unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();

        let error = lock
            .write_guarded_with_policy_and_hook(
                &config,
                b"kin update",
                Some(original),
                false,
                || {
                    fs::remove_file(&config)?;
                    fs::write(&config, replacement)?;
                    Ok(())
                },
            )
            .expect_err("a replacement after final validation must not be overwritten");

        assert!(format!("{error:#}").contains("atomic exchange boundary"));
        assert_eq!(fs::read(&config).unwrap(), replacement);
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            !name.contains("kin-quarantine") && !name.contains("kin-update-")
        }));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn guarded_config_removal_restores_raced_replacement_after_final_validation() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        let original = b"original config";
        let replacement = b"editor replacement";
        fs::write(&config, original).unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();

        let error = lock
            .remove_guarded_with_hook(&config, Some(original), || {
                fs::remove_file(&config)?;
                fs::write(&config, replacement)?;
                Ok(())
            })
            .expect_err("a replacement after final validation must not be deleted");

        assert!(format!("{error:#}").contains("changed object identity"));
        assert_eq!(fs::read(&config).unwrap(), replacement);
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains("kin-quarantine")
        }));
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn guarded_config_write_revalidates_authority_after_transition_hook() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let sidecar = lock.lock_path.clone();
        let vault = lock.transaction.vault_path.clone();

        let error = lock
            .write_guarded_with_policy_and_hook(
                &config,
                b"replacement\n",
                Some(b"original\n"),
                false,
                || {
                    fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644))?;
                    Ok(())
                },
            )
            .expect_err("authority drift after the hook must stop before Prepared");

        assert!(format!("{error:#}").contains("mode 0600"));
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
        assert!(fs::read_dir(&vault).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains("kin-update")));
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn write_namespace_phase_refuses_authority_drift_and_restart_rolls_back() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let sidecar = lock.lock_path.clone();
        inject_config_authority_drift_at_phase(Some((
            "write-namespace-committed",
            &sidecar,
            0o644,
        )));

        let error = lock
            .write_guarded(&config, b"replacement\n", Some(b"original\n"))
            .expect_err("authority drift must stop before NamespaceCommitted");
        inject_config_authority_drift_at_phase(None);

        assert!(
            format!("{error:#}").contains("mode 0600"),
            "unexpected boundary error: {error:#}"
        );
        assert_eq!(
            read_config_transaction(&lock.transaction.file)
                .unwrap()
                .unwrap()
                .phase,
            ConfigTransactionPhase::Prepared
        );
        assert_eq!(fs::read(&config).unwrap(), b"replacement\n");

        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
        drop(lock);
        let recovered = ConfigLock::acquire(&config).unwrap();
        assert_eq!(
            recovered.original_bytes(&config).unwrap().unwrap(),
            b"original\n"
        );
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn write_namespace_phase_reobserves_retained_bytes_before_advancing_wal() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let external = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config)
            .unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        inject_config_object_drift_at_phase(Some((
            "write-namespace-committed",
            InjectedConfigObjectDrift::Bytes(external, b"external edit\n".to_vec()),
        )));

        let error = lock
            .write_guarded(&config, b"Kin replacement\n", Some(b"original\n"))
            .expect_err("retained-object content drift must stop before NamespaceCommitted");
        inject_config_object_drift_at_phase(None);

        assert!(format!("{error:#}").contains("retained managed config original changed"));
        assert_eq!(
            read_config_transaction(&lock.transaction.file)
                .unwrap()
                .unwrap()
                .phase,
            ConfigTransactionPhase::Prepared
        );
        assert_eq!(fs::read(&config).unwrap(), b"Kin replacement\n");

        drop(lock);
        let recovered = ConfigLock::acquire(&config).unwrap();
        assert_eq!(
            recovered.original_bytes(&config).unwrap().unwrap(),
            b"external edit\n"
        );
        assert_eq!(fs::read(&config).unwrap(), b"external edit\n");
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn write_rollback_phase_refuses_authority_drift_and_preserves_raced_object() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let sidecar = lock.lock_path.clone();
        inject_config_authority_drift_at_phase(Some(("write-rollback-applied", &sidecar, 0o644)));

        let error = lock
            .write_guarded_with_policy_and_hook(
                &config,
                b"Kin replacement\n",
                Some(b"original\n"),
                false,
                || {
                    fs::remove_file(&config)?;
                    fs::write(&config, b"editor replacement\n")?;
                    Ok(())
                },
            )
            .expect_err("authority drift must stop before RollbackApplied");
        inject_config_authority_drift_at_phase(None);

        let diagnostic = format!("{error:#}");
        assert!(
            diagnostic.contains("before durable RollbackApplied")
                && diagnostic.contains("mode 0600"),
            "unexpected boundary error: {diagnostic}"
        );
        assert_eq!(
            read_config_transaction(&lock.transaction.file)
                .unwrap()
                .unwrap()
                .phase,
            ConfigTransactionPhase::Prepared
        );
        assert_eq!(fs::read(&config).unwrap(), b"editor replacement\n");

        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
        drop(lock);
        let recovered = ConfigLock::acquire(&config).unwrap();
        assert_eq!(
            recovered.original_bytes(&config).unwrap().unwrap(),
            b"editor replacement\n"
        );
        assert_eq!(fs::read(&config).unwrap(), b"editor replacement\n");
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn guarded_config_remove_revalidates_authority_after_quarantine_hook() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let sidecar = lock.lock_path.clone();

        let error = lock
            .remove_guarded_with_hook(&config, Some(b"original\n"), || {
                fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o644))?;
                Ok(())
            })
            .expect_err("authority drift after the hook must stop before Prepared");

        assert!(format!("{error:#}").contains("mode 0600"));
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn remove_namespace_phase_refuses_authority_drift_and_restart_restores() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let sidecar = lock.lock_path.clone();
        inject_config_authority_drift_at_phase(Some((
            "remove-namespace-committed",
            &sidecar,
            0o644,
        )));

        let error = lock
            .remove_guarded(&config, Some(b"original\n"))
            .expect_err("authority drift must stop before removal NamespaceCommitted");
        inject_config_authority_drift_at_phase(None);

        assert!(format!("{error:#}").contains("mode 0600"));
        assert_eq!(
            read_config_transaction(&lock.transaction.file)
                .unwrap()
                .unwrap()
                .phase,
            ConfigTransactionPhase::Prepared
        );
        assert!(!config.exists());

        fs::set_permissions(&sidecar, fs::Permissions::from_mode(0o600)).unwrap();
        drop(lock);
        let recovered = ConfigLock::acquire(&config).unwrap();
        assert_eq!(
            recovered.original_bytes(&config).unwrap().unwrap(),
            b"original\n"
        );
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn remove_namespace_phase_reobserves_retained_metadata_before_advancing_wal() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
        let external = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&config)
            .unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        inject_config_object_drift_at_phase(Some((
            "remove-namespace-committed",
            InjectedConfigObjectDrift::Mode(external, 0o640),
        )));

        let error = lock
            .remove_guarded(&config, Some(b"original\n"))
            .expect_err("retained-object metadata drift must stop before NamespaceCommitted");
        inject_config_object_drift_at_phase(None);

        assert!(format!("{error:#}").contains("removal quarantine changed"));
        assert_eq!(
            read_config_transaction(&lock.transaction.file)
                .unwrap()
                .unwrap()
                .phase,
            ConfigTransactionPhase::Prepared
        );
        assert!(!config.exists());

        drop(lock);
        let recovered = ConfigLock::acquire(&config).unwrap();
        assert_eq!(
            recovered.original_bytes(&config).unwrap().unwrap(),
            b"original\n"
        );
        assert_eq!(
            fs::symlink_metadata(&config).unwrap().permissions().mode() & 0o7777,
            0o640
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn next_guarded_acquire_removes_only_exact_unjournaled_stage_names() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.json");
        fs::write(&config, b"original\n").unwrap();
        let lock = ConfigLock::acquire(&config).unwrap();
        let stage_name = format!(".config.json.kin-update-{}.tmp", uuid::Uuid::new_v4());
        let unknown_name = ".config.json.kin-update-not-a-uuid.tmp";
        let fd = rustix::fs::openat(
            &lock.transaction.vault,
            stage_name.as_str(),
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let mut stage = fs::File::from(fd);
        stage.write_all(b"secret crash residue").unwrap();
        stage.sync_all().unwrap();
        fs::write(lock.transaction.vault_path.join(unknown_name), b"unknown").unwrap();
        sync_config_parent(&lock.transaction.vault).unwrap();
        let vault = lock.transaction.vault_path.clone();
        drop(lock);

        let recovered = ConfigLock::acquire(&config).unwrap();
        assert!(!vault.join(&stage_name).exists());
        assert_eq!(fs::read(vault.join(unknown_name)).unwrap(), b"unknown");
        assert_eq!(fs::read(&config).unwrap(), b"original\n");
        drop(recovered);
        fs::remove_file(vault.join(unknown_name)).unwrap();
    }

    #[test]
    #[serial]
    fn static_mcp_ids_are_bound_to_their_exact_client_paths() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(kin_home.join("config")).unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let digest = crate::commands::setup_ledger::sha256_hex(b"{}");

        let primary = home.join(".claude.json");
        let legacy = home.join(".claude/config.json");
        fs::write(&primary, b"{}").unwrap();
        fs::write(&legacy, b"{}").unwrap();
        let allowed = normalize_mcp_repair_targets([
            McpRepairTarget {
                id: "claude".to_string(),
                path: primary,
                repo_root: None,
                captured_config_sha256: digest.clone(),
            },
            McpRepairTarget {
                id: "claude".to_string(),
                path: legacy,
                repo_root: None,
                captured_config_sha256: digest.clone(),
            },
        ])
        .unwrap();
        assert_eq!(allowed.len(), 2, "both real Claude locations are valid");

        for victim in [
            home.join("arbitrary.json"),
            kin_home.join("update-restart-ack-required.json"),
            kin_home.join("config/setup-ledger.json"),
        ] {
            let bytes = br#"{"user":"authority"}"#;
            fs::write(&victim, bytes).unwrap();
            let error = normalize_mcp_repair_targets([McpRepairTarget {
                id: "cursor".to_string(),
                path: victim.clone(),
                repo_root: None,
                captured_config_sha256: crate::commands::setup_ledger::sha256_hex(bytes),
            }])
            .expect_err("a static client id cannot grant arbitrary path authority");
            assert!(format!("{error:#}").contains("not an allowed canonical config path"));
            assert_eq!(fs::read(victim).unwrap(), bytes);
        }
    }

    #[test]
    #[serial]
    fn stale_codex_binding_is_refused_before_repair_or_marker_clear() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::copy(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        let repo_a = dir.path().join("repo-a");
        let repo_b = dir.path().join("repo-b");
        fs::create_dir_all(repo_a.join(".kin")).unwrap();
        fs::create_dir_all(repo_b.join(".kin")).unwrap();
        let repo_a = repo_a.canonicalize().unwrap();
        let repo_b = repo_b.canonicalize().unwrap();
        let config = home.join(".codex/config.toml");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        fs::write(
            &config,
            format!(
                "[mcp_servers.kin]\ncommand = \"/stale/kin\"\nargs = [\"mcp\", \"start\", \"--repo\", {:?}]\n",
                repo_a.to_string_lossy()
            ),
        )
        .unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);

        let captured = current_mcp_repair_targets().unwrap();
        let captured = captured
            .into_iter()
            .find(|target| target.id == "codex")
            .expect("Codex target must be captured");
        merge_mcp_config_toml(&config, &repo_b).unwrap();
        let rebound_bytes = fs::read(&config).unwrap();
        let finalized = std::cell::Cell::new(false);

        let error = remerge_mcp_targets_exact_with_finalizer(&[captured], || {
            finalized.set(true);
            Ok(())
        })
        .expect_err("captured repo A must not overwrite a later repo B binding");

        assert!(format!("{error:#}").contains("stale repair authority"));
        assert!(!finalized.get());
        assert_eq!(fs::read(&config).unwrap(), rebound_bytes);
        let current = read_kin_mcp_entry(&config).unwrap();
        assert_eq!(current["args"][3].as_str(), repo_b.to_str());
    }

    #[test]
    #[serial]
    fn finalizer_recaptures_and_repairs_target_added_after_manifest_capture() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::copy(std::env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        let cursor = home.join(".cursor/mcp.json");
        let windsurf = home.join(".codeium/windsurf/mcp_config.json");
        fs::create_dir_all(cursor.parent().unwrap()).unwrap();
        fs::write(
            &cursor,
            r#"{"mcpServers":{"kin":{"command":"/stale/kin","args":["mcp","start"]}}}"#,
        )
        .unwrap();
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let captured = current_mcp_repair_targets().unwrap();
        assert_eq!(captured.len(), 1);

        // This is a normal setup writer that wins after the updater's durable
        // target capture. Finalization must include it, not clear an incomplete
        // obligation.
        merge_mcp_config(&windsurf, "windsurf").unwrap();
        let finalized = std::cell::Cell::new(false);
        let repaired = remerge_mcp_targets_exact_with_finalizer(&captured, || {
            finalized.set(true);
            Ok(())
        })
        .unwrap();

        assert!(finalized.get());
        assert!(repaired.contains(&ConfigLock::normalized_path(&cursor).unwrap()));
        assert!(repaired.contains(&ConfigLock::normalized_path(&windsurf).unwrap()));
        assert_eq!(
            read_kin_mcp_entry(&windsurf).unwrap()["command"].as_str(),
            Some(kin_home.join("bin/kin").to_string_lossy().as_ref())
        );
    }

    #[test]
    #[serial]
    fn workspace_mcp_excludes_are_idempotent_in_linked_worktrees() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let linked = dir.path().join("linked");
        fs::create_dir_all(&main).unwrap();
        let git = |args: &[&str], cwd: &Path| {
            let output = crate::commands::test_subprocess::fixture_git(cwd)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q"], &main);
        git(&["config", "user.email", "kin-test@example.invalid"], &main);
        git(&["config", "user.name", "Kin Test"], &main);
        fs::write(main.join("README.md"), "fixture\n").unwrap();
        git(&["add", "README.md"], &main);
        git(&["commit", "-qm", "fixture"], &main);
        let linked_text = linked.to_string_lossy().into_owned();
        git(
            &["worktree", "add", "-q", "-b", "linked-test", &linked_text],
            &main,
        );

        let first = ensure_workspace_mcp_git_excluded(&linked).unwrap().unwrap();
        let second = ensure_workspace_mcp_git_excluded(&linked).unwrap().unwrap();
        assert_eq!(first, second);
        let config = linked.join(".agents/mcp_config.json");
        drop(ConfigLock::acquire(&config).unwrap());
        fs::write(&config, "{}\n").unwrap();

        let exclude = fs::read_to_string(first).unwrap();
        for pattern in WORKSPACE_MCP_GIT_EXCLUDE_PATTERNS {
            assert_eq!(exclude.lines().filter(|line| *line == pattern).count(), 1);
        }
        let status = crate::commands::test_subprocess::fixture_git(&linked)
            .args(["status", "--porcelain", "--untracked-files=all"])
            .output()
            .unwrap();
        assert!(status.status.success());
        assert!(
            status.stdout.is_empty(),
            "workspace MCP config or lock leaked into Git status: {}",
            String::from_utf8_lossy(&status.stdout)
        );
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn antigravity_first_setup_captures_and_repairs_global_and_workspace_bindings() {
        struct CurrentDirGuard(PathBuf);
        impl Drop for CurrentDirGuard {
            fn drop(&mut self) {
                let _ = env::set_current_dir(&self.0);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        let repo = dir.path().join("repo");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::create_dir_all(repo.join(".kin")).unwrap();
        fs::copy(env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        let legacy = home.join(".gemini/antigravity-ide/mcp_config.json");
        fs::create_dir_all(legacy.parent().unwrap()).unwrap();
        let legacy_without_kin =
            br#"{"mcpServers":{"other":{"command":"other"}},"userPolicy":"preserve"}"#;
        fs::write(&legacy, legacy_without_kin).unwrap();
        let git = crate::commands::test_subprocess::fixture_git(&repo)
            .args(["init", "-q"])
            .output()
            .unwrap();
        assert!(git.status.success());
        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _scan_root =
            EnvVarGuard::set(crate::commands::managed_config_scope::SCAN_ROOT_ENV, &repo);
        let previous = env::current_dir().unwrap();
        env::set_current_dir(&repo).unwrap();
        let _cwd = CurrentDirGuard(previous);
        let canonical_repo = repo.canonicalize().unwrap();

        let global = configure_antigravity().unwrap();
        let workspace = repo.join(".agents/mcp_config.json");
        assert_eq!(
            fs::read(&legacy).unwrap(),
            legacy_without_kin,
            "legacy Antigravity config without a Kin entry must remain untouched"
        );
        assert_eq!(global, home.join(".gemini/config/mcp_config.json"));
        for path in [&global, &workspace] {
            let entry = read_kin_mcp_entry(path).unwrap();
            assert_eq!(
                entry["command"].as_str(),
                Some(kin_home.join("bin/kin").to_string_lossy().as_ref())
            );
            assert_eq!(
                entry["args"],
                serde_json::json!(["mcp", "start", "--repo", canonical_repo.to_string_lossy()])
            );
            assert_eq!(
                entry["cwd"].as_str(),
                Some(canonical_repo.to_string_lossy().as_ref())
            );
        }

        let targets = current_mcp_repair_targets().unwrap();
        let antigravity = targets
            .iter()
            .filter(|target| target.id == "antigravity" || target.id == "antigravity_workspace")
            .collect::<Vec<_>>();
        assert_eq!(antigravity.len(), 2);
        assert!(antigravity
            .iter()
            .all(|target| target.repo_root.as_deref() == Some(canonical_repo.as_path())));
        let finalized = std::cell::Cell::new(false);
        let repaired = remerge_mcp_targets_exact_with_finalizer(&targets, || {
            finalized.set(true);
            Ok(())
        })
        .unwrap();
        assert!(finalized.get());
        assert!(repaired.contains(&ConfigLock::normalized_path(&global).unwrap()));
        assert!(repaired.contains(&ConfigLock::normalized_path(&workspace).unwrap()));
        assert!(mcp_repair_targets_ledger_verified(&targets).unwrap());
        assert!(!kin_home.join("update-restart-ack-required.json").exists());
    }

    /// `kin setup` resolved `--repo` from the directory it ran in and the health
    /// checker resolved its own expectation from the directory IT ran in, so the
    /// two disagreed about a binding neither of them had touched and a fresh,
    /// successful setup read as config drift on the next check. The binding
    /// setup recorded is the one fact; this test walks a real write through a
    /// check from somewhere else, and then proves the check can still fail.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn a_binding_setup_wrote_reads_exact_from_another_repository() {
        use crate::commands::health::{evaluate_antigravity_binding, HealthStatus};

        struct CurrentDirGuard(PathBuf);
        impl Drop for CurrentDirGuard {
            fn drop(&mut self) {
                let _ = env::set_current_dir(&self.0);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        let bound = dir.path().join("bound-repo");
        let moved = dir.path().join("bound-repo-moved");
        let elsewhere = dir.path().join("another-repo");
        fs::create_dir_all(kin_home.join("bin")).unwrap();
        fs::create_dir_all(bound.join(".kin")).unwrap();
        fs::create_dir_all(elsewhere.join(".kin")).unwrap();
        fs::create_dir_all(&home).unwrap();
        fs::copy(env::current_exe().unwrap(), kin_home.join("bin/kin")).unwrap();
        // The workspace binding refuses a repository without trusted Git
        // authority, so the fixture is a real one.
        for repo in [&bound, &elsewhere] {
            let git = crate::commands::test_subprocess::fixture_git(repo)
                .args(["init", "-q"])
                .output()
                .unwrap();
            assert!(git.status.success());
        }

        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let previous = env::current_dir().unwrap();
        let _cwd = CurrentDirGuard(previous);
        let scan_root = crate::commands::managed_config_scope::SCAN_ROOT_ENV;

        let global = {
            let _scan_root = EnvVarGuard::set(scan_root, &bound);
            env::set_current_dir(&bound).unwrap();
            configure_antigravity().unwrap()
        };
        let canonical_bound = bound.canonicalize().unwrap();
        assert_eq!(
            bound_repo_for_mcp_config(&global),
            Some(canonical_bound.clone()),
            "setup binds the repository it resolved from its own directory"
        );

        {
            let _scan_root = EnvVarGuard::set(scan_root, &bound);
            assert!(
                evaluate_antigravity_binding(&global, false).is_none(),
                "the binding is exact in the repository it was written from"
            );
        }

        let _scan_root = EnvVarGuard::set(scan_root, &elsewhere);
        env::set_current_dir(&elsewhere).unwrap();
        assert!(
            evaluate_antigravity_binding(&global, false).is_none(),
            "a binding kin setup wrote must not read as drift because the checker stood elsewhere"
        );

        // A binding whose repository has gone away is a real fault, not a
        // disagreement about directories, so the recorded fingerprint does not
        // excuse it.
        fs::rename(&bound, &moved).unwrap();
        assert!(
            matches!(
                evaluate_antigravity_binding(&global, false),
                Some((HealthStatus::Misconfigured, _))
            ),
            "a binding pointing at a repository that no longer exists must be caught"
        );
        fs::rename(&moved, &bound).unwrap();
        assert!(
            evaluate_antigravity_binding(&global, false).is_none(),
            "the untouched binding reads exact again once its repository is back"
        );

        // The control. A verifier that cannot fail is not a verifier: an entry
        // edited after setup wrote it no longer matches what the ledger
        // recorded, so the strict comparison applies and the edit is caught
        // from either directory.
        let mut root: serde_json::Value =
            serde_json::from_slice(&fs::read(&global).unwrap()).unwrap();
        root["mcpServers"]["kin"]["args"] = serde_json::json!([
            "mcp",
            "start",
            "--repo",
            dir.path().join("never-a-repository").to_string_lossy()
        ]);
        fs::write(&global, serde_json::to_vec_pretty(&root).unwrap()).unwrap();
        assert!(
            matches!(
                evaluate_antigravity_binding(&global, false),
                Some((HealthStatus::Misconfigured, _))
            ),
            "an entry edited after setup wrote it must still be caught"
        );
        env::set_current_dir(&bound).unwrap();
        let _scan_root_bound = EnvVarGuard::set(scan_root, &bound);
        assert!(
            matches!(
                evaluate_antigravity_binding(&global, false),
                Some((HealthStatus::Misconfigured, _))
            ),
            "the edited entry is caught from the repository it was bound to as well"
        );
    }

    /// A repository enclosing the fixture is not the repository under test.
    /// Discovery walks upward, so without a ceiling a test running below a real
    /// checkout binds that checkout and captures its workspace MCP config.
    #[cfg(unix)]
    #[test]
    #[serial]
    fn enclosing_workspace_config_is_never_captured_from_a_scoped_fixture() {
        struct CurrentDirGuard(PathBuf);
        impl Drop for CurrentDirGuard {
            fn drop(&mut self) {
                let _ = env::set_current_dir(&self.0);
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let outer = dir.path().join("enclosing-checkout");
        let inner = outer.join("fixture");
        let home = dir.path().join("home");
        let kin_home = dir.path().join("kin-home");
        fs::create_dir_all(outer.join(".kin")).unwrap();
        fs::create_dir_all(outer.join(".agents")).unwrap();
        fs::create_dir_all(&inner).unwrap();
        fs::create_dir_all(&home).unwrap();
        let decoy = outer.join(".agents").join("mcp_config.json");
        let decoy_bytes =
            br#"{"mcpServers":{"kin":{"command":"/enclosing/kin","args":["mcp","start"]}}}"#;
        fs::write(&decoy, decoy_bytes).unwrap();

        let _home = EnvVarGuard::set("HOME", &home);
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let _scan_root =
            EnvVarGuard::set(crate::commands::managed_config_scope::SCAN_ROOT_ENV, &inner);
        let previous = env::current_dir().unwrap();
        env::set_current_dir(&inner).unwrap();
        let _cwd = CurrentDirGuard(previous);

        let canonical_decoy = decoy.canonicalize().unwrap();
        let discovered = crate::commands::health::mcp_client_config_paths();
        assert!(
            !discovered.iter().any(|(_, _, path)| path
                .canonicalize()
                .is_ok_and(|path| path == canonical_decoy)),
            "discovery reached the enclosing checkout: {discovered:?}"
        );

        let targets = current_mcp_repair_targets().unwrap();
        assert!(
            !targets.iter().any(|target| target.path == canonical_decoy
                || target.repo_root.as_deref() == Some(outer.canonicalize().unwrap().as_path())),
            "repair capture reached the enclosing checkout: {targets:?}"
        );
        assert_eq!(fs::read(&decoy).unwrap(), decoy_bytes);
    }

    /// The fixture guard must fail at the moment an escaping path is resolved,
    /// so a leak is reported against the flow that produced it.
    ///
    /// Not serialized, and it does not need to be: the declaration is
    /// thread-local, so no other test can observe it however they interleave.
    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "managed config path escaped its fixture")]
    fn managed_config_outside_the_declared_fixture_aborts_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = dir.path().join("fixture");
        let outside = dir.path().join("outside");
        fs::create_dir_all(&fixture).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let _fixture_root =
            crate::commands::managed_config_scope::test_scope::FixtureScope::declare(&fixture);
        let _ = ConfigLock::acquire(&outside.join("mcp.json"));
    }

    #[test]
    #[serial]
    fn antigravity_global_remerge_preserves_existing_cwd_and_policy() {
        let dir = tempfile::tempdir().unwrap();
        let kin_home = dir.path().join("kin-home");
        let repo = dir.path().join("repo");
        let config = dir.path().join("mcp_config.json");
        fs::create_dir_all(repo.join(".kin")).unwrap();
        fs::write(
            &config,
            br#"{
  "mcpServers": {
    "kin": {
      "command": "/old/kin",
      "args": ["mcp", "start"],
      "cwd": "/user/chosen/cwd",
      "policy": {"approval": "manual"}
    }
  }
}"#,
        )
        .unwrap();
        let _kin_home = EnvVarGuard::set("KIN_HOME", &kin_home);
        let target = McpRepairTarget {
            id: "antigravity".to_string(),
            path: config.clone(),
            repo_root: Some(repo.canonicalize().unwrap()),
            captured_config_sha256: "0".repeat(64),
        };
        let lock = ConfigLock::acquire(&config).unwrap();
        merge_json_mcp_target_locked(&target, "/managed/kin", &lock).unwrap();
        let entry = read_kin_mcp_entry(&config).unwrap();
        assert_eq!(entry["cwd"], "/user/chosen/cwd");
        assert_eq!(entry["policy"]["approval"], "manual");
        assert_eq!(
            entry["args"],
            serde_json::json!([
                "mcp",
                "start",
                "--repo",
                repo.canonicalize().unwrap().to_string_lossy()
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn workspace_mcp_excludes_reject_symlink_and_external_gitdir_authority() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let trusted = dir.path().join("trusted");
        fs::create_dir_all(&trusted).unwrap();
        let output = crate::commands::test_subprocess::fixture_git(&trusted)
            .args(["init", "-q"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let external_exclude = trusted.join(".git/info/exclude");
        let baseline = fs::read(&external_exclude).unwrap();

        let symlinked = dir.path().join("symlinked");
        fs::create_dir_all(&symlinked).unwrap();
        symlink(trusted.join(".git"), symlinked.join(".git")).unwrap();
        let error = ensure_workspace_mcp_git_excluded(&symlinked)
            .expect_err("symlinked .git authority must fail closed");
        assert!(format!("{error:#}").contains("must not be a symlink"));
        assert_eq!(fs::read(&external_exclude).unwrap(), baseline);

        let redirected = dir.path().join("redirected");
        fs::create_dir_all(&redirected).unwrap();
        fs::write(
            redirected.join(".git"),
            format!("gitdir: {}\n", trusted.join(".git").display()),
        )
        .unwrap();
        ensure_workspace_mcp_git_excluded(&redirected)
            .expect_err("arbitrary external gitdir authority must fail closed");
        assert_eq!(fs::read(&external_exclude).unwrap(), baseline);
    }

    #[test]
    fn workspace_mcp_excludes_reject_escaped_commondir_and_wrong_backpointer() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let linked = dir.path().join("linked");
        fs::create_dir_all(&main).unwrap();
        let git = |args: &[&str], cwd: &Path| {
            let output = crate::commands::test_subprocess::fixture_git(cwd)
                .args(args)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&output.stderr)
            );
        };
        git(&["init", "-q"], &main);
        git(&["config", "user.email", "kin-test@example.invalid"], &main);
        git(&["config", "user.name", "Kin Test"], &main);
        fs::write(main.join("README.md"), "fixture\n").unwrap();
        git(&["add", "README.md"], &main);
        git(&["commit", "-qm", "fixture"], &main);
        let linked_text = linked.to_string_lossy().into_owned();
        git(
            &[
                "worktree",
                "add",
                "-q",
                "-b",
                "authority-test",
                &linked_text,
            ],
            &main,
        );

        let pointer = fs::read_to_string(linked.join(".git")).unwrap();
        let git_dir = PathBuf::from(pointer.trim().strip_prefix("gitdir:").unwrap().trim());
        let commondir = git_dir.join("commondir");
        let original_commondir = fs::read(&commondir).unwrap();
        fs::write(&commondir, format!("{}\n", dir.path().display())).unwrap();
        let error = ensure_workspace_mcp_git_excluded(&linked)
            .expect_err("absolute commondir escape must fail closed");
        assert!(format!("{error:#}").contains("commondir authority must be relative"));
        fs::write(&commondir, original_commondir).unwrap();

        let reverse = git_dir.join("gitdir");
        let original_reverse = fs::read(&reverse).unwrap();
        fs::write(&reverse, format!("{}\n", main.join(".git/HEAD").display())).unwrap();
        let error = ensure_workspace_mcp_git_excluded(&linked)
            .expect_err("wrong gitdir backpointer must fail closed");
        assert!(format!("{error:#}").contains("backpointer"));
        fs::write(reverse, original_reverse).unwrap();
    }

    // -----------------------------------------------------------------------
    // `--install-language-servers` says what it did (FIR-2502)
    // -----------------------------------------------------------------------

    /// A request with nothing observed. Each test names only the facts it is
    /// about, so no assertion below depends on what this machine has installed.
    fn request(requested: bool, fixing: bool) -> super::LanguageServerRequest {
        super::LanguageServerRequest {
            requested,
            fixing,
            in_repository: true,
            coverage_status: Some(HealthStatus::Healthy),
            missing_on_host: Vec::new(),
        }
    }

    fn explained(request: &super::LanguageServerRequest) -> Vec<String> {
        match super::decide_language_server_request(request) {
            super::LanguageServerDecision::Explain(lines) => lines,
            other => panic!("expected an explanation, got {other:?}"),
        }
    }

    /// Hole one. The flag was bound at `doctor`'s signature and first read past
    /// the `--fix` early return, so a stranger's `kin doctor
    /// --install-language-servers` printed an ordinary report, installed
    /// nothing, said nothing about language servers and exited 0.
    #[test]
    fn the_flag_without_fix_names_the_command_that_would_work() {
        let lines = explained(&request(true, false));
        let text = lines.join("\n");
        assert!(
            text.contains("Nothing installed."),
            "the no-op has to be stated before anything else: {text}"
        );
        assert!(
            text.contains("only runs under `--fix`"),
            "the reason has to name the missing flag: {text}"
        );
        assert!(
            text.contains("kin doctor --fix --install-language-servers"),
            "an honest refusal names the command that works: {text}"
        );
    }

    /// The other half of hole one: a run that never asked keeps its output.
    /// A line about a repair nobody requested is noise on every healthy install.
    #[test]
    fn a_doctor_run_that_did_not_ask_stays_silent() {
        assert_eq!(
            super::decide_language_server_request(&request(false, false)),
            super::LanguageServerDecision::Silent
        );
        assert_eq!(
            super::decide_language_server_request(&super::LanguageServerRequest {
                missing_on_host: vec![LanguageId::Python],
                ..request(false, true)
            }),
            super::LanguageServerDecision::Silent
        );
    }

    /// Hole two, outside a repository. The coverage row reads `Unsupported`
    /// there, the gate stays shut, and before this the run downloaded nothing
    /// and printed not one word.
    #[test]
    fn outside_a_repository_the_run_says_where_to_run_it_instead() {
        let lines = explained(&super::LanguageServerRequest {
            in_repository: false,
            coverage_status: Some(HealthStatus::Unsupported),
            missing_on_host: vec![LanguageId::Python, LanguageId::TypeScript],
            ..request(true, true)
        });
        let text = lines.join("\n");
        assert!(
            text.contains("not inside a Kin repository"),
            "the reader has to be told which state they are in: {text}"
        );
        // The scoping nuance the stranger had to reverse-engineer by hand:
        // servers install per host, the gap is measured per repository.
        assert!(
            text.contains("per repository") && text.contains("per host"),
            "both scopes have to be named or the reader guesses: {text}"
        );
        assert!(
            text.contains("rust, python, typescript, javascript"),
            "it has to name what it would have checked: {text}"
        );
        assert!(
            text.contains("missing a server for python, typescript"),
            "it has to name what this host actually lacks: {text}"
        );
    }

    /// Hole two, inside a repository with nothing to do. The host being
    /// complete is a fact about the machine, so it is stated about the machine.
    #[test]
    fn a_complete_host_is_reported_as_a_fact_about_the_host() {
        let lines = explained(&request(true, true));
        let text = lines.join("\n");
        assert!(
            text.contains("Every language this build enriches already has a server on this host"),
            "{text}"
        );
        assert!(
            text.contains("rust, python, typescript, javascript"),
            "naming the set is what separates this from a silent exit: {text}"
        );
        assert!(
            !text.contains("reference-edge gap"),
            "no gap was observed, so none may be asserted: {text}"
        );
    }

    /// The second half of hole two, and the state the two strangers were
    /// actually in: servers missing from the host, and a repository whose graph
    /// reported no gap for them to close.
    #[test]
    fn a_repository_with_no_gap_names_the_missing_servers_and_the_commands() {
        let lines = explained(&super::LanguageServerRequest {
            missing_on_host: vec![LanguageId::Python],
            ..request(true, true)
        });
        let text = lines.join("\n");
        assert!(
            text.contains("This repository's graph reports no reference-edge gap"),
            "{text}"
        );
        assert!(
            text.contains("This host is still missing a server for python"),
            "the host fact and the repository fact are different facts: {text}"
        );
        assert!(
            text.contains("npm install -g pyright"),
            "the command is the whole value of saying anything here: {text}"
        );
    }

    /// A row that never read the graph must not be reported as a row that read
    /// it and found nothing. Both are non-Pending, and only one of them means
    /// the repository actually has no gap.
    #[test]
    fn an_unread_coverage_row_is_never_reported_as_no_gap() {
        let lines = explained(&super::LanguageServerRequest {
            coverage_status: Some(HealthStatus::Unsupported),
            missing_on_host: vec![LanguageId::Python],
            ..request(true, true)
        });
        let text = lines.join("\n");
        assert!(
            text.contains("could not measure this repository's reference-edge coverage"),
            "{text}"
        );
        assert!(
            !text.contains("reports no reference-edge gap"),
            "an unread row proves nothing about the gap: {text}"
        );
    }

    /// The gate itself still opens on exactly the two observed-gap states, and
    /// on nothing else. This is the behavior the honesty batch must not spend.
    #[test]
    fn only_an_observed_gap_installs_anything() {
        for status in [HealthStatus::Pending, HealthStatus::Stale] {
            assert_eq!(
                super::decide_language_server_request(&super::LanguageServerRequest {
                    coverage_status: Some(status.clone()),
                    missing_on_host: vec![LanguageId::Python],
                    ..request(true, true)
                }),
                super::LanguageServerDecision::Install(vec![LanguageId::Python]),
                "{status:?} is an observed gap"
            );
        }
        for status in [
            None,
            Some(HealthStatus::Healthy),
            Some(HealthStatus::Unsupported),
            Some(HealthStatus::Missing),
            Some(HealthStatus::Degraded),
            Some(HealthStatus::Misconfigured),
        ] {
            let decision = super::decide_language_server_request(&super::LanguageServerRequest {
                coverage_status: status.clone(),
                missing_on_host: vec![LanguageId::Python],
                ..request(true, true)
            });
            assert!(
                !matches!(decision, super::LanguageServerDecision::Install(_)),
                "{status:?} is not an observed gap, so it must not spend bandwidth"
            );
        }
    }

    /// The empty block at the heart of hole two: a real gap that no install
    /// closes, because the host already has every server. It used to be a
    /// comment and nothing else.
    #[test]
    fn an_observed_gap_a_complete_host_cannot_close_says_so() {
        let lines = explained(&super::LanguageServerRequest {
            coverage_status: Some(HealthStatus::Pending),
            ..request(true, true)
        });
        let text = lines.join("\n");
        assert!(text.contains("already has a server on this host"), "{text}");
        assert!(
            text.contains("still reports a reference-edge gap"),
            "the gap is real and the reader came here to close it: {text}"
        );
    }

    /// The founder register, enforced rather than reviewed. Every message this
    /// rule can produce, in every state it can produce one.
    #[test]
    fn no_language_server_message_carries_an_em_dash() {
        let statuses = [
            None,
            Some(HealthStatus::Healthy),
            Some(HealthStatus::Pending),
            Some(HealthStatus::Stale),
            Some(HealthStatus::Unsupported),
            Some(HealthStatus::Missing),
            Some(HealthStatus::Degraded),
            Some(HealthStatus::Misconfigured),
        ];
        let mut seen = 0;
        for fixing in [false, true] {
            for in_repository in [false, true] {
                for missing in [
                    Vec::new(),
                    vec![LanguageId::Python],
                    vec![
                        LanguageId::Rust,
                        LanguageId::Python,
                        LanguageId::TypeScript,
                        LanguageId::JavaScript,
                    ],
                ] {
                    for status in &statuses {
                        let decision =
                            super::decide_language_server_request(&super::LanguageServerRequest {
                                requested: true,
                                fixing,
                                in_repository,
                                coverage_status: status.clone(),
                                missing_on_host: missing.clone(),
                            });
                        if let super::LanguageServerDecision::Explain(lines) = decision {
                            seen += 1;
                            for line in lines {
                                assert!(!line.contains('\u{2014}'), "em dash in: {line}");
                                assert!(!line.is_empty(), "an empty line explains nothing");
                            }
                        }
                    }
                }
            }
        }
        assert!(seen > 0, "the sweep must actually reach an explanation");
    }
}
