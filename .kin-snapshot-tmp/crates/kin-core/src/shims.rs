// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Native-mode command shims.
//!
//! When Kin launches an assistant or shell in native mode, it prepends a
//! directory of small wrapper scripts to `$PATH`. These shims intercept
//! common file-system commands (`cat`, `rg`, `find`, etc.) and
//! transparently redirect them to `.kin/source-root/` so agents don't
//! waste tokens on "file not found" failures against the empty control root.
//!
//! Two shim strategies:
//!
//! - **Content shims** (cat, head, tail, sed): resolve individual file-path
//!   arguments against `$KIN_SOURCE_ROOT` when they don't exist locally.
//!   This lets `cat AGENTS.md` still read the bootstrap doc at the control
//!   root while `cat src/main.rs` transparently reads from source-root.
//!
//! - **Discovery shims** (rg, grep, find, ls, tree, fd, wc): `cd` into
//!   `$KIN_SOURCE_ROOT` before executing, so searches and listings default
//!   to the real source tree.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{KinError, Result};
use crate::layout::KinLayout;

/// Commands that get the content-shim treatment (path-level resolution).
const CONTENT_COMMANDS: &[&str] = &["cat", "head", "tail", "sed", "bat"];

/// Commands that get the discovery-shim treatment (cd to source-root).
const DISCOVERY_COMMANDS: &[&str] = &["rg", "grep", "find", "fd", "ls", "tree", "wc"];

/// Generate (or regenerate) the shim directory at `.kin/shims/`.
///
/// Returns the absolute path to the shim directory, ready to be prepended
/// to `$PATH`.
pub fn ensure_shim_dir(layout: &KinLayout) -> Result<PathBuf> {
    let shim_dir = layout.root().join("shims");
    fs::create_dir_all(&shim_dir).map_err(|e| KinError::io(&shim_dir, e))?;

    for cmd in CONTENT_COMMANDS {
        write_shim(&shim_dir, cmd, &content_shim_script(cmd))?;
    }
    for cmd in DISCOVERY_COMMANDS {
        write_shim(&shim_dir, cmd, &discovery_shim_script(cmd))?;
    }

    Ok(shim_dir)
}

/// Build the environment variables needed for shims to function, targeting a
/// specific root directory.
///
/// Returns a list of `(key, value)` pairs to set on the launched process:
/// - `KIN_SOURCE_ROOT` — absolute path to the shim target root
/// - `KIN_ORIGINAL_PATH` — the original `$PATH` so shims can find real binaries
/// - `PATH` — shim dir prepended to the original `$PATH`
/// - `KIN_DISCOVERY_MODE` — optional discovery policy (`redirect` or `deny`)
/// - `KIN_CONTENT_MODE` — optional content-read policy (`redirect` or `deny`)
pub fn shim_env_for_root(shim_dir: &Path, target_root: &Path) -> Vec<(String, String)> {
    let original_path = std::env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", shim_dir.display(), original_path);

    vec![
        (
            "KIN_SOURCE_ROOT".into(),
            target_root.to_string_lossy().into(),
        ),
        ("KIN_ORIGINAL_PATH".into(), original_path),
        ("PATH".into(), new_path),
    ]
}

/// Build the environment variables needed for shims to function against the
/// repository's canonical source surface.
pub fn shim_env(layout: &KinLayout, shim_dir: &Path) -> Vec<(String, String)> {
    shim_env_for_root(shim_dir, &layout.source_root_dir())
}

// ---------------------------------------------------------------------------
// Shim script generators
// ---------------------------------------------------------------------------

/// Content shim: resolves individual file-path arguments against
/// `$KIN_SOURCE_ROOT` when they don't exist at the current directory.
fn content_shim_script(cmd: &str) -> String {
    format!(
        r#"#!/bin/bash
# Kin native-mode shim for {cmd}
# Resolves file paths against $KIN_SOURCE_ROOT when not found locally.
REAL="$(PATH="$KIN_ORIGINAL_PATH" command -v {cmd})"
[[ -z "$REAL" ]] && {{ echo "{cmd}: command not found" >&2; exit 127; }}
if [[ "$KIN_CONTENT_MODE" == "deny" ]]; then
    echo "{cmd}: direct file reads are disabled in this Kin-native mode" >&2
    echo "Use: kin overview --compact" >&2
    echo "Use: kin search <name> --show-body --limit 5" >&2
    echo "Use: kin context <entity>" >&2
    exit 87
fi
if [[ -z "$KIN_SOURCE_ROOT" ]]; then
    exec "$REAL" "$@"
fi
args=()
for arg in "$@"; do
    if [[ "$arg" != -* && ! -e "$arg" && -e "$KIN_SOURCE_ROOT/$arg" ]]; then
        args+=("$KIN_SOURCE_ROOT/$arg")
    else
        args+=("$arg")
    fi
done
if [[ -n "$KIN_SHIM_LOG" ]]; then
    _kin_args=$(printf '%q ' "$@")
    _kin_cwd=$(pwd)
    _kin_args=${{_kin_args//\\/\\\\}}
    _kin_args=${{_kin_args//\"/\\\"}}
    _kin_args=${{_kin_args//$'\n'/\\n}}
    _kin_cwd=${{_kin_cwd//\\/\\\\}}
    _kin_cwd=${{_kin_cwd//\"/\\\"}}
    _kin_cwd=${{_kin_cwd//$'\n'/\\n}}
    _kin_start_s=$(date +%s)
    _kin_start_ms=$((_kin_start_s * 1000))
    "$REAL" "${{args[@]}}"
    _kin_exit=$?
    _kin_end_s=$(date +%s)
    _kin_end_ms=$((_kin_end_s * 1000))
    printf '{{"cmd":"{cmd}","args":"%s","cwd":"%s","start_epoch_ms":%d,"end_epoch_ms":%d,"exit_code":%d}}\n' \
      "$_kin_args" "$_kin_cwd" "$_kin_start_ms" "$_kin_end_ms" "$_kin_exit" >> "$KIN_SHIM_LOG" 2>/dev/null
    exit $_kin_exit
fi
exec "$REAL" "${{args[@]}}"
"#,
        cmd = cmd
    )
}

/// Discovery shim: changes to `$KIN_SOURCE_ROOT` before executing so
/// searches and listings target the real source tree by default.
fn discovery_shim_script(cmd: &str) -> String {
    format!(
        r#"#!/bin/bash
# Kin native-mode shim for {cmd}
# Searches source-root by default instead of the empty control root.
# If KIN_DISCOVERY_MODE=deny, blocks filesystem discovery and tells
# the caller to use Kin-native discovery commands instead.
REAL="$(PATH="$KIN_ORIGINAL_PATH" command -v {cmd})"
[[ -z "$REAL" ]] && {{ echo "{cmd}: command not found" >&2; exit 127; }}
if [[ "$KIN_DISCOVERY_MODE" == "deny" ]]; then
    echo "{cmd}: filesystem discovery is disabled in this Kin-native benchmark mode" >&2
    echo "Use: kin overview --compact" >&2
    echo "Use: kin search <name> --show-body --limit 5" >&2
    echo "Use: kin context <entity>" >&2
    exit 86
fi
if [[ -n "$KIN_SOURCE_ROOT" && -d "$KIN_SOURCE_ROOT" ]]; then
    cd "$KIN_SOURCE_ROOT"
fi
if [[ -n "$KIN_SHIM_LOG" ]]; then
    _kin_args=$(printf '%q ' "$@")
    _kin_cwd=$(pwd)
    _kin_args=${{_kin_args//\\/\\\\}}
    _kin_args=${{_kin_args//\"/\\\"}}
    _kin_args=${{_kin_args//$'\n'/\\n}}
    _kin_cwd=${{_kin_cwd//\\/\\\\}}
    _kin_cwd=${{_kin_cwd//\"/\\\"}}
    _kin_cwd=${{_kin_cwd//$'\n'/\\n}}
    _kin_start_s=$(date +%s)
    _kin_start_ms=$((_kin_start_s * 1000))
    "$REAL" "$@"
    _kin_exit=$?
    _kin_end_s=$(date +%s)
    _kin_end_ms=$((_kin_end_s * 1000))
    printf '{{"cmd":"{cmd}","args":"%s","cwd":"%s","start_epoch_ms":%d,"end_epoch_ms":%d,"exit_code":%d}}\n' \
      "$_kin_args" "$_kin_cwd" "$_kin_start_ms" "$_kin_end_ms" "$_kin_exit" >> "$KIN_SHIM_LOG" 2>/dev/null
    exit $_kin_exit
fi
exec "$REAL" "$@"
"#,
        cmd = cmd
    )
}

fn write_shim(dir: &Path, name: &str, script: &str) -> Result<()> {
    let path = dir.join(name);
    fs::write(&path, script).map_err(|e| KinError::io(&path, e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .map_err(|e| KinError::io(&path, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_shim_has_path_resolution() {
        let script = content_shim_script("cat");
        assert!(script.contains("KIN_CONTENT_MODE"));
        assert!(script.contains("direct file reads are disabled"));
        assert!(script.contains("KIN_SOURCE_ROOT"));
        assert!(script.contains("KIN_ORIGINAL_PATH"));
        assert!(script.contains("command -v cat"));
        assert!(script.contains("exec"));
        assert!(script.contains("KIN_SHIM_LOG"));
    }

    #[test]
    fn discovery_shim_cds_to_source_root() {
        let script = discovery_shim_script("rg");
        assert!(script.contains("KIN_DISCOVERY_MODE"));
        assert!(script.contains("filesystem discovery is disabled"));
        assert!(script.contains("cd \"$KIN_SOURCE_ROOT\""));
        assert!(script.contains("command -v rg"));
        assert!(script.contains("exec"));
        assert!(script.contains("KIN_SHIM_LOG"));
    }

    #[test]
    fn content_shim_logs_jsonl_when_kin_shim_log_set() {
        let script = content_shim_script("cat");
        // Verify logging block structure
        assert!(script.contains(r#"if [[ -n "$KIN_SHIM_LOG" ]]; then"#));
        assert!(script.contains("_kin_start_s=$(date +%s)"));
        assert!(script.contains("_kin_start_ms=$((_kin_start_s * 1000))"));
        assert!(script.contains("_kin_exit=$?"));
        assert!(script.contains("_kin_end_ms=$((_kin_end_s * 1000))"));
        assert!(script.contains(r#""cmd":"cat""#));
        assert!(script.contains(r#">> "$KIN_SHIM_LOG" 2>/dev/null"#));
        assert!(script.contains("exit $_kin_exit"));
    }

    #[test]
    fn discovery_shim_logs_jsonl_when_kin_shim_log_set() {
        let script = discovery_shim_script("rg");
        // Verify logging block structure
        assert!(script.contains(r#"if [[ -n "$KIN_SHIM_LOG" ]]; then"#));
        assert!(script.contains("_kin_start_s=$(date +%s)"));
        assert!(script.contains("_kin_start_ms=$((_kin_start_s * 1000))"));
        assert!(script.contains("_kin_exit=$?"));
        assert!(script.contains("_kin_end_ms=$((_kin_end_s * 1000))"));
        assert!(script.contains(r#""cmd":"rg""#));
        assert!(script.contains(r#">> "$KIN_SHIM_LOG" 2>/dev/null"#));
        assert!(script.contains("exit $_kin_exit"));
    }

    #[test]
    fn shim_log_block_preserves_exec_fallback() {
        // When KIN_SHIM_LOG is not set, the script should still fall through to exec
        let content = content_shim_script("sed");
        let discovery = discovery_shim_script("find");

        // Both shims must end with an exec line after the logging block
        let content_lines: Vec<&str> = content.trim().lines().collect();
        let discovery_lines: Vec<&str> = discovery.trim().lines().collect();

        assert!(
            content_lines.last().unwrap().contains("exec \"$REAL\""),
            "content shim must end with exec fallback"
        );
        assert!(
            discovery_lines.last().unwrap().contains("exec \"$REAL\""),
            "discovery shim must end with exec fallback"
        );
    }

    #[test]
    fn all_shims_are_generated() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();

        let layout = KinLayout::discover(dir.path()).unwrap();
        let shim_dir = ensure_shim_dir(&layout).unwrap();

        for cmd in CONTENT_COMMANDS {
            let path = shim_dir.join(cmd);
            assert!(path.exists(), "missing content shim: {}", cmd);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let meta = std::fs::metadata(&path).unwrap();
                assert!(
                    meta.permissions().mode() & 0o111 != 0,
                    "{} not executable",
                    cmd
                );
            }
        }
        for cmd in DISCOVERY_COMMANDS {
            let path = shim_dir.join(cmd);
            assert!(path.exists(), "missing discovery shim: {}", cmd);
        }
    }

    #[test]
    fn shim_env_prepends_path() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();

        let layout = KinLayout::discover(dir.path()).unwrap();
        let shim_dir = kin_dir.join("shims");
        std::fs::create_dir_all(&shim_dir).unwrap();

        let env = shim_env(&layout, &shim_dir);
        let path_entry = env.iter().find(|(k, _)| k == "PATH").unwrap();
        assert!(
            path_entry
                .1
                .starts_with(&shim_dir.to_string_lossy().to_string()),
            "PATH should start with shim dir"
        );

        let source_root = env.iter().find(|(k, _)| k == "KIN_SOURCE_ROOT").unwrap();
        assert!(source_root.1.contains("source-root"));
    }

    #[test]
    fn shim_env_for_root_targets_custom_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let shim_dir = dir.path().join("shims");
        std::fs::create_dir_all(&shim_dir).unwrap();
        let target_root = dir.path().join("run/session-123");
        std::fs::create_dir_all(&target_root).unwrap();

        let env = shim_env_for_root(&shim_dir, &target_root);
        let source_root = env.iter().find(|(k, _)| k == "KIN_SOURCE_ROOT").unwrap();
        assert_eq!(source_root.1, target_root.to_string_lossy());
    }
}
