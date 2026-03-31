// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;

use kin_runtime::workspace::MaterializeStrategy;

/// `kin shell [--strategy <s>]` — Open an interactive shell in a materialized session workspace.
pub async fn run(
    strategy: Option<String>,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;

    let session_id = uuid::Uuid::new_v4();
    let session_dir = layout
        .root()
        .join("runs")
        .join(format!("session-{}", session_id));

    let mat_strategy: Option<MaterializeStrategy> = match strategy.as_deref() {
        Some(s) => Some(s.parse().map_err(|e: String| anyhow::anyhow!("{}", e))?),
        None => None,
    };

    let ws = super::session_workspace::create_session_workspace(
        &layout,
        &session_dir,
        mat_strategy,
        None,
    )
    .await?;

    eprintln!("Session workspace: {}", ws.root.display());
    eprintln!("(exit shell to return to Kin)");

    // In native mode, use the shim layer but target the live session
    // workspace rather than `.kin/source-root/`. This preserves the
    // native command contract for interactive terminals while ensuring
    // discovery commands see live, unreconciled workspace edits.
    let shim_env =
        native_session_shim_env(&layout, &ws.root, restrict_discovery, restrict_filesystem)?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "bash".into());

    let status = std::process::Command::new(&shell)
        .current_dir(&ws.root)
        .env("KIN_SESSION", session_id.to_string())
        .env("KIN_SESSION_DIR", ws.root.to_string_lossy().as_ref())
        .envs(shim_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to launch shell '{}': {}", shell, e))?;

    let code = status.code().unwrap_or(1);
    eprintln!("\nShell exited (code {}).", code);

    match super::reconcile::reconcile_session_dir(&layout, &session_dir) {
        Ok(summary) => {
            if summary.change_count == 0 {
                eprintln!("No session changes detected.");
            } else {
                eprintln!(
                    "Reconciled session: {} changes, {} files indexed, {} entities upserted, {} entities removed.",
                    summary.change_count, summary.files_indexed, summary.total_upserted, summary.total_removed
                );
            }

            if let Err(e) = std::fs::remove_dir_all(&session_dir) {
                eprintln!(
                    "Warning: failed to clean up session workspace {}: {}",
                    session_dir.display(),
                    e
                );
            } else {
                eprintln!("Cleaned up session workspace.");
            }
        }
        Err(e) => {
            eprintln!("Warning: failed to reconcile session changes: {}", e);
            eprintln!("Session workspace kept at: {}", ws.root.display());
            eprintln!("To reconcile manually: kin reconcile {}", session_id);
            eprintln!("To clean up after that: rm -rf {}", session_dir.display());
        }
    }

    Ok(())
}

fn native_session_shim_env(
    layout: &kin_core::KinLayout,
    workspace_root: &std::path::Path,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<Vec<(String, String)>> {
    if kin_core::read_repo_mode(layout) != kin_core::RepoMode::Native {
        return Ok(vec![]);
    }

    let shim_dir = kin_core::shims::ensure_shim_dir(layout)?;
    let mut env = kin_core::shims::shim_env_for_root(&shim_dir, workspace_root);
    if restrict_filesystem {
        eprintln!("Native mode: filesystem discovery and direct file reads are restricted");
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
        env.push(("KIN_CONTENT_MODE".into(), "deny".into()));
    } else if restrict_discovery {
        eprintln!("Native mode: filesystem discovery commands are restricted");
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use kin_core::RepoMode;
    use kin_runtime::workspace::MaterializeStrategy;

    #[test]
    fn materialize_strategy_parses_copy() {
        let s: MaterializeStrategy = "copy".parse().unwrap();
        assert_eq!(s, MaterializeStrategy::Copy);
    }

    #[test]
    fn materialize_strategy_parses_reflink() {
        let s: MaterializeStrategy = "reflink".parse().unwrap();
        assert_eq!(s, MaterializeStrategy::Reflink);
    }

    #[test]
    fn materialize_strategy_parses_hardlink() {
        let s: MaterializeStrategy = "hardlink".parse().unwrap();
        assert_eq!(s, MaterializeStrategy::Hardlink);
    }

    #[test]
    fn materialize_strategy_rejects_invalid() {
        let result: Result<MaterializeStrategy, String> = "foobar".parse();
        assert!(result.is_err());
    }

    #[test]
    fn session_dir_has_expected_format() {
        let session_id = uuid::Uuid::new_v4();
        let session_name = format!("session-{}", session_id);
        assert!(session_name.starts_with("session-"));
        // UUID v4 has the form 8-4-4-4-12 = 36 chars
        assert_eq!(session_name.len(), "session-".len() + 36);
    }

    #[test]
    fn shell_env_vars_are_set_correctly() {
        // Validate that the env var names we use match expected conventions
        let session_id = uuid::Uuid::new_v4();
        let session_str = session_id.to_string();

        // KIN_SESSION should be a valid UUID string
        assert!(uuid::Uuid::parse_str(&session_str).is_ok());

        // Session dir path construction
        let root = std::path::Path::new("/tmp/test-repo");
        let session_dir = root.join("runs").join(format!("session-{}", session_id));
        assert!(session_dir
            .to_string_lossy()
            .contains(&session_id.to_string()));
    }

    #[test]
    fn native_session_shim_env_targets_workspace_and_can_deny_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let workspace_root = dir.path().join("runs/session-123");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        kin_core::write_repo_mode(&layout, RepoMode::Native).unwrap();

        let env = super::native_session_shim_env(&layout, &workspace_root, true, false).unwrap();
        assert!(
            env.iter()
                .any(|(k, v)| k == "KIN_SOURCE_ROOT"
                    && v == workspace_root.to_string_lossy().as_ref())
        );
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
    }

    #[test]
    fn native_session_shim_env_can_restrict_all_filesystem_access() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let workspace_root = dir.path().join("runs/session-123");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        kin_core::write_repo_mode(&layout, RepoMode::Native).unwrap();

        let env = super::native_session_shim_env(&layout, &workspace_root, false, true).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"));
    }
}
