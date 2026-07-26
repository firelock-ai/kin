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

    let repo_binding = super::session_process::VerifiedRepoBinding::resolve(&layout).await?;
    let ws = super::session_workspace::create_session_workspace(
        &repo_binding,
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
        native_session_shim_env(&layout, &ws.root, restrict_discovery, restrict_filesystem)
            .map_err(|error| {
                anyhow::anyhow!(
            "failed to prepare shell session environment: {error}. Session workspace kept at {}",
            session_dir.display()
        )
            })?;
    let process_binding =
        super::session_process::SessionProcessBinding::new(&repo_binding, session_id, &ws.root);
    process_binding.persist_context().map_err(|error| {
        anyhow::anyhow!(
            "failed to persist session context: {error}. Session workspace kept at {}",
            session_dir.display()
        )
    })?;

    let shell = std::env::var("SHELL").unwrap_or_else(|_| "bash".into());

    let mut command = std::process::Command::new(&shell);
    process_binding
        .configure_command(&mut command, shim_env.iter().map(|(k, v)| (k, v)))
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to bind shell process to session: {error}. Session workspace kept at {}",
                session_dir.display()
            )
        })?;
    let lease = repo_binding
        .register_session(session_id, &ws.root, "kin shell")
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to register session: {error}. Session workspace kept at {}",
                session_dir.display()
            )
        })?;
    let status = match command
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
    {
        Ok(status) => status,
        Err(error) => {
            let _ = lease.finish().await;
            return Err(anyhow::anyhow!(
                "failed to launch shell '{}': {}. Session workspace kept at {}",
                shell,
                error,
                session_dir.display()
            ));
        }
    };

    let code = status.code().unwrap_or(1);
    eprintln!("\nShell exited (code {}).", code);

    let close_result = close_session_after_shell(&repo_binding, &session_dir, code).await;
    let lease_result = lease.finish().await;

    if code != 0 {
        if let Err(error) = close_result {
            eprintln!("Kin: failed to report preserved session workspace: {error}");
        }
        if let Err(error) = lease_result {
            eprintln!("Kin: failed to end daemon session lease: {error}");
        }
        std::process::exit(code);
    }
    close_result?;
    lease_result?;
    Ok(())
}

async fn close_session_after_shell(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &std::path::Path,
    exit_code: i32,
) -> Result<()> {
    super::session_closeout::finalize_shell_session(binding, session_dir, exit_code).await
}

fn native_session_shim_env(
    layout: &kin_core::KinLayout,
    workspace_root: &std::path::Path,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<Vec<(String, String)>> {
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
    use crate::commands::session_closeout::finalize_shell_session_with_writer;
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
    fn native_session_shim_env_targets_workspace_and_can_deny_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let workspace_root = dir.path().join("runs/session-123");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

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
        // No mode to set — there's one mode: Kin.

        let env = super::native_session_shim_env(&layout, &workspace_root, false, true).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"));
    }

    #[tokio::test]
    async fn close_session_after_shell_warns_and_preserves_workspace_when_copy_back_fails() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-copy-fail");
        let mut stderr = Vec::new();

        std::fs::write(repo.path().join("src"), "blocking file").unwrap();
        std::fs::create_dir_all(session_dir.join("src")).unwrap();
        std::fs::write(
            session_dir.join("src/lib.rs"),
            "pub fn keep_me() -> &'static str { \"still here\" }\n",
        )
        .unwrap();

        finalize_shell_session_with_writer(
            &crate::commands::session_closeout::test_binding(&layout),
            &session_dir,
            0,
            &mut stderr,
        )
        .await
        .unwrap();

        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("Warning: failed to reconcile session changes"));
        assert!(output.contains("session-copy-fail"));
        assert!(
            session_dir.join("src/lib.rs").exists(),
            "warn-mode closeout should keep the session workspace on reconcile failure",
        );
        assert_eq!(
            std::fs::read_to_string(repo.path().join("src")).unwrap(),
            "blocking file",
            "warn-mode closeout should leave the original source tree untouched",
        );
    }

    #[tokio::test]
    async fn close_session_after_shell_warns_and_preserves_workspace_when_semantic_reconcile_fails()
    {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-broken-source");
        let source_file = repo.path().join("src/lib.rs");
        let original = "pub fn stable_source() -> &'static str { \"ok\" }\n";
        let mut stderr = Vec::new();

        std::fs::create_dir_all(source_file.parent().unwrap()).unwrap();
        std::fs::write(&source_file, original).unwrap();
        std::fs::create_dir_all(session_dir.join("src")).unwrap();
        std::fs::write(session_dir.join("src/lib.rs"), "pub fn stable_source( {\n").unwrap();

        finalize_shell_session_with_writer(
            &crate::commands::session_closeout::test_binding(&layout),
            &session_dir,
            0,
            &mut stderr,
        )
        .await
        .unwrap();

        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("Warning: failed to reconcile session changes"));
        assert!(output.contains("kin reconcile broken-source"));
        assert!(
            session_dir.join("src/lib.rs").exists(),
            "warn-mode closeout should keep the session workspace after semantic failure",
        );
        assert_eq!(
            std::fs::read_to_string(&source_file).unwrap(),
            original,
            "warn-mode closeout should preserve the checked-out source file",
        );
    }
}
