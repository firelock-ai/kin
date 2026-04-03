// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;

/// `kin open <editor>` — Launch an editor in a materialized session workspace.
pub async fn run(
    editor: String,
    restrict_discovery: bool,
    restrict_filesystem: bool,
    wait: bool,
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

    let ws = super::session_workspace::create_session_workspace(&layout, &session_dir, None, None)
        .await?;

    println!("Session workspace: {}", ws.root.display());

    // In native mode, editors should inherit the same command contract as the
    // live session workspace. Integrated terminals and shell-outs should
    // resolve against the workspace root, not the empty control root.
    let shim_env =
        native_open_shim_env(&layout, &ws.root, restrict_discovery, restrict_filesystem)?;

    let (program, editor_args) = build_editor_command(&editor, wait);
    let mut command = std::process::Command::new(&program);
    command
        .args(&editor_args)
        .current_dir(&ws.root)
        .env("KIN_SESSION", session_id.to_string())
        .env("KIN_SESSION_DIR", ws.root.to_string_lossy().as_ref())
        .envs(shim_env.iter().map(|(k, v)| (k.as_str(), v.as_str())));

    if wait {
        let status = command
            .stdin(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .status();

        match status {
            Ok(status) => {
                println!("Editor exited (code {}).", status.code().unwrap_or(1));
                reconcile_and_cleanup(&layout, &session_dir).await?;
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to launch '{}': {}. Is it installed and on PATH?",
                    editor,
                    e
                ));
            }
        }
    } else {
        let status = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();

        match status {
            Ok(_child) => {
                println!("Launched '{}' in session workspace.", editor);
                println!(
                    "To reconcile and clean up when done: kin reconcile {} --cleanup",
                    session_id
                );
                println!(
                    "To clean up without reconciling: rm -rf {}",
                    session_dir.display()
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to launch '{}': {}. Is it installed and on PATH?",
                    editor,
                    e
                ));
            }
        }
    }

    Ok(())
}

fn build_editor_command(editor: &str, wait: bool) -> (String, Vec<String>) {
    let mut args = Vec::new();

    if wait && matches!(editor, "code" | "cursor") {
        args.push("--wait".to_string());
    }

    args.push(".".to_string());
    (editor.to_string(), args)
}

async fn reconcile_and_cleanup(
    layout: &kin_core::KinLayout,
    session_dir: &std::path::Path,
) -> Result<()> {
    super::session_closeout::finalize_open_session(layout, session_dir).await
}

fn native_open_shim_env(
    layout: &kin_core::KinLayout,
    workspace_root: &std::path::Path,
    restrict_discovery: bool,
    restrict_filesystem: bool,
) -> Result<Vec<(String, String)>> {
    let shim_dir = kin_core::shims::ensure_shim_dir(layout)?;
    let mut env = kin_core::shims::shim_env_for_root(&shim_dir, workspace_root);
    if restrict_filesystem {
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
        env.push(("KIN_CONTENT_MODE".into(), "deny".into()));
    } else if restrict_discovery {
        env.push(("KIN_DISCOVERY_MODE".into(), "deny".into()));
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    #[test]
    fn session_dir_is_under_runs() {
        let root = Path::new("/tmp/test-repo");
        let session_id = uuid::Uuid::new_v4();
        let session_dir = root.join("runs").join(format!("session-{}", session_id));

        assert!(session_dir.starts_with(root.join("runs")));
        assert!(session_dir
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("session-"));
    }

    #[test]
    fn session_ids_are_unique() {
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();
        assert_ne!(id1, id2);

        let dir1 = format!("session-{}", id1);
        let dir2 = format!("session-{}", id2);
        assert_ne!(dir1, dir2);
    }

    #[test]
    fn editor_arg_is_dot() {
        let (program, args) = super::build_editor_command("code", false);
        assert_eq!(program, "code");
        assert_eq!(args, vec![".".to_string()]);
    }

    #[test]
    fn code_and_cursor_wait_mode_use_editor_wait_flag() {
        let (_, code_args) = super::build_editor_command("code", true);
        let (_, cursor_args) = super::build_editor_command("cursor", true);
        assert_eq!(code_args, vec!["--wait".to_string(), ".".to_string()]);
        assert_eq!(cursor_args, vec!["--wait".to_string(), ".".to_string()]);
    }

    #[test]
    fn generic_editor_wait_mode_does_not_invent_flags() {
        let (_, args) = super::build_editor_command("vim", true);
        assert_eq!(args, vec![".".to_string()]);
    }

    #[test]
    fn native_open_shim_env_targets_workspace_and_can_deny_discovery() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let workspace_root = dir.path().join("runs/session-123");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

        let env = super::native_open_shim_env(&layout, &workspace_root, true, false).unwrap();
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
    fn native_open_shim_env_can_restrict_all_filesystem_access() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let workspace_root = dir.path().join("runs/session-123");
        std::fs::create_dir_all(&workspace_root).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        // No mode to set — there's one mode: Kin.

        let env = super::native_open_shim_env(&layout, &workspace_root, false, true).unwrap();
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_DISCOVERY_MODE" && v == "deny"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "KIN_CONTENT_MODE" && v == "deny"));
    }

    #[tokio::test]
    async fn reconcile_and_cleanup_fails_cleanly_for_missing_session() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("source-root")).unwrap();
        std::fs::create_dir_all(kin_dir.join("graph")).unwrap();
        std::fs::create_dir_all(kin_dir.join("blobs")).unwrap();
        std::fs::write(kin_dir.join("HEAD"), "main").unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let missing = dir.path().join("runs/session-missing");
        let err = super::reconcile_and_cleanup(&layout, &missing)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to reconcile session changes"));
        assert!(err.contains("session-missing"));
    }

    #[tokio::test]
    async fn reconcile_and_cleanup_preserves_workspace_when_copy_back_fails() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-copy-fail");

        std::fs::write(repo.path().join("src"), "blocking file").unwrap();
        std::fs::create_dir_all(session_dir.join("src")).unwrap();
        std::fs::write(
            session_dir.join("src/lib.rs"),
            "pub fn keep_me() -> &'static str { \"still here\" }\n",
        )
        .unwrap();

        let err = super::reconcile_and_cleanup(&layout, &session_dir)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to reconcile session changes"));
        assert!(err.contains(&session_dir.display().to_string()));
        assert!(
            session_dir.join("src/lib.rs").exists(),
            "cleanup should not remove the session workspace after reconcile failure",
        );
        assert_eq!(
            std::fs::read_to_string(repo.path().join("src")).unwrap(),
            "blocking file",
            "failed reconcile should leave the original source tree untouched",
        );
    }

    #[tokio::test]
    async fn reconcile_and_cleanup_preserves_workspace_when_semantic_reconcile_fails() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-broken-source");
        let source_file = repo.path().join("src/lib.rs");
        let original = "pub fn stable_source() -> &'static str { \"ok\" }\n";

        std::fs::create_dir_all(source_file.parent().unwrap()).unwrap();
        std::fs::write(&source_file, original).unwrap();
        std::fs::create_dir_all(session_dir.join("src")).unwrap();
        std::fs::write(session_dir.join("src/lib.rs"), "pub fn stable_source( {\n").unwrap();

        let err = super::reconcile_and_cleanup(&layout, &session_dir)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to reconcile session changes"));
        assert!(err.contains(&session_dir.display().to_string()));
        assert!(
            session_dir.join("src/lib.rs").exists(),
            "cleanup should not remove the session workspace after semantic reconcile failure",
        );
        assert_eq!(
            std::fs::read_to_string(&source_file).unwrap(),
            original,
            "failed semantic reconcile should restore the checked-out source file",
        );
    }

    #[tokio::test]
    async fn reconcile_and_cleanup_removes_workspace_after_successful_reconcile() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-success");
        let source_file = repo.path().join("src/lib.rs");
        let updated = "pub fn closeout_success() -> &'static str { \"ok\" }\n";

        std::fs::create_dir_all(session_dir.join("src")).unwrap();
        std::fs::write(session_dir.join("src/lib.rs"), updated).unwrap();

        super::reconcile_and_cleanup(&layout, &session_dir)
            .await
            .unwrap();

        assert!(
            !session_dir.exists(),
            "successful closeout should remove the session workspace"
        );
        assert_eq!(std::fs::read_to_string(&source_file).unwrap(), updated);
    }
}
