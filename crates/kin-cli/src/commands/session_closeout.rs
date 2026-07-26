// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::io::Write;
use std::path::Path;

use anyhow::Result;

#[derive(Clone, Copy, Debug)]
enum SessionCloseoutStyle {
    Open,
    Shell,
}

pub(crate) async fn finalize_open_session(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
    exit_code: i32,
) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    finalize_session(
        binding,
        session_dir,
        exit_code,
        &mut stdout,
        SessionCloseoutStyle::Open,
    )
    .await
}

pub(crate) async fn finalize_shell_session(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
    exit_code: i32,
) -> Result<()> {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    finalize_session(
        binding,
        session_dir,
        exit_code,
        &mut stderr,
        SessionCloseoutStyle::Shell,
    )
    .await
}

#[cfg(test)]
pub async fn finalize_open_session_with_writer<W: Write>(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    writer: &mut W,
) -> Result<()> {
    let binding = test_binding(layout);
    finalize_session(&binding, session_dir, 0, writer, SessionCloseoutStyle::Open).await
}

pub(crate) async fn finalize_shell_session_with_writer<W: Write>(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
    exit_code: i32,
    writer: &mut W,
) -> Result<()> {
    finalize_session(
        binding,
        session_dir,
        exit_code,
        writer,
        SessionCloseoutStyle::Shell,
    )
    .await
}

async fn finalize_session<W: Write>(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
    exit_code: i32,
    writer: &mut W,
    style: SessionCloseoutStyle,
) -> Result<()> {
    if exit_code != 0 {
        writeln!(
            writer,
            "{} exited unsuccessfully; session workspace kept at: {}",
            match style {
                SessionCloseoutStyle::Open => "Editor",
                SessionCloseoutStyle::Shell => "Shell",
            },
            session_dir.display()
        )?;
        writeln!(
            writer,
            "To reconcile its changes anyway: kin reconcile {} --cleanup",
            session_id_hint(session_dir)
        )?;
        return Ok(());
    }

    match super::reconcile::reconcile_session_dir_with_binding(binding, session_dir).await {
        Ok(summary) => {
            if summary.change_count == 0 {
                writeln!(writer, "No session changes detected.")?;
            } else {
                writeln!(
                    writer,
                    "Reconciled session: {} changes, {} files indexed, {} entities upserted, {} entities removed.",
                    summary.change_count,
                    summary.files_indexed,
                    summary.total_upserted,
                    summary.total_removed
                )?;
            }

            match std::fs::remove_dir_all(session_dir) {
                Ok(()) => {
                    writeln!(writer, "{}", cleanup_success_message(style, session_dir))?;
                    Ok(())
                }
                Err(e) => match style {
                    SessionCloseoutStyle::Open => Err(anyhow::anyhow!(
                        "reconciled successfully, but failed to clean up {}: {}",
                        session_dir.display(),
                        e
                    )),
                    SessionCloseoutStyle::Shell => {
                        writeln!(
                            writer,
                            "Warning: failed to clean up session workspace {}: {}",
                            session_dir.display(),
                            e
                        )?;
                        Ok(())
                    }
                },
            }
        }
        Err(e) => match style {
            SessionCloseoutStyle::Open => Err(anyhow::anyhow!(
                "failed to reconcile session changes: {}. Session workspace kept at: {}",
                e,
                session_dir.display()
            )),
            SessionCloseoutStyle::Shell => {
                writeln!(
                    writer,
                    "Warning: failed to reconcile session changes: {}",
                    e
                )?;
                writeln!(
                    writer,
                    "Session workspace kept at: {}",
                    session_dir.display()
                )?;
                writeln!(
                    writer,
                    "To reconcile manually: kin reconcile {}",
                    session_id_hint(session_dir)
                )?;
                writeln!(
                    writer,
                    "To clean up after that: rm -rf {}",
                    session_dir.display()
                )?;
                Ok(())
            }
        },
    }
}

#[cfg(test)]
pub(crate) fn test_binding(
    layout: &kin_core::KinLayout,
) -> super::session_process::VerifiedRepoBinding {
    super::session_process::VerifiedRepoBinding::for_test(
        layout.clone(),
        "http://127.0.0.1:9/test",
        "test-repo",
        None,
        std::env::var("PATH").unwrap_or_default(),
    )
}

fn cleanup_success_message(style: SessionCloseoutStyle, session_dir: &Path) -> String {
    match style {
        SessionCloseoutStyle::Open => {
            format!("Cleaned up session workspace: {}", session_dir.display())
        }
        SessionCloseoutStyle::Shell => "Cleaned up session workspace.".to_string(),
    }
}

fn session_id_hint(session_dir: &Path) -> String {
    session_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("session-"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| session_dir.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unsuccessful_shell_preserves_workspace_without_reconcile() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-failed");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("compose.yaml"), "services: {}\n").unwrap();
        let mut output = Vec::new();

        finalize_shell_session_with_writer(&test_binding(&layout), &session_dir, 23, &mut output)
            .await
            .unwrap();

        assert!(session_dir.join("compose.yaml").exists());
        assert!(!repo.path().join("compose.yaml").exists());
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("exited unsuccessfully"));
        assert!(output.contains("kin reconcile failed --cleanup"));
    }
}
