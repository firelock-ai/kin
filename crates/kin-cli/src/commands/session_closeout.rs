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

pub async fn finalize_open_session(layout: &kin_core::KinLayout, session_dir: &Path) -> Result<()> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    finalize_session(layout, session_dir, &mut stdout, SessionCloseoutStyle::Open).await
}

pub async fn finalize_shell_session(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
) -> Result<()> {
    let stderr = std::io::stderr();
    let mut stderr = stderr.lock();
    finalize_session(
        layout,
        session_dir,
        &mut stderr,
        SessionCloseoutStyle::Shell,
    )
    .await
}

#[cfg(test)]
pub fn finalize_open_session_with_writer<W: Write>(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    writer: &mut W,
) -> Result<()> {
    let rt = tokio::runtime::Handle::current();
    rt.block_on(finalize_session(
        layout,
        session_dir,
        writer,
        SessionCloseoutStyle::Open,
    ))
}

#[cfg(test)]
pub fn finalize_shell_session_with_writer<W: Write>(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    writer: &mut W,
) -> Result<()> {
    let rt = tokio::runtime::Handle::current();
    rt.block_on(finalize_session(
        layout,
        session_dir,
        writer,
        SessionCloseoutStyle::Shell,
    ))
}

async fn finalize_session<W: Write>(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    writer: &mut W,
    style: SessionCloseoutStyle,
) -> Result<()> {
    match super::reconcile::reconcile_session_dir(layout, session_dir).await {
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
