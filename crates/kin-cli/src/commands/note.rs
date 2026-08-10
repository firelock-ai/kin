// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
#[cfg(test)]
use kin_db::SnapshotManager;
use kin_model::*;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum NoteRequest {
    Add {
        target: String,
        kind: String,
        body: String,
    },
    List {
        target: String,
    },
    Stale,
    TodoImport {
        path: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteResponse {
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, Clone)]
pub struct NoteExecution {
    pub response: NoteResponse,
    pub mutated: bool,
}

async fn run_daemon_note(request: &NoteRequest) -> Result<NoteResponse> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(&layout).await?);
    let base_url = daemon_url
        .ok_or_else(|| crate::daemon_client::daemon_required_error("note commands", &layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.note(request).await.context("daemon note failed")
}

fn print_note_response(response: NoteResponse) {
    print!("{}", response.text);
}

/// `kin note add` — Add an annotation to a semantic scope or work item.
pub async fn add(target: String, kind: String, body: String) -> Result<()> {
    print_note_response(run_daemon_note(&NoteRequest::Add { target, kind, body }).await?);
    Ok(())
}

/// `kin note list` — List annotations for a semantic scope or work item.
pub async fn list(target: String) -> Result<()> {
    print_note_response(run_daemon_note(&NoteRequest::List { target }).await?);
    Ok(())
}

/// `kin note stale` — Show stale annotations.
pub async fn stale() -> Result<()> {
    print_note_response(run_daemon_note(&NoteRequest::Stale).await?);
    Ok(())
}

/// `kin todo import` — Import inline TODOs from source files.
pub async fn todo_import(path: Option<String>) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let scan_root = path
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| layout.working_dir().to_path_buf());
    println!("Scanning for inline TODOs in {}...", scan_root.display());
    print_note_response(run_daemon_note(&NoteRequest::TodoImport { path }).await?);
    Ok(())
}

// -- Helpers --

fn parse_annotation_target(target: &str) -> Result<AnnotationTarget> {
    if let Some(rest) = target.strip_prefix("work:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid work item UUID: {}", rest))?;
        Ok(AnnotationTarget::Work(WorkId(uuid)))
    } else {
        Ok(AnnotationTarget::Scope(
            crate::commands::work::parse_work_scope(target)?,
        ))
    }
}

#[cfg(test)]
fn open_snapshot(layout: &kin_core::KinLayout) -> Result<kin_db::SnapshotManager> {
    Ok(crate::backend::open_kindb_snapshot(layout)?)
}

fn build_annotation(
    graph: &kin_db::InMemoryGraph,
    target: &str,
    kind: String,
    body: String,
) -> Result<(Annotation, WorkLink)> {
    let ann_kind: AnnotationKind = kind.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let target = parse_annotation_target(target)?;
    let (scopes, anchored, attached_target) = match &target {
        AnnotationTarget::Scope(scope) => {
            let anchored = if let WorkScope::Entity(eid) = scope {
                graph.get_entity(eid)?.map(|e| SemanticAnchor {
                    ast_hash: e.fingerprint.ast_hash,
                    signature_hash: e.fingerprint.signature_hash,
                })
            } else {
                None
            };
            (vec![scope.clone()], anchored, target.clone())
        }
        AnnotationTarget::Work(work_id) => {
            let item = graph
                .get_work_item(work_id)?
                .ok_or_else(|| anyhow::anyhow!("work item not found: {}", work_id))?;
            (item.scopes, None, target.clone())
        }
    };

    let ann = Annotation {
        annotation_id: AnnotationId::new(),
        kind: ann_kind,
        body,
        scopes,
        anchored_fingerprint: anchored,
        authored_by: IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
        staleness: StalenessState::Fresh,
    };

    let link = WorkLink::AttachedTo {
        annotation_id: ann.annotation_id,
        target: attached_target,
    };

    Ok((ann, link))
}

fn annotation_body_preview(body: &str) -> String {
    let mut chars = body.chars();
    let preview: String = chars.by_ref().take(60).collect();
    if chars.next().is_some() {
        let shortened: String = body.chars().take(57).collect();
        format!("{shortened}...")
    } else {
        preview
    }
}

fn render_annotation_rows(
    annotations: &[Annotation],
    empty_message: String,
    state_label: &str,
) -> Result<String> {
    if annotations.is_empty() {
        return Ok(format!("{empty_message}\n"));
    }

    let mut out = String::new();
    writeln!(
        out,
        "{:<36}  {:<12}  {:<8}  BODY",
        "ID", "KIND", state_label
    )?;
    writeln!(out, "{}", "-".repeat(100))?;

    for ann in annotations {
        writeln!(
            out,
            "{:<36}  {:<12}  {:<8}  {}",
            ann.annotation_id,
            ann.kind,
            ann.staleness,
            annotation_body_preview(&ann.body),
        )?;
    }
    Ok(out)
}

pub fn execute_note_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: NoteRequest,
) -> Result<NoteExecution> {
    let mut mutated = false;
    let text = match request {
        NoteRequest::Add { target, kind, body } => {
            let (ann, link) = build_annotation(graph, &target, kind, body)?;
            graph.create_annotation(&ann)?;
            graph.create_work_link(&link)?;
            crate::provenance::record_cli_audit_event(
                graph,
                "note.add",
                ann.scopes.first().cloned(),
                Some(format!(
                    "annotation_id={}; kind={}",
                    ann.annotation_id, ann.kind
                )),
            )?;
            mutated = true;
            format!(
                "Added {} annotation ({}) to {}\n",
                ann.kind, ann.annotation_id, target
            )
        }
        NoteRequest::List { target } => {
            let annotations = match parse_annotation_target(&target)? {
                AnnotationTarget::Scope(scope) => graph.get_annotations_for_scope(&scope)?,
                AnnotationTarget::Work(work_id) => graph.get_annotations_for_work_item(&work_id)?,
            };
            let mut out = render_annotation_rows(
                &annotations,
                format!("No annotations for {}.", target),
                "STALE",
            )?;
            if !annotations.is_empty() {
                writeln!(out, "\n{} annotation(s)", annotations.len())?;
            }
            out
        }
        NoteRequest::Stale => {
            let filter = AnnotationFilter {
                include_stale: true,
                ..Default::default()
            };
            let all = graph.list_annotations(&filter)?;
            let stale_or_suspect: Vec<_> = all
                .into_iter()
                .filter(|a| matches!(a.staleness, StalenessState::Stale | StalenessState::Suspect))
                .collect();
            let mut out = render_annotation_rows(
                &stale_or_suspect,
                "No stale annotations found.".to_string(),
                "STATE",
            )?;
            if !stale_or_suspect.is_empty() {
                writeln!(
                    out,
                    "\n{} stale/suspect annotation(s)",
                    stale_or_suspect.len()
                )?;
            }
            out
        }
        NoteRequest::TodoImport { path } => {
            let execution = crate::commands::work::execute_work_request(
                layout,
                graph,
                crate::commands::work::WorkRequest::TodoImport { path },
            )?;
            mutated = execution.mutated;
            execution.response.text
        }
    };
    Ok(NoteExecution {
        response: NoteResponse { text },
        mutated,
    })
}

#[cfg(test)]
fn add_with_snapshot(
    snap: SnapshotManager,
    target: &str,
    kind: String,
    body: String,
) -> Result<Annotation> {
    let graph = snap.graph();
    let (ann, link) = build_annotation(graph.as_ref(), target, kind, body)?;
    graph.create_annotation(&ann)?;
    graph.create_work_link(&link)?;
    crate::provenance::record_cli_audit_event(
        graph.as_ref(),
        "note.add",
        ann.scopes.first().cloned(),
        Some(format!(
            "annotation_id={}; kind={}",
            ann.annotation_id, ann.kind
        )),
    )?;
    snap.save()?;
    drop(graph);
    drop(snap);

    Ok(ann)
}

#[cfg(test)]
fn add_in_layout(
    layout: &kin_core::KinLayout,
    target: &str,
    kind: String,
    body: String,
) -> Result<Annotation> {
    let snap = open_snapshot(layout)?;
    add_with_snapshot(snap, target, kind, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_annotation_persists_to_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let ann = add_in_layout(
            &layout,
            "file:src/main.rs",
            "instruction".into(),
            "never bypass semantic scopes".into(),
        )
        .unwrap();

        let snap = open_snapshot(&layout).unwrap();
        let graph = snap.graph();
        let stored = graph.get_annotation(&ann.annotation_id).unwrap().unwrap();
        assert_eq!(stored.kind, AnnotationKind::Instruction);
        assert_eq!(stored.body, "never bypass semantic scopes");
        let anns = graph
            .get_annotations_for_scope(&WorkScope::Artifact(FilePathId::new("src/main.rs")))
            .unwrap();
        assert_eq!(anns.len(), 1);

        let audit_events = graph.query_audit_events(None, 10).unwrap();
        assert_eq!(audit_events.len(), 1);
        assert_eq!(audit_events[0].action, "note.add");
    }

    #[tokio::test]
    async fn add_annotation_to_work_item_persists_target_link() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();

        let work = WorkItem {
            work_id: WorkId::new(),
            kind: WorkKind::Task,
            title: "capture semantic note".into(),
            description: String::new(),
            status: WorkStatus::Proposed,
            priority: Priority::None,
            scopes: vec![WorkScope::Artifact(FilePathId::new("src/lib.rs"))],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("test"),
            created_at: Timestamp::now(),
        };
        let snap = open_snapshot(&layout).unwrap();
        let graph = snap.graph();
        graph.create_work_item(&work).unwrap();
        snap.save().unwrap();
        drop(graph);
        drop(snap);

        let ann = add_in_layout(
            &layout,
            &format!("work:{}", work.work_id),
            "reasoning".into(),
            "This task remains blocked on hosted review semantics.".into(),
        )
        .unwrap();

        let snap = open_snapshot(&layout).unwrap();
        let graph = snap.graph();
        let anns = graph.get_annotations_for_work_item(&work.work_id).unwrap();
        assert_eq!(anns.len(), 1);
        assert_eq!(anns[0].annotation_id, ann.annotation_id);
        assert_eq!(anns[0].scopes, work.scopes);
    }
}
