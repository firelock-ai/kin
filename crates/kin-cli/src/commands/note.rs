// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
#[cfg(test)]
use kin_db::SnapshotManager;
use kin_model::*;

/// `kin note add` — Add an annotation to a semantic scope or work item.
pub async fn add(target: String, kind: String, body: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let ann = add_in_layout_daemon_first(&layout, &target, kind, body.clone()).await?;
    println!(
        "Added {} annotation ({}) to {}",
        ann.kind, ann.annotation_id, target
    );
    Ok(())
}

/// `kin note list` — List annotations for a semantic scope or work item.
pub async fn list(target: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();

    let annotations = match parse_annotation_target(&target)? {
        AnnotationTarget::Scope(scope) => graph.get_annotations_for_scope(&scope)?,
        AnnotationTarget::Work(work_id) => graph.get_annotations_for_work_item(&work_id)?,
    };

    if annotations.is_empty() {
        println!("No annotations for {}.", target);
        return Ok(());
    }

    println!("{:<36}  {:<12}  {:<8}  BODY", "ID", "KIND", "STALE");
    println!("{}", "-".repeat(100));

    for ann in &annotations {
        let body_preview = if ann.body.len() > 60 {
            format!("{}...", &ann.body[..57])
        } else {
            ann.body.clone()
        };
        println!(
            "{:<36}  {:<12}  {:<8}  {}",
            ann.annotation_id, ann.kind, ann.staleness, body_preview,
        );
    }

    println!("\n{} annotation(s)", annotations.len());
    Ok(())
}

/// `kin note stale` — Show stale annotations.
pub async fn stale() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();

    let filter = AnnotationFilter {
        include_stale: true,
        ..Default::default()
    };
    let all = graph.list_annotations(&filter)?;
    let stale_or_suspect: Vec<_> = all
        .into_iter()
        .filter(|a| matches!(a.staleness, StalenessState::Stale | StalenessState::Suspect))
        .collect();

    if stale_or_suspect.is_empty() {
        println!("No stale annotations found.");
        return Ok(());
    }

    println!("{:<36}  {:<12}  {:<8}  BODY", "ID", "KIND", "STATE");
    println!("{}", "-".repeat(100));

    for ann in &stale_or_suspect {
        let body_preview = if ann.body.len() > 60 {
            format!("{}...", &ann.body[..57])
        } else {
            ann.body.clone()
        };
        println!(
            "{:<36}  {:<12}  {:<8}  {}",
            ann.annotation_id, ann.kind, ann.staleness, body_preview,
        );
    }

    println!("\n{} stale/suspect annotation(s)", stale_or_suspect.len());
    Ok(())
}

/// `kin todo import` — Import inline TODOs from source files.
pub async fn todo_import(path: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let scan_root = path
        .clone()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| kin_core::source_dir(&layout));
    println!("Scanning for inline TODOs in {}...", scan_root.display());

    let (imported, skipped) = crate::commands::work::todo_import_in_layout(&layout, path).await?;
    if imported == 0 && skipped == 0 {
        println!("No TODOs found.");
        return Ok(());
    }
    println!("Imported {} TODO(s) as work items.", imported);
    if skipped > 0 {
        println!("Skipped {} TODO(s) that were already imported.", skipped);
    }
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

async fn open_snapshot_daemon_first_read_only(
    layout: &kin_core::KinLayout,
) -> Result<kin_db::SnapshotManager> {
    Ok(crate::backend::open_snapshot_daemon_first_read_only(layout).await?)
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

async fn add_in_layout_daemon_first(
    layout: &kin_core::KinLayout,
    target: &str,
    kind: String,
    body: String,
) -> Result<Annotation> {
    let snap = open_snapshot_daemon_first_read_only(layout).await?;
    let graph = snap.graph();
    let (ann, link) = build_annotation(graph.as_ref(), target, kind, body)?;
    let mut batch = crate::backend::GraphMutationBatch::default();
    batch.annotations.push(ann.clone());
    batch.work_links.push(link);
    batch.audit_events.push(crate::backend::AuditMutation {
        action: "note.add".to_string(),
        target_scope: ann.scopes.first().cloned(),
        details: Some(format!(
            "annotation_id={}; kind={}",
            ann.annotation_id, ann.kind
        )),
    });
    crate::backend::require_daemon_graph_mutations(layout, batch).await?;
    Ok(ann)
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
