use anyhow::Result;
use kin_model::*;

/// `kin note add` — Add an annotation to a scope.
pub async fn add(scope: String, kind: String, body: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let ann = add_in_layout(&layout, &scope, kind, body.clone())?;
    println!(
        "Added {} annotation ({}) to {}",
        ann.kind, ann.annotation_id, scope
    );
    Ok(())
}

/// `kin note list` — List annotations for a scope.
pub async fn list(scope: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();

    let ws = parse_scope(&scope)?;
    let annotations = graph.get_annotations_for_scope(&ws)?;

    if annotations.is_empty() {
        println!("No annotations for {}.", scope);
        return Ok(());
    }

    println!("{:<36}  {:<12}  {:<8}  {}", "ID", "KIND", "STALE", "BODY");
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
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
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

    println!("{:<36}  {:<12}  {:<8}  {}", "ID", "KIND", "STATE", "BODY");
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

    let (imported, skipped) = crate::commands::work::todo_import_in_layout(&layout, path)?;
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

fn parse_scope(s: &str) -> Result<WorkScope> {
    if let Some(rest) = s.strip_prefix("entity:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid entity UUID: {}", rest))?;
        Ok(WorkScope::Entity(EntityId(uuid)))
    } else if let Some(rest) = s.strip_prefix("contract:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| anyhow::anyhow!("invalid contract UUID: {}", rest))?;
        Ok(WorkScope::Contract(ContractId(uuid)))
    } else if let Some(rest) = s.strip_prefix("artifact:") {
        Ok(WorkScope::Artifact(FilePathId::new(rest)))
    } else if let Some(rest) = s.strip_prefix("file:") {
        Ok(WorkScope::Artifact(FilePathId::new(rest)))
    } else {
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            Ok(WorkScope::Entity(EntityId(uuid)))
        } else {
            Ok(WorkScope::Artifact(FilePathId::new(s)))
        }
    }
}

fn add_in_layout(
    layout: &kin_core::KinLayout,
    scope: &str,
    kind: String,
    body: String,
) -> Result<Annotation> {
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(layout))?;
    let graph = snap.graph();

    let ann_kind: AnnotationKind = kind.parse().map_err(|e: String| anyhow::anyhow!(e))?;
    let ws = parse_scope(scope)?;
    let anchored = if let WorkScope::Entity(eid) = &ws {
        graph.get_entity(eid)?.map(|e| SemanticAnchor {
            ast_hash: e.fingerprint.ast_hash,
            signature_hash: e.fingerprint.signature_hash,
        })
    } else {
        None
    };

    let ann = Annotation {
        annotation_id: AnnotationId::new(),
        kind: ann_kind,
        body,
        scopes: vec![ws.clone()],
        anchored_fingerprint: anchored,
        authored_by: IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
        staleness: StalenessState::Fresh,
    };

    graph.create_annotation(&ann)?;
    graph.create_work_link(&WorkLink::AttachedTo {
        annotation_id: ann.annotation_id,
        target: AnnotationTarget::Scope(ws),
    })?;
    snap.save()?;

    Ok(ann)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::GraphStore;

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

        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();
        let stored = graph.get_annotation(&ann.annotation_id).unwrap().unwrap();
        assert_eq!(stored.kind, AnnotationKind::Instruction);
        assert_eq!(stored.body, "never bypass semantic scopes");
        let anns = graph
            .get_annotations_for_scope(&WorkScope::Artifact(FilePathId::new("src/main.rs")))
            .unwrap();
        assert_eq!(anns.len(), 1);
    }
}
