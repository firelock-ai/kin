use anyhow::Result;
use kin_model::*;

/// `kin note add` — Add an annotation to a scope.
pub async fn add(scope: String, kind: String, body: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let ann_kind: AnnotationKind = kind
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;
    let ws = parse_scope(&scope)?;

    // If scope is an entity, capture its current fingerprint for staleness tracking.
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
        body: body.clone(),
        scopes: vec![ws],
        anchored_fingerprint: anchored,
        authored_by: IdentityRef::human("cli-user"),
        created_at: Timestamp::now(),
        staleness: StalenessState::Fresh,
    };

    graph.create_annotation(&ann)?;
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
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let ws = parse_scope(&scope)?;
    let annotations = graph.get_annotations_for_scope(&ws)?;

    if annotations.is_empty() {
        println!("No annotations for {}.", scope);
        return Ok(());
    }

    println!(
        "{:<36}  {:<12}  {:<8}  {}",
        "ID", "KIND", "STALE", "BODY"
    );
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
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

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

    println!(
        "{:<36}  {:<12}  {:<8}  {}",
        "ID", "KIND", "STATE", "BODY"
    );
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
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let scan_root = path
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| layout.working_dir().to_path_buf());

    println!("Scanning for inline TODOs in {}...", scan_root.display());

    let todos = kin_parser::extract_todos(&scan_root)?;

    if todos.is_empty() {
        println!("No TODOs found.");
        return Ok(());
    }

    let mut imported = 0usize;
    for todo in &todos {
        let work_kind = match todo.kind.as_str() {
            "FIXME" => WorkKind::Issue,
            "HACK" => WorkKind::Debt,
            _ => WorkKind::Todo,
        };

        let item = WorkItem {
            work_id: WorkId::new(),
            kind: work_kind,
            title: todo.body.clone(),
            description: format!(
                "Imported from {} (line {})",
                todo.file_path, todo.line_number
            ),
            status: WorkStatus::Proposed,
            priority: if todo.kind == "FIXME" {
                Priority::High
            } else {
                Priority::Medium
            },
            scopes: vec![WorkScope::Artifact(FilePathId::new(&todo.file_path))],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: IdentityRef::human("kin-todo-import"),
            created_at: Timestamp::now(),
        };

        graph.create_work_item(&item)?;
        imported += 1;
    }

    println!("Imported {} TODO(s) as work items.", imported);
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
