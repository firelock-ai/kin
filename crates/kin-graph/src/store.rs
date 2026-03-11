use std::path::{Path, PathBuf};

use kuzu::{Connection, Database, SystemConfig, Value};
use tracing::debug;

use kin_model::branch::Branch;
use kin_model::change::SemanticChange;
use kin_model::entity::{
    Entity, EntityKind, EntityMetadata, SemanticFingerprint, SourceSpan, Visibility,
};
use kin_model::graph::{EntityFilter, GraphStore, SubGraph};
use kin_model::ids::*;
use kin_model::relation::{Relation, RelationKind, RelationOrigin};
use kin_model::review::RiskSummary;
use kin_model::session::{
    AgentSession, Intent, IntentScope, LockType, SessionCapabilities, SessionTransport,
};
use kin_model::timestamp::Timestamp;

use crate::error::{GraphError, Result};
use crate::queries;
use crate::schema;

/// KuzuDB-backed implementation of the `GraphStore` trait.
///
/// All Cypher queries are internal to this crate. External code
/// interacts exclusively through the `GraphStore` trait.
pub struct KuzuGraphStore {
    db: Database,
}

// Safety: kuzu::Database implements Send + Sync internally.
unsafe impl Send for KuzuGraphStore {}
unsafe impl Sync for KuzuGraphStore {}

impl KuzuGraphStore {
    /// Open or create a KuzuDB graph at the given path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::new(path, SystemConfig::default())?;
        let store = Self { db };
        store.with_conn(|conn| schema::init_schema(conn))?;
        Ok(store)
    }

    /// Create an in-memory graph store (useful for testing).
    pub fn in_memory() -> Result<Self> {
        let db = Database::in_memory(SystemConfig::default())?;
        let store = Self { db };
        store.with_conn(|conn| schema::init_schema(conn))?;
        Ok(store)
    }

    /// Execute a closure with a fresh connection.
    fn with_conn<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection<'_>) -> Result<T>,
    {
        let conn = Connection::new(&self.db)?;
        f(&conn)
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers: Entity <-> KuzuDB row
// ---------------------------------------------------------------------------

fn entity_from_row(row: &[Value]) -> Result<Entity> {
    // Row order matches the RETURN clause in queries.rs GET_ENTITY / LIST_ALL_ENTITIES:
    // id, kind, name, language, fingerprint_json, file_origin, span_json,
    // signature, visibility, doc_summary, metadata_json, lineage_parent,
    // created_in, superseded_by
    let id = EntityId(
        uuid::Uuid::parse_str(&val_string(&row[0])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let kind: EntityKind = serde_json::from_str(&format!("\"{}\"", val_string(&row[1])?))?;
    let name = val_string(&row[2])?;
    let language: LanguageId = serde_json::from_str(&format!("\"{}\"", val_string(&row[3])?))?;
    let fingerprint: SemanticFingerprint = serde_json::from_str(&val_string(&row[4])?)?;
    let file_origin = val_opt_string(&row[5])?.map(FilePathId::new);
    let span: Option<SourceSpan> = match val_opt_string(&row[6])? {
        Some(s) => Some(serde_json::from_str(&s)?),
        None => None,
    };
    let signature = val_string(&row[7])?;
    let visibility: Visibility = serde_json::from_str(&format!("\"{}\"", val_string(&row[8])?))?;
    let doc_summary = val_opt_string(&row[9])?;
    let metadata: EntityMetadata = match val_opt_string(&row[10])? {
        Some(s) => serde_json::from_str(&s)?,
        None => EntityMetadata::default(),
    };
    let lineage_parent =
        val_opt_string(&row[11])?.and_then(|s| uuid::Uuid::parse_str(&s).ok().map(EntityId));
    let created_in = val_opt_string(&row[12])?
        .and_then(|s| Hash256::from_hex(&s).ok().map(SemanticChangeId::from_hash));
    let superseded_by =
        val_opt_string(&row[13])?.and_then(|s| uuid::Uuid::parse_str(&s).ok().map(EntityId));

    Ok(Entity {
        id,
        kind,
        name,
        language,
        fingerprint,
        file_origin,
        span,
        signature,
        visibility,
        doc_summary,
        metadata,
        lineage_parent,
        created_in,
        superseded_by,
    })
}

fn entity_params(e: &Entity) -> Result<Vec<(&str, Value)>> {
    let kind_str = serde_json::to_string(&e.kind)?;
    let kind_str = kind_str.trim_matches('"').to_string();
    let language_str = serde_json::to_string(&e.language)?;
    let language_str = language_str.trim_matches('"').to_string();
    let fingerprint_json = serde_json::to_string(&e.fingerprint)?;
    let visibility_str = serde_json::to_string(&e.visibility)?;
    let visibility_str = visibility_str.trim_matches('"').to_string();

    Ok(vec![
        ("id", Value::String(e.id.to_string())),
        ("kind", Value::String(kind_str)),
        ("name", Value::String(e.name.clone())),
        ("language", Value::String(language_str)),
        ("fingerprint_json", Value::String(fingerprint_json)),
        (
            "file_origin",
            opt_string_val(e.file_origin.as_ref().map(|f| f.to_string())),
        ),
        (
            "span_json",
            opt_string_val(e.span.as_ref().map(|s| serde_json::to_string(s).unwrap())),
        ),
        ("signature", Value::String(e.signature.clone())),
        ("visibility", Value::String(visibility_str)),
        ("doc_summary", opt_string_val(e.doc_summary.clone())),
        (
            "metadata_json",
            Value::String(serde_json::to_string(&e.metadata)?),
        ),
        (
            "lineage_parent",
            opt_string_val(e.lineage_parent.map(|id| id.to_string())),
        ),
        (
            "created_in",
            opt_string_val(e.created_in.map(|id| id.to_string())),
        ),
        (
            "superseded_by",
            opt_string_val(e.superseded_by.map(|id| id.to_string())),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Conversion helpers: Relation <-> KuzuDB row
// ---------------------------------------------------------------------------

fn relation_from_row(row: &[Value]) -> Result<Relation> {
    // rel_id, kind, src_id, dst_id, confidence, origin, created_in
    let id = RelationId(
        uuid::Uuid::parse_str(&val_string(&row[0])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let kind: RelationKind = serde_json::from_str(&format!("\"{}\"", val_string(&row[1])?))?;
    let src = EntityId(
        uuid::Uuid::parse_str(&val_string(&row[2])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let dst = EntityId(
        uuid::Uuid::parse_str(&val_string(&row[3])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let confidence = val_float(&row[4])?;
    let origin: RelationOrigin = serde_json::from_str(&format!("\"{}\"", val_string(&row[5])?))?;
    let created_in = val_opt_string(&row[6])?
        .and_then(|s| Hash256::from_hex(&s).ok().map(SemanticChangeId::from_hash));

    Ok(Relation {
        id,
        kind,
        src,
        dst,
        confidence,
        origin,
        created_in,
    })
}

// ---------------------------------------------------------------------------
// Conversion helpers: SemanticChange <-> KuzuDB row
// ---------------------------------------------------------------------------

fn change_from_row(row: &[Value]) -> Result<SemanticChange> {
    // id, parents_json, timestamp, author, message,
    // entity_deltas_json, relation_deltas_json, artifact_deltas_json,
    // projected_files_json, spec_link, evidence_json,
    // risk_summary_json, authored_on
    let id_hex = val_string(&row[0])?;
    let id = SemanticChangeId::from_hash(
        Hash256::from_hex(&id_hex).map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let parents: Vec<SemanticChangeId> = serde_json::from_str(&val_string(&row[1])?)?;
    let ts_str = val_string(&row[2])?;
    let timestamp: Timestamp = serde_json::from_str(&format!("\"{}\"", ts_str))?;
    let author = AuthorId::new(val_string(&row[3])?);
    let message = val_string(&row[4])?;
    let entity_deltas = serde_json::from_str(&val_string(&row[5])?)?;
    let relation_deltas = serde_json::from_str(&val_string(&row[6])?)?;
    let artifact_deltas = serde_json::from_str(&val_string(&row[7])?)?;
    let projected_files = serde_json::from_str(&val_string(&row[8])?)?;
    let spec_link: Option<SpecId> = match val_opt_string(&row[9])? {
        Some(s) => serde_json::from_str(&format!("\"{}\"", s)).ok(),
        None => None,
    };
    let evidence: Vec<EvidenceId> = serde_json::from_str(&val_string(&row[10])?)?;
    let risk_summary: Option<RiskSummary> = match val_opt_string(&row[11])? {
        Some(s) => Some(serde_json::from_str(&s)?),
        None => None,
    };
    let authored_on = val_opt_string(&row[12])?.map(BranchName::new);

    Ok(SemanticChange {
        id,
        parents,
        timestamp,
        author,
        message,
        entity_deltas,
        relation_deltas,
        artifact_deltas,
        projected_files,
        spec_link,
        evidence,
        risk_summary,
        authored_on,
    })
}

fn change_params(c: &SemanticChange) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("id", Value::String(c.id.to_string())),
        (
            "parents_json",
            Value::String(serde_json::to_string(&c.parents)?),
        ),
        ("timestamp", Value::String(c.timestamp.to_string())),
        ("author", Value::String(c.author.to_string())),
        ("message", Value::String(c.message.clone())),
        (
            "entity_deltas_json",
            Value::String(serde_json::to_string(&c.entity_deltas)?),
        ),
        (
            "relation_deltas_json",
            Value::String(serde_json::to_string(&c.relation_deltas)?),
        ),
        (
            "artifact_deltas_json",
            Value::String(serde_json::to_string(&c.artifact_deltas)?),
        ),
        (
            "projected_files_json",
            Value::String(serde_json::to_string(&c.projected_files)?),
        ),
        (
            "spec_link",
            opt_string_val(c.spec_link.map(|id| id.to_string())),
        ),
        (
            "evidence_json",
            Value::String(serde_json::to_string(&c.evidence)?),
        ),
        (
            "risk_summary_json",
            opt_string_val(
                c.risk_summary
                    .as_ref()
                    .map(|r| serde_json::to_string(r).unwrap()),
            ),
        ),
        (
            "authored_on",
            opt_string_val(c.authored_on.as_ref().map(|b| b.to_string())),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Conversion helpers: AgentSession <-> KuzuDB row
// ---------------------------------------------------------------------------

fn session_from_row(row: &[Value]) -> Result<AgentSession> {
    // session_id, vendor, client_name, transport, pid, cwd,
    // started_at, last_heartbeat, capabilities_json
    let session_id = SessionId(
        uuid::Uuid::parse_str(&val_string(&row[0])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let vendor = val_string(&row[1])?;
    let client_name = val_string(&row[2])?;
    let transport: SessionTransport =
        serde_json::from_str(&format!("\"{}\"", val_string(&row[3])?))?;
    let pid: Option<u32> = val_opt_string(&row[4])?.and_then(|s| s.parse().ok());
    let cwd = PathBuf::from(val_string(&row[5])?);
    let started_at: Timestamp = serde_json::from_str(&format!("\"{}\"", val_string(&row[6])?))?;
    let last_heartbeat: Timestamp = serde_json::from_str(&format!("\"{}\"", val_string(&row[7])?))?;
    let capabilities: SessionCapabilities = match val_opt_string(&row[8])? {
        Some(s) => serde_json::from_str(&s)?,
        None => SessionCapabilities::default(),
    };

    Ok(AgentSession {
        session_id,
        vendor,
        client_name,
        transport,
        pid,
        cwd,
        started_at,
        last_heartbeat,
        capabilities,
    })
}

fn session_params(s: &AgentSession) -> Result<Vec<(&str, Value)>> {
    let transport_str = serde_json::to_string(&s.transport)?;
    let transport_str = transport_str.trim_matches('"').to_string();

    Ok(vec![
        ("session_id", Value::String(s.session_id.to_string())),
        ("vendor", Value::String(s.vendor.clone())),
        ("client_name", Value::String(s.client_name.clone())),
        ("transport", Value::String(transport_str)),
        ("pid", opt_string_val(s.pid.map(|p| p.to_string()))),
        ("cwd", Value::String(s.cwd.to_string_lossy().to_string())),
        ("started_at", Value::String(s.started_at.to_string())),
        (
            "last_heartbeat",
            Value::String(s.last_heartbeat.to_string()),
        ),
        (
            "capabilities_json",
            Value::String(serde_json::to_string(&s.capabilities)?),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Conversion helpers: Intent <-> KuzuDB row
// ---------------------------------------------------------------------------

fn intent_from_row(row: &[Value]) -> Result<Intent> {
    // intent_id, session_id, scopes_json, lock_type,
    // task_description, registered_at, expires_at
    let intent_id = IntentId(
        uuid::Uuid::parse_str(&val_string(&row[0])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let session_id = SessionId(
        uuid::Uuid::parse_str(&val_string(&row[1])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let scopes: Vec<IntentScope> = serde_json::from_str(&val_string(&row[2])?)?;
    let lock_type: LockType = serde_json::from_str(&format!("\"{}\"", val_string(&row[3])?))?;
    let task_description = val_string(&row[4])?;
    let registered_at: Timestamp = serde_json::from_str(&format!("\"{}\"", val_string(&row[5])?))?;
    let expires_at: Option<Timestamp> = match val_opt_string(&row[6])? {
        Some(s) => Some(serde_json::from_str(&format!("\"{}\"", s))?),
        None => None,
    };

    Ok(Intent {
        intent_id,
        session_id,
        scopes,
        lock_type,
        task_description,
        registered_at,
        expires_at,
    })
}

fn intent_params(i: &Intent) -> Result<Vec<(&str, Value)>> {
    let lock_type_str = serde_json::to_string(&i.lock_type)?;
    let lock_type_str = lock_type_str.trim_matches('"').to_string();

    Ok(vec![
        ("intent_id", Value::String(i.intent_id.to_string())),
        ("session_id", Value::String(i.session_id.to_string())),
        (
            "scopes_json",
            Value::String(serde_json::to_string(&i.scopes)?),
        ),
        ("lock_type", Value::String(lock_type_str)),
        (
            "task_description",
            Value::String(i.task_description.clone()),
        ),
        ("registered_at", Value::String(i.registered_at.to_string())),
        (
            "expires_at",
            opt_string_val(i.expires_at.as_ref().map(|t| t.to_string())),
        ),
    ])
}

// ---------------------------------------------------------------------------
// Value extraction helpers
// ---------------------------------------------------------------------------

fn val_string(v: &Value) -> Result<String> {
    match v {
        Value::String(s) => Ok(s.clone()),
        _ => Err(GraphError::Deserialization(format!(
            "Expected String, got {:?}",
            v
        ))),
    }
}

fn val_opt_string(v: &Value) -> Result<Option<String>> {
    match v {
        Value::Null(_) => Ok(None),
        Value::String(s) if s.is_empty() => Ok(None),
        Value::String(s) => Ok(Some(s.clone())),
        _ => Err(GraphError::Deserialization(format!(
            "Expected String or Null, got {:?}",
            v
        ))),
    }
}

fn val_float(v: &Value) -> Result<f32> {
    match v {
        Value::Float(f) => Ok(*f),
        Value::Double(d) => Ok(*d as f32),
        _ => Err(GraphError::Deserialization(format!(
            "Expected Float, got {:?}",
            v
        ))),
    }
}

fn opt_string_val(opt: Option<String>) -> Value {
    match opt {
        Some(s) => Value::String(s),
        None => Value::String(String::new()),
    }
}

// ---------------------------------------------------------------------------
// Conversion helpers: WorkItem <-> KuzuDB row
// ---------------------------------------------------------------------------

fn work_item_params(w: &kin_model::WorkItem) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("work_id", Value::String(w.work_id.to_string())),
        ("kind", Value::String(w.kind.to_string())),
        ("title", Value::String(w.title.clone())),
        ("description", Value::String(w.description.clone())),
        ("status", Value::String(w.status.to_string())),
        ("priority", Value::String(w.priority.to_string())),
        (
            "scopes_json",
            Value::String(serde_json::to_string(&w.scopes)?),
        ),
        (
            "acceptance_criteria_json",
            Value::String(serde_json::to_string(&w.acceptance_criteria)?),
        ),
        (
            "external_refs_json",
            Value::String(serde_json::to_string(&w.external_refs)?),
        ),
        (
            "created_by_json",
            Value::String(serde_json::to_string(&w.created_by)?),
        ),
        ("created_at", Value::String(w.created_at.to_string())),
    ])
}

fn work_item_from_row(row: &[Value]) -> Result<kin_model::WorkItem> {
    // work_id, kind, title, description, status, priority,
    // scopes_json, acceptance_criteria_json, external_refs_json,
    // created_by_json, created_at
    let work_id = kin_model::WorkId(
        uuid::Uuid::parse_str(&val_string(&row[0])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let kind: kin_model::WorkKind = val_string(&row[1])?
        .parse()
        .map_err(|e: String| GraphError::Deserialization(e))?;
    let title = val_string(&row[2])?;
    let description = val_string(&row[3])?;
    let status: kin_model::WorkStatus = val_string(&row[4])?
        .parse()
        .map_err(|e: String| GraphError::Deserialization(e))?;
    let priority: kin_model::Priority = val_string(&row[5])?
        .parse()
        .map_err(|e: String| GraphError::Deserialization(e))?;
    let scopes: Vec<kin_model::WorkScope> = serde_json::from_str(&val_string(&row[6])?)?;
    let acceptance_criteria: Vec<String> = serde_json::from_str(&val_string(&row[7])?)?;
    let external_refs: Vec<kin_model::ExternalRef> = serde_json::from_str(&val_string(&row[8])?)?;
    let created_by: kin_model::IdentityRef = serde_json::from_str(&val_string(&row[9])?)?;
    let created_at: Timestamp = serde_json::from_str(&format!("\"{}\"", val_string(&row[10])?))?;

    Ok(kin_model::WorkItem {
        work_id,
        kind,
        title,
        description,
        status,
        priority,
        scopes,
        acceptance_criteria,
        external_refs,
        created_by,
        created_at,
    })
}

// ---------------------------------------------------------------------------
// Conversion helpers: Annotation <-> KuzuDB row
// ---------------------------------------------------------------------------

fn annotation_params(a: &kin_model::Annotation) -> Result<Vec<(&str, Value)>> {
    let fingerprint_json = match &a.anchored_fingerprint {
        Some(fp) => serde_json::to_string(fp)?,
        None => String::new(),
    };

    Ok(vec![
        ("annotation_id", Value::String(a.annotation_id.to_string())),
        ("kind", Value::String(a.kind.to_string())),
        ("body", Value::String(a.body.clone())),
        (
            "scopes_json",
            Value::String(serde_json::to_string(&a.scopes)?),
        ),
        ("anchored_fingerprint_json", Value::String(fingerprint_json)),
        (
            "authored_by_json",
            Value::String(serde_json::to_string(&a.authored_by)?),
        ),
        ("created_at", Value::String(a.created_at.to_string())),
        ("staleness", Value::String(a.staleness.to_string())),
    ])
}

fn annotation_from_row(row: &[Value]) -> Result<kin_model::Annotation> {
    // annotation_id, kind, body, scopes_json,
    // anchored_fingerprint_json, authored_by_json, created_at, staleness
    let annotation_id = kin_model::AnnotationId(
        uuid::Uuid::parse_str(&val_string(&row[0])?)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let kind: kin_model::AnnotationKind = val_string(&row[1])?
        .parse()
        .map_err(|e: String| GraphError::Deserialization(e))?;
    let body = val_string(&row[2])?;
    let scopes: Vec<kin_model::WorkScope> = serde_json::from_str(&val_string(&row[3])?)?;
    let fp_str = val_string(&row[4])?;
    let anchored_fingerprint: Option<kin_model::SemanticAnchor> = if fp_str.is_empty() {
        None
    } else {
        Some(serde_json::from_str(&fp_str)?)
    };
    let authored_by: kin_model::IdentityRef = serde_json::from_str(&val_string(&row[5])?)?;
    let created_at: Timestamp = serde_json::from_str(&format!("\"{}\"", val_string(&row[6])?))?;
    let staleness_str = val_string(&row[7])?;
    let staleness = match staleness_str.as_str() {
        "fresh" => kin_model::StalenessState::Fresh,
        "suspect" => kin_model::StalenessState::Suspect,
        "stale" => kin_model::StalenessState::Stale,
        _ => kin_model::StalenessState::Fresh,
    };

    Ok(kin_model::Annotation {
        annotation_id,
        kind,
        body,
        scopes,
        anchored_fingerprint,
        authored_by,
        created_at,
        staleness,
    })
}

// ---------------------------------------------------------------------------
// Conversion helpers: TestCase <-> KuzuDB row (Phase 9)
// ---------------------------------------------------------------------------

fn test_case_params(t: &kin_model::verification::TestCase) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("test_id", Value::String(t.test_id.to_string())),
        ("name", Value::String(t.name.clone())),
        ("language", Value::String(t.language.clone())),
        ("kind", Value::String(t.kind.to_string())),
        (
            "scopes_json",
            Value::String(serde_json::to_string(&t.scopes)?),
        ),
        ("runner", Value::String(t.runner.to_string())),
        (
            "file_origin",
            opt_string_val(t.file_origin.as_ref().map(|f| f.to_string())),
        ),
    ])
}

fn test_case_from_row(row: &[Value]) -> Result<kin_model::verification::TestCase> {
    // test_id, name, language, kind, scopes_json, runner, file_origin
    let id_hex = val_string(&row[0])?;
    let test_id = kin_model::verification::TestId::from_hash(
        Hash256::from_hex(&id_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let name = val_string(&row[1])?;
    let language = val_string(&row[2])?;
    let kind_str = val_string(&row[3])?;
    let kind = match kind_str.as_str() {
        "unit" => kin_model::verification::TestKind::Unit,
        "integration" => kin_model::verification::TestKind::Integration,
        "contract" => kin_model::verification::TestKind::Contract,
        "property" => kin_model::verification::TestKind::Property,
        _ => kin_model::verification::TestKind::Unit,
    };
    let scopes: Vec<kin_model::WorkScope> = serde_json::from_str(&val_string(&row[4])?)?;
    let runner_str = val_string(&row[5])?;
    let runner = match runner_str.as_str() {
        "cargo" => kin_model::verification::TestRunner::Cargo,
        "jest" => kin_model::verification::TestRunner::Jest,
        "pytest" => kin_model::verification::TestRunner::Pytest,
        "go" => kin_model::verification::TestRunner::Go,
        "junit" => kin_model::verification::TestRunner::JUnit,
        other => kin_model::verification::TestRunner::Custom(other.to_string()),
    };
    let file_origin = val_opt_string(&row[6])?.map(FilePathId::new);

    Ok(kin_model::verification::TestCase {
        test_id,
        name,
        language,
        kind,
        scopes,
        runner,
        file_origin,
    })
}

fn assertion_v_params(a: &kin_model::verification::Assertion) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("assertion_id", Value::String(a.assertion_id.to_string())),
        ("summary", Value::String(a.summary.clone())),
        (
            "expected_behavior",
            Value::String(a.expected_behavior.clone()),
        ),
        (
            "target_scope_json",
            Value::String(serde_json::to_string(&a.target_scope)?),
        ),
    ])
}

fn assertion_from_row(row: &[Value]) -> Result<kin_model::verification::Assertion> {
    // assertion_id, summary, expected_behavior, target_scope_json
    let id_hex = val_string(&row[0])?;
    let assertion_id = kin_model::verification::AssertionId(
        Hash256::from_hex(&id_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let summary = val_string(&row[1])?;
    let expected_behavior = val_string(&row[2])?;
    let target_scope: kin_model::WorkScope = serde_json::from_str(&val_string(&row[3])?)?;

    Ok(kin_model::verification::Assertion {
        assertion_id,
        summary,
        expected_behavior,
        target_scope,
    })
}

// ---------------------------------------------------------------------------
// Conversion helpers: Provenance types <-> KuzuDB row (Phase 10)
// ---------------------------------------------------------------------------

fn actor_params(a: &kin_model::provenance::Actor) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("actor_id", Value::String(a.actor_id.to_string())),
        ("kind", Value::String(a.kind.to_string())),
        ("display_name", Value::String(a.display_name.clone())),
        (
            "external_refs_json",
            Value::String(serde_json::to_string(&a.external_refs)?),
        ),
    ])
}

fn actor_from_row(row: &[Value]) -> Result<kin_model::provenance::Actor> {
    // actor_id, kind, display_name, external_refs_json
    let id_hex = val_string(&row[0])?;
    let actor_id = kin_model::provenance::ActorId::from_hash(
        Hash256::from_hex(&id_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let kind_str = val_string(&row[1])?;
    let kind = match kind_str.as_str() {
        "human" => kin_model::provenance::ActorKind::Human,
        "assistant" => kin_model::provenance::ActorKind::Assistant,
        "service" => kin_model::provenance::ActorKind::Service,
        _ => kin_model::provenance::ActorKind::Human,
    };
    let display_name = val_string(&row[2])?;
    let external_refs: Vec<kin_model::ExternalRef> =
        serde_json::from_str(&val_string(&row[3])?)?;

    Ok(kin_model::provenance::Actor {
        actor_id,
        kind,
        display_name,
        external_refs,
    })
}

fn delegation_params(d: &kin_model::provenance::Delegation) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("delegation_id", Value::String(d.delegation_id.to_string())),
        ("principal", Value::String(d.principal.to_string())),
        ("delegate_actor", Value::String(d.delegate.to_string())),
        (
            "scope_json",
            Value::String(serde_json::to_string(&d.scope)?),
        ),
        ("started_at", Value::String(d.started_at.to_string())),
        (
            "ended_at",
            opt_string_val(d.ended_at.as_ref().map(|t| t.to_string())),
        ),
    ])
}

fn delegation_from_row(row: &[Value]) -> Result<kin_model::provenance::Delegation> {
    // delegation_id, principal, delegate_actor, scope_json, started_at, ended_at
    let id_hex = val_string(&row[0])?;
    let delegation_id = kin_model::provenance::DelegationId::from_hash(
        Hash256::from_hex(&id_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let principal_hex = val_string(&row[1])?;
    let principal = kin_model::provenance::ActorId::from_hash(
        Hash256::from_hex(&principal_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let delegate_hex = val_string(&row[2])?;
    let delegate = kin_model::provenance::ActorId::from_hash(
        Hash256::from_hex(&delegate_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let scope: Vec<kin_model::WorkScope> = serde_json::from_str(&val_string(&row[3])?)?;
    let started_at: Timestamp =
        serde_json::from_str(&format!("\"{}\"", val_string(&row[4])?))?;
    let ended_at: Option<Timestamp> = match val_opt_string(&row[5])? {
        Some(s) if !s.is_empty() => Some(serde_json::from_str(&format!("\"{}\"", s))?),
        _ => None,
    };

    Ok(kin_model::provenance::Delegation {
        delegation_id,
        principal,
        delegate,
        scope,
        started_at,
        ended_at,
    })
}

fn approval_params(a: &kin_model::provenance::Approval) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("approval_id", Value::String(a.approval_id.to_string())),
        ("change_id", Value::String(a.change_id.to_string())),
        ("approver", Value::String(a.approver.to_string())),
        ("decision", Value::String(a.decision.to_string())),
        ("reason", Value::String(a.reason.clone())),
        ("timestamp", Value::String(a.timestamp.to_string())),
    ])
}

fn approval_from_row(row: &[Value]) -> Result<kin_model::provenance::Approval> {
    // approval_id, change_id, approver, decision, reason, timestamp
    let id_hex = val_string(&row[0])?;
    let approval_id = kin_model::provenance::ApprovalId::from_hash(
        Hash256::from_hex(&id_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let change_hex = val_string(&row[1])?;
    let change_id = SemanticChangeId::from_hash(
        Hash256::from_hex(&change_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let approver_hex = val_string(&row[2])?;
    let approver = kin_model::provenance::ActorId::from_hash(
        Hash256::from_hex(&approver_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let decision_str = val_string(&row[3])?;
    let decision = match decision_str.as_str() {
        "approved" => kin_model::provenance::ApprovalDecision::Approved,
        "rejected" => kin_model::provenance::ApprovalDecision::Rejected,
        "conditional" => kin_model::provenance::ApprovalDecision::Conditional,
        _ => kin_model::provenance::ApprovalDecision::Approved,
    };
    let reason = val_string(&row[4])?;
    let timestamp: Timestamp =
        serde_json::from_str(&format!("\"{}\"", val_string(&row[5])?))?;

    Ok(kin_model::provenance::Approval {
        approval_id,
        change_id,
        approver,
        decision,
        reason,
        timestamp,
    })
}

fn audit_event_params(ev: &kin_model::provenance::AuditEvent) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("event_id", Value::String(ev.event_id.to_string())),
        ("actor_id", Value::String(ev.actor_id.to_string())),
        ("action", Value::String(ev.action.clone())),
        (
            "target_scope_json",
            opt_string_val(
                ev.target_scope
                    .as_ref()
                    .map(|s| serde_json::to_string(s).unwrap()),
            ),
        ),
        ("timestamp", Value::String(ev.timestamp.to_string())),
        ("details", opt_string_val(ev.details.clone())),
    ])
}

fn audit_event_from_row(row: &[Value]) -> Result<kin_model::provenance::AuditEvent> {
    // event_id, actor_id, action, target_scope_json, timestamp, details
    let id_hex = val_string(&row[0])?;
    let event_id = kin_model::provenance::AuditEventId::from_hash(
        Hash256::from_hex(&id_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let actor_hex = val_string(&row[1])?;
    let actor_id = kin_model::provenance::ActorId::from_hash(
        Hash256::from_hex(&actor_hex)
            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
    );
    let action = val_string(&row[2])?;
    let target_scope: Option<kin_model::WorkScope> = match val_opt_string(&row[3])? {
        Some(s) if !s.is_empty() => Some(serde_json::from_str(&s)?),
        _ => None,
    };
    let timestamp: Timestamp =
        serde_json::from_str(&format!("\"{}\"", val_string(&row[4])?))?;
    let details = val_opt_string(&row[5])?;

    Ok(kin_model::provenance::AuditEvent {
        event_id,
        actor_id,
        action,
        target_scope,
        timestamp,
        details,
    })
}

fn shallow_file_params(s: &kin_model::ShallowTrackedFile) -> Result<Vec<(&str, Value)>> {
    Ok(vec![
        ("file_id", Value::String(s.file_id.to_string())),
        ("language_hint", Value::String(s.language_hint.clone())),
        ("declaration_count", Value::Int64(s.declaration_count as i64)),
        ("import_count", Value::Int64(s.import_count as i64)),
        ("syntax_hash", Value::String(s.syntax_hash.to_string())),
        (
            "signature_hash",
            opt_string_val(s.signature_hash.map(|h| h.to_string())),
        ),
    ])
}

fn shallow_file_from_row(row: &[Value]) -> Result<kin_model::ShallowTrackedFile> {
    let file_id = FilePathId::new(val_string(&row[0])?);
    let language_hint = val_string(&row[1])?;
    let declaration_count = match &row[2] {
        Value::Int64(n) => *n as usize,
        other => {
            return Err(GraphError::Deserialization(format!(
                "Expected Int64 for declaration_count, got {:?}",
                other
            )))
        }
    };
    let import_count = match &row[3] {
        Value::Int64(n) => *n as usize,
        other => {
            return Err(GraphError::Deserialization(format!(
                "Expected Int64 for import_count, got {:?}",
                other
            )))
        }
    };
    let syntax_hash = Hash256::from_hex(&val_string(&row[4])?)
        .map_err(|e| GraphError::Deserialization(e.to_string()))?;
    let signature_hash = match val_opt_string(&row[5])? {
        Some(s) => Some(
            Hash256::from_hex(&s).map_err(|e| GraphError::Deserialization(e.to_string()))?,
        ),
        None => None,
    };

    Ok(kin_model::ShallowTrackedFile {
        file_id,
        language_hint,
        declaration_count,
        import_count,
        syntax_hash,
        signature_hash,
    })
}

// ---------------------------------------------------------------------------
// GraphStore implementation
// ---------------------------------------------------------------------------

impl GraphStore for KuzuGraphStore {
    type Error = GraphError;

    fn get_entity(&self, id: &EntityId) -> std::result::Result<Option<Entity>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_ENTITY)?;
            let mut result =
                conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            match result.next() {
                Some(row) => Ok(Some(entity_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn get_relations(
        &self,
        id: &EntityId,
        kinds: &[RelationKind],
    ) -> std::result::Result<Vec<Relation>, GraphError> {
        self.with_conn(|conn| {
            let mut all = Vec::new();
            for kind in kinds {
                let kind_str = serde_json::to_string(kind)?;
                let kind_str = kind_str.trim_matches('"').to_string();
                let mut stmt = conn.prepare(queries::GET_RELATIONS_BY_KIND)?;
                let result = conn.execute(
                    &mut stmt,
                    vec![
                        ("id", Value::String(id.to_string())),
                        ("kind", Value::String(kind_str)),
                    ],
                )?;
                for row in result {
                    all.push(relation_from_row(&row)?);
                }
            }
            Ok(all)
        })
    }

    fn get_all_relations_for_entity(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<Relation>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_RELATIONS_FOR_ENTITY)?;
            let result = conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            let mut rels = Vec::new();
            for row in result {
                rels.push(relation_from_row(&row)?);
            }
            Ok(rels)
        })
    }

    fn get_downstream_impact(
        &self,
        id: &EntityId,
        _max_depth: u32,
    ) -> std::result::Result<Vec<Entity>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DOWNSTREAM_IMPACT)?;
            let result = conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            let mut entities = Vec::new();
            for row in result {
                entities.push(entity_from_row(&row)?);
            }
            Ok(entities)
        })
    }

    fn get_dependency_neighborhood(
        &self,
        id: &EntityId,
        _depth: u32,
    ) -> std::result::Result<SubGraph, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DEPENDENCY_NEIGHBORHOOD)?;
            let result = conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            let mut subgraph = SubGraph::default();
            for row in result {
                let entity = entity_from_row(&row)?;
                subgraph.entities.insert(entity.id, entity);
            }
            // Also fetch relations for all entities in the subgraph.
            let entity_ids: Vec<EntityId> = subgraph.entities.keys().copied().collect();
            for eid in &entity_ids {
                let mut rstmt = conn.prepare(queries::GET_RELATIONS_FOR_ENTITY)?;
                let rresult =
                    conn.execute(&mut rstmt, vec![("id", Value::String(eid.to_string()))])?;
                for rrow in rresult {
                    let rel = relation_from_row(&rrow)?;
                    subgraph.relations.push(rel);
                }
            }
            Ok(subgraph)
        })
    }

    fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::DEAD_CODE)?;
            let mut entities = Vec::new();
            for row in result {
                entities.push(entity_from_row(&row)?);
            }
            Ok(entities)
        })
    }

    fn get_entity_history(
        &self,
        id: &EntityId,
    ) -> std::result::Result<Vec<SemanticChange>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::ENTITY_HISTORY)?;
            let result = conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            let mut changes = Vec::new();
            for row in result {
                changes.push(change_from_row(&row)?);
            }
            Ok(changes)
        })
    }

    fn find_merge_bases(
        &self,
        a: &SemanticChangeId,
        b: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChangeId>, GraphError> {
        // Walk ancestors of both a and b to find common ancestors.
        // V1 strategy: BFS ancestors of each, return intersection.
        self.with_conn(|conn| {
            let ancestors_a = collect_ancestors(conn, a)?;
            let ancestors_b = collect_ancestors(conn, b)?;
            let common: Vec<SemanticChangeId> = ancestors_a
                .into_iter()
                .filter(|id| ancestors_b.contains(id))
                .collect();
            Ok(common)
        })
    }

    fn query_entities(
        &self,
        filter: &EntityFilter,
    ) -> std::result::Result<Vec<Entity>, GraphError> {
        self.with_conn(|conn| {
            // Use the most specific filter available.
            if let Some(ref file_path) = filter.file_path {
                let mut stmt = conn.prepare(queries::QUERY_ENTITIES_BY_FILE)?;
                let result = conn.execute(
                    &mut stmt,
                    vec![("file_path", Value::String(file_path.to_string()))],
                )?;
                let mut entities = Vec::new();
                for row in result {
                    let entity = entity_from_row(&row)?;
                    if matches_filter(&entity, filter) {
                        entities.push(entity);
                    }
                }
                return Ok(entities);
            }

            if let Some(ref name_pattern) = filter.name_pattern {
                let mut stmt = conn.prepare(queries::QUERY_ENTITIES_BY_NAME)?;
                let result = conn.execute(
                    &mut stmt,
                    vec![("name_pattern", Value::String(name_pattern.clone()))],
                )?;
                let mut entities = Vec::new();
                for row in result {
                    let entity = entity_from_row(&row)?;
                    if matches_filter(&entity, filter) {
                        entities.push(entity);
                    }
                }
                return Ok(entities);
            }

            if let Some(ref kinds) = filter.kinds {
                if kinds.len() == 1 {
                    let kind_str = serde_json::to_string(&kinds[0])?;
                    let kind_str = kind_str.trim_matches('"').to_string();
                    let mut stmt = conn.prepare(queries::QUERY_ENTITIES_BY_KIND)?;
                    let result =
                        conn.execute(&mut stmt, vec![("kind", Value::String(kind_str))])?;
                    let mut entities = Vec::new();
                    for row in result {
                        let entity = entity_from_row(&row)?;
                        if matches_filter(&entity, filter) {
                            entities.push(entity);
                        }
                    }
                    return Ok(entities);
                }
            }

            // Fallback: list all and filter in Rust.
            let result = conn.query(queries::LIST_ALL_ENTITIES)?;
            let mut entities = Vec::new();
            for row in result {
                let entity = entity_from_row(&row)?;
                if matches_filter(&entity, filter) {
                    entities.push(entity);
                }
            }
            Ok(entities)
        })
    }

    fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_ALL_ENTITIES)?;
            let mut entities = Vec::new();
            for row in result {
                entities.push(entity_from_row(&row)?);
            }
            Ok(entities)
        })
    }

    fn upsert_entity(&self, entity: &Entity) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = entity_params(entity)?;
            let mut stmt = conn.prepare(queries::UPSERT_ENTITY)?;
            conn.execute(&mut stmt, params)?;
            debug!(entity_id = %entity.id, "upserted entity");
            Ok(())
        })
    }

    fn upsert_relation(&self, relation: &Relation) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let kind_str = serde_json::to_string(&relation.kind)?;
            let kind_str = kind_str.trim_matches('"').to_string();
            let origin_str = serde_json::to_string(&relation.origin)?;
            let origin_str = origin_str.trim_matches('"').to_string();

            let params = vec![
                ("src", Value::String(relation.src.to_string())),
                ("dst", Value::String(relation.dst.to_string())),
                ("rel_id", Value::String(relation.id.to_string())),
                ("kind", Value::String(kind_str)),
                ("confidence", Value::Float(relation.confidence)),
                ("origin", Value::String(origin_str)),
                (
                    "created_in",
                    opt_string_val(relation.created_in.map(|id| id.to_string())),
                ),
            ];
            let mut stmt = conn.prepare(queries::UPSERT_RELATION)?;
            conn.execute(&mut stmt, params)?;
            debug!(relation_id = %relation.id, "upserted relation");
            Ok(())
        })
    }

    fn remove_entity(&self, id: &EntityId) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_ENTITY)?;
            conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            Ok(())
        })
    }

    fn remove_relation(&self, id: &RelationId) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_RELATION)?;
            conn.execute(&mut stmt, vec![("rel_id", Value::String(id.to_string()))])?;
            Ok(())
        })
    }

    fn create_change(&self, change: &SemanticChange) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = change_params(change)?;
            let mut stmt = conn.prepare(queries::CREATE_CHANGE)?;
            conn.execute(&mut stmt, params)?;

            // Create PARENT_OF edges.
            for parent in &change.parents {
                let mut pstmt = conn.prepare(queries::CREATE_PARENT_EDGE)?;
                conn.execute(
                    &mut pstmt,
                    vec![
                        ("child_id", Value::String(change.id.to_string())),
                        ("parent_id", Value::String(parent.to_string())),
                    ],
                )?;
            }

            // Create MODIFIES edges for each entity delta.
            for delta in &change.entity_deltas {
                let entity_id = match delta {
                    kin_model::change::EntityDelta::Added(e) => e.id,
                    kin_model::change::EntityDelta::Modified { new, .. } => new.id,
                    kin_model::change::EntityDelta::Removed(id) => *id,
                };
                // Only create edge if entity node exists.
                if let Some(_) = self.get_entity(&entity_id)? {
                    let mut mstmt = conn.prepare(queries::CREATE_MODIFIES_EDGE)?;
                    conn.execute(
                        &mut mstmt,
                        vec![
                            ("change_id", Value::String(change.id.to_string())),
                            ("entity_id", Value::String(entity_id.to_string())),
                        ],
                    )?;
                }
            }

            debug!(change_id = %change.id, "created semantic change");
            Ok(())
        })
    }

    fn get_change(
        &self,
        id: &SemanticChangeId,
    ) -> std::result::Result<Option<SemanticChange>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_CHANGE)?;
            let mut result =
                conn.execute(&mut stmt, vec![("id", Value::String(id.to_string()))])?;
            match result.next() {
                Some(row) => Ok(Some(change_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn get_changes_since(
        &self,
        base: &SemanticChangeId,
        head: &SemanticChangeId,
    ) -> std::result::Result<Vec<SemanticChange>, GraphError> {
        // Walk backwards from head via parents until we reach base.
        self.with_conn(|conn| {
            let mut result = Vec::new();
            let mut queue = vec![*head];
            let mut visited = std::collections::HashSet::new();

            while let Some(current) = queue.pop() {
                if current == *base || !visited.insert(current) {
                    continue;
                }
                let mut stmt = conn.prepare(queries::GET_CHANGE)?;
                let mut qr =
                    conn.execute(&mut stmt, vec![("id", Value::String(current.to_string()))])?;
                if let Some(row) = qr.next() {
                    let change = change_from_row(&row)?;
                    for parent in &change.parents {
                        queue.push(*parent);
                    }
                    result.push(change);
                }
            }

            // Reverse to get chronological order.
            result.reverse();
            Ok(result)
        })
    }

    fn get_branch(&self, name: &BranchName) -> std::result::Result<Option<Branch>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_BRANCH)?;
            let mut result =
                conn.execute(&mut stmt, vec![("name", Value::String(name.to_string()))])?;
            match result.next() {
                Some(row) => {
                    let name = BranchName::new(val_string(&row[0])?);
                    let head_hex = val_string(&row[1])?;
                    let head = SemanticChangeId::from_hash(
                        Hash256::from_hex(&head_hex)
                            .map_err(|e| GraphError::Deserialization(e.to_string()))?,
                    );
                    Ok(Some(Branch { name, head }))
                }
                None => Ok(None),
            }
        })
    }

    fn create_branch(&self, branch: &Branch) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::CREATE_BRANCH)?;
            conn.execute(
                &mut stmt,
                vec![
                    ("name", Value::String(branch.name.to_string())),
                    ("head", Value::String(branch.head.to_string())),
                ],
            )?;
            debug!(branch_name = %branch.name, "created branch");
            Ok(())
        })
    }

    fn update_branch_head(
        &self,
        name: &BranchName,
        new_head: &SemanticChangeId,
    ) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::UPDATE_BRANCH_HEAD)?;
            conn.execute(
                &mut stmt,
                vec![
                    ("name", Value::String(name.to_string())),
                    ("head", Value::String(new_head.to_string())),
                ],
            )?;
            Ok(())
        })
    }

    fn delete_branch(&self, name: &BranchName) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_BRANCH)?;
            conn.execute(&mut stmt, vec![("name", Value::String(name.to_string()))])?;
            Ok(())
        })
    }

    fn list_branches(&self) -> std::result::Result<Vec<Branch>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_BRANCHES)?;
            let mut branches = Vec::new();
            for row in result {
                let name = BranchName::new(val_string(&row[0])?);
                let head_hex = val_string(&row[1])?;
                let head = SemanticChangeId::from_hash(
                    Hash256::from_hex(&head_hex)
                        .map_err(|e| GraphError::Deserialization(e.to_string()))?,
                );
                branches.push(Branch { name, head });
            }
            Ok(branches)
        })
    }

    // -----------------------------------------------------------------------
    // Phase 8: Work graph operations
    // -----------------------------------------------------------------------

    fn create_work_item(&self, item: &kin_model::WorkItem) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = work_item_params(item)?;
            let mut stmt = conn.prepare(queries::UPSERT_WORK_ITEM)?;
            conn.execute(&mut stmt, params)?;

            // Create AFFECTS edges for entity scopes.
            for scope in &item.scopes {
                if let kin_model::WorkScope::Entity(eid) = scope {
                    let mut stmt2 = conn.prepare(queries::CREATE_AFFECTS_EDGE)?;
                    conn.execute(
                        &mut stmt2,
                        vec![
                            ("work_id", Value::String(item.work_id.to_string())),
                            ("entity_id", Value::String(eid.to_string())),
                            ("scope_kind", Value::String("entity".to_string())),
                        ],
                    )?;
                }
            }
            debug!(work_id = %item.work_id, kind = %item.kind, "created work item");
            Ok(())
        })
    }

    fn get_work_item(
        &self,
        id: &kin_model::WorkId,
    ) -> std::result::Result<Option<kin_model::WorkItem>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_WORK_ITEM)?;
            let mut result =
                conn.execute(&mut stmt, vec![("work_id", Value::String(id.to_string()))])?;
            match result.next() {
                Some(row) => Ok(Some(work_item_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn list_work_items(
        &self,
        filter: &kin_model::WorkFilter,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_ALL_WORK_ITEMS)?;
            let mut items = Vec::new();
            for row in result {
                let item = work_item_from_row(&row)?;
                // Apply in-memory filtering.
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&item.kind) {
                        continue;
                    }
                }
                if let Some(ref statuses) = filter.statuses {
                    if !statuses.contains(&item.status) {
                        continue;
                    }
                }
                if let Some(ref scope) = filter.scope {
                    if !item.scopes.contains(scope) {
                        continue;
                    }
                }
                items.push(item);
            }
            Ok(items)
        })
    }

    fn update_work_status(
        &self,
        id: &kin_model::WorkId,
        status: kin_model::WorkStatus,
    ) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::UPDATE_WORK_STATUS)?;
            conn.execute(
                &mut stmt,
                vec![
                    ("work_id", Value::String(id.to_string())),
                    ("status", Value::String(status.to_string())),
                ],
            )?;
            Ok(())
        })
    }

    fn delete_work_item(&self, id: &kin_model::WorkId) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_WORK_ITEM)?;
            conn.execute(&mut stmt, vec![("work_id", Value::String(id.to_string()))])?;
            Ok(())
        })
    }

    fn create_annotation(
        &self,
        ann: &kin_model::Annotation,
    ) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = annotation_params(ann)?;
            let mut stmt = conn.prepare(queries::UPSERT_ANNOTATION)?;
            conn.execute(&mut stmt, params)?;

            // Create ATTACHED_TO edges for scopes.
            for scope in &ann.scopes {
                match scope {
                    kin_model::WorkScope::Entity(eid) => {
                        let mut stmt2 = conn.prepare(queries::CREATE_ATTACHED_TO_ENTITY_EDGE)?;
                        conn.execute(
                            &mut stmt2,
                            vec![
                                (
                                    "annotation_id",
                                    Value::String(ann.annotation_id.to_string()),
                                ),
                                ("entity_id", Value::String(eid.to_string())),
                            ],
                        )?;
                    }
                    _ => {
                        // Non-entity scopes stored in JSON only (no separate edge table yet).
                    }
                }
            }
            debug!(annotation_id = %ann.annotation_id, kind = %ann.kind, "created annotation");
            Ok(())
        })
    }

    fn get_annotation(
        &self,
        id: &kin_model::AnnotationId,
    ) -> std::result::Result<Option<kin_model::Annotation>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_ANNOTATION)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("annotation_id", Value::String(id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(annotation_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn list_annotations(
        &self,
        filter: &kin_model::AnnotationFilter,
    ) -> std::result::Result<Vec<kin_model::Annotation>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_ALL_ANNOTATIONS)?;
            let mut annotations = Vec::new();
            for row in result {
                let ann = annotation_from_row(&row)?;
                if let Some(ref kinds) = filter.kinds {
                    if !kinds.contains(&ann.kind) {
                        continue;
                    }
                }
                if !filter.include_stale && ann.staleness == kin_model::StalenessState::Stale {
                    continue;
                }
                if let Some(ref scopes) = filter.scopes {
                    if !ann.scopes.iter().any(|s| scopes.contains(s)) {
                        continue;
                    }
                }
                annotations.push(ann);
            }
            Ok(annotations)
        })
    }

    fn update_annotation_staleness(
        &self,
        id: &kin_model::AnnotationId,
        staleness: kin_model::StalenessState,
    ) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::UPDATE_ANNOTATION_STALENESS)?;
            conn.execute(
                &mut stmt,
                vec![
                    ("annotation_id", Value::String(id.to_string())),
                    ("staleness", Value::String(staleness.to_string())),
                ],
            )?;
            Ok(())
        })
    }

    fn delete_annotation(
        &self,
        id: &kin_model::AnnotationId,
    ) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_ANNOTATION)?;
            conn.execute(
                &mut stmt,
                vec![("annotation_id", Value::String(id.to_string()))],
            )?;
            Ok(())
        })
    }

    fn create_work_link(&self, link: &kin_model::WorkLink) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            match link {
                kin_model::WorkLink::Affects { work_id, scope } => {
                    if let kin_model::WorkScope::Entity(eid) = scope {
                        let mut stmt = conn.prepare(queries::CREATE_AFFECTS_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("work_id", Value::String(work_id.to_string())),
                                ("entity_id", Value::String(eid.to_string())),
                                ("scope_kind", Value::String("entity".to_string())),
                            ],
                        )?;
                    }
                }
                kin_model::WorkLink::DecomposesTo { parent, child } => {
                    let mut stmt = conn.prepare(queries::CREATE_DECOMPOSES_TO_EDGE)?;
                    conn.execute(
                        &mut stmt,
                        vec![
                            ("parent_id", Value::String(parent.to_string())),
                            ("child_id", Value::String(child.to_string())),
                        ],
                    )?;
                }
                kin_model::WorkLink::BlockedBy { blocked, blocker } => {
                    let mut stmt = conn.prepare(queries::CREATE_BLOCKED_BY_EDGE)?;
                    conn.execute(
                        &mut stmt,
                        vec![
                            ("blocked_id", Value::String(blocked.to_string())),
                            ("blocker_id", Value::String(blocker.to_string())),
                        ],
                    )?;
                }
                kin_model::WorkLink::Implements { scope, work_id } => {
                    if let kin_model::WorkScope::Entity(eid) = scope {
                        let mut stmt = conn.prepare(queries::CREATE_IMPLEMENTS_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("entity_id", Value::String(eid.to_string())),
                                ("work_id", Value::String(work_id.to_string())),
                                ("scope_kind", Value::String("entity".to_string())),
                            ],
                        )?;
                    }
                }
                kin_model::WorkLink::AttachedTo {
                    annotation_id,
                    target,
                } => match target {
                    kin_model::AnnotationTarget::Scope(kin_model::WorkScope::Entity(eid)) => {
                        let mut stmt = conn.prepare(queries::CREATE_ATTACHED_TO_ENTITY_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("annotation_id", Value::String(annotation_id.to_string())),
                                ("entity_id", Value::String(eid.to_string())),
                            ],
                        )?;
                    }
                    kin_model::AnnotationTarget::Work(wid) => {
                        let mut stmt = conn.prepare(queries::CREATE_ATTACHED_TO_WORK_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("annotation_id", Value::String(annotation_id.to_string())),
                                ("work_id", Value::String(wid.to_string())),
                            ],
                        )?;
                    }
                    _ => {}
                },
                kin_model::WorkLink::Supersedes { new_id, old_id } => {
                    let mut stmt = conn.prepare(queries::CREATE_SUPERSEDES_EDGE)?;
                    conn.execute(
                        &mut stmt,
                        vec![
                            ("new_id", Value::String(new_id.to_string())),
                            ("old_id", Value::String(old_id.to_string())),
                        ],
                    )?;
                }
            }
            Ok(())
        })
    }

    fn delete_work_link(&self, link: &kin_model::WorkLink) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            match link {
                kin_model::WorkLink::Affects { work_id, scope } => {
                    if let kin_model::WorkScope::Entity(eid) = scope {
                        let mut stmt = conn.prepare(queries::DELETE_AFFECTS_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("work_id", Value::String(work_id.to_string())),
                                ("entity_id", Value::String(eid.to_string())),
                            ],
                        )?;
                    }
                }
                kin_model::WorkLink::DecomposesTo { parent, child } => {
                    let mut stmt = conn.prepare(queries::DELETE_DECOMPOSES_TO_EDGE)?;
                    conn.execute(
                        &mut stmt,
                        vec![
                            ("parent_id", Value::String(parent.to_string())),
                            ("child_id", Value::String(child.to_string())),
                        ],
                    )?;
                }
                kin_model::WorkLink::BlockedBy { blocked, blocker } => {
                    let mut stmt = conn.prepare(queries::DELETE_BLOCKED_BY_EDGE)?;
                    conn.execute(
                        &mut stmt,
                        vec![
                            ("blocked_id", Value::String(blocked.to_string())),
                            ("blocker_id", Value::String(blocker.to_string())),
                        ],
                    )?;
                }
                kin_model::WorkLink::Implements { scope, work_id } => {
                    if let kin_model::WorkScope::Entity(eid) = scope {
                        let mut stmt = conn.prepare(queries::DELETE_IMPLEMENTS_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("entity_id", Value::String(eid.to_string())),
                                ("work_id", Value::String(work_id.to_string())),
                            ],
                        )?;
                    }
                }
                kin_model::WorkLink::AttachedTo {
                    annotation_id,
                    target,
                } => match target {
                    kin_model::AnnotationTarget::Scope(kin_model::WorkScope::Entity(eid)) => {
                        let mut stmt = conn.prepare(queries::DELETE_ATTACHED_TO_ENTITY_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("annotation_id", Value::String(annotation_id.to_string())),
                                ("entity_id", Value::String(eid.to_string())),
                            ],
                        )?;
                    }
                    kin_model::AnnotationTarget::Work(wid) => {
                        let mut stmt = conn.prepare(queries::DELETE_ATTACHED_TO_WORK_EDGE)?;
                        conn.execute(
                            &mut stmt,
                            vec![
                                ("annotation_id", Value::String(annotation_id.to_string())),
                                ("work_id", Value::String(wid.to_string())),
                            ],
                        )?;
                    }
                    _ => {}
                },
                kin_model::WorkLink::Supersedes { new_id, old_id } => {
                    let mut stmt = conn.prepare(queries::DELETE_SUPERSEDES_EDGE)?;
                    conn.execute(
                        &mut stmt,
                        vec![
                            ("new_id", Value::String(new_id.to_string())),
                            ("old_id", Value::String(old_id.to_string())),
                        ],
                    )?;
                }
            }
            Ok(())
        })
    }

    fn get_work_for_scope(
        &self,
        scope: &kin_model::WorkScope,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, GraphError> {
        match scope {
            kin_model::WorkScope::Entity(eid) => self.with_conn(|conn| {
                let mut stmt = conn.prepare(queries::WORK_FOR_ENTITY)?;
                let result = conn.execute(
                    &mut stmt,
                    vec![("entity_id", Value::String(eid.to_string()))],
                )?;
                let mut items = Vec::new();
                for row in result {
                    items.push(work_item_from_row(&row)?);
                }
                Ok(items)
            }),
            // Non-entity scopes fall back to in-memory filter over all items.
            other => {
                let filter = kin_model::WorkFilter {
                    scope: Some(other.clone()),
                    ..Default::default()
                };
                self.list_work_items(&filter)
            }
        }
    }

    fn get_annotations_for_scope(
        &self,
        scope: &kin_model::WorkScope,
    ) -> std::result::Result<Vec<kin_model::Annotation>, GraphError> {
        match scope {
            kin_model::WorkScope::Entity(eid) => self.with_conn(|conn| {
                let mut stmt = conn.prepare(queries::ANNOTATIONS_FOR_ENTITY)?;
                let result = conn.execute(
                    &mut stmt,
                    vec![("entity_id", Value::String(eid.to_string()))],
                )?;
                let mut annotations = Vec::new();
                for row in result {
                    annotations.push(annotation_from_row(&row)?);
                }
                Ok(annotations)
            }),
            other => {
                let filter = kin_model::AnnotationFilter {
                    scopes: Some(vec![other.clone()]),
                    include_stale: true,
                    ..Default::default()
                };
                self.list_annotations(&filter)
            }
        }
    }

    fn get_child_work_items(
        &self,
        parent: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkItem>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::CHILD_WORK_ITEMS)?;
            let result = conn.execute(
                &mut stmt,
                vec![("parent_id", Value::String(parent.to_string()))],
            )?;
            let mut items = Vec::new();
            for row in result {
                items.push(work_item_from_row(&row)?);
            }
            Ok(items)
        })
    }

    fn get_implementors(
        &self,
        work_id: &kin_model::WorkId,
    ) -> std::result::Result<Vec<kin_model::WorkScope>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::IMPLEMENTORS_FOR_WORK)?;
            let result = conn.execute(
                &mut stmt,
                vec![("work_id", Value::String(work_id.to_string()))],
            )?;
            let mut scopes = Vec::new();
            for row in result {
                let id_str = val_string(&row[0])?;
                let eid = EntityId(
                    uuid::Uuid::parse_str(&id_str)
                        .map_err(|e| GraphError::Deserialization(e.to_string()))?,
                );
                scopes.push(kin_model::WorkScope::Entity(eid));
            }
            Ok(scopes)
        })
    }

    // -----------------------------------------------------------------------
    // Phase 9: Verification graph operations
    // -----------------------------------------------------------------------

    fn create_test_case(&self, test: &kin_model::verification::TestCase) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = test_case_params(test)?;
            let mut stmt = conn.prepare(queries::CREATE_TEST_CASE)?;
            conn.execute(&mut stmt, params)?;

            // Create TESTS_ENTITY edges for entity scopes.
            for scope in &test.scopes {
                if let kin_model::WorkScope::Entity(eid) = scope {
                    if self.get_entity(eid)?.is_some() {
                        let mut edge_stmt = conn.prepare(queries::CREATE_TESTS_ENTITY_EDGE)?;
                        conn.execute(
                            &mut edge_stmt,
                            vec![
                                ("test_id", Value::String(test.test_id.to_string())),
                                ("entity_id", Value::String(eid.to_string())),
                                ("scope_kind", Value::String("entity".to_string())),
                            ],
                        )?;
                    }
                }
            }
            debug!(test_id = %test.test_id, name = %test.name, "created test case");
            Ok(())
        })
    }

    fn get_test_case(&self, id: &kin_model::verification::TestId) -> std::result::Result<Option<kin_model::verification::TestCase>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_TEST_CASE)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("test_id", Value::String(id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(test_case_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn get_tests_for_entity(&self, id: &EntityId) -> std::result::Result<Vec<kin_model::verification::TestCase>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::TESTS_FOR_ENTITY)?;
            let result = conn.execute(
                &mut stmt,
                vec![("entity_id", Value::String(id.to_string()))],
            )?;
            let mut tests = Vec::new();
            for row in result {
                tests.push(test_case_from_row(&row)?);
            }
            Ok(tests)
        })
    }

    fn delete_test_case(&self, id: &kin_model::verification::TestId) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_TEST_CASE)?;
            conn.execute(
                &mut stmt,
                vec![("test_id", Value::String(id.to_string()))],
            )?;
            debug!(test_id = %id, "deleted test case");
            Ok(())
        })
    }

    fn create_assertion(&self, assertion: &kin_model::verification::Assertion) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = assertion_v_params(assertion)?;
            let mut stmt = conn.prepare(queries::CREATE_ASSERTION)?;
            conn.execute(&mut stmt, params)?;
            debug!(assertion_id = %assertion.assertion_id, "created assertion");
            Ok(())
        })
    }

    fn get_assertion(&self, id: &kin_model::verification::AssertionId) -> std::result::Result<Option<kin_model::verification::Assertion>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_ASSERTION)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("assertion_id", Value::String(id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(assertion_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn get_coverage_summary(&self) -> std::result::Result<kin_model::verification::CoverageSummary, GraphError> {
        self.with_conn(|conn| {
            // Count total entities.
            let total_result = conn.query(queries::LIST_ALL_ENTITIES)?;
            let mut total_entities = 0usize;
            let mut all_entity_ids = Vec::new();
            for row in total_result {
                total_entities += 1;
                if let Ok(id_str) = val_string(&row[0]) {
                    if let Ok(uuid) = uuid::Uuid::parse_str(&id_str) {
                        all_entity_ids.push(EntityId(uuid));
                    }
                }
            }

            // Count entities with at least one test.
            let covered_result = conn.query(queries::COVERED_ENTITY_COUNT)?;
            let mut covered_entities = 0usize;
            for row in covered_result {
                if let Value::Int64(n) = &row[0] {
                    covered_entities = *n as usize;
                }
            }

            let coverage_ratio = if total_entities == 0 {
                0.0
            } else {
                covered_entities as f64 / total_entities as f64
            };

            // Collect entity IDs that lack any test coverage.
            let mut covered_set = std::collections::HashSet::new();
            let all_tests = conn.query(queries::ALL_TEST_CASES)?;
            for row in all_tests {
                if let Ok(tc) = test_case_from_row(&row) {
                    for scope in &tc.scopes {
                        if let kin_model::WorkScope::Entity(eid) = scope {
                            covered_set.insert(*eid);
                        }
                    }
                }
            }
            let missing_proof: Vec<EntityId> = all_entity_ids
                .into_iter()
                .filter(|id| !covered_set.contains(id))
                .collect();

            Ok(kin_model::verification::CoverageSummary {
                total_entities,
                covered_entities,
                coverage_ratio,
                missing_proof,
            })
        })
    }

    // -----------------------------------------------------------------------
    // Phase 10: Provenance operations
    // -----------------------------------------------------------------------

    fn create_actor(&self, actor: &kin_model::provenance::Actor) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = actor_params(actor)?;
            let mut stmt = conn.prepare(queries::CREATE_ACTOR)?;
            conn.execute(&mut stmt, params)?;
            debug!(actor_id = %actor.actor_id, kind = %actor.kind, "created actor");
            Ok(())
        })
    }

    fn get_actor(&self, id: &kin_model::provenance::ActorId) -> std::result::Result<Option<kin_model::provenance::Actor>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_ACTOR)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("actor_id", Value::String(id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(actor_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    fn list_actors(&self) -> std::result::Result<Vec<kin_model::provenance::Actor>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_ACTORS)?;
            let mut actors = Vec::new();
            for row in result {
                actors.push(actor_from_row(&row)?);
            }
            Ok(actors)
        })
    }

    fn create_delegation(&self, delegation: &kin_model::provenance::Delegation) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = delegation_params(delegation)?;
            let mut stmt = conn.prepare(queries::CREATE_DELEGATION)?;
            conn.execute(&mut stmt, params)?;
            debug!(delegation_id = %delegation.delegation_id, "created delegation");
            Ok(())
        })
    }

    fn get_delegations_for_actor(&self, id: &kin_model::provenance::ActorId) -> std::result::Result<Vec<kin_model::provenance::Delegation>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELEGATIONS_FOR_ACTOR)?;
            let result = conn.execute(
                &mut stmt,
                vec![("actor_id", Value::String(id.to_string()))],
            )?;
            let mut delegations = Vec::new();
            for row in result {
                delegations.push(delegation_from_row(&row)?);
            }
            Ok(delegations)
        })
    }

    fn create_approval(&self, approval: &kin_model::provenance::Approval) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = approval_params(approval)?;
            let mut stmt = conn.prepare(queries::CREATE_APPROVAL)?;
            conn.execute(&mut stmt, params)?;
            debug!(approval_id = %approval.approval_id, "created approval");
            Ok(())
        })
    }

    fn get_approvals_for_change(&self, id: &SemanticChangeId) -> std::result::Result<Vec<kin_model::provenance::Approval>, GraphError> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::APPROVALS_FOR_CHANGE)?;
            let result = conn.execute(
                &mut stmt,
                vec![("change_id", Value::String(id.to_string()))],
            )?;
            let mut approvals = Vec::new();
            for row in result {
                approvals.push(approval_from_row(&row)?);
            }
            Ok(approvals)
        })
    }

    fn record_audit_event(&self, event: &kin_model::provenance::AuditEvent) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = audit_event_params(event)?;
            let mut stmt = conn.prepare(queries::CREATE_AUDIT_EVENT)?;
            conn.execute(&mut stmt, params)?;
            debug!(event_id = %event.event_id, action = %event.action, "recorded audit event");
            Ok(())
        })
    }

    fn query_audit_events(&self, actor_id: Option<&kin_model::provenance::ActorId>, limit: usize) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, GraphError> {
        self.with_conn(|conn| {
            let mut events = Vec::new();
            match actor_id {
                Some(aid) => {
                    let mut stmt = conn.prepare(queries::QUERY_AUDIT_EVENTS_BY_ACTOR)?;
                    let result = conn.execute(
                        &mut stmt,
                        vec![
                            ("actor_id", Value::String(aid.to_string())),
                            ("limit", Value::Int64(limit as i64)),
                        ],
                    )?;
                    for row in result {
                        events.push(audit_event_from_row(&row)?);
                    }
                }
                None => {
                    let mut stmt = conn.prepare(queries::QUERY_AUDIT_EVENTS_ALL)?;
                    let result = conn.execute(
                        &mut stmt,
                        vec![("limit", Value::Int64(limit as i64))],
                    )?;
                    for row in result {
                        events.push(audit_event_from_row(&row)?);
                    }
                }
            }
            Ok(events)
        })
    }

    fn upsert_shallow_file(&self, shallow: &kin_model::ShallowTrackedFile) -> std::result::Result<(), GraphError> {
        self.with_conn(|conn| {
            let params = shallow_file_params(shallow)?;
            let mut stmt = conn.prepare(queries::UPSERT_SHALLOW_FILE)?;
            conn.execute(&mut stmt, params)?;
            debug!(file_id = %shallow.file_id, "upserted shallow tracked file");
            Ok(())
        })
    }

    fn list_shallow_files(&self) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, GraphError> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_SHALLOW_FILES)?;
            let mut files = Vec::new();
            for row in result {
                files.push(shallow_file_from_row(&row)?);
            }
            Ok(files)
        })
    }
}

// ---------------------------------------------------------------------------
// Transient session/intent operations (Phase 7)
// ---------------------------------------------------------------------------

impl KuzuGraphStore {
    /// Upsert an agent session into the graph.
    pub fn upsert_session(&self, session: &AgentSession) -> Result<()> {
        self.with_conn(|conn| {
            let params = session_params(session)?;
            let mut stmt = conn.prepare(queries::UPSERT_SESSION)?;
            conn.execute(&mut stmt, params)?;
            debug!(session_id = %session.session_id, "upserted agent session");
            Ok(())
        })
    }

    /// Get an agent session by ID.
    pub fn get_session(&self, session_id: &SessionId) -> Result<Option<AgentSession>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_SESSION)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("session_id", Value::String(session_id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(session_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    /// Delete an agent session and all its owned intents.
    pub fn delete_session(&self, session_id: &SessionId) -> Result<()> {
        self.with_conn(|conn| {
            // First delete all intents owned by this session (cascading cleanup).
            let mut stmt = conn.prepare(queries::DELETE_INTENTS_FOR_SESSION)?;
            conn.execute(
                &mut stmt,
                vec![("session_id", Value::String(session_id.to_string()))],
            )?;

            // Then delete the session itself.
            let mut stmt = conn.prepare(queries::DELETE_SESSION)?;
            conn.execute(
                &mut stmt,
                vec![("session_id", Value::String(session_id.to_string()))],
            )?;
            debug!(session_id = %session_id, "deleted agent session");
            Ok(())
        })
    }

    /// List all active sessions.
    pub fn list_sessions(&self) -> Result<Vec<AgentSession>> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_SESSIONS)?;
            let mut sessions = Vec::new();
            for row in result {
                sessions.push(session_from_row(&row)?);
            }
            Ok(sessions)
        })
    }

    /// Update only the heartbeat timestamp for a session.
    pub fn update_heartbeat(&self, session_id: &SessionId, heartbeat: &Timestamp) -> Result<()> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::UPDATE_HEARTBEAT)?;
            conn.execute(
                &mut stmt,
                vec![
                    ("session_id", Value::String(session_id.to_string())),
                    ("last_heartbeat", Value::String(heartbeat.to_string())),
                ],
            )?;
            Ok(())
        })
    }

    /// Register an intent and create ownership/lock edges.
    ///
    /// This creates the Intent node, OWNS_INTENT edge from the session,
    /// and LOCKS edges for each scope that maps to a known Entity.
    pub fn register_intent(&self, intent: &Intent) -> Result<()> {
        self.with_conn(|conn| {
            // Create the Intent node.
            let params = intent_params(intent)?;
            let mut stmt = conn.prepare(queries::CREATE_INTENT)?;
            conn.execute(&mut stmt, params)?;

            // Create OWNS_INTENT edge.
            let mut own_stmt = conn.prepare(queries::CREATE_OWNS_INTENT_EDGE)?;
            conn.execute(
                &mut own_stmt,
                vec![
                    ("session_id", Value::String(intent.session_id.to_string())),
                    ("intent_id", Value::String(intent.intent_id.to_string())),
                ],
            )?;

            // Create LOCKS edges for each scope that targets an Entity.
            let lock_type_str = serde_json::to_string(&intent.lock_type)?;
            let lock_type_str = lock_type_str.trim_matches('"').to_string();
            for scope in &intent.scopes {
                let (entity_id_str, scope_kind) = match scope {
                    IntentScope::Entity(eid) => (eid.to_string(), "Entity"),
                    IntentScope::Contract(cid) => (cid.to_string(), "Contract"),
                    IntentScope::Artifact(fid) => (fid.to_string(), "Artifact"),
                };
                // Only create edge if the entity exists in the graph.
                let check_id = EntityId(uuid::Uuid::parse_str(&entity_id_str)
                    .unwrap_or_else(|_| uuid::Uuid::nil()));
                if scope_kind == "Entity" {
                    if let Some(_) = self.get_entity(&check_id)? {
                        let mut lock_stmt = conn.prepare(queries::CREATE_LOCK_EDGE)?;
                        conn.execute(
                            &mut lock_stmt,
                            vec![
                                ("intent_id", Value::String(intent.intent_id.to_string())),
                                ("entity_id", Value::String(entity_id_str)),
                                ("lock_type", Value::String(lock_type_str.clone())),
                                ("scope_kind", Value::String(scope_kind.to_string())),
                            ],
                        )?;
                    }
                }
            }

            debug!(intent_id = %intent.intent_id, session_id = %intent.session_id, "registered intent");
            Ok(())
        })
    }

    /// Get an intent by ID.
    pub fn get_intent(&self, intent_id: &IntentId) -> Result<Option<Intent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_INTENT)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("intent_id", Value::String(intent_id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(intent_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    /// Delete an intent and all its LOCKS/WARNS_DOWNSTREAM edges.
    pub fn delete_intent(&self, intent_id: &IntentId) -> Result<()> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_INTENT)?;
            conn.execute(
                &mut stmt,
                vec![("intent_id", Value::String(intent_id.to_string()))],
            )?;
            debug!(intent_id = %intent_id, "deleted intent");
            Ok(())
        })
    }

    /// List all intents owned by a session.
    pub fn list_intents_for_session(&self, session_id: &SessionId) -> Result<Vec<Intent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::LIST_INTENTS_FOR_SESSION)?;
            let result = conn.execute(
                &mut stmt,
                vec![("session_id", Value::String(session_id.to_string()))],
            )?;
            let mut intents = Vec::new();
            for row in result {
                intents.push(intent_from_row(&row)?);
            }
            Ok(intents)
        })
    }

    /// List all intents in the graph.
    pub fn list_all_intents(&self) -> Result<Vec<Intent>> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_ALL_INTENTS)?;
            let mut intents = Vec::new();
            for row in result {
                intents.push(intent_from_row(&row)?);
            }
            Ok(intents)
        })
    }

    /// Check for hard lock collisions on an entity (excluding the given intent).
    pub fn hard_collisions_for_entity(
        &self,
        entity_id: &EntityId,
        exclude_intent: &IntentId,
    ) -> Result<Vec<Intent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::HARD_COLLISIONS_FOR_ENTITY)?;
            let result = conn.execute(
                &mut stmt,
                vec![
                    ("entity_id", Value::String(entity_id.to_string())),
                    (
                        "exclude_intent_id",
                        Value::String(exclude_intent.to_string()),
                    ),
                ],
            )?;
            let mut intents = Vec::new();
            for row in result {
                intents.push(intent_from_row(&row)?);
            }
            Ok(intents)
        })
    }

    /// Find all intents that lock a given entity.
    pub fn locks_for_entity(&self, entity_id: &EntityId) -> Result<Vec<Intent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::LOCKS_FOR_ENTITY)?;
            let result = conn.execute(
                &mut stmt,
                vec![("entity_id", Value::String(entity_id.to_string()))],
            )?;
            let mut intents = Vec::new();
            for row in result {
                intents.push(intent_from_row(&row)?);
            }
            Ok(intents)
        })
    }

    /// Find all intents with downstream warnings on a given entity.
    pub fn downstream_warnings_for_entity(&self, entity_id: &EntityId) -> Result<Vec<Intent>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DOWNSTREAM_WARNINGS_FOR_ENTITY)?;
            let result = conn.execute(
                &mut stmt,
                vec![("entity_id", Value::String(entity_id.to_string()))],
            )?;
            let mut intents = Vec::new();
            for row in result {
                intents.push(intent_from_row(&row)?);
            }
            Ok(intents)
        })
    }

    /// Create a WARNS_DOWNSTREAM edge from an intent to an entity.
    pub fn create_downstream_warning(
        &self,
        intent_id: &IntentId,
        entity_id: &EntityId,
        scope_kind: &str,
    ) -> Result<()> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::CREATE_WARNS_DOWNSTREAM_EDGE)?;
            conn.execute(
                &mut stmt,
                vec![
                    ("intent_id", Value::String(intent_id.to_string())),
                    ("entity_id", Value::String(entity_id.to_string())),
                    ("scope_kind", Value::String(scope_kind.to_string())),
                ],
            )?;
            Ok(())
        })
    }

    /// Upsert a shallow tracked file into the local graph.
    pub fn upsert_shallow_file(&self, shallow: &kin_model::ShallowTrackedFile) -> Result<()> {
        self.with_conn(|conn| {
            let params = shallow_file_params(shallow)?;
            let mut stmt = conn.prepare(queries::UPSERT_SHALLOW_FILE)?;
            conn.execute(&mut stmt, params)?;
            debug!(file_id = %shallow.file_id, "upserted shallow tracked file");
            Ok(())
        })
    }

    /// Get a shallow tracked file by file path.
    pub fn get_shallow_file(&self, file_id: &FilePathId) -> Result<Option<kin_model::ShallowTrackedFile>> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::GET_SHALLOW_FILE)?;
            let mut result = conn.execute(
                &mut stmt,
                vec![("file_id", Value::String(file_id.to_string()))],
            )?;
            match result.next() {
                Some(row) => Ok(Some(shallow_file_from_row(&row)?)),
                None => Ok(None),
            }
        })
    }

    /// List all shallow tracked files.
    pub fn list_shallow_files(&self) -> Result<Vec<kin_model::ShallowTrackedFile>> {
        self.with_conn(|conn| {
            let result = conn.query(queries::LIST_SHALLOW_FILES)?;
            let mut files = Vec::new();
            for row in result {
                files.push(shallow_file_from_row(&row)?);
            }
            Ok(files)
        })
    }

    /// Delete a shallow tracked file entry.
    pub fn delete_shallow_file(&self, file_id: &FilePathId) -> Result<()> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(queries::DELETE_SHALLOW_FILE)?;
            conn.execute(
                &mut stmt,
                vec![("file_id", Value::String(file_id.to_string()))],
            )?;
            debug!(file_id = %file_id, "deleted shallow tracked file");
            Ok(())
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn matches_filter(entity: &Entity, filter: &EntityFilter) -> bool {
    if let Some(ref kinds) = filter.kinds {
        if !kinds.contains(&entity.kind) {
            return false;
        }
    }
    if let Some(ref languages) = filter.languages {
        if !languages.contains(&entity.language) {
            return false;
        }
    }
    if let Some(ref name_pattern) = filter.name_pattern {
        if !entity.name.contains(name_pattern.as_str()) {
            return false;
        }
    }
    if let Some(ref file_path) = filter.file_path {
        match &entity.file_origin {
            Some(f) if f == file_path => {}
            _ => return false,
        }
    }
    true
}

fn collect_ancestors(
    conn: &Connection<'_>,
    start: &SemanticChangeId,
) -> Result<Vec<SemanticChangeId>> {
    let mut ancestors = Vec::new();
    let mut queue = vec![*start];
    let mut visited = std::collections::HashSet::new();

    while let Some(current) = queue.pop() {
        if !visited.insert(current) {
            continue;
        }
        ancestors.push(current);
        let mut stmt = conn.prepare(queries::GET_CHANGE)?;
        let mut result =
            conn.execute(&mut stmt, vec![("id", Value::String(current.to_string()))])?;
        if let Some(row) = result.next() {
            let change = change_from_row(&row)?;
            for parent in &change.parents {
                queue.push(*parent);
            }
        }
    }

    Ok(ancestors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::entity::FingerprintAlgorithm;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0xaa; 32]),
                signature_hash: Hash256::from_bytes([0xbb; 32]),
                behavior_hash: Hash256::from_bytes([0xcc; 32]),
                stability_score: 0.95,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
            span: None,
            signature: "fn test() -> bool".to_string(),
            visibility: Visibility::Public,
            doc_summary: Some("A test function".to_string()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_relation(src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        }
    }

    #[test]
    fn roundtrip_entity() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let entity = test_entity("my_func");

        store.upsert_entity(&entity).unwrap();
        let got = store.get_entity(&entity.id).unwrap().unwrap();

        assert_eq!(got.id, entity.id);
        assert_eq!(got.name, "my_func");
        assert_eq!(got.kind, EntityKind::Function);
        assert_eq!(got.language, LanguageId::Rust);
        assert_eq!(got.signature, entity.signature);
    }

    #[test]
    fn entity_not_found_returns_none() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let result = store.get_entity(&EntityId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn upsert_entity_updates() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let mut entity = test_entity("original");
        store.upsert_entity(&entity).unwrap();

        entity.name = "updated".to_string();
        store.upsert_entity(&entity).unwrap();

        let got = store.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(got.name, "updated");
    }

    #[test]
    fn remove_entity_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let entity = test_entity("to_remove");
        store.upsert_entity(&entity).unwrap();
        store.remove_entity(&entity.id).unwrap();
        assert!(store.get_entity(&entity.id).unwrap().is_none());
    }

    #[test]
    fn list_all_entities_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let e1 = test_entity("func_a");
        let e2 = test_entity("func_b");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();

        let all = store.list_all_entities().unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn roundtrip_relation() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();

        let rel = test_relation(e1.id, e2.id);
        store.upsert_relation(&rel).unwrap();

        let rels = store.get_all_relations_for_entity(&e1.id).unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0].kind, RelationKind::Calls);
    }

    #[test]
    fn remove_relation_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let e1 = test_entity("a");
        let e2 = test_entity("b");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();

        let rel = test_relation(e1.id, e2.id);
        store.upsert_relation(&rel).unwrap();
        store.remove_relation(&rel.id).unwrap();

        let rels = store.get_all_relations_for_entity(&e1.id).unwrap();
        assert_eq!(rels.len(), 0);
    }

    #[test]
    fn branch_crud() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let head = SemanticChangeId::from_hash(Hash256::from_bytes([0x01; 32]));
        let branch = Branch {
            name: BranchName::new("main"),
            head,
        };

        store.create_branch(&branch).unwrap();
        let got = store.get_branch(&BranchName::new("main")).unwrap().unwrap();
        assert_eq!(got.name.0, "main");
        assert_eq!(got.head, head);

        let new_head = SemanticChangeId::from_hash(Hash256::from_bytes([0x02; 32]));
        store
            .update_branch_head(&BranchName::new("main"), &new_head)
            .unwrap();
        let got = store.get_branch(&BranchName::new("main")).unwrap().unwrap();
        assert_eq!(got.head, new_head);

        let branches = store.list_branches().unwrap();
        assert_eq!(branches.len(), 1);

        store.delete_branch(&BranchName::new("main")).unwrap();
        assert!(store
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn query_entities_by_name() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let e1 = test_entity("foo_bar");
        let e2 = test_entity("baz_qux");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();

        let filter = EntityFilter {
            name_pattern: Some("foo".to_string()),
            ..Default::default()
        };
        let found = store.query_entities(&filter).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name, "foo_bar");
    }

    // --- Phase 7: Session/Intent tests ---

    fn test_session(vendor: &str) -> AgentSession {
        let now = Timestamp::now();
        AgentSession {
            session_id: SessionId::new(),
            vendor: vendor.to_string(),
            client_name: format!("{}-session", vendor),
            transport: SessionTransport::Mcp,
            pid: Some(12345),
            cwd: PathBuf::from("/project"),
            started_at: now.clone(),
            last_heartbeat: now,
            capabilities: SessionCapabilities::default(),
        }
    }

    fn test_intent(session_id: SessionId, entity_id: EntityId, lock: LockType) -> Intent {
        let now = Timestamp::now();
        Intent {
            intent_id: IntentId::new(),
            session_id,
            scopes: vec![IntentScope::Entity(entity_id)],
            lock_type: lock,
            task_description: "refactoring module".to_string(),
            registered_at: now,
            expires_at: None,
        }
    }

    #[test]
    fn roundtrip_session() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");

        store.upsert_session(&session).unwrap();
        let got = store.get_session(&session.session_id).unwrap().unwrap();

        assert_eq!(got.session_id, session.session_id);
        assert_eq!(got.vendor, "claude-code");
        assert_eq!(got.transport, SessionTransport::Mcp);
    }

    #[test]
    fn session_not_found_returns_none() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let result = store.get_session(&SessionId::new()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_sessions_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let s1 = test_session("claude-code");
        let s2 = test_session("codex");
        store.upsert_session(&s1).unwrap();
        store.upsert_session(&s2).unwrap();

        let sessions = store.list_sessions().unwrap();
        assert_eq!(sessions.len(), 2);
    }

    #[test]
    fn delete_session_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");
        store.upsert_session(&session).unwrap();
        store.delete_session(&session.session_id).unwrap();
        assert!(store.get_session(&session.session_id).unwrap().is_none());
    }

    #[test]
    fn update_heartbeat_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("codex");
        store.upsert_session(&session).unwrap();

        let new_ts = Timestamp::now();
        store
            .update_heartbeat(&session.session_id, &new_ts)
            .unwrap();

        let got = store.get_session(&session.session_id).unwrap().unwrap();
        assert_eq!(got.last_heartbeat.to_string(), new_ts.to_string());
    }

    #[test]
    fn roundtrip_intent() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");
        store.upsert_session(&session).unwrap();

        let entity = test_entity("target_fn");
        store.upsert_entity(&entity).unwrap();

        let intent = test_intent(session.session_id, entity.id, LockType::Hard);
        store.register_intent(&intent).unwrap();

        let got = store.get_intent(&intent.intent_id).unwrap().unwrap();
        assert_eq!(got.intent_id, intent.intent_id);
        assert_eq!(got.session_id, session.session_id);
        assert_eq!(got.lock_type, LockType::Hard);
    }

    #[test]
    fn list_intents_for_session_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");
        store.upsert_session(&session).unwrap();

        let e1 = test_entity("fn_a");
        let e2 = test_entity("fn_b");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();

        let i1 = test_intent(session.session_id, e1.id, LockType::Hard);
        let i2 = test_intent(session.session_id, e2.id, LockType::Soft);
        store.register_intent(&i1).unwrap();
        store.register_intent(&i2).unwrap();

        let intents = store.list_intents_for_session(&session.session_id).unwrap();
        assert_eq!(intents.len(), 2);
    }

    #[test]
    fn delete_intent_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("codex");
        store.upsert_session(&session).unwrap();

        let entity = test_entity("to_remove");
        store.upsert_entity(&entity).unwrap();

        let intent = test_intent(session.session_id, entity.id, LockType::Soft);
        store.register_intent(&intent).unwrap();
        store.delete_intent(&intent.intent_id).unwrap();
        assert!(store.get_intent(&intent.intent_id).unwrap().is_none());
    }

    #[test]
    fn hard_collision_detection() {
        let store = KuzuGraphStore::in_memory().unwrap();

        // Two sessions targeting the same entity with hard locks.
        let s1 = test_session("claude-code");
        let s2 = test_session("codex");
        store.upsert_session(&s1).unwrap();
        store.upsert_session(&s2).unwrap();

        let entity = test_entity("shared_fn");
        store.upsert_entity(&entity).unwrap();

        let i1 = test_intent(s1.session_id, entity.id, LockType::Hard);
        let i2 = test_intent(s2.session_id, entity.id, LockType::Hard);
        store.register_intent(&i1).unwrap();
        store.register_intent(&i2).unwrap();

        // i2 should see i1 as a collision.
        let collisions = store
            .hard_collisions_for_entity(&entity.id, &i2.intent_id)
            .unwrap();
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].intent_id, i1.intent_id);
    }

    #[test]
    fn locks_for_entity_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");
        store.upsert_session(&session).unwrap();

        let entity = test_entity("locked_fn");
        store.upsert_entity(&entity).unwrap();

        let intent = test_intent(session.session_id, entity.id, LockType::Hard);
        store.register_intent(&intent).unwrap();

        let locks = store.locks_for_entity(&entity.id).unwrap();
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].intent_id, intent.intent_id);
    }

    #[test]
    fn downstream_warnings_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");
        store.upsert_session(&session).unwrap();

        let entity = test_entity("downstream_fn");
        store.upsert_entity(&entity).unwrap();

        let intent = test_intent(session.session_id, EntityId::new(), LockType::Hard);
        store.register_intent(&intent).unwrap();

        // Manually create a downstream warning edge.
        store
            .create_downstream_warning(&intent.intent_id, &entity.id, "Entity")
            .unwrap();

        let warnings = store.downstream_warnings_for_entity(&entity.id).unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].intent_id, intent.intent_id);
    }

    #[test]
    fn delete_session_cascades_intents() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let session = test_session("claude-code");
        store.upsert_session(&session).unwrap();

        let entity = test_entity("target");
        store.upsert_entity(&entity).unwrap();

        let intent = test_intent(session.session_id, entity.id, LockType::Hard);
        store.register_intent(&intent).unwrap();

        // Deleting session should cascade-delete its intents.
        store.delete_session(&session.session_id).unwrap();
        assert!(store.get_intent(&intent.intent_id).unwrap().is_none());
    }

    // -------------------------------------------------------------------
    // Phase 9: Verification graph persistence tests
    // -------------------------------------------------------------------

    #[test]
    fn test_case_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let entity = test_entity("checkout_fn");
        store.upsert_entity(&entity).unwrap();

        let tc = kin_model::verification::TestCase {
            test_id: kin_model::verification::TestId::new(),
            name: "test_checkout_flow".into(),
            language: "rust".into(),
            kind: kin_model::verification::TestKind::Integration,
            scopes: vec![kin_model::WorkScope::Entity(entity.id)],
            runner: kin_model::verification::TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout.rs")),
        };

        store.create_test_case(&tc).unwrap();

        let fetched = store.get_test_case(&tc.test_id).unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.test_id, tc.test_id);
        assert_eq!(fetched.name, "test_checkout_flow");
        assert_eq!(fetched.language, "rust");
        assert_eq!(fetched.kind, kin_model::verification::TestKind::Integration);
        assert_eq!(fetched.runner, kin_model::verification::TestRunner::Cargo);
        assert_eq!(
            fetched.file_origin.as_ref().map(|f| f.to_string()),
            Some("tests/checkout.rs".to_string())
        );
    }

    #[test]
    fn test_case_not_found() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let missing = kin_model::verification::TestId::new();
        assert!(store.get_test_case(&missing).unwrap().is_none());
    }

    #[test]
    fn tests_for_entity_via_edge() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let entity = test_entity("my_func");
        store.upsert_entity(&entity).unwrap();

        let tc = kin_model::verification::TestCase {
            test_id: kin_model::verification::TestId::new(),
            name: "test_my_func".into(),
            language: "rust".into(),
            kind: kin_model::verification::TestKind::Unit,
            scopes: vec![kin_model::WorkScope::Entity(entity.id)],
            runner: kin_model::verification::TestRunner::Cargo,
            file_origin: None,
        };
        store.create_test_case(&tc).unwrap();

        let tests = store.get_tests_for_entity(&entity.id).unwrap();
        assert_eq!(tests.len(), 1);
        assert_eq!(tests[0].name, "test_my_func");
    }

    #[test]
    fn tests_for_entity_returns_empty_when_none() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let entity = test_entity("untested");
        store.upsert_entity(&entity).unwrap();

        let tests = store.get_tests_for_entity(&entity.id).unwrap();
        assert!(tests.is_empty());
    }

    #[test]
    fn delete_test_case_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let tc = kin_model::verification::TestCase {
            test_id: kin_model::verification::TestId::new(),
            name: "ephemeral_test".into(),
            language: "python".into(),
            kind: kin_model::verification::TestKind::Unit,
            scopes: vec![],
            runner: kin_model::verification::TestRunner::Pytest,
            file_origin: None,
        };
        store.create_test_case(&tc).unwrap();
        assert!(store.get_test_case(&tc.test_id).unwrap().is_some());

        store.delete_test_case(&tc.test_id).unwrap();
        assert!(store.get_test_case(&tc.test_id).unwrap().is_none());
    }

    #[test]
    fn create_assertion_persists() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let a = kin_model::verification::Assertion {
            assertion_id: kin_model::verification::AssertionId::new(),
            summary: "Must validate input".into(),
            expected_behavior: "Returns error on invalid input".into(),
            target_scope: kin_model::WorkScope::Entity(EntityId::new()),
        };
        // Should not panic.
        store.create_assertion(&a).unwrap();
    }

    #[test]
    fn get_assertion_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let a = kin_model::verification::Assertion {
            assertion_id: kin_model::verification::AssertionId::new(),
            summary: "Must validate card".into(),
            expected_behavior: "Returns error on invalid card number".into(),
            target_scope: kin_model::WorkScope::Entity(EntityId::new()),
        };
        store.create_assertion(&a).unwrap();

        let retrieved = store.get_assertion(&a.assertion_id).unwrap().expect("assertion should exist");
        assert_eq!(retrieved.assertion_id, a.assertion_id);
        assert_eq!(retrieved.summary, a.summary);
        assert_eq!(retrieved.expected_behavior, a.expected_behavior);

        // Non-existent assertion returns None.
        let missing = store.get_assertion(&kin_model::verification::AssertionId::new()).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn coverage_summary_with_mixed_coverage() {
        let store = KuzuGraphStore::in_memory().unwrap();

        // Create 3 entities.
        let e1 = test_entity("covered1");
        let e2 = test_entity("covered2");
        let e3 = test_entity("uncovered");
        store.upsert_entity(&e1).unwrap();
        store.upsert_entity(&e2).unwrap();
        store.upsert_entity(&e3).unwrap();

        // Create tests for 2 of them.
        let tc1 = kin_model::verification::TestCase {
            test_id: kin_model::verification::TestId::new(),
            name: "test_e1".into(),
            language: "rust".into(),
            kind: kin_model::verification::TestKind::Unit,
            scopes: vec![kin_model::WorkScope::Entity(e1.id)],
            runner: kin_model::verification::TestRunner::Cargo,
            file_origin: None,
        };
        let tc2 = kin_model::verification::TestCase {
            test_id: kin_model::verification::TestId::new(),
            name: "test_e2".into(),
            language: "rust".into(),
            kind: kin_model::verification::TestKind::Unit,
            scopes: vec![kin_model::WorkScope::Entity(e2.id)],
            runner: kin_model::verification::TestRunner::Cargo,
            file_origin: None,
        };
        store.create_test_case(&tc1).unwrap();
        store.create_test_case(&tc2).unwrap();

        let summary = store.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 3);
        assert_eq!(summary.covered_entities, 2);
        assert!((summary.coverage_ratio - 2.0 / 3.0).abs() < 0.01);
        assert_eq!(summary.missing_proof.len(), 1);
        assert_eq!(summary.missing_proof[0], e3.id);
    }

    #[test]
    fn coverage_summary_empty_graph() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let summary = store.get_coverage_summary().unwrap();
        assert_eq!(summary.total_entities, 0);
        assert_eq!(summary.covered_entities, 0);
        assert_eq!(summary.coverage_ratio, 0.0);
        assert!(summary.missing_proof.is_empty());
    }

    // -------------------------------------------------------------------
    // Phase 10: Provenance persistence tests
    // -------------------------------------------------------------------

    #[test]
    fn actor_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let actor = kin_model::provenance::Actor {
            actor_id: kin_model::provenance::ActorId::new(),
            kind: kin_model::provenance::ActorKind::Human,
            display_name: "Alice".into(),
            external_refs: vec![kin_model::ExternalRef {
                system: "github".into(),
                identifier: "alice".into(),
                url: None,
            }],
        };
        store.create_actor(&actor).unwrap();

        let fetched = store.get_actor(&actor.actor_id).unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.actor_id, actor.actor_id);
        assert_eq!(fetched.kind, kin_model::provenance::ActorKind::Human);
        assert_eq!(fetched.display_name, "Alice");
        assert_eq!(fetched.external_refs.len(), 1);
    }

    #[test]
    fn actor_not_found() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let missing = kin_model::provenance::ActorId::new();
        assert!(store.get_actor(&missing).unwrap().is_none());
    }

    #[test]
    fn list_actors_works() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let a1 = kin_model::provenance::Actor {
            actor_id: kin_model::provenance::ActorId::new(),
            kind: kin_model::provenance::ActorKind::Human,
            display_name: "Alice".into(),
            external_refs: vec![],
        };
        let a2 = kin_model::provenance::Actor {
            actor_id: kin_model::provenance::ActorId::new(),
            kind: kin_model::provenance::ActorKind::Assistant,
            display_name: "Claude".into(),
            external_refs: vec![],
        };
        store.create_actor(&a1).unwrap();
        store.create_actor(&a2).unwrap();

        let actors = store.list_actors().unwrap();
        assert_eq!(actors.len(), 2);
    }

    #[test]
    fn delegation_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let principal = kin_model::provenance::ActorId::new();
        let delegate = kin_model::provenance::ActorId::new();

        let d = kin_model::provenance::Delegation {
            delegation_id: kin_model::provenance::DelegationId::new(),
            principal,
            delegate,
            scope: vec![],
            started_at: Timestamp::now(),
            ended_at: None,
        };
        store.create_delegation(&d).unwrap();

        let found = store.get_delegations_for_actor(&principal).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].delegation_id, d.delegation_id);
        assert_eq!(found[0].principal, principal);
        assert_eq!(found[0].delegate, delegate);
    }

    #[test]
    fn approval_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xaa; 32]));

        let approval = kin_model::provenance::Approval {
            approval_id: kin_model::provenance::ApprovalId::new(),
            change_id,
            approver: kin_model::provenance::ActorId::new(),
            decision: kin_model::provenance::ApprovalDecision::Approved,
            reason: "LGTM".into(),
            timestamp: Timestamp::now(),
        };
        store.create_approval(&approval).unwrap();

        let found = store.get_approvals_for_change(&change_id).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].approval_id, approval.approval_id);
        assert_eq!(
            found[0].decision,
            kin_model::provenance::ApprovalDecision::Approved
        );
        assert_eq!(found[0].reason, "LGTM");
    }

    #[test]
    fn audit_event_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let actor_id = kin_model::provenance::ActorId::new();

        let event = kin_model::provenance::AuditEvent {
            event_id: kin_model::provenance::AuditEventId::new(),
            actor_id,
            action: "commit".into(),
            target_scope: Some(kin_model::WorkScope::Entity(EntityId::new())),
            timestamp: Timestamp::now(),
            details: Some("committed feature X".into()),
        };
        store.record_audit_event(&event).unwrap();

        let all = store.query_audit_events(None, 10).unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].action, "commit");
        assert!(all[0].details.as_deref() == Some("committed feature X"));

        let by_actor = store.query_audit_events(Some(&actor_id), 10).unwrap();
        assert_eq!(by_actor.len(), 1);
    }

    #[test]
    fn audit_events_empty() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let events = store.query_audit_events(None, 10).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn shallow_file_roundtrip() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let shallow = kin_model::ShallowTrackedFile {
            file_id: FilePathId::new("src/foo.c"),
            language_hint: "c".into(),
            declaration_count: 2,
            import_count: 1,
            syntax_hash: Hash256::from_bytes([0x11; 32]),
            signature_hash: Some(Hash256::from_bytes([0x22; 32])),
        };

        store.upsert_shallow_file(&shallow).unwrap();

        let fetched = store.get_shallow_file(&shallow.file_id).unwrap().unwrap();
        assert_eq!(fetched.file_id, shallow.file_id);
        assert_eq!(fetched.language_hint, "c");
        assert_eq!(fetched.declaration_count, 2);
        assert_eq!(fetched.import_count, 1);
        assert_eq!(fetched.syntax_hash, shallow.syntax_hash);
        assert_eq!(fetched.signature_hash, shallow.signature_hash);
    }

    #[test]
    fn list_and_delete_shallow_files() {
        let store = KuzuGraphStore::in_memory().unwrap();
        let s1 = kin_model::ShallowTrackedFile {
            file_id: FilePathId::new("src/a.c"),
            language_hint: "c".into(),
            declaration_count: 1,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([0x33; 32]),
            signature_hash: None,
        };
        let s2 = kin_model::ShallowTrackedFile {
            file_id: FilePathId::new("src/b.h"),
            language_hint: "c".into(),
            declaration_count: 3,
            import_count: 2,
            syntax_hash: Hash256::from_bytes([0x44; 32]),
            signature_hash: Some(Hash256::from_bytes([0x55; 32])),
        };

        store.upsert_shallow_file(&s1).unwrap();
        store.upsert_shallow_file(&s2).unwrap();

        let listed = store.list_shallow_files().unwrap();
        assert_eq!(listed.len(), 2);

        store.delete_shallow_file(&s1.file_id).unwrap();
        assert!(store.get_shallow_file(&s1.file_id).unwrap().is_none());
        assert_eq!(store.list_shallow_files().unwrap().len(), 1);
    }
}
