use crate::error::Result;

/// KuzuDB schema DDL statements for the Kin semantic graph.
///
/// Node tables: Entity, SemanticChange, Branch, AgentSession, Intent
/// Relationship tables: RELATES_TO, PARENT_OF, MODIFIES, OWNS_INTENT, LOCKS, WARNS_DOWNSTREAM
///
/// AgentSession and Intent are **transient** — they are not part of
/// SemanticChange history and are not exported to Git.

const CREATE_ENTITY_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS Entity(
    id STRING,
    kind STRING,
    name STRING,
    language STRING,
    fingerprint_json STRING,
    file_origin STRING,
    span_json STRING,
    signature STRING,
    visibility STRING,
    doc_summary STRING,
    metadata_json STRING,
    lineage_parent STRING,
    created_in STRING,
    superseded_by STRING,
    PRIMARY KEY(id)
)";

const CREATE_SEMANTIC_CHANGE_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS SemanticChange(
    id STRING,
    parents_json STRING,
    timestamp STRING,
    author STRING,
    message STRING,
    entity_deltas_json STRING,
    relation_deltas_json STRING,
    artifact_deltas_json STRING,
    projected_files_json STRING,
    spec_link STRING,
    evidence_json STRING,
    risk_summary_json STRING,
    authored_on STRING,
    PRIMARY KEY(id)
)";

const CREATE_BRANCH_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS Branch(
    name STRING,
    head STRING,
    PRIMARY KEY(name)
)";

const CREATE_RELATES_TO_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS RELATES_TO(
    FROM Entity TO Entity,
    rel_id STRING,
    kind STRING,
    confidence FLOAT,
    origin STRING,
    created_in STRING
)";

const CREATE_PARENT_OF_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS PARENT_OF(
    FROM SemanticChange TO SemanticChange
)";

const CREATE_MODIFIES_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS MODIFIES(
    FROM SemanticChange TO Entity
)";

// ---------------------------------------------------------------------------
// Transient tables (Phase 7): AgentSession, Intent, and coordination edges.
// These are NOT part of SemanticChange history and are NOT exported to Git.
// ---------------------------------------------------------------------------

const CREATE_AGENT_SESSION_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS AgentSession(
    session_id STRING,
    vendor STRING,
    client_name STRING,
    transport STRING,
    pid STRING,
    cwd STRING,
    started_at STRING,
    last_heartbeat STRING,
    capabilities_json STRING,
    PRIMARY KEY(session_id)
)";

const CREATE_INTENT_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS Intent(
    intent_id STRING,
    session_id STRING,
    scopes_json STRING,
    lock_type STRING,
    task_description STRING,
    registered_at STRING,
    expires_at STRING,
    PRIMARY KEY(intent_id)
)";

const CREATE_OWNS_INTENT_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS OWNS_INTENT(
    FROM AgentSession TO Intent
)";

const CREATE_LOCKS_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS LOCKS(
    FROM Intent TO Entity,
    lock_type STRING,
    scope_kind STRING
)";

const CREATE_WARNS_DOWNSTREAM_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS WARNS_DOWNSTREAM(
    FROM Intent TO Entity,
    scope_kind STRING
)";

// ---------------------------------------------------------------------------
// Durable tables (Phase 8): WorkItem, Annotation, and work graph edges.
// These ARE part of the semantic history (unlike Phase 7 transient traffic).
// ---------------------------------------------------------------------------

const CREATE_WORK_ITEM_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS WorkItem(
    work_id STRING,
    kind STRING,
    title STRING,
    description STRING,
    status STRING,
    priority STRING,
    scopes_json STRING,
    acceptance_criteria_json STRING,
    external_refs_json STRING,
    created_by_json STRING,
    created_at STRING,
    PRIMARY KEY(work_id)
)";

const CREATE_ANNOTATION_TABLE: &str = "
CREATE NODE TABLE IF NOT EXISTS Annotation(
    annotation_id STRING,
    kind STRING,
    body STRING,
    scopes_json STRING,
    anchored_fingerprint_json STRING,
    authored_by_json STRING,
    created_at STRING,
    staleness STRING,
    PRIMARY KEY(annotation_id)
)";

const CREATE_AFFECTS_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS AFFECTS(
    FROM WorkItem TO Entity,
    scope_kind STRING
)";

const CREATE_DECOMPOSES_TO_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS DECOMPOSES_TO(
    FROM WorkItem TO WorkItem
)";

const CREATE_BLOCKED_BY_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS BLOCKED_BY(
    FROM WorkItem TO WorkItem
)";

const CREATE_IMPLEMENTS_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS IMPLEMENTS(
    FROM Entity TO WorkItem,
    scope_kind STRING
)";

const CREATE_ATTACHED_TO_ENTITY_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS ATTACHED_TO_ENTITY(
    FROM Annotation TO Entity
)";

const CREATE_ATTACHED_TO_WORK_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS ATTACHED_TO_WORK(
    FROM Annotation TO WorkItem
)";

const CREATE_SUPERSEDES_TABLE: &str = "
CREATE REL TABLE IF NOT EXISTS SUPERSEDES(
    FROM Annotation TO Annotation
)";

/// Initialize the KuzuDB schema. Idempotent (uses IF NOT EXISTS).
pub fn init_schema(conn: &kuzu::Connection<'_>) -> Result<()> {
    let statements = [
        // Core tables (V1).
        CREATE_ENTITY_TABLE,
        CREATE_SEMANTIC_CHANGE_TABLE,
        CREATE_BRANCH_TABLE,
        CREATE_RELATES_TO_TABLE,
        CREATE_PARENT_OF_TABLE,
        CREATE_MODIFIES_TABLE,
        // Transient tables (Phase 7).
        CREATE_AGENT_SESSION_TABLE,
        CREATE_INTENT_TABLE,
        CREATE_OWNS_INTENT_TABLE,
        CREATE_LOCKS_TABLE,
        CREATE_WARNS_DOWNSTREAM_TABLE,
        // Durable tables (Phase 8).
        CREATE_WORK_ITEM_TABLE,
        CREATE_ANNOTATION_TABLE,
        CREATE_AFFECTS_TABLE,
        CREATE_DECOMPOSES_TO_TABLE,
        CREATE_BLOCKED_BY_TABLE,
        CREATE_IMPLEMENTS_TABLE,
        CREATE_ATTACHED_TO_ENTITY_TABLE,
        CREATE_ATTACHED_TO_WORK_TABLE,
        CREATE_SUPERSEDES_TABLE,
    ];

    for stmt in &statements {
        conn.query(stmt).map_err(|e| {
            crate::error::GraphError::SchemaInit(format!("{}: {}", e, stmt.trim()))
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_init_idempotent() {
        let db = kuzu::Database::in_memory(kuzu::SystemConfig::default()).unwrap();
        let conn = kuzu::Connection::new(&db).unwrap();
        // Should succeed twice without error.
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap();
    }
}
