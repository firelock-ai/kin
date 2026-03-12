/// Internal Cypher query strings. These MUST NOT be used outside kin-graph.

// --- Entity CRUD ---

pub const UPSERT_ENTITY: &str = "
MERGE (e:Entity {id: $id})
SET e.kind = $kind,
    e.name = $name,
    e.language = $language,
    e.fingerprint_json = $fingerprint_json,
    e.file_origin = $file_origin,
    e.span_json = $span_json,
    e.signature = $signature,
    e.visibility = $visibility,
    e.doc_summary = $doc_summary,
    e.metadata_json = $metadata_json,
    e.lineage_parent = $lineage_parent,
    e.created_in = $created_in,
    e.superseded_by = $superseded_by
";

pub const GET_ENTITY: &str = "
MATCH (e:Entity {id: $id})
RETURN e.id, e.kind, e.name, e.language, e.fingerprint_json,
       e.file_origin, e.span_json, e.signature, e.visibility,
       e.doc_summary, e.metadata_json, e.lineage_parent,
       e.created_in, e.superseded_by
";

pub const DELETE_ENTITY: &str = "
MATCH (e:Entity {id: $id})
DETACH DELETE e
";

pub const LIST_ALL_ENTITIES: &str = "
MATCH (e:Entity)
RETURN e.id, e.kind, e.name, e.language, e.fingerprint_json,
       e.file_origin, e.span_json, e.signature, e.visibility,
       e.doc_summary, e.metadata_json, e.lineage_parent,
       e.created_in, e.superseded_by
";

pub const QUERY_ENTITIES_BY_KIND: &str = "
MATCH (e:Entity)
WHERE e.kind = $kind
RETURN e.id, e.kind, e.name, e.language, e.fingerprint_json,
       e.file_origin, e.span_json, e.signature, e.visibility,
       e.doc_summary, e.metadata_json, e.lineage_parent,
       e.created_in, e.superseded_by
";

pub const QUERY_ENTITIES_BY_FILE: &str = "
MATCH (e:Entity)
WHERE e.file_origin = $file_path
RETURN e.id, e.kind, e.name, e.language, e.fingerprint_json,
       e.file_origin, e.span_json, e.signature, e.visibility,
       e.doc_summary, e.metadata_json, e.lineage_parent,
       e.created_in, e.superseded_by
";

pub const QUERY_ENTITIES_BY_NAME: &str = "
MATCH (e:Entity)
WHERE e.name CONTAINS $name_pattern
RETURN e.id, e.kind, e.name, e.language, e.fingerprint_json,
       e.file_origin, e.span_json, e.signature, e.visibility,
       e.doc_summary, e.metadata_json, e.lineage_parent,
       e.created_in, e.superseded_by
";

// --- Relation CRUD ---

pub const UPSERT_RELATION: &str = "
MATCH (src:Entity {id: $src}), (dst:Entity {id: $dst})
MERGE (src)-[r:RELATES_TO {rel_id: $rel_id}]->(dst)
SET r.kind = $kind,
    r.confidence = $confidence,
    r.origin = $origin,
    r.created_in = $created_in
";

pub const GET_RELATIONS_FOR_ENTITY: &str = "
MATCH (e:Entity {id: $id})-[r:RELATES_TO]-(other:Entity)
RETURN r.rel_id, r.kind, e.id, other.id, r.confidence, r.origin, r.created_in
";

pub const GET_RELATIONS_BY_KIND: &str = "
MATCH (e:Entity {id: $id})-[r:RELATES_TO]-(other:Entity)
WHERE r.kind = $kind
RETURN r.rel_id, r.kind, e.id, other.id, r.confidence, r.origin, r.created_in
";

pub const DELETE_RELATION: &str = "
MATCH ()-[r:RELATES_TO {rel_id: $rel_id}]->()
DELETE r
";

/// Delete all outgoing RELATES_TO edges from a specific entity.
/// Used during commit to clear stale relations before re-linking.
pub const DELETE_OUTGOING_RELATIONS: &str = "
MATCH (e:Entity {id: $id})-[r:RELATES_TO]->()
DELETE r
";

// --- Impact / Neighborhood ---

pub const DOWNSTREAM_IMPACT: &str = "
MATCH (e:Entity {id: $id})<-[r:RELATES_TO* 1..10 (r, _ | WHERE r.kind IN ['Calls', 'Imports', 'References'])]-(affected:Entity)
RETURN DISTINCT affected.id, affected.kind, affected.name, affected.language,
       affected.fingerprint_json, affected.file_origin, affected.span_json,
       affected.signature, affected.visibility, affected.doc_summary,
       affected.metadata_json, affected.lineage_parent,
       affected.created_in, affected.superseded_by
";

#[allow(dead_code)]
pub const DEPENDENCY_NEIGHBORHOOD: &str = "
MATCH (e:Entity {id: $id})-[r:RELATES_TO*1..]-(neighbor:Entity)
RETURN DISTINCT neighbor.id, neighbor.kind, neighbor.name, neighbor.language,
       neighbor.fingerprint_json, neighbor.file_origin, neighbor.span_json,
       neighbor.signature, neighbor.visibility, neighbor.doc_summary,
       neighbor.metadata_json, neighbor.lineage_parent,
       neighbor.created_in, neighbor.superseded_by
";

pub const DEAD_CODE: &str = "
MATCH (e:Entity)
WHERE NOT EXISTS { MATCH ()-[r:RELATES_TO]->(e) WHERE r.kind IN ['Calls', 'Imports', 'References'] }
AND e.kind IN ['Function', 'Class', 'Method']
RETURN e.id, e.kind, e.name, e.language, e.fingerprint_json,
       e.file_origin, e.span_json, e.signature, e.visibility,
       e.doc_summary, e.metadata_json, e.lineage_parent,
       e.created_in, e.superseded_by
";

// --- SemanticChange DAG ---

pub const CREATE_CHANGE: &str = "
CREATE (c:SemanticChange {
    id: $id,
    parents_json: $parents_json,
    timestamp: $timestamp,
    author: $author,
    message: $message,
    entity_deltas_json: $entity_deltas_json,
    relation_deltas_json: $relation_deltas_json,
    artifact_deltas_json: $artifact_deltas_json,
    projected_files_json: $projected_files_json,
    spec_link: $spec_link,
    evidence_json: $evidence_json,
    risk_summary_json: $risk_summary_json,
    authored_on: $authored_on
})
";

pub const GET_CHANGE: &str = "
MATCH (c:SemanticChange {id: $id})
RETURN c.id, c.parents_json, c.timestamp, c.author, c.message,
       c.entity_deltas_json, c.relation_deltas_json, c.artifact_deltas_json,
       c.projected_files_json, c.spec_link, c.evidence_json,
       c.risk_summary_json, c.authored_on
";

pub const CREATE_PARENT_EDGE: &str = "
MATCH (child:SemanticChange {id: $child_id}), (parent:SemanticChange {id: $parent_id})
CREATE (child)-[:PARENT_OF]->(parent)
";

pub const CREATE_MODIFIES_EDGE: &str = "
MATCH (c:SemanticChange {id: $change_id}), (e:Entity {id: $entity_id})
CREATE (c)-[:MODIFIES]->(e)
";

pub const ENTITY_HISTORY: &str = "
MATCH (c:SemanticChange)-[:MODIFIES]->(e:Entity {id: $id})
RETURN c.id, c.parents_json, c.timestamp, c.author, c.message,
       c.entity_deltas_json, c.relation_deltas_json, c.artifact_deltas_json,
       c.projected_files_json, c.spec_link, c.evidence_json,
       c.risk_summary_json, c.authored_on
ORDER BY c.timestamp DESC
";

// --- Branch operations ---

pub const GET_BRANCH: &str = "
MATCH (b:Branch {name: $name})
RETURN b.name, b.head
";

pub const CREATE_BRANCH: &str = "
CREATE (b:Branch {name: $name, head: $head})
";

pub const UPDATE_BRANCH_HEAD: &str = "
MATCH (b:Branch {name: $name})
SET b.head = $head
";

pub const DELETE_BRANCH: &str = "
MATCH (b:Branch {name: $name})
DELETE b
";

pub const LIST_BRANCHES: &str = "
MATCH (b:Branch)
RETURN b.name, b.head
";

// ===========================================================================
// Transient tables (Phase 7): AgentSession, Intent, and coordination queries.
// ===========================================================================

// --- AgentSession CRUD ---

pub const UPSERT_SESSION: &str = "
MERGE (s:AgentSession {session_id: $session_id})
SET s.vendor = $vendor,
    s.client_name = $client_name,
    s.transport = $transport,
    s.pid = $pid,
    s.cwd = $cwd,
    s.started_at = $started_at,
    s.last_heartbeat = $last_heartbeat,
    s.capabilities_json = $capabilities_json
";

pub const GET_SESSION: &str = "
MATCH (s:AgentSession {session_id: $session_id})
RETURN s.session_id, s.vendor, s.client_name, s.transport,
       s.pid, s.cwd, s.started_at, s.last_heartbeat, s.capabilities_json
";

pub const DELETE_SESSION: &str = "
MATCH (s:AgentSession {session_id: $session_id})
DETACH DELETE s
";

pub const LIST_SESSIONS: &str = "
MATCH (s:AgentSession)
RETURN s.session_id, s.vendor, s.client_name, s.transport,
       s.pid, s.cwd, s.started_at, s.last_heartbeat, s.capabilities_json
";

pub const UPDATE_HEARTBEAT: &str = "
MATCH (s:AgentSession {session_id: $session_id})
SET s.last_heartbeat = $last_heartbeat
";

// --- Intent CRUD ---

pub const CREATE_INTENT: &str = "
CREATE (i:Intent {
    intent_id: $intent_id,
    session_id: $session_id,
    scopes_json: $scopes_json,
    lock_type: $lock_type,
    task_description: $task_description,
    registered_at: $registered_at,
    expires_at: $expires_at
})
";

pub const GET_INTENT: &str = "
MATCH (i:Intent {intent_id: $intent_id})
RETURN i.intent_id, i.session_id, i.scopes_json, i.lock_type,
       i.task_description, i.registered_at, i.expires_at
";

pub const DELETE_INTENT: &str = "
MATCH (i:Intent {intent_id: $intent_id})
DETACH DELETE i
";

pub const LIST_INTENTS_FOR_SESSION: &str = "
MATCH (s:AgentSession {session_id: $session_id})-[:OWNS_INTENT]->(i:Intent)
RETURN i.intent_id, i.session_id, i.scopes_json, i.lock_type,
       i.task_description, i.registered_at, i.expires_at
";

pub const LIST_ALL_INTENTS: &str = "
MATCH (i:Intent)
RETURN i.intent_id, i.session_id, i.scopes_json, i.lock_type,
       i.task_description, i.registered_at, i.expires_at
";

// --- Ownership edge ---

pub const CREATE_OWNS_INTENT_EDGE: &str = "
MATCH (s:AgentSession {session_id: $session_id}), (i:Intent {intent_id: $intent_id})
CREATE (s)-[:OWNS_INTENT]->(i)
";

// --- Lock edges ---

pub const CREATE_LOCK_EDGE: &str = "
MATCH (i:Intent {intent_id: $intent_id}), (e:Entity {id: $entity_id})
CREATE (i)-[:LOCKS {lock_type: $lock_type, scope_kind: $scope_kind}]->(e)
";

pub const CREATE_WARNS_DOWNSTREAM_EDGE: &str = "
MATCH (i:Intent {intent_id: $intent_id}), (e:Entity {id: $entity_id})
CREATE (i)-[:WARNS_DOWNSTREAM {scope_kind: $scope_kind}]->(e)
";

// --- Collision detection ---

/// Find intents that lock the same entity via hard locks (excluding a given intent).
pub const HARD_COLLISIONS_FOR_ENTITY: &str = "
MATCH (other:Intent)-[l:LOCKS]->(e:Entity {id: $entity_id})
WHERE other.intent_id <> $exclude_intent_id AND l.lock_type = 'Hard'
RETURN other.intent_id, other.session_id, other.scopes_json, other.lock_type,
       other.task_description, other.registered_at, other.expires_at
";

/// Find all intents that lock a given entity (any lock type).
pub const LOCKS_FOR_ENTITY: &str = "
MATCH (i:Intent)-[l:LOCKS]->(e:Entity {id: $entity_id})
RETURN i.intent_id, i.session_id, i.scopes_json, i.lock_type,
       i.task_description, i.registered_at, i.expires_at
";

/// Find all intents that have downstream warnings on a given entity.
pub const DOWNSTREAM_WARNINGS_FOR_ENTITY: &str = "
MATCH (i:Intent)-[:WARNS_DOWNSTREAM]->(e:Entity {id: $entity_id})
RETURN i.intent_id, i.session_id, i.scopes_json, i.lock_type,
       i.task_description, i.registered_at, i.expires_at
";

/// Delete all LOCKS edges from a specific intent.
#[allow(dead_code)]
pub const DELETE_LOCKS_FOR_INTENT: &str = "
MATCH (i:Intent {intent_id: $intent_id})-[l:LOCKS]->()
DELETE l
";

/// Delete all WARNS_DOWNSTREAM edges from a specific intent.
#[allow(dead_code)]
pub const DELETE_WARNS_FOR_INTENT: &str = "
MATCH (i:Intent {intent_id: $intent_id})-[w:WARNS_DOWNSTREAM]->()
DELETE w
";

/// Delete all intents owned by a session (cleanup on session removal).
pub const DELETE_INTENTS_FOR_SESSION: &str = "
MATCH (s:AgentSession {session_id: $session_id})-[:OWNS_INTENT]->(i:Intent)
DETACH DELETE i
";

// ---------------------------------------------------------------------------
// Phase 8: Work Item and Annotation queries
// ---------------------------------------------------------------------------

// --- WorkItem CRUD ---

pub const UPSERT_WORK_ITEM: &str = "
MERGE (w:WorkItem {work_id: $work_id})
SET w.kind = $kind,
    w.title = $title,
    w.description = $description,
    w.status = $status,
    w.priority = $priority,
    w.scopes_json = $scopes_json,
    w.acceptance_criteria_json = $acceptance_criteria_json,
    w.external_refs_json = $external_refs_json,
    w.created_by_json = $created_by_json,
    w.created_at = $created_at
";

pub const GET_WORK_ITEM: &str = "
MATCH (w:WorkItem {work_id: $work_id})
RETURN w.work_id, w.kind, w.title, w.description, w.status, w.priority,
       w.scopes_json, w.acceptance_criteria_json, w.external_refs_json,
       w.created_by_json, w.created_at
";

pub const LIST_ALL_WORK_ITEMS: &str = "
MATCH (w:WorkItem)
RETURN w.work_id, w.kind, w.title, w.description, w.status, w.priority,
       w.scopes_json, w.acceptance_criteria_json, w.external_refs_json,
       w.created_by_json, w.created_at
";

pub const UPDATE_WORK_STATUS: &str = "
MATCH (w:WorkItem {work_id: $work_id})
SET w.status = $status
";

pub const DELETE_WORK_ITEM: &str = "
MATCH (w:WorkItem {work_id: $work_id})
DETACH DELETE w
";

// --- Annotation CRUD ---

pub const UPSERT_ANNOTATION: &str = "
MERGE (a:Annotation {annotation_id: $annotation_id})
SET a.kind = $kind,
    a.body = $body,
    a.scopes_json = $scopes_json,
    a.anchored_fingerprint_json = $anchored_fingerprint_json,
    a.authored_by_json = $authored_by_json,
    a.created_at = $created_at,
    a.staleness = $staleness
";

pub const GET_ANNOTATION: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id})
RETURN a.annotation_id, a.kind, a.body, a.scopes_json,
       a.anchored_fingerprint_json, a.authored_by_json,
       a.created_at, a.staleness
";

pub const LIST_ALL_ANNOTATIONS: &str = "
MATCH (a:Annotation)
RETURN a.annotation_id, a.kind, a.body, a.scopes_json,
       a.anchored_fingerprint_json, a.authored_by_json,
       a.created_at, a.staleness
";

pub const UPDATE_ANNOTATION_STALENESS: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id})
SET a.staleness = $staleness
";

pub const DELETE_ANNOTATION: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id})
DETACH DELETE a
";

// --- Work graph relationship queries ---

pub const CREATE_AFFECTS_EDGE: &str = "
MATCH (w:WorkItem {work_id: $work_id}), (e:Entity {id: $entity_id})
CREATE (w)-[:AFFECTS {scope_kind: $scope_kind}]->(e)
";

pub const CREATE_DECOMPOSES_TO_EDGE: &str = "
MATCH (p:WorkItem {work_id: $parent_id}), (c:WorkItem {work_id: $child_id})
CREATE (p)-[:DECOMPOSES_TO]->(c)
";

pub const CREATE_BLOCKED_BY_EDGE: &str = "
MATCH (b:WorkItem {work_id: $blocked_id}), (k:WorkItem {work_id: $blocker_id})
CREATE (b)-[:BLOCKED_BY]->(k)
";

pub const CREATE_IMPLEMENTS_EDGE: &str = "
MATCH (e:Entity {id: $entity_id}), (w:WorkItem {work_id: $work_id})
CREATE (e)-[:IMPLEMENTS {scope_kind: $scope_kind}]->(w)
";

pub const CREATE_ATTACHED_TO_ENTITY_EDGE: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id}), (e:Entity {id: $entity_id})
CREATE (a)-[:ATTACHED_TO_ENTITY]->(e)
";

pub const CREATE_ATTACHED_TO_WORK_EDGE: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id}), (w:WorkItem {work_id: $work_id})
CREATE (a)-[:ATTACHED_TO_WORK]->(w)
";

pub const CREATE_SUPERSEDES_EDGE: &str = "
MATCH (n:Annotation {annotation_id: $new_id}), (o:Annotation {annotation_id: $old_id})
CREATE (n)-[:SUPERSEDES]->(o)
";

// --- Relationship deletion queries ---

pub const DELETE_AFFECTS_EDGE: &str = "
MATCH (w:WorkItem {work_id: $work_id})-[r:AFFECTS]->(e:Entity {id: $entity_id})
DELETE r
";

pub const DELETE_DECOMPOSES_TO_EDGE: &str = "
MATCH (p:WorkItem {work_id: $parent_id})-[r:DECOMPOSES_TO]->(c:WorkItem {work_id: $child_id})
DELETE r
";

pub const DELETE_BLOCKED_BY_EDGE: &str = "
MATCH (b:WorkItem {work_id: $blocked_id})-[r:BLOCKED_BY]->(k:WorkItem {work_id: $blocker_id})
DELETE r
";

pub const DELETE_IMPLEMENTS_EDGE: &str = "
MATCH (e:Entity {id: $entity_id})-[r:IMPLEMENTS]->(w:WorkItem {work_id: $work_id})
DELETE r
";

pub const DELETE_ATTACHED_TO_ENTITY_EDGE: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id})-[r:ATTACHED_TO_ENTITY]->(e:Entity {id: $entity_id})
DELETE r
";

pub const DELETE_ATTACHED_TO_WORK_EDGE: &str = "
MATCH (a:Annotation {annotation_id: $annotation_id})-[r:ATTACHED_TO_WORK]->(w:WorkItem {work_id: $work_id})
DELETE r
";

pub const DELETE_SUPERSEDES_EDGE: &str = "
MATCH (n:Annotation {annotation_id: $new_id})-[r:SUPERSEDES]->(o:Annotation {annotation_id: $old_id})
DELETE r
";

// --- Traversal queries ---

pub const WORK_FOR_ENTITY: &str = "
MATCH (w:WorkItem)-[:AFFECTS]->(e:Entity {id: $entity_id})
RETURN w.work_id, w.kind, w.title, w.description, w.status, w.priority,
       w.scopes_json, w.acceptance_criteria_json, w.external_refs_json,
       w.created_by_json, w.created_at
";

pub const ANNOTATIONS_FOR_ENTITY: &str = "
MATCH (a:Annotation)-[:ATTACHED_TO_ENTITY]->(e:Entity {id: $entity_id})
RETURN a.annotation_id, a.kind, a.body, a.scopes_json,
       a.anchored_fingerprint_json, a.authored_by_json,
       a.created_at, a.staleness
";

#[allow(dead_code)]
pub const ANNOTATIONS_FOR_WORK: &str = "
MATCH (a:Annotation)-[:ATTACHED_TO_WORK]->(w:WorkItem {work_id: $work_id})
RETURN a.annotation_id, a.kind, a.body, a.scopes_json,
       a.anchored_fingerprint_json, a.authored_by_json,
       a.created_at, a.staleness
";

pub const CHILD_WORK_ITEMS: &str = "
MATCH (p:WorkItem {work_id: $parent_id})-[:DECOMPOSES_TO]->(c:WorkItem)
RETURN c.work_id, c.kind, c.title, c.description, c.status, c.priority,
       c.scopes_json, c.acceptance_criteria_json, c.external_refs_json,
       c.created_by_json, c.created_at
";

pub const IMPLEMENTORS_FOR_WORK: &str = "
MATCH (e:Entity)-[:IMPLEMENTS]->(w:WorkItem {work_id: $work_id})
RETURN e.id
";

// ===========================================================================
// Phase 9: TestCase and Assertion queries
// ===========================================================================

pub const CREATE_TEST_CASE: &str = "
CREATE (t:TestCase {
    test_id: $test_id,
    name: $name,
    language: $language,
    kind: $kind,
    scopes_json: $scopes_json,
    runner: $runner,
    file_origin: $file_origin
})
";

pub const GET_TEST_CASE: &str = "
MATCH (t:TestCase {test_id: $test_id})
RETURN t.test_id, t.name, t.language, t.kind, t.scopes_json, t.runner, t.file_origin
";

pub const DELETE_TEST_CASE: &str = "
MATCH (t:TestCase {test_id: $test_id})
DETACH DELETE t
";

pub const CREATE_TESTS_ENTITY_EDGE: &str = "
MATCH (t:TestCase {test_id: $test_id}), (e:Entity {id: $entity_id})
CREATE (t)-[:TESTS_ENTITY {scope_kind: $scope_kind}]->(e)
";

pub const TESTS_FOR_ENTITY: &str = "
MATCH (t:TestCase)-[:TESTS_ENTITY]->(e:Entity {id: $entity_id})
RETURN t.test_id, t.name, t.language, t.kind, t.scopes_json, t.runner, t.file_origin
";

pub const ALL_TEST_CASES: &str = "
MATCH (t:TestCase)
RETURN t.test_id, t.name, t.language, t.kind, t.scopes_json, t.runner, t.file_origin
";

pub const CREATE_ASSERTION: &str = "
CREATE (a:Assertion {
    assertion_id: $assertion_id,
    summary: $summary,
    expected_behavior: $expected_behavior,
    target_scope_json: $target_scope_json
})
";

pub const GET_ASSERTION: &str = "
MATCH (a:Assertion {assertion_id: $assertion_id})
RETURN a.assertion_id, a.summary, a.expected_behavior, a.target_scope_json
";

/// Count entities that have at least one linked test.
pub const COVERED_ENTITY_COUNT: &str = "
MATCH (t:TestCase)-[:TESTS_ENTITY]->(e:Entity)
RETURN COUNT(DISTINCT e.id)
";

// ===========================================================================
// Phase 9 completion: VerificationRun, COVERS/VERIFIES edges, MockHint
// ===========================================================================

pub const CREATE_VERIFICATION_RUN: &str = "
CREATE (vr:VerificationRun {
    run_id: $run_id,
    test_ids_json: $test_ids_json,
    status: $status,
    runner: $runner,
    started_at: $started_at,
    finished_at: $finished_at,
    duration_ms: $duration_ms,
    evidence_blob: $evidence_blob,
    exit_code: $exit_code
})";

pub const GET_VERIFICATION_RUN: &str = "
MATCH (vr:VerificationRun {run_id: $run_id})
RETURN vr.run_id, vr.test_ids_json, vr.status, vr.runner,
       vr.started_at, vr.finished_at, vr.duration_ms,
       vr.evidence_blob, vr.exit_code";

pub const RUNS_FOR_TEST: &str = "
MATCH (vr:VerificationRun)-[:EXECUTED]->(t:TestCase {test_id: $test_id})
RETURN vr.run_id, vr.test_ids_json, vr.status, vr.runner,
       vr.started_at, vr.finished_at, vr.duration_ms,
       vr.evidence_blob, vr.exit_code";

pub const CREATE_COVERS_EDGE: &str = "
MATCH (t:TestCase {test_id: $test_id}), (e:Entity {id: $entity_id})
CREATE (t)-[:COVERS {scope_kind: $scope_kind}]->(e)";

pub const CREATE_COVERS_CONTRACT_EDGE: &str = "
MATCH (t:TestCase {test_id: $test_id}), (c:Contract {contract_id: $contract_id})
CREATE (t)-[:COVERS_CONTRACT {scope_kind: $scope_kind}]->(c)";

pub const CREATE_VERIFIES_EDGE: &str = "
MATCH (t:TestCase {test_id: $test_id}), (w:WorkItem {work_id: $work_id})
CREATE (t)-[:VERIFIES {scope_kind: $scope_kind}]->(w)";

pub const TESTS_COVERING_CONTRACT: &str = "
MATCH (t:TestCase)-[:COVERS_CONTRACT]->(c:Contract {contract_id: $contract_id})
RETURN t.test_id, t.name, t.language, t.kind, t.scopes_json, t.runner, t.file_origin";

pub const TESTS_VERIFYING_WORK: &str = "
MATCH (t:TestCase)-[:VERIFIES]->(w:WorkItem {work_id: $work_id})
RETURN t.test_id, t.name, t.language, t.kind, t.scopes_json, t.runner, t.file_origin";

pub const CREATE_EXECUTED_EDGE: &str = "
MATCH (vr:VerificationRun {run_id: $run_id}), (t:TestCase {test_id: $test_id})
CREATE (vr)-[:EXECUTED]->(t)";

pub const CREATE_PROVES_ENTITY_EDGE: &str = "
MATCH (vr:VerificationRun {run_id: $run_id}), (e:Entity {id: $entity_id})
CREATE (vr)-[:PROVES_ENTITY]->(e)";

pub const CREATE_PROVES_WORK_EDGE: &str = "
MATCH (vr:VerificationRun {run_id: $run_id}), (w:WorkItem {work_id: $work_id})
CREATE (vr)-[:PROVES_WORK]->(w)";

pub const CREATE_MOCK_HINT: &str = "
CREATE (mh:MockHint {
    hint_id: $hint_id,
    test_id: $test_id,
    dependency_scope_json: $dependency_scope_json,
    strategy: $strategy
})";

pub const MOCK_HINTS_FOR_TEST: &str = "
MATCH (mh:MockHint)
WHERE mh.test_id = $test_id
RETURN mh.hint_id, mh.test_id, mh.dependency_scope_json, mh.strategy";

pub const CONTRACT_COVERED_COUNT: &str = "
MATCH (t:TestCase)-[:COVERS_CONTRACT]->(c:Contract)
RETURN COUNT(DISTINCT c.contract_id)";

pub const ALL_CONTRACTS_COUNT: &str = "
MATCH (c:Contract)
RETURN COUNT(c.contract_id)";

pub const CREATE_CONTRACT: &str = "
CREATE (c:Contract {
    contract_id: $contract_id,
    kind: $kind,
    name: $name,
    schema_ref: $schema_ref
})";

pub const GET_CONTRACT: &str = "
MATCH (c:Contract {contract_id: $contract_id})
RETURN c.contract_id, c.kind, c.name, c.schema_ref";

pub const ALL_CONTRACTS: &str = "
MATCH (c:Contract)
RETURN c.contract_id, c.kind, c.name, c.schema_ref";

pub const COVERED_CONTRACT_IDS: &str = "
MATCH (t:TestCase)-[:COVERS_CONTRACT]->(c:Contract)
RETURN DISTINCT c.contract_id";

// ===========================================================================
// Phase 10: Actor, Delegation, Approval, AuditEvent queries
// ===========================================================================

pub const CREATE_ACTOR: &str = "
CREATE (a:Actor {
    actor_id: $actor_id,
    kind: $kind,
    display_name: $display_name,
    external_refs_json: $external_refs_json
})
";

pub const GET_ACTOR: &str = "
MATCH (a:Actor {actor_id: $actor_id})
RETURN a.actor_id, a.kind, a.display_name, a.external_refs_json
";

pub const LIST_ACTORS: &str = "
MATCH (a:Actor)
RETURN a.actor_id, a.kind, a.display_name, a.external_refs_json
";

pub const CREATE_DELEGATION: &str = "
CREATE (d:Delegation {
    delegation_id: $delegation_id,
    principal: $principal,
    delegate_actor: $delegate_actor,
    scope_json: $scope_json,
    started_at: $started_at,
    ended_at: $ended_at
})
";

pub const DELEGATIONS_FOR_ACTOR: &str = "
MATCH (d:Delegation)
WHERE d.principal = $actor_id OR d.delegate_actor = $actor_id
RETURN d.delegation_id, d.principal, d.delegate_actor, d.scope_json, d.started_at, d.ended_at
";

pub const CREATE_APPROVAL: &str = "
CREATE (ap:Approval {
    approval_id: $approval_id,
    change_id: $change_id,
    approver: $approver,
    decision: $decision,
    reason: $reason,
    timestamp: $timestamp
})
";

pub const APPROVALS_FOR_CHANGE: &str = "
MATCH (ap:Approval)
WHERE ap.change_id = $change_id
RETURN ap.approval_id, ap.change_id, ap.approver, ap.decision, ap.reason, ap.timestamp
";

pub const CREATE_AUDIT_EVENT: &str = "
CREATE (ev:AuditEvent {
    event_id: $event_id,
    actor_id: $actor_id,
    action: $action,
    target_scope_json: $target_scope_json,
    timestamp: $timestamp,
    details: $details
})
";

pub const QUERY_AUDIT_EVENTS_ALL: &str = "
MATCH (ev:AuditEvent)
RETURN ev.event_id, ev.actor_id, ev.action, ev.target_scope_json, ev.timestamp, ev.details
ORDER BY ev.timestamp DESC
LIMIT $limit
";

pub const QUERY_AUDIT_EVENTS_BY_ACTOR: &str = "
MATCH (ev:AuditEvent)
WHERE ev.actor_id = $actor_id
RETURN ev.event_id, ev.actor_id, ev.action, ev.target_scope_json, ev.timestamp, ev.details
ORDER BY ev.timestamp DESC
LIMIT $limit
";

// ===========================================================================
// C2: Shallow tracked file queries
// ===========================================================================

pub const UPSERT_SHALLOW_FILE: &str = "
MERGE (s:ShallowFile {file_id: $file_id})
SET s.language_hint = $language_hint,
    s.declaration_count = $declaration_count,
    s.import_count = $import_count,
    s.syntax_hash = $syntax_hash,
    s.signature_hash = $signature_hash
";

pub const GET_SHALLOW_FILE: &str = "
MATCH (s:ShallowFile {file_id: $file_id})
RETURN s.file_id, s.language_hint, s.declaration_count, s.import_count, s.syntax_hash, s.signature_hash
";

pub const LIST_SHALLOW_FILES: &str = "
MATCH (s:ShallowFile)
RETURN s.file_id, s.language_hint, s.declaration_count, s.import_count, s.syntax_hash, s.signature_hash
";

pub const DELETE_SHALLOW_FILE: &str = "
MATCH (s:ShallowFile {file_id: $file_id})
DELETE s
";
