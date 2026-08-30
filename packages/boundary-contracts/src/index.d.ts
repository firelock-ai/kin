export interface CommandValidationResult {
  ok: boolean;
  errors: string[];
}

export declare function loadSchema(name: string): Promise<unknown>;
export declare function loadAllSchemas(): Promise<Record<string, unknown>>;
export declare function validateContract(name: string, payload: unknown): Promise<CommandValidationResult>;
export declare function assertContract(name: string, payload: unknown): Promise<void>;

export type RepoScopedSemanticToolName =
  | "semantic_locate"
  | "get_context_pack"
  | "trace_data_flow";

export type RepoScopedSemanticBudgetArguments =
  | { max_chars?: number; max_response_chars?: never }
  | { max_chars?: never; max_response_chars?: number };

export type RepoScopedSemanticLocateArguments = RepoScopedSemanticBudgetArguments &
  ({ query: string; cursor?: string } | { query?: string; cursor: string }) & {
  queries?: string[];
  limit?: number;
  page_size?: number;
  cursor?: string;
  granularity?: "file" | "entity";
  include_snippet?: boolean;
  snippet_alias?: boolean;
  pipeline?: "fused";
  include_tests?: boolean;
  explain?: boolean;
  compact?: boolean;
};

export type RepoScopedContextPackArguments = RepoScopedSemanticBudgetArguments & {
  entity_id: string;
  token_budget?: number;
  depth?: number;
  include_traffic?: false;
  compact?: boolean;
};

export type RepoScopedTraceDataFlowArguments = RepoScopedSemanticBudgetArguments & {
  focal: string;
  depth?: number;
  direction?: "calls" | "callers" | "both";
  limit_per_step?: number;
  target?: string;
  include_body?: boolean;
  compact?: boolean;
  include_type_edges?: boolean;
};

export type RepoScopedSemanticToolCall =
  | {
      schema_version: 1;
      name: "semantic_locate";
      arguments: RepoScopedSemanticLocateArguments;
    }
  | {
      schema_version: 1;
      name: "get_context_pack";
      arguments: RepoScopedContextPackArguments;
    }
  | {
      schema_version: 1;
      name: "trace_data_flow";
      arguments: RepoScopedTraceDataFlowArguments;
    };

export interface RepoScopedSemanticAuthority {
  repo_id: string;
  /**
   * Opaque 64-hex identity of the publication that answered. Equality is the
   * only comparison it supports; it deliberately does not order.
   */
  snapshot_identity: string;
  graph_root: string;
  selected_change_id: string;
}

export interface RepoScopedSemanticTextContent {
  type: "text";
  text: string;
}

export interface RepoScopedSemanticToolResult {
  content: RepoScopedSemanticTextContent[];
  isError?: boolean;
}

export interface RepoScopedSemanticToolResponse {
  schema_version: 1;
  capability: "repo_scoped_semantic_tools_v1";
  repository: RepoScopedSemanticAuthority;
  name: RepoScopedSemanticToolName;
  result: RepoScopedSemanticToolResult;
}

export type RepoScopedSemanticToolErrorCode =
  | "authentication_required"
  | "invalid_semantic_tool_call"
  | "invalid_repository_id"
  | "repo_not_served"
  | "repo_not_ingested"
  | "repo_semantic_unready"
  | "repo_authority_unavailable"
  | "hosted_authority_required"
  | "invalid_cursor"
  | "cursor_repository_mismatch"
  | "cursor_stale"
  | "cursor_unavailable"
  | "cursor_encoding_failed"
  | "trace_response_invalid";

export interface RepoScopedSemanticToolError {
  schema_version: 1;
  capability: "repo_scoped_semantic_tools_v1";
  error: {
    code: RepoScopedSemanticToolErrorCode;
    message: string;
    repo_id: string;
    retryable: boolean;
  };
}

export type ActorKind = "human" | "agent" | "system";
export type EvidenceStatus = "complete" | "partial" | "missing";
export type ReviewRisk = "low" | "medium" | "high";
export type ReviewAuthority = "graph" | "overlay";
export type ReviewPlane = "repo-local" | "hosted-managed";
export type ReviewProvenance = "graph" | "overlay" | "system-generated";
export type ReviewLifecycle = "authoritative" | "migration-only";
export type ReviewDecisionState = "pending" | "approved" | "needs-work" | "blocked";
export type ReviewCompletionState = "in-review" | "ready" | "blocked";
export type ReviewDiscussionState = "open" | "resolved";
export type ReviewFileStatus = "added" | "modified" | "deleted" | "renamed" | "untracked" | "unknown";
export type ReviewSource = "system" | "user";
export type ReviewScopeType = "entity" | "module" | "work-item";
export type SurfaceDiscoveryKind =
  | "rust-workspace"
  | "manifest"
  | "brownfield"
  | "fallback-root"
  | "loading";
export type SurfaceTruthCompleteness = "structured" | "partial" | "minimal";

export interface ReviewRepositoryRef {
  repoId: string;
  repoLabel: string;
  defaultBranch: string | null;
  visibility?: "private" | "public";
}

export interface ReviewChangedFile {
  path: string;
  status: ReviewFileStatus;
}

export interface ReviewChangeContext {
  baselineRef: string | null;
  headRef: string | null;
  changedFiles: ReviewChangedFile[];
}

export interface ReviewAssignment {
  reviewer: string;
  status: "assigned" | "completed";
  assignedAt: string;
  assignedBy: string;
  actorKind: ActorKind;
  completedAt?: string;
  completedBy?: string;
  completedByKind?: ActorKind;
  decidedAt?: string;
  decisionState?: ReviewDecisionState;
}

export interface ReviewDecision {
  state: ReviewDecisionState;
  summary: string;
  decidedBy?: string;
  decidedByKind?: ActorKind;
  decidedAt?: string;
}

export interface ReviewNote {
  id: string;
  author: string;
  authorKind: ActorKind;
  body: string;
  createdAt: string;
}

export interface ReviewDiscussionComment {
  id: string;
  author: string;
  authorKind: ActorKind;
  body: string;
  createdAt: string;
}

export interface ReviewDiscussionThread {
  id: string;
  filePath: string;
  line?: number;
  state: ReviewDiscussionState;
  createdAt: string;
  updatedAt: string;
  createdBy?: string;
  createdByKind?: ActorKind;
  resolvedAt?: string;
  resolvedBy?: string;
  comments: ReviewDiscussionComment[];
}

export interface ReviewQueueItem {
  id: string;
  domainId: string;
  title: string;
  domain: string;
  scope: string;
  summary: string;
  changedEntities: number;
  activeAgents: number;
  evidenceStatus: EvidenceStatus;
  risk: ReviewRisk;
  decisionState: ReviewDecisionState;
  completionState?: ReviewCompletionState;
  completionSummary?: string;
  assignedReviewers?: ReviewAssignment[];
  source?: ReviewSource;
  authority?: ReviewAuthority;
  plane?: ReviewPlane;
  provenance?: ReviewProvenance;
  lifecycle?: ReviewLifecycle;
  repository?: ReviewRepositoryRef;
}

export interface ReviewFileDiff {
  path: string;
  status: ReviewFileStatus;
  baselineRef: string | null;
  headRef: string | null;
  patch: string | null;
  truncated: boolean;
}

export interface ReviewDecisionRequest {
  state: Exclude<ReviewDecisionState, "pending">;
  summary: string;
  actor?: string;
  actorKind?: ActorKind;
}

export interface ReviewAssignmentRequest {
  reviewers: string[];
  actor?: string;
  actorKind?: ActorKind;
}

export interface ReviewNoteCreateRequest {
  body: string;
  author?: string;
  authorKind?: ActorKind;
}

export interface ReviewDiscussionCreateRequest {
  filePath: string;
  line?: number;
  body: string;
  author?: string;
  authorKind?: ActorKind;
}

export interface ReviewDiscussionReplyCreateRequest {
  body: string;
  author?: string;
  authorKind?: ActorKind;
}

export interface ReviewDiscussionStateRequest {
  state: ReviewDiscussionState;
  actor?: string;
  actorKind?: ActorKind;
}

export interface ReviewScope {
  type: ReviewScopeType;
  entityIds: string[];
}

export interface CreateReviewRequest {
  repoId?: string;
  title: string;
  description: string;
  scope: ReviewScope;
  requestedReviewers?: string[];
  createdBy?: string;
  createdByKind?: ActorKind;
}

export interface ReviewQueueResponse {
  items: ReviewQueueItem[];
}

export interface ReviewFileDiffResponse {
  diff: ReviewFileDiff;
}

export interface ProjectedFileEntry {
  path: string;
  kind: "source" | "manifest" | "test" | "config" | "doc" | "file";
}

export interface SearchResult {
  id: string;
  domainId: string;
  title: string;
  kind: "entity" | "contract" | "work-item" | "memory" | "derived-insight";
  domain: string;
  scope: string;
  summary: string;
  why: string;
  score: number;
}

export interface BlobEntityAnnotation {
  id: string;
  name: string;
  kind: string;
  startByte: number;
  endByte: number;
  startLine: number;
  endLine: number;
  signature: string;
  relationCount: number;
  coverageStatus: "verified" | "partial" | "missing" | "unknown";
  domain: string;
}

export interface SearchResponse {
  query: string;
  results: SearchResult[];
}

export interface SemanticDiffEntityChange {
  field: string;
  old: string | null;
  new: string | null;
}

export interface SemanticDiffEntity {
  id: string;
  name: string;
  kind: string;
  changeType: "added" | "modified" | "removed";
  riskLevel: "low" | "medium" | "high";
  changes: SemanticDiffEntityChange[];
}

export interface SemanticDiffResponse {
  entities: SemanticDiffEntity[];
}

export interface EntityChange {
  name: string;
  kind: string;
  riskLevel: "low" | "medium" | "high";
  beforeSignature?: string;
  afterSignature?: string;
}

export interface SemanticChangeSet {
  added: EntityChange[];
  modified: EntityChange[];
  removed: EntityChange[];
}

export interface CrossRepoImpact {
  repoId: string;
  repoName: string;
  entityName: string;
  entityKind: string;
  impactType: "direct" | "transitive";
}

export interface RepositoryRef {
  repoId: string;
  repoLabel: string;
  defaultBranch: string | null;
  visibility?: RepoVisibility;
}

export type RepoVisibility = "private" | "public";
export type RepoRefKind = "head" | "branch" | "remote" | "tag";
export type NativeRemoteDivergenceState = "unknown" | "unpublished" | "in-sync" | "ahead" | "behind" | "diverged";

export interface RepoProtectionViolation {
  ruleId: string;
  targetKind: "branch" | "tag" | "environment" | "release-gate";
  targetName?: string | null;
  message: string;
}

export interface RepoHistoryCommit {
  commitId: string;
  shortCommitId: string;
  author: string;
  authoredAt: string;
  subject: string;
}

export interface RepoHistory {
  repository: RepositoryRef;
  branchName: string | null;
  baselineRef: string | null;
  headRef: string | null;
  commits: RepoHistoryCommit[];
}

export interface RepoHistoryResponse {
  history: RepoHistory;
}

export interface RepoBlob {
  path: string;
  kind: ProjectedFileEntry["kind"];
  source: "ref" | "working-tree";
  requestedRef: string | null;
  resolvedRef: string | null;
  content: string;
  lineCount: number;
  truncated: boolean;
  language: string;
  entities: BlobEntityAnnotation[];
}

export interface RepoBlobResponse {
  blob: RepoBlob;
}

export interface RepoFilesResponse {
  repository: RepositoryRef;
  files: ProjectedFileEntry[];
}

export interface RepoCompare {
  repository: RepositoryRef;
  requestedBaseRef: string;
  requestedHeadRef: string;
  baseRef: string;
  headRef: string;
  mergeBaseRef: string | null;
  aheadBy: number;
  behindBy: number;
  files: ReviewChangedFile[];
}

export interface RepoCompareResponse {
  compare: RepoCompare;
}

export interface RepoRefSummary {
  name: string;
  shortName: string;
  kind: RepoRefKind;
  commitId: string;
  shortCommitId: string;
  isHead: boolean;
  isDefaultBranch: boolean;
}

export interface RepoRefs {
  repository: RepositoryRef;
  branchName: string | null;
  defaultBranch: string | null;
  headRef: string | null;
  refs: RepoRefSummary[];
}

export interface RepoRefsResponse {
  refs: RepoRefs;
}

export interface RepoSnapshotFile {
  path: string;
  kind: ProjectedFileEntry["kind"];
  content: string;
}

export interface RepoSnapshotResponse {
  repository: RepositoryRef;
  files: RepoSnapshotFile[];
}

export interface DomainFileContent {
  path: string;
  kind: ProjectedFileEntry["kind"];
  content: string;
  lineCount: number;
  truncated: boolean;
}

export interface DomainFileContentResponse {
  file: DomainFileContent | null;
}

export interface NativeRemoteTarget {
  repoId: string;
  repoLabel: string;
  remoteName: string;
  defaultBranch: string | null;
  transport: string | null;
  url: string | null;
  publishReviewStateDefault: boolean;
  publishProofsDefault: boolean;
}

export interface NativeRemotePublishEvent {
  id: string;
  branchName: string;
  localHead: string;
  previousRemoteHead: string | null;
  publishedAt: string;
  publishedBy: string;
  publishReviewState: boolean;
  publishProofs: boolean;
}

export interface NativeRemotePublishPlan {
  branchName: string | null;
  localHead: string | null;
  approvedHead: boolean | null;
}

export interface NativeRemoteStatus {
  repoId: string;
  remoteName: string;
  branchName: string | null;
  localHead: string | null;
  remoteHead: string | null;
  divergenceState: NativeRemoteDivergenceState;
  publishedAt?: string;
  publishedBy?: string;
  publishCount: number;
  publishReviewState: boolean;
  publishProofs: boolean;
  history: NativeRemotePublishEvent[];
}

export interface NativeRemoteStatusResponse {
  remote: NativeRemoteStatus;
}

export interface NativeRemotePublishRequest {
  branchName: string;
  localHead: string;
  expectedRemoteHead?: string | null;
  approved: boolean;
  publishReviewState: boolean;
  publishProofs: boolean;
  actor?: string;
  actorKind?: ActorKind;
  leaseSessionId?: string;
  leaseFenceEpoch?: number;
}

/**
 * Repository-v6 native transfer is a separate, strict authority protocol.
 * Embedded semantic-change and Git-object payloads retain the canonical Rust
 * model JSON shape and are independently decoded and verified by the daemon.
 */
export interface RepositoryTransferRefName {
  bytes_hex: string;
}

export type RepositoryTransferRefTarget =
  | { type: "change"; change_id: string }
  | {
      type: "external_object";
      object: {
        kind: "commit" | "tree" | "blob" | "tag";
        oid:
          | { algorithm: "sha1"; bytes: number[] }
          | { algorithm: "sha256"; bytes: number[] };
      };
    }
  | { type: "symbolic"; target: RepositoryTransferRefName };

export interface RepositoryTransferAuthorityRoot {
  version: number;
  hash: string;
}

export interface RepositoryTransferRootBundle {
  version: number;
  generation: number;
  history: RepositoryTransferAuthorityRoot;
  ref_state: RepositoryTransferAuthorityRoot;
  ref_log: RepositoryTransferAuthorityRoot;
  collaboration: RepositoryTransferAuthorityRoot;
  replication: RepositoryTransferAuthorityRoot;
  local_state: RepositoryTransferAuthorityRoot;
}

export interface RepositoryTransferLimits {
  max_changes: number;
  max_trees: number;
  max_bodies: number;
  max_external_objects: number;
  max_aliases: number;
  max_decoded_body_bytes: number;
  max_single_body_bytes: number;
}

export interface RepositoryTransferStatus {
  schema_version: 4;
  protocol: "kin-repository-v6-fast-forward";
  repository_id: string;
  destination_ref: RepositoryTransferRefName;
  destination_target: RepositoryTransferRefTarget | null;
  destination_head: string | null;
  destination_tree_hash: string | null;
  roots: RepositoryTransferRootBundle;
  default_ref: RepositoryTransferRefName | null;
  git_authority_hash: string | null;
  supported_features: string[];
  limits: RepositoryTransferLimits;
  push_apply_ready: boolean;
  bounded_envelope_export_ready: boolean;
  pull_apply_ready: boolean;
}

/** One advertised ref and the change it resolves to. */
export interface RepositoryRefAdvertisementEntry {
  name: RepositoryTransferRefName;
  target: RepositoryTransferRefTarget;
  head: string;
}

/**
 * What a repository publishes before any history moves.
 *
 * A clone starts here: it has no ref of its own to ask about yet, so it cannot
 * use the per-ref transfer status, and it needs the default ref before it can
 * initialize a replica that adopts the remote layout. An unborn repository
 * publishes a `default_ref` that is absent from `refs`, which a clone must
 * reproduce rather than treat as an error.
 */
export interface RepositoryRefAdvertisement {
  schema_version: 4;
  protocol: "kin-repository-v6-fast-forward";
  repository_id: string;
  refs: RepositoryRefAdvertisementEntry[];
  default_ref: RepositoryTransferRefName | null;
  roots: RepositoryTransferRootBundle;
  supported_features: string[];
  limits: RepositoryTransferLimits;
}

/**
 * What a sender must satisfy for the receiver to admit its pack.
 *
 * Derived from a transfer status by bounding the peer's declared limits with
 * the local ones, so neither side can be made to build an envelope the other
 * would refuse. It travels as the `expectation` member of an export request.
 */
export interface RepositoryTransferExpectation {
  repository_id: string;
  destination_ref: RepositoryTransferRefName;
  destination_target: RepositoryTransferRefTarget | null;
  destination_head: string | null;
  roots: RepositoryTransferRootBundle;
  default_ref: RepositoryTransferRefName | null;
  git_authority_hash: string | null;
  supported_features: string[];
  limits: RepositoryTransferLimits;
}

export interface RepositoryTransferBody {
  hash: string;
  byte_len: number;
  bytes_base64: string;
}

export interface RepositoryTransferPack {
  schema_version: 4;
  protocol: "kin-repository-v6-fast-forward";
  transfer_id: string;
  operation_id: string;
  repository_id: string;
  source_ref: RepositoryTransferRefName;
  destination_ref: RepositoryTransferRefName;
  /** The exact head this one pack publishes. */
  source_head: string;
  /**
   * The head the whole transfer is moving toward. Equal to `source_head` on a
   * single-pack transfer and on the last pack of a continuation; an earlier
   * exact ancestor of it on every pack before that.
   */
  transfer_target_head: string;
  source_tree_hash: string;
  expected_destination_target: RepositoryTransferRefTarget | null;
  expected_destination_head: string | null;
  expected_destination_roots: RepositoryTransferRootBundle;
  expected_destination_default_ref: RepositoryTransferRefName | null;
  source_git_authority_hash: string | null;
  expected_destination_git_authority_hash: string | null;
  /**
   * The imported-Git authority this pack ESTABLISHES on a destination that has
   * none. Present only for a bootstrap, which is the one case where the two
   * replicas' Git authority may differ; `null` on every ordinary fast-forward,
   * where the two hashes above must already be equal.
   */
  git_authority_bootstrap: Record<string, unknown> | null;
  required_features: string[];
  changes: Record<string, unknown>[];
  trees: Array<{ change_id: string; tree_hash: string }>;
  external_objects: Record<string, unknown>[];
  aliases: Record<string, unknown>[];
  bodies: RepositoryTransferBody[];
}

export interface RepositoryTransferReceipt {
  schema_version: 4;
  protocol: "kin-repository-v6-fast-forward";
  transfer_id: string;
  repository_id: string;
  destination_ref: RepositoryTransferRefName;
  destination_head: string;
  outcome: "committed" | "idempotent_replay";
  authority_receipt: Record<string, unknown> & {
    operation_id: string;
    repository_id: string;
    transaction_hash: string;
    outcome: "committed" | "idempotent_replay";
    generation: number;
    roots_before: RepositoryTransferRootBundle;
    roots_after: RepositoryTransferRootBundle;
  };
}

/**
 * One leaf of the hosted repository-v6 transfer seam, as the contract declares
 * it. `requestKeys` is the exact top-level key set of the request body, and
 * `responseKeys` the exact top-level key set the client deserializes.
 */
export interface HostedRepositoryTransferLeaf {
  leaf: "advertise" | "status" | "export" | "receive";
  method: "GET" | "POST";
  requestKeys: string[];
  responseKeys: string[];
}

export interface HostedRepositoryTransferRefusal {
  status: number;
  reason: string;
}

/**
 * The hosted transfer seam a `kin push` and a `kin pull` address, and the one
 * KinLab serves. Read it rather than spelling the route or the envelope keys
 * again.
 */
export interface HostedRepositoryTransferSeam {
  protocol: "kin-repository-v6-fast-forward";
  schemaVersion: 4;
  routeTemplate: string;
  authorizationScheme: "Bearer";
  orgScoped: true;
  leaves: HostedRepositoryTransferLeaf[];
  expectationKeys: string[];
  limitsKeys: string[];
  refusals: HostedRepositoryTransferRefusal[];
}

export declare function hostedRepositoryTransferSeam(): Promise<HostedRepositoryTransferSeam>;
export declare function hostedRepositoryTransferLeaf(
  leaf: string
): Promise<HostedRepositoryTransferLeaf>;
export declare function hostedRepositoryTransferPath(
  orgId: string,
  repoId: string,
  leaf: string
): Promise<string>;

export interface RepositoryTransferPublishRequest {
  pack: RepositoryTransferPack;
  publishReviewState: boolean;
  publishProofs: boolean;
  actor?: string;
  actorKind?: ActorKind;
  leaseSessionId?: string;
  leaseFenceEpoch?: number;
}

export interface RepositoryTransferPublishResponse {
  remote: NativeRemoteStatus;
  receipt: RepositoryTransferReceipt;
}

export interface NativeRemotePublishApprovalRequiredConflict {
  kind: "approval-required";
  message: string;
  expectedRemoteHead: null;
}

export interface NativeRemotePublishDivergenceConflict {
  kind: "divergence";
  message: string;
  expectedRemoteHead: string | null;
}

export interface NativeRemotePublishLeaseInvalidConflict {
  kind: "lease-invalid";
  message: string;
  expectedRemoteHead: null;
  leaseSessionId: string | null;
  expectedFenceEpoch: number | null;
}

export interface NativeRemotePublishProtectionConflict {
  kind: "protection-rule";
  message: string;
  violations: RepoProtectionViolation[];
}

export type NativeRemotePublishConflict =
  | NativeRemotePublishApprovalRequiredConflict
  | NativeRemotePublishDivergenceConflict
  | NativeRemotePublishLeaseInvalidConflict
  | NativeRemotePublishProtectionConflict;

export interface NativeRemotePublishResponse {
  remote: NativeRemoteStatus;
  published: boolean;
  conflict: NativeRemotePublishConflict | null;
}

export interface GitExportPushRequest {
  remoteName: string;
  branchName?: string;
  remoteUrl?: string;
  actor?: string;
  actorKind?: ActorKind;
}

export interface GitExportPushFastForwardConflict {
  kind: "fast-forward-required";
  message: string;
}

export interface GitExportPushApprovalConflict {
  kind: "approval-required";
  message: string;
}

export interface GitExportPushSemanticStateConflict {
  kind: "semantic-state-required";
  message: string;
}

export interface GitExportPushExportFailedConflict {
  kind: "export-failed";
  message: string;
}

export interface GitExportPushPushFailedConflict {
  kind: "push-failed";
  message: string;
}

export interface GitExportPushProtectionConflict {
  kind: "protection-rule";
  message: string;
  violations: RepoProtectionViolation[];
}

export type GitExportPushConflict =
  | GitExportPushFastForwardConflict
  | GitExportPushApprovalConflict
  | GitExportPushSemanticStateConflict
  | GitExportPushExportFailedConflict
  | GitExportPushPushFailedConflict
  | GitExportPushProtectionConflict;

export interface GitExportPushResponse {
  pushed: boolean;
  branchName: string | null;
  remoteUrl: string | null;
  commitCount: number;
  conflict: GitExportPushConflict | null;
  output: string | null;
}

export interface RepoWorkActor {
  name: string;
  kind: ActorKind;
}

export interface RepoWorkExternalRef {
  system: string;
  identifier: string;
  url: string | null;
}

export type RepoWorkSummaryTracker = RepoWorkExternalRef;

export interface RepoWorkItemRelationship {
  repoId?: string;
  workId: string;
  kind: string;
  title: string;
  status: string;
}

export interface RepoWorkAnnotation {
  annotationId: string;
  kind: string;
  body: string;
  staleness: string;
  scopes: string[];
}

export interface RepoWorkLinkedReview {
  repoId?: string;
  reviewId: string;
  title: string;
  decisionState: ReviewDecisionState;
  completionState?: ReviewCompletionState;
  matchingFiles: string[];
}

export interface RepoWorkItemSummary {
  workId: string;
  kind: string;
  title: string;
  status: string;
  priority: string;
  createdAt: string | null;
  createdBy: RepoWorkActor | null;
  externalRefs: RepoWorkExternalRef[];
  tracker: RepoWorkSummaryTracker | null;
  trackerState: string | null;
  labels: string[];
  labelCount: number;
  milestone: string | null;
  assignees: RepoWorkActor[];
  assigneeCount: number;
  scopeCount: number;
  annotationCount: number;
  linkedReviewId: string | null;
  linkedReviewTitle: string | null;
}

export interface RepoWorkItemUpdateRequest {
  actor?: string;
  actorKind?: ActorKind;
  status?: string;
  assignees?: RepoWorkActor[];
}

export interface RepoWorkItemsResponse {
  repository: RepositoryRef;
  items: RepoWorkItemSummary[];
}

export interface RepoImportedWorkSummary {
  totalItems: number;
  activeItems: number;
  completedItems: number;
  issueCount: number;
  pullRequestCount: number;
  assignedItems: number;
  highPriorityItems: number;
  topLabels: string[];
  highlightedWorkId: string | null;
  highlightedTitle: string | null;
  highlightedKind: string | null;
  highlightedStatus: string | null;
  highlightedMilestone: string | null;
}
