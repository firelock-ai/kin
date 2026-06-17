export interface CommandValidationResult {
  ok: boolean;
  errors: string[];
}

export declare function loadSchema(name: string): Promise<unknown>;
export declare function loadAllSchemas(): Promise<Record<string, unknown>>;
export declare function validateContract(name: string, payload: unknown): Promise<CommandValidationResult>;
export declare function assertContract(name: string, payload: unknown): Promise<void>;

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
  semanticChanges?: Record<string, unknown>[];
  actor?: string;
  actorKind?: ActorKind;
  leaseSessionId?: string;
  leaseFenceEpoch?: number;
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
