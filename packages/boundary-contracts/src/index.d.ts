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
