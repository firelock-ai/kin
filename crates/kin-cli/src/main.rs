// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{self, Shell};
use kin_cli::commands;
use std::path::PathBuf;
use tracing::Instrument;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

kin_buildinfo::embed_update_build_identity!(
    KIN_UPDATE_BUILD_IDENTITY,
    env!("CARGO_PKG_VERSION"),
    kin_db::GraphSnapshot::CURRENT_VERSION
);

#[derive(Parser)]
#[command(name = "kin", version = kin_buildinfo::version(), about = "Kin semantic VCS")]
struct Cli {
    /// Write a machine-readable execution profile to this JSON file
    #[arg(long, global = true, value_name = "FILE")]
    profile_out: Option<PathBuf>,

    /// Print the hottest profiled stages to stderr after the command finishes
    #[arg(long, global = true, default_value_t = false)]
    profile_summary: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show which Git-replacement commands are ready on repository-v6
    Capabilities {
        /// Output the versioned capability inventory as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Initialize a new Kin repository
    Init {
        /// Directory to initialize (defaults to current directory)
        path: Option<String>,
        /// Output machine-readable JSON status instead of human text
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show coherent repository-v6 workspace status
    Status {
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// [OPEN GATE] Create an exact semantic and artifact commit
    Commit {
        /// Commit message
        #[arg(short, long)]
        message: String,
        /// Suppress progress output (only print final summary)
        #[arg(short, long)]
        quiet: bool,
        /// Run the full pipeline but do not save the snapshot or update branch head
        #[arg(long)]
        dry_run: bool,
    },
    /// [OPEN GATE] Show the repository-v6 change log
    Log {
        /// Maximum number of entries
        #[arg(short = 'n', long, default_value = "10")]
        count: usize,
    },
    /// Repository-v6 branch operations (see subcommand readiness)
    Branch {
        #[command(subcommand)]
        action: BranchAction,
    },
    /// [OPEN GATE] Show exact artifact and semantic changes between refs
    Diff {
        /// Base change ID
        base: Option<String>,
        /// Head change ID
        head: Option<String>,
    },
    /// [OPEN GATE] Verify the graph-derived projection and detach Kin.
    ///
    /// The acceptance gate requires every graph-owned artifact and blob to
    /// match one durable projection generation before metadata can be detached.
    /// Until that executor lands, this command fails before repository discovery.
    Eject {
        /// Skip the typed "eject" confirmation.
        #[arg(long)]
        yes: bool,
        /// Permanently delete the detached metadata archive after the atomic move.
        #[arg(long, requires = "yes")]
        purge_metadata: bool,
    },
    /// Show downstream impact of an entity
    Impact {
        /// Entity name or ID
        entity: String,
        /// Maximum depth
        #[arg(short, long, default_value = "3")]
        depth: u32,
        /// Exact repo-relative file qualifier for stable identity resolution
        #[arg(long)]
        file: Option<String>,
        /// Exact entity-kind qualifier (for example: function or method)
        #[arg(long)]
        kind: Option<String>,
        /// Whitespace-normalized declaration signature for overload resolution
        #[arg(long)]
        signature: Option<String>,
        /// Emit the ranked graph-evidence report as JSON; ambiguous identities fail closed
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Build a context pack for an entity
    Context {
        /// Entity name or ID
        entity: String,
        /// Token budget (8k, 16k, 32k, or custom number)
        #[arg(short, long, default_value = "8k")]
        budget: String,
        /// Assistant hint for tuning context pack strategy
        #[arg(long)]
        assistant: Option<String>,
    },
    /// Hidden ContextBench locate wrapper that keeps benchmark query shaping inside Kin
    #[command(hide = true)]
    ContextbenchLocate {
        /// Path to the raw ContextBench task payload JSON
        #[arg(long)]
        task_file: PathBuf,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Persist the full locate debug payload and per-file signal/score breakdowns
        #[arg(long, default_value_t = false)]
        debug: bool,
    },
    /// Trace a focal entity in one shot: resolve it, show the body, and summarize nearby context
    Trace {
        /// Entity name or ID
        entity: String,
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Render a smaller, cheaper trace tuned for assistant workflows
        #[arg(long, default_value_t = false)]
        compact: bool,
        /// Compatibility no-op: trace already shows the focal body by default
        #[arg(long, hide = true, default_value_t = false)]
        show_body: bool,
        /// Compatibility alias: interpreted as the nearby entry cap when provided
        #[arg(long, hide = true)]
        limit: Option<usize>,
        /// Token budget (8k, 16k, 32k, or custom number)
        #[arg(short, long, default_value = "8k")]
        budget: String,
        /// Assistant hint for tuning context pack strategy
        #[arg(long)]
        assistant: Option<String>,
        /// Max lines to print for any single source snippet
        #[arg(long, default_value_t = 40)]
        max_lines: usize,
        /// Max nearby entries to print
        #[arg(long, default_value_t = 4)]
        nearby: usize,
        /// Max transitive entries to print
        #[arg(long, default_value_t = 2)]
        transitive: usize,
    },
    /// Search entities in the graph
    Search {
        /// Search pattern (use '|' for OR, e.g. "save|load|persist")
        pattern: String,
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Filter by entity kind
        #[arg(short, long)]
        kind: Option<String>,
        /// Filter by language
        #[arg(short, long)]
        language: Option<String>,
        /// Show entity source body inline
        #[arg(long)]
        show_body: bool,
        /// Max lines per entity body (with --show-body)
        #[arg(long)]
        limit: Option<usize>,
        /// Use semantic (vector similarity) search instead of name matching
        #[arg(long)]
        semantic: bool,
    },
    /// Set, show, or clear a temporal scope for the current session
    Scope {
        /// Ref to scope to (git:sha, branch name, HEAD~N, etc.)
        ref_string: Option<String>,
        /// Clear the current scope
        #[arg(long)]
        clear: bool,
        /// Show the current scope
        #[arg(long)]
        show: bool,
        /// Session ID (or set KIN_SESSION_ID env var)
        #[arg(long)]
        session: Option<String>,
    },
    /// Locate files relevant to an issue or problem description
    Locate {
        /// Problem text (inline)
        text: Option<String>,
        /// Additional query variant(s) for multi-query fan-out (repeatable).
        /// The primary text plus each variant are retrieved independently and
        /// their rankings RRF-fused into one deduped result. Diverse variants
        /// (identifiers, behavior, subsystem) recover more relevant files than
        /// any single phrasing. Omit for a normal single-query locate.
        #[arg(long = "query", value_name = "QUERY")]
        query: Vec<String>,
        /// Read problem text from file
        #[arg(long)]
        file: Option<String>,
        /// Read from stdin
        #[arg(long)]
        stdin: bool,
        /// Output JSON
        #[arg(long)]
        json: bool,
        /// Include graph-native projection reasons in the output
        #[arg(long, default_value_t = false)]
        explain: bool,
        /// Diagnostic mode: enables --json --explain, adds per-stage scoring
        /// detail, entity seed dump, and timing breakdown. Compares against
        /// --gold files if provided. Use this for debugging locate quality.
        #[arg(long, default_value_t = false)]
        diagnose: bool,
        /// Gold file paths for diagnostic comparison (comma-separated).
        /// With --diagnose, shows where each gold file appears/disappears
        /// in the scoring pipeline and why.
        #[arg(long, value_delimiter = ',')]
        gold: Vec<String>,
        /// Max files to return (omit for adaptive sizing)
        #[arg(long)]
        max_files: Option<usize>,
        /// Resolve locate against a specific ref.
        /// Accepts `HEAD`, `HEAD~N`, branch names, `branch:<name>`,
        /// imported Git commits as `git:<sha>` or bare 40-hex SHAs,
        /// and semantic changes as `kin:<id>`, `change:<id>`, or bare change IDs.
        #[arg(long = "ref", value_name = "REF")]
        reference: Option<String>,
        /// Attach a bounded inline source snippet (signature + first body lines)
        /// to each top definition symbol. Default ON for `--json` (the agent
        /// surface), so an agent can act on the first locate without a follow-up
        /// read; force it on for any output with this flag.
        #[arg(long)]
        snippets: bool,
        /// Suppress inline snippets even on the `--json` surface.
        #[arg(long = "no-snippets", conflicts_with = "snippets")]
        no_snippets: bool,
        /// Fetch the NEXT page of ranked entities from the previous query,
        /// reading the cursor persisted in `.kin/locate-cursor`. No retrieval
        /// re-run; pages the daemon's cached ranking. Query text is not required.
        #[arg(long, conflicts_with = "cursor")]
        next: bool,
        /// Fetch a specific entity page using an explicit cursor token (from a
        /// prior result's `next_cursor`). Lower-level alternative to `--next`.
        #[arg(long)]
        cursor: Option<String>,
        /// Entities per page for the graph-native `entities` surface
        /// (`KIN_LOCATE_ENTITY_CAP` otherwise).
        #[arg(long)]
        page_size: Option<usize>,
    },
    /// Debug locate results: show per-signal breakdown, rank gold files,
    /// and diagnose why targets were missed.
    #[command(name = "locate-debug")]
    LocateDebug {
        /// Problem text (inline query)
        #[arg(default_value = "")]
        text: String,
        /// Gold file to track (report rank and signal breakdown)
        #[arg(long)]
        target: Option<String>,
        /// Load query and gold files from a benchmark task JSON
        #[arg(long)]
        task_file: Option<String>,
        /// Max files to search (wider than default to find low-ranked targets)
        #[arg(long, default_value_t = 50)]
        max_files: usize,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Build embeddings for the current repository's entity graph.
    ///
    /// Generates vector embeddings for all entities using a local code retriever
    /// (nomic-embed-text-v1.5, 768 dimensions; override via KIN_EMBED_MODEL_ID).
    /// Embeddings enable semantic similarity
    /// search in `kin locate` and `kin search --semantic`.
    ///
    /// Repository admission and enrichment are separate: `kin init` commits
    /// repository authority; `kin embed` adds vectors for graph-owned entities
    /// after semantic enrichment exists.
    ///
    /// If a repo was indexed with an older model at a different dimension, pass
    /// `--rebuild` to drop the stale index and re-embed every entity at the
    /// current model's dimension.
    Embed {
        /// Embedding batch size (entities per inference pass). Defaults to 64, or
        /// the throughput resource plan's per-chunk budget when
        /// KIN_RESOURCE_PROFILE=throughput is set.
        #[arg(long)]
        batch_size: Option<usize>,
        /// Stop after this many seconds, persist completed vectors, and leave the rest pending.
        #[arg(long, value_name = "SECONDS")]
        max_seconds: Option<u64>,
        /// Drop the existing vector index and re-embed every entity at the current
        /// model's dimension. Use this to migrate a repo indexed with an older
        /// model (e.g. a 384-dim index that fails against the 768-dim default).
        #[arg(long, visible_alias = "force")]
        rebuild: bool,
        /// Output JSON status instead of progress text.
        #[arg(long)]
        json: bool,
    },
    /// [OPEN GATE] Build a semantic rename plan from graph and source-CAS truth
    Rename {
        /// Entity name or symbol under the cursor
        symbol: String,
        /// Replacement name
        new_name: String,
        /// File hint to disambiguate the target entity
        #[arg(long)]
        file: Option<String>,
        /// 1-based line hint to disambiguate the target entity
        #[arg(long)]
        line: Option<u32>,
        /// 0-based column hint to disambiguate the target entity
        #[arg(long)]
        column: Option<u32>,
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show upstream callers/importers/references for an entity
    Refs {
        /// Entity name or ID. Required unless --bulk-json + --entities is provided.
        #[arg(default_value = "")]
        entity: String,
        /// Filter relation kinds: all, calls, imports, or references (or Any for bulk mode)
        #[arg(long, default_value = "all")]
        kind: String,
        /// Bulk mode: classify many entities by reachability in one daemon call.
        /// Outputs JSON to stdout. Requires --entities.
        #[arg(long, default_value_t = false)]
        bulk_json: bool,
        /// Comma-separated entity UUIDs for --bulk-json. Required when --bulk-json is set.
        #[arg(long)]
        entities: Option<String>,
        /// If true (default) emit compact bulk-mode rows ({entity_id, has_references, reference_count}).
        /// Set --no-compact for verbose rows with name/kind/file_path/matched_kinds.
        #[arg(long, default_value_t = true)]
        compact: bool,
        /// Force verbose bulk-mode rows (overrides --compact). Required for clap to accept `--no-compact`.
        #[arg(long = "no-compact", default_value_t = false, action = clap::ArgAction::SetTrue)]
        no_compact: bool,
    },
    /// Run semantic review on changes, or manage review state
    Review {
        /// Change ID to review (defaults to latest)
        change: Option<String>,
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Comma-separated entity IDs to review
        #[arg(long)]
        entities: Option<String>,
        /// Comma-separated file paths to review
        #[arg(long)]
        files: Option<String>,
        /// Comma-separated change IDs to combine into one review
        #[arg(long)]
        changes: Option<String>,
        /// Review mutation subcommand
        #[command(subcommand)]
        action: Option<ReviewAction>,
    },
    /// Show entity history
    History {
        /// Entity name or ID
        entity: String,
        /// Resolve history against a specific ref.
        /// Accepts `HEAD`, `HEAD~N`, branch names, `branch:<name>`,
        /// imported Git commits as `git:<sha>` or bare 40-hex SHAs,
        /// and semantic changes as `kin:<id>`, `change:<id>`, or bare change IDs.
        #[arg(long = "ref", value_name = "REF")]
        reference: Option<String>,
    },
    /// Find dead code (whole-repo scan, or seeded by semantic query)
    DeadCode {
        /// Seeded mode: run semantic_search(query) → classify each top-N
        /// candidate by incoming references → return dead-first ranked JSON.
        /// Closes the find-dead-code accuracy gap on large repos where
        /// the agent burns the tool-call cap looping search → find_references.
        #[arg(long = "seed", value_name = "QUERY")]
        seed: Option<String>,
        /// Max candidates to classify in seeded mode (default 20, max 200).
        /// Ignored when --seed is not set.
        #[arg(long = "limit", value_name = "N")]
        limit: Option<usize>,
        /// Optional case-insensitive substring filter on the candidate entity name.
        /// Lets callers pre-narrow to a known prefix or suffix (e.g., a planted-secret
        /// tag like "_eaca1f07") without burning extra tool-call rounds.
        #[arg(long = "name-pattern", value_name = "SUBSTRING")]
        name_pattern: Option<String>,
    },
    /// Trace the call/data-flow chain rooted at a focal entity.
    ///
    /// Returns the focal body plus a structured chain of callees, callers, or
    /// both (with bodies inlined) in a single substrate call. Closes the
    /// trace-computation accuracy gap where the agent loops `get_entity_source`
    /// per step and burns the 24-round tool-call cap.
    TraceDataFlow {
        /// Focal entity to start tracing from. Accepts a UUID or an exact
        /// entity name (resolved via the same ranking path as `graph source`).
        #[arg(long = "focal", value_name = "ENTITY")]
        focal: String,
        /// Maximum traversal depth from the focal (default 3, capped at 8).
        #[arg(long = "depth", value_name = "N")]
        depth: Option<usize>,
        /// Traversal direction: `calls`, `callers`, or `both` (default both).
        #[arg(long = "direction", value_name = "DIR")]
        direction: Option<String>,
        /// Max relations expanded per step (default 5, capped at 25).
        #[arg(long = "limit-per-step", value_name = "M")]
        limit_per_step: Option<usize>,
    },
    /// Show local cross-repo dependencies
    Deps,
    /// Show federated cross-repo references (xrefs) for an entity
    Xref {
        /// Entity name or ID
        entity: String,
    },
    /// Manage specs
    Spec {
        #[command(subcommand)]
        action: SpecAction,
    },
    /// [OPEN GATE] Merge semantic and exact-tree changes from another branch
    Merge {
        /// Branch to merge from
        branch: String,
        /// Merge strategy: structural or semantic
        #[arg(short, long, default_value = "structural")]
        strategy: String,
    },
    /// [OPEN GATE] Show repository-v6 merge conflicts
    Conflicts,
    /// [OPEN GATE] Resolve repository-v6 merge conflicts
    Resolve {
        /// Keep your (target branch) version of a conflicting entity
        #[arg(long, value_name = "ENTITY")]
        ours: Option<String>,
        /// Keep the incoming (source branch) version of a conflicting entity
        #[arg(long, value_name = "ENTITY")]
        theirs: Option<String>,
        /// Resolve all remaining conflicts keeping your version
        #[arg(long)]
        all_ours: bool,
        /// Resolve all remaining conflicts keeping the incoming version
        #[arg(long)]
        all_theirs: bool,
        /// Complete the merge after all conflicts are resolved
        #[arg(long, alias = "continue")]
        do_continue: bool,
        /// Abort the merge and discard conflict state
        #[arg(long)]
        abort: bool,
    },
    /// [OPEN GATE] Stash exact repository-v6 workspace state
    Stash {
        #[command(subcommand)]
        action: StashAction,
    },
    /// Show blame (version history) for an entity
    Blame {
        /// Entity name or ID
        entity: String,
        /// Resolve blame against a specific ref.
        /// Accepts `HEAD`, `HEAD~N`, branch names, `branch:<name>`,
        /// imported Git commits as `git:<sha>` or bare 40-hex SHAs,
        /// and semantic changes as `kin:<id>`, `change:<id>`, or bare change IDs.
        #[arg(long = "ref", value_name = "REF")]
        reference: Option<String>,
    },
    /// MCP server commands
    Mcp {
        #[command(subcommand)]
        action: McpAction,
    },
    /// Authenticate with KinLab for native remotes
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    /// Manage native and compatibility remotes
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },
    /// Package and upload crate(s) to the kin-daemon registry
    Publish {
        /// Package(s) to publish (can be repeated: -p foo -p bar)
        #[arg(short = 'p', long = "package")]
        packages: Vec<String>,
        /// Registry URL (default: http://localhost:4219, or KIN_REGISTRY_URL env var)
        #[arg(long, default_value = "http://localhost:4219")]
        registry: String,
        /// Don't actually publish, just package and show what would be uploaded
        #[arg(long)]
        dry_run: bool,
    },
    /// [OPEN GATE] Plan or prepare an exact publish to the default remote
    Push {
        /// Remote name (defaults to configured default or detected origin)
        #[arg(long)]
        remote: Option<String>,
    },
    /// [OPEN GATE] Pull exact changes from a remote
    #[command(visible_alias = "fetch")]
    Pull {
        /// Remote name (defaults to configured default)
        #[arg(long)]
        remote: Option<String>,
    },
    /// Clone a repository
    Clone {
        /// Git repository URL (native Kin transport is an explicit open gate)
        url: String,
        /// Target directory (defaults to repo name)
        path: Option<String>,
    },
    /// [OPEN GATE] Restore an artifact from an immutable repository-v6 tree
    Checkout {
        /// File path to restore
        path: String,
        /// Change ID (defaults to current branch head)
        #[arg(long)]
        change: Option<String>,
    },
    /// Verify test coverage for entities
    Verify {
        #[command(subcommand)]
        action: VerifyAction,
    },
    /// [OPEN GATE] Run a command in an exact graph-backed session workspace
    Exec {
        /// Command to run (put kin flags before it: `kin exec --keep -- npm test`)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
        /// Interpret the command through the platform shell instead of preserving argv boundaries
        #[arg(long)]
        shell: bool,
        /// Keep the session workspace after the run and defer reconcile
        #[arg(long)]
        keep: bool,
        /// Discard all workspace changes after the run (no reconcile)
        #[arg(long, conflicts_with = "keep")]
        discard: bool,
        /// Materialization strategy
        #[arg(long)]
        strategy: Option<String>,
        /// Scope filter
        #[arg(long)]
        scope: Option<String>,
    },
    /// Manage local telemetry consent and the spool
    Telemetry {
        #[command(subcommand)]
        action: TelemetryAction,
    },
    /// Show graph observability
    Support {
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Emit benchmark/runtime metadata for strict prepared-state cache keys
    #[command(hide = true)]
    BenchMeta {
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Include repo-specific prepared-state cache manifest fields
        #[arg(long, default_value_t = false, hide = true)]
        prepared_state: bool,
    },
    /// Hidden prepared-state publish/materialize surfaces for benchmark/runtime orchestration
    #[command(hide = true)]
    PreparedState {
        #[command(subcommand)]
        action: PreparedStateAction,
    },
    /// Show audit trail
    Audit {
        /// Filter by actor ID
        #[arg(long)]
        actor: Option<String>,
        /// Maximum number of events
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Filter by action type
        #[arg(long)]
        action: Option<String>,
        /// Filter events since date (ISO 8601)
        #[arg(long)]
        since: Option<String>,
        /// Filter by target scope
        #[arg(long)]
        scope: Option<String>,
    },
    /// Backup and restore graph snapshots
    Backup {
        #[command(subcommand)]
        action: BackupAction,
    },
    /// Manage change approvals
    Approvals {
        #[command(subcommand)]
        action: ApprovalsAction,
    },
    /// Scan entity graph for security patterns
    Security {
        /// Trace transitive dependency vulnerabilities
        #[arg(long)]
        propagate: bool,
    },
    /// [OPEN GATE] Analyze semver impact from immutable repository-v6 changes
    Semver,
    /// Cross-repo release orchestration and per-repo release snapshots
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    /// [OPEN GATE] Create a repository-v6 release snapshot
    Tag {
        /// Release tag
        tag: String,
        /// Block release if entities lack linked passing tests
        #[arg(long)]
        require_proof: bool,
        /// Require known-human approval for every reachable non-root change
        #[arg(long)]
        require_approval: bool,
        /// Force release even with low coverage
        #[arg(long)]
        force: bool,
    },
    /// [OPEN GATE] Commit an exact inverse of a previous change
    #[command(visible_alias = "revert")]
    Rollback {
        /// Change ID to rollback to
        change_id: String,
        /// Rollback all changes linked to a work item ID
        #[arg(long)]
        feature: Option<String>,
    },
    /// Run benchmarks (delegates to kin-bench binary)
    Bench {
        /// Arguments to forward to kin-bench
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Migrate an existing Git repository into graph-owned Kin truth
    Migrate {
        /// Source repository path (defaults to current directory)
        source: Option<String>,
        /// Distinct destination (defaults to an in-place migration)
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Inspect and bound the on-disk embedding cache
    Cache {
        #[command(subcommand)]
        action: CacheAction,
    },
    /// Inspect and validate the semantic graph
    Graph {
        #[command(subcommand)]
        action: GraphAction,
    },
    /// Git interop commands (currently fail-closed pending exact export)
    Git {
        #[command(subcommand)]
        action: GitAction,
    },
    /// Manage agent intents (locks on scopes)
    Intent {
        #[command(subcommand)]
        action: IntentAction,
    },
    /// Show traffic (active intents) on a scope
    Traffic {
        #[command(subcommand)]
        action: TrafficAction,
    },
    /// Manage assistant adapters
    Assistant {
        #[command(subcommand)]
        action: AssistantAction,
    },
    /// Manage work items (features, tasks, issues, debt, TODOs)
    Work {
        #[command(subcommand)]
        action: WorkAction,
    },
    /// Manage annotations (comments, warnings, instructions, reasoning)
    Note {
        #[command(subcommand)]
        action: NoteAction,
    },
    /// Create a feature (alias for `kin work create --kind feature`)
    Feature {
        /// Feature title
        title: String,
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Import inline TODOs as work items
    Todo {
        #[command(subcommand)]
        action: TodoAction,
    },
    /// [OPEN GATE] Launch an editor in an exact graph-derived session workspace
    Open {
        /// Editor to launch: code or cursor
        editor: String,
        /// In native mode, block filesystem discovery commands and require Kin discovery
        #[arg(long)]
        restrict_discovery: bool,
        /// In native mode, block both filesystem discovery and direct file reads
        #[arg(long, conflicts_with = "restrict_discovery")]
        restrict_filesystem: bool,
    },
    /// [OPEN GATE] Launch an assistant in a graph-derived session
    With {
        /// Assistant to launch: claude, codex, gemini
        assistant: String,
        /// Launch inside a graph-backed session workspace: the assistant starts
        /// with its cwd in the session, receives session/daemon env, and its
        /// changes reconcile into the graph on a successful exit
        #[arg(long)]
        session: bool,
        /// Pass the raw task only; keep AGENTS/bootstrap docs on disk but do not inject prompt guidance
        #[arg(long)]
        passive_guidance: bool,
        /// In native mode, block filesystem discovery commands and require Kin discovery
        #[arg(long)]
        restrict_discovery: bool,
        /// In native mode, block both filesystem discovery and direct file reads
        #[arg(long, conflicts_with = "restrict_discovery")]
        restrict_filesystem: bool,
        /// Task prompt
        #[arg(last = true)]
        task: Vec<String>,
    },
    /// [OPEN GATE] Admit explicit session deltas into repository-v6 authority
    Reconcile {
        /// Session ID (defaults to most recent session)
        session: Option<String>,
        /// Remove the session workspace after successful reconciliation
        #[arg(long)]
        cleanup: bool,
    },
    /// [OPEN GATE] Open a shell in an exact graph-derived session workspace
    Shell {
        /// Materialization strategy
        #[arg(long)]
        strategy: Option<String>,
        /// In native mode, block filesystem discovery commands and require Kin discovery
        #[arg(long)]
        restrict_discovery: bool,
        /// In native mode, block both filesystem discovery and direct file reads
        #[arg(long, conflicts_with = "restrict_discovery")]
        restrict_filesystem: bool,
    },
    /// Show a quick codebase overview (entity counts by kind, language, top files)
    Overview {
        /// Compact mode: only show counts, no entity listings
        #[arg(long)]
        compact: bool,
        /// Output all entities as JSON (for programmatic use)
        #[arg(long)]
        json: bool,
    },
    /// Generate shell completions for bash, zsh, or fish
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Update Kin to the latest release
    Update {
        /// Skip SHA-256 checksum verification (NOT recommended)
        #[arg(long, conflicts_with = "check_only")]
        skip_verify: bool,
        /// Release channel: `stable` (default) or `alpha` (latest pre-release,
        /// unstable). A mutating update saves the choice; check-only never writes it.
        #[arg(long, value_enum)]
        channel: Option<commands::update::Channel>,
        /// Require the selected release to have this exact SemVer. This selects
        /// a release; it does not authenticate archive bytes. Automation must
        /// provide the complete pinned expectation tuple.
        #[arg(
            long,
            requires_all = ["expect_sha", "expect_archive_sha256"],
            conflicts_with = "ack_restart",
            value_name = "SEMVER"
        )]
        expect_version: Option<semver::Version>,
        /// Require the selected release tag to peel to this exact Kin commit.
        /// This selects the tag source; it does not authenticate archive bytes.
        #[arg(
            long,
            requires_all = ["expect_version", "expect_archive_sha256"],
            conflicts_with = "ack_restart",
            value_parser = commands::update::parse_expected_commit_sha,
            value_name = "40HEX"
        )]
        expect_sha: Option<String>,
        /// Require the downloaded platform archive to match this exact SHA-256.
        /// Supply it only after external cryptographic attestation verification
        /// pins firelock-ai/kin, release.yml, the release tag, and source commit.
        #[arg(
            long,
            requires_all = ["expect_version", "expect_sha"],
            conflicts_with = "ack_restart",
            value_parser = commands::update::parse_expected_archive_sha256,
            value_name = "64HEX"
        )]
        expect_archive_sha256: Option<String>,
        /// Check whether an update is available without downloading or installing it.
        #[arg(long)]
        check_only: bool,
        /// Emit the check-only result as JSON.
        #[arg(long, requires = "check_only")]
        json: bool,
        /// Verify the durable restart fence and exact installed binary
        /// identities for the release awaiting acknowledgement. Legacy markers
        /// may additionally require explicit replacement-session evidence.
        #[arg(
            long,
            conflicts_with_all = [
                "skip_verify",
                "channel",
                "expect_version",
                "expect_sha",
                "expect_archive_sha256",
                "check_only",
                "json"
            ]
        )]
        ack_restart: bool,
        /// Legacy-marker live replacement proof: `daemon=PID`, `mcp=PID`, or
        /// `vfs=PID`. New stop-before-update markers reject these arguments and
        /// require no replacement session evidence.
        #[arg(
            long = "runtime-session",
            requires = "ack_restart",
            value_name = "KIND=PID"
        )]
        runtime_sessions: Vec<String>,
    },
    /// Show or manage the global Kin repository registry
    Registry {
        #[command(subcommand)]
        action: Option<RegistryAction>,
    },
    /// Inspect and gracefully stop Kin daemons
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Probe first-run health and optionally apply safe repairs
    Doctor {
        /// Apply safe automatic repairs (shell hook, MCP configs, config dirs)
        #[arg(long, default_value_t = false)]
        fix: bool,
        /// Emit the machine-readable health report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
        /// [OPEN GATE] Compare an explicit projection observation with graph truth
        #[arg(long, default_value_t = false)]
        drift: bool,
        /// [OPEN GATE] Rematerialize a projection from graph truth. Implies --drift
        #[arg(long, default_value_t = false)]
        heal: bool,
    },
    /// First-time setup and health checks for the Kin system
    Setup {
        #[command(subcommand)]
        action: Option<SetupAction>,
        /// First-run intent: local, agent, editor, hosted, or advanced
        #[arg(long, global = true, value_parser = ["local", "agent", "editor", "hosted", "advanced"])]
        intent: Option<String>,
        /// Repository mode: native or compatibility
        #[arg(long, global = true)]
        mode: Option<String>,
        /// Shell to configure: zsh, bash, or powershell
        #[arg(long, global = true)]
        shell: Option<String>,
        /// Auto-start kin-daemon when entering workspaces
        #[arg(long, global = true)]
        auto_daemon: bool,
        /// Run non-interactively using defaults or provided flags
        #[arg(long, global = true)]
        no_interactive: bool,
        /// Skip the wizard and only run the first-run health check
        #[arg(long, default_value_t = false)]
        check: bool,
    },
    /// Manage secrets (org and repo level)
    Secret {
        #[command(subcommand)]
        action: SecretAction,
    },
    /// Manage CI/CD pipelines
    Pipeline {
        #[command(subcommand)]
        action: PipelineAction,
    },
    /// Manage hosted releases
    #[command(name = "hosted-release")]
    HostedRelease {
        #[command(subcommand)]
        action: HostedReleaseAction,
    },
    /// Inspect host/accelerator/memory resources and per-profile budgets
    Resources {
        #[command(subcommand)]
        action: ResourcesAction,
    },
}

#[derive(Subcommand)]
enum ResourcesAction {
    /// Report the detected resource plan and live daemon embedding state
    Inspect {
        /// Output the stable JSON resource plan instead of a human summary
        #[arg(long)]
        json: bool,
        /// Resource profile to plan for: proof, interactive, throughput, or ci
        #[arg(long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum BranchAction {
    /// [OPEN GATE] List byte-exact repository-v6 refs
    List,
    /// [OPEN GATE] Create a ref with compare-and-swap
    Create {
        /// Branch name
        name: String,
    },
    /// [OPEN GATE] Delete a ref with force-with-lease
    Delete {
        /// Branch name
        name: String,
    },
    /// [OPEN GATE] Switch workspace authority and projection atomically
    Switch {
        /// Branch name
        name: String,
    },
}

#[derive(Subcommand)]
enum BackupAction {
    /// Create a backup of the current graph snapshot
    Create {
        /// Optional tag to label the backup
        #[arg(short, long)]
        tag: Option<String>,
    },
    /// List available backups
    List,
    /// Restore the graph from a backup
    Restore {
        /// Backup name (partial match supported)
        name: Option<String>,
        /// Restore from the most recent backup
        #[arg(long)]
        latest: bool,
    },
    /// Delete a specific backup
    Delete {
        /// Backup name (partial match supported)
        name: String,
    },
}

#[derive(Subcommand)]
enum PreparedStateAction {
    /// Publish the current repo's .kin state into a prepared-state directory
    Publish {
        /// Target prepared-state directory
        #[arg(long)]
        target: PathBuf,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Materialize a prepared-state directory into the current repo
    Materialize {
        /// Source prepared-state directory
        #[arg(long)]
        source: PathBuf,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SpecAction {
    /// Create a new spec
    Create {
        /// Spec intent description
        intent: String,
    },
    /// List specs
    List,
    /// Show a spec
    Show {
        /// Spec ID
        id: String,
    },
}

#[derive(Subcommand)]
enum GraphAction {
    /// Quick health check of the semantic graph
    Status,
    /// Structural integrity validation
    Validate,
    /// Look up an entity by name and show its relations
    Inspect {
        /// Entity name or UUID to inspect
        name: String,
        /// Output machine-readable JSON ({lines, error}); missing entities exit 0 with structured error.
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Print the exact implementation body for an entity
    Source {
        /// Entity name or ID
        entity: String,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Alias for source: print the exact implementation body for an entity
    Body {
        /// Entity name or ID
        entity: String,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Serve an interactive force-directed visualization of the semantic graph
    Viz {
        /// Port to bind the local HTTP server to
        #[arg(long, default_value_t = 4220)]
        port: u16,
        /// Open the visualization in the system default browser
        #[arg(long, default_value_t = false)]
        open: bool,
    },
}

#[derive(Subcommand)]
enum CacheAction {
    /// Report embedding-cache size, composition, and age distribution
    Status {
        /// Output machine-readable JSON instead of a human summary
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Reclaim space: drop abandoned schema versions and/or evict oldest entries to a budget
    Gc {
        /// Report what would be reclaimed without deleting anything
        #[arg(long)]
        dry_run: bool,
        /// Evict the oldest entries until the cache fits this many gigabytes.
        /// Overrides KIN_EMBED_CACHE_BUDGET_GB; unset means no budget eviction.
        #[arg(long, value_name = "GB")]
        budget_gb: Option<f64>,
        /// Also remove every abandoned (non-current) schema-version subtree
        #[arg(long)]
        prune_stale_schema: bool,
    },
}

#[derive(Subcommand)]
enum GitAction {
    /// [OPEN GATE] Export exact objects, refs, aliases, and source CAS to Git
    Export {
        /// Target directory
        #[arg(short, long)]
        output: Option<String>,
        /// Allow exporting directly into the checked-out Git working repository
        #[arg(long, default_value_t = false)]
        in_place: bool,
    },
}

#[derive(Subcommand)]
enum RemoteAction {
    /// List configured and detected remotes
    List,
    /// Add or update a configured remote
    Add {
        /// Remote name
        name: String,
        /// Host kind: github or kinlab
        #[arg(long)]
        host: String,
        /// Transport kind: git-export or native-kin
        #[arg(long)]
        transport: String,
        /// Optional remote URL or locator
        #[arg(long)]
        url: Option<String>,
        /// Publish review state to this remote
        #[arg(long, default_value_t = false)]
        publish_review_state: bool,
        /// Publish proofs to this remote
        #[arg(long, default_value_t = false)]
        publish_proofs: bool,
        /// Set as the default remote
        #[arg(long, default_value_t = false)]
        default: bool,
    },
    /// [OPEN GATE] Show an exact closure and lease-protected push plan
    PlanPush {
        /// Remote name (defaults to configured default or detected origin)
        #[arg(long)]
        remote: Option<String>,
    },
    /// Acquire a graph-aware session lease for a native Kin remote
    Lease {
        /// Remote name (defaults to configured default)
        #[arg(long)]
        remote: Option<String>,
        /// Override the actor ID sent to KinLab
        #[arg(long)]
        actor_id: Option<String>,
        /// Optional lease TTL in seconds
        #[arg(long)]
        ttl_seconds: Option<u64>,
        /// Print the full lease payload as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// List active hosted repo sessions for a native Kin remote
    Sessions {
        /// Remote name (defaults to configured default)
        #[arg(long)]
        remote: Option<String>,
        /// Print the full session payload as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum IntentAction {
    /// List all active intents
    List,
    /// Register a new intent (lock a scope)
    Register {
        /// Scope to lock (entity:<uuid>, file:<path>, or bare UUID/path)
        scope: String,
        /// Lock type: hard or soft
        #[arg(short, long, default_value = "soft")]
        lock: String,
        /// Task description
        #[arg(short, long)]
        task: String,
        /// Session ID (defaults to a new CLI session)
        #[arg(short, long)]
        session: Option<String>,
    },
    /// Release a specific intent
    Release {
        /// Intent ID to release
        intent_id: String,
    },
    /// Clear all intents for a session
    Clear {
        /// Session ID whose intents to clear
        session_id: String,
    },
}

#[derive(Subcommand)]
enum ReviewAction {
    /// Shadow-mode merge gate: evaluate a PR-shaped change and emit a
    /// report-only verdict with blast radius, repair context, and audit
    /// evidence. Never blocks and never mutates graph state.
    Shadow {
        /// Change range as <base>..<head>. Refs accept branch names,
        /// semantic change IDs, and imported Git commit SHAs.
        range: Option<String>,
        /// Base ref (alternative to the positional range)
        #[arg(long)]
        base: Option<String>,
        /// Head ref (alternative to the positional range)
        #[arg(long)]
        head: Option<String>,
        /// Change title for the report (e.g. PR title)
        #[arg(long)]
        title: Option<String>,
        /// Source URL for the report (e.g. PR URL)
        #[arg(long = "source-url")]
        source_url: Option<String>,
        /// Change author identity for the report
        #[arg(long)]
        author: Option<String>,
        /// Emit the report as machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Create a new review
    Create {
        /// Review title
        #[arg(short, long)]
        title: String,
        /// Base ref (branch name or change ID)
        #[arg(long)]
        base: String,
        /// Head ref (branch name or change ID)
        #[arg(long)]
        head: String,
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
    },
    /// Record a review decision (approve, needs-work, block)
    Decide {
        /// Review ID
        review_id: String,
        /// Decision state: approved, needs_work, blocked
        #[arg(long)]
        state: String,
        /// Optional comment
        #[arg(long)]
        comment: Option<String>,
    },
    /// Add a note to a review
    Note {
        /// Review ID
        review_id: String,
        /// Note body
        #[arg(long)]
        body: String,
        /// Optional scope (entity:<uuid> or artifact:<path>)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Start a discussion thread on a review
    Discuss {
        /// Review ID
        review_id: String,
        /// Discussion body
        #[arg(long)]
        body: String,
        /// Optional scope (entity:<uuid> or artifact:<path>)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Reply to a discussion thread
    Reply {
        /// Discussion ID
        discussion_id: String,
        /// Reply body
        #[arg(long)]
        body: String,
    },
    /// Resolve a discussion thread
    Resolve {
        /// Discussion ID
        discussion_id: String,
    },
    /// Assign a reviewer
    Assign {
        /// Review ID
        review_id: String,
        /// Reviewer identity (email or handle)
        #[arg(long)]
        reviewer: String,
    },
    /// List reviews
    List {
        /// Filter by state: pending, approved, needs_work, blocked
        #[arg(long)]
        state: Option<String>,
    },
    /// Show a specific review with all details
    Show {
        /// Review ID
        review_id: String,
    },
}

#[derive(Subcommand)]
enum TrafficAction {
    /// Show active traffic on a scope
    Show {
        /// Scope to query (entity:<uuid>, file:<path>, or bare UUID/path)
        scope: String,
    },
    /// List all active sessions
    Sessions,
}

#[derive(Subcommand)]
enum AssistantAction {
    /// Install an assistant adapter
    Install {
        /// Assistant name: claude-code, codex, gemini-cli, cursor, generic
        assistant: String,
    },
    /// Run connectivity checks
    Doctor {
        /// Specific assistant to check (checks all if omitted)
        assistant: Option<String>,
    },
    /// List installed adapters
    List,
    /// Sync managed doc blocks
    Sync,
    /// Configure managed doc sync targets
    Configure {
        /// Sync mode: manual, on-commit, daemon-auto
        #[arg(long)]
        sync_mode: Option<String>,
        /// Enable a target file
        #[arg(long)]
        enable: Option<String>,
        /// Disable a target file
        #[arg(long)]
        disable: Option<String>,
    },
    /// Generate ready-to-paste config snippets
    Snippets {
        /// Specific assistant (defaults to all MCP-capable)
        assistant: Option<String>,
    },
    /// Show recommended hook templates
    Hooks {
        /// Specific assistant (defaults to claude-code)
        assistant: Option<String>,
    },
    /// Generate injectable prompt guidance
    Prompt {
        /// Assistant: claude, codex, gemini
        #[arg(long)]
        assistant: String,
        /// Mode: normal or benchmark
        #[arg(long, default_value = "normal")]
        mode: String,
    },
}

#[derive(Subcommand)]
enum StashAction {
    /// [OPEN GATE] Snapshot exact repository-v6 workspace state.
    Push {
        /// DESTRUCTIVE: delete source files from the working tree after
        /// snapshotting. Requires typing "remove" to confirm (or --yes).
        #[arg(long)]
        remove_from_tree: bool,
        /// Skip typed confirmation for --remove-from-tree (for non-interactive use).
        #[arg(long)]
        yes: bool,
    },
    /// [OPEN GATE] Restore the most recent exact stash transaction
    Pop,
    /// [OPEN GATE] List repository-v6 stash transactions
    List,
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the MCP stdio server
    Start {
        /// Run in global mode, serving all registered repos from ~/.kin/registry.toml
        #[arg(long)]
        global: bool,
        /// Bind this server to a specific Kin repository instead of relying on
        /// the launching process's working directory. Overrides KIN_MCP_REPO.
        /// Use this for a global agent-CLI MCP entry that may launch outside
        /// any Kin repository (e.g. an umbrella workspace root).
        #[arg(long, value_name = "PATH")]
        repo: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    /// Log into KinLab and store a CLI credential
    Login {
        /// Override the KinLab base URL
        #[arg(long)]
        base_url: Option<String>,
        /// Print a browser URL and exchange a one-time code manually
        #[arg(long, default_value_t = false)]
        no_browser: bool,
    },
    /// Log out and remove the stored KinLab credential
    Logout {
        /// Override the KinLab base URL
        #[arg(long)]
        base_url: Option<String>,
    },
    /// Show the authenticated KinLab user
    Whoami {
        /// Override the KinLab base URL
        #[arg(long)]
        base_url: Option<String>,
    },
    /// Show whether a KinLab credential is stored
    Status {
        /// Override the KinLab base URL
        #[arg(long)]
        base_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum WorkAction {
    /// Create a new work item
    Create {
        /// Work kind: feature, task, issue, debt, todo, investigation
        #[arg(short, long)]
        kind: String,
        /// Work item title
        #[arg(short, long)]
        title: String,
        /// Optional description
        #[arg(short, long)]
        description: Option<String>,
        /// Scope to link (entity:<uuid>, artifact:<path>, or bare path)
        #[arg(short, long)]
        scope: Option<String>,
        /// Priority: critical, high, medium, low, none
        #[arg(short, long)]
        priority: Option<String>,
    },
    /// List work items
    List {
        /// Filter by status
        #[arg(short, long)]
        status: Option<String>,
        /// Filter by kind
        #[arg(short, long)]
        kind: Option<String>,
        /// Filter by scope (entity:<uuid>, contract:<uuid>, artifact:<path>, change:<id>, or bare path)
        #[arg(long)]
        scope: Option<String>,
    },
    /// Show work item details
    Show {
        /// Work item ID
        work_id: String,
    },
    /// Link a work item to a scope
    Link {
        /// Work item ID
        work_id: String,
        /// Scope to link
        scope: String,
    },
    /// Link a parent work item to a child work item
    Decompose {
        /// Parent work item ID
        parent_work_id: String,
        /// Child work item ID
        child_work_id: String,
    },
    /// Mark one work item as blocked by another
    Block {
        /// Blocked work item ID
        blocked_work_id: String,
        /// Blocker work item ID
        blocker_work_id: String,
    },
    /// Link semantic scopes that implement a work item
    Implement {
        /// Work item ID
        work_id: String,
        /// Implementing scope
        scope: String,
    },
    /// Update a work item status
    Status {
        /// Work item ID
        work_id: String,
        /// New status: proposed, planned, in_progress, blocked, done, verified, archived
        status: String,
    },
    /// Close a work item
    Close {
        /// Work item ID
        work_id: String,
    },
    /// Verify test coverage for a work item's implementing entities
    Verify {
        /// Work item ID
        work_id: String,
    },
}

#[derive(Subcommand)]
enum NoteAction {
    /// Add an annotation to a semantic scope or work item
    Add {
        /// Target to annotate (entity:<uuid>, contract:<uuid>, artifact:<path>, change:<id>, work:<uuid>, or bare path)
        target: String,
        /// Annotation kind: comment, warning, instruction, reasoning
        #[arg(short, long)]
        kind: String,
        /// Annotation body
        #[arg(short, long)]
        body: String,
    },
    /// List annotations for a semantic scope or work item
    List {
        /// Target to query (entity:<uuid>, contract:<uuid>, artifact:<path>, change:<id>, work:<uuid>, or bare path)
        target: String,
    },
    /// Show stale annotations
    Stale,
}

#[derive(Subcommand)]
enum TodoAction {
    /// Import inline TODOs from source files
    Import {
        /// Path to scan (defaults to working directory)
        path: Option<String>,
    },
}

#[derive(Subcommand)]
enum VerifyAction {
    /// Check coverage for a specific entity
    Entity {
        /// Entity name or ID
        entity: String,
    },
    /// Plan a targeted proof set from an entity and its downstream impact
    Plan {
        /// Entity name or ID
        entity: String,
        /// Dependent traversal depth used to widen the proof set
        #[arg(long, default_value_t = 2)]
        depth: u32,
    },
    /// Plan a targeted proof set for a semantic change or the current HEAD
    Change {
        /// Semantic change ID (defaults to current branch head)
        change_id: Option<String>,
        /// Dependent traversal depth used to widen the proof set
        #[arg(long, default_value_t = 2)]
        depth: u32,
    },
    /// Show repository-wide coverage summary
    Summary,
    /// Show only entities missing test coverage
    Missing,
    /// Execute tests for an entity and record a VerificationRun
    Run {
        /// Entity name or ID
        entity: String,
        /// Test runner: cargo, jest, pytest, go, junit, or custom command
        #[arg(long, default_value = "cargo")]
        runner: String,
        /// Dependent traversal depth used to widen the proof set
        #[arg(long, default_value_t = 2)]
        depth: u32,
    },
}

#[derive(Subcommand)]
enum TelemetryAction {
    /// Show consent status and spool statistics
    Status,
    /// Record consent to local telemetry collection
    Consent,
    /// Revoke telemetry consent
    Revoke,
    /// Delete all spooled telemetry data
    Purge,
}

#[derive(Subcommand)]
enum ApprovalsAction {
    /// Show approvals for a change
    Show {
        /// Change ID
        change_id: String,
    },
    /// List all actors and delegations
    List,
}

#[derive(Subcommand)]
enum SetupAction {
    /// Show what's installed
    Status {
        /// Emit the machine-readable health report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Quick health check
    Doctor {
        /// Apply safe automatic repairs (shell hook, MCP configs, config dirs)
        #[arg(long, default_value_t = false)]
        fix: bool,
        /// Emit the machine-readable health report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show the install ledger and verify it against disk
    Ledger {
        /// Emit the ledger + verification as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Remove exactly what `kin setup` recorded (ledger-verified)
    Uninstall {
        /// Show what would be removed without changing anything
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Also remove entries modified since install (never done by default)
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Emit the per-artifact outcomes as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum RegistryAction {
    /// Verify local registry authority without reading its contents
    Authority {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
        /// Explicitly repair mode bits on structurally safe authority files
        #[arg(long)]
        fix: bool,
        /// Create missing private authority files without replacing existing data
        #[arg(long)]
        initialize: bool,
    },
    /// Show repo daemons registered with the central local supervisor
    Daemons {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Remove stale entries (paths that no longer contain .kin/)
    Clean,
}

#[derive(Subcommand)]
enum DaemonAction {
    /// Show the supervisor and every repo worker daemon, with stale-file detection
    Status {
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
    /// Gracefully stop the current repo's worker daemon (or every daemon with --all)
    Stop {
        /// Stop every worker daemon and the supervisor (supervisor last)
        #[arg(long)]
        all: bool,
        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SecretAction {
    /// Set an org-level secret (reads value from stdin)
    Set {
        /// Secret name
        name: String,
    },
    /// List org-level secrets
    List,
    /// Delete an org-level secret
    Delete {
        /// Secret name
        name: String,
    },
    /// Set a repo-level secret (reads value from stdin)
    SetRepo {
        /// Secret name
        name: String,
    },
    /// List repo-level secrets
    ListRepo,
}

#[derive(Subcommand)]
enum PipelineAction {
    /// List pipelines for the current repo
    List,
    /// Manually trigger a pipeline
    Run {
        /// Pipeline name
        name: String,
    },
    /// Show logs for a pipeline run
    Logs {
        /// Run ID
        run_id: String,
    },
    /// Cancel a running pipeline
    Cancel {
        /// Run ID
        run_id: String,
    },
}

/// Deliberate, bottom-up cross-repo release orchestration (the in-binary port
/// of the umbrella `bin/kin-release`), plus the per-repo graph release snapshot.
///
/// `plan`/`apply`/`intent` read registry truth + the local sibling manifests and
/// drive the bottom-up front (primitives -> kin-model -> kin-db -> kin -> bench/
/// vfs/lsp) deliberately. They never publish — publishing stays in CI behind the
/// version gate. `snapshot` is the original `kin release <tag>` graph snapshot.
#[derive(Subcommand)]
enum ReleaseAction {
    /// Read-only bottom-up release plan: which crates need publishing and which
    /// downstream pins lag a published crate.
    Plan {
        /// Skip registry queries; show local versions + pins only.
        #[arg(long)]
        offline: bool,
    },
    /// Propagate a published crate version into downstream Cargo.toml pins
    /// (registry = "kin"). Edits manifests locally; never commits/pushes/publishes.
    Apply {
        /// The registry crate whose pin to bump (e.g. kin-db).
        crate_name: String,
        /// The version to pin (e.g. 0.2.24).
        version: String,
        /// Repos to update (default: every consumer repo).
        repos: Vec<String>,
        /// Do not refresh Cargo.lock with `cargo update --precise` after editing.
        #[arg(long)]
        no_lock: bool,
    },
    /// Release-intent gate for one repo (exit 0 = release intended / nothing to
    /// do, non-zero = staged but out of sync). For `kin`, runs the canonical
    /// scripts/release-intent.mjs gate.
    Intent {
        /// Repo to gate (e.g. kin, kin-db).
        repo: String,
    },
    /// [OPEN GATE] Create a release snapshot bound to exact repository roots.
    Snapshot {
        /// Release tag
        tag: String,
        /// Block release if entities lack linked passing tests
        #[arg(long)]
        require_proof: bool,
        /// Require known-human approval for every reachable non-root change
        #[arg(long)]
        require_approval: bool,
        /// Force release even with low coverage
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum HostedReleaseAction {
    /// Create a hosted release
    Create {
        /// Release tag
        tag: String,
        /// Release name
        #[arg(long)]
        name: Option<String>,
        /// Release notes
        #[arg(long)]
        notes: Option<String>,
    },
    /// List hosted releases
    List,
    /// Upload an artifact to a release
    Upload {
        /// Release ID
        release_id: String,
        /// File to upload
        file: String,
    },
}

fn main() -> Result<()> {
    kin_buildinfo::retain_update_build_identity(&KIN_UPDATE_BUILD_IDENTITY);
    let cli = Cli::parse();
    let command_name = current_command_name();
    let cwd = std::env::current_dir()?.display().to_string();
    let profile_out = cli
        .profile_out
        .clone()
        .or_else(|| std::env::var_os("KIN_PROFILE_OUT").map(PathBuf::from));
    let profile_summary = cli.profile_summary || env_flag("KIN_PROFILE_SUMMARY");
    let profile_session = profile_out
        .clone()
        .map(|path| kin_cli::profile::ProfileSession::new(command_name.clone(), cwd.clone(), path));

    if let Some(session) = profile_session.clone() {
        tracing_subscriber::registry()
            .with(kin_cli::profile::ProfilingLayer::new(session))
            .init();
    } else {
        tracing_subscriber::registry()
            .with(default_env_filter(false))
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
            .init();
    }

    // Validate the KIN_* environment surface once logging is live. Unknown names
    // (likely typos) and out-of-range values are surfaced loudly instead of
    // silently no-op'ing; an invalid correctness-relevant value refuses to run
    // rather than mis-behaving. Governed by KIN_ENV_VALIDATION (off/warn/strict).
    if let Err(err) = kin_core::env_registry::enforce_startup_env() {
        eprintln!("kin: {err}");
        std::process::exit(2);
    }

    // A durable MCP marker is an active repair obligation. Ordinary commands
    // retry it; the update command retries while holding the install lock.
    if !matches!(&cli.command, Command::Update { .. }) {
        match commands::update::retry_pending_mcp_repair_from_managed_process() {
            Ok(_) => {}
            Err(error) => eprintln!("kin: MCP repair remains pending: {error:#}"),
        }
    }

    let root_span = tracing::info_span!(
        "kin.command",
        command = %command_name,
        cwd = %cwd
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let result = runtime.block_on(
        (async move {
            match cli.command {
                Command::Capabilities { json } => commands::capabilities::run(json),
                Command::Init { path, json } => commands::init::run(path, json).await,
                Command::Status { json } => commands::status::run(json),
                Command::Resources { action } => match action {
                    ResourcesAction::Inspect { json, profile } => {
                        commands::resources::run(json, profile).await
                    }
                },
                Command::Commit { .. } => commands::capabilities::require_ready("commit"),
                Command::Log { count: _ } => commands::capabilities::require_ready("log"),
                Command::Branch { action } => match action {
                    BranchAction::List => commands::capabilities::require_ready("branch list"),
                    BranchAction::Create { name: _ } => {
                        commands::capabilities::require_ready("branch create")
                    }
                    BranchAction::Delete { name: _ } => {
                        commands::capabilities::require_ready("branch delete")
                    }
                    BranchAction::Switch { name: _ } => {
                        commands::capabilities::require_ready("branch switch")
                    }
                },
                Command::Diff { .. } => commands::capabilities::require_ready("diff"),
                Command::Eject { .. } => commands::capabilities::require_ready("eject"),
                Command::Impact {
                    entity,
                    depth,
                    file,
                    kind,
                    signature,
                    json,
                } => commands::impact::run(entity, depth, file, kind, signature, json).await,
                Command::Context {
                    entity,
                    budget,
                    assistant,
                } => commands::context::run(entity, budget, assistant).await,
                Command::ContextbenchLocate {
                    task_file,
                    json,
                    debug,
                } => commands::contextbench_locate::run(task_file, json, debug).await,
                Command::Trace {
                    entity,
                    json,
                    compact,
                    show_body: _,
                    limit,
                    budget,
                    assistant,
                    max_lines,
                    nearby,
                    transitive,
                } => {
                    if json {
                        commands::trace::run_json(
                            entity,
                            compact,
                            budget,
                            assistant,
                            max_lines,
                            limit.unwrap_or(nearby),
                            transitive,
                        )
                        .await
                    } else {
                        commands::trace::run(
                            entity,
                            compact,
                            budget,
                            assistant,
                            max_lines,
                            limit.unwrap_or(nearby),
                            transitive,
                        )
                        .await
                    }
                }
                Command::Search {
                    pattern,
                    json,
                    kind,
                    language,
                    show_body,
                    limit,
                    semantic,
                } => {
                    if semantic {
                        if json {
                            commands::search::run_semantic_json(
                                pattern,
                                kind,
                                language,
                                limit.unwrap_or(10),
                            )
                            .await
                        } else {
                            commands::search::run_semantic(
                                pattern,
                                kind,
                                language,
                                limit.unwrap_or(10),
                            )
                            .await
                        }
                    } else {
                        if json {
                            commands::search::run_json(pattern, kind, language, show_body, limit)
                                .await
                        } else {
                            commands::search::run(pattern, kind, language, show_body, limit).await
                        }
                    }
                }
                Command::Scope {
                    ref_string,
                    clear,
                    show,
                    session,
                } => {
                    commands::scope::run(ref_string.as_deref(), clear, show, session.as_deref())
                        .await
                }
                Command::Locate {
                    text,
                    query,
                    file,
                    stdin,
                    json,
                    explain,
                    diagnose,
                    gold,
                    max_files,
                    reference,
                    snippets,
                    no_snippets,
                    next,
                    cursor,
                    page_size,
                } => {
                    // Inline snippets default ON for the structured/agent `--json`
                    // surface (so an agent gets code on the first locate);
                    // --diagnose stays lean unless --snippets is explicit;
                    // --no-snippets always wins.
                    let want_snippets = !no_snippets && (snippets || (json && !diagnose));
                    // --diagnose implies --json --explain
                    let json = json || diagnose;
                    let explain = explain || diagnose;
                    let max_files_explicit = max_files.is_some();
                    let max_files_val = max_files.unwrap_or(10);
                    // Resolve the paging cursor: --next reads the persisted cursor
                    // from the prior page; --cursor takes an explicit token.
                    let paging_cursor = if next {
                        Some(commands::locate_cursor::read_persisted_locate_cursor()?)
                    } else {
                        cursor
                    };
                    let paging = commands::locate::LocatePaging {
                        cursor: paging_cursor,
                        page_size,
                    };
                    // On a paging request the query text is carried by the cursor
                    // (the daemon holds the cached ranking), so it is optional.
                    let paging_active = paging.cursor.is_some();
                    let problem_text = if stdin {
                        let mut buf = String::new();
                        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                        buf
                    } else if let Some(path) = file {
                        std::fs::read_to_string(&path)?
                    } else if let Some(t) = text {
                        t
                    } else if paging_active {
                        // --next / --cursor without inline text: the daemon pages
                        // its cached ranking; text is only a cache-miss fallback.
                        String::new()
                    } else {
                        anyhow::bail!("provide problem text, --file, or --stdin");
                    };
                    if diagnose {
                        // Diagnostic mode: capture result, print JSON, then
                        // print gold file comparison to stderr.
                        let result = commands::locate::capture(
                            &problem_text,
                            query.clone(),
                            true, // always explain in diagnose mode
                            max_files_val,
                            max_files_explicit,
                            reference,
                            want_snippets,
                            paging,
                        )
                        .await?;

                        // Print full JSON to stdout
                        println!("{}", serde_json::to_string_pretty(&result)?);

                        // Print diagnostic comparison to stderr
                        let retrieved: Vec<&str> =
                            result.files.iter().map(|f| f.path.as_str()).collect();
                        let gold_set: std::collections::HashSet<&str> =
                            gold.iter().map(|s| s.as_str()).collect();
                        let overlap: Vec<&&str> = retrieved
                            .iter()
                            .filter(|f| gold_set.contains(**f))
                            .collect();
                        let precision = if retrieved.is_empty() {
                            0.0
                        } else {
                            overlap.len() as f64 / retrieved.len() as f64
                        };
                        let recall = if gold.is_empty() {
                            0.0
                        } else {
                            overlap.len() as f64 / gold.len() as f64
                        };
                        let f1 = if precision + recall > 0.0 {
                            2.0 * precision * recall / (precision + recall)
                        } else {
                            0.0
                        };

                        eprintln!();
                        eprintln!("━━━ DIAGNOSE ━━━━━━━━━━━━━━━━━━━━━━━");
                        if let Some(ref debug) = result.debug {
                            eprintln!(
                                "Track:      {}",
                                debug.scoring_track.as_deref().unwrap_or("?")
                            );
                            if let Some(ref fp) = debug.fast_path {
                                eprintln!("Fast path:  {}", fp);
                            }
                            if !debug.query_terms.is_empty() {
                                eprintln!("Terms:      {:?}", debug.query_terms);
                            }
                        }
                        eprintln!("Retrieved:  {} files", retrieved.len());
                        for (i, f) in result.files.iter().enumerate() {
                            let marker = if gold_set.contains(f.path.as_str()) {
                                "✓ GOLD"
                            } else {
                                "  miss"
                            };
                            eprintln!("  #{:<2} {:60} {:6.3} {}", i + 1, f.path, f.score, marker);
                        }
                        if !gold.is_empty() {
                            eprintln!("Gold:       {} files", gold.len());
                            for g in &gold {
                                let found = retrieved.contains(&g.as_str());
                                let marker = if found { "✓ found" } else { "✗ MISSED" };
                                // Check if gold file appears in any stage
                                let mut stage_info = String::new();
                                if !found {
                                    if let Some(ref debug) = result.debug {
                                        if !debug.stages.is_empty() {
                                            for stage in &debug.stages {
                                                if let Some(entry) =
                                                    stage.files.iter().find(|e| e.path == *g)
                                                {
                                                    stage_info = format!(
                                                        " (seen in {} at score {:.4})",
                                                        stage.name, entry.score
                                                    );
                                                    break;
                                                }
                                            }
                                        }
                                        if stage_info.is_empty() && !debug.resolved_files.is_empty()
                                        {
                                            if let Some(rf) =
                                                debug.resolved_files.iter().find(|r| r.path == *g)
                                            {
                                                stage_info =
                                                    format!(" (resolved at score {:.1})", rf.score);
                                            }
                                        }
                                        if stage_info.is_empty() {
                                            stage_info = " (never seen in pipeline)".to_string();
                                        }
                                    }
                                }
                                eprintln!("  {:60} {}{}", g, marker, stage_info);
                            }
                            eprintln!(
                                "Scores:     P={:.3} R={:.3} F1={:.3}",
                                precision, recall, f1
                            );
                        }
                        eprintln!(
                            "Timing:     {:.0}ms",
                            result
                                .files
                                .first()
                                .map(|_| {
                                    // Use locate_ms if available from debug
                                    0.0 // timing is in the debug output
                                })
                                .unwrap_or(0.0)
                        );
                        eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
                        Ok(())
                    } else {
                        commands::locate::run(
                            &problem_text,
                            query,
                            json,
                            explain,
                            max_files_val,
                            max_files_explicit,
                            reference,
                            want_snippets,
                            paging,
                        )
                        .await
                    }
                }
                Command::LocateDebug {
                    text,
                    target,
                    task_file,
                    max_files,
                    json,
                } => commands::locate_debug::run(text, target, task_file, max_files, json).await,
                Command::Embed {
                    batch_size,
                    max_seconds,
                    rebuild,
                    json,
                } => commands::embed::run(batch_size, json, max_seconds, rebuild).await,
                Command::Rename { .. } => commands::capabilities::require_ready("rename"),
                Command::Refs {
                    entity,
                    kind,
                    bulk_json,
                    entities,
                    compact,
                    no_compact,
                } => {
                    if bulk_json {
                        let entities = entities.ok_or_else(|| {
                            anyhow::anyhow!(
                                "--bulk-json requires --entities (comma-separated entity UUIDs)"
                            )
                        })?;
                        let effective_compact = compact && !no_compact;
                        commands::refs::run_bulk(entities, kind, effective_compact).await
                    } else {
                        if entity.is_empty() {
                            anyhow::bail!(
                                "missing positional entity argument (or use --bulk-json --entities)"
                            );
                        }
                        commands::refs::run(entity, kind).await
                    }
                }
                Command::Review {
                    change,
                    json,
                    entities,
                    files,
                    changes,
                    action,
                } => {
                    if let Some(review_action) = action {
                        match review_action {
                            ReviewAction::Shadow {
                                range,
                                base,
                                head,
                                title,
                                source_url,
                                author,
                                json,
                            } => {
                                let (base, head) = match (range, base, head) {
                                    (Some(range), None, None) => match range.split_once("..") {
                                        Some((base, head))
                                            if !base.is_empty() && !head.is_empty() =>
                                        {
                                            (base.to_string(), head.to_string())
                                        }
                                        _ => anyhow::bail!(
                                            "invalid range '{}': expected <base>..<head>",
                                            range
                                        ),
                                    },
                                    (None, Some(base), Some(head)) => (base, head),
                                    _ => anyhow::bail!(
                                        "provide a <base>..<head> range or both --base and --head"
                                    ),
                                };
                                commands::review::shadow_report(
                                    base, head, title, source_url, author, json,
                                )
                                .await
                            }
                            ReviewAction::Create {
                                title,
                                base,
                                head,
                                description,
                            } => {
                                commands::review::create_review(title, base, head, description)
                                    .await
                            }
                            ReviewAction::Decide {
                                review_id,
                                state,
                                comment,
                            } => commands::review::decide_review(review_id, state, comment).await,
                            ReviewAction::Note {
                                review_id,
                                body,
                                scope,
                            } => commands::review::add_note(review_id, body, scope).await,
                            ReviewAction::Discuss {
                                review_id,
                                body,
                                scope,
                            } => commands::review::start_discussion(review_id, body, scope).await,
                            ReviewAction::Reply {
                                discussion_id,
                                body,
                            } => commands::review::reply_discussion(discussion_id, body).await,
                            ReviewAction::Resolve { discussion_id } => {
                                commands::review::resolve_discussion(discussion_id).await
                            }
                            ReviewAction::Assign {
                                review_id,
                                reviewer,
                            } => commands::review::assign_reviewer(review_id, reviewer).await,
                            ReviewAction::List { state } => {
                                commands::review::list_reviews(state).await
                            }
                            ReviewAction::Show { review_id } => {
                                commands::review::show_review(review_id).await
                            }
                        }
                    } else if json {
                        commands::review::run_json(change, entities, files, changes).await
                    } else {
                        commands::review::run(change, entities, files, changes).await
                    }
                }
                Command::History { entity, reference } => {
                    commands::history::run(entity, reference).await
                }
                Command::DeadCode {
                    seed,
                    limit,
                    name_pattern,
                } => match seed {
                    Some(query) => {
                        commands::dead_code::run_seeded(query, limit, name_pattern).await
                    }
                    None => commands::dead_code::run().await,
                },
                Command::TraceDataFlow {
                    focal,
                    depth,
                    direction,
                    limit_per_step,
                } => {
                    commands::trace_data_flow::run_seeded(focal, depth, direction, limit_per_step)
                        .await
                }
                Command::Deps => commands::deps::run().await,
                Command::Xref { entity } => commands::xref::run(entity).await,
                Command::Spec { action } => match action {
                    SpecAction::Create { intent } => commands::spec::create(intent).await,
                    SpecAction::List => commands::spec::list().await,
                    SpecAction::Show { id } => commands::spec::show(id).await,
                },
                Command::Merge { .. } => commands::capabilities::require_ready("merge"),
                Command::Conflicts => commands::capabilities::require_ready("conflicts"),
                Command::Resolve { .. } => commands::capabilities::require_ready("resolve"),
                Command::Stash { action: _ } => commands::capabilities::require_ready("stash"),
                Command::Blame { entity, reference } => {
                    commands::blame::run(entity, reference).await
                }
                Command::Mcp { action } => match action {
                    McpAction::Start { global, repo } => commands::mcp::start(global, repo).await,
                },
                Command::Auth { action } => match action {
                    AuthAction::Login {
                        base_url,
                        no_browser,
                    } => commands::auth::login(base_url, no_browser).await,
                    AuthAction::Logout { base_url } => commands::auth::logout(base_url).await,
                    AuthAction::Whoami { base_url } => commands::auth::whoami(base_url).await,
                    AuthAction::Status { base_url } => commands::auth::status(base_url).await,
                },
                Command::Remote { action } => match action {
                    RemoteAction::List => commands::remote::list().await,
                    RemoteAction::Add {
                        name,
                        host,
                        transport,
                        url,
                        publish_review_state,
                        publish_proofs,
                        default,
                    } => {
                        commands::remote::add(
                            name,
                            host,
                            transport,
                            url,
                            publish_review_state,
                            publish_proofs,
                            default,
                        )
                        .await
                    }
                    RemoteAction::PlanPush { .. } => {
                        commands::capabilities::require_ready("remote plan-push")
                    }
                    RemoteAction::Lease {
                        remote,
                        actor_id,
                        ttl_seconds,
                        json,
                    } => commands::remote::lease(remote, actor_id, ttl_seconds, json).await,
                    RemoteAction::Sessions { remote, json } => {
                        commands::remote::sessions(remote, json).await
                    }
                },
                Command::Publish {
                    packages,
                    registry,
                    dry_run,
                } => {
                    let registry = std::env::var("KIN_REGISTRY_URL").unwrap_or(registry);
                    commands::publish::run(packages, registry, dry_run).await
                }
                Command::Push { remote: _ } => commands::capabilities::require_ready("push"),
                Command::Pull { remote: _ } => commands::capabilities::require_ready("pull"),
                Command::Clone { url, path } => commands::clone::run(url, path).await,
                Command::Checkout { .. } => commands::capabilities::require_ready("checkout"),
                Command::Verify { action } => match action {
                    VerifyAction::Entity { entity } => commands::verify::run(entity).await,
                    VerifyAction::Plan { entity, depth } => {
                        commands::verify::plan(entity, depth).await
                    }
                    VerifyAction::Change { change_id, depth } => {
                        commands::verify::plan_change(change_id, depth).await
                    }
                    VerifyAction::Summary => commands::verify::summary().await,
                    VerifyAction::Missing => commands::verify::missing().await,
                    VerifyAction::Run {
                        entity,
                        runner,
                        depth,
                    } => commands::verify::run_verification(entity, runner, depth).await,
                },
                Command::Exec { .. } => commands::capabilities::require_ready("exec"),
                Command::Telemetry { action } => match action {
                    TelemetryAction::Status => commands::telemetry::run_status().await,
                    TelemetryAction::Consent => commands::telemetry::run_consent().await,
                    TelemetryAction::Revoke => commands::telemetry::run_revoke().await,
                    TelemetryAction::Purge => commands::telemetry::run_purge().await,
                },
                Command::Support { json } => commands::support::run(json).await,
                Command::BenchMeta {
                    json,
                    prepared_state,
                } => commands::bench_meta::run(json, prepared_state).await,
                Command::PreparedState { action } => match action {
                    PreparedStateAction::Publish { target, json } => {
                        commands::prepared_state::publish(target, json).await
                    }
                    PreparedStateAction::Materialize { source, json } => {
                        commands::prepared_state::materialize(source, json).await
                    }
                },
                Command::Audit {
                    actor,
                    limit,
                    action,
                    since,
                    scope,
                } => {
                    commands::audit::run_with_filters(
                        actor,
                        limit,
                        commands::audit::AuditFilters {
                            action,
                            since,
                            scope,
                        },
                    )
                    .await
                }
                Command::Backup { action } => match action {
                    BackupAction::Create { tag } => commands::backup::create(tag).await,
                    BackupAction::List => commands::backup::list().await,
                    BackupAction::Restore { name, latest } => {
                        commands::backup::restore(name, latest).await
                    }
                    BackupAction::Delete { name } => commands::backup::delete(name).await,
                },
                Command::Approvals { action } => match action {
                    ApprovalsAction::Show { change_id } => {
                        commands::approvals::show(change_id).await
                    }
                    ApprovalsAction::List => commands::approvals::list().await,
                },
                Command::Security { propagate } => {
                    commands::security::run_with_options(propagate).await
                }
                Command::Semver => commands::capabilities::require_ready("semver"),
                Command::Release { action } => match action {
                    ReleaseAction::Plan { offline } => commands::release_orch::plan(offline).await,
                    ReleaseAction::Apply {
                        crate_name,
                        version,
                        repos,
                        no_lock,
                    } => commands::release_orch::apply(crate_name, version, repos, !no_lock).await,
                    ReleaseAction::Intent { repo } => commands::release_orch::intent(repo).await,
                    ReleaseAction::Snapshot { .. } => {
                        commands::capabilities::require_ready("release snapshot")
                    }
                },
                Command::Tag { .. } => commands::capabilities::require_ready("tag"),
                Command::Rollback { .. } => commands::capabilities::require_ready("rollback"),
                Command::Bench { args } => commands::bench::bench_proxy(&args),
                Command::Migrate { source, target } => commands::migrate::run(source, target).await,
                Command::Cache { action } => match action {
                    CacheAction::Status { json } => commands::cache::status(json).await,
                    CacheAction::Gc {
                        dry_run,
                        budget_gb,
                        prune_stale_schema,
                    } => commands::cache::gc(dry_run, budget_gb, prune_stale_schema).await,
                },
                Command::Graph { action } => match action {
                    GraphAction::Status => commands::graph::status().await,
                    GraphAction::Validate => commands::graph::validate().await,
                    GraphAction::Inspect { name, json } => {
                        commands::graph::inspect(name, json).await
                    }
                    GraphAction::Source { entity, json } => {
                        commands::graph::source(entity, json).await
                    }
                    GraphAction::Body { entity, json } => commands::graph::body(entity, json).await,
                    GraphAction::Viz { port, open } => commands::graph_viz::run(port, open).await,
                },
                Command::Git { action: _ } => commands::capabilities::require_ready("git export"),
                Command::Intent { action } => match action {
                    IntentAction::List => commands::intent::list().await,
                    IntentAction::Register {
                        scope,
                        lock,
                        task,
                        session,
                    } => commands::intent::register(scope, lock, task, session).await,
                    IntentAction::Release { intent_id } => {
                        commands::intent::release(intent_id).await
                    }
                    IntentAction::Clear { session_id } => commands::intent::clear(session_id).await,
                },
                Command::Traffic { action } => match action {
                    TrafficAction::Show { scope } => commands::traffic::run(scope).await,
                    TrafficAction::Sessions => commands::traffic::sessions().await,
                },
                Command::Assistant { action } => match action {
                    AssistantAction::Install { assistant } => {
                        commands::assistant::install(assistant).await
                    }
                    AssistantAction::Doctor { assistant } => {
                        commands::assistant::run_doctor(assistant).await
                    }
                    AssistantAction::List => commands::assistant::list().await,
                    AssistantAction::Sync => commands::assistant::sync().await,
                    AssistantAction::Configure {
                        sync_mode,
                        enable,
                        disable,
                    } => commands::assistant::configure(sync_mode, enable, disable).await,
                    AssistantAction::Snippets { assistant } => {
                        commands::assistant::snippets(assistant).await
                    }
                    AssistantAction::Hooks { assistant } => {
                        commands::assistant::hooks(assistant).await
                    }
                    AssistantAction::Prompt { assistant, mode } => {
                        commands::assistant::prompt(assistant, mode).await
                    }
                },
                Command::Work { action } => match action {
                    WorkAction::Create {
                        kind,
                        title,
                        description,
                        scope,
                        priority,
                    } => commands::work::create(kind, title, description, scope, priority).await,
                    WorkAction::List {
                        status,
                        kind,
                        scope,
                    } => commands::work::list(status, kind, scope).await,
                    WorkAction::Show { work_id } => commands::work::show(work_id).await,
                    WorkAction::Link { work_id, scope } => {
                        commands::work::link(work_id, scope).await
                    }
                    WorkAction::Decompose {
                        parent_work_id,
                        child_work_id,
                    } => commands::work::decompose(parent_work_id, child_work_id).await,
                    WorkAction::Block {
                        blocked_work_id,
                        blocker_work_id,
                    } => commands::work::block(blocked_work_id, blocker_work_id).await,
                    WorkAction::Implement { work_id, scope } => {
                        commands::work::implement(work_id, scope).await
                    }
                    WorkAction::Status { work_id, status } => {
                        commands::work::status(work_id, status).await
                    }
                    WorkAction::Close { work_id } => commands::work::close(work_id).await,
                    WorkAction::Verify { work_id } => commands::work::verify(work_id).await,
                },
                Command::Note { action } => match action {
                    NoteAction::Add { target, kind, body } => {
                        commands::note::add(target, kind, body).await
                    }
                    NoteAction::List { target } => commands::note::list(target).await,
                    NoteAction::Stale => commands::note::stale().await,
                },
                Command::Feature { title, description } => {
                    commands::work::create("feature".to_string(), title, description, None, None)
                        .await
                }
                Command::Todo { action } => match action {
                    TodoAction::Import { path } => commands::note::todo_import(path).await,
                },
                Command::Open { .. } => commands::capabilities::require_ready("open"),
                Command::Reconcile { .. } => commands::capabilities::require_ready("reconcile"),
                Command::With { .. } => commands::capabilities::require_ready("with"),
                Command::Shell { .. } => commands::capabilities::require_ready("shell"),
                Command::Overview { compact, json } => {
                    if json {
                        commands::overview::run_json().await
                    } else {
                        commands::overview::run(compact).await
                    }
                }
                Command::Completions { shell } => {
                    clap_complete::generate(
                        shell,
                        &mut Cli::command(),
                        "kin",
                        &mut std::io::stdout(),
                    );
                    Ok(())
                }
                Command::Update {
                    skip_verify,
                    channel,
                    expect_version,
                    expect_sha,
                    expect_archive_sha256,
                    check_only,
                    json,
                    ack_restart,
                    runtime_sessions,
                } => {
                    commands::update::run(
                        skip_verify,
                        channel,
                        expect_version,
                        expect_sha,
                        expect_archive_sha256,
                        check_only,
                        json,
                        ack_restart,
                        runtime_sessions,
                    )
                    .await
                }
                Command::Registry { action } => match action {
                    Some(RegistryAction::Authority {
                        json,
                        fix,
                        initialize,
                    }) => commands::registry::authority(json, fix, initialize).await,
                    Some(RegistryAction::Daemons { json }) => {
                        commands::registry::daemons(json).await
                    }
                    Some(RegistryAction::Clean) => commands::registry::clean().await,
                    None => commands::registry::list().await,
                },
                Command::Daemon { action } => match action {
                    DaemonAction::Status { json } => commands::daemon::status(json).await,
                    DaemonAction::Stop { all, json } => commands::daemon::stop(all, json).await,
                },
                Command::Doctor {
                    fix,
                    json,
                    drift,
                    heal,
                } => {
                    // `--drift`/`--heal` run the graph⇄file drift tripwire; bare
                    // `kin doctor` stays the first-run config health check.
                    if drift || heal {
                        commands::capabilities::require_ready("doctor --drift")
                    } else {
                        commands::setup::doctor(fix, json).await
                    }
                }
                Command::Setup {
                    action,
                    intent,
                    mode,
                    shell,
                    auto_daemon,
                    no_interactive,
                    check,
                } => match action {
                    Some(SetupAction::Status { json }) => commands::setup::status(json).await,
                    Some(SetupAction::Doctor { fix, json }) => {
                        commands::setup::doctor(fix, json).await
                    }
                    Some(SetupAction::Ledger { json }) => commands::setup::ledger_status(json),
                    Some(SetupAction::Uninstall {
                        dry_run,
                        force,
                        json,
                    }) => commands::setup::uninstall(dry_run, force, json),
                    // `kin setup --check` is shorthand for the first-run health
                    // check without running the wizard.
                    None if check => commands::setup::doctor(false, false).await,
                    None => {
                        commands::setup::run_wizard(commands::setup::WizardOptions {
                            mode,
                            shell,
                            auto_daemon,
                            no_interactive,
                            intent,
                        })
                        .await
                    }
                },
                Command::Secret { action } => match action {
                    SecretAction::Set { name } => commands::secret::set(name).await,
                    SecretAction::List => commands::secret::list().await,
                    SecretAction::Delete { name } => commands::secret::delete(name).await,
                    SecretAction::SetRepo { name } => commands::secret::set_repo(name).await,
                    SecretAction::ListRepo => commands::secret::list_repo().await,
                },
                Command::Pipeline { action } => match action {
                    PipelineAction::List => commands::pipeline::list().await,
                    PipelineAction::Run { name } => commands::pipeline::run_pipeline(name).await,
                    PipelineAction::Logs { run_id } => commands::pipeline::logs(run_id).await,
                    PipelineAction::Cancel { run_id } => commands::pipeline::cancel(run_id).await,
                },
                Command::HostedRelease { action } => match action {
                    HostedReleaseAction::Create { tag, name, notes } => {
                        commands::release_cmd::create(tag, name, notes).await
                    }
                    HostedReleaseAction::List => commands::release_cmd::list().await,
                    HostedReleaseAction::Upload { release_id, file } => {
                        commands::release_cmd::upload(release_id, file).await
                    }
                },
            }
        })
        .instrument(root_span),
    );

    if let Some(session) = profile_session {
        if let Err(err) = session.write_report() {
            eprintln!(
                "warning: failed to write Kin profile to {}: {err}",
                session.output_path().display()
            );
        } else if profile_summary {
            eprintln!("{}", session.render_summary(12));
        }
    }

    result
}

fn current_command_name() -> String {
    Cli::command()
        .try_get_matches_from(std::env::args_os())
        .ok()
        .and_then(|matches| matches.subcommand_name().map(|value| value.to_string()))
        .unwrap_or_else(|| "help".to_string())
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

fn default_env_filter(profile_enabled: bool) -> EnvFilter {
    if std::env::var_os("RUST_LOG").is_some() {
        EnvFilter::from_default_env()
    } else if profile_enabled {
        EnvFilter::new("info")
    } else {
        EnvFilter::new("warn")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn on_cli_test_stack(test: impl FnOnce() + Send + 'static) {
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(test)
            .expect("spawn CLI test thread")
            .join()
            .expect("CLI test thread must succeed");
    }

    #[test]
    fn cli_definition_is_valid() {
        // clap's debug_assert recurses over the full command tree, which has
        // outgrown the default 2 MiB test-thread stack; give it a dedicated
        // thread with room to validate every subcommand.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| Cli::command().debug_assert())
            .expect("spawn cli validation thread")
            .join()
            .expect("cli definition validation must succeed");
    }

    #[test]
    fn workspace_is_not_a_cli_surface() {
        on_cli_test_stack(|| {
            for args in [
                vec!["kin", "workspace"],
                vec!["kin", "workspace", "list"],
                vec!["kin", "workspace", "create", "demo"],
                vec!["kin", "workspace", "switch", "demo"],
                vec!["kin", "workspace", "delete", "demo"],
                vec!["kin", "workspace", "rename", "demo", "renamed"],
            ] {
                assert!(
                    Cli::try_parse_from(args).is_err(),
                    "the descriptor-only workspace command must not be parseable"
                );
            }

            let mut command = Cli::command();
            let help = command.render_long_help().to_string();
            for supported in [
                "Run a command in a graph-backed session workspace",
                "Launch an editor in a materialized session workspace",
                "Open an interactive shell in a materialized session workspace",
            ] {
                assert!(
                    help.contains(supported),
                    "supported graph-backed session surface missing from help: {supported}"
                );
            }
        });
    }

    #[test]
    fn git_interop_exposes_only_exact_export() {
        on_cli_test_stack(|| {
            for args in [
                &["kin", "import", "https://example.com/repo.git"][..],
                &["kin", "git", "import"][..],
                &["kin", "git", "sync"][..],
                &["kin", "git", "sync", "--in-place"][..],
            ] {
                assert!(
                    Cli::try_parse_from(args).is_err(),
                    "removed Git compatibility command must not be parseable: {args:?}"
                );
            }

            let cli = Cli::try_parse_from(["kin", "git", "export", "--in-place"])
                .expect("exact Git export remains the explicit interoperability surface");
            assert!(matches!(
                cli.command,
                Command::Git {
                    action: GitAction::Export {
                        output: None,
                        in_place: true
                    }
                }
            ));
        });
    }

    #[test]
    fn update_release_expectation_tuple_is_complete_and_works_with_check_only() {
        on_cli_test_stack(|| {
            let digest = "a".repeat(64);
            let uppercase_digest = "C".repeat(64);
            for args in [
                vec!["kin", "update", "--expect-version", "0.2.22"],
                vec![
                    "kin",
                    "update",
                    "--expect-sha",
                    "0123456789abcdef0123456789abcdef01234567",
                ],
                vec!["kin", "update", "--expect-archive-sha256", digest.as_str()],
                vec![
                    "kin",
                    "update",
                    "--expect-version",
                    "0.2.22",
                    "--expect-sha",
                    "0123456789abcdef0123456789abcdef01234567",
                ],
            ] {
                assert!(Cli::try_parse_from(args).is_err());
            }

            let cli = Cli::try_parse_from([
                "kin",
                "update",
                "--channel",
                "stable",
                "--expect-version",
                "0.2.22",
                "--expect-sha",
                "0123456789ABCDEF0123456789ABCDEF01234567",
                "--expect-archive-sha256",
                uppercase_digest.as_str(),
                "--check-only",
                "--json",
            ])
            .expect("complete release expectation must be accepted for check-only automation");
            match cli.command {
                Command::Update {
                    expect_version,
                    expect_sha,
                    expect_archive_sha256,
                    check_only,
                    json,
                    ..
                } => {
                    assert_eq!(expect_version.unwrap(), semver::Version::new(0, 2, 22));
                    assert_eq!(
                        expect_sha.unwrap(),
                        "0123456789abcdef0123456789abcdef01234567"
                    );
                    assert_eq!(expect_archive_sha256.unwrap(), "c".repeat(64));
                    assert!(check_only);
                    assert!(json);
                }
                _ => panic!("expected update command"),
            }
        });
    }

    #[test]
    fn restart_ack_rejects_release_pins_at_argument_parsing() {
        on_cli_test_stack(|| {
            let digest = "a".repeat(64);
            assert!(Cli::try_parse_from([
                "kin",
                "update",
                "--expect-version",
                "0.2.22",
                "--expect-sha",
                "0123456789abcdef0123456789abcdef01234567",
                "--expect-archive-sha256",
                digest.as_str(),
                "--ack-restart",
            ])
            .is_err());
        });
    }

    #[test]
    fn exec_shell_mode_is_explicit_and_direct_mode_preserves_cli_parts() {
        on_cli_test_stack(|| {
            let direct = Cli::try_parse_from([
                "kin",
                "exec",
                "--",
                "printf",
                "value with spaces",
                "literal;semicolon",
            ])
            .unwrap();
            match direct.command {
                Command::Exec { command, shell, .. } => {
                    assert!(!shell);
                    assert_eq!(
                        command,
                        vec!["printf", "value with spaces", "literal;semicolon"]
                    );
                }
                _ => panic!("expected exec command"),
            }

            let shell = Cli::try_parse_from([
                "kin",
                "exec",
                "--shell",
                "--",
                "printf '%s' \"$KIN_REPO_ID\"",
            ])
            .unwrap();
            match shell.command {
                Command::Exec { command, shell, .. } => {
                    assert!(shell);
                    assert_eq!(command, vec!["printf '%s' \"$KIN_REPO_ID\""]);
                }
                _ => panic!("expected exec command"),
            }

            assert!(
                Cli::try_parse_from(["kin", "run", "--", "true"]).is_err(),
                "the pre-release `run` compatibility alias must not remain"
            );
        });
    }
}
