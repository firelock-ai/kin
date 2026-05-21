// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{self, Shell};
use kin_cli::commands;
use std::path::PathBuf;
use tracing::Instrument;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "kin", version, about = "Kin semantic VCS")]
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
    /// Initialize a new Kin repository
    Init {
        /// Directory to initialize (defaults to current directory)
        path: Option<String>,
        /// Output machine-readable JSON status instead of human text
        #[arg(long, default_value_t = false)]
        json: bool,
        /// Skip the Git repository check (init even if .git/ exists)
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Show detailed classification, parsing, and role assignment info
        #[arg(short, long, default_value_t = false)]
        verbose: bool,
        /// Skip LSP enrichment (faster init, tree-sitter only)
        #[arg(long, default_value_t = false)]
        no_lsp: bool,
        /// Git history import depth for detected Git repositories: `off`, `recent`, or `full`
        #[arg(long, default_value = "recent", value_parser = ["off", "recent", "full"])]
        git_history: String,
    },
    /// Show working copy status
    Status {
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Create a semantic commit
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
    /// Show semantic change log
    Log {
        /// Maximum number of entries
        #[arg(short = 'n', long, default_value = "10")]
        count: usize,
    },
    /// Branch operations
    Branch {
        #[command(subcommand)]
        action: BranchAction,
    },
    /// Show entity diff between changes
    Diff {
        /// Base change ID
        base: Option<String>,
        /// Head change ID
        head: Option<String>,
    },
    /// Remove Kin and restore files to pre-init state
    Eject {
        /// Skip confirmation prompt
        #[arg(long)]
        force: bool,
    },
    /// Show downstream impact of an entity
    Impact {
        /// Entity name or ID
        entity: String,
        /// Maximum depth
        #[arg(short, long, default_value = "3")]
        depth: u32,
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
    /// Generates vector embeddings for all entities using a local BERT model
    /// (BGE-small-en-v1.5, 384 dimensions). Embeddings enable semantic similarity
    /// search in `kin locate` and `kin search --semantic`.
    ///
    /// Fast init + progressive embedding: `kin init` builds the graph instantly,
    /// then `kin embed` adds vector search capability as a separate step.
    Embed {
        /// Embedding batch size (entities per inference pass).
        #[arg(long, default_value_t = crate::commands::embed::DEFAULT_BATCH_SIZE)]
        batch_size: usize,
        /// Stop after this many seconds, persist completed vectors, and leave the rest pending.
        #[arg(long, value_name = "SECONDS")]
        max_seconds: Option<u64>,
        /// Output JSON status instead of progress text.
        #[arg(long)]
        json: bool,
    },
    /// Build a semantic rename plan for an entity and its references
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
        /// Entity name or ID
        entity: String,
        /// Filter relation kinds: all, calls, imports, or references
        #[arg(long, default_value = "all")]
        kind: String,
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
    /// Find dead code
    DeadCode,
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
    /// Semantic merge from another branch
    Merge {
        /// Branch to merge from
        branch: String,
        /// Merge strategy: structural or semantic
        #[arg(short, long, default_value = "structural")]
        strategy: String,
    },
    /// Show active merge conflicts
    Conflicts,
    /// Resolve merge conflicts
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
    /// Stash working copy state
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
    /// Manage workspaces
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Run a validation command and capture evidence
    Run {
        /// Command to execute
        command: String,
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
    /// Plan or prepare a publish to the default remote
    Push {
        /// Remote name (defaults to configured default or detected origin)
        #[arg(long)]
        remote: Option<String>,
    },
    /// Pull changes from a remote
    #[command(visible_alias = "fetch")]
    Pull {
        /// Remote name (defaults to configured default)
        #[arg(long)]
        remote: Option<String>,
    },
    /// Clone a repository
    Clone {
        /// Repository URL (Git or Kin)
        url: String,
        /// Target directory (defaults to repo name)
        path: Option<String>,
    },
    /// Import a repository (git URL or local path) into Kin
    Import {
        /// Repository URL (https/git) or local path
        url: String,
    },
    /// Restore a file from a specific change
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
    /// Execute a command in a materialized workspace
    Exec {
        /// Command to execute
        command: String,
        /// Keep the workspace after execution
        #[arg(long)]
        keep: bool,
        /// Materialization strategy
        #[arg(long)]
        strategy: Option<String>,
        /// Scope filter
        #[arg(long)]
        scope: Option<String>,
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
    /// Analyze semver impact of changes
    Semver,
    /// Create a release snapshot
    #[command(visible_alias = "tag")]
    Release {
        /// Release tag
        tag: String,
        /// Block release if entities lack linked passing tests
        #[arg(long)]
        require_proof: bool,
        /// Block release if unapproved agent changes exist
        #[arg(long)]
        require_approval: bool,
        /// Force release even with low coverage
        #[arg(long)]
        force: bool,
    },
    /// Rollback to a previous change
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
    /// Run schema migrations
    Migrate {
        /// Source repository path (defaults to current directory)
        source: Option<String>,
        /// Migration depth: shallow (HEAD only) or deep (full history)
        #[arg(short, long, default_value = "shallow")]
        depth: String,
        /// Resume an interrupted migration from the last checkpoint
        #[arg(long)]
        resume: bool,
    },
    /// Inspect and validate the semantic graph
    Graph {
        #[command(subcommand)]
        action: GraphAction,
    },
    /// Git interop commands
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
    /// Launch an editor in a materialized session workspace
    Open {
        /// Editor to launch: code, cursor, or any editor command
        editor: String,
        /// In native mode, block filesystem discovery commands and require Kin discovery
        #[arg(long)]
        restrict_discovery: bool,
        /// In native mode, block both filesystem discovery and direct file reads
        #[arg(long, conflicts_with = "restrict_discovery")]
        restrict_filesystem: bool,
        /// Wait for the editor to exit, then reconcile and clean up automatically
        #[arg(long)]
        wait: bool,
    },
    /// Launch an assistant with Kin guidance injected
    With {
        /// Assistant to launch: claude, codex, gemini
        assistant: String,
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
    /// Reconcile session workspace changes back into the graph
    Reconcile {
        /// Session ID (defaults to most recent session)
        session: Option<String>,
        /// Remove the session workspace after successful reconciliation
        #[arg(long)]
        cleanup: bool,
    },
    /// Open an interactive shell in a materialized session workspace
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
        /// Skip signature and checksum verification (NOT recommended)
        #[arg(long)]
        skip_verify: bool,
    },
    /// Show or manage the global Kin repository registry
    Registry {
        #[command(subcommand)]
        action: Option<RegistryAction>,
    },
    /// First-time setup and health checks for the Kin system
    Setup {
        #[command(subcommand)]
        action: Option<SetupAction>,
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
}

#[derive(Subcommand)]
enum BranchAction {
    /// List branches
    List,
    /// Create a new branch
    Create {
        /// Branch name
        name: String,
    },
    /// Delete a branch
    Delete {
        /// Branch name
        name: String,
    },
    /// Switch to a branch
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
        /// Entity name to inspect
        name: String,
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
enum GitAction {
    /// Export current state to Git
    Export {
        /// Target directory
        #[arg(short, long)]
        output: Option<String>,
        /// Allow exporting directly into the checked-out Git working repository
        #[arg(long, default_value_t = false)]
        in_place: bool,
    },
    /// Import from Git history (deprecated: use `kin init` or `kin migrate` instead)
    #[command(hide = true)]
    Import {
        /// Git repository path
        path: Option<String>,
    },
    /// Sync with Git remote
    Sync {
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
    /// Show the push plan for a remote
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
    /// Save current working state
    Push,
    /// Restore the most recent stash entry
    Pop,
    /// List stash entries
    List,
}

#[derive(Subcommand)]
enum WorkspaceAction {
    /// List workspaces
    List,
    /// Create a new workspace
    Create {
        /// Workspace name
        name: String,
    },
    /// Switch to a workspace
    Switch {
        /// Workspace name
        name: String,
    },
    /// Delete a workspace
    Delete {
        /// Workspace name
        name: String,
    },
    /// Rename a workspace
    Rename {
        /// Current workspace name
        old_name: String,
        /// New workspace name
        new_name: String,
    },
}

#[derive(Subcommand)]
enum McpAction {
    /// Start the MCP stdio server
    Start {
        /// Run in global mode, serving all registered repos from ~/.kin/registry.toml
        #[arg(long)]
        global: bool,
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
    Status,
    /// Quick health check
    Doctor,
}

#[derive(Subcommand)]
enum RegistryAction {
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
                Command::Init {
                    path,
                    json,
                    force,
                    verbose,
                    no_lsp,
                    git_history,
                } => commands::init::run(path, json, force, verbose, no_lsp, git_history).await,
                Command::Status { json } => {
                    if json {
                        commands::status::run_json().await
                    } else {
                        commands::status::run().await
                    }
                }
                Command::Commit {
                    message,
                    quiet,
                    dry_run: _,
                } => commands::commit::run(message, quiet).await,
                Command::Log { count } => commands::log::run(count).await,
                Command::Branch { action } => match action {
                    BranchAction::List => commands::branch::list().await,
                    BranchAction::Create { name } => commands::branch::create(name).await,
                    BranchAction::Delete { name } => commands::branch::delete(name).await,
                    BranchAction::Switch { name } => commands::branch::switch(name).await,
                },
                Command::Diff { base, head } => commands::diff::run(base, head).await,
                Command::Eject { force } => commands::eject::run(force).await,
                Command::Impact { entity, depth } => commands::impact::run(entity, depth).await,
                Command::Context {
                    entity,
                    budget,
                    assistant,
                } => commands::context::run(entity, budget, assistant).await,
                Command::ContextbenchLocate { task_file, json } => {
                    commands::contextbench_locate::run(task_file, json).await
                }
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
                    file,
                    stdin,
                    json,
                    explain,
                    diagnose,
                    gold,
                    max_files,
                    reference,
                } => {
                    // --diagnose implies --json --explain
                    let json = json || diagnose;
                    let explain = explain || diagnose;
                    let max_files_explicit = max_files.is_some();
                    let max_files_val = max_files.unwrap_or(10);
                    let problem_text = if stdin {
                        let mut buf = String::new();
                        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)?;
                        buf
                    } else if let Some(path) = file {
                        std::fs::read_to_string(&path)?
                    } else if let Some(t) = text {
                        t
                    } else {
                        anyhow::bail!("provide problem text, --file, or --stdin");
                    };
                    if diagnose {
                        // Diagnostic mode: capture result, print JSON, then
                        // print gold file comparison to stderr.
                        let result = commands::locate::capture(
                            &problem_text,
                            true, // always explain in diagnose mode
                            max_files_val,
                            max_files_explicit,
                            reference,
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
                                        if stage_info.is_empty() {
                                            if !debug.resolved_files.is_empty() {
                                                if let Some(rf) = debug
                                                    .resolved_files
                                                    .iter()
                                                    .find(|r| r.path == *g)
                                                {
                                                    stage_info = format!(
                                                        " (resolved at score {:.1})",
                                                        rf.score
                                                    );
                                                }
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
                            json,
                            explain,
                            max_files_val,
                            max_files_explicit,
                            reference,
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
                    json,
                } => commands::embed::run(batch_size, json, max_seconds).await,
                Command::Rename {
                    symbol,
                    new_name,
                    file,
                    line,
                    column,
                    json,
                } => commands::rename::run(symbol, new_name, file, line, column, json).await,
                Command::Refs { entity, kind } => commands::refs::run(entity, kind).await,
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
                Command::DeadCode => commands::dead_code::run().await,
                Command::Deps => commands::deps::run().await,
                Command::Xref { entity } => commands::xref::run(entity).await,
                Command::Spec { action } => match action {
                    SpecAction::Create { intent } => commands::spec::create(intent).await,
                    SpecAction::List => commands::spec::list().await,
                    SpecAction::Show { id } => commands::spec::show(id).await,
                },
                Command::Merge { branch, strategy } => commands::merge::run(branch, strategy).await,
                Command::Conflicts => commands::conflicts::run().await,
                Command::Resolve {
                    ours,
                    theirs,
                    all_ours,
                    all_theirs,
                    do_continue,
                    abort,
                } => {
                    commands::resolve::run(ours, theirs, all_ours, all_theirs, do_continue, abort)
                        .await
                }
                Command::Stash { action } => match action {
                    StashAction::Push => commands::stash::push().await,
                    StashAction::Pop => commands::stash::pop().await,
                    StashAction::List => commands::stash::list().await,
                },
                Command::Blame { entity, reference } => {
                    commands::blame::run(entity, reference).await
                }
                Command::Workspace { action } => match action {
                    WorkspaceAction::List => commands::workspace::list().await,
                    WorkspaceAction::Create { name } => commands::workspace::create(name).await,
                    WorkspaceAction::Switch { name } => commands::workspace::switch(name).await,
                    WorkspaceAction::Delete { name } => commands::workspace::delete(name).await,
                    WorkspaceAction::Rename { old_name, new_name } => {
                        commands::workspace::rename(old_name, new_name).await
                    }
                },
                Command::Run { command } => commands::run::run(command).await,
                Command::Mcp { action } => match action {
                    McpAction::Start { global: _ } => commands::mcp::start().await,
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
                    RemoteAction::PlanPush { remote } => commands::remote::plan_push(remote).await,
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
                Command::Push { remote } => commands::push::run(remote).await,
                Command::Pull { remote } => commands::pull::run(remote).await,
                Command::Clone { url, path } => commands::clone::run(url, path).await,
                Command::Import { url } => commands::import::run(url).await,
                Command::Checkout { path, change } => commands::checkout::run(path, change).await,
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
                Command::Exec {
                    command,
                    keep,
                    strategy,
                    scope,
                } => commands::exec::run_full(command, keep, strategy, scope).await,
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
                Command::Semver => commands::release::semver().await,
                Command::Release {
                    tag,
                    require_proof,
                    require_approval,
                    force,
                } => {
                    commands::release::release_with_options(
                        tag,
                        commands::release::ReleaseOptions {
                            force,
                            require_proof,
                            require_approval,
                        },
                    )
                    .await
                }
                Command::Rollback { change_id, feature } => {
                    commands::release::rollback_with_options(change_id, feature).await
                }
                Command::Bench { args } => commands::bench::bench_proxy(&args),
                Command::Migrate {
                    source,
                    depth,
                    resume,
                } => commands::migrate::run(source, depth, resume).await,
                Command::Graph { action } => match action {
                    GraphAction::Status => commands::graph::status().await,
                    GraphAction::Validate => commands::graph::validate().await,
                    GraphAction::Inspect { name } => commands::graph::inspect(name).await,
                    GraphAction::Viz { port, open } => commands::graph_viz::run(port, open).await,
                },
                Command::Git { action } => match action {
                    GitAction::Export { output, in_place } => {
                        commands::git::export(output, in_place).await
                    }
                    GitAction::Import { path } => commands::git::import(path).await,
                    GitAction::Sync { in_place } => commands::git::sync(in_place).await,
                },
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
                Command::Open {
                    editor,
                    restrict_discovery,
                    restrict_filesystem,
                    wait,
                } => {
                    commands::open::run(editor, restrict_discovery, restrict_filesystem, wait).await
                }
                Command::Reconcile { session, cleanup } => {
                    commands::reconcile::run(session, cleanup).await
                }
                Command::With {
                    assistant,
                    passive_guidance,
                    restrict_discovery,
                    restrict_filesystem,
                    task,
                } => {
                    commands::with::run(
                        assistant,
                        task,
                        passive_guidance,
                        restrict_discovery,
                        restrict_filesystem,
                    )
                    .await
                }
                Command::Shell {
                    strategy,
                    restrict_discovery,
                    restrict_filesystem,
                } => commands::shell::run(strategy, restrict_discovery, restrict_filesystem).await,
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
                Command::Update { skip_verify } => commands::update::run(skip_verify).await,
                Command::Registry { action } => match action {
                    Some(RegistryAction::Daemons { json }) => {
                        commands::registry::daemons(json).await
                    }
                    Some(RegistryAction::Clean) => commands::registry::clean().await,
                    None => commands::registry::list().await,
                },
                Command::Setup {
                    action,
                    mode,
                    shell,
                    auto_daemon,
                    no_interactive,
                } => match action {
                    Some(SetupAction::Status) => commands::setup::status().await,
                    Some(SetupAction::Doctor) => commands::setup::doctor().await,
                    None => {
                        commands::setup::run_wizard(commands::setup::WizardOptions {
                            mode,
                            shell,
                            auto_daemon,
                            no_interactive,
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

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
