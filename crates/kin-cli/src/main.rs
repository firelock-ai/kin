use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

mod commands;

#[derive(Parser)]
#[command(name = "kin", version, about = "Kin semantic VCS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new Kin repository
    Init {
        /// Directory to initialize (defaults to current directory)
        path: Option<String>,
    },
    /// Show working copy status
    Status,
    /// Create a semantic commit
    Commit {
        /// Commit message
        #[arg(short, long)]
        message: String,
        /// Suppress progress output (only print final summary)
        #[arg(short, long)]
        quiet: bool,
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
    /// Trace a focal entity in one shot: resolve it, show the body, and summarize nearby context
    Trace {
        /// Entity name or ID
        entity: String,
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
    },
    /// Show upstream callers/importers/references for an entity
    Refs {
        /// Entity name or ID
        entity: String,
        /// Filter relation kinds: all, calls, imports, or references
        #[arg(long, default_value = "all")]
        kind: String,
    },
    /// Run semantic review on changes
    Review {
        /// Change ID to review (defaults to latest)
        change: Option<String>,
    },
    /// Show entity history
    History {
        /// Entity name or ID
        entity: String,
    },
    /// Find dead code
    DeadCode,
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
    /// Stash working copy state
    Stash {
        #[command(subcommand)]
        action: StashAction,
    },
    /// Show blame (version history) for an entity
    Blame {
        /// Entity name or ID
        entity: String,
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
    /// Show support and coverage report
    Support,
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
    Rollback {
        /// Change ID to rollback to
        change_id: String,
        /// Rollback all changes linked to a work item ID
        #[arg(long)]
        feature: Option<String>,
    },
    /// Run benchmarks
    Bench {
        #[command(subcommand)]
        action: Option<BenchAction>,
    },
    /// Run schema migrations
    Migrate {
        /// Source repository path (defaults to current directory)
        source: Option<String>,
        /// Migration depth: shallow (HEAD only) or deep (full history)
        #[arg(short, long, default_value = "shallow")]
        depth: String,
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
    /// Manage repository mode (compat or native)
    Mode {
        #[command(subcommand)]
        action: ModeAction,
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
enum GitAction {
    /// Export current state to Git
    Export {
        /// Target directory
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Import from Git history
    Import {
        /// Git repository path
        path: Option<String>,
    },
    /// Sync with Git remote
    Sync,
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
    Start,
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
    /// Add an annotation to a scope
    Add {
        /// Scope to annotate (entity:<uuid>, artifact:<path>, or bare path)
        scope: String,
        /// Annotation kind: comment, warning, instruction, reasoning
        #[arg(short, long)]
        kind: String,
        /// Annotation body
        #[arg(short, long)]
        body: String,
    },
    /// List annotations for a scope
    List {
        /// Scope to query
        scope: String,
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
enum ModeAction {
    /// Switch to Kin-native mode (source files move to .kin/source-root/)
    Native,
    /// Switch back to compatibility mode (source files at repo root)
    Compat,
    /// Show current repository mode
    Show,
}

#[derive(Subcommand)]
enum BenchAction {
    /// Run benchmarks with optional assistant run files
    Run {
        /// Paths to assistant run JSON files
        #[arg(long = "assistant-run")]
        assistant_run: Vec<String>,
    },
    /// Run corpus benchmarks across repos
    Corpus {
        /// Repository paths
        #[arg(long = "repo")]
        repo: Vec<String>,
        /// Directory containing GitHub repos
        #[arg(long = "github-dir")]
        github_dir: Option<String>,
    },
    /// Capture a benchmark run from flags
    Capture {
        /// Assistant name
        #[arg(long)]
        assistant: String,
        /// Task name
        #[arg(long)]
        task: String,
        /// Substrate: git or kin
        #[arg(long)]
        substrate: String,
        /// Model name
        #[arg(long)]
        model: Option<String>,
        /// Duration in milliseconds
        #[arg(long)]
        duration_ms: f64,
        /// Input tokens
        #[arg(long)]
        tokens_in: u64,
        /// Output tokens
        #[arg(long)]
        tokens_out: u64,
        /// Estimated cost in USD
        #[arg(long)]
        cost: f64,
        /// Whether validation passed
        #[arg(long)]
        passed: bool,
    },
    /// Capture a benchmark run from a vendor artifact file
    CaptureArtifact {
        /// Vendor: claude, codex, gemini
        #[arg(long)]
        vendor: String,
        /// Path to the artifact file
        #[arg(long)]
        path: String,
        /// Task name (defaults to filename stem)
        #[arg(long)]
        task: Option<String>,
        /// Substrate: git or kin (defaults to kin)
        #[arg(long)]
        substrate: Option<String>,
    },
    /// Run live benchmark arms (git, kin-compat, kin-native, and optional native variants)
    /// using detected assistant CLIs
    Live {
        /// Repository URL or local path to benchmark (defaults to current directory)
        #[arg(long)]
        repo: Option<String>,
        /// Custom task prompts (can be repeated; defaults to built-in tasks if omitted)
        #[arg(long = "task")]
        tasks: Vec<String>,
        /// Only run built-in tasks with these exact names (can be repeated)
        #[arg(long = "task-name")]
        task_names: Vec<String>,
        /// Which built-in task set to run: discovery, mutation, or all (default: all).
        /// Ignored when --task is provided.
        #[arg(long, default_value = "all")]
        task_set: String,
        /// Only run with this assistant CLI (claude, codex, or gemini)
        #[arg(long)]
        assistant: Option<String>,
        /// Exclude specific CLIs (can be repeated, e.g. --exclude gemini --exclude claude)
        #[arg(long = "exclude")]
        exclude: Vec<String>,
        /// Number of repetitions per task (default 1)
        #[arg(long, default_value = "1")]
        repeat: u32,
        /// Only run these benchmark arms (git, kin-compat, kin-native, kin-native-cli, kin-codex-native)
        #[arg(long = "arm")]
        arms: Vec<String>,
        /// Skip resource monitoring during runs
        #[arg(long)]
        no_monitor: bool,
        /// Keep workspace after benchmark (skip cleanup)
        #[arg(long)]
        keep_workspace: bool,
        /// [Shim mode] Inject PATH shims that block discovery commands (ls, find, tree). Default native mode uses MCP + permission deny rules instead.
        #[arg(long)]
        native_restrict_discovery: bool,
        /// [Shim mode] Inject PATH shims that block both discovery AND file reads (cat, head, grep). Default native mode uses MCP + permission deny rules instead.
        #[arg(long, conflicts_with = "native_restrict_discovery")]
        native_restrict_filesystem: bool,
        /// Force fresh kin init + commit, ignoring any cached conversion
        #[arg(long, alias = "rebuild-cache")]
        fresh_conversion: bool,
        /// For Claude runs, disable subagent delegation across all arms
        #[arg(long)]
        claude_disable_explore: bool,
        /// Path to a Claude Code plugin directory to load for Kin arms
        #[arg(long)]
        plugin_dir: Option<String>,
        /// Include the experimental kin-codex-native arm in the live matrix
        #[arg(long)]
        include_kin_codex_native: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init { path } => commands::init::run(path).await,
        Command::Status => commands::status::run().await,
        Command::Commit { message, quiet } => commands::commit::run(message, quiet).await,
        Command::Log { count } => commands::log::run(count).await,
        Command::Branch { action } => match action {
            BranchAction::List => commands::branch::list().await,
            BranchAction::Create { name } => commands::branch::create(name).await,
            BranchAction::Delete { name } => commands::branch::delete(name).await,
            BranchAction::Switch { name } => commands::branch::switch(name).await,
        },
        Command::Diff { base, head } => commands::diff::run(base, head).await,
        Command::Impact { entity, depth } => commands::impact::run(entity, depth).await,
        Command::Context {
            entity,
            budget,
            assistant,
        } => commands::context::run(entity, budget, assistant).await,
        Command::Trace {
            entity,
            compact,
            show_body: _,
            limit,
            budget,
            assistant,
            max_lines,
            nearby,
            transitive,
        } => {
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
        Command::Search {
            pattern,
            kind,
            language,
            show_body,
            limit,
        } => commands::search::run(pattern, kind, language, show_body, limit).await,
        Command::Refs { entity, kind } => commands::refs::run(entity, kind).await,
        Command::Review { change } => commands::review::run(change).await,
        Command::History { entity } => commands::history::run(entity).await,
        Command::DeadCode => commands::dead_code::run().await,
        Command::Spec { action } => match action {
            SpecAction::Create { intent } => commands::spec::create(intent).await,
            SpecAction::List => commands::spec::list().await,
            SpecAction::Show { id } => commands::spec::show(id).await,
        },
        Command::Merge { branch, strategy } => commands::merge::run(branch, strategy).await,
        Command::Stash { action } => match action {
            StashAction::Push => commands::stash::push().await,
            StashAction::Pop => commands::stash::pop().await,
            StashAction::List => commands::stash::list().await,
        },
        Command::Blame { entity } => commands::blame::run(entity).await,
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
            McpAction::Start => commands::mcp::start().await,
        },
        Command::Verify { action } => match action {
            VerifyAction::Entity { entity } => commands::verify::run(entity).await,
            VerifyAction::Summary => commands::verify::summary().await,
            VerifyAction::Missing => commands::verify::missing().await,
            VerifyAction::Run { entity, runner } => {
                commands::verify::run_verification(entity, runner).await
            }
        },
        Command::Exec {
            command,
            keep,
            strategy,
            scope,
        } => commands::exec::run_full(command, keep, strategy, scope).await,
        Command::Support => commands::support::run().await,
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
        Command::Approvals { action } => match action {
            ApprovalsAction::Show { change_id } => commands::approvals::show(change_id).await,
            ApprovalsAction::List => commands::approvals::list().await,
        },
        Command::Security { propagate } => commands::security::run_with_options(propagate).await,
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
        Command::Bench { action } => match action {
            Some(BenchAction::Run { assistant_run }) => commands::bench::run(assistant_run).await,
            Some(BenchAction::Corpus { repo, github_dir }) => {
                commands::bench::corpus(repo, github_dir).await
            }
            Some(BenchAction::Capture {
                assistant,
                task,
                substrate,
                model,
                duration_ms,
                tokens_in,
                tokens_out,
                cost,
                passed,
            }) => {
                commands::bench::capture(
                    assistant,
                    task,
                    substrate,
                    model,
                    duration_ms,
                    tokens_in,
                    tokens_out,
                    cost,
                    passed,
                )
                .await
            }
            Some(BenchAction::CaptureArtifact {
                vendor,
                path,
                task,
                substrate,
            }) => commands::bench::capture_artifact(&vendor, path, task, substrate).await,
            Some(BenchAction::Live {
                repo,
                tasks,
                task_names,
                task_set,
                assistant,
                exclude,
                repeat,
                arms,
                no_monitor,
                keep_workspace,
                native_restrict_discovery,
                native_restrict_filesystem,
                fresh_conversion,
                claude_disable_explore,
                plugin_dir,
                include_kin_codex_native,
            }) => {
                commands::bench::run_live(
                    repo,
                    tasks,
                    task_names,
                    task_set,
                    assistant,
                    exclude,
                    repeat,
                    arms,
                    no_monitor,
                    keep_workspace,
                    native_restrict_discovery,
                    native_restrict_filesystem,
                    fresh_conversion,
                    claude_disable_explore,
                    plugin_dir,
                    include_kin_codex_native,
                )
                .await
            }
            None => commands::bench::run(vec![]).await,
        },
        Command::Migrate { source, depth } => commands::migrate::run(source, depth).await,
        Command::Git { action } => match action {
            GitAction::Export { output } => commands::git::export(output).await,
            GitAction::Import { path } => commands::git::import(path).await,
            GitAction::Sync => commands::git::sync().await,
        },
        Command::Intent { action } => match action {
            IntentAction::List => commands::intent::list().await,
            IntentAction::Register {
                scope,
                lock,
                task,
                session,
            } => commands::intent::register(scope, lock, task, session).await,
            IntentAction::Release { intent_id } => commands::intent::release(intent_id).await,
            IntentAction::Clear { session_id } => commands::intent::clear(session_id).await,
        },
        Command::Traffic { action } => match action {
            TrafficAction::Show { scope } => commands::traffic::run(scope).await,
            TrafficAction::Sessions => commands::traffic::sessions().await,
        },
        Command::Assistant { action } => match action {
            AssistantAction::Install { assistant } => commands::assistant::install(assistant).await,
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
            AssistantAction::Hooks { assistant } => commands::assistant::hooks(assistant).await,
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
            WorkAction::List { status, kind } => commands::work::list(status, kind).await,
            WorkAction::Show { work_id } => commands::work::show(work_id).await,
            WorkAction::Link { work_id, scope } => commands::work::link(work_id, scope).await,
            WorkAction::Close { work_id } => commands::work::close(work_id).await,
            WorkAction::Verify { work_id } => commands::work::verify(work_id).await,
        },
        Command::Note { action } => match action {
            NoteAction::Add { scope, kind, body } => commands::note::add(scope, kind, body).await,
            NoteAction::List { scope } => commands::note::list(scope).await,
            NoteAction::Stale => commands::note::stale().await,
        },
        Command::Feature { title, description } => {
            commands::work::create("feature".to_string(), title, description, None, None).await
        }
        Command::Todo { action } => match action {
            TodoAction::Import { path } => commands::note::todo_import(path).await,
        },
        Command::Open {
            editor,
            restrict_discovery,
            restrict_filesystem,
            wait,
        } => commands::open::run(editor, restrict_discovery, restrict_filesystem, wait).await,
        Command::Reconcile { session, cleanup } => commands::reconcile::run(session, cleanup).await,
        Command::Mode { action } => match action {
            ModeAction::Native => commands::mode::native().await,
            ModeAction::Compat => commands::mode::compat().await,
            ModeAction::Show => commands::mode::show().await,
        },
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
        Command::Overview { compact } => commands::overview::run(compact).await,
    }
}
