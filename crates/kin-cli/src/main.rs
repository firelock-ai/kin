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
    },
    /// Search entities in the graph
    Search {
        /// Search pattern
        pattern: String,
        /// Filter by entity kind
        #[arg(short, long)]
        kind: Option<String>,
        /// Filter by language
        #[arg(short, long)]
        language: Option<String>,
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
    /// Run benchmarks
    Bench,
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

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init { path } => commands::init::run(path).await,
        Command::Status => commands::status::run().await,
        Command::Commit { message } => commands::commit::run(message).await,
        Command::Log { count } => commands::log::run(count).await,
        Command::Branch { action } => match action {
            BranchAction::List => commands::branch::list().await,
            BranchAction::Create { name } => commands::branch::create(name).await,
            BranchAction::Delete { name } => commands::branch::delete(name).await,
            BranchAction::Switch { name } => commands::branch::switch(name).await,
        },
        Command::Diff { base, head } => commands::diff::run(base, head).await,
        Command::Impact { entity, depth } => commands::impact::run(entity, depth).await,
        Command::Context { entity, budget } => commands::context::run(entity, budget).await,
        Command::Search {
            pattern,
            kind,
            language,
        } => commands::search::run(pattern, kind, language).await,
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
        },
        Command::Run { command } => commands::run::run(command).await,
        Command::Mcp { action } => match action {
            McpAction::Start => commands::mcp::start().await,
        },
        Command::Bench => commands::bench::run().await,
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
            AssistantAction::Install { assistant } => {
                commands::assistant::install(assistant).await
            }
            AssistantAction::Doctor { assistant } => {
                commands::assistant::run_doctor(assistant).await
            }
            AssistantAction::List => commands::assistant::list().await,
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
        },
        Command::Note { action } => match action {
            NoteAction::Add { scope, kind, body } => commands::note::add(scope, kind, body).await,
            NoteAction::List { scope } => commands::note::list(scope).await,
            NoteAction::Stale => commands::note::stale().await,
        },
        Command::Feature { title, description } => {
            commands::work::create(
                "feature".to_string(),
                title,
                description,
                None,
                None,
            )
            .await
        }
        Command::Todo { action } => match action {
            TodoAction::Import { path } => commands::note::todo_import(path).await,
        },
    }
}
