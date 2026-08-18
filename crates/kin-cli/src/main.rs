// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{self, Shell};
use kin_cli::commands;
use std::io::IsTerminal;
use std::path::PathBuf;
use tracing::Instrument;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

kin_buildinfo::embed_update_build_identity!(
    KIN_UPDATE_BUILD_IDENTITY,
    env!("CARGO_PKG_VERSION"),
    kin_db::GraphSnapshot::CURRENT_VERSION
);

/// Orientation for the flat subcommand list. The command surface is wide
/// because it spans version control, semantic query, sessions, and operations,
/// and clap renders subcommands as one undifferentiated block with no grouping
/// primitive. Naming the everyday path here is what separates it from the
/// benchmarking, hosted-release, and diagnostic commands beside it.
const AFTER_HELP: &str = "\
Start here:
  kin init            admit an existing or new repository
  kin clone <source>  admit a repository from elsewhere
  kin status          workspace, refs, and semantic enrichment state
  kin commit          publish an exact semantic and artifact change
  kin log / kin diff  read the immutable change log and exact changes

Ask the graph:
  kin locate / search / trace / impact / refs / context

`kin capabilities` prints the full readiness matrix, `--json` for machines.";

/// The `[OPEN GATE]` legend, which is only true while something carries the
/// marker.
const OPEN_GATE_LEGEND: &str = "\n\nCommands marked [OPEN GATE] are fail-closed on \
repository-v6 and say why when run.";

/// Root after-help, with the open-gate legend appended only when the inventory
/// actually reports a gate.
///
/// The legend teaches a marker, so printing it when nothing is marked tells a
/// caller scanning the list for what works that everything is ready. It had
/// been doing exactly that: the gates all closed, the markers came off, and the
/// sentence describing them stayed, pinned by a test asserting the bare string.
///
/// An unreadable inventory drops the legend rather than failing, because help
/// has to render; a broken inventory is reported by `kin capabilities`, which
/// is the command that exists to read it.
fn after_help() -> String {
    let gated = commands::capabilities::inventory()
        .map(|inventory| {
            inventory.commands.iter().any(|capability| {
                capability.status == commands::capabilities::CapabilityStatus::OpenGate
            })
        })
        .unwrap_or(false);
    if gated {
        format!("{AFTER_HELP}{OPEN_GATE_LEGEND}")
    } else {
        AFTER_HELP.to_string()
    }
}

#[derive(Parser)]
#[command(
    name = "kin",
    version = kin_buildinfo::version(),
    about = "Kin semantic VCS",
    after_help = after_help(),
)]
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
        /// Add the per-command notes under each matrix row
        #[arg(long, default_value_t = false, conflicts_with = "json")]
        verbose: bool,
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
        /// Seconds to keep re-reading while embedding coverage is only
        /// momentarily unobservable, such as an embedding pass or a graph
        /// mutation batch spanning the sample. Never waits on a coverage that
        /// was observed, nor on an absence a re-read cannot clear. 0 reads once
        #[arg(long, value_name = "SECONDS", default_value_t = 0)]
        wait_quiesce: u64,
    },
    /// Create an exact semantic and artifact commit
    Commit {
        /// Commit message
        #[arg(short, long)]
        message: String,
        /// Suppress progress output (only print final summary)
        #[arg(short, long)]
        quiet: bool,
    },
    /// Show the immutable repository-v6 change log
    Log {
        /// Maximum number of entries
        #[arg(short = 'n', long, default_value = "10")]
        count: usize,
        /// Output the exact authority-backed report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Repository-v6 branch operations (see subcommand readiness)
    Branch {
        #[command(subcommand)]
        action: BranchAction,
    },
    /// Show exact repository-v6 artifact and semantic changes
    Diff {
        /// Base ref, change ID, Git object ID, HEAD, or ref-hex:<hex>
        base: Option<String>,
        /// Head ref, change ID, Git object ID, WORKSPACE, or ref-hex:<hex>
        head: Option<String>,
        /// Output the exact authority-backed report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Verify graph-derived projection, install exact Git, and detach Kin.
    ///
    /// Every graph-owned artifact and blob must match one durable authority
    /// generation before metadata can be detached.
    Eject {
        /// Skip the typed "eject" confirmation.
        #[arg(long)]
        yes: bool,
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
        /// Emit the resolved target and the whole context pack as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
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
    /// Bounded graph-native rename; unsupported cases fail closed
    Rename {
        /// Entity name or symbol under the cursor
        symbol: String,
        /// Replacement name
        new_name: String,
        /// File hint to disambiguate the target entity
        #[arg(long)]
        file: Option<String>,
        /// 1-based line hint in --file; required when --column is provided
        #[arg(long)]
        line: Option<u32>,
        /// 0-based UTF-8 byte column (tree-sitter coordinate), requires --line
        #[arg(long)]
        column: Option<u32>,
        /// Output machine-readable JSON for editor integrations
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Show upstream callers/importers/references for an entity
    Refs {
        /// Entity name or ID. Required unless --bulk-json + --entities is provided.
        #[arg(required_unless_present = "bulk_json")]
        entity: Option<String>,
        /// Filter relation kinds: all, calls, imports, or references (or Any for bulk mode)
        #[arg(long, default_value = "all")]
        kind: String,
        /// Bulk mode: classify many entities by reachability in one daemon call.
        /// Outputs JSON to stdout. Requires --entities.
        #[arg(long, default_value_t = false, requires = "entities")]
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
        /// Return the chain's shape — names, kinds, roles, spans, edges —
        /// without inlining any source body.
        #[arg(long = "no-bodies", default_value_t = false)]
        no_bodies: bool,
        /// Serialized characters this response may occupy before the tool cuts
        /// bodies, and then steps, to fit (default 80000).
        #[arg(long = "max-response-chars", value_name = "C")]
        max_response_chars: Option<usize>,
    },
    /// Show this repository's recorded cross-repo dependencies
    Deps {
        /// Report every registered repository instead of this one
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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
    /// Merge semantic and exact-tree changes from another branch
    Merge {
        /// Branch to merge from
        branch: String,
        /// Emit the machine-readable merge report
        #[arg(long)]
        json: bool,
    },
    /// Show the durable merge transaction held for this workspace
    Conflicts {
        /// Emit the machine-readable merge transaction record
        #[arg(long)]
        json: bool,
    },
    /// Resolve repository-v6 merge conflicts
    ///
    /// Nine flags name a resolution and at least one is required, which is a
    /// group rather than a per-argument condition. `kin conflicts` is the
    /// read-only view of the same transaction, so nothing here has to accept
    /// an empty invocation in order to be inspectable.
    #[command(group = clap::ArgGroup::new("resolution")
        .required(true)
        .multiple(true)
        .args([
            "ours", "theirs", "base", "remove", "keep_path",
            "all_ours", "all_theirs", "do_continue", "abort",
        ]))]
    Resolve {
        /// Keep your (target branch) version of a conflicting identity
        #[arg(long, value_name = "SELECTOR")]
        ours: Vec<String>,
        /// Keep the incoming (source branch) version of a conflicting identity
        #[arg(long, value_name = "SELECTOR")]
        theirs: Vec<String>,
        /// Keep the merge base version of a conflicting identity
        #[arg(long, value_name = "SELECTOR")]
        base: Vec<String>,
        /// Settle a conflicting identity by dropping it from the merge
        #[arg(long, value_name = "SELECTOR")]
        remove: Vec<String>,
        /// Settle a contested path by naming the artifact that keeps it
        #[arg(long, value_name = "PATH=ARTIFACT")]
        keep_path: Vec<String>,
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
        /// Require the merge transaction to still be the one this identity names
        #[arg(long, value_name = "HASH")]
        expect: Option<String>,
        /// Emit the machine-readable merge transaction record
        #[arg(long)]
        json: bool,
    },
    /// Seal and restore exact graph-owned workspace state
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
    /// Run a task through Kin's own agent loop, or check that it can start.
    ///
    /// The agent answers repository questions from the Kin graph over MCP and has no
    /// shell, no grep and no file-reading tool, so it cannot fall back to raw file
    /// search. Its only writes are edit_file and write_file, and each one runs inside a
    /// Kin transaction under a Kin session, so the change carries provenance naming the
    /// agent rather than landing as an anonymous file write.
    Agent {
        #[command(subcommand)]
        action: AgentAction,
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
    /// Publish exact repository-v6 history to a native Kin remote
    Push {
        /// Remote name (defaults to the configured default native-kin remote)
        #[arg(long)]
        remote: Option<String>,
        /// Peer transfer base URL, overriding any configured remote
        #[arg(long)]
        url: Option<String>,
        /// Ref to publish (defaults to the repository default ref)
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Print the negotiated outcome as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Admit exact repository-v6 history from a native Kin remote and move the
    /// workspace onto it
    #[command(visible_alias = "fetch")]
    Pull {
        /// Remote name (defaults to the configured default native-kin remote)
        #[arg(long)]
        remote: Option<String>,
        /// Peer transfer base URL, overriding any configured remote
        #[arg(long)]
        url: Option<String>,
        /// Ref to admit (defaults to the repository default ref)
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Print the negotiated outcome as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Clone a repository
    Clone {
        /// Git repository URL (native Kin transport is an explicit open gate)
        url: String,
        /// Target directory (defaults to repo name)
        path: Option<String>,
    },
    /// Restore an exact path or subtree from immutable repository-v6 history
    Checkout {
        /// UTF-8 repository path to restore
        path: Option<String>,
        /// Byte-exact repository path as canonical lowercase hexadecimal
        #[arg(long, conflicts_with = "path")]
        path_hex: Option<String>,
        /// Change ID (defaults to current branch head)
        #[arg(long)]
        change: Option<String>,
    },
    /// Verify test coverage for entities
    Verify {
        #[command(subcommand)]
        action: VerifyAction,
    },
    /// Run a command in an exact graph-derived session workspace
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
    /// List the languages Kin extracts semantics from
    Languages {
        /// Output machine-readable JSON
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
    /// Analyze semver impact from immutable repository-v6 changes
    Semver {
        /// Explicit base endpoint: a ref, change, HEAD, or WORKSPACE
        #[arg(long)]
        base: String,
        /// Explicit head endpoint (defaults to the committed workspace base)
        #[arg(long, default_value = "HEAD")]
        head: String,
        /// Emit the machine-readable impact report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Cross-repo release orchestration and per-repo release snapshots
    Release {
        #[command(subcommand)]
        action: ReleaseAction,
    },
    /// Publish an exact repository-v6 tag ref
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
    /// Publish an exact restoration of a previous change
    #[command(visible_alias = "revert")]
    Rollback {
        /// Change ID to rollback to. Omit when naming a work item with --feature.
        #[arg(required_unless_present = "feature", conflicts_with = "feature")]
        change_id: Option<String>,
        /// Roll back every change the named work item records
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
    /// Exact Git interoperability projections
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
    /// Launch an editor over an exact graph-derived session workspace
    Open {
        /// Editor to launch: code or cursor
        editor: String,
    },
    /// Launch an assistant in an exact graph-derived session workspace
    With {
        /// Assistant to launch: claude, codex, gemini
        assistant: String,
        /// Deny the assistant's native discovery tools for this launch, leaving
        /// Kin's semantic tools as the only discovery surface; the enforcement
        /// tier is printed at launch and differs per assistant
        #[arg(long)]
        semantic_only: bool,
        /// Task prompt
        #[arg(last = true)]
        task: Vec<String>,
    },
    /// Hidden PreToolUse adjudicator for a `kin with --semantic-only` session.
    ///
    /// Reads one hook payload on stdin and exits 0 to permit or 2 to refuse.
    /// The launched assistant calls this, not an operator.
    #[command(hide = true)]
    SemanticOnlyGuard,
    /// Retire tracked paths that ignore rules now cover. Reports without changing anything
    /// unless --confirm is given.
    PurgeIgnored {
        /// Publish the removal instead of only reporting it
        #[arg(long)]
        confirm: bool,
        /// Accept a purge that removes more than 75% of a non-trivial tree
        #[arg(long)]
        confirm_mass_deletion: bool,
    },
    /// Admit the complete exact working tree into graph authority now
    ///
    /// The daemon admits a complete tree on startup, on commit, and on what its
    /// watcher observes. This is the trigger for the case none of those covers:
    /// a graph that fell behind its working tree and is waiting for churn that
    /// is not coming.
    Admit,
    /// Admit one exact disposable-session observation into repository-v6 authority
    Reconcile {
        /// Session ID (defaults to most recent session)
        session: Option<String>,
        /// Confirm an observation that removes more than 75% of a non-trivial tree
        #[arg(long)]
        confirm_mass_deletion: bool,
    },
    /// Open a shell in an exact graph-derived session workspace
    Shell {
        /// Materialization strategy
        #[arg(long)]
        strategy: Option<String>,
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
        /// Set how an available update should reach this machine and exit.
        /// `auto` (the default) installs unattended through the gated
        /// executor: it waits for a moment with no managed Kin process or
        /// agent session, defers at most a bounded window, and runs the full
        /// stop-install-acknowledge chain. `prompt` notifies with the remedy
        /// attached and waits to be told. `manual` never notifies; checks
        /// still run.
        #[arg(
            long,
            value_enum,
            value_name = "POLICY",
            conflicts_with_all = [
                "skip_verify",
                "channel",
                "expect_version",
                "expect_sha",
                "expect_archive_sha256",
                "check_only",
                "json",
                "ack_restart",
                "apply"
            ]
        )]
        set_policy: Option<commands::update::UpdatePolicy>,
        /// Bring this machine current in one gesture: install the release,
        /// acknowledge the restart fence, and repair agent configs, in that
        /// order. This is what the update notification's button runs.
        #[arg(long, conflicts_with_all = ["check_only", "json", "ack_restart"])]
        apply: bool,
        /// With --apply: print the ordered steps and change nothing.
        #[arg(long, requires = "apply")]
        dry_run: bool,
        /// Run the unattended executor (what the update watchdog invokes on a
        /// stale install with policy auto): evaluate the machine-activity
        /// gates, and on proceed stop every managed Kin process cooperatively
        /// and run the full --apply chain. Blocked runs persist a deferral
        /// clock instead of installing. The final stdout line is one JSON
        /// record (also appended to ~/.kin/update-ledger.jsonl) carrying the
        /// decision, reason, blocked_seconds, and window_seconds.
        #[arg(long, conflicts_with_all = [
            "skip_verify",
            "channel",
            "expect_version",
            "expect_sha",
            "expect_archive_sha256",
            "check_only",
            "json",
            "ack_restart",
            "set_policy",
            "apply",
            "dry_run"
        ])]
        unattended: bool,
        /// With --unattended: apply despite the activity gates. For the
        /// watchdog once a deferred record shows blocked_seconds >=
        /// window_seconds (24h). Never overrides a recorded prompt or manual
        /// policy, only the executor's own activity gates.
        #[arg(long, requires = "unattended")]
        force_window: bool,
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
        /// Compare an explicit projection observation with graph truth
        #[arg(long, default_value_t = false)]
        drift: bool,
        /// Rematerialize the derived projection from graph truth, DISCARDING
        /// uncommitted changes to tracked files that diverge from it
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
    /// Send a user-facing notification through Kin's own identity
    Notify {
        #[command(subcommand)]
        action: Option<NotifyAction>,
        /// Notification title
        #[arg(long)]
        title: Option<String>,
        /// Notification body
        #[arg(long)]
        body: Option<String>,
        /// Urgency: info (silent), warn (silent), or urgent (sound, breaks through Focus)
        #[arg(long, default_value = "info", value_parser = ["info", "warn", "urgent"])]
        level: String,
        /// Suppression and replacement identity; reposting under the same key
        /// replaces the previous notification instead of stacking another
        #[arg(long)]
        key: Option<String>,
        /// With --key: re-notify only after this many seconds have passed
        #[arg(long)]
        cooldown: Option<u64>,
        /// With --key: notify once, then stay quiet until `kin notify clear`
        #[arg(long, default_value_t = false)]
        latch: bool,
        /// Emit the outcome as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
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
enum NotifyAction {
    /// Release a latch or cooldown so the next send is delivered
    Clear {
        /// The suppression key to forget
        key: String,
        /// Emit the result as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Report which backend would deliver and what is currently held back
    Status {
        /// Emit the report as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
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
    /// List byte-exact repository-v6 branch refs
    List {
        /// Output exact ref names and targets as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Create a ref with compare-and-swap
    Create {
        /// UTF-8 short branch name or fully-qualified refs/heads/... name
        #[arg(required_unless_present = "ref_hex", conflicts_with = "ref_hex")]
        name: Option<String>,
        /// Canonical lowercase hex for a fully-qualified byte-exact branch ref
        #[arg(long, value_name = "LOWER_HEX")]
        ref_hex: Option<String>,
    },
    /// Delete a ref with force-with-lease
    Delete {
        /// UTF-8 short branch name or fully-qualified refs/heads/... name
        #[arg(required_unless_present = "ref_hex", conflicts_with = "ref_hex")]
        name: Option<String>,
        /// Canonical lowercase hex for a fully-qualified byte-exact branch ref
        #[arg(long, value_name = "LOWER_HEX")]
        ref_hex: Option<String>,
    },
    /// Switch workspace authority and projection atomically
    ///
    /// Uncommitted work comes with you, the way it does across a Git checkout.
    /// Pending work at a path the destination branch does not track moves
    /// across and is still uncommitted when you arrive. Pending work at a path
    /// the destination already tracks with identical content becomes an
    /// ordinary member of that branch. A pending edit to a member both branches
    /// hold identically moves across too.
    ///
    /// The switch refuses only where replaying the work would lose something:
    /// a new file whose path the destination tracks with different content, or
    /// an edit to a member the destination holds differently or does not hold
    /// at all. It names every blocked path, and commit or `kin stash push`
    /// clears the way.
    Switch {
        /// UTF-8 short branch name or fully-qualified refs/heads/... name
        #[arg(required_unless_present = "ref_hex", conflicts_with = "ref_hex")]
        name: Option<String>,
        /// Canonical lowercase hex for a fully-qualified byte-exact branch ref
        #[arg(long, value_name = "LOWER_HEX")]
        ref_hex: Option<String>,
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
    List {
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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
    List {
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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
        /// Stop scanning after this many entries and report the partial totals.
        /// Unset scans the whole cache, which on a bench-scale tree takes minutes
        /// but is the only way the totals are exact
        #[arg(long, value_name = "ENTRIES")]
        limit: Option<u64>,
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
    /// Export exact objects, refs, aliases, and source CAS to a new Git repo
    Export {
        /// New target directory (must be outside the Kin working repository)
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
enum RemoteAction {
    /// List configured and detected remotes
    List {
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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
    /// Negotiate an exact closure and lease-protected push plan, moving nothing
    PlanPush {
        /// Remote name (defaults to the configured default native-kin remote)
        #[arg(long)]
        remote: Option<String>,
        /// Peer transfer base URL, overriding any configured remote
        #[arg(long)]
        url: Option<String>,
        /// Ref to plan for (defaults to the repository default ref)
        #[arg(long = "ref")]
        reference: Option<String>,
        /// Print the negotiated plan as JSON
        #[arg(long, default_value_t = false)]
        json: bool,
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
        #[arg(
            required_unless_present = "base",
            conflicts_with_all = ["base", "head"]
        )]
        range: Option<String>,
        /// Base ref (alternative to the positional range; pair with --head)
        #[arg(long, requires = "head")]
        base: Option<String>,
        /// Head ref (alternative to the positional range; pair with --base)
        #[arg(long, requires = "base")]
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
    List {
        /// Output machine-readable JSON
        #[arg(long, default_value_t = false)]
        json: bool,
    },
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
    /// Seal exact graph-owned workspace state and return the workspace to its base.
    Push {
        /// Label the sealed state. Defaults to the workspace head it was sealed on.
        #[arg(long, short = 'm')]
        message: Option<String>,
        /// Skip the typed confirmation for discarding the projected working
        /// files (for non-interactive use).
        #[arg(long)]
        yes: bool,
    },
    /// Restore the most recently sealed workspace state and drop its stash
    Pop,
    /// List sealed workspace states
    List {
        /// Output the machine-readable stash report
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AgentAction {
    /// Run one task to completion against an OpenAI-compatible endpoint
    Run {
        /// The task: a path to a file holding it, or the text itself
        #[arg(long, value_name = "FILE|TEXT")]
        task: String,
        /// Model id as the endpoint names it
        #[arg(long, value_name = "ID")]
        model: String,
        /// OpenAI-compatible base URL, with or without a trailing /v1
        #[arg(long = "base-url", value_name = "URL")]
        base_url: String,
        /// Name of an environment variable holding the API key. The key itself is never
        /// accepted on the command line, so it cannot land in a process listing.
        #[arg(long = "api-key-env", value_name = "NAME")]
        api_key_env: Option<String>,
        /// Repository to work in (default: the current directory)
        #[arg(long, value_name = "PATH")]
        repo: Option<PathBuf>,
        /// Override the MCP server command (default: this binary serving --repo)
        #[arg(long = "mcp-command", value_name = "CMD")]
        mcp_command: Option<String>,
        /// Directory for the transcript, the Kin trace and the result record
        #[arg(long, value_name = "DIR")]
        out: Option<PathBuf>,
        /// Tool-call budget before the agent is asked for a final answer
        #[arg(long = "max-tool-calls", value_name = "N")]
        max_tool_calls: Option<u32>,
        /// Wall-clock deadline in seconds
        #[arg(long, value_name = "S")]
        deadline: Option<u64>,
        /// File holding a system prompt that replaces the built-in one
        #[arg(long, value_name = "FILE")]
        system: Option<PathBuf>,
        /// Sampling temperature passed through to the endpoint
        #[arg(long, value_name = "F")]
        temperature: Option<f32>,
        /// Tool surface the MCP server should serve
        #[arg(long = "tool-profile", value_name = "PROFILE")]
        tool_profile: Option<String>,
    },
    /// Check that the model endpoint and the Kin MCP server both answer
    Doctor {
        /// OpenAI-compatible base URL
        #[arg(long = "base-url", value_name = "URL")]
        base_url: String,
        /// Model id to look for in the endpoint's list
        #[arg(long, value_name = "ID")]
        model: Option<String>,
        /// Repository to serve (default: the current directory)
        #[arg(long, value_name = "PATH")]
        repo: Option<PathBuf>,
        /// Override the MCP server command
        #[arg(long = "mcp-command", value_name = "CMD")]
        mcp_command: Option<String>,
        /// Name of an environment variable holding the API key
        #[arg(long = "api-key-env", value_name = "NAME")]
        api_key_env: Option<String>,
        /// Tool surface the MCP server should serve
        #[arg(long = "tool-profile", value_name = "PROFILE")]
        tool_profile: Option<String>,
    },
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
        /// Tool surface to serve: `agent-default` (the curated agent belt, and
        /// the default), `full` (every tool, roughly 12k extra tokens of
        /// schemas per session), `benchmark`, or `context-bench`. Overrides
        /// KIN_MCP_TOOL_PROFILE.
        #[arg(long = "tool-profile", value_name = "PROFILE")]
        tool_profile: Option<String>,
        /// Never start or revive a daemon from this server: bind only a daemon
        /// that is already running, and answer graph tool calls with an honest
        /// "no daemon is running" error otherwise. This is the probe mode for
        /// watchdogs and boot-time checks (equivalent to KIN_NO_DAEMON=1): the
        /// MCP handshake and tool list are served in full, and nothing heavy
        /// is ever spawned by the check itself.
        #[arg(long)]
        no_spawn: bool,
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
        /// Remove the complete managed install after ledger cleanup (Windows retains an inert authority sidecar)
        #[arg(long, default_value_t = false)]
        all: bool,
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
        /// Stop every worker daemon under this KIN_HOME, then the supervisor
        ///
        /// The supervisor is machine-wide, so it can hold daemons from other
        /// managed homes. Those are skipped and named rather than stopped, and
        /// the supervisor itself is left running while any of them remain. Use
        /// --machine to stop every daemon on the box regardless of home.
        #[arg(long)]
        all: bool,
        /// Widen --all to every daemon on this machine, whatever KIN_HOME it runs under
        #[arg(long, requires = "all")]
        machine: bool,
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
    /// Publish a release tag and the snapshot bound to its exact repository state.
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

/// Command paths that Kin used to accept, mapped to the surface that replaced
/// them.
///
/// These names stay unparseable: the table exists only to replace clap's
/// "similar subcommand" tip, which ranks by edit distance and so answers
/// `import` with `support` and `impact`. A caller arriving from Git types the
/// retired name first, and a suggestion pointing at an unrelated command costs
/// more than no suggestion at all.
const RETIRED_COMMANDS: &[(&[&str], &str)] = &[
    (
        &["import"],
        "`kin clone <source>` admits a repository from elsewhere, and `kin init` admits one in place.",
    ),
    (
        &["git", "import"],
        "`kin clone <source>` admits a repository from elsewhere, and `kin init` admits one in place. \
         `kin git export` remains the only Git interoperability direction.",
    ),
    (
        &["git", "sync"],
        "`kin reconcile` republishes workspace changes into graph truth, and `kin git export` \
         publishes an exact Git repository to a new destination.",
    ),
    (
        &["workspace"],
        "Session workspaces are graph-derived and command-scoped: `kin with`, `kin open`, \
         `kin shell`, and `kin exec` each run against one.",
    ),
    (
        &["run"],
        "`kin exec` runs a command in an exact graph-derived session workspace.",
    ),
    (&["gc"], "`kin cache gc` reclaims embedding cache space."),
];

/// Leading command-path tokens of `args`, excluding flags and the values they take.
///
/// A global flag declared with a value consumes the token after it, so that
/// token is a value and never a command a caller typed. Reading it as one names
/// a retired command nobody asked for: `kin --profile-out run frobnicate` writes
/// its profile to a file called `run`. Which flags take a value is read from the
/// parser definition rather than restated, so a new global flag is accounted for
/// where it is declared.
fn typed_command_path(args: &[String]) -> Vec<&str> {
    let cli = Cli::command();
    // Arity is resolved when clap builds the command, so an unbuilt definition
    // answers through the declared action instead. Both spellings carry the
    // same fact, and reading the definition costs no parse.
    let takes_value = |matches: &dyn Fn(&clap::Arg) -> bool| {
        cli.get_arguments().any(|declared| {
            matches(declared)
                && declared.get_num_args().map_or_else(
                    || declared.get_action().takes_values(),
                    |arity| arity.takes_values(),
                )
        })
    };

    let mut typed = Vec::new();
    let mut consumes_next = false;
    for arg in args {
        if consumes_next {
            consumes_next = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            if !long.is_empty() && !long.contains('=') {
                consumes_next = takes_value(&|declared| declared.get_long() == Some(long));
            }
            continue;
        }
        if let Some(shorts) = arg.strip_prefix('-') {
            if let Some(last) = shorts.chars().last() {
                consumes_next = takes_value(&|declared| declared.get_short() == Some(last));
            }
            continue;
        }
        typed.push(arg.as_str());
        if typed.len() == 2 {
            break;
        }
    }
    typed
}

/// Longest retired path matching the command path a caller typed.
///
/// Matching is longest-first so `git import` resolves to the Git interoperability
/// guidance rather than the bare `import` entry. A caller whose tokens do not
/// match any entry falls through to clap's own reporting.
fn retired_command_signpost(args: &[String]) -> Option<(String, &'static str)> {
    let typed = typed_command_path(args);
    RETIRED_COMMANDS
        .iter()
        .filter(|(path, _)| path.len() <= typed.len() && typed[..path.len()] == **path)
        .max_by_key(|(path, _)| path.len())
        .map(|(path, guidance)| (path.join(" "), *guidance))
}

/// Parse the command line, answering a retired command path by name.
///
/// Anything clap reports that is not a retired path, including `--help` and
/// `--version`, is handed back to clap so its exit codes and rendering stay
/// exactly as they were.
fn parse_cli_or_report_retired_command() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::InvalidSubcommand {
                let args: Vec<String> = std::env::args().skip(1).collect();
                if let Some((path, guidance)) = retired_command_signpost(&args) {
                    eprintln!("error: `kin {path}` was retired.");
                    eprintln!();
                    eprintln!("  {guidance}");
                    eprintln!();
                    eprintln!(
                        "Run `kin --help` for the current commands, or `kin capabilities` for \
                         repository-v6 readiness."
                    );
                    std::process::exit(2);
                }
            }
            err.exit()
        }
    }
}

fn main() -> Result<()> {
    // Select this process's resource profile before anything reads it: the GPU
    // kernel plan and the Metal submission depth are each resolved once per
    // process, and mutating the environment is only safe while the process is
    // still single-threaded. An operator's explicit KIN_RESOURCE_PROFILE wins.
    kin_cli::resource_profile::apply_product_default();
    if kin_migrate::run_migration_process_host_if_requested()? {
        return Ok(());
    }
    kin_buildinfo::retain_update_build_identity(&KIN_UPDATE_BUILD_IDENTITY);
    let cli = parse_cli_or_report_retired_command();
    // The semantic-only guard runs once per tool call of a launched assistant
    // and adjudicates a payload on stdin. It touches no repository, so it
    // returns before the tracing subscriber, the environment audit, the pending
    // MCP repair retry, and the tokio runtime: none of them would change its
    // answer, and all of them would be charged to the subject's tool latency.
    if matches!(cli.command, Command::SemanticOnlyGuard) {
        return commands::assistant_adapter::run_semantic_only_guard();
    }
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
            .with(default_env_filter(&command_name))
            .with(AdmissionProgressLayer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    // The fmt layer does not sniff for a terminal, so without
                    // this it writes colour escapes into a redirected log or a
                    // captured transcript.
                    .with_ansi(std::io::stderr().is_terminal())
                    .with_filter(tracing_subscriber::filter::filter_fn(|metadata| {
                        !is_periodic_admission_progress(metadata.target())
                    })),
            )
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
                Command::Capabilities { json, verbose } => {
                    commands::capabilities::run(json, verbose)
                }
                Command::Init { path, json } => commands::init::run(path, json).await,
                Command::Status { json, wait_quiesce } => {
                    commands::status::run(json, std::time::Duration::from_secs(wait_quiesce)).await
                }
                Command::Resources { action } => match action {
                    ResourcesAction::Inspect { json, profile } => {
                        commands::resources::run(json, profile).await
                    }
                },
                Command::Commit { message, quiet } => {
                    commands::capabilities::require_ready("commit")?;
                    commands::commit::run(message, quiet).await
                }
                Command::Log { count, json } => commands::log::run(count, json),
                Command::Branch { action } => match action {
                    BranchAction::List { json } => commands::branch::list(json).await,
                    BranchAction::Create { name, ref_hex } => {
                        commands::branch::create(commands::branch::parse_branch_ref(
                            name.as_deref(),
                            ref_hex.as_deref(),
                        )?)
                        .await
                    }
                    BranchAction::Delete { name, ref_hex } => {
                        commands::branch::delete(commands::branch::parse_branch_ref(
                            name.as_deref(),
                            ref_hex.as_deref(),
                        )?)
                        .await
                    }
                    BranchAction::Switch { name, ref_hex } => {
                        commands::branch::switch(commands::branch::parse_branch_ref(
                            name.as_deref(),
                            ref_hex.as_deref(),
                        )?)
                        .await
                    }
                },
                Command::Diff { base, head, json } => commands::diff::run(base, head, json),
                Command::Eject { yes } => commands::eject::run(yes).await,
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
                    json,
                } => commands::context::run(entity, budget, assistant, json).await,
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
                            // Diagnose prints the structured payload, so it wants
                            // the graph-native entity ranking even though it stays
                            // lean on bodies unless --snippets is explicit.
                            true,
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
                Command::Rename {
                    symbol,
                    new_name,
                    file,
                    line,
                    column,
                    json,
                } => commands::rename::run(symbol, new_name, file, line, column, json).await,
                Command::Refs {
                    entity,
                    kind,
                    bulk_json,
                    entities,
                    compact,
                    no_compact,
                } => {
                    // Both requirements are clap's now, so a caller who names
                    // nothing to operate on gets a usage block and exit 2 like
                    // the other 45 leaves, instead of exit 1 and one line.
                    if bulk_json {
                        let entities =
                            entities.expect("clap requires --entities alongside --bulk-json");
                        let effective_compact = compact && !no_compact;
                        commands::refs::run_bulk(entities, kind, effective_compact).await
                    } else {
                        let entity = entity.expect("clap requires an entity without --bulk-json");
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
                                // Clap owns the choice between the positional
                                // range and the --base/--head pair, and pairs
                                // the two flags. What it cannot own is the
                                // shape of the range string, which is checked
                                // here because a value parser is the only other
                                // place to put it.
                                let (base, head) = match (range, base, head) {
                                    (Some(range), _, _) => match range.split_once("..") {
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
                                    _ => unreachable!(
                                        "clap requires a range or both --base and --head"
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
                    no_bodies,
                    max_response_chars,
                } => {
                    commands::trace_data_flow::run_seeded(
                        focal,
                        depth,
                        direction,
                        limit_per_step,
                        no_bodies.then_some(false),
                        max_response_chars,
                    )
                    .await
                }
                Command::Deps { all, json } => commands::deps::run(all, json).await,
                Command::Xref { entity } => commands::xref::run(entity).await,
                Command::Spec { action } => match action {
                    SpecAction::Create { intent } => commands::spec::create(intent).await,
                    SpecAction::List { json } => commands::spec::list(json).await,
                    SpecAction::Show { id } => commands::spec::show(id).await,
                },
                Command::Merge { branch, json } => {
                    commands::capabilities::require_ready("merge")?;
                    commands::merge::run(branch, json).await
                }
                Command::Conflicts { json } => {
                    commands::capabilities::require_ready("conflicts")?;
                    commands::conflicts::run(json).await
                }
                Command::Resolve {
                    ours,
                    theirs,
                    base,
                    remove,
                    keep_path,
                    all_ours,
                    all_theirs,
                    do_continue,
                    abort,
                    expect,
                    json,
                } => {
                    commands::capabilities::require_ready("resolve")?;
                    commands::resolve::run(
                        ours,
                        theirs,
                        base,
                        remove,
                        keep_path,
                        all_ours,
                        all_theirs,
                        do_continue,
                        abort,
                        expect,
                        json,
                    )
                    .await
                }
                Command::Stash { action } => match action {
                    StashAction::Push { message, yes } => commands::stash::push(message, yes).await,
                    StashAction::Pop => commands::stash::pop().await,
                    StashAction::List { json } => commands::stash::list(json).await,
                },
                Command::Blame { entity, reference } => {
                    commands::blame::run(entity, reference).await
                }
                Command::Agent { action } => {
                    let code = match action {
                        AgentAction::Run {
                            task,
                            model,
                            base_url,
                            api_key_env,
                            repo,
                            mcp_command,
                            out,
                            max_tool_calls,
                            deadline,
                            system,
                            temperature,
                            tool_profile,
                        } => commands::agent::run(commands::agent::RunArgs {
                            task,
                            model,
                            base_url,
                            api_key_env,
                            repo,
                            mcp_command,
                            out,
                            max_tool_calls,
                            deadline,
                            system,
                            temperature,
                            tool_profile,
                        }),
                        AgentAction::Doctor {
                            base_url,
                            model,
                            repo,
                            mcp_command,
                            api_key_env,
                            tool_profile,
                        } => commands::agent::doctor(
                            base_url,
                            model,
                            repo,
                            mcp_command,
                            api_key_env,
                            tool_profile,
                        ),
                    }?;
                    // The run's own taxonomy is reported through the exit code: 2 budget,
                    // 3 deadline, 4 endpoint, 5 MCP. A caller must be able to tell a task
                    // the agent could not do from an endpoint that was never there.
                    if code != 0 {
                        std::process::exit(code);
                    }
                    Ok(())
                }
                Command::Mcp { action } => match action {
                    McpAction::Start {
                        global,
                        repo,
                        tool_profile,
                        no_spawn,
                    } => commands::mcp::start(global, repo, tool_profile, no_spawn).await,
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
                    RemoteAction::List { json } => commands::remote::list(json).await,
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
                    RemoteAction::PlanPush {
                        remote,
                        url,
                        reference,
                        json,
                    } => {
                        commands::capabilities::require_ready("remote plan-push")?;
                        commands::transfer::plan_push(remote, url, reference, json).await
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
                Command::Push {
                    remote,
                    url,
                    reference,
                    json,
                } => {
                    commands::capabilities::require_ready("push")?;
                    commands::transfer::push(remote, url, reference, json).await
                }
                Command::Pull {
                    remote,
                    url,
                    reference,
                    json,
                } => {
                    commands::capabilities::require_ready("pull")?;
                    commands::transfer::pull(remote, url, reference, json).await
                }
                Command::Clone { url, path } => commands::clone::run(url, path).await,
                Command::Checkout {
                    path,
                    path_hex,
                    change,
                } => {
                    commands::capabilities::require_ready("checkout")?;
                    commands::checkout::run(path, path_hex, change).await
                }
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
                    shell,
                    keep,
                    discard,
                    strategy,
                    scope,
                } => {
                    commands::capabilities::require_ready("exec")?;
                    commands::session_run::exec(command, shell, keep, discard, strategy, scope)
                        .await
                }
                Command::Telemetry { action } => match action {
                    TelemetryAction::Status => commands::telemetry::run_status().await,
                    TelemetryAction::Consent => commands::telemetry::run_consent().await,
                    TelemetryAction::Revoke => commands::telemetry::run_revoke().await,
                    TelemetryAction::Purge => commands::telemetry::run_purge().await,
                },
                Command::Support { json } => commands::support::run(json).await,
                Command::Languages { json } => commands::languages::run(json).await,
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
                    BackupAction::List { json } => commands::backup::list(json).await,
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
                Command::Semver { base, head, json } => {
                    commands::capabilities::require_ready("semver")?;
                    commands::semver::run(base, head, json)
                }
                Command::Release { action } => match action {
                    ReleaseAction::Plan { offline } => commands::release_orch::plan(offline).await,
                    ReleaseAction::Apply {
                        crate_name,
                        version,
                        repos,
                        no_lock,
                    } => commands::release_orch::apply(crate_name, version, repos, !no_lock).await,
                    ReleaseAction::Intent { repo } => commands::release_orch::intent(repo).await,
                    ReleaseAction::Snapshot {
                        tag,
                        require_proof,
                        require_approval,
                        force,
                    } => {
                        commands::capabilities::require_ready("release snapshot")?;
                        commands::tag::snapshot(tag, require_proof, require_approval, force).await
                    }
                },
                Command::Tag {
                    tag,
                    require_proof,
                    require_approval,
                    force,
                } => {
                    commands::capabilities::require_ready("tag")?;
                    commands::tag::run(tag, require_proof, require_approval, force).await
                }
                Command::Rollback { change_id, feature } => {
                    commands::capabilities::require_ready("rollback")?;
                    commands::rollback::run(change_id, feature).await
                }
                Command::Bench { args } => commands::bench::bench_proxy(&args),
                Command::Migrate { source, target } => commands::migrate::run(source, target).await,
                Command::Cache { action } => match action {
                    CacheAction::Status { json, limit } => {
                        commands::cache::status(json, limit).await
                    }
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
                Command::Git { action } => match action {
                    GitAction::Export { output } => commands::git::export(output),
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
                    AssistantAction::List { json } => commands::assistant::list(json).await,
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
                Command::Open { editor } => {
                    commands::capabilities::require_ready("open")?;
                    commands::session_run::open(editor).await
                }
                Command::PurgeIgnored {
                    confirm,
                    confirm_mass_deletion,
                } => {
                    commands::capabilities::require_ready("purge-ignored")?;
                    commands::purge_ignored::run(confirm, confirm_mass_deletion).await
                }
                Command::Admit => {
                    commands::capabilities::require_ready("admit")?;
                    commands::admit::run().await
                }
                Command::Reconcile {
                    session,
                    confirm_mass_deletion,
                } => {
                    commands::capabilities::require_ready("reconcile")?;
                    commands::reconcile::run(session, confirm_mass_deletion).await
                }
                Command::With {
                    assistant,
                    semantic_only,
                    task,
                } => {
                    commands::capabilities::require_ready("with")?;
                    commands::session_run::with(assistant, semantic_only, task).await
                }
                // Adjudicated before the runtime starts; see the early return
                // at the top of `main`.
                Command::SemanticOnlyGuard => {
                    commands::assistant_adapter::run_semantic_only_guard()
                }
                Command::Shell { strategy } => {
                    commands::capabilities::require_ready("shell")?;
                    commands::session_run::shell(strategy).await
                }
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
                    set_policy,
                    apply,
                    dry_run,
                    unattended,
                    force_window,
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
                        set_policy,
                        apply,
                        dry_run,
                        unattended,
                        force_window,
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
                    DaemonAction::Stop { all, machine, json } => {
                        commands::daemon::stop(all, machine, json).await
                    }
                },
                Command::Doctor {
                    fix,
                    json,
                    drift,
                    heal,
                } => {
                    // `--drift` reports the derived projection against graph
                    // truth; `--heal` rematerializes it. Bare `kin doctor`
                    // stays the first-run config health check.
                    if heal {
                        commands::capabilities::require_ready("doctor --heal")?;
                        commands::drift::heal(json).await
                    } else if drift {
                        commands::capabilities::require_ready("doctor --drift")?;
                        commands::drift::run(json).await
                    } else {
                        commands::setup::doctor(fix, json).await
                    }
                }
                Command::Notify {
                    action,
                    title,
                    body,
                    level,
                    key,
                    cooldown,
                    latch,
                    json,
                } => {
                    let code = match action {
                        Some(NotifyAction::Clear { key, json }) => {
                            commands::notify::clear(&key, json)
                        }
                        Some(NotifyAction::Status { json }) => commands::notify::status(json),
                        None => {
                            // clap cannot express "required unless a subcommand
                            // was given", so the pairing is checked here.
                            match (title.as_deref(), body.as_deref()) {
                                (Some(title), Some(body)) => commands::notify::send(
                                    title,
                                    body,
                                    &level,
                                    key.as_deref(),
                                    cooldown,
                                    latch,
                                    json,
                                ),
                                _ => Err(anyhow::anyhow!(
                                    "--title and --body are both required to send a notification"
                                )),
                            }
                        }
                    }?;
                    // Suppressed and undelivered are reported through the exit
                    // code so callers can branch without parsing output.
                    if code != 0 {
                        std::process::exit(code);
                    }
                    Ok(())
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
                        all,
                        dry_run,
                        force,
                        json,
                    }) => commands::setup::uninstall(all, dry_run, force, json).await,
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

/// Commands that run one long uninterruptible phase over a whole repository.
///
/// For everything else the default stays `warn`, because a short command that
/// prints its own result has nothing to report in between. These two can spend
/// hours inside a single call, and at that length no output at all is
/// indistinguishable from a wedged process: a full-history admission was once
/// killed after 11h43m of silence that turned out to be ordinary progress.
const PROGRESS_REPORTING_COMMANDS: [&str; 2] = ["init", "clone"];

/// Targets whose events are progress within an admission phase, not outcomes.
///
/// These report the same work the phase ladder is already drawing a line for,
/// repeatedly, while that line is on screen. Formatting them as log records put
/// ANSI escapes and the internal span path they were emitted under straight
/// through a redrawn progress display, so [`AdmissionProgressLayer`] takes them
/// and the fmt layer is filtered to leave them alone.
fn is_periodic_admission_progress(target: &str) -> bool {
    target == "kin_db::storage::history_replay"
}

/// Render an admission progress event onto the live phase line.
///
/// The event's own message is not reused. `history_replay` reports elapsed
/// whole seconds, so its terminal line reads "validated 6,413 changes in 0s"
/// for any replay under a second and says nothing useful about a replay that
/// took two minutes. The phase line already carries its own elapsed time, so
/// what is wanted from the event is how far along it is, which is what its
/// `validated` and `total` fields carry.
///
/// With no ladder open the line is printed plainly instead of dropped, so
/// running an admission phase's instrumentation outside the ladder still says
/// something, just without escapes or span paths.
struct AdmissionProgressLayer;

#[derive(Default)]
struct AdmissionProgressFields {
    message: Option<String>,
    validated: Option<u64>,
    total: Option<u64>,
}

impl tracing::field::Visit for AdmissionProgressFields {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        match field.name() {
            "validated" => self.validated = Some(value),
            "total" => self.total = Some(value),
            _ => {}
        }
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for AdmissionProgressLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if !is_periodic_admission_progress(event.metadata().target()) {
            return;
        }
        let mut fields = AdmissionProgressFields::default();
        event.record(&mut fields);
        let detail = match (fields.validated, fields.total) {
            (Some(validated), Some(total)) => format!("{validated}/{total} changes validated"),
            (Some(validated), None) => format!("{validated} changes validated"),
            _ => match fields.message {
                Some(message) => message,
                None => return,
            },
        };
        if !kin_core::report_admission_progress(&detail) {
            eprintln!("  {detail}");
        }
    }
}

/// Admission targets raised to `info` for [`PROGRESS_REPORTING_COMMANDS`].
///
/// Deliberately target-scoped rather than crate-wide. `kin_core=info` would also
/// surface every unrelated event those crates emit, which is how a default
/// filter becomes noise nobody reads.
///
/// What each target actually delivers today, because the difference matters to
/// anyone watching a long run:
///
/// - `kin_core::init` and `kin_core::git_init` carry three callsites between
///   them, and all three are **terminal**: two report a completed admission and
///   one reports recovered stale initialization stages. They add at most three
///   lines, and none of them appears mid-flight. They are enabled so the
///   admission surfaces its own outcome and so no further `kin-cli` change is
///   needed later.
/// - `kin_db::storage::history_replay` is the only periodic emitter, throttled
///   at its source. It is **live**, and has been since this workspace's KinDB
///   pin moved: the module ships in the pinned version, so the directive that
///   was written as pre-wired and inert now matches. That is how raw log
///   records first appeared inside the phase ladder's display, and it is why
///   [`AdmissionProgressLayer`] exists rather than the fmt layer rendering
///   them. Anything added to this list that emits mid-flight rather than
///   terminally needs the same treatment, or it will scribble over the ladder
///   the same way.
///
/// So a long admission does report mid-flight progress, on the phase line
/// itself rather than as separate records.
///
/// `kin_db::storage::snapshot` is deliberately not here, despite carrying three
/// live conditional `info!` sites. All three sit on `SnapshotManager` reopen and
/// reload paths, one after loading a vector sidecar, one on delta replay at
/// open, and one where pending deltas bypass the locate cache, so each of them
/// needs a snapshot that already exists. An admission never has one, because
/// `kin init` refuses outright when `.kin` is already present
/// (`reject_existing_repository`, run before any admission work in
/// `commands/init.rs`) rather than rebuilding authority over it. There is
/// nothing for an admission to reopen, replay, or load a sidecar from, so
/// naming the module would add a fourth directive that matches nothing on
/// either of these two commands.
///
/// That reason is structural and survives a refactor of who imports what. The
/// supporting type-name fact points the same way but is weaker: admission
/// builds authority through `RepositoryAuthorityManager`, which `kin-core`'s
/// `init.rs` and `git_init.rs` open, and the kin-db module defining that
/// manager holds no reference to `SnapshotManager` to reach those callsites
/// through. A future kin-db could invalidate that observation without failing
/// anything here, which is why it is the secondary note rather than the reason.
///
/// Where those events do fire, the daemon already runs at `info` and records
/// them, and on ordinary graph-reading commands they report finished counts
/// rather than progress, so raising them there would restate the mistake this
/// allowlist exists to avoid.
const ADMISSION_PROGRESS_TARGETS: [&str; 3] = [
    "kin_core::init",
    "kin_core::git_init",
    "kin_db::storage::history_replay",
];

fn default_env_filter(command: &str) -> EnvFilter {
    if std::env::var_os("RUST_LOG").is_some() {
        return EnvFilter::from_default_env();
    }
    EnvFilter::new(default_filter_directives(command))
}

/// The directive string [`default_env_filter`] would install, absent `RUST_LOG`.
///
/// Split out so the choice is testable without mutating process environment,
/// which no test can do without racing every other test in the binary.
///
/// Profiling is deliberately absent here. That path installs its own subscriber
/// with no `EnvFilter` at all, so it never reaches this function; carrying a
/// `profile_enabled` branch would only invite a test that proves a dead arm.
fn default_filter_directives(command: &str) -> String {
    if !PROGRESS_REPORTING_COMMANDS.contains(&command) {
        return "warn".to_string();
    }
    let mut directives = String::from("warn");
    for target in ADMISSION_PROGRESS_TARGETS {
        directives.push(',');
        directives.push_str(target);
        directives.push_str("=info");
    }
    directives
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// The admission commands must carry every configured target without
    /// `RUST_LOG` being set.
    #[test]
    fn progress_reporting_commands_raise_admission_targets_to_info() {
        for command in PROGRESS_REPORTING_COMMANDS {
            let directives = default_filter_directives(command);
            assert!(
                directives.starts_with("warn"),
                "{command} must keep warn as its floor: {directives}"
            );
            for target in ADMISSION_PROGRESS_TARGETS {
                assert!(
                    directives.contains(&format!("{target}=info")),
                    "{command} must report {target} progress: {directives}"
                );
            }
        }
    }

    /// The filter is keyed on the clap subcommand name, so a renamed command
    /// would silently stop reporting progress with every other test still green.
    /// This CLI does rename subcommands, so pin the names against clap itself.
    #[test]
    fn progress_reporting_commands_are_real_subcommands() {
        on_cli_test_stack(|| {
            let command = Cli::command();
            let known: Vec<String> = command
                .get_subcommands()
                .map(|sub| sub.get_name().to_string())
                .collect();
            for expected in PROGRESS_REPORTING_COMMANDS {
                assert!(
                    known.iter().any(|name| name == expected),
                    "{expected:?} is not a kin subcommand; known: {known:?}"
                );
            }
        });
    }

    /// Ordinary commands print their own result, so raising them would only add
    /// noise to every invocation.
    #[test]
    fn ordinary_commands_keep_the_quiet_default() {
        for command in ["locate", "commit", "status", "log", "help"] {
            assert!(
                !PROGRESS_REPORTING_COMMANDS.contains(&command),
                "{command} is not a long single-phase command"
            );
            assert_eq!(
                default_filter_directives(command),
                "warn",
                "{command} must stay quiet by default"
            );
        }
    }

    /// A malformed directive is silently dropped by `EnvFilter`, which would
    /// disable progress reporting while every other test still passed. Parse the
    /// exact string the binary installs and require each target to survive.
    #[test]
    fn every_default_directive_parses_and_is_retained() {
        for command in ["init", "clone", "locate", "help"] {
            let directives = default_filter_directives(command);
            let filter = tracing_subscriber::filter::EnvFilter::builder()
                .parse(&directives)
                .unwrap_or_else(|error| {
                    panic!("default directives {directives:?} must parse: {error}")
                });
            let rendered = filter.to_string();
            for directive in directives.split(',') {
                assert!(
                    rendered.contains(directive),
                    "directive {directive:?} was dropped from {rendered:?}"
                );
            }
        }
    }

    // Behavioral probes for the default log filter.
    //
    // The assertions above check the shape of the directive string, and a string
    // can be correct while admitting nothing. `EnvFilter` resolves directives
    // against a callsite at runtime, so a reordered list, an added global
    // directive, or a target shadowed by a broader one all leave the string
    // intact and every assertion above green while the event is dropped. These
    // probes install what production installs and assert on what actually
    // reaches a writer.
    //
    // They build the filter from `default_filter_directives` rather than calling
    // `default_env_filter`, deliberately: that function consults `RUST_LOG`, and
    // a probe inheriting the developer's or the runner's environment would fail
    // or pass vacuously depending on it. `EnvFilter::new` over the pure
    // directive string is exactly what production installs when `RUST_LOG` is
    // unset.

    /// Collects everything a subscriber writes, standing in for the terminal.
    #[derive(Clone)]
    struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("log buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLog;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// The filter a plain run of `command` installs, absent `RUST_LOG`.
    fn installed_filter(command: &str) -> EnvFilter {
        EnvFilter::new(default_filter_directives(command))
    }

    /// Run `emit` under `filter` and report whether anything reached the writer.
    ///
    /// The caller emits rather than naming a target, because `tracing`'s macros
    /// build a static callsite and so require a literal target. A helper taking
    /// `&'static str` does not compile, which is why the probes below spell out
    /// one emission per target instead of looping over
    /// `ADMISSION_PROGRESS_TARGETS`. Looping over commands stays available,
    /// since a command reaches the filter as an ordinary argument.
    fn survives(filter: EnvFilter, emit: impl FnOnce()) -> bool {
        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().with_writer(CapturedLog(buffer.clone())));
        tracing::subscriber::with_default(subscriber, emit);
        let captured = buffer.lock().expect("log buffer poisoned").len();
        captured > 0
    }

    /// Forces an edit in this file whenever the target list changes length.
    ///
    /// That is the whole of what it guarantees, and it is less than it looks.
    /// `ADMISSION_PROGRESS_TARGETS` is declared `[&str; 3]`, so `.len()` is a
    /// compile-time constant and this assertion cannot fail on its own. What
    /// trips it is the edit that adding a target requires: changing the array's
    /// length parameter forces changing this literal, which puts the author in
    /// the module where the probes live, next to the reason a new entry needs
    /// one. It is a reminder, not a coupling, and it says nothing about
    /// identity. Swapping one target for another holds the length at 3 and
    /// leaves this test green.
    ///
    /// A swapped target is caught by
    /// `an_admission_command_admits_every_progress_target` instead, whose probes
    /// name their targets as literals. `EnvFilter` matches a directive against
    /// an event's target by prefix, so a renamed entry stops prefix-matching the
    /// probe that names the old one, the event falls back to the `warn` floor,
    /// and the probe stops surviving.
    #[test]
    fn every_admission_target_has_a_probe() {
        assert_eq!(
            ADMISSION_PROGRESS_TARGETS.len(),
            3,
            "add a probe below when adding an admission target"
        );
    }

    /// Every progress-reporting command must admit the whole target set on its
    /// own, which is stronger than the set being admitted somewhere.
    ///
    /// `default_filter_directives` emits one identical string for every member
    /// of `PROGRESS_REPORTING_COMMANDS` today, so probing `init` for one target
    /// and `clone` for another would pass. It would also keep passing the moment
    /// that function grew a per-command branch, which is a natural extension the
    /// first time `clone` wants a transport target `init` has no use for. The
    /// set would then be satisfied across two commands with neither carrying it,
    /// and the name of this test would be a claim its body no longer made.
    #[test]
    fn an_admission_command_admits_every_progress_target() {
        for command in PROGRESS_REPORTING_COMMANDS {
            assert!(
                survives(installed_filter(command), || tracing::info!(
                    target: "kin_core::init",
                    "probe"
                )),
                "kin {command} must admit the admission receipt"
            );
            assert!(
                survives(installed_filter(command), || tracing::info!(
                    target: "kin_core::git_init",
                    "probe"
                )),
                "kin {command} must admit Git admission output"
            );
            // Live, not pre-wired: the module ships in the pinned KinDB and
            // emits during the commit phase. It has to survive the filter to
            // reach `AdmissionProgressLayer`, which is what draws it onto the
            // phase line instead of letting the fmt layer print it.
            assert!(
                survives(installed_filter(command), || tracing::info!(
                    target: "kin_db::storage::history_replay",
                    "probe"
                )),
                "kin {command} must admit the replay progress target"
            );
        }
    }

    /// The periodic replay target reaches the progress layer and not the fmt
    /// layer, and every other admission target keeps printing as a record.
    ///
    /// Both halves matter and they fail differently. If the replay target were
    /// not excluded from fmt it would print raw, with ANSI and the internal
    /// span path, over the redrawn phase line, which is the defect. If the
    /// exclusion were written broadly enough to catch `kin_core::git_init` it
    /// would swallow the admission receipt, and the command would finish
    /// saying nothing about what it admitted.
    #[test]
    fn only_the_periodic_replay_target_is_taken_off_the_record_layer() {
        assert!(is_periodic_admission_progress(
            "kin_db::storage::history_replay"
        ));
        for printed in [
            "kin_core::init",
            "kin_core::git_init",
            "kin_db::storage::snapshot",
            "kin_db::storage::repository",
            "kin_cli",
        ] {
            assert!(
                !is_periodic_admission_progress(printed),
                "{printed} must keep printing as a record"
            );
        }
    }

    /// With no admission ladder open, a progress event is printed rather than
    /// dropped.
    ///
    /// The sink reports whether a live phase took the line, and that return is
    /// the only thing standing between "routed onto the phase line" and
    /// "silently discarded". A sink that always answered true would make an
    /// admission's instrumentation vanish outside the ladder, and nothing about
    /// the display would look wrong while it did.
    #[test]
    fn a_progress_report_with_no_ladder_open_is_not_swallowed() {
        assert!(
            !kin_core::report_admission_progress("4096/6413 changes validated"),
            "no ladder is open in a unit test, so the sink must decline the line"
        );
    }

    #[test]
    fn an_ordinary_command_denies_the_progress_targets() {
        assert!(
            !survives(installed_filter("locate"), || tracing::info!(
                target: "kin_core::git_init",
                "probe"
            )),
            "a short command must not gain admission output"
        );
        assert!(
            !survives(installed_filter("locate"), || tracing::info!(
                target: "kin_core::init",
                "probe"
            )),
            "a short command must not gain the admission receipt"
        );
    }

    #[test]
    fn the_quiet_floor_holds_for_every_target_not_named() {
        // Why the raised set is an allowlist rather than a crate-wide or global
        // level: unnamed info stays exactly as silent as it was, the embedding
        // hot path most of all, and warnings still reach the user from anywhere.
        assert!(
            !survives(installed_filter("init"), || tracing::info!(
                target: "kin_db::embed",
                "probe"
            )),
            "the embedding hot path must not become visible by default"
        );
        assert!(
            !survives(installed_filter("init"), || tracing::info!(
                target: "reqwest::connect",
                "probe"
            )),
            "dependency info must not become visible by default"
        );
        assert!(
            survives(installed_filter("init"), || tracing::warn!(
                target: "kin_db::embed",
                "probe"
            )),
            "warnings must still reach the user from every target"
        );
    }

    #[test]
    fn a_bare_warn_default_drops_the_admission_targets() {
        // Root cause, and the guard against vacuity. Without it the probes above
        // would pass just as well against a directive that admitted everything,
        // and would say nothing about the behavior they exist to pin.
        assert!(
            !survives(EnvFilter::new("warn"), || tracing::info!(
                target: "kin_core::git_init",
                "probe"
            )),
            "the bare warn default this replaced must be shown to drop admission output"
        );
        assert!(
            !survives(EnvFilter::new("warn"), || tracing::info!(
                target: "kin_core::init",
                "probe"
            )),
            "the bare warn default this replaced must be shown to drop the receipt"
        );
    }

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
    fn setup_uninstall_all_is_explicit_and_composable_with_safety_flags() {
        on_cli_test_stack(|| {
            let cli = Cli::try_parse_from([
                "kin",
                "setup",
                "uninstall",
                "--all",
                "--dry-run",
                "--force",
                "--json",
            ])
            .expect("the explicit full-uninstall surface must parse");
            assert!(matches!(
                cli.command,
                Command::Setup {
                    action: Some(SetupAction::Uninstall {
                        all: true,
                        dry_run: true,
                        force: true,
                        json: true,
                    }),
                    ..
                }
            ));
        });
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
                "Run a command in an exact graph-derived session workspace",
                "Launch an editor over an exact graph-derived session workspace",
                "Launch an assistant in an exact graph-derived session workspace",
                "Open a shell in an exact graph-derived session workspace",
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

            let cli = Cli::try_parse_from(["kin", "git", "export", "--output", "../export.git"])
                .expect("exact Git export remains the explicit interoperability surface");
            assert!(matches!(
                cli.command,
                Command::Git {
                    action: GitAction::Export { output }
                } if output.as_path() == std::path::Path::new("../export.git")
            ));
            assert!(Cli::try_parse_from(["kin", "git", "export", "--in-place"]).is_err());
        });
    }

    /// A work item names the changes to roll back, so requiring a change on the
    /// same invocation made the flag unreachable: the caller had to already know
    /// the answer the flag exists to compute.
    #[test]
    fn work_item_rollback_parses_without_a_change_argument() {
        on_cli_test_stack(|| {
            let cli = Cli::try_parse_from(["kin", "rollback", "--feature", "some-work-id"])
                .expect("naming a work item must be a complete rollback invocation");
            assert!(matches!(
                cli.command,
                Command::Rollback {
                    change_id: None,
                    feature: Some(ref work_id),
                } if work_id == "some-work-id"
            ));

            let cli = Cli::try_parse_from(["kin", "rollback", "abc123"])
                .expect("naming a change stays a complete rollback invocation");
            assert!(matches!(
                cli.command,
                Command::Rollback {
                    change_id: Some(ref change),
                    feature: None,
                } if change == "abc123"
            ));
        });
    }

    /// Not supplying the thing to operate on is one mistake, and it produced
    /// two contracts: 45 leaves exited 2 with a usage block through clap, and a
    /// handful exited 1 with a bare line. A caller keying on exit 2 for "I
    /// called this wrong" misclassified the second set.
    ///
    /// These four moved to clap. `kin locate` and `kin scope` deliberately did
    /// not: `locate --next` takes its query from a persisted cursor and `scope`
    /// reads KIN_SESSION_ID, so a parse-time requirement would reject
    /// invocations that work. Their argument is not optional to the command,
    /// only to the command line, which is not something clap can express.
    #[test]
    fn a_missing_required_argument_is_a_usage_error_not_a_runtime_one() {
        on_cli_test_stack(|| {
            for argv in [
                &["kin", "refs"][..],
                &["kin", "rollback"][..],
                &["kin", "resolve"][..],
                &["kin", "review", "shadow"][..],
            ] {
                let error = Cli::try_parse_from(argv)
                    .err()
                    .unwrap_or_else(|| panic!("{argv:?} must not parse"));
                assert_eq!(
                    error.exit_code(),
                    2,
                    "{argv:?} must fail the way every other misuse does"
                );
                let rendered = error.to_string();
                assert!(
                    rendered.contains("Usage:"),
                    "{argv:?} must print usage: {rendered}"
                );
            }

            // Every shape that did work still parses. A required-group that
            // over-reaches would take these with it, and each is the reason its
            // command's requirement is conditional rather than plain.
            for argv in [
                &["kin", "refs", "Foo"][..],
                &["kin", "refs", "--bulk-json", "--entities", "a,b"][..],
                &["kin", "resolve", "--abort"][..],
                &["kin", "resolve", "--all-ours", "--json"][..],
                &["kin", "resolve", "--ours", "x", "--theirs", "y"][..],
                &["kin", "review", "shadow", "main..head"][..],
                &["kin", "review", "shadow", "--base", "a", "--head", "b"][..],
                // Untouched on purpose: both take their input from somewhere
                // the command line cannot see.
                &["kin", "locate", "--next"][..],
                &["kin", "scope"][..],
            ] {
                assert!(
                    Cli::try_parse_from(argv).is_ok(),
                    "{argv:?} must stay a complete invocation"
                );
            }

            // Half-supplied pairs are refused at parse time too, rather than
            // reaching a command body that has to re-derive what is missing.
            for argv in [
                &["kin", "refs", "--bulk-json"][..],
                &["kin", "review", "shadow", "--base", "a"][..],
                &["kin", "review", "shadow", "--head", "b"][..],
                &["kin", "rollback", "abc123", "--feature", "w-1"][..],
            ] {
                let error = Cli::try_parse_from(argv)
                    .err()
                    .unwrap_or_else(|| panic!("{argv:?} must not parse"));
                assert_eq!(error.exit_code(), 2, "{argv:?} must be a usage error");
            }
        });
    }

    #[test]
    fn every_retired_command_path_names_its_replacement() {
        on_cli_test_stack(|| {
            for (path, _) in RETIRED_COMMANDS {
                let mut argv = vec!["kin"];
                argv.extend_from_slice(path);
                assert!(
                    Cli::try_parse_from(&argv).is_err(),
                    "a retired command path must stay unparseable: {path:?}"
                );

                let typed: Vec<String> = path.iter().map(|token| token.to_string()).collect();
                let (matched, guidance) = retired_command_signpost(&typed)
                    .unwrap_or_else(|| panic!("retired path {path:?} must be signposted"));
                assert_eq!(matched, path.join(" "));
                assert!(
                    guidance.contains("kin "),
                    "guidance for {path:?} must name a replacement command: {guidance}"
                );
            }
        });
    }

    #[test]
    fn retired_signposting_prefers_the_longest_path_and_ignores_live_commands() {
        on_cli_test_stack(|| {
            let git_import = ["git".to_string(), "import".to_string()];
            let (matched, guidance) =
                retired_command_signpost(&git_import).expect("`kin git import` is retired");
            assert_eq!(matched, "git import");
            assert!(
                guidance.contains("git export"),
                "the Git path must name export as the remaining direction: {guidance}"
            );

            let bare_import = [
                "import".to_string(),
                "https://example.com/r.git".to_string(),
            ];
            let (matched, _) =
                retired_command_signpost(&bare_import).expect("`kin import` is retired");
            assert_eq!(matched, "import");

            // Leading global flags precede the command path a caller typed.
            let flagged = ["--profile-summary".to_string(), "gc".to_string()];
            assert_eq!(
                retired_command_signpost(&flagged).map(|(matched, _)| matched),
                Some("gc".to_string())
            );

            // A flag that takes a value consumes the token after it, so that
            // token names a file and not a command. The retired name here is
            // the caller's profile path, and `frobnicate` is what they typed.
            let value_named_after_a_retired_command = [
                "--profile-out".to_string(),
                "run".to_string(),
                "frobnicate".to_string(),
            ];
            assert!(
                retired_command_signpost(&value_named_after_a_retired_command).is_none(),
                "a flag value must not be read as a command a caller typed"
            );

            // The command path still resolves past a consumed value, in both
            // the separated and the inline spelling.
            for spelling in [
                vec![
                    "--profile-out".to_string(),
                    "/tmp/profile.json".to_string(),
                    "import".to_string(),
                ],
                vec![
                    "--profile-out=/tmp/profile.json".to_string(),
                    "import".to_string(),
                ],
            ] {
                assert_eq!(
                    retired_command_signpost(&spelling).map(|(matched, _)| matched),
                    Some("import".to_string()),
                    "a retired command behind a flag value must still be signposted: {spelling:?}"
                );
            }

            // A live command, and an unknown name with no replacement to name,
            // both fall through to clap's own reporting.
            for live in [
                vec!["status".to_string()],
                vec!["git".to_string(), "export".to_string()],
                vec!["cache".to_string(), "gc".to_string()],
                vec!["frobnicate".to_string()],
            ] {
                assert!(
                    retired_command_signpost(&live).is_none(),
                    "must not signpost {live:?}"
                );
            }
        });
    }

    #[test]
    fn help_orients_a_caller_to_the_everyday_path() {
        on_cli_test_stack(|| {
            let mut command = Cli::command();
            let help = command.render_long_help().to_string();
            for anchor in [
                "Start here:",
                "kin init",
                "kin status",
                "kin commit",
                "kin capabilities",
            ] {
                assert!(
                    help.contains(anchor),
                    "help must orient a caller with {anchor:?}"
                );
            }
        });
    }

    /// The legend teaches a marker, so it may only appear while a marker does.
    ///
    /// Asserting the bare string was what let it outlive the thing it
    /// describes: every gate closed, every marker came off, and the sentence
    /// stayed, telling a caller to look for a signal that no command carried.
    #[test]
    fn the_open_gate_legend_appears_exactly_when_a_gate_does() {
        on_cli_test_stack(|| {
            let mut command = Cli::command();
            let help = command.render_long_help().to_string();
            let inventory =
                commands::capabilities::inventory().expect("capability inventory must parse");
            let gated = inventory.commands.iter().any(|capability| {
                capability.status == commands::capabilities::CapabilityStatus::OpenGate
            });

            assert_eq!(
                help.contains(OPEN_GATE_MARKER),
                gated,
                "the legend must track the inventory, which reports gated={gated}"
            );

            // The conditional is what is under test, so exercise both arms
            // rather than only the one this inventory happens to select.
            assert!(after_help().contains("Start here:"));
            assert!(!AFTER_HELP.contains(OPEN_GATE_MARKER));
            assert!(OPEN_GATE_LEGEND.contains(OPEN_GATE_MARKER));
            assert!(
                format!("{AFTER_HELP}{OPEN_GATE_LEGEND}").contains(OPEN_GATE_MARKER),
                "the gated arm must carry the legend it exists to add"
            );
        });
    }

    const OPEN_GATE_MARKER: &str = "[OPEN GATE]";

    /// Every help entry carrying the open-gate marker, keyed by the command path
    /// a caller types to reach it.
    ///
    /// Flags are qualified by the command that owns them, matching how the
    /// capability inventory names `doctor --heal`, so a marker on a flag and a
    /// marker on a subcommand are comparable against the same inventory.
    fn open_gate_marked_entries(
        command: &clap::Command,
        prefix: &str,
        marked: &mut std::collections::BTreeSet<String>,
    ) {
        let qualify = |entry: &str| {
            if prefix.is_empty() {
                entry.to_string()
            } else {
                format!("{prefix} {entry}")
            }
        };
        for arg in command.get_arguments() {
            let Some(long) = arg.get_long() else { continue };
            let carries = arg
                .get_help()
                .or_else(|| arg.get_long_help())
                .is_some_and(|help| help.to_string().contains(OPEN_GATE_MARKER));
            if carries {
                marked.insert(qualify(&format!("--{long}")));
            }
        }
        for subcommand in command.get_subcommands() {
            let path = qualify(subcommand.get_name());
            let carries = subcommand
                .get_about()
                .or_else(|| subcommand.get_long_about())
                .is_some_and(|about| about.to_string().contains(OPEN_GATE_MARKER));
            if carries {
                marked.insert(path.clone());
            }
            open_gate_marked_entries(subcommand, &path, marked);
        }
    }

    #[test]
    fn open_gate_markers_name_exactly_the_fail_closed_commands() {
        on_cli_test_stack(|| {
            // The after-help sentence promises that a marked command is
            // fail-closed on repository-v6, which makes the marker a contract
            // against the capability inventory rather than decoration. A gate
            // that opens without its marker coming off steers a caller away
            // from a command that now runs, which is the misdirection the
            // marker exists to prevent.
            let mut marked = std::collections::BTreeSet::new();
            open_gate_marked_entries(&Cli::command(), "", &mut marked);

            let inventory =
                commands::capabilities::inventory().expect("capability inventory must parse");
            let fail_closed: std::collections::BTreeSet<String> = inventory
                .commands
                .iter()
                .filter(|capability| {
                    capability.status == commands::capabilities::CapabilityStatus::OpenGate
                })
                .map(|capability| capability.command.clone())
                .collect();

            assert_eq!(
                marked, fail_closed,
                "help must mark exactly the commands `kin capabilities` reports as open gates"
            );

            // The marker has to survive rendering, since the rendered surface
            // is what the after-help sentence governs.
            let mut command = Cli::command();
            let rendered = command.render_long_help().to_string();
            let flattened = rendered.split_whitespace().collect::<Vec<_>>().join(" ");
            for subcommand in Cli::command().get_subcommands() {
                let name = subcommand.get_name();
                assert_eq!(
                    flattened.contains(&format!("{name} {OPEN_GATE_MARKER}")),
                    fail_closed.contains(name),
                    "rendered help must mark `kin {name}` exactly when the inventory calls it \
                     an open gate"
                );
            }
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
