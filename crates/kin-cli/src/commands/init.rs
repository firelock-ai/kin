// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Clean-slate repository authority initialization.
//!
//! `kin init` has exactly two admission paths:
//!
//! - a fresh Git worktree is captured by [`kin_core::init_from_git`] as exact
//!   reachable history, refs, raw objects, workspace state, and admission policy;
//! - an empty non-Git directory is initialized as an unborn Kin-native repository.
//!
//! This command deliberately does not parse a checkout, synthesize a snapshot
//! change, or rebuild an existing repository from raw filesystem contents.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::status::{SemanticEnrichmentPresence, SemanticEnrichmentStatus};
use super::store_footprint::{store_size_notice, StoreFootprint};

/// Invalidates prepared state when the repository bootstrap authority changes.
pub(crate) const GRAPH_BUILD_PIPELINE_EPOCH: &str =
    "graph-build-2026-07-26-repository-v6-authority-v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitBoundary {
    ExactGit,
    NativeUnborn,
}

impl InitBoundary {
    fn source_boundary(self) -> &'static str {
        match self {
            Self::ExactGit => "git-exact-reachable-history",
            Self::NativeUnborn => "native-unborn",
        }
    }

    fn history(self) -> &'static str {
        match self {
            Self::ExactGit => "exact-reachable",
            Self::NativeUnborn => "unborn",
        }
    }
}

#[derive(Debug, Serialize)]
struct InitResultPayload<'a> {
    schema: &'static str,
    authority: &'static str,
    source_boundary: &'static str,
    history: &'static str,
    /// Durable generation-bound enrichment committed by admission. This is
    /// carried from the bootstrap lease, not reopened after publication.
    semantic_enrichment: SemanticEnrichmentStatus,
    repo_root: String,
    kin_dir: String,
    repository_id: &'a kin_model::RepositoryId,
    workspace_id: kin_model::WorkspaceId,
    default_ref: Option<&'a kin_model::RefName>,
    authority_generation: u64,
    workspace_generation: u64,
    workspace_head: &'a kin_model::WorkspaceHead,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_git_head: Option<&'a kin_model::GitRawTarget>,
    base_target: Option<&'a kin_model::RefTarget>,
    base_tree_hash: Option<kin_model::Hash256>,
    workspace_tree_hash: kin_model::Hash256,
    roots: &'a kin_model::RootBundle,
    initial_change_id: Option<&'a kin_model::SemanticChangeId>,
    exact_reachable_git_history: bool,
    /// What the store this command just wrote costs on disk, and what the Git
    /// object store it was admitted from costs. Measured after publication, so
    /// it describes the store the caller now has rather than a projection of it.
    store_footprint: StoreFootprint,
    /// Source paths that were not the committed state, and are therefore not in
    /// what was admitted. Absent when the source carried none.
    #[serde(skip_serializing_if = "Option::is_none")]
    uncommitted_worktree: Option<UncommittedWorktreePayload>,
    /// The embedding model the first embed pass will need, and whether this
    /// machine already has it. This command starts that pass, so on a fresh
    /// machine the download is work `kin init` does rather than work it defers.
    /// Additive to this schema version: a consumer that does not read it is
    /// unaffected, and one that does can tell a fresh machine's pending
    /// download from a warm cache before it schedules work.
    embedding_model: crate::embed_model::EmbedModelFetch,
    /// A daemon serving this store that was killed during this conversion.
    ///
    /// Absent is the ordinary case and means the store has no record of losing
    /// one. Present is the machine-readable half of the sentence the human
    /// summary already prints, and it is why this command can exit non-zero on
    /// a run that produced a real store: until it existed, a `--json` caller had
    /// no field to read and every caller had a zero to misread. Additive to this
    /// schema version, so a consumer that does not read it is unaffected.
    #[serde(skip_serializing_if = "Option::is_none")]
    daemon_killed: Option<DaemonKilledPayload>,
    /// Whether the verified repository was also prepared for its first fast
    /// workspace-base reopen. This is a representation outcome, not a second
    /// semantic commit.
    graph_section_materialization: &'a InitGraphSectionMaterialization,
}

/// The post-publication graph-section phase can fail without undoing the
/// verified repository init that preceded it. Keep that degraded result in the
/// init receipt while the explicit command remains a hard-failing retry.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum InitGraphSectionMaterialization {
    Complete(super::repository_authority::GraphSectionMaterialization),
    Failed {
        schema: &'static str,
        scope: super::repository_authority::GraphSectionMaterializationScope,
        state: &'static str,
        error: String,
        retry: &'static str,
    },
}

impl InitGraphSectionMaterialization {
    fn failed(error: &anyhow::Error) -> Self {
        Self::Failed {
            schema: "kin.graph-section-materialization.v1",
            scope: super::repository_authority::GraphSectionMaterializationScope::WorkspaceBase,
            state: "failed",
            error: format!("{error:#}"),
            retry: "kin graph materialize",
        }
    }

    fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }

    fn human_line(&self) -> String {
        match self {
            Self::Complete(outcome) => outcome.human_line(),
            Self::Failed { error, retry, .. } => format!(
                "Graph-section materialization did not complete. Run `{retry}` to retry: {error}"
            ),
        }
    }
}

/// What one machine-readable result says about a daemon it lost.
#[derive(Debug, Serialize)]
struct DaemonKilledPayload {
    /// The store's own sentence about the death, unchanged from the one the
    /// human summary prints, so the two surfaces cannot drift apart.
    summary: String,
    /// The status this command exits with because of it, stated rather than
    /// inferred, so a consumer reading the payload and a consumer reading `$?`
    /// agree without either having to know the constant.
    exit_code: i32,
}

/// The uncommitted delta initialization saw and did not admit.
#[derive(Debug, Serialize)]
struct UncommittedWorktreePayload {
    /// Paths observed, including every one this payload does not carry.
    observed_paths: usize,
    /// Observed paths not carried in `paths`.
    unlisted_paths: usize,
    paths: Vec<UncommittedPathPayload>,
}

/// Paths one machine-readable result carries by name.
///
/// Nothing bounds how many paths can differ: a repository whose checkout Git
/// rewrote reports every text file it holds. A count of those is useful on a
/// piped stdout and tens of thousands of path strings are not, so the payload
/// carries a sample and says exactly how many it left out.
const SERIALIZED_PATHS: usize = 200;

#[derive(Debug, Serialize)]
struct UncommittedPathPayload {
    path: String,
    state: &'static str,
}

/// Write one conversion-phase line to stderr, tolerating a closed pipe.
///
/// `eprintln!` PANICS when its pipe is gone, and `kin init` has a contract that
/// its exit status reports the admission rather than the reader going away. A
/// progress line is not worth an exit code, let alone a panic, so this drops the
/// line instead.
macro_rules! note {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr(), $($arg)*);
    }};
}

/// Exit status for a conversion that produced a store whose semantic enrichment
/// a killed daemon left unattested.
///
/// Distinct from success so a script can tell "converted" from "converted, and
/// something died on the way", and distinct from 1 so it is never read as the
/// conversion having failed. The store is real, publishable and answers
/// questions; what nobody can attest is that its enrichment finished.
pub const EXIT_ENRICHMENT_UNATTESTED: i32 = 7;

/// Exit status for a verified init whose reopen-acceleration section did not
/// persist. The repository exists and remains graph-authoritative; the
/// explicit graph command retries only the missing representation step.
pub const EXIT_GRAPH_SECTION_UNMATERIALIZED: i32 = 8;

pub async fn run(
    path: Option<String>,
    json: bool,
    no_enrich: bool,
    adopt_repository_id: Option<String>,
) -> Result<i32> {
    let _span = tracing::info_span!("kin.init").entered();
    // Read before any work, so the closing summary can say what this run did
    // rather than what a run of its shape usually does. The summary used to
    // say the 523 MB download "happens during this command" unconditionally,
    // and on a container under memory pressure the background embed pass never
    // started, so nothing was fetched and the sentence was still printed.
    //
    // The whole reading is kept rather than its presence bit alone, because the
    // bytes are what decide attribution. A machine carrying an interrupted
    // cache from some earlier attempt is absent before and absent after with a
    // non-zero numerator throughout, and reading only `present` cannot tell
    // that apart from a fetch this command actually moved.
    let model_before = crate::embed_model::EmbedModelFetch::probe(false);
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let adopted = parse_adopted_repository_id(adopt_repository_id.as_deref())?;

    ensure_directory(&dir)?;
    reject_existing_repository(&dir)?;

    let boundary = if path_exists(&dir.join(".git"))? {
        InitBoundary::ExactGit
    } else {
        require_empty_native_boundary(&dir)?;
        InitBoundary::NativeUnborn
    };

    // Both boundaries honour adoption. A flag that worked on one of them and
    // was silently ignored on the other would produce a store that looks
    // adopted and pushes nowhere, which is the failure this whole path exists
    // to remove.
    let result = match (boundary, &adopted) {
        (InitBoundary::ExactGit, None) => kin_core::init_from_git(&dir)
            .context("admit exact reachable Git repository authority")?,
        (InitBoundary::ExactGit, Some(adopted)) => kin_core::init_from_git_adopting(&dir, adopted)
            .with_context(|| {
                format!("admit exact reachable Git repository authority adopting {adopted}")
            })?,
        (InitBoundary::NativeUnborn, None) => {
            kin_core::init(&dir).context("initialize unborn Kin-native repository authority")?
        }
        (InitBoundary::NativeUnborn, Some(adopted)) => kin_core::init_adopting(&dir, adopted)
            .with_context(|| {
                format!("initialize unborn Kin-native repository authority adopting {adopted}")
            })?,
    };

    // Core init has finished publishing and proving semantic authority here.
    // Reopen that exact persisted authority in a short-lived scope and memoize
    // its complete workspace base before enrichment starts a daemon. This
    // keeps the section's capture allocation out of the calibrated publish
    // peak and lets the first real daemon reopen consume the section.
    let graph_section_materialization = match materialize_graph_section_after_init(&result.layout) {
        Ok(outcome) => InitGraphSectionMaterialization::Complete(outcome),
        Err(error) => {
            note!(
                "warning: repository initialization completed, but graph-section materialization did not; run `kin graph materialize` to retry: {error:#}"
            );
            InitGraphSectionMaterialization::failed(&error)
        }
    };

    if let Err(error) = exclude_store_from_git(result.layout.working_dir()) {
        eprintln!(
            "warning: the Kin store at {} was not added to this repository's local Git excludes, \
             so `git status` will list it as untracked: {error:#}",
            result.layout.root().display()
        );
    }

    let enrichment =
        SemanticEnrichmentStatus::from_durable_summary(&result.authority.semantic_enrichment);

    if let Err(error) =
        kin_migrate::update_registry(result.layout.working_dir(), enrichment.entity_count)
    {
        eprintln!(
            "warning: {} was not added to the local repository registry, so cross-repo \
             commands (`kin deps`, `kin xref`) will not see it from sibling repositories: \
             {error:#}",
            result.layout.root().display()
        );
    }

    // Conversion is not finished when the graph exists. Cross-file reference,
    // override and type-use edges are not derivable from a single-file parse:
    // they need a resolved program from a language server, and until this ran
    // here nothing ever asked for one. The sweep had exactly one caller,
    // `POST /lsp/sweep`, which nothing in the product called, so every converted
    // repository answered cross-file questions by matching bare names.
    //
    // Runs before the result is printed so what a reader is told about their
    // repository is true of the repository they now have.
    let cross_file = if !no_enrich {
        // Isolated on its own task so a panic inside it cannot decide init's
        // exit status. `kin init 2>&1 | head -1` closes both streams after one
        // line and every advisory write after that panics; init's contract is
        // that its status reports the admission, not the reader going away. The
        // phase's own writes are already pipe-safe, but it reaches shared
        // advisory paths whose writes are not, and auditing every one of them
        // forever is a worse guarantee than making the phase structurally unable
        // to matter.
        let kin_root = result.layout.root().to_path_buf();
        match tokio::spawn(async move { enrich_after_init(&kin_root).await }).await {
            Ok(outcome) => outcome,
            Err(error) => {
                note!("note: the cross-file enrichment phase did not finish cleanly: {error}");
                CrossFileEnrichment::unreadable()
            }
        }
    } else {
        CrossFileEnrichment::Withheld {
            pending: "`--no-enrich` skipped the language-server sweep, so cross-file reference \
                      and override edges are not in this graph; `kin daemon sweep` runs it"
                .to_string(),
        }
    };

    // Read once, here, and handed to whichever surface reports it. The kill
    // happens during the enrichment phase above and leaves nothing in this
    // process, so it has to come off the store's own records; reading it twice,
    // once for the prose and once for the exit status, would let the sentence a
    // person reads and the number a script reads disagree about the same run.
    let daemon_death = crate::daemon_death::recorded_for_store(result.layout.root());

    if json {
        print_json_result(
            &result,
            boundary,
            enrichment,
            &graph_section_materialization,
            daemon_death.as_ref(),
        )?;
    } else {
        print_human_result(
            &result,
            boundary,
            &enrichment,
            &cross_file,
            &graph_section_materialization,
            &model_before,
            daemon_death.as_ref(),
        )?;
    }
    Ok(exit_code_for(
        daemon_death.as_ref(),
        graph_section_materialization.is_failed(),
    ))
}

fn materialize_graph_section_after_init(
    layout: &kin_core::KinLayout,
) -> Result<super::repository_authority::GraphSectionMaterialization> {
    super::repository_authority::materialize_workspace_base_offline(layout)
        .context("prepare the initialized repository's first graph reopen")
}

/// Exit status for a conversion that finished.
///
/// A store exists either way, which is why this is not an error: the repository
/// was admitted, its authority is durable and every count printed above is
/// true. What a killed daemon takes away is the attestation that the enrichment
/// beside those counts ever finished, and that is invisible to a caller reading
/// a status code, which is the caller most likely to act on it. A scripted
/// setup, a CI step or an agent driving `kin init` reads zero and moves on to
/// asking questions of a graph that stopped converging, and the store's own
/// summary says as much in words nobody parsed.
///
/// So the degraded outcome gets its own code rather than an error. Exit 1 would
/// say the conversion failed and invite a re-run, which at the repository size
/// that causes this is a loop that cannot terminate.
fn exit_code_for(
    daemon_death: Option<&kin_daemon_spawn::DaemonKillRecord>,
    graph_section_failed: bool,
) -> i32 {
    match daemon_death {
        Some(_) => EXIT_ENRICHMENT_UNATTESTED,
        None if graph_section_failed => EXIT_GRAPH_SECTION_UNMATERIALIZED,
        None => 0,
    }
}

/// Resolve `--adopt-repository-id` into the identity the store will carry.
///
/// An empty or blank value is refused rather than treated as absent. The two
/// mean opposite things: absent mints a fresh identity, and present says this
/// store must be a replica of a repository that already exists. Reading a blank
/// argument as absent would hand back a store that mints, which is exactly the
/// state an operator reaching for this flag is trying to avoid, and it would
/// only be discovered at the push.
fn parse_adopted_repository_id(value: Option<&str>) -> Result<Option<kin_model::RepositoryId>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("--adopt-repository-id needs the identity to adopt; it was given an empty value");
    }
    kin_model::RepositoryId::new(trimmed.to_string())
        .map(Some)
        .map_err(|error| anyhow::anyhow!("invalid --adopt-repository-id {trimmed:?}: {error}"))
}

/// How long the conversion phase will wait for the sweep before handing the
/// repository over anyway.
///
/// Bounded because a language server can hang and a conversion that never
/// returns is worse than one that finishes thin: the sweep is resumable, so
/// what this budget cuts short the next daemon start continues. Generous
/// because the alternative failure is worse, an enrichment abandoned at 80% on
/// a large repository every single time.
const ENRICH_BUDGET: std::time::Duration = std::time::Duration::from_secs(900);

/// Stop the daemon the conversion phase started, and only that one.
///
/// Called after the sweep has completed or its budget expired, never mid-pass:
/// a sweep killed halfway is the failure this whole area exists to prevent, and
/// the marker only makes it resumable, not free.
async fn stop_conversion_daemon(borrowed_existing: bool, kin_root: &Path) {
    if borrowed_existing {
        return;
    }
    if let Err(error) = crate::commands::daemon::stop_current_repo_quiet(kin_root).await {
        note!("note: the conversion daemon could not be stopped: {error:#}");
    }
}

/// How long the conversion phase waits for the first embedding pass to settle
/// before it stops the daemon it started.
///
/// [`stop_conversion_daemon`] already waits for the sweep, and its own doc says
/// why: "a sweep killed halfway is the failure this whole area exists to
/// prevent". The first embedding pass was given no such wait, so a conversion
/// that queued a backlog stopped the only process that could drain it, and the
/// daemon a user's next command started began that pass from zero. On the
/// journey run of 2026-09-04 the store handed over reported `Embeddings: 0/804
/// indexed (804 pending)` and the session's first semantic query ranked on
/// lexical fallback.
///
/// Bounded for the reason `ENRICH_BUDGET` is bounded, and much more tightly: the
/// pass is resumable, so what this cuts short the next daemon continues from a
/// persisted checkpoint rather than from zero, and a conversion that waits
/// without end on a very large first fill is worse than one that hands over a
/// store still filling and says so.
///
/// Sized from the pass, not from a feeling. Measured on 2026-09-05 on a
/// 180-file Python repository admitted through `kin init`, whose store queues
/// 1,800 embeddings: a daemon drained 880 of them in 21 seconds on the CPU
/// backend with the host carrying six concurrent Rust builders, so the whole
/// queue from zero is around 45 seconds on that shape, and the 804 the journey
/// run left on express would be under 20. Two minutes is that with well over
/// double the margin, and it stays under half of what an import of this size
/// already costs: this one took 134 seconds and express took 296.
const FIRST_EMBED_PASS_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// How often the wait asks the daemon where the pass has reached.
const FIRST_EMBED_PASS_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// How long a pass may report no progress before this wait stops calling it a
/// pass.
///
/// The daemon stands its embedding worker down for reasons this reading cannot
/// see. `KIN_DAEMON_AUTO_EMBED=0` pauses it outright, and
/// `background_embed_worker_can_drain` gates on that pause, on a permanently
/// failed worker and on whether embed progress can be persisted at all, while
/// `EmbedRuntimeState` carries only the last two of those three. So a queue on
/// an opt-out host is `Filling` by every field this wait can read, and without
/// this the conversion would sit here for the whole budget on a store where
/// nothing was ever going to be embedded.
///
/// Answered by progress rather than by a flag, which is what makes it cover the
/// case nobody has thought of yet: a pass that is neither indexing, nor
/// downloading its model, nor holding the embed mutex is not a pass. The window
/// is not a race against how long a drain takes, because a running drain moves
/// the indexed count on every batch and resets it: the 880 embeddings measured
/// on 2026-09-05 took 21 seconds in total and would have reset this many times
/// over. It only has to be longer than the gap between two batches.
const FIRST_EMBED_PASS_STALL: std::time::Duration = std::time::Duration::from_secs(20);

/// How often the wait says where the pass has reached.
///
/// A conversion that has already taken minutes must not then go silent for two
/// more, and a line every poll is a wall nobody reads. Fifteen seconds puts at
/// most eight lines under a wait that runs to its budget, and one under a wait
/// that ends in a few seconds.
const FIRST_EMBED_PASS_REPORT_EVERY: std::time::Duration = std::time::Duration::from_secs(15);

/// What the conversion phase should do about the embedding pass it started,
/// read from one daemon reading.
///
/// Split from the poll for the reason every other reader in this file is split
/// from its fetch: each branch has to be provable without a daemon, an
/// embedding model or a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstEmbedPassStanding {
    /// Nothing is queued. Stopping the daemon now costs nothing.
    Settled,
    /// Work is outstanding and something in this daemon will drain it. This is
    /// the state the stop must not cut short.
    Filling,
    /// Work is outstanding and nothing in this daemon will drain it, so waiting
    /// buys the store nothing.
    Stalled(&'static str),
}

/// Read one daemon reading into a decision.
///
/// The stalled arms mirror the daemon's own `background_embed_worker_can_drain`
/// predicate rather than a second copy of its rule: a backlog nobody will
/// consume is not work in flight, and treating it as such would make every
/// conversion on such a store sit here for the whole budget.
fn first_embed_pass_standing(
    embed: &crate::commands::resources::EmbedRuntimeState,
) -> FirstEmbedPassStanding {
    if embed.embed_worker_failed {
        return FirstEmbedPassStanding::Stalled(
            "the daemon's background embedding worker has stopped",
        );
    }
    if embed.embed_persistence_unavailable {
        return FirstEmbedPassStanding::Stalled(
            "this store's graph authority carries no durable local vector sidecar, so nothing \
             embeds here",
        );
    }
    if embed.embeddings_pending == 0 {
        return FirstEmbedPassStanding::Settled;
    }
    FirstEmbedPassStanding::Filling
}

/// What one wait for the first embedding pass ended in.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FirstEmbedPassOutcome {
    /// The daemon could not be read, so nothing was waited for. Never an error:
    /// a conversion that already succeeded must not be turned into a failure,
    /// or a hang, by a probe.
    Unread,
    /// The queue drained.
    Drained { indexed: usize },
    /// Nothing in this daemon would drain the queue.
    Stalled {
        pending: usize,
        reason: &'static str,
    },
    /// The budget ran out with the queue still filling. The budget is carried
    /// rather than read back off the constant, so the line a reader sees names
    /// the wait that actually happened.
    BudgetSpent {
        indexed: usize,
        total: usize,
        waited_secs: u64,
    },
}

impl FirstEmbedPassOutcome {
    /// The line the conversion prints, or nothing when there is nothing a
    /// reader could act on.
    ///
    /// Silent on `Unread` and on a queue that was already empty, because a
    /// conversion of a repository with nothing to embed must not grow a line
    /// about embedding.
    fn note(&self) -> Option<String> {
        match self {
            Self::Unread => None,
            Self::Drained { indexed: 0 } => None,
            Self::Drained { indexed } => Some(format!(
                "First embedding pass: complete, {indexed} indexed before this command handed the \
                 repository over."
            )),
            Self::Stalled { pending, reason } => Some(format!(
                "First embedding pass: {pending} still queued and {reason}, so this command did \
                 not wait for them."
            )),
            Self::BudgetSpent {
                indexed,
                total,
                waited_secs,
            } => Some(format!(
                "First embedding pass: {indexed} of {total} indexed in the {waited_secs}s this \
                 command was willing to wait. The rest is persisted work in progress: the daemon \
                 your next command starts resumes it from here, and semantic queries answer from \
                 lexical retrieval until it finishes."
            )),
        }
    }
}

/// Wait for the first embedding pass to settle, under a budget, reporting where
/// it has reached.
///
/// `read` is injected so the loop's behaviour is provable without a daemon, an
/// embedding model or a network: the property under test is that this waits
/// while work is filling and stops when it is not, and no fixture can produce
/// that against a real first fill inside a test.
async fn settle_first_embed_pass_within<F, Fut>(
    budget: std::time::Duration,
    poll: std::time::Duration,
    stall: std::time::Duration,
    mut read: F,
) -> FirstEmbedPassOutcome
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<crate::commands::resources::EmbedRuntimeState>>,
{
    // A watch loop that ends on its first failed read reports a settled pass
    // over a daemon that was merely busy for one poll. A watch loop that never
    // ends on a failed read waits out its whole budget against a daemon that is
    // gone. So consecutive failures are counted, and the count is what decides.
    const UNREADABLE_POLLS_BEFORE_GIVING_UP: usize = 3;

    // `tokio::time::Instant`, not `std::time::Instant`, and this is load
    // bearing rather than tidiness. The budget is what a paused-clock test
    // drives the loop to, and `std::time::Instant::elapsed` does not move under
    // `#[tokio::test(start_paused = true)]`, so a budget read from the wall
    // clock would never be reached and the test that proves this wait STOPS
    // would hang instead of failing. Outside a test the two are the same clock.
    let began = tokio::time::Instant::now();
    let mut last_report: Option<tokio::time::Instant> = None;
    let mut unreadable = 0usize;
    let mut last_progress = tokio::time::Instant::now();
    let mut last_indexed: Option<usize> = None;
    loop {
        let Some(embed) = read().await else {
            unreadable += 1;
            if unreadable >= UNREADABLE_POLLS_BEFORE_GIVING_UP || began.elapsed() >= budget {
                return FirstEmbedPassOutcome::Unread;
            }
            tokio::time::sleep(poll).await;
            continue;
        };
        unreadable = 0;
        match first_embed_pass_standing(&embed) {
            FirstEmbedPassStanding::Settled => {
                return FirstEmbedPassOutcome::Drained {
                    indexed: embed.embeddings_indexed,
                }
            }
            FirstEmbedPassStanding::Stalled(reason) => {
                return FirstEmbedPassOutcome::Stalled {
                    pending: embed.embeddings_pending,
                    reason,
                }
            }
            FirstEmbedPassStanding::Filling => {}
        }
        // Whether this reading is evidence the pass is alive. Any one of the
        // three is enough: the model arriving is progress on a pass that cannot
        // index yet, and the embed mutex being held is progress on a batch
        // whose count has not landed.
        let moved = last_indexed != Some(embed.embeddings_indexed);
        if moved || embed.embedding_work_busy || embed.model_fetch.fetching {
            last_progress = tokio::time::Instant::now();
            last_indexed = Some(embed.embeddings_indexed);
        } else if last_progress.elapsed() >= stall {
            return FirstEmbedPassOutcome::Stalled {
                pending: embed.embeddings_pending,
                reason: "no embed pass is running and the indexed count has not moved, so this \
                         daemon is not draining the queue",
            };
        }
        if began.elapsed() >= budget {
            return FirstEmbedPassOutcome::BudgetSpent {
                indexed: embed.embeddings_indexed,
                total: embed.embeddings_total,
                waited_secs: budget.as_secs(),
            };
        }
        let due = last_report
            .map(|at| at.elapsed() >= FIRST_EMBED_PASS_REPORT_EVERY)
            .unwrap_or(true);
        if due {
            last_report = Some(tokio::time::Instant::now());
            match embed.model_fetch.download_phase() {
                Some(phase) => note!(
                    "  → first embedding pass: {} of {} indexed; {phase}",
                    embed.embeddings_indexed,
                    embed.embeddings_total
                ),
                None => note!(
                    "  → first embedding pass: {} of {} indexed",
                    embed.embeddings_indexed,
                    embed.embeddings_total
                ),
            }
        }
        tokio::time::sleep(poll).await;
    }
}

/// Ask the daemon this conversion started where its first embedding pass has
/// reached, and wait for it under [`FIRST_EMBED_PASS_BUDGET`].
async fn settle_first_embed_pass(layout: &kin_core::KinLayout) -> FirstEmbedPassOutcome {
    let Some(url) = crate::daemon_client::resolve_daemon_url_if_running_async(layout).await else {
        return FirstEmbedPassOutcome::Unread;
    };
    let Ok(client) = crate::daemon_client::DaemonClient::from_base_url_for_layout(url, layout)
    else {
        return FirstEmbedPassOutcome::Unread;
    };
    settle_first_embed_pass_within(
        FIRST_EMBED_PASS_BUDGET,
        FIRST_EMBED_PASS_POLL,
        FIRST_EMBED_PASS_STALL,
        || async {
            client
                .command_resources(&crate::commands::resources::CommandResourcesRequest::default())
                .await
                .ok()
                .map(|response| response.embed_runtime)
        },
    )
    .await
}

/// Run the language-server sweep as a phase of conversion, with progress.
///
/// Every line this prints goes to STDERR, including the progress. `kin init
/// --json` writes one machine-readable document to stdout and callers parse it,
/// so a progress line there is not chatty output, it is a corrupted response:
/// twelve tests failed with `stdout should be valid json` and
/// `expected value, line 1 column 1` the first time this wrote to stdout. The
/// closed-pipe contract is the same fact from the other side, where an extra
/// stdout write changes what `kin init` reports when its reader goes away.
///
/// Every failure here is reported and swallowed. A repository whose graph is
/// built is a usable repository, and refusing the whole `kin init` because a
/// language server was missing, slow, or broken would turn an enrichment
/// shortfall into a conversion failure. The shortfall is visible afterwards:
/// `kin doctor` reports the enrichment gap and names the command that closes it.
/// `kin_root` is the `.kin` directory, which is what `ensure_daemon_running`
/// takes. Passing the working directory instead resolves a store that is not
/// there and fails with a version error naming a layout nothing wrote, which is
/// exactly how this read as "no daemon could be started" on a repository whose
/// store had just been created successfully.
/// What the conversion's enrichment phase produced, as the summary has to
/// describe it.
///
/// `kin init` reported "Semantic enrichment: present" on a repository whose
/// graph held no cross-file reference edge at all, because presence is scored
/// from entity and relation counts and a single-file parse fills both. The
/// containment edges are real, so the counts are right; the word over them is
/// what claimed a graph the run did not build. FIR-2787 is the reader who was
/// told four separate times, on four surfaces, what this one word had already
/// said wrongly.
///
/// The phase already knows the answer at no extra cost. It watches the sweep it
/// started, so it sees a daemon that could not sweep, a sweep that walked files
/// and enriched none, and a sweep cut short by its own budget, and each of the
/// three is a run that produced no complete cross-file graph. Nothing here
/// re-reads the store to find that out, which matters on the repository this
/// ticket came from, where a `graph status` costs half a minute.
///
/// The claim is deliberately about THIS RUN and not about the store. The phase
/// watched one sweep; it did not count the graph's edges, and saying it had
/// would be the same overreach in the other direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CrossFileEnrichment {
    /// A sweep finished having enriched files, so this run produced cross-file
    /// edges.
    Produced,
    /// This run produced no complete cross-file graph, with what is pending and
    /// what would finish it.
    Withheld { pending: String },
}

impl CrossFileEnrichment {
    /// The phase reached the daemon and could not learn what the sweep did.
    ///
    /// Withheld rather than `Produced`, because the summary's word is a claim
    /// and an unread sweep supports no claim. It says so plainly instead of
    /// borrowing the confident word from a run nobody watched.
    fn unreadable() -> Self {
        Self::Withheld {
            pending: "this run could not read what the cross-file sweep did, so whether it \
                      produced any cross-file edge is unknown; run `kin doctor` to read this \
                      store's reference-edge coverage"
                .to_string(),
        }
    }

    /// What is still owed, when something is.
    fn pending(&self) -> Option<&str> {
        match self {
            Self::Withheld { pending } => Some(pending),
            Self::Produced => None,
        }
    }
}

/// One language a cold sweep could not serve, as `/lsp/sweep/status` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SkippedLanguage {
    language: String,
    files: u64,
    reason: String,
}

/// The languages `/lsp/sweep/status` says this sweep could not serve.
///
/// A row missing either half is dropped rather than defaulted. A language with
/// no reason would print a skip nothing explains, and a reason with no language
/// names nothing; both are worse than a shorter list, because the caller below
/// keys its whole verdict on whether this comes back empty. A daemon too old to
/// send the field reads as nothing skipped, which is the same conservative
/// reading an unpublished readiness map already gets.
pub(crate) fn skipped_languages_from_status(status: &serde_json::Value) -> Vec<SkippedLanguage> {
    let Some(rows) = status.get("languages_skipped").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let language = row.get("language")?.as_str()?.to_string();
            let reason = row.get("reason")?.as_str()?.to_string();
            if language.is_empty() || reason.is_empty() {
                return None;
            }
            Some(SkippedLanguage {
                language,
                files: row.get("files").and_then(|v| v.as_u64()).unwrap_or(0),
                reason,
            })
        })
        .collect()
}

/// `1 file` and `2 files`, so a count never reads `1 files`.
fn plural_count(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {many}")
    }
}

/// The detail lines under a sweep outcome: one per language, plus the remainder.
///
/// `blocked` is the daemon's own total and the rows are the part of it the
/// daemon could attribute to a language. They are not the same number. A file is
/// also blocked when its extension maps to no language server this build wires,
/// or when its source could not be read from graph authority, and neither of
/// those paths records a row. Measured on a three-rust, three-typescript,
/// two-ruby repository: `files_blocked` 5, rows accounting for 3, and a reader
/// who added the sentence's own figures got six of eight with nowhere to go for
/// the other two. So the remainder is stated rather than dropped, because a
/// sentence whose whole purpose is to name what was lost cannot leave part of it
/// out and stay honest.
fn skipped_detail_lines(blocked: u64, skipped: &[SkippedLanguage]) -> Vec<String> {
    let mut lines: Vec<String> = skipped
        .iter()
        .map(|entry| {
            format!(
                "    {}: {} not enriched, because {}",
                entry.language,
                plural_count(entry.files, "file", "files"),
                entry.reason
            )
        })
        .collect();
    let named: u64 = skipped.iter().map(|entry| entry.files).sum();
    let unattributed = blocked.saturating_sub(named);
    if unattributed > 0 {
        // `further` only when there are rows above for it to be further than.
        let count = if skipped.is_empty() {
            plural_count(unattributed, "file", "files")
        } else {
            plural_count(unattributed, "further file", "further files")
        };
        lines.push(format!(
            "    {count} blocked for a reason this sweep did not attribute to a language: an \
             extension no language server here serves, or source it could not read from graph \
             authority; `.kin/daemon.log` records each one"
        ));
    }
    lines
}

/// What a FINISHED sweep amounts to: the line to print and the verdict to carry.
///
/// One function rather than a wording helper beside a branch, because the two
/// are the same claim and a test that reaches only one of them proves nothing
/// about the other: a renderer test stays green when the branch that calls it is
/// deleted. `kin daemon sweep` calls it too, for the same reason: it is the
/// command the pending line below tells a reader to run next, and it printed
/// `sweep complete (3/6 files)` off the same status object that named a language
/// it could not serve.
///
/// The middle arm is coldwalk finding 6. A macOS pass on `tokio-rs/axum`, on a
/// host that DID carry rustup and rust-analyzer, printed
/// `cross-file enrichment complete (5/303 files)`, and the same store's next
/// `kin graph status` read `imports 0/1085 (0%)` and `cross-file reference and
/// override edges unavailable for rust: no language server found`, numbers
/// byte-identical to a container with no language server at all. The five files
/// were JavaScript. One store cannot say both things. The zero-file guard could
/// not catch it, because `done` was five rather than zero, and the count alone
/// never could: `files_blocked` counts files and cannot name a language.
///
/// Only one arm here is entitled to the word `complete`, and it is the one where
/// nothing at all was blocked. `complete (6/8 files)` was measured live on a
/// ruby fixture: its own two numbers disagree, and the two files between them
/// were named by nothing.
pub(crate) fn cross_file_enrichment_outcome(
    done: u64,
    total: u64,
    blocked: u64,
    skipped: &[SkippedLanguage],
) -> (String, CrossFileEnrichment) {
    let languages: Vec<&str> = skipped
        .iter()
        .map(|entry| entry.language.as_str())
        .collect();

    // A sweep that enriched nothing reported the same sentence as one that had
    // nothing left to do, and on a JavaScript repository with 66 admitted files
    // that sentence was "complete (0/66 files)".
    if done == 0 && total > 0 {
        let mut lines = vec![format!(
            "note: cross-file enrichment finished without enriching any of the {total} files \
             it walked ({blocked} blocked); reference and import edges will be missing until \
             it can run, and `.kin/daemon.log` records what stopped it"
        )];
        // The arm that loses the most used to name the least: it returned before
        // it looked at the rows, so the coldwalk's own container leg, where the
        // sweep walked 66 files and enriched none, handed a reader a count and a
        // blocked number and never said which language they had lost or why.
        // With no rows the headline already accounts for every blocked file, so
        // nothing is appended and the sentence stays the one that shipped.
        if !skipped.is_empty() {
            lines.extend(skipped_detail_lines(blocked, skipped));
        }
        let pending = if languages.is_empty() {
            format!(
                "the sweep walked {total} files and enriched none of them, so cross-file \
                 reference and override edges are not in this graph; `kin daemon sweep` \
                 retries it"
            )
        } else {
            format!(
                "the sweep walked {total} files and enriched none of them, so cross-file \
                 reference and override edges are not in this graph, and it could not serve \
                 {} at all: {}; the note above names what each one needs, and `kin daemon \
                 sweep` retries once that is repaired",
                plural_count(languages.len() as u64, "language", "languages"),
                languages.join(", ")
            )
        };
        return (lines.join("\n"), CrossFileEnrichment::Withheld { pending });
    }
    if !skipped.is_empty() {
        let mut lines = vec![format!(
            "  cross-file enrichment ended having enriched {done} of {total} files, leaving {} \
             unserved:",
            plural_count(skipped.len() as u64, "language", "languages")
        )];
        lines.extend(skipped_detail_lines(blocked, skipped));
        return (
            lines.join("\n"),
            CrossFileEnrichment::Withheld {
                pending: format!(
                    "the sweep enriched {done} of {total} files and could not serve {}, so \
                     cross-file reference and override edges for {} are not in this graph; the \
                     note above names what each one needs, and `kin daemon sweep` retries once \
                     that is repaired",
                    plural_count(skipped.len() as u64, "language", "languages"),
                    languages.join(", ")
                ),
            },
        );
    }
    if blocked > 0 {
        // Blocked files the daemon could not attribute to a language. The
        // verdict deliberately stays `Produced`: every language this build
        // serves WAS served, and telling a reader that `kin daemon sweep` would
        // repair a file whose extension no server here handles is the same
        // fabricated-cause defect in the other direction. What changes is the
        // sentence, which no longer calls a pass with blocked files complete.
        let mut lines = vec![format!(
            "  cross-file enrichment covered {done} of {total} files:"
        )];
        lines.extend(skipped_detail_lines(blocked, skipped));
        return (lines.join("\n"), CrossFileEnrichment::Produced);
    }
    (
        format!("  cross-file enrichment complete ({done}/{total} files)"),
        CrossFileEnrichment::Produced,
    )
}

/// Run the conversion phase and ALWAYS clean up after it.
///
/// The cleanup used to sit after the happy-path wait, so every early return
/// skipped it. On a CI runner the sweep POST was refused 401 and the phase
/// returned before the stop, leaking the daemon it had started; two minutes
/// later an independent daemon could not start because "another kin daemon (pid
/// 10195) already owns" the repository. That is the fourth time this phase
/// broke a contract it has no business touching, and the first three were all
/// on the happy path, so the fix is structural rather than another audited exit.
///
/// The phase runs on its own task and the cleanup runs after the join, so it is
/// reached on success, on refusal, on timeout and on panic alike.
async fn enrich_after_init(kin_root: &Path) -> CrossFileEnrichment {
    let Some(layout) = kin_core::KinLayout::discover(kin_root) else {
        note!("note: cross-file reference enrichment was skipped: no Kin layout at this path");
        return CrossFileEnrichment::unreadable();
    };

    // Whether a daemon was already serving this repository. If not, anything
    // running afterwards is ours, and a daemon left behind by `kin init` pins a
    // repository cursor that makes the next mutation refuse.
    let borrowed_existing = crate::daemon_client::resolve_daemon_url_if_running_async(&layout)
        .await
        .is_some();

    let root = kin_root.to_path_buf();
    let phase_layout = layout.clone();
    let phase = tokio::spawn(async move { enrich_phase(&root, &phase_layout).await });
    let outcome = match phase.await {
        Ok(outcome) => outcome,
        Err(error) => {
            note!("note: the cross-file enrichment phase did not finish cleanly: {error}");
            CrossFileEnrichment::unreadable()
        }
    };

    // Before the stop, never after it. The daemon this phase started is the
    // only process that can drain the embedding queue its own ingest filled,
    // and stopping it mid-pass lands wherever the pass happens to be. The same
    // 180-file import measured twice on 2026-09-05 handed over `0/1800
    // indexed` on one run and a salvaged `920/1800` on the next, because the
    // stop is unrelated to where the pass is. `stop_conversion_daemon` already
    // waits for the sweep for exactly this reason, and gave the embedding pass
    // no such wait. Skipped when this phase borrowed a daemon somebody else
    // started, because then there is no stop to protect against.
    if !borrowed_existing {
        if let Some(line) = settle_first_embed_pass(&layout).await.note() {
            note!("{line}");
        }
    }
    stop_conversion_daemon(borrowed_existing, kin_root).await;
    outcome
}

/// The sentence `kin init` prints when a run produced no cross-file edges.
///
/// One argument per thing the daemon reported, and nothing read from this host,
/// so what a user sees is decided entirely by what the daemon observed. This
/// used to be one hardcoded sentence asserting "no language server is
/// installed", which was false on a daemon with enrichment switched off and
/// false again on a host that installed a server after the daemon started, and
/// it prescribed an install that would have changed nothing in either case.
///
/// The repair travels with the cause rather than beside it. The old note was
/// accidentally right about the cure, since its second step restarted the
/// daemon, and that is the worst shape for a reader: following it works and
/// believing it leaves them wrong about their own system.
///
/// An unrecognised reason keeps its own row instead of falling back to the
/// missing-install sentence. A daemon older or newer than this CLI is exactly
/// the case where guessing would reintroduce the defect.
fn enrichment_unavailable_note(reason: &str, detail: Option<&str>) -> String {
    // Both rows where the daemon looked at startup and found nothing share this
    // repair, and they share it because the daemon cannot tell them apart: it
    // read its own PATH once, at its own start, so whether this host has a
    // server NOW is the reader's fact rather than the daemon's. Naming one
    // repair would assert the state these rows exist to leave open, which is
    // how the sentence this replaced came to send a user with a server
    // installed off to install another.
    const REPAIR: &str = "Run `kin doctor --fix --install-language-servers` if this host has \
                          none, or `kin daemon stop` if one was installed after this daemon \
                          started; the next command re-enriches this repository.";

    match (reason, detail) {
        ("no_language_server", Some(detail)) => format!(
            "note: {detail}. Cross-file reference and override edges were not produced by this \
             run. {REPAIR}"
        ),
        ("discovery_stale", Some(detail)) => format!(
            "note: {detail}. Cross-file reference and override edges were not produced by this \
             run. Run `kin daemon stop`; the next command re-enriches this repository."
        ),
        ("language_server_unusable", Some(detail)) => format!(
            "note: {detail}. Cross-file reference and override edges were not produced. Repair \
             the language server, then run `kin daemon stop`; the next command re-enriches this \
             repository."
        ),
        ("enrichment_disabled", Some(detail)) => format!(
            "note: {detail}. Cross-file reference and override edges were not produced by this \
             run."
        ),
        // Startup discovery found nothing and the readiness probe has not
        // landed either, so this row knows strictly less than
        // `no_language_server` and says so in its detail. The repair is the
        // same because the reader's question is the same.
        ("discovery_found_none", Some(detail)) => format!(
            "note: {detail}. Cross-file reference and override edges were not produced by this \
             run. {REPAIR}"
        ),
        (_, detail) => format!(
            "note: cross-file reference and override edges were not produced by this run, and \
             this daemon did not report why ({}). Run `kin doctor` to see what its language \
             servers can do.",
            detail.unwrap_or("cause not established")
        ),
    }
}

async fn enrich_phase(kin_root: &Path, layout: &kin_core::KinLayout) -> CrossFileEnrichment {
    let url = match crate::daemon_client::ensure_daemon_running(kin_root).await {
        Ok(url) => url,
        Err(error) => {
            note!(
                "note: cross-file reference enrichment was skipped because no daemon could be \
                 started ({error}); run `kin doctor` to see what is missing"
            );
            return CrossFileEnrichment::unreadable();
        }
    };
    // FOR_LAYOUT, not the plain constructor. The plain one resolves the
    // daemon bearer token from the PROCESS WORKING DIRECTORY, and `kin init`
    // takes the repository as an argument, so on a runner whose cwd is not the
    // new repository the token was never found and the sweep POST went out
    // unauthenticated: "kin lsp sweep refused (HTTP 401)". The layout is the
    // repository this phase is about, and its `.kin` holds the token the daemon
    // just minted.
    let client = match crate::daemon_client::DaemonClient::from_base_url_for_layout(url, layout) {
        Ok(client) => client,
        Err(error) => {
            note!("note: cross-file reference enrichment was skipped: {error:#}");
            return CrossFileEnrichment::unreadable();
        }
    };

    let queued = match client.queue_lsp_sweep().await {
        Ok(value) => value,
        Err(error) => {
            note!("note: cross-file reference enrichment could not be started: {error:#}");
            return CrossFileEnrichment::unreadable();
        }
    };
    // A daemon with no language server never sweeps. Saying so, with the
    // command that fixes it, beats waiting fifteen minutes for an event that
    // cannot happen.
    if queued.get("enrichment_available").and_then(|v| v.as_bool()) == Some(false) {
        // Report the cause the daemon OBSERVED, never a cause derived from the
        // boolean. That boolean collapses several states, and this note used to
        // assert the one it could not know, telling users with a language server
        // installed that none was, and prescribing an install that would change
        // nothing. The remedy is chosen by the same observed cause, so a reader
        // who follows it is also right about why.
        let observed = queued.get("enrichment_unavailable");
        let reason = observed
            .and_then(|value| value.get("reason"))
            .and_then(|value| value.as_str())
            .unwrap_or("unknown");
        let detail = observed
            .and_then(|value| value.get("detail"))
            .and_then(|value| value.as_str());
        note!("{}", enrichment_unavailable_note(reason, detail));
        return CrossFileEnrichment::Withheld {
            pending: "no language-server sweep ran for this repository, so cross-file reference \
                      and override edges are not in this graph; the note above names what would \
                      let it run"
                .to_string(),
        };
    }
    let baseline = queued
        .get("sweeps_completed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    note!("Enriching cross-file references (language server)...");
    let deadline = std::time::Instant::now() + ENRICH_BUDGET;
    let mut last_reported = 0u64;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let status = match client.lsp_sweep_status().await {
            Ok(status) => status,
            Err(error) => {
                note!("note: enrichment progress could not be read: {error:#}");
                return CrossFileEnrichment::unreadable();
            }
        };
        let done = status
            .get("files_done")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let total = status
            .get("files_total")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Progress is printed per file rather than at the end, because a
        // conversion that prints nothing for minutes reads as hung and gets
        // interrupted, which is how the work a user asked for gets thrown away.
        if done > last_reported {
            last_reported = done;
            note!("  enriched {done}/{total} files");
        }
        let completed = status
            .get("sweeps_completed")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let running = status
            .get("running")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        // Both, not either. The counter says a sweep ended; `running` says none
        // is in flight now. Returning on the counter alone hands back a graph a
        // later sweep is still mutating, and a query issued into that window
        // fails to resolve entities it resolves fine before and after.
        if completed > baseline && !running {
            let blocked = status
                .get("files_blocked")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let skipped = skipped_languages_from_status(&status);
            let (line, outcome) = cross_file_enrichment_outcome(done, total, blocked, &skipped);
            note!("{}", line);
            return outcome;
        }
        if std::time::Instant::now() >= deadline {
            note!(
                "note: cross-file enrichment did not finish within {}s and was left running; it \
                 resumes from where it stopped on the next daemon start",
                ENRICH_BUDGET.as_secs()
            );
            return CrossFileEnrichment::Withheld {
                pending: format!(
                    "the sweep reached {last_reported} files and did not finish within {}s, so \
                     the cross-file edges it has not got to are not in this graph; it resumes on \
                     the next daemon start",
                    ENRICH_BUDGET.as_secs()
                ),
            };
        }
    }
}
fn ensure_directory(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => anyhow::bail!("repository path is not a directory: {}", dir.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => std::fs::create_dir_all(dir)
            .with_context(|| format!("create repository directory {}", dir.display())),
        Err(error) => {
            Err(error).with_context(|| format!("inspect repository directory {}", dir.display()))
        }
    }
}

fn reject_existing_repository(dir: &Path) -> Result<()> {
    if path_exists(&dir.join(".kin"))? {
        anyhow::bail!(existing_repository_refusal(dir));
    }
    Ok(())
}

/// The refusal `kin init` raises over a directory that already holds a store.
///
/// The reader who arrives here most often is the one the store wall just sent,
/// after an older store refused to open. That wall names a rebuild, and `kin
/// init` is half of it, so this refusal names the same rebuild instead of
/// stopping at the fact that a store exists.
fn existing_repository_refusal(dir: &Path) -> String {
    format!(
        "Kin repository already exists at {}; `kin init` never rebuilds graph authority from the \
         working tree. If this build cannot open that store, {} again to rebuild it from the \
         repository's Git history.",
        dir.display(),
        super::REBUILD_INCOMPATIBLE_STORE
    )
}

fn require_empty_native_boundary(dir: &Path) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("inspect native repository boundary {}", dir.display()))?;
    if entries
        .next()
        .transpose()
        .with_context(|| format!("inspect native repository boundary {}", dir.display()))?
        .is_some()
    {
        anyhow::bail!(
            "non-Git repository admission currently requires an empty directory: {}; Kin will \
             not silently ignore or derive authority from existing filesystem contents. Commit \
             the exact files to Git and retry, or initialize an empty Kin-native repository.{}",
            dir.display(),
            git_prerequisite_note(which::which("git").is_ok())
        );
    }
    Ok(())
}

/// The suffix naming Git as a prerequisite of the remedy above.
///
/// Kin reads a repository's history through `gix` and never needs the host
/// binary to admit one, so this error is reachable on a host with no Git at
/// all — and the first remedy it offers is a `git commit`. Say that the tool
/// is missing rather than sending the reader to a command they do not have.
fn git_prerequisite_note(git_on_path: bool) -> &'static str {
    if git_on_path {
        ""
    } else {
        " Git is not installed on this host, so committing to Git needs `git` installed first."
    }
}

/// The rule `kin init` adds so the store stays out of `git status`.
///
/// Anchored and directory-scoped so it names the store this command just wrote
/// and nothing else. An unanchored `.kin/` would also hide a nested directory
/// of that name anywhere in the tree, which is not this command's to decide.
const STORE_EXCLUDE_RULE: &str = "/.kin/";

/// Spellings of a rule that already keeps the store out of `git status`.
///
/// A repository converted before this command excluded anything, or one whose
/// author added the rule by hand, is already correct. Re-stating it would leave
/// a duplicate line behind on every re-init.
const STORE_EXCLUDE_EQUIVALENTS: &[&str] = &[".kin", ".kin/", "/.kin", "/.kin/"];

/// Keep the store out of the converted repository's `git status`.
///
/// Admission writes a `.kin` directory that is routinely a gigabyte, and Git
/// has no reason to know it is Kin's. Without a rule it is reported as
/// untracked forever, on every `git status` the author runs, which is a
/// permanent cost paid for a one-time conversion.
///
/// The rule goes in `.git/info/exclude` rather than the repository's tracked
/// `.gitignore`, because whether a peer's checkout carries a Kin store is that
/// peer's business. Excluding it locally costs the author nothing and changing
/// a tracked file would put Kin in their next diff.
///
/// Every refusal here is reported and none of them fail the command: the store
/// is durable before this runs, and an admission that succeeded must not be
/// turned into a failure by a convenience.
fn exclude_store_from_git(working_dir: &Path) -> Result<Option<PathBuf>> {
    let Some(common_dir) = git_common_dir(working_dir)? else {
        return Ok(None);
    };
    if store_already_excluded(working_dir, &common_dir)? {
        return Ok(None);
    }

    let info_dir = common_dir.join("info");
    std::fs::create_dir_all(&info_dir)
        .with_context(|| format!("create Git info directory {}", info_dir.display()))?;
    let exclude = info_dir.join("exclude");
    if let Ok(metadata) = std::fs::symlink_metadata(&exclude) {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            anyhow::bail!(
                "Git exclude authority must be a regular non-symlink file: {}",
                exclude.display()
            );
        }
    }

    let mut body = read_optional_text(&exclude)?.unwrap_or_default();
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str(STORE_EXCLUDE_RULE);
    body.push('\n');
    std::fs::write(&exclude, body)
        .with_context(|| format!("write Git exclude {}", exclude.display()))?;
    Ok(Some(exclude))
}

/// The directory holding the shared `info/exclude` for this worktree.
///
/// A `.git` directory is its own common directory. A linked worktree or a
/// submodule instead carries a `gitdir:` pointer file, and a linked worktree's
/// excludes live with the repository it was added from, which its `commondir`
/// names. Following the pointer is what makes this work in the worktrees Kin's
/// own fleet runs in.
fn git_common_dir(working_dir: &Path) -> Result<Option<PathBuf>> {
    let dot_git = working_dir.join(".git");
    let metadata = match std::fs::symlink_metadata(&dot_git) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {}", dot_git.display())),
    };
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "repository Git authority must not be a symlink: {}",
            dot_git.display()
        );
    }
    if metadata.is_dir() {
        return Ok(Some(dot_git));
    }
    if !metadata.is_file() {
        return Ok(None);
    }

    let pointer = std::fs::read_to_string(&dot_git)
        .with_context(|| format!("read Git pointer file {}", dot_git.display()))?;
    let Some(target) = pointer
        .lines()
        .find_map(|line| line.trim().strip_prefix("gitdir:"))
    else {
        anyhow::bail!("Git pointer file names no gitdir: {}", dot_git.display());
    };
    let git_dir = resolve_against(working_dir, target.trim());
    match read_optional_text(&git_dir.join("commondir"))? {
        Some(common) => match common
            .lines()
            .next()
            .map(str::trim)
            .filter(|l| !l.is_empty())
        {
            Some(common) => Ok(Some(resolve_against(&git_dir, common))),
            None => Ok(Some(git_dir)),
        },
        None => Ok(Some(git_dir)),
    }
}

fn resolve_against(base: &Path, target: &str) -> PathBuf {
    let target = Path::new(target);
    if target.is_absolute() {
        target.to_path_buf()
    } else {
        base.join(target)
    }
}

/// Whether some rule Git already reads keeps the store out of `git status`.
///
/// Git is asked for the rules it actually resolves, which is the only answer
/// that matches what the author will see. That covers a rule living in a
/// `core.excludesFile` outside the repository, and it reads a later `!.kin`
/// negation as Git reads it, where matching exclude-file lines against a fixed
/// set of spellings would call the store excluded when `git status` still names
/// it.
///
/// The line scan below stands in only when the question cannot be put to Git at
/// all, which is a directory carrying a `.git` that is not an openable
/// repository. Nothing there resolves ignore rules either, so the two files a
/// rule can be written into are the whole of what a reader could consult.
fn store_already_excluded(working_dir: &Path, common_dir: &Path) -> Result<bool> {
    match kin_git::kin_store_is_git_ignored(working_dir) {
        Ok(excluded) => return Ok(excluded),
        Err(error) => tracing::debug!(
            %error,
            "Git could not resolve ignore rules here; reading the exclude files directly"
        ),
    }
    for candidate in [
        common_dir.join("info").join("exclude"),
        working_dir.join(".gitignore"),
    ] {
        let Some(body) = read_optional_text(&candidate)? else {
            continue;
        };
        if body
            .lines()
            .map(str::trim)
            .any(|line| STORE_EXCLUDE_EQUIVALENTS.contains(&line))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn read_optional_text(path: &Path) -> Result<Option<String>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            Ok(Some(String::from_utf8(bytes).with_context(|| {
                format!("{} is not UTF-8", path.display())
            })?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

fn path_exists(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn print_json_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: SemanticEnrichmentStatus,
    graph_section_materialization: &InitGraphSectionMaterialization,
    daemon_death: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> Result<()> {
    let workspace = &result.authority.workspace;
    let default_ref = initialized_default_ref(result);
    let payload = InitResultPayload {
        schema: "kin.init-result.v6",
        authority: "repository-v6",
        source_boundary: boundary.source_boundary(),
        history: boundary.history(),
        semantic_enrichment,
        repo_root: result.layout.working_dir().display().to_string(),
        kin_dir: result.layout.root().display().to_string(),
        repository_id: &result.repository_id,
        workspace_id: result.workspace_id,
        default_ref,
        authority_generation: result.authority.receipt.generation,
        workspace_generation: workspace.workspace_generation,
        workspace_head: &workspace.workspace_head,
        raw_git_head: initialized_raw_git_head(result),
        base_target: workspace.base_target.as_ref(),
        base_tree_hash: workspace.base_tree_hash,
        workspace_tree_hash: workspace.workspace_tree_hash,
        roots: &result.authority.receipt.roots_after,
        initial_change_id: result.authority.initial_change_id.as_ref(),
        exact_reachable_git_history: boundary == InitBoundary::ExactGit,
        store_footprint: StoreFootprint::measure(&result.layout),
        uncommitted_worktree: uncommitted_worktree_payload(&result.workspace_divergence),
        embedding_model: crate::embed_model::EmbedModelFetch::probe(false),
        daemon_killed: daemon_death.map(|record| DaemonKilledPayload {
            summary: record.summary(),
            exit_code: EXIT_ENRICHMENT_UNATTESTED,
        }),
        graph_section_materialization,
    };
    emit(&format!("{}\n", serde_json::to_string_pretty(&payload)?))
}

fn uncommitted_worktree_payload(
    divergence: &kin_git::GitWorkspaceDivergenceFacts,
) -> Option<UncommittedWorktreePayload> {
    if divergence.is_empty() {
        return None;
    }
    let paths = divergence
        .entries
        .iter()
        .take(SERIALIZED_PATHS)
        .map(|entry| UncommittedPathPayload {
            path: entry.path.to_string(),
            state: entry.kind.label(),
        })
        .collect::<Vec<_>>();
    Some(UncommittedWorktreePayload {
        observed_paths: divergence.observed_paths(),
        unlisted_paths: divergence.observed_paths() - paths.len(),
        paths,
    })
}

fn print_human_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: &SemanticEnrichmentStatus,
    cross_file: &CrossFileEnrichment,
    graph_section_materialization: &InitGraphSectionMaterialization,
    model_before: &crate::embed_model::EmbedModelFetch,
    daemon_death: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> Result<()> {
    emit(&render_human_result(
        result,
        boundary,
        semantic_enrichment,
        cross_file,
        graph_section_materialization,
        model_before,
        daemon_death,
    )?)
}

/// Hand a finished result to stdout, tolerating a reader that already left.
///
/// The store is durable before a single byte of this is written, so a consumer
/// that closed its pipe must not turn a completed admission into a failure.
/// `println!` panics on a write error, which is exactly what `kin init | head`
/// did. Every write error that is not a departed reader is still reported.
fn emit(rendered: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error).context("write the kin init result to stdout"),
    }
}

/// The whole human result as one string, so it reaches stdout in one write.
fn render_human_result(
    result: &kin_core::InitResult,
    boundary: InitBoundary,
    semantic_enrichment: &SemanticEnrichmentStatus,
    cross_file: &CrossFileEnrichment,
    graph_section_materialization: &InitGraphSectionMaterialization,
    model_before: &crate::embed_model::EmbedModelFetch,
    daemon_death: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> Result<String> {
    let default_ref = initialized_default_ref(result);
    let mut out = String::new();
    writeln!(
        out,
        "Initialized Kin repository authority at {}",
        result.layout.root().display()
    )?;
    writeln!(out, "  Authority: repository-v6 (graph-owned)")?;
    writeln!(out, "  Repository: {}", result.repository_id)?;
    writeln!(out, "  Workspace: {}", result.workspace_id)?;
    match default_ref {
        Some(default_ref) => writeln!(out, "  Default ref: {default_ref}")?,
        None => writeln!(out, "  Default ref: none (detached workspace)")?,
    }
    writeln!(
        out,
        "  Authority generation: {}",
        result.authority.receipt.generation
    )?;
    writeln!(
        out,
        "  Workspace generation: {}",
        result.authority.workspace.workspace_generation
    )?;
    writeln!(
        out,
        "  Workspace head: {}",
        serde_json::to_string(&result.authority.workspace.workspace_head)?
    )?;
    writeln!(
        out,
        "  Graph reopen: {}",
        graph_section_materialization.human_line()
    )?;
    match boundary {
        InitBoundary::ExactGit => {
            writeln!(
                out,
                "  Imported: exact reachable Git history, refs, raw objects, workspace, and admission policy"
            )?;
        }
        InitBoundary::NativeUnborn => {
            writeln!(out, "  History: unborn (no synthetic commit)")?;
            writeln!(out, "  Workspace: empty exact tree")?;
        }
    }
    // The reading that explains a fetch that did not happen, selected by the
    // work it is about. `read_all(...).last()` was the newest refusal of ANY
    // heavy work, so on a pressured host whose last refusal was the LSP sweep
    // this line explained a missing model download with a cause about something
    // else. Read here rather than remembered, for the same reason the daemon
    // death beside it is: the refusal is written by a daemon during the
    // enrichment phase and leaves nothing in this process.
    let embed_refusal = embed_refusal_for(result.layout.root());
    let guidance = ordered_init_guidance_lines(
        format!(
            "  Semantic enrichment: {}",
            render_semantic_enrichment(semantic_enrichment, daemon_death, cross_file)
        ),
        enrichment_kill_warning(daemon_death),
        cross_file_pending_notice(semantic_enrichment, cross_file),
        semantic_absence_notice(semantic_enrichment),
        format!(
            "  {}",
            embedding_model_notice(
                &crate::embed_model::EmbedModelFetch::probe(false),
                model_before,
                embed_refusal.as_ref(),
            )
        ),
    );
    for line in guidance {
        writeln!(out, "{line}")?;
    }
    writeln!(
        out,
        "  Store size: {}",
        StoreFootprint::measure(&result.layout).render()
    )?;
    writeln!(out, "  {}", store_size_notice())?;
    for line in uncommitted_worktree_disclosure(&result.workspace_divergence) {
        writeln!(out, "{line}")?;
    }
    Ok(out)
}

/// Keep language-server and cross-file guidance before the embedding notice.
///
/// The inputs are already-rendered lines so the ordering contract is pure and
/// can be tested without probing a host or mutating an environment. `kin init`
/// measured LSP enrichment as the material contributor on the reported stores;
/// embedding advice must not lead the section while that guidance follows it.
fn ordered_init_guidance_lines(
    semantic_enrichment: String,
    enrichment_kill: Option<String>,
    cross_file_pending: Option<String>,
    semantic_absence: Option<String>,
    embedding_model: String,
) -> Vec<String> {
    let mut lines = vec![semantic_enrichment];
    lines.extend(enrichment_kill);
    lines.extend(cross_file_pending);
    lines.extend(semantic_absence);
    lines.push(embedding_model);
    lines
}

/// What this command owes a reader about the embedding model.
///
/// No install ships the weights, so a converted repository that has never
/// embedded is one large download away from its first vector, and admission
/// finishes long before that download starts.
///
/// Who pays for it is the part this line used to get wrong. It said "the first
/// embed pass fetches", which reads as a later command's cost, and the stranger
/// pass on shipped 0.5.45 measured otherwise: 2.576s to init an empty
/// repository against 67.1s to init a one-file TypeScript one, the difference
/// being the fetch (FIR-2555). The enrichment phase at `enrich_after_init`
/// starts a daemon, that daemon's background embed worker starts as soon as its
/// first reconcile lands (`kin-daemon/src/daemon.rs`, "embedding worker
/// started"), and it queues everything the index is missing unless an operator
/// opted out. So on a repository with parseable content the download is work
/// `kin init` does, during `kin init`, and this notice prints after it rather
/// than before. Saying so costs a clause and saves a reader the wrong mental
/// model of when their machine is busy.
/// The refusal that explains a model download this run did not do.
///
/// Selected by the work it is about. The newest refusal of ANY heavy work was
/// what this used to read, so on a pressured host whose last refusal was the
/// LSP sweep the notice explained a missing model download with a cause about
/// something else entirely. `LspSweep` is a live sibling producer, not a
/// hypothetical one.
fn embed_refusal_for(root: &std::path::Path) -> Option<kin_core::memory_pressure::PressureRefusal> {
    kin_core::memory_pressure::PressureRefusal::read_for_work(
        root,
        kin_core::memory_pressure::HeavyWork::EmbedBatch,
    )
}

/// Visible to the crate so `health.rs` can grade its own row against what
/// this function actually says, rather than against a second copy of the
/// sentence. See `doctor_and_init_agree_about_the_model_fetch`.
pub(crate) fn embedding_model_notice(
    fetch: &crate::embed_model::EmbedModelFetch,
    before: &crate::embed_model::EmbedModelFetch,
    refusal: Option<&kin_core::memory_pressure::PressureRefusal>,
) -> String {
    if let Some(reason) = fetch.no_fetch_reason.as_deref() {
        return format!("Embedding model: {} ({reason})", fetch.model_id);
    }
    let location = match fetch.cache_dir.as_deref() {
        Some(dir) => format!(" at {dir}"),
        None => String::new(),
    };
    match (before.present, fetch.present) {
        (true, _) => format!(
            "Embedding model: {} was already cached{location}, so this command downloaded nothing",
            fetch.model_id
        ),
        (false, true) => format!(
            "Embedding model: {} was not on this machine, and this command fetched it{location}",
            fetch.model_id
        ),
        // Bytes this command actually added, with no resolved snapshot at the
        // end: a fetch it started or continued and did not finish. This is the
        // state the five-command walk lands in on a small repository. `kin init`
        // on `expressjs/body-parser` took ten seconds end to end against a fixed
        // 523 MB download, and the summary then said the command "did not fetch
        // it" over a download that was partway through, which reads as nothing
        // having happened.
        //
        // Gated on GROWTH rather than on a non-zero numerator, because those are
        // different facts and only one of them belongs to this run. A machine
        // carrying an interrupted cache from an earlier attempt has bytes in it
        // before this command starts, and attributing them here would credit
        // this run with a download it never made.
        (false, false) if fetch.fetched_bytes > before.fetched_bytes => {
            let because = match refusal {
                Some(refusal) => format!(", because {}", refusal.cause_sentence()),
                None => String::new(),
            };
            format!(
                "Embedding model: {} is not on this machine yet and this command did not finish \
                 fetching it{because}. It fetched {} of {}, so {} is in the cache{}; `kin locate` \
                 ranks on lexical and graph signals until the rest arrives; run `kin embed` to \
                 finish it now",
                fetch.model_id,
                crate::embed_model::render_megabytes(
                    fetch.fetched_bytes.saturating_sub(before.fetched_bytes)
                ),
                fetch.expected_download(),
                fetch.render_progress(),
                match fetch.cache_dir.as_deref() {
                    Some(dir) => format!(" at {dir}"),
                    None => String::new(),
                }
            )
        }
        // Bytes were already here and none were added. The reader still needs to
        // know why their first query ranks on lexical signals, and this run
        // still has to not claim a download it did not make.
        (false, false) if fetch.fetched_bytes > 0 => {
            let because = match refusal {
                Some(refusal) => format!(", because {}", refusal.cause_sentence()),
                None => String::new(),
            };
            format!(
                "Embedding model: {} is not on this machine{because}. {} of an earlier fetch is \
                 in the cache{} and this command added none of it, so `kin locate` ranks on \
                 lexical and graph signals; run `kin embed` to fetch the rest now",
                fetch.model_id,
                fetch.render_progress(),
                match fetch.cache_dir.as_deref() {
                    Some(dir) => format!(" at {dir}"),
                    None => String::new(),
                }
            )
        }
        (false, false) => {
            let because = match refusal {
                Some(refusal) => format!(", because {}", refusal.cause_sentence()),
                None => String::new(),
            };
            format!(
                "Embedding model: {} is not on this machine and this command did not fetch \
                 it{because}. The first embed pass fetches {} from {}{} and needs egress; run \
                 `kin embed` to start it now",
                fetch.model_id,
                fetch.expected_download(),
                crate::embed_model::endpoint_host(),
                match fetch.cache_dir.as_deref() {
                    Some(dir) => format!(" into {dir}"),
                    None => String::new(),
                }
            )
        }
    }
}

/// Paths listed by name before the rest are counted rather than named.
const DISCLOSED_PATHS: usize = 10;

/// What to say about a source that had been worked in before it was admitted.
///
/// Authority is the committed state, so none of this is in the repository this
/// command published, and none of it was lost either: it is still in the
/// worktree, and the daemon admits it as workspace state the same way it admits
/// every later edit. Both halves have to be said. A list with no disposition
/// reads as damage, and a disposition with no list is a claim the operator
/// cannot check.
///
/// Returns the exact lines to print, so absence is one empty vector rather than
/// a branch at the call site.
fn uncommitted_worktree_disclosure(
    divergence: &kin_git::GitWorkspaceDivergenceFacts,
) -> Vec<String> {
    if divergence.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "  Uncommitted worktree state: {} path(s) differ from the committed state that was admitted",
        divergence.observed_paths()
    )];
    for kind in [
        kin_git::GitWorkspaceDivergenceKind::Staged,
        kin_git::GitWorkspaceDivergenceKind::StagedRemoval,
        kin_git::GitWorkspaceDivergenceKind::Modified,
        kin_git::GitWorkspaceDivergenceKind::Missing,
        kin_git::GitWorkspaceDivergenceKind::Untracked,
    ] {
        let paths = divergence
            .of_kind(kind)
            .map(|entry| entry.path.to_string())
            .collect::<Vec<_>>();
        if paths.is_empty() {
            continue;
        }
        // Paths the walk stopped naming are part of the total this line states
        // and are not among the ones it can list, so they count once in each
        // and never in both.
        let observed = paths.len()
            + if kind == kin_git::GitWorkspaceDivergenceKind::Untracked {
                divergence.untracked_beyond_cap
            } else {
                0
            };
        let mut rendered = paths
            .iter()
            .take(DISCLOSED_PATHS)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        let unlisted = observed - paths.len().min(DISCLOSED_PATHS);
        if unlisted > 0 {
            rendered.push_str(&format!(", and {unlisted} more"));
        }
        lines.push(format!("    {} ({observed}): {rendered}", kind.label()));
    }
    lines.push(
        "  None of it entered repository authority, and none of it was touched. It becomes \
         workspace state the first time the daemon runs here."
            .to_string(),
    );
    lines
}

/// What to say when initialization produced no semantic entities at all.
///
/// Absence here was previously reported as a number and nothing else, and a
/// repository whose languages Kin does not parse then answers every later query
/// with an empty list — byte-identical to a query that legitimately found
/// nothing. The two call for opposite next actions and the operator had no way
/// to tell them apart, on any surface, in any output.
///
/// The wording is deliberately CONDITIONAL rather than diagnostic. This function
/// knows that zero entities were extracted; it does NOT know whether that is
/// because no admitted file had an adapter or because something went wrong for a
/// language Kin does support, and asserting the first would be a confident guess
/// dressed as a finding. Naming the possibility and handing over the command
/// that settles it costs one line and cannot be wrong.
fn semantic_absence_notice(enrichment: &SemanticEnrichmentStatus) -> Option<String> {
    if !matches!(enrichment.presence, SemanticEnrichmentPresence::Absent) {
        return None;
    }
    Some(
        "  No semantic entities were extracted. If this repository's languages are not \
         ones Kin parses, that is expected, and `kin languages` lists the ones it does; \
         content and history are still under repository authority either way."
            .to_string(),
    )
}

/// The enrichment line, and the one word in it that used to hide a kill.
///
/// "Completion not attested" is a true statement about every store, which is
/// exactly the problem FIR-2650 names. On the measured run the daemon had been
/// OOM-killed inside its enrichment commit, and the summary carried that as a
/// parenthetical inside a success line: same counts, same presence, same
/// caveat, indistinguishable from a store whose enrichment simply has not been
/// certified yet. A reader saw exit 0, a 1.1 GB store, and no signal at all.
///
/// The counts stay, because they are still true. What changes is that when the
/// store can prove one of its daemons was killed, the caveat says so, and
/// [`enrichment_kill_warning`] carries the cause and the remedy on a line of
/// its own rather than in a parenthesis.
fn render_semantic_enrichment(
    enrichment: &SemanticEnrichmentStatus,
    death: Option<&kin_daemon_spawn::DaemonKillRecord>,
    cross_file: &CrossFileEnrichment,
) -> String {
    // "partial" and not "present", on a run that built the within-file half of
    // the graph and not the cross-file half. The counts under the word are
    // unchanged and still exact; only the word moves, because the word is the
    // part that was claiming a graph this run did not build.
    //
    // `absent` is left alone. A store with no entity and no relation is not
    // partially enriched, and downgrading a word that is already the weakest
    // one would say less than the truth rather than more.
    let presence = match (&enrichment.presence, cross_file.pending().is_some()) {
        (SemanticEnrichmentPresence::Absent, _) => "absent",
        (SemanticEnrichmentPresence::Present, true) => "partial",
        (SemanticEnrichmentPresence::Present, false) => "present",
    };
    format!(
        "{presence} ({} entities, {} relations, {} changes in durable authority generation {}; {})",
        enrichment.entity_count,
        enrichment.relation_count,
        enrichment.semantic_change_count,
        enrichment.authority_generation,
        crate::daemon_death::enrichment_clause(death)
    )
}

/// What the word "partial" is short for, on the line beneath it.
///
/// Beneath rather than inside, matching every other qualifier on this summary,
/// and because the sentence names a next action and the counts line does not.
/// It is emitted only when the counts line actually said `partial`, so the two
/// can never disagree: an `absent` store keeps its own notice and gets no
/// second one, and a run that produced cross-file edges prints nothing here at
/// all. A line that appeared after every conversion would be read once and
/// skipped forever.
fn cross_file_pending_notice(
    enrichment: &SemanticEnrichmentStatus,
    cross_file: &CrossFileEnrichment,
) -> Option<String> {
    if matches!(enrichment.presence, SemanticEnrichmentPresence::Absent) {
        return None;
    }
    Some(format!("  ⚠ {}", cross_file.pending()?))
}

/// The warning line a store whose daemon was killed carries beneath its
/// enrichment counts.
///
/// A warning rather than a parenthetical, and beneath the counts rather than
/// inside them, because the counts describe what was derived and this describes
/// whether anything more was coming. It quotes the record's own summary so this
/// surface says what `kin graph status` and `kin doctor` say about the same
/// store, word for word.
fn enrichment_kill_warning(death: Option<&kin_daemon_spawn::DaemonKillRecord>) -> Option<String> {
    Some(format!("  ⚠ {}", death?.summary()))
}

fn initialized_default_ref(result: &kin_core::InitResult) -> Option<&kin_model::RefName> {
    result
        .authority
        .receipt
        .operation
        .default_ref_mutation
        .as_ref()
        .and_then(|mutation| mutation.new_default.as_ref())
}

fn initialized_raw_git_head(result: &kin_core::InitResult) -> Option<&kin_model::GitRawTarget> {
    result
        .authority
        .receipt
        .operation
        .git_authority_delta
        .as_ref()
        .and_then(|delta| delta.new.as_ref())
        .map(|authority| &authority.raw_head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::status::SemanticEnrichmentView;

    /// A queue nobody is draining is not work in flight.
    ///
    /// Both stalled arms mirror the daemon's own reasons for standing its
    /// worker down. Without them a conversion on such a store would sit here
    /// for the whole budget and then hand over exactly the store it would have
    /// handed over immediately.
    #[test]
    fn a_backlog_nothing_will_drain_is_not_a_pass_worth_waiting_for() {
        let filling = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 12,
            embeddings_pending: 80,
            embeddings_total: 92,
            ..Default::default()
        };
        assert_eq!(
            first_embed_pass_standing(&filling),
            FirstEmbedPassStanding::Filling,
            "a queue with a healthy worker behind it is the state the stop must not cut short"
        );

        let failed = crate::commands::resources::EmbedRuntimeState {
            embed_worker_failed: true,
            ..filling.clone()
        };
        assert!(matches!(
            first_embed_pass_standing(&failed),
            FirstEmbedPassStanding::Stalled(_)
        ));

        let unpersistable = crate::commands::resources::EmbedRuntimeState {
            embed_persistence_unavailable: true,
            ..filling.clone()
        };
        assert!(matches!(
            first_embed_pass_standing(&unpersistable),
            FirstEmbedPassStanding::Stalled(_)
        ));

        let drained = crate::commands::resources::EmbedRuntimeState {
            embeddings_indexed: 92,
            embeddings_pending: 0,
            embeddings_total: 92,
            ..Default::default()
        };
        assert_eq!(
            first_embed_pass_standing(&drained),
            FirstEmbedPassStanding::Settled
        );
    }

    /// The wait actually waits.
    ///
    /// This is the property the whole change exists for: before it, the
    /// conversion stopped the daemon the moment the sweep phase ended, and the
    /// embedding pass that daemon had queued died with it. A reader that
    /// reports work filling has to hold this function until the work is not.
    #[tokio::test(start_paused = true)]
    async fn the_wait_holds_while_the_pass_is_filling_and_returns_when_it_drains() {
        let readings = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let counter = std::sync::Arc::clone(&readings);
        let outcome = settle_first_embed_pass_within(
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(20),
            move || {
                let counter = std::sync::Arc::clone(&counter);
                async move {
                    let mut seen = counter.lock().unwrap();
                    *seen += 1;
                    Some(if *seen < 4 {
                        crate::commands::resources::EmbedRuntimeState {
                            embeddings_indexed: *seen * 10,
                            embeddings_pending: 40 - *seen * 10,
                            embeddings_total: 40,
                            ..Default::default()
                        }
                    } else {
                        crate::commands::resources::EmbedRuntimeState {
                            embeddings_indexed: 40,
                            embeddings_pending: 0,
                            embeddings_total: 40,
                            ..Default::default()
                        }
                    })
                }
            },
        )
        .await;
        assert_eq!(outcome, FirstEmbedPassOutcome::Drained { indexed: 40 });
        assert!(
            *readings.lock().unwrap() >= 4,
            "a wait that returned on its first reading did not wait for anything"
        );
    }

    /// And it stops waiting.
    ///
    /// The other half of the same contract. A conversion that never returns is
    /// worse than one that hands over a store still filling, so a pass that
    /// never drains has to end this wait at the budget and say where it got to.
    #[tokio::test(start_paused = true)]
    async fn a_pass_that_never_drains_ends_at_the_budget_and_says_where_it_reached() {
        // The elapsed clock is read as well as the outcome, and it is the half
        // that matters. A `BudgetSpent` carrying the right counts proves
        // nothing on its own: a loop that returned on its first reading would
        // report exactly the same value while having waited for nothing at all.
        let began = tokio::time::Instant::now();
        let outcome = settle_first_embed_pass_within(
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(2),
            // A stall window longer than the budget, so the budget is what this
            // arm actually proves. Without that this test would pass on the
            // stall guard and say nothing about the budget at all.
            std::time::Duration::from_secs(3_600),
            || async {
                Some(crate::commands::resources::EmbedRuntimeState {
                    embeddings_indexed: 7,
                    embeddings_pending: 33,
                    embeddings_total: 40,
                    embedding_work_busy: true,
                    ..Default::default()
                })
            },
        )
        .await;
        assert_eq!(
            outcome,
            FirstEmbedPassOutcome::BudgetSpent {
                indexed: 7,
                total: 40,
                waited_secs: 300,
            }
        );
        assert!(
            began.elapsed() >= std::time::Duration::from_secs(300),
            "the wait has to actually reach its budget, not merely name it: {:?}",
            began.elapsed()
        );
        let note = outcome.note().expect("a partial pass is worth a line");
        assert!(
            note.contains("7 of 40") && note.contains("resumes it from here"),
            "the reader has to learn where it reached and that nothing is lost: {note}"
        );
    }

    /// A queue that nothing is draining stops being waited on, even when every
    /// field this wait can read says it is filling.
    ///
    /// `KIN_DAEMON_AUTO_EMBED=0` pauses the daemon's worker and
    /// `EmbedRuntimeState` carries no flag for that pause, so an opt-out host
    /// reports a non-empty queue, a healthy worker and persistable progress
    /// forever. Answering that with the budget would put two minutes into every
    /// `kin init` on such a host. Progress, not a flag, is what separates them.
    #[tokio::test(start_paused = true)]
    async fn a_queue_that_never_moves_stops_being_waited_on_before_the_budget() {
        let outcome = settle_first_embed_pass_within(
            std::time::Duration::from_secs(300),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(20),
            || async {
                Some(crate::commands::resources::EmbedRuntimeState {
                    embeddings_indexed: 0,
                    embeddings_pending: 40,
                    embeddings_total: 40,
                    embedding_work_busy: false,
                    ..Default::default()
                })
            },
        )
        .await;
        match outcome {
            FirstEmbedPassOutcome::Stalled { pending, .. } => assert_eq!(pending, 40),
            other => panic!("a queue nothing moves is not a pass worth waiting for: {other:?}"),
        }
    }

    /// The control for the arm above: the same shape with the model still
    /// arriving is a pass, and must NOT be cut off.
    ///
    /// Without this, a stall guard that fired on any zero-progress reading
    /// would look correct and would abandon every first `kin init` on a machine
    /// that has to download the 522 MiB model before it can index anything.
    #[tokio::test(start_paused = true)]
    async fn a_queue_waiting_on_the_model_download_is_still_a_pass() {
        let outcome = settle_first_embed_pass_within(
            std::time::Duration::from_secs(120),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(20),
            || async {
                Some(crate::commands::resources::EmbedRuntimeState {
                    embeddings_indexed: 0,
                    embeddings_pending: 40,
                    embeddings_total: 40,
                    embedding_work_busy: false,
                    model_fetch: crate::embed_model::EmbedModelFetch {
                        fetching: true,
                        fetched_bytes: 1,
                        ..Default::default()
                    },
                    ..Default::default()
                })
            },
        )
        .await;
        assert!(
            matches!(outcome, FirstEmbedPassOutcome::BudgetSpent { .. }),
            "a download in progress is progress; this wait must run to its budget, not stall: \
             {outcome:?}"
        );
    }

    /// No daemon, no wait, and no failure.
    ///
    /// The real wiring, against a real layout with nothing serving it. A probe
    /// must never be able to turn a conversion that already succeeded into a
    /// hang or an error.
    #[tokio::test]
    async fn the_wait_returns_at_once_when_no_daemon_is_serving_the_store() {
        let repo = tempfile::tempdir().expect("temp repo");
        let layout = kin_core::init(repo.path()).expect("init").layout;
        let began = std::time::Instant::now();
        let outcome = settle_first_embed_pass(&layout).await;
        assert_eq!(outcome, FirstEmbedPassOutcome::Unread);
        assert!(
            began.elapsed() < std::time::Duration::from_secs(30),
            "a store with no daemon must not be waited on at all"
        );
        assert!(outcome.note().is_none());
    }

    /// Pin the LSP-first output contract so an embedding notice cannot drift
    /// ahead of the materially stronger cross-file guidance.
    #[test]
    fn init_places_semantic_enrichment_guidance_before_embedding_advice() {
        let lines = ordered_init_guidance_lines(
            "  Semantic enrichment: partial".to_string(),
            Some("language-server sweep was killed".to_string()),
            Some("cross-file relations are pending".to_string()),
            Some("no cross-file edge was produced".to_string()),
            "  Embedding model: fetch pending".to_string(),
        );
        assert_eq!(
            lines,
            vec![
                "  Semantic enrichment: partial",
                "language-server sweep was killed",
                "cross-file relations are pending",
                "no cross-file edge was produced",
                "  Embedding model: fetch pending",
            ],
            "every LSP and cross-file line must precede the embedding notice"
        );
    }

    /// `--adopt-repository-id` and no flag at all mean opposite things, so a
    /// blank value must not quietly become the second one.
    ///
    /// An operator reaching for this flag is saying the store has to be a
    /// replica of a repository that already exists. Reading a blank argument
    /// as absent would hand them a store that minted its own identity, which
    /// looks fine until the push, and the push is minutes of staging later.
    #[test]
    fn a_blank_adopted_repository_id_is_refused_rather_than_read_as_absent() {
        assert!(parse_adopted_repository_id(None).unwrap().is_none());
        assert_eq!(
            parse_adopted_repository_id(Some("  kin-db  "))
                .unwrap()
                .map(|id| id.as_str().to_string()),
            Some("kin-db".to_string()),
            "surrounding whitespace is trimmed, not adopted"
        );
        for blank in ["", "   ", "\t"] {
            let error = parse_adopted_repository_id(Some(blank))
                .expect_err("a blank identity is not an absent one");
            assert!(
                error.to_string().contains("empty value"),
                "the refusal must say what was missing: {error}"
            );
        }
    }

    /// What `kin init` actually prints when a run produced no cross-file edges.
    ///
    /// The daemon-side rows are tested where they are decided. These test the
    /// other half, the sentence a user reads, because the defect this replaced
    /// lived in the sentence: the daemon computed the truth, logged the truth
    /// to itself, and handed the reader a fabrication.
    /// Coldwalk finding 6, as its own module.
    ///
    /// Every fixture below is that walk's measurement rather than a shape
    /// invented here: `tokio-rs/axum` on a macOS host carrying rustup and
    /// rust-analyzer, `enriched 5/303 files`, the five JavaScript, and the same
    /// store's next `kin graph status` reading `cross-file reference and
    /// override edges unavailable for rust: no language server found`.
    mod a_sweep_that_skipped_a_language {
        use super::super::{
            cross_file_enrichment_outcome, skipped_languages_from_status, CrossFileEnrichment,
            SkippedLanguage,
        };

        const RUST_REASON: &str = "the `rust-analyzer` language server did not start (No such \
                                   file or directory (os error 2)), so nothing in this language \
                                   was enriched";

        fn coldwalk_status() -> serde_json::Value {
            serde_json::json!({
                "running": false,
                "files_done": 5,
                "files_total": 303,
                "files_blocked": 298,
                "sweeps_completed": 1,
                "enrichment_available": true,
                "languages_skipped": [
                    { "language": "rust", "files": 298, "reason": RUST_REASON }
                ]
            })
        }

        /// The sentence the walk caught, on the input that produced it.
        ///
        /// The ban on "complete" is the assertion rather than a style note. This
        /// is the one place in that whole walkthrough where the product stated a
        /// completion that did not happen, and it happened because `done` was 5
        /// rather than 0, so the only guard on this branch could not fire.
        #[test]
        fn the_word_complete_is_not_used_and_the_gap_is_named() {
            let skipped = skipped_languages_from_status(&coldwalk_status());
            assert_eq!(skipped.len(), 1, "the fixture carries one skipped language");
            let (line, outcome) = cross_file_enrichment_outcome(5, 303, 298, &skipped);

            assert!(
                !line.contains("complete"),
                "a pass that could not serve a language must not report a completion: {line}"
            );
            assert!(
                line.contains("enriched 5 of 303 files"),
                "the line must say what WAS enriched: {line}"
            );
            assert!(
                line.contains("rust"),
                "the line must name the language that was skipped: {line}"
            );
            assert!(
                line.contains("298 files"),
                "the line must say how much was skipped: {line}"
            );
            assert!(
                line.contains("rust-analyzer"),
                "the line must say WHY, from what the daemon observed: {line}"
            );
            match outcome {
                CrossFileEnrichment::Withheld { pending } => assert!(
                    pending.contains("rust"),
                    "the withheld reason must name the language still owed: {pending}"
                ),
                CrossFileEnrichment::Produced => {
                    panic!("a sweep that skipped a whole language did not produce that language")
                }
            }
        }

        /// The control, and it is half of the test above.
        ///
        /// A ban on one word is satisfied by never saying anything, so the same
        /// function on a sweep that skipped nothing must still reach the
        /// completion line and `Produced`. Without this, deleting the word
        /// everywhere would pass.
        #[test]
        fn a_sweep_that_skipped_nothing_still_reports_a_completion() {
            let status = serde_json::json!({
                "files_done": 303,
                "files_total": 303,
                "files_blocked": 0,
                "languages_skipped": []
            });
            let skipped = skipped_languages_from_status(&status);
            assert!(skipped.is_empty(), "no rows means nothing was skipped");

            let (line, outcome) = cross_file_enrichment_outcome(303, 303, 0, &skipped);
            assert!(
                line.contains("cross-file enrichment complete (303/303 files)"),
                "a sweep that served every language it met still completes: {line}"
            );
            assert_eq!(outcome, CrossFileEnrichment::Produced);
        }

        /// A daemon too old to send the field reads as nothing skipped, never as
        /// an empty list dressed up as knowledge.
        #[test]
        fn a_status_without_the_field_reports_no_skipped_language() {
            let status = serde_json::json!({ "files_done": 5, "files_total": 303 });
            assert!(skipped_languages_from_status(&status).is_empty());
        }

        /// A row missing its reason is dropped rather than defaulted, because a
        /// skip nothing explains sends its reader hunting a cause the daemon
        /// never observed.
        #[test]
        fn a_row_missing_a_half_is_dropped_rather_than_defaulted() {
            let status = serde_json::json!({
                "languages_skipped": [
                    { "language": "rust", "files": 298 },
                    { "files": 12, "reason": "no language was named" },
                    { "language": "python", "files": 12, "reason": "pyright did not start" }
                ]
            });
            assert_eq!(
                skipped_languages_from_status(&status),
                vec![SkippedLanguage {
                    language: "python".to_string(),
                    files: 12,
                    reason: "pyright did not start".to_string(),
                }]
            );
        }

        /// The zero-file case keeps its own sentence, which predates this and is
        /// a different claim: nothing at all moved, rather than one language
        /// moving while another could not.
        #[test]
        fn the_zero_file_case_keeps_its_own_sentence() {
            let (line, outcome) = cross_file_enrichment_outcome(0, 66, 66, &[]);
            assert!(
                line.contains("without enriching any of the 66 files"),
                "{line}"
            );
            assert!(!line.contains("complete"), "{line}");
            assert!(matches!(outcome, CrossFileEnrichment::Withheld { .. }));
        }

        /// The sentence accounts for every file the daemon says was blocked.
        ///
        /// Measured, at the sha this test lands on, on three rust, three
        /// typescript and two ruby files with both language servers reachable:
        /// `files_total` 8, `files_done` 3, `files_blocked` 5, and one skip row
        /// naming rust with three files. The sentence's own figures added to six
        /// of eight and the two ruby files were named by nothing, which is the
        /// overclaim this whole function exists to close, surviving on an input
        /// the row list cannot describe.
        #[test]
        fn every_blocked_file_is_accounted_for_even_when_no_row_names_it() {
            let skipped = vec![SkippedLanguage {
                language: "rust".to_string(),
                files: 3,
                reason: "the `rust-analyzer` language server did not start".to_string(),
            }];
            let (line, _) = cross_file_enrichment_outcome(3, 8, 5, &skipped);

            assert!(
                line.contains("rust: 3 files not enriched"),
                "the row still names what it can: {line}"
            );
            assert!(
                line.contains("2 further files"),
                "the five blocked files minus the three the row names leaves two the \
                 sentence must still account for: {line}"
            );
            assert!(
                line.contains("did not attribute to a language"),
                "the remainder says what it is rather than appearing as a gap in the \
                 arithmetic: {line}"
            );
        }

        /// One blocked file reads `1 further file`, never `1 further files`.
        #[test]
        fn the_remainder_counts_one_file_in_the_singular() {
            let skipped = vec![SkippedLanguage {
                language: "rust".to_string(),
                files: 3,
                reason: "the `rust-analyzer` language server did not start".to_string(),
            }];
            let (line, _) = cross_file_enrichment_outcome(4, 8, 4, &skipped);
            assert!(line.contains("1 further file "), "{line}");
            assert!(!line.contains("1 further files"), "{line}");
        }

        /// A pass with blocked files and no row to name them is not complete.
        ///
        /// `cross_file_enrichment_outcome(6, 8, 2, &[])` is the ruby fixture
        /// above with both servers reachable, and it printed
        /// `cross-file enrichment complete (6/8 files)` on a real `kin init` at
        /// the parent commit. The function took `blocked` and used it only in
        /// the zero-file arm, so the argument that catches this was already in
        /// the signature.
        ///
        /// The verdict stays `Produced` on purpose: every language this build
        /// serves was served, and promising that `kin daemon sweep` would repair
        /// a file whose extension no server here handles is the fabricated-cause
        /// defect pointing the other way. What is fixed is the sentence.
        #[test]
        fn blocked_files_with_no_row_still_end_the_word_complete() {
            let (line, outcome) = cross_file_enrichment_outcome(6, 8, 2, &[]);
            assert!(
                !line.contains("complete"),
                "a pass that blocked two of eight files did not complete: {line}"
            );
            assert!(
                line.contains("covered 6 of 8 files"),
                "the line still says what it did cover: {line}"
            );
            assert!(
                line.contains("2 files blocked"),
                "and it accounts for the rest: {line}"
            );
            assert!(
                !line.contains("further"),
                "there is no row above for these to be further than: {line}"
            );
            assert_eq!(outcome, CrossFileEnrichment::Produced);
        }

        /// With nothing enriched, the language the daemon named is still named.
        ///
        /// This is the coldwalk's own container leg: no language server existed,
        /// `kin init` walked 66 files and enriched none. The arm that loses the
        /// most used to name the least, because it returned before it looked at
        /// the rows, so a user was told a count and a blocked number and never
        /// which language they had lost.
        #[test]
        fn the_zero_file_case_names_the_language_when_the_daemon_named_one() {
            let skipped = vec![SkippedLanguage {
                language: "rust".to_string(),
                files: 60,
                reason: "the `rust-analyzer` language server did not start".to_string(),
            }];
            let (line, outcome) = cross_file_enrichment_outcome(0, 66, 66, &skipped);

            assert!(!line.contains("complete"), "{line}");
            assert!(
                line.contains("rust: 60 files not enriched"),
                "the language, its file count and its reason: {line}"
            );
            assert!(
                line.contains("6 further files"),
                "and the blocked files no row names: {line}"
            );
            match outcome {
                CrossFileEnrichment::Withheld { pending } => assert!(
                    pending.contains("rust"),
                    "the withheld reason must name the language still owed: {pending}"
                ),
                CrossFileEnrichment::Produced => {
                    panic!("a sweep that enriched nothing did not produce cross-file edges")
                }
            }
        }
    }

    mod enrichment_unavailable_notes {
        use super::super::enrichment_unavailable_note;

        /// The claim the old note made unconditionally, and the one claim no
        /// row may make.
        ///
        /// Not because absence is unmentionable: the absent row below says
        /// plainly that this daemon found no server. It is that "is installed"
        /// speaks for the host, and nothing in this process ever read the host.
        /// Discovery and the readiness probe each ran once, on this process's
        /// PATH, at this process's start, and the ticket's own machine is what
        /// the difference costs: a server sat at /opt/homebrew/bin while the
        /// daemon that started before it reported none.
        const FABRICATION: &str = "no language server is installed";

        /// Every row the daemon can send, so the rule below is checked against
        /// all of them rather than the ones a reader thought of.
        fn every_row() -> Vec<(&'static str, Option<&'static str>)> {
            vec![
                (
                    "no_language_server",
                    Some(
                        "this daemon found no language server for any language it enriches, and \
                         it looks only at startup",
                    ),
                ),
                (
                    "discovery_found_none",
                    Some(
                        "this daemon found no language server when it started, and it looks only \
                         at startup; the check of what this host can run has not finished",
                    ),
                ),
                (
                    "discovery_stale",
                    Some(
                        "a language server is usable now, but this daemon found none when it \
                         started and it looks only at startup",
                    ),
                ),
                (
                    "language_server_unusable",
                    Some(
                        "a language server is installed but did not start (javascript: Could not \
                         find a valid TypeScript installation), so it enriches nothing until \
                         that is repaired",
                    ),
                ),
                (
                    "enrichment_disabled",
                    Some(
                        "cross-file reference enrichment is switched off for this daemon, so no \
                         language server was consulted",
                    ),
                ),
                ("something_this_cli_predates", None),
            ]
        }

        #[test]
        fn no_row_tells_a_user_that_no_language_server_is_installed() {
            for (reason, detail) in every_row() {
                let note = enrichment_unavailable_note(reason, detail);
                assert!(
                    !note.contains(FABRICATION),
                    "row `{reason}` asserts a fact about the host that no daemon reads. Report \
                     what this daemon found, at its own start, and let the reader decide which \
                     repair applies: {note}"
                );
            }
        }

        #[test]
        fn a_host_with_no_server_still_says_so_and_still_offers_the_install() {
            let note = enrichment_unavailable_note(
                "no_language_server",
                Some(
                    "this daemon found no language server for any language it enriches, and it \
                     looks only at startup",
                ),
            );
            assert!(
                note.contains("found no language server"),
                "the row the old note was right about must keep reporting the absence: {note}"
            );
            assert!(
                note.contains("kin doctor --fix --install-language-servers"),
                "and must keep offering the command that closes it: {note}"
            );
        }

        #[test]
        fn a_stale_discovery_names_a_restart_and_never_an_absent_install() {
            let note = enrichment_unavailable_note(
                "discovery_stale",
                Some(
                    "a language server is usable now, but this daemon found none when it \
                     started and it looks only at startup",
                ),
            );
            assert!(
                !note.contains(FABRICATION),
                "a host with a usable server must never be told it has none: {note}"
            );
            assert!(
                note.contains("kin daemon stop"),
                "the repair for a stale discovery is a restart: {note}"
            );
            assert!(
                !note.contains("--install-language-servers"),
                "and it is not an install, so that command must not appear: {note}"
            );
        }

        /// Reached by `--storage gcs` or `KIN_DAEMON_DISABLE_LSP`. Telling this
        /// operator to install a server sends them to buy a tool they own for a
        /// job nothing will run.
        #[test]
        fn a_disabled_daemon_prescribes_nothing_about_language_servers() {
            let note = enrichment_unavailable_note(
                "enrichment_disabled",
                Some(
                    "cross-file reference enrichment is switched off for this daemon, so no \
                     language server was consulted",
                ),
            );
            assert!(
                !note.contains(FABRICATION),
                "a switched-off daemon is not a bare host: {note}"
            );
            assert!(
                !note.contains("kin doctor --fix --install-language-servers")
                    && !note.contains("kin daemon stop"),
                "neither an install nor a restart changes a daemon told not to enrich: {note}"
            );
        }

        /// Both rows that end in "this daemon found nothing at startup" name
        /// both repairs, because the daemon cannot tell a bare host from one
        /// that gained a server after it started, and naming one repair would
        /// assert exactly the state it cannot see. This is the row the ticket's
        /// own host lands on.
        #[test]
        fn a_startup_miss_offers_both_repairs_and_asserts_neither_cause() {
            for reason in ["no_language_server", "discovery_found_none"] {
                let (_, detail) = every_row()
                    .into_iter()
                    .find(|(row, _)| *row == reason)
                    .expect("the row table covers every reason this CLI reads");
                let note = enrichment_unavailable_note(reason, detail);
                assert!(
                    note.contains("kin doctor --fix --install-language-servers")
                        && note.contains("kin daemon stop"),
                    "row `{reason}` must name both repairs: {note}"
                );
                assert!(
                    note.contains("if this host has none"),
                    "row `{reason}` must offer the install on a condition rather than assert \
                     it: {note}"
                );
            }
        }

        #[test]
        fn an_installed_server_that_cannot_start_asks_for_a_repair() {
            let note = enrichment_unavailable_note(
                "language_server_unusable",
                Some(
                    "a language server is installed but did not start (javascript: Could not \
                     find a valid TypeScript installation), so it enriches nothing until that \
                     is repaired",
                ),
            );
            assert!(
                !note.contains(FABRICATION),
                "a broken install is not an absent one: {note}"
            );
            assert!(
                note.contains("Could not find a valid TypeScript installation"),
                "the server's own message is the only text that names the repair: {note}"
            );
        }

        /// A daemon older or newer than this CLI is exactly the case where
        /// guessing would put the fabrication back.
        #[test]
        fn an_unrecognised_reason_reports_the_gap_rather_than_guessing() {
            let note = enrichment_unavailable_note("something_this_cli_predates", None);
            assert!(
                !note.contains(FABRICATION),
                "an unreadable cause must not become a missing install: {note}"
            );
            assert!(
                note.contains("did not report why"),
                "it must say the cause did not arrive: {note}"
            );
        }
    }

    fn enrichment(
        presence: SemanticEnrichmentPresence,
        entities: usize,
    ) -> SemanticEnrichmentStatus {
        SemanticEnrichmentStatus {
            view: SemanticEnrichmentView::DurableRepositoryAuthority,
            authority_generation: 1,
            workspace_generation: 1,
            presence,
            entity_count: entities,
            relation_count: 0,
            semantic_change_count: 0,
            completion_attested: false,
        }
    }

    /// What the word over the counts is allowed to claim.
    ///
    /// The measured FIR-2787 run: entities and relations both nonzero, no
    /// cross-file reference edge anywhere in the graph, and a summary reading
    /// "present". Every number under that word was correct. The word was the
    /// claim, and the reader took it, converted a second repository, and found
    /// out on a different surface hours later.
    ///
    /// The produced arm is half of this test and not a formality. A build that
    /// said "partial" whenever the counts were nonzero would pass the withheld
    /// arm and downgrade every healthy conversion Kin has ever done.
    mod cross_file_enrichment_wording {
        use super::super::{
            cross_file_pending_notice, render_semantic_enrichment, CrossFileEnrichment,
        };
        use super::enrichment;
        use crate::commands::status::SemanticEnrichmentPresence;

        fn withheld() -> CrossFileEnrichment {
            CrossFileEnrichment::Withheld {
                pending: "no language-server sweep ran for this repository".to_string(),
            }
        }

        #[test]
        fn a_run_that_built_no_cross_file_graph_says_partial_and_names_what_is_pending() {
            let status = enrichment(SemanticEnrichmentPresence::Present, 1058);
            let line = render_semantic_enrichment(&status, None, &withheld());
            assert!(
                line.starts_with("partial"),
                "a run that produced no cross-file edge has not produced a present graph: {line}"
            );
            assert!(
                !line.contains("present"),
                "the word this replaced must be gone, not merely joined: {line}"
            );
            assert!(
                line.contains("1058 entities"),
                "the counts were never wrong and are still printed: {line}"
            );

            let notice = cross_file_pending_notice(&status, &withheld())
                .expect("a partial graph names what is pending beneath the counts");
            assert!(
                notice.contains("no language-server sweep ran"),
                "the notice carries the phase's own reason, not a guess: {notice}"
            );
        }

        #[test]
        fn a_run_that_produced_cross_file_edges_keeps_present_and_prints_no_second_line() {
            let status = enrichment(SemanticEnrichmentPresence::Present, 1058);
            let line = render_semantic_enrichment(&status, None, &CrossFileEnrichment::Produced);
            assert!(
                line.starts_with("present"),
                "a conversion that swept its files is present, and a build that could not say so \
                 would downgrade every healthy repository: {line}"
            );
            assert!(
                cross_file_pending_notice(&status, &CrossFileEnrichment::Produced).is_none(),
                "and it carries no notice at all"
            );
        }

        /// A store with no entity and no relation is not partially anything.
        ///
        /// It already carries `semantic_absence_notice`, which says more than
        /// this one would and says it about the right absence. Two notices
        /// under one line would each be read as qualifying the other.
        #[test]
        fn an_absent_store_keeps_its_own_word_and_gets_no_second_notice() {
            let status = enrichment(SemanticEnrichmentPresence::Absent, 0);
            let line = render_semantic_enrichment(&status, None, &withheld());
            assert!(line.starts_with("absent"), "{line}");
            assert!(cross_file_pending_notice(&status, &withheld()).is_none());
        }

        /// A sweep nobody could read supports no claim, so it makes none.
        ///
        /// The tempting shape is to treat an unreadable probe as success and
        /// keep the confident word. That is the exact trade this ticket exists
        /// to undo, one layer down.
        #[test]
        fn a_sweep_this_run_could_not_read_is_withheld_rather_than_produced() {
            let unreadable = CrossFileEnrichment::unreadable();
            assert_ne!(unreadable, CrossFileEnrichment::Produced);
            let pending = unreadable
                .pending()
                .expect("an unread sweep is not a produced graph");
            assert!(
                pending.contains("unknown"),
                "and it says it does not know, rather than picking a side: {pending}"
            );
        }
    }

    /// The measured FIR-2650 summary, and the two stores it could not tell
    /// apart.
    ///
    /// `kin init` exited 0 over a 1.1 GB store and summarized the enrichment as
    /// "present (... ; completion not attested)" while the daemon that would
    /// have finished it lay OOM-killed. Every word of that is also true of a
    /// healthy store nobody has certified yet, so the reader had no signal at
    /// all. This surface prints once per repository, which no scripted check can
    /// re-ask, so the rendering is pinned here.
    ///
    /// The quiet arm is not decoration. A build that named a kill
    /// unconditionally would pass the killed arm and alarm every ordinary user.
    #[test]
    fn a_killed_daemon_changes_the_enrichment_summary_and_nothing_else_does() {
        let status = enrichment(SemanticEnrichmentPresence::Present, 1058);

        let quiet = render_semantic_enrichment(&status, None, &CrossFileEnrichment::Produced);
        assert!(
            quiet.contains("completion not attested"),
            "the caveat is true of every store and stays: {quiet}"
        );
        assert!(
            !quiet.contains("killed"),
            "a store that lost no daemon must not report one: {quiet}"
        );
        assert!(
            enrichment_kill_warning(None).is_none(),
            "and it carries no warning line at all"
        );

        let record = kin_daemon_spawn::DaemonKillRecord {
            kills: 1,
            memory_kills: 1,
            first_unix: 1_787_000_000,
            last_unix: 1_787_000_000,
            last_pid: Some(4103),
            last_cause: kin_daemon_spawn::DaemonKillCause::MemoryLimit {
                kernel_oom_kills: 1,
            },
            limit_bytes: Some(12 * 1024 * 1024 * 1024),
            last_rss_bytes: Some(11 * 1024 * 1024 * 1024),
        };
        let killed =
            render_semantic_enrichment(&status, Some(&record), &CrossFileEnrichment::Produced);
        assert!(
            killed.contains("1058 entities"),
            "the counts are still true and still printed: {killed}"
        );
        assert!(
            killed.contains("completion not attested") && killed.contains("killed"),
            "the caveat alone was the defect, so both halves are required: {killed}"
        );

        let warning = enrichment_kill_warning(Some(&record))
            .expect("a store with a kill on record carries the line that explains it");
        assert!(warning.contains("memory limit"), "{warning}");
        assert!(
            warning.contains("12.0 GiB"),
            "a kill named without its figure is not actionable: {warning}"
        );
        assert!(
            warning.contains("To recover:"),
            "and a cause with no remedy is most of the way back to the parenthetical: {warning}"
        );
    }

    /// The sentence and the exit code have to say the same thing about one run.
    ///
    /// The measured defect is the gap between them. On `pallets/flask` inside an
    /// 8 GiB container `kin init` exited 0 after 473 seconds with a summary that
    /// read "completion not attested, and a daemon serving this store was
    /// killed". The prose was already right; the zero was what a scripted setup
    /// or an agent reads, and a zero says done.
    ///
    /// Asserted as an agreement rather than as two facts, because two readings
    /// that are each correct can still jointly guarantee nothing: this walks the
    /// same reading into both surfaces and requires them to match, so a future
    /// change that fixes one and forgets the other goes red here.
    #[test]
    fn the_exit_code_and_the_summary_agree_about_a_killed_daemon() {
        let status = enrichment(SemanticEnrichmentPresence::Present, 1058);
        let record = kin_daemon_spawn::DaemonKillRecord {
            kills: 1,
            memory_kills: 1,
            first_unix: 1_787_000_000,
            last_unix: 1_787_000_000,
            last_pid: Some(4103),
            last_cause: kin_daemon_spawn::DaemonKillCause::MemoryLimit {
                kernel_oom_kills: 1,
            },
            limit_bytes: Some(8 * 1024 * 1024 * 1024),
            last_rss_bytes: Some(7 * 1024 * 1024 * 1024),
        };

        for reading in [None, Some(&record)] {
            let summary =
                render_semantic_enrichment(&status, reading, &CrossFileEnrichment::Produced);
            let names_a_kill = summary.contains("a daemon serving this store was killed");
            let code = exit_code_for(reading, false);
            assert_eq!(
                names_a_kill,
                code != 0,
                "the summary and the exit code disagree about one run: summary said \
                 {names_a_kill}, exit code was {code} ({summary})"
            );
        }

        assert_eq!(
            exit_code_for(None, false),
            0,
            "a conversion that lost no daemon must still exit 0"
        );
        assert_eq!(
            exit_code_for(Some(&record), false),
            EXIT_ENRICHMENT_UNATTESTED,
            "a conversion that lost one must exit the degraded code"
        );
        assert_ne!(
            EXIT_ENRICHMENT_UNATTESTED, 1,
            "exit 1 says the conversion failed and invites a re-run, which at the repository \
             size that causes this is a loop that cannot terminate"
        );
        assert_eq!(
            exit_code_for(None, true),
            EXIT_GRAPH_SECTION_UNMATERIALIZED,
            "a verified repository whose reopen section failed gets its own degraded code"
        );
    }

    /// The non-empty-directory refusal offers "commit the exact files to Git"
    /// as its first remedy. Measured on a fresh ubuntu:24.04 curl install, that
    /// host has no git at all, so the remedy names a command the reader does
    /// not have and the error dead-ends.
    #[test]
    fn the_non_git_refusal_names_git_as_a_prerequisite_only_when_it_is_absent() {
        assert_eq!(
            git_prerequisite_note(true),
            "",
            "a host that has git needs no extra instruction"
        );

        let absent = git_prerequisite_note(false);
        assert!(
            absent.contains("not installed") && absent.contains("git"),
            "a host without git must be told before being sent to a git commit: {absent}"
        );
    }

    /// The store wall and this refusal are read in sequence by one reader, so
    /// they have to name one remedy between them.
    ///
    /// They did not. The wall sent the reader to `kin init` in a fresh checkout,
    /// and `kin init` answered that a repository already exists and that it
    /// never rebuilds graph authority, which reads as a flat contradiction and
    /// leaves no next move.
    #[test]
    fn the_store_wall_and_the_existing_repository_refusal_name_one_remedy() {
        let wall = crate::commands::incompatible_store_refusal(
            std::path::Path::new("/repo/.kin"),
            &kin_core::KinError::IncompatibleVersion {
                found: 1,
                supported: 2,
            },
        );
        let refusal = existing_repository_refusal(std::path::Path::new("/repo"));

        assert!(
            wall.contains(crate::commands::REBUILD_INCOMPATIBLE_STORE),
            "the store wall must name the shared remedy: {wall}"
        );
        assert!(
            refusal.contains(crate::commands::REBUILD_INCOMPATIBLE_STORE),
            "the existing-repository refusal must name the same remedy: {refusal}"
        );
        assert!(
            wall.contains("found v1, this binary requires v2"),
            "the wall must lead with the version gap it is about: {wall}"
        );
        assert!(
            !wall.contains("fresh checkout") && !refusal.contains("fresh checkout"),
            "neither text may send the reader to a checkout they do not have"
        );
    }

    /// A repository Kin could not extract anything from must SAY so and name the
    /// command that explains why. Silence here is what made "no parser for my
    /// language" indistinguishable from "my search was bad".
    #[test]
    fn an_empty_semantic_layer_points_at_the_supported_languages() {
        let notice = semantic_absence_notice(&enrichment(SemanticEnrichmentPresence::Absent, 0))
            .expect("absence must be explained, not merely counted");
        assert!(
            notice.contains("kin languages"),
            "the notice must hand over the command that settles it: {notice}"
        );
        // The claim must stay conditional. Asserting the cause outright would be
        // a guess: this code knows the count, not the reason.
        assert!(
            notice.contains("If this repository's languages are not"),
            "the notice must not assert a cause it cannot know: {notice}"
        );
    }

    /// The falsification: a repository that DID get semantics must print
    /// nothing extra, or the notice is noise on every successful init rather
    /// than a signal on the failing ones.
    #[test]
    fn a_repository_with_semantics_gets_no_notice() {
        assert!(
            semantic_absence_notice(&enrichment(SemanticEnrichmentPresence::Present, 19_405))
                .is_none()
        );
    }

    fn divergence(
        entries: Vec<(&str, kin_git::GitWorkspaceDivergenceKind)>,
        beyond_cap: usize,
    ) -> kin_git::GitWorkspaceDivergenceFacts {
        let mut facts = kin_git::GitWorkspaceDivergenceFacts::none();
        facts.entries = entries
            .into_iter()
            .map(|(path, kind)| kin_git::GitWorkspaceDivergence {
                path: kin_model::RepoPath::from_bytes(path.as_bytes().to_vec())
                    .expect("test repo path"),
                kind,
                detail: String::new(),
                observed: None,
            })
            .collect();
        facts.untracked_beyond_cap = beyond_cap;
        facts
    }

    /// The disclosure names the paths and says where they went.
    ///
    /// A list with no disposition reads as damage, so the sentence about what
    /// happens to the delta is asserted alongside the paths themselves.
    #[test]
    fn the_uncommitted_disclosure_names_paths_and_their_disposition() {
        let lines = uncommitted_worktree_disclosure(&divergence(
            vec![
                ("src/main.rs", kin_git::GitWorkspaceDivergenceKind::Modified),
                ("notes.txt", kin_git::GitWorkspaceDivergenceKind::Untracked),
                ("staged.rs", kin_git::GitWorkspaceDivergenceKind::Staged),
            ],
            0,
        ))
        .join("\n");

        assert!(lines.contains("3 path(s) differ"), "{lines}");
        assert!(lines.contains("staged (1): staged.rs"), "{lines}");
        assert!(lines.contains("modified (1): src/main.rs"), "{lines}");
        assert!(lines.contains("untracked (1): notes.txt"), "{lines}");
        assert!(
            lines.contains("None of it entered repository authority"),
            "{lines}"
        );
        assert!(lines.contains("the first time the daemon runs"), "{lines}");
    }

    /// A long list is capped and the rest counted, including what the walk
    /// stopped naming, so the total the header states is never contradicted by
    /// the lines beneath it.
    #[test]
    fn the_uncommitted_disclosure_counts_what_it_does_not_list() {
        let entries = (0..12)
            .map(|index| (index, kin_git::GitWorkspaceDivergenceKind::Untracked))
            .collect::<Vec<_>>();
        let named = entries
            .iter()
            .map(|(index, kind)| (format!("untracked-{index:02}.log"), *kind))
            .collect::<Vec<_>>();
        let lines = uncommitted_worktree_disclosure(&divergence(
            named
                .iter()
                .map(|(path, kind)| (path.as_str(), *kind))
                .collect(),
            7,
        ))
        .join("\n");

        assert!(lines.contains("19 path(s) differ"), "{lines}");
        assert!(lines.contains("untracked (19)"), "{lines}");
        assert!(lines.contains("untracked-00.log"), "{lines}");
        assert!(lines.contains("untracked-09.log"), "{lines}");
        assert!(!lines.contains("untracked-10.log"), "{lines}");
        assert!(lines.contains("and 9 more"), "{lines}");
    }

    /// The machine-readable payload carries a sample and counts the rest.
    ///
    /// A repository whose checkout Git rewrote reports every text file it
    /// holds, so an unbounded array here is tens of thousands of path strings
    /// on a piped stdout. The count stays exact either way, and the two
    /// numbers must always add up to it.
    #[test]
    fn the_uncommitted_payload_bounds_its_path_list_without_losing_the_count() {
        let entries = (0..SERIALIZED_PATHS + 40)
            .map(|index| {
                (
                    format!("src/file-{index:04}.rs"),
                    kin_git::GitWorkspaceDivergenceKind::Modified,
                )
            })
            .collect::<Vec<_>>();
        let payload = uncommitted_worktree_payload(&divergence(
            entries
                .iter()
                .map(|(path, kind)| (path.as_str(), *kind))
                .collect(),
            13,
        ))
        .expect("a divergent source carries a payload");

        assert_eq!(payload.observed_paths, SERIALIZED_PATHS + 53);
        assert_eq!(payload.paths.len(), SERIALIZED_PATHS);
        assert_eq!(payload.unlisted_paths, 53);
        assert_eq!(
            payload.paths.len() + payload.unlisted_paths,
            payload.observed_paths,
            "what is listed plus what is not must be what was observed"
        );
    }

    /// The falsification: a source that matched prints nothing, or the
    /// disclosure is noise on every clean init.
    #[test]
    fn a_source_that_matched_gets_no_disclosure() {
        assert!(
            uncommitted_worktree_disclosure(&kin_git::GitWorkspaceDivergenceFacts::none())
                .is_empty()
        );
        assert!(
            uncommitted_worktree_payload(&kin_git::GitWorkspaceDivergenceFacts::none()).is_none()
        );
    }

    fn git(repository: &Path, args: &[&str]) {
        let output = crate::commands::test_subprocess::fixture_git(repository)
            .args(args)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn git_status(repository: &Path) -> String {
        let output = crate::commands::test_subprocess::fixture_git(repository)
            .args(["status", "--porcelain"])
            .output()
            .expect("run fixture git status");
        assert!(output.status.success());
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    fn write_store(working_dir: &Path) {
        let store = working_dir.join(".kin");
        std::fs::create_dir_all(store.join("objects")).unwrap();
        std::fs::write(store.join("objects").join("pack"), b"store bytes").unwrap();
    }

    /// The whole point, asked of Git itself rather than of a string.
    ///
    /// A converted repository leaves a store that is routinely a gigabyte, and
    /// before this the author saw it as untracked on every `git status` they
    /// ever ran again. The assertion is on the porcelain, because a rule that
    /// parses correctly and does not actually exclude the store reads exactly
    /// like one that works.
    #[test]
    fn an_excluded_store_is_absent_from_git_status() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", "-q"]);
        write_store(repo);

        let before = git_status(repo);
        assert!(
            before.contains(".kin"),
            "the fixture must start with a visible store, or this test proves nothing: {before:?}"
        );

        exclude_store_from_git(repo).unwrap().expect("a rule");

        let after = git_status(repo);
        assert!(
            !after.contains(".kin"),
            "the store must be absent from git status: {after:?}"
        );
    }

    /// Re-running init must not stack duplicate rules.
    #[test]
    fn excluding_the_store_twice_writes_one_rule() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git").join("info")).unwrap();

        let exclude = exclude_store_from_git(repo).unwrap().expect("a rule");
        assert!(
            exclude_store_from_git(repo).unwrap().is_none(),
            "the second pass must find the rule already present"
        );

        let body = std::fs::read_to_string(&exclude).unwrap();
        assert_eq!(
            body.lines()
                .filter(|line| line.trim() == STORE_EXCLUDE_RULE)
                .count(),
            1,
            "exactly one rule survives a re-init: {body:?}"
        );
    }

    /// A repository whose `.git` carries no `info` directory yet.
    #[test]
    fn a_missing_info_directory_is_created_rather_than_refused() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".git")).unwrap();
        assert!(!repo.join(".git").join("info").exists());

        let exclude = exclude_store_from_git(repo).unwrap().expect("a rule");
        assert_eq!(exclude, repo.join(".git").join("info").join("exclude"));
        assert!(std::fs::read_to_string(&exclude)
            .unwrap()
            .contains(STORE_EXCLUDE_RULE));
    }

    /// A rule that already excludes the store, in either place Git reads one.
    #[test]
    fn an_existing_rule_is_left_alone() {
        for (name, seed) in [
            (".git/info/exclude", ".kin\n"),
            (".gitignore", "target\n.kin/\n"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let repo = dir.path();
            std::fs::create_dir_all(repo.join(".git").join("info")).unwrap();
            let seeded = repo.join(name);
            std::fs::write(&seeded, seed).unwrap();

            assert!(
                exclude_store_from_git(repo).unwrap().is_none(),
                "{name} already excludes the store"
            );
            assert_eq!(
                std::fs::read_to_string(&seeded).unwrap(),
                seed,
                "{name} must be untouched"
            );
        }
    }

    /// A rule Git resolves from outside the repository is honored.
    ///
    /// `core.excludesFile` names a file that is neither the local exclude nor
    /// the tracked ignore file, so reading those two alone reports the store as
    /// visible and writes a rule Git already had. The fixture proves Git itself
    /// agrees before the decision is asked for: the store is on disk and absent
    /// from `git status`.
    #[test]
    fn a_rule_resolved_from_outside_the_repository_is_honored() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        let excludes = dir.path().join("global-excludes");
        std::fs::write(&excludes, "/.kin/\n").unwrap();
        git(
            &repo,
            &["config", "core.excludesFile", excludes.to_str().unwrap()],
        );
        write_store(&repo);

        let status = git_status(&repo);
        assert!(
            !status.contains(".kin"),
            "the fixture must start with the store already hidden: {status:?}"
        );

        assert!(
            exclude_store_from_git(&repo).unwrap().is_none(),
            "a rule Git already resolves must not be restated locally"
        );
        let info_exclude = std::fs::read_to_string(repo.join(".git").join("info").join("exclude"))
            .unwrap_or_default();
        assert!(
            !info_exclude.contains(".kin"),
            "no second rule may be written: {info_exclude:?}"
        );
    }

    /// A directory Git does not own is not this command's to write into.
    #[test]
    fn a_directory_without_git_gets_no_rule() {
        let dir = tempfile::tempdir().unwrap();
        assert!(exclude_store_from_git(dir.path()).unwrap().is_none());
        assert!(!dir.path().join(".git").exists());
    }

    /// A linked worktree's excludes live with the repository it came from.
    ///
    /// Kin's own fleet runs almost entirely in linked worktrees, where `.git`
    /// is a pointer file and `info/exclude` is shared through `commondir`. A
    /// resolver that stopped at the pointer would write a rule into the
    /// worktree's private gitdir, where Git never reads one for excludes.
    #[test]
    fn a_linked_worktree_is_followed_to_its_common_directory() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("main");
        let linked = dir.path().join("linked");
        std::fs::create_dir_all(&main).unwrap();
        git(&main, &["init", "-q"]);
        git(&main, &["config", "user.email", "kin-test@example.invalid"]);
        git(&main, &["config", "user.name", "Kin Test"]);
        std::fs::write(main.join("seed"), b"seed").unwrap();
        git(&main, &["add", "seed"]);
        git(&main, &["commit", "-qm", "seed"]);
        git(
            &main,
            &[
                "worktree",
                "add",
                "-q",
                linked.to_str().unwrap(),
                "-b",
                "linked",
            ],
        );
        write_store(&linked);

        let before = git_status(&linked);
        assert!(
            before.contains(".kin"),
            "fixture must start visible: {before:?}"
        );

        let exclude = exclude_store_from_git(&linked).unwrap().expect("a rule");
        assert_eq!(
            exclude.canonicalize().unwrap(),
            main.join(".git")
                .join("info")
                .join("exclude")
                .canonicalize()
                .unwrap(),
            "a linked worktree writes to the shared exclude, not its private gitdir"
        );

        let after = git_status(&linked);
        assert!(!after.contains(".kin"), "store must be excluded: {after:?}");
    }

    /// A machine that does not have the weights is told the download is coming
    /// before this command returns, with the model, the size, the source and
    /// the destination, and a machine that has them is told nothing is owed.
    #[test]
    #[serial_test::serial]
    fn init_reports_the_embedding_model_outcome_this_run_actually_had() {
        let _endpoint = kin_core::test_env::EnvVarGuard::unset("HF_ENDPOINT");
        let absent = crate::embed_model::EmbedModelFetch {
            model_id: crate::embed_model::DEFAULT_EMBED_MODEL_ID.to_string(),
            cache_dir: Some("/home/dev/.cache/huggingface/hub/models--x".to_string()),
            present: false,
            fetched_bytes: 0,
            expected_bytes: Some(crate::embed_model::DEFAULT_EMBED_MODEL_BYTES),
            fetching: false,
            no_fetch_reason: None,
            relocated_hf_home: None,
        };

        // State one: absent when the command opened, still absent when it
        // closed. The line this replaced said the 523 MB "download happens
        // during this command" whatever the run had done, and a cold-user walk
        // on 0.6.0 read that sentence off a run whose background embed pass had
        // never started, with no `~/.cache/huggingface` on the machine at all.
        let did_not_fetch = embedding_model_notice(&absent, &absent, None);
        assert!(
            did_not_fetch.contains("nomic-ai/nomic-embed-text-v1.5")
                && did_not_fetch.contains("about 523 MB")
                && did_not_fetch.contains("huggingface.co")
                && did_not_fetch.contains("/home/dev/.cache/huggingface/hub/models--x"),
            "the model, the size, the source and the destination are all named: {did_not_fetch}"
        );
        assert!(
            did_not_fetch.contains("did not fetch it"),
            "a run that fetched nothing must say so: {did_not_fetch}"
        );
        assert!(
            did_not_fetch.contains("`kin embed`"),
            "and must name what does fetch it: {did_not_fetch}"
        );
        assert!(
            !did_not_fetch.contains("happens during this command"),
            "the old unconditional promise is gone: {did_not_fetch}"
        );

        // The same state, with the daemon's own account of why. A refusal is
        // the difference between "this did not happen" and "this did not
        // happen, and here is the machine that decided".
        let refusal = kin_core::memory_pressure::PressureRefusal {
            work: kin_core::memory_pressure::HeavyWork::EmbedBatch
                .id()
                .to_string(),
            level: "critical".to_string(),
            reason: "the host had no room for the embed pass".to_string(),
            at_unix: 4_800,
        };
        let refused = embedding_model_notice(&absent, &absent, Some(&refusal));
        assert!(
            refused.contains("the host had no room for the embed pass"),
            "a refusal on record is named as the cause: {refused}"
        );

        // State two: it arrived during this run. FIR-2555's point survives
        // here, where it is true: the cost belongs to `kin init`, not to some
        // later command the reader has not run.
        let fetched = embedding_model_notice(
            &crate::embed_model::EmbedModelFetch {
                present: true,
                ..absent.clone()
            },
            &absent,
            None,
        );
        assert!(
            fetched.contains("this command fetched it"),
            "a run that paid for the download says which command paid: {fetched}"
        );
        assert!(
            !fetched.contains("did not fetch it"),
            "the states must be distinguishable: {fetched}"
        );

        // State three: it was already here, so this command owed nothing.
        let cached = crate::embed_model::EmbedModelFetch {
            present: true,
            ..absent.clone()
        };
        let cached_notice = embedding_model_notice(&cached, &cached, None);
        assert!(
            cached_notice.contains("was already cached") && !cached_notice.contains("523"),
            "a machine that had the model is not warned about a download: {cached_notice}"
        );
        assert!(
            !cached_notice.contains("this command fetched it"),
            "and is not told this run fetched what it already had: {cached_notice}"
        );

        let overridden = crate::embed_model::EmbedModelFetch {
            model_id: "acme/private-embed".to_string(),
            expected_bytes: None,
            present: false,
            ..cached
        };
        let overridden_notice = embedding_model_notice(&overridden, &absent, None);
        assert!(
            !overridden_notice.contains("523"),
            "a model this build never measured is given no size: {overridden_notice}"
        );
        assert!(
            overridden_notice.contains("fetches the model from huggingface.co"),
            "the fetch is still named without a size: {overridden_notice}"
        );
    }

    /// Three absent-model states, told apart by bytes rather than by a
    /// non-zero numerator, because only one of them belongs to this run.
    ///
    /// A fast `kin init` on a small repository lands in the first.
    /// `expressjs/body-parser` converted in ten seconds against a fixed 523 MB
    /// download and the summary reported "did not fetch it" over a download
    /// that was partway through, which reads as nothing having happened. The
    /// second is what a machine carrying an interrupted cache from an earlier
    /// attempt produces: bytes are there throughout, and crediting them to this
    /// command claims a download it never made.
    #[test]
    #[serial_test::serial]
    fn the_absent_model_states_are_told_apart_by_the_bytes_this_run_added() {
        let _endpoint = kin_core::test_env::EnvVarGuard::unset("HF_ENDPOINT");
        let empty = crate::embed_model::EmbedModelFetch {
            model_id: crate::embed_model::DEFAULT_EMBED_MODEL_ID.to_string(),
            cache_dir: Some("/home/dev/.cache/huggingface/hub/models--x".to_string()),
            present: false,
            fetched_bytes: 0,
            expected_bytes: Some(crate::embed_model::DEFAULT_EMBED_MODEL_BYTES),
            fetching: false,
            no_fetch_reason: None,
            relocated_hf_home: None,
        };
        let partial = |bytes: u64| crate::embed_model::EmbedModelFetch {
            fetched_bytes: bytes,
            ..empty.clone()
        };

        // One: this command moved the download from nothing to 137 MB.
        let moved = embedding_model_notice(&partial(137 * 1024 * 1024), &empty, None);
        assert!(
            moved.contains("It fetched 137 MB of about 523 MB")
                && moved.contains("137 of 523 MB is in the cache"),
            "what this run added and where the whole fetch stands are both \
             named: {moved}"
        );
        assert!(
            moved.contains("did not finish fetching it"),
            "a fetch that started and stopped short says so: {moved}"
        );
        assert!(
            !moved.contains("did not fetch it"),
            "a partial fetch must not read as a run that fetched nothing: {moved}"
        );

        // Two, the review's case: the same 137 MB was already there and this
        // command added none of it. Same numerator, different run, and the
        // sentence may not credit this one.
        let earlier = partial(137 * 1024 * 1024);
        let untouched = embedding_model_notice(&earlier, &earlier, None);
        assert!(
            untouched.contains("137 of 523 MB of an earlier fetch is in the cache")
                && untouched.contains("this command added none of it"),
            "a pre-existing cache is attributed to the run that made it: {untouched}"
        );
        assert!(
            !untouched.contains("It fetched") && !untouched.contains("did not finish fetching it"),
            "and this run claims no download it did not make: {untouched}"
        );

        // Three: nothing in the cache before or after keeps the sentence it
        // always had, so the arms above are selected by bytes rather than by
        // being reachable from every absent state.
        let nothing = embedding_model_notice(&empty, &empty, None);
        assert!(
            nothing.contains("did not fetch it") && !nothing.contains("of 523 MB is in the cache"),
            "an untouched cache reports no numerator: {nothing}"
        );

        // And the reader is told what it costs the next query in both states
        // where something is owed.
        assert!(
            moved.contains("ranks on lexical and graph signals")
                && untouched.contains("ranks on lexical and graph signals"),
            "both partial states say what the next query gets: {moved} / {untouched}"
        );
    }

    /// The notice explains itself with the embed refusal, never with whatever
    /// heavy work happened to be refused last.
    ///
    /// `LspSweep` writes refusals to the same ledger, so on a pressured host
    /// the newest row is often about the sweep. Reading that one told a user
    /// their model download was skipped for a reason belonging to different
    /// work.
    #[test]
    fn the_model_notice_reads_the_embed_refusal_and_not_the_newest_one() {
        use kin_core::memory_pressure::{HeavyWork, PressureLevel, PressureRefusal};
        let dir = tempfile::tempdir().expect("a temp dir");
        // Order matters: the sweep is published second, so it is the newest
        // refusal of any work, which is what the old selection returned.
        PressureRefusal::record(
            dir.path(),
            HeavyWork::EmbedBatch,
            PressureLevel::Critical,
            "the embed batch was held back",
        );
        PressureRefusal::record(
            dir.path(),
            HeavyWork::LspSweep,
            PressureLevel::Critical,
            "the sweep was held back",
        );

        // This is only the case that matters if the newest really is the other
        // work, so that is asserted rather than assumed.
        assert_eq!(
            PressureRefusal::read_all(dir.path())
                .last()
                .map(|refusal| refusal.work.clone()),
            Some(HeavyWork::LspSweep.id().to_string()),
            "the newest refusal on this store is about the sweep"
        );

        let chosen = embed_refusal_for(dir.path()).expect("the embed refusal is on record");
        assert_eq!(
            chosen.work,
            HeavyWork::EmbedBatch.id().to_string(),
            "a download that did not happen is explained by the refusal about downloading"
        );
    }

    /// The registration defect, made visible under a scratch registry with
    /// nothing in it. On a developer machine a leftover registry.toml from an
    /// old migration hides that nothing calls `update_registry`; this test
    /// starts from empty, so it cannot be fooled the same way.
    #[tokio::test]
    async fn init_registers_the_repository_under_a_scratch_registry() {
        let scratch = tempfile::tempdir().unwrap();
        let repo = scratch.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "kin-test@example.invalid"]);
        git(&repo, &["config", "user.name", "Kin Test"]);
        std::fs::write(repo.join("seed"), b"seed").unwrap();
        git(&repo, &["add", "seed"]);
        git(&repo, &["commit", "-qm", "seed"]);

        let kin_home = scratch.path().join("kin-home");
        let registry_path = kin_home.join("registry.toml");
        let _home = kin_core::test_env::EnvVarGuard::set("HOME", &kin_home);
        let _kin_home_var = kin_core::test_env::EnvVarGuard::set("KIN_HOME", &kin_home);
        let _registry = kin_core::test_env::EnvVarGuard::set("KIN_REGISTRY_PATH", &registry_path);

        // Enrichment off: this case is about the conversion transaction, and
        // starting a daemon to query a language server would make it depend on
        // what the host has installed.
        run(Some(repo.to_str().unwrap().to_string()), false, true, None)
            .await
            .expect("kin init must succeed under a scratch registry");

        let registry = kin_core::registry::KinRegistry::load_from(&registry_path)
            .expect("registry must be readable after init");
        let canonical = repo.canonicalize().unwrap();
        assert!(
            registry.repos.iter().any(|entry| entry.path == canonical),
            "kin init must register the repository it just admitted, so a second \
             repository's registration can later find it as a cross-repo sibling; \
             registry entries: {:?}",
            registry.repos
        );
    }
}
