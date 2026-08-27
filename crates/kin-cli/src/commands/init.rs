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

pub async fn run(
    path: Option<String>,
    json: bool,
    no_enrich: bool,
    adopt_repository_id: Option<String>,
) -> Result<()> {
    let _span = tracing::info_span!("kin.init").entered();
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

    if json {
        print_json_result(&result, boundary, enrichment)?;
    } else {
        print_human_result(&result, boundary, &enrichment, &cross_file)?;
    }
    Ok(())
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
            // A sweep that enriched nothing reported the same sentence as one
            // that had nothing left to do, and on a JavaScript repository with
            // 66 admitted files that sentence was "complete (0/66 files)". The
            // conversion had not failed and nothing said the enrichment had.
            if done == 0 && total > 0 {
                note!(
                    "note: cross-file enrichment finished without enriching any of the {total} \
                     files it walked ({blocked} blocked); reference and import edges will be \
                     missing until it can run"
                );
                return CrossFileEnrichment::Withheld {
                    pending: format!(
                        "the sweep walked {total} files and enriched none of them, so cross-file \
                         reference and override edges are not in this graph; `kin daemon sweep` \
                         retries it"
                    ),
                };
            }
            note!("  cross-file enrichment complete ({done}/{total} files)");
            return CrossFileEnrichment::Produced;
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
) -> Result<()> {
    emit(&render_human_result(
        result,
        boundary,
        semantic_enrichment,
        cross_file,
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
    // Read here rather than remembered from the enrichment phase, because the
    // death this looks for happens during that phase and leaves nothing in this
    // process. The daemon publishes a serving record at start and retires it as
    // it exits on its own terms, so a surviving record beside a dead pid is the
    // only trace an unwatched kill leaves, and this is the summary a reader is
    // already looking at when they need it.
    let daemon_death = crate::daemon_death::recorded_for_store(result.layout.root());
    writeln!(
        out,
        "  Semantic enrichment: {}",
        render_semantic_enrichment(semantic_enrichment, daemon_death.as_ref(), cross_file)
    )?;
    if let Some(warning) = enrichment_kill_warning(daemon_death.as_ref()) {
        writeln!(out, "{warning}")?;
    }
    if let Some(notice) = cross_file_pending_notice(semantic_enrichment, cross_file) {
        writeln!(out, "{notice}")?;
    }
    if let Some(notice) = semantic_absence_notice(semantic_enrichment) {
        writeln!(out, "{notice}")?;
    }
    writeln!(
        out,
        "  {}",
        embedding_model_notice(&crate::embed_model::EmbedModelFetch::probe(false))
    )?;
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
fn embedding_model_notice(fetch: &crate::embed_model::EmbedModelFetch) -> String {
    if let Some(reason) = fetch.no_fetch_reason.as_deref() {
        return format!("Embedding model: {} ({reason})", fetch.model_id);
    }
    let location = match fetch.cache_dir.as_deref() {
        Some(dir) => format!(" at {dir}"),
        None => String::new(),
    };
    if fetch.present {
        return format!(
            "Embedding model: {} is already cached{location}, so nothing is downloaded",
            fetch.model_id
        );
    }
    format!(
        "Embedding model: {} is not on this machine yet; `kin init` starts the first embed \
         pass, which fetches {} from {}{} and needs egress. On a repository with parseable \
         content that download happens during this command, before any vector exists",
        fetch.model_id,
        fetch.expected_download(),
        crate::embed_model::endpoint_host(),
        match fetch.cache_dir.as_deref() {
            Some(dir) => format!(" into {dir}"),
            None => String::new(),
        }
    )
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
    fn init_states_the_model_download_a_fresh_machine_still_owes() {
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
        let notice = embedding_model_notice(&absent);
        assert!(
            notice.contains("nomic-ai/nomic-embed-text-v1.5")
                && notice.contains("about 523 MB")
                && notice.contains("huggingface.co")
                && notice.contains("/home/dev/.cache/huggingface/hub/models--x"),
            "the model, the size, the source and the destination are all named: {notice}"
        );

        // FIR-2555. The size and the host were already here; who pays was not.
        // This line used to read "the first embed pass fetches", which put the
        // cost on a command the reader had not run, while the enrichment phase
        // of this very `kin init` was starting the daemon whose embed worker
        // does the fetching. A stranger measured 2.576s to init an empty
        // repository against 67.1s to init a one-file TypeScript one on shipped
        // 0.5.45, and the difference was this download.
        assert!(
            notice.contains("`kin init` starts the first embed pass"),
            "the notice must name the command that pays for the download: {notice}"
        );
        assert!(
            notice.contains("during this command"),
            "the notice must say the download happens now rather than later: {notice}"
        );
        assert!(
            !notice.contains("after this command finishes"),
            "the check must be able to fail: {notice}"
        );

        let cached = crate::embed_model::EmbedModelFetch {
            present: true,
            ..absent
        };
        let cached_notice = embedding_model_notice(&cached);
        assert!(
            cached_notice.contains("already cached") && !cached_notice.contains("523"),
            "a machine that has the model is not warned about a download: {cached_notice}"
        );

        let overridden = crate::embed_model::EmbedModelFetch {
            model_id: "acme/private-embed".to_string(),
            expected_bytes: None,
            present: false,
            ..cached
        };
        let overridden_notice = embedding_model_notice(&overridden);
        assert!(
            !overridden_notice.contains("523"),
            "a model this build never measured is given no size: {overridden_notice}"
        );
        assert!(
            overridden_notice.contains("fetches the model from huggingface.co"),
            "the fetch is still named without a size: {overridden_notice}"
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
