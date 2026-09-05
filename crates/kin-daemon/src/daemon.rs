// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::api;
use crate::error::{DaemonError, Result};
use crate::loop_runner::{self, LoopConfig};
use crate::state::{DaemonState, RECON_IDLE};

/// Configuration for the daemon process.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Port for the HTTP API server.
    pub api_port: u16,
    /// Reconciliation loop configuration.
    pub loop_config: LoopConfig,
    /// Interval for the orphan session sweeper (default 30s).
    pub sweep_interval: Duration,
    /// Interval for the background embedding worker (default 5s).
    pub embed_interval: Duration,
    /// Batch size for embedding inference (entities per pass).
    pub embed_batch_size: usize,
    /// Whether to enable LSP enrichment (auto-detected if not set).
    pub lsp_enabled: bool,
    /// Optional idle timeout. Intended for CLI-autostarted daemons so command
    /// bursts can reuse warm state without leaving background processes alive
    /// indefinitely.
    pub idle_timeout: Option<Duration>,
    /// Overlap the background embed worker's per-batch persist with the next
    /// batch's prep + GPU forward, so the accelerator is never idle during a
    /// flush. Off by default: the serial path is deterministic and is what the
    /// proof profile relies on. Enabled only under the throughput profile.
    pub embed_pipeline_overlap: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            api_port: 4219,
            loop_config: LoopConfig::default(),
            sweep_interval: Duration::from_secs(30),
            embed_interval: Duration::from_secs(5),
            embed_batch_size: 512,
            lsp_enabled: true,
            idle_timeout: None,
            embed_pipeline_overlap: false,
        }
    }
}

fn should_enable_lsp_enrichment(config_enabled: bool, filesystem_reconcile_disabled: bool) -> bool {
    config_enabled && !filesystem_reconcile_disabled
}

/// Whether the daemon opens its enrichment channel at startup.
///
/// Taken ONCE, during startup, and that is the whole reason a language server
/// installed while a daemon is already running may not reach it. With no server
/// discovered here the channel is never created, so no enrichment message is
/// ever sent for the life of the process and no adapter is ever consulted. That
/// is the state the container behind the v0.5.42 stranger run was in: the Python
/// adapter did not fail to start, it was never reached.
///
/// When discovery DID find a server the channel exists and each language's
/// server is started lazily on first use, so a server installed afterwards is
/// picked up with no restart. Both halves are true, and only the pessimistic one
/// is safe for a surface to print, because a fresh install is exactly the host
/// where discovery finds nothing.
fn enrichment_channel_opens(enrichment_enabled: bool, servers_discovered: usize) -> bool {
    enrichment_enabled && servers_discovered > 0
}

/// Acquire the process-lifetime repository authority before daemon state opens.
pub fn acquire_daemon_authority(
    kin_root: &std::path::Path,
) -> Result<crate::lifecycle::DaemonLock> {
    acquire_daemon_authority_within(kin_root, crate::lifecycle::SINGLETON_LOCK_RETRY_BUDGET)
}

/// Acquire process-lifetime repository authority with one caller-owned budget.
///
/// Exposed so the process entrypoint can acquire before constructing
/// [`DaemonState`], and so deterministic tests can use a short deadline without
/// changing the production retry contract.
pub fn acquire_daemon_authority_within(
    kin_root: &std::path::Path,
    budget: Duration,
) -> Result<crate::lifecycle::DaemonLock> {
    let deadline = Instant::now() + budget;
    let reclaim = match crate::lifecycle::acquire_singleton_lock_within(kin_root, Duration::ZERO) {
        Ok(Some(lock)) => return Ok(lock),
        Ok(None) => {
            // Current automatic recovery deliberately refuses pathname
            // replacement at the mixed-version boundary. It still resolves
            // and reports owner evidence before the bounded retry. Both that
            // resolution and retry share this caller's one deadline.
            crate::lifecycle::reclaim_stale_locks_within(
                kin_root,
                deadline.saturating_duration_since(Instant::now()),
            )
        }
        Err(error) => return Err(DaemonError::Io(error)),
    };

    match crate::lifecycle::acquire_singleton_lock_within(
        kin_root,
        deadline.saturating_duration_since(Instant::now()),
    ) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(DaemonError::RepoOwnedByAnotherDaemon(
            singleton_contention_message(kin_root, reclaim),
        )),
        Err(error) => Err(DaemonError::Io(error)),
    }
}

/// Actionable refusal text for a daemon that lost the per-repo singleton lock.
///
/// Reads the holder from disk evidence and renders it. Kept split from
/// [`format_singleton_contention`] so the wording is testable without a repo.
fn singleton_contention_message(
    kin_root: &std::path::Path,
    reclaim: crate::lifecycle::StaleLockReclaim,
) -> String {
    format_singleton_contention(
        &kin_root.display().to_string(),
        crate::lifecycle::singleton_lock_holder(kin_root),
        &reclaim,
    )
}

/// Render the refusal a contended starter reports.
///
/// The old text ("another kin daemon already owns this repo") named nothing an
/// operator could act on, and the process exited 0 so the message never even
/// reached the caller as a failure. Every branch here names the evidence that
/// produced it and what to do next.
fn format_singleton_contention(
    repo: &str,
    holder: Option<crate::lifecycle::SingletonLockHolder>,
    reclaim: &crate::lifecycle::StaleLockReclaim,
) -> String {
    let reclaimed = reclaim.cleared().len();
    let context = match holder {
        Some(holder) if holder.alive => format!(
            "another kin daemon (pid {}) already owns {repo} and is still running",
            holder.pid
        ),
        // An identity-verified stamp can say the owning incarnation is gone
        // without implying anything about whoever holds that PID now.
        Some(holder) if holder.identity_verified => format!(
            "the daemon lock for {repo} is still held after the process that took it (pid {}) \
             exited, so a leaked lock fd is keeping it alive; pid {} no longer identifies that \
             daemon and may since have been reused",
            holder.pid, holder.pid
        ),
        Some(holder) => format!(
            "the daemon lock for {repo} is still held after its recorded owner (pid {}) exited, \
             so a leaked lock fd is keeping it alive",
            holder.pid
        ),
        None => format!(
            "the daemon lock for {repo} is held but names no owner, so the holding process \
             cannot be identified from disk"
        ),
    };
    let remedy = match holder {
        Some(holder) if holder.alive => format!(
            "wait for pid {} to finish starting, or stop it with `kin daemon stop`",
            holder.pid
        ),
        _ => "stop any remaining kin-daemon process for this repo, then retry".to_string(),
    };
    let compatibility_boundary = match reclaim {
        crate::lifecycle::StaleLockReclaim::CoordinationUnavailable(reason) => {
            format!(
                " Automatic lock-file retirement was refused because safe coordination is \
                 unavailable: {reason}. Replacing the inode cannot be proven safe."
            )
        }
        _ => String::new(),
    };
    if reclaimed > 0 {
        format!(
            "refusing to start a second daemon: {context} (reclaimed {reclaimed} stale lock \
             file(s) first, and the lock is still contended).{compatibility_boundary} To proceed, \
             {remedy}."
        )
    } else {
        format!(
            "refusing to start a second daemon: {context}.{compatibility_boundary} To proceed, \
             {remedy}."
        )
    }
}

fn idle_check_interval(idle_timeout: Duration) -> Duration {
    let millis = (idle_timeout.as_millis() / 4).clamp(100, 5_000) as u64;
    Duration::from_millis(millis)
}

/// Next backoff after a persistent embedding-worker error. Doubles the previous
/// backoff (starting from `base` on the first failure) and caps at `max`. Kept
/// pure so the no-tight-spin guarantee is unit-testable.
fn next_embed_error_backoff(current: Option<Duration>, base: Duration, max: Duration) -> Duration {
    current.unwrap_or(base).saturating_mul(2).min(max)
}

#[derive(Debug)]
enum BackgroundEmbeddingBatchOutcome {
    Completed(usize),
    ResetAfterIndexError(kin_db::KinDbError),
    Failed(kin_db::KinDbError),
}

/// Run one background embedding batch and any first-error vector recovery under
/// one `embedding_work` guard.
///
/// The recovery decision belongs inside this critical section. In particular,
/// a foreground `/embed --rebuild` that is already waiting must not acquire the
/// guard, publish a fresh index, and then be wiped by recovery from this stale
/// failed batch.
fn run_background_embedding_batch(
    state: &DaemonState,
    reset_on_index_error: bool,
    process: impl FnOnce(&DaemonState) -> std::result::Result<usize, kin_db::KinDbError>,
) -> BackgroundEmbeddingBatchOutcome {
    let _embedding_guard = match state.embedding_work.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return BackgroundEmbeddingBatchOutcome::Failed(
                kin_db::KinDbError::ConcurrentAccessError(
                    "embedding work lock poisoned".to_string(),
                ),
            );
        }
    };

    // Record a settled status reading before this batch makes one impossible.
    //
    // `kin_graph_status` samples every counter under this same lock, which this
    // batch is about to hold for its whole length, so a status call landing
    // inside the batch answers from the settled cache. This is where that
    // reading is taken, at an instant when no embedding work is in flight.
    //
    // At the top of the batch and not the bottom: `embedding_status` is memoized
    // on the graph truth epoch and the vector index key-set token, this batch
    // changes that token, and the worker's own batch decision just filled the
    // memo. A call here hits it; a call after `process` always misses and
    // rescans the retrievable key set.
    state.seed_settled_head_graph_status();

    match process(state) {
        Ok(count) => BackgroundEmbeddingBatchOutcome::Completed(count),
        Err(error)
            if reset_on_index_error && matches!(&error, kin_db::KinDbError::IndexError(_)) =>
        {
            reset_vector_index_and_requeue_under_guard(state);
            BackgroundEmbeddingBatchOutcome::ResetAfterIndexError(error)
        }
        Err(error) => BackgroundEmbeddingBatchOutcome::Failed(error),
    }
}

/// Detach a stale vector index and rebuild both embedding queues while the
/// caller owns `embedding_work`.
fn reset_vector_index_and_requeue_under_guard(state: &DaemonState) {
    state.graph.reset_vector_index();
    #[cfg(feature = "embeddings")]
    state.graph.queue_missing_for_embedding();
    state.graph.queue_missing_artifacts_for_embedding();
}

/// Deterministically expose reset contention to the status/reset race test.
#[cfg(all(test, feature = "vector"))]
pub(crate) fn reset_vector_index_and_requeue_after_contention_for_test(
    state: &DaemonState,
    on_contention: impl FnOnce(),
) -> std::result::Result<(), kin_db::KinDbError> {
    let _embedding_guard = match state.embedding_work.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => {
            on_contention();
            state.embedding_work.lock().map_err(|_| {
                kin_db::KinDbError::ConcurrentAccessError(
                    "embedding work lock poisoned".to_string(),
                )
            })?
        }
        Err(std::sync::TryLockError::Poisoned(_)) => {
            return Err(kin_db::KinDbError::ConcurrentAccessError(
                "embedding work lock poisoned".to_string(),
            ));
        }
    };

    reset_vector_index_and_requeue_under_guard(state);
    Ok(())
}

/// The language server this build starts for `language`, if any.
///
/// One map, read by both the incremental and the sweep enrichment paths below.
/// It used to be two `match` blocks three hundred lines apart, and they agreed
/// only because nobody had added a language since they were written. Adding a
/// language to a single copy is invisible in review and worse at runtime: the
/// sweep would enrich files the incremental path ignored, so the edges would
/// appear only after a full re-ingest and vanish on the next incremental pass.
///
/// This map is also the referent of the claim in
/// `kin_core::reference_coverage::ENRICHABLE_LANGUAGES`, that the daemon wires
/// an adapter for exactly those languages. A test in this module fails when the
/// two disagree, because they already disagreed once: JavaScript and TypeScript
/// were absent here while kin-lsp carried a working adapter for both, so a
/// JavaScript repository was told its reference edges were `unsupported` and
/// cross-file resolution fell back to matching bare names.
///
/// The returned triple is exactly what `LspServer::start` takes: the command,
/// its arguments, and the initialization options for this workspace.
/// Public because it is this build's whole answer to "which server do you start
/// for this language", and two surfaces outside the enrichment loop need that
/// answer to agree with it: the provisioning advice that tells an operator what
/// to install, and the proof that starts a real server against a fixture.
/// Probe what each enrichable language's server can actually do, then publish
/// it for the query paths.
///
/// Spawned rather than awaited. Probing means starting each server and running
/// the initialize handshake, and five languages against the probe budget would
/// add seconds to daemon startup in the healthy case and far more when a server
/// hangs. Nothing waits on the answer: until it publishes, every observation
/// reads the readiness as unknown, which already keeps the absence-trust gate
/// silent and is the honest state for a daemon that has not finished looking.
///
/// Safe against the daemon's own enrichment path by construction, not by
/// timing. The sweep decides what to start from `lsp_adapter_for` and its own
/// `servers` map, and enrichment availability comes from `discover_servers`;
/// neither reads the published verdict, so a probe still in flight cannot
/// change what the daemon does. The publish is write-only here and consumed
/// only by kin-mcp.
///
/// The probes run concurrently, so the worst case is one probe budget rather
/// than one per language.
fn spawn_language_server_readiness_probe(workspace_root: std::path::PathBuf) {
    use kin_core::reference_coverage::{
        LanguageServerReadiness, LanguageServerReadinessMap, ENRICHABLE_LANGUAGES,
    };
    use kin_lsp::registry::{ProviderGapReason, ProviderRegistry};

    tokio::spawn(async move {
        // One task per language so the probes overlap: the worst case is one
        // probe budget rather than one per language.
        let probes: Vec<_> = ENRICHABLE_LANGUAGES
            .iter()
            .copied()
            .map(|language| {
                let workspace_root = workspace_root.clone();
                tokio::spawn(async move {
                    let registry = ProviderRegistry::with_defaults();
                    let initialization_options = lsp_adapter_for(language, &workspace_root)
                        .and_then(|(_, _, init_opts)| init_opts);
                    let readiness = match kin_lsp::lifecycle::probe_readiness(
                        &registry,
                        language,
                        &workspace_root,
                        initialization_options,
                    )
                    .await
                    {
                        Ok(_) => LanguageServerReadiness::Usable,
                        Err(gap) => match gap.reason {
                            ProviderGapReason::ServerUnusable { message } => {
                                LanguageServerReadiness::Unusable { reason: message }
                            }
                            _ => LanguageServerReadiness::Absent,
                        },
                    };
                    (language, readiness)
                })
            })
            .collect();

        let mut readiness = LanguageServerReadinessMap::new();
        for probe in probes {
            match probe.await {
                Ok((language, state)) => {
                    if let LanguageServerReadiness::Unusable { reason } = &state {
                        warn!(
                            %language,
                            %reason,
                            "a language server is installed but cannot start, so this \
                             language's cross-file reference edges cannot be produced on \
                             this host"
                        );
                    }
                    readiness.insert(language, state);
                }
                // A probe task that panicked establishes nothing about its
                // language, and recording it as Absent would be a claim this
                // process did not earn. Leaving it out reads as unknown.
                Err(error) => warn!(%error, "a language server readiness probe did not finish"),
            }
        }

        kin_mcp::edge_coverage::publish_language_server_readiness(readiness);
    });
}

pub fn lsp_adapter_for(
    language: kin_model::LanguageId,
    workspace_root: &std::path::Path,
) -> Option<(String, Vec<String>, Option<serde_json::Value>)> {
    use kin_lsp::adapters::LspAdapter;

    fn describe(
        adapter: &dyn LspAdapter,
        workspace_root: &std::path::Path,
    ) -> (String, Vec<String>, Option<serde_json::Value>) {
        (
            adapter.server_command().to_string(),
            adapter.server_args(),
            adapter.initialization_options(workspace_root),
        )
    }

    match language {
        kin_model::LanguageId::Rust => Some(describe(
            &kin_lsp::adapters::rust_analyzer::RustAnalyzerAdapter,
            workspace_root,
        )),
        kin_model::LanguageId::Python => Some(describe(
            &kin_lsp::adapters::python::PyrightAdapter,
            workspace_root,
        )),
        // One adapter serves both. `typescript-language-server` resolves a
        // CommonJS `require` chain through the same tsserver project model it
        // uses for TypeScript imports, which is why kin-lsp's discovery table
        // maps both language names onto the same binary.
        kin_model::LanguageId::TypeScript | kin_model::LanguageId::JavaScript => Some(describe(
            &kin_lsp::adapters::typescript::TypeScriptAdapter,
            workspace_root,
        )),
        kin_model::LanguageId::Go => Some(describe(
            &kin_lsp::adapters::go::GoplsAdapter,
            workspace_root,
        )),
        _ => None,
    }
}

/// Every language this build knows about.
///
/// Written as an exhaustive `match` rather than a hand-kept array so a new
/// `LanguageId` variant fails to compile here instead of silently escaping the
/// coverage assertions below. A list that quietly stops enumerating everything
/// is the shape of guard that passes forever.
#[cfg(test)]
fn all_known_languages() -> Vec<kin_model::LanguageId> {
    use kin_model::LanguageId::*;
    let every = [
        TypeScript, JavaScript, Python, Go, Java, Rust, C, Cpp, CSharp, Ruby, Php, Swift, Kotlin,
        Hcl,
    ];
    for language in every {
        // Exhaustive on purpose: adding a variant breaks this arm, which is the
        // point. The body is a no-op; the compiler is the assertion.
        match language {
            TypeScript | JavaScript | Python | Go | Java | Rust | C | Cpp | CSharp | Ruby | Php
            | Swift | Kotlin | Hcl => {}
        }
    }
    every.to_vec()
}

#[cfg(test)]
mod adapter_wiring_tests {
    use super::{all_known_languages, lsp_adapter_for};
    use kin_core::reference_coverage::ENRICHABLE_LANGUAGES;
    use kin_model::LanguageId;
    use std::path::Path;

    /// Languages kin-lsp registers a complete provider for that this build
    /// deliberately does not construct yet.
    ///
    /// A decision written down, not an oversight left implicit. Each of these
    /// has a `ProviderSpec` in `ProviderRegistry::with_defaults` and an adapter
    /// module in `kin_lsp::adapters`, so wiring one is the same shape the Go row
    /// already is: an arm here, an entry in `ENRICHABLE_LANGUAGES`, and an
    /// install recipe in kin-cli. None is wired today because none has an
    /// install recipe and none is on the corpus the enrichment work is measured
    /// against, and a language with an arm and no recipe fails
    /// `every_enrichable_language_has_an_install_command`.
    const NOT_YET_WIRED: &[LanguageId] = &[LanguageId::Java, LanguageId::C, LanguageId::Cpp];

    /// `ENRICHABLE_LANGUAGES` documents itself as the set the daemon wires an
    /// adapter for. This is that sentence as an assertion, in both directions.
    ///
    /// It failed before this test existed: JavaScript and TypeScript had a
    /// complete adapter in kin-lsp and no arm in the daemon's map, so a
    /// JavaScript repository read `reference_enrichment: "unsupported"` and its
    /// cross-file calls were resolved by matching bare names.
    #[test]
    fn the_adapter_map_and_the_enrichable_set_name_the_same_languages() {
        let root = Path::new("/nonexistent-workspace");
        for language in all_known_languages() {
            let wired = lsp_adapter_for(language, root).is_some();
            let declared = ENRICHABLE_LANGUAGES.contains(&language);
            assert_eq!(
                wired, declared,
                "{language}: daemon wires an adapter = {wired}, ENRICHABLE_LANGUAGES says {declared}"
            );
        }
    }

    /// Both JavaScript and TypeScript resolve to one server binary.
    ///
    /// Pinned because the two are separate `LanguageId` values reaching one
    /// adapter, and a future edit that gives JavaScript its own arm would be
    /// invisible to the set-equality test above while breaking every `.js`
    /// repository that has `typescript-language-server` installed.
    #[test]
    fn javascript_and_typescript_share_one_server_binary() {
        let root = Path::new("/nonexistent-workspace");
        let (js_cmd, js_args, _) =
            lsp_adapter_for(LanguageId::JavaScript, root).expect("JavaScript must be wired");
        let (ts_cmd, ts_args, _) =
            lsp_adapter_for(LanguageId::TypeScript, root).expect("TypeScript must be wired");
        assert_eq!(js_cmd, "typescript-language-server");
        assert_eq!(js_cmd, ts_cmd);
        assert_eq!(js_args, ts_args);
        assert_eq!(js_args, vec!["--stdio".to_string()]);
    }

    /// The commands the map hands `LspServer::start` are the binary names a
    /// host actually installs, so the provisioning advice and the runtime agree.
    #[test]
    fn wired_languages_name_the_binaries_an_operator_installs() {
        let root = Path::new("/nonexistent-workspace");
        for (language, expected) in [
            (LanguageId::Rust, "rust-analyzer"),
            (LanguageId::Python, "pyright-langserver"),
            (LanguageId::TypeScript, "typescript-language-server"),
            (LanguageId::JavaScript, "typescript-language-server"),
            (LanguageId::Go, "gopls"),
        ] {
            let (cmd, _, _) =
                lsp_adapter_for(language, root).unwrap_or_else(|| panic!("{language} not wired"));
            assert_eq!(cmd, expected, "{language} server command");
        }
    }

    /// The startup gate behind the restart advice `kin doctor` prints.
    ///
    /// Asserted rather than reasoned about, because it is a user-facing claim:
    /// a host that had no language server when its daemon started does not gain
    /// enrichment when one is installed, and that is exactly the host doing the
    /// installing. If this predicate ever stops keying on the discovered count,
    /// the advice becomes wrong in the direction that leaves an operator
    /// waiting for edges that will never arrive.
    #[test]
    fn no_server_at_startup_means_no_enrichment_channel_for_this_daemon() {
        use super::enrichment_channel_opens;

        assert!(
            !enrichment_channel_opens(true, 0),
            "with enrichment enabled and no server discovered the channel must stay closed"
        );
        assert!(
            enrichment_channel_opens(true, 1),
            "one discovered server is enough to open the channel"
        );
        assert!(
            !enrichment_channel_opens(false, 3),
            "disabled enrichment must not open a channel however many servers exist"
        );
    }

    /// A language with no adapter stays unwired, so `Unsupported` remains a
    /// truthful state rather than a default nobody maintains.
    #[test]
    fn an_unwired_language_has_no_adapter() {
        let root = Path::new("/nonexistent-workspace");
        for language in [LanguageId::Ruby, LanguageId::Swift, LanguageId::Hcl] {
            assert!(
                lsp_adapter_for(language, root).is_none(),
                "{language} must not be wired without being declared enrichable"
            );
        }
    }

    /// Every language kin-lsp registers a provider for is either wired here or
    /// named above as a decision somebody made.
    ///
    /// This is the class that shipped in v0.6.4 and it is invisible to the
    /// set-equality test above. kin-lsp's adapter suite grew to six languages
    /// while this map stayed at four, so a Go repository was told its reference
    /// edges were `unsupported` while a complete `gopls` adapter sat inside the
    /// same binary. `the_adapter_map_and_the_enrichable_set_name_the_same_languages`
    /// cannot catch that: a language missing from BOTH constants agrees with
    /// itself, and the two stayed in lockstep the whole time they were wrong.
    ///
    /// So this one reads the third constant, kin-lsp's own registry, which is
    /// the thing that actually grew. A seventh provider arriving there now fails
    /// here rather than going quiet for a release.
    #[test]
    fn every_registered_provider_is_wired_or_named_as_a_decision() {
        let root = Path::new("/nonexistent-workspace");
        let registered: Vec<LanguageId> = kin_lsp::registry::ProviderRegistry::with_defaults()
            .known_binaries()
            .into_iter()
            .map(|(language, _)| language)
            .collect();

        // Positive controls, not decoration. A registry that answered with an
        // empty list, or with only the languages this build already wires,
        // would satisfy every assertion below while grading nothing, and it
        // would read exactly like a pass. One language from each side of the
        // decision has to be in the set before the loop means anything.
        assert!(
            registered.contains(&LanguageId::Go),
            "kin-lsp registers no Go provider, so this guard is reading the wrong list: \
             {registered:?}"
        );
        assert!(
            registered.contains(&LanguageId::Java),
            "kin-lsp registers no Java provider, so nothing here exercises the deferred \
             side: {registered:?}"
        );

        for language in registered {
            let wired = lsp_adapter_for(language, root).is_some();
            let deferred = NOT_YET_WIRED.contains(&language);
            assert!(
                wired != deferred,
                "{language}: kin-lsp registers a provider for it, so it must either have an \
                 arm in lsp_adapter_for (wired = {wired}) or be named on NOT_YET_WIRED \
                 (deferred = {deferred}). Both at once is a list that rotted; neither is the \
                 gap that shipped."
            );
        }
    }
}

/// Poll `workspace/symbol` with an empty query until the LSP server responds
/// or the deadline is reached. Language servers like rust-analyzer and pyright
/// continue background indexing after the `initialize` handshake; this probe
/// detects when they are actually ready to serve symbol queries.
///
/// Falls back to a best-effort fixed delay if the server does not respond to
/// `workspace/symbol` (e.g., server does not declare the capability).
async fn wait_for_lsp_index(server: &kin_lsp::lifecycle::LspServer, max: Duration) {
    const POLL_INTERVAL: Duration = Duration::from_millis(500);
    if !server.has_references() && !server.has_definition() {
        tokio::time::sleep(max.min(Duration::from_secs(5))).await;
        return;
    }
    let deadline = tokio::time::Instant::now() + max;
    loop {
        let probe = server
            .client
            .request("workspace/symbol", serde_json::json!({ "query": "" }))
            .await;
        if probe.is_ok() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Await an in-flight embed-progress flush, logging any persistence or task
/// failure. Awaiting before the next flush is scheduled is what serializes
/// successive flushes: at most one persist runs at a time, so two flushes can
/// never interleave and the persisted generation cursor advances monotonically.
/// Returns once the handle is cleared so callers can use this both to overlap a
/// flush with the next batch's prep and to drain the tail at every loop exit.
///
/// The returned flag says whether a flush actually reached disk, which is what
/// lets a caller credit persisted progress without crediting a failed persist.
/// Nothing in flight is reported as nothing persisted.
async fn drain_pending_flush(pending: &mut Option<tokio::task::JoinHandle<Result<usize>>>) -> bool {
    let Some(handle) = pending.take() else {
        return false;
    };
    match handle.await {
        Ok(Ok(_pending)) => true,
        Ok(Err(e)) => {
            error!(error = %e, "failed to flush embed progress");
            false
        }
        Err(e) => {
            error!(error = %e, "embed progress flush task panicked");
            false
        }
    }
}

/// Drain the in-flight flush and credit what it persisted to the embedding pass.
///
/// Progress is credited here rather than when a batch finishes embedding,
/// because the counter the supervisor judges liveness on has to mean work that
/// survived to disk. A batch whose flush failed produced nothing durable, and
/// crediting it anyway would let a worker that can never persist keep vouching
/// for itself indefinitely — the exact silence this supervisor exists to end.
async fn drain_embed_flush(
    pending: &mut Option<tokio::task::JoinHandle<Result<usize>>>,
    embedded: &mut u64,
    pass: &crate::background_work::BackgroundPass,
) {
    let persisted = drain_pending_flush(pending).await;
    let credited = std::mem::take(embedded);
    if persisted {
        pass.advanced(credited, Instant::now());
    }
}

/// Ceiling on the wait between retries of a refused vector checkpoint.
const DEFERRED_CHECKPOINT_RETRY_MAX: Duration = Duration::from_secs(300);

/// Everything the persistence task does on its way out.
///
/// A named function rather than the body of a `select!` arm, because both
/// halves are durability decisions that have to be drivable by a test. The
/// graph half was already load-bearing; the vector half below is the case the
/// coverage regression was actually found in, and a wiring nothing exercises is
/// how the first half of this fix would have shipped covering only a daemon
/// nobody stops.
///
/// Runs under the persistence task's own shutdown budget
/// (`KIN_DAEMON_SHUTDOWN_FLUSH_SECS`, five minutes by default), which exists
/// because the graph flush here can need minutes on a real store.
/// Visible to the crate so the authority-envelope guard can be exercised
/// through this caller as well as the periodic one. The invariant it protects
/// is stated regardless of caller, and four callers reach the same write, so a
/// test that only ever drives the periodic path proves the guard is positioned
/// correctly by inspection rather than by behaviour.
pub(crate) async fn run_shutdown_persistence(state: &Arc<DaemonState>) {
    if state.is_dirty() {
        if state.shutdown_flush_would_wipe_graph() {
            // The in-memory graph collapsed to a small fraction of the last
            // persisted entity count, almost certainly a transient wipe (e.g. an
            // empty/bare checkout reconciled as all-deleted) rather than a real
            // edit. Skip the final flush so the larger good snapshot survives;
            // the daemon reloads it and re-reconciles against the filesystem on
            // restart. (Graph-keyed, not embed-keyed: a stale vector index
            // self-heals on load and never blocks this flush.)
            warn!(
                persisted = state
                    .persisted_entity_count
                    .load(std::sync::atomic::Ordering::SeqCst),
                current = state.graph.entity_count(),
                "skipping final graph flush on shutdown — in-memory entity count collapsed vs on-disk snapshot; preserving the larger snapshot"
            );
        } else {
            info!("final persistence flush on shutdown");
            if let Err(e) = save_snapshot_blocking(Arc::clone(state)).await {
                error!(error = %e, "shutdown save failed");
            } else {
                state.mark_clean();
            }
        }
    }
    retry_deferred_vector_checkpoint_at_shutdown(state).await;
}

/// Give a standing vector-checkpoint refusal its one attempt before the process
/// ends.
///
/// The wake-tick retry covers a daemon that keeps running. This covers the case
/// the regression was found in, where the process ENDED with a refusal standing
/// and every vector embedded since the previous successful checkpoint went with
/// it. Nothing else would have written them: the sidecar is not part of the
/// graph flush above, so a clean shutdown published graph truth and left the
/// vectors behind.
///
/// Unconditional and with no backoff, unlike the wake-tick retry, because
/// shutdown has no next tick to defer to: the choice here is one attempt or
/// lose the work. It costs one authority reopen, charged against the same
/// budget the flush above already spends minutes of on a real store, and it
/// costs an ordinary daemon nothing at all, because the first check returns at
/// once when no refusal stands.
///
/// After the graph flush rather than before it, deliberately. Publishing
/// advances the authority generation, which is exactly what closes the
/// divergence a refusal is about, so this is the moment in shutdown when the
/// checkpoint is most likely to be provable.
async fn retry_deferred_vector_checkpoint_at_shutdown(state: &Arc<DaemonState>) {
    if state.deferred_vector_checkpoint().is_none() {
        return;
    }
    info!("retrying a refused vector checkpoint before shutdown");
    let retry_state = Arc::clone(state);
    match tokio::task::spawn_blocking(move || retry_state.retry_deferred_vector_checkpoint()).await
    {
        Ok(Some(Ok(pending))) => {
            info!(
                pending,
                "checkpointed before shutdown the vector progress a refused checkpoint had left in memory"
            );
        }
        Ok(Some(Err(error))) => {
            // Loud, and named as loss rather than as a slow exit. This is the
            // one path left where the vectors genuinely do not survive, and a
            // reader has to be able to tell it from an untidy shutdown.
            warn!(
                error = %error,
                "the vector checkpoint was still refused at shutdown; vectors embedded since the refusal are NOT durable and the next open re-derives them"
            );
        }
        Ok(None) => {}
        Err(error) => {
            error!(error = %error, "shutdown vector checkpoint retry task panicked");
        }
    }
}

/// Re-attempt a vector checkpoint the daemon had to refuse, so the vectors it
/// left in memory reach the sidecar instead of dying with the process.
///
/// A refusal means the live exact tree had moved away from committed workspace
/// authority, which is what a commit in flight does to it, and it closes when
/// that commit settles. The work therefore needs nothing but somewhere to be
/// retried from. There was nowhere: the only caller of the checkpoint is the
/// flush the worker runs after a batch embeds something, so a refusal on the
/// last batch of a draining queue was the end of it, and everything embedded
/// since the previous successful checkpoint was gone on the next open. This
/// worker's wake tick is the one clock that keeps running with no batch to
/// embed, which is exactly the case that was losing the work.
///
/// The backoff is not politeness. Proving the tree against authority costs a
/// full reopen, linear in store size rather than in the batch, so a mismatch
/// that does not close would otherwise reopen authority on every tick for as
/// long as it lasts.
async fn retry_deferred_vector_checkpoint(
    state: &Arc<DaemonState>,
    backoff: &mut Option<Duration>,
    due: &mut Option<Instant>,
    base: Duration,
) {
    if state.deferred_vector_checkpoint().is_none() {
        *backoff = None;
        *due = None;
        return;
    }
    if due.is_some_and(|at| Instant::now() < at) {
        return;
    }
    let retry_state = Arc::clone(state);
    match tokio::task::spawn_blocking(move || retry_state.retry_deferred_vector_checkpoint()).await
    {
        Ok(Some(Ok(pending))) => {
            *backoff = None;
            *due = None;
            info!(
                pending,
                "checkpointed the vector progress a refused checkpoint had left in memory"
            );
        }
        Ok(Some(Err(error))) => {
            let next = next_embed_error_backoff(*backoff, base, DEFERRED_CHECKPOINT_RETRY_MAX);
            *backoff = Some(next);
            *due = Some(Instant::now() + next);
            warn!(
                error = %error,
                next_retry_s = next.as_secs(),
                "vector checkpoint still refused; embedded vectors stay in memory until it lands"
            );
        }
        // The record cleared under us, which is the ordinary outcome when the
        // worker's own flush landed between the read above and this call.
        Ok(None) => {
            *backoff = None;
            *due = None;
        }
        Err(error) => {
            error!(error = %error, "deferred vector checkpoint retry task panicked");
        }
    }
}

// Shutdown-latency bound — how long the daemon may take to actually disappear.
// Callers that budget for daemon cleanup (the merge-trust harness attests
// against a 45s window) depend on this being bounded rather than generous, so
// the terms are stated explicitly.
//
// SIGTERM/SIGINT → process gone:
// 1. the signal is observed by the async handler — prompt even mid-hydration,
//    because hydration runs on the blocking pool and leaves the async workers
//    schedulable;
// 2. `drain_handles` joins the daemon's tasks, bounded at 10s. An in-flight
//    hydration is a blocking task rather than a drained handle, but the API
//    server's graceful shutdown waits on in-flight requests, so a hydrating
//    daemon rides this full 10s;
// 3. the final storage flush, the derived-CAS directory barrier, and
//    endpoint-file removal run (all fast on the local backend; the barrier is
//    bounded at one fsync per shard directory touched, so at most 256);
// 4. `runtime.shutdown_timeout(runtime_shutdown_grace())` waits up to 8s for
//    the blocking pool, then abandons whatever is still running;
// 5. the process exits.
//
// That normal path is ~18s. Independently, the escalation watchdog force-exits
// DEFAULT_SHUTDOWN_ESCALATION_GRACE after shutdown is signalled, so the hard
// bound is ~25s. A force-escalated exit skips step 3 entirely: neither the
// barrier nor endpoint retirement runs, which is the deliberate trade of a
// backstop that exists to end a wedged process. Both are recoverable, since
// the derived CAS re-hydrates on open and a stale endpoint is swept by the
// next liveness probe. Owner death costs at most one OWNER_WATCH_CHECK_INTERVAL of
// detection on top of the same bound: ~27s from owner exit to process gone,
// with no signal ever sent.
//
// Both grace periods are configurable — KIN_DAEMON_SHUTDOWN_GRACE_SECS and
// KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS — so a caller with a tighter cleanup
// budget than 45s can lower the bound rather than resorting to SIGKILL.

/// Default grace the shutdown-escalation watchdog grants — once graceful
/// shutdown is signalled — before force-exiting the process. Generous enough
/// for a legitimate final snapshot flush + task drain to win the race on their
/// own, short enough that a wedged embed batch (blocking GPU compute that cannot
/// observe the cancel signal) can never leave a SIGTERM-immune CPU zombie.
const DEFAULT_SHUTDOWN_ESCALATION_GRACE: Duration = Duration::from_secs(25);

/// Default bound on how long tokio runtime teardown waits for in-flight blocking
/// tasks (e.g. an embedding batch mid GPU-compute) before abandoning them so the
/// process can actually exit.
const DEFAULT_RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

/// How often the escalation watchdog polls for the shutdown signal.
const SHUTDOWN_WATCH_POLL: Duration = Duration::from_millis(250);

/// Parse a whole-seconds duration, falling back to `default` for absent, empty,
/// or unparseable input. Kept pure so the grace-period config is unit-testable.
fn parse_duration_secs(raw: Option<&str>, default: Duration) -> Duration {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}

fn duration_from_env_secs(name: &str, default: Duration) -> Duration {
    parse_duration_secs(std::env::var(name).ok().as_deref(), default)
}

/// Decide whether the background persistence task should flush dirty state.
///
/// Both clocks are suppressed while a daemon-side embed pass is in flight:
/// - Periodic (`since_save`): bounds how long dirty state may sit unpersisted.
/// - Idle (`since_mutation`): debounces the full-graph serialize to mutation
///   quiet periods.
///
/// During an embed pass the embed handler persists its own progress (pre-pass
/// snapshot, per-batch kvec, post-pass snapshot), and the only graph mutations
/// are re-derivable enrichment (LSP relations). A background FULL-graph flush
/// here is therefore redundant — and on large repos ruinous: it re-serializes
/// the entire graph on every fire. Observed killing the daemon on a ~955MB mui
/// graph (repeated 955MB writes every few seconds starved the embed feed and
/// pressured host memory until the process died — "Connection refused" mid-pass).
/// The post-pass snapshot persists the final state once the pass completes, and
/// a mid-pass crash only loses re-derivable enrichment, never primary truth.
/// O(gaps × graph size) writes on large repos are the failure mode being closed.
///
/// An LSP cold sweep is suppressed for the SAME reason, and the paragraph above
/// described it before it was covered: a sweep's only graph mutations are
/// re-derivable enrichment, and a background flush mid-sweep re-serializes the
/// whole graph to persist edges the next sweep would recompute. Measured on a
/// converted psf/requests store (6491 commits): one 188-second sweep triggered a
/// single flush costing 96.6 seconds, which carried a 56.2-second repository
/// authority successor preparation whose own `change_bodies_ms` was 0. That is
/// a whole-workspace rebuild and a whole-store re-admission performed for zero
/// changed content bodies.
///
/// Suppression is bounded by the sweep, not open-ended: the sweep marks the
/// graph dirty when it finishes, so the flush fires immediately after rather
/// than never, and the sweep's own duration is bounded by the per-file
/// definitions budget and the per-query caps. A live-only write landing
/// mid-sweep therefore waits at most one sweep before it is persisted.
/// Which background pass, if any, is holding the flush clocks down.
///
/// Named rather than passed as a second bool beside the first: two adjacent
/// booleans at a call site say nothing about which is which, and the reason a
/// flush was suppressed is exactly what a reader of this decision wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlushSuppression {
    /// Nothing is holding the clocks; the durability bounds apply as written.
    None,
    /// A daemon-side embed pass is in flight.
    EmbedPass,
    /// An LSP cold sweep is in flight.
    LspSweep,
}

fn should_flush_now(
    since_save: Duration,
    since_mutation: Duration,
    suppression: FlushSuppression,
    idle_flush: Duration,
    periodic_flush: Duration,
) -> bool {
    if suppression != FlushSuppression::None {
        return false;
    }
    since_save >= periodic_flush || since_mutation >= idle_flush
}

/// Operator opt-out for the background embedding pass the daemon starts on its
/// own after the first reconciliation cycle.
pub(crate) const AUTO_EMBED_ENV: &str = "KIN_DAEMON_AUTO_EMBED";

/// Fault injection, both off by default and both named for the state they
/// create rather than for the test that wants it.
///
/// The acceptance estate cannot otherwise reach either state. Every suite in
/// `scripts/acceptance/` runs a three-file fixture, so a daemon over it opens in
/// under a second and the first query is never slow enough to be owed a
/// disclosure; and with the embedding backfill trivially short the enrichment
/// sweep never lags, so a reference answer is never thin. A check that cannot
/// reach the state it grades passes on its trivial branch and proves nothing,
/// which is what the first run of `first_query_readiness_repro.py` did.
///
/// These ship with their consumer. `scripts/acceptance/first_query_readiness_repro.py`
/// sets both in CI, so neither is a branch that exists on every daemon and is
/// exercised by nothing.
pub(crate) const STARTUP_HOLD_ENV: &str = "KIN_DAEMON_TEST_STARTUP_HOLD_SECS";
pub(crate) const HOLD_SWEEP_ENV: &str = "KIN_DAEMON_TEST_HOLD_ENRICHMENT_SWEEP";

/// How long to hold the endpoint unpublished, from a raw value.
///
/// Pure so the rule is testable without a daemon. Unset, empty, zero and
/// unparseable all disarm it: a fault injector that fires on a typo is a worse
/// defect than the one it exists to expose.
pub(crate) fn startup_hold_from(value: Option<&str>) -> Duration {
    match value.map(str::trim) {
        Some(raw) if !raw.is_empty() => raw
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or(Duration::ZERO),
        _ => Duration::ZERO,
    }
}

/// Whether to refuse the enrichment sweep, from a raw value.
pub(crate) fn hold_sweep_from(value: Option<&str>) -> bool {
    matches!(
        value.map(str::trim).map(str::to_ascii_lowercase).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Whether the daemon may queue and drain the embedding backlog without being
/// asked. Default ON: unset, or any value other than the documented falsy set,
/// keeps today's behavior exactly. A falsy value defers the pass until an
/// explicit embed request, which is the opt-out for an operator who does not
/// want a bulk accelerator pass starting because a store was opened.
///
/// The falsy set matches `KIN_DAEMON_REQUIRE_TOKEN`, the sibling boolean knob,
/// so one spelling works across the daemon's env surface.
pub(crate) fn auto_embed_enabled() -> bool {
    kin_daemon_spawn::auto_embed_enabled_from(std::env::var(AUTO_EMBED_ENV).ok().as_deref())
}

/// Whether the selected graph has no queued or unindexed embedding work.
///
/// Keeping all three fields explicit prevents an empty in-memory queue from
/// standing in for coverage. A refused missing-key backfill can have no queued
/// batch yet while `indexed < total`, and that refusal must remain durable.
fn embedding_coverage_is_complete(pending: usize, indexed: usize, total: usize) -> bool {
    kin_core::memory_pressure::EmbeddingCoverage {
        pending,
        indexed,
        total,
    }
    .is_complete()
}

/// Retire a stale memory cause when this daemon cannot run embedding for the
/// independent persistence reason reported by `/health`.
///
/// Exact-work retirement preserves LSP and future-work refusals. Keeping the
/// embed record would tell MCP and CLI readers that freeing memory can restart
/// a worker this backend deliberately never starts.
fn retire_embed_pressure_for_unavailable_persistence(state: &DaemonState) {
    clear_pressure_refusal_for_work(state, kin_core::memory_pressure::HeavyWork::EmbedBatch);
}

/// Build the background embedding backlog and announce it, or defer the whole
/// pass because an operator opted out. Returns whether the backlog was queued.
///
/// Announcing matters because nothing the user ran asks for this work. Opening
/// a store whose index has not caught up is enough to start it, so the pass is
/// a property of the store's state rather than of the command issued, and on an
/// accelerator it is a bulk run writing a sidecar nobody requested. A worker
/// that starts silently leaves an operator inferring it from machine load.
///
/// Deferring pauses rather than disables. The queue is left unbuilt and the
/// worker stood down, so an explicit embed request still runs the pass on
/// demand (`/embed` resumes the worker). Pausing is also what keeps a deferred
/// daemon eligible for idle shutdown: a backlog no worker will drain must not
/// read as work in flight.
fn start_or_defer_background_embed(state: &DaemonState) -> bool {
    // The opt-out is asked FIRST, and this order is the whole of FIR-2632.
    //
    // Pressure is a question about work somebody wants done. An operator who
    // turned background embedding off wants none of it, so on a loaded host the
    // earlier order answered a question nobody had asked: it declined the pass
    // for memory, wrote a refusal into the store, and put "background embedding
    // did not start" on `kin doctor`, `kin graph status` and the MCP envelope,
    // about a pass that was never going to start for a reason that had nothing
    // to do with memory. The opt-out's own line never printed, so an operator
    // checking that their opt-out took effect saw a memory complaint instead.
    //
    // It hid because it needs a loaded host to appear at all. Quiet CI is never
    // near the bar, so `a_cli_spawned_daemon_honours_the_background_embed_opt_out`
    // was green there and red on any busy machine.
    if !auto_embed_enabled() {
        state.pause_background_embed();
        clear_pressure_refusal_for_work(state, kin_core::memory_pressure::HeavyWork::EmbedBatch);
        warn!(
            trigger = AUTO_EMBED_ENV,
            "background embedding deferred by operator opt-out: no vectors will be generated, and semantic coverage stays as it is until an explicit embed request runs"
        );
        return false;
    }
    // Coverage is the question pressure qualifies, so establish that there is
    // work before asking whether the host can hold it. Otherwise opening an
    // already-complete store on a critical host publishes an embed refusal
    // even though there is no batch to start. Current readers can filter that
    // contradiction after another daemon round trip, but older readers show it
    // until the worker's first wake retires it.
    let embed_status = state.graph.embedding_status();
    if embedding_coverage_is_complete(
        embed_status.pending,
        embed_status.indexed,
        embed_status.total,
    ) {
        clear_pressure_refusal_for_work(state, kin_core::memory_pressure::HeavyWork::EmbedBatch);
        info!(
            opt_out = AUTO_EMBED_ENV,
            indexed = embed_status.indexed,
            total = embed_status.total,
            "background embedding coverage already complete: no backlog needs admission"
        );
        return true;
    }
    // Now that the pass is genuinely wanted, ask whether the machine has room
    // for it. Before the queue is built rather than after, because building it
    // walks the graph for everything the index is missing and a machine with no
    // room should not pay for a queue nothing is going to drain. The pass is
    // left unqueued, so a daemon that declines here stays eligible for idle
    // shutdown. Unlike the operator opt-out, pressure is temporary: the worker
    // remains runnable and asks again on its next wake.
    let call = pressure_verdict(kin_core::memory_pressure::HeavyWork::EmbedBatch);
    publish_footprint_standing(state, &call);
    if let kin_core::memory_pressure::Verdict::Refuse { reason } = &call.verdict {
        let reason = reason.clone();
        disclose_pressure_refusal(
            state,
            kin_core::memory_pressure::HeavyWork::EmbedBatch,
            &call,
            &reason,
        );
        return false;
    }
    // Re-queue every object the persisted index still lacks a vector for, so the
    // worker resumes after a restart drained the in-memory queue (the queue is
    // not persisted; coverage is, via graph-vs-index truth). Idempotent (HashSet
    // queues) — a fresh start that already enqueued via reconcile is unaffected.
    #[cfg(feature = "embeddings")]
    state.graph.queue_missing_for_embedding();
    state.graph.queue_missing_artifacts_for_embedding();
    info!(
        queued_entities = state.graph.pending_embeddings(),
        queued_artifacts = state.graph.pending_artifact_embeddings(),
        opt_out = AUTO_EMBED_ENV,
        "background embedding started: generating vectors for everything the index is missing"
    );
    true
}

/// Grace period the escalation watchdog waits after shutdown is signalled before
/// force-exiting. Configurable via `KIN_DAEMON_SHUTDOWN_GRACE_SECS` (0 escalates
/// immediately once the signal fires — used by tests).
pub fn shutdown_escalation_grace() -> Duration {
    duration_from_env_secs(
        "KIN_DAEMON_SHUTDOWN_GRACE_SECS",
        DEFAULT_SHUTDOWN_ESCALATION_GRACE,
    )
}

/// Bound on how long tokio runtime teardown waits for in-flight blocking tasks
/// before abandoning them. Configurable via
/// `KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS`.
pub fn runtime_shutdown_grace() -> Duration {
    duration_from_env_secs(
        "KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS",
        DEFAULT_RUNTIME_SHUTDOWN_GRACE,
    )
}

/// What the on-disk control plane says about this daemon's right to keep
/// serving.
///
/// Endpoint files disappearing is not, on its own, a reason for a healthy
/// daemon to die. The two cases that are — the repository was removed, or
/// another daemon took the repo over — are distinguishable from a third party
/// deleting `daemon.pid`/`daemon.port` out from under a running incumbent, and
/// conflating them is how a refused second start killed the daemon it lost to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlPlane {
    /// `.kin` is present and the published endpoint names this process.
    Ours,
    /// The `.kin` root itself is gone: `kin eject` or doctor removed the repo.
    RootGone,
    /// The endpoint names a different daemon that is still running, so this
    /// process is no longer the one serving the repo.
    Superseded { pid: u32 },
    /// `.kin` is present, but this daemon's endpoint is missing, incomplete, or
    /// attributed to a process that is gone. The daemon still owns the repo
    /// singleton, so the endpoint is repairable rather than fatal.
    EndpointLost,
}

/// How often the control plane is re-examined when no idle timeout paces the
/// monitor. Cheap: three `exists` checks and, at most, one small read.
const CONTROL_PLANE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Whether the `.kin` directory this daemon serves has been removed. The only
/// condition under which a flush must be skipped: there is nowhere to write.
fn repository_root_missing(state: &DaemonState) -> bool {
    !state.layout.root().exists()
}

fn classify_control_plane(state: &DaemonState) -> ControlPlane {
    let root = state.layout.root();
    if !root.exists() {
        return ControlPlane::RootGone;
    }
    // Yielding is gated on proof, not on a PID. This daemon holds the
    // repository singleton for its whole lifetime, so no legitimate successor
    // can exist; a foreign endpoint that cannot prove a live owner is debris,
    // and treating debris as an eviction notice is what killed the incumbent.
    if let Some(pid) = crate::lifecycle::proven_live_other_endpoint_owner(root) {
        return ControlPlane::Superseded { pid };
    }
    match crate::lifecycle::endpoint_ownership(root) {
        crate::lifecycle::EndpointOwnership::CurrentProcess
            if crate::lifecycle::read_port_file(root).is_some() =>
        {
            ControlPlane::Ours
        }
        _ => ControlPlane::EndpointLost,
    }
}

/// Whether outstanding embedding work would be abandoned by a shutdown.
///
/// `embed_pass_active` counts unconditionally: an explicit pass is running
/// right now. A queued backlog counts only while something will actually drain
/// it, which is what `worker_can_drain` reports. A backlog the worker has
/// already stood down from is not work in progress, and treating it as such
/// would make the daemon immortal rather than patient.
fn embed_work_outstanding(embed_pass_active: bool, queued: bool, worker_can_drain: bool) -> bool {
    embed_pass_active || (queued && worker_can_drain)
}

/// What the background embed worker should do when its queue drains.
///
/// The queue is the worker's whole notion of work, so a retrieval key with no
/// vector and no queue entry is work nothing will ever do, announced as
/// `remaining=0`. Coverage is the authority for whether work exists; the queue
/// is only how it gets done, and `kin embed` has always known the difference.
/// Re-queueing the gap is therefore the right answer, and bounding it is what
/// keeps a key that can never be embedded from spinning the worker every
/// interval: the same gap twice running means the previous re-queue changed
/// nothing, so the worker reports it once and stops asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverageDrainVerdict {
    /// Coverage is whole. The drain really is finished.
    Complete,
    /// Coverage is short and no re-queue has been tried at this gap yet.
    Backfill { missing: usize },
    /// Coverage is short and the last re-queue at this gap produced nothing.
    Stalled { missing: usize },
}

impl CoverageDrainVerdict {
    /// Pressure work whose durable refusal this coverage boundary may retire.
    ///
    /// Backfill and stalled queues are still outstanding work. Only whole
    /// coverage authorizes retiring an embedding refusal.
    fn completed_pressure_work(self) -> Option<kin_core::memory_pressure::HeavyWork> {
        matches!(self, Self::Complete).then_some(kin_core::memory_pressure::HeavyWork::EmbedBatch)
    }
}

fn coverage_drain_verdict(missing: usize, backfilled_gap: Option<usize>) -> CoverageDrainVerdict {
    if missing == 0 {
        CoverageDrainVerdict::Complete
    } else if backfilled_gap == Some(missing) {
        CoverageDrainVerdict::Stalled { missing }
    } else {
        CoverageDrainVerdict::Backfill { missing }
    }
}

fn embed_work_in_flight(state: &DaemonState) -> bool {
    embed_work_outstanding(
        state.embed_pass_active(),
        state.graph.pending_embeddings() > 0 || state.graph.pending_artifact_embeddings() > 0,
        state.background_embed_worker_can_drain(),
    )
}

/// Work a shutdown would destroy rather than merely interrupt, independent of
/// whether any client can currently reach this daemon.
///
/// The idle clock advances only on API traffic (`begin_request` /
/// `end_request`); no background task touches it. So a daemon still ingesting a
/// repository for the first time, or draining the embedding backlog that first
/// ingest queued, reads as perfectly idle to the monitor, and a CLI autostart,
/// which injects a 60s timeout, kills it mid-pass. None of that work resumes:
/// the next command starts the pass over from the beginning.
fn work_would_be_lost_by_shutdown(state: &DaemonState) -> bool {
    if state.active_request_count() > 0 {
        return true;
    }
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return true;
    }
    if state
        .reconciliation_status
        .load(std::sync::atomic::Ordering::Relaxed)
        != RECON_IDLE
    {
        return true;
    }
    embed_work_in_flight(state)
}

fn ready_for_idle_shutdown(
    state: &DaemonState,
    idle_timeout: Duration,
    control_plane: ControlPlane,
) -> bool {
    if work_would_be_lost_by_shutdown(state) {
        return false;
    }
    if control_plane == ControlPlane::EndpointLost {
        // Rare by construction: the control-plane check earlier in this same
        // tick repairs a lost endpoint, so reaching here means republication
        // itself failed. Kept because that is exactly when it matters: the
        // daemon is unreachable by new clients, so the session and event-
        // subscriber gates below cannot be waiting on anything, and it should be
        // allowed to idle out rather than linger unreachable.
        //
        // Only those client-reachability gates are skipped. The work gates
        // above are not, because an unreachable daemon loses an in-flight first
        // scan or embed drain exactly as a reachable one does, and an endpoint
        // blip is transient where a discarded first ingest is not.
        return state.idle_duration() >= idle_timeout;
    }
    if state.event_tx.receiver_count() > 0 {
        return false;
    }
    if state.has_external_sessions() {
        return false;
    }
    state.idle_duration() >= idle_timeout
}

async fn save_snapshot_blocking(state: Arc<DaemonState>) -> Result<()> {
    tokio::task::spawn_blocking(move || state.save_snapshot())
        .await
        .map_err(|error| DaemonError::Io(std::io::Error::other(error.to_string())))?
}

/// How often the owner-death watchdog checks whether the owning process is
/// still alive. A `kill(pid, 0)` every couple of seconds is a single cheap
/// syscall, so this is set for detection latency rather than to save work.
/// How long endpoint publication waits for the reconcile loop's file watcher.
///
/// A ceiling, not an amount of waiting: the healthy path returns the instant the
/// loop reports, and this only decides how long a wedged loop may hold the
/// endpoint back. Registering a recursive watch is fast on the backends Kin
/// uses, so reaching this bound means something is wrong rather than large.
const WATCH_ARMING_BOUND: Duration = Duration::from_secs(30);

/// How the wait for the reconcile loop's watch ended.
///
/// Three outcomes rather than a bool because they mean different things to an
/// operator reading the log. Only `Armed` promises that a write landing after
/// the endpoint appears will be observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WatchArming {
    /// The loop reported its watcher. Publication is safe to proceed.
    Armed,
    /// The loop closed its signal without reporting one. A disabled reconciler
    /// or bare checkout may remain parked until shutdown; a refused watcher may
    /// end the task. Either way, there is no watch to wait for.
    LoopGone,
    /// The bound expired with the loop neither arming nor ending.
    TimedOut,
}

/// Wait for the reconcile loop to report its file watcher, but never forever.
///
/// Publishing late beats not publishing: an endpoint that never appears is a
/// daemon no client can reach, so the bound expires into publication with the
/// reason recorded rather than into a refusal.
pub(crate) async fn await_watch_armed(
    armed: tokio::sync::oneshot::Receiver<()>,
    bound: Duration,
) -> WatchArming {
    match tokio::time::timeout(bound, armed).await {
        Ok(Ok(())) => WatchArming::Armed,
        Ok(Err(_)) => WatchArming::LoopGone,
        Err(_) => WatchArming::TimedOut,
    }
}

/// Say what the wait produced, at the level each outcome deserves.
fn announce_watch_arming(arming: WatchArming, bound: Duration) {
    match arming {
        WatchArming::Armed => {
            debug!("the reconciliation watch is armed; publishing the daemon endpoint")
        }
        WatchArming::LoopGone => info!(
            "the reconciliation loop will not arm a watch, so this daemon observes no \
             working-copy edits; publishing the endpoint so it stays reachable"
        ),
        WatchArming::TimedOut => warn!(
            bound_s = bound.as_secs(),
            "the reconciliation loop did not report a file watcher within its bound; publishing \
             the endpoint anyway, so a host write landing now may go unobserved until an \
             explicit admission seam takes it"
        ),
    }
}

#[cfg(test)]
mod watch_arming_log_tests {
    use super::{announce_watch_arming, WatchArming};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tracing_subscriber::layer::SubscriberExt as _;

    #[derive(Default)]
    struct Captured(Vec<(tracing::Level, String)>);

    struct CaptureLayer(Arc<Mutex<Captured>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            #[derive(Default)]
            struct Read {
                message: Option<String>,
            }

            impl tracing::field::Visit for Read {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message" {
                        self.message = Some(format!("{value:?}").trim_matches('"').to_string());
                    }
                }
            }

            let mut read = Read::default();
            event.record(&mut read);
            if let Some(message) = read.message {
                self.0
                    .lock()
                    .unwrap()
                    .0
                    .push((*event.metadata().level(), message));
            }
        }
    }

    /// The endpoint log is an operator-facing promise, not a generic progress
    /// line. A loop that explicitly declined its watcher must say that it
    /// observes no working-copy edits, while the enabled control alone may say
    /// that a watcher is armed.
    #[test]
    fn no_watch_and_real_watch_make_different_log_promises() {
        let captured = Arc::new(Mutex::new(Captured::default()));
        let subscriber = tracing_subscriber::registry().with(CaptureLayer(Arc::clone(&captured)));
        {
            let _capture = crate::capture_events_on_this_thread(subscriber);
            announce_watch_arming(WatchArming::LoopGone, Duration::from_secs(30));
            announce_watch_arming(WatchArming::Armed, Duration::from_secs(30));
        }

        assert_eq!(
            captured.lock().unwrap().0,
            vec![
                (
                    tracing::Level::INFO,
                    "the reconciliation loop will not arm a watch, so this daemon observes no \
                     working-copy edits; publishing the endpoint so it stays reachable"
                        .to_string(),
                ),
                (
                    tracing::Level::DEBUG,
                    "the reconciliation watch is armed; publishing the daemon endpoint".to_string(),
                ),
            ],
            "the no-watch arm and enabled control must make different operator-facing promises"
        );
    }
}

const OWNER_WATCH_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// Validate a raw `KIN_DAEMON_WATCH_PID` value into an owner PID this daemon may
/// watch, or `None` to run with no owner-death watchdog at all.
///
/// The rejections here are the safety boundary for the watchdog, so each one is
/// deliberate:
/// - absent / empty / unparseable → no watchdog. This is the default for every
///   daemon; a spawner must opt in explicitly.
/// - `<= 1` → rejects a caller that passed `getppid()` after the daemon already
///   reparented (init is PID 1), and rejects the `kill(0, …)` / `kill(-1, …)`
///   process-group and broadcast selectors, which are not owner PIDs at all.
/// - the daemon's own PID → a self-watch can never observe a death. Treat an
///   obviously misconfigured owner as "no watchdog" instead of as armed.
///
/// Note what is NOT accepted as a source: `getppid()`. Both daemon spawn paths
/// call `setsid()`, so a healthy persistent daemon reparents to init as soon as
/// the CLI that launched it exits. `ppid == 1` is the normal, correct state for
/// a legitimately detached daemon, which is why ownership must be stated
/// explicitly by the spawner rather than inferred from the process tree.
fn parse_owner_watch_pid(raw: Option<&str>, self_pid: u32) -> Option<i32> {
    let pid = raw?.trim().parse::<i32>().ok()?;
    if pid <= 1 {
        return None;
    }
    if i64::from(pid) == i64::from(self_pid) {
        return None;
    }
    Some(pid)
}

/// Shutdown requested through a path that no scheduler can starve.
///
/// Written from a real OS signal handler, so every write must stay
/// async-signal-safe: one relaxed atomic store, no allocation, no locking, no
/// logging.
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Has shutdown been requested through a runtime-independent path?
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Arm the runtime-independent shutdown flag from signal delivery itself.
///
/// Registered through `signal_hook_registry`, which chains handlers, so tokio's
/// own SIGTERM/SIGINT registration keeps driving the graceful path unchanged.
/// This handler exists only so the force-exit backstop is armed by the kernel
/// delivering the signal rather than by the runtime's willingness to poll a
/// future.
///
/// A real signal is deliberately the ONLY writer of [`SHUTDOWN_REQUESTED`]. The
/// flag is process-global and never cleared, and the watchdog it arms ends the
/// process with `exit(0)`, so a non-signal writer would let one caller latch the
/// flag and a later, unrelated watchdog inherit it. In a test binary that
/// truncates the run and still reports success. Keeping signal delivery as the
/// sole writer makes the latch mean what it says.
///
/// Registration also replaces SIGTERM's default disposition, because
/// signal-hook-registry skips a `SIG_DFL` previous handler rather than chaining
/// to it. From this call until tokio registers its own listener, a SIGTERM sets
/// only this flag and death comes from the watchdog at grace rather than
/// instantly. Every step between the two is a `tokio::spawn` with no top-level
/// await, so the window is sub-millisecond and stays inside the documented
/// bound, but it is a real window and the watchdog must be spawned right after
/// this call rather than later.
#[cfg(unix)]
pub fn install_shutdown_signal_handler() {
    // `SigId` has no `Drop`, so every call appends another action to the signal
    // slot permanently. Production installs once; the guard keeps the `pub` API
    // from leaking that footgun to any other caller.
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        for signal in [libc::SIGTERM, libc::SIGINT] {
            // SAFETY: the handler body performs a single relaxed atomic store
            // and calls nothing that is not async-signal-safe.
            let registered = unsafe {
                signal_hook_registry::register(signal, || {
                    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
                })
            };
            if let Err(error) = registered {
                warn!(
                    signal,
                    error = %error,
                    "failed to arm the runtime-independent shutdown flag; \
                     force-exit escalation falls back to in-runtime arming"
                );
            }
        }
    });
}

#[cfg(not(unix))]
pub fn install_shutdown_signal_handler() {}

/// Has shutdown been signalled by any path?
///
/// Three independent sources, because the force-exit backstop must not depend
/// on the runtime it exists to rescue:
/// - `os_requested`: set by the SIGTERM/SIGINT handler itself, or by the
///   cooperative `/shutdown` endpoint at the moment it accepts the request.
/// - `cancel`: the watch-channel flag every in-runtime shutdown trigger sets.
/// - `is_shutdown`: the state flag the propagation task writes.
///
/// Only `os_requested` survives a saturated runtime. Both other flags are
/// written from inside it: the SIGTERM arm of `select_with_signals` sets
/// `cancel`, but that arm is a future the runtime has to poll, and the
/// propagation task that writes `is_shutdown` is a task the runtime has to
/// schedule. A reconciliation batch occupying every worker thread with
/// synchronous work therefore disarmed the backstop that exists for precisely
/// that case, and the daemon outlived its documented grace with no bound at
/// all — a stop request that never terminated anything.
fn shutdown_signalled(is_shutdown: bool, cancel: bool, os_requested: bool) -> bool {
    is_shutdown || cancel || os_requested
}

/// Spawn the shutdown-escalation watchdog: a plain OS thread — deliberately
/// NOT a tokio task — so it stays runnable even while the async runtime is
/// tearing down or saturated. Once shutdown is signalled it grants a bounded
/// grace period for the drain plus final flush to finish, then force-exits.
///
/// This is the hard backstop against two zombies. A blocking embedding batch
/// mid GPU-compute cannot observe the cancel signal, so runtime teardown can
/// otherwise block forever and leave a headless, SIGTERM-immune CPU zombie that
/// still races kvec writes. A reconciliation batch that occupies every runtime
/// worker with synchronous work is the same failure from the other direction:
/// nothing inside the runtime runs, so nothing inside the runtime can arm this.
///
/// `is_shutdown` is taken as a probe rather than a flag so the production call
/// site keeps reading `DaemonState` while a test can model the runtime whose
/// propagation task never runs at all.
pub fn spawn_shutdown_escalation_watchdog<F>(
    is_shutdown: F,
    cancel: tokio::sync::watch::Receiver<bool>,
    grace: Duration,
) where
    F: Fn() -> bool + Send + 'static,
{
    if let Err(error) = std::thread::Builder::new()
        .name("kin-shutdown-watchdog".to_string())
        .spawn(move || {
            while !shutdown_signalled(is_shutdown(), *cancel.borrow(), shutdown_requested()) {
                std::thread::sleep(SHUTDOWN_WATCH_POLL);
            }
            std::thread::sleep(grace);
            // Still alive after the grace period → the graceful path is wedged
            // (a blocking embed batch the runtime drop is waiting on, or a
            // reconciliation batch holding every worker thread). Force the whole
            // process down so a stop request always results in actual
            // termination — no zombie, and no unbounded stop.
            eprintln!(
                "kin-daemon: graceful shutdown exceeded {}s grace — forcing process exit to prevent a CPU zombie",
                grace.as_secs()
            );
             std::process::exit(0);
        })
    {
        warn!(error = %error, "failed to spawn shutdown-escalation watchdog");
    }
}

/// Is the process with this PID still alive?
///
/// Sends signal 0 — this delivers no signal and only checks for existence. A
/// return of 0 means the process exists. A non-zero return with `ESRCH` (no
/// such process) means it is gone; any other error (e.g. `EPERM`, the process
/// exists but is owned by another user) is treated as still alive so the
/// watchdog never shuts down on a process that is merely out of reach.
#[cfg(unix)]
fn watched_process_is_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    !matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    )
}

#[cfg(windows)]
fn watched_process_is_alive(pid: i32) -> bool {
    u32::try_from(pid)
        .ok()
        .is_some_and(kin_cli::daemon_client::is_process_alive)
}

#[cfg(not(any(unix, windows)))]
fn watched_process_is_alive(_pid: i32) -> bool {
    // Fail closed on unsupported targets rather than treating an uncheckable
    // owner as dead.
    true
}

/// Watch the control plane for the two states that end this daemon, repairing
/// the one that does not.
///
/// Returns `true` when the daemon must shut down. A lost endpoint is
/// republished instead: this process holds the repository singleton, so it is
/// the only legitimate publisher, and restoring its own record is the exact
/// truth rather than a guess. Republication also makes the failure
/// self-healing, because the clients that lost the endpoint find it again on
/// their next poll.
fn control_plane_demands_shutdown(
    state: &DaemonState,
    bound_port: u16,
    shutting_down: bool,
) -> bool {
    match classify_control_plane(state) {
        ControlPlane::Ours => false,
        ControlPlane::RootGone => {
            warn!(
                root = %state.layout.root().display(),
                "Kin control directory disappeared; shutting down daemon"
            );
            true
        }
        ControlPlane::Superseded { pid } => {
            warn!(
                root = %state.layout.root().display(),
                successor_pid = pid,
                "another daemon now owns this repository endpoint; shutting down"
            );
            true
        }
        ControlPlane::EndpointLost if shutting_down => {
            // Retirement is already running or about to. Republishing now
            // would race it and could land after it, leaving an endpoint
            // advertising a daemon that is about to exit. Task drain is
            // bounded and does not abort this monitor, and publication can
            // block on the coordination lock, so the window is real.
            false
        }
        ControlPlane::EndpointLost => {
            match crate::lifecycle::publish_daemon_endpoint(state.layout.root(), bound_port) {
                Ok(()) => info!(
                    root = %state.layout.root().display(),
                    port = bound_port,
                    "daemon endpoint files were removed by another process; republished them"
                ),
                Err(error) => warn!(
                    root = %state.layout.root().display(),
                    port = bound_port,
                    %error,
                    "daemon endpoint files are missing and could not be republished"
                ),
            }
            false
        }
    }
}

async fn run_idle_monitor(
    state: Arc<DaemonState>,
    idle_timeout: Option<Duration>,
    bound_port: u16,
    cancel_tx: tokio::sync::watch::Sender<bool>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let Some(idle_timeout) = idle_timeout else {
        // Endpoint repair is the idle monitor's other job, so it must keep
        // running even for a daemon that never idles out.
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CONTROL_PLANE_CHECK_INTERVAL) => {}
                _ = cancel_rx.changed() => return,
            }
            if *cancel_rx.borrow() {
                return;
            }
            if control_plane_demands_shutdown(&state, bound_port, *cancel_rx.borrow()) {
                let _ = cancel_tx.send(true);
                return;
            }
        }
    };
    // Start the idle window from when monitoring begins, not from process
    // construction. `last_activity_ms` is seeded to 0, so without this the
    // idle clock counts from `started_at` — which includes snapshot load and
    // projection rebuild — and a short timeout can fire before the daemon has
    // ever served a request, racing clients that haven't connected yet.
    state.touch_activity();
    info!(
        idle_timeout_s = idle_timeout.as_secs_f64(),
        "daemon idle shutdown enabled"
    );

    loop {
        // Re-read the window every tick rather than closing over the startup
        // value. An attached client whose session outlasts the window this
        // daemon was spawned with can raise it (see
        // `DaemonState::raise_idle_timeout`), and a monitor holding the old
        // value would shut down underneath the client that just said so.
        let Some(idle_timeout) = state.idle_timeout() else {
            // Only reachable if the window were switched off mid-run, which
            // raising cannot do. Treat it as "never idles out" rather than as
            // "idle out now".
            tokio::select! {
                _ = tokio::time::sleep(CONTROL_PLANE_CHECK_INTERVAL) => {}
                _ = cancel_rx.changed() => return,
            }
            if *cancel_rx.borrow() {
                return;
            }
            if control_plane_demands_shutdown(&state, bound_port, *cancel_rx.borrow()) {
                let _ = cancel_tx.send(true);
                return;
            }
            continue;
        };
        let check_interval = idle_check_interval(idle_timeout);
        tokio::select! {
            _ = tokio::time::sleep(check_interval) => {}
            _ = cancel_rx.changed() => return,
        }

        if *cancel_rx.borrow() {
            return;
        }
        if control_plane_demands_shutdown(&state, bound_port, *cancel_rx.borrow()) {
            let _ = cancel_tx.send(true);
            return;
        }
        // Re-read once more before deciding: a raise that landed during the
        // sleep above must be honoured by this tick, not the next one.
        let idle_timeout = state.idle_timeout().unwrap_or(idle_timeout);
        let control_plane = classify_control_plane(&state);
        if ready_for_idle_shutdown(&state, idle_timeout, control_plane) {
            if state.is_dirty() {
                if repository_root_missing(&state) {
                    warn!(
                        root = %state.layout.root().display(),
                        "skipping dirty graph flush before idle shutdown because Kin control directory is gone"
                    );
                } else {
                    info!("flushing dirty graph before idle shutdown");
                    if let Err(error) = save_snapshot_blocking(Arc::clone(&state)).await {
                        if repository_root_missing(&state) {
                            warn!(
                                error = %error,
                                root = %state.layout.root().display(),
                                "skipping dirty graph flush after Kin control directory disappeared"
                            );
                        } else {
                            warn!(error = %error, "idle shutdown delayed because snapshot flush failed");
                            continue;
                        }
                    } else {
                        state.mark_clean();
                    }
                }
            }
            info!(
                idle_ms = state.idle_duration().as_millis(),
                "daemon idle timeout reached, shutting down"
            );
            let _ = cancel_tx.send(true);
            return;
        }
    }
}

/// Where the sweep records the files it has finished.
///
/// Operational state, beside the pid and port files, not semantic authority: it
/// records what a background pass DID, and nothing answers a query from it.
fn lsp_enriched_marker_path(state: &DaemonState) -> std::path::PathBuf {
    state.layout.root().join("lsp-enriched-files.json")
}

/// Load the marker set, so a daemon that restarts does not re-sweep a graph a
/// previous one already enriched.
///
/// An unreadable or absent marker means "nothing is known to be enriched", which
/// costs a re-sweep and never skips a file wrongly. That asymmetry is deliberate:
/// a wrong skip is silent and loses the answers, a wrong re-sweep only costs
/// time.
///
/// A marker is honored only while the graph it describes still holds
/// language-server relations. A store swept before enrichment became durable
/// carries a complete marker and none of the edges it recorded, and the marker
/// is exactly what makes that loss permanent: every later daemon skips the same
/// files and re-derives nothing, so the store can never repair itself. Dropping
/// such a marker costs one re-sweep and fixes it. A sweep that legitimately
/// produced no relation at all is re-swept too, which is the same asymmetry
/// again and the cheap direction to be wrong in.
///
/// The file is left alone rather than deleted. The judgment is made again from
/// the graph on every load, and the sweep that follows rewrites the marker with
/// what it finished, so removing it would change nothing a later open decides.
///
/// The scan runs only when a marker exists, and costs one snapshot at startup
/// beside a read-index build that already walks the whole graph.
fn load_lsp_enriched_marker(state: &DaemonState) {
    let Ok(bytes) = std::fs::read(lsp_enriched_marker_path(state)) else {
        return;
    };
    let Ok(files) = serde_json::from_slice::<Vec<String>>(&bytes) else {
        return;
    };
    if files.is_empty() {
        return;
    }
    if !graph_holds_language_server_relations(state) {
        warn!(
            marked = files.len(),
            "ignoring the language-server enrichment marker: this graph holds none of the relations it records, so the files it marks are swept again"
        );
        return;
    }
    if let Ok(mut marked) = state.lsp_enriched_files.lock() {
        marked.extend(files);
    }
}

/// Whether this graph still holds any relation a language server produced.
fn graph_holds_language_server_relations(state: &DaemonState) -> bool {
    state
        .graph
        .to_snapshot()
        .relations
        .values()
        .any(|relation| relation.origin == kin_model::RelationOrigin::Lsp)
}

/// Record that a sweep's files are DURABLE, and persist the set once.
///
/// This was written per FILE, as the sweep finished each one, so that a killed
/// pass resumed rather than restarted. That ordering records the wrong fact.
/// The marker's only reader skips a file it names, so what it must mean is "the
/// enrichment for this file is durable", and per-file it meant "this file was
/// visited". A sweep whose publication then failed left every file marked and
/// the next sweep skipped them, permanently, behind a clean log.
///
/// The pre-existing mitigation does not close that: `load_lsp_enriched_marker`
/// discards the marker only when `graph_holds_language_server_relations` is
/// false, and that helper is an `.any()` over the snapshot. Any single surviving
/// Lsp relation, from an earlier sweep or from the incremental path, keeps the
/// marker and with it the skip.
///
/// So the set is written once, after publication succeeds. Resume-after-kill
/// degrades in the correct direction: a hard kill now re-sweeps, which is right,
/// because a hard kill did not publish either.
/// The marker generation a pass starting now would be recording against.
///
/// Read once when a pass takes its entity snapshot and carried to its tail,
/// never read at the tail: the whole point is to notice that the set moved
/// between the two.
pub(crate) fn current_marker_epoch(state: &DaemonState) -> u64 {
    state
        .lsp_enriched_marker_epoch
        .load(std::sync::atomic::Ordering::SeqCst)
}

/// Persist the enrichment marker set for this store.
///
/// Called ONLY with the `lsp_enriched_files` guard held by the caller, so the
/// in-memory set and its durable record move together. Two writers that release
/// before they persist can land in either order, and the losing order
/// reintroduces at the next daemon start exactly the skips the winner retired.
///
/// One write site for both the marking path and the merge's retirement, which is
/// also what keeps this file's raw filesystem touches to the three the
/// zero-file-search allowlist accounts for.
fn persist_enriched_marker(state: &DaemonState, files: &[String]) {
    if let Ok(bytes) = serde_json::to_vec(files) {
        let _ = std::fs::write(lsp_enriched_marker_path(state), bytes);
    }
}

pub(crate) fn mark_files_enriched(state: &DaemonState, files: &[String], captured_epoch: u64) {
    if files.is_empty() {
        return;
    }
    {
        let Ok(mut marked) = state.lsp_enriched_files.lock() else {
            return;
        };
        // Read INSIDE the guard the insert happens under, and never before it.
        // Read outside, a pass could satisfy this comparison, wait while a
        // merge advanced the generation and cleared the set, and then insert
        // its stale marks beneath that clear. That is the silent skip this
        // whole rule exists to end, so the generation and the set move as one.
        let epoch = state
            .lsp_enriched_marker_epoch
            .load(std::sync::atomic::Ordering::SeqCst);
        if epoch != captured_epoch {
            warn!(
                files = files.len(),
                captured_epoch,
                epoch,
                "not recording these files as enriched: the marker set was invalidated after \
                 this pass started, so its answers describe a graph that has since moved"
            );
            return;
        }
        for file in files {
            marked.insert(file.clone());
        }
        // Written INSIDE the guard, not after it. Written after, an old pass's
        // snapshot could reach the file behind the cleared write a merge just
        // made, and the next daemon would load the stale skips straight back.
        persist_enriched_marker(state, &marked.iter().cloned().collect::<Vec<_>>());
    }
}

/// Retire the enrichment marker for files a reconcile just changed.
///
/// The marker means "the enrichment for this file is durable", and an edit that
/// re-derives the file's declarations makes that false: the language-server
/// answers behind those edges were taken at positions the edit moved, and the
/// entities they were installed on may no longer be the ones the graph carries.
/// Nothing retired an entry before this, so once a file was swept it was skipped
/// by every later sweep for the life of the store.
///
/// That is what made the FIR-2598 loss permanent and what made the recovery lie.
/// A 26-line docstring commit on `psf/requests` cost the store 11 `Calls` edges
/// and one `Overrides` edge, and the `kin daemon sweep` a user runs next
/// finished in 518 ms reporting "enriched 37/37 files" over 37 files it skipped
/// without asking a language server anything. A no-op that reports full coverage
/// in half a second reads exactly like a sweep that did the work.
///
/// Retiring costs one file's re-enrichment on the next sweep and is the cheap
/// direction to be wrong in, which is the same asymmetry
/// [`load_lsp_enriched_marker`] is built on: a wrong skip is silent and loses
/// the answers, a wrong re-sweep only costs time. The persisted set is rewritten
/// so a restart does not reload the entry this just dropped.
pub(crate) fn retire_enrichment_marker(state: &DaemonState, files: &[String]) {
    if files.is_empty() {
        return;
    }
    let snapshot = {
        let Ok(mut marked) = state.lsp_enriched_files.lock() else {
            return;
        };
        let mut retired = 0usize;
        for file in files {
            if marked.remove(file) {
                retired += 1;
            }
        }
        if retired == 0 {
            return;
        }
        marked.iter().cloned().collect::<Vec<_>>()
    };
    debug!(
        files = files.len(),
        "retired the enrichment marker for edited files; the next sweep re-enriches them"
    );
    if let Ok(bytes) = serde_json::to_vec(&snapshot) {
        let _ = std::fs::write(lsp_enriched_marker_path(state), bytes);
    }
}

/// Publish that the cold sweep this worker was running has ended.
///
/// Extracted from the worker's own tail so the daemon has one named place where
/// a sweep finishes. Every caller of a sweep waits on `lsp_sweeps_completed`
/// rather than on `lsp_sweep_running`, because polling `running` alone races
/// the worker, so the two have to move together and this is where they do.
///
/// Marked complete even when the loop broke early on shutdown or a supervisor
/// halt, which is the behaviour the tail already had: a waiter blocked on a
/// counter that only advances on a clean finish would wait out its whole budget
/// on a sweep that already stopped.
pub(crate) fn complete_lsp_sweep(state: &DaemonState, files_blocked: u64) {
    state
        .lsp_sweep_running
        .store(false, std::sync::atomic::Ordering::SeqCst);
    state
        .lsp_sweeps_completed
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    state
        .lsp_sweep_files_blocked
        .store(files_blocked, std::sync::atomic::Ordering::SeqCst);
    // A merge admitted while this pass ran could not be covered by it, because
    // the pass had already taken its entity, file and target snapshot. Its
    // demand waited here rather than being queued beside this one, so that a
    // caller waiting on `lsp_sweeps_completed` could not see the wrong pass
    // finish. Drained after the running flag clears, so the queue accepts it.
    drain_pending_lsp_sweep(state);
}

/// Hand the worker a sweep a merge asked for while a pass was running, if the
/// queue will take one now.
///
/// The bit is RESTORED when the queue refuses. `queue_lsp_sweep` answers false
/// for a FULL channel exactly as it does for a closed one, and consuming the bit
/// while ignoring that answer threw the demand away in the one case it exists
/// for.
///
/// Called at the worker's receive boundary as well as at a sweep's tail, and the
/// receive boundary is the one that makes it converge: the tail runs only when a
/// sweep COMPLETES, so a queue full of incremental work with no sweep queued
/// would drain message by message while the demand sat in the bit forever. At
/// the boundary the worker has just taken a message, so the next attempt has
/// room.
pub(crate) fn drain_pending_lsp_sweep(state: &DaemonState) {
    if state.take_pending_lsp_sweep() && !state.queue_lsp_sweep() {
        state
            .lsp_sweep_pending
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Retire every enrichment marker this store holds, because a merge changed
/// what the files they name can bind to.
///
/// The marker means "the enrichment for this file is durable", and the sweep
/// skips a marked file before it asks a language server anything. A merge makes
/// that claim false for files nothing edited: a caller on one branch and its
/// callee on the other produce an edge that exists only once the merge exists,
/// and the caller's file is unchanged by the merge, was legitimately marked
/// when it was swept, and is skipped by the sweep the merge queues. Retiring
/// only the files the merge changed does not close it, because the answer that
/// went stale is a cross-file one whose target moved elsewhere.
///
/// So the whole set goes. It costs the merge's own sweep one re-derivation of
/// this store and is the cheap direction to be wrong in, the same asymmetry
/// [`load_lsp_enriched_marker`] and [`retire_enrichment_marker`] are already
/// built on: a wrong skip is silent and loses the answers, a wrong re-sweep
/// only costs time.
pub(crate) fn retire_enrichment_evidence_for_merge(state: &DaemonState) {
    let retired = {
        // One critical section, and the same lock taken first by every writer
        // of this evidence. Bumping outside it would let a pass's tail read the
        // old generation, block here, and then insert beneath the clear below,
        // which is the interleaving the generation exists to refuse.
        let Ok(mut marked) = state.lsp_enriched_files.lock() else {
            return;
        };
        // Bumped unconditionally, and before the clear, because what a merge
        // invalidates is not only what is marked at this instant: a sweep
        // already in flight is holding the files it is about to mark, derived
        // from language-server answers taken before this merge existed, and an
        // empty marker set right now does not mean there is nothing to
        // invalidate.
        state
            .lsp_enriched_marker_epoch
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let retired = marked.len();
        marked.clear();
        if retired > 0 {
            persist_enriched_marker(state, &[]);
        }
        retired
    };
    if retired > 0 {
        debug!(
            files = retired,
            "retired every enrichment marker for a published merge; the sweep it queued \
             re-derives them"
        );
    }
}

/// The batch size one embedding pass may use under a pressure verdict.
///
/// Shrinking rather than refusing is the whole reason `Elevated` exists as a
/// separate level. An embedding pass holds a batch of vectors and the model
/// that produced them, and the batch is the part that scales with the number
/// this picks; a quarter of it is a quarter of the transient peak, and the pass
/// still converges, just more slowly. The floor of one keeps a shrink from
/// becoming a silent refusal, which is the failure mode of every size knob that
/// is allowed to reach zero.
///
/// Pure, so the rule is testable without an embedder.
fn embed_batch_under_pressure(
    configured: usize,
    verdict: &kin_core::memory_pressure::Verdict,
) -> usize {
    match verdict {
        kin_core::memory_pressure::Verdict::Shrink { .. } => (configured / 4).max(1),
        kin_core::memory_pressure::Verdict::Proceed
        | kin_core::memory_pressure::Verdict::Refuse { .. } => configured,
    }
}

/// One row of the host's process table, in the four fields a footprint needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessRow {
    pub(crate) pid: u32,
    pub(crate) parent: Option<u32>,
    /// Whether the host reported this row as a THREAD of `parent` rather than
    /// as a process of its own.
    ///
    /// Linux lists a process's threads under `/proc/<pid>/task` and `sysinfo`
    /// returns them from `processes()` beside real processes, each with its own
    /// tid as a pid and its owning process as its parent. Nothing in the shape
    /// of such a row says it is not a process, which is the whole of FIR-2823:
    /// a thread shares its process's address space, so `/proc/<tid>/smaps_rollup`
    /// answers with the WHOLE process's proportional set, and charging one row
    /// per thread multiplies a daemon's footprint by its thread count.
    pub(crate) is_thread: bool,
    /// What this process contributes to what the container is charged: a
    /// proportional or private figure, never a resident set. See
    /// [`kin_daemon_spawn::process_footprint_bytes`] for what each platform
    /// publishes and why summing resident sets is the defect FIR-2653 names.
    pub(crate) footprint_bytes: u64,
}

/// Fold a process table into the footprint of the tree rooted at `root`.
///
/// Pure over the table, because this is the rule the whole budget rests on and
/// a rule that can only be exercised by starting a language server is a rule
/// nobody tests. Descendants at every depth, not just direct children: a
/// language server that spawns a worker is still Kin's memory, charged to the
/// same container, and stopping at depth one would reintroduce the blindness
/// one level down.
///
/// Adding the rows up is only meaningful because each row is already
/// proportional. Summing resident sets here charged every process the whole of
/// every page it shared with its siblings, which is FIR-2653: the sum tracked
/// how many descendants there were rather than any memory anyone held, and it
/// reported 25.3 GiB inside a container that could hold 12.
///
/// A table whose parent links form a cycle is malformed and cannot be walked,
/// so the visited set is not an optimisation. Without it a two-process loop
/// hangs the daemon inside its own back-off check, which is the least
/// forgivable place to hang.
///
/// A root absent from the table reports its own bytes as zero rather than
/// refusing to answer, because the descendants are still real and a caller that
/// got nothing would fall back to the pre-budget behaviour on a reading that
/// mostly succeeded.
///
/// A row the host reported as a THREAD is not a descendant and is never
/// charged, which is FIR-2823. Threads share one address space, so every one of
/// them reads back the whole process's proportional set, and counting them as
/// children multiplies the process by its thread count rather than measuring
/// anything: the v0.6.1 stranger measured a 1.41 GiB daemon reporting 10.35
/// GiB, its own figure repeated once per thread, which refused background
/// embedding on a repository that had room and left it at 0 of 2116 vectors for
/// the life of the container. Skipping the row outright loses nothing a real
/// child would have contributed, because Linux parents a process forked from a
/// thread to the thread's PROCESS, so no real descendant ever hangs off a tid.
pub(crate) fn tree_footprint_from(
    root: u32,
    rows: &[ProcessRow],
) -> kin_core::memory_pressure::TreeFootprint {
    let mut own_bytes = 0;
    let mut children_bytes = 0u64;
    let mut child_count = 0usize;
    let mut visited = std::collections::HashSet::from([root]);
    let mut frontier = vec![root];
    while let Some(pid) = frontier.pop() {
        if pid == root {
            own_bytes = rows
                .iter()
                .find(|row| row.pid == root)
                .map_or(0, |row| row.footprint_bytes);
        }
        for row in rows.iter().filter(|row| row.parent == Some(pid)) {
            if !visited.insert(row.pid) {
                continue;
            }
            if row.is_thread {
                continue;
            }
            children_bytes = children_bytes.saturating_add(row.footprint_bytes);
            child_count += 1;
            frontier.push(row.pid);
        }
    }
    kin_core::memory_pressure::TreeFootprint {
        own_bytes,
        children_bytes,
        child_count,
        kernel_capped: false,
    }
}

/// How long a sampled footprint is reused before the process table is walked
/// again.
///
/// The reading behind [`pressure_verdict`] is four small file reads; this one
/// walks the host's whole process table, which is milliseconds rather than
/// microseconds and is called from a loop that can turn several times a second.
/// A footprint two seconds old is exactly as good for deciding whether to start
/// a bulk pass, and the cache is what keeps a guard against spending the
/// machine from becoming a way of spending it.
const FOOTPRINT_SAMPLE_INTERVAL: Duration = Duration::from_secs(2);

/// This daemon's tree footprint, sampled at most once per
/// [`FOOTPRINT_SAMPLE_INTERVAL`].
///
/// `None` when the process table could not be read at all, which keeps the
/// P1 rule on this axis too: a daemon that cannot measure itself decides
/// exactly as it did before the budget existed.
fn sample_tree_footprint() -> Option<kin_core::memory_pressure::TreeFootprint> {
    static LAST: std::sync::OnceLock<
        std::sync::Mutex<Option<(Instant, Option<kin_core::memory_pressure::TreeFootprint>)>>,
    > = std::sync::OnceLock::new();
    let cell = LAST.get_or_init(|| std::sync::Mutex::new(None));
    let mut guard = cell.lock().ok()?;
    if let Some((taken, footprint)) = guard.as_ref() {
        if taken.elapsed() < FOOTPRINT_SAMPLE_INTERVAL {
            return *footprint;
        }
    }
    let sampled = walk_process_table();
    *guard = Some((Instant::now(), sampled));
    sampled
}

/// Walk the host's process table and fold this process's tree out of it.
///
/// The pid comes from `sysinfo::get_current_pid` rather than from `std`, for
/// the reason `commit_liveness` gives: the zero-file-search guard reads a
/// `process::`-prefixed path as a subprocess launch, and the crate's own
/// accessor states the intent without arguing with a guard that is right to be
/// blunt.
fn walk_process_table() -> Option<kin_core::memory_pressure::TreeFootprint> {
    let (me, rows) = current_process_rows()?;
    if rows.is_empty() {
        return None;
    }
    // A daemon that cannot measure ITSELF has measured nothing, and reporting
    // the descendants alone would publish a number smaller than the process
    // publishing it. That is the same answer an unreadable process table gives,
    // and it leaves the budget axis out of the decision rather than deciding on
    // a figure nobody could take.
    if !rows
        .iter()
        .any(|row| row.pid == me && row.footprint_bytes > 0)
    {
        return None;
    }
    let folded = tree_footprint_from(me, &rows);
    // Held to what the kernel says this container is charged, so the figure a
    // reader sees beside a cap can never exceed it. Off a cgroup there is no
    // such ceiling and the reading stands as measured.
    Some(folded.clamped_to(kin_daemon_spawn::cgroup_memory().current_bytes))
}

/// This process's pid and the host's process table as rows the fold can take.
///
/// Split from the fold above it so the marking can be checked against a real
/// host. The fold's refusal to charge a thread is only worth anything if
/// something actually marks one, and that join cannot be seen from either side
/// alone: a `thread_kind()` that never answered `Some` would leave the fold's
/// rule dead and every synthetic test still green, which is exactly how
/// FIR-2823 would come back.
fn current_process_rows() -> Option<(u32, Vec<ProcessRow>)> {
    let me = sysinfo::get_current_pid().ok()?.as_u32();
    let mut system = sysinfo::System::new();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::All,
        true,
        sysinfo::ProcessRefreshKind::nothing().with_memory(),
    );
    let rows = system
        .processes()
        .iter()
        .map(|(pid, process)| {
            // `thread_kind()` is `Some` exactly for the `/proc/<pid>/task`
            // entries Linux publishes beside real processes, and `None` for a
            // process on every platform. A thread is marked rather than dropped
            // here so the rule that refuses to charge it lives in the fold,
            // where the budget rests on it and a synthetic table can exercise
            // it.
            let is_thread = process.thread_kind().is_some();
            ProcessRow {
                pid: pid.as_u32(),
                parent: process.parent().map(|parent| parent.as_u32()),
                is_thread,
                // Not read for a thread: `/proc/<tid>/smaps_rollup` answers
                // with the whole owning process's proportional set, so the
                // figure would be both wrong and, on a large address space,
                // expensive to be wrong with.
                footprint_bytes: if is_thread {
                    0
                } else {
                    row_footprint_bytes(pid.as_u32(), process)
                },
            }
        })
        .collect::<Vec<_>>();
    Some((me, rows))
}

/// What one row of the process table contributes, in bytes.
///
/// Linux and macOS answer through `kin-daemon-spawn`, which reads a
/// proportional or private figure rather than a resident set. Windows has such
/// a figure too and `sysinfo` already carries it under a name that describes
/// the API rather than the number: `virtual_memory()` is
/// `PROCESS_MEMORY_COUNTERS_EX.PrivateUsage`, private commit, which by
/// definition shares no page with another process. Resident set, which is what
/// `memory()` returns on every platform, is the one figure that must not be
/// summed here.
///
/// A process the reader could not open contributes zero. On the platforms
/// above that means the pid died between the walk and the read, or belongs to
/// another user, and a daemon's own descendants are never the second; the
/// caller separately refuses to publish anything when the ROOT is the row that
/// could not be read.
fn row_footprint_bytes(pid: u32, process: &sysinfo::Process) -> u64 {
    #[cfg(windows)]
    {
        let _ = pid;
        process.virtual_memory()
    }
    #[cfg(not(windows))]
    {
        let _ = process;
        kin_daemon_spawn::process_footprint_bytes(pid).unwrap_or(0)
    }
}

/// This daemon's standing against its own budget, when both halves are readable.
///
/// The ceiling comes from the same reading [`pressure_verdict`] takes, so the
/// derived budget on a capped container is derived from the cap rather than
/// from the host underneath it.
fn budget_standing(
    pressure: &kin_core::memory_pressure::MemoryPressure,
) -> Option<kin_core::memory_pressure::BudgetStanding> {
    let footprint = sample_tree_footprint()?;
    // The reading's own ceiling when it has one, and the machine's otherwise.
    // A pinned pressure level carries no figures by design, and deriving the
    // budget from that absence would let the test lever switch the budget off
    // rather than exercise it.
    let ceiling = pressure
        .reading()
        .map(|reading| reading.limit_bytes)
        .or_else(kin_core::memory_pressure::ceiling_bytes);
    let budget = kin_core::memory_pressure::FootprintBudget::resolve(ceiling)?;
    Some(kin_core::memory_pressure::BudgetStanding { footprint, budget })
}

/// What host memory pressure says about one piece of heavy work, right now.
///
/// One function so every consultation in this daemon reads the same machine
/// through the same thresholds. The reading itself is four small pseudo-file
/// reads on Linux and two syscalls on macOS, so this is safe to call at the top
/// of a loop; it is deliberately not called per file or per entity, where the
/// cost would start to matter and the answer could not change fast enough to
/// earn it.
pub(crate) fn pressure_verdict(work: kin_core::memory_pressure::HeavyWork) -> PressureCall {
    let pressure = kin_core::memory_pressure::read();
    let thresholds = kin_core::memory_pressure::Thresholds::from_env();
    let standing = budget_standing(&pressure);
    let host_level = pressure.level_under(&thresholds);
    let level = standing.as_ref().map_or(host_level, |standing| {
        host_level.max(standing.level_under(&thresholds))
    });
    PressureCall {
        level,
        verdict: kin_core::memory_pressure::Verdict::decide(
            work,
            &pressure,
            standing.as_ref(),
            &thresholds,
        ),
        standing,
    }
}

/// One consultation: what was measured, and what that means for this work.
pub(crate) struct PressureCall {
    pub(crate) level: kin_core::memory_pressure::PressureLevel,
    pub(crate) verdict: kin_core::memory_pressure::Verdict,
    /// What this daemon's own tree was holding when the call was made, when it
    /// could be measured. Carried so a caller can publish the standing without
    /// walking the process table a second time.
    pub(crate) standing: Option<kin_core::memory_pressure::BudgetStanding>,
}

/// How often this daemon republishes what it is holding.
///
/// Slower than it samples, because the record exists so `kin status` and
/// `kin doctor` can answer without asking a daemon, not so the store has a
/// time series. Thirty seconds keeps the published standing inside the freshness
/// window every reader judges it by, at one small write per half minute.
const FOOTPRINT_PUBLISH_INTERVAL: Duration = Duration::from_secs(30);

/// Publish this daemon's standing against its budget, on a cadence.
///
/// Called from every point that already took a pressure call, so the standing
/// keeps up with the daemon's own work without a task of its own to schedule,
/// idle-shutdown against, or leak. A level change publishes at once: the rung
/// is the part a reader acts on, and delaying it by up to half a minute would
/// be the one field worth having promptly.
/// When this daemon last published a standing, and at what level.
///
/// Hoisted out of [`publish_footprint_standing`] so the idle path can ask
/// whether the interval alone owes a publish WITHOUT paying for a pressure
/// read first. That question has to be cheap: it is asked on a tick that found
/// nothing to do, at the loop's poll cadence.
static FOOTPRINT_LAST_PUBLISH: std::sync::OnceLock<
    std::sync::Mutex<Option<(Instant, kin_core::memory_pressure::PressureLevel)>>,
> = std::sync::OnceLock::new();

fn footprint_last_publish(
) -> &'static std::sync::Mutex<Option<(Instant, kin_core::memory_pressure::PressureLevel)>> {
    FOOTPRINT_LAST_PUBLISH.get_or_init(|| std::sync::Mutex::new(None))
}

/// Whether the interval alone owes a publish.
///
/// Pure over the one fact that decides it, so the cadence is gradeable without
/// a daemon, a clock or a process table. `None` is "never published", which is
/// owed: a store whose daemon has published nothing has no standing to read.
fn interval_owes_publish(since_last: Option<Duration>) -> bool {
    match since_last {
        None => true,
        Some(elapsed) => elapsed >= FOOTPRINT_PUBLISH_INTERVAL,
    }
}

/// Whether a publish is owed, over the two facts that decide it.
///
/// A level change publishes immediately because the number a reader acts on has
/// moved; otherwise the interval decides.
fn publish_is_owed(since_last: Option<Duration>, level_changed: bool) -> bool {
    level_changed || interval_owes_publish(since_last)
}

/// Publish a standing on a tick that found nothing to admit.
///
/// The defect this exists for, measured on 2026-08-29 into 2026-08-30: the
/// reconciliation loop returns early at its empty-pending-events guard, well
/// above the publish at the end of the tick, so a store nobody is editing
/// published no standing from the ambient tick at all. On a host with no
/// language server nothing else publishes either, since the enrichment sweep
/// is what covers that case elsewhere, and the record simply stops advancing
/// for the life of the daemon.
///
/// That is the wrong contract twice over. Memory pressure moves with nothing on
/// disk moving, and a daemon sitting quiet on a large repository is exactly
/// when its standing matters most: the reader wanting it is the one deciding
/// whether this machine can serve the store at all.
///
/// The interval is checked BEFORE the pressure read rather than after, which is
/// the whole reason this is a separate function. `pressure_verdict` documents
/// itself as safe at the top of a loop, and it is, but "safe" is not "free" at
/// a hundred millisecond poll, and the answer it would return is thrown away on
/// twenty-nine of every thirty seconds.
pub(crate) fn publish_footprint_standing_on_idle_tick(state: &DaemonState) {
    let since_last = match footprint_last_publish().lock() {
        Ok(guard) => guard.as_ref().map(|(published, _)| published.elapsed()),
        // A poisoned lock is not a reason to publish; the busy path holds the
        // same lock and will report its own failure.
        Err(_) => return,
    };
    if !interval_owes_publish(since_last) {
        return;
    }
    let call = pressure_verdict(kin_core::memory_pressure::HeavyWork::AmbientAdmission);
    publish_footprint_standing(state, &call);
}

pub(crate) fn publish_footprint_standing(state: &DaemonState, call: &PressureCall) {
    let Some(standing) = call.standing.as_ref() else {
        return;
    };
    let cell = footprint_last_publish();
    let Ok(mut guard) = cell.lock() else {
        return;
    };
    let (since_last, level_changed) = match guard.as_ref() {
        Some((published, level)) => (Some(published.elapsed()), *level != call.level),
        None => (None, false),
    };
    if !publish_is_owed(since_last, level_changed) {
        return;
    }
    *guard = Some((Instant::now(), call.level));
    drop(guard);
    kin_core::memory_pressure::DaemonFootprint::record(
        state.layout.root(),
        standing,
        call.level,
        std::process::id(),
    );
}

/// Serialize the daemon's only production pressure-record writer and clearer.
static PRESSURE_REFUSAL_RECORD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Publish a pressure refusal where the surfaces outside this process can read
/// it, and log it here.
///
/// Both halves, because neither is enough on its own. The log line is what an
/// operator reading `daemon.log` after the fact needs, and the record is what
/// `kin doctor`, `kin graph status` and the MCP envelope read on their own next
/// run. The sweep circuit spent two releases as a WARN nobody saw, which is
/// exactly the mistake not to repeat here.
pub(crate) fn disclose_pressure_refusal(
    state: &DaemonState,
    work: kin_core::memory_pressure::HeavyWork,
    call: &PressureCall,
    reason: &str,
) {
    warn!(
        work = work.id(),
        pressure = call.level.as_str(),
        "{reason} {}",
        kin_core::memory_pressure::PRESSURE_REMEDY
    );
    let _record_guard = PRESSURE_REFUSAL_RECORD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    kin_core::memory_pressure::PressureRefusal::record(
        state.layout.root(),
        work,
        call.level,
        reason,
    );
}

/// Whether the durable refusal is for the exact work that just completed.
///
/// Missing and future work ids never match. A completion has authority to
/// retire its own disclosure and no other producer's.
fn pressure_refusal_matches_work(
    refusal: Option<&kin_core::memory_pressure::PressureRefusal>,
    completed_work: kin_core::memory_pressure::HeavyWork,
) -> bool {
    refusal.is_some_and(|refusal| refusal.work == completed_work.id())
}

/// Retire this work's pressure refusal after the work reaches its completion
/// boundary.
///
/// The same lock serializes the daemon's only production writer. The core
/// store removes the exact key and atomically republishes every other known or
/// future-work refusal, so one producer cannot erase another's outstanding
/// disclosure.
pub(crate) fn clear_pressure_refusal_for_work(
    state: &DaemonState,
    completed_work: kin_core::memory_pressure::HeavyWork,
) -> bool {
    let _record_guard = PRESSURE_REFUSAL_RECORD_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    kin_core::memory_pressure::PressureRefusal::clear_for_work(state.layout.root(), completed_work)
}

/// Forget a spoken pressure level only when its durable refusal was retired.
///
/// Completion is a lifecycle boundary, not merely another nominal sample. If
/// this latch survives the retirement, a later backlog refused at the same
/// pressure level is silently treated as already disclosed even though there
/// is no longer a record for MCP or CLI readers to see.
fn pressure_announcement_after_retirement(
    announced: Option<kin_core::memory_pressure::PressureLevel>,
    retired: bool,
) -> Option<kin_core::memory_pressure::PressureLevel> {
    if retired {
        None
    } else {
        announced
    }
}

/// Whether this refusal must be published for out-of-process readers.
///
/// The level latch suppresses duplicate logging only while the matching
/// durable record still exists. A missing record, or another producer's
/// record, must not suppress a fresh refusal at the same level.
fn pressure_refusal_needs_disclosure(
    announced: Option<kin_core::memory_pressure::PressureLevel>,
    current_level: kin_core::memory_pressure::PressureLevel,
    refusal: Option<&kin_core::memory_pressure::PressureRefusal>,
    work: kin_core::memory_pressure::HeavyWork,
) -> bool {
    announced != Some(current_level) || !pressure_refusal_matches_work(refusal, work)
}

/// Disclose one refused embedding decision and report whether work must stop.
fn disclose_embed_pressure_refusal_if_needed(
    state: &DaemonState,
    announced: &mut Option<kin_core::memory_pressure::PressureLevel>,
    call: &PressureCall,
) -> bool {
    let kin_core::memory_pressure::Verdict::Refuse { reason } = &call.verdict else {
        return false;
    };
    let work = kin_core::memory_pressure::HeavyWork::EmbedBatch;
    let refusal =
        kin_core::memory_pressure::PressureRefusal::read_for_work(state.layout.root(), work);
    if pressure_refusal_needs_disclosure(*announced, call.level, refusal.as_ref(), work) {
        disclose_pressure_refusal(state, work, call, reason);
        *announced = Some(call.level);
    }
    true
}

/// Queue a missing-coverage rebuild only after the machine admits the work.
///
/// The closure is the graph walk that materializes the backlog. Keeping it
/// behind this seam makes the ordering testable: sustained critical pressure
/// retries later without paying for the very walk startup refused to perform.
fn queue_embedding_backfill_under_pressure(
    state: &DaemonState,
    announced: &mut Option<kin_core::memory_pressure::PressureLevel>,
    queue_backfill: impl FnOnce(),
) -> bool {
    let call = pressure_verdict(kin_core::memory_pressure::HeavyWork::EmbedBatch);
    publish_footprint_standing(state, &call);
    if disclose_embed_pressure_refusal_if_needed(state, announced, &call) {
        return false;
    }
    queue_backfill();
    true
}

/// How many consecutive fruitless interrupted sweeps disable the next one.
///
/// Defined in `kin-daemon-spawn` rather than here, because the daemon is the
/// only writer of this tally and three surfaces outside it now have to read the
/// same rule to say the store is suspended. One definition or they drift.
const SWEEP_INTERRUPTION_LIMIT: u32 = kin_daemon_spawn::SWEEP_INTERRUPTION_LIMIT;

/// The count after a sweep that ended the way this tally describes.
///
/// A clean finish resets, because the loop this guards is defined by never
/// finishing. An interruption that still enriched files made progress and is
/// left alone; the pathological case is the sweep that dies before enriching
/// anything, over and over, which is what a store too small for its own sweep
/// produces.
fn next_interruption_count(previous: u32, ended_early: bool, enriched: usize) -> u32 {
    if !ended_early {
        0
    } else if enriched == 0 {
        previous.saturating_add(1)
    } else {
        previous
    }
}

/// Whether the sweep circuit is open, so the next sweep must not be queued.
fn sweep_circuit_open(consecutive_fruitless_interruptions: u32) -> bool {
    kin_daemon_spawn::sweep_circuit_open(consecutive_fruitless_interruptions)
}

/// Read the consecutive-interruption count this store carries.
///
/// Persisted rather than held in memory because the loop it guards spans daemon
/// RESTARTS: a sweep dies, the daemon comes back, queues another sweep at
/// startup, and dies again. One stranger session did that 24 times. An
/// in-memory counter resets on every start and can never see the pattern.
///
/// The read itself moved down to `kin-daemon-spawn` once the CLI and the MCP
/// envelope had to answer the same question. This wrapper stays because every
/// caller in this module holds a `DaemonState` rather than a root.
fn read_sweep_interruptions(state: &DaemonState) -> u32 {
    kin_daemon_spawn::read_sweep_interruptions(state.layout.root())
}

fn write_sweep_interruptions(state: &DaemonState, count: u32) {
    kin_daemon_spawn::write_sweep_interruptions(state.layout.root(), count)
}

/// Where a sweep records that it has begun and not yet ended.
///
/// Everything a sweep says about itself is written after its last file: the
/// publication, the resume marker, the interruption count and the completion
/// line all live in the tail of the loop. The enrichment worker is a detached
/// task that nothing joins, so a daemon whose process ends mid-sweep reaches
/// none of them, and the store keeps no trace that a sweep ever ran. A killed
/// sweep and a sweep that never started are then the same store, which is the
/// half of this that made the loss permanent: nothing downstream can act on a
/// fact nobody recorded.
fn sweep_in_flight_path(state: &DaemonState) -> std::path::PathBuf {
    state.layout.root().join("lsp-sweep-in-flight")
}

/// Record that a cold sweep has begun.
fn sweep_started(state: &DaemonState) {
    let _ = std::fs::write(sweep_in_flight_path(state), b"");
}

/// Record how a cold sweep ended, and that it ended at all.
///
/// One function because they are one fact. A sweep that reaches here has an
/// outcome the count describes, and clearing the in-flight record is what makes
/// the absence of an outcome mean something. Written apart, a future exit could
/// clear the record without counting, and the store would call a killed sweep a
/// finished one.
///
/// Returns the count it wrote, which is what the completion line reports.
fn sweep_finished(state: &DaemonState, ended_early: bool, enriched: usize) -> u32 {
    let counted = next_interruption_count(read_sweep_interruptions(state), ended_early, enriched);
    write_sweep_interruptions(state, counted);
    let _ = std::fs::remove_file(sweep_in_flight_path(state));
    counted
}

/// What a starting daemon does about a cold sweep, given what this store
/// records about the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SweepStartDecision {
    /// Queue a cold sweep.
    Queue,
    /// Queue nothing: this store's last sweeps all died without enriching.
    CircuitOpen { interruptions: u32 },
    /// Queue nothing yet: this machine has no room for the pass that peaked at
    /// 18.2 GB on a one-gigabyte store. Unlike the circuit, this is about the
    /// host and not the store, so it clears by itself when the machine does.
    PressureRefused { reason: String },
}

/// Settle the previous sweep, then decide about this one.
///
/// A sweep killed before its own tail is counted HERE, because it could not
/// count itself. Nothing it did was published or marked, so its outcome is
/// exactly an interruption that enriched nothing, and reading it at startup is
/// the only place the fact is available. Taking the record also clears it, so
/// one kill is counted once however many daemons follow it.
fn decide_sweep_on_start(state: &DaemonState) -> SweepStartDecision {
    let path = sweep_in_flight_path(state);
    if path.exists() {
        let _ = std::fs::remove_file(&path);
        let counted = next_interruption_count(read_sweep_interruptions(state), true, 0);
        write_sweep_interruptions(state, counted);
        warn!(
            consecutive_fruitless_interruptions = counted,
            "the previous language-server sweep did not reach its own end, so it published \
             nothing and recorded nothing; this start counts it and sweeps its files again"
        );
    }
    let interruptions = read_sweep_interruptions(state);
    if sweep_circuit_open(interruptions) {
        return SweepStartDecision::CircuitOpen { interruptions };
    }
    // Asked after the circuit and before the queue, because the two are
    // different facts and the store's own tally is the one that survives a
    // reboot. A machine with no room today says nothing about a store whose
    // sweeps keep dying.
    let call = pressure_verdict(kin_core::memory_pressure::HeavyWork::LspSweep);
    publish_footprint_standing(state, &call);
    if let kin_core::memory_pressure::Verdict::Refuse { reason } = &call.verdict {
        let reason = reason.clone();
        disclose_pressure_refusal(
            state,
            kin_core::memory_pressure::HeavyWork::LspSweep,
            &call,
            &reason,
        );
        return SweepStartDecision::PressureRefused { reason };
    }
    SweepStartDecision::Queue
}

/// Whether a finished sweep may record its files as enriched.
///
/// Marking is safe when the sweep published, and also when it produced nothing
/// to publish: a file that yielded no relations has nothing that can be lost, so
/// re-sweeping it forever would be waste rather than safety. Everything else
/// stays unmarked and is swept again.
///
/// Losing a relation is the third case, and it used to be invisible here.
/// `published` says the snapshot reached disk, not that every relation the
/// sweep offered reached the graph, and marking a file enriched is what stops
/// it ever being swept again: `file_already_enriched` skips it from then on. So
/// a pass that offered a relation the graph does not hold and then saved
/// cleanly would have written off the loss permanently, with the marker
/// asserting the file was done.
///
/// This is the repair. There is nothing to fix in place, because the pass
/// cannot know why the graph declined; what it can do is decline to say the
/// file is finished, so the next sweep offers those relations again. A sweep
/// that lost nothing marks and moves on, and one that lost something leaves the
/// work where the next pass will find it.
fn sweep_marker_is_durable(written: EnrichmentWrite, published: bool) -> bool {
    written.lost() == 0 && (written.published == 0 || published)
}

/// How long a cold sweep waits for the embedding backfill before starting
/// anyway.
///
/// A ceiling on the ordering rather than an amount of waiting: a backfill that
/// drains in ninety seconds holds the sweep for ninety seconds, and only one
/// still working past this bound loses its exclusivity. Ten minutes because the
/// backfill this was written for took about five on the store it was measured
/// on, and a bound shorter than the work it orders would order nothing. The
/// sweep starting late is a slower convergence; the two running together is a
/// daemon that dies and loses both.
const SWEEP_BACKFILL_WAIT_BOUND: Duration = Duration::from_secs(600);

/// How long the backfill may hold the sweep back while making no progress.
///
/// The wait bound alone is not enough. A backfill wedged on a refused vector
/// checkpoint neither drains nor errors, so without this the sweep would spend
/// the whole ten minutes waiting on a count that was never going to move.
/// Progress is a fall in the pending count, so a backfill that is landing
/// batches resets this on every one of them and is never cut short by it.
const SWEEP_BACKFILL_STALL_BOUND: Duration = Duration::from_secs(90);

/// How often the gate re-reads the store's pending-embedding count.
const SWEEP_BACKFILL_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Why the cold sweep was released to start, which is what the gate logs.
///
/// Five outcomes rather than a bool because an operator reading the daemon log
/// needs to tell a sweep that waited its turn from one that gave up on a
/// backfill going nowhere. The first two are the fast paths that keep an
/// already-embedded store behaving exactly as it did before this gate existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepStartReason {
    /// The store had nothing left to embed, so there was nothing to wait for.
    NothingPending,
    /// No worker will drain a backlog on this boot, so waiting would never end.
    BackfillNotRunning,
    /// The backfill finished while the sweep waited.
    BackfillDrained,
    /// The backfill stopped making progress for the stall bound.
    BackfillStalled,
    /// The backfill was still working when the whole wait bound expired.
    WaitBoundExpired,
}

impl SweepStartReason {
    fn as_str(self) -> &'static str {
        match self {
            SweepStartReason::NothingPending => "nothing-pending",
            SweepStartReason::BackfillNotRunning => "backfill-not-running",
            SweepStartReason::BackfillDrained => "backfill-drained",
            SweepStartReason::BackfillStalled => "backfill-stalled",
            SweepStartReason::WaitBoundExpired => "wait-bound-expired",
        }
    }
}

/// What the gate does on one look at the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SweepGateStep {
    /// Keep holding the sweep back.
    Wait,
    /// Release the sweep, for this reason.
    Start(SweepStartReason),
}

/// One look at the embedding backfill, in the terms the gate decides on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BackfillLook {
    /// Whether any worker will drain a backlog on this boot. False when an
    /// operator opted out, and false when the graph authority has no durable
    /// vector-sidecar contract to persist progress into.
    running: bool,
    /// Entities and artifacts the vector index still lacks vectors for.
    pending: usize,
    /// Whether the gate has already held the sweep back at least once. What
    /// separates a store that arrived converged from one that drained while
    /// the sweep waited, which read the same without it.
    held: bool,
    /// How long the gate has been holding the sweep back.
    waited: Duration,
    /// How long since the pending count last fell.
    since_progress: Duration,
}

/// Whether the sweep may start yet, given what the backfill is doing.
///
/// Pure, and separate from the loop that calls it, because the rule is what
/// this change is about and a rule embedded in an async loop with two clocks
/// can only be tested by waiting out its bounds.
fn sweep_gate_step(
    look: BackfillLook,
    wait_bound: Duration,
    stall_bound: Duration,
) -> SweepGateStep {
    if look.pending == 0 {
        return SweepGateStep::Start(if look.held {
            SweepStartReason::BackfillDrained
        } else {
            SweepStartReason::NothingPending
        });
    }
    if !look.running {
        return SweepGateStep::Start(SweepStartReason::BackfillNotRunning);
    }
    if look.waited >= wait_bound {
        return SweepGateStep::Start(SweepStartReason::WaitBoundExpired);
    }
    if look.since_progress >= stall_bound {
        return SweepGateStep::Start(SweepStartReason::BackfillStalled);
    }
    SweepGateStep::Wait
}

/// Hold a cold sweep until the embedding backfill has had the process to
/// itself, and report why it was released.
///
/// Both passes used to be peer spawns with nothing ordering them, and on a
/// full-history store in a memory-capped container that is what killed the
/// daemon: the sweep reopens repository authority and rebuilds the graph from
/// snapshot while the backfill holds a batch of vectors, and neither is small.
/// The backfill goes first because it checkpoints durably as it goes, so a kill
/// costs it the batch in flight rather than the pass; everything the sweep
/// makes durable happens after its last file, so a kill costs the sweep all of
/// it.
///
/// The bounds are parameters so the loop itself can be tested rather than only
/// the rule it applies; production passes the constants above.
async fn await_backfill_before_sweep<F>(
    running: bool,
    mut pending: F,
    wait_bound: Duration,
    stall_bound: Duration,
    poll: Duration,
) -> SweepStartReason
where
    F: FnMut() -> usize,
{
    let started = Instant::now();
    let mut last_progress = started;
    let mut lowest = usize::MAX;
    let mut held = false;
    loop {
        let current = pending();
        if current < lowest {
            lowest = current;
            last_progress = Instant::now();
        }
        let now = Instant::now();
        let look = BackfillLook {
            running,
            pending: current,
            held,
            waited: now.duration_since(started),
            since_progress: now.duration_since(last_progress),
        };
        match sweep_gate_step(look, wait_bound, stall_bound) {
            SweepGateStep::Start(reason) => return reason,
            SweepGateStep::Wait => {
                held = true;
                tokio::time::sleep(poll).await;
            }
        }
    }
}

/// The ordering between the cold sweep and the embedding backfill, which is
/// what FIR-2493 is about.
///
/// Both used to be peer spawns, and the tally tests further down passed
/// throughout while a first boot ran them together. Arithmetic was never the
/// gap. These tests drive the gate's own loop with a synthetic pending count
/// and small bounds, so the rule is exercised rather than the constants.
#[cfg(test)]
mod footprint_cadence_tests {
    use super::{interval_owes_publish, publish_is_owed, FOOTPRINT_PUBLISH_INTERVAL};
    use std::time::Duration;

    /// A quiet tick publishes once the interval has elapsed, and not before.
    ///
    /// The defect: the reconciliation loop returned early at its
    /// empty-pending-events guard, above the publish at the end of the tick, so
    /// a store nobody was editing published no standing from this loop at all.
    /// On a host with no language server nothing else published either, and
    /// `memory_pressure_refusal.py` check 12 spent its whole two minute bound
    /// waiting for a record that could never be minted. Six consecutive
    /// Acceptance runs on main were red on it.
    ///
    /// Graded over the decision rather than over a daemon, so the cadence is
    /// falsifiable without a clock, a process table or a store.
    #[test]
    fn an_idle_tick_is_owed_a_publish_only_once_the_interval_elapses() {
        assert!(
            interval_owes_publish(Some(FOOTPRINT_PUBLISH_INTERVAL)),
            "exactly the interval is elapsed"
        );
        assert!(
            interval_owes_publish(Some(FOOTPRINT_PUBLISH_INTERVAL + Duration::from_secs(1))),
            "past the interval is elapsed"
        );
        // The control, and the half that can fail quietly: a publish on every
        // idle tick would satisfy the assertion above and put a pressure read
        // on the loop's poll cadence.
        assert!(
            !interval_owes_publish(Some(FOOTPRINT_PUBLISH_INTERVAL - Duration::from_millis(1))),
            "one millisecond short of the interval is NOT owed"
        );
        assert!(
            !interval_owes_publish(Some(Duration::from_secs(0))),
            "a publish that just happened is not owed another"
        );
    }

    /// A store whose daemon has published nothing is owed one immediately.
    ///
    /// `None` is not "recently published", it is "no standing exists to read",
    /// and a reader asking what this daemon holds gets nothing until the first
    /// one lands.
    #[test]
    fn a_daemon_that_has_never_published_is_owed_one_at_once() {
        assert!(interval_owes_publish(None));
        assert!(publish_is_owed(None, false));
    }

    /// A level change still publishes before the interval, which is the
    /// behaviour the busy path had and must keep.
    #[test]
    fn a_level_change_publishes_without_waiting_for_the_interval() {
        let recent = Some(Duration::from_secs(1));
        assert!(
            publish_is_owed(recent, true),
            "the number a reader acts on moved, so it publishes"
        );
        assert!(
            !publish_is_owed(recent, false),
            "and an unchanged level one second in still waits"
        );
    }
}

#[cfg(test)]
mod sweep_backfill_gate_tests {
    use super::{
        await_backfill_before_sweep, sweep_gate_step, BackfillLook, SweepGateStep,
        SweepStartReason, SWEEP_BACKFILL_POLL_INTERVAL, SWEEP_BACKFILL_STALL_BOUND,
        SWEEP_BACKFILL_WAIT_BOUND,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// The gate returns the reason the daemon then logs, so asserting on the
    /// returned reason asserts on the log line's content: the `info!` at the
    /// gate's call site takes `reason.as_str()` and nothing else decides it.
    fn reason_is_logged(reason: SweepStartReason) -> &'static str {
        reason.as_str()
    }

    /// A store with work left to embed holds the sweep, and the sweep starts
    /// once the backfill has drained.
    ///
    /// The count starts above zero on purpose. A source that began at zero
    /// would make "the sweep waited" trivially true of any code at all,
    /// including code with the gate deleted, and the test could not fail.
    #[tokio::test]
    async fn pending_embeddings_hold_the_sweep_until_the_backfill_drains() {
        let pending = Arc::new(AtomicUsize::new(3));
        let looks = Arc::new(AtomicUsize::new(0));
        let source = Arc::clone(&pending);
        let counter = Arc::clone(&looks);

        // One entity embedded per look, so the backfill is unmistakably working
        // and the gate has to hold through three of them.
        let reason = await_backfill_before_sweep(
            true,
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                let seen = source.load(Ordering::SeqCst);
                source.store(seen.saturating_sub(1), Ordering::SeqCst);
                seen
            },
            Duration::from_secs(30),
            Duration::from_secs(30),
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(
            reason,
            SweepStartReason::BackfillDrained,
            "a sweep released after waiting must say so; `NothingPending` here would mean the \
             gate let it start beside a backfill that still had work"
        );
        assert_eq!(
            looks.load(Ordering::SeqCst),
            4,
            "three looks with work pending and a fourth that found the backfill drained"
        );
        assert_eq!(
            pending.load(Ordering::SeqCst),
            0,
            "and the backfill really did drain, rather than the gate giving up on it"
        );
        assert_eq!(reason_is_logged(reason), "backfill-drained");
    }

    /// An opted-out backfill releases the sweep at once rather than making it
    /// wait out a bound nothing will satisfy.
    ///
    /// Run against the production constants deliberately. If the rule were
    /// wrong this test would sit for the stall bound and then fail, so the
    /// assertion below is not the only thing that can catch a regression.
    #[tokio::test]
    async fn an_opted_out_backfill_releases_the_sweep_at_once() {
        let looks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&looks);

        let reason = await_backfill_before_sweep(
            false,
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                4096
            },
            SWEEP_BACKFILL_WAIT_BOUND,
            SWEEP_BACKFILL_STALL_BOUND,
            SWEEP_BACKFILL_POLL_INTERVAL,
        )
        .await;

        assert_eq!(
            reason,
            SweepStartReason::BackfillNotRunning,
            "with no worker to drain it, a pending count is not a reason to wait"
        );
        assert_eq!(
            looks.load(Ordering::SeqCst),
            1,
            "one look and no sleep: an opt-out is known before the first poll interval"
        );
        assert_eq!(reason_is_logged(reason), "backfill-not-running");
    }

    /// A backfill still working when the whole wait bound expires loses the
    /// sweep, and the reason says which bound ended it.
    ///
    /// The count falls on every look, so the stall bound can never fire here
    /// and only the total wait bound can end this wait. That is what makes the
    /// assertion about the wait bound rather than about either bound.
    #[tokio::test]
    async fn the_wait_bound_releases_a_sweep_a_working_backfill_is_still_holding() {
        let source = Arc::new(AtomicUsize::new(1_000_000));
        let pending = Arc::clone(&source);

        let reason = await_backfill_before_sweep(
            true,
            move || pending.fetch_sub(1, Ordering::SeqCst),
            Duration::from_millis(50),
            Duration::from_secs(30),
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(
            reason,
            SweepStartReason::WaitBoundExpired,
            "the ordering is a ceiling, not a promise: a backfill that outlasts the bound must \
             not hold the sweep forever"
        );
        assert!(
            source.load(Ordering::SeqCst) > 0,
            "and it must have been released with work still pending, or this proved nothing"
        );
        assert_eq!(reason_is_logged(reason), "wait-bound-expired");
    }

    /// A backfill that stops moving releases the sweep on the stall bound
    /// rather than holding it for the whole wait bound.
    ///
    /// The case the wait bound alone gets wrong: a backfill wedged on a refused
    /// vector checkpoint neither drains nor errors, so its pending count simply
    /// stops falling.
    #[tokio::test]
    async fn a_wedged_backfill_releases_the_sweep_on_the_stall_bound() {
        let reason = await_backfill_before_sweep(
            true,
            || 512,
            Duration::from_secs(30),
            Duration::from_millis(20),
            Duration::from_millis(1),
        )
        .await;

        assert_eq!(
            reason,
            SweepStartReason::BackfillStalled,
            "a count that never falls is a backfill going nowhere, and waiting out the full \
             bound on it delays the sweep for nothing"
        );
        assert_eq!(reason_is_logged(reason), "backfill-stalled");
    }

    /// A store with nothing left to embed sweeps exactly as it did before this
    /// gate existed: released on the first look, having waited for nothing.
    #[tokio::test]
    async fn a_converged_store_is_released_on_the_first_look() {
        let looks = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&looks);

        let reason = await_backfill_before_sweep(
            true,
            move || {
                counter.fetch_add(1, Ordering::SeqCst);
                0
            },
            SWEEP_BACKFILL_WAIT_BOUND,
            SWEEP_BACKFILL_STALL_BOUND,
            SWEEP_BACKFILL_POLL_INTERVAL,
        )
        .await;

        assert_eq!(reason, SweepStartReason::NothingPending);
        assert_eq!(
            looks.load(Ordering::SeqCst),
            1,
            "one look: an already-embedded store must not pay a poll interval for this gate"
        );
    }

    /// The rule itself, at the boundaries the loop can only reach by waiting.
    #[test]
    fn the_gate_holds_a_sweep_while_a_running_backfill_is_inside_both_bounds() {
        let wait = Duration::from_secs(600);
        let stall = Duration::from_secs(90);
        let working = BackfillLook {
            running: true,
            pending: 576,
            held: true,
            waited: Duration::from_secs(300),
            since_progress: Duration::from_secs(5),
        };
        assert_eq!(
            sweep_gate_step(working, wait, stall),
            SweepGateStep::Wait,
            "a backfill halfway through its bound and landing batches keeps the sweep back"
        );
        assert_eq!(
            sweep_gate_step(
                BackfillLook {
                    waited: wait,
                    ..working
                },
                wait,
                stall
            ),
            SweepGateStep::Start(SweepStartReason::WaitBoundExpired),
            "and stops keeping it back the moment the bound is reached, not after it"
        );
        assert_eq!(
            sweep_gate_step(
                BackfillLook {
                    since_progress: stall,
                    ..working
                },
                wait,
                stall
            ),
            SweepGateStep::Start(SweepStartReason::BackfillStalled),
        );
    }

    /// A stall bound at or above the wait bound could never fire, so the wedged
    /// backfill it exists for would hold the sweep for the full ten minutes.
    #[test]
    fn the_stall_bound_can_fire_before_the_wait_bound_it_sits_inside() {
        assert!(
            SWEEP_BACKFILL_STALL_BOUND < SWEEP_BACKFILL_WAIT_BOUND,
            "the stall bound is the inner one; at or above the wait bound it is unreachable"
        );
        assert!(
            SWEEP_BACKFILL_POLL_INTERVAL < SWEEP_BACKFILL_STALL_BOUND,
            "and the gate has to look more than once inside the shorter bound, or it cannot \
             tell a stalled backfill from a working one"
        );
    }
}

/// Whether the sweep has already finished this file.
pub(crate) fn file_already_enriched(state: &DaemonState, file: &str) -> bool {
    state
        .lsp_enriched_files
        .lock()
        .map(|marked| marked.contains(file))
        .unwrap_or(false)
}

/// Column an LSP query should be asked at for one entity, given its signature
/// and the column its declaration starts on.
///
/// The cursor has to sit on the name rather than on the declaration's first
/// byte, and for a dotted name it has to sit on the LAST segment. An entity
/// named `app.handle` whose signature reads `app.handle = function handle(`
/// starts at the `app` token, and `signature.find(name)` returns 0 for it, so
/// the query went to the receiver instead of the member.
///
/// That is not a near miss. Asking a language server for references at a
/// receiver returns everything the object touches, so express minted an
/// all-pairs whole-file fan, and every edge in it was stamped `Lsp` and
/// therefore read as `type_resolved` with no evidence behind it. A caller walk
/// then counted fabricated callees as real ones, which is worse than the
/// missing edge it was meant to supply: a wrong answer wearing the label of a
/// resolved one.
///
/// A name with no dot is unaffected. Its segment offset is zero and the result
/// is exactly what it always was.
fn lsp_query_column(signature: &str, name: &str, start_col: u32) -> u32 {
    let segment_offset = name.rfind('.').map_or(0, |dot| dot + 1);
    if let Some(offset) = signature.find(name) {
        return start_col.saturating_add((offset + segment_offset) as u32);
    }
    // The signature does not spell the dotted name out. Ask for the final
    // segment on its own rather than falling back to the declaration start,
    // which is the receiver again whenever the receiver is what opens the line.
    if segment_offset > 0 {
        if let Some(offset) = signature.find(&name[segment_offset..]) {
            return start_col.saturating_add(offset as u32);
        }
    }
    start_col
}

/// What a cold sweep did with every file it walked.
///
/// The sweep used to report only the files it counted, and it counted a file in
/// exactly two places: one it enriched, and one it skipped as already enriched.
/// Every other way out of the loop was a bare `continue`, so a sweep that could
/// not do anything at all reported `files=0 total_files=66` and called itself
/// complete. On a JavaScript repository with a working language server on PATH
/// that is what a stranger saw at the end of their first conversion, and the
/// zero read as convergence rather than as a sweep that never ran.
///
/// Every exit now lands in one of these fields, and `unaccounted` is what
/// catches the next one that does not.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct SweepTally {
    /// Files the sweep queried a language server about.
    enriched: usize,
    /// Files skipped because this graph already holds server evidence for them.
    already_enriched: usize,
    /// Files whose extension maps to no language this build enriches.
    unsupported_language: usize,
    /// Files whose language server could not be started.
    server_unavailable: usize,
    /// Files whose source could not be loaded from graph authority.
    source_unreadable: usize,
    /// Files whose file-level definitions pass exceeded its wall-clock budget.
    ///
    /// Counted rather than merely logged so the sweep's own completion record
    /// carries it. These files are still visited and still get the per-entity
    /// arm, so they are not blocked; what they lost is the definitions pass.
    definitions_over_budget: usize,
    /// Whether the loop stopped before walking every file, on shutdown or on
    /// the background-work supervisor's verdict.
    ///
    /// Without this the two reasons a file can be missing from the counts are
    /// indistinguishable, and they are opposites: one is a bug in this loop,
    /// the other is this loop being told to stop. The guard below reported the
    /// second as the first, so a SIGTERM at 31 of 37 files logged "an exit from
    /// the sweep loop is not being counted" about six files nothing had failed
    /// to count, and sent its reader hunting a counting bug that did not exist.
    ended_early: bool,
}

impl SweepTally {
    /// What the sweep reports as `files`, and what `/lsp/sweep/status` serves
    /// as `files_done`. Unchanged in meaning: a file the sweep is done with.
    fn files_processed(&self) -> usize {
        self.enriched + self.already_enriched
    }

    /// Files the sweep walked past without being able to do anything.
    fn blocked(&self) -> usize {
        self.unsupported_language + self.server_unavailable + self.source_unreadable
    }

    /// Files the sweep's total holds that no field above accounts for.
    ///
    /// Shared arithmetic for the two questions below; on its own it cannot say
    /// which of them applies, which is exactly the confusion this split fixes.
    fn unreached(&self, total_files: usize) -> usize {
        total_files.saturating_sub(self.files_processed() + self.blocked())
    }

    /// Files the loop never walked because it was told to stop.
    ///
    /// Zero for a sweep that ran to completion. This is a normal outcome, not a
    /// finding: shutdown and the supervisor's halt both stop the loop between
    /// files on purpose, and what was enriched stays durable.
    fn not_visited(&self, total_files: usize) -> usize {
        if self.ended_early {
            self.unreached(total_files)
        } else {
            0
        }
    }

    /// Files that went missing while the loop was still walking.
    ///
    /// This is the guard, not a statistic. A new `continue` added without a
    /// counter shows up here rather than silently deflating `files`. It is zero
    /// for an interrupted sweep by construction, because an interrupted sweep
    /// has not finished walking and its remaining files are `not_visited`.
    fn unaccounted(&self, total_files: usize) -> usize {
        if self.ended_early {
            0
        } else {
            self.unreached(total_files)
        }
    }

    /// Why a sweep enriched nothing, when nothing is what it enriched.
    ///
    /// `None` when the sweep did process files, so a caller can tell a sweep
    /// that converged from one that could not run. The distinction is the whole
    /// point: both used to print the same sentence.
    fn blocked_reason(&self, total_files: usize) -> Option<&'static str> {
        // A sweep that was stopped before it could do anything is not a
        // blocked one, and saying so would send a reader after a language
        // server that was never the problem.
        if total_files == 0 || self.files_processed() > 0 || self.ended_early {
            return None;
        }
        if self.server_unavailable > 0 {
            return Some("no language server could be started for these files");
        }
        if self.source_unreadable > 0 {
            return Some("their source could not be read from graph authority");
        }
        if self.unsupported_language > 0 {
            return Some("this build enriches no language they are written in");
        }
        Some("the sweep reached none of them")
    }
}

/// How long the file-level definitions pass may take for one file.
///
/// The pass had no bound of any kind. It is called at its sweep site as
/// `.await.unwrap_or_default()`, and `locations_at` wraps nothing of its own, so
/// every query inherits only the JSON-RPC client's own 10-second cap and a
/// timeout yields an empty result that lets the loop continue to the NEXT
/// identifier. A file whose language server stops answering therefore costs
/// identifiers times ten seconds rather than failing, which on a large file is
/// hours. Its sibling `enrich_single_entity` caps every query at 5 seconds, so
/// the per-entity arm was bounded and the per-file arm was not.
///
/// 120 seconds is chosen from measurement, not taste. On a converted
/// psf/requests store the whole per-file pass, both arms together, ran to a
/// median of 1.2 s, a p90 of 12.0 s and a maximum of 62.4 s. The budget sits at
/// nearly twice the slowest healthy file, so it cannot truncate work that is
/// merely slow; it exists to turn an unbounded hang into a bounded, counted one.
fn lsp_file_definitions_budget() -> Duration {
    duration_from_env_secs("KIN_DAEMON_LSP_FILE_BUDGET_SECS", Duration::from_secs(120))
}

/// Run the file-level definitions pass under a wall-clock budget.
///
/// A pass that overruns yields the empty result the call site already used for
/// a failed pass, and is counted on the tally so the sweep reports it rather
/// than losing it. Split out from the call site so the budget decision can be
/// tested against a provider that never answers, which is the case that
/// motivated it and the one a live language server will not reproduce on demand.
async fn file_definitions_within_budget<F, E>(
    pass: F,
    budget: Duration,
    file: &str,
    tally: &mut SweepTally,
) -> kin_lsp::file_enrichment::FileEnrichmentResult
where
    F: std::future::Future<
        Output = std::result::Result<kin_lsp::file_enrichment::FileEnrichmentResult, E>,
    >,
{
    match tokio::time::timeout(budget, pass).await {
        Ok(Ok(result)) => result,
        // A pass that failed keeps the behaviour the call site always had.
        Ok(Err(_)) => kin_lsp::file_enrichment::FileEnrichmentResult::default(),
        Err(_) => {
            tally.definitions_over_budget += 1;
            warn!(
                file = %file,
                budget_s = budget.as_secs(),
                "the file-level definitions pass exceeded its budget and was abandoned for \
                 this file; its language server is not answering"
            );
            kin_lsp::file_enrichment::FileEnrichmentResult::default()
        }
    }
}

/// How many relations one enrichment write to the graph carries at most.
///
/// A cold sweep hands its output to the graph one language-server query arm at
/// a time, and every arm opens its own graph-authority mutation, invalidates
/// the spine's cross-repo edges, and writes `vfs_version` to disk. On the
/// psf/requests corpus a sweep enriches 37 files and derives about 4200
/// relations, so a pass costs thousands of mutation batches for one logical
/// unit of work.
///
/// Batching bounds two different quantities at once. The number of authority
/// mutations a sweep opens becomes `ceil(relations / this)` rather than one per
/// arm, and the buffer a pass holds between deriving a relation and writing it
/// never exceeds this many, whatever one file yields. `src/requests/models.py`
/// yields 1167 in a single file.
const ENRICHMENT_WRITE_BATCH: usize = 256;

/// Relations an enrichment pass has derived and has not yet written.
///
/// Bounded on purpose. [`PendingEnrichment::absorb`] hands every full batch to
/// the caller's writer before it returns, so the undrained remainder is always
/// smaller than one batch however many relations arrive at once. A pass that
/// accumulated a whole file, or a whole sweep, would hold a structure whose
/// size is a property of the repository being swept rather than of this code,
/// which is the shape this type exists to refuse.
/// What an enrichment write actually did, as opposed to what it attempted.
///
/// The count this replaces was the write call's own return, and that cannot be
/// trusted for this question. `upsert_relation` inserts the relation into the
/// graph BEFORE its embedding invalidation can fail, so a call that returns
/// `Err` may have published the relation anyway. Counting that as a loss
/// over-reports, and a zero-loss gate built on it would hard-fail a sweep that
/// dropped nothing.
///
/// So `published` is read from the graph rather than inferred from the call:
/// the graph is the truth being written to, and it is the only surface that can
/// separate "never written" from "written, then a later step failed".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct EnrichmentWrite {
    /// Relations the graph holds afterwards, counted from the graph.
    published: usize,
    /// Relations this write was asked to publish.
    offered: usize,
    /// Relations the graph holds whose write still reported an error, which on
    /// this path means embedding invalidation failed after the insert. The
    /// relation is not lost; the endpoints' vectors may be stale. Disclosed
    /// separately because folding it into a green would trade one swallowed
    /// degradation for another.
    vector_stale: usize,
}

impl EnrichmentWrite {
    /// Relations offered that the graph does not hold. The zero-loss number.
    fn lost(&self) -> usize {
        self.offered.saturating_sub(self.published)
    }

    /// A write that published everything it was offered and lost nothing.
    ///
    /// For the buffer test, whose subject is batching rather than outcome: it
    /// asks whether every relation reached the writer, and a writer that always
    /// succeeds is the right stand-in for that question.
    #[cfg(test)]
    fn all_published(count: usize) -> Self {
        Self {
            published: count,
            offered: count,
            vector_stale: 0,
        }
    }
}

impl std::ops::AddAssign for EnrichmentWrite {
    fn add_assign(&mut self, other: Self) {
        self.published += other.published;
        self.offered += other.offered;
        self.vector_stale += other.vector_stale;
    }
}

#[derive(Default)]
struct PendingEnrichment {
    relations: Vec<kin_model::Relation>,
}

impl PendingEnrichment {
    /// How many derived relations are waiting to be written.
    fn len(&self) -> usize {
        self.relations.len()
    }

    /// Take newly derived relations and write out every full batch.
    ///
    /// Returns what `write` reported installing, which is what the graph took
    /// rather than what was offered it.
    fn absorb<F>(&mut self, derived: Vec<kin_model::Relation>, mut write: F) -> EnrichmentWrite
    where
        F: FnMut(&[kin_model::Relation]) -> EnrichmentWrite,
    {
        self.relations.extend(derived);
        let mut installed = EnrichmentWrite::default();
        while self.relations.len() >= ENRICHMENT_WRITE_BATCH {
            let batch: Vec<kin_model::Relation> =
                self.relations.drain(..ENRICHMENT_WRITE_BATCH).collect();
            installed += write(&batch);
        }
        installed
    }

    /// Write the remainder, leaving the buffer empty.
    ///
    /// Called at the end of every file rather than at the end of the sweep, so
    /// the relations a file produced reach the graph before the next file is
    /// opened, and a sweep stopped between files has already written them.
    fn flush<F>(&mut self, mut write: F) -> EnrichmentWrite
    where
        F: FnMut(&[kin_model::Relation]) -> EnrichmentWrite,
    {
        if self.relations.is_empty() {
            return EnrichmentWrite::default();
        }
        debug!(
            tail = self.len(),
            "writing the tail of this file's enrichment"
        );
        let batch = std::mem::take(&mut self.relations);
        write(&batch)
    }
}

/// The relations from `relations` this graph does not already hold in exactly
/// this form.
///
/// A sweep killed before it published records nothing, so the next daemon
/// sweeps the same files and derives the same relations again. Their ids are
/// content-addressed from source, target and kind, so each one is a
/// byte-identical rewrite of an edge the graph already carries.
/// `upsert_relation` cannot tell the difference and pays the full price for
/// every one: it removes the old edge and its indexes, reinserts them, records
/// a delta remove beside a delta upsert, rebuilds both endpoints'
/// relation-derived text fields by walking their whole edge lists, and then
/// drops both endpoints' vectors and re-queues them for embedding. That last
/// step is not merely wasted, it is destructive, because a re-sweep that
/// changes nothing discards embeddings a completed backfill had produced.
///
/// The rewrite is therefore dropped before the graph is opened at all, which
/// also means a converged re-sweep never marks the graph dirty and so never
/// arms the whole-store publication that a dirty graph triggers.
///
/// Equality is the whole relation, so a re-derivation whose confidence,
/// evidence, import source or origin changed is still written. An unreadable
/// neighbourhood abandons the comparison and offers everything, which costs a
/// rewrite and can never drop a relation wrongly.
fn unheld_lsp_relations(
    state: &DaemonState,
    relations: &[kin_model::Relation],
) -> Vec<kin_model::Relation> {
    use kin_model::EntityStore;
    let mut held: std::collections::HashMap<kin_model::RelationId, kin_model::Relation> =
        std::collections::HashMap::new();
    let mut fetched: std::collections::HashSet<kin_model::EntityId> =
        std::collections::HashSet::new();
    for relation in relations {
        let kin_model::GraphNodeId::Entity(source) = relation.src else {
            continue;
        };
        if !fetched.insert(source) {
            continue;
        }
        let Ok(existing) = state.graph.get_all_relations_for_entity(&source) else {
            return relations.to_vec();
        };
        for existing in existing {
            held.insert(existing.id, existing);
        }
    }
    relations
        .iter()
        .filter(|candidate| {
            held.get(&candidate.id)
                .is_none_or(|held| held != *candidate)
        })
        .cloned()
        .collect()
}

/// The ids, among `relations`, that the graph actually holds right now.
///
/// Read per distinct source entity, the same way [`unheld_lsp_relations`] reads
/// them. An unreadable neighbourhood yields nothing for that source, which
/// makes those relations count as unpublished: reconciliation must fail toward
/// reporting a loss it cannot rule out, never toward a green it cannot support.
fn held_relation_ids(
    state: &DaemonState,
    relations: &[kin_model::Relation],
) -> std::collections::HashSet<kin_model::RelationId> {
    use kin_model::EntityStore;
    let mut held = std::collections::HashSet::new();
    let mut fetched = std::collections::HashSet::new();
    for relation in relations {
        let kin_model::GraphNodeId::Entity(source) = relation.src else {
            continue;
        };
        if !fetched.insert(source) {
            continue;
        }
        let Ok(existing) = state.graph.get_all_relations_for_entity(&source) else {
            continue;
        };
        for existing in existing {
            held.insert(existing.id);
        }
    }
    held
}

pub(crate) fn install_lsp_relations(
    state: &DaemonState,
    relations: &[kin_model::Relation],
) -> EnrichmentWrite {
    if relations.is_empty() {
        return EnrichmentWrite::default();
    }

    let relations = unheld_lsp_relations(state, relations);
    if relations.is_empty() {
        debug!("every enrichment relation offered is already held in this form; nothing written");
        return EnrichmentWrite::default();
    }

    use kin_model::EntityStore;
    let graph_mutation = state.begin_graph_authority_mutation();
    let offered = relations.len();
    let mut errored: std::collections::HashSet<kin_model::RelationId> =
        std::collections::HashSet::new();
    for relation in &relations {
        match state.graph.upsert_relation(relation) {
            Ok(_) => {}
            Err(error) => {
                errored.insert(relation.id);
                // Was `let _ =`. A write the graph refused was indistinguishable
                // from one it took, and the count returned was the number of
                // relations ATTEMPTED, so a pass that installed nothing reported
                // exactly the same number as one that installed everything. That
                // is how a language-server answer proved correct in the trace
                // reached the graph as nothing at all, and every log line about
                // it said the enrichment had worked.
                debug!(
                    kind = ?relation.kind,
                    src = ?relation.src,
                    dst = ?relation.dst,
                    %error,
                    "graph refused an enrichment relation"
                );
            }
        }
    }
    // Reconcile against the GRAPH, not against the calls. `upsert_relation`
    // inserts before its embedding invalidation can fail, so an `Err` does not
    // prove the relation is absent, and counting errors as losses reports a
    // sweep that dropped nothing as one that dropped hundreds.
    let held = held_relation_ids(state, &relations);
    let published = relations
        .iter()
        .filter(|relation| held.contains(&relation.id))
        .count();
    let vector_stale = errored.iter().filter(|id| held.contains(id)).count();
    let written = EnrichmentWrite {
        published,
        offered,
        vector_stale,
    };

    if written.lost() > 0 {
        warn!(
            offered,
            published,
            lost = written.lost(),
            "enrichment relations were offered and the graph does not hold them"
        );
    }
    if vector_stale > 0 {
        warn!(
            vector_stale,
            "enrichment relations were published but their endpoints' embedding invalidation \
             failed, so those vectors may be stale"
        );
    }
    state.bump_version();
    drop(graph_mutation);
    written
}

/// Enrich a single entity with all available LSP relation types (calls, overrides,
/// uses-type, references). Each query is capped at 5 seconds.
///
/// Returns what the language server answered rather than writing it. The
/// caller owns the graph write, so one entity's four query arms no longer open
/// four separate graph-authority mutations, and the payload each arm returned
/// is dropped here once its relations have been extracted.
async fn enrich_single_entity(
    server: &kin_lsp::lifecycle::LspServer,
    entity_ref: &kin_lsp::EntityRef,
    index: &kin_lsp::EntityIndex,
    root: &std::path::Path,
    documents: Option<kin_lsp::DocumentProvider<'_>>,
) -> Vec<kin_model::Relation> {
    let timeout = std::time::Duration::from_secs(5);
    let mut derived: Vec<kin_model::Relation> = Vec::new();

    // Calls
    match tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_calls(server, entity_ref, index, root),
    )
    .await
    {
        Ok(Ok(relations)) => {
            derived.extend(relations);
        }
        Ok(Err(e)) => {
            debug!(entity = %entity_ref.name, error = %e, "LSP calls enrichment failed");
        }
        Err(_) => {
            debug!(entity = %entity_ref.name, "LSP calls enrichment timed out");
        }
    }

    // Overrides
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_overrides(server, entity_ref, index, root),
    )
    .await
    {
        derived.extend(relations);
    }

    // UsesType
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_uses_type(server, entity_ref, index, root, documents),
    )
    .await
    {
        derived.extend(relations);
    }

    // References
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_references(server, entity_ref, index, root),
    )
    .await
    {
        derived.extend(relations);
    }

    derived
}

/// Run the kin daemon. This is the main entry point.
///
/// Starts:
/// 1. The reconciliation loop (file watcher + reconciler)
/// 2. The HTTP API server (for CLI, MCP, and UI)
/// 3. The orphan session sweeper (Phase 7)
///
/// All run concurrently. Any shutting down causes the others to stop.
pub async fn run(state: DaemonState, config: DaemonConfig) -> Result<()> {
    let authority = acquire_daemon_authority(state.layout.root())?;
    run_with_authority(state, config, authority).await
}

/// Run with repository singleton authority already acquired.
///
/// The production process entrypoint uses this form so the lifetime guard is
/// held before `DaemonState::open*` can recover or publish persisted state.
/// [`run`] remains as the source-compatible wrapper for library callers.
pub async fn run_with_authority(
    state: DaemonState,
    config: DaemonConfig,
    daemon_lock: crate::lifecycle::DaemonLock,
) -> Result<()> {
    run_with_authority_on(state, config, daemon_lock, None).await
}

/// The API socket a caller bound and published before opening state.
///
/// Opening state re-verifies the whole durable publication, so a daemon that
/// binds only afterwards refuses every connection for the length of that load.
/// A caller that binds first passes the second handle to its already-bound
/// socket here, along with the signal that retires the readiness surface it has
/// been answering probes on in the meantime.
pub struct PreboundApi {
    /// The serving handle of a socket already bound and already published.
    pub listener: tokio::net::TcpListener,
    pub port: u16,
    /// Set when the full API takes over, which stops the readiness surface.
    pub ready_tx: tokio::sync::watch::Sender<bool>,
}

/// Run with singleton authority held, optionally on an already-bound socket.
pub async fn run_with_authority_on(
    mut state: DaemonState,
    config: DaemonConfig,
    daemon_lock: crate::lifecycle::DaemonLock,
    prebound: Option<PreboundApi>,
) -> Result<()> {
    // A singleton file handle is authority for one canonical repository, not a
    // process-global permission to run any DaemonState. Validate the binding
    // before migration, listener binding, or endpoint publication so a safe
    // public API caller cannot replay repo A's capability against repo B.
    let state_root = state
        .layout
        .root()
        .canonicalize()
        .map_err(DaemonError::Io)?;
    if daemon_lock.canonical_kin_root() != state_root {
        return Err(DaemonError::AuthorityMismatch {
            authority_root: daemon_lock.canonical_kin_root().to_path_buf(),
            state_root,
        });
    }

    // Refuse to serve an incompatible `.kin/` layout. We now hold the singleton
    // lock (sole writer for this repo) but have not bound a port, written
    // endpoint files, or touched graph/kindb state — the safe point to validate
    // and forward-migrate the on-disk layout version. A newer-than-supported or
    // un-upgradable layout fails loudly here instead of being silently
    // mis-served; a current layout is a cheap read with no disk write.
    if let Err(error) = state.layout.migrate() {
        tracing::error!(
            repo = %state.layout.root().display(),
            %error,
            "refusing to start: .kin/ layout is incompatible with this kin build"
        );
        return Err(error.into());
    }

    // Publish which language servers this host has, so every answer this daemon
    // serves reports the same fact the enrichment path acts on. Without it the
    // absence-trust gate cannot tell a language whose program a server resolved
    // from one nothing resolved, and it certified an absence over the latter.
    //
    // A cheap PATH lookup rather than `discover_servers`, which runs `--version`
    // on every server it finds, and published unconditionally: a daemon with
    // enrichment switched off produces no reference edge either, so its answers
    // must not claim otherwise.
    // Load what a previous daemon already enriched, so a restart resumes rather
    // than re-sweeping a converged graph.
    load_lsp_enriched_marker(&state);

    // The working directory as the layout already holds it. Deliberately not
    // canonicalized: a readiness probe asks whether a server starts and
    // completes a handshake, never resolving a file through this path, so the
    // filesystem round trip would buy nothing and this is an authority-path
    // crate where every such call has to earn itself.
    spawn_language_server_readiness_probe(state.layout.working_dir().to_path_buf());

    // Set up LSP enrichment channel before wrapping state in Arc.
    let enrichment_enabled =
        should_enable_lsp_enrichment(config.lsp_enabled, state.filesystem_reconcile_disabled());
    // Recorded so a caller can tell a deliberately disabled daemon from one that
    // simply found no server. Those need opposite answers and the channel alone
    // cannot separate them.
    state.lsp_enrichment_enabled = enrichment_enabled;
    let lsp_rx = if enrichment_enabled {
        let discovered = kin_lsp::discovery::discover_servers();
        if enrichment_channel_opens(enrichment_enabled, discovered.len()) {
            info!(
                count = discovered.len(),
                languages = ?discovered.iter().map(|s| format!("{}", s.language)).collect::<Vec<_>>(),
                "LSP servers available for enrichment"
            );
            let (tx, rx) = tokio::sync::mpsc::channel::<crate::state::LspEnrichmentMessage>(256);
            state.lsp_enrichment_tx = Some(tx);
            Some(rx)
        } else {
            // Built from the shared marker rather than spelled here, because a
            // remedy in kin-daemon-spawn keys on this sentence to know that
            // offering KIN_DAEMON_DISABLE_LSP would be advice nobody can take.
            // Two copies of the words would let this one drift and disarm that
            // remedy silently.
            info!(
                "{}, so enrichment is disabled for the life of this daemon; install one and \
                 restart to enable it",
                kin_daemon_spawn::ENRICHMENT_UNAVAILABLE_MARKER
            );
            None
        }
    } else {
        if config.lsp_enabled && state.filesystem_reconcile_disabled() {
            info!(
                "LSP discovery and enrichment disabled; filesystem-derived relations cannot mutate graph-only authority"
            );
        }
        None
    };

    let state = Arc::new(state);
    // Publish the resolved background batch size so `kin resources inspect` can
    // report the value actually in force rather than leaving an operator to
    // infer it from log lines (FIR-2504).
    state.publish_embed_batch_size(config.embed_batch_size);

    // Nothing used to trigger a sweep. The enrichment worker started, blocked on
    // a channel, and waited: the incremental path fires only on watcher
    // file-change events, and the only caller of `queue_lsp_sweep` was
    // `POST /lsp/sweep`, which nothing in the product calls. So a freshly
    // converted repository sat with a running server, a wired adapter and zero
    // cross-file reference edges, and the first daemon after `kin init` was
    // signalled 189 ms after its enrichment worker started, taking the intent
    // with it.
    //
    // Queued here, after the channel exists and before the listener binds, so a
    // daemon that comes up for any reason converges the graph it was handed. The
    // sweep skips files that already carry language-server evidence, so this is
    // cheap on a converged repository, resumable after a kill, and safe to queue
    // on every start.
    // Decided here and acted on later. Settling the previous sweep has to happen
    // at startup, because the in-flight record it takes is the only trace a
    // killed sweep leaves and a second daemon would read it as its own. Queueing
    // does not: the sweep is handed to the gate below, which starts it once the
    // embedding backfill is out of the way.
    let mut sweep_admitted = false;
    let hold_sweep = hold_sweep_from(std::env::var(HOLD_SWEEP_ENV).ok().as_deref());
    if hold_sweep {
        // The thin-answer state, on purpose. Until the sweep publishes, the
        // cross-file edges a reference answer counts do not exist, so the
        // surface answers promptly, successfully and with fewer upstreams than
        // the repository holds. Logged as loudly as any refusal, so a daemon in
        // this state can never be mistaken for a healthy one.
        warn!(
            lever = HOLD_SWEEP_ENV,
            "refusing to admit the LSP enrichment sweep: fault injection is armed, so cross-file \
             edges will not publish and reference answers will be thin. This is not a healthy \
             daemon; unset the lever to restore it."
        );
    } else if enrichment_enabled && state.lsp_enrichment_tx.is_some() {
        // A store whose sweeps keep dying before enriching anything gets one
        // fewer, not another. Decided on EVERY daemon start, this is the point
        // the marker-discard loop turns at: a sweep dies, the daemon restarts,
        // queues another, dies again. One stranger session logged 24 of them.
        match decide_sweep_on_start(&state) {
            SweepStartDecision::CircuitOpen { interruptions } => {
                warn!(
                    consecutive_fruitless_interruptions = interruptions,
                    limit = SWEEP_INTERRUPTION_LIMIT,
                    "not queueing an LSP sweep: this store's last sweeps all ended early without \
                     enriching anything, so another would repeat what has been failing. \
                     Enrichment stays at what is already durable; one sweep that completes \
                     clears this, and `kin daemon sweep` asks for one."
                );
            }
            SweepStartDecision::PressureRefused { .. } => {
                // The reason was disclosed where it was decided, both to this
                // log and to the record every surface outside this process
                // reads. Nothing further is needed here beyond not queueing.
            }
            SweepStartDecision::Queue => {
                sweep_admitted = true;
                clear_pressure_refusal_for_work(
                    &state,
                    kin_core::memory_pressure::HeavyWork::LspSweep,
                );
            }
        }
    }

    // Bind the API listener so the daemon owns port selection. With
    // config.api_port == 0 the OS assigns a free ephemeral port; we then publish
    // the *actual* bound port via the port file. Binding before the port file is
    // written closes the reserve-release-rebind race (find_free_port TOCTOU)
    // where a launcher picked a port, dropped it, and a sibling process stole it
    // before the daemon bound.
    //
    // Binding HERE is still after `DaemonState::open*`, which reads and
    // re-verifies the whole durable publication. An earlier comment claimed this
    // ran "before the slower graph/LSP startup"; that was true of this function
    // and false of the process, and it read as though first contact during the
    // open window were already handled. It is not, on this path: a client
    // arriving while state opens finds no socket. The process entrypoint passes
    // `prebound` precisely to close that window, and when it does, the socket is
    // already bound, already published, and already answering.
    let (api_listener, bound_port, warming_retired) = match prebound {
        Some(prebound) => (prebound.listener, prebound.port, Some(prebound.ready_tx)),
        None => {
            let (listener, port) = match api::bind_api_listener(&state.layout, config.api_port) {
                Ok(bound) => bound,
                Err(error) => return Err(DaemonError::Io(error)),
            };
            (listener, port, None)
        }
    };

    // Shutdown signal: when set to true, all loops exit.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Spawn the reconciliation loop BEFORE the endpoint is published, and wait
    // for it to report its file watcher.
    //
    // Serving is not watching. The endpoint file is the readiness signal real
    // clients key on, so a client that connects the moment it appears and
    // writes immediately used to land in a window where the watcher did not yet
    // exist: the write raised no event, startup replayed nothing, and the file
    // stayed absent from the graph until some unrelated later touch of the same
    // path (FIR-2466). Publishing after the watch closes that window by
    // construction rather than by racing it.
    //
    // The wait is bounded and the signal fires on the loop's drop as well as on
    // arming, so no early return, disabled loop, bare checkout, or refused
    // watcher can leave this daemon unpublished.
    let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
    let loop_state = Arc::clone(&state);
    let loop_config = config.loop_config.clone();
    let loop_cancel = cancel_rx.clone();
    let loop_handle = tokio::spawn(async move {
        loop_runner::run_loop_armed(
            loop_state,
            loop_config,
            loop_cancel,
            Some(loop_runner::WatchArmed::new(armed_tx)),
        )
        .await
    });
    let arming = await_watch_armed(armed_rx, WATCH_ARMING_BOUND).await;
    announce_watch_arming(arming, WATCH_ARMING_BOUND);

    // Publish PID and the actual bound port as one lifecycle-authorized
    // operation. Endpoint retirement takes the same authority, so no client can
    // delete a successor publication using a verdict about its predecessor.
    //
    // This happens HERE, after state is open, for a prebound caller too. The
    // endpoint is what makes a daemon findable, and a client that finds one
    // sends commands against it — it waits on readiness only when it spawned
    // the daemon itself. Publishing during the open window would therefore turn
    // "not ready yet" into a failed command on the attach path. Binding early
    // costs nothing here because it advertises nothing; only publication does.
    // Settle the previous daemon's death before recording this one's life, and
    // in that order for the reason `decide_sweep_on_start` settles a killed
    // sweep at startup: the record an unwatched death leaves is the only trace
    // of it, and a second daemon would otherwise read that trace as its own.
    //
    // A daemon killed while nothing watched it used to leave nothing at all.
    // The before-reading a memory attribution needs lived in `DaemonWatch`,
    // which lives in the process that spawned the daemon, so a daemon that
    // outlived its spawner and was then killed was observed by nobody and every
    // surface downstream was free to call the silence an idle exit. That is
    // what let a measured OOM be reported as a normal retirement.
    if let Some(record) = kin_daemon_spawn::settle_unwatched_daemon_death(state.layout.root()) {
        warn!(
            kills = record.kills,
            memory_kills = record.memory_kills,
            "a daemon serving this store died without being watched, and this start counted it: {}",
            record.cause_sentence()
        );
    }
    // The still-starting state, on purpose. The endpoint file is the readiness
    // signal a client keys on, so holding it keeps the launcher's startup
    // binding PENDING, which is the only way a `tools/call` reaches the
    // disclosure branch on a fixture small enough for CI.
    let startup_hold = startup_hold_from(std::env::var(STARTUP_HOLD_ENV).ok().as_deref());
    if !startup_hold.is_zero() {
        warn!(
            lever = STARTUP_HOLD_ENV,
            seconds = startup_hold.as_secs(),
            "holding the daemon endpoint unpublished: fault injection is armed, so clients will \
             see a still-starting daemon for this long. This is not a healthy daemon; unset the \
             lever to restore it."
        );
        tokio::time::sleep(startup_hold).await;
    }
    kin_daemon_spawn::publish_serving_daemon(state.layout.root(), std::process::id());
    crate::lifecycle::publish_daemon_endpoint(state.layout.root(), bound_port)
        .map_err(DaemonError::Io)?;
    // Recorded so the ordering above is readable off the daemon's own log
    // rather than inferred from timings. A watcher record that does not precede
    // this one is the regression.
    info!(port = bound_port, "published the daemon endpoint");

    // Retire the readiness surface: the full API serves this socket from here.
    // Both handles accept from one listen queue, so there is no instant at which
    // neither is answering — during the handover a connection is answered by
    // whichever accepts it, and both answers are correct.
    if let Some(ready_tx) = warming_retired {
        let _ = ready_tx.send(true);
    }

    info!(port = bound_port, "starting kin daemon");

    // Publish the startup window into shared state before the monitor reads
    // it, so an attached client can see and grow the window this daemon is
    // actually running with rather than the one its spawner happened to choose.
    state.install_idle_timeout(config.idle_timeout);
    let idle_state = Arc::clone(&state);
    let idle_timeout = config.idle_timeout;
    let idle_cancel_tx = cancel_tx.clone();
    let idle_cancel = cancel_rx.clone();
    let idle_handle = tokio::spawn(async move {
        run_idle_monitor(
            idle_state,
            idle_timeout,
            bound_port,
            idle_cancel_tx,
            idle_cancel,
        )
        .await
    });

    // Opt-in owner-death watchdog. A harness (e.g. the benchmark driver) sets
    // KIN_DAEMON_WATCH_PID to the PID of the process that owns this daemon's
    // work. When that owner dies, nothing will ever consume what this daemon is
    // computing, so it shuts itself down instead of burning cores and holding
    // tens of GB on a result no one will read. An orphaned daemon caught
    // mid-hydration is the motivating case: hydration cost is superlinear, so
    // the longer an abandoned walk runs the more expensive it gets.
    //
    // Deliberately a plain OS thread, NOT a tokio task. The whole point of this
    // watchdog is to work when the daemon is in trouble, and the previous tokio
    // task could only fire if the async runtime was still willing to schedule
    // it. It also sets `is_shutdown` directly rather than relying on the
    // propagation task, so the force-exit backstop is armed even if no tokio
    // task ever runs again.
    //
    // Opt-in only, and never inferred from getppid() — see
    // `parse_owner_watch_pid` for why the process tree cannot answer this
    // question for a daemon that is detached by design.
    if let Some(owner_pid) = parse_owner_watch_pid(
        std::env::var("KIN_DAEMON_WATCH_PID").ok().as_deref(),
        std::process::id(),
    ) {
        info!(owner_pid, "daemon owner-death shutdown enabled");
        let watch_state = Arc::clone(&state);
        let watch_cancel_tx = cancel_tx.clone();
        let watch_cancel_rx = cancel_rx.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("kin-owner-watchdog".to_string())
            .spawn(move || loop {
                std::thread::sleep(OWNER_WATCH_CHECK_INTERVAL);
                if shutdown_signalled(
                    watch_state
                        .is_shutdown
                        .load(std::sync::atomic::Ordering::Relaxed),
                    *watch_cancel_rx.borrow(),
                    shutdown_requested(),
                ) {
                    return;
                }
                if watched_process_is_alive(owner_pid) {
                    continue;
                }
                warn!(
                    owner_pid,
                    "owner process is gone — shutting down orphaned daemon"
                );
                // Arm the force-exit backstop here, not via the propagation
                // task: an orphaned daemon is exactly the case where the async
                // runtime may be unable to make progress.
                watch_state
                    .is_shutdown
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                // Best-effort graceful path; it normally wins the race against
                // the escalation grace and exits cleanly with state flushed.
                let _ = watch_cancel_tx.send(true);
                return;
            })
        {
            warn!(error = %error, "failed to spawn owner-death watchdog");
        }
    }

    // Spawn the API server on the pre-bound listener.
    let api_state = Arc::clone(&state);
    let api_cancel_tx = cancel_tx.clone();
    let api_cancel = cancel_rx.clone();
    let api_handle = tokio::spawn(async move {
        api::serve_bound_with_shutdown(api_state, api_listener, Some(api_cancel_tx), api_cancel)
            .await
    });

    // Register this repo-scoped graph daemon with the lightweight central
    // supervisor when one is available. The supervisor owns process/routing
    // metadata only; this daemon remains graph-authoritative for its repo.
    let supervisor_state = Arc::clone(&state);
    let supervisor_port = bound_port;
    let supervisor_cancel = cancel_rx.clone();
    let supervisor_handle = tokio::spawn(async move {
        crate::supervisor::repo_daemon_registration_loop(
            supervisor_state,
            supervisor_port,
            supervisor_cancel,
        )
        .await
    });

    // Startup watchdog: monitor initialization and warn if it takes too long.
    let watchdog_state = Arc::clone(&state);
    let mut watchdog_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        let init_timeout = Duration::from_secs(120);
        let check = Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(check) => {}
                _ = watchdog_cancel.changed() => return,
            }
            if watchdog_state
                .is_initialized
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                info!(
                    elapsed_ms = start.elapsed().as_millis(),
                    "daemon initialization complete"
                );
                return;
            }
            let elapsed = start.elapsed();
            if elapsed >= init_timeout {
                error!(
                    elapsed_s = elapsed.as_secs(),
                    "daemon initialization timed out — first reconciliation did not complete within 120s; check snapshot or repo state"
                );
                return;
            }
            info!(
                elapsed_s = elapsed.as_secs(),
                "daemon still initializing (waiting for first reconciliation)"
            );
        }
    });

    // Spawn task to propagate shutdown signals to state.is_shutdown.
    let shutdown_state = Arc::clone(&state);
    let mut shutdown_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        while !*shutdown_cancel.borrow() {
            if shutdown_cancel.changed().await.is_err() {
                break;
            }
        }
        if *shutdown_cancel.borrow() {
            shutdown_state
                .is_shutdown
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });

    // Arm the runtime-independent shutdown flag before the reconciliation loop
    // can start occupying worker threads. Neither this flag nor the watchdog
    // below is ever set during normal operation, so neither can fire on a
    // healthy daemon.
    install_shutdown_signal_handler();
    let escalation_state = Arc::clone(&state);
    spawn_shutdown_escalation_watchdog(
        move || {
            escalation_state
                .is_shutdown
                .load(std::sync::atomic::Ordering::Relaxed)
        },
        cancel_rx.clone(),
        shutdown_escalation_grace(),
    );

    // Spawn the orphan session sweeper (Phase 7).
    let sweep_state = Arc::clone(&state);
    let sweep_interval = config.sweep_interval;
    let mut sweep_cancel = cancel_rx.clone();
    let sweep_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(sweep_interval) => {}
                _ = sweep_cancel.changed() => {
                    info!("session sweeper shutting down");
                    break;
                }
            }
            if *sweep_cancel.borrow() {
                break;
            }
            let _coordination = sweep_state.coordination_gate.lock().await;
            let mode = sweep_state.coordination_mode().as_str().to_string();
            match sweep_state
                .coordinator
                .sweep_stale_sessions_with_reservation(|session, intents| {
                    for intent in intents {
                        sweep_state.record_coordination_event(
                            crate::state::CoordinationEventDraft {
                                event: "intent_release",
                                outcome: "pending:session_reaped".to_string(),
                                session_id: Some(session.session_id.to_string()),
                                intent_id: Some(intent.intent_id.to_string()),
                                intent_ids: vec![intent.intent_id.to_string()],
                                transaction_id: None,
                                scopes: intent
                                    .scopes
                                    .iter()
                                    .map(crate::api::format_scope)
                                    .collect(),
                                enforcement_mode: mode.clone(),
                                blocking_intent_ids: Vec::new(),
                            },
                        )?;
                    }
                    Ok(())
                }) {
                Ok(reaped) => {
                    for (session, intents) in reaped {
                        for intent in intents {
                            let _ = sweep_state.record_coordination_event(
                                crate::state::CoordinationEventDraft {
                                    event: "intent_release",
                                    outcome: "session_reaped".to_string(),
                                    session_id: Some(session.session_id.to_string()),
                                    intent_id: Some(intent.intent_id.to_string()),
                                    intent_ids: vec![intent.intent_id.to_string()],
                                    transaction_id: None,
                                    scopes: intent
                                        .scopes
                                        .iter()
                                        .map(crate::api::format_scope)
                                        .collect(),
                                    enforcement_mode: mode.clone(),
                                    blocking_intent_ids: Vec::new(),
                                },
                            );
                        }
                    }
                }
                Err(e) => {
                    sweep_state.mark_coordination_evidence_incomplete(format!(
                        "stale-session sweep failed after reservation may have been written: {e}"
                    ));
                    error!(error = %e, "session sweeper error");
                }
            }
        }
    });

    // Spawn the background persistence task.
    // Instead of blocking the reconcile loop with synchronous save_graph(),
    // this task periodically flushes dirty state to disk:
    //   - Idle flush: KIN_DAEMON_IDLE_FLUSH_SECS (default 2s) after the last
    //     mutation with no new mutations; suppressed while a daemon-side
    //     embed pass is in flight (see should_flush_now)
    //   - Periodic flush: every KIN_DAEMON_PERIODIC_FLUSH_SECS (default 30s)
    //     of unpersisted dirty state, regardless of activity
    //   - Shutdown flush: handled separately in the graceful shutdown path
    let persist_state = Arc::clone(&state);
    let mut persist_cancel = cancel_rx.clone();
    let persist_handle = tokio::spawn(async move {
        let idle_flush =
            duration_from_env_secs("KIN_DAEMON_IDLE_FLUSH_SECS", Duration::from_secs(2));
        let periodic_flush =
            duration_from_env_secs("KIN_DAEMON_PERIODIC_FLUSH_SECS", Duration::from_secs(30));
        info!(
            idle_flush_s = idle_flush.as_secs(),
            periodic_flush_s = periodic_flush.as_secs(),
            "background persistence intervals"
        );
        let base_interval = Duration::from_millis(500);
        let max_backoff = Duration::from_secs(30);
        const UNHEALTHY_THRESHOLD: u32 = 5;

        let mut consecutive_failures: u32 = 0;
        let mut current_interval = base_interval;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(current_interval) => {}
                _ = persist_cancel.changed() => {
                    run_shutdown_persistence(&persist_state).await;
                    break;
                }
            }
            if *persist_cancel.borrow() {
                break;
            }

            if !persist_state.is_dirty() {
                continue;
            }

            let suppression = if persist_state.embed_pass_active() {
                FlushSuppression::EmbedPass
            } else if persist_state
                .lsp_sweep_running
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                FlushSuppression::LspSweep
            } else {
                FlushSuppression::None
            };
            let should_flush = should_flush_now(
                persist_state.time_since_save(),
                persist_state.time_since_mutation(),
                suppression,
                idle_flush,
                periodic_flush,
            );

            if should_flush {
                let start = std::time::Instant::now();
                match save_snapshot_blocking(Arc::clone(&persist_state)).await {
                    Ok(()) => {
                        persist_state.mark_clean();
                        if consecutive_failures > 0 {
                            info!(
                                prior_failures = consecutive_failures,
                                "persistence recovered"
                            );
                        }
                        consecutive_failures = 0;
                        current_interval = base_interval;
                        info!(
                            elapsed_ms = start.elapsed().as_millis(),
                            "background persistence flush complete"
                        );
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        let backoff_secs =
                            (1u64 << consecutive_failures.min(5)).min(max_backoff.as_secs());
                        current_interval = Duration::from_secs(backoff_secs);
                        if consecutive_failures >= UNHEALTHY_THRESHOLD {
                            error!(
                                error = %e,
                                consecutive_failures,
                                next_retry_s = backoff_secs,
                                "daemon persistence unhealthy — check disk space and permissions"
                            );
                        } else {
                            tracing::warn!(
                                error = %e,
                                consecutive_failures,
                                next_retry_s = backoff_secs,
                                "background persistence flush failed, backing off"
                            );
                        }
                    }
                }
            }
        }
    });

    // Spawn the background embedding worker.
    // Periodically drains the embedding queue, generating vector embeddings
    // for newly added/modified entities. Non-blocking to the reconcile loop.
    let embed_state = Arc::clone(&state);
    let embed_interval = config.embed_interval;
    let embed_batch_size = config.embed_batch_size;
    let embed_pipeline_overlap = config.embed_pipeline_overlap;
    let mut embed_cancel = cancel_rx.clone();
    let embed_handle = tokio::spawn(async move {
        if !embed_state.can_persist_embed_progress_locally() {
            retire_embed_pressure_for_unavailable_persistence(&embed_state);
            warn!(
                "background embedding worker disabled: durable vector-artifact capability or its compare-and-swap cursor is unavailable; graph serving remains available"
            );
            return;
        }
        // Wait for the daemon to finish its first reconciliation cycle
        // before starting embedding work — no point embedding an empty graph.
        while !embed_state
            .is_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                _ = embed_cancel.changed() => return,
            }
        }
        info!("embedding worker started");
        start_or_defer_background_embed(&embed_state);
        // Register with the self-limit supervisor. Registration is what makes
        // this worker's CPU accountable: from here it declares when it is
        // working, credits what it persists, and is stopped and announced if
        // those two ever come apart.
        let embed_pass = embed_state
            .background_work
            .pass(crate::background_work::PASS_EMBED);
        let embed_retry_budget = crate::background_work::configured_retry_budget();
        let mut consecutive_panics: u32 = 0;
        const MAX_CONSECUTIVE_PANICS: u32 = 3;
        // Recovery + backoff state for vector-index errors (e.g. a stale on-disk
        // index dimension vs the live embedder). We trigger the kin-db
        // reset/re-queue contract exactly ONCE; if the error persists, we back
        // off exponentially so the worker can never busy-spin requeuing a batch
        // that keeps failing — the 100% CPU / 5s requeue-fail loop class.
        let mut index_reset_triggered = false;
        let mut error_backoff: Option<Duration> = None;
        const EMBED_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(60);
        // The coverage gap this worker last re-queued, so a gap it cannot close
        // is reported once instead of re-queued every interval. Cleared by any
        // batch that embeds something, since progress makes the next gap a new
        // question.
        let mut backfilled_gap: Option<usize> = None;
        // A refused vector checkpoint outlives the batch that hit it, so its
        // retry schedule lives out here with the wake loop rather than inside
        // the drain that produced the refusal.
        let mut deferred_checkpoint_backoff: Option<Duration> = None;
        let mut deferred_checkpoint_due: Option<Instant> = None;
        // The pressure level this worker has already spoken about. Held so a
        // machine that stays critical is disclosed once rather than on every
        // wake: the record is a statement of the current state, and rewriting
        // it every few seconds would turn a disclosure into a log.
        let mut announced_pressure: Option<kin_core::memory_pressure::PressureLevel> = None;
        'wake: loop {
            // Between wakes this worker is genuinely doing nothing, so the
            // working stretch ends here. A wedged drain never reaches this
            // point, which is precisely why the stretch it started keeps
            // accumulating and becomes observable.
            embed_pass.idle();
            // While an embed/index error is being retried, sleep for the current
            // backoff instead of the normal idle interval (no tight-spin).
            let idle = error_backoff.unwrap_or(embed_interval);
            tokio::select! {
                _ = tokio::time::sleep(idle) => {}
                _ = embed_cancel.changed() => {
                    info!("embedding worker shutting down");
                    break;
                }
            }
            if *embed_cancel.borrow() {
                break;
            }
            if embed_pass.halted() {
                break;
            }

            // Before anything this tick might embed, land what the last tick
            // already embedded and could not checkpoint. A drained queue never
            // reaches the flush below, so this is the only path that closes a
            // refusal once there is nothing left to embed, which is the state
            // the regression was found in.
            retry_deferred_vector_checkpoint(
                &embed_state,
                &mut deferred_checkpoint_backoff,
                &mut deferred_checkpoint_due,
                embed_interval,
            )
            .await;

            // Drain the pending backlog continuously within this wake rather than
            // one batch per `embed_interval`. A fresh central-graph embed (or an
            // explicit `kin embed --rebuild`) enqueues thousands of entities;
            // trickling a single batch per interval would cap throughput at
            // `embed_batch_size / embed_interval` no
            // matter how fast the GPU runs. We yield between batches so locate,
            // persistence, and cancellation stay responsive, then fall back to the
            // idle sleep once the queue is empty. Incremental trickle (a handful of
            // newly-reconciled entities) drains in a single pass and is unchanged.
            // At most one batch's flush is in flight at a time. Under the
            // throughput profile its flush stays here while the next batch's
            // prep + GPU forward runs, so the accelerator is never idle during a
            // persist; it is drained before the next flush is scheduled and at
            // every loop exit so two flushes never interleave and the tail is
            // always awaited.
            let mut pending_flush: Option<tokio::task::JoinHandle<Result<usize>>> = None;
            // Entities embedded by batches whose flush has not been awaited yet.
            // Credited to the pass only once that flush reports it reached disk.
            let mut embedded_since_flush: u64 = 0;
            loop {
                if *embed_cancel.borrow() {
                    drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass)
                        .await;
                    break 'wake;
                }
                // The supervisor's verdict is enforced here, at the worker's own
                // checkpoint, so an in-flight batch and its flush finish rather
                // than being torn out from under the vector sidecar.
                if embed_pass.halted() {
                    drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass)
                        .await;
                    break 'wake;
                }
                if embed_state.background_embed_paused() {
                    debug!("embedding worker paused after bounded explicit embed");
                    break;
                }
                if embed_state.embed_pass_active() {
                    debug!("embedding worker yielding to explicit embed pass");
                    break;
                }
                let pending = embed_state.graph.pending_embeddings();
                let pending_artifacts = embed_state.graph.pending_artifact_embeddings();
                if pending == 0 && pending_artifacts == 0 {
                    // An empty queue is not the same fact as whole coverage,
                    // and the difference is what let every commit cost a store
                    // part of its memory in silence. A change mints a HEAD
                    // revision key per touched entity, and anything that puts a
                    // retrievable key into truth without queueing it leaves the
                    // worker nothing to do and no reason to say so. Ask coverage
                    // before believing the drain.
                    let status = embed_state.graph.embedding_status();
                    let missing = status.total.saturating_sub(status.indexed);
                    let coverage_verdict = coverage_drain_verdict(missing, backfilled_gap);
                    match coverage_verdict {
                        CoverageDrainVerdict::Backfill { missing } => {
                            if !queue_embedding_backfill_under_pressure(
                                &embed_state,
                                &mut announced_pressure,
                                || {
                                    #[cfg(feature = "embeddings")]
                                    embed_state.graph.queue_missing_for_embedding();
                                    embed_state.graph.queue_missing_artifacts_for_embedding();
                                },
                            ) {
                                break;
                            }
                            warn!(
                                missing,
                                indexed = status.indexed,
                                total = status.total,
                                "embedding queue drained while coverage is short; re-queueing the missing keys"
                            );
                            // This latch means a re-queue was actually tried.
                            // A pressure refusal above tried nothing and must
                            // remain eligible on the next wake.
                            backfilled_gap = Some(missing);
                            if embed_state.graph.pending_embeddings() > 0
                                || embed_state.graph.pending_artifact_embeddings() > 0
                            {
                                continue;
                            }
                            warn!(
                                missing,
                                "no retrievable key could be queued for the missing coverage"
                            );
                            break;
                        }
                        CoverageDrainVerdict::Stalled { missing } => {
                            debug!(
                                missing,
                                "embedding coverage is short and re-queueing it changed nothing"
                            );
                            break;
                        }
                        CoverageDrainVerdict::Complete => {
                            // Coverage is whole here, so this is where the
                            // has-ever-completed marker is published. Recording
                            // it on the side that did the work keeps the claim
                            // off a reader that only saw a quiet queue.
                            let completed_work = coverage_verdict
                                .completed_pressure_work()
                                .expect("complete coverage names its completed pressure work");
                            let retired_refusal =
                                clear_pressure_refusal_for_work(&embed_state, completed_work);
                            announced_pressure = pressure_announcement_after_retirement(
                                announced_pressure,
                                retired_refusal,
                            );
                            embed_state.record_embedding_coverage_complete();
                            break;
                        }
                    }
                }
                // Everything below spends the machine, so the machine is
                // asked first. A refusal leaves the queue exactly as it is and
                // goes back to the idle wake, which is what makes this a
                // back-off rather than a loss: the work is still owed, and the
                // next wake takes it when there is room.
                let call = pressure_verdict(kin_core::memory_pressure::HeavyWork::EmbedBatch);
                publish_footprint_standing(&embed_state, &call);
                let pressure_changed = announced_pressure != Some(call.level);
                if disclose_embed_pressure_refusal_if_needed(
                    &embed_state,
                    &mut announced_pressure,
                    &call,
                ) {
                    break;
                }
                if pressure_changed {
                    match &call.verdict {
                        kin_core::memory_pressure::Verdict::Shrink { reason } => {
                            warn!(
                                pressure = call.level.as_str(),
                                batch = embed_batch_under_pressure(embed_batch_size, &call.verdict),
                                configured = embed_batch_size,
                                "{reason}"
                            );
                        }
                        kin_core::memory_pressure::Verdict::Proceed => {}
                        kin_core::memory_pressure::Verdict::Refuse { .. } => {}
                    }
                    announced_pressure = Some(call.level);
                }
                // From here to the next `idle` this worker is spending the
                // machine. Latched, so a drain that never finishes keeps one
                // stretch rather than restarting it every batch.
                embed_pass.working(Instant::now());
                let batch = embed_batch_under_pressure(embed_batch_size, &call.verdict);
                let state_for_embed = Arc::clone(&embed_state);
                let is_artifact = pending == 0;
                let reset_on_index_error = !index_reset_triggered;
                let label = if is_artifact {
                    "embedded artifacts"
                } else {
                    "embedded entities"
                };
                let remaining = if is_artifact {
                    pending_artifacts
                } else {
                    pending
                };

                let embed_result = tokio::task::spawn_blocking(move || {
                    run_background_embedding_batch(
                        &state_for_embed,
                        reset_on_index_error,
                        |state| {
                            if is_artifact {
                                state.graph.process_artifact_embedding_queue(batch)
                            } else {
                                state.graph.process_embedding_queue(batch)
                            }
                        },
                    )
                })
                .await;

                match embed_result {
                    Ok(BackgroundEmbeddingBatchOutcome::Completed(count)) if count > 0 => {
                        consecutive_panics = 0;
                        // A successful batch means the index now matches the
                        // embedder — clear any error backoff / reset latch.
                        index_reset_triggered = false;
                        error_backoff = None;
                        // Progress makes the next coverage gap a new question,
                        // so a gap that once looked unclosable gets asked again.
                        backfilled_gap = None;
                        embed_pass.reset_retries();
                        info!(count, remaining = remaining.saturating_sub(count), label);
                        // Serialize successive flushes: the previous batch's
                        // flush — which may still be running concurrently with
                        // this batch's prep + GPU forward under the throughput
                        // profile — must finish before this batch's flush starts.
                        // This guarantees at most one persist runs at a time, so
                        // two flushes never interleave and the persisted
                        // generation cursor advances monotonically.
                        drain_embed_flush(
                            &mut pending_flush,
                            &mut embedded_since_flush,
                            &embed_pass,
                        )
                        .await;
                        embedded_since_flush = count as u64;
                        // Persist the vector index under the shared persist lock so
                        // this kvec write can never interleave with a snapshot save
                        // running in the persistence loop or idle-shutdown flush.
                        // Run inside spawn_blocking so the std persist Mutex is held
                        // only across the synchronous write, never across an await.
                        let state_for_persist = Arc::clone(&embed_state);
                        // Flush this batch incrementally — the vector
                        // sidecar plus any concurrent LSP-enrichment graph delta —
                        // instead of relying on the periodic full-graph save that
                        // re-serializes the whole ~1 GB graph each tick. The method
                        // holds the persist lock and advances the generation cursor
                        // (mirrors save_snapshot), so the two paths never tear.
                        let flush = tokio::task::spawn_blocking(move || {
                            state_for_persist.flush_embed_progress()
                        });
                        pending_flush = Some(flush);
                        // Throughput leaves the flush in flight and loops straight
                        // to the next batch so the GPU is fed while the persist
                        // runs; proof/serial blocks on it now so the persisted
                        // order is fully deterministic.
                        if !embed_pipeline_overlap {
                            drain_embed_flush(
                                &mut pending_flush,
                                &mut embedded_since_flush,
                                &embed_pass,
                            )
                            .await;
                        }
                    }
                    Ok(BackgroundEmbeddingBatchOutcome::Completed(_)) => {
                        // Queue drained out from under us (e.g. an explicit
                        // `/embed` request raced ahead). Stop draining and return
                        // to the idle sleep.
                        consecutive_panics = 0;
                        index_reset_triggered = false;
                        error_backoff = None;
                        embed_pass.reset_retries();
                        break;
                    }
                    Ok(BackgroundEmbeddingBatchOutcome::ResetAfterIndexError(e)) => {
                        warn!(
                            error = %e,
                            "embedding worker hit a vector-index error — reset vector index and re-queued once"
                        );
                        index_reset_triggered = true;
                        error_backoff = None;
                        error!(
                            error = %e,
                            "embedding worker error — reset vector index, retrying next interval"
                        );
                        break;
                    }
                    Ok(BackgroundEmbeddingBatchOutcome::Failed(e)) => {
                        // Distinguish a persistent vector-index error (a stale
                        // loaded index dimension vs the live embedder) from a
                        // transient one. The first IndexError was recovered
                        // inside the failed batch's critical section above. If
                        // it persists (reset already attempted) or it is some
                        // other error, back off exponentially so the worker
                        // never busy-spins. A stale vector index is NOT a reason
                        // to block the graph snapshot flush — it self-heals on
                        // load — so shutdown persistence is left untouched
                        // here; the graph anti-wipe guard is keyed on
                        // entity-count collapse, not on embed errors.
                        let next = next_embed_error_backoff(
                            error_backoff,
                            embed_interval,
                            EMBED_ERROR_BACKOFF_MAX,
                        );
                        error_backoff = Some(next);
                        error!(
                            error = %e,
                            backoff_s = next.as_secs(),
                            "embedding worker error — backing off"
                        );
                        // Backoff bounds how fast this ladder retries and not how
                        // long it retries for, so a failure that never clears
                        // retries at the ceiling until the process dies. Charging
                        // each delay against a cumulative budget puts an end on
                        // it: the work parks with a reason a user can read
                        // instead of retrying out of sight forever.
                        if !embed_pass.charge_retry(
                            next,
                            embed_retry_budget,
                            "the background embedding worker",
                        ) {
                            error!(
                                budget_s = embed_retry_budget.as_secs(),
                                "embedding worker parked — cumulative retry budget exhausted (see /health background_passes)"
                            );
                        }
                        break;
                    }
                    Err(e) => {
                        consecutive_panics += 1;
                        if consecutive_panics >= MAX_CONSECUTIVE_PANICS {
                            // Mark the derived-index worker as permanently failed
                            // so /health surfaces the degraded state LOUDLY. The
                            // daemon keeps serving graph/locate/reconcile — the
                            // worker exiting must NOT take the whole process down
                            // (that was the exit(0) "silent death", #11).
                            embed_state
                                .embed_worker_failed
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            // Say it on the pass surface too. A reader looking at
                            // background passes must not see this worker sitting
                            // at `idle` when it is never coming back.
                            embed_pass.halt(format!(
                                "the embedding worker panicked {consecutive_panics} times in a row \
                                 and stopped; the vector index will not advance until the daemon \
                                 restarts and the daemon keeps serving graph, locate and reconcile"
                            ));
                            error!(
                                error = %e,
                                consecutive_panics,
                                "embedding worker permanently failed — vector index will not update until daemon restart; daemon continues in embed-degraded mode (see /health embed_worker_failed)"
                            );
                            drain_embed_flush(
                                &mut pending_flush,
                                &mut embedded_since_flush,
                                &embed_pass,
                            )
                            .await;
                            break 'wake;
                        }
                        error!(
                            error = %e,
                            consecutive_panics,
                            "embedding task panicked, respawning after 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                }

                // Cooperative cancellation: a shutdown signalled mid-drain must
                // not linger in the pacing sleep or loop back for another batch.
                // Break promptly the moment cancel is observed so only the single
                // in-flight blocking batch (which cannot itself observe the
                // signal) is left for the bounded teardown to handle.
                if *embed_cancel.borrow() {
                    info!("embedding worker stopping mid-drain on shutdown");
                    drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass)
                        .await;
                    break 'wake;
                }

                // Cooperative pause: let locate, persistence, and explicit
                // `/embed` requests acquire the embedding lock between background
                // batches during a long drain. A plain yield can let this worker
                // immediately reacquire and starve foreground benchmark backfill.
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            // Drain the tail flush at every drain-loop exit (pause, queue empty,
            // transient error, or panic respawn) so a persist started under the
            // throughput profile is always awaited before the worker idles or
            // re-enters the next wake — no flush outlives the loop unobserved.
            drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass).await;
        }
        embed_pass.idle();
    });

    // Order the cold sweep behind the embedding backfill.
    //
    // Until this gate the two were peer spawns in one process with nothing
    // between them: the sweep was queued at startup (`decide_sweep_on_start`
    // above) and the backfill started as soon as the daemon reported itself
    // initialized, so on a first boot they ran together. On a full-history store
    // inside a memory cap that is what killed the daemon, and the loss is not
    // symmetric. The backfill checkpoints as it goes, so a kill costs it the
    // batch in flight. Everything the sweep makes durable happens after its last
    // file, so a kill costs the sweep the whole pass and the next daemon sweeps
    // the same files again.
    //
    // So the one that checkpoints goes first. A store with nothing left to embed
    // is released on the gate's first look and behaves exactly as it did before
    // this existed.
    if sweep_admitted {
        let gate_state = Arc::clone(&state);
        let pending_state = Arc::clone(&state);
        let mut gate_cancel = cancel_rx.clone();
        // Read once, here, rather than inside the loop: both halves are fixed
        // for the life of the process, and a gate that re-read them could wait
        // on a backfill that was never going to run.
        let backfill_running =
            auto_embed_enabled() && pending_state.can_persist_embed_progress_locally();
        tokio::spawn(async move {
            let gate = await_backfill_before_sweep(
                backfill_running,
                move || pending_state.graph.embedding_status().pending,
                SWEEP_BACKFILL_WAIT_BOUND,
                SWEEP_BACKFILL_STALL_BOUND,
                SWEEP_BACKFILL_POLL_INTERVAL,
            );
            let reason = tokio::select! {
                // Biased so a shutdown that arrives while the gate waits ends it
                // rather than racing it. A daemon asked to stop must not queue a
                // sweep on its way out.
                biased;
                _ = gate_cancel.changed() => {
                    info!("daemon shutting down before the LSP sweep gate released; no sweep queued");
                    return;
                }
                reason = gate => reason,
            };
            info!(
                reason = reason.as_str(),
                wait_bound_s = SWEEP_BACKFILL_WAIT_BOUND.as_secs(),
                stall_bound_s = SWEEP_BACKFILL_STALL_BOUND.as_secs(),
                "queueing an LSP sweep so a graph with unenriched files converges"
            );
            gate_state.queue_lsp_sweep();
        });
    }

    // Spawn the background-work supervisor.
    //
    // The daemon is the only Kin process on a user's machine, so no watchdog
    // outside it will ever notice a pass that has wedged. This one keys on the
    // persisted-progress delta rather than on CPU utilization — a busy-spin pegs
    // a core while achieving nothing, so utilization cannot tell working from
    // stuck — and stops a pass that spends the machine without advancing,
    // announcing the stop through `/health` and `kin resources` rather than
    // leaving a warm fan as the only evidence.
    let supervisor_work = Arc::clone(&state.background_work);
    let supervisor_work_cancel = cancel_rx.clone();
    tokio::spawn(crate::background_work::run_background_work_supervisor(
        supervisor_work,
        supervisor_work_cancel,
    ));

    // Spawn the LSP enrichment worker (channel was set up before Arc::new).
    // Held rather than dropped. This worker owns the cold sweep, and everything
    // a sweep makes durable happens after its last file, so a shutdown that
    // does not wait for it throws away the whole pass. See
    // `drain_lsp_enrichment` below for what the waiting costs and when.
    let mut lsp_handle: Option<tokio::task::JoinHandle<()>> = None;
    if let Some(mut lsp_rx) = lsp_rx {
        let mut lsp_cancel = cancel_rx.clone();
        let lsp_state = Arc::clone(&state);
        // Canonicalize to resolve symlinks (macOS /tmp → /private/tmp).
        // RA needs rootUri and file URIs to match.
        let lsp_root = state
            .layout
            .working_dir()
            .canonicalize()
            .unwrap_or_else(|_| state.layout.working_dir().to_path_buf());
        // Registered with the self-limit supervisor. Unlike the projection
        // rebuild this pass is a real loop, so it has a checkpoint to read a
        // halt at and can be stopped rather than only disclosed.
        let lsp_pass = state.background_work.pass(crate::background_work::PASS_LSP);
        lsp_handle = Some(tokio::spawn(async move {
            info!("LSP enrichment worker started");
            let source_view = match lsp_state.graph_owned_source_view() {
                Ok(view) => view,
                Err(error) => {
                    error!(
                        error = %error,
                        "LSP enrichment worker cannot open graph-owned source authority"
                    );
                    return;
                }
            };
            let load_document = |path: &str| -> Option<String> {
                source_view
                    .load_text(&kin_model::FilePathId::new(path))
                    .ok()
            };
            let documents: Option<kin_lsp::DocumentProvider<'_>> = Some(&load_document);

            // Lazily start LSP servers on first use per language.
            let mut servers: std::collections::HashMap<
                kin_model::LanguageId,
                kin_lsp::lifecycle::LspServer,
            > = std::collections::HashMap::new();
            // Buffer for requests that arrive during server startup.
            let mut pending_buffer: Vec<crate::state::LspEnrichmentRequest> = Vec::new();
            // Track which languages have had their first didOpen processed.
            let mut first_open_done: std::collections::HashSet<kin_model::LanguageId> =
                std::collections::HashSet::new();

            loop {
                use crate::state::LspEnrichmentMessage;

                // The supervisor's verdict is read here, at the worker's own
                // checkpoint, so an enrichment in flight finishes rather than
                // being torn out from under the LSP server it is talking to.
                if lsp_pass.halted() {
                    for (lang, server) in servers {
                        info!(language = %lang, "shutting down LSP server");
                        let _ = server.shutdown().await;
                    }
                    info!("LSP enrichment worker stopped by the background-work supervisor");
                    break;
                }

                // A merge admitted while a pass was running left its demand on
                // the pending bit. Drained here, at the receive boundary, and
                // not only at a sweep's tail: the tail runs only when a sweep
                // completes, so a queue holding nothing but incremental work
                // would drain forever with the demand still sitting in the bit.
                drain_pending_lsp_sweep(&lsp_state);

                // Process buffered requests first (always incremental), then wait for new messages.
                let message = if let Some(buffered) = pending_buffer.pop() {
                    LspEnrichmentMessage::Incremental(buffered)
                } else {
                    // Blocked on the channel is genuinely doing nothing, so the
                    // working stretch ends here. A wedged enrichment never
                    // reaches this point, which is exactly why the stretch it
                    // started keeps accumulating and becomes observable.
                    lsp_pass.idle();
                    tokio::select! {
                        // Biased so shutdown wins over a queued message. Both
                        // arms are ready at once whenever a sweep is waiting
                        // when the cancel arrives, and an unbiased select picks
                        // between them at random: half the time a daemon that
                        // was asked to stop STARTS a sweep instead, and the
                        // shutdown then waits out its drain budget on work
                        // nobody can use.
                        biased;
                        _ = lsp_cancel.changed() => {
                            for (lang, server) in servers {
                                info!(language = %lang, "shutting down LSP server");
                                let _ = server.shutdown().await;
                            }
                            info!("LSP enrichment worker shutting down");
                            break;
                        }
                        Some(msg) = lsp_rx.recv() => msg,
                    }
                };
                lsp_pass.working(Instant::now());

                match message {
                    LspEnrichmentMessage::Incremental(request) => {
                        // The URI is a compatibility projection of the
                        // graph-owned repository path. didOpen content is
                        // loaded separately from repository authority below.
                        let path = lsp_root.join(&request.file_id.0);
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        let language = match ext {
                            "rs" => Some(kin_model::LanguageId::Rust),
                            "py" | "pyi" => Some(kin_model::LanguageId::Python),
                            "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                            "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                            "go" => Some(kin_model::LanguageId::Go),
                            "java" => Some(kin_model::LanguageId::Java),
                            "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => {
                                Some(kin_model::LanguageId::C)
                            }
                            _ => None,
                        };

                        let Some(lang) = language else {
                            continue;
                        };

                        // Lazily start LSP server for this language.
                        if !servers.contains_key(&lang) {
                            if let Some((cmd, args, init_opts)) = lsp_adapter_for(lang, &lsp_root) {
                                let args_refs: Vec<&str> =
                                    args.iter().map(|s| s.as_str()).collect();
                                match kin_lsp::lifecycle::LspServer::start(
                                    &cmd, &args_refs, &lsp_root, init_opts,
                                )
                                .await
                                {
                                    Ok(server) => {
                                        info!(language = %lang, "LSP server started, polling for readiness...");
                                        wait_for_lsp_index(&server, Duration::from_secs(60)).await;
                                        info!(language = %lang, "LSP server ready");
                                        servers.insert(lang, server);

                                        // Buffer the current request + drain any that arrived during startup.
                                        pending_buffer.push(request);
                                        while let Ok(queued) = lsp_rx.try_recv() {
                                            if let LspEnrichmentMessage::Incremental(req) = queued {
                                                pending_buffer.push(req);
                                            }
                                            // Sweep messages are not buffered — they'll be re-sent if needed.
                                        }
                                        info!(
                                            buffered = pending_buffer.len(),
                                            "replaying requests after server startup"
                                        );
                                        continue; // Re-enter loop to process from buffer
                                    }
                                    Err(e) => {
                                        debug!(language = %lang, error = %e, "failed to start LSP server");
                                        continue;
                                    }
                                }
                            }
                        }

                        // Build entity index from graph for matching LSP locations.
                        let Some(server) = servers.get(&lang) else {
                            continue;
                        };
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities
                            .iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                // Compute name position by finding name in signature.
                                // LSP needs cursor on name, not declaration start.
                                let name_col =
                                    lsp_query_column(&e.signature, &e.name, span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();
                        let index = kin_lsp::EntityIndex::new(entity_refs);

                        // Open exact graph/CAS bytes in the LSP server. A
                        // missing body or authority mismatch fails this
                        // enrichment request loudly; the working tree is never
                        // allowed to repair or answer it.
                        let file_content = match source_view.load_text(&request.file_id) {
                            Ok(content) => content,
                            Err(error) => {
                                warn!(
                                    file = %request.file_id,
                                    error = %error,
                                    "LSP enrichment skipped because graph-owned source could not be loaded"
                                );
                                continue;
                            }
                        };
                        let file_uri = kin_lsp::protocol::path_to_uri(&path);
                        let lang_str = match lang {
                            kin_model::LanguageId::Rust => "rust",
                            kin_model::LanguageId::Python => "python",
                            kin_model::LanguageId::TypeScript => "typescript",
                            kin_model::LanguageId::JavaScript => "javascript",
                            kin_model::LanguageId::Go => "go",
                            kin_model::LanguageId::Java => "java",
                            kin_model::LanguageId::C | kin_model::LanguageId::Cpp => "c",
                            _ => "plaintext",
                        };
                        let _ = server
                            .client
                            .notify(
                                "textDocument/didOpen",
                                serde_json::json!({
                                    "textDocument": {
                                        "uri": file_uri,
                                        "languageId": lang_str,
                                        "version": 1,
                                        "text": file_content,
                                    }
                                }),
                            )
                            .await;

                        // On first file per language, wait for RA to process the didOpen.
                        // Subsequent files don't need this — RA is already indexed.
                        if first_open_done.insert(lang) {
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }

                        let rel_path = request.file_id.0.clone();

                        // Cap: if too many entities changed, it's a full re-parse — skip
                        // this batch to avoid flooding the LSP server. Incremental changes
                        // (1-10 entities) get enriched; bulk changes wait for next edit.
                        const MAX_ENTITIES_PER_REQUEST: usize = 20;
                        if request.changed_entity_ids.len() > MAX_ENTITIES_PER_REQUEST {
                            debug!(
                                path = %rel_path,
                                count = request.changed_entity_ids.len(),
                                max = MAX_ENTITIES_PER_REQUEST,
                                "skipping LSP enrichment — too many changed entities (likely full re-parse)"
                            );
                            continue;
                        }

                        info!(
                            path = %rel_path,
                            entities = request.changed_entity_ids.len(),
                            "enriching changed entities via LSP"
                        );

                        // Only enrich the entities that actually changed.
                        let file_entities: Vec<kin_lsp::EntityRef> = request
                            .changed_entity_ids
                            .iter()
                            .filter_map(|id| {
                                let entity = entities.iter().find(|e| e.id == *id)?;
                                let fo = entity.file_origin.as_ref()?;
                                let span = entity.span.as_ref()?;
                                let name_col = lsp_query_column(
                                    &entity.signature,
                                    &entity.name,
                                    span.start_col as u32,
                                );
                                Some(kin_lsp::EntityRef {
                                    id: entity.id,
                                    name: entity.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();

                        let mut pending = PendingEnrichment::default();
                        let mut total_relations = EnrichmentWrite::default();
                        for entity_ref in &file_entities {
                            info!(entity = %entity_ref.name, "querying LSP for entity");
                            let derived = enrich_single_entity(
                                server, entity_ref, &index, &lsp_root, documents,
                            )
                            .await;
                            total_relations += pending
                                .absorb(derived, |batch| install_lsp_relations(&lsp_state, batch));
                        }
                        total_relations +=
                            pending.flush(|batch| install_lsp_relations(&lsp_state, batch));

                        if total_relations.published > 0 {
                            info!(
                                path = %rel_path,
                                relations = total_relations.published,
                                "LSP enrichment added relations"
                            );
                            lsp_state.mark_dirty();
                            // Relations reaching the graph is this pass's unit of
                            // durable work, so it is what the supervisor is told
                            // about. Querying an LSP server and finding nothing is
                            // not progress, and crediting it would let a worker
                            // that answers "no relations" forever look healthy.
                            lsp_pass.advanced(total_relations.published as u64, Instant::now());
                        } else {
                            info!(
                                path = %rel_path,
                                entities_queried = file_entities.len(),
                                "LSP enrichment completed — no new relations found"
                            );
                        }
                    } // end Incremental

                    LspEnrichmentMessage::Sweep => {
                        info!("LSP cold sweep started, enriching all entities");
                        // Durable, and before any work, so a process that ends
                        // between here and the tail leaves the store saying so.
                        // First, because "any work" includes the probe below.
                        sweep_started(&lsp_state);
                        // Re-probe here, not only at daemon start. Readiness
                        // taken once latches: a user who follows Kin's own
                        // advice and installs the server it just named leaves a
                        // long-lived daemon reporting that language unavailable
                        // for the rest of its life, and the stale answer is an
                        // input under an agent-facing verdict. A sweep is the
                        // moment the daemon is about to want servers, so it is
                        // the firing point that needs no new signal invented.
                        // Same probe-then-publish as at start, and it overwrites
                        // rather than merges, because a fresh answer supersedes
                        // an old one wholesale.
                        spawn_language_server_readiness_probe(lsp_root.clone());
                        lsp_state
                            .lsp_sweep_running
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        lsp_state
                            .lsp_sweep_files_done
                            .store(0, std::sync::atomic::Ordering::SeqCst);

                        // The marker generation this pass's answers describe,
                        // captured with the entity snapshot they are taken over
                        // rather than at the tail, because the tail is where
                        // the record is written and by then the graph may have
                        // moved underneath every answer in it.
                        let marker_epoch = current_marker_epoch(&lsp_state);

                        // Get all entities from the graph.
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };

                        // Group entities by file.
                        let mut by_file: std::collections::HashMap<
                            kin_model::FilePathId,
                            Vec<&kin_model::Entity>,
                        > = std::collections::HashMap::new();
                        for entity in &entities {
                            if let Some(ref fo) = entity.file_origin {
                                by_file.entry(fo.clone()).or_default().push(entity);
                            }
                        }

                        let total_files = by_file.len();
                        lsp_state
                            .lsp_sweep_files_total
                            .store(total_files as u64, std::sync::atomic::Ordering::SeqCst);
                        let mut tally = SweepTally::default();
                        let mut enriched_this_sweep: Vec<String> = Vec::new();
                        let file_definitions_budget = lsp_file_definitions_budget();
                        let mut total_relations = EnrichmentWrite::default();
                        // Languages whose server refused to start, remembered for
                        // the rest of this sweep. Without it the loop retries the
                        // start once per FILE: express logged 66 spawn attempts
                        // per sweep and 462 across one session, every one of them
                        // a process spawn plus a 30-second-capped initialize
                        // handshake, and none of them could succeed for a reason
                        // that had nothing to do with the file being visited.
                        let mut server_start_failed: std::collections::HashSet<
                            kin_model::LanguageId,
                        > = std::collections::HashSet::new();
                        // What this process OBSERVED when it tried to serve each
                        // language it could not, and how many files that cost.
                        // `files_blocked` counts files and cannot name a
                        // language, which is why a completion line could read
                        // "complete (5/303 files)" over a pass whose Rust server
                        // never started. Kept beside the set rather than
                        // replacing it so the retry short-circuit above stays a
                        // set membership test.
                        let mut skip_reason: std::collections::HashMap<
                            kin_model::LanguageId,
                            String,
                        > = std::collections::HashMap::new();
                        let mut skip_files: std::collections::HashMap<kin_model::LanguageId, u64> =
                            std::collections::HashMap::new();

                        // Build entity index for the whole graph (used for target matching).
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities
                            .iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                let name_col =
                                    lsp_query_column(&e.signature, &e.name, span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();
                        let index = kin_lsp::EntityIndex::new(entity_refs);

                        for (file_id, file_entities) in &by_file {
                            let abs_path = lsp_root.join(&file_id.0);

                            // Determine language from file extension.
                            let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            let language = match ext {
                                "rs" => Some(kin_model::LanguageId::Rust),
                                "py" | "pyi" => Some(kin_model::LanguageId::Python),
                                "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                                "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                                "go" => Some(kin_model::LanguageId::Go),
                                "java" => Some(kin_model::LanguageId::Java),
                                "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => {
                                    Some(kin_model::LanguageId::C)
                                }
                                _ => None,
                            };
                            let Some(lang) = language else {
                                tally.unsupported_language += 1;
                                continue;
                            };

                            // Skip a file this graph already holds language-server
                            // evidence for. This is what makes the sweep idempotent
                            // and resumable: a pass killed halfway leaves the files
                            // it finished carrying Lsp-origin edges, so the next
                            // pass starts where the last one stopped instead of
                            // re-querying the server for every entity again. On the
                            // requests corpus a full pass is about three minutes,
                            // so re-running one from scratch on every daemon start
                            // is not a cost anyone would accept, and a sweep nobody
                            // dares run is a sweep that never runs.
                            if file_already_enriched(&lsp_state, &file_id.0) {
                                tally.already_enriched += 1;
                                // Published here as well as on the enriching
                                // arm, because `files_done` means a file the
                                // sweep is done with and a skip is one. Stored
                                // only there, a sweep over a converged store
                                // reported `files_done=0 files_total=4` while
                                // its own completion line said
                                // `already_enriched=4`, and every waiter reads
                                // the counter rather than the line: `kin init`
                                // and `kin daemon sweep` both print "finished
                                // without enriching any of the 4 files it
                                // walked" over a repository that is fully
                                // enriched. The alarm was the reporting, not
                                // the store.
                                lsp_state.lsp_sweep_files_done.store(
                                    tally.files_processed() as u64,
                                    std::sync::atomic::Ordering::SeqCst,
                                );
                                // Info, not debug. A skip and a zero are different
                                // facts and both are findings, and a skip nobody can
                                // see is how a predicate that dropped the three files
                                // this ticket is about survived a run that reported
                                // 37 of 37 complete.
                                info!(
                                    file = %file_id.0,
                                    progress = %format!(
                                        "{}/{total_files}",
                                        tally.files_processed()
                                    ),
                                    "sweep skipped an already-enriched file"
                                );
                                continue;
                            }

                            // A language whose server already refused to start is
                            // not retried for every remaining file.
                            if server_start_failed.contains(&lang) {
                                tally.server_unavailable += 1;
                                *skip_files.entry(lang).or_insert(0) += 1;
                                continue;
                            }

                            // Lazily start LSP server for this language (same as incremental).
                            if !servers.contains_key(&lang) {
                                if let Some((cmd, args, init_opts)) =
                                    lsp_adapter_for(lang, &lsp_root)
                                {
                                    let args_refs: Vec<&str> =
                                        args.iter().map(|s| s.as_str()).collect();
                                    match kin_lsp::lifecycle::LspServer::start(
                                        &cmd, &args_refs, &lsp_root, init_opts,
                                    )
                                    .await
                                    {
                                        Ok(server) => {
                                            info!(language = %lang, "LSP server started for sweep, polling for readiness...");
                                            wait_for_lsp_index(&server, Duration::from_secs(60))
                                                .await;
                                            info!(language = %lang, "LSP server ready");
                                            servers.insert(lang, server);
                                        }
                                        Err(e) => {
                                            // Warn, and once per language rather
                                            // than once per file. At debug this
                                            // was invisible on a default daemon,
                                            // so the only trace a whole language
                                            // failed to enrich was a sweep that
                                            // reported zero files and called
                                            // itself complete.
                                            warn!(
                                                language = %lang,
                                                command = %cmd,
                                                error = %e,
                                                "could not start the language server for this sweep; \
                                                 files in this language are left unenriched"
                                            );
                                            server_start_failed.insert(lang);
                                            skip_reason.entry(lang).or_insert_with(|| {
                                                format!(
                                                    "the `{cmd}` language server did not start \
                                                     ({e}), so nothing in this language was \
                                                     enriched"
                                                )
                                            });
                                            tally.server_unavailable += 1;
                                            *skip_files.entry(lang).or_insert(0) += 1;
                                            continue;
                                        }
                                    }
                                }
                            }

                            let Some(server) = servers.get(&lang) else {
                                // No adapter is wired for this language, so no
                                // start was even attempted. Counted, because an
                                // uncounted file is how `files=0 total_files=66`
                                // came to read as a completed sweep.
                                server_start_failed.insert(lang);
                                skip_reason.entry(lang).or_insert_with(|| {
                                    "this build wires no language server for this language, so \
                                     none was started"
                                        .to_string()
                                });
                                tally.server_unavailable += 1;
                                *skip_files.entry(lang).or_insert(0) += 1;
                                continue;
                            };

                            // didOpen exact graph/CAS content. The compatibility
                            // path may not exist on the host; that must not
                            // affect graph-owned semantic enrichment.
                            let file_content = match source_view.load_text(file_id) {
                                Ok(content) => content,
                                Err(error) => {
                                    warn!(
                                        file = %file_id,
                                        error = %error,
                                        "LSP sweep skipped graph source that could not be loaded from authority"
                                    );
                                    tally.source_unreadable += 1;
                                    continue;
                                }
                            };
                            let uri = kin_lsp::protocol::path_to_uri(&abs_path);
                            let lang_str = match lang {
                                kin_model::LanguageId::Rust => "rust",
                                kin_model::LanguageId::Python => "python",
                                kin_model::LanguageId::TypeScript => "typescript",
                                kin_model::LanguageId::JavaScript => "javascript",
                                kin_model::LanguageId::Go => "go",
                                kin_model::LanguageId::Java => "java",
                                kin_model::LanguageId::C | kin_model::LanguageId::Cpp => "c",
                                _ => "plaintext",
                            };
                            let _ = server.client.notify("textDocument/didOpen", serde_json::json!({
                            "textDocument": { "uri": uri, "languageId": lang_str, "version": 1, "text": file_content }
                        })).await;

                            // First file per language gets a processing delay.
                            if first_open_done.insert(lang) {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            }

                            // Enrich each entity in this file.
                            let file_entity_refs: Vec<kin_lsp::EntityRef> = file_entities
                                .iter()
                                .filter_map(|e| {
                                    let span = e.span.as_ref()?;
                                    let name_col = lsp_query_column(
                                        &e.signature,
                                        &e.name,
                                        span.start_col as u32,
                                    );
                                    Some(kin_lsp::EntityRef {
                                        id: e.id,
                                        name: e.name.clone(),
                                        file_path: file_id.0.clone(),
                                        start_line: span.start_line as u32,
                                        start_col: span.start_col as u32,
                                        end_line: span.end_line as u32,
                                        name_line: span.start_line as u32,
                                        name_col,
                                    })
                                })
                                .collect();

                            // File-level enrichment: query definition at every identifier
                            // to capture ALL relationships (40-50x more than per-entity).
                            let file_result = file_definitions_within_budget(
                                kin_lsp::file_enrichment::enrich_file_definitions(
                                    server,
                                    &abs_path,
                                    &file_content,
                                    &index,
                                    &lsp_root,
                                    documents,
                                ),
                                file_definitions_budget,
                                &file_id.0,
                                &mut tally,
                            )
                            .await;

                            // One buffer for the whole file, drained in bounded
                            // batches. What a file yields is a property of the
                            // repository (1167 relations from one file on the
                            // requests corpus), so the buffer bounds itself
                            // rather than trusting the file to be small.
                            let mut pending = PendingEnrichment::default();
                            let mut file_relations = pending
                                .absorb(file_result.relations, |batch| {
                                    install_lsp_relations(&lsp_state, batch)
                                });

                            // Also run per-entity call hierarchy for Calls relations
                            // (definition approach gives References, call hierarchy gives Calls).
                            for entity_ref in &file_entity_refs {
                                let derived = enrich_single_entity(
                                    server, entity_ref, &index, &lsp_root, documents,
                                )
                                .await;
                                file_relations += pending.absorb(derived, |batch| {
                                    install_lsp_relations(&lsp_state, batch)
                                });
                            }
                            // Written before the file is closed, so the graph
                            // holds this file's work before the next didOpen.
                            file_relations +=
                                pending.flush(|batch| install_lsp_relations(&lsp_state, batch));

                            // didClose to free LSP server memory.
                            let _ = server
                                .client
                                .notify(
                                    "textDocument/didClose",
                                    serde_json::json!({
                                        "textDocument": { "uri": uri }
                                    }),
                                )
                                .await;

                            tally.enriched += 1;
                            enriched_this_sweep.push(file_id.0.clone());
                            lsp_state.lsp_sweep_files_done.store(
                                tally.files_processed() as u64,
                                std::sync::atomic::Ordering::SeqCst,
                            );
                            total_relations += file_relations;
                            // Credited per file rather than once at the end. A
                            // cold sweep walks the whole graph, and a pass that
                            // reported nothing until it finished would look
                            // stalled for the entire run and be stopped part
                            // way through exactly the work a user asked for.
                            if file_relations.published > 0 {
                                lsp_pass.advanced(file_relations.published as u64, Instant::now());
                            }

                            if file_relations.published > 0 {
                                info!(
                                    file = %file_id,
                                    relations = file_relations.published,
                                    progress = format!("{}/{}", tally.files_processed(), total_files),
                                    "sweep enriched file"
                                );
                            } else {
                                // A file the sweep visited and got nothing from is a
                                // finding, not a non-event. Only enriched files used
                                // to be logged, so a pass could report itself complete
                                // over 37 files while the three that carried the
                                // answers produced nothing, and the log said only that
                                // the other 34 went fine. On the requests corpus that
                                // is exactly what happened: sessions.py, auth.py and
                                // adapters.py each yielded zero while a test file
                                // yielded a thousand.
                                info!(
                                    file = %file_id,
                                    entities = file_entity_refs.len(),
                                    progress = format!("{}/{}", tally.files_processed(), total_files),
                                    "sweep enriched NOTHING for this file"
                                );
                            }

                            // Check for shutdown between files.
                            if *lsp_cancel.borrow() {
                                tally.ended_early = true;
                                break;
                            }
                            // Same checkpoint, for the supervisor's verdict. A
                            // sweep that is burning the CPU without enriching
                            // anything stops here, between files, rather than
                            // mid-request to a language server.
                            if lsp_pass.halted() {
                                tally.ended_early = true;
                                info!("LSP cold sweep stopped by the background-work supervisor");
                                break;
                            }
                        }

                        if total_relations.published > 0 {
                            lsp_state.mark_dirty();
                        }

                        // Record the relation census this sweep produced,
                        // before the publication below makes it durable.
                        //
                        // The sweep's relations are all in the live graph by
                        // here; what remains is writing them to disk. Taking
                        // the census now means the record describes the graph
                        // the snapshot is about to publish, and a census taken
                        // afterwards would be a second reading of the same
                        // graph for no gain. `kin graph status` compares its
                        // own census against this record, which is what lets it
                        // notice a relation kind that went to zero instead of
                        // printing the histogram that proves the loss and then
                        // an all-clear over it.
                        crate::background_work::record_relation_census(
                            &lsp_state.layout,
                            lsp_state.graph.as_ref(),
                            kin_core::relation_census::CensusSource::Sweep,
                        );

                        // Publish this sweep's enrichment ONCE, here, and wait
                        // for it.
                        //
                        // Publication is not a separate path: it happens inside
                        // save_snapshot_impl, so the background flush IS the
                        // publication. Leaving it to that flush is what made
                        // suppressing the flush lose the work entirely. Measured
                        // on a converted psf/requests store: a sweep enriched 37
                        // files and 4231 relations, the daemon began idle
                        // shutdown 65 ms after the sweep ended, logged its final
                        // shutdown flush, and then reported that tasks had not
                        // stopped within 10 s. That flush takes about 96 s on
                        // this store. Nothing was published, and the whole sweep
                        // was lost on a path `kin init` takes every time.
                        //
                        // Ordering carries the guarantee. This runs BEFORE the
                        // running flag clears and before the completion counter
                        // advances, so the sweep is still in flight while it
                        // happens: nothing reads the daemon as idle, and a
                        // caller waiting for the sweep (`kin init` does) waits
                        // for durability rather than for a promise of it.
                        //
                        // Both exits, deliberately. The loop reaches here after
                        // a clean finish AND after breaking early on shutdown or
                        // a supervisor halt, so an interrupted sweep still makes
                        // durable what it actually completed, and the crash
                        // window narrows to a hard kill, which the resume marker
                        // already recovers by re-sweeping.
                        let published = if total_relations.published > 0 {
                            match save_snapshot_blocking(Arc::clone(&lsp_state)).await {
                                Ok(()) => {
                                    lsp_state.mark_clean();
                                    true
                                }
                                Err(error) => {
                                    // Loud, and not fatal. The relations stay in
                                    // the live graph and the resume marker still
                                    // records what was enriched, so the next
                                    // sweep re-derives them; what must not happen
                                    // is losing this silently, which is the
                                    // defect being closed.
                                    warn!(
                                        %error,
                                        relations = total_relations.published,
                                        "could not publish this sweep's enrichment; the \
                                         relations stay live and the next sweep re-derives them"
                                    );
                                    false
                                }
                            }
                        } else {
                            false
                        };

                        // The breaker's count moves on the sweep's own outcome,
                        // and is persisted because the loop it guards spans
                        // daemon restarts rather than living inside one. The
                        // same call clears the in-flight record, so reaching
                        // here is what makes this sweep a finished one.
                        let interruptions =
                            sweep_finished(&lsp_state, tally.ended_early, tally.enriched);

                        // The marker records durability, so it is written here
                        // and only here, after the publication above settled it.
                        // The set and the count come from the same arm, so a
                        // divergence means a file was counted enriched without
                        // being recorded, or recorded without being counted.
                        // Either way the marker would stop describing the sweep.
                        if enriched_this_sweep.len() != tally.enriched {
                            warn!(
                                recorded = enriched_this_sweep.len(),
                                counted = tally.enriched,
                                "the enriched-file set and the enriched count disagree; the \
                                 marker no longer describes this sweep"
                            );
                        }
                        if sweep_marker_is_durable(total_relations, published) {
                            mark_files_enriched(&lsp_state, &enriched_this_sweep, marker_epoch);
                        } else {
                            warn!(
                                files = enriched_this_sweep.len(),
                                relations = total_relations.published,
                                "not recording these files as enriched: their relations were \
                                 not published, so the next sweep must redo them"
                            );
                        }

                        // Marked complete even when the loop broke early on
                        // shutdown or a supervisor halt. What was enriched is
                        // durable either way, and the next sweep resumes from
                        // it. The reason the counters move together, and the
                        // demand this drains, are on the function.
                        complete_lsp_sweep(&lsp_state, tally.blocked() as u64);
                        // Published with the counts, so a caller reading a
                        // nonzero blocked count can also say which language it
                        // lost and what this process saw. Replaces the previous
                        // sweep's record wholesale: a fresh answer supersedes an
                        // old one, and a merged one would keep naming a language
                        // whose server now starts.
                        {
                            let mut skipped: Vec<crate::state::SweepLanguageSkip> = skip_files
                                .iter()
                                .map(|(language, files)| crate::state::SweepLanguageSkip {
                                    language: language.to_string(),
                                    files: *files,
                                    reason: skip_reason.get(language).cloned().unwrap_or_else(
                                        || {
                                            "this sweep could not serve the language and did not \
                                             record why"
                                                .to_string()
                                        },
                                    ),
                                })
                                .collect();
                            // A HashMap iterates in an arbitrary order, so two
                            // broken servers would otherwise hand the same host
                            // a different sentence each run.
                            skipped.sort_by(|a, b| a.language.cmp(&b.language));
                            if let Ok(mut slot) = lsp_state.lsp_sweep_languages_skipped.lock() {
                                *slot = skipped;
                            }
                        }
                        let unaccounted = tally.unaccounted(total_files);
                        let not_visited = tally.not_visited(total_files);

                        // The sweep's own zero-loss verdict, written where a
                        // later process can read it. A pass that published
                        // everything it offered with nothing left stale retires
                        // the record; anything else writes it, because a
                        // shortfall that reaches only a log line reaches nobody.
                        //
                        // Recorded here rather than inside the per-batch write:
                        // the claim is about the sweep, and a per-batch record
                        // under last-writer-wins would report whatever the final
                        // batch happened to do.
                        if total_relations.lost() > 0 || total_relations.vector_stale > 0 {
                            warn!(
                                offered = total_relations.offered,
                                published = total_relations.published,
                                lost = total_relations.lost(),
                                vector_stale = total_relations.vector_stale,
                                "this sweep did not publish everything it offered"
                            );
                            kin_daemon_spawn::RefusedEnrichment::record(
                                lsp_state.layout.root(),
                                total_relations.lost() as u32,
                                total_relations.offered as u32,
                                total_relations.vector_stale as u32,
                            );
                        } else {
                            kin_daemon_spawn::RefusedEnrichment::clear(lsp_state.layout.root());
                        }

                        info!(
                            files = tally.files_processed(),
                            total_files,
                            relations = total_relations.published,
                            enriched = tally.enriched,
                            already_enriched = tally.already_enriched,
                            unsupported_language = tally.unsupported_language,
                            server_unavailable = tally.server_unavailable,
                            source_unreadable = tally.source_unreadable,
                            definitions_over_budget = tally.definitions_over_budget,
                            not_visited,
                            ended_early = tally.ended_early,
                            published,
                            consecutive_fruitless_interruptions = interruptions,
                            unaccounted,
                            "LSP cold sweep complete"
                        );
                        // A sweep that finished having done nothing is a
                        // finding, and it used to be indistinguishable from a
                        // converged one. Both printed `files=0`.
                        if let Some(reason) = tally.blocked_reason(total_files) {
                            warn!(
                                total_files,
                                server_unavailable = tally.server_unavailable,
                                source_unreadable = tally.source_unreadable,
                                unsupported_language = tally.unsupported_language,
                                "LSP cold sweep enriched no files: {reason}"
                            );
                        }
                        if unaccounted > 0 {
                            warn!(
                                unaccounted,
                                total_files,
                                "LSP cold sweep left files unaccounted for; an exit from the \
                                 sweep loop is not being counted"
                            );
                        }
                    } // end Sweep
                } // end match
            }
        }));
    }

    // Persistent daemons stay alive until SIGTERM/SIGINT, `kin eject`, or
    // `kin setup doctor`. CLI-autostarted daemons opt into idle shutdown via
    // KIN_DAEMON_IDLE_TIMEOUT_SECS.

    // Wait for either task to finish (or fail), or a shutdown signal.
    // When one exits, signal the others to shut down.
    //
    // SIGTERM handling is Unix-only (used in Docker containers).
    // On Windows we rely solely on ctrl_c() (Ctrl+C / CTRL_C_EVENT).
    let result = select_with_signals(
        loop_handle,
        api_handle,
        sweep_handle,
        embed_handle,
        idle_handle,
        persist_handle,
        supervisor_handle,
        lsp_handle,
        cancel_tx,
    )
    .await;

    // The derived ingestion CAS defers its directory barriers and commits them
    // on an explicit sync, on drop, or on a self-drain. This process ends in
    // `process::exit`, which runs no destructor, so the barrier has to be
    // issued here or the only one that ever fires is the self-drain.
    sync_blob_store_blocking(Arc::clone(&state)).await;

    // Remove PID and port files after final flush work finishes, so a successor
    // daemon cannot start while this process is still draining persistent state.
    crate::lifecycle::remove_daemon_files_if_current_process(state.layout.root());

    result
}

/// Issue the ingestion CAS barrier off the async workers: it is a run of
/// `fsync` calls on directories, one per shard touched since the last commit.
async fn sync_blob_store_blocking(state: Arc<DaemonState>) {
    let outcome = tokio::task::spawn_blocking(move || state.sync_blob_store()).await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(%error, "ingestion CAS barrier failed on shutdown")
        }
        Err(error) => {
            warn!(%error, "ingestion CAS barrier task failed on shutdown")
        }
    }
}

#[cfg(unix)]
async fn select_with_signals(
    mut loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    mut api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    mut sweep_handle: tokio::task::JoinHandle<()>,
    embed_handle: tokio::task::JoinHandle<()>,
    mut idle_handle: tokio::task::JoinHandle<()>,
    persist_handle: tokio::task::JoinHandle<()>,
    supervisor_handle: tokio::task::JoinHandle<()>,
    lsp_handle: Option<tokio::task::JoinHandle<()>>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(DaemonError::Io)?;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CompletedTask {
        Reconciliation,
        Api,
        Sweeper,
        Idle,
        Signal,
    }

    let (completed, result) = tokio::select! {
        // NOTE: this arm shuts the daemon down, so the reconciliation loop
        // must only exit for reasons that end the daemon: the cancel signal,
        // or a real startup/runtime error. A background-work supervisor stop
        // parks the loop inside `run_loop` instead of exiting it, precisely
        // because reaching this arm cancels the API task and every other
        // task, the opposite of the stop announcement's "the daemon keeps
        // serving" (FIR-2317).
        result = &mut loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Reconciliation, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        result = &mut api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Api, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        _ = &mut sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Sweeper, Ok(()))
        }
        // NOTE: the embedding worker is deliberately NOT a select! arm. Embeddings
        // are a DERIVED index, so the worker exiting (e.g. exhausting its
        // consecutive-panic budget under heavy umbrella-scale load) must NOT shut
        // the daemon down — doing so produced a clean exit(0) that read as an
        // intentional shutdown and left the daemon silently dead (#11). The worker
        // now sets `embed_worker_failed`; the daemon keeps serving
        // graph/locate/reconcile in an embed-degraded state, surfaced LOUDLY via
        // /health. `embed_handle` is handed to `drain_handles` only on a REAL
        // shutdown below.
        _ = &mut idle_handle => {
            info!("idle monitor exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Idle, Ok(()))
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
    };

    // Before `drain_handles`, and so before the final persistence flush that
    // kin#994 gave its own budget and drains ahead of everything else. Order is
    // the whole point twice over. A sweep publishes into the graph, so letting
    // it finish first is what puts its relations in the flush rather than in the
    // next daemon's re-derivation, and a flush that can legitimately run for
    // minutes would otherwise spend the entire escalation grace before the sweep
    // was ever asked to stop.
    drain_lsp_enrichment(lsp_handle).await;

    drain_handles(
        (completed != CompletedTask::Reconciliation).then_some(loop_handle),
        (completed != CompletedTask::Api).then_some(api_handle),
        (completed != CompletedTask::Sweeper).then_some(sweep_handle),
        Some(embed_handle),
        (completed != CompletedTask::Idle).then_some(idle_handle),
        Some(persist_handle),
        Some(supervisor_handle),
    )
    .await;
    result
}

/// Ceiling on how long a shutdown waits for an in-flight cold sweep to reach
/// its own end.
///
/// A ceiling, not an amount of waiting. The enrichment worker's idle arm selects
/// on the cancel signal, so a daemon with no sweep running joins immediately
/// however large this is, and the budget is spent only when a sweep is actually
/// mid-file. What it buys is the sweep's tail, which is where the publication,
/// the resume marker, the interruption count and the completion line all live.
/// Without it a shutdown lands between the first file and the last and the
/// whole pass is lost: measured on a four-file Python store, a SIGTERM 327 ms
/// into a sweep drained all seven other tasks by name, produced no completion
/// line at all, and left the store carrying neither a resume marker nor an
/// interruption count.
///
/// Derived from the escalation grace rather than written as a number, because
/// the escalation watchdog is the real hard bound: it force-exits the process
/// once the grace elapses, and a drain budget larger than that is a promise the
/// process cannot keep. It would also be silent, since a force-exit runs no
/// warning. Half, so the flush, the derived-CAS barrier and endpoint retirement
/// still have the other half to finish in.
fn lsp_drain_budget_from(escalation_grace: Duration) -> Duration {
    escalation_grace / 2
}

fn lsp_drain_budget() -> Duration {
    lsp_drain_budget_from(shutdown_escalation_grace())
}

/// Wait for the enrichment worker to finish what it was doing, under a ceiling.
async fn drain_lsp_enrichment(handle: Option<tokio::task::JoinHandle<()>>) {
    let Some(handle) = handle else {
        return;
    };
    let budget = lsp_drain_budget();
    match tokio::time::timeout(budget, handle).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(%error, "the LSP enrichment worker panicked during shutdown")
        }
        Err(_) => warn!(
            budget_secs = budget.as_secs(),
            "an LSP sweep did not reach its end within the shutdown budget; this store records \
             it as in flight and the next daemon sweeps its files again"
        ),
    }
}

async fn drain_handles(
    loop_handle: Option<
        tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    >,
    api_handle: Option<tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>>,
    sweep_handle: Option<tokio::task::JoinHandle<()>>,
    embed_handle: Option<tokio::task::JoinHandle<()>>,
    idle_handle: Option<tokio::task::JoinHandle<()>>,
    persist_handle: Option<tokio::task::JoinHandle<()>>,
    supervisor_handle: Option<tokio::task::JoinHandle<()>>,
) {
    let drain_timeout = Duration::from_secs(10);
    info!("draining task handles before cleanup...");

    // Persistence drains on its own budget, and before the rest.
    //
    // It used to share the ten seconds below with six other tasks, and it is the
    // only one that can need minutes: its shutdown arm performs the final
    // flush, and a flush IS the publication, so a store with pending work
    // cannot become durable in ten seconds. Measured on a converted psf/requests
    // store (6491 commits), flushes completed at 96245, 96636 and 107496 ms
    // against that ten-second drain, and the daemon logged only that "one or
    // more daemon tasks did not stop within 10s", which reads as a slow
    // shutdown rather than as discarded durability.
    //
    // A longer budget costs an idle daemon nothing. The persistence task's
    // shutdown arm returns immediately when the graph is not dirty, so this is
    // a ceiling on waiting rather than an amount of waiting: time is spent here
    // only when there is work to lose, which is exactly when spending it is
    // right.
    let persistence = drain_persistence(persist_handle, shutdown_flush_budget()).await;

    let mut drain_tasks = Vec::new();

    macro_rules! join_or_warn {
        ($name:expr, $handle:expr) => {
            if let Some(handle) = $handle {
                drain_tasks.push(tokio::spawn(async move {
                    match handle.await {
                        Ok(_) => info!(task = $name, "task drained"),
                        Err(e) => warn!(task = $name, error = %e, "task panicked during drain"),
                    }
                }));
            }
        };
    }

    join_or_warn!("reconciliation", loop_handle);
    join_or_warn!("api", api_handle);
    join_or_warn!("sweeper", sweep_handle);
    join_or_warn!("embedding", embed_handle);
    join_or_warn!("idle-monitor", idle_handle);
    join_or_warn!("supervisor-registration", supervisor_handle);

    if tokio::time::timeout(drain_timeout, async {
        for task in drain_tasks {
            let _ = task.await;
        }
    })
    .await
    .is_err()
    {
        warn!(
            drain_timeout_s = drain_timeout.as_secs(),
            "one or more daemon tasks did not stop within the drain budget, proceeding. \
             Persistence is not among them; it drains separately and reported above."
        );
    }
    if persistence == PersistenceDrain::Abandoned {
        // Named, because the generic drain warning above is what hid this. A
        // reader must be able to tell "a task was slow to stop" from "durable
        // work was discarded", and only one of those is data loss.
        warn!(
            budget_s = shutdown_flush_budget().as_secs(),
            "the final persistence flush did not finish within its shutdown budget and was \
             abandoned; graph mutations it had not yet published are NOT durable and will be \
             re-derived or lost. Raise KIN_DAEMON_SHUTDOWN_FLUSH_SECS if this store needs longer."
        );
    }
}

/// How long shutdown waits for the final persistence flush.
///
/// Generous by default because the cost is bounded by the work outstanding: an
/// idle daemon's persistence arm returns at once and never touches this budget.
/// Measured flushes on a converted psf/requests store ran 96 to 108 seconds, so
/// a ten-second drain could not have completed one, and five minutes clears them
/// with room while still bounding a pathological case rather than hanging.
fn shutdown_flush_budget() -> Duration {
    duration_from_env_secs("KIN_DAEMON_SHUTDOWN_FLUSH_SECS", Duration::from_secs(300))
}

/// What became of the persistence task during shutdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PersistenceDrain {
    /// No persistence task was running.
    NotRunning,
    /// It finished within its budget; whatever it was flushing is durable.
    Completed,
    /// It outlived its budget and shutdown proceeded without it.
    Abandoned,
}

/// Wait for the persistence task, bounded, and report which happened.
///
/// Split out so the budget's behaviour can be tested in both directions: that a
/// flush finishing inside the budget is not delayed by it, and that one
/// outliving it returns at the budget rather than hanging shutdown forever.
async fn drain_persistence(
    handle: Option<tokio::task::JoinHandle<()>>,
    budget: Duration,
) -> PersistenceDrain {
    let Some(handle) = handle else {
        return PersistenceDrain::NotRunning;
    };
    match tokio::time::timeout(budget, handle).await {
        Ok(Ok(())) => {
            info!(task = "persistence", "task drained");
            PersistenceDrain::Completed
        }
        Ok(Err(error)) => {
            warn!(task = "persistence", %error, "task panicked during drain");
            PersistenceDrain::Abandoned
        }
        Err(_) => PersistenceDrain::Abandoned,
    }
}

#[cfg(not(unix))]
async fn select_with_signals(
    mut loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    mut api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    mut sweep_handle: tokio::task::JoinHandle<()>,
    embed_handle: tokio::task::JoinHandle<()>,
    mut idle_handle: tokio::task::JoinHandle<()>,
    persist_handle: tokio::task::JoinHandle<()>,
    supervisor_handle: tokio::task::JoinHandle<()>,
    lsp_handle: Option<tokio::task::JoinHandle<()>>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CompletedTask {
        Reconciliation,
        Api,
        Sweeper,
        Idle,
        Signal,
    }

    let (completed, result) = tokio::select! {
        // NOTE: this arm shuts the daemon down, so the reconciliation loop
        // must only exit for reasons that end the daemon: the cancel signal,
        // or a real startup/runtime error. A background-work supervisor stop
        // parks the loop inside `run_loop` instead of exiting it, precisely
        // because reaching this arm cancels the API task and every other
        // task, the opposite of the stop announcement's "the daemon keeps
        // serving" (FIR-2317).
        result = &mut loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Reconciliation, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        result = &mut api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Api, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        _ = &mut sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Sweeper, Ok(()))
        }
        // NOTE: the embedding worker is deliberately NOT a select! arm. Embeddings
        // are a DERIVED index, so the worker exiting (e.g. exhausting its
        // consecutive-panic budget under heavy umbrella-scale load) must NOT shut
        // the daemon down — doing so produced a clean exit(0) that read as an
        // intentional shutdown and left the daemon silently dead (#11). The worker
        // now sets `embed_worker_failed`; the daemon keeps serving
        // graph/locate/reconcile in an embed-degraded state, surfaced LOUDLY via
        // /health. `embed_handle` is handed to `drain_handles` only on a REAL
        // shutdown below.
        _ = &mut idle_handle => {
            info!("idle monitor exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Idle, Ok(()))
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
    };

    // Before `drain_handles`, and so before the final persistence flush that
    // kin#994 gave its own budget and drains ahead of everything else. Order is
    // the whole point twice over. A sweep publishes into the graph, so letting
    // it finish first is what puts its relations in the flush rather than in the
    // next daemon's re-derivation, and a flush that can legitimately run for
    // minutes would otherwise spend the entire escalation grace before the sweep
    // was ever asked to stop.
    drain_lsp_enrichment(lsp_handle).await;

    drain_handles(
        (completed != CompletedTask::Reconciliation).then_some(loop_handle),
        (completed != CompletedTask::Api).then_some(api_handle),
        (completed != CompletedTask::Sweeper).then_some(sweep_handle),
        Some(embed_handle),
        (completed != CompletedTask::Idle).then_some(idle_handle),
        Some(persist_handle),
        Some(supervisor_handle),
    )
    .await;
    result
}

#[cfg(all(test, unix))]
mod tests {

    use super::{
        await_watch_armed, coverage_drain_verdict, drain_pending_flush, embed_work_outstanding,
        format_singleton_contention, next_embed_error_backoff, parse_duration_secs,
        parse_owner_watch_pid, should_enable_lsp_enrichment, should_flush_now, shutdown_signalled,
        watched_process_is_alive, ControlPlane, CoverageDrainVerdict, DaemonConfig, DaemonState,
        FlushSuppression, WatchArming, DEFAULT_RUNTIME_SHUTDOWN_GRACE,
        DEFAULT_SHUTDOWN_ESCALATION_GRACE, RECON_IDLE,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    /// FIR-2466. The healthy path: the loop reports its watcher and publication
    /// proceeds.
    ///
    /// The arming is deliberately delayed rather than already sent. A future
    /// that is ready on its first poll returns before any deadline applies, so a
    /// version of this test with an instantly-ready signal stays green at a
    /// one-nanosecond bound and can never tell waiting from not waiting.
    #[tokio::test]
    async fn a_reported_watch_releases_publication() {
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            let _ = armed_tx.send(());
        });

        assert_eq!(
            await_watch_armed(armed_rx, Duration::from_secs(10)).await,
            WatchArming::Armed,
            "a watch reported inside the bound is what lets the endpoint be published"
        );
    }

    /// A loop that ends before building a watcher releases publication too.
    ///
    /// Filesystem reconcile switched off, a bare checkout, or a watcher the host
    /// refused all reach this. There is no watch coming, so waiting the bound
    /// out would hold the endpoint back for nothing.
    #[tokio::test]
    async fn a_loop_that_ends_without_a_watch_releases_publication_at_once() {
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();
        drop(armed_tx);

        assert_eq!(
            await_watch_armed(armed_rx, Duration::from_secs(10)).await,
            WatchArming::LoopGone
        );
    }

    /// The bound is a ceiling on a wedged loop, not on a healthy one. An
    /// endpoint that never appears is a daemon no client can reach, so the wait
    /// expires into publication with the reason recorded.
    #[tokio::test]
    async fn a_loop_that_never_reports_stops_holding_publication_at_its_bound() {
        // Held rather than dropped: dropping it is the LoopGone arm above, and
        // this arm is the one where nothing happens at all.
        let (_armed_tx, armed_rx) = tokio::sync::oneshot::channel::<()>();

        assert_eq!(
            await_watch_armed(armed_rx, Duration::from_millis(80)).await,
            WatchArming::TimedOut
        );
    }

    #[test]
    fn default_embed_batch_is_backlog_friendly() {
        assert_eq!(DaemonConfig::default().embed_batch_size, 512);
    }

    /// FIR-2254's accounting half. A drained queue over a store that is short
    /// on coverage is the exact state the daemon used to log as `remaining=0`
    /// while `kin graph status` reported hundreds pending, because the worker
    /// asked the queue and the status asked coverage. An empty queue alone must
    /// never be read as finished.
    #[test]
    fn a_drained_queue_over_short_coverage_is_not_finished() {
        let backfill = coverage_drain_verdict(641, None);
        let complete = coverage_drain_verdict(0, None);

        assert_eq!(backfill, CoverageDrainVerdict::Backfill { missing: 641 });
        assert_eq!(backfill.completed_pressure_work(), None);
        assert_eq!(complete, CoverageDrainVerdict::Complete);
        assert_eq!(
            complete.completed_pressure_work(),
            Some(kin_core::memory_pressure::HeavyWork::EmbedBatch)
        );
    }

    /// Re-queueing is bounded by what it achieves. The same gap twice running
    /// means the previous re-queue placed nothing the worker could embed, so
    /// the worker reports it and stands down instead of rebuilding the same
    /// queue every interval forever.
    #[test]
    fn a_gap_that_requeueing_cannot_close_is_reported_not_retried() {
        let stalled = coverage_drain_verdict(641, Some(641));
        assert_eq!(stalled, CoverageDrainVerdict::Stalled { missing: 641 });
        assert_eq!(
            stalled.completed_pressure_work(),
            None,
            "stalled work stays outstanding and cannot retire its refusal"
        );
        // A different gap is a different question, and gets its own attempt.
        assert_eq!(
            coverage_drain_verdict(210, Some(641)),
            CoverageDrainVerdict::Backfill { missing: 210 }
        );
        // Coverage closing outranks the latch entirely.
        assert_eq!(
            coverage_drain_verdict(0, Some(641)),
            CoverageDrainVerdict::Complete
        );
    }

    #[test]
    fn graph_only_authority_disables_lsp_discovery_and_worker() {
        assert!(should_enable_lsp_enrichment(true, false));
        assert!(!should_enable_lsp_enrichment(true, true));
        assert!(!should_enable_lsp_enrichment(false, false));
        assert!(!should_enable_lsp_enrichment(false, true));
    }

    #[tokio::test]
    async fn preacquired_authority_cannot_be_replayed_against_another_repo() {
        let repo_a = tempfile::tempdir().unwrap();
        let repo_b = tempfile::tempdir().unwrap();
        let initialized_a = kin_core::init(repo_a.path()).unwrap();
        let initialized_b = kin_core::init(repo_b.path()).unwrap();
        let repo_b_kin_root = initialized_b.layout.root().to_path_buf();

        let authority = super::acquire_daemon_authority(initialized_a.layout.root()).unwrap();
        let state = DaemonState::open(initialized_b.layout).unwrap();
        let result = super::run_with_authority(
            state,
            DaemonConfig {
                api_port: 0,
                ..DaemonConfig::default()
            },
            authority,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(crate::error::DaemonError::AuthorityMismatch { .. })
            ),
            "repo A authority must not authorize repo B state: {result:?}"
        );
        assert!(
            !repo_b_kin_root.join("daemon.pid").exists()
                && !repo_b_kin_root.join("daemon.port").exists(),
            "authority mismatch must fail before endpoint publication"
        );
    }

    // ── Control-plane classification ──────────────────────────────────────
    //
    // A healthy daemon used to read "my endpoint files are gone" as "the
    // repository is gone" and shut itself down, which is how a refused second
    // start killed the incumbent it lost to. The two states that genuinely end
    // a daemon are distinguishable from the one that is repairable.

    #[tokio::test]
    async fn a_published_endpoint_reads_as_this_daemons_own() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();

        assert_eq!(super::classify_control_plane(&state), ControlPlane::Ours);
    }

    #[tokio::test]
    async fn a_deleted_endpoint_is_repairable_rather_than_fatal() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();

        std::fs::remove_file(kin_root.join("daemon.pid")).unwrap();
        std::fs::remove_file(kin_root.join("daemon.port")).unwrap();

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::EndpointLost
        );
        assert!(
            !super::control_plane_demands_shutdown(&state, 51234, false),
            "a daemon that still owns the repo must repair its endpoint, not exit"
        );
        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::Ours,
            "the repair must republish this daemon's own endpoint"
        );
        assert_eq!(
            crate::lifecycle::read_port_file(&kin_root),
            Some(51234),
            "republication must restore the port this daemon actually bound"
        );
    }

    #[tokio::test]
    async fn a_lost_endpoint_is_not_republished_once_shutdown_is_signalled() {
        // Task drain is bounded and does not abort this monitor, and
        // publication can block on the coordination lock, so a repair that
        // started late could land after retirement and advertise an endpoint
        // for a process that is exiting.
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();
        std::fs::remove_file(kin_root.join("daemon.pid")).unwrap();
        std::fs::remove_file(kin_root.join("daemon.port")).unwrap();

        assert!(
            !super::control_plane_demands_shutdown(&state, 51234, true),
            "a lost endpoint is still not a reason to shut down"
        );
        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::EndpointLost,
            "a shutting-down daemon must not republish an endpoint it is about to retire"
        );
    }

    #[tokio::test]
    async fn a_removed_repository_root_ends_the_daemon() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();

        std::fs::remove_dir_all(&kin_root).unwrap();

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::RootGone
        );
        assert!(super::control_plane_demands_shutdown(&state, 51234, false));
    }

    #[tokio::test]
    async fn a_proven_live_successor_endpoint_ends_the_daemon() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();

        let mut successor = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in successor");
        let identity = kin_cli::daemon_client::process_identity(successor.id())
            .expect("read the successor's identity")
            .expect("the successor is running");
        crate::lifecycle::publish_foreign_endpoint_for_test(&kin_root, identity, 51234);

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::Superseded {
                pid: successor.id()
            }
        );
        assert!(super::control_plane_demands_shutdown(&state, 4219, false));
        assert_eq!(
            std::fs::read_to_string(kin_root.join("daemon.port")).unwrap(),
            "51234",
            "yielding to a successor must not disturb the endpoint it published"
        );

        let _ = successor.kill();
        let _ = successor.wait();
    }

    #[tokio::test]
    async fn a_foreign_endpoint_that_proves_nothing_is_repaired_not_obeyed() {
        // PID 1 is alive and is not this process, but a bare-PID record cannot
        // prove that number still names a daemon. This process holds the
        // repository singleton, so no successor can legitimately exist and the
        // record is debris — the exact debris a refusing starter used to leave.
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        std::fs::write(kin_root.join("daemon.pid"), "1").unwrap();
        std::fs::write(kin_root.join("daemon.port"), "51234").unwrap();

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::EndpointLost
        );
        assert!(!super::control_plane_demands_shutdown(&state, 4219, false));
        assert_eq!(super::classify_control_plane(&state), ControlPlane::Ours);
        assert_eq!(crate::lifecycle::read_port_file(&kin_root), Some(4219));
    }

    // ── Idle shutdown vs work in flight ───────────────────────────────────
    //
    // The idle clock only advances on API traffic, so background work is
    // invisible to it. A CLI autostart injects a 60s timeout, which is shorter
    // than a first ingest and far shorter than the embed drain that ingest
    // queues, and the killed pass restarts from zero on the next command.

    #[test]
    fn an_embedding_backlog_counts_only_while_a_worker_will_drain_it() {
        // An explicit pass is in flight regardless of the background worker.
        assert!(embed_work_outstanding(true, false, false));
        assert!(embed_work_outstanding(true, true, true));
        // Queued work with a live worker is work in progress.
        assert!(embed_work_outstanding(false, true, true));
        // Queued work the worker has stood down from is not: counting it would
        // hold a daemon open forever on a backlog nobody consumes.
        assert!(!embed_work_outstanding(false, true, false));
        // Nothing queued, nothing running.
        assert!(!embed_work_outstanding(false, false, true));
        assert!(!embed_work_outstanding(false, false, false));
    }

    #[tokio::test]
    async fn an_embed_pass_in_flight_survives_the_idle_timeout() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();
        state.is_initialized.store(true, Ordering::Relaxed);

        // Zero timeout: every check below is past the deadline, so the only
        // thing that can hold the daemon open is the work itself.
        let expired = Duration::ZERO;
        let pass = state.begin_embed_pass();
        assert!(
            !super::ready_for_idle_shutdown(&state, expired, ControlPlane::Ours),
            "an embed pass in flight must outrank an expired idle timeout"
        );

        drop(pass);
        assert!(
            super::ready_for_idle_shutdown(&state, expired, ControlPlane::Ours),
            "a genuinely idle initialized daemon must still idle out"
        );
    }

    /// The idle-window contract at the daemon: an attached client whose session
    /// outlasts the window this daemon was spawned with grows it, and the grown
    /// window is what the shutdown decision then reads.
    ///
    /// The two-sided part is the second half. Growing the window must not stop
    /// the daemon idling out; it must only move when.
    #[tokio::test]
    async fn a_raised_idle_window_is_what_the_shutdown_decision_reads() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();
        state.is_initialized.store(true, Ordering::Relaxed);

        // Spawned the way a CLI autostart spawns one.
        state.install_idle_timeout(Some(Duration::from_secs(60)));
        assert_eq!(state.idle_timeout(), Some(Duration::from_secs(60)));

        let raise = state.raise_idle_timeout(Duration::from_secs(1800));
        assert_eq!(raise.effective, Some(Duration::from_secs(1800)));
        assert_eq!(raise.raised_from, Some(Duration::from_secs(60)));
        assert_eq!(
            state.idle_timeout(),
            Some(Duration::from_secs(1800)),
            "the monitor reads the window through this accessor, so the raise must land here"
        );

        // The daemon is idle by every other measure, and the grown window is
        // the only thing holding it open.
        let window = state.idle_timeout().expect("a window is installed");
        assert!(
            !super::ready_for_idle_shutdown(&state, window, ControlPlane::Ours),
            "a session that just stated a 1800s need must not be cut off immediately"
        );
        assert!(
            super::ready_for_idle_shutdown(&state, Duration::ZERO, ControlPlane::Ours),
            "growing the window must move when the daemon idles out, never whether"
        );

        // A second client that fits inside the window changes nothing.
        let redundant = state.raise_idle_timeout(Duration::from_secs(300));
        assert!(!redundant.raised());
        assert_eq!(state.idle_timeout(), Some(Duration::from_secs(1800)));
    }

    /// The monitor reads the live window, not the one it was handed at start.
    ///
    /// This is the half the state round-trip above cannot reach: a monitor that
    /// closed over its startup value would keep counting against 60 seconds
    /// however loudly an attached session said 1800, and the state accessor
    /// would look perfectly correct while the daemon still died.
    #[tokio::test]
    async fn the_idle_monitor_counts_against_the_live_window_not_its_startup_one() {
        async fn open_idle_state() -> (tempfile::TempDir, Arc<DaemonState>) {
            let repo = tempfile::tempdir().unwrap();
            let initialized = kin_core::init(repo.path()).unwrap();
            let state = Arc::new(DaemonState::open(initialized.layout).unwrap());
            state.is_initialized.store(true, Ordering::Relaxed);
            (repo, state)
        }
        let short = Duration::from_millis(200);

        // Control. Without it the second half could pass because the monitor
        // never reaches a shutdown decision at all, which is exactly the shape
        // of guard that cannot fail.
        let (_expiring_repo, expiring) = open_idle_state().await;
        expiring.install_idle_timeout(Some(short));
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let monitor = tokio::spawn(super::run_idle_monitor(
            Arc::clone(&expiring),
            Some(short),
            4219,
            cancel_tx.clone(),
            cancel_rx,
        ));
        tokio::time::timeout(Duration::from_secs(30), monitor)
            .await
            .expect("an idle daemon on a 200ms window must reach idle shutdown")
            .expect("the idle monitor must not panic");
        assert!(
            *cancel_tx.borrow(),
            "the control monitor must have requested shutdown"
        );

        // The same startup window, raised by an attached client before the
        // monitor's first decision. Counting against the startup value would
        // shut this daemon down inside the wait below.
        let (_raised_repo, raised) = open_idle_state().await;
        raised.install_idle_timeout(Some(short));
        raised.raise_idle_timeout(Duration::from_secs(3600));
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let monitor = tokio::spawn(super::run_idle_monitor(
            Arc::clone(&raised),
            Some(short),
            4219,
            cancel_tx.clone(),
            cancel_rx,
        ));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !*cancel_tx.borrow(),
            "a session that raised the window to 3600s must not be shut down after 1.5s"
        );
        assert!(
            !monitor.is_finished(),
            "the monitor must still be watching, not have exited"
        );
        cancel_tx
            .send(true)
            .expect("the monitor still holds a receiver");
        monitor.await.expect("the idle monitor must not panic");
    }

    /// A daemon configured never to idle out stays that way. Nothing an
    /// attached client says may give it a finite lifetime it did not have.
    #[tokio::test]
    async fn a_daemon_that_never_idles_out_cannot_be_given_a_window() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();

        state.install_idle_timeout(None);
        assert_eq!(state.idle_timeout(), None);

        let raise = state.raise_idle_timeout(Duration::from_secs(1800));
        assert_eq!(raise.effective, None);
        assert_eq!(raise.effective_secs(), 0);
        assert!(!raise.raised());
        assert_eq!(state.idle_timeout(), None);
    }

    #[tokio::test]
    async fn an_endpoint_blip_cannot_shut_down_a_daemon_mid_scan() {
        // The EndpointLost branch used to return on the idle clock alone,
        // before the initialization and reconciliation gates, so a republication
        // failure could end a daemon that had never finished its first scan.
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();
        let expired = Duration::ZERO;

        state.is_initialized.store(false, Ordering::Relaxed);
        assert!(
            !super::ready_for_idle_shutdown(&state, expired, ControlPlane::EndpointLost),
            "a first scan still running must outrank a lost endpoint"
        );

        state.is_initialized.store(true, Ordering::Relaxed);
        state
            .reconciliation_status
            .store(crate::state::RECON_PROCESSING, Ordering::Relaxed);
        assert!(
            !super::ready_for_idle_shutdown(&state, expired, ControlPlane::EndpointLost),
            "reconciliation in progress must outrank a lost endpoint"
        );

        state
            .reconciliation_status
            .store(RECON_IDLE, Ordering::Relaxed);
        assert!(
            super::ready_for_idle_shutdown(&state, expired, ControlPlane::EndpointLost),
            "an unreachable daemon with no work left must still idle out"
        );
    }

    // ── Background auto-embed: announced, and opt-out-able ────────────────
    //
    // The pass starts because a store was opened, not because anyone asked for
    // it, so it needs both a line that says it started and a way to say no.
    // The default is unchanged: auto-embed stays on.

    /// Read `auto_embed_enabled` with `KIN_DAEMON_AUTO_EMBED` held at `value`
    /// (`None` removes it) for the duration of the read. The guard restores what
    /// the process had and serializes against every other env-mutating test.
    /// Both levers must be off unless somebody deliberately armed them, and a
    /// typo must disarm rather than arm. A fault injector that fires on a
    /// malformed value is a worse defect than the one it exists to expose.
    #[test]
    fn the_startup_hold_is_disarmed_by_anything_but_a_positive_number() {
        assert_eq!(super::startup_hold_from(None), Duration::ZERO);
        assert_eq!(super::startup_hold_from(Some("")), Duration::ZERO);
        assert_eq!(super::startup_hold_from(Some("   ")), Duration::ZERO);
        assert_eq!(super::startup_hold_from(Some("0")), Duration::ZERO);
        assert_eq!(super::startup_hold_from(Some("nonsense")), Duration::ZERO);
        assert_eq!(super::startup_hold_from(Some("-5")), Duration::ZERO);
        assert_eq!(
            super::startup_hold_from(Some("20")),
            Duration::from_secs(20)
        );
        assert_eq!(
            super::startup_hold_from(Some(" 20 ")),
            Duration::from_secs(20)
        );
    }

    #[test]
    fn the_sweep_hold_is_off_unless_explicitly_armed() {
        assert!(!super::hold_sweep_from(None));
        assert!(!super::hold_sweep_from(Some("")));
        assert!(!super::hold_sweep_from(Some("0")));
        assert!(!super::hold_sweep_from(Some("false")));
        assert!(!super::hold_sweep_from(Some("maybe")));
        assert!(super::hold_sweep_from(Some("1")));
        assert!(super::hold_sweep_from(Some("true")));
        assert!(super::hold_sweep_from(Some("TRUE")));
        assert!(super::hold_sweep_from(Some(" on ")));
    }

    fn auto_embed_enabled_with(value: Option<&str>) -> bool {
        let _env = match value {
            Some(value) => kin_core::test_env::EnvVarGuard::set(super::AUTO_EMBED_ENV, value),
            None => kin_core::test_env::EnvVarGuard::unset(super::AUTO_EMBED_ENV),
        };
        super::auto_embed_enabled()
    }

    #[test]
    fn auto_embed_is_on_unless_an_operator_spells_out_otherwise() {
        // Absent is the shipped default and stays on.
        assert!(auto_embed_enabled_with(None));
        assert!(auto_embed_enabled_with(Some("1")));
        assert!(auto_embed_enabled_with(Some("true")));
        // The falsy set matches KIN_DAEMON_REQUIRE_TOKEN, whitespace and case
        // included, so one spelling works across the daemon's env surface.
        assert!(!auto_embed_enabled_with(Some("0")));
        assert!(!auto_embed_enabled_with(Some("false")));
        assert!(!auto_embed_enabled_with(Some("no")));
        assert!(!auto_embed_enabled_with(Some("off")));
        assert!(!auto_embed_enabled_with(Some("  OFF  ")));
        // An unparseable value is not silently read as an opt-out: the default
        // is on, and a typo must not disable embedding behind the operator.
        assert!(auto_embed_enabled_with(Some("maybe")));
        assert!(auto_embed_enabled_with(Some("")));
    }

    #[tokio::test]
    async fn background_embed_queues_by_default_and_defers_on_opt_out() {
        // Both of the axes this arm is not about, pinned, exactly as every arm
        // in `memory_pressure_tests` pins them. `start_or_defer_background_embed`
        // consults host pressure AND this daemon's own budget, so an arm about
        // the opt-out was being decided by how large the test binary happened to
        // be and how full the machine running it was. It failed here on a
        // development box at load, which is the failure it exists to be immune
        // to; FIR-2653 sharpened it on macOS, where the footprint reader counts
        // compressed pages and a compressing host reads a process as larger than
        // its resident set.
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let _forced = kin_core::test_env::EnvVarGuard::set(
            kin_core::memory_pressure::PRESSURE_OVERRIDE_ENV,
            "nominal",
        );
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();

        {
            let _env = kin_core::test_env::EnvVarGuard::unset(super::AUTO_EMBED_ENV);
            assert!(
                super::start_or_defer_background_embed(&state),
                "the default must still build the backlog and start the pass"
            );
        }
        assert!(
            !state.background_embed_paused(),
            "the default must leave the worker running"
        );

        state.resume_background_embed();
        {
            let _env = kin_core::test_env::EnvVarGuard::set(super::AUTO_EMBED_ENV, "0");
            assert!(
                !super::start_or_defer_background_embed(&state),
                "an opt-out must defer the pass rather than queue it"
            );
        }
        assert!(
            state.background_embed_paused(),
            "a deferred pass must stand the worker down, so a daemon holding no \
             drainable backlog can still idle out"
        );
    }

    #[test]
    fn idle_flush_waits_for_mutation_quiet() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        // Mutations still arriving: dirty state is old but the graph is hot —
        // no flush. (The pre-fix predicate compared only `since_save`, so it
        // fired a full-graph save on every >=2s save gap mid-activity.)
        assert!(!should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(1),
            FlushSuppression::None,
            idle,
            periodic,
        ));
        // Mutation-quiet past the idle threshold: flush.
        assert!(should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(3),
            FlushSuppression::None,
            idle,
            periodic,
        ));
    }

    #[test]
    fn active_embed_pass_suppresses_both_flush_clocks() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        // A starved feed gap mid-pass looks idle; the pass marker suppresses
        // the idle flush so the gap cannot trigger a full-graph save.
        assert!(!should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(5),
            FlushSuppression::EmbedPass,
            idle,
            periodic,
        ));
        // The periodic clock is ALSO suppressed during an embed pass: re-serializing
        // the full graph mid-pass re-derives only enrichment and, on large repos
        // (~955MB mui), the repeated O(graph) writes starved the feed and killed the
        // daemon. The post-pass snapshot persists the final state.
        assert!(!should_flush_now(
            Duration::from_secs(31),
            Duration::from_secs(5),
            FlushSuppression::EmbedPass,
            idle,
            periodic,
        ));
        // Once the pass ends, the periodic durability bound fires as before.
        assert!(should_flush_now(
            Duration::from_secs(31),
            Duration::from_secs(5),
            FlushSuppression::None,
            idle,
            periodic,
        ));
    }

    /// A cold sweep suppresses both clocks, for the reason the embed-pass arm
    /// above already documents.
    ///
    /// Measured on a converted psf/requests store: one 188-second sweep
    /// triggered a single background flush costing 96.6 seconds, carrying a
    /// 56.2-second successor preparation whose `change_bodies_ms` was 0. A
    /// whole-workspace rebuild and whole-store re-admission, for zero changed
    /// content bodies, to persist edges the next sweep recomputes.
    #[test]
    fn an_lsp_sweep_suppresses_both_flush_clocks() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        // A gap between files mid-sweep looks mutation-quiet; the idle clock
        // must not read that as a moment to serialize the whole graph.
        assert!(!should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(5),
            FlushSuppression::LspSweep,
            idle,
            periodic,
        ));
        // The periodic clock is suppressed too. A sweep runs for minutes, so a
        // 30-second bound fires inside it by construction.
        assert!(!should_flush_now(
            Duration::from_secs(31),
            Duration::from_secs(5),
            FlushSuppression::LspSweep,
            idle,
            periodic,
        ));
    }

    /// Suppression that became never-flushing would be a worse defect than the
    /// flush it removed, so this is the arm that says it ends.
    ///
    /// The sweep marks the graph dirty when it finishes, so the very next pass
    /// of the persistence loop sees a mutation-quiet dirty graph with no
    /// suppression and flushes. Both clocks are checked, because a fix that
    /// only restored the periodic bound would leave a sweep's own output
    /// unpersisted for up to thirty seconds after it converged.
    #[test]
    fn the_flush_fires_as_soon_as_the_sweep_ends() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        // Mutation-quiet past the idle threshold, sweep over: flush now.
        assert!(should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(3),
            FlushSuppression::None,
            idle,
            periodic,
        ));
        // And the periodic durability bound is intact the moment it lifts.
        assert!(should_flush_now(
            Duration::from_secs(31),
            Duration::from_secs(1),
            FlushSuppression::None,
            idle,
            periodic,
        ));
    }

    /// A mutation that is NOT the sweep's own is still persisted, just later.
    ///
    /// This is the consequence worth stating rather than discovering: a live
    /// write landing mid-sweep waits for the sweep to end before it is
    /// flushed. The staleness is bounded by the sweep's own duration, and the
    /// predicate cannot tell whose mutation it was, so the guarantee is
    /// "flushed at sweep end", not "flushed immediately". Both rows below are
    /// the same dirty state; only the suppression differs.
    #[test]
    fn a_non_sweep_mutation_mid_sweep_is_flushed_when_the_sweep_ends() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        let since_save = Duration::from_secs(45);
        let since_mutation = Duration::from_secs(10);
        assert!(
            !should_flush_now(
                since_save,
                since_mutation,
                FlushSuppression::LspSweep,
                idle,
                periodic
            ),
            "a live write mid-sweep waits: this is the bounded staleness the change accepts"
        );
        assert!(
            should_flush_now(
                since_save,
                since_mutation,
                FlushSuppression::None,
                idle,
                periodic
            ),
            "and it is flushed as soon as the sweep ends, from the same dirty state"
        );
    }

    /// An interrupted sweep records exactly the files it completed, and no more.
    ///
    /// The accumulator is pushed only on the arm that increments
    /// `tally.enriched`, so today the property holds by code shape and a runtime
    /// warning reports any divergence. Neither is enough on its own: a shape
    /// invariant is one refactor from silently gone, and the warning only speaks
    /// in production, after the damage. This pins the property where CI sees it.
    ///
    /// The case is a sweep that broke early having finished three files of four.
    /// The marker must name those three and must NOT name the file the sweep
    /// never reached, because naming it would make the next sweep skip a file
    /// that was never enriched at all.
    #[test]
    fn an_interrupted_sweep_records_exactly_what_it_completed() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();

        let completed = vec![
            "src/requests/sessions.py".to_string(),
            "src/requests/adapters.py".to_string(),
            "src/requests/auth.py".to_string(),
        ];
        let never_reached = "src/requests/models.py";

        super::mark_files_enriched(&state, &completed, super::current_marker_epoch(&state));

        for file in &completed {
            assert!(
                super::file_already_enriched(&state, file),
                "a file the interrupted sweep completed and published must be recorded: {file}"
            );
        }
        assert!(
            !super::file_already_enriched(&state, never_reached),
            "a file the sweep never reached must NOT be recorded, or the next sweep skips a \
             file that was never enriched"
        );
    }

    /// A flush that outlives its budget is ABANDONED, and shutdown proceeds.
    ///
    /// The loss half of the defect: the persistence task's shutdown arm performs
    /// the final flush, a flush is the publication, and on a converted
    /// psf/requests store those ran 96 to 108 seconds against a ten-second drain
    /// shared with six other tasks. Shutdown must still end rather than hang, so
    /// the budget is a ceiling; what changes is that the outcome is now named
    /// instead of hidden inside a generic drain warning.
    #[tokio::test]
    async fn a_flush_outliving_its_budget_is_reported_abandoned() {
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let started = std::time::Instant::now();
        let outcome = super::drain_persistence(Some(handle), Duration::from_millis(80)).await;
        assert_eq!(
            outcome,
            super::PersistenceDrain::Abandoned,
            "a flush that outlives its budget must be reported as abandoned, because a reader \
             has to tell discarded durability from a merely slow task"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "shutdown must proceed at the budget rather than wait the flush out forever"
        );
    }

    /// The other direction, and the one that keeps the fix from overcorrecting.
    ///
    /// An idle daemon's persistence arm returns at once, because its shutdown
    /// path skips the flush when nothing is dirty. A generous budget must
    /// therefore cost such a shutdown NOTHING: it is a ceiling on waiting, not
    /// an amount of waiting. A fix that made every shutdown sit out a full flush
    /// window would be worse than the bug it replaced.
    #[tokio::test]
    async fn a_fast_shutdown_is_not_delayed_by_a_generous_budget() {
        let handle = tokio::spawn(async {});
        let started = std::time::Instant::now();
        let outcome = super::drain_persistence(Some(handle), Duration::from_secs(300)).await;
        assert_eq!(outcome, super::PersistenceDrain::Completed);
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "a persistence task with nothing to flush must return at once, however large the \
             budget is"
        );
        assert_eq!(
            super::drain_persistence(None, Duration::from_secs(300)).await,
            super::PersistenceDrain::NotRunning,
            "no persistence task at all is not an abandonment"
        );
    }

    #[test]
    fn shutdown_grace_parsing_is_robust() {
        let default = Duration::from_secs(25);
        // Absent / empty / unparseable input all fall back to the default.
        assert_eq!(parse_duration_secs(None, default), default);
        assert_eq!(parse_duration_secs(Some(""), default), default);
        assert_eq!(parse_duration_secs(Some("  "), default), default);
        assert_eq!(parse_duration_secs(Some("garbage"), default), default);
        assert_eq!(parse_duration_secs(Some("-5"), default), default);
        // Valid whole-seconds values (with surrounding whitespace) are honoured.
        assert_eq!(
            parse_duration_secs(Some("10"), default),
            Duration::from_secs(10)
        );
        assert_eq!(
            parse_duration_secs(Some("  3 "), default),
            Duration::from_secs(3)
        );
        // 0 is honoured so tests can force the watchdog to escalate immediately
        // once the shutdown signal fires.
        assert_eq!(
            parse_duration_secs(Some("0"), default),
            Duration::from_secs(0)
        );
    }

    #[test]
    fn shutdown_grace_defaults_are_sane() {
        // The escalation backstop must outlast the runtime-teardown bound so the
        // normal (block_on returns → shutdown_timeout → process::exit) path wins
        // the race in the common case; the watchdog only fires when that stalls.
        assert!(
            DEFAULT_SHUTDOWN_ESCALATION_GRACE > DEFAULT_RUNTIME_SHUTDOWN_GRACE,
            "escalation grace must exceed the runtime teardown bound"
        );
    }

    #[test]
    fn embed_error_backoff_doubles_then_caps() {
        let base = Duration::from_secs(5);
        let max = Duration::from_secs(60);

        // First failure starts from the base interval and doubles it.
        let b1 = next_embed_error_backoff(None, base, max);
        assert_eq!(b1, Duration::from_secs(10));
        // Subsequent failures keep doubling…
        let b2 = next_embed_error_backoff(Some(b1), base, max);
        assert_eq!(b2, Duration::from_secs(20));
        let b3 = next_embed_error_backoff(Some(b2), base, max);
        assert_eq!(b3, Duration::from_secs(40));
        // …until they saturate at the cap and never grow unbounded.
        let b4 = next_embed_error_backoff(Some(b3), base, max);
        assert_eq!(b4, max);
        let b5 = next_embed_error_backoff(Some(b4), base, max);
        assert_eq!(b5, max, "backoff must stay clamped at the cap");

        // The backoff is always strictly greater than the idle interval, so a
        // persistent error can never tight-spin at the 5s idle cadence.
        assert!(b1 > base);
    }

    /// Recovery from a failed background batch must precede a foreground
    /// rebuild that was already waiting on `embedding_work`.
    ///
    /// Both rendezvous channels are zero-capacity: the batch cannot report its
    /// synthetic IndexError until the foreground thread has observed real lock
    /// contention, and the foreground cannot acquire until the batch has reset
    /// under that same guard. No sleeps or scheduler timing are involved.
    #[cfg(feature = "vector")]
    #[test]
    fn background_index_recovery_precedes_already_waiting_foreground_rebuild() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = Arc::new(DaemonState::open(initialized.layout).unwrap());

        // Prepare one compatible sidecar for both sides of the race. Attach it
        // now as the stale index recovery must detach, then let the foreground
        // `/embed --rebuild` install it fresh after acquiring `embedding_work`.
        let descriptor = kin_db::IndexDescriptor {
            model_id: Some("foreground-rebuild-race-fixture@v1".to_string()),
            graph_root: Some(hex::encode(state.graph.compute_root_hash())),
        };
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors
            .upsert(kin_model::EntityId::new(), &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        vectors.set_descriptor(descriptor.clone());
        let sidecar = state.layout.root().join("foreground-rebuild-race.kvec");
        vectors.save(&sidecar).unwrap();
        assert!(matches!(
            state
                .graph
                .load_vector_index_compatible(&sidecar, &descriptor),
            kin_db::VectorIndexLoad::Loaded(1)
        ));

        let (batch_started_tx, batch_started_rx) = std::sync::mpsc::sync_channel(0);
        let (foreground_waiting_tx, foreground_waiting_rx) = std::sync::mpsc::sync_channel(0);

        let batch_state = Arc::clone(&state);
        let background = std::thread::spawn(move || {
            super::run_background_embedding_batch(&batch_state, true, move |_| {
                batch_started_tx.send(()).unwrap();
                foreground_waiting_rx.recv().unwrap();
                Err(kin_db::KinDbError::IndexError(
                    "synthetic stale background index".to_string(),
                ))
            })
        });

        batch_started_rx.recv().unwrap();
        let foreground_state = Arc::clone(&state);
        let foreground = std::thread::spawn(move || {
            let _foreground_guard = match foreground_state.embedding_work.try_lock() {
                Ok(_) => panic!("background batch must still own embedding_work"),
                Err(std::sync::TryLockError::WouldBlock) => {
                    foreground_waiting_tx.send(()).unwrap();
                    foreground_state.embedding_work.lock().unwrap()
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("embedding_work unexpectedly poisoned")
                }
            };

            assert!(
                foreground_state.graph.vector_index_stats().is_none(),
                "the stale background index must be reset before the waiting rebuild acquires"
            );
            assert!(matches!(
                foreground_state
                    .graph
                    .load_vector_index_compatible(&sidecar, &descriptor),
                kin_db::VectorIndexLoad::Loaded(1)
            ));
        });

        let outcome = background.join().unwrap();
        match outcome {
            super::BackgroundEmbeddingBatchOutcome::ResetAfterIndexError(error) => {
                assert!(matches!(error, kin_db::KinDbError::IndexError(_)));
            }
            other => panic!("unexpected background batch outcome: {other:?}"),
        }
        foreground.join().unwrap();

        assert_eq!(
            state.graph.vector_index_stats(),
            Some((4, 1)),
            "no stale recovery may run after the waiting foreground rebuild publishes"
        );
    }

    #[test]
    fn watched_process_liveness() {
        // The current process is obviously alive.
        assert!(watched_process_is_alive(std::process::id() as i32));

        // A child that has exited and been reaped no longer exists, so its PID
        // reads as gone (barring a near-instant PID recycle, which is not a
        // realistic risk inside this test window).
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id() as i32;
        child.wait().expect("reap child");
        assert!(!watched_process_is_alive(pid));
    }

    #[test]
    fn owner_watchdog_is_opt_in_and_never_derived_from_the_process_tree() {
        let self_pid = std::process::id();

        // Absent or unusable configuration must leave the watchdog disarmed.
        // This is the default for every daemon: unless a spawner explicitly
        // names an owner, nothing can self-terminate.
        assert_eq!(parse_owner_watch_pid(None, self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some(""), self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some("   "), self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some("garbage"), self_pid), None);

        // PID 1 is the decisive rejection. Both daemon spawn paths call
        // setsid(), so a healthy persistent daemon reparents to init the moment
        // the CLI that launched it exits — ppid == 1 is the NORMAL state for a
        // legitimately detached daemon. A watchdog that accepted 1 as an owner
        // would treat "init is alive" as its liveness question and, worse, any
        // getppid()-derived wiring would arm against every daemon on the
        // machine. Ownership is only ever what the spawner states explicitly.
        assert_eq!(parse_owner_watch_pid(Some("1"), self_pid), None);

        // 0 and negatives are process-group / broadcast selectors for kill(2),
        // not owner PIDs; accepting them would make the liveness probe
        // meaningless.
        assert_eq!(parse_owner_watch_pid(Some("0"), self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some("-1"), self_pid), None);

        // A self-watch can never observe a death, so it is misconfiguration
        // rather than a live watchdog.
        let self_pid_text = self_pid.to_string();
        assert_eq!(
            parse_owner_watch_pid(Some(self_pid_text.as_str()), self_pid),
            None
        );

        // A real, explicitly-stated owner arms it (whitespace tolerated).
        assert_eq!(parse_owner_watch_pid(Some("4242"), self_pid), Some(4242));
        assert_eq!(parse_owner_watch_pid(Some(" 4242 "), self_pid), Some(4242));
    }

    #[test]
    fn escalation_backstop_arms_on_the_signal_not_on_a_scheduled_task() {
        // A healthy daemon never arms the force-exit backstop.
        assert!(!shutdown_signalled(false, false, false));

        // Each source arms it on its own.
        assert!(shutdown_signalled(false, true, false));
        assert!(shutdown_signalled(true, false, false));

        // The one that matters: both in-runtime flags unset, because a
        // saturated runtime polls neither the SIGTERM future that sets `cancel`
        // nor the propagation task that writes `is_shutdown`. The OS handler
        // must arm the backstop by itself, or a stop request against a busy
        // daemon has no bound at all.
        assert!(shutdown_signalled(false, false, true));
    }

    #[test]
    fn escalation_arm_loop_fires_when_only_the_os_handler_ran() {
        // The escalation watchdog's arm loop on the real primitives: an
        // AtomicBool standing in for `state.is_shutdown`, the daemon's actual
        // cancel watch-channel, and a flag standing in for the process-global
        // one the signal handler writes.
        //
        // Neither in-runtime flag is ever written here, which is exactly what a
        // saturated runtime looks like: the SIGTERM future that would set
        // `cancel` is never polled, and the propagation task that would write
        // `is_shutdown` is never scheduled. Only the OS handler ran.
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let is_shutdown = Arc::new(AtomicBool::new(false));
        let os_requested = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));

        let loop_is_shutdown = Arc::clone(&is_shutdown);
        let loop_os_requested = Arc::clone(&os_requested);
        let loop_armed = Arc::clone(&armed);
        std::thread::spawn(move || {
            while !shutdown_signalled(
                loop_is_shutdown.load(Ordering::Relaxed),
                *cancel_rx.borrow(),
                loop_os_requested.load(Ordering::Relaxed),
            ) {
                std::thread::sleep(Duration::from_millis(5));
            }
            loop_armed.store(true, Ordering::Relaxed);
        });

        // Nothing has signalled shutdown yet, so a healthy daemon's watchdog
        // sits disarmed rather than counting down to a force-exit.
        assert!(!armed.load(Ordering::Relaxed));

        // Exactly what the signal handler does, and only that: one relaxed
        // store. No tokio task runs in this test at all.
        os_requested.store(true, Ordering::Relaxed);

        // Bounded wait rather than join(): a regression here must fail the test,
        // not hang CI until the job timeout.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !armed.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(
            armed.load(Ordering::Relaxed),
            "the OS handler alone must arm the force-exit backstop; keying it \
             only on flags written from inside the runtime made the \
             saturated-runtime backstop depend on that runtime"
        );
        assert!(
            !is_shutdown.load(Ordering::Relaxed),
            "is_shutdown was never set — the backstop must not depend on it"
        );
    }

    #[test]
    fn pipeline_overlap_off_by_default() {
        // The deterministic serial persist path is the default; only the
        // throughput profile opts into overlap (wired in the daemon binary).
        assert!(!DaemonConfig::default().embed_pipeline_overlap);
    }

    // ── A contended start must name what it lost to ───────────────────────
    //
    // The old refusal said "another kin daemon already owns this repo" and
    // exited 0, so the CLI reported only "daemon exited during startup" and the
    // operator had no way to tell a live holder from a leaked lock fd.

    #[test]
    fn contention_message_names_a_live_holder_and_how_to_clear_it() {
        let message = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: true,
                identity_verified: true,
            }),
            &crate::lifecycle::StaleLockReclaim::OwnerAlive(4242),
        );
        assert!(message.contains("4242"), "must name the holder: {message}");
        assert!(
            message.contains("/repo/.kin"),
            "must name the repo: {message}"
        );
        assert!(
            message.contains("kin daemon stop"),
            "must give the operator an action: {message}"
        );
    }

    #[test]
    fn contention_message_distinguishes_a_dead_owner_from_an_unidentified_one() {
        let leaked = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: false,
                identity_verified: false,
            }),
            &crate::lifecycle::StaleLockReclaim::Cleared(vec![std::path::PathBuf::from(
                "/repo/.kin/daemon.lock",
            )]),
        );
        assert!(
            leaked.contains("leaked lock fd"),
            "a dead recorded owner is a leaked fd, not a running daemon: {leaked}"
        );
        assert!(
            leaked.contains("reclaimed 1 stale lock"),
            "the reclaim that already ran must be reported: {leaked}"
        );

        let unknown = format_singleton_contention(
            "/repo/.kin",
            None,
            &crate::lifecycle::StaleLockReclaim::OwnerUnknown,
        );
        assert!(
            unknown.contains("names no owner"),
            "an unidentifiable holder must be described as such, not guessed at: {unknown}"
        );

        let compatibility_boundary = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: false,
                identity_verified: false,
            }),
            &crate::lifecycle::StaleLockReclaim::CoordinationUnavailable(
                "recorded owner pid 4242 is dead, but compatible older daemons do not participate"
                    .to_string(),
            ),
        );
        assert!(
            compatibility_boundary.contains("Automatic lock-file retirement was refused"),
            "the refusal must disclose the unsupported mixed-version boundary: \
             {compatibility_boundary}"
        );
        assert!(
            compatibility_boundary.contains("cannot be proven safe"),
            "the message must not claim exclusion it cannot enforce: {compatibility_boundary}"
        );
    }

    #[test]
    fn an_identity_verified_dead_owner_does_not_vouch_for_whoever_holds_its_pid_now() {
        let message = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: false,
                identity_verified: true,
            }),
            &crate::lifecycle::StaleLockReclaim::OwnerUnknown,
        );
        assert!(
            message.contains("may since have been reused"),
            "a verified-dead owner must not leave the operator believing pid 4242 is still the \
             daemon: {message}"
        );
    }

    // The embed worker keeps at most one flush in flight and always awaits it
    // before scheduling the next. Modeling that bookkeeping with the real
    // `drain_pending_flush` helper proves two flushes can never run at once,
    // regardless of how long any single persist takes — the stable persisted
    // vector order depends on flushes never interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pipelined_flushes_never_interleave() {
        let concurrent = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        let mut pending: Option<tokio::task::JoinHandle<super::Result<usize>>> = None;
        const BATCHES: usize = 8;
        for _ in 0..BATCHES {
            // Serialize the previous flush before scheduling the next, exactly as
            // the drain loop does between successful batches.
            drain_pending_flush(&mut pending).await;
            let concurrent = Arc::clone(&concurrent);
            let peak = Arc::clone(&peak);
            let completed = Arc::clone(&completed);
            pending = Some(tokio::task::spawn_blocking(move || {
                let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                concurrent.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }));
        }
        // The tail flush must always be drained at loop exit.
        drain_pending_flush(&mut pending).await;

        assert!(pending.is_none(), "tail flush must be cleared on drain");
        assert_eq!(completed.load(Ordering::SeqCst), BATCHES, "every flush ran");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "at most one flush may run at a time"
        );
    }

    // The point of the lever: when a flush is left in flight (throughput
    // profile), the next batch's prep + GPU forward proceeds concurrently
    // instead of blocking on the persist. The flush parks until the "next
    // batch" signals it has started; if the loop had instead drained the flush
    // before running the next batch, this would deadlock — the timeout guards
    // against that regression.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_flush_overlaps_next_batch() {
        let flush_started = Arc::new(AtomicBool::new(false));
        let next_batch_started = Arc::new(AtomicBool::new(false));

        let flush_started_w = Arc::clone(&flush_started);
        let next_batch_started_r = Arc::clone(&next_batch_started);
        let mut pending: Option<tokio::task::JoinHandle<super::Result<usize>>> =
            Some(tokio::task::spawn_blocking(move || {
                flush_started_w.store(true, Ordering::SeqCst);
                // Hold the "persist" open until the next batch is underway.
                while !next_batch_started_r.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(0)
            }));

        // The next batch runs WITHOUT first draining the in-flight flush.
        let overlap = tokio::time::timeout(Duration::from_secs(5), async {
            while !flush_started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            next_batch_started.store(true, Ordering::SeqCst);
        })
        .await;
        assert!(
            overlap.is_ok(),
            "next batch must make progress while a flush is in flight"
        );

        drain_pending_flush(&mut pending).await;
        assert!(pending.is_none());
    }
}

#[cfg(test)]
mod enrichment_marker_tests {
    use super::{
        file_already_enriched, install_lsp_relations, load_lsp_enriched_marker,
        lsp_enriched_marker_path, EnrichmentWrite, PendingEnrichment, ENRICHMENT_WRITE_BATCH,
    };
    use crate::state::DaemonState;
    use kin_model::EntityStore;

    fn entity(name: &str) -> kin_model::Entity {
        kin_model::Entity {
            id: kin_model::EntityId::new(),
            kind: kin_model::EntityKind::Function,
            name: name.to_string(),
            language: kin_model::LanguageId::Python,
            fingerprint: kin_model::SemanticFingerprint {
                algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(kin_model::FilePathId::new("src/sessions.py")),
            span: None,
            signature: format!("def {name}()"),
            visibility: kin_model::Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn install_language_server_relation(state: &DaemonState) {
        let src = entity("send");
        let dst = entity("adapter_send");
        state.graph.upsert_entity(&src).unwrap();
        state.graph.upsert_entity(&dst).unwrap();
        state
            .graph
            .upsert_relation(&kin_model::Relation {
                id: kin_model::RelationId::new(),
                kind: kin_model::RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(src.id),
                dst: kin_model::GraphNodeId::Entity(dst.id),
                confidence: 1.0,
                origin: kin_model::RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    fn write_marker(state: &DaemonState, files: &[&str]) {
        std::fs::write(
            lsp_enriched_marker_path(state),
            serde_json::to_vec(&files.iter().map(|f| f.to_string()).collect::<Vec<_>>()).unwrap(),
        )
        .unwrap();
    }

    /// A marker whose relations are gone must not keep the loss permanent.
    ///
    /// This is what made the persistence defect unrecoverable rather than
    /// merely wasteful: the sweep recorded every file it finished, the
    /// relations did not survive the process, and each later daemon skipped the
    /// same files and re-derived nothing.
    #[test]
    fn a_marker_without_its_relations_is_discarded() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        write_marker(&state, &["src/sessions.py"]);

        load_lsp_enriched_marker(&state);

        assert!(
            !file_already_enriched(&state, "src/sessions.py"),
            "a marker the graph cannot corroborate must not skip the file it names"
        );
        load_lsp_enriched_marker(&state);
        assert!(
            !file_already_enriched(&state, "src/sessions.py"),
            "and it stays unhonored while the graph still cannot corroborate it, so the \
             judgment does not depend on having deleted the file"
        );
    }

    /// The FIR-2598 recovery path. A comment-only commit on `psf/requests` cost
    /// the store 11 `Calls` edges and one `Overrides` edge, and the
    /// `kin daemon sweep` a user runs next finished in 518 ms reporting
    /// "enriched 37/37 files" over 37 files it skipped. Nothing retired a
    /// marker entry, so a file swept once was skipped for the life of the
    /// store however far its declarations later moved.
    #[test]
    fn an_edited_file_loses_its_enrichment_marker_and_is_swept_again() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        install_language_server_relation(&state);
        super::mark_files_enriched(
            &state,
            &["src/sessions.py".to_string(), "src/adapters.py".to_string()],
            super::current_marker_epoch(&state),
        );
        assert!(
            file_already_enriched(&state, "src/sessions.py"),
            "the control: a swept file is skipped, which is what makes the retirement mean \
             something"
        );

        super::retire_enrichment_marker(&state, &["src/sessions.py".to_string()]);

        assert!(
            !file_already_enriched(&state, "src/sessions.py"),
            "an edited file must be swept again, or the edge its edit dropped never comes back"
        );
        assert!(
            file_already_enriched(&state, "src/adapters.py"),
            "and only the edited file is retired, so one commit does not re-sweep the repository"
        );

        // The retirement has to survive a restart, or the next daemon reloads
        // the entry this just dropped and skips the file again.
        let reopened =
            DaemonState::open(kin_core::KinLayout::new(repo_dir.path().join(".kin"))).unwrap();
        install_language_server_relation(&reopened);
        load_lsp_enriched_marker(&reopened);
        assert!(
            !file_already_enriched(&reopened, "src/sessions.py"),
            "a restart must not reload a marker entry an edit retired"
        );
        assert!(
            file_already_enriched(&reopened, "src/adapters.py"),
            "while the entries the edit did not touch are still resumed"
        );
    }

    /// The counterpart, so the retirement cannot be an unconditional wipe. A
    /// file nothing edited keeps its marker and its skip.
    #[test]
    fn retiring_a_file_no_marker_names_changes_nothing() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        install_language_server_relation(&state);
        super::mark_files_enriched(
            &state,
            &["src/sessions.py".to_string()],
            super::current_marker_epoch(&state),
        );

        super::retire_enrichment_marker(&state, &["src/models.py".to_string()]);

        assert!(
            file_already_enriched(&state, "src/sessions.py"),
            "editing one file must not re-sweep another"
        );
    }

    /// The other direction, so the reset is not simply "always re-sweep".
    #[test]
    fn a_marker_backed_by_relations_is_honored() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        install_language_server_relation(&state);
        write_marker(&state, &["src/sessions.py"]);

        load_lsp_enriched_marker(&state);

        assert!(
            file_already_enriched(&state, "src/sessions.py"),
            "a graph that still holds language-server relations resumes rather than re-sweeping"
        );
        assert!(lsp_enriched_marker_path(&state).exists());
    }

    /// `count` distinct language-server relations out of one source entity.
    ///
    /// Distinct ids, because the property under test is how many relations the
    /// buffer holds; a repeated id would be deduplicated by the graph and make
    /// a growing buffer look bounded.
    fn derived_relations(source: kin_model::EntityId, count: usize) -> Vec<kin_model::Relation> {
        (0..count)
            .map(|index| kin_model::Relation {
                id: kin_model::RelationId::from_content(
                    &source.to_string(),
                    &format!("target-{index}"),
                    "Calls",
                ),
                kind: kin_model::RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(source),
                dst: kin_model::GraphNodeId::Entity(kin_model::EntityId::new()),
                confidence: 1.0,
                origin: kin_model::RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .collect()
    }

    /// The buffer between a language server's answer and the graph is bounded.
    ///
    /// This is the property the sweep needs and did not have. Its cost per pass
    /// scales with the repository, not with anything this code chooses: one
    /// file on the requests corpus yields 1167 relations, and a pass that held a
    /// file, or a sweep, would hold a structure sized by the store being swept.
    ///
    /// The two assertions guard different things on purpose. The bound alone
    /// would pass for a buffer that silently dropped its overflow, and the total
    /// alone would pass for a buffer that held everything until the flush.
    #[test]
    fn an_enrichment_buffer_never_holds_more_than_one_write_batch() {
        let source = kin_model::EntityId::new();
        let mut pending = PendingEnrichment::default();
        let mut written = EnrichmentWrite::default();
        // A file's shape: several entities, one of them answering with far more
        // than a batch, and a remainder left over at the end.
        let arms = [400usize, 900, 7, 1, 300];
        for count in arms {
            written += pending.absorb(derived_relations(source, count), |batch| {
                EnrichmentWrite::all_published(batch.len())
            });
            assert!(
                pending.len() < ENRICHMENT_WRITE_BATCH,
                "after absorbing {count} relations the buffer still holds {}, which is a whole \
                 answer rather than less than one batch of {ENRICHMENT_WRITE_BATCH}",
                pending.len()
            );
        }
        written += pending.flush(|batch| EnrichmentWrite::all_published(batch.len()));
        assert_eq!(
            pending.len(),
            0,
            "the flush must leave nothing behind, or a file's tail never reaches the graph"
        );
        assert_eq!(
            written.published,
            arms.iter().sum::<usize>(),
            "every relation offered to the buffer must reach the writer exactly once"
        );
    }

    /// The bounded path writes exactly the relation set the unbounded one did,
    /// and a re-derivation of that same set writes nothing at all.
    ///
    /// Completeness first, because a bound that loses relations is a worse
    /// defect than the cost it removes. Then idempotence, which is the half
    /// that matters on a store whose sweep keeps being killed: the ids are
    /// content-addressed, so every re-sweep offers the graph the edges it
    /// already holds, and `upsert_relation` answers a byte-identical rewrite by
    /// dropping both endpoints' vectors and re-queueing them for embedding.
    #[test]
    fn the_bounded_path_writes_the_same_set_and_a_re_sweep_writes_nothing() {
        let unbounded_repo = tempfile::tempdir().unwrap();
        let unbounded =
            DaemonState::open(kin_core::init(unbounded_repo.path()).unwrap().layout).unwrap();
        let bounded_repo = tempfile::tempdir().unwrap();
        let bounded =
            DaemonState::open(kin_core::init(bounded_repo.path()).unwrap().layout).unwrap();

        let source = entity("Session_send");
        unbounded.graph.upsert_entity(&source).unwrap();
        bounded.graph.upsert_entity(&source).unwrap();
        let relations = derived_relations(source.id, 600);

        // The unbounded path: every relation offered on its own, which is what
        // one language-server query arm used to do.
        let mut unbounded_installed = EnrichmentWrite::default();
        for relation in &relations {
            unbounded_installed +=
                install_lsp_relations(&unbounded, std::slice::from_ref(relation));
        }

        // The bounded path: the same relations through the buffer.
        let mut pending = PendingEnrichment::default();
        let mut bounded_installed = pending.absorb(relations.clone(), |batch| {
            install_lsp_relations(&bounded, batch)
        });
        bounded_installed += pending.flush(|batch| install_lsp_relations(&bounded, batch));

        assert_eq!(
            bounded_installed.published, unbounded_installed.published,
            "the bounded path must install exactly what the unbounded one installed"
        );
        let held = |state: &DaemonState| -> std::collections::BTreeSet<kin_model::RelationId> {
            use kin_model::EntityStore;
            state
                .graph
                .get_all_relations_for_entity(&source.id)
                .unwrap()
                .into_iter()
                .map(|relation| relation.id)
                .collect()
        };
        assert_eq!(
            held(&bounded),
            held(&unbounded),
            "the two paths must leave the same relations in the graph"
        );
        assert_eq!(
            held(&bounded).len(),
            relations.len(),
            "every derived relation must be published, not just counted"
        );

        // The re-sweep. Same relations, same ids, nothing changed.
        let mut again = PendingEnrichment::default();
        let mut rewritten = again.absorb(relations.clone(), |batch| {
            install_lsp_relations(&bounded, batch)
        });
        rewritten += again.flush(|batch| install_lsp_relations(&bounded, batch));
        assert_eq!(
            rewritten.published, 0,
            "a re-derivation of relations the graph already holds must write nothing, or every \
             killed sweep discards the embeddings of every entity it touches"
        );
        assert_eq!(
            held(&bounded).len(),
            relations.len(),
            "and writing nothing must not remove anything either"
        );
    }
}

/// A budget no test process can fill, so an arm about host pressure reads host
/// pressure.
///
/// [`pressure_verdict`] takes the worse of two axes: the host's own reading, and
/// this daemon's standing against its own budget. An arm that pins only the host
/// still fails when the test binary itself is large. One run of this suite held
/// 6.1 GiB across a thousand parallel tests, against the 8.0 GiB the budget
/// derives on this machine, and a `Proceed` control came back `Shrink`. That is
/// the budget being right about a question the arm was not asking.
///
/// The operator value wins outright and is not clamped, so pinning it takes the
/// second axis out of every arm that is not about it. The budget itself is
/// proven in `scripts/acceptance/memory_pressure_refusal.py`, where the levers
/// are the other way round.
#[cfg(test)]
fn budget_no_test_can_fill() -> kin_core::test_env::EnvVarGuard {
    kin_core::test_env::EnvVarGuard::set(
        kin_core::memory_pressure::FOOTPRINT_BUDGET_ENV,
        (1024u64 * 1024 * 1024 * 1024).to_string(),
    )
}

/// What the daemon does about heavy work when the machine has no room for it.
///
/// Driven through the forced-level override rather than by filling the host,
/// because a test that has to exhaust a machine's memory to prove Kin backs off
/// is a test that takes the machine down to run. The override is the same seam
/// the acceptance suite uses, so what is proven here is what ships.
///
/// Each case is paired with its control: the same call under no pressure has to
/// reach the same decision it reached before this guard existed, or the guard
/// would be indistinguishable from having broken the work outright.
#[cfg(test)]
mod memory_pressure_tests {
    use super::{
        clear_pressure_refusal_for_work, decide_sweep_on_start, embed_batch_under_pressure,
        embedding_coverage_is_complete, pressure_announcement_after_retirement,
        pressure_refusal_matches_work, pressure_refusal_needs_disclosure, pressure_verdict,
        queue_embedding_backfill_under_pressure, retire_embed_pressure_for_unavailable_persistence,
        sample_tree_footprint, start_or_defer_background_embed, tree_footprint_from, ProcessRow,
        SweepStartDecision,
    };
    // Gated exactly like its only caller, the walk test that spawns a real
    // child. The daemon itself calls this on every platform; it is the test
    // that cannot, so an ungated import here is dead on Windows and `-D
    // warnings` makes dead imports fatal.
    #[cfg(unix)]
    use super::walk_process_table;
    use crate::state::DaemonState;
    use kin_core::memory_pressure::{HeavyWork, PressureLevel, PressureRefusal, Verdict};
    use kin_core::test_env::EnvVarGuard;
    use kin_model::EntityStore;

    fn open_store(repo_dir: &std::path::Path) -> DaemonState {
        let init = kin_core::init(repo_dir).unwrap();
        DaemonState::open(init.layout).unwrap()
    }

    fn write_pressure_refusal(root: &std::path::Path, work: &str) -> PressureRefusal {
        let refusal = PressureRefusal {
            work: work.to_string(),
            level: "critical".to_string(),
            reason: format!("{work} was refused"),
            at_unix: 1,
        };
        let mut refusals = PressureRefusal::read_all(root);
        refusals.retain(|existing| existing.work != refusal.work);
        refusals.push(refusal.clone());
        let newest = refusals.last().expect("one refusal").clone();
        std::fs::write(
            kin_core::memory_pressure::pressure_record_path(root),
            serde_json::to_vec(&serde_json::json!({
                "work": newest.work,
                "level": newest.level,
                "reason": newest.reason,
                "at_unix": newest.at_unix,
                "refusals": refusals,
            }))
            .unwrap(),
        )
        .unwrap();
        refusal
    }

    fn install_pending_embedding(state: &DaemonState) {
        state
            .graph
            .upsert_entity(&kin_model::Entity {
                id: kin_model::EntityId::new(),
                kind: kin_model::EntityKind::Function,
                name: "pending_embedding".to_string(),
                language: kin_model::LanguageId::Rust,
                fingerprint: kin_model::SemanticFingerprint {
                    algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                    signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                    behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(kin_model::FilePathId::new("src/lib.rs")),
                span: None,
                signature: "fn pending_embedding()".to_string(),
                visibility: kin_model::Visibility::Private,
                role: kin_model::EntityRole::Source,
                doc_summary: None,
                metadata: kin_model::EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            })
            .unwrap();
        assert!(
            state.graph.embedding_status().pending > 0,
            "the fixture must represent real selected-graph work, not just an empty queue"
        );
    }

    fn row(pid: u32, parent: Option<u32>, footprint_bytes: u64) -> ProcessRow {
        ProcessRow {
            pid,
            parent,
            is_thread: false,
            footprint_bytes,
        }
    }

    /// One `/proc/<pid>/task` row as Linux publishes it: its own tid, its
    /// owning process as its parent, and, because a thread shares that
    /// process's address space, that process's whole proportional set as its
    /// reading. FIR-2823.
    fn thread_of(tid: u32, owner: u32, footprint_bytes: u64) -> ProcessRow {
        ProcessRow {
            pid: tid,
            parent: Some(owner),
            is_thread: true,
            footprint_bytes,
        }
    }

    /// FIR-2653, over a synthetic process table carrying what `/proc` would
    /// publish for each of its rows.
    ///
    /// The shape is the measured one: a daemon and thirteen children that all
    /// map the same 1.75 GiB of shared image, each holding a little of its own.
    /// Every row's body goes through the same resolver the daemon reads a live
    /// `/proc` with, so what is exercised here is the reading and the fold
    /// together rather than a hand-written number standing in for both.
    ///
    /// The resident-set column is kept in the fixture and asserted on, because
    /// it is what makes this test able to fail: summing it is the pre-fix
    /// arithmetic, it comes to 25.6 GiB, and a 12 GiB container cannot hold it.
    #[test]
    fn a_page_thirteen_children_share_is_counted_once_across_the_tree() {
        const KB: u64 = 1024;
        const GIB: u64 = 1024 * 1024 * 1024;
        // One 1.75 GiB image, mapped by all fourteen processes. 14 divides it
        // evenly, so the per-process PSS share is exact and the test asserts
        // figures rather than tolerances.
        const SHARED_KB: u64 = 1_835_008;
        const SHARE_KB: u64 = SHARED_KB / 14;
        const DAEMON_PRIVATE_KB: u64 = 716_800;
        const CHILD_PRIVATE_KB: u64 = 30_720;

        fn rollup(private_kb: u64) -> String {
            format!(
                "Rss:            {} kB\nPss:            {} kB\n\
                 Shared_Clean:   {SHARED_KB} kB\nShared_Dirty:         0 kB\n\
                 Private_Clean:  {private_kb} kB\nPrivate_Dirty:        0 kB\n",
                SHARED_KB + private_kb,
                SHARE_KB + private_kb,
            )
        }

        let bodies: Vec<(u32, Option<u32>, String)> =
            std::iter::once((100u32, Some(1u32), rollup(DAEMON_PRIVATE_KB)))
                .chain((0..13).map(|n| (200 + n, Some(100u32), rollup(CHILD_PRIVATE_KB))))
                .collect();

        let table = bodies
            .iter()
            .map(|(pid, parent, body)| ProcessRow {
                pid: *pid,
                parent: *parent,
                is_thread: false,
                footprint_bytes: kin_daemon_spawn::resolve_process_footprint(
                    Some(body),
                    None,
                    None,
                    4096,
                )
                .expect("a rollup carrying a Pss line is readable"),
            })
            .collect::<Vec<_>>();

        // The pre-fix arithmetic, computed from the same fixture so the control
        // and the experiment cannot drift apart.
        let summed_resident: u64 = bodies
            .iter()
            .map(|(_, _, body)| {
                body.lines()
                    .find_map(|line| {
                        line.strip_prefix("Rss:")?
                            .split_whitespace()
                            .next()?
                            .parse::<u64>()
                            .ok()
                    })
                    .expect("every fixture row carries a resident set")
                    * KB
            })
            .sum();
        assert!(
            summed_resident > 25 * GIB,
            "the pre-fix reading of this fixture is {summed_resident} bytes, which is what \
             this test exists to be able to see"
        );
        assert!(
            summed_resident > 12 * GIB,
            "and it is more than the container it was measured in could physically hold"
        );

        let tree = tree_footprint_from(100, &table);
        assert_eq!(tree.child_count, 13);
        assert_eq!(
            tree.total_bytes(),
            (SHARED_KB + DAEMON_PRIVATE_KB + 13 * CHILD_PRIVATE_KB) * KB,
            "the shared image is counted once across the fourteen processes that map it, \
             plus what each holds alone"
        );
        assert!(
            tree.total_bytes() < 3 * GIB,
            "roughly 2.8 GiB, against 25.6 GiB summed resident"
        );

        // What that costs is not a label on a dial. Under a 12 GiB container
        // the derived budget is 6 GiB, and the two readings give opposite
        // answers to "may background embedding start".
        let bars = kin_core::memory_pressure::Thresholds::default();
        let host = kin_core::memory_pressure::MemoryPressure::Known(
            kin_core::memory_pressure::MemoryReading {
                source: kin_core::memory_pressure::PressureSource::Cgroup,
                limit_bytes: 12 * GIB,
                used_bytes: 3 * GIB,
                swap_used_bytes: None,
                swap_total_bytes: None,
                oom_kills: Some(0),
                peak_bytes: None,
            },
        );
        // Derived by hand rather than through `resolve`, which consults the
        // process environment: a sibling test in this module pins an operator
        // budget no test can fill, and a parallel run of this one would then
        // grade 25.6 GiB against a terabyte and proceed. A check that another
        // test can switch off is a check that cannot fail.
        let budget = kin_core::memory_pressure::FootprintBudget {
            bytes: kin_core::memory_pressure::FootprintBudget::derived_from(12 * GIB),
            source: kin_core::memory_pressure::BudgetSource::Derived,
        };
        assert_eq!(budget.bytes, 6 * GIB, "half of a 12 GiB container");
        let stand = |footprint| kin_core::memory_pressure::BudgetStanding { footprint, budget };
        assert_eq!(
            kin_core::memory_pressure::Verdict::decide(
                kin_core::memory_pressure::HeavyWork::EmbedBatch,
                &host,
                Some(&stand(tree)),
                &bars,
            ),
            kin_core::memory_pressure::Verdict::Proceed,
            "under the cap, with room, embedding starts"
        );
        let pre_fix = kin_core::memory_pressure::TreeFootprint {
            own_bytes: 0,
            children_bytes: summed_resident,
            child_count: 13,
            kernel_capped: false,
        };
        assert!(
            kin_core::memory_pressure::Verdict::decide(
                kin_core::memory_pressure::HeavyWork::EmbedBatch,
                &host,
                Some(&stand(pre_fix)),
                &bars,
            )
            .refused(),
            "and the pre-fix reading refuses it, which is the defect this fixes"
        );
    }

    /// FIR-2823, over the process table Linux publishes for a threaded daemon.
    ///
    /// The shape is the v0.6.1 stranger's express reading: one daemon whose
    /// eleven threads `sysinfo` returns from `processes()` beside real
    /// processes, each with its own tid and the daemon as its parent. Every
    /// thread row carries the daemon's rollup VERBATIM, because that is what
    /// `/proc/<tid>/smaps_rollup` answers with: threads share one address
    /// space, so each reads back the whole process's proportional set.
    ///
    /// Two real descendants sit beside the threads, a language server and its
    /// worker, so the test separates the fix from an over-deletion. A fold that
    /// stopped counting children at all would satisfy "the number got smaller"
    /// and fails here on `child_count` and on the children's own bytes.
    ///
    /// The pre-fix figure is computed from the same fixture rather than written
    /// down, so the control and the experiment cannot drift apart.
    #[test]
    fn a_daemons_threads_are_not_children_and_are_counted_once() {
        const KB: u64 = 1024;
        const GIB: u64 = 1024 * 1024 * 1024;
        // The measured express daemon: 1.41 GiB resident, 0.863 GiB
        // proportional, eleven threads, and Kin reporting 10.35 GiB.
        const DAEMON_RSS_KB: u64 = 1_478_656;
        const DAEMON_PSS_KB: u64 = 905_216;
        const THREADS: u64 = 11;
        const SERVER_PSS_KB: u64 = 512 * KB;
        const WORKER_PSS_KB: u64 = 128 * KB;

        fn rollup(rss_kb: u64, pss_kb: u64) -> String {
            format!(
                "Rss:            {rss_kb} kB\nPss:            {pss_kb} kB\n\
                 Shared_Clean:   {} kB\nPrivate_Clean:  {pss_kb} kB\n",
                rss_kb.saturating_sub(pss_kb),
            )
        }
        let read = |body: &str| {
            kin_daemon_spawn::resolve_process_footprint(Some(body), None, None, 4096)
                .expect("a rollup carrying a Pss line is readable")
        };

        let daemon_body = rollup(DAEMON_RSS_KB, DAEMON_PSS_KB);
        let daemon_bytes = read(&daemon_body);
        let server_bytes = read(&rollup(SERVER_PSS_KB * 2, SERVER_PSS_KB));
        let worker_bytes = read(&rollup(WORKER_PSS_KB * 2, WORKER_PSS_KB));

        // The fixture's central claim, asserted rather than assumed: a thread's
        // rollup IS its process's, so a thread row's reading is the daemon's
        // own figure over again.
        let thread_bytes = read(&daemon_body);
        assert_eq!(
            thread_bytes, daemon_bytes,
            "a thread reads back the whole address space it shares, which is why summing \
             threads multiplies rather than measures"
        );

        let table = |threads: u64| {
            let mut rows = vec![
                row(100, Some(1), daemon_bytes),
                row(200, Some(100), server_bytes),
                row(201, Some(200), worker_bytes),
            ];
            rows.extend((0..threads).map(|n| {
                thread_of(
                    u32::try_from(300 + n).expect("fixture tids fit in a u32"),
                    100,
                    thread_bytes,
                )
            }));
            rows
        };

        let tree = tree_footprint_from(100, &table(THREADS));

        assert_eq!(
            tree.child_count, 2,
            "the language server and its worker are the daemon's only children; the eleven \
             threads are the daemon itself"
        );
        assert_eq!(
            tree.own_bytes, daemon_bytes,
            "the daemon's own proportional set, counted once"
        );
        assert_eq!(
            tree.children_bytes,
            server_bytes + worker_bytes,
            "every real descendant still charged, so this cannot be satisfied by counting none"
        );
        assert_eq!(
            tree.total_bytes(),
            daemon_bytes + server_bytes + worker_bytes,
            "one reading per process, threads folded into the process that owns them"
        );

        // The acceptance criterion, stated the way it was written: thread count
        // must not move the answer.
        assert_eq!(
            tree_footprint_from(100, &table(1)),
            tree_footprint_from(100, &table(64)),
            "a daemon with 64 threads reports what the same daemon with one thread reports"
        );

        // The pre-fix arithmetic, from the same fixture: the daemon's own
        // figure once per thread plus itself.
        let pre_fix_bytes = daemon_bytes * (THREADS + 1) + server_bytes + worker_bytes;
        assert!(
            pre_fix_bytes > 10 * GIB,
            "the pre-fix reading of this fixture is {pre_fix_bytes} bytes, the 10.35 GiB the \
             stranger was shown, and this test exists to be able to see it"
        );
        assert!(
            tree.total_bytes() < 2 * GIB,
            "roughly 1.5 GiB, against the 10.35 GiB reported"
        );

        // What that costs is not a label on a dial. Under the stranger's 12 GiB
        // container the derived budget is 6 GiB, and the two readings give
        // opposite answers to "may background embedding start", which is why
        // one repository sat at 0 of 2116 vectors.
        let bars = kin_core::memory_pressure::Thresholds::default();
        let host = kin_core::memory_pressure::MemoryPressure::Known(
            kin_core::memory_pressure::MemoryReading {
                source: kin_core::memory_pressure::PressureSource::Cgroup,
                limit_bytes: 12 * GIB,
                used_bytes: 3 * GIB,
                swap_used_bytes: None,
                swap_total_bytes: None,
                oom_kills: Some(0),
                peak_bytes: None,
            },
        );
        // Derived by hand rather than through `resolve`, for the reason the
        // FIR-2653 test above gives: a sibling test pins an operator budget,
        // and a check another test can switch off is a check that cannot fail.
        let budget = kin_core::memory_pressure::FootprintBudget {
            bytes: kin_core::memory_pressure::FootprintBudget::derived_from(12 * GIB),
            source: kin_core::memory_pressure::BudgetSource::Derived,
        };
        assert_eq!(budget.bytes, 6 * GIB, "half of a 12 GiB container");
        let stand = |footprint| kin_core::memory_pressure::BudgetStanding { footprint, budget };
        assert_eq!(
            kin_core::memory_pressure::Verdict::decide(
                kin_core::memory_pressure::HeavyWork::EmbedBatch,
                &host,
                Some(&stand(tree)),
                &bars,
            ),
            kin_core::memory_pressure::Verdict::Proceed,
            "counted once, the daemon has room and embedding starts"
        );
        let pre_fix = kin_core::memory_pressure::TreeFootprint {
            own_bytes: daemon_bytes,
            children_bytes: pre_fix_bytes - daemon_bytes,
            child_count: usize::try_from(THREADS).expect("fixture thread count fits") + 2,
            kernel_capped: false,
        };
        assert!(
            kin_core::memory_pressure::Verdict::decide(
                kin_core::memory_pressure::HeavyWork::EmbedBatch,
                &host,
                Some(&stand(pre_fix)),
                &bars,
            )
            .refused(),
            "and the pre-fix reading refuses it, which is the defect this fixes"
        );
    }

    /// A thread that is somehow reported as owning a process must not smuggle
    /// that process back into the count through the walk, and a thread of a
    /// CHILD is the daemon's memory exactly once, through the child.
    #[test]
    fn threads_are_skipped_at_every_depth() {
        let table = [
            row(100, Some(1), 1024),
            row(200, Some(100), 2048),
            thread_of(300, 100, 1024),
            thread_of(301, 200, 2048),
        ];
        let tree = tree_footprint_from(100, &table);
        assert_eq!(
            tree.child_count, 1,
            "one real child, whose own threads are itself"
        );
        assert_eq!(tree.children_bytes, 2048, "the child charged once");
        assert_eq!(tree.total_bytes(), 1024 + 2048);
    }

    /// The shape the measured failure had: a daemon, a language server it
    /// started, and an unrelated process that must not be counted.
    #[test]
    fn the_fold_counts_the_daemons_own_children_and_nothing_else() {
        let table = [
            row(1, None, 8 * 1024 * 1024),
            row(100, Some(1), 6 * 1024 * 1024 * 1024),
            row(200, Some(100), 1930 * 1024 * 1024),
            // Somebody else's browser, on the same host, charged to nobody here.
            row(300, Some(1), 40 * 1024 * 1024 * 1024),
        ];
        let tree = tree_footprint_from(100, &table);
        assert_eq!(tree.own_bytes, 6 * 1024 * 1024 * 1024);
        assert_eq!(tree.children_bytes, 1930 * 1024 * 1024);
        assert_eq!(tree.child_count, 1);
        assert_eq!(
            tree.total_bytes(),
            6 * 1024 * 1024 * 1024 + 1930 * 1024 * 1024
        );
    }

    /// A language server that spawns a worker is still Kin's memory. Stopping
    /// at direct children reintroduces the same blindness one level down.
    #[test]
    fn the_fold_reaches_every_depth() {
        let table = [
            row(100, Some(1), 1024),
            row(200, Some(100), 2048),
            row(300, Some(200), 4096),
            row(400, Some(300), 8192),
        ];
        let tree = tree_footprint_from(100, &table);
        assert_eq!(tree.child_count, 3);
        assert_eq!(tree.children_bytes, 2048 + 4096 + 8192);
    }

    /// A malformed table must not hang the daemon inside its own back-off
    /// check, which is the least forgivable place to hang.
    #[test]
    fn a_parent_cycle_terminates_rather_than_spinning() {
        let table = [
            row(100, Some(300), 1024),
            row(200, Some(100), 2048),
            row(300, Some(200), 4096),
        ];
        let tree = tree_footprint_from(100, &table);
        assert_eq!(tree.own_bytes, 1024);
        assert_eq!(tree.child_count, 2, "each process is counted once");
        assert_eq!(tree.children_bytes, 2048 + 4096);
    }

    #[test]
    fn a_root_absent_from_the_table_still_reports_its_descendants() {
        // The descendants are real. A caller handed nothing would fall back to
        // the pre-budget behaviour on a reading that mostly succeeded.
        let table = [row(200, Some(100), 2048), row(300, Some(200), 4096)];
        let tree = tree_footprint_from(100, &table);
        assert_eq!(tree.own_bytes, 0);
        assert_eq!(tree.children_bytes, 2048 + 4096);
        assert_eq!(tree.child_count, 2);
    }

    #[test]
    fn a_lone_process_reports_itself_and_no_children() {
        let table = [row(100, Some(1), 4096)];
        let tree = tree_footprint_from(100, &table);
        assert_eq!(tree.own_bytes, 4096);
        assert_eq!(tree.children_bytes, 0);
        assert_eq!(tree.child_count, 0);
    }

    /// The sampler against this very test process, whatever host it runs on.
    ///
    /// Asserting a size here would be asserting on the machine CI happens to
    /// use. What is assertable is that the walk answers at all and that its own
    /// figure is the test binary's, which is never zero.
    #[test]
    fn the_sampler_measures_this_process() {
        let sampled = sample_tree_footprint().expect("this host publishes a process table");
        assert!(
            sampled.own_bytes > 0,
            "a running process holds more than nothing"
        );
        assert!(sampled.total_bytes() >= sampled.own_bytes);
    }

    /// FIR-2823 on the LIVE path: the seam between marking a thread and
    /// refusing to charge it.
    ///
    /// The fold test proves the fold skips a row marked as a thread. It cannot
    /// prove anything marks one, and a `thread_kind()` that never answered
    /// `Some` would leave that rule dead with every synthetic test still green.
    /// That is the join, so it is asserted over the real process table rather
    /// than at either end of it: threads this test starts itself must appear as
    /// thread rows, and the fold over the same reading must not have grown
    /// children by them.
    ///
    /// Linux only, because Linux is the platform that publishes
    /// `/proc/<pid>/task` and the only one where `sysinfo` returns threads from
    /// `processes()` at all. On macOS and Windows the reading contains no
    /// thread rows to find, so this would pass without exercising anything, and
    /// a check that cannot fail is worse than an absent one.
    #[cfg(target_os = "linux")]
    #[test]
    fn threads_this_process_starts_are_marked_and_never_become_children() {
        use super::current_process_rows;

        const SPAWNED: usize = 64;

        let own_threads = |rows: &[ProcessRow], me: u32| {
            rows.iter()
                .filter(|row| row.parent == Some(me) && row.is_thread)
                .count()
        };

        let (me, before) = current_process_rows().expect("Linux publishes a process table");
        let threads_before = own_threads(&before, me);

        // Parked rather than spinning, so the threads are alive for the second
        // reading and cost the box nothing while they wait.
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let wait = std::sync::Arc::new(std::sync::Mutex::new(wait));
        let started = std::sync::Arc::new(std::sync::Barrier::new(SPAWNED + 1));
        let handles = (0..SPAWNED)
            .map(|_| {
                let wait = std::sync::Arc::clone(&wait);
                let started = std::sync::Arc::clone(&started);
                std::thread::spawn(move || {
                    started.wait();
                    let _ = wait
                        .lock()
                        .expect("the park channel is not poisoned")
                        .recv();
                })
            })
            .collect::<Vec<_>>();
        started.wait();

        let (me_again, after) = current_process_rows().expect("Linux publishes a process table");
        assert_eq!(me_again, me, "the same process across both readings");
        let threads_after = own_threads(&after, me);

        // Half the join: the marking is live. Without this, the fold's rule
        // could be unreachable and nothing here would say so.
        //
        // An absolute floor rather than a delta, because a delta is only sound
        // when this test owns the process. `cargo nextest` gives it one, plain
        // `cargo test --workspace` does not, and there a sibling test's threads
        // exiting between the two readings subtracts from the delta and fails a
        // correct build. The floor cannot be gamed the same way: the SPAWNED
        // threads are alive at the second reading by construction, so anything
        // that marks threads at all must report at least that many.
        assert!(
            threads_after >= SPAWNED,
            "starting {SPAWNED} threads must show up as thread rows parented to this process: \
             {threads_before} before, {threads_after} after"
        );

        // The other half, over that same reading. Bounded by the number of
        // threads started rather than by an exact count, because other tests in
        // this binary run concurrently and may hold real child processes; the
        // pre-fix reading would be at least SPAWNED and this is well under it.
        let tree = tree_footprint_from(me, &after);
        assert!(
            tree.child_count < SPAWNED,
            "the {SPAWNED} threads this test started are not children of it, yet the fold \
             counted {} of them",
            tree.child_count
        );

        drop(release);
        for handle in handles {
            handle.join().expect("a parked thread exits when released");
        }
    }

    /// FIR-2653, on the LIVE path rather than over a fixture.
    ///
    /// The fold test above proves the arithmetic; this proves the figure that
    /// fills each row comes from the footprint reader and not from the resident
    /// set sitting beside it in the same `sysinfo` process. Nothing else covers
    /// that seam: a build that kept every corrected structure and went on
    /// reading `Process::memory()` passes every other test in this module,
    /// which is not a guess, it is what the falsification run reported.
    ///
    /// It compares distances rather than sizes, so it asserts nothing about the
    /// machine CI runs on and needs no tolerance constant: the row has to be at
    /// least as close to the footprint reading as to the resident one. Where a
    /// host cannot tell the two apart that is a tie and passes, which is the
    /// honest outcome rather than a threshold invented to break it.
    ///
    /// It measures the ROW rather than the finished walk, deliberately. The
    /// first version compared `walk_process_table`'s published total against
    /// readings taken around it, and building the whole process table allocates
    /// megabytes into the process being measured: under parallel tests the
    /// process grew more between the walk and the comparison than the two
    /// figures differ by, and the mutant went undetected. Here all three
    /// readings come from one refresh, microseconds apart.
    #[test]
    #[cfg(unix)]
    fn a_row_carries_the_footprint_reading_rather_than_the_resident_set_beside_it() {
        let me = sysinfo::get_current_pid().expect("this host names its own pid");
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[me]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_memory(),
        );
        let process = system
            .process(me)
            .expect("this host publishes its own process");
        let row = super::row_footprint_bytes(me.as_u32(), process);
        let footprint = kin_daemon_spawn::process_footprint_bytes(me.as_u32())
            .expect("this platform publishes a per-process footprint");
        let resident = process.memory();

        assert!(row > 0, "a running process holds something");
        assert!(
            row.abs_diff(footprint) <= row.abs_diff(resident),
            "the row carries {row} for this process, which is closer to its resident set of \
             {resident} than to its footprint of {footprint}"
        );
    }

    /// A real child, counted through the real process table.
    ///
    /// Every test above folds a table this file wrote. This one spawns an
    /// actual process and asks the host, which is the only way to catch the
    /// case where the fold is right and the walk that feeds it is not: a
    /// `parent()` this platform does not populate, or a table this build reads
    /// per-pid. That is the exact blindness the budget exists to end, so it
    /// gets a test that talks to the kernel.
    ///
    /// `walk_process_table` rather than `sample_tree_footprint`, because the
    /// sampler caches for two seconds and a test that read a cache primed by
    /// its neighbours would pass without asking anything.
    #[test]
    #[cfg(unix)]
    fn a_real_child_process_is_counted_by_the_real_walk() {
        let before = walk_process_table().expect("this host publishes a process table");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a child");
        // The child has to be scheduled and carry a resident set before the
        // table can show one. That wait is this test's whole flake surface, so
        // it retries rather than sleeping once and hoping.
        let mut after = before;
        for _ in 0..40 {
            std::thread::sleep(std::time::Duration::from_millis(50));
            after = walk_process_table().expect("this host publishes a process table");
            if after.child_count > before.child_count {
                break;
            }
        }
        let counted = after.child_count > before.child_count;
        let _ = child.kill();
        let _ = child.wait();
        assert!(
            counted,
            "a process this one started was not counted: before={before:?} after={after:?}. \
             A daemon that cannot see the language server it spawned is the blindness that \
             let the sweep run"
        );
    }

    #[test]
    fn a_critical_machine_refuses_the_cold_sweep_and_says_why() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());

        // The control first, so a refusal below cannot be a store that would
        // have declined a sweep anyway.
        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "nominal");
            assert_eq!(
                decide_sweep_on_start(&state),
                SweepStartDecision::Queue,
                "a machine with room sweeps exactly as it did before this guard"
            );
        }

        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
        let decision = decide_sweep_on_start(&state);
        let SweepStartDecision::PressureRefused { reason } = decision else {
            panic!("a critical machine must not queue an 18 GB pass: {decision:?}");
        };
        assert!(
            reason.contains("critical") && reason.contains("enrichment sweep"),
            "the refusal names the pressure and the work: {reason}"
        );

        let record = PressureRefusal::read(state.layout.root())
            .expect("a refusal reaches the surfaces outside this process, not just the log");
        assert_eq!(record.work, "lsp-sweep");
        assert_eq!(record.level, "critical");
        assert_eq!(record.reason, reason);
    }

    #[test]
    fn an_unreadable_machine_sweeps_exactly_as_before() {
        // Absence of evidence is not pressure. A host whose accounting cannot
        // be read has said nothing, and a daemon that stopped enriching over it
        // would have invented a limit nobody measured.
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "unknown");
        assert_eq!(decide_sweep_on_start(&state), SweepStartDecision::Queue);
        assert!(
            PressureRefusal::read(state.layout.root()).is_none(),
            "an unknown reading discloses nothing, because there is nothing to disclose"
        );
    }

    /// FIR-2632. An opted-out daemon on a full machine says the opt-out, and
    /// says nothing about memory.
    ///
    /// Pressure is a question about work somebody wants done. Asking it first
    /// meant an operator who had turned background embedding off got a memory
    /// refusal written into their store and printed on `kin doctor`,
    /// `kin graph status` and the MCP envelope, about a pass that was never
    /// going to run for a reason that had nothing to do with memory, while the
    /// opt-out's own line never printed at all.
    ///
    /// Both halves are asserted, because the disclosure is the part that
    /// reached three surfaces and the return value alone would have passed
    /// throughout.
    #[test]
    fn an_opted_out_daemon_on_a_full_machine_discloses_no_memory_refusal() {
        let _lock = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
        let _opted_out = EnvVarGuard::set(super::AUTO_EMBED_ENV, "0");
        write_pressure_refusal(state.layout.root(), HeavyWork::EmbedBatch.id());

        assert!(
            !start_or_defer_background_embed(&state),
            "the pass is deferred either way; what differs is why"
        );
        assert!(
            PressureRefusal::read(state.layout.root()).is_none(),
            "work nobody asked for must not be reported as work memory prevented: {:?}",
            PressureRefusal::read(state.layout.root())
        );

        for work in [HeavyWork::LspSweep.id(), "future-heavy-work"] {
            let expected = write_pressure_refusal(state.layout.root(), work);
            assert!(!start_or_defer_background_embed(&state));
            assert_eq!(
                PressureRefusal::read(state.layout.root()),
                Some(expected),
                "the embedding opt-out has no authority to retire {work}"
            );
        }
    }

    /// The same machine with the opt-out absent still refuses for memory, so
    /// the fix above is a precedence change and not a way of turning the gate
    /// off.
    #[test]
    fn a_wanted_pass_on_the_same_full_machine_still_refuses_for_memory() {
        let _lock = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        install_pending_embedding(&state);
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
        let _wanted = EnvVarGuard::unset(super::AUTO_EMBED_ENV);

        assert!(!start_or_defer_background_embed(&state));
        let record = PressureRefusal::read(state.layout.root())
            .expect("a pass somebody wanted, declined for memory, is disclosed");
        assert_eq!(record.work, "embed-batch");
        assert!(
            !state.background_embed_paused(),
            "pressure is a retryable backoff; only the operator opt-out permanently pauses"
        );
    }

    #[test]
    fn a_pressure_refusal_retries_on_the_next_wake_after_pressure_clears() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        install_pending_embedding(&state);
        let _wanted = EnvVarGuard::unset(super::AUTO_EMBED_ENV);

        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
            assert!(!start_or_defer_background_embed(&state));
            assert!(
                !state.background_embed_paused(),
                "the worker must remain eligible for its ambient retry"
            );
        }
        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "nominal");
            assert!(
                start_or_defer_background_embed(&state),
                "the next wake starts the same wanted pass once pressure clears"
            );
        }
    }

    #[test]
    fn sustained_pressure_refuses_before_materializing_the_backfill_queue() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        let mut announced = None;
        let mut queue_ran = false;

        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
            assert!(!queue_embedding_backfill_under_pressure(
                &state,
                &mut announced,
                || queue_ran = true,
            ));
        }
        assert!(
            !queue_ran,
            "a refused wake must not pay for the graph walk that builds its backlog"
        );
        assert!(
            !state.background_embed_paused(),
            "the refused worker stays eligible to try again on its next wake"
        );

        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "nominal");
            assert!(queue_embedding_backfill_under_pressure(
                &state,
                &mut announced,
                || queue_ran = true,
            ));
        }
        assert!(queue_ran, "the same queue is admitted once pressure clears");
    }

    #[test]
    fn a_critical_machine_defers_the_background_embedding_pass() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        install_pending_embedding(&state);
        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "nominal");
            assert!(
                start_or_defer_background_embed(&state),
                "a machine with room queues the backlog exactly as it did before"
            );
        }
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
        assert!(
            !start_or_defer_background_embed(&state),
            "a machine with no room must not start a bulk accelerator pass"
        );
        let record = PressureRefusal::read(state.layout.root()).expect("a disclosed refusal");
        assert_eq!(record.work, "embed-batch");
    }

    #[test]
    fn an_empty_queue_is_not_complete_while_indexed_coverage_is_short() {
        assert!(embedding_coverage_is_complete(0, 9, 9));
        assert!(
            !embedding_coverage_is_complete(0, 8, 9),
            "a refused missing-key backfill has no queued batch yet but still has outstanding work"
        );
        assert!(
            !embedding_coverage_is_complete(1, 9, 9),
            "queued artifact or entity work keeps the pass live even when indexed reaches total"
        );
        assert!(
            !embedding_coverage_is_complete(0, 10, 9),
            "an impossible over-indexed observation cannot retire durable work"
        );
    }

    #[test]
    fn unavailable_embed_persistence_retires_only_the_stale_memory_cause() {
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        write_pressure_refusal(state.layout.root(), HeavyWork::LspSweep.id());
        write_pressure_refusal(state.layout.root(), HeavyWork::EmbedBatch.id());
        write_pressure_refusal(state.layout.root(), "future-heavy-work");

        retire_embed_pressure_for_unavailable_persistence(&state);

        assert_eq!(
            PressureRefusal::read_all(state.layout.root())
                .into_iter()
                .map(|record| record.work)
                .collect::<Vec<_>>(),
            vec![
                HeavyWork::LspSweep.id().to_string(),
                "future-heavy-work".to_string(),
            ],
            "a persistence blocker replaces only the embed memory cause"
        );
    }

    #[test]
    fn a_complete_store_does_not_publish_a_refusal_before_looking_for_work() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
        let _wanted = EnvVarGuard::unset(super::AUTO_EMBED_ENV);

        for order in [
            [HeavyWork::LspSweep.id(), HeavyWork::EmbedBatch.id()],
            [HeavyWork::EmbedBatch.id(), HeavyWork::LspSweep.id()],
        ] {
            let dir = tempfile::tempdir().unwrap();
            let state = open_store(dir.path());
            for work in order {
                write_pressure_refusal(state.layout.root(), work);
            }
            write_pressure_refusal(state.layout.root(), "future-heavy-work");

            assert_eq!(state.graph.embedding_status().pending, 0);
            assert!(
                start_or_defer_background_embed(&state),
                "a complete wanted pass is admitted as a no-op even on a critical host"
            );
            assert_eq!(
                PressureRefusal::read_all(state.layout.root())
                    .into_iter()
                    .map(|record| record.work)
                    .collect::<Vec<_>>(),
                vec![
                    HeavyWork::LspSweep.id().to_string(),
                    "future-heavy-work".to_string(),
                ],
                "completion retires only the stale embed refusal and preserves independent work"
            );
            assert!(
                !state.background_embed_paused(),
                "a no-op completion is not the operator's permanent opt-out"
            );
        }
    }

    #[test]
    fn the_record_is_retired_once_the_work_runs_again() {
        // A surface reporting last week's refusal reads exactly like one
        // reporting this second's, so the pass that proceeds clears it.
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        {
            let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
            assert!(matches!(
                decide_sweep_on_start(&state),
                SweepStartDecision::PressureRefused { .. }
            ));
        }
        assert!(PressureRefusal::read(state.layout.root()).is_some());
        assert!(clear_pressure_refusal_for_work(&state, HeavyWork::LspSweep));
        assert!(PressureRefusal::read(state.layout.root()).is_none());
    }

    #[test]
    fn pressure_refusal_matching_is_exact_and_unknown_safe() {
        let embed = PressureRefusal {
            work: "embed-batch".to_string(),
            level: "critical".to_string(),
            reason: "embed refused".to_string(),
            at_unix: 1,
        };
        let lsp = PressureRefusal {
            work: "lsp-sweep".to_string(),
            ..embed.clone()
        };
        let future = PressureRefusal {
            work: "future-heavy-work".to_string(),
            ..embed.clone()
        };

        assert!(pressure_refusal_matches_work(
            Some(&embed),
            HeavyWork::EmbedBatch
        ));
        assert!(!pressure_refusal_matches_work(
            Some(&lsp),
            HeavyWork::EmbedBatch
        ));
        assert!(!pressure_refusal_matches_work(
            Some(&future),
            HeavyWork::EmbedBatch
        ));
        assert!(!pressure_refusal_matches_work(None, HeavyWork::EmbedBatch));
    }

    #[test]
    fn completed_embedding_retires_only_its_matching_refusal() {
        let _lock = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        let root = state.layout.root();

        write_pressure_refusal(root, "embed-batch");
        assert!(clear_pressure_refusal_for_work(
            &state,
            HeavyWork::EmbedBatch
        ));
        assert!(
            PressureRefusal::read(root).is_none(),
            "whole embedding coverage retires the embed refusal that would otherwise be probed \
             on every MCP response"
        );

        for work in ["lsp-sweep", "future-heavy-work"] {
            let expected = write_pressure_refusal(root, work);
            assert!(!clear_pressure_refusal_for_work(
                &state,
                HeavyWork::EmbedBatch
            ));
            assert_eq!(
                PressureRefusal::read(root),
                Some(expected),
                "embedding completion has no authority to clear {work}"
            );
        }
    }

    #[test]
    fn one_producer_cannot_retire_the_other_producers_record() {
        let _lock = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        let root = state.layout.root();

        let embed = write_pressure_refusal(root, "embed-batch");
        assert!(!clear_pressure_refusal_for_work(
            &state,
            HeavyWork::LspSweep
        ));
        assert_eq!(PressureRefusal::read(root), Some(embed));

        let lsp = write_pressure_refusal(root, "lsp-sweep");
        assert!(clear_pressure_refusal_for_work(
            &state,
            HeavyWork::EmbedBatch
        ));
        assert_eq!(PressureRefusal::read(root), Some(lsp));
        assert!(PressureRefusal::read_for_work(root, HeavyWork::EmbedBatch).is_none());
        assert!(PressureRefusal::read_for_work(root, HeavyWork::LspSweep).is_some());
    }

    #[test]
    fn completed_embedding_rearms_same_level_refusal_disclosure() {
        let _lock = crate::test_env_lock();
        let dir = tempfile::tempdir().unwrap();
        let state = open_store(dir.path());
        let root = state.layout.root();
        write_pressure_refusal(root, HeavyWork::EmbedBatch.id());
        let announced = Some(PressureLevel::Critical);

        let retired = clear_pressure_refusal_for_work(&state, HeavyWork::EmbedBatch);
        let announced = pressure_announcement_after_retirement(announced, retired);

        assert!(retired, "whole coverage retires the matching refusal");
        assert_eq!(
            announced, None,
            "completion re-arms disclosure even when the host remains critical"
        );
        assert!(pressure_refusal_needs_disclosure(
            announced,
            PressureLevel::Critical,
            PressureRefusal::read(root).as_ref(),
            HeavyWork::EmbedBatch,
        ));

        let lsp = write_pressure_refusal(root, HeavyWork::LspSweep.id());
        assert!(pressure_refusal_needs_disclosure(
            Some(PressureLevel::Critical),
            PressureLevel::Critical,
            Some(&lsp),
            HeavyWork::EmbedBatch,
        ));
        let embed = write_pressure_refusal(root, HeavyWork::EmbedBatch.id());
        assert!(
            !pressure_refusal_needs_disclosure(
                Some(PressureLevel::Critical),
                PressureLevel::Critical,
                Some(&embed),
                HeavyWork::EmbedBatch,
            ),
            "the same level is suppressed only while its matching durable record exists"
        );
    }

    #[test]
    fn an_elevated_machine_shrinks_the_batch_rather_than_stopping() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "elevated");
        let call = pressure_verdict(HeavyWork::EmbedBatch);
        assert!(
            matches!(call.verdict, Verdict::Shrink { .. }),
            "elevated shrinks; refusing at three-quarters would stop embedding on every busy \
             machine"
        );
        assert_eq!(embed_batch_under_pressure(512, &call.verdict), 128);
    }

    #[test]
    fn a_shrink_never_reaches_a_batch_of_zero() {
        // A size knob allowed to reach zero is a silent refusal wearing a
        // shrink's name: the loop would run forever embedding nothing.
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "elevated");
        let call = pressure_verdict(HeavyWork::EmbedBatch);
        assert_eq!(embed_batch_under_pressure(1, &call.verdict), 1);
        assert_eq!(embed_batch_under_pressure(3, &call.verdict), 1);
    }

    #[test]
    fn a_machine_with_room_leaves_every_batch_at_its_configured_size() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "nominal");
        let call = pressure_verdict(HeavyWork::EmbedBatch);
        assert_eq!(call.verdict, Verdict::Proceed);
        assert_eq!(embed_batch_under_pressure(512, &call.verdict), 512);
    }

    /// FIR-2632's sibling half, at the seam the reconcile loop reads.
    ///
    /// Admission is measured and never held. It was held when this landed, on
    /// the reasoning that a tick can wait because its events go back on the
    /// queue, and that holds for one tick and fails for a machine that stays
    /// loaded: the tick that would admit never comes and a written file stops
    /// being queryable for as long as the machine is busy.
    #[test]
    fn ambient_admission_is_measured_and_never_held() {
        let _lock = crate::test_env_lock();
        let _budget = super::budget_no_test_can_fill();
        let _forced = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "critical");
        let ambient = pressure_verdict(HeavyWork::AmbientAdmission);
        assert_eq!(
            ambient.verdict,
            Verdict::Proceed,
            "a file somebody wrote must not wait on a busy machine"
        );
        // The call still carries the level, which is what the reconcile loop
        // publishes the footprint standing from.
        assert_eq!(
            ambient.level,
            kin_core::memory_pressure::PressureLevel::Critical
        );
    }
}

/// The lifecycle a cold sweep has across daemon restarts, which is where this
/// went wrong and where its unit tests never looked.
///
/// The tally tests below exercise a sweep's arithmetic in isolation, and six of
/// them passed throughout while an interrupted sweep on a real store recorded
/// nothing at all. Arithmetic was never the gap: the gap was that everything a
/// sweep writes lives after its last file, and nobody modelled a process that
/// ends before then. These tests model exactly that, by calling the same two
/// functions the sweep calls and simply not calling the second one.
#[cfg(test)]
mod sweep_lifecycle_tests {
    use super::{
        decide_sweep_on_start, file_already_enriched, load_lsp_enriched_marker,
        mark_files_enriched, read_sweep_interruptions, sweep_finished, sweep_in_flight_path,
        sweep_started, SweepStartDecision, SWEEP_INTERRUPTION_LIMIT,
    };
    use crate::state::DaemonState;
    use kin_core::test_env::EnvVarGuard;
    use kin_model::EntityStore;

    fn open_store(repo_dir: &std::path::Path) -> DaemonState {
        let init = kin_core::init(repo_dir).unwrap();
        DaemonState::open(init.layout).unwrap()
    }

    /// Hold the pressure lever still for a test that only reads it.
    ///
    /// `decide_sweep_on_start` consults host memory pressure, and
    /// `KIN_MEMORY_PRESSURE` overrides that reading for the whole process. The
    /// sibling pressure tests set it under `test_env_lock`, whose stated domain
    /// is every env-mutating test in this binary. These tests mutate nothing,
    /// so they were never inside it, and a lock serializes only the sessions
    /// that take it: a reader outside sees whatever a writer is holding
    /// mid-test. Pinning the no-pressure control under the same lock is what
    /// makes these assertions about interruption counting rather than about
    /// what a sibling thread left behind, and it keeps them honest on a box
    /// that is genuinely short of memory.
    fn unpressured() -> (EnvVarGuard, EnvVarGuard, std::sync::MutexGuard<'static, ()>) {
        let lock = crate::test_env_lock();
        let budget = super::budget_no_test_can_fill();
        let pressure = EnvVarGuard::set("KIN_MEMORY_PRESSURE", "nominal");
        // Both pins are released before the lock, so no window exists where the
        // next holder can observe this test's overrides.
        (pressure, budget, lock)
    }

    /// One language-server relation, so the resume marker is corroborated by the
    /// graph and `load_lsp_enriched_marker` honors it. Without this a marker is
    /// discarded by design, and the skip half of these tests would pass for a
    /// reason that has nothing to do with what they check.
    fn install_language_server_relation(state: &DaemonState) {
        let mut entities = Vec::new();
        for name in ["send", "adapter_send"] {
            let entity = kin_model::Entity {
                id: kin_model::EntityId::new(),
                kind: kin_model::EntityKind::Function,
                name: name.to_string(),
                language: kin_model::LanguageId::Python,
                fingerprint: kin_model::SemanticFingerprint {
                    algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                    ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                    signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                    behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                    equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                    stability_score: 1.0,
                },
                file_origin: Some(kin_model::FilePathId::new("src/pkg/adapter.py")),
                span: None,
                signature: format!("def {name}()"),
                visibility: kin_model::Visibility::Public,
                role: kin_model::EntityRole::Source,
                doc_summary: None,
                metadata: kin_model::EntityMetadata::default(),
                lineage_parent: None,
                created_in: None,
                superseded_by: None,
            };
            state.graph.upsert_entity(&entity).unwrap();
            entities.push(entity);
        }
        state
            .graph
            .upsert_relation(&kin_model::Relation {
                id: kin_model::RelationId::new(),
                kind: kin_model::RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(entities[0].id),
                dst: kin_model::GraphNodeId::Entity(entities[1].id),
                confidence: 1.0,
                origin: kin_model::RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    fn swept_files() -> Vec<String> {
        vec![
            "src/pkg/adapter.py".to_string(),
            "src/pkg/auth.py".to_string(),
            "src/pkg/models.py".to_string(),
            "src/main.py".to_string(),
        ]
    }

    /// The failure this ticket is about, as a lifecycle: a sweep starts, the
    /// daemon's process ends before the sweep's tail, and a successor comes up.
    ///
    /// Observed on a four-file Python store at kin d4335ad0: a SIGTERM 327 ms
    /// into a sweep drained all seven other daemon tasks by name, emitted no
    /// completion line, and left the store carrying neither a resume marker nor
    /// an interruption count. A kill nobody records is a kill nothing can act
    /// on, which is why the breaker written for exactly this loop could not see
    /// it.
    #[test]
    fn a_sweep_killed_before_its_tail_is_counted_once_and_the_successor_still_sweeps() {
        let _quiet = unpressured();
        let repo_dir = tempfile::tempdir().unwrap();
        let state = open_store(repo_dir.path());

        sweep_started(&state);
        assert!(
            sweep_in_flight_path(&state).exists(),
            "a sweep must record that it began before it does any work, because the process \
             can end at any point after this and nothing later runs"
        );

        // The daemon dies here. Nothing in the sweep's tail executes.
        let decision = decide_sweep_on_start(&state);

        assert_eq!(
            decision,
            SweepStartDecision::Queue,
            "a daemon following an interrupted sweep must queue a cold sweep"
        );
        assert_eq!(
            read_sweep_interruptions(&state),
            1,
            "the successor must count the killed sweep, because the sweep could not count \
             itself; an uncounted kill is invisible to the breaker that exists for it"
        );
        assert!(
            !sweep_in_flight_path(&state).exists(),
            "and it must take the record rather than read it, so one kill is counted once \
             however many daemons follow"
        );

        assert_eq!(
            decide_sweep_on_start(&state),
            SweepStartDecision::Queue,
            "a second start after the same kill still sweeps"
        );
        assert_eq!(
            read_sweep_interruptions(&state),
            1,
            "and does not count that one kill again"
        );
    }

    /// A budget the process cannot spend is not a budget.
    ///
    /// The escalation watchdog force-exits once its grace elapses, and it runs
    /// no warning on the way out, so a drain budget at or above that grace both
    /// overstates what the shutdown waits and hides the overrun it promised to
    /// report. The first version of this fix was written as a flat 30 seconds
    /// against a 25-second grace, which is exactly that mistake.
    #[test]
    fn the_drain_budget_always_ends_before_the_force_exit_it_races() {
        let grace = super::DEFAULT_SHUTDOWN_ESCALATION_GRACE;
        assert!(
            super::lsp_drain_budget_from(grace) < grace,
            "the shutdown's wait for a sweep must end before the watchdog force-exits, or the \
             budget describes a wait the process never performs"
        );
        // An operator who sets the grace very low gets a proportionally low
        // budget rather than one that swallows the whole shutdown.
        let tight = std::time::Duration::from_secs(2);
        assert!(
            super::lsp_drain_budget_from(tight) < tight,
            "and it must stay under a grace an operator has tightened, which is the case a \
             flat constant gets wrong"
        );
    }

    /// The breaker still turns, so counting kills does not mint an endless loop.
    #[test]
    fn enough_killed_sweeps_open_the_circuit() {
        let _quiet = unpressured();
        let repo_dir = tempfile::tempdir().unwrap();
        let state = open_store(repo_dir.path());

        let mut decision = SweepStartDecision::Queue;
        for _ in 0..SWEEP_INTERRUPTION_LIMIT {
            sweep_started(&state);
            decision = decide_sweep_on_start(&state);
        }

        assert_eq!(
            decision,
            SweepStartDecision::CircuitOpen {
                interruptions: SWEEP_INTERRUPTION_LIMIT
            },
            "a store whose sweeps have all died without enriching anything must stop being \
             handed another one"
        );
    }

    /// The other direction, so the fix above is not simply "always call it
    /// interrupted": a sweep that reached its own end is a finished sweep, and
    /// the next daemon must not re-derive what it already made durable.
    #[test]
    fn a_completed_sweep_is_not_counted_as_an_interruption_and_its_files_are_not_re_swept() {
        let _quiet = unpressured();
        let repo_dir = tempfile::tempdir().unwrap();
        let files = swept_files();

        // The empty case is its own failure, ahead of everything below. With no
        // files enriched, "no file is re-swept" is true of any code at all,
        // including code with the skip deleted, so an empty list would make
        // every assertion after this one vacuous.
        assert!(
            !files.is_empty(),
            "this test proves files are not re-swept, so it needs files; an empty set makes \
             the property trivially true and the test unable to fail"
        );

        let layout = kin_core::init(repo_dir.path()).unwrap().layout;
        {
            let state = DaemonState::open(layout.clone()).unwrap();

            sweep_started(&state);
            // The sweep's tail, in the order the sweep runs it.
            mark_files_enriched(&state, &files, super::current_marker_epoch(&state));
            let counted = sweep_finished(&state, false, files.len());

            assert_eq!(
                counted, 0,
                "a sweep that finished must reset the interruption count"
            );
            assert!(
                !sweep_in_flight_path(&state).exists(),
                "and must leave no in-flight record, or the next start reads a finished sweep \
                 as a killed one"
            );
        }

        // A new daemon on the same store. Opened fresh rather than reused,
        // because the skip below must come from the marker this store now
        // carries, not from a set the first daemon left in memory.
        let state = DaemonState::open(layout).unwrap();
        // The relations the completed sweep published, which this daemon opened
        // its graph on. They are what the marker is checked against: a marker
        // the graph cannot corroborate is discarded by design, so without them
        // the skip below would fail for a reason that is not this test's.
        install_language_server_relation(&state);

        assert_eq!(
            decide_sweep_on_start(&state),
            SweepStartDecision::Queue,
            "the successor still queues a sweep, which is what keeps an unfinished graph \
             converging"
        );
        assert_eq!(
            read_sweep_interruptions(&state),
            0,
            "but a completed sweep must not be counted as an interruption by the next start"
        );

        load_lsp_enriched_marker(&state);
        for file in &files {
            assert!(
                file_already_enriched(&state, file),
                "the successor's sweep must skip {file}, which the completed sweep already \
                 made durable"
            );
        }
    }
}

#[cfg(test)]
mod lsp_query_column_tests {
    use super::lsp_query_column;

    /// The express case, which is what this exists for.
    ///
    /// `app.handle` at `lib/application.js` has the signature below, so the old
    /// `signature.find(name)` returned 0 and the query landed on `app`. The
    /// language server then answered about the receiver and the walk counted
    /// `app.set`, `res.send` and `res.redirect` as callees of `app.handle`.
    #[test]
    fn a_dotted_name_is_queried_at_its_final_segment() {
        assert_eq!(
            lsp_query_column("app.handle = function handle(", "app.handle", 0),
            4,
            "the cursor belongs on `handle`, not on the `app` receiver"
        );
    }

    /// The declaration's own column still offsets the result.
    #[test]
    fn the_declaration_column_is_carried_through() {
        assert_eq!(
            lsp_query_column("app.handle = function handle(", "app.handle", 6),
            10
        );
    }

    /// An undotted name keeps exactly the behavior it had.
    #[test]
    fn a_plain_name_is_unchanged() {
        assert_eq!(lsp_query_column("function handle(", "handle", 0), 9);
        assert_eq!(lsp_query_column("def send(self):", "send", 4), 8);
    }

    /// A deeper receiver chain still resolves to the last segment.
    #[test]
    fn only_the_final_segment_is_addressed() {
        assert_eq!(
            lsp_query_column("this.router.handle = fn", "this.router.handle", 0),
            12
        );
    }

    /// When the signature does not spell the dotted name out, the segment is
    /// still preferred over the declaration start, because the declaration
    /// start is the receiver again whenever the receiver opens the line.
    #[test]
    fn an_unspelled_dotted_name_falls_back_to_its_segment() {
        assert_eq!(
            lsp_query_column("exports.handle = function handle(", "app.handle", 0),
            8
        );
    }

    /// A signature that repeats the receiver must not pull the cursor back to
    /// it.
    ///
    /// `app.app = function app(` carries the token `app` three times. Anchoring
    /// on the whole dotted name and then stepping to its last segment lands on
    /// the member at 4. Searching for the segment on its own would return 0,
    /// the receiver, which is this same defect wearing a different disguise.
    #[test]
    fn a_signature_that_repeats_the_receiver_still_addresses_the_member() {
        assert_eq!(lsp_query_column("app.app = function app(", "app.app", 0), 4);
    }

    /// And a name the signature does not carry at all keeps the old answer
    /// rather than inventing a position.
    #[test]
    fn a_name_absent_from_the_signature_keeps_the_declaration_column() {
        assert_eq!(lsp_query_column("const x = 1", "handle", 3), 3);
    }
}

#[cfg(test)]
mod sweep_tally_tests {
    use super::{
        file_definitions_within_budget, next_interruption_count, sweep_circuit_open,
        sweep_marker_is_durable, EnrichmentWrite, SweepTally, SWEEP_INTERRUPTION_LIMIT,
    };
    use std::time::Duration;

    /// The number the sweep reports as `files`, and the one `/lsp/sweep/status`
    /// serves as `files_done`, is unchanged in meaning by the tally: a file the
    /// sweep finished with, whether it enriched it or found it already done.
    #[test]
    fn files_processed_counts_enriched_and_already_enriched_only() {
        let tally = SweepTally {
            enriched: 3,
            already_enriched: 4,
            unsupported_language: 5,
            server_unavailable: 6,
            source_unreadable: 7,
            definitions_over_budget: 0,
            ended_early: false,
        };
        assert_eq!(tally.files_processed(), 7);
        assert_eq!(tally.blocked(), 18);
    }

    /// A sweep that did work is not asked to explain itself. This is the arm
    /// that keeps the new warning off a healthy conversion.
    #[test]
    fn a_sweep_that_processed_files_reports_no_blocked_reason() {
        let tally = SweepTally {
            enriched: 37,
            ..SweepTally::default()
        };
        assert_eq!(tally.blocked_reason(37), None);
    }

    /// The express case, exactly: 66 files in the graph, a language server that
    /// would not start, and every file walked past. This used to report
    /// `files=0 total_files=66` and call itself complete, which is what a
    /// stranger read as a finished conversion.
    #[test]
    fn a_sweep_blocked_on_its_language_server_says_so() {
        let tally = SweepTally {
            server_unavailable: 66,
            ..SweepTally::default()
        };
        assert_eq!(
            tally.blocked_reason(66),
            Some("no language server could be started for these files"),
            "a sweep that enriched nothing because no server started must not be \
             indistinguishable from a converged one"
        );
    }

    /// Unreadable source and an unenrichable language are different findings
    /// and get different sentences, so a reader is not told to install a
    /// language server for a repository that has no supported language in it.
    #[test]
    fn the_blocked_reason_names_the_cause_it_actually_hit() {
        let unreadable = SweepTally {
            source_unreadable: 2,
            ..SweepTally::default()
        };
        assert_eq!(
            unreadable.blocked_reason(2),
            Some("their source could not be read from graph authority")
        );
        let unsupported = SweepTally {
            unsupported_language: 2,
            ..SweepTally::default()
        };
        assert_eq!(
            unsupported.blocked_reason(2),
            Some("this build enriches no language they are written in")
        );
    }

    /// The guard, and the reason the tally exists rather than a second counter.
    ///
    /// Every exit from the sweep loop lands in one of the tally's fields. A new
    /// `continue` added without a counter shows up here as an unaccounted file
    /// instead of silently deflating the `files` the sweep reports, which is the
    /// shape of the defect this whole change is about.
    #[test]
    fn a_file_that_reached_no_counter_is_reported_as_unaccounted() {
        let complete = SweepTally {
            enriched: 30,
            already_enriched: 6,
            server_unavailable: 30,
            ..SweepTally::default()
        };
        assert_eq!(complete.unaccounted(66), 0);

        let leaking = SweepTally {
            enriched: 30,
            ..SweepTally::default()
        };
        assert_eq!(
            leaking.unaccounted(66),
            36,
            "36 files left the sweep without reaching any counter and must be visible"
        );
    }

    /// One interrupted sweep must NOT open the circuit.
    ///
    /// A plain SIGTERM during shutdown ends a sweep early, so a breaker that
    /// tripped on a single interruption would fire on every clean stop and stop
    /// enriching a perfectly healthy store. This is the arm that keeps the
    /// breaker from being worse than the loop it guards.
    #[test]
    fn a_single_interrupted_sweep_does_not_open_the_circuit() {
        let after_one = next_interruption_count(0, true, 0);
        assert_eq!(after_one, 1);
        assert!(
            !sweep_circuit_open(after_one),
            "one interrupted sweep is ordinary, not a failing store"
        );
        assert!(
            !sweep_circuit_open(SWEEP_INTERRUPTION_LIMIT - 1),
            "the breaker opens at the limit, not before it"
        );
    }

    /// A store that keeps killing fruitless sweeps must back off.
    ///
    /// This is the marker-discard loop's own shape: a sweep dies before
    /// enriching anything, the daemon restarts, queues another, dies again. One
    /// stranger session logged 24 such sweeps.
    #[test]
    fn repeated_fruitless_interruptions_open_the_circuit() {
        let mut count = 0;
        for _ in 0..SWEEP_INTERRUPTION_LIMIT {
            count = next_interruption_count(count, true, 0);
        }
        assert!(
            sweep_circuit_open(count),
            "after {SWEEP_INTERRUPTION_LIMIT} consecutive fruitless interruptions the next \
             sweep must not be queued"
        );
    }

    /// One clean completion clears it, and progress is not punished.
    ///
    /// Two distinct cases. A sweep that FINISHED resets the count outright, so a
    /// store that recovers is not left permanently unswept. And a sweep that was
    /// interrupted but still enriched files made progress, so it neither trips
    /// the breaker nor resets it: the loop being guarded is the one that never
    /// achieves anything.
    #[test]
    fn a_clean_completion_resets_and_progress_is_not_punished() {
        assert_eq!(
            next_interruption_count(SWEEP_INTERRUPTION_LIMIT, false, 0),
            0,
            "a sweep that ran to completion clears the breaker"
        );
        assert!(!sweep_circuit_open(0));
        assert_eq!(
            next_interruption_count(2, true, 19),
            2,
            "an interrupted sweep that still enriched 19 files made progress: neither a trip \
             nor a reset"
        );
    }

    /// A sweep whose publication failed must NOT record its files as enriched.
    ///
    /// This is the arm that keeps a failure recoverable. The marker's only
    /// reader skips what it names, so marking unpublished files converts a
    /// transient publication failure into a permanent skip: the relations are
    /// gone, the marker says the files are done, and the next sweep passes over
    /// them reporting `already_enriched`.
    ///
    /// The pre-existing recovery check cannot catch that, because
    /// `graph_holds_language_server_relations` is an `.any()` over the graph and
    /// a single surviving Lsp relation from any earlier pass keeps the marker.
    #[test]
    fn a_sweep_that_did_not_publish_records_nothing() {
        assert!(
            !sweep_marker_is_durable(EnrichmentWrite::all_published(4231), false),
            "a sweep with relations that failed to publish must leave its files unmarked, \
             so the next sweep redoes them instead of skipping them forever"
        );
        assert!(
            sweep_marker_is_durable(EnrichmentWrite::all_published(4231), true),
            "a sweep that published records what it enriched"
        );
    }

    /// A sweep that published its snapshot but lost relations records nothing.
    ///
    /// The case the durability check could not see before. `published` says the
    /// snapshot reached disk; it says nothing about whether every relation the
    /// sweep offered reached the graph. A pass that offered 600 and got 588 in
    /// used to mark its files enriched on the strength of that clean save, and
    /// `file_already_enriched` would skip them from then on, so the twelve were
    /// written off permanently under a marker asserting the file was done.
    ///
    /// Leaving them unmarked is the repair: the pass cannot fix what the graph
    /// declined, but it can decline to call the file finished, and the next
    /// sweep offers those relations again.
    #[test]
    fn a_sweep_that_published_but_lost_relations_records_nothing() {
        let lossy = EnrichmentWrite {
            published: 588,
            offered: 600,
            vector_stale: 0,
        };
        assert_eq!(lossy.lost(), 12);
        assert!(
            !sweep_marker_is_durable(lossy, true),
            "a snapshot that saved cleanly does not make a lost relation durable, and marking \
             these files would skip them forever"
        );
        assert!(
            sweep_marker_is_durable(EnrichmentWrite::all_published(600), true),
            "a pass that lost nothing still marks, or the fix trades a permanent skip for a \
             permanent re-sweep"
        );
    }

    /// A sweep that produced nothing to publish still records its files.
    ///
    /// Without this arm the fix would trade a permanent skip for a permanent
    /// re-sweep: a file that yields no relations has nothing that can be lost,
    /// and sweeping it again on every daemon start forever is waste, not safety.
    #[test]
    fn a_sweep_with_nothing_to_publish_still_records_its_files() {
        assert!(
            sweep_marker_is_durable(EnrichmentWrite::all_published(0), false),
            "no relations means nothing could be lost, so the visit is worth recording"
        );
    }

    /// A provider that never answers is abandoned at its budget and counted.
    ///
    /// This is the case the budget exists for and the one a live language server
    /// will not reproduce on demand: the pass had no bound at all, and every
    /// query inside it inherits only the client's 10-second cap and yields an
    /// empty result that lets the loop continue to the next identifier, so a
    /// dead server costs identifiers times ten seconds instead of failing.
    #[tokio::test]
    async fn a_definitions_pass_that_never_answers_is_abandoned_and_counted() {
        let mut tally = SweepTally::default();
        let stalled = std::future::pending::<
            std::result::Result<kin_lsp::file_enrichment::FileEnrichmentResult, ()>,
        >();
        let result = file_definitions_within_budget(
            stalled,
            Duration::from_millis(60),
            "src/requests/models.py",
            &mut tally,
        )
        .await;
        assert_eq!(
            tally.definitions_over_budget, 1,
            "a pass abandoned at its budget must be counted, not merely logged"
        );
        assert!(
            result.relations.is_empty(),
            "an abandoned pass yields the same empty result a failed pass always did"
        );
    }

    /// The other direction: a pass that answers inside its budget is handed
    /// back UNCHANGED and costs the tally nothing.
    ///
    /// Without this arm the budget could quietly truncate healthy enrichment and
    /// every test above would still pass, which is the failure mode that matters
    /// most here: relations silently going missing look exactly like a corpus
    /// that had none.
    #[tokio::test]
    async fn a_pass_inside_its_budget_is_returned_byte_identical() {
        use kin_model::{GraphNodeId, Relation, RelationId, RelationKind, RelationOrigin};
        let src = kin_model::EntityId::new();
        let dst = kin_model::EntityId::new();
        let build = || kin_lsp::file_enrichment::FileEnrichmentResult {
            relations: vec![Relation {
                id: RelationId::from_bytes([9u8; 16]),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(src),
                dst: GraphNodeId::Entity(dst),
                confidence: 0.85,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            }],
            definitions_resolved: 7,
            positions_queried: 913,
        };
        let expected = build();
        let mut tally = SweepTally::default();
        // The pass must take REAL time before answering. An instantly-ready
        // future is polled once and returned before any budget can apply, so a
        // test written that way passes even with the budget set to a
        // nanosecond, and proves nothing about truncation. Found by falsifying
        // this very test: at a 1 ns budget it stayed green.
        let healthy = async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            std::result::Result::<_, ()>::Ok(build())
        };
        let result = file_definitions_within_budget(
            healthy,
            Duration::from_secs(120),
            "src/requests/models.py",
            &mut tally,
        )
        .await;
        assert_eq!(
            tally.definitions_over_budget, 0,
            "a pass that answered in time must not be counted against the budget"
        );
        assert_eq!(
            result.relations, expected.relations,
            "a healthy pass must come back with its relations unchanged; a budget that \
             quietly truncated them would look exactly like a corpus that had none"
        );
        assert_eq!(result.definitions_resolved, expected.definitions_resolved);
        assert_eq!(result.positions_queried, expected.positions_queried);
    }

    /// An interrupted sweep is not a miscounted one, and the guard must not
    /// confuse them.
    ///
    /// This is the real case, from a run whose daemon took SIGTERM at 31 of 37
    /// files: it logged `unaccounted=6` and warned that "an exit from the sweep
    /// loop is not being counted" about six files nothing had failed to count.
    /// The loop had simply been told to stop. A guard that reports a normal
    /// shutdown as a counting bug is worse than no guard, because it sends its
    /// reader after something that is not there.
    #[test]
    fn a_sweep_stopped_before_it_finished_reports_not_visited_and_never_warns() {
        let interrupted = SweepTally {
            enriched: 31,
            ended_early: true,
            ..SweepTally::default()
        };
        assert_eq!(
            interrupted.unaccounted(37),
            0,
            "a sweep that was told to stop has not miscounted anything"
        );
        assert_eq!(
            interrupted.not_visited(37),
            6,
            "the six files it never walked are still reported, as not_visited"
        );
        assert_eq!(
            interrupted.blocked_reason(37),
            None,
            "a stopped sweep is not a blocked one"
        );

        // The second sweep of that same run, which broke after one file.
        let barely_started = SweepTally {
            enriched: 1,
            ended_early: true,
            ..SweepTally::default()
        };
        assert_eq!(barely_started.unaccounted(37), 0);
        assert_eq!(barely_started.not_visited(37), 36);
    }

    /// The other direction, which is what the guard exists for: a sweep that
    /// ran to completion and still cannot account for every file HAS a counting
    /// bug, and must say so.
    #[test]
    fn a_completed_sweep_that_cannot_account_for_its_files_still_warns() {
        let leaking = SweepTally {
            enriched: 30,
            ended_early: false,
            ..SweepTally::default()
        };
        assert_eq!(
            leaking.unaccounted(66),
            36,
            "a completed sweep missing 36 files is the defect this guard is for"
        );
        assert_eq!(
            leaking.not_visited(66),
            0,
            "a completed sweep visited everything, so nothing is not_visited"
        );
    }

    /// A stopped sweep that enriched nothing must not be reported as blocked on
    /// its language server, which would send a reader after a server that was
    /// never the problem.
    #[test]
    fn a_sweep_stopped_before_enriching_anything_is_not_called_blocked() {
        let stopped_cold = SweepTally {
            ended_early: true,
            ..SweepTally::default()
        };
        assert_eq!(stopped_cold.blocked_reason(37), None);
        let really_blocked = SweepTally {
            server_unavailable: 37,
            ended_early: false,
            ..SweepTally::default()
        };
        assert_eq!(
            really_blocked.blocked_reason(37),
            Some("no language server could be started for these files")
        );
    }

    /// An empty graph is not a blocked sweep. Without this arm the new warning
    /// fires on every repository with nothing to enrich.
    #[test]
    fn a_sweep_over_no_files_is_not_blocked() {
        assert_eq!(SweepTally::default().blocked_reason(0), None);
        assert_eq!(SweepTally::default().unaccounted(0), 0);
    }
}

/// The shutdown half of FIR-2497.
///
/// The wake-tick retry proves durability for a daemon that keeps running. The
/// coverage regression was found on a daemon that STOPPED with a refusal
/// standing, and nothing in the graph flush writes the vector sidecar, so a
/// clean shutdown published graph truth and left the vectors in a process that
/// was about to end. These tests drive the real shutdown arm rather than the
/// helper beside it, because what has to hold is the wiring: a retry that
/// exists and is never called from shutdown is the bug it was written to fix.
#[cfg(all(test, feature = "embeddings"))]
mod shutdown_vector_checkpoint_tests {
    use super::{run_shutdown_persistence, DaemonState};
    use kin_db::EntityStore;
    use kin_model::{
        ArtifactId, Entity, EntityKind, EntityMetadata, FilePathId, FingerprintAlgorithm, Hash256,
        LanguageId, LocatedEntry, RepoPath, SemanticFingerprint, TreeDelta, TreeEntry, Visibility,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const STAGED_VECTORS: usize = 3;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// Open a store, stage coverage the product's own counter can see, leave
    /// nothing durable behind it, and force one authority-mismatch refusal by
    /// moving the live tree inside the checkpoint's reopen window.
    ///
    /// Returns the state with a refusal standing and the divergence still open.
    fn state_with_a_standing_refusal(
        repo_dir: &std::path::Path,
    ) -> (Arc<DaemonState>, ArtifactId, LocatedEntry) {
        let init = kin_core::init(repo_dir).unwrap();
        let vector_path = init.layout.kindb_vector_index_path();
        let state = Arc::new(DaemonState::open(init.layout).expect("fixture store must open"));

        let descriptor = kin_db::vector::IndexDescriptor {
            model_id: Some("fixture-embedder-v1".to_string()),
            graph_root: Some("fixture-root".to_string()),
        };
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors.set_descriptor(descriptor.clone());
        for slot in 0..STAGED_VECTORS {
            let entity = test_entity(&format!("embedded_{slot}"));
            state.graph.upsert_entity(&entity).unwrap();
            let mut embedding = [0.0f32; 4];
            embedding[slot] = 1.0;
            vectors
                .upsert_retrievable(kin_db::RetrievalKey::Entity(entity.id), &embedding)
                .expect("the fixture index must accept a staged vector");
        }
        vectors.save(&vector_path).unwrap();
        assert!(matches!(
            state
                .graph
                .load_vector_index_compatible(&vector_path, &descriptor),
            kin_db::vector::VectorIndexLoad::Loaded(STAGED_VECTORS)
        ));
        std::fs::remove_file(&vector_path).unwrap();
        assert_eq!(
            state.graph.embedding_status().indexed,
            STAGED_VECTORS,
            "the fixture must stage coverage the counter can see"
        );

        let arriving = ArtifactId::new();
        let arrived = LocatedEntry::new(
            RepoPath::from_utf8("src/arrived_during_reopen.rs").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([9u8; 32]), false),
        );
        let moving_graph = Arc::clone(&state.graph);
        let moved = Arc::new(AtomicBool::new(false));
        let arrived_seam = arrived.clone();
        state.set_vector_checkpoint_reopen_test_hook(Some(Arc::new(move || {
            // Once only: a seam that moved the tree on every reopen would model
            // a repository nobody can ever checkpoint, not a commit that lands.
            if moved.swap(true, Ordering::SeqCst) {
                return;
            }
            moving_graph
                .apply_transaction_delta(&kin_model::TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: arriving,
                        new: arrived_seam.clone(),
                    }],
                    ..Default::default()
                })
                .expect("the live graph must accept the concurrent mutation under test");
        })));
        state
            .flush_embed_progress()
            .expect_err("a live tree that moved away from authority must be refused");
        assert!(
            state.deferred_vector_checkpoint().is_some(),
            "the fixture must leave a refusal standing"
        );
        assert!(
            !vector_path.exists(),
            "the fixture must leave nothing durable behind the refusal"
        );

        (state, arriving, arrived)
    }

    /// Refusal standing, daemon shuts down cleanly, restart, count equals N.
    ///
    /// This is the arm the regression's own evidence asks for. Before the
    /// shutdown retry, the sequence ended with the sidecar still holding its
    /// older content and the process gone, which is why a store read
    /// 2112/2112 on one daemon and 1770/2112 on the next.
    ///
    /// The restart is modelled by dropping the live index and re-reading the
    /// sidecar through `load_vector_index_into_graph_if_valid`, the exact call
    /// `DaemonState::load_validated_vector_index` makes at open. The drop is
    /// load-bearing: without it the final count would come from the memory the
    /// shutdown was supposed to be rescuing the vectors out of, and the test
    /// could not fail.
    #[tokio::test]
    async fn a_refusal_standing_at_shutdown_is_checkpointed_and_survives_the_restart() {
        let repo_dir = tempfile::tempdir().unwrap();
        let (state, arriving, arrived) = state_with_a_standing_refusal(repo_dir.path());
        let vector_path = state.layout.kindb_vector_index_path();

        // The divergence closes, the way it closes in a real store once the
        // commit that opened it has settled.
        state
            .graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: arriving,
                    old: arrived,
                }],
                ..Default::default()
            })
            .expect("the live graph must accept the settling transition");

        run_shutdown_persistence(&state).await;

        assert!(
            vector_path.exists(),
            "shutdown must land a standing refusal rather than end with the vectors in memory"
        );
        assert!(
            state.deferred_vector_checkpoint().is_none(),
            "a checkpoint that landed must retire the record it closed"
        );

        state.graph.reset_vector_index();
        assert_eq!(
            state.graph.embedding_status().indexed,
            0,
            "the control: with the live index dropped the count must come from disk alone"
        );
        assert!(
            kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
                state.graph.as_ref(),
                &state.layout.kindb_snapshot_path(),
                None,
            )
            .expect("the checkpointed sidecar must be readable")
            .attached,
            "the checkpointed sidecar must install through the daemon's own open-time path"
        );
        assert_eq!(
            state.graph.embedding_status().indexed,
            STAGED_VECTORS,
            "a restart after a clean shutdown must read back every staged vector"
        );
    }

    /// The budget kin#994 gave this arm is a ceiling, not an amount, and this
    /// change must not turn it into one.
    ///
    /// An ordinary daemon has no refusal standing, so the shutdown retry has to
    /// cost it nothing: no authority reopen, no sidecar write, no delay. A
    /// version that retried unconditionally would pay a full reopen on every
    /// clean exit, which is the overcorrection this must not become.
    ///
    /// The fixture stages a real attached index and then removes the sidecar,
    /// which is what gives this test the ability to fail at all. An earlier
    /// version opened a bare store with no index, so "no sidecar was written"
    /// held whatever the code did, and the unconditional-retry sabotage passed
    /// it cleanly. A control whose subject cannot act is not a control.
    #[tokio::test]
    async fn a_shutdown_with_no_refusal_standing_writes_no_sidecar() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let vector_path = init.layout.kindb_vector_index_path();
        let state = Arc::new(DaemonState::open(init.layout).expect("fixture store must open"));

        let descriptor = kin_db::vector::IndexDescriptor {
            model_id: Some("fixture-embedder-v1".to_string()),
            graph_root: Some("fixture-root".to_string()),
        };
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors.set_descriptor(descriptor.clone());
        for slot in 0..STAGED_VECTORS {
            let entity = test_entity(&format!("embedded_{slot}"));
            state.graph.upsert_entity(&entity).unwrap();
            let mut embedding = [0.0f32; 4];
            embedding[slot] = 1.0;
            vectors
                .upsert_retrievable(kin_db::RetrievalKey::Entity(entity.id), &embedding)
                .expect("the fixture index must accept a staged vector");
        }
        vectors.save(&vector_path).unwrap();
        assert!(matches!(
            state
                .graph
                .load_vector_index_compatible(&vector_path, &descriptor),
            kin_db::vector::VectorIndexLoad::Loaded(STAGED_VECTORS)
        ));
        // Removed so a write during shutdown is visible. The index stays
        // attached, so there is real content a stray checkpoint would write,
        // and an unconditional retry recreates this file.
        std::fs::remove_file(&vector_path).unwrap();
        assert!(
            state.graph.embedding_status().indexed > 0,
            "the fixture must hold coverage a stray checkpoint could write, or this control \
             cannot fail"
        );
        assert!(
            state.deferred_vector_checkpoint().is_none(),
            "the control fixture must carry no refusal"
        );

        let started = std::time::Instant::now();
        run_shutdown_persistence(&state).await;
        let elapsed = started.elapsed();

        assert!(
            !vector_path.exists(),
            "a shutdown with nothing refused must not checkpoint the vector sidecar at all"
        );
        assert!(
            state.deferred_vector_checkpoint().is_none(),
            "and must not invent a refusal"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(30),
            "a shutdown with nothing refused must not pay for an authority reopen; took {elapsed:?}"
        );
    }
}
