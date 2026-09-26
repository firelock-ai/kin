// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin upgrade`: bring a store an older Kin build wrote up to this build's
//! replay semantics, in place, keeping everything the store holds.
//!
//! A store records the replay-semantics version it was created under
//! ([`kin_core::hydration_semantics`]), and every answer it serves is qualified
//! while that version is behind this build's. Re-ingesting with `kin init`
//! builds a fresh store from source files, which clears the qualification and
//! drops every native commit, branch, review and spec the store held. This is
//! the path that keeps them.
//!
//! ## What it changes, and what it leaves alone
//!
//! History is not rewritten. A change's identity hashes its deltas and its
//! parents, so re-deriving the past would rename every change and every ref,
//! review, alias, receipt and replica that names one. What is brought current is
//! the state the store SERVES:
//!
//! 1. Every local branch head, and a detached workspace base, is re-derived from
//!    the exact tree that head holds and the bodies the store keeps, under this
//!    build's replay ([`kin_index::rederive_tree_semantics`]), the derivation a
//!    fresh admission of that tree would run. Entity identities carry over from
//!    what the head already held, so an unchanged declaration keeps its id.
//! 2. Where the re-derived state differs, one native change records the
//!    difference on top of the head: no tree delta, its parent the old head, its
//!    message naming both versions. Branches fast-forward onto it. Where it does
//!    not differ, the head itself is the verified state and nothing is added,
//!    unless a change the older build recorded already builds on that head:
//!    then a change with no delta marks it, so the upgrade's claim, which
//!    follows first parents from its anchors, never reaches state that build
//!    recorded afterwards. The workspace's own head also takes a change with
//!    no delta when nothing else in the upgrade changes and the workspace
//!    carries no checked binding history: the lineage starts at the commit,
//!    and a commit that changes nothing is refused. Relations no derivation
//!    authors (language-server and manual edges, and co-change edges) are
//!    carried over whenever both endpoints survive.
//! 3. The workspace moves onto its new base, and uncommitted work is re-derived
//!    under the same build so the pending overlay stays exact.
//!
//! Those three are one repository transaction, compared against the authority
//! generation it was planned from, so the store holds either all of it or none
//! of it. The same transaction pays the workspace's owed derivation work, the
//! parses a daemon's standalone publications recorded as owed, against that
//! exact predecessor, where the re-derivation verifier proves the workspace's
//! committed graph. Only after that commit does the upgrade re-baseline the relation
//! census (a re-derivation can legitimately remove edges an older build minted)
//! and write the hydration-semantics record, last, because the record is the
//! claim and the transaction is what makes it true. A run stopped before the
//! commit leaves the store exactly as it was; a run stopped after it is finished
//! by running `kin upgrade` again, which finds every head already derived and
//! records it without adding a change.
//!
//! On a store that already records this build's semantics a second run changes
//! nothing, unless the workspace graph carries no checked binding history. Then
//! it re-qualifies: the same re-derivation and commit, which lets the
//! re-derivation verifier start a lineage, and the record, already current, is
//! left alone. Its commit is the workspace head's change with no delta when
//! every head already holds this build's derivation.
//!
//! ## What it refuses
//!
//! Nothing is written on any refusal: a record a newer build wrote or one this
//! build cannot read, a store holding more than its own workspace, an open
//! merge, a stash sealed on a head the upgrade would move (restoring it onto
//! the moved head would be refused, so it is named first), a source body the
//! store does not hold, a tree this build cannot derive, and authority that
//! moved while the upgrade was planned.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Write as _;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use kin_core::hydration_semantics::{self, HydrationStanding};
use kin_model::{
    compute_semantic_change_id, AuthorId, ChangeOrigin, ChangeStore, Entity, EntityId, GraphNodeId,
    Hash256, OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    Relation, RelationId, RepositoryTransaction, ResolvedTree, SemanticChange, SemanticChangeId,
    Timestamp, WorkspaceExpectation, WorkspaceHead, WorkspaceMutation, WorkspaceState,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde::Serialize;

use super::repository_authority::ActiveRepositoryAuthority;

/// Schema of the machine-readable report `kin upgrade --json` prints.
pub const UPGRADE_REPORT_SCHEMA: &str = "kin.store-upgrade.v1";

/// How often a long derivation says it is still working.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(5);

/// Where an upgrade that ran stood when it finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeState {
    /// The store already records this build's replay semantics.
    AlreadyCurrent,
    /// The served state was re-derived and the record written.
    Upgraded,
    /// The store already recorded this build's semantics but its workspace
    /// carried no checked binding history, so the served state was re-derived
    /// to start a lineage. The record was already current and is unchanged.
    Requalified,
}

/// One head the upgrade re-derived.
#[derive(Debug, Clone, Serialize)]
pub struct HeadUpgrade {
    /// The branches naming this head, and `HEAD` for a detached workspace base.
    pub refs: Vec<String>,
    /// The change the head named before the upgrade.
    pub previous: String,
    /// The change whose state is this build's derivation: a new checkpoint, or
    /// `previous` itself when the head already held exactly that state.
    pub anchor: String,
    /// Whether a checkpoint change was recorded for this head.
    pub checkpoint: bool,
    pub entity_deltas: usize,
    pub relation_deltas: usize,
    /// Relations no derivation authors that were carried to the new state.
    pub carried_relations: usize,
}

/// What `kin upgrade` did.
#[derive(Debug, Clone, Serialize)]
pub struct UpgradeReport {
    pub schema: &'static str,
    pub state: UpgradeState,
    /// The version the store recorded before, or `None` when it recorded none.
    pub from: Option<u32>,
    /// The version this build derives, and now records.
    pub to: u32,
    pub heads: Vec<HeadUpgrade>,
    /// Whether the workspace held uncommitted work that was re-derived too.
    ///
    /// Language-server enrichment the daemon published into the workspace
    /// overlay after a commit is Kin's own derived state, not work anyone
    /// still has to commit, so an overlay holding only that does not count.
    pub workspace_dirty: bool,
    /// Entity-source files the upgrade parsed, counted once per distinct tree.
    pub source_files: usize,
    /// Authority generation after the upgrade committed.
    pub authority_generation: Option<u64>,
    /// Whether the workspace's graph carries checked binding history after the
    /// upgrade. `None` only when the upgrade stopped before reading it.
    pub binding_history_checked: Option<bool>,
    /// Why the re-derivation verifier did not start a binding-history lineage,
    /// when it looked and refused.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binding_history_refusal: Option<String>,
    pub elapsed_ms: u64,
    /// Follow-up steps that could not be completed after the commit, each
    /// naming what the store still needs. Empty on a complete upgrade.
    pub warnings: Vec<String>,
}

impl UpgradeReport {
    fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        let from = self.from.map_or_else(
            || "no recorded version".to_string(),
            |v| format!("version {v}"),
        );
        match self.state {
            UpgradeState::AlreadyCurrent => lines.push(format!(
                "This store already records hydration semantics version {}, the version this \
                 build derives. Nothing to upgrade.",
                self.to
            )),
            UpgradeState::Upgraded | UpgradeState::Requalified => {
                lines.push(if self.state == UpgradeState::Upgraded {
                    format!(
                        "Upgraded this store's served state from {from} to hydration semantics \
                         version {}.",
                        self.to
                    )
                } else {
                    format!(
                        "This store already records hydration semantics version {}, and its \
                         workspace carried no checked binding history, so its served state was \
                         re-derived to check it.",
                        self.to
                    )
                });
                for head in &self.heads {
                    let names = head.refs.join(", ");
                    if head.checkpoint {
                        lines.push(format!(
                            "  {names}: recorded change {} over {} ({} entity and {} relation \
                             changes, {} carried relation(s))",
                            head.anchor,
                            head.previous,
                            head.entity_deltas,
                            head.relation_deltas,
                            head.carried_relations
                        ));
                    } else {
                        lines.push(format!(
                            "  {names}: {} already holds this build's derivation; no change added",
                            head.previous
                        ));
                    }
                }
                if self.workspace_dirty {
                    lines.push(
                        "  workspace: uncommitted work re-derived under the same build and kept \
                         pending"
                            .to_string(),
                    );
                }
                lines.push(format!(
                    "Parsed {} source file(s) in {} ms. Every earlier change, branch, review, \
                     spec and history record is unchanged; changes recorded before this upgrade \
                     keep the replay version that authored them.",
                    self.source_files, self.elapsed_ms
                ));
                match self.binding_history_checked {
                    Some(true) => lines.push(
                        "Binding history is checked from this upgrade forward, so answers over \
                         the upgraded state can certify."
                            .to_string(),
                    ),
                    Some(false) => lines.push(format!(
                        "Binding history could not be checked for this workspace{}, so \
                         source-derived answers stay qualified. Running `kin upgrade` again \
                         re-derives the served state and checks it once more.",
                        self.binding_history_refusal
                            .as_deref()
                            .map(|reason| format!(" ({reason})"))
                            .unwrap_or_default()
                    )),
                    None => {}
                }
            }
        }
        for warning in &self.warnings {
            lines.push(format!("warning: {warning}"));
        }
        lines
    }
}

/// Test seams around the one durable commit, so a test can stop a real
/// upgrade at the exact points a crash could.
///
/// The command passes [`UpgradeHooks::default`], which does nothing.
#[derive(Default)]
pub struct UpgradeHooks {
    /// Runs after planning and before the repository transaction commits.
    pub before_commit: Option<Box<dyn Fn() -> Result<()>>>,
    /// Runs after the transaction commits and before the record is written.
    pub after_commit: Option<Box<dyn Fn() -> Result<()>>>,
}

/// `kin upgrade`.
pub async fn run(json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    // Read-only checks first, so a refusal costs nothing and stops no daemon.
    let before = hydration_semantics::read(&layout);
    refuse_unupgradable(&hydration_semantics::standing_of(
        &before,
        hydration_semantics::binary_version(),
    ))?;
    let author = crate::commands::require_commit_author_for(&layout)?;
    // The daemon is the long-lived writer, and the upgrade moves the refs and
    // the workspace it serves. It is stopped first so it neither plans against
    // the authority this transaction replaces nor keeps serving the state it
    // held once the transaction lands.
    crate::commands::daemon::stop_current_repo_quiet(layout.root())
        .await
        .context("stop this repository's daemon before upgrading its store")?;
    // Then the upgrade takes the repository's runtime authority, which every
    // daemon holds from before it opens any state until it exits, and keeps it
    // until the upgrade is done, so no daemon starts beside it. Taken after the
    // stop, so a stopping daemon's exit is waited out within the budget. This
    // is for liveness only: the upgrade's commit is a compare-and-swap on the
    // generation it planned from, and pays exactly what that predecessor owed.
    let runtime = crate::daemon_client::acquire_repository_runtime_authority_within(
        layout.root(),
        kin_daemon_spawn::REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET,
    )
    .with_context(|| {
        format!(
            "acquire repository runtime authority for {}",
            layout.root().display()
        )
    })?
    .ok_or_else(|| {
        anyhow!(
            "kin upgrade refused: another Kin process holds this repository's runtime authority \
             ({}), so the upgrade cannot run with no daemon beside it. Run `kin daemon stop`, \
             then `kin upgrade` again. Nothing was changed",
            layout.root().display()
        )
    })?;
    let progress = |line: &str| {
        if !json {
            let _ = writeln!(std::io::stderr(), "{line}");
        }
    };
    let report = upgrade_store(&layout, author, &UpgradeHooks::default(), &progress);
    drop(runtime);
    let report = report?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in report.lines() {
            println!("{line}");
        }
    }
    if report.warnings.is_empty() {
        Ok(())
    } else {
        bail!(
            "the upgrade committed and {} follow-up step(s) did not complete; run `kin upgrade` \
             again to finish them",
            report.warnings.len()
        )
    }
}

/// Refuse a standing an upgrade must not touch, naming why and what to do.
fn refuse_unupgradable(standing: &HydrationStanding) -> Result<()> {
    match standing {
        HydrationStanding::Ahead { .. } => bail!(
            "kin upgrade refused: {}. Upgrade Kin itself instead; this build does not re-derive a \
             store a newer build recorded, and nothing was changed",
            standing.sentence()
        ),
        HydrationStanding::Rederived { under, derives, .. } if under > derives => bail!(
            "kin upgrade refused: {}. Upgrade Kin itself instead; this build does not re-derive a \
             store a newer build recorded, and nothing was changed",
            standing.sentence()
        ),
        HydrationStanding::Unreadable { .. } => bail!(
            "kin upgrade refused: {}. A record this build cannot read can belong to a store a \
             newer build created, so upgrade Kin to the newest build first. If the newest build \
             still cannot read it, the record is damaged: remove \
             `.kin/kindb/hydration-semantics` and run `kin upgrade` again. Nothing was changed",
            standing.sentence()
        ),
        _ => Ok(()),
    }
}

/// Upgrade the store at `layout`, attributing any checkpoint to `author`.
///
/// Touches no daemon: the command stops this repository's daemon around it,
/// and a caller in a test runs it against a store no daemon serves.
pub fn upgrade_store(
    layout: &kin_core::KinLayout,
    author: AuthorId,
    hooks: &UpgradeHooks,
    progress: &dyn Fn(&str),
) -> Result<UpgradeReport> {
    let started = Instant::now();
    let derives = hydration_semantics::binary_version();
    let before = hydration_semantics::read(layout);
    let standing = hydration_semantics::standing_of(&before, derives);
    refuse_unupgradable(&standing)?;
    let from = before
        .upgrade()
        .map(|upgrade| upgrade.under)
        .or(before.created_under());
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?;
    let authority = ActiveRepositoryAuthority::open(&binding)
        .context("open this store's repository authority")?;
    // A store that already records this build's semantics needs nothing,
    // unless its workspace graph carries no checked binding history. Then this
    // run re-qualifies it: it re-derives the served state exactly as an
    // upgrade does and lets the re-derivation verifier start a lineage, and it
    // leaves the hydration record alone, which already states the version.
    let requalify = !standing.is_gap();
    if requalify && workspace_binding_history_checked(&authority)? {
        return Ok(UpgradeReport {
            schema: UPGRADE_REPORT_SCHEMA,
            state: UpgradeState::AlreadyCurrent,
            from,
            to: derives,
            heads: Vec::new(),
            workspace_dirty: false,
            source_files: 0,
            authority_generation: Some(authority.manager().read_authority().roots().generation),
            binding_history_checked: Some(true),
            binding_history_refusal: None,
            elapsed_ms: elapsed_ms(started),
            warnings: Vec::new(),
        });
    }
    let retire_python = from.is_none_or(|version| version < kin_core::lsp_scope::HYDRATION_VERSION)
        && derives >= kin_core::lsp_scope::HYDRATION_VERSION;
    let plan = plan_upgrade(
        layout,
        &authority,
        author,
        derives,
        from,
        !requalify,
        retire_python,
        progress,
    )?;

    if let Some(hook) = &hooks.before_commit {
        hook()?;
    }
    let verifier = kin_index::binding_history::RederivationBindingHistoryVerifier::default();
    // The same compare-and-swap pays the workspace's owed derivation work,
    // recorded against the exact predecessor it was planned from, where the
    // verifier proves the re-derivation it pays for. A record a later
    // publication makes stays owed; one that lands first makes this refuse.
    let payment = kin_db::RederivationPayment {
        workspace_id: authority.workspace_id,
        hydration_version: derives,
    };
    let receipt = match &plan.transaction {
        Some(transaction) => Some(
            authority
                .manager()
                .commit_rederived_repository_transaction(transaction.clone(), &verifier, payment)
                .map_err(|error| {
                    anyhow!(
                        "kin upgrade refused to commit: {error}. Nothing was changed; if another \
                         command moved this store while the upgrade was planned, run `kin \
                         upgrade` again"
                    )
                })?,
        ),
        None => None,
    };
    if let Some(receipt) = &receipt {
        receipt
            .validate()
            .context("validate the upgrade's repository receipt")?;
    }
    if let Some(hook) = &hooks.after_commit {
        hook()?;
    }

    // The hydration record is the completion claim and remains old if this
    // cleanup fails. Rerunning the existing upgrade heals the committed prefix.
    if retire_python {
        retire_python_enrichment_sidecars(layout, &plan.python_entities).context(
            "the upgrade committed; finish Python enrichment retirement with kin upgrade",
        )?;
    }

    let mut warnings = Vec::new();
    if receipt.is_some() {
        // A memo of the new workspace base, so the next open serves it rather
        // than folding history. A failure costs time, never truth.
        if let Err(error) = authority.materialize_workspace_base_graph_section() {
            tracing::warn!(%error, "could not memoize the upgraded workspace base graph section");
        }
    }
    // What a daemon from an earlier build kept beside the store is paid by the
    // commit above once authority records that commit's payment for this
    // workspace: its re-derivation covered every body the workspace tree
    // names, and a record for any other body was overtaken before it. Removed
    // only then, and never by what the files are. A removal that fails leaves
    // the files for the next daemon start, which judges each entry against the
    // graph this commit left and finds it paid.
    if let Some(transaction) = plan.transaction.as_ref().filter(|_| receipt.is_some()) {
        if paid_by(&authority, transaction.operation_id) {
            remove_legacy_owed_work_records(layout);
        }
    }
    let upgraded = authority
        .manager()
        .read_authority()
        .workspace_graph_snapshot(&authority.workspace_id)
        .context("read the upgraded workspace graph")?
        .ok_or_else(|| anyhow!("repository authority has no graph for this workspace"))?;
    let binding_history_checked = upgraded.verified_binding_history.is_some();
    // Why the verifier refused, when it did, so the report says what kept the
    // lineage from starting rather than only that it did not.
    let binding_history_refusal = (!binding_history_checked)
        .then(|| verifier.refusals().into_iter().next())
        .flatten();
    // The census baseline describes the graph a pass last left behind. The
    // re-derivation can remove edges an older build minted, and a comparison
    // against the older build's census would report that as a loss on the
    // next commit and qualify every answer, so the upgraded graph is the new
    // baseline. Written before the record, which is the claim.
    if let Err(error) = rebaseline_relation_census(layout, upgraded) {
        warnings.push(format!(
            "the relation census was not re-baselined ({error:#}); the next commit may report \
             edges the older build minted as lost"
        ));
    }
    if !requalify {
        let record = hydration_semantics::upgraded_stamp(
            &before,
            derives,
            &plan.anchors,
            chrono::Utc::now(),
        )
        .map_err(|error| anyhow!("kin upgrade could not write its record: {error}"))?;
        hydration_semantics::write(layout, &record).with_context(|| {
            format!(
                "the upgrade committed and its record could not be written to {}; run `kin \
                 upgrade` again, which finds the upgraded heads and writes it without adding a \
                 change",
                layout.kindb_hydration_semantics_path().display()
            )
        })?;
    }

    Ok(UpgradeReport {
        schema: UPGRADE_REPORT_SCHEMA,
        state: if requalify {
            UpgradeState::Requalified
        } else {
            UpgradeState::Upgraded
        },
        from,
        to: derives,
        heads: plan.heads,
        workspace_dirty: plan.workspace_dirty,
        source_files: plan.source_files,
        authority_generation: Some(
            receipt
                .as_ref()
                .map(|receipt| receipt.generation)
                .unwrap_or(plan.generation),
        ),
        binding_history_checked: Some(binding_history_checked),
        binding_history_refusal,
        elapsed_ms: elapsed_ms(started),
        warnings,
    })
}

/// Whether the graph this repository's workspace selects carries checked
/// binding history.
fn workspace_binding_history_checked(authority: &ActiveRepositoryAuthority) -> Result<bool> {
    Ok(authority
        .manager()
        .read_authority()
        .workspace_graph_snapshot(&authority.workspace_id)
        .context("read this store's workspace graph")?
        .is_some_and(|graph| graph.verified_binding_history.is_some()))
}

/// Whether authority records `operation`'s payment of this workspace's owed
/// derivation work.
fn paid_by(authority: &ActiveRepositoryAuthority, operation: OperationId) -> bool {
    let lease = authority.manager().read_authority();
    let ledger = &lease.metadata().owed_derivations;
    ledger
        .payment_for(authority.workspace_id)
        .is_some_and(|payment| payment.operation_id() == operation)
}

/// The records of owed work a daemon from an earlier build kept beside the
/// store: the parses it owed, and the paths it derived entities for that no
/// commit had published.
const LEGACY_OWED_WORK_RECORDS: [&str; 2] = ["semantic-debt.json", "unpublished-enrichment.json"];

/// Remove [`LEGACY_OWED_WORK_RECORDS`] once a re-derivation commit has paid
/// them.
///
/// The migration boundary's one write, and never fatal: this build records
/// owed work in repository authority and never writes these files, and one
/// left behind is judged at the next daemon start against the graph the
/// upgrade committed, which already holds every parse it named.
fn remove_legacy_owed_work_records(layout: &kin_core::KinLayout) {
    for name in LEGACY_OWED_WORK_RECORDS {
        let record = layout.root().join(name);
        match std::fs::remove_file(&record) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => tracing::warn!(
                record = %record.display(),
                %error,
                "could not remove an earlier build's record of owed work; the next daemon start \
                 judges it against the upgraded graph, which holds every parse it named"
            ),
        }
    }
}

/// Clean the operational records only after the exact upgrade transaction.
/// This command owns runtime authority, so no daemon can append or mark a
/// completed pass beside these replacements. The final hydration claim is
/// written later. Legacy Python journal rows also fail closed in daemon replay,
/// covering a crash between the authority commit and this cleanup.
fn retire_python_enrichment_sidecars(
    layout: &kin_core::KinLayout,
    python_entities: &HashSet<EntityId>,
) -> Result<()> {
    use std::io::BufRead as _;
    rewrite_upgrade_sidecar(
        &layout.root().join("lsp-accepted-evidence.jsonl"),
        |input, out| {
            let mut line = Vec::new();
            while input.read_until(b'\n', &mut line)? != 0 {
                let retire = serde_json::from_slice::<kin_core::lsp_scope::AcceptedRelation>(&line)
                    .is_ok_and(|record| {
                        record.python_workspace_scope != Some(kin_core::lsp_scope::WORKSPACE_SCOPE)
                            && kin_core::lsp_scope::is_python_relation(&record.relation, |id| {
                                python_entities
                                    .contains(id)
                                    .then_some(kin_model::LanguageId::Python)
                            })
                    });
                if !retire {
                    out.write_all(&line)?;
                }
                line.clear();
            }
            Ok(())
        },
    )?;
    rewrite_upgrade_sidecar(
        &layout.root().join("lsp-enriched-files.json"),
        |input, out| {
            let mut marker: serde_json::Value = serde_json::from_reader(input)?;
            // Version 1 wrote only the path array. Keep its representation
            // (and unrelated paths) even though the daemon no longer trusts
            // that version as proof of completion.
            let files = if marker.is_array() {
                marker.as_array_mut()
            } else {
                marker
                    .get_mut("files")
                    .and_then(|files| files.as_array_mut())
            }
            .ok_or_else(|| anyhow!("unreadable language-server completion record"))?;
            if files.iter().any(|file| !file.is_string()) {
                bail!("language-server completion record contains a non-path entry");
            }
            files.retain(|file| !kin_core::lsp_scope::is_python_path(file.as_str().unwrap()));
            serde_json::to_writer(out, &marker)?;
            Ok(())
        },
    )?;
    rewrite_upgrade_sidecar(&layout.root().join("lsp-owed-files.json"), |input, out| {
        let mut owed: serde_json::Map<String, serde_json::Value> = serde_json::from_reader(input)?;
        owed.retain(|file, _| !kin_core::lsp_scope::is_python_path(file));
        serde_json::to_writer(out, &owed)?;
        Ok(())
    })
}

fn rewrite_upgrade_sidecar(
    path: &std::path::Path,
    rewrite: impl FnOnce(&mut std::io::BufReader<std::fs::File>, &mut std::fs::File) -> Result<()>,
) -> Result<()> {
    let input = match std::fs::File::open(path) {
        Ok(input) => input,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("upgrade sidecar has no parent"))?;
    let mut staged = tempfile::NamedTempFile::new_in(parent)?;
    rewrite(&mut std::io::BufReader::new(input), staged.as_file_mut())?;
    staged.as_file_mut().sync_all()?;
    staged.persist(path)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Everything the upgrade decided, before anything is written.
struct UpgradePlan {
    /// `None` when every head already held this build's derivation and the
    /// workspace needs nothing, so only the record is written.
    transaction: Option<RepositoryTransaction>,
    anchors: Vec<SemanticChangeId>,
    heads: Vec<HeadUpgrade>,
    workspace_dirty: bool,
    source_files: usize,
    generation: u64,
    python_entities: HashSet<EntityId>,
}

/// One distinct change some head names, and who names it.
struct Head {
    change: SemanticChangeId,
    refs: Vec<(RefName, RefTarget)>,
    detached_workspace: bool,
}

/// `fresh_anchors` is set when the plan's anchors will be recorded as the
/// upgrade's claim, and cleared for a re-qualification, which records none.
fn plan_upgrade(
    layout: &kin_core::KinLayout,
    authority: &ActiveRepositoryAuthority,
    author: AuthorId,
    derives: u32,
    from: Option<u32>,
    fresh_anchors: bool,
    retire_python: bool,
    progress: &dyn Fn(&str),
) -> Result<UpgradePlan> {
    let lease = authority.manager().read_authority();
    let roots = lease.roots().clone();
    let metadata = lease.metadata();

    // The one workspace this store serves. A store that holds others cannot
    // move them in the same transaction, so it is refused rather than left
    // half upgraded.
    let workspace = match metadata.workspaces.as_slice() {
        [workspace] if workspace.workspace_id == authority.workspace_id => workspace.clone(),
        workspaces => bail!(
            "kin upgrade refused: this store's authority holds {} workspace(s) and the upgrade \
             moves exactly one, this repository's own ({}). Nothing was changed",
            workspaces.len(),
            authority.workspace_id
        ),
    };
    workspace
        .validate()
        .context("this store's workspace authority is invalid")?;
    if !metadata.merge_transactions.is_empty() {
        bail!(
            "kin upgrade refused: a merge is open on this workspace. Finish it with `kin resolve \
             --continue` or abandon it, then run `kin upgrade`. Nothing was changed"
        );
    }

    // Distinct heads: every local branch, and the workspace base when the
    // workspace is detached. Two branches on one change share one checkpoint.
    let mut heads: BTreeMap<SemanticChangeId, Head> = BTreeMap::new();
    for reference in &metadata.ref_state.refs {
        if !reference.name.is_branch() || matches!(reference.target, RefTarget::Symbolic { .. }) {
            continue;
        }
        let change = lease
            .resolve_target_change_id(&reference.target)
            .with_context(|| format!("resolve branch {}", reference.name))?;
        heads
            .entry(change)
            .or_insert_with(|| Head {
                change,
                refs: Vec::new(),
                detached_workspace: false,
            })
            .refs
            .push((reference.name.clone(), reference.target.clone()));
    }
    let workspace_base = workspace
        .base_target
        .as_ref()
        .map(|target| lease.resolve_target_change_id(target))
        .transpose()
        .context("resolve the workspace base")?;
    if let (WorkspaceHead::Detached { .. }, Some(base)) = (&workspace.head, workspace_base) {
        heads
            .entry(base)
            .or_insert_with(|| Head {
                change: base,
                refs: Vec::new(),
                detached_workspace: false,
            })
            .detached_workspace = true;
    }

    // A stash restores only onto the exact base it was sealed against, and the
    // upgrade moves every head, so a stash sealed on one could never be
    // restored afterwards. Named before anything is written.
    let mut stranded = Vec::new();
    for reference in &metadata.ref_state.refs {
        let Some(name) = reference.name.as_utf8() else {
            continue;
        };
        if !name.starts_with("refs/kin/stash/") {
            continue;
        }
        let sealed = lease
            .resolve_target_change_id(&reference.target)
            .with_context(|| format!("resolve stash {name}"))?;
        let sealed_base = lease
            .snapshot()
            .changes
            .get(&sealed)
            .and_then(|change| change.parents.first().copied());
        if sealed_base.is_some_and(|base| heads.contains_key(&base)) {
            stranded.push(name.to_string());
        }
    }
    if !stranded.is_empty() {
        bail!(
            "kin upgrade refused: {} stash(es) ({}) were sealed on a head this upgrade moves, and \
             `kin stash pop` restores a stash only onto the exact base it was sealed against. \
             Restore them first with `kin stash pop`, run `kin upgrade`, then seal the work again \
             with `kin stash push`. Nothing was changed",
            stranded.len(),
            stranded.join(", ")
        );
    }

    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize the workspace graph")?
        .ok_or_else(|| anyhow!("repository authority has no graph for this workspace"))?;
    // An anchor vouches for every state whose first-parent line reaches it.
    // A head something already builds on cannot be its own anchor, because
    // restoring a change the older build recorded on top of it would keep the
    // claim over state that build derived, so such a head is given a
    // checkpoint even when its own state is already this build's derivation.
    let built_on: HashSet<SemanticChangeId> = if fresh_anchors {
        lease
            .snapshot()
            .changes
            .values()
            .filter_map(|change| change.parents.first().copied())
            .collect()
    } else {
        HashSet::new()
    };
    let python_entities = workspace_graph
        .entities
        .values()
        .filter(|entity| entity.language == kin_model::LanguageId::Python)
        .map(|entity| entity.id)
        .collect();
    let mut history_snapshot = lease.snapshot().clone();
    history_snapshot.repository_authority = None;
    let generation = roots.generation;
    drop(lease);
    let history = kin_db::InMemoryGraph::from_snapshot(history_snapshot)
        .context("open this store's history")?;

    // Bodies come from the staging store when it holds them and from
    // repository authority otherwise. Each derivation copies what it reads
    // into a scratch store of its own, so the store's directories are
    // untouched until the transaction commits.
    let staged = kin_blobs::BlobStore::new(layout.ingest_cas_dir()).ok();
    let mut source_files = 0usize;

    // Every head is derived before any is decided, because whether a head
    // needs a checkpoint can depend on what the rest of the upgrade changes.
    let mut derivations = Vec::with_capacity(heads.len());
    let total = heads.len();
    for (index, head) in heads.values().enumerate() {
        let names = head_names(head);
        progress(&format!(
            "kin upgrade: re-deriving {names} ({} of {total})",
            index + 1
        ));
        let state = history
            .resolve_graph_at(&head.change)
            .with_context(|| format!("resolve the state {names} serves at {}", head.change))?;
        let derived = with_heartbeat(&names, progress, || {
            let mut load = body_loader(staged.as_ref(), authority);
            derive(
                &state.tree,
                &state.entities,
                &state.relations,
                &state.external_references,
                retire_python,
                &mut load,
            )
        })
        .with_context(|| format!("re-derive the state {names} serves"))?;
        source_files += derived.source_files;
        derivations.push(HeadDerivation {
            head,
            entity_deltas: entity_transition(&state.entities, &derived.entities),
            relation_deltas: relation_transition(&state.relations, &derived.relations),
            derived,
        });
    }

    // Whatever the workspace holds beyond its base is re-derived under the
    // same build, so its overlay stays the exact difference between the two.
    let base_state = workspace_base
        .map(|base| {
            derivations
                .iter()
                .find(|derivation| derivation.head.change == base)
                .map(|derivation| &derivation.derived)
                .ok_or_else(|| {
                    anyhow!("the workspace base {base} is not a head this upgrade derived")
                })
        })
        .transpose()?;
    let base_tree_matches = base_state.is_some_and(|state| state.tree == workspace.tree);
    let workspace_dirty = workspace.holds_uncommitted_work();
    let desired = match base_state {
        Some(state) if base_tree_matches && workspace.semantic_overlay.is_empty() => state.clone(),
        _ => {
            progress("kin upgrade: re-deriving the workspace's uncommitted work");
            let derived = with_heartbeat("the workspace", progress, || {
                let mut load = body_loader(staged.as_ref(), authority);
                derive(
                    &workspace.tree,
                    &workspace_graph.entities,
                    &workspace_graph.relations,
                    &workspace_graph.external_references,
                    retire_python,
                    &mut load,
                )
            })
            .context("re-derive the workspace's uncommitted work")?;
            source_files += derived.source_files;
            derived
        }
    };
    let semantic_delta = kin_core::diff_workspace_semantics(
        &workspace_graph.entities,
        &workspace_graph.relations,
        &desired.entities,
        &desired.relations,
    )
    .context("plan the workspace's semantic transition")?;
    let overlay_changes =
        !semantic_delta.entity_deltas().is_empty() || !semantic_delta.relation_deltas().is_empty();

    // A head whose state is already this build's derivation is its own
    // anchor, unless something already builds on it (see `built_on`). One
    // more case takes a change with no delta. A workspace whose graph carries
    // no checked binding history has its lineage started by this upgrade's
    // commit, which the re-derivation verifier qualifies, and a repository
    // commit has to change something: a no-op mutation is refused. So when no
    // head and nothing in the workspace changes, as on a store whose lineage
    // an unchecked commit ended, or one whose heads a replica already brought
    // current, the workspace's own head is given that change.
    let unproven = workspace_graph.verified_binding_history.is_none();
    let mut reasons: Vec<Option<CheckpointReason>> = derivations
        .iter()
        .map(|derivation| {
            if !derivation.entity_deltas.is_empty() || !derivation.relation_deltas.is_empty() {
                Some(CheckpointReason::Rederived)
            } else if built_on.contains(&derivation.head.change) {
                Some(CheckpointReason::BuiltOn)
            } else {
                None
            }
        })
        .collect();
    if unproven && !overlay_changes && reasons.iter().all(Option::is_none) {
        if let Some(index) = workspace_base.and_then(|base| {
            derivations
                .iter()
                .position(|derivation| derivation.head.change == base)
        }) {
            reasons[index] = Some(CheckpointReason::LineageStart);
        }
    }

    let mut changes = Vec::new();
    let mut anchors = Vec::new();
    let mut reports = Vec::new();
    let mut ref_mutations = Vec::new();
    let mut anchor_of: HashMap<SemanticChangeId, SemanticChangeId> = HashMap::new();
    let timestamp = Timestamp::now();
    for (derivation, reason) in derivations.iter().zip(&reasons) {
        let head = derivation.head;
        let anchor = match reason {
            None => head.change,
            Some(reason) => {
                let mut change = SemanticChange {
                    id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
                    origin: ChangeOrigin::Native,
                    parents: vec![head.change],
                    timestamp: timestamp.clone(),
                    author: author.clone(),
                    message: checkpoint_message(from, derives, *reason),
                    entity_deltas: derivation.entity_deltas.clone(),
                    relation_deltas: derivation.relation_deltas.clone(),
                    tree_deltas: Vec::new(),
                    admission_policy_delta: None,
                    projected_files: Vec::new(),
                    spec_link: None,
                    evidence: Vec::new(),
                    risk_summary: None,
                    external_reference_deltas: Vec::new(),
                    resolution_record_deltas: Vec::new(),
                };
                change.id = compute_semantic_change_id(&change)
                    .context("identify the checkpoint change")?;
                let id = change.id;
                changes.push(change);
                for (name, target) in &head.refs {
                    ref_mutations.push(RefMutation {
                        name: name.clone(),
                        expected: RefExpectation::MustEqual {
                            target: target.clone(),
                        },
                        new_target: Some(RefTarget::change(id)),
                        policy: RefUpdatePolicy::FastForwardOnly,
                    });
                }
                id
            }
        };
        anchors.push(anchor);
        reports.push(HeadUpgrade {
            refs: names_of(head),
            previous: head.change.to_string(),
            anchor: anchor.to_string(),
            checkpoint: reason.is_some(),
            entity_deltas: derivation.entity_deltas.len(),
            relation_deltas: derivation.relation_deltas.len(),
            carried_relations: derivation.derived.carried,
        });
        anchor_of.insert(head.change, anchor);
    }

    // The workspace follows its base onto that head's anchor. It is mutated
    // only when that moves it or its overlay changes; a lineage needs no
    // workspace mutation, only a commit whose successor holds the workspace.
    let new_base = workspace_base
        .map(|base| {
            anchor_of.get(&base).copied().ok_or_else(|| {
                anyhow!("the workspace base {base} is not a head this upgrade derived")
            })
        })
        .transpose()?;
    let base_moves = new_base != workspace_base;
    let workspace_mutation = (base_moves || overlay_changes)
        .then(|| -> Result<WorkspaceMutation> {
            Ok(WorkspaceMutation {
                workspace_id: workspace.workspace_id,
                expected: expect_exact(&workspace),
                new_generation: workspace
                    .generation
                    .checked_add(1)
                    .ok_or_else(|| anyhow!("workspace generation exhausted"))?,
                new_head: match (&workspace.head, new_base) {
                    (WorkspaceHead::Detached { .. }, Some(anchor)) => WorkspaceHead::Detached {
                        target: RefTarget::change(anchor),
                    },
                    (head, _) => head.clone(),
                },
                new_base_target: match (base_moves, new_base) {
                    (true, Some(anchor)) => Some(RefTarget::change(anchor)),
                    _ => workspace.base_target.clone(),
                },
                new_base_tree_hash: workspace.base_tree_hash,
                tree_deltas: Vec::new(),
                new_tree_hash: workspace.tree_hash,
                semantic_delta,
                new_shared_admission_policy: workspace.shared_admission_policy.clone(),
                new_admission_policy: workspace.admission_policy,
            })
        })
        .transpose()?;

    let transaction =
        (!changes.is_empty() || workspace_mutation.is_some()).then(|| RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::new(),
            repository_id: authority.repository_id.clone(),
            expected_generation: roots.generation,
            expected_roots: roots.clone(),
            actor: author.clone(),
            reason: format!(
                "re-derive the served state under hydration semantics version {derives}"
            ),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes,
            aliases: Vec::new(),
            ref_mutations,
            default_ref_mutation: None,
            workspace_mutation,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
            collaboration_delta: None,
        });
    if let Some(transaction) = &transaction {
        transaction
            .validate()
            .context("validate the upgrade's repository transaction")?;
    }
    Ok(UpgradePlan {
        transaction,
        anchors,
        heads: reports,
        workspace_dirty,
        source_files,
        generation,
        python_entities,
    })
}

/// One head, the state this build derives for it, and how that differs from
/// what the head served.
struct HeadDerivation<'a> {
    head: &'a Head,
    derived: DerivedState,
    entity_deltas: Vec<kin_model::EntityDelta>,
    relation_deltas: Vec<kin_model::RelationDelta>,
}

/// Why a head is given a checkpoint change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckpointReason {
    /// This build derives different state from the head's tree than the head
    /// served.
    Rederived,
    /// The head already served this build's derivation, and a change an
    /// earlier build recorded builds on it, so it cannot be its own anchor.
    BuiltOn,
    /// The head already served this build's derivation and nothing else in
    /// the upgrade changes, but the workspace carries no checked binding
    /// history, and a lineage starts only at a commit that changes something.
    LineageStart,
}

/// The state one tree derives under this build, with what was carried.
#[derive(Clone)]
struct DerivedState {
    tree: ResolvedTree,
    entities: HashMap<EntityId, Entity>,
    relations: HashMap<RelationId, Relation>,
    carried: usize,
    source_files: usize,
}

/// Re-derive `tree` under this build, carrying identities from `held_entities`
/// and every relation no derivation authors whose endpoints survive.
fn derive(
    tree: &ResolvedTree,
    held_entities: &HashMap<EntityId, Entity>,
    held_relations: &HashMap<RelationId, Relation>,
    external_references: &HashMap<kin_model::ExternalReferenceId, kin_model::ExternalReference>,
    retire_python: bool,
    bodies: &mut dyn FnMut(Hash256) -> std::result::Result<Option<Vec<u8>>, String>,
) -> Result<DerivedState> {
    let derived = kin_index::rederive_tree_semantics_from(tree, held_entities.values(), bodies)
        .map_err(|error| anyhow!("{error}"))?;
    let source_files = derived.source_files;
    let entities: HashMap<EntityId, Entity> = derived.entities.into_iter().collect();
    let mut relations: HashMap<RelationId, Relation> = derived.relations.into_iter().collect();
    let present = |node: &GraphNodeId| match node {
        GraphNodeId::Entity(id) => entities.contains_key(id),
        GraphNodeId::Artifact(id) => tree.get(id).is_some(),
        GraphNodeId::ExternalReference(id) => external_references.contains_key(id),
        // Tests, contracts, work items and verification runs live in domains
        // the upgrade does not touch, so an edge to one survives with them.
        GraphNodeId::Test(_)
        | GraphNodeId::Contract(_)
        | GraphNodeId::Work(_)
        | GraphNodeId::VerificationRun(_) => true,
    };
    let mut carried = 0usize;
    for (id, relation) in held_relations {
        if retire_python
            && kin_core::lsp_scope::is_python_relation(relation, |id| {
                held_entities.get(id).map(|entity| entity.language)
            })
        {
            continue;
        }
        if kin_index::binding_history::relation_is_derived(relation) || relations.contains_key(id) {
            continue;
        }
        if present(&relation.src) && present(&relation.dst) {
            relations.insert(*id, relation.clone());
            carried += 1;
        }
    }
    Ok(DerivedState {
        tree: tree.clone(),
        entities,
        relations,
        carried,
        source_files,
    })
}

/// Read a body by its content address from the staging store, or from
/// repository authority when staging does not hold it.
fn body_loader<'a>(
    staged: Option<&'a kin_blobs::BlobStore>,
    authority: &'a ActiveRepositoryAuthority,
) -> impl FnMut(Hash256) -> std::result::Result<Option<Vec<u8>>, String> + 'a {
    move |hash| {
        if let Some(body) = staged.and_then(|store| store.read(&hash).ok()) {
            return Ok(Some(body));
        }
        authority
            .manager()
            .load_source_blob(hash)
            .map_err(|error| error.to_string())
    }
}

/// Run `work`, saying every few seconds that it is still running.
fn with_heartbeat<T>(what: &str, progress: &dyn Fn(&str), work: impl FnOnce() -> T + Send) -> T
where
    T: Send,
{
    let started = Instant::now();
    let (done, finished) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let handle = scope.spawn(move || {
            let result = work();
            // Wakes the wait below the moment the work ends, rather than at the
            // next interval.
            let _ = done.send(());
            result
        });
        loop {
            match finished.recv_timeout(PROGRESS_INTERVAL) {
                Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => progress(&format!(
                    "kin upgrade: still re-deriving {what} ({}s)",
                    started.elapsed().as_secs()
                )),
            }
        }
        handle.join().expect("the derivation thread panicked")
    })
}

fn head_names(head: &Head) -> String {
    names_of(head).join(", ")
}

fn names_of(head: &Head) -> Vec<String> {
    let mut names: Vec<String> = head
        .refs
        .iter()
        .map(|(name, _)| {
            name.as_utf8()
                .map(str::to_string)
                .unwrap_or_else(|| format!("{name:?}"))
        })
        .collect();
    if head.detached_workspace {
        names.push("HEAD".to_string());
    }
    names
}

fn checkpoint_message(from: Option<u32>, to: u32, reason: CheckpointReason) -> String {
    let title = match from {
        Some(from) if from != to => {
            format!("Re-derive semantics under hydration semantics version {to} (was {from})")
        }
        _ => format!("Re-derive semantics under hydration semantics version {to}"),
    };
    let body = match reason {
        CheckpointReason::Rederived => match from {
            Some(from) if from != to => format!(
                "kin upgrade recorded this change. It carries no file change: it moves the entity \
                 and relation state this head serves from what replay version {from} derived to \
                 what version {to} derives from the same tree."
            ),
            Some(_) => format!(
                "kin upgrade recorded this change. It carries no file change: it moves the entity \
                 and relation state this head serves to what replay version {to} derives from the \
                 same tree."
            ),
            None => format!(
                "kin upgrade recorded this change. It carries no file change: it moves the entity \
                 and relation state this head serves to what replay version {to} derives from the \
                 same tree. The store recorded no version before it."
            ),
        },
        CheckpointReason::BuiltOn => format!(
            "kin upgrade recorded this change. It carries no file, entity or relation change: \
             this head already served what replay version {to} derives from its tree, and later \
             changes an earlier build recorded build on it, so this change marks where the \
             upgraded state begins."
        ),
        CheckpointReason::LineageStart => format!(
            "kin upgrade recorded this change. It carries no file, entity or relation change: \
             this head already served what replay version {to} derives from its tree and nothing \
             else needed to change, but the workspace carried no checked binding history, and a \
             checked lineage can start only at a recorded change, so it starts here."
        ),
    };
    format!("{title}\n\n{body}")
}

fn expect_exact(workspace: &WorkspaceState) -> WorkspaceExpectation {
    WorkspaceExpectation::MustEqual {
        generation: workspace.generation,
        head: workspace.head.clone(),
        base_target: workspace.base_target.clone(),
        base_tree_hash: workspace.base_tree_hash,
        tree_hash: workspace.tree_hash,
        semantic_overlay_hash: workspace.semantic_overlay_hash,
        admission_policy: workspace.admission_policy,
    }
}

fn entity_transition(
    previous: &HashMap<EntityId, Entity>,
    target: &HashMap<EntityId, Entity>,
) -> Vec<kin_model::EntityDelta> {
    let mut deltas = Vec::new();
    for (id, entity) in target {
        match previous.get(id) {
            None => deltas.push(kin_model::EntityDelta::Added {
                new: entity.clone(),
            }),
            Some(old) if old != entity => deltas.push(kin_model::EntityDelta::Modified {
                old: old.clone(),
                new: entity.clone(),
            }),
            _ => {}
        }
    }
    for (id, entity) in previous {
        if !target.contains_key(id) {
            deltas.push(kin_model::EntityDelta::Removed {
                old: entity.clone(),
            });
        }
    }
    deltas.sort_by_key(kin_model::EntityDelta::target_id);
    deltas
}

fn relation_transition(
    previous: &HashMap<RelationId, Relation>,
    target: &HashMap<RelationId, Relation>,
) -> Vec<kin_model::RelationDelta> {
    let mut deltas = Vec::new();
    for (id, relation) in target {
        match previous.get(id) {
            None => deltas.push(kin_model::RelationDelta::Added {
                new: relation.clone(),
            }),
            Some(old) if old != relation => deltas.push(kin_model::RelationDelta::Modified {
                old: old.clone(),
                new: relation.clone(),
            }),
            _ => {}
        }
    }
    for (id, relation) in previous {
        if !target.contains_key(id) {
            deltas.push(kin_model::RelationDelta::Removed {
                old: relation.clone(),
            });
        }
    }
    deltas.sort_by_key(kin_model::RelationDelta::target_id);
    deltas
}

/// Make the upgraded workspace graph the relation census baseline.
fn rebaseline_relation_census(
    layout: &kin_core::KinLayout,
    snapshot: kin_db::GraphSnapshot,
) -> Result<()> {
    let graph = kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot)?;
    let (kinds, entities) = super::graph::measure_relation_census_with_entities(&graph)?;
    let census = kin_core::relation_census::RelationCensus::new(
        chrono::Utc::now(),
        kin_core::relation_census::CensusSource::Commit,
        kinds,
        kin_core::relation_census::known_causes(std::env::vars()),
    )
    .with_entities(entities);
    kin_core::relation_census::rebaseline(layout, &census)?;
    Ok(())
}
