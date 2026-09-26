//! `kin graph owed`: the owed derivation ledger repository authority holds.
//!
//! A read of persisted authority and nothing else. It binds the local store
//! from its layout and reads the authority envelope and its acknowledged
//! journal without writing, and when that cheap read cannot answer, it
//! validates the store in full, still without writing. Either way the ledger
//! it prints has passed the checks every open runs. An open also records its
//! history validation and cleans up after interrupted writes; this command
//! does neither, so every file in the store is as it found it. It contacts no
//! daemon and starts none, admits nothing, reads nothing from the working
//! copy, and migrates nothing: a record an earlier build kept beside the store
//! is not in the ledger until a daemon of this build carries it into
//! authority.
//!
//! It reads under the repository authority lock, which a daemon also takes
//! while it commits. [`AUTHORITY_LOCK_WAIT`] is one budget for the whole
//! command: while another process holds the lock it retries, holding nothing,
//! and once the budget is spent it refuses rather than waiting on. How long it
//! then holds the lock depends on the path. The envelope read holds it only
//! while it reads the snapshot and the journal and checks them against the
//! authority record, and releases it before decoding. The full validation,
//! taken only when that read cannot answer, holds it from the start of the
//! recovery through the history replay, storage admission and every persisted
//! body check until the report is built, so on a large store a daemon's commit
//! can wait for all of that. The validation is not shortened to shorten the
//! hold.
//!
//! An empty ledger is reported as exactly that, never as "nothing owed". Work
//! an earlier build recorded outside authority, or enrichment that is still
//! incomplete, is not something an empty ledger rules out.
//!
//! Beside the ledger it reports owed enrichment: every file of this store's
//! workspace graph holding a caller no current call-site ledger describes,
//! with how many, read through the one site-state reading every Kin surface
//! shares. The graph is derived state, so this half validates authority in
//! full, still read-only and within the same lock budget, and materializes the
//! workspace graph from it after releasing the lock.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::Serialize;

/// The wire schema of `kin graph owed --json`.
pub const OWED_DERIVATIONS_SCHEMA: &str = "kin.graph.owed-derivations.v1";

/// How long the command waits in total for a repository authority lock another
/// process holds. A daemon holds it while it commits, normally for a moment.
/// The envelope read and, when it cannot answer, the full validation share
/// this one budget, each waiting only for what remains of it; once it is spent
/// the command refuses instead of waiting on.
pub const AUTHORITY_LOCK_WAIT: Duration = Duration::from_secs(10);

/// What a workspace with no records reads, in place of any claim that nothing
/// is owed.
pub const NO_OWED_DERIVATION_RECORDS: &str = "no owed derivation records in repository authority";

/// The owed derivation ledger of one repository, as persisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwedDerivationsReport {
    pub schema: &'static str,
    pub repository_id: String,
    /// The logical repository generation the ledger was read at.
    pub generation: u64,
    /// Every workspace authority holds, in authority's order.
    pub workspaces: Vec<WorkspaceOwedDerivations>,
    /// The callers this store's workspace graph holds with no current
    /// call-site ledger, by file. Absent only from a report built without
    /// reading the graph.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owed_enrichment: Option<OwedEnrichmentReport>,
}

/// The callers whose enrichment is owed, read from one workspace's graph.
///
/// A caller is an entity with source text, and its enrichment is owed while no
/// current call-site ledger describes it: its sites are then not accounted
/// for, whatever the owed derivation ledger above holds. Each is read through
/// the one site-state reading every Kin surface shares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwedEnrichmentReport {
    /// The workspace whose graph was read.
    pub workspace_id: String,
    /// Entities with source text the graph holds.
    pub callers: u64,
    /// Of those, the ones no current ledger describes.
    pub callers_owed: u64,
    /// Every file holding such a caller, in path order, with how many.
    pub files: Vec<kin_mcp::call_sites::OwedFile>,
    /// Why the graph could not be read, when it could not. The derivation
    /// ledger above is reported either way.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<String>,
}

impl OwedEnrichmentReport {
    /// The report for a graph already in hand.
    pub fn from_graph<G: kin_model::GraphStore>(workspace_id: String, graph: &G) -> Result<Self> {
        let entities = graph
            .list_all_entities()
            .map_err(|error| anyhow!("list the workspace graph's entities: {error}"))?;
        let files = kin_mcp::call_sites::owed_files(graph, &entities);
        Ok(Self {
            workspace_id,
            callers: entities
                .iter()
                .filter(|entity| entity.span.is_some())
                .count() as u64,
            callers_owed: files.iter().map(|file| file.callers).sum(),
            files,
            unavailable: None,
        })
    }

    /// The report for a graph that could not be read, saying why.
    fn unavailable(workspace_id: String, reason: String) -> Self {
        Self {
            workspace_id,
            callers: 0,
            callers_owed: 0,
            files: Vec::new(),
            unavailable: Some(reason),
        }
    }

    /// The human rendering: one line for the workspace, then one per file.
    /// A graph that could not be read says so, and never reads as owing
    /// nothing.
    pub fn human_lines(&self) -> Vec<String> {
        if let Some(reason) = &self.unavailable {
            return vec![format!(
                "owed enrichment in workspace {}: not read, because {reason}",
                self.workspace_id
            )];
        }
        if self.callers_owed == 0 {
            return vec![format!(
                "owed enrichment in workspace {}: every one of the {} callers with source text \
                 holds a current call-site ledger or sits in a file with no call",
                self.workspace_id, self.callers
            )];
        }
        let mut lines = vec![format!(
            "owed enrichment in workspace {}: {} of the {} callers with source text hold no \
             current call-site ledger, in {} file(s)",
            self.workspace_id,
            self.callers_owed,
            self.callers,
            self.files.len()
        )];
        lines.extend(
            self.files
                .iter()
                .map(|file| format!("  {}: {} caller(s)", file.file, file.callers)),
        );
        lines
    }
}

/// Read the callers this store's own workspace graph holds with no current
/// call-site ledger.
///
/// The graph is derived state, so it is materialized from repository
/// authority validated in full and read-only, under the lock, the way the
/// derivation ledger's fallback read is. The lock is released before the
/// graph is read. Anything that stops the read is reported in the report's
/// `unavailable` rather than failing the command, because the derivation
/// ledger beside it was read on its own.
pub fn read_owed_enrichment(layout: &kin_core::KinLayout, wait: Duration) -> OwedEnrichmentReport {
    let binding = match kin_core::LocalRepositoryAuthorityBinding::from_layout(layout) {
        Ok(binding) => binding,
        Err(error) => {
            return OwedEnrichmentReport::unavailable(
                String::new(),
                format!("this store's repository authority could not be bound: {error:#}"),
            )
        }
    };
    let workspace_id = binding.workspace_id();
    let snapshot = binding
        .freeze_existing_read_only(wait)
        .map_err(|error| format!("repository authority could not be validated read-only: {error}"))
        .and_then(|freeze| {
            freeze
                .authority()
                .workspace_graph_snapshot(&workspace_id)
                .map_err(|error| format!("the workspace graph could not be read: {error}"))
        });
    let workspace = workspace_id.to_string();
    let snapshot = match snapshot {
        Ok(Some(snapshot)) => snapshot,
        Ok(None) => {
            return OwedEnrichmentReport::unavailable(
                workspace,
                "repository authority holds no such workspace".to_string(),
            )
        }
        Err(reason) => return OwedEnrichmentReport::unavailable(workspace, reason),
    };
    match kin_db::InMemoryGraph::from_snapshot_without_text_index(snapshot)
        .map_err(|error| anyhow!("materialize the workspace graph: {error}"))
        .and_then(|graph| OwedEnrichmentReport::from_graph(workspace.clone(), &graph))
    {
        Ok(report) => report,
        Err(error) => OwedEnrichmentReport::unavailable(workspace, format!("{error:#}")),
    }
}

/// One workspace's records and the payment it last recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceOwedDerivations {
    pub workspace_id: String,
    pub records: Vec<OwedDerivationRecord>,
    /// Shown whenever authority records one, whether or not records remain.
    pub payment: Option<DerivationPaymentRecord>,
}

/// One path whose exact body is owed a parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OwedDerivationRecord {
    /// The path in its UTF-8 rendering, or null when it has none.
    pub path: Option<String>,
    /// The exact path bytes, hex encoded.
    pub path_hex: String,
    /// Hex of the body the parse is owed for.
    pub body: String,
    /// The logical generation that recorded it.
    pub recorded_at: u64,
    /// `publication`, or `legacy` for a record carried in from an earlier
    /// build's file.
    pub cause: &'static str,
}

/// The re-derivation that last paid a workspace's records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DerivationPaymentRecord {
    /// The logical generation the paying commit was taken against.
    pub paid_through: u64,
    pub operation_id: String,
    pub hydration_version: u32,
}

/// Read the owed derivation ledger of the store at `layout`.
pub fn read_owed_derivations(layout: &kin_core::KinLayout) -> Result<OwedDerivationsReport> {
    // One lock budget for the whole read, computed once: each acquisition
    // below waits only for what remains of it.
    let deadline = Instant::now() + AUTHORITY_LOCK_WAIT;
    let remaining = || deadline.saturating_duration_since(Instant::now());
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)
        .context("bind this store's local repository authority")?;
    let repository_id = binding.repository_id().to_string();
    if let Some(envelope) = binding
        .read_authority_metadata_read_only(remaining())
        .context("read the repository authority envelope")?
    {
        return Ok(report(
            repository_id,
            envelope.generation(),
            envelope.metadata(),
        ));
    }
    // The cheap read cannot answer this store, so it is validated in full:
    // the recovery, history replay and body checks a full open runs, without
    // the history-validation record an open writes. The lock is held through
    // all of it and released when the freeze drops, after the report is built.
    let freeze = binding
        .freeze_existing_read_only(remaining())
        .context("validate repository authority read-only")?;
    let authority = freeze.authority();
    Ok(report(
        repository_id,
        freeze.roots().generation,
        authority.metadata(),
    ))
}

fn report(
    repository_id: String,
    generation: u64,
    authority: &kin_db::PersistedRepositoryAuthority,
) -> OwedDerivationsReport {
    let ledger = &authority.owed_derivations;
    OwedDerivationsReport {
        schema: OWED_DERIVATIONS_SCHEMA,
        repository_id,
        generation,
        workspaces: authority
            .workspaces
            .iter()
            .map(|workspace| WorkspaceOwedDerivations {
                workspace_id: workspace.workspace_id.to_string(),
                records: ledger
                    .records_for(workspace.workspace_id)
                    .map(|owed| OwedDerivationRecord {
                        path: owed.path().as_utf8().map(str::to_string),
                        path_hex: hex::encode(owed.path().as_bytes()),
                        body: owed.body().to_string(),
                        recorded_at: owed.recorded_at(),
                        cause: match owed.cause() {
                            kin_db::OwedDerivationCause::Publication => "publication",
                            kin_db::OwedDerivationCause::Legacy => "legacy",
                        },
                    })
                    .collect(),
                payment: ledger.payment_for(workspace.workspace_id).map(|payment| {
                    DerivationPaymentRecord {
                        paid_through: payment.paid_through(),
                        operation_id: payment.operation_id().to_string(),
                        hydration_version: payment.hydration_version(),
                    }
                }),
            })
            .collect(),
        owed_enrichment: None,
    }
}

impl OwedDerivationsReport {
    /// The human rendering: one header, then each workspace with its records
    /// or the empty-ledger sentence, and its payment whenever one is recorded.
    pub fn human_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Owed derivation ledger of repository {} at generation {}",
            self.repository_id, self.generation
        )];
        for workspace in &self.workspaces {
            if workspace.records.is_empty() {
                lines.push(format!(
                    "workspace {}: {NO_OWED_DERIVATION_RECORDS}",
                    workspace.workspace_id
                ));
            } else {
                lines.push(format!(
                    "workspace {}: {} owed derivation record(s)",
                    workspace.workspace_id,
                    workspace.records.len()
                ));
            }
            for record in &workspace.records {
                let path = record
                    .path
                    .clone()
                    .unwrap_or_else(|| format!("<non-UTF-8 path, bytes {}>", record.path_hex));
                lines.push(format!(
                    "  {path}: parse owed for body {}, recorded at generation {} ({})",
                    record.body, record.recorded_at, record.cause
                ));
            }
            if let Some(payment) = &workspace.payment {
                lines.push(format!(
                    "  last paid through generation {} by operation {} under hydration semantics \
                     version {}",
                    payment.paid_through, payment.operation_id, payment.hydration_version
                ));
            }
        }
        if let Some(enrichment) = &self.owed_enrichment {
            lines.extend(enrichment.human_lines());
        }
        lines
    }
}

/// `kin graph owed [--json]`.
pub async fn owed(json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let started = Instant::now();
    let mut report = read_owed_derivations(&layout).map_err(|error| {
        anyhow!(
            "kin graph owed: could not read the owed derivation ledger from repository \
             authority: {error:#}"
        )
    })?;
    // What remains of the one lock budget, so the command as a whole waits no
    // longer than it says it does.
    report.owed_enrichment = Some(read_owed_enrichment(
        &layout,
        AUTHORITY_LOCK_WAIT.saturating_sub(started.elapsed()),
    ));
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    for line in report.human_lines() {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(path: Option<&str>, path_hex: &str) -> OwedDerivationRecord {
        OwedDerivationRecord {
            path: path.map(str::to_string),
            path_hex: path_hex.to_string(),
            body: "ab".repeat(32),
            recorded_at: 7,
            cause: "publication",
        }
    }

    fn report(workspaces: Vec<WorkspaceOwedDerivations>) -> OwedDerivationsReport {
        OwedDerivationsReport {
            schema: OWED_DERIVATIONS_SCHEMA,
            repository_id: "repository".to_string(),
            generation: 9,
            workspaces,
            owed_enrichment: None,
        }
    }

    #[test]
    fn an_empty_workspace_reads_as_no_records_and_still_shows_its_payment() {
        let lines = report(vec![WorkspaceOwedDerivations {
            workspace_id: "w".to_string(),
            records: Vec::new(),
            payment: Some(DerivationPaymentRecord {
                paid_through: 8,
                operation_id: "op".to_string(),
                hydration_version: 30,
            }),
        }])
        .human_lines();
        assert_eq!(
            lines[1],
            format!("workspace w: {NO_OWED_DERIVATION_RECORDS}")
        );
        assert!(lines[2].contains("last paid through generation 8 by operation op"));
        assert!(
            lines.iter().all(|line| !line.contains("nothing owed")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_path_with_no_utf8_rendering_is_named_by_its_bytes() {
        let lines = report(vec![WorkspaceOwedDerivations {
            workspace_id: "w".to_string(),
            records: vec![record(None, "ff2e7079")],
            payment: None,
        }])
        .human_lines();
        assert!(
            lines[2].contains("<non-UTF-8 path, bytes ff2e7079>"),
            "{lines:?}"
        );
        let value = serde_json::to_value(record(None, "ff2e7079")).unwrap();
        assert!(value["path"].is_null());
        assert_eq!(value["path_hex"], "ff2e7079");
    }

    /// Owed enrichment names each file holding a caller no current call-site
    /// ledger describes, with how many, read from the graph through the one
    /// site-state reading; a caller whose ledger is current is not listed.
    #[test]
    fn owed_enrichment_names_each_file_holding_callers_with_no_ledger() {
        use crate::commands::call_site_fixture::{admit, spanned};
        let graph = kin_db::InMemoryGraph::new();
        let done_body = "def done():\n    go()\n";
        let done = spanned("done", "app.py", 0, done_body);
        let first = spanned("first", "lib/tools.py", 0, "def first():\n    a()\n");
        let second = spanned("second", "lib/tools.py", 40, "def second():\n    b()\n");
        let third = spanned("third", "pkg/io.py", 0, "def third():\n    c()\n");
        admit(
            &graph,
            &[&done, &first, &second, &third],
            vec![(
                &done,
                done_body,
                vec![("go", kin_model::CallSiteState::ProvenOutside)],
            )],
        );
        let report = OwedEnrichmentReport::from_graph("w".to_string(), &graph).unwrap();
        assert_eq!(report.callers, 4);
        assert_eq!(report.callers_owed, 3);
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            value["files"],
            serde_json::json!([
                {"file": "lib/tools.py", "callers": 2},
                {"file": "pkg/io.py", "callers": 1},
            ]),
            "{value}"
        );
        let lines = report.human_lines();
        assert_eq!(
            lines[0],
            "owed enrichment in workspace w: 3 of the 4 callers with source text hold no \
             current call-site ledger, in 2 file(s)"
        );
        assert!(
            lines.contains(&"  lib/tools.py: 2 caller(s)".to_string()),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"  pkg/io.py: 1 caller(s)".to_string()),
            "{lines:?}"
        );
    }
}
