// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Process-local handshake observations. These never validate a graph ledger.
//!
//! A language's probes and real worker starts share one ordered slot. Waiting
//! callers reuse the completed attempt, including a failure; a later request
//! retries a failure. Only an identified, unchanged successful launch can be
//! reused across attempts. Dropping an in-flight attempt leaves it unknown.

use std::collections::HashMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use kin_core::reference_coverage::{LanguageServerReadiness, LanguageServerReadinessMap};
use kin_lsp::adapters::ServerLaunch;
use kin_model::{LanguageId, ProofContext};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// The exact invocation, including settings, environment and fallback order.
/// Kept only in memory, never logged or serialized: inherited values may be
/// private. The content identity uses the same resolver rule as ProofContext.
#[derive(Clone, PartialEq)]
pub(super) struct LaunchKey {
    workspace: PathBuf,
    program: PathBuf,
    identity: Option<String>,
    args: Vec<String>,
    launch: ServerLaunch,
    inherited: Vec<(OsString, OsString)>,
    current_dir: Option<PathBuf>,
    permissions: Option<u32>,
    interpreters: Option<Vec<ExecutableInput>>,
}

/// Script identity alone does not identify the process needed to run it. This
/// is readiness-only launch evidence, separate from persisted proof contexts.
#[derive(Clone, PartialEq)]
struct ExecutableInput {
    path: PathBuf,
    identity: String,
    permissions: u32,
}

fn executable_permissions(program: &Path) -> Option<u32> {
    let permissions = std::fs::metadata(program).ok()?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        Some(permissions.mode())
    }
    #[cfg(not(unix))]
    Some(u32::from(permissions.readonly()))
}

fn executable_head(program: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut head = [0u8; 256];
    let size = std::fs::File::open(program).ok()?.read(&mut head).ok()?;
    Some(head[..size].to_vec())
}

fn native_input(program: &Path) -> Option<ExecutableInput> {
    let path = std::fs::canonicalize(program).ok()?;
    // An interpreter that is itself an opaque shim needs a fresh handshake.
    if !std::fs::metadata(&path).ok()?.is_file() || executable_head(&path)?.starts_with(b"#!") {
        return None;
    }
    let permissions = executable_permissions(&path)?;
    #[cfg(unix)]
    if permissions & 0o111 == 0 {
        return None;
    }
    Some(ExecutableInput {
        identity: kin_lsp::proof_context::resolver_content_identity(&path)?,
        path,
        permissions,
    })
}

/// Attest the common Node entry forms exactly. More complex interpreter or
/// env-option semantics remain probeable, but cannot reuse a prior launch.
fn interpreter_inputs(
    program: &Path,
    launch: &ServerLaunch,
    inherited: &[(OsString, OsString)],
    current_dir: Option<&Path>,
) -> Option<Vec<ExecutableInput>> {
    let head = executable_head(program)?;
    if !head.starts_with(b"#!") {
        return Some(Vec::new());
    }
    let end = head
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(head.len());
    if end == 256 {
        return None;
    }
    let line = std::str::from_utf8(&head[2..end]).ok()?;
    let words: Vec<_> = line.split_ascii_whitespace().collect();
    let interpreter = Path::new(*words.first()?);
    if !interpreter.is_absolute() {
        return None;
    }
    let mut inputs = vec![native_input(interpreter)?];
    match (interpreter.file_name()?.to_str()?, words.as_slice()) {
        ("node" | "nodejs", [_]) => Some(inputs),
        ("env", [_, command @ ("node" | "nodejs")]) => {
            let mut next = Some(launch);
            while let Some(launch) = next {
                // Command::envs overrides inherited values in order. Do not
                // consult this process's PATH after capturing the key.
                let path = launch
                    .env
                    .iter()
                    .rev()
                    .find(|(key, _)| key == "PATH")
                    .map(|(_, value)| OsString::from(value))
                    .or_else(|| {
                        inherited
                            .iter()
                            .find(|(key, _)| key == "PATH")
                            .map(|(_, value)| value.clone())
                    })?;
                let node = which::which_in(command, Some(path), current_dir?).ok()?;
                inputs.push(native_input(&node)?);
                next = launch.fallback.as_deref();
            }
            Some(inputs)
        }
        _ => None,
    }
}

impl LaunchKey {
    pub(super) fn capture(
        workspace: &Path,
        program: &Path,
        args: &[String],
        launch: &ServerLaunch,
    ) -> Self {
        let mut inherited: Vec<_> = std::env::vars_os().collect();
        inherited.sort();
        let permissions = executable_permissions(program);
        let current_dir = std::env::current_dir().ok();
        let interpreters = interpreter_inputs(program, launch, &inherited, current_dir.as_deref());
        Self {
            workspace: workspace.to_path_buf(),
            program: program.to_path_buf(),
            identity: kin_lsp::proof_context::resolver_content_identity(program),
            args: args.to_vec(),
            launch: launch.clone(),
            inherited,
            current_dir,
            permissions,
            interpreters,
        }
    }

    fn identifies(&self, context: &ProofContext) -> bool {
        if self.interpreters.is_none() {
            return false;
        }
        let Some(identity) = &self.identity else {
            return false;
        };
        let program = self.program.to_string_lossy();
        let mut next = Some(&self.launch);
        while let Some(launch) = next {
            let expected = kin_lsp::proof_context::prestart_hashes(
                launch,
                &self.workspace,
                &program,
                identity,
            );
            if expected == (context.configuration_hash, context.environment_hash) {
                return true;
            }
            next = launch.fallback.as_deref();
        }
        false
    }
}

#[derive(Default)]
struct Observation {
    key: Option<LaunchKey>,
    result: Option<LanguageServerReadiness>,
    reusable: bool,
}

#[derive(Default)]
struct Slot {
    observation: Arc<AsyncMutex<Observation>>,
    completed: AtomicU64,
}

#[derive(Default)]
pub(super) struct ReadinessObservations {
    slots: Mutex<HashMap<LanguageId, Arc<Slot>>>,
    published: Mutex<LanguageServerReadinessMap>,
}

impl ReadinessObservations {
    pub(super) async fn acquire(&self, language: LanguageId) -> Attempt<'_> {
        let slot = Arc::clone(
            self.slots
                .lock()
                .expect("readiness slots")
                .entry(language)
                .or_default(),
        );
        let before = slot.completed.load(Ordering::Acquire);
        let observation = Arc::clone(&slot.observation).lock_owned().await;
        Attempt {
            owner: self,
            language,
            slot,
            before,
            observation,
        }
    }

    fn publish(&self, language: LanguageId, result: Option<LanguageServerReadiness>) {
        let mut all = self.published.lock().expect("readiness observations");
        if let Some(result) = result {
            all.insert(language, result);
        } else {
            all.remove(&language);
        }
        // Serialize publication with the merged map. A delayed completion for
        // another language cannot overwrite a newer observation wholesale.
        kin_mcp::edge_coverage::publish_language_server_readiness(all.clone());
    }

    /// Record that language-server enrichment is switched off for this process,
    /// as a completed finding for every enrichable language.
    ///
    /// Such a process starts no probe and no sweep, so without this finding its
    /// readiness would stay unobserved for its whole life and read as pending.
    /// No launch is attempted, so nothing is reusable and nothing is spawned.
    pub(super) async fn switched_off(&self) {
        for &language in kin_core::reference_coverage::ENRICHABLE_LANGUAGES {
            let mut attempt = self.acquire(language).await;
            attempt.finish(None, LanguageServerReadiness::Disabled, None);
        }
    }

    /// The completed findings this owner has published, for a test to read.
    #[cfg(test)]
    pub(super) fn published_findings(&self) -> LanguageServerReadinessMap {
        self.published
            .lock()
            .expect("readiness observations")
            .clone()
    }

    pub(super) async fn failed(&self, language: LanguageId, reason: String) {
        let mut attempt = self.acquire(language).await;
        attempt.begin();
        attempt.finish(None, LanguageServerReadiness::Unusable { reason }, None);
    }

    pub(super) async fn probe(
        &self,
        language: LanguageId,
        workspace: &Path,
    ) -> LanguageServerReadiness {
        // Resolve after acquiring the slot: another caller may have waited
        // while the executable, adapter settings or environment changed.
        let mut attempt = self.acquire(language).await;
        let Some((command, args, launch)) = super::lsp_adapter_for(language, workspace) else {
            attempt.begin();
            return attempt.finish(None, LanguageServerReadiness::Absent, None);
        };
        let resolved =
            crate::language_server_command::resolve_on_this_host(command, workspace.to_path_buf())
                .await;
        let program = match resolved {
            crate::language_server_command::ServerCommand::Resolved { program, .. } => program,
            crate::language_server_command::ServerCommand::NotInstalled => {
                attempt.begin();
                return attempt.finish(None, LanguageServerReadiness::Absent, None);
            }
            crate::language_server_command::ServerCommand::Unresolvable { reason } => {
                attempt.begin();
                return attempt.finish(None, LanguageServerReadiness::Unusable { reason }, None);
            }
        };
        let key = LaunchKey::capture(workspace, &program, &args, &launch);
        if let Some(result) = attempt.reuse(&key) {
            return result;
        }
        attempt.begin();
        match super::probe_server(&program, &args, workspace, &launch).await {
            Ok(server) => {
                let context = server.proof_context(language);
                let result = if server.is_disconnected() {
                    LanguageServerReadiness::Unusable {
                        reason: "the language server disconnected after its handshake".into(),
                    }
                } else {
                    LanguageServerReadiness::Usable
                };
                drop(server);
                attempt.finish(Some(key), result, Some(&context))
            }
            Err(reason) => attempt.finish(
                Some(key),
                LanguageServerReadiness::Unusable { reason },
                None,
            ),
        }
    }
}

pub(super) struct Attempt<'a> {
    owner: &'a ReadinessObservations,
    language: LanguageId,
    slot: Arc<Slot>,
    before: u64,
    observation: OwnedMutexGuard<Observation>,
}

impl Attempt<'_> {
    fn reuse(&self, key: &LaunchKey) -> Option<LanguageServerReadiness> {
        if self.observation.key.as_ref() != Some(key) {
            return None;
        }
        if self.observation.reusable || self.slot.completed.load(Ordering::Acquire) > self.before {
            self.observation.result.clone()
        } else {
            None
        }
    }

    pub(super) fn begin(&mut self) {
        *self.observation = Observation::default();
        self.owner.publish(self.language, None);
    }

    pub(super) fn finish(
        &mut self,
        key: Option<LaunchKey>,
        result: LanguageServerReadiness,
        context: Option<&ProofContext>,
    ) -> LanguageServerReadiness {
        let reusable = result == LanguageServerReadiness::Usable
            && context.is_some_and(|context| {
                context.language == self.language
                    && key.as_ref().is_some_and(|key| key.identifies(context))
            });
        *self.observation = Observation {
            key,
            result: Some(result.clone()),
            reusable,
        };
        self.slot.completed.fetch_add(1, Ordering::Release);
        self.owner.publish(self.language, Some(result.clone()));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::task::Poll;

    fn key() -> LaunchKey {
        LaunchKey {
            workspace: PathBuf::from("/workspace"),
            program: PathBuf::from("/tools/server"),
            identity: Some("sha256:identified-server".into()),
            args: vec!["--stdio".into()],
            launch: ServerLaunch::default(),
            inherited: vec![("PATH".into(), "/tools".into())],
            current_dir: Some(PathBuf::from("/workspace")),
            permissions: Some(0o755),
            interpreters: Some(Vec::new()),
        }
    }

    fn context(key: &LaunchKey, launch: &ServerLaunch) -> ProofContext {
        kin_lsp::proof_context::ProofBasis::of_resolver(
            launch,
            &key.workspace,
            &key.program.to_string_lossy(),
            key.identity.as_deref(),
            Some("server"),
            Some("1.0"),
        )
        .proof_context(LanguageId::Python)
    }

    #[tokio::test]
    async fn a_settled_worker_observation_replaces_redundant_readiness_probes() {
        let owner = ReadinessObservations::default();
        let key = key();
        let context = context(&key, &key.launch);
        let mut worker = owner.acquire(LanguageId::Python).await;
        worker.begin();
        worker.finish(
            Some(key.clone()),
            LanguageServerReadiness::Usable,
            Some(&context),
        );
        drop(worker);
        let probe = owner.acquire(LanguageId::Python).await;
        assert_eq!(probe.reuse(&key), Some(LanguageServerReadiness::Usable));
        assert_eq!(probe.slot.completed.load(Ordering::Acquire), 1);
        assert_eq!(
            owner.published.lock().unwrap().get(&LanguageId::Python),
            Some(&LanguageServerReadiness::Usable)
        );
    }

    #[tokio::test]
    async fn pending_and_cancelled_attempts_publish_unknown_until_a_completed_finding() {
        use kin_core::reference_coverage::{reference_enrichment_for, ReferenceEnrichment};
        let owner = ReadinessObservations::default();
        let mut sibling = owner.acquire(LanguageId::Go).await;
        sibling.begin();
        sibling.finish(None, LanguageServerReadiness::Usable, None);
        drop(sibling);
        for (finding, expected) in [
            (
                LanguageServerReadiness::Usable,
                ReferenceEnrichment::Available,
            ),
            (
                LanguageServerReadiness::Absent,
                ReferenceEnrichment::NoLanguageServer,
            ),
            (
                LanguageServerReadiness::Unusable {
                    reason: "initialize refused".into(),
                },
                ReferenceEnrichment::LanguageServerUnusable,
            ),
        ] {
            let mut attempt = owner.acquire(LanguageId::Python).await;
            attempt.begin();
            assert_eq!(
                reference_enrichment_for(LanguageId::Python, &owner.published.lock().unwrap()),
                ReferenceEnrichment::Unknown
            );
            attempt.finish(None, finding, None);
            assert_eq!(
                reference_enrichment_for(LanguageId::Python, &owner.published.lock().unwrap()),
                expected
            );
            drop(attempt);
            let mut cancelled = owner.acquire(LanguageId::Python).await;
            cancelled.begin();
            drop(cancelled);
            let published = owner.published.lock().unwrap();
            assert_eq!(
                reference_enrichment_for(LanguageId::Python, &published),
                ReferenceEnrichment::Unknown
            );
            assert_eq!(
                reference_enrichment_for(LanguageId::Go, &published),
                ReferenceEnrichment::Available
            );
        }
    }

    /// A process with enrichment switched off starts no probe and no sweep.
    /// Its readiness is a completed finding for every enrichable language at
    /// once, never a pending one, and it claims no missing installation.
    #[tokio::test]
    async fn a_switched_off_process_completes_every_language_as_disabled() {
        use kin_core::reference_coverage::{
            reference_enrichment_for, ReferenceEnrichment, ENRICHABLE_LANGUAGES,
        };
        let owner = ReadinessObservations::default();
        owner.switched_off().await;
        let published = owner.published_findings();
        assert_eq!(published.len(), ENRICHABLE_LANGUAGES.len());
        for language in ENRICHABLE_LANGUAGES {
            assert_eq!(
                published.get(language),
                Some(&LanguageServerReadiness::Disabled)
            );
            let state = reference_enrichment_for(*language, &published);
            assert_eq!(state, ReferenceEnrichment::EnrichmentDisabled);
            assert!(!state.is_actionable_gap(), "{language}: {state:?}");
        }
        // Completed, so a later request reads it as settled, and nothing was
        // launched, so there is no launch to reuse.
        let attempt = owner.acquire(LanguageId::Python).await;
        assert_eq!(attempt.slot.completed.load(Ordering::Acquire), 1);
        assert_eq!(attempt.reuse(&key()), None);
    }

    /// The original repair holds beside the completed findings: an attempt in
    /// progress withdraws its language's earlier finding, whatever it was, and
    /// reads unknown until it finishes, while other languages keep theirs.
    #[tokio::test]
    async fn an_attempt_in_progress_reads_unknown_over_any_earlier_finding() {
        use kin_core::reference_coverage::{reference_enrichment_for, ReferenceEnrichment};
        let owner = ReadinessObservations::default();
        owner.switched_off().await;
        for earlier in [
            LanguageServerReadiness::Absent,
            LanguageServerReadiness::Disabled,
            LanguageServerReadiness::Usable,
        ] {
            let mut settled = owner.acquire(LanguageId::Python).await;
            settled.begin();
            settled.finish(None, earlier, None);
            drop(settled);
            let mut attempt = owner.acquire(LanguageId::Python).await;
            attempt.begin();
            let during = owner.published_findings();
            assert_eq!(
                reference_enrichment_for(LanguageId::Python, &during),
                ReferenceEnrichment::Unknown
            );
            assert_eq!(
                reference_enrichment_for(LanguageId::Go, &during),
                ReferenceEnrichment::EnrichmentDisabled
            );
            attempt.finish(None, LanguageServerReadiness::Absent, None);
            assert_eq!(
                reference_enrichment_for(LanguageId::Python, &owner.published_findings()),
                ReferenceEnrichment::NoLanguageServer
            );
        }
    }

    #[tokio::test]
    async fn concurrent_readiness_requests_share_a_failure_but_later_requests_retry_it() {
        let owner = ReadinessObservations::default();
        let key = key();
        let mut first = owner.acquire(LanguageId::Python).await;
        first.begin();
        let mut queued = Box::pin(owner.acquire(LanguageId::Python));
        std::future::poll_fn(|cx| {
            assert!(queued.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let failure = LanguageServerReadiness::Unusable {
            reason: "handshake refused".into(),
        };
        first.finish(Some(key.clone()), failure.clone(), None);
        drop(first);
        let waiting = queued.await;
        assert_eq!(waiting.reuse(&key), Some(failure));
        drop(waiting);
        let later = owner.acquire(LanguageId::Python).await;
        assert_eq!(later.reuse(&key), None, "a failure must not latch forever");
    }

    #[tokio::test]
    async fn a_worker_failure_supersedes_an_older_probe_and_keeps_other_languages() {
        let owner = ReadinessObservations::default();
        let key = key();
        let context = context(&key, &key.launch);
        let mut other = owner.acquire(LanguageId::Go).await;
        other.begin();
        other.finish(None, LanguageServerReadiness::Absent, None);
        drop(other);
        let mut probe = owner.acquire(LanguageId::Python).await;
        probe.begin();
        let mut failure = Box::pin(owner.failed(LanguageId::Python, "backend exited".into()));
        std::future::poll_fn(|cx| {
            assert!(failure.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        probe.finish(
            Some(key.clone()),
            LanguageServerReadiness::Usable,
            Some(&context),
        );
        drop(probe);
        failure.await;
        let next = owner.acquire(LanguageId::Python).await;
        assert_eq!(next.reuse(&key), None);
        let published = owner.published.lock().unwrap();
        assert_eq!(
            published.get(&LanguageId::Go),
            Some(&LanguageServerReadiness::Absent)
        );
        assert_eq!(
            published.get(&LanguageId::Python),
            Some(&LanguageServerReadiness::Unusable {
                reason: "backend exited".into()
            })
        );
    }

    #[tokio::test]
    async fn a_cancelled_readiness_attempt_cannot_leave_a_reusable_success() {
        let owner = ReadinessObservations::default();
        let key = key();
        let context = context(&key, &key.launch);
        let mut attempt = owner.acquire(LanguageId::Python).await;
        attempt.begin();
        attempt.finish(
            Some(key.clone()),
            LanguageServerReadiness::Usable,
            Some(&context),
        );
        drop(attempt);
        let mut cancelled = owner.acquire(LanguageId::Python).await;
        cancelled.begin();
        drop(cancelled);
        let next = owner.acquire(LanguageId::Python).await;
        assert_eq!(next.reuse(&key), None);
        assert!(!owner
            .published
            .lock()
            .unwrap()
            .contains_key(&LanguageId::Python));
    }

    #[tokio::test]
    async fn changed_launch_inputs_cannot_reuse_a_settled_observation() {
        let owner = ReadinessObservations::default();
        let original = key();
        let context = context(&original, &original.launch);
        let mut worker = owner.acquire(LanguageId::Python).await;
        worker.begin();
        worker.finish(
            Some(original.clone()),
            LanguageServerReadiness::Usable,
            Some(&context),
        );
        drop(worker);
        let probe = owner.acquire(LanguageId::Python).await;
        let mut alternatives = Vec::new();
        let mut key = original.clone();
        key.identity = Some("sha256:new-server".into());
        alternatives.push(key);
        let mut key = original.clone();
        key.program = PathBuf::from("/other/server");
        alternatives.push(key);
        let mut key = original.clone();
        key.args.push("--other".into());
        alternatives.push(key);
        let mut key = original.clone();
        key.launch.settings = Some(serde_json::json!({"python": "other"}));
        alternatives.push(key);
        let mut key = original.clone();
        key.launch.env.push(("MODE".into(), "other".into()));
        alternatives.push(key);
        let mut key = original.clone();
        key.launch.fallback = Some(Box::new(ServerLaunch::default()));
        alternatives.push(key);
        let mut key = original.clone();
        key.inherited.push(("MODE".into(), "other".into()));
        alternatives.push(key);
        let mut key = original.clone();
        key.workspace = PathBuf::from("/other-workspace");
        alternatives.push(key);
        let mut key = original.clone();
        key.current_dir = Some(PathBuf::from("/other-cwd"));
        alternatives.push(key);
        let mut key = original.clone();
        key.permissions = Some(0o644);
        alternatives.push(key);
        for changed in alternatives {
            assert_eq!(probe.reuse(&changed), None);
        }
        assert_eq!(
            probe.reuse(&original),
            Some(LanguageServerReadiness::Usable)
        );
    }

    #[tokio::test]
    async fn only_a_matching_running_context_makes_an_observation_reusable() {
        let owner = ReadinessObservations::default();
        let mut key = key();
        let fallback = ServerLaunch {
            label: "fallback".into(),
            ..ServerLaunch::default()
        };
        key.launch.fallback = Some(Box::new(fallback.clone()));
        let matching = context(&key, &fallback);
        let mut worker = owner.acquire(LanguageId::Python).await;
        worker.begin();
        worker.finish(
            Some(key.clone()),
            LanguageServerReadiness::Usable,
            Some(&matching),
        );
        drop(worker);
        let mut probe = owner.acquire(LanguageId::Python).await;
        assert_eq!(probe.reuse(&key), Some(LanguageServerReadiness::Usable));
        let mut wrong = matching.clone();
        wrong.environment_hash = kin_model::Hash256::from_bytes([42; 32]);
        probe.begin();
        probe.finish(
            Some(key.clone()),
            LanguageServerReadiness::Usable,
            Some(&wrong),
        );
        drop(probe);
        let mut next = owner.acquire(LanguageId::Python).await;
        assert_eq!(next.reuse(&key), None);
        key.identity = None;
        next.begin();
        next.finish(
            Some(key.clone()),
            LanguageServerReadiness::Usable,
            Some(&matching),
        );
        drop(next);
        let later = owner.acquire(LanguageId::Python).await;
        assert_eq!(
            later.reuse(&key),
            None,
            "an unidentified wrapper needs a fresh process observation"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn node_interpreter_changes_and_removal_invalidate_readiness_reuse() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let node = directory.path().join("node");
        let program = directory.path().join("server.js");
        std::fs::write(&program, "#!/usr/bin/env node\n// server entry\n").unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"version":"1.0"}"#,
        )
        .unwrap();
        std::fs::write(&node, b"native node version one").unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        let launch = ServerLaunch {
            env: vec![(
                "PATH".into(),
                directory.path().to_string_lossy().into_owned(),
            )],
            ..ServerLaunch::default()
        };
        let capture = || LaunchKey::capture(directory.path(), &program, &[], &launch);
        let original = capture();
        assert_eq!(original.interpreters.as_ref().unwrap().len(), 2);
        let context = context(&original, &launch);
        let owner = ReadinessObservations::default();
        let mut worker = owner.acquire(LanguageId::Python).await;
        worker.begin();
        worker.finish(
            Some(original.clone()),
            LanguageServerReadiness::Usable,
            Some(&context),
        );
        drop(worker);
        let next = owner.acquire(LanguageId::Python).await;
        assert_eq!(
            next.reuse(&capture()),
            Some(LanguageServerReadiness::Usable)
        );

        std::fs::write(&node, b"native node version two").unwrap();
        let changed = capture();
        assert_eq!(
            original.identity, changed.identity,
            "entry/package bytes did not change"
        );
        assert!(changed.interpreters.is_some());
        assert_eq!(next.reuse(&changed), None);
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o644)).unwrap();
        let unavailable = capture();
        assert!(unavailable.interpreters.is_none());
        assert!(!unavailable.identifies(&context));
        assert_eq!(next.reuse(&unavailable), None);
        std::fs::remove_file(&node).unwrap();
        let removed = capture();
        assert!(removed.interpreters.is_none());
        assert_eq!(next.reuse(&removed), None);

        // An executable wrapper at the same PATH is not a native Node proof.
        std::fs::write(&node, b"#!/bin/sh\nexec other-node \"$@\"\n").unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(capture().interpreters.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn direct_node_and_fallback_interpreters_are_part_of_the_readiness_key() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let node = directory.path().join("node");
        let program = directory.path().join("server.js");
        std::fs::write(&node, b"native node").unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            directory.path().join("package.json"),
            r#"{"version":"1.0"}"#,
        )
        .unwrap();
        std::fs::write(&program, format!("#!{}\n// server\n", node.display())).unwrap();
        let direct = LaunchKey::capture(directory.path(), &program, &[], &ServerLaunch::default());
        assert_eq!(direct.interpreters.as_ref().unwrap().len(), 1);
        std::fs::write(&program, "#!/usr/bin/env -S node --flag\n// server\n").unwrap();
        let complex = LaunchKey::capture(directory.path(), &program, &[], &ServerLaunch::default());
        assert!(complex.interpreters.is_none());

        std::fs::write(&program, "#!/usr/bin/env node\n// server\n").unwrap();
        let launch = ServerLaunch {
            env: vec![(
                "PATH".into(),
                directory.path().to_string_lossy().into_owned(),
            )],
            fallback: Some(Box::new(ServerLaunch {
                env: vec![(
                    "PATH".into(),
                    directory
                        .path()
                        .join("missing")
                        .to_string_lossy()
                        .into_owned(),
                )],
                ..ServerLaunch::default()
            })),
            ..ServerLaunch::default()
        };
        let unknown_fallback = LaunchKey::capture(directory.path(), &program, &[], &launch);
        assert!(unknown_fallback.interpreters.is_none());
    }

    #[test]
    fn executable_bytes_and_permissions_are_recaptured_before_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("server");
        std::fs::write(&program, b"native executable version one").unwrap();
        let first = LaunchKey::capture(directory.path(), &program, &[], &ServerLaunch::default());
        assert!(first.identity.is_some());
        std::fs::write(&program, b"native executable version two").unwrap();
        let second = LaunchKey::capture(directory.path(), &program, &[], &ServerLaunch::default());
        assert!(first != second);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o000)).unwrap();
            let third =
                LaunchKey::capture(directory.path(), &program, &[], &ServerLaunch::default());
            assert!(second != third);
        }
    }
}
