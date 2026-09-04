// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The embedding model this build fetches at runtime, and how far along that
//! fetch is.
//!
//! No install ships the weights. The first local embed pass resolves
//! `nomic-ai/nomic-embed-text-v1.5` through `hf-hub`, which downloads it into
//! the Hugging Face hub cache before a single vector is computed. On a fresh
//! machine that is several hundred megabytes of egress, and every counter the
//! product published during it read as an embed pass that was working and
//! recording nothing.
//!
//! `kin init` is what usually pays it. The command's enrichment phase starts a
//! daemon, and that daemon's background embed worker queues everything the
//! index is missing as soon as its first reconcile lands, so on a repository
//! with parseable content the fetch happens inside `kin init` rather than
//! between it and a later `kin embed`. Wording on every surface says so, since
//! the earlier phrasing put the cost on a command the user had not run yet.
//!
//! This module is the one place that knows where those bytes land, how many of
//! them have landed, and what to say about it. Its probes are local filesystem
//! reads of a cache this process does not own: resource and configuration
//! disclosure, never an answer to a graph question.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The model `kin-db` embeds with when nothing overrides it
/// (`KIN_EMBED_MODEL_ID`).
pub const DEFAULT_EMBED_MODEL_ID: &str = "nomic-ai/nomic-embed-text-v1.5";

/// The host `hf-hub` fetches from when `HF_ENDPOINT` is unset
/// (`hf-hub-0.5.0/src/api/sync.rs:268`).
pub const EMBED_MODEL_HOST: &str = "huggingface.co";

/// What a complete fetch of [`DEFAULT_EMBED_MODEL_ID`] occupies in the hub
/// cache, as `du -h` reported it on a converted repository:
/// `523M .../hub/models--nomic-ai--nomic-embed-text-v1.5`.
///
/// Held in bytes rather than as a phrase because it is the denominator of a
/// progress figure, and it is the stored size rather than the transferred size
/// because the numerator is read off the same directory.
pub const DEFAULT_EMBED_MODEL_BYTES: u64 = 523 * 1024 * 1024;

/// Directory entries one cache walk will visit before it stops counting.
///
/// A hub cache for one model holds tens of files. The bound exists so a status
/// path can never be made slow by whatever else is under the cache root, and it
/// is reported by [`EmbedModelFetch::fetched_bytes`] understating rather than
/// by an error, which is the safe direction for a progress numerator.
const CACHE_WALK_BUDGET: u32 = 4096;

/// Where the fetch stands, as the status surfaces render it.
///
/// Sourced entirely from the local cache plus one fact the daemon owns (whether
/// its embed pass is running). Nothing here is inferred from elapsed time: a
/// figure that climbs on a clock rather than on bytes is exactly the reassurance
/// an air-gapped host must not be given.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedModelFetch {
    /// The model id the embedder will resolve.
    pub model_id: String,
    /// The directory `hf-hub` fills for that model, when a home resolved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_dir: Option<String>,
    /// A resolved snapshot is present, so no fetch is owed.
    pub present: bool,
    /// Bytes already under `cache_dir`, partial blobs included.
    pub fetched_bytes: u64,
    /// What a complete fetch of this model weighs, for the models this build
    /// carries a measurement for. Absent for an overridden model id, where a
    /// denominator would be invented rather than measured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_bytes: Option<u64>,
    /// The embed pass is running and the model is not here yet, so the pass is
    /// inside the fetch rather than inside inference.
    pub fetching: bool,
    /// Why no Hugging Face fetch applies to this configuration, when none does.
    /// Set for a remote embedding provider and for a model id that already
    /// names a local directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_fetch_reason: Option<String>,
    /// `HF_HOME`, when it is set and names a root the embedding loader does not
    /// read. A model pre-seeded there is not the one this build loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relocated_hf_home: Option<String>,
}

impl EmbedModelFetch {
    /// Read the local cache and say where the fetch stands.
    ///
    /// `embed_pass_working` is the daemon's own account of its embed pass. The
    /// pass being at work while the model is absent is what makes the fetch the
    /// thing blocking coverage, and it is the only input this function cannot
    /// read for itself.
    pub fn probe(embed_pass_working: bool) -> Self {
        let model_id = configured_model_id();
        if let Some(reason) = no_fetch_reason(&model_id) {
            return Self {
                model_id,
                no_fetch_reason: Some(reason),
                ..Default::default()
            };
        }
        let base = loader_cache_base();
        let dir = base
            .as_deref()
            .map(|base| crate::retrieval_profile::model_cache_dir(base, &model_id));
        let present = dir
            .as_deref()
            .map(crate::retrieval_profile::snapshot_present)
            .unwrap_or(false);
        // Only measured while something is owed. A resolved snapshot renders no
        // numerator anywhere, so walking a complete cache would be work no
        // surface reads.
        let fetched_bytes = match (present, dir.as_deref()) {
            (false, Some(dir)) => fetched_bytes(dir),
            _ => 0,
        };
        Self {
            expected_bytes: expected_bytes(&model_id),
            cache_dir: dir.map(|dir| dir.display().to_string()),
            present,
            fetched_bytes,
            fetching: embed_pass_working && !present,
            no_fetch_reason: None,
            relocated_hf_home: relocated_hf_home(base.as_deref()),
            model_id,
        }
    }

    /// What to call this pass while it is inside the fetch, or `None` when it
    /// is not.
    ///
    /// The zero-byte wording is deliberately different from the progressing
    /// one. A download that has moved names its numerator; one that has not is
    /// the shape an unreachable host produces, and saying so is the whole point
    /// of the phase.
    pub fn download_phase(&self) -> Option<String> {
        if !self.fetching {
            return None;
        }
        if self.fetched_bytes == 0 {
            return Some(format!(
                "embedding model download pending, no bytes yet (needs egress to {EMBED_MODEL_HOST})"
            ));
        }
        Some(format!(
            "downloading embedding model ({})",
            self.render_progress()
        ))
    }

    /// The `Embed model:` line `kin resources inspect` always prints.
    ///
    /// Rendered in every state rather than only during a fetch, for the reason
    /// every other counter on that surface is: a line that appears only while
    /// something is happening cannot be checked against, and its absence reads
    /// identically to a surface nobody wired up.
    pub fn inspect_line(&self) -> String {
        if let Some(reason) = self.no_fetch_reason.as_deref() {
            return format!("Embed model: {} ({reason})", self.model_id);
        }
        let location = match self.cache_dir.as_deref() {
            Some(dir) => format!(" at {dir}"),
            None => String::new(),
        };
        let mut line = if self.fetching {
            format!(
                "Embed model: downloading {} ({}){location}",
                self.model_id,
                self.render_progress()
            )
        } else if self.present {
            format!("Embed model: {} cached{location}", self.model_id)
        } else {
            format!(
                "Embed model: {} not in the cache{location}; `kin init` starts the first embed pass, which fetches {} from {EMBED_MODEL_HOST}",
                self.model_id,
                self.expected_download(),
            )
        };
        if let Some(hf_home) = self.relocated_hf_home.as_deref() {
            line.push_str(&format!(
                "; HF_HOME is set to {hf_home}, which this embedder does not read"
            ));
        }
        line
    }

    /// The clause `kin graph status` appends to its embedding counters while
    /// the model is still arriving, or `None` when nothing is being fetched.
    ///
    /// Appended rather than substituted: the counters and whatever else the
    /// daemon already knows about them are all still true, and this names the
    /// one thing standing in front of them right now.
    pub fn status_clause(&self) -> Option<String> {
        if !self.fetching {
            return None;
        }
        if self.fetched_bytes == 0 {
            return Some(format!(
                "; the {} embedding model is not on this machine and no bytes of it have arrived \
                 yet, so nothing can embed until it lands (the fetch needs egress to {EMBED_MODEL_HOST})",
                self.model_id
            ));
        }
        Some(format!(
            "; the {} embedding model is still downloading ({} from {EMBED_MODEL_HOST}), so \
             nothing can embed until it lands",
            self.model_id,
            self.render_progress()
        ))
    }

    /// Whether the fetch MOVED across a window the caller already held, taken
    /// from two measurements of the same directory rather than from a worker
    /// nobody asked.
    ///
    /// [`Self::probe`] takes `embed_pass_working` from a caller that holds the
    /// daemon's own account of its embed pass. A one-shot CLI surface holds no
    /// such account, and passing `true` there asserts it: an `.incomplete` blob
    /// left by a download that died last week reads exactly like one being
    /// written to right now, and so does an air-gapped host whose fetch never
    /// started. Both were then told a download was in flight and to wait for it.
    ///
    /// `hf-hub` streams into an `.incomplete` blob in the model's own cache
    /// directory, so bytes that grew between the two probes are a fetch that is
    /// running, with nothing inferred and nothing assumed. The converse is NOT
    /// claimed: a window that saw no growth is reported as a window that saw no
    /// growth, never as a dead fetch, because a slow link inside a short window
    /// looks the same. That asymmetry is the whole point. Over-claiming sends a
    /// reader away to wait for something that may never arrive; under-claiming
    /// costs them one command.
    pub fn with_progress_since(mut self, earlier: &Self) -> Self {
        self.fetching = !self.present
            && self.no_fetch_reason.is_none()
            && self.fetched_bytes > earlier.fetched_bytes;
        self
    }

    /// The line a ranked answer owes a reader when the weights it would have
    /// ranked with are not on this machine, or `None` when the model is not
    /// what stands in the way.
    ///
    /// Three sentences, and only one of them tells the reader to wait. Which
    /// one is decided by [`Self::fetching`], which on this path means bytes
    /// were measured arriving rather than a worker was assumed to be running.
    ///
    /// It exists because a fast `kin init` on a small repository returns before
    /// the fetch does. On `expressjs/body-parser` the whole command took ten
    /// seconds against a fixed 523 MB download, so the first `kin locate` ran
    /// with no embeddings at all and said only that no row had cleared the
    /// answer floor. That sentence is true and it names the wrong cause:
    /// nothing about the query or the store was short, the weights had simply
    /// not arrived.
    pub fn retrieval_clause(&self) -> Option<String> {
        if self.present || self.no_fetch_reason.is_some() {
            return None;
        }
        // Bytes moved while this answer was being produced. This is the only
        // arm that may promise an arrival, because it is the only one holding
        // evidence of one.
        if self.fetching {
            return Some(format!(
                "embedding model still downloading ({}); results are lexical until it lands",
                self.render_progress()
            ));
        }
        // Nothing here and nothing arriving. An air-gapped host reaches this,
        // and telling it to wait is telling it to wait forever, so the egress
        // the fetch needs leads and the command that starts it closes.
        if self.fetched_bytes == 0 {
            return Some(format!(
                "the {} embedding model is not on this machine and no bytes of it have arrived, \
                 so no row here can carry vector evidence; the fetch needs egress to {} and `kin \
                 embed` runs it",
                self.model_id,
                endpoint_host()
            ));
        }
        // Part of it is here and none of it moved. Says exactly that, because a
        // stalled download and a slow one are indistinguishable inside one
        // window and only one of them is worth waiting for.
        Some(format!(
            "the {} embedding model is not on this machine yet ({} in the cache) and none of it \
             arrived while this answer was produced, so no row here can carry vector evidence; \
             run `kin embed` to fetch it now",
            self.model_id,
            self.render_progress()
        ))
    }

    /// `N of 523 MB` where the total is known, `N MB fetched` where it is not.
    ///
    /// Visible to the crate because `kin init`'s closing summary renders the
    /// same numerator, and a second copy of this formatting would let the two
    /// surfaces disagree about the same bytes.
    pub(crate) fn render_progress(&self) -> String {
        match self.expected_bytes {
            Some(expected) => format!(
                "{} of {}",
                megabytes(self.fetched_bytes.min(expected)),
                render_megabytes(expected)
            ),
            None => format!("{} fetched", render_megabytes(self.fetched_bytes)),
        }
    }

    /// The download size as a phrase, and deliberately sizeless for a model
    /// this build has never measured.
    ///
    /// An overridden `KIN_EMBED_MODEL_ID` can weigh anything. Falling back to
    /// the default model's figure would print a number nobody measured for the
    /// model actually being fetched, which is worse than printing none.
    pub fn expected_download(&self) -> String {
        match self.expected_bytes {
            Some(expected) => format!("about {}", render_megabytes(expected)),
            None => "the model".to_string(),
        }
    }
}

/// The model id the embedder will resolve, mirroring `kin-db`'s own read of
/// `KIN_EMBED_MODEL_ID` (trimmed, and empty read as unset).
pub fn configured_model_id() -> String {
    non_empty_env("KIN_EMBED_MODEL_ID").unwrap_or_else(|| DEFAULT_EMBED_MODEL_ID.to_string())
}

/// Why this configuration fetches nothing from the hub, when it fetches
/// nothing.
///
/// Two shapes reach the embedder without a download. A remote provider embeds
/// over HTTP and never loads local weights, and a model id that already names a
/// directory is loaded from it in place (`kin-db` `embed/mod.rs`, where a
/// `is_dir()` id short-circuits the hub path). Reporting either as a pending
/// download would announce egress that will never happen.
fn no_fetch_reason(model_id: &str) -> Option<String> {
    if let Some(provider) = remote_provider() {
        return Some(format!(
            "the {provider} provider embeds over HTTP, so no model is fetched to this machine"
        ));
    }
    if Path::new(model_id).is_dir() {
        return Some("a local model directory, so nothing is fetched".to_string());
    }
    None
}

/// The configured OpenAI-compatible provider, or `None` for local embedding.
///
/// Mirrors `kin-db`'s parse exactly, including its fallback: every value it
/// does not recognize embeds locally, so only the names it maps to an HTTP
/// provider are treated as remote here.
fn remote_provider() -> Option<String> {
    let value = non_empty_env("KIN_EMBED_PROVIDER")?.to_ascii_lowercase();
    match value.as_str() {
        "openai" | "lmstudio" | "lm-studio" | "openai-compat" | "openai-compatible"
        | "compatible" => Some(value),
        _ => None,
    }
}

/// What a complete fetch of `model_id` weighs, for ids this build has measured.
fn expected_bytes(model_id: &str) -> Option<u64> {
    (model_id == DEFAULT_EMBED_MODEL_ID).then_some(DEFAULT_EMBED_MODEL_BYTES)
}

/// The hub cache root the embedding loader actually fills.
///
/// `kin-db` builds its hub client with `hf_hub::api::sync::Api::new()`, which
/// resolves `Cache::default()`: the process home joined with
/// `.cache/huggingface`, with `HF_HOME` never consulted
/// (`hf-hub-0.5.0/src/lib.rs:201-208`). Only `ApiBuilder::from_env()` reads that
/// variable, and the embedder does not call it. So this mirrors the constructor
/// the weights are fetched through rather than the variable a reader would
/// expect to govern them: a progress numerator taken from a directory nobody is
/// writing to is worse than no numerator at all.
pub fn loader_cache_base() -> Option<PathBuf> {
    loader_cache_base_from(
        cfg!(windows),
        || directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
        || directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
    )
}

/// The root above, with its home resolvers taken as arguments.
///
/// Split out for the reason `retrieval_profile::hf_cache_base` gives: a
/// `cfg`-gated Windows arm is compiled, and therefore tested, only on the
/// platform this fleet has no host for.
///
/// The Windows arm follows `dirs::home_dir()`, which is `FOLDERID_Profile`
/// (`dirs-6.0.0/src/win.rs:5`), and deliberately does NOT prefer `USERPROFILE`
/// the way `setup::resolve_home_dir` does. This function answers where the
/// fetched bytes go, and a native Windows host with `USERPROFILE` redirected
/// away from the known-folder profile still had `hf-hub` write its cache under
/// the profile.
fn loader_cache_base_from(
    windows: bool,
    known_profile_root: impl FnOnce() -> Option<PathBuf>,
    base_dirs_home: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    let home = if windows {
        known_profile_root().or_else(base_dirs_home)
    } else {
        base_dirs_home()
    };
    home.map(|home| home.join(".cache").join("huggingface"))
}

/// `HF_HOME`, when it is set and names a root other than `loader_base`.
///
/// `hf-hub` honours it from `Cache::from_env()` and ignores it from
/// `Cache::default()`, and the embedder reaches the second. So a caller who
/// relocated their cache and pre-seeded the model there will still watch the
/// loader fetch it again into the home root, and every surface that reports the
/// cache says so rather than leaving the two roots to be discovered by the
/// download.
fn relocated_hf_home(loader_base: Option<&Path>) -> Option<String> {
    let hf_home = non_empty_env("HF_HOME")?;
    match loader_base {
        Some(base) if Path::new(&hf_home) == base => None,
        _ => Some(hf_home),
    }
}

/// Bytes present under a model's cache directory, partial blobs included.
///
/// Symlinks are counted as zero and never followed. A resolved hub snapshot is
/// a tree of links into `blobs`, so following them would count every weight
/// twice and report a fetch as further along than it is. Reading the real files
/// once is also what makes an interrupted download visible: `hf-hub` streams
/// into an `.incomplete` blob in the same directory, so a fetch in flight is
/// exactly the bytes this returns.
pub fn fetched_bytes(model_dir: &Path) -> u64 {
    let mut total = 0_u64;
    let mut budget = CACHE_WALK_BUDGET;
    accumulate_bytes(model_dir, &mut total, &mut budget);
    total
}

fn accumulate_bytes(dir: &Path, total: &mut u64, budget: &mut u32) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if *budget == 0 {
            return;
        }
        *budget -= 1;
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            accumulate_bytes(&entry.path(), total, budget);
        } else if let Ok(metadata) = entry.metadata() {
            *total = total.saturating_add(metadata.len());
        }
    }
}

/// Whole mebibytes, truncated, labelled the way `du -h` labels them.
///
/// Truncating keeps a progress numerator from ever reading ahead of the bytes
/// that are actually on disk.
pub fn render_megabytes(bytes: u64) -> String {
    format!("{} MB", megabytes(bytes))
}

/// Whole mebibytes, truncated. The numerator of a progress figure carries no
/// unit of its own, so it is rendered from this rather than from the labelled
/// form.
fn megabytes(bytes: u64) -> u64 {
    bytes / (1024 * 1024)
}

/// The host the fetch would reach, honouring `HF_ENDPOINT` the way `hf-hub`
/// does from `ApiBuilder::from_env()` (`hf-hub-0.5.0/src/api/sync.rs:249`).
pub fn endpoint_host() -> String {
    let Some(endpoint) = non_empty_env("HF_ENDPOINT") else {
        return EMBED_MODEL_HOST.to_string();
    };
    let without_scheme = endpoint
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(&endpoint);
    let host = without_scheme
        .split(['/', ':'])
        .next()
        .unwrap_or(without_scheme);
    if host.is_empty() {
        EMBED_MODEL_HOST.to_string()
    } else {
        host.to_string()
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fetching(fetched_bytes: u64) -> EmbedModelFetch {
        EmbedModelFetch {
            model_id: DEFAULT_EMBED_MODEL_ID.to_string(),
            cache_dir: Some("/home/dev/.cache/huggingface/hub/models--x".to_string()),
            present: false,
            fetched_bytes,
            expected_bytes: Some(DEFAULT_EMBED_MODEL_BYTES),
            fetching: true,
            no_fetch_reason: None,
            relocated_hf_home: None,
        }
    }

    /// The phase a fetch in flight renders, from an injected byte count rather
    /// than from a clock. Both halves are asserted: the numerator moves with
    /// the bytes, and the denominator is the measured size.
    #[test]
    fn a_fetch_in_flight_renders_its_measured_progress() {
        let phase = fetching(137 * 1024 * 1024)
            .download_phase()
            .expect("a fetch in flight has a phase");
        assert_eq!(phase, "downloading embedding model (137 of 523 MB)");

        let later = fetching(400 * 1024 * 1024)
            .download_phase()
            .expect("a fetch in flight has a phase");
        assert_eq!(later, "downloading embedding model (400 of 523 MB)");
    }

    /// Zero bytes is not "downloading". It is the shape a host with no route to
    /// the model host produces, and it renders as its own phase naming the
    /// egress the fetch needs.
    #[test]
    fn a_fetch_with_no_bytes_names_the_egress_instead_of_claiming_progress() {
        let phase = fetching(0)
            .download_phase()
            .expect("a fetch in flight has a phase");
        assert_eq!(
            phase,
            "embedding model download pending, no bytes yet (needs egress to huggingface.co)"
        );
        assert!(
            !phase.contains("downloading"),
            "a fetch that has moved nothing must not read as one that has: {phase}"
        );
    }

    /// A model already in the cache produces no phase at all, so the pass line
    /// keeps saying what it said before any of this existed.
    #[test]
    fn a_cached_model_renders_no_download_phase() {
        let cached = EmbedModelFetch {
            present: true,
            fetching: false,
            ..fetching(DEFAULT_EMBED_MODEL_BYTES)
        };
        assert_eq!(cached.download_phase(), None);
        assert_eq!(cached.status_clause(), None);
        assert!(cached.inspect_line().contains("cached"));
    }

    /// The counters line gains a clause while the model is arriving and loses
    /// it once the model is here.
    #[test]
    fn the_status_clause_names_the_blocker_only_while_it_blocks() {
        let clause = fetching(137 * 1024 * 1024)
            .status_clause()
            .expect("a fetch in flight has a clause");
        assert!(
            clause.contains("still downloading (137 of 523 MB from huggingface.co)"),
            "the clause carries the measured progress: {clause}"
        );
        assert!(
            clause.contains("nothing can embed until it lands"),
            "the clause says what the counters mean: {clause}"
        );

        let stalled = fetching(0)
            .status_clause()
            .expect("a fetch in flight has a clause");
        assert!(
            stalled.contains("no bytes of it have arrived yet"),
            "a fetch that moved nothing says so: {stalled}"
        );
    }

    /// The only arm that may tell a reader to wait, and it may only be reached
    /// by bytes that were measured arriving.
    #[test]
    #[serial_test::serial]
    fn a_ranked_answer_promises_an_arrival_only_when_bytes_actually_moved() {
        let _endpoint = kin_core::test_env::EnvVarGuard::unset("HF_ENDPOINT");
        let earlier = fetching(120 * 1024 * 1024);
        let moved = fetching(137 * 1024 * 1024).with_progress_since(&earlier);
        assert!(
            moved.fetching,
            "growth across the window is a running fetch"
        );
        assert_eq!(
            moved
                .retrieval_clause()
                .expect("a fetch that moved has a clause"),
            "embedding model still downloading (137 of 523 MB); results are lexical until it lands"
        );
    }

    /// The reviewer's case on kin#1491: an `.incomplete` blob from a download
    /// that already died reads exactly like one being written to right now, so
    /// a window that saw no growth must not promise an arrival.
    #[test]
    #[serial_test::serial]
    fn a_stalled_cache_is_never_reported_as_a_download_in_flight() {
        let _endpoint = kin_core::test_env::EnvVarGuard::unset("HF_ENDPOINT");
        let earlier = fetching(137 * 1024 * 1024);
        let stalled = fetching(137 * 1024 * 1024).with_progress_since(&earlier);
        assert!(
            !stalled.fetching,
            "no growth across the window is not a running fetch"
        );
        let clause = stalled
            .retrieval_clause()
            .expect("an absent model still explains the rows");
        assert!(
            clause.contains("137 of 523 MB in the cache")
                && clause.contains("none of it arrived while this answer was produced")
                && clause.contains("run `kin embed` to fetch it now"),
            "it reports what was measured and hands over the command: {clause}"
        );
        assert!(
            !clause.contains("still downloading") && !clause.contains("until it lands"),
            "and never tells the reader to wait on evidence it does not have: {clause}"
        );
    }

    /// The air-gapped host. Nothing here, nothing arriving, and no instruction
    /// to wait for something that will never come.
    #[test]
    #[serial_test::serial]
    fn an_unreachable_host_is_told_about_egress_and_never_told_to_wait() {
        let _endpoint = kin_core::test_env::EnvVarGuard::unset("HF_ENDPOINT");
        let earlier = fetching(0);
        let offline = fetching(0).with_progress_since(&earlier);
        assert!(!offline.fetching);
        let clause = offline
            .retrieval_clause()
            .expect("an absent model still explains the rows");
        assert!(
            clause.contains("no bytes of it have arrived")
                && clause.contains("needs egress to huggingface.co")
                && clause.contains("`kin embed` runs it"),
            "the egress it needs leads and the command that starts it closes: {clause}"
        );
        assert!(
            !clause.contains("until it lands"),
            "an air-gapped host is never told to wait: {clause}"
        );
    }

    /// Every state in which the model is not the blocker renders nothing, so
    /// the line can never appear beside an answer it does not explain.
    ///
    /// `with_progress_since` is applied to each, because a cached model whose
    /// byte count fell to zero would otherwise show growth in reverse.
    #[test]
    fn a_ranked_answer_says_nothing_when_the_model_is_not_the_blocker() {
        let cached = EmbedModelFetch {
            present: true,
            fetching: false,
            ..fetching(DEFAULT_EMBED_MODEL_BYTES)
        };
        assert_eq!(
            cached
                .clone()
                .with_progress_since(&fetching(0))
                .retrieval_clause(),
            None,
            "a resolved snapshot owes no clause however the byte counts read"
        );

        let remote = EmbedModelFetch {
            model_id: "text-embedding-3-small".to_string(),
            no_fetch_reason: Some("the openai provider embeds over HTTP".to_string()),
            ..Default::default()
        };
        assert_eq!(
            remote.with_progress_since(&fetching(0)).retrieval_clause(),
            None,
            "a configuration that fetches nothing is never reported as fetching"
        );
    }

    /// An absent model with no pass running still reports what the first pass
    /// will cost and where it will put it.
    #[test]
    fn an_absent_model_states_the_download_before_anything_starts() {
        let absent = EmbedModelFetch {
            fetching: false,
            ..fetching(0)
        };
        let line = absent.inspect_line();
        assert!(
            line.contains("not in the cache")
                && line.contains("about 523 MB")
                && line.contains("huggingface.co"),
            "an absent model states its cost and its source: {line}"
        );
        // FIR-2555: which command pays. `kin init` starts the daemon whose
        // background embed worker does the fetching, so a reader told to expect
        // it from a later `kin embed` is told the wrong thing.
        assert!(
            line.contains("`kin init` starts the first embed pass"),
            "an absent model names the command that fetches it: {line}"
        );
        assert!(
            !line.contains("a later embed pass fetches"),
            "the check must be able to fail: {line}"
        );
    }

    /// An overridden model id has no measured size, so the surfaces report the
    /// bytes that arrived and invent no denominator.
    #[test]
    fn an_overridden_model_reports_bytes_without_inventing_a_total() {
        let custom = EmbedModelFetch {
            model_id: "acme/private-embed".to_string(),
            expected_bytes: None,
            ..fetching(12 * 1024 * 1024)
        };
        assert_eq!(
            custom.download_phase(),
            Some("downloading embedding model (12 MB fetched)".to_string())
        );
        assert!(
            !custom.inspect_line().contains("523"),
            "no measured size may be attributed to an unmeasured model: {}",
            custom.inspect_line()
        );
    }

    /// A relocated `HF_HOME` is named wherever the cache is reported, because a
    /// model pre-seeded there is not the one the embedder loads.
    #[test]
    fn a_relocated_hf_home_is_named_beside_the_cache() {
        let relocated = EmbedModelFetch {
            relocated_hf_home: Some("/mnt/models/hf".to_string()),
            fetching: false,
            ..fetching(0)
        };
        assert!(
            relocated
                .inspect_line()
                .contains("HF_HOME is set to /mnt/models/hf"),
            "the disagreement is reported: {}",
            relocated.inspect_line()
        );
    }

    #[test]
    fn a_configuration_that_fetches_nothing_says_why() {
        let remote = EmbedModelFetch {
            model_id: "text-embedding-3-small".to_string(),
            no_fetch_reason: Some("the openai provider embeds over HTTP".to_string()),
            ..Default::default()
        };
        assert_eq!(remote.download_phase(), None);
        assert_eq!(
            remote.inspect_line(),
            "Embed model: text-embedding-3-small (the openai provider embeds over HTTP)"
        );
    }

    /// Symlinked snapshot entries must not be counted: a resolved snapshot
    /// links into `blobs`, and following the links would report a fetch as
    /// twice as far along as it is.
    #[test]
    fn cache_bytes_count_real_files_once_and_never_follow_links() {
        let temp = tempfile::tempdir().expect("temp dir");
        let blobs = temp.path().join("blobs");
        let snapshots = temp.path().join("snapshots").join("abc123");
        std::fs::create_dir_all(&blobs).expect("create blobs");
        std::fs::create_dir_all(&snapshots).expect("create snapshot");
        let blob = blobs.join("deadbeef");
        std::fs::write(&blob, vec![0_u8; 4096]).expect("write blob");
        std::fs::write(blobs.join("partial.incomplete"), vec![0_u8; 2048])
            .expect("write partial blob");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&blob, snapshots.join("model.safetensors"))
            .expect("link the snapshot entry at its blob");

        assert_eq!(
            fetched_bytes(temp.path()),
            4096 + 2048,
            "every real byte counts once and a link adds none"
        );
    }

    #[test]
    fn an_absent_cache_directory_reads_as_no_bytes() {
        let temp = tempfile::tempdir().expect("temp dir");
        assert_eq!(fetched_bytes(&temp.path().join("never-fetched")), 0);
    }

    /// The loader root is the home cache root on every platform, and on Windows
    /// it follows the known-folder profile rather than `USERPROFILE`, which is
    /// where `hf-hub` was measured writing.
    #[test]
    fn the_loader_root_is_the_home_cache_root_on_both_platforms() {
        let profile = PathBuf::from("/known/profile");
        let base_home = PathBuf::from("/base/home");
        assert_eq!(
            loader_cache_base_from(false, || Some(profile.clone()), || Some(base_home.clone())),
            Some(base_home.join(".cache").join("huggingface"))
        );
        assert_eq!(
            loader_cache_base_from(true, || Some(profile.clone()), || Some(base_home.clone())),
            Some(profile.join(".cache").join("huggingface"))
        );
        assert_eq!(loader_cache_base_from(false, || None, || None), None);
    }

    #[test]
    #[serial_test::serial]
    fn a_relocated_hf_home_is_detected_only_when_it_differs() {
        let base = PathBuf::from("/home/dev/.cache/huggingface");
        let mut guard = kin_core::test_env::EnvVarGuard::unset("HF_HOME");
        assert_eq!(relocated_hf_home(Some(&base)), None);

        guard.apply("HF_HOME", Some(&base));
        assert_eq!(
            relocated_hf_home(Some(&base)),
            None,
            "a variable pointing at the root the loader already reads is not a relocation"
        );

        guard.apply("HF_HOME", Some("/mnt/models/hf"));
        assert_eq!(
            relocated_hf_home(Some(&base)),
            Some("/mnt/models/hf".to_string())
        );
    }

    #[test]
    #[serial_test::serial]
    fn the_endpoint_host_follows_hf_endpoint_and_defaults_to_the_hub() {
        let mut guard = kin_core::test_env::EnvVarGuard::unset("HF_ENDPOINT");
        assert_eq!(endpoint_host(), "huggingface.co");

        guard.apply("HF_ENDPOINT", Some("https://mirror.example.invalid/hub"));
        assert_eq!(endpoint_host(), "mirror.example.invalid");

        guard.apply("HF_ENDPOINT", Some("http://10.0.0.4:8080"));
        assert_eq!(endpoint_host(), "10.0.0.4");

        guard.apply("HF_ENDPOINT", Some("  "));
        assert_eq!(endpoint_host(), "huggingface.co");
    }

    #[test]
    #[serial_test::serial]
    fn a_remote_provider_and_a_local_directory_both_cancel_the_fetch() {
        let temp = tempfile::tempdir().expect("temp dir");
        let mut provider = kin_core::test_env::EnvVarGuard::unset("KIN_EMBED_PROVIDER");
        assert_eq!(no_fetch_reason(DEFAULT_EMBED_MODEL_ID), None);

        provider.apply("KIN_EMBED_PROVIDER", Some("lmstudio"));
        assert!(no_fetch_reason(DEFAULT_EMBED_MODEL_ID)
            .expect("a remote provider cancels the fetch")
            .contains("lmstudio"));

        // kin-db falls back to local embedding for every name it does not
        // recognize, so an unknown value must still report a pending fetch.
        provider.apply("KIN_EMBED_PROVIDER", Some("warp-drive"));
        assert_eq!(no_fetch_reason(DEFAULT_EMBED_MODEL_ID), None);

        provider.apply::<_, &str>("KIN_EMBED_PROVIDER", None);
        assert!(no_fetch_reason(&temp.path().display().to_string())
            .expect("a local model directory cancels the fetch")
            .contains("local model directory"));
    }

    #[test]
    #[serial_test::serial]
    fn the_model_id_follows_its_override_and_falls_back_to_the_default() {
        let mut guard = kin_core::test_env::EnvVarGuard::unset("KIN_EMBED_MODEL_ID");
        assert_eq!(configured_model_id(), DEFAULT_EMBED_MODEL_ID);

        guard.apply("KIN_EMBED_MODEL_ID", Some(" acme/private-embed "));
        assert_eq!(configured_model_id(), "acme/private-embed");

        guard.apply("KIN_EMBED_MODEL_ID", Some(""));
        assert_eq!(configured_model_id(), DEFAULT_EMBED_MODEL_ID);
    }
}
