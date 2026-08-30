// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::error::{KinError, Result};
use crate::layout::KinLayout;

/// Minimum `kin_version` (major, minor) this binary can open an existing repo
/// with. A repo created by an older Kin (e.g. 0.1.x) carries an on-disk graph
/// and vector index built before a breaking format change; the post-load embed
/// and readiness path cannot serve it, so opening it must be refused up front
/// with an actionable error instead of loading and then being SIGTERM-killed by
/// the CLI supervisor when readiness never arrives.
pub const MIN_COMPATIBLE_KIN_VERSION: (u64, u64) = (0, 2);

/// Repo identity stored in `.kin/manifest.json`.
///
/// This records the Kin version that created the repo, detected languages,
/// and registered adapters. It is the "birth certificate" of a Kin repo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KinManifest {
    /// Kin version that created this repository.
    pub kin_version: String,

    /// Detected/configured languages in this repo.
    #[serde(default)]
    pub languages: Vec<String>,

    /// Registered assistant adapters.
    #[serde(default)]
    pub adapters: Vec<String>,

    /// Unique repository identifier.
    ///
    /// A UUID v4 when this build minted it. A replica that adopted another
    /// repository's identity carries that identity verbatim instead, which is
    /// how a hosted slug reaches a local manifest, so nothing may read this
    /// field as UUID text without handling the case where it is not.
    pub repo_id: String,

    /// Unique identity of this local materialized workspace (UUID v4).
    ///
    /// This is deliberately distinct from `repo_id`: two clones share
    /// repository truth but must never share local workspace/session authority.
    ///
    /// Defaults to empty on load so a manifest written before this field
    /// existed still parses; the layout version gate, not a serde error, is
    /// what refuses a repository this build cannot serve. Consumers that need
    /// workspace identity must validate it or mint one via
    /// [`Self::ensure_workspace_identity`].
    #[serde(default)]
    pub workspace_id: String,

    /// Timestamp of repository creation.
    pub created_at: String,

    /// Where admitted Git history ends, when `kin init --history-limit` bounded
    /// it.
    ///
    /// Absent on every repository admitted with whole history, which is the
    /// default and every repository written before this field existed, so its
    /// absence means "nothing was cut" and never "nobody recorded it". A reader
    /// that finds it present must not describe the oldest change as the point
    /// where the repository began, because it is the point where admission
    /// began and the Git commits before it are in this store as Git objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history_boundary: Option<ManifestHistoryBoundary>,
}

/// The durable form of a bounded admission's edge.
///
/// Kept in the manifest rather than derived on demand, because the only way to
/// derive it is to notice that the oldest change's Git commit has parents the
/// graph does not hold, and a reader that has to infer a boundary is a reader
/// that will sometimes infer it wrongly. Object ids are hex strings so this
/// record stays readable by anything that can read JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestHistoryBoundary {
    /// The `--history-limit N` the operator asked for.
    pub requested_limit: usize,
    /// Commits actually admitted into the semantic graph.
    pub admitted_commits: usize,
    /// Oldest admitted Git commit. Admitted history starts here.
    pub oldest_admitted_commit: String,
    /// Git commits that are parents of an admitted commit and were not
    /// admitted: the first entry of the mainline edge, plus every side branch
    /// a merge in the window reached for.
    pub unadmitted_parents: Vec<String>,
}

/// The admitted-history boundary this repository recorded, if any.
///
/// Returns `None` both for a whole-history repository and for a manifest this
/// build cannot read, and the two are the same answer on purpose: every command
/// that calls this is about to describe history, and the honest description of
/// an unreadable manifest is the one that claims no boundary rather than one it
/// invented. A store whose manifest cannot be read has larger problems, and the
/// commands that open the authority report them.
pub fn history_boundary_for(layout: &KinLayout) -> Option<ManifestHistoryBoundary> {
    KinManifest::load(&layout.manifest_path())
        .ok()
        .and_then(|manifest| manifest.history_boundary)
}

impl ManifestHistoryBoundary {
    /// One sentence a command prints about where admitted history ends.
    pub fn summary(&self) -> String {
        format!(
            "admitted history starts at Git commit {}, the oldest of {} commit(s) admitted under              `--history-limit {}`; {} older or side-branch Git commit(s) are in this store as Git              objects and are not in the semantic graph",
            self.oldest_admitted_commit,
            self.admitted_commits,
            self.requested_limit,
            self.unadmitted_parents.len(),
        )
    }
}

impl Default for KinManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of comparing a repo's recorded `kin_version` against this binary's
/// minimum-compatible floor ([`MIN_COMPATIBLE_KIN_VERSION`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestCompatibility {
    /// The recorded version meets or exceeds the floor (or is unparseable and
    /// therefore not provably old — see [`classify_kin_version`]).
    Compatible,
    /// The recorded version predates the floor and the repo must be rebuilt
    /// before this binary can open it.
    TooOld { found: String },
}

impl ManifestCompatibility {
    /// Whether the repo can be opened by this binary.
    pub fn is_compatible(&self) -> bool {
        matches!(self, ManifestCompatibility::Compatible)
    }

    /// An actionable, user-facing message describing the version gap and how to
    /// resolve it, or `None` when the repo is compatible. Names the recorded
    /// version, the required floor, and the two rebuild paths (`kin migrate` /
    /// `kin embed --rebuild`).
    pub fn incompatibility_message(&self) -> Option<String> {
        match self {
            ManifestCompatibility::Compatible => None,
            ManifestCompatibility::TooOld { found } => Some(format!(
                "this repository was created by kin {found}, but this kin build \
                 requires a repository created by kin {}.{}.x or newer. Its \
                 on-disk graph and vector index predate a breaking format change \
                 and cannot be served as-is. Run `kin migrate` to rebuild the \
                 graph from source, or `kin embed --rebuild` to rebuild the \
                 vector index at the current model dimension.",
                MIN_COMPATIBLE_KIN_VERSION.0, MIN_COMPATIBLE_KIN_VERSION.1
            )),
        }
    }
}

/// Parse the leading `MAJOR.MINOR` from a `kin_version` string, ignoring any
/// patch / pre-release suffix. Returns `None` when major or minor are not
/// numeric.
fn parse_major_minor(version: &str) -> Option<(u64, u64)> {
    let mut parts = version.trim().split('.');
    let major = parts.next()?.trim().parse::<u64>().ok()?;
    // A patch/pre-release suffix may ride on the minor segment (e.g. "2-rc1");
    // take the leading run of digits so it still parses.
    let minor_segment = parts.next()?.trim();
    let minor_digits: String = minor_segment
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let minor = minor_digits.parse::<u64>().ok()?;
    Some((major, minor))
}

/// Classify a recorded `kin_version` against [`MIN_COMPATIBLE_KIN_VERSION`].
///
/// An unparseable version is treated as [`ManifestCompatibility::Compatible`]:
/// the gate only blocks a version it can prove is older than the floor, never a
/// version it merely fails to understand. (`KinManifest::new` always stamps a
/// valid semver, so unparseable should not occur for repos this binary made.)
pub fn classify_kin_version(version: &str) -> ManifestCompatibility {
    match parse_major_minor(version) {
        Some(found) if found < MIN_COMPATIBLE_KIN_VERSION => ManifestCompatibility::TooOld {
            found: version.trim().to_string(),
        },
        _ => ManifestCompatibility::Compatible,
    }
}

impl KinManifest {
    /// Create a new manifest for a freshly initialized repository.
    pub fn new() -> Self {
        Self {
            kin_version: env!("CARGO_PKG_VERSION").to_string(),
            languages: Vec::new(),
            adapters: Vec::new(),
            repo_id: uuid::Uuid::new_v4().to_string(),
            workspace_id: uuid::Uuid::new_v4().to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            history_boundary: None,
        }
    }

    /// Create a manifest for a replica that adopts an existing repository
    /// identity rather than minting one.
    ///
    /// `repo_id` is written verbatim, because a replica that altered the
    /// identity it was given would be unable to exchange history with the
    /// repository it came from. The workspace identity is still minted: two
    /// replicas share repository truth and must never share local
    /// workspace/session authority.
    ///
    /// Shape is not validated here. `prepare_repository_layout_with_origin`
    /// decides it, and what it admits depends on where the identity came from:
    /// an adopted one must be one portable filesystem component, because a
    /// local store is a directory named by its repository id, and a minted one
    /// must be a UUID v4. Workspace identity is a UUID v4 either way, and the
    /// pair is refused when they are equal. So an identity this build cannot
    /// serve is refused before any repository layout is staged.
    pub fn adopting(repo_id: impl Into<String>) -> Self {
        Self {
            repo_id: repo_id.into(),
            ..Self::new()
        }
    }

    /// Load manifest from a JSON file.
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
        let manifest: Self = serde_json::from_str(&contents)?;
        Ok(manifest)
    }

    /// Save manifest to a JSON file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let contents = serde_json::to_string_pretty(self)?;
        std::fs::write(path, contents).map_err(|e| KinError::io(path, e))?;
        Ok(())
    }

    /// Classify this manifest's recorded `kin_version` against the
    /// minimum-compatible floor ([`MIN_COMPATIBLE_KIN_VERSION`]).
    pub fn compatibility(&self) -> ManifestCompatibility {
        classify_kin_version(&self.kin_version)
    }

    /// Whether a repo with this manifest can be opened by this binary.
    pub fn is_compatible(&self) -> bool {
        self.compatibility().is_compatible()
    }
}

/// Read ONLY the `kin_version` from a `.kin/manifest.json` and classify it
/// against [`MIN_COMPATIBLE_KIN_VERSION`].
///
/// Deliberately resilient: it deserializes just the version field, so an older
/// or partial manifest (one that predates fields this build expects) still
/// gates correctly rather than failing with an opaque parse error. A missing
/// file yields [`ManifestCompatibility::Compatible`] — callers decide how to
/// treat an absent manifest — and a manifest with no `kin_version` is likewise
/// treated as compatible rather than blocked.
pub fn check_manifest_compatibility(path: &Path) -> Result<ManifestCompatibility> {
    if !path.exists() {
        return Ok(ManifestCompatibility::Compatible);
    }
    #[derive(Deserialize)]
    struct VersionProbe {
        #[serde(default)]
        kin_version: Option<String>,
    }
    let contents = std::fs::read_to_string(path).map_err(|e| KinError::io(path, e))?;
    let probe: VersionProbe = serde_json::from_str(&contents)?;
    Ok(match probe.kin_version {
        Some(version) => classify_kin_version(&version),
        None => ManifestCompatibility::Compatible,
    })
}

/// Resolve the canonical repo id for a discovered Kin layout.
///
/// If `explicit_override` is present and non-empty, it wins. Otherwise the
/// repo id is read from `.kin/manifest.json`.
pub fn resolve_repo_id(layout: &KinLayout, explicit_override: Option<&str>) -> Result<String> {
    if let Some(repo_id) = explicit_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(repo_id.to_string());
    }

    Ok(KinManifest::load(&layout.manifest_path())?.repo_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_manifest_has_version() {
        let manifest = KinManifest::new();
        assert_eq!(manifest.kin_version, env!("CARGO_PKG_VERSION"));
        assert!(!manifest.repo_id.is_empty());
        assert!(!manifest.workspace_id.is_empty());
        assert_ne!(manifest.repo_id, manifest.workspace_id);
        assert!(!manifest.created_at.is_empty());
    }

    #[test]
    fn save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        let manifest = KinManifest::new();
        manifest.save(&path).unwrap();

        let loaded = KinManifest::load(&path).unwrap();
        assert_eq!(loaded.kin_version, manifest.kin_version);
        assert_eq!(loaded.repo_id, manifest.repo_id);
        assert_eq!(loaded.workspace_id, manifest.workspace_id);
    }

    #[test]
    fn json_roundtrip() {
        let manifest = KinManifest::new();
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: KinManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.repo_id, manifest.repo_id);
        assert_eq!(parsed.workspace_id, manifest.workspace_id);
    }

    #[test]
    fn legacy_manifest_without_workspace_id_parses() {
        // The exact field set released 0.3.6 wrote. It must parse, so the
        // layout gate can refuse in its own voice instead of a serde error.
        let legacy = r#"{
  "kin_version": "0.3.6",
  "languages": [],
  "adapters": [],
  "repo_id": "54c48711-e6f0-4950-b00d-5585b59188fe",
  "created_at": "2026-07-28T03:10:45.730166+00:00"
}"#;
        let parsed: KinManifest = serde_json::from_str(legacy).unwrap();
        assert_eq!(parsed.repo_id, "54c48711-e6f0-4950-b00d-5585b59188fe");
        assert!(parsed.workspace_id.is_empty());
    }

    #[test]
    fn resolve_repo_id_prefers_explicit_override() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let manifest = KinManifest::new();
        manifest.save(&kin_dir.join("manifest.json")).unwrap();
        let layout = KinLayout::new(kin_dir);

        let resolved = resolve_repo_id(&layout, Some("explicit-repo")).unwrap();
        assert_eq!(resolved, "explicit-repo");
    }

    #[test]
    fn resolve_repo_id_reads_manifest_identity() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let manifest = KinManifest::new();
        manifest.save(&kin_dir.join("manifest.json")).unwrap();
        let layout = KinLayout::new(kin_dir);

        let resolved = resolve_repo_id(&layout, None).unwrap();
        assert_eq!(resolved, manifest.repo_id);
    }

    #[test]
    fn classify_rejects_pre_floor_versions() {
        assert_eq!(
            classify_kin_version("0.1.0"),
            ManifestCompatibility::TooOld {
                found: "0.1.0".to_string()
            }
        );
        assert_eq!(
            classify_kin_version("0.0.9"),
            ManifestCompatibility::TooOld {
                found: "0.0.9".to_string()
            }
        );
    }

    #[test]
    fn classify_accepts_floor_and_newer() {
        assert_eq!(
            classify_kin_version("0.2.0"),
            ManifestCompatibility::Compatible
        );
        assert_eq!(
            classify_kin_version("0.2.5"),
            ManifestCompatibility::Compatible
        );
        assert_eq!(
            classify_kin_version("0.3.0"),
            ManifestCompatibility::Compatible
        );
        assert_eq!(
            classify_kin_version("1.0.0"),
            ManifestCompatibility::Compatible
        );
    }

    #[test]
    fn classify_is_lenient_on_unparseable_versions() {
        // A version we cannot understand is never blocked — only provably-old
        // versions are refused.
        assert_eq!(classify_kin_version(""), ManifestCompatibility::Compatible);
        assert_eq!(
            classify_kin_version("garbage"),
            ManifestCompatibility::Compatible
        );
        assert_eq!(classify_kin_version("0"), ManifestCompatibility::Compatible);
    }

    #[test]
    fn classify_handles_prerelease_suffix_on_minor() {
        assert_eq!(
            classify_kin_version("0.1-rc1"),
            ManifestCompatibility::TooOld {
                found: "0.1-rc1".to_string()
            }
        );
        assert_eq!(
            classify_kin_version("0.2-rc1"),
            ManifestCompatibility::Compatible
        );
    }

    #[test]
    fn current_build_version_is_compatible() {
        // The version this binary stamps into fresh manifests must always pass
        // its own floor — otherwise `kin init` would create unopenable repos.
        assert!(KinManifest::new().is_compatible());
    }

    #[test]
    fn incompatibility_message_names_gap_and_fix_commands() {
        let message = classify_kin_version("0.1.0")
            .incompatibility_message()
            .expect("0.1.0 is below the floor");
        assert!(message.contains("0.1.0"));
        assert!(message.contains("0.2"));
        assert!(message.contains("kin migrate"));
        assert!(message.contains("kin embed --rebuild"));
        // Compatible versions carry no message.
        assert!(classify_kin_version("0.2.0")
            .incompatibility_message()
            .is_none());
    }

    #[test]
    fn check_manifest_compatibility_gates_tiny_old_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        // A minimal manifest with only the version field — the probe reads just
        // `kin_version`, so it gates without the other fields being present.
        std::fs::write(&path, r#"{"kin_version":"0.1.0"}"#).unwrap();
        assert_eq!(
            check_manifest_compatibility(&path).unwrap(),
            ManifestCompatibility::TooOld {
                found: "0.1.0".to_string()
            }
        );
    }

    #[test]
    fn check_manifest_compatibility_missing_file_is_compatible() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.json");
        assert_eq!(
            check_manifest_compatibility(&path).unwrap(),
            ManifestCompatibility::Compatible
        );
    }

    #[test]
    fn check_manifest_compatibility_accepts_current_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");
        KinManifest::new().save(&path).unwrap();
        assert_eq!(
            check_manifest_compatibility(&path).unwrap(),
            ManifestCompatibility::Compatible
        );
    }
}
