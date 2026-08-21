// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use crate::error::KinError;

/// Current `.kin/` directory schema version.
///
/// Bump this when the layout changes in a way that requires migration.
pub const KIN_LAYOUT_VERSION: u32 = 2;

/// The `.kin/` directory layout.
///
/// All paths are computed lazily from a single `root` — the `.kin/` directory.
#[derive(Debug, Clone)]
pub struct KinLayout {
    root: PathBuf,
}

impl KinLayout {
    /// Create a layout rooted at the given `.kin/` directory.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// Discover the `.kin/` directory by walking up from `start`.
    ///
    /// Returns `None` if no `.kin/` directory is found. The managed install
    /// root `~/.kin` is the cross-repo registry, binary, shim and model root,
    /// not a servable repo. Discovery skips it so running outside any repo does
    /// not resolve to the toolchain directory and spawn a daemon that fails
    /// `resolve_repo_id` against a non-existent manifest. It is recognized by
    /// the entries it carries rather than by where this process's `$HOME`
    /// points; see [`is_managed_kin_home`] for why that distinction is the
    /// whole guard.
    ///
    /// Discovery also refuses to bind a parent store across a nested-repository
    /// boundary: if the walk passes a directory that is itself a repository root
    /// (it has a `.git`) without its own `.kin/`, then a `.kin/` found higher up
    /// belongs to a different repository and is not bound — the nested repo is
    /// reported as having no store rather than silently sharing the parent's
    /// graph (the failure mode behind the parent-store poisoning incident). Set
    /// `KIN_ALLOW_PARENT_STORE=1` to opt back into binding the parent store.
    ///
    /// Repository discovery is always filesystem-rooted. A daemon endpoint is
    /// transport configuration, not evidence that `<start>/.kin` exists or
    /// belongs to the endpoint's repository.
    pub fn discover(start: &Path) -> Option<Self> {
        let mut current = start.to_path_buf();
        let mut crossed_boundary: Option<PathBuf> = None;
        loop {
            let candidate = current.join(".kin");
            if candidate.is_dir() && !is_managed_kin_home(&candidate) {
                if let Some(boundary) = &crossed_boundary {
                    if std::env::var("KIN_ALLOW_PARENT_STORE").is_err() {
                        eprintln!(
                            "kin: refusing to bind the parent store at {} across the repository \
                             boundary at {} (the nested repository has no .kin/ of its own). Run \
                             `kin init` here to create its own store, or set \
                             KIN_ALLOW_PARENT_STORE=1 to bind the parent store explicitly.",
                            candidate.display(),
                            boundary.display(),
                        );
                        return None;
                    }
                }
                return Some(Self::new(candidate));
            }
            if crossed_boundary.is_none() && current.join(".git").exists() {
                crossed_boundary = Some(current.clone());
            }
            if !current.pop() {
                return None;
            }
        }
    }

    /// The `.kin/` root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The working directory (parent of `.kin/`).
    pub fn working_dir(&self) -> &Path {
        self.root
            .parent()
            .expect(".kin/ always has a parent directory")
    }

    /// `.kin/config.toml`
    pub fn config_path(&self) -> PathBuf {
        self.root.join("config.toml")
    }

    /// `.kin/manifest.json`
    pub fn manifest_path(&self) -> PathBuf {
        self.root.join("manifest.json")
    }

    /// `.kin/kindb/` — KinDB snapshot and index directory.
    pub fn kindb_dir(&self) -> PathBuf {
        self.root.join("kindb")
    }

    /// `.kin/kindb/ingest-cas/` — non-authoritative blob staging for explicit
    /// filesystem reconciliation.
    ///
    /// Reconcile parses exact input bytes from this cache before a repository
    /// transaction copies referenced bodies into repository-owned source CAS.
    /// Runtime history, VFS, and semantic query paths must never treat this
    /// staging directory as committed repository authority.
    pub fn ingest_cas_dir(&self) -> PathBuf {
        self.kindb_dir().join("ingest-cas")
    }

    /// `.kin/kindb/graph.kndb` — KinDB snapshot file.
    pub fn kindb_snapshot_path(&self) -> PathBuf {
        self.kindb_dir().join("graph.kndb")
    }

    /// `.kin/kindb/head-generation` — daemon-published durable authority head.
    ///
    /// This is intentionally separate from `.kin/kindb/generation`, which is
    /// owned by KinDB as the generation of its legacy compatibility projection.
    pub fn kindb_head_generation_path(&self) -> PathBuf {
        self.kindb_dir().join("head-generation")
    }

    /// `.kin/kindb/last-admission` — when a complete exact-tree admission last
    /// succeeded.
    ///
    /// Durable rather than in-process on purpose. The reconcile probes already
    /// record this, but they record it in daemon memory, so a restart erases it
    /// and every freshness surface reports that no admission has ever succeeded.
    /// A store that has not been admitted since March then reads the same as one
    /// admitted a second ago, which is the whole defect: nothing a reader can
    /// consult says how far graph truth has fallen behind the repository.
    ///
    /// Deliberately not written by the generation-publish path. That path also
    /// runs on daemon startup, so stamping it there would refresh the timestamp
    /// on every restart and manufacture exactly the false freshness this marker
    /// exists to prevent. It is written only where an admission actually
    /// succeeded.
    pub fn kindb_last_admission_path(&self) -> PathBuf {
        self.kindb_dir().join("last-admission")
    }

    /// `.kin/kindb/relation-census` — the relation-kind histogram as it stood
    /// when the graph's relations were last settled.
    ///
    /// Durable rather than in-process for the same reason the last-admission
    /// marker beside it is: a census is only interpretable against the census
    /// before it, and an in-memory one dies with the daemon that took it. It is
    /// written where relations actually change, at the end of a completed
    /// enrichment sweep and at the end of a commit, and never on a read path.
    /// Stamping it from `graph status` would make every reading compare against
    /// the reading before it, so a store that lost a whole relation kind would
    /// announce the loss once and then report itself clean forever.
    pub fn kindb_relation_census_path(&self) -> PathBuf {
        self.kindb_dir().join("relation-census")
    }

    /// `.kin/kindb/graph.kvec` — persisted vector index aligned with the snapshot.
    pub fn kindb_vector_index_path(&self) -> PathBuf {
        self.kindb_snapshot_path().with_extension("kvec")
    }

    /// `.kin/kindb/embedding-coverage-complete` — daemon-published marker that
    /// this store's embedding coverage has been whole at least once.
    ///
    /// Partial coverage on its own cannot say whether a store is filling for
    /// the first time or lost ground it already held, and only the second is
    /// something to act on. The marker is what separates them.
    pub fn kindb_embedding_coverage_marker_path(&self) -> PathBuf {
        self.kindb_dir().join("embedding-coverage-complete")
    }

    /// `.kin/kindb/text-index/` — Persistent tantivy text index directory.
    pub fn text_index_dir(&self) -> PathBuf {
        self.kindb_dir().join("text-index")
    }

    /// `.kin/stashes/` — Named overlay snapshots.
    pub fn stashes_dir(&self) -> PathBuf {
        self.root.join("stashes")
    }

    /// `.kin/backups/` — Graph snapshot backups.
    pub fn backups_dir(&self) -> PathBuf {
        self.root.join("backups")
    }

    /// `.kin/projections/` — Generated file/doc projections.
    pub fn projections_dir(&self) -> PathBuf {
        self.root.join("projections")
    }

    /// `.kin/docs/` — Living docs (AGENTS.md, ARCHITECTURE.md, etc.).
    pub fn docs_dir(&self) -> PathBuf {
        self.root.join("docs")
    }

    /// `.kin/bench/` — Benchmark traces and reports.
    pub fn bench_dir(&self) -> PathBuf {
        self.root.join("bench")
    }

    /// `.kin/runs/` — Validation run evidence.
    pub fn runs_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    /// `.kin/logs/` — Daemon logs.
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `.kin/adapters/` — Assistant adapter config.
    pub fn adapters_dir(&self) -> PathBuf {
        self.root.join("adapters")
    }

    /// `.kin/shallow/` — Persisted C2 shallow-syntax metadata.
    pub fn shallow_dir(&self) -> PathBuf {
        self.root.join("shallow")
    }

    /// `.kin/version` — layout schema version marker.
    pub fn version_path(&self) -> PathBuf {
        self.root.join("version")
    }

    /// Read the schema version from the `.kin/version` file.
    ///
    /// Returns version 1 if the file does not exist (pre-versioning repos).
    pub fn read_version(&self) -> Result<u32, KinError> {
        let path = self.version_path();
        if !path.exists() {
            return Ok(1);
        }
        let text = std::fs::read_to_string(&path).map_err(|e| KinError::io(&path, e))?;
        text.trim().parse::<u32>().map_err(|_| {
            KinError::Config(format!("invalid version in {}: {text:?}", path.display()))
        })
    }

    /// Verify that this binary can read the `.kin/` directory.
    ///
    /// Returns an error unless the on-disk version is exactly current.
    ///
    /// Version 2 is the clean-slate repository-authority layout. Older
    /// file/branch-authority layouts must not be served as if they carried v6
    /// refs and workspaces.
    pub fn check_version(&self) -> Result<(), KinError> {
        let current = self.read_version()?;
        if current != KIN_LAYOUT_VERSION {
            return Err(KinError::IncompatibleVersion {
                found: current,
                supported: KIN_LAYOUT_VERSION,
            });
        }
        Ok(())
    }

    /// Write the `.kin/version` marker, stamping the layout at `version`.
    fn write_version(&self, version: u32) -> Result<(), KinError> {
        let path = self.version_path();
        std::fs::write(&path, version.to_string()).map_err(|e| KinError::io(&path, e))
    }

    /// Bring the on-disk `.kin/` layout up to the version this binary writes.
    ///
    /// This is never a silent no-op:
    /// - a newer-than-supported layout is refused with [`KinError::IncompatibleVersion`];
    /// - a pre-versioning repo (no `.kin/version`) is treated as version 1 and
    ///   refused because no compatibility migration can manufacture v6
    ///   repository authority;
    /// - an older layout is walked forward one step at a time via [`Self::migrate_step`],
    ///   which transforms `v -> v+1` on disk or **loudly refuses** when no step is
    ///   registered for that version. An older layout is never accepted as-is.
    ///
    /// When the on-disk version already equals [`KIN_LAYOUT_VERSION`] there is
    /// genuinely nothing to do and `Ok(())` is returned without touching disk.
    pub fn migrate(&self) -> Result<(), KinError> {
        let mut current = self.read_version()?;
        if current > KIN_LAYOUT_VERSION {
            return Err(KinError::IncompatibleVersion {
                found: current,
                supported: KIN_LAYOUT_VERSION,
            });
        }

        while current < KIN_LAYOUT_VERSION {
            self.migrate_step(current)?;
            current += 1;
            self.write_version(current)?;
        }
        Ok(())
    }

    /// Apply the single migration that upgrades the on-disk layout from `from`
    /// to `from + 1`.
    ///
    /// Each future breaking layout change registers its step in the `match`
    /// below (e.g. `1 => self.migrate_v1_to_v2(),`). A version with no
    /// registered step is refused loudly rather than skipped, so an old `.kin/`
    /// can never be served against a binary that does not know how to upgrade
    /// it.
    fn migrate_step(&self, from: u32) -> Result<(), KinError> {
        // Register future migration steps here, lowest version first. Until
        // one exists, every old authority is deliberately refused.
        Err(KinError::Config(format!(
            "no migration path for .kin/ layout version {from} -> {next}: \
             this repository predates a breaking layout change that this kin \
             build cannot auto-upgrade. Re-run `kin init` in a fresh checkout \
             or restore from a backup made with a matching kin version.",
            next = from + 1,
        )))
    }

    /// `.kin/sync_state.json` — persisted sync state per remote.
    pub fn sync_state_path(&self) -> PathBuf {
        self.root.join("sync_state.json")
    }

    /// `.kin/merge_state.json` — persisted merge conflict state.
    ///
    /// Written by `kin merge` when conflicts are detected, read by
    /// `kin conflicts` and `kin resolve`, cleared on resolution or abort.
    pub fn merge_state_path(&self) -> PathBuf {
        self.root.join("merge_state.json")
    }

    /// `.kin/pending-release.json` — exact serialized daemon release request
    /// retained until the daemon reports durable success or definitive
    /// rejection. This lets a later CLI process resume an uncertain timeout or
    /// transport failure without constructing a second release marker.
    pub fn pending_release_path(&self) -> PathBuf {
        self.root.join("pending-release.json")
    }

    /// `.kin/pending-release.lock` — cross-process serialization for release
    /// recovery, policy preflight, and marker construction.
    pub fn pending_release_lock_path(&self) -> PathBuf {
        self.root.join("pending-release.lock")
    }

    /// All directories that must exist inside `.kin/`.
    ///
    pub fn all_dirs(&self) -> Vec<PathBuf> {
        vec![
            self.kindb_dir(),
            self.ingest_cas_dir(),
            self.stashes_dir(),
            self.backups_dir(),
            self.projections_dir(),
            self.docs_dir(),
            self.bench_dir(),
            self.runs_dir(),
            self.logs_dir(),
            self.adapters_dir(),
            self.shallow_dir(),
        ]
    }
}

/// The global home Kin directory `~/.kin` — the cross-repo registry/cache root,
/// not a servable repo. Returns `None` when no home directory is resolvable.
pub fn global_home_kin_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|dirs| dirs.home_dir().join(".kin"))
}

/// Entries a managed Kin install root carries and a repository store never
/// does: the cross-repo registry, the installed binaries, the injected shim,
/// and the shell hooks.
///
/// [`KinLayout`] has no accessor for any of these names, and that is the point.
/// Finding them inside a `.kin` is evidence about what the directory *is*,
/// which is an answer no environment variable can contradict.
const MANAGED_HOME_MARKERS: [&str; 4] = ["registry.toml", "bin", "lib", "shell"];

/// How many markers settle it.
///
/// One could be an accident, say a stray `bin/` somebody dropped inside a
/// repository store. Two together are the installer's fingerprint. A store has
/// no reason to grow even one, so a quorum of two errs toward still resolving a
/// real repository, which is the direction this guard must fail in: refusing a
/// user's own store is worse than binding an install root, and binding an
/// install root is what this exists to stop.
const MANAGED_HOME_MARKER_QUORUM: usize = 2;

/// Whether `candidate` holds enough toolchain-owned entries to be an install
/// root. Pure over the path, so it is decided by the directory rather than by
/// the environment the caller happens to have.
fn carries_managed_home_markers(candidate: &Path) -> bool {
    MANAGED_HOME_MARKERS
        .iter()
        .filter(|name| candidate.join(name).exists())
        .count()
        >= MANAGED_HOME_MARKER_QUORUM
}

/// Whether two paths name the same directory, comparing canonical forms too so
/// symlinked or non-normalized paths (a `/var` vs `/private/var` home on macOS)
/// still match.
fn same_dir(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize().ok(), b.canonicalize().ok()) {
        (Some(x), Some(y)) => x == y,
        _ => false,
    }
}

/// Whether `candidate` is a directory the Kin toolchain owns — the managed
/// install root holding the registry, the binaries, the shim and the models —
/// rather than a repository store that can be served.
///
/// Two tests, and the order is the fix. The first asks what the directory *is*,
/// by the entries only an install root carries. The second is the older
/// question of whether the path *is where this process's install root would
/// be*, kept because a freshly created home carrying one marker or none is
/// still not a repository.
///
/// Identity alone was the defect. It resolved the install root from the running
/// process's `$HOME`, so a process whose home was not the home that owns the
/// `.kin` being walked into compared two different paths, found them unequal,
/// and bound the toolchain directory as a repository. Every `kin` command in
/// that process then addressed the wrong root, not just `kin doctor`. A CI
/// runner with a redirected home, a `sudo` or service context, a container
/// mounting a host home, and every rig that isolates `HOME` all land there.
/// Asking what the directory holds is an answer none of them can change.
///
/// The manifest escape stays on the identity arm only. A `.kin` that is where
/// this process's install root would be, and carries a `manifest.json`, and
/// carries no toolchain markers, is somebody's repository sitting at that path,
/// and it is still bound. A directory carrying the markers is the install root
/// whatever else appears in it, so planting a `manifest.json` there does not
/// turn it into a repository.
fn is_managed_kin_home(candidate: &Path) -> bool {
    if carries_managed_home_markers(candidate) {
        return true;
    }
    let identities = [
        global_home_kin_dir(),
        Some(crate::registry::managed_kin_home()),
    ];
    for home in identities.into_iter().flatten() {
        if same_dir(candidate, &home) {
            return !candidate.join("manifest.json").exists();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_paths() {
        let layout = KinLayout::new(PathBuf::from("/repo/.kin"));
        assert_eq!(
            layout.config_path(),
            PathBuf::from("/repo/.kin/config.toml")
        );
        assert_eq!(
            layout.manifest_path(),
            PathBuf::from("/repo/.kin/manifest.json")
        );
        assert_eq!(layout.kindb_dir(), PathBuf::from("/repo/.kin/kindb"));
        assert_eq!(
            layout.ingest_cas_dir(),
            PathBuf::from("/repo/.kin/kindb/ingest-cas")
        );
        assert_eq!(
            layout.kindb_snapshot_path(),
            PathBuf::from("/repo/.kin/kindb/graph.kndb")
        );
        assert_eq!(
            layout.kindb_head_generation_path(),
            PathBuf::from("/repo/.kin/kindb/head-generation")
        );
        assert_eq!(layout.working_dir(), Path::new("/repo"));
    }

    #[test]
    fn all_dirs_count() {
        let layout = KinLayout::new(PathBuf::from("/repo/.kin"));
        // kindb, ingest-cas, stashes, backups, projections, docs, bench, runs,
        // logs, adapters, shallow
        assert_eq!(layout.all_dirs().len(), 11);
    }

    #[test]
    fn discover_finds_kin_dir() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();

        let found = KinLayout::discover(dir.path()).unwrap();
        assert_eq!(found.root(), kin_dir);
    }

    #[test]
    fn discover_walks_up() {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let sub = dir.path().join("src").join("deep");
        std::fs::create_dir_all(&sub).unwrap();

        let found = KinLayout::discover(&sub).unwrap();
        assert_eq!(found.root(), kin_dir);
    }

    #[test]
    fn discover_returns_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(KinLayout::discover(dir.path()).is_none());
    }

    #[test]
    fn discover_requires_a_real_kin_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(KinLayout::discover(dir.path()).is_none());

        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let found = KinLayout::discover(dir.path()).unwrap();
        assert_eq!(found.root(), kin_dir);
    }

    #[test]
    fn discover_refuses_parent_store_across_nested_repo_boundary() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join(".kin")).unwrap();
        let nested = dir.path().join("nested");
        std::fs::create_dir_all(nested.join(".git")).unwrap();
        let deep = nested.join("src");
        std::fs::create_dir_all(&deep).unwrap();

        assert!(
            KinLayout::discover(&deep).is_none(),
            "must refuse to bind a parent .kin across a nested-repo (.git) boundary"
        );

        std::fs::create_dir(nested.join(".kin")).unwrap();
        let found = KinLayout::discover(&deep).unwrap();
        assert_eq!(
            found.root(),
            nested.join(".kin"),
            "a nested repo with its own .kin binds that store, not the parent"
        );
    }

    #[test]
    fn is_managed_kin_home_rejects_unrelated_and_repo_paths() {
        // A normal repo `.kin` (carrying a manifest) is never the install root.
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        std::fs::write(kin_dir.join("manifest.json"), "{}").unwrap();
        assert!(!is_managed_kin_home(&kin_dir));

        // An unrelated `.kin` path that is not the install root is never the
        // install root either, regardless of manifest presence.
        let bare = dir.path().join("sub").join(".kin");
        std::fs::create_dir_all(&bare).unwrap();
        assert!(!is_managed_kin_home(&bare));
    }

    /// Build a `.kin` that looks exactly like what the installer leaves behind:
    /// the cross-repo registry, the installed binaries, the shim and the hooks.
    fn managed_install_root(at: &Path) -> PathBuf {
        let managed = at.join(".kin");
        std::fs::create_dir_all(managed.join("bin")).unwrap();
        std::fs::create_dir_all(managed.join("lib")).unwrap();
        std::fs::create_dir_all(managed.join("shell")).unwrap();
        std::fs::write(managed.join("registry.toml"), "").unwrap();
        managed
    }

    /// The defect FIR-2018 and FIR-2014 both describe, from the side that
    /// produced it: a process whose `$HOME` is not the home owning the `.kin`
    /// the walk reaches. The identity comparison cannot save this case, so what
    /// the directory holds has to.
    #[test]
    fn discover_refuses_the_install_root_when_home_is_elsewhere() {
        let scratch = tempfile::tempdir().unwrap();
        let toolchain = scratch.path().join("toolchain");
        let managed = managed_install_root(&toolchain);
        let cwd = toolchain.join("sub");
        std::fs::create_dir_all(&cwd).unwrap();

        let elsewhere = scratch.path().join("otherhome");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let _home = crate::test_env::EnvVarGuard::set("HOME", &elsewhere);
        let _kin_home = crate::test_env::EnvVarGuard::unset("KIN_HOME");
        let _kin_dir = crate::test_env::EnvVarGuard::unset("KIN_DIR");

        let found = KinLayout::discover(&cwd);
        assert!(
            found.is_none(),
            "discover bound the managed install root at {:?} because $HOME pointed elsewhere",
            found.map(|layout| layout.root().to_path_buf())
        );
        // The install root really was there to be found, so the assertion above
        // is about the guard rather than about an empty walk.
        assert!(managed.is_dir(), "the fixture install root must exist");
    }

    /// The same directory, with `$HOME` set to the home that owns it. This is
    /// the arm the old identity comparison already handled, and it must keep
    /// working: a fix that only moved the failure to the correct-home case
    /// would pass the test above and still be wrong.
    #[test]
    fn discover_refuses_the_install_root_when_home_is_its_own() {
        let scratch = tempfile::tempdir().unwrap();
        let toolchain = scratch.path().join("toolchain");
        managed_install_root(&toolchain);
        let cwd = toolchain.join("sub");
        std::fs::create_dir_all(&cwd).unwrap();

        let _home = crate::test_env::EnvVarGuard::set("HOME", &toolchain);
        let _kin_home = crate::test_env::EnvVarGuard::unset("KIN_HOME");
        let _kin_dir = crate::test_env::EnvVarGuard::unset("KIN_DIR");

        let found = KinLayout::discover(&cwd);
        assert!(
            found.is_none(),
            "discover bound the managed install root at {:?} under its own home",
            found.map(|layout| layout.root().to_path_buf())
        );
    }

    /// A `manifest.json` planted in the install root does not promote it to a
    /// repository. FIR-2014 names this as its own acceptance line, because the
    /// old guard read the manifest as proof of a real repo and would have been
    /// flipped by one file.
    #[test]
    fn a_planted_manifest_does_not_make_the_install_root_a_repository() {
        let scratch = tempfile::tempdir().unwrap();
        let toolchain = scratch.path().join("toolchain");
        let managed = managed_install_root(&toolchain);
        std::fs::write(managed.join("manifest.json"), "{}").unwrap();
        let cwd = toolchain.join("sub");
        std::fs::create_dir_all(&cwd).unwrap();

        let _home = crate::test_env::EnvVarGuard::set("HOME", &toolchain);
        let _kin_home = crate::test_env::EnvVarGuard::unset("KIN_HOME");
        let _kin_dir = crate::test_env::EnvVarGuard::unset("KIN_DIR");

        assert!(
            KinLayout::discover(&cwd).is_none(),
            "a manifest planted in the install root turned it into a repository"
        );
    }

    /// The blast radius the ticket named, held open on purpose. A repository
    /// part way through `kin init`, before its manifest exists, still resolves,
    /// because it carries none of the toolchain's entries. A guard written as
    /// "a `.kin` with no manifest is not a repository" would fail here, which is
    /// exactly why this fix does not do that.
    #[test]
    fn a_repository_without_its_manifest_yet_still_resolves() {
        let scratch = tempfile::tempdir().unwrap();
        let repo = scratch.path().join("repo");
        let store = repo.join(".kin");
        std::fs::create_dir_all(store.join("kindb")).unwrap();
        let cwd = repo.join("src");
        std::fs::create_dir_all(&cwd).unwrap();

        let elsewhere = scratch.path().join("otherhome");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let _home = crate::test_env::EnvVarGuard::set("HOME", &elsewhere);
        let _kin_home = crate::test_env::EnvVarGuard::unset("KIN_HOME");
        let _kin_dir = crate::test_env::EnvVarGuard::unset("KIN_DIR");

        let found = KinLayout::discover(&cwd).expect("a store mid-init must still be discovered");
        assert_eq!(found.root(), store);
    }

    /// `KIN_HOME` relocates the install root, and a relocated root that has not
    /// yet grown two markers is still not a repository.
    #[test]
    fn discover_refuses_a_relocated_install_root_named_by_kin_home() {
        let scratch = tempfile::tempdir().unwrap();
        let relocated = scratch.path().join("relocated").join(".kin");
        std::fs::create_dir_all(&relocated).unwrap();
        let cwd = scratch.path().join("relocated").join("sub");
        std::fs::create_dir_all(&cwd).unwrap();

        let elsewhere = scratch.path().join("otherhome");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let _home = crate::test_env::EnvVarGuard::set("HOME", &elsewhere);
        let _kin_home = crate::test_env::EnvVarGuard::set("KIN_HOME", &relocated);
        let _kin_dir = crate::test_env::EnvVarGuard::unset("KIN_DIR");

        assert!(
            KinLayout::discover(&cwd).is_none(),
            "the install root named by KIN_HOME was bound as a repository"
        );
    }

    /// One marker is not a quorum. A repository store that happens to carry a
    /// `bin/` is still a repository, which is the direction this guard is
    /// deliberately built to fail in.
    #[test]
    fn one_toolchain_marker_does_not_condemn_a_repository() {
        let scratch = tempfile::tempdir().unwrap();
        let repo = scratch.path().join("repo");
        let store = repo.join(".kin");
        std::fs::create_dir_all(store.join("bin")).unwrap();
        std::fs::write(store.join("manifest.json"), "{}").unwrap();
        let cwd = repo.join("src");
        std::fs::create_dir_all(&cwd).unwrap();

        let elsewhere = scratch.path().join("otherhome");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let _home = crate::test_env::EnvVarGuard::set("HOME", &elsewhere);
        let _kin_home = crate::test_env::EnvVarGuard::unset("KIN_HOME");
        let _kin_dir = crate::test_env::EnvVarGuard::unset("KIN_DIR");

        let found = KinLayout::discover(&cwd).expect("one stray marker must not hide a repository");
        assert_eq!(found.root(), store);
    }

    #[test]
    fn global_home_kin_dir_targets_home_dot_kin() {
        if let Some(home_kin) = global_home_kin_dir() {
            assert_eq!(home_kin.file_name().and_then(|n| n.to_str()), Some(".kin"));
        }
    }

    fn empty_kin_layout() -> (tempfile::TempDir, KinLayout) {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir(&kin_dir).unwrap();
        let layout = KinLayout::new(kin_dir);
        (dir, layout)
    }

    #[test]
    fn migrate_refuses_pre_versioning_repo_without_authority() {
        let (_dir, layout) = empty_kin_layout();
        assert!(!layout.version_path().exists());
        let error = layout.migrate().unwrap_err();
        assert!(error.to_string().contains("no migration path"));
        assert!(!layout.version_path().exists());
    }

    #[test]
    fn migrate_is_noop_on_current_version() {
        let (_dir, layout) = empty_kin_layout();
        layout.write_version(KIN_LAYOUT_VERSION).unwrap();
        let before = std::fs::metadata(layout.version_path())
            .unwrap()
            .modified()
            .unwrap();
        layout.migrate().unwrap();
        // Current version: nothing rewritten.
        let after = std::fs::metadata(layout.version_path())
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn migrate_refuses_newer_layout() {
        let (_dir, layout) = empty_kin_layout();
        layout.write_version(KIN_LAYOUT_VERSION + 7).unwrap();
        match layout.migrate() {
            Err(KinError::IncompatibleVersion { found, supported }) => {
                assert_eq!(found, KIN_LAYOUT_VERSION + 7);
                assert_eq!(supported, KIN_LAYOUT_VERSION);
            }
            other => panic!("expected IncompatibleVersion, got {other:?}"),
        }
    }

    #[test]
    fn migrate_loudly_refuses_old_unmigratable_layout() {
        // Synthesize an older layout (version 0) with no registered upgrade
        // step. migrate() must refuse loudly, never silently accept it.
        let (_dir, layout) = empty_kin_layout();
        layout.write_version(0).unwrap();
        match layout.migrate() {
            Err(KinError::Config(msg)) => {
                assert!(msg.contains("no migration path"), "got: {msg}");
            }
            other => panic!("expected loud Config refusal, got {other:?}"),
        }
        // The on-disk version is left untouched by a refused migration.
        assert_eq!(layout.read_version().unwrap(), 0);
    }
}
