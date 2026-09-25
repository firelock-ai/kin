// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuildInfo {
    pub sha: &'static str,
    pub dirty: bool,
    /// Whether both the Git commit/status and locked dependency provenance were
    /// captured successfully at build time.
    pub source_known: bool,
    /// SHA-256 of the workspace Cargo.lock used for this build.
    pub dependency_provenance: &'static str,
    pub branch: &'static str,
    pub built_at: &'static str,
}

/// Versioned, fixed-width build identity embedded exactly once in each
/// release executable. The updater reads this structure as inert bytes; it
/// never executes an uninstalled candidate.
///
/// Every field is byte-aligned and explicitly encoded so the on-disk format
/// is identical across ELF, Mach-O, and PE/COFF targets.
#[repr(C)]
pub struct UpdateBuildIdentitySentinel {
    start_magic: [u8; 16],
    schema: [u8; 24],
    version: [u8; 32],
    commit: [u8; 40],
    clean: u8,
    source_known: u8,
    dependency_provenance: [u8; 64],
    graph_snapshot_version_le: [u8; 4],
    end_magic: [u8; 16],
}

pub const UPDATE_BUILD_IDENTITY_SENTINEL_LEN: usize = 198;

const UPDATE_BUILD_IDENTITY_START: [u8; 16] = [
    0x00, 0x89, b'K', b'I', b'N', b'U', b'P', b'D', b'A', b'T', b'E', 1, 0x0d, 0x0a, 0x1a, 0x0a,
];
const UPDATE_BUILD_IDENTITY_END: [u8; 16] = [
    0x00, 0x89, b'K', b'I', b'N', b'E', b'N', b'D', b'V', b'1', 0xff, 1, 0x0d, 0x0a, 0x1a, 0x0a,
];
const UPDATE_BUILD_IDENTITY_SCHEMA: &str = "kin.update-build.v1";

const fn fixed_ascii<const N: usize>(value: &str) -> [u8; N] {
    let bytes = value.as_bytes();
    assert!(
        !bytes.is_empty(),
        "static build identity fields must not be empty"
    );
    assert!(bytes.len() <= N, "static build identity field is too long");
    let mut output = [0_u8; N];
    let mut index = 0;
    while index < bytes.len() {
        assert!(
            bytes[index].is_ascii_graphic(),
            "static build identity must be canonical ASCII"
        );
        output[index] = bytes[index];
        index += 1;
    }
    output
}

const fn env_bool(value: &str) -> u8 {
    let bytes = value.as_bytes();
    let is_true = bytes.len() == 4
        && bytes[0] == b't'
        && bytes[1] == b'r'
        && bytes[2] == b'u'
        && bytes[3] == b'e';
    if is_true {
        1
    } else {
        let is_false = bytes.len() == 5
            && bytes[0] == b'f'
            && bytes[1] == b'a'
            && bytes[2] == b'l'
            && bytes[3] == b's'
            && bytes[4] == b'e';
        assert!(
            is_false,
            "static build identity booleans must be exactly true or false"
        );
        0
    }
}

impl UpdateBuildIdentitySentinel {
    pub const fn current(version: &str, graph_snapshot_version: u32) -> Self {
        assert!(
            graph_snapshot_version != 0,
            "graph snapshot version must be nonzero"
        );
        let dirty = env_bool(env!("KIN_BUILD_DIRTY"));
        Self {
            start_magic: UPDATE_BUILD_IDENTITY_START,
            schema: fixed_ascii(UPDATE_BUILD_IDENTITY_SCHEMA),
            version: fixed_ascii(version),
            commit: fixed_ascii(env!("KIN_BUILD_GIT_SHA")),
            clean: if dirty == 0 { 1 } else { 0 },
            source_known: env_bool(env!("KIN_BUILD_SOURCE_KNOWN")),
            dependency_provenance: fixed_ascii(env!("KIN_BUILD_DEPENDENCY_PROVENANCE")),
            graph_snapshot_version_le: graph_snapshot_version.to_le_bytes(),
            end_magic: UPDATE_BUILD_IDENTITY_END,
        }
    }
}

const _: () = assert!(
    std::mem::size_of::<UpdateBuildIdentitySentinel>() == UPDATE_BUILD_IDENTITY_SENTINEL_LEN
);

/// Make the static address observably reachable from the executable entry
/// point so link-time section garbage collection cannot discard it.
#[inline(never)]
pub fn retain_update_build_identity(sentinel: &'static UpdateBuildIdentitySentinel) {
    std::hint::black_box(sentinel);
}

/// Embed the shared updater identity format in a binary crate. Call
/// `retain_update_build_identity` with the generated static at process start.
#[macro_export]
macro_rules! embed_update_build_identity {
    ($name:ident, $version:expr, $graph_snapshot_version:expr) => {
        #[used]
        static $name: $crate::UpdateBuildIdentitySentinel =
            $crate::UpdateBuildIdentitySentinel::current($version, $graph_snapshot_version);
    };
}

pub fn get() -> BuildInfo {
    BuildInfo {
        sha: env!("KIN_BUILD_GIT_SHA"),
        dirty: env!("KIN_BUILD_DIRTY") == "true",
        source_known: env!("KIN_BUILD_SOURCE_KNOWN") == "true",
        dependency_provenance: env!("KIN_BUILD_DEPENDENCY_PROVENANCE"),
        branch: env!("KIN_BUILD_BRANCH"),
        built_at: env!("KIN_BUILD_TIME"),
    }
}

pub fn sha_with_dirty(info: BuildInfo) -> String {
    if info.dirty && info.sha != "unknown" {
        format!("{}-dirty", info.sha)
    } else {
        info.sha.to_string()
    }
}

pub fn version() -> &'static str {
    env!("KIN_BUILD_VERSION")
}

pub fn version_line(binary: &str) -> String {
    format!("{binary} {}", version())
}

pub fn format_version(package_version: &str, info: BuildInfo) -> String {
    format!(
        "{} ({} {} {})",
        package_version,
        sha_with_dirty(info),
        info.branch,
        info.built_at
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_includes_dirty_suffix_branch_and_time() {
        let info = BuildInfo {
            sha: "bd7cd12",
            dirty: true,
            source_known: true,
            dependency_provenance: "lock-sha",
            branch: "main",
            built_at: "2026-06-10T16:00:00Z",
        };

        assert_eq!(
            format_version("0.1.0", info),
            "0.1.0 (bd7cd12-dirty main 2026-06-10T16:00:00Z)"
        );
    }

    #[test]
    fn clean_sha_has_no_suffix() {
        let info = BuildInfo {
            sha: "bd7cd12",
            dirty: false,
            source_known: true,
            dependency_provenance: "lock-sha",
            branch: "main",
            built_at: "2026-06-10T16:00:00Z",
        };

        assert_eq!(sha_with_dirty(info), "bd7cd12");
    }

    #[test]
    fn embedded_source_identity_is_full_or_fail_closed() {
        let info = get();
        assert!(
            info.sha == "unknown" || info.sha.len() >= 40,
            "build provenance must use the full commit id, got {}",
            info.sha
        );
        if info.source_known {
            assert_eq!(info.dependency_provenance.len(), 64);
            assert!(info
                .dependency_provenance
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn updater_identity_sentinel_has_a_stable_cross_platform_size() {
        let sentinel = UpdateBuildIdentitySentinel::current("1.2.3", 7);
        assert_eq!(
            std::mem::size_of_val(&sentinel),
            UPDATE_BUILD_IDENTITY_SENTINEL_LEN
        );
    }

    #[test]
    #[should_panic(expected = "must be exactly true or false")]
    fn updater_identity_rejects_noncanonical_build_booleans() {
        let _ = env_bool("yes");
    }
}

#[cfg(all(test, unix))]
mod relocation_test;

// What this crate's build script tells cargo to watch, read back from the
// output cargo recorded for the very run that built this test.
//
// Cargo reruns a build script on every invocation while any path it declared
// with `rerun-if-changed` is missing, and while a declared directory holds a
// file newer than the last run. kin-buildinfo is linked into every Kin binary,
// so either mistake relinks all of them on every build of an unchanged tree.
// Both shipped: the repository root's Cargo.lock was watched for a workspace
// that sits below the root, and a watched top-level directory held the
// target directory the build writes into.
#[cfg(test)]
mod declared_inputs {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Every `rerun-if-changed` path, from the stdout cargo keeps beside OUT_DIR.
    fn declared_paths() -> Vec<PathBuf> {
        let out_dir = Path::new(env!("OUT_DIR"));
        let output = out_dir
            .parent()
            .expect("OUT_DIR has a parent")
            .join("output");
        let text = fs::read_to_string(&output).unwrap_or_else(|error| {
            panic!(
                "cannot read the build script output cargo recorded at {}: {error}",
                output.display()
            )
        });
        let paths: Vec<PathBuf> = text
            .lines()
            .filter_map(|line| {
                line.strip_prefix("cargo:rerun-if-changed=")
                    .or_else(|| line.strip_prefix("cargo::rerun-if-changed="))
            })
            .map(PathBuf::from)
            .collect();
        assert!(
            !paths.is_empty(),
            "the build script declared no rerun-if-changed path in {}",
            output.display()
        );
        paths
    }

    #[test]
    fn every_watched_path_exists() {
        for path in declared_paths() {
            assert!(
                path.exists(),
                "the build script watches {}, which does not exist, so cargo reruns it and relinks every Kin binary on every build",
                path.display()
            );
        }
    }

    #[test]
    fn no_watched_path_holds_the_build_output() {
        let out_dir = fs::canonicalize(env!("OUT_DIR")).expect("OUT_DIR exists");
        for path in declared_paths() {
            let path = fs::canonicalize(&path).unwrap_or(path);
            assert!(
                !out_dir.starts_with(&path),
                "the build script watches {}, which holds its own output {}, so every build changes it and the script never reads fresh",
                path.display(),
                out_dir.display()
            );
        }
    }

    #[test]
    fn the_workspace_lock_is_watched() {
        let manifest_dir =
            fs::canonicalize(env!("CARGO_MANIFEST_DIR")).expect("the manifest directory exists");
        let workspace = manifest_dir
            .ancestors()
            .find(|dir| {
                dir.join("Cargo.lock").is_file()
                    && fs::read_to_string(dir.join("Cargo.toml")).is_ok_and(|manifest| {
                        manifest.lines().any(|line| line.trim() == "[workspace]")
                    })
            })
            .expect("this crate sits in a workspace that has a Cargo.lock");
        let lock = workspace.join("Cargo.lock");
        let watched: BTreeSet<PathBuf> = declared_paths()
            .into_iter()
            .map(|path| fs::canonicalize(&path).unwrap_or(path))
            .collect();
        assert!(
            watched.contains(&lock),
            "the build script hashes {} as the dependency provenance but does not watch it",
            lock.display()
        );
    }

    #[test]
    fn dependency_provenance_is_known() {
        let provenance = super::get().dependency_provenance;
        assert!(
            provenance.len() == 64
                && provenance
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "the embedded dependency provenance is {provenance:?}, not the SHA-256 of the workspace Cargo.lock"
        );
    }
}
