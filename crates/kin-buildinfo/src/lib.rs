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
