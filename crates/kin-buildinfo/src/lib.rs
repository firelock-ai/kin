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
}
