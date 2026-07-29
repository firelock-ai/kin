//! Scope boundary for managed-config repository discovery and IO.
//!
//! Every managed MCP client config except the checkout-local Antigravity
//! workspace binding is addressed from the home directory, so the home
//! directory alone bounds where those paths can land. The workspace binding is
//! instead addressed from a discovered repository root, and repository
//! discovery walks upward without a ceiling. A caller running below an
//! unrelated repository therefore binds that repository, reads its
//! `.agents/mcp_config.json`, and writes back into it.
//!
//! This module supplies the ceiling. `KIN_MCP_SCAN_ROOT` pins discovery to one
//! directory and rejects any repository root found above it, and
//! `KIN_MCP_FIXTURE_ROOT` turns an escape into an immediate panic instead of a
//! silent write into the enclosing checkout.

use std::path::{Path, PathBuf};

/// Directory that bounds managed-config repository discovery.
///
/// Discovery starts here and never binds a repository above it.
pub(crate) const SCAN_ROOT_ENV: &str = "KIN_MCP_SCAN_ROOT";

/// Directory that bounds every managed-config path a test may touch.
///
/// Set only by tests. A managed path outside it aborts the test at the moment
/// the path is resolved, rather than after it has written into a real checkout.
pub(crate) const FIXTURE_ROOT_ENV: &str = "KIN_MCP_FIXTURE_ROOT";

/// Resolve a directory to its canonical form, tolerating a path that does not
/// exist yet by canonicalizing the nearest existing ancestor and re-appending
/// the remainder. Containment is compared on canonical paths so a symlinked
/// temp directory (`/var` to `/private/var` on macOS) still matches.
fn canonical_dir(path: &Path) -> PathBuf {
    if let Ok(resolved) = path.canonicalize() {
        return resolved;
    }
    let mut suffix = Vec::new();
    let mut current = path.to_path_buf();
    while let Some(parent) = current.parent().map(Path::to_path_buf) {
        let Some(name) = current.file_name().map(|name| name.to_os_string()) else {
            break;
        };
        suffix.push(name);
        if let Ok(resolved) = parent.canonicalize() {
            let mut out = resolved;
            for part in suffix.iter().rev() {
                out.push(part);
            }
            return out;
        }
        current = parent;
    }
    path.to_path_buf()
}

fn env_dir(key: &str) -> Option<PathBuf> {
    let raw = std::env::var_os(key)?;
    if raw.is_empty() {
        return None;
    }
    Some(canonical_dir(Path::new(&raw)))
}

/// True when `path` is `root` or lives beneath it.
pub(crate) fn is_within(root: &Path, path: &Path) -> bool {
    canonical_dir(path).starts_with(canonical_dir(root))
}

/// Directory managed-config repository discovery starts from.
///
/// An explicit scan root always wins. Without one, a test build discovers
/// nothing at all: unit tests that expect a workspace binding declare the
/// fixture they mean, and the rest can no longer reach whatever repository
/// happens to enclose the test runner's working directory.
fn scan_root() -> Option<PathBuf> {
    if let Some(explicit) = env_dir(SCAN_ROOT_ENV) {
        return Some(explicit);
    }
    if cfg!(test) {
        return None;
    }
    std::env::current_dir().ok()
}

/// Repository root that owns the checkout-local managed config, bounded by the
/// scan root so discovery can never bind an enclosing repository.
pub(crate) fn discover_repo_root() -> Option<PathBuf> {
    let start = scan_root()?;
    let layout = kin_core::KinLayout::discover(&start)?;
    let root = layout.working_dir().to_path_buf();
    // `KinLayout::discover` walks upward, so a root outside the scan root is a
    // repository that encloses it rather than the one the caller addressed.
    if std::env::var_os(SCAN_ROOT_ENV).is_some() && !is_within(&start, &root) {
        return None;
    }
    Some(root)
}

/// Abort immediately when a managed-config path escapes the declared fixture.
///
/// A test that would read or write outside its fixture has already lost its
/// isolation; failing at path resolution names the offending path while the
/// stack still shows which flow produced it.
pub(crate) fn guard_managed_path(path: &Path) {
    let Some(fixture) = env_dir(FIXTURE_ROOT_ENV) else {
        return;
    };
    assert!(
        is_within(&fixture, path),
        "managed config path escaped its fixture: {} is outside {}",
        canonical_dir(path).display(),
        fixture.display()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_matches_self_and_descendants() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        assert!(is_within(root, root));
        assert!(is_within(root, &root.join("a/b/c")));
        assert!(!is_within(&root.join("a"), root));
    }

    #[test]
    fn canonical_dir_resolves_through_missing_leaves() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent/leaf.json");
        assert_eq!(
            canonical_dir(&missing),
            dir.path().canonicalize().unwrap().join("absent/leaf.json")
        );
    }
}
