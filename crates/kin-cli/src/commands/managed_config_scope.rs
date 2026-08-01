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
//! directory and rejects any repository root found above it, and a test build
//! additionally refuses a managed path that leaves the fixture the test
//! declared or that lands under the real user's home directory, so an escape is
//! an immediate panic rather than a silent write into a live config.

use std::path::{Path, PathBuf};

/// Directory that bounds managed-config repository discovery.
///
/// Discovery starts here and never binds a repository above it.
pub(crate) const SCAN_ROOT_ENV: &str = "KIN_MCP_SCAN_ROOT";

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

/// Abort immediately when a managed-config path escapes its test scope.
///
/// A test that would read or write outside its fixture has already lost its
/// isolation; failing at path resolution names the offending path while the
/// stack still shows which flow produced it. Compiled away entirely outside a
/// test build, so the shipped CLI carries no lever that can panic it.
pub(crate) fn guard_managed_path(path: &Path) {
    #[cfg(test)]
    test_scope::assert_managed_path_is_test_scoped(path);
    #[cfg(not(test))]
    let _ = path;
}

/// The ceiling a test build puts under managed-config path resolution.
///
/// Two rules, both enforced where the path is resolved rather than where it is
/// written:
///
/// - a test may declare a fixture directory, and a managed path outside it
///   aborts
/// - no test may resolve a managed path under the real user's home directory,
///   declared fixture or not
///
/// The second rule needs no per-test opt-in, which is the point: the defect it
/// catches is a test *forgetting* to scope its home, and a guard a test has to
/// remember is not a guard against forgetting. It reads the home from the
/// password database rather than from `$HOME` precisely because `$HOME` is what
/// a correctly scoped test overrides.
///
/// The declaration is thread-local and not an environment variable. The
/// environment table is process-global and readers of it take no lock, so a
/// variable one test sets is observed by every test running beside it;
/// `#[serial]` does not close that, because it orders a test only against other
/// serial tests. A thread-local declaration cannot be observed by another test
/// at all. The cost is that a flow which resolves managed paths on a spawned
/// thread is outside its parent's declaration, so a test that needs the ceiling
/// there declares it in the worker too.
#[cfg(test)]
pub(crate) mod test_scope {
    use super::{canonical_dir, is_within};
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    thread_local! {
        /// Fixture ceiling declared by the test running on this thread.
        static DECLARED_FIXTURE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }

    /// A declared fixture ceiling, in force until it is dropped.
    pub(crate) struct FixtureScope {
        previous: Option<PathBuf>,
        /// Binds the scope to the thread that declared it, since that is the
        /// only thread whose thread-local it can restore.
        _not_send: std::marker::PhantomData<*const ()>,
    }

    impl FixtureScope {
        /// Bound every managed path this thread resolves to `root`.
        pub(crate) fn declare(root: &Path) -> Self {
            let previous = DECLARED_FIXTURE.with(|slot| slot.replace(Some(canonical_dir(root))));
            Self {
                previous,
                _not_send: std::marker::PhantomData,
            }
        }
    }

    impl Drop for FixtureScope {
        fn drop(&mut self) {
            let previous = self.previous.take();
            // `try_with` because a scope dropped during thread teardown may
            // find the thread-local already destroyed, and a panic there would
            // abort the process rather than fail the test.
            let _ = DECLARED_FIXTURE.try_with(|slot| *slot.borrow_mut() = previous);
        }
    }

    /// The invoking user's home directory as the system records it.
    ///
    /// Read from the password database so that overriding `$HOME`, which is how
    /// a test scopes itself, cannot also move the boundary it is checked
    /// against. Windows has no equivalent lookup wired here, so the home rule
    /// is unenforced there and the declared-fixture rule carries alone.
    #[cfg(unix)]
    pub(crate) fn real_user_home() -> Option<&'static Path> {
        use std::ffi::{CStr, OsStr};
        use std::os::unix::ffi::OsStrExt;

        static HOME: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
        HOME.get_or_init(|| {
            let mut buffer = vec![0 as libc::c_char; 4096];
            let mut record: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: `record` and `buffer` outlive the call and are not
            // aliased, the reentrant form is required because managed paths are
            // resolved from several test threads at once, and `record` is read
            // only after the call reports a match.
            let code = unsafe {
                libc::getpwuid_r(
                    libc::getuid(),
                    &mut record,
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut found,
                )
            };
            if code != 0 || found.is_null() || record.pw_dir.is_null() {
                return None;
            }
            // SAFETY: a matched record's `pw_dir` points into `buffer`, which is
            // still alive, and the string it points at is NUL terminated.
            let dir = unsafe { CStr::from_ptr(record.pw_dir) };
            Some(PathBuf::from(OsStr::from_bytes(dir.to_bytes())))
        })
        .as_deref()
    }

    #[cfg(not(unix))]
    fn real_user_home() -> Option<&'static Path> {
        None
    }

    /// Panic unless `path` belongs to the test that resolved it.
    pub(crate) fn assert_managed_path_is_test_scoped(path: &Path) {
        if let Some(fixture) = DECLARED_FIXTURE.with(|slot| slot.borrow().clone()) {
            assert!(
                is_within(&fixture, path),
                "managed config path escaped its fixture: {} is outside {}",
                canonical_dir(path).display(),
                fixture.display()
            );
        }
        if let Some(home) = real_user_home() {
            assert!(
                !is_within(home, path),
                "a test resolved the managed config path {} under the real home {}. Point HOME \
                 and KIN_HOME at a fixture directory for the duration of the test, or this test \
                 reads and can write the developer's live configuration",
                canonical_dir(path).display(),
                home.display()
            );
        }
    }
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

    /// A fixture one test declares must not bound any other test.
    ///
    /// This is the shape that made the suite intermittently fail: the
    /// declaration used to be an environment variable, which is one table
    /// shared by every thread in the process, so a test that merely resolved a
    /// managed path in its own temporary directory aborted whenever it happened
    /// to run beside the declaring test. Serializing the declaring test did not
    /// close it, because that orders it only against other serial tests.
    #[test]
    fn a_declared_fixture_does_not_reach_another_thread() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = dir.path().join("fixture");
        let outside = dir.path().join("outside/mcp.json");
        std::fs::create_dir_all(&fixture).unwrap();

        let _declared = test_scope::FixtureScope::declare(&fixture);
        test_scope::assert_managed_path_is_test_scoped(&fixture.join("mcp.json"));

        let escaping = outside.clone();
        let bounded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            test_scope::assert_managed_path_is_test_scoped(&escaping);
        }));
        assert!(
            bounded.is_err(),
            "the thread that declared the fixture must still be bounded by it"
        );

        std::thread::spawn(move || test_scope::assert_managed_path_is_test_scoped(&outside))
            .join()
            .expect("a fixture declared on one thread must not bound another");
    }

    /// No test may resolve a managed config path under the real home, whether
    /// or not it declared a fixture. The developer's live client configuration
    /// is there, and a test that reaches it reports on state it does not
    /// control and can write state it does not own.
    #[cfg(unix)]
    #[test]
    #[should_panic(expected = "under the real home")]
    fn a_managed_path_under_the_real_home_aborts_with_no_declaration() {
        let home = test_scope::real_user_home().expect("the password database records a home");
        test_scope::assert_managed_path_is_test_scoped(&home.join(".kin/probe.json"));
    }

    #[test]
    fn a_managed_path_in_a_temporary_fixture_needs_no_declaration() {
        let dir = tempfile::tempdir().unwrap();
        test_scope::assert_managed_path_is_test_scoped(&dir.path().join("mcp.json"));
    }
}
