// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Analysis environments: the dependencies a repository's lockfile pins,
//! fetched by Kin so a language server can resolve calls into them, without
//! running any of the repository's or the dependencies' code.
//!
//! An analysis environment is built the way Kin already installs language
//! servers: plain downloads, each checked against a digest before anything
//! is unpacked, kept under `KIN_HOME/cache` in a store named by content so
//! that repositories pinning the same package share one copy. Nothing is
//! built: a package that exists only as source needing a build is left out
//! and reported. The user's own environment still wins when it matches the
//! lock, and a repository whose environment cannot be built from what it
//! chose has its environment reported missing rather than borrowed from
//! somewhere else.
//!
//! Analysis environments are on by default. [`SWITCH_ENV`] turns them off.

use std::path::PathBuf;

pub mod fetch;
pub mod go;
pub mod js;
pub mod python;
pub mod rust;
pub mod unpack;

/// The one switch: a falsy value (`0`, `false`, `no`, `off`) turns analysis
/// environments off, so no dependency is fetched and a repository without a
/// matching environment of its own reports its environment missing.
pub const SWITCH_ENV: &str = "KIN_ANALYSIS_ENVIRONMENTS";

/// Whether analysis environments are on, for a value of [`SWITCH_ENV`].
pub fn enabled_from(value: Option<&str>) -> bool {
    !value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        )
    })
}

/// Whether analysis environments are on in this process.
pub fn enabled() -> bool {
    enabled_from(std::env::var(SWITCH_ENV).ok().as_deref())
}

/// Kin's cache directory, `$KIN_HOME/cache`, `~/.kin/cache` without it.
pub fn kin_cache_dir() -> PathBuf {
    std::env::var_os("KIN_HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|home| !home.is_empty())
                .map(|home| PathBuf::from(home).join(".kin"))
        })
        .unwrap_or_else(|| std::env::temp_dir().join("kin"))
        .join("cache")
}

/// Where analysis environments keep their store, under Kin's cache.
pub fn store_root(cache: &std::path::Path) -> PathBuf {
    cache.join("analysis-environments")
}

/// How long an environment whose fetch left artifacts out counts as built
/// before the fetch is tried again. A package that is gone from its registry
/// is not asked for on every server start, and one a network failure left
/// out is asked for again the next day.
pub const RETRY_AFTER: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);

fn attempt_file(
    store: &std::path::Path,
    identity: &crate::adapters::contract::EnvironmentIdentity,
) -> PathBuf {
    store.join("attempts").join(identity.hex())
}

/// Record that a fetch for `identity` ran, and how many artifacts it could
/// not fetch.
pub(crate) fn record_attempt(
    store: &std::path::Path,
    identity: &crate::adapters::contract::EnvironmentIdentity,
    failures: usize,
) {
    let _ = write_atomically(
        &attempt_file(store, identity),
        format!("failures {failures}\n").as_bytes(),
    );
}

/// Whether the last fetch for `identity` left artifacts out less than
/// [`RETRY_AFTER`] ago, so the environment counts as built as it is.
pub(crate) fn recently_failed(
    store: &std::path::Path,
    identity: &crate::adapters::contract::EnvironmentIdentity,
) -> bool {
    failed_attempt_age(store, identity).is_some_and(|age| age < RETRY_AFTER)
}

/// Whether the last fetch for `identity` left artifacts out [`RETRY_AFTER`]
/// ago or more, so it is due to be tried again.
pub(crate) fn failed_long_ago(
    store: &std::path::Path,
    identity: &crate::adapters::contract::EnvironmentIdentity,
) -> bool {
    failed_attempt_age(store, identity).is_some_and(|age| age >= RETRY_AFTER)
}

fn failed_attempt_age(
    store: &std::path::Path,
    identity: &crate::adapters::contract::EnvironmentIdentity,
) -> Option<std::time::Duration> {
    let file = attempt_file(store, identity);
    let text = std::fs::read_to_string(&file).ok()?;
    let failures: usize = text.trim().strip_prefix("failures ")?.parse().ok()?;
    if failures == 0 {
        return None;
    }
    let modified = std::fs::metadata(&file).ok()?.modified().ok()?;
    Some(modified.elapsed().unwrap_or_default())
}

/// How many downloads one environment runs at once.
pub const PARALLEL_FETCHES: usize = 16;

/// Run `work` over `items` on up to `threads` threads, and return the results
/// in the items' order.
pub(crate) fn parallel_map<T: Sync, R: Send>(
    items: &[T],
    threads: usize,
    work: impl Fn(&T) -> R + Sync,
) -> Vec<R> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    std::thread::scope(|scope| {
        for _ in 0..threads.clamp(1, items.len().max(1)) {
            scope.spawn(|| loop {
                let at = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(at) else {
                    break;
                };
                let result = work(item);
                results.lock().unwrap_or_else(|e| e.into_inner())[at] = Some(result);
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_else(|e| e.into_inner())
        .into_iter()
        .flatten()
        .collect()
}

/// Write `bytes` to `path` through a staged name and a rename, so a reader
/// never sees part of a file. An existing file is replaced.
pub(crate) fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> Result<(), String> {
    let dir = path
        .parent()
        .ok_or_else(|| format!("{} has no directory", path.display()))?;
    std::fs::create_dir_all(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    let staging = dir.join(format!(
        ".{}.{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy(),
        python::store::unique_suffix()
    ));
    std::fs::write(&staging, bytes).map_err(|error| format!("{}: {error}", staging.display()))?;
    std::fs::rename(&staging, path).map_err(|error| {
        let _ = std::fs::remove_file(&staging);
        format!("{}: {error}", path.display())
    })
}

/// Standard base64, as Go's module hashes and npm's integrity strings use it.
pub(crate) fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * index)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fetch that left artifacts out counts as built for a day, then is
    /// due again; one that left nothing out never is.
    #[test]
    fn a_failed_fetch_is_retried_after_a_day() {
        let store = crate::adapters::repo_scan::Fixture::new("attempts");
        let identity = crate::adapters::contract::EnvironmentIdentity::of(&["x"]);
        assert!(!recently_failed(&store.root, &identity));
        record_attempt(&store.root, &identity, 0);
        assert!(!recently_failed(&store.root, &identity));
        assert!(!failed_long_ago(&store.root, &identity));
        record_attempt(&store.root, &identity, 2);
        assert!(recently_failed(&store.root, &identity));
        assert!(!failed_long_ago(&store.root, &identity));
        let two_days = std::time::Duration::from_secs(2 * 24 * 60 * 60);
        std::fs::File::options()
            .write(true)
            .open(attempt_file(&store.root, &identity))
            .unwrap()
            .set_modified(std::time::SystemTime::now() - two_days)
            .unwrap();
        assert!(!recently_failed(&store.root, &identity));
        assert!(failed_long_ago(&store.root, &identity));
    }

    #[test]
    fn base64_matches_the_standard_alphabet() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(&[0xfb, 0xff]), "+/8=");
    }

    #[test]
    fn parallel_work_keeps_the_items_order() {
        let items: Vec<u32> = (0..50).collect();
        let doubled = parallel_map(&items, 8, |item| item * 2);
        assert_eq!(
            doubled,
            items.iter().map(|item| item * 2).collect::<Vec<_>>()
        );
        assert!(parallel_map(&[] as &[u32], 8, |item| *item).is_empty());
    }

    /// Under cargo every test runs with analysis environments off: the
    /// `[env]` table of the workspace's cargo configuration sets the switch,
    /// and the test harnesses that start daemons set it again. For a
    /// repository in each language whose lock would need a download, no
    /// adapter's network step sends a request. This fails if either half is
    /// lost.
    #[test]
    fn the_test_harness_never_fetches() {
        use crate::adapters::LspAdapter;
        assert!(
            !enabled(),
            "{SWITCH_ENV} must be off under the test harness (the [env] table of .cargo/config.toml)"
        );
        let repo = crate::adapters::repo_scan::Fixture::new("harness-never-fetches");
        let sha = "a".repeat(64);
        repo.write(
            "go.mod",
            "module example.com/x\n\ngo 1.21\n\nrequire example.com/dep v1.0.0\n",
        );
        repo.write(
            "go.sum",
            "example.com/dep v1.0.0 h1:AAAA=\nexample.com/dep v1.0.0/go.mod h1:BBBB=\n",
        );
        repo.write(
            "Cargo.toml",
            "[package]\nname = \"x\"\nversion = \"0.1.0\"\n[dependencies]\nserde = \"1\"\n",
        );
        repo.write(
            "Cargo.lock",
            &format!(
                "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\n\
                 source = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{sha}\"\n"
            ),
        );
        repo.write(
            "package.json",
            "{\"name\": \"x\", \"dependencies\": {\"left-pad\": \"1.3.0\"}}",
        );
        repo.write(
            "package-lock.json",
            "{\"lockfileVersion\": 3, \"packages\": {\"\": {\"dependencies\": {\"left-pad\": \"1.3.0\"}}, \
             \"node_modules/left-pad\": {\"version\": \"1.3.0\", \"resolved\": \
             \"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\", \"integrity\": \
             \"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}}}",
        );
        repo.write(
            "pyproject.toml",
            "[project]\nname = \"x\"\nrequires-python = \">=3.11\"\ndependencies = [\"idna\"]\n",
        );
        repo.write(
            "requirements.txt",
            &format!("idna==3.10 \\\n    --hash=sha256:{sha}\n"),
        );
        let before = fetch::requests_sent();
        let adapters: Vec<Box<dyn LspAdapter>> = vec![
            Box::new(crate::adapters::go::GoplsAdapter),
            Box::new(crate::adapters::rust_analyzer::RustAnalyzerAdapter),
            Box::new(crate::adapters::typescript::TypeScriptAdapter),
            Box::new(crate::adapters::python::PyrightAdapter),
        ];
        for adapter in &adapters {
            assert!(
                adapter.provision(&repo.root).is_none(),
                "{} tried to provision under the test harness",
                adapter.server_command()
            );
            let launch = adapter.launch(&repo.root);
            assert!(
                launch
                    .resolution
                    .as_ref()
                    .is_none_or(|resolution| resolution.environment.pending.is_none()),
                "{} left a fetch pending under the test harness",
                adapter.server_command()
            );
        }
        assert_eq!(fetch::requests_sent(), before, "no request went out");
    }

    #[test]
    fn analysis_environments_are_on_unless_switched_off() {
        assert!(enabled_from(None));
        assert!(enabled_from(Some("1")));
        assert!(enabled_from(Some("")));
        for off in ["0", "false", "No", " off "] {
            assert!(!enabled_from(Some(off)), "{off}");
        }
    }
}
