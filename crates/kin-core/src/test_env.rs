// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The workspace's one sanctioned mutation of the process environment from test
//! code.
//!
//! `std::env::set_var` and `std::env::remove_var` write a single table shared by
//! every thread in the process. `cargo test` runs a binary's tests as threads
//! inside one process, so a variable one test sets is read by every test running
//! beside it, and a test that returns early or panics before its cleanup line
//! leaks the value into everything that follows. `cargo nextest` gives each test
//! its own process, which makes the same defect structurally invisible there, so
//! a green nextest run does not cover it. Plain `cargo test` is the authority
//! when the two runners disagree.
//!
//! What this guard buys, stated exactly so it is not over-trusted:
//!
//! - the previous value is restored on drop, including on panic and on an early
//!   `return`, so a mutation cannot outlive the test that made it
//! - mutating tests are serialized against each other, so two tests holding
//!   opposite expectations of one variable cannot interleave
//!
//! What no guard can buy: it does not hide the mutation from a test that merely
//! *reads* the variable. The table is process-global, and a reader takes no
//! lock. `#[serial_test::serial]` has the same ceiling, because it orders a test
//! only against other serial tests and not against the rest of a suite running
//! in parallel. So when the code under test resolves configuration that other
//! code under test also resolves, the fix is to take that configuration by
//! argument and leave the environment alone. Reach for this guard only when the
//! behavior under test *is* the environment read itself.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard};

/// Serialization domain for every environment mutation in one test process.
static ENV_MUTATION_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    /// How many guards this thread holds, and the lock it took for the first.
    ///
    /// Reentrant on purpose: a test commonly holds several guards at once (a
    /// home directory and a registry path, say), each a separate binding whose
    /// lifetime the test controls. Taking the mutex once per thread rather than
    /// once per guard is what keeps the second guard from deadlocking against
    /// the first.
    static HELD: RefCell<(usize, Option<MutexGuard<'static, ()>>)> =
        const { RefCell::new((0, None)) };
}

fn enter_env_mutation_domain() {
    HELD.with(|held| {
        let mut held = held.borrow_mut();
        if held.0 == 0 {
            // A test that panics while holding the lock poisons it. The next
            // test still needs the domain, and the environment it will find is
            // whatever the panicking guard's Drop restored, so recover rather
            // than cascade one failure into every later one.
            held.1 = Some(
                ENV_MUTATION_LOCK
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()),
            );
        }
        held.0 += 1;
    });
}

fn leave_env_mutation_domain() {
    // `try_with` because a guard dropped during thread teardown may find the
    // thread-local already destroyed, and a panic there would abort the process.
    let _ = HELD.try_with(|held| {
        let mut held = held.borrow_mut();
        held.0 = held.0.saturating_sub(1);
        if held.0 == 0 {
            held.1 = None;
        }
    });
}

/// A scoped, restoring, serialized mutation of process-global environment
/// variables.
///
/// The guard restores every name it touched when it drops, in the state that
/// name had when the guard first touched it.
pub struct EnvVarGuard {
    restore: BTreeMap<OsString, Option<OsString>>,
    /// Binds the guard to the thread that created it.
    ///
    /// The domain's reentrancy count and the mutex guard behind it live in
    /// thread-local storage, so a guard released on a different thread than the
    /// one that took it would leave the mutex held forever and stall every
    /// later env-mutating test. Being `!Send` makes that a compile error rather
    /// than a hang, and it is also what stops a guard being held across an
    /// `.await` in a future a runtime may move between threads.
    _not_send: std::marker::PhantomData<*const ()>,
}

impl EnvVarGuard {
    /// Enter the serialization domain without changing anything yet.
    ///
    /// Useful for a test that needs the domain to itself while it reads the
    /// environment, or that decides which names to touch at runtime.
    pub fn new() -> Self {
        enter_env_mutation_domain();
        Self {
            restore: BTreeMap::new(),
            _not_send: std::marker::PhantomData,
        }
    }

    /// Enter the domain with `key` set to `value` for the guard's lifetime.
    pub fn set(key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        Self::new().with(key, value)
    }

    /// Enter the domain with `key` removed for the guard's lifetime.
    pub fn unset(key: impl AsRef<OsStr>) -> Self {
        Self::new().without(key)
    }

    /// Also set `key` to `value` for the guard's lifetime.
    pub fn with(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.apply(key, Some(value));
        self
    }

    /// Also remove `key` for the guard's lifetime.
    pub fn without(mut self, key: impl AsRef<OsStr>) -> Self {
        self.apply::<_, &OsStr>(key, None);
        self
    }

    /// Set or remove `key` inside an already-held guard.
    ///
    /// The restore value recorded is the one from before this guard first
    /// touched `key`, so a loop that walks a name through several values still
    /// restores what the process had on entry.
    pub fn apply<K: AsRef<OsStr>, V: AsRef<OsStr>>(&mut self, key: K, value: Option<V>) {
        let key = key.as_ref().to_os_string();
        self.restore
            .entry(key.clone())
            .or_insert_with(|| std::env::var_os(&key));
        match value {
            Some(value) => std::env::set_var(&key, value.as_ref()),
            None => std::env::remove_var(&key),
        }
    }
}

impl Default for EnvVarGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Install a value for the whole test process, deliberately without restoring.
///
/// A few fixtures have to hold for every test in a binary rather than for one
/// scope: pointing the registry authority away from the developer's real
/// `~/.kin`, for instance, where restoring the original between tests would
/// expose the real home to whatever ran in that window. The honest shape for
/// that is an override installed once, before any test observes the name, and
/// never taken back.
///
/// This is not a lighter-weight [`EnvVarGuard`]. Anything scoped to one test
/// belongs in a guard, because a value left behind is read by every test that
/// follows.
pub fn install_process_wide(key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
    let _domain = EnvVarGuard::new();
    std::env::set_var(key.as_ref(), value.as_ref());
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, previous) in std::mem::take(&mut self.restore) {
            match previous {
                Some(value) => std::env::set_var(&key, value),
                None => std::env::remove_var(&key),
            }
        }
        leave_env_mutation_domain();
    }
}

/// Workspace-relative path of the one module allowed to write the environment
/// table directly. Everything else in the workspace goes through the guard.
pub const SANCTIONED_MUTATION_SITE: &str = "crates/kin-core/src/test_env.rs";

/// Name of the allowlist beside `Cargo.toml` naming product code that writes the
/// environment as real behavior rather than as test setup.
pub const MUTATION_ALLOWLIST_FILE: &str = "env_mutation_allowlist.txt";

#[cfg(test)]
mod tests {
    use super::*;

    const ABSENT: &str = "KIN_TEST_ENV_GUARD_ABSENT";
    const PRESENT: &str = "KIN_TEST_ENV_GUARD_PRESENT";

    #[test]
    fn a_guard_restores_absence_and_a_prior_value() {
        let mut outer = EnvVarGuard::new();
        outer.apply(ABSENT, None::<&str>);
        outer.apply(PRESENT, Some("original"));

        {
            let _inner = EnvVarGuard::set(ABSENT, "temporary").with(PRESENT, "overridden");
            assert_eq!(std::env::var(ABSENT).as_deref(), Ok("temporary"));
            assert_eq!(std::env::var(PRESENT).as_deref(), Ok("overridden"));
        }

        assert!(
            std::env::var_os(ABSENT).is_none(),
            "a name absent before the guard must be absent after it"
        );
        assert_eq!(
            std::env::var(PRESENT).as_deref(),
            Ok("original"),
            "a name present before the guard must keep its original value"
        );
    }

    #[test]
    fn repeated_application_restores_the_value_from_before_the_guard() {
        let mut outer = EnvVarGuard::new();
        outer.apply(PRESENT, Some("entry"));

        {
            let mut inner = EnvVarGuard::new();
            for value in ["one", "two", "three"] {
                inner.apply(PRESENT, Some(value));
                assert_eq!(std::env::var(PRESENT).as_deref(), Ok(value));
            }
            inner.apply(PRESENT, None::<&str>);
            assert!(std::env::var_os(PRESENT).is_none());
        }

        assert_eq!(
            std::env::var(PRESENT).as_deref(),
            Ok("entry"),
            "walking a name through several values must still restore the entry value"
        );
    }

    #[test]
    fn a_panicking_scope_still_restores() {
        let mut outer = EnvVarGuard::new();
        outer.apply(PRESENT, Some("survivor"));

        let panicked = std::panic::catch_unwind(|| {
            let _guard = EnvVarGuard::set(PRESENT, "doomed");
            panic!("the scope under test panics");
        });

        assert!(panicked.is_err());
        assert_eq!(
            std::env::var(PRESENT).as_deref(),
            Ok("survivor"),
            "unwinding through a guard must restore, or a failing test poisons its neighbours"
        );
    }

    /// Every `path:line` in `text` that writes the process environment table.
    ///
    /// The needles are assembled from fragments so this scanner's own source
    /// never contains the pattern it searches for.
    fn scan_env_mutations(text: &str) -> Vec<(usize, String)> {
        let module = "env";
        let needles = [
            format!("{module}::set_{}", "var("),
            format!("{module}::remove_{}", "var("),
        ];
        let mut found = Vec::new();
        for needle in &needles {
            let mut from = 0;
            while let Some(offset) = text[from..].find(needle.as_str()) {
                let at = from + offset;
                found.push((text[..at].lines().count(), needle.clone()));
                from = at + needle.len();
            }
        }
        found.sort();
        found
    }

    /// The parsed allowlist. `paths` are exact workspace-relative files whose
    /// write is product behavior. `tests_only_crates` holds `crates/<name>/`
    /// prefixes whose TEST code is exempt as a whole, for a crate that sits below
    /// kin-core and so cannot take `EnvVarGuard` as a dev-dependency: its
    /// `tests/` binaries and its top-level `#[cfg(test)]` items, and nothing else.
    /// Product code in such a crate stays graded, and every other crate keeps
    /// exact-path semantics.
    struct MutationAllowlist {
        paths: std::collections::BTreeSet<String>,
        tests_only_crates: std::collections::BTreeSet<String>,
    }

    /// Parse `env_mutation_allowlist.txt`. A line is either an exact path or
    /// `crates/<name> tests-only`; anything else shaped like the second form is
    /// refused rather than read as a path that matches nothing.
    fn parse_mutation_allowlist(text: &str) -> MutationAllowlist {
        let mut allow = MutationAllowlist {
            paths: std::collections::BTreeSet::from([SANCTIONED_MUTATION_SITE.to_string()]),
            tests_only_crates: std::collections::BTreeSet::new(),
        };
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split_whitespace().collect();
            match fields.as_slice() {
                [path] => {
                    allow.paths.insert((*path).to_string());
                }
                [krate, "tests-only"]
                    if krate.starts_with("crates/")
                        && !krate.ends_with('/')
                        && krate.matches('/').count() == 1 =>
                {
                    allow.tests_only_crates.insert(format!("{krate}/"));
                }
                _ => panic!(
                    "{MUTATION_ALLOWLIST_FILE}: cannot read {line:?}; a line is one \
                     workspace-relative path, or `crates/<name> tests-only`"
                ),
            }
        }
        allow
    }

    fn load_mutation_allowlist(manifest: &std::path::Path) -> MutationAllowlist {
        let text =
            std::fs::read_to_string(manifest.join(MUTATION_ALLOWLIST_FILE)).unwrap_or_default();
        parse_mutation_allowlist(&text)
    }

    /// Line ranges, 1-based and inclusive, of the top-level `#[cfg(test)]` items
    /// in `text` that open a block: from the attribute through the item's closing
    /// brace. It leans on rustfmt, which CI enforces: a top-level item's closing
    /// brace is a `}` alone at column 0. Whatever fools it ends a range early and
    /// so grades more, never less; a `#[cfg(test)] mod x;` declaration is not a
    /// block, and the file it names is graded as product code.
    fn top_level_cfg_test_ranges(text: &str) -> Vec<(usize, usize)> {
        let lines: Vec<&str> = text.lines().collect();
        let mut ranges = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i] == "#[cfg(test)]" {
                let mut j = i + 1;
                while j < lines.len() && lines[j].starts_with("#[") {
                    j += 1;
                }
                if j < lines.len()
                    && !lines[j].starts_with(char::is_whitespace)
                    && lines[j].ends_with('{')
                {
                    if let Some(close) = (j + 1..lines.len()).find(|&k| lines[k] == "}") {
                        ranges.push((i + 1, close + 1));
                        i = close + 1;
                        continue;
                    }
                }
            }
            i += 1;
        }
        ranges
    }

    /// The writes the scan reports in one file. Pure, so the arms below can hand
    /// it files that do not exist.
    fn offending_writes(
        relative: &str,
        text: &str,
        allow: &MutationAllowlist,
    ) -> Vec<(usize, String)> {
        if allow.paths.contains(relative) {
            return Vec::new();
        }
        let hits = scan_env_mutations(text);
        let Some(krate) = allow
            .tests_only_crates
            .iter()
            .find(|k| relative.starts_with(k.as_str()))
        else {
            return hits;
        };
        if relative[krate.len()..].starts_with("tests/") {
            return Vec::new();
        }
        let tests = top_level_cfg_test_ranges(text);
        hits.into_iter()
            .filter(|(line, _)| !tests.iter().any(|(lo, hi)| (lo..=hi).contains(&line)))
            .collect()
    }

    /// No source in the workspace writes the environment table on its own.
    ///
    /// Two confirmed defects came from a test doing exactly that, and neither
    /// could ever turn CI red: the test job runs nextest, which gives each test
    /// its own process. The shape is invisible in review too, because a
    /// `set_var` line reads as ordinary setup and its blast radius is every
    /// other test in the binary. So the ban is on the shape rather than on any
    /// one variable, and the exemptions are enumerated in a file a reviewer
    /// sees change.
    #[test]
    fn no_source_outside_the_sanctioned_guard_writes_the_environment() {
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let root = manifest.join("../..");
        // Skip in a packaged single-crate context, where the sibling crates
        // this scans are not present. Mirrors the env-read completeness scan.
        if !root.join("crates/kin-cli/src").is_dir() {
            eprintln!("workspace crates not present; skipping env-mutation scan");
            return;
        }
        let allowed = load_mutation_allowlist(manifest);

        let mut offenders = Vec::new();
        let mut stack = vec![root.clone()];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if path.is_dir() {
                    if name == "target" || name == "node_modules" || name.starts_with('.') {
                        continue;
                    }
                    stack.push(path);
                    continue;
                }
                if !name.ends_with(".rs") {
                    continue;
                }
                let relative = path
                    .strip_prefix(&root)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                if allowed.paths.contains(relative.as_str()) {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                for (line, needle) in offending_writes(&relative, &text, &allowed) {
                    offenders.push(format!("{relative}:{line} {needle}"));
                }
            }
        }
        offenders.sort();

        assert!(
            offenders.is_empty(),
            "these sources write the process environment directly. Test code must go through \
             kin_core::test_env::EnvVarGuard (or install_process_wide for a binary-wide fixture) \
             so the write is restored and serialized, and code whose subject is configuration \
             other code under test also reads must take that configuration by argument instead. \
             Product code that writes the environment as real behavior belongs in \
             crates/kin-core/{MUTATION_ALLOWLIST_FILE}. Offenders: {offenders:#?}"
        );
    }

    // The three arms the tests-only form has to hold, on inputs built here.
    // The needle is assembled so this file's own text stays a plain example.
    fn write_line() -> String {
        format!("    std::env::set_{}(\"KIN_EXAMPLE\", \"1\");", "var")
    }

    fn fixture_in_test_module() -> String {
        format!(
            "pub fn f() {{}}\n\n#[cfg(test)]\nmod tests {{\n    fn g() {{\n{}\n    }}\n}}\n",
            write_line()
        )
    }

    #[test]
    fn a_product_write_in_a_tests_only_crate_is_still_flagged() {
        let allow = parse_mutation_allowlist("crates/kin-infer tests-only\n");
        let product = format!("pub fn f() {{\n{}\n}}\n", write_line());
        assert_eq!(
            offending_writes("crates/kin-infer/src/lib.rs", &product, &allow).len(),
            1
        );
        // And a write after the test module closes is product code again.
        let after = format!(
            "{}pub fn h() {{\n{}\n}}\n",
            fixture_in_test_module(),
            write_line()
        );
        assert_eq!(
            offending_writes("crates/kin-infer/src/lib.rs", &after, &allow).len(),
            1
        );
    }

    #[test]
    fn a_test_module_write_outside_a_tests_only_crate_is_flagged() {
        let allow = parse_mutation_allowlist("crates/kin-infer tests-only\n");
        assert_eq!(
            offending_writes(
                "crates/kin-cli/src/lib.rs",
                &fixture_in_test_module(),
                &allow
            )
            .len(),
            1
        );
        let product = format!("pub fn f() {{\n{}\n}}\n", write_line());
        assert_eq!(
            offending_writes("crates/kin-cli/tests/probe.rs", &product, &allow).len(),
            1
        );
    }

    #[test]
    fn a_test_module_write_in_a_tests_only_crate_passes() {
        let allow = parse_mutation_allowlist("crates/kin-infer tests-only\n");
        assert!(offending_writes(
            "crates/kin-infer/src/lib.rs",
            &fixture_in_test_module(),
            &allow
        )
        .is_empty());
        let product = format!("pub fn f() {{\n{}\n}}\n", write_line());
        assert!(offending_writes("crates/kin-infer/tests/probe.rs", &product, &allow).is_empty());
    }

    #[test]
    fn a_malformed_tests_only_line_is_refused() {
        for bad in [
            "kin-infer tests-only",
            "crates/kin-infer/ tests-only",
            "crates/kin-infer tests-only extra",
            "crates/kin-infer/src tests-only",
        ] {
            let result = std::panic::catch_unwind(|| parse_mutation_allowlist(bad));
            assert!(result.is_err(), "{bad:?} must be refused");
        }
    }
}
