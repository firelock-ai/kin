// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where Kin installs the tools it provisions for itself, and how the processes
//! that look for them find them.
//!
//! Language-server discovery is `which` over `PATH` and nothing else
//! (`kin_lsp::discovery::discover_servers`), so a server Kin installs is
//! reachable only if the directory it landed in is on the `PATH` of the process
//! that starts the enrichment. That process is the repo daemon, which inherits
//! the environment of whichever `kin` command spawned it. Both binaries
//! therefore call [`augment_path_with_managed_tools`] at process start, while
//! they are still single-threaded, exactly as they both call
//! `resource_profile::apply_product_default`.
//!
//! Two directories, because two installers write in different shapes. A binary
//! Kin downloads and verifies itself lands in [`managed_tool_bin_dir`]. A
//! package installed with `npm install --prefix` lands under
//! [`managed_node_prefix`], whose executables npm links into
//! [`managed_node_bin_dir`]; that is the same prefix shape
//! `scripts/ci-install-language-servers.sh` already uses on hosted runners, and
//! it is what lets a provisioning run succeed on a host whose global npm prefix
//! is owned by root.
//!
//! These directories go on the END of `PATH`, never the front. A server the
//! operator installed themselves is the one their toolchain expects, and a
//! rustup `rust-analyzer` tracks the toolchain that compiled the code while
//! Kin's pinned copy does not. Kin's copy is a fallback for a host that has
//! none, so it must never shadow one that is already there.
//!
//! # Servers the operator installed, for a process their shell did not start
//!
//! The daemon an AI client starts inherits that client's `PATH`, and a desktop
//! client or an agent's sandbox rarely carries the one the operator's shell
//! builds: npm's global prefix, `~/go/bin`, `~/.cargo/bin`, a pyenv or nvm
//! install. `kin doctor` in a terminal found those servers while the daemon
//! the client started could not, so enrichment was partial for exactly the
//! people who use Kin only through an agent, and nothing said so.
//!
//! So the same startup call also appends, behind the operator's own entries
//! and ahead of Kin's managed copies, two kinds of directory that exist on this
//! host: the ones [`record_tool_dirs`] recorded from a shell `kin setup` or
//! `kin doctor --fix` ran in, and the usual per-user install places
//! [`usual_tool_dirs`] names. A directory already on `PATH` is left where it is.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The root Kin installs provisioned tools under.
pub fn managed_tool_root() -> PathBuf {
    crate::registry::managed_kin_home().join("tools")
}

/// Where a binary Kin downloaded and verified itself is installed.
pub fn managed_tool_bin_dir() -> PathBuf {
    managed_tool_root().join("bin")
}

/// The npm prefix Kin owns, for packages a shared global prefix refuses.
pub fn managed_node_prefix() -> PathBuf {
    managed_tool_root().join("node")
}

/// Where npm links the executables of packages installed into
/// [`managed_node_prefix`].
///
/// `npm install --prefix <dir> <pkg>` is a LOCAL install rooted at `<dir>`, so
/// its binaries land in `<dir>/node_modules/.bin` rather than in `<dir>/bin`.
/// Naming the wrong one of those two is a provisioning run that reports success
/// over a binary nothing can reach, which is the shape `kin doctor` already
/// re-probes `PATH` to catch.
pub fn managed_node_bin_dir() -> PathBuf {
    managed_node_prefix().join("node_modules").join(".bin")
}

/// Every directory Kin's own provisioning writes executables into.
pub fn managed_tool_dirs() -> Vec<PathBuf> {
    vec![managed_tool_bin_dir(), managed_node_bin_dir()]
}

/// `PATH` with Kin's tool directories appended, or `None` when it already
/// carries all of them.
///
/// Pure over its inputs so the composition is testable without touching the
/// process environment, and returning `None` for a no-op is what keeps a
/// repeated call from growing `PATH` once per invocation in a shell that
/// re-execs `kin`.
pub fn path_with_managed_tools(current: Option<&OsString>, dirs: &[PathBuf]) -> Option<OsString> {
    path_with_tool_dirs(current, &[], dirs)
}

/// `PATH` with the operator's language-tool directories and Kin's managed
/// directories added, or `None` when nothing is missing.
///
/// The operator's entries keep their order and come first. A missing search
/// directory goes in ahead of the first managed directory already on `PATH`,
/// or at the end when there is none, so a server the operator installed always
/// resolves ahead of Kin's pinned fallback. Missing managed directories go last.
pub fn path_with_tool_dirs(
    current: Option<&OsString>,
    search: &[PathBuf],
    managed: &[PathBuf],
) -> Option<OsString> {
    let original: Vec<PathBuf> = current
        .map(|value| std::env::split_paths(value).collect())
        .unwrap_or_default();
    let mut entries = original.clone();
    let mut missing_search: Vec<PathBuf> = Vec::new();
    for dir in search {
        if !entries.contains(dir) && !missing_search.contains(dir) && !managed.contains(dir) {
            missing_search.push(dir.clone());
        }
    }
    let at = entries
        .iter()
        .position(|entry| managed.contains(entry))
        .unwrap_or(entries.len());
    entries.splice(at..at, missing_search);
    for dir in managed {
        if !entries.contains(dir) {
            entries.push(dir.clone());
        }
    }
    if entries == original {
        return None;
    }
    std::env::join_paths(entries).ok()
}

/// Put the operator's language-tool directories and Kin's own on this
/// process's `PATH`.
///
/// Call while the process is still single-threaded. Mutating the environment
/// after threads exist is unsound, and both binaries already have a
/// single-threaded prologue for exactly this class of change.
///
/// Returns whether `PATH` was changed, so a caller can say so rather than
/// assert it.
pub fn augment_path_with_managed_tools() -> bool {
    let search = language_tool_search_dirs();
    let managed = managed_tool_dirs();
    let current = std::env::var_os("PATH");
    match path_with_tool_dirs(current.as_ref(), &search, &managed) {
        Some(updated) => {
            std::env::set_var("PATH", updated);
            true
        }
        None => false,
    }
}

/// Name an operator uses to keep Kin to the inherited `PATH`.
///
/// Set falsy (`0`, `false`, `no` or `off`) and neither the recorded directories
/// nor the usual install places are searched, which is how every Kin process
/// behaved before they were. For a host whose operator controls exactly which
/// servers run, and for a test that has to know no server is reachable.
pub const LANGUAGE_TOOL_SEARCH_ENV: &str = "KIN_LANGUAGE_TOOL_SEARCH";

/// Whether [`LANGUAGE_TOOL_SEARCH_ENV`] leaves the extra search on.
fn language_tool_search_enabled(value: Option<OsString>) -> bool {
    !matches!(
        value
            .as_deref()
            .and_then(|value| value.to_str())
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "false" | "no" | "off")
    )
}

/// The directories, beyond the inherited `PATH`, that this host's language
/// servers and their toolchains are looked for in: the recorded ones first,
/// then the usual install places, each only when it exists. Empty when
/// [`LANGUAGE_TOOL_SEARCH_ENV`] turns the search off.
pub fn language_tool_search_dirs() -> Vec<PathBuf> {
    let home = directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf());
    search_dirs_from(&recorded_tool_dirs_path(), home.as_deref(), |key| {
        std::env::var_os(key)
    })
}

/// [`language_tool_search_dirs`] with the record, the home and the environment
/// as arguments, so it is testable without touching the process environment.
fn search_dirs_from(
    recorded: &Path,
    home: Option<&Path>,
    var_os: impl Fn(&str) -> Option<OsString>,
) -> Vec<PathBuf> {
    if !language_tool_search_enabled(var_os(LANGUAGE_TOOL_SEARCH_ENV)) {
        return Vec::new();
    }
    let mut dirs = read_recorded_tool_dirs_at(recorded);
    for dir in usual_tool_dirs(home, var_os) {
        if !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs.retain(|dir| dir.is_dir());
    dirs
}

/// The file that records where a shell found language servers.
pub fn recorded_tool_dirs_path() -> PathBuf {
    managed_tool_root().join("search-path")
}

/// Directories recorded by [`record_tool_dirs`], in the order they were
/// recorded. Relative and empty lines are skipped, and a missing or unreadable
/// file records nothing.
pub fn read_recorded_tool_dirs() -> Vec<PathBuf> {
    read_recorded_tool_dirs_at(&recorded_tool_dirs_path())
}

fn read_recorded_tool_dirs_at(recorded: &Path) -> Vec<PathBuf> {
    std::fs::read_to_string(recorded)
        .map(|text| parse_recorded_tool_dirs(&text))
        .unwrap_or_default()
}

fn parse_recorded_tool_dirs(text: &str) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    for line in text.lines() {
        let dir = PathBuf::from(line.trim());
        if dir.is_absolute() && !dirs.contains(&dir) {
            dirs.push(dir);
        }
    }
    dirs
}

/// Directories a process started by an AI client would never search without
/// being told: every one of `found` that is absolute, exists, is not one of
/// Kin's managed directories, is not already searched and is not a system
/// directory every process has.
fn tool_dirs_worth_recording(
    found: &[PathBuf],
    searched: &[PathBuf],
    managed: &[PathBuf],
) -> Vec<PathBuf> {
    let mut new: Vec<PathBuf> = Vec::new();
    for dir in found {
        if dir.is_absolute()
            && dir.is_dir()
            && !managed.contains(dir)
            && !searched.contains(dir)
            && !is_system_bin_dir(dir)
            && !new.contains(dir)
        {
            new.push(dir.clone());
        }
    }
    new
}

/// Record where this process found language servers and their toolchains, so
/// a daemon started with some other process's `PATH` searches there too.
///
/// Adds to what is recorded rather than replacing it, and writes through a
/// sibling file renamed into place, so a reader never sees half a list.
/// Returns the directories this call added.
pub fn record_tool_dirs(found: &[PathBuf]) -> std::io::Result<Vec<PathBuf>> {
    record_tool_dirs_at(
        &recorded_tool_dirs_path(),
        found,
        &language_tool_search_dirs(),
        &managed_tool_dirs(),
    )
}

fn record_tool_dirs_at(
    recorded: &Path,
    found: &[PathBuf],
    searched: &[PathBuf],
    managed: &[PathBuf],
) -> std::io::Result<Vec<PathBuf>> {
    let mut already = read_recorded_tool_dirs_at(recorded);
    already.extend(searched.iter().cloned());
    let added = tool_dirs_worth_recording(found, &already, managed);
    if added.is_empty() {
        return Ok(added);
    }
    let mut all = read_recorded_tool_dirs_at(recorded);
    all.extend(added.iter().cloned());
    let mut text = String::new();
    for dir in &all {
        let Some(line) = dir.to_str() else { continue };
        text.push_str(line);
        text.push('\n');
    }
    if let Some(parent) = recorded.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let staged = recorded.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&staged, text)?;
    std::fs::rename(&staged, recorded)?;
    Ok(added)
}

/// Directories every process gets from the operating system's default `PATH`,
/// which a record would only repeat.
fn is_system_bin_dir(dir: &Path) -> bool {
    ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/sbin"]
        .iter()
        .any(|system| dir == Path::new(system))
}

/// Where people usually install language servers and the toolchains those
/// servers run on, for a home and an environment.
///
/// Every candidate, whether it exists or not; [`language_tool_search_dirs`]
/// keeps the ones that do. The environment is an argument and the only files
/// read are npm's and nvm's own configuration, so every shape is testable
/// without the toolchains a test machine happens to have.
///
/// In order: rustup's proxies (`rust-analyzer`, and the `cargo` it runs), the
/// Go bin directory (`gopls`), npm's configured global prefix, nvm's default
/// node, volta, fnm, the pyenv, asdf and mise shims, `~/.local/bin` (pipx and
/// `pip --user`), then the system-wide places a desktop app's `PATH` lacks on
/// macOS: the Go installer's directory and Homebrew's.
pub fn usual_tool_dirs(
    home: Option<&Path>,
    var_os: impl Fn(&str) -> Option<OsString>,
) -> Vec<PathBuf> {
    let var = |key: &str| {
        var_os(key)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let from_home = |relative: &str| home.map(|home| home.join(relative));
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut push = |dir: Option<PathBuf>| {
        if let Some(dir) = dir.filter(|dir| dir.is_absolute()) {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    };

    push(
        var("CARGO_HOME")
            .map(|cargo| cargo.join("bin"))
            .or_else(|| from_home(".cargo/bin")),
    );

    push(var("GOBIN"));
    push(
        var("GOPATH")
            .and_then(|gopath| std::env::split_paths(&gopath).next())
            .map(|first| first.join("bin"))
            .or_else(|| from_home("go/bin")),
    );

    for prefix in [
        var("NPM_CONFIG_PREFIX").or_else(|| var("npm_config_prefix")),
        home.and_then(npmrc_prefix),
    ]
    .into_iter()
    .flatten()
    {
        push(Some(npm_prefix_bin(&prefix)));
    }
    push(from_home(".npm-global/bin"));
    if cfg!(windows) {
        push(var("APPDATA").map(|appdata| appdata.join("npm")));
    }

    let nvm = var("NVM_DIR").or_else(|| from_home(".nvm"));
    push(nvm.as_deref().and_then(nvm_default_bin));
    push(
        var("VOLTA_HOME")
            .map(|volta| volta.join("bin"))
            .or_else(|| from_home(".volta/bin")),
    );
    for fnm in [
        var("FNM_DIR"),
        from_home(".local/share/fnm"),
        from_home("Library/Application Support/fnm"),
        from_home(".fnm"),
    ]
    .into_iter()
    .flatten()
    {
        push(Some(fnm.join("aliases").join("default").join("bin")));
    }

    push(
        var("PYENV_ROOT")
            .map(|pyenv| pyenv.join("shims"))
            .or_else(|| from_home(".pyenv/shims")),
    );
    push(
        var("ASDF_DATA_DIR")
            .map(|asdf| asdf.join("shims"))
            .or_else(|| from_home(".asdf/shims")),
    );
    push(
        var("MISE_DATA_DIR")
            .map(|mise| mise.join("shims"))
            .or_else(|| from_home(".local/share/mise/shims")),
    );
    push(from_home(".local/bin"));

    if !cfg!(windows) {
        for system in [
            "/usr/local/go/bin",
            "/opt/homebrew/bin",
            "/usr/local/bin",
            "/home/linuxbrew/.linuxbrew/bin",
        ] {
            push(Some(PathBuf::from(system)));
        }
    }
    dirs
}

/// Where npm links the executables of a global prefix.
fn npm_prefix_bin(prefix: &Path) -> PathBuf {
    if cfg!(windows) {
        prefix.to_path_buf()
    } else {
        prefix.join("bin")
    }
}

/// The `prefix` a user's `~/.npmrc` sets, which is where `npm install -g`
/// puts packages when it is set.
fn npmrc_prefix(home: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(home.join(".npmrc")).ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim() != "prefix" {
            return None;
        }
        // Quotes, double or single, spelled by code point so no scanner that
        // reads string literals mistakes a quote character for one.
        let value = value
            .trim()
            .trim_matches(|c: char| c == '\u{22}' || c == '\u{27}');
        let expanded = match value.strip_prefix("~/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(value),
        };
        expanded.is_absolute().then_some(expanded)
    })
}

/// The `bin` directory of the node nvm uses by default.
///
/// nvm names its default in `alias/default`, as an exact version (`v20.11.1`),
/// a version prefix (`20`), `node` or `stable` for the newest installed, or
/// another alias such as `lts/*`, which names `lts/iron`, which names a version.
/// A few hops are followed, and the newest installed version the name matches
/// is the one used, which is how nvm resolves it.
fn nvm_default_bin(nvm_dir: &Path) -> Option<PathBuf> {
    let versions = nvm_dir.join("versions").join("node");
    let mut name = "default".to_string();
    for _ in 0..4 {
        let target = std::fs::read_to_string(nvm_dir.join("alias").join(&name)).ok()?;
        let target = target.trim().to_string();
        if let Some(bin) = newest_installed_node(&versions, &target) {
            return Some(bin);
        }
        name = target;
    }
    None
}

/// The `bin` directory of the newest installed node whose version `spec`
/// names, or `None` when `spec` is not a version name or nothing matches.
fn newest_installed_node(versions: &Path, spec: &str) -> Option<PathBuf> {
    let spec = spec.trim_start_matches('v');
    let any = matches!(spec, "node" | "stable");
    if !any && !spec.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut best: Option<(Vec<u64>, PathBuf)> = None;
    for entry in std::fs::read_dir(versions).ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(version) = name.strip_prefix('v') else {
            continue;
        };
        let matches = any
            || version == spec
            || version
                .strip_prefix(spec)
                .is_some_and(|rest| rest.starts_with('.'));
        if !matches {
            continue;
        }
        let key: Vec<u64> = version
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect();
        if best.as_ref().is_none_or(|(current, _)| key > *current) {
            best = Some((key, entry.path().join("bin")));
        }
    }
    best.map(|(_, bin)| bin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(value: &str) -> OsString {
        OsString::from(value)
    }

    fn parts(value: &OsString) -> Vec<PathBuf> {
        std::env::split_paths(value).collect()
    }

    /// The tool directories land at the END, behind whatever the operator has.
    ///
    /// The direction is the whole point. Kin's pinned `rust-analyzer` does not
    /// track the toolchain that compiled the repository and a rustup component
    /// does, so a host that has one must keep using it. A composition that put
    /// Kin's copy first would silently replace a working server with a
    /// different one and nothing downstream would report the swap.
    #[test]
    fn managed_directories_are_appended_rather_than_prepended() {
        let current = os("/usr/local/bin:/usr/bin");
        let dirs = vec![PathBuf::from("/home/u/.kin/tools/bin")];
        let updated = path_with_managed_tools(Some(&current), &dirs)
            .expect("a PATH without the tool dir must be rewritten");
        assert_eq!(
            parts(&updated),
            vec![
                PathBuf::from("/usr/local/bin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/home/u/.kin/tools/bin"),
            ],
            "Kin's own tool directory must not shadow an operator's toolchain"
        );
    }

    /// A second call adds nothing, so a re-exec cannot grow `PATH` without end.
    #[test]
    fn a_path_that_already_carries_the_directories_is_left_alone() {
        let dirs = vec![
            PathBuf::from("/home/u/.kin/tools/bin"),
            PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
        ];
        let current =
            os("/usr/bin:/home/u/.kin/tools/bin:/home/u/.kin/tools/node/node_modules/.bin");
        assert_eq!(
            path_with_managed_tools(Some(&current), &dirs),
            None,
            "every directory was already present, so there is nothing to add"
        );
    }

    /// A partly-present `PATH` gains only what it is missing.
    #[test]
    fn only_the_missing_directories_are_added() {
        let dirs = vec![
            PathBuf::from("/home/u/.kin/tools/bin"),
            PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
        ];
        let current = os("/home/u/.kin/tools/bin:/usr/bin");
        let updated = path_with_managed_tools(Some(&current), &dirs)
            .expect("one directory is missing, so PATH must be rewritten");
        assert_eq!(
            parts(&updated),
            vec![
                PathBuf::from("/home/u/.kin/tools/bin"),
                PathBuf::from("/usr/bin"),
                PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
            ]
        );
    }

    /// An unset `PATH` still yields the tool directories rather than nothing.
    #[test]
    fn an_absent_path_becomes_the_tool_directories() {
        let dirs = vec![PathBuf::from("/home/u/.kin/tools/bin")];
        let updated =
            path_with_managed_tools(None, &dirs).expect("an unset PATH must still be composed");
        assert_eq!(
            parts(&updated),
            vec![PathBuf::from("/home/u/.kin/tools/bin")]
        );
    }

    /// The npm prefix and the directory npm links binaries into are different
    /// paths, and provisioning has to name the second one.
    #[test]
    fn the_node_bin_directory_is_the_local_install_link_directory() {
        let prefix = managed_node_prefix();
        let bin = managed_node_bin_dir();
        assert_eq!(
            bin,
            prefix.join("node_modules").join(".bin"),
            "`npm install --prefix` links binaries into node_modules/.bin, not into bin"
        );
        assert!(
            managed_tool_dirs().contains(&bin),
            "a directory provisioning writes into must be one PATH carries"
        );
    }

    /// The process mutation and the composition agree, asserted against the
    /// live environment rather than inferred from the pure half.
    ///
    /// Kept separate and behind the workspace's one sanctioned environment
    /// guard, because this is the only assertion here whose subject IS the
    /// environment read.
    #[test]
    fn the_process_path_gains_the_tool_directories() {
        let _guard = crate::test_env::EnvVarGuard::set("PATH", "/usr/bin");
        assert!(
            augment_path_with_managed_tools(),
            "a PATH of /usr/bin alone carries none of Kin's tool directories"
        );
        let after = std::env::var_os("PATH").expect("PATH must still be set");
        let entries = parts(&after);
        for dir in managed_tool_dirs() {
            assert!(
                entries.contains(&dir),
                "PATH must carry {} after augmentation, got {after:?}",
                dir.display()
            );
        }
        // The same call carries this host's language-tool directories, ahead
        // of Kin's own. Read from the live environment on purpose: this is the
        // wiring a daemon started by an AI client runs through.
        let first_managed = entries
            .iter()
            .position(|entry| managed_tool_dirs().contains(entry))
            .expect("a managed directory is on PATH");
        for dir in language_tool_search_dirs() {
            if dir == Path::new("/usr/bin") {
                continue;
            }
            let at = entries.iter().position(|entry| *entry == dir);
            assert!(
                at.is_some_and(|at| at < first_managed),
                "{} must be on PATH ahead of Kin's managed directories, got {after:?}",
                dir.display()
            );
        }
        assert!(
            !augment_path_with_managed_tools(),
            "a second call must be a no-op rather than a second append"
        );
    }

    /// An executable file at `path`, so `which` accepts it. Unix only, like
    /// every test that uses it.
    #[cfg(unix)]
    fn fake_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// Kin's managed directories for a fixture home, named rather than read
    /// from the environment. Unix only, like every test that uses it.
    #[cfg(unix)]
    fn fixture_managed(home: &Path) -> Vec<PathBuf> {
        vec![
            home.join(".kin/tools/bin"),
            home.join(".kin/tools/node/node_modules/.bin"),
        ]
    }

    /// A daemon an AI client starts gets that client's bare `PATH`, and it
    /// still finds the language servers installed where people install them.
    ///
    /// This is the defect: `kin doctor` in a terminal reported gopls and
    /// rust-analyzer present, and the daemon the client started searched only
    /// its inherited `PATH` and Kin's own directories, so it found neither.
    ///
    /// Falsify by returning nothing from `search_dirs_from`: neither server
    /// resolves.
    #[cfg(unix)]
    #[test]
    fn a_server_in_a_usual_install_place_resolves_for_a_process_with_a_bare_path() {
        let home = tempfile::tempdir().unwrap();
        let gopls = home.path().join("go/bin/gopls");
        let rust_analyzer = home.path().join(".cargo/bin/rust-analyzer");
        fake_executable(&gopls);
        fake_executable(&rust_analyzer);
        let managed = fixture_managed(home.path());

        let search = search_dirs_from(
            &home.path().join("absent-record"),
            Some(home.path()),
            |_| None,
        );
        let path = path_with_tool_dirs(Some(&os("/usr/bin:/bin")), &search, &managed)
            .expect("the usual places are missing from a bare PATH");

        assert_eq!(
            which::which_in("gopls", Some(&path), home.path()).ok(),
            Some(gopls)
        );
        assert_eq!(
            which::which_in("rust-analyzer", Some(&path), home.path()).ok(),
            Some(rust_analyzer)
        );
        let entries = parts(&path);
        let go_bin = entries
            .iter()
            .position(|dir| *dir == home.path().join("go/bin"));
        let first_managed = entries.iter().position(|dir| managed.contains(dir));
        assert!(
            go_bin.is_some() && first_managed.is_some() && go_bin < first_managed,
            "the operator's install must resolve ahead of Kin's pinned copies: {entries:?}"
        );
        assert_eq!(
            entries.iter().take(2).cloned().collect::<Vec<_>>(),
            vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")],
            "the inherited entries keep their place at the front"
        );
    }

    /// The opt-out keeps a process to its inherited `PATH`, and only an
    /// explicit falsy value turns the search off.
    #[cfg(unix)]
    #[test]
    fn the_extra_search_can_be_turned_off() {
        let home = tempfile::tempdir().unwrap();
        fake_executable(&home.path().join("go/bin/gopls"));
        let off = |key: &str| (key == LANGUAGE_TOOL_SEARCH_ENV).then(|| OsString::from("off"));

        let search = search_dirs_from(&home.path().join("absent-record"), Some(home.path()), off);
        assert!(search.is_empty(), "{search:?}");

        for (value, enabled) in [
            (None, true),
            (Some("1"), true),
            (Some("yes"), true),
            (Some(""), true),
            (Some("0"), false),
            (Some(" False "), false),
            (Some("no"), false),
            (Some("OFF"), false),
        ] {
            assert_eq!(
                language_tool_search_enabled(value.map(OsString::from)),
                enabled,
                "{value:?}"
            );
        }
    }

    /// What a shell recorded is searched by a process that shell did not
    /// start, and recording the same place twice adds nothing.
    #[cfg(unix)]
    #[test]
    fn a_recorded_directory_is_searched_and_recorded_once() {
        let home = tempfile::tempdir().unwrap();
        let recorded = home.path().join(".kin/tools/search-path");
        let custom = home.path().join("opt/servers/bin");
        fake_executable(&custom.join("pyright-langserver"));
        let managed = fixture_managed(home.path());

        let added = record_tool_dirs_at(
            &recorded,
            &[
                custom.clone(),
                PathBuf::from("/usr/bin"),
                managed[0].clone(),
            ],
            &[],
            &managed,
        )
        .unwrap();
        assert_eq!(
            added,
            vec![custom.clone()],
            "a system directory and Kin's own are never recorded"
        );
        assert!(
            record_tool_dirs_at(&recorded, std::slice::from_ref(&custom), &[], &managed)
                .unwrap()
                .is_empty(),
            "a recorded directory is not recorded again"
        );
        assert_eq!(read_recorded_tool_dirs_at(&recorded), vec![custom.clone()]);

        let search = search_dirs_from(&recorded, Some(home.path()), |_| None);
        assert_eq!(search.first(), Some(&custom), "recorded directories lead");
        let path = path_with_tool_dirs(Some(&os("/usr/bin:/bin")), &search, &managed).unwrap();
        assert_eq!(
            which::which_in("pyright-langserver", Some(&path), home.path()).ok(),
            Some(custom.join("pyright-langserver"))
        );
    }

    /// A search directory goes in ahead of Kin's managed ones even when a
    /// parent process already put those on `PATH`, and a second composition
    /// changes nothing.
    #[test]
    fn operator_directories_go_ahead_of_managed_ones_already_on_path() {
        let managed = vec![
            PathBuf::from("/home/u/.kin/tools/bin"),
            PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
        ];
        let search = vec![PathBuf::from("/home/u/.cargo/bin")];
        let current = os("/usr/bin:/home/u/.kin/tools/bin");
        let updated = path_with_tool_dirs(Some(&current), &search, &managed)
            .expect("two directories are missing");
        assert_eq!(
            parts(&updated),
            vec![
                PathBuf::from("/usr/bin"),
                PathBuf::from("/home/u/.cargo/bin"),
                PathBuf::from("/home/u/.kin/tools/bin"),
                PathBuf::from("/home/u/.kin/tools/node/node_modules/.bin"),
            ]
        );
        assert_eq!(
            path_with_tool_dirs(Some(&updated), &search, &managed),
            None,
            "a re-exec must not grow PATH"
        );
    }

    /// The usual places follow the toolchain's own environment and
    /// configuration when they are set, and fall back to the defaults when not.
    #[cfg(unix)]
    #[test]
    fn the_usual_places_follow_each_toolchains_own_settings() {
        let home = tempfile::tempdir().unwrap();
        let home_path = home.path();
        std::fs::write(
            home_path.join(".npmrc"),
            "color=false\nprefix=~/.npm-packages\n",
        )
        .unwrap();
        let nvm = home_path.join(".nvm");
        for version in ["v18.19.0", "v20.1.0", "v20.11.1", "v22.3.0"] {
            std::fs::create_dir_all(nvm.join("versions/node").join(version).join("bin")).unwrap();
        }
        std::fs::create_dir_all(nvm.join("alias/lts")).unwrap();
        std::fs::write(nvm.join("alias/default"), "lts/*\n").unwrap();
        std::fs::write(nvm.join("alias/lts/*"), "lts/iron\n").unwrap();
        std::fs::write(nvm.join("alias/lts/iron"), "v20.11.1\n").unwrap();

        let env = |key: &str| match key {
            "CARGO_HOME" => Some(OsString::from("/opt/cargo")),
            "GOPATH" => Some(OsString::from("/work/go:/other/go")),
            _ => None,
        };
        let dirs = usual_tool_dirs(Some(home_path), env);

        for expected in [
            PathBuf::from("/opt/cargo/bin"),
            PathBuf::from("/work/go/bin"),
            home_path.join(".npm-packages/bin"),
            nvm.join("versions/node/v20.11.1/bin"),
            home_path.join(".pyenv/shims"),
            home_path.join(".local/bin"),
        ] {
            assert!(
                dirs.contains(&expected),
                "{expected:?} missing from {dirs:?}"
            );
        }
        assert!(
            !dirs.contains(&home_path.join(".cargo/bin")),
            "CARGO_HOME replaces the default rather than adding to it: {dirs:?}"
        );
        assert!(
            !dirs.iter().any(|dir| dir.ends_with("v22.3.0/bin")),
            "nvm's default names lts/iron, not the newest node: {dirs:?}"
        );

        std::fs::write(nvm.join("alias/default"), "20\n").unwrap();
        let dirs = usual_tool_dirs(Some(home_path), |_| None);
        assert!(
            dirs.contains(&nvm.join("versions/node/v20.11.1/bin")),
            "a version prefix resolves to the newest install it names: {dirs:?}"
        );
    }
}
