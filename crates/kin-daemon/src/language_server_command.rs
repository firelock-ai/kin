// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which executable this daemon starts for a language server.
//!
//! One answer, decided here and used by every path that starts a server: the
//! readiness probe, the cold sweep and the incremental path. Each of them used
//! to hand a bare command name to `LspServer::start`, which resolved it through
//! `PATH` from whatever working directory the daemon inherited, and the probe
//! resolved a list of its own through kin-lsp's registry. For `rust-analyzer`
//! that name is usually rustup's proxy, and the proxy picks a toolchain from the
//! working directory it runs in.
//!
//! Measured on a kin-db clone that pins `channel = "1.96.0"`, a toolchain
//! installed without the rust-analyzer component: the daemon `kin init` started
//! from outside the clone ran stable's rust-analyzer and enriched 72 of 72
//! files, and the daemon `kin mcp start --repo` started inside the clone could
//! not start one at all. Two daemons on one store disagreed about whether Rust
//! could be enriched, and which one a user got depended on the directory they
//! launched from.
//!
//! So the proxy is asked, from the workspace root, which binary it would run
//! there, and when the toolchain the workspace selects does not ship one, every
//! other installed toolchain is asked in turn. The first that answers is started
//! by absolute path, which the daemon's working directory can no longer change.
//! When none answers, the failure names every toolchain tried and the command
//! that repairs it, rather than a bare "did not start".

use std::path::{Path, PathBuf};
use std::time::Duration;

/// What one language server's command resolves to on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ServerCommand {
    /// Start this program. `chosen` says how it was picked, which is what the
    /// daemon logs so a reader can tell which binary ran.
    Resolved { program: PathBuf, chosen: String },
    /// Nothing by the adapter's command name is on this daemon's `PATH`.
    NotInstalled,
    /// Something by that name is on `PATH` and nothing it leads to can serve.
    /// `reason` names what was tried and what would repair it.
    Unresolvable { reason: String },
}

/// What the resolver asks of the host, so every branch is testable without
/// the toolchains a test machine happens to have.
pub(crate) trait ToolchainHost {
    /// Where `binary` resolves on this process's `PATH`.
    fn find_on_path(&self, binary: &str) -> Option<PathBuf>;

    /// The rustup executable behind `program` when `program` is one of
    /// rustup's proxies, and `None` when it is a server binary of its own.
    fn rustup_behind(&self, program: &Path) -> Option<PathBuf>;

    /// The toolchain rustup selects in `dir`, by name.
    fn active_toolchain(&self, rustup: &Path, dir: &Path) -> Option<String>;

    /// Every installed toolchain, the default first.
    fn installed_toolchains(&self, rustup: &Path, dir: &Path) -> Vec<String>;

    /// `rustup which <binary>` run in `dir`, or for `toolchain` when one is
    /// named. The error is rustup's own words.
    fn rustup_which(
        &self,
        rustup: &Path,
        dir: &Path,
        toolchain: Option<&str>,
        binary: &str,
    ) -> Result<PathBuf, String>;
}

/// Resolve `binary`, the command an adapter names, for the workspace rooted at
/// `workspace_root`.
///
/// A binary that is not rustup's proxy is started from where `PATH` found it,
/// which is every server but rust-analyzer on a rustup host and is the behaviour
/// the daemon always had for them. Only the proxy is resolved further, because
/// only the proxy's answer depends on the directory it is asked from.
pub(crate) fn resolve_server_command(
    binary: &str,
    workspace_root: &Path,
    host: &dyn ToolchainHost,
) -> ServerCommand {
    let Some(found) = host.find_on_path(binary) else {
        return ServerCommand::NotInstalled;
    };
    let Some(rustup) = host.rustup_behind(&found) else {
        return ServerCommand::Resolved {
            chosen: format!("{} on this daemon's PATH", found.display()),
            program: found,
        };
    };

    let selected = host.active_toolchain(&rustup, workspace_root);
    let selected_name = selected
        .clone()
        .unwrap_or_else(|| "the toolchain this workspace selects".to_string());
    let mut tried: Vec<String> = Vec::new();
    match host.rustup_which(&rustup, workspace_root, None, binary) {
        Ok(program) => {
            return ServerCommand::Resolved {
                chosen: format!(
                    "rustup toolchain {selected_name}, which {} selects",
                    workspace_root.display()
                ),
                program,
            };
        }
        Err(error) => tried.push(format!("{selected_name} ({error})")),
    }
    for toolchain in host.installed_toolchains(&rustup, workspace_root) {
        if selected.as_deref() == Some(toolchain.as_str()) {
            continue;
        }
        match host.rustup_which(&rustup, workspace_root, Some(&toolchain), binary) {
            Ok(program) => {
                return ServerCommand::Resolved {
                    chosen: format!(
                        "rustup toolchain {toolchain}, because {selected_name}, which {} \
                         selects, does not ship {binary}",
                        workspace_root.display()
                    ),
                    program,
                };
            }
            Err(error) => tried.push(format!("{toolchain} ({error})")),
        }
    }
    let repair_for_selected = selected
        .as_deref()
        .map(|name| {
            format!(
                ", or `rustup component add {binary} --toolchain {name}` for the toolchain this \
                 workspace selects"
            )
        })
        .unwrap_or_default();
    ServerCommand::Unresolvable {
        reason: format!(
            "`{binary}` on this daemon's PATH is rustup's proxy ({}), and no installed toolchain \
             ships it. Tried {}. Install it with `rustup component add {binary}`{repair_for_selected}",
            found.display(),
            tried.join(", "),
        ),
    }
}

/// [`resolve_server_command`] against this host, off the async runtime,
/// because a rustup query is a process to wait for.
pub(crate) async fn resolve_on_this_host(binary: String, workspace_root: PathBuf) -> ServerCommand {
    tokio::task::spawn_blocking(move || {
        resolve_server_command(&binary, &workspace_root, &SystemToolchainHost)
    })
    .await
    .unwrap_or_else(|error| ServerCommand::Unresolvable {
        reason: format!("the language-server resolver did not finish ({error})"),
    })
}

/// The host this daemon runs on.
pub(crate) struct SystemToolchainHost;

/// How long one rustup query may take.
///
/// rustup answers these from local state in milliseconds. The bound exists so a
/// rustup that decides to do something slower cannot hold a sweep, and it is
/// paid only when a query hangs.
const RUSTUP_QUERY_BUDGET: Duration = Duration::from_secs(10);

impl ToolchainHost for SystemToolchainHost {
    fn find_on_path(&self, binary: &str) -> Option<PathBuf> {
        which::which(binary).ok()
    }

    fn rustup_behind(&self, program: &Path) -> Option<PathBuf> {
        proxy_rustup_for(program)
    }

    fn active_toolchain(&self, rustup: &Path, dir: &Path) -> Option<String> {
        run_rustup(rustup, dir, &["show", "active-toolchain"])
            .ok()
            .and_then(|stdout| first_token(&stdout))
    }

    fn installed_toolchains(&self, rustup: &Path, dir: &Path) -> Vec<String> {
        run_rustup(rustup, dir, &["toolchain", "list"])
            .map(|stdout| parse_toolchain_list(&stdout))
            .unwrap_or_default()
    }

    fn rustup_which(
        &self,
        rustup: &Path,
        dir: &Path,
        toolchain: Option<&str>,
        binary: &str,
    ) -> Result<PathBuf, String> {
        let mut args = vec!["which"];
        if let Some(toolchain) = toolchain {
            args.push("--toolchain");
            args.push(toolchain);
        }
        args.push(binary);
        let stdout = run_rustup(rustup, dir, &args)?;
        first_line(&stdout)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| format!("rustup named no absolute path for {binary}"))
    }
}

/// The rustup executable behind `program`, when `program` is one of its
/// proxies.
///
/// rustup installs a proxy for every tool it manages beside itself in
/// `$CARGO_HOME/bin`, as a symbolic link to `rustup` on some hosts and as a hard
/// link on others. A program that is neither, including a rust-analyzer
/// installed into the same directory by its own installer, is a server binary
/// and is started as found.
fn proxy_rustup_for(program: &Path) -> Option<PathBuf> {
    let rustup = program
        .parent()?
        .join(format!("rustup{}", std::env::consts::EXE_SUFFIX));
    if program.file_name() == rustup.file_name() {
        return None;
    }
    let rustup_identity = std::fs::metadata(&rustup).ok()?;
    if let (Ok(target), Ok(rustup_target)) = (
        std::fs::canonicalize(program),
        std::fs::canonicalize(&rustup),
    ) {
        if target == rustup_target {
            return Some(rustup);
        }
    }
    let identity = std::fs::metadata(program).ok()?;
    #[cfg(unix)]
    let same_file = {
        use std::os::unix::fs::MetadataExt;
        identity.dev() == rustup_identity.dev() && identity.ino() == rustup_identity.ino()
    };
    // Windows exposes no stable file identity through std, and rustup installs
    // its proxies there as hard links to, or copies of, the rustup.exe beside
    // them, so the same length beside it is the proxy.
    #[cfg(not(unix))]
    let same_file = identity.len() == rustup_identity.len();
    same_file.then_some(rustup)
}

/// Run one local rustup query in `dir` and return its standard output.
///
/// `RUSTUP_AUTO_INSTALL=0` because a query must never install a toolchain a
/// `rust-toolchain.toml` names: this runs inside a daemon nobody is watching,
/// and a download it started would be a side effect nobody asked for. The
/// error carries rustup's first line of standard error, which is the sentence
/// that names the toolchain and what it lacks.
fn run_rustup(rustup: &Path, dir: &Path, args: &[&str]) -> Result<String, String> {
    use std::process::{Command, Stdio};

    let mut child = Command::new(rustup)
        .args(args)
        .current_dir(dir)
        .env("RUSTUP_AUTO_INSTALL", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not run {}: {error}", rustup.display()))?;
    let deadline = std::time::Instant::now() + RUSTUP_QUERY_BUDGET;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "`rustup {}` did not answer within {}s",
                    args.join(" "),
                    RUSTUP_QUERY_BUDGET.as_secs()
                ));
            }
            Err(error) => return Err(format!("could not wait for rustup: {error}")),
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not read rustup's answer: {error}"))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(first_line(&stderr).unwrap_or_else(|| format!("rustup exited with {}", output.status)))
}

/// The first non-empty line, trimmed.
fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_string)
}

/// The first word of the first non-empty line: the toolchain name in
/// `rustup show active-toolchain`'s answer, which follows it with why it was
/// chosen.
fn first_token(text: &str) -> Option<String> {
    first_line(text)?
        .split_whitespace()
        .next()
        .map(str::to_string)
}

/// Toolchain names from `rustup toolchain list`, the default first and the
/// rest in the order rustup printed them.
///
/// Each line is a name optionally followed by markers such as `(default)`,
/// `(active)` or `(active, default)`. A line that does not start with a name,
/// such as rustup's "no installed toolchains", names nothing.
fn parse_toolchain_list(stdout: &str) -> Vec<String> {
    let mut default = Vec::new();
    let mut rest = Vec::new();
    for line in stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with("no installed toolchains") {
            continue;
        }
        let Some(name) = line.split_whitespace().next() else {
            continue;
        };
        let markers = &line[name.len()..];
        if markers.contains("default") {
            default.push(name.to_string());
        } else {
            rest.push(name.to_string());
        }
    }
    default.extend(rest);
    default
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    const WORKSPACE: &str = "/work/kin-db";
    const PROXY: &str = "/home/u/.cargo/bin/rust-analyzer";
    const RUSTUP: &str = "/home/u/.cargo/bin/rustup";
    const STABLE_RA: &str = "/home/u/.rustup/toolchains/stable/bin/rust-analyzer";
    const PINNED_RA: &str = "/home/u/.rustup/toolchains/1.96.0/bin/rust-analyzer";

    /// A host whose PATH, proxies and toolchains are whatever a test says.
    #[derive(Default)]
    struct FakeHost {
        on_path: HashMap<String, PathBuf>,
        proxies: HashMap<PathBuf, PathBuf>,
        active: Option<String>,
        installed: Vec<String>,
        /// What `rustup which` answers in the workspace directory.
        workspace_answer: Option<Result<PathBuf, String>>,
        /// What `rustup which --toolchain <name>` answers, per toolchain.
        toolchain_answers: HashMap<String, Result<PathBuf, String>>,
        asked: RefCell<Vec<String>>,
    }

    impl ToolchainHost for FakeHost {
        fn find_on_path(&self, binary: &str) -> Option<PathBuf> {
            self.on_path.get(binary).cloned()
        }

        fn rustup_behind(&self, program: &Path) -> Option<PathBuf> {
            self.proxies.get(program).cloned()
        }

        fn active_toolchain(&self, _rustup: &Path, _dir: &Path) -> Option<String> {
            self.active.clone()
        }

        fn installed_toolchains(&self, _rustup: &Path, _dir: &Path) -> Vec<String> {
            self.installed.clone()
        }

        fn rustup_which(
            &self,
            _rustup: &Path,
            dir: &Path,
            toolchain: Option<&str>,
            binary: &str,
        ) -> Result<PathBuf, String> {
            self.asked.borrow_mut().push(format!(
                "{}:{}",
                toolchain.unwrap_or("<workspace>"),
                binary
            ));
            assert_eq!(
                dir,
                Path::new(WORKSPACE),
                "rustup is asked from the workspace root"
            );
            match toolchain {
                None => self
                    .workspace_answer
                    .clone()
                    .unwrap_or_else(|| Err("no answer configured".to_string())),
                Some(name) => self
                    .toolchain_answers
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| Err(format!("unknown toolchain {name}"))),
            }
        }
    }

    fn unknown_binary(toolchain: &str) -> Result<PathBuf, String> {
        Err(format!(
            "error: unknown binary 'rust-analyzer' in toolchain '{toolchain}'"
        ))
    }

    /// The kin-db host, exactly: rustup's proxy on PATH, a workspace pinned to
    /// 1.96.0 installed without the component, and stable carrying it.
    fn pinned_workspace_host() -> FakeHost {
        FakeHost {
            on_path: HashMap::from([("rust-analyzer".to_string(), PathBuf::from(PROXY))]),
            proxies: HashMap::from([(PathBuf::from(PROXY), PathBuf::from(RUSTUP))]),
            active: Some("1.96.0-aarch64-apple-darwin".to_string()),
            installed: vec![
                "stable-aarch64-apple-darwin".to_string(),
                "nightly-2026-06-17-aarch64-apple-darwin".to_string(),
                "1.96.0-aarch64-apple-darwin".to_string(),
            ],
            workspace_answer: Some(unknown_binary("1.96.0-aarch64-apple-darwin")),
            toolchain_answers: HashMap::from([
                (
                    "stable-aarch64-apple-darwin".to_string(),
                    Ok(PathBuf::from(STABLE_RA)),
                ),
                (
                    "nightly-2026-06-17-aarch64-apple-darwin".to_string(),
                    unknown_binary("nightly-2026-06-17-aarch64-apple-darwin"),
                ),
                (
                    "1.96.0-aarch64-apple-darwin".to_string(),
                    unknown_binary("1.96.0-aarch64-apple-darwin"),
                ),
            ]),
            ..FakeHost::default()
        }
    }

    /// The measured failure. A workspace whose pinned toolchain has no
    /// rust-analyzer still gets one, from a toolchain that ships it, by
    /// absolute path, and the log line says why that toolchain was chosen.
    #[test]
    fn a_pinned_toolchain_without_the_server_falls_back_to_one_that_ships_it() {
        let host = pinned_workspace_host();
        match resolve_server_command("rust-analyzer", Path::new(WORKSPACE), &host) {
            ServerCommand::Resolved { program, chosen } => {
                assert_eq!(program, PathBuf::from(STABLE_RA));
                assert!(
                    chosen.contains("stable-aarch64-apple-darwin")
                        && chosen.contains("1.96.0-aarch64-apple-darwin")
                        && chosen.contains("does not ship rust-analyzer"),
                    "the log line must name the toolchain used and the one it replaced: {chosen}"
                );
            }
            other => panic!("expected stable's rust-analyzer, got {other:?}"),
        }
        let asked = host.asked.borrow();
        assert_eq!(
            asked.first().map(String::as_str),
            Some("<workspace>:rust-analyzer"),
            "the workspace's own selection is asked first, so a pin that does ship it wins: \
             {asked:?}"
        );
    }

    /// A workspace whose selected toolchain ships the server uses that one and
    /// asks nothing else.
    #[test]
    fn the_workspace_toolchain_is_used_when_it_ships_the_server() {
        let mut host = pinned_workspace_host();
        host.workspace_answer = Some(Ok(PathBuf::from(PINNED_RA)));
        match resolve_server_command("rust-analyzer", Path::new(WORKSPACE), &host) {
            ServerCommand::Resolved { program, chosen } => {
                assert_eq!(program, PathBuf::from(PINNED_RA));
                assert!(chosen.contains("1.96.0-aarch64-apple-darwin"), "{chosen}");
            }
            other => panic!("expected the pinned toolchain's rust-analyzer, got {other:?}"),
        }
        assert_eq!(
            host.asked.borrow().len(),
            1,
            "no fallback when the pin answers"
        );
    }

    /// No toolchain ships it: the failure is loud, names every toolchain it
    /// tried with rustup's own words, and says how to repair it.
    #[test]
    fn no_toolchain_that_ships_the_server_fails_loud_naming_every_one_tried() {
        let mut host = pinned_workspace_host();
        host.toolchain_answers.insert(
            "stable-aarch64-apple-darwin".to_string(),
            unknown_binary("stable-aarch64-apple-darwin"),
        );
        match resolve_server_command("rust-analyzer", Path::new(WORKSPACE), &host) {
            ServerCommand::Unresolvable { reason } => {
                for toolchain in [
                    "1.96.0-aarch64-apple-darwin",
                    "stable-aarch64-apple-darwin",
                    "nightly-2026-06-17-aarch64-apple-darwin",
                ] {
                    assert!(reason.contains(toolchain), "{toolchain} missing: {reason}");
                }
                assert!(
                    reason.contains("unknown binary 'rust-analyzer'"),
                    "{reason}"
                );
                assert!(
                    reason.contains("rustup component add rust-analyzer"),
                    "{reason}"
                );
                assert!(
                    !reason.contains("; "),
                    "a reason can reach a verdict clause, where `; ` divides clauses: {reason}"
                );
            }
            other => panic!("expected a loud failure, got {other:?}"),
        }
        let asked = host.asked.borrow();
        assert_eq!(
            asked
                .iter()
                .filter(|question| question.starts_with("1.96.0"))
                .count(),
            0,
            "the workspace's own toolchain is not asked twice: {asked:?}"
        );
    }

    /// A server that is not rustup's proxy is started from where PATH found
    /// it, and rustup is never asked about it.
    #[test]
    fn a_binary_that_is_not_a_proxy_starts_as_found() {
        let host = FakeHost {
            on_path: HashMap::from([(
                "rust-analyzer".to_string(),
                PathBuf::from("/opt/homebrew/bin/rust-analyzer"),
            )]),
            ..FakeHost::default()
        };
        assert_eq!(
            resolve_server_command("rust-analyzer", Path::new(WORKSPACE), &host),
            ServerCommand::Resolved {
                program: PathBuf::from("/opt/homebrew/bin/rust-analyzer"),
                chosen: "/opt/homebrew/bin/rust-analyzer on this daemon's PATH".to_string(),
            }
        );
        assert!(host.asked.borrow().is_empty());
    }

    /// Nothing on PATH is `NotInstalled`, which the probe reports as absent
    /// and the sweep as a skip, exactly as a missing binary always was.
    #[test]
    fn nothing_on_path_is_not_installed() {
        assert_eq!(
            resolve_server_command("gopls", Path::new(WORKSPACE), &FakeHost::default()),
            ServerCommand::NotInstalled
        );
    }

    #[test]
    fn the_toolchain_list_puts_the_default_first_and_keeps_rustups_order() {
        let listed = "stable-aarch64-apple-darwin\n\
                      nightly-aarch64-apple-darwin (default)\n\
                      1.96.0-aarch64-apple-darwin (active)\n\
                      1.91.0-aarch64-apple-darwin\n";
        assert_eq!(
            parse_toolchain_list(listed),
            vec![
                "nightly-aarch64-apple-darwin",
                "stable-aarch64-apple-darwin",
                "1.96.0-aarch64-apple-darwin",
                "1.91.0-aarch64-apple-darwin",
            ]
        );
        assert_eq!(
            parse_toolchain_list("1.96.0-aarch64-apple-darwin (active, default)\n"),
            vec!["1.96.0-aarch64-apple-darwin"]
        );
        assert!(parse_toolchain_list("no installed toolchains\n").is_empty());
    }

    #[test]
    fn the_active_toolchain_is_the_first_word_of_rustups_answer() {
        assert_eq!(
            first_token(
                "1.96.0-aarch64-apple-darwin (overridden by '/work/kin-db/rust-toolchain.toml')\n"
            )
            .as_deref(),
            Some("1.96.0-aarch64-apple-darwin")
        );
        assert_eq!(first_token("\n\n"), None);
    }

    /// The proxy check against real files: a symbolic link and a hard link to
    /// `rustup` are proxies, and a server binary installed beside rustup by its
    /// own installer is not.
    #[cfg(unix)]
    #[test]
    fn a_proxy_is_recognised_by_file_identity_and_a_real_binary_is_not() {
        let dir = tempfile::tempdir().expect("temp dir");
        let rustup = dir.path().join("rustup");
        std::fs::write(&rustup, b"#!/bin/sh\n").expect("rustup stand-in");

        let symlinked = dir.path().join("rust-analyzer");
        std::os::unix::fs::symlink("rustup", &symlinked).expect("symlink proxy");
        assert_eq!(proxy_rustup_for(&symlinked), Some(rustup.clone()));

        let hard_linked = dir.path().join("cargo");
        std::fs::hard_link(&rustup, &hard_linked).expect("hard-link proxy");
        assert_eq!(proxy_rustup_for(&hard_linked), Some(rustup.clone()));

        let standalone = dir.path().join("gopls");
        std::fs::write(&standalone, b"#!/bin/sh\necho a real server\n").expect("server");
        assert_eq!(proxy_rustup_for(&standalone), None);

        assert_eq!(
            proxy_rustup_for(&rustup),
            None,
            "rustup itself is not a proxy"
        );

        let elsewhere = tempfile::tempdir().expect("second temp dir");
        let lonely = elsewhere.path().join("rust-analyzer");
        std::fs::write(&lonely, b"#!/bin/sh\n").expect("server without rustup beside it");
        assert_eq!(proxy_rustup_for(&lonely), None);
    }
}
