// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which resolver proved something, and under what.
//!
//! Every proof Kin records names a [`ProofContext`]: the resolver, its own
//! version, a hash of everything it was configured with, and the identity of
//! the environment it answered against. Two proofs under one context were made
//! the same way; a proof whose context is no longer the one the resolver runs
//! under is stale.
//!
//! The configuration hash covers the resolver's own executable by content,
//! the initialize options, the answers to `workspace/configuration`, the
//! adapter's environment variables and label, and the workspace folder, each
//! with the workspace root and the home directory written as placeholders, so
//! one repository configured the same way hashes the same on every machine.
//! Everything in it is known before the server starts, so a sweep can tell
//! whether a proof is current without starting a server to ask. The environment hash is the resolver
//! contract's environment identity: the toolchain and the dependency versions
//! the repository's lock names.

use std::path::Path;

use kin_model::{Hash256, LanguageId, ProofContext};

use crate::adapters::ServerLaunch;

/// Domain of a proof context's configuration hash. The second version adds
/// the resolver's content identity.
const CONFIGURATION_DOMAIN: &str = "kin.proof-context.configuration.v2";

/// What a configuration hash records for a resolver whose executable cannot be
/// identified by content: a shim that picks a program at run time, a script
/// that is not a Node package's entry, or a file that cannot be read.
const UNIDENTIFIED_RESOLVER: &[u8] = b"unidentified";

/// Domain of the environment hash of a launch that names no environment.
const NO_ENVIRONMENT_DOMAIN: &str = "kin.proof-context.environment.none.v1";

/// What a started server's proofs are made under, apart from the language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBasis {
    resolver: String,
    resolver_version: String,
    configuration_hash: Hash256,
    environment_hash: Hash256,
    environment_summary: String,
}

impl ProofBasis {
    /// The basis of a server started from `launch` for `workspace_root`, which
    /// reported `server_name` and `server_version` in its initialize answer.
    /// `command` names the resolver when the server reported no name.
    pub fn of(
        launch: &ServerLaunch,
        workspace_root: &Path,
        command: &str,
        server_name: Option<&str>,
        server_version: Option<&str>,
    ) -> Self {
        Self::of_resolver(
            launch,
            workspace_root,
            command,
            None,
            server_name,
            server_version,
        )
    }

    /// [`Self::of`] for a resolver whose executable has the content identity
    /// `resolver` (see [`resolver_content_identity`]), `None` when it has none.
    pub fn of_resolver(
        launch: &ServerLaunch,
        workspace_root: &Path,
        command: &str,
        resolver_identity: Option<&str>,
        server_name: Option<&str>,
        server_version: Option<&str>,
    ) -> Self {
        let resolver = format!("lsp:{}", resolver_name(server_name, command));
        let resolver_version = server_version
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(|version| sanitize(version, 256))
            .unwrap_or_else(|| "unknown".to_string());
        let (configuration_hash, environment_hash) =
            launch_hashes(launch, workspace_root, command, resolver_identity);
        let environment_summary = launch
            .resolution
            .as_ref()
            .map(|resolution| &resolution.environment)
            .map(|environment| {
                let mut summary = environment.provider.kind().to_string();
                if let Some(toolchain) = &environment.toolchain {
                    summary = format!("{} {}; {summary}", toolchain.name, toolchain.version);
                }
                sanitize(&summary, 512)
            })
            .unwrap_or_default();
        Self {
            resolver,
            resolver_version,
            configuration_hash,
            environment_hash,
            environment_summary,
        }
    }

    /// The proof context of this server's answers about `language`.
    pub fn proof_context(&self, language: LanguageId) -> ProofContext {
        ProofContext {
            language,
            resolver: self.resolver.clone(),
            resolver_version: self.resolver_version.clone(),
            configuration_hash: self.configuration_hash,
            environment_hash: self.environment_hash,
            environment_summary: self.environment_summary.clone(),
        }
    }
}

/// The configuration and environment hashes a server started from `launch`
/// for `workspace_root`, running the executable with content identity
/// `resolver_identity`, proves under, known before it starts.
///
/// A proof context whose two hashes are these was made by a server started
/// exactly this way: the same executable bytes, the same configuration and the
/// same environment, so its proofs are current without asking the server
/// again. Its resolver name and version are what that same executable
/// reports, and add nothing the content identity does not already fix.
pub fn prestart_hashes(
    launch: &ServerLaunch,
    workspace_root: &Path,
    command: &str,
    resolver_identity: &str,
) -> (Hash256, Hash256) {
    launch_hashes(launch, workspace_root, command, Some(resolver_identity))
}

/// The content identity of the executable a resolver runs, or `None` when its
/// content does not fix what runs.
///
/// A native binary is identified by its bytes. A Node package's entry script
/// is identified by its bytes and its package's `package.json`, whose version
/// moves when anything the package ships does. Anything else run through an
/// interpreter is a shim or a wrapper that chooses its program at run time,
/// such as a version manager's, and cannot be identified this way, so a proof
/// made through it is re-checked against a running server instead.
pub fn resolver_content_identity(program: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let real = std::fs::canonicalize(program).ok()?;
    let mut file = std::fs::File::open(&real).ok()?;
    let mut head = [0u8; 256];
    let read = file.read(&mut head).ok()?;
    let head = &head[..read];
    let node_entry = matches!(
        real.extension().and_then(|extension| extension.to_str()),
        Some("js" | "mjs" | "cjs")
    );
    let script = head.starts_with(b"#!");
    if script && !node_entry {
        let line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
        if !String::from_utf8_lossy(line).contains("node") {
            return None;
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(head);
    let mut chunk = vec![0u8; 1 << 16];
    loop {
        let read = file.read(&mut chunk).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    if script || node_entry {
        let manifest = real
            .ancestors()
            .skip(1)
            .take(8)
            .map(|directory| directory.join("package.json"))
            .find(|candidate| candidate.is_file())?;
        hasher.update(b"\0package.json\0");
        hasher.update(std::fs::read(manifest).ok()?);
    }
    Some(format!("sha256:{}", hex_digest(&hasher.finalize())))
}

/// The content identity of what a started server process is running, read
/// from the process itself, or `None` when that does not fix what runs.
///
/// A server started through a shim is identified by what the shim ran: an
/// exec-style shim, like a version manager's, replaces itself with the real
/// server, so the process's executable is that server. A Node server's
/// process is `node`, so its identity is its entry script's, from the
/// process's arguments. A process still running a shell or another
/// interpreter, one that forked the server rather than becoming it, cannot be
/// identified this way.
#[cfg(unix)]
pub fn running_resolver_identity(pid: i32) -> Option<String> {
    let (executable, arguments) = running_process_image(pid)?;
    let name = executable.file_name()?.to_string_lossy().into_owned();
    if name == "node" || name == "nodejs" {
        let script = arguments
            .iter()
            .skip(1)
            .find(|argument| !argument.starts_with('-'))
            .map(std::path::PathBuf::from)
            .filter(|script| script.is_absolute())?;
        return resolver_content_identity(&script);
    }
    const INTERPRETERS: &[&str] = &[
        "sh", "bash", "zsh", "dash", "fish", "env", "python", "ruby", "perl", "java", "deno", "bun",
    ];
    let interpreter = INTERPRETERS
        .iter()
        .any(|interpreter| name == *interpreter || name.starts_with(&format!("{interpreter}3")));
    if interpreter {
        return None;
    }
    resolver_content_identity(&executable)
}

#[cfg(not(unix))]
pub fn running_resolver_identity(_pid: i32) -> Option<String> {
    None
}

/// The executable a process runs and its arguments.
#[cfg(target_os = "macos")]
fn running_process_image(pid: i32) -> Option<(std::path::PathBuf, Vec<String>)> {
    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let written = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) };
    if written <= 0 {
        return None;
    }
    path.truncate(written as usize);
    let executable = std::path::PathBuf::from(String::from_utf8(path).ok()?);

    // KERN_PROCARGS2: argc, the exec path, padding, then argc arguments.
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    let sized = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if sized != 0 || size < 4 {
        return Some((executable, Vec::new()));
    }
    let mut buffer = vec![0u8; size];
    let read = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buffer.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if read != 0 {
        return Some((executable, Vec::new()));
    }
    buffer.truncate(size);
    let argc = i32::from_ne_bytes(buffer[..4].try_into().ok()?).max(0) as usize;
    let mut rest = &buffer[4..];
    // Skip the exec path and the NUL padding after it.
    let path_end = rest.iter().position(|byte| *byte == 0)?;
    rest = &rest[path_end..];
    let start = rest
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(rest.len());
    rest = &rest[start..];
    let arguments = rest
        .split(|byte| *byte == 0)
        .take(argc)
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect();
    Some((executable, arguments))
}

/// The executable a process runs and its arguments.
#[cfg(all(unix, not(target_os = "macos")))]
fn running_process_image(pid: i32) -> Option<(std::path::PathBuf, Vec<String>)> {
    let executable = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let arguments = std::fs::read(format!("/proc/{pid}/cmdline"))
        .ok()
        .map(|bytes| {
            bytes
                .split(|byte| *byte == 0)
                .filter(|argument| !argument.is_empty())
                .map(|argument| String::from_utf8_lossy(argument).into_owned())
                .collect()
        })
        .unwrap_or_default();
    Some((executable, arguments))
}

/// The identity a proof context records for a server whose program cannot be
/// identified by content, even from its running process: one that no other
/// start shares, so its proofs are asked about again by every later start
/// rather than taken as current.
pub fn unverified_start_identity(pid: u32) -> String {
    static STARTS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let start = STARTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!("unverified-start:{pid}:{nanos}:{start}")
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The configuration and environment hashes of `launch`.
fn launch_hashes(
    launch: &ServerLaunch,
    workspace_root: &Path,
    command: &str,
    resolver_identity: Option<&str>,
) -> (Hash256, Hash256) {
    let placeholders = Placeholders::new(workspace_root);
    let json = |value: &Option<serde_json::Value>| {
        value
            .as_ref()
            .map(|value| placeholders.apply(&value.to_string()))
            .unwrap_or_default()
    };
    let mut env: Vec<String> = launch
        .env
        .iter()
        .map(|(name, value)| {
            let recorded = launch
                .env_identity
                .iter()
                .find(|(identified, _)| identified == name)
                .map_or(value.as_str(), |(_, identity)| identity.as_str());
            format!("{name}={}", placeholders.apply(recorded))
        })
        .collect();
    env.sort();
    let initialization = json(&launch.initialization_options);
    let settings = json(&launch.settings);
    let env = env.join("\n");
    let label = placeholders.apply(&launch.label);
    let configuration_hash = kin_model::proof_context_digest(
        CONFIGURATION_DOMAIN,
        &[
            resolver_identity.map_or(UNIDENTIFIED_RESOLVER, str::as_bytes),
            label.as_bytes(),
            initialization.as_bytes(),
            settings.as_bytes(),
            env.as_bytes(),
            // The one workspace folder every server is given.
            b"${workspace}",
        ],
    );
    let environment = launch
        .resolution
        .as_ref()
        .map(|resolution| &resolution.environment);
    let environment_hash = environment
        .and_then(|environment| Hash256::from_hex(environment.identity.hex()).ok())
        .unwrap_or_else(|| {
            kin_model::proof_context_digest(NO_ENVIRONMENT_DOMAIN, &[command.as_bytes()])
        });
    (configuration_hash, environment_hash)
}

/// The resolver's name as a proof context spells it: lower case, and only the
/// characters a resolver name may carry.
fn resolver_name(server_name: Option<&str>, command: &str) -> String {
    let source = server_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            Path::new(command)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(command)
        });
    let mut name: String = source
        .to_lowercase()
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' | '+' => ch,
            _ => '-',
        })
        .collect();
    while name.starts_with(|ch: char| !ch.is_ascii_alphanumeric()) {
        name.remove(0);
    }
    name.truncate(100);
    if name.is_empty() {
        "unnamed".to_string()
    } else {
        name
    }
}

/// `text` without control characters, trimmed, and at most `max` bytes.
fn sanitize(text: &str, max: usize) -> String {
    let mut clean: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    while clean.len() > max {
        clean.pop();
    }
    clean.trim().to_string()
}

/// The local paths a configuration may carry, written as placeholders.
struct Placeholders {
    replacements: Vec<(String, &'static str)>,
}

impl Placeholders {
    fn new(workspace_root: &Path) -> Self {
        let mut replacements = Vec::new();
        let root = workspace_root.to_string_lossy().into_owned();
        if !root.is_empty() && root != "/" {
            replacements.push((root, "${workspace}"));
        }
        if let Some(home) = std::env::var_os("KIN_HOME") {
            let home = home.to_string_lossy().into_owned();
            if !home.is_empty() && home != "/" {
                replacements.push((home, "${kin_home}"));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            let home = home.to_string_lossy().into_owned();
            if !home.is_empty() && home != "/" {
                replacements.push((home, "${home}"));
            }
        }
        // The longest path first, so a root inside the home directory is
        // written as the workspace rather than as a path below the home.
        replacements.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
        Self { replacements }
    }

    fn apply(&self, text: &str) -> String {
        let mut text = text.to_string();
        for (path, placeholder) in &self.replacements {
            text = text.replace(path.as_str(), placeholder);
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(root: &Path) -> ServerLaunch {
        ServerLaunch {
            initialization_options: Some(serde_json::json!({
                "linkedProjects": [root.join("Cargo.toml").to_string_lossy()],
            })),
            label: "rust-analyzer, all features".to_string(),
            ..ServerLaunch::default()
        }
    }

    /// A binary is identified by its bytes, a Node package's entry by its
    /// bytes and its package's manifest, and a shim not at all.
    #[cfg(unix)]
    #[test]
    fn a_resolver_is_identified_by_its_content() {
        let dir = std::env::temp_dir().join(format!(
            "kin-resolver-identity-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let binary = dir.join("server");
        std::fs::write(&binary, b"\x7fELF native bytes").unwrap();
        let first = resolver_content_identity(&binary).expect("a binary is identified");
        std::fs::write(&binary, b"\x7fELF other bytes").unwrap();
        assert_ne!(resolver_content_identity(&binary).unwrap(), first);

        let package = dir.join("node_modules/lsp");
        std::fs::create_dir_all(package.join("lib")).unwrap();
        std::fs::write(package.join("package.json"), r#"{"version":"1.0.0"}"#).unwrap();
        let entry = package.join("lib/cli.mjs");
        std::fs::write(&entry, "#!/usr/bin/env node\nimport './main.js';\n").unwrap();
        let link = dir.join("lsp");
        std::os::unix::fs::symlink(&entry, &link).unwrap();
        let released = resolver_content_identity(&link).expect("a Node entry is identified");
        std::fs::write(package.join("package.json"), r#"{"version":"1.0.1"}"#).unwrap();
        assert_ne!(
            resolver_content_identity(&link).unwrap(),
            released,
            "a new package version is a new resolver, though the entry's bytes did not move"
        );

        let shim = dir.join("shim");
        std::fs::write(&shim, "#!/usr/bin/env bash\nexec \"$(pick)\" \"$@\"\n").unwrap();
        assert_eq!(
            resolver_content_identity(&shim),
            None,
            "a shim picks its program later"
        );
        assert_eq!(resolver_content_identity(&dir.join("absent")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A running process is identified by what it runs: a native program by
    /// its bytes, and a shell still running a command it forked not at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_running_server_is_identified_by_what_it_runs() {
        use crate::server_process::ServerProcess;
        use tokio::io::AsyncReadExt;

        let mut native_command = tokio::process::Command::new("/bin/sleep");
        native_command.arg("30");
        let mut native = ServerProcess::spawn(native_command).unwrap();
        let mut forking_command = tokio::process::Command::new("/bin/sh");
        forking_command.args(["-c", "sleep 30; true"]);
        let mut forking = ServerProcess::spawn(forking_command).unwrap();
        let outputs = [
            native.take_stdio().1.unwrap(),
            forking.take_stdio().1.unwrap(),
        ];
        // Long enough for both to be running their final image.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let native_identity = running_resolver_identity(native.leader_pid());
        let forking_identity = running_resolver_identity(forking.leader_pid());
        // The shell's child inherits its stdout. Killing only the shell leaves
        // that child and its open pipe behind, so own and stop both full groups
        // through the same PID-lifetime guard used by actual language servers.
        native.terminate().await;
        forking.terminate().await;
        for mut output in outputs {
            let mut bytes = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(1),
                output.read_to_end(&mut bytes),
            )
            .await
            .expect("the owned process group must release its output pipe")
            .unwrap();
            assert!(bytes.is_empty());
        }
        assert_eq!(
            native_identity,
            resolver_content_identity(Path::new("/bin/sleep")),
            "a native program is identified by its own bytes"
        );
        assert!(native_identity.is_some());
        assert_eq!(
            forking_identity, None,
            "a shell running what it forked is not the server"
        );
        assert_ne!(
            unverified_start_identity(1),
            unverified_start_identity(1),
            "no two unverified starts share an identity"
        );
    }

    /// The hashes a sweep computes before a server starts are the ones the
    /// started server proves under, and the resolver's bytes move them.
    #[test]
    fn prestart_hashes_are_the_ones_the_started_server_proves_under() {
        let root = Path::new("/work/a/axum");
        let started = ProofBasis::of_resolver(
            &launch(root),
            root,
            "rust-analyzer",
            Some("sha256:aa"),
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        )
        .proof_context(LanguageId::Rust);
        assert_eq!(
            prestart_hashes(&launch(root), root, "rust-analyzer", "sha256:aa"),
            (started.configuration_hash, started.environment_hash)
        );
        assert_ne!(
            prestart_hashes(&launch(root), root, "rust-analyzer", "sha256:bb").0,
            started.configuration_hash,
            "another executable is another configuration"
        );
        let unidentified = ProofBasis::of(
            &launch(root),
            root,
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        )
        .proof_context(LanguageId::Rust);
        assert_ne!(unidentified.configuration_hash, started.configuration_hash);
    }

    #[test]
    fn one_configuration_hashes_the_same_wherever_the_repository_is() {
        let here = ProofBasis::of(
            &launch(Path::new("/work/a/axum")),
            Path::new("/work/a/axum"),
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        );
        let there = ProofBasis::of(
            &launch(Path::new("/elsewhere/axum")),
            Path::new("/elsewhere/axum"),
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        );
        assert_eq!(here, there);
        let context = here.proof_context(LanguageId::Rust);
        assert_eq!(context.resolver, "lsp:rust-analyzer");
        assert_eq!(context.resolver_version, "0.3.2600-standalone");
        kin_model::ResolutionRecord::ProofContext(context)
            .validate()
            .unwrap();

        let mut other = launch(Path::new("/work/a/axum"));
        other.label = "rust-analyzer, default features".to_string();
        let changed = ProofBasis::of(
            &other,
            Path::new("/work/a/axum"),
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        );
        assert_ne!(
            changed.proof_context(LanguageId::Rust),
            here.proof_context(LanguageId::Rust),
            "another configuration is another context"
        );
    }

    #[test]
    fn a_server_without_a_name_is_named_by_its_command() {
        let basis = ProofBasis::of(
            &ServerLaunch::default(),
            Path::new("/r"),
            "/opt/bin/pyright-langserver",
            None,
            None,
        );
        let context = basis.proof_context(LanguageId::Python);
        assert_eq!(context.resolver, "lsp:pyright-langserver");
        assert_eq!(context.resolver_version, "unknown");
        assert_eq!(resolver_name(Some("Pyright"), "x"), "pyright");
        assert_eq!(
            resolver_name(Some("typescript-language-server"), "x"),
            "typescript-language-server"
        );
        kin_model::ResolutionRecord::ProofContext(context)
            .validate()
            .unwrap();
    }
}
