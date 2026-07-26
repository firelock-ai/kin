// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use kin_core::{ExternalToolExecutionPolicy, KinConfig};
use kin_model::EntityStore;
use kin_model::{EntityFilter, EntityId};

#[derive(Debug, Clone)]
enum ExecInvocation {
    Direct { program: String, args: Vec<String> },
    Shell(String),
}

impl ExecInvocation {
    fn parse(command_parts: Vec<String>, shell: bool) -> Result<Self> {
        if command_parts.is_empty() || command_parts.iter().all(|part| part.is_empty()) {
            anyhow::bail!(
                "no command provided. Usage: kin exec [--shell] [--keep|--discard] [--scope <s>] -- <command...>"
            );
        }
        if shell {
            if command_parts.len() != 1 {
                anyhow::bail!(
                    "`--shell` requires exactly one script argument; quote the full script, for example: kin exec --shell -- 'printf \"%s\\n\" \"$HOME\"'"
                );
            }
            let command = command_parts
                .into_iter()
                .next()
                .expect("one shell script checked above")
                .trim()
                .to_string();
            if command.is_empty() {
                anyhow::bail!("shell command cannot be empty");
            }
            return Ok(Self::Shell(command));
        }
        let mut parts = command_parts.into_iter();
        let program = parts.next().expect("non-empty command checked above");
        if program.is_empty() {
            anyhow::bail!("command program cannot be empty");
        }
        Ok(Self::Direct {
            program,
            args: parts.collect(),
        })
    }

    fn planning_text(&self) -> String {
        match self {
            Self::Direct { program, args } => std::iter::once(program.as_str())
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
            Self::Shell(command) => command.clone(),
        }
    }

    fn command(&self) -> std::process::Command {
        match self {
            Self::Direct { program, args } => {
                let mut command = std::process::Command::new(program);
                command.args(args);
                command
            }
            Self::Shell(script) if cfg!(target_os = "windows") => {
                let mut command = std::process::Command::new("cmd");
                command.args(["/C", script]);
                command
            }
            Self::Shell(script) => {
                let mut command = std::process::Command::new("sh");
                command.args(["-c", script]);
                command
            }
        }
    }
}

/// `kin exec [flags] -- <command...>`.
///
/// Runs an ordinary command through a graph-backed session workspace:
/// the daemon materializes graph truth into `.kin/runs/session-<id>`, the
/// command runs locally in that workspace with session env set, and on
/// success the changes are reconciled back into the graph (generated
/// directories like `node_modules/` are excluded by the reconcile skip
/// policy). On failure the workspace is preserved with recovery commands.
///
/// The command itself always executes in this CLI process. Argument boundaries
/// are preserved by default; shell parsing is available only with `--shell`.
pub async fn run_full(
    command_parts: Vec<String>,
    shell: bool,
    keep: bool,
    discard: bool,
    strategy: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let invocation = ExecInvocation::parse(command_parts, shell)?;

    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let config = KinConfig::load_or_default(&layout.config_path())?;
    let planned_scope = plan_materialization_scope(&invocation.planning_text(), scope, &config)?;

    let parsed_strategy = strategy
        .as_deref()
        .map(str::parse::<kin_runtime::MaterializeStrategy>)
        .transpose()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let session_id = uuid::Uuid::new_v4();
    let session_dir = layout
        .root()
        .join("runs")
        .join(format!("session-{session_id}"));

    eprintln!("Materializing session workspace...");
    let repo_binding = super::session_process::VerifiedRepoBinding::resolve(&layout).await?;
    let ws = super::session_workspace::create_session_workspace(
        &repo_binding,
        &session_dir,
        parsed_strategy,
        planned_scope.as_deref(),
    )
    .await?;
    match &planned_scope {
        Some(scope) => eprintln!("  Scope: {scope}"),
        None => eprintln!("  Scope: full workspace"),
    }
    eprintln!("  Workspace: {}", ws.root.display());

    let process_binding =
        super::session_process::SessionProcessBinding::new(&repo_binding, session_id, &ws.root);
    process_binding.persist_context().map_err(|error| {
        anyhow::anyhow!(
            "failed to persist session context: {error}. Session workspace kept at {}",
            session_dir.display()
        )
    })?;
    let lease = repo_binding
        .register_session(session_id, &ws.root, "kin exec")
        .await
        .map_err(|error| {
            anyhow::anyhow!(
                "failed to register session: {error}. Session workspace kept at {}",
                session_dir.display()
            )
        })?;
    let outcome = match run_command_in_session(
        &invocation,
        &process_binding,
        std::iter::empty::<(&str, &str)>(),
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = lease.finish().await;
            return Err(error.context(format!(
                "session workspace kept at {}",
                session_dir.display()
            )));
        }
    };
    eprintln!(
        "\nCommand exited (code {}, {}ms).",
        outcome.exit_code, outcome.duration_ms
    );

    let (close_result, lease_result) = {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        let close_result = close_exec_session(
            &repo_binding,
            &session_dir,
            outcome.exit_code,
            keep,
            discard,
            &mut stderr,
        )
        .await;
        let lease_result = lease.finish().await;
        (close_result, lease_result)
    };

    if outcome.exit_code != 0 {
        if let Err(error) = close_result {
            eprintln!("Kin: failed to report preserved session workspace: {error}");
        }
        if let Err(error) = lease_result {
            eprintln!("Kin: failed to end daemon session lease: {error}");
        }
        std::process::exit(outcome.exit_code);
    }
    close_result?;
    lease_result?;
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SessionExecOutcome {
    exit_code: i32,
    duration_ms: u64,
}

/// Run a command in the materialized session workspace, streaming stdio to the
/// caller's terminal.
fn run_command_in_session<K, V, I>(
    invocation: &ExecInvocation,
    binding: &super::session_process::SessionProcessBinding,
    projection_env: I,
) -> Result<SessionExecOutcome>
where
    K: AsRef<std::ffi::OsStr>,
    V: AsRef<std::ffi::OsStr>,
    I: IntoIterator<Item = (K, V)>,
{
    let start = std::time::Instant::now();

    let mut cmd = invocation.command();

    binding.configure_command(&mut cmd, projection_env)?;
    let status = cmd
        // A real `kin exec` hands the terminal to the command, which is the
        // point of the surface. A unit test has no terminal to hand over: a
        // command that reads stdin there would wait on a descriptor nobody
        // writes to, so the test blocks forever instead of failing.
        .stdin(if cfg!(test) {
            std::process::Stdio::null()
        } else {
            std::process::Stdio::inherit()
        })
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run command in session workspace: {e}"))?;

    Ok(SessionExecOutcome {
        exit_code: status.code().unwrap_or(1),
        duration_ms: start.elapsed().as_millis() as u64,
    })
}

/// Close out an exec session workspace.
///
/// - `discard`: remove the workspace without reconciling.
/// - non-zero exit: preserve the workspace and print recovery commands —
///   a failed run must never be silently reconciled or deleted.
/// - `keep`: preserve the workspace and defer reconcile to the user.
/// - otherwise: reconcile into the graph and clean up; reconcile failure
///   preserves the workspace with recovery commands.
async fn close_exec_session<W: Write>(
    binding: &super::session_process::VerifiedRepoBinding,
    session_dir: &Path,
    exit_code: i32,
    keep: bool,
    discard: bool,
    writer: &mut W,
) -> Result<()> {
    let session_hint = session_id_hint(session_dir);

    if discard {
        match std::fs::remove_dir_all(session_dir) {
            Ok(()) => writeln!(writer, "Discarded session workspace.")?,
            Err(e) => writeln!(
                writer,
                "Warning: failed to discard session workspace {}: {}",
                session_dir.display(),
                e
            )?,
        }
        return Ok(());
    }

    if exit_code != 0 {
        writeln!(
            writer,
            "Command failed; session workspace kept at: {}",
            session_dir.display()
        )?;
        writeln!(
            writer,
            "To reconcile its changes anyway: kin reconcile {session_hint} --cleanup"
        )?;
        writeln!(writer, "To discard it: rm -rf {}", session_dir.display())?;
        return Ok(());
    }

    if keep {
        writeln!(
            writer,
            "Session workspace kept at: {}",
            session_dir.display()
        )?;
        writeln!(
            writer,
            "To reconcile and clean up: kin reconcile {session_hint} --cleanup"
        )?;
        return Ok(());
    }

    super::session_closeout::finalize_shell_session_with_writer(binding, session_dir, 0, writer)
        .await
}

fn session_id_hint(session_dir: &Path) -> String {
    session_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("session-"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| session_dir.display().to_string())
}

pub(crate) fn resolve_materialization_scope(
    graph: &kin_db::InMemoryGraph,
    scope: Option<String>,
) -> Result<Option<String>> {
    let Some(scope) = scope else {
        return Ok(None);
    };

    if let Some(raw) = scope.strip_prefix("entity:") {
        if let Ok(uuid) = uuid::Uuid::parse_str(raw) {
            let entity_id = EntityId(uuid);
            let entity = graph
                .get_entity(&entity_id)?
                .ok_or_else(|| anyhow::anyhow!("entity '{}' not found", raw))?;
            let file = entity
                .file_origin
                .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", raw))?;
            return Ok(Some(format!("file:{}", file.0)));
        }

        let matches = graph.query_entities(&EntityFilter {
            name_pattern: Some(raw.to_string()),
            ..Default::default()
        })?;

        let exact: Vec<_> = matches.into_iter().filter(|e| e.name == raw).collect();
        let entity = match exact.as_slice() {
            [entity] => entity,
            [] => return Err(anyhow::anyhow!("entity '{}' not found", raw)),
            _ => {
                return Err(anyhow::anyhow!(
                    "entity '{}' is ambiguous; use entity:<uuid>",
                    raw
                ))
            }
        };

        let file = entity
            .file_origin
            .clone()
            .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", raw))?;
        return Ok(Some(format!("file:{}", file.0)));
    }

    if let Some(raw) = scope.strip_prefix("artifact:") {
        let path = raw.trim();
        if path.is_empty() {
            return Err(anyhow::anyhow!("artifact scope cannot be empty"));
        }
        return Ok(Some(format!("file:{path}")));
    }

    Ok(Some(scope))
}

fn plan_materialization_scope(
    command: &str,
    scope: Option<String>,
    config: &KinConfig,
) -> Result<Option<String>> {
    let Some(tool) = detect_external_tool(command) else {
        return Ok(scope);
    };

    let Some(active_scope) = scope else {
        return Ok(None);
    };

    match config.execution.external_tools {
        ExternalToolExecutionPolicy::Workspace => {
            eprintln!(
                "Execution policy widened `{}` from `{}` to a full compatibility workspace.",
                tool.display_name(),
                active_scope
            );
            Ok(None)
        }
        ExternalToolExecutionPolicy::Strict => Err(anyhow::anyhow!(
            "execution policy `strict` will not auto-widen `{}` from `{}`. Run without `--scope` for a full workspace or switch to `kin mode preset compatibility`.",
            tool.display_name(),
            active_scope,
        )),
    }
}

/// Package-manager front-ends that read manifests, lockfiles, and arbitrary
/// project scripts. A partially materialized workspace surprises them, so
/// scoped execution widens to a full workspace under the default policy.
const PACKAGE_MANAGER_COMMANDS: &[&str] = &[
    "npm", "npx", "pnpm", "pnpx", "yarn", "bun", "bunx", "corepack",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalToolKind {
    DockerCompose,
    DockerBuild,
    Make,
    PackageManager(&'static str),
}

impl ExternalToolKind {
    fn display_name(self) -> &'static str {
        match self {
            Self::DockerCompose => "docker compose",
            Self::DockerBuild => "docker build",
            Self::Make => "make",
            Self::PackageManager(name) => name,
        }
    }
}

fn detect_external_tool(command: &str) -> Option<ExternalToolKind> {
    let parts: Vec<_> = command.split_whitespace().collect();
    match parts.as_slice() {
        ["docker-compose", ..] | ["podman-compose", ..] => Some(ExternalToolKind::DockerCompose),
        ["docker", "compose", ..] | ["podman", "compose", ..] => {
            Some(ExternalToolKind::DockerCompose)
        }
        ["docker", "build", ..]
        | ["podman", "build", ..]
        | ["docker", "bake", ..]
        | ["docker", "buildx", "bake", ..]
        | ["podman", "bake", ..] => Some(ExternalToolKind::DockerBuild),
        ["make", ..] | ["gmake", ..] => Some(ExternalToolKind::Make),
        [first, ..] => PACKAGE_MANAGER_COMMANDS
            .iter()
            .find(|name| *name == first)
            .map(|name| ExternalToolKind::PackageManager(name)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::run_command_in_session;
    use super::{
        close_exec_session, detect_external_tool, plan_materialization_scope,
        resolve_materialization_scope, ExecInvocation, ExternalToolKind,
    };
    use kin_core::{ExternalToolExecutionPolicy, KinConfig, WorldPreset};
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };
    use std::path::Path;

    fn test_repo_binding(
        layout: &kin_core::KinLayout,
    ) -> crate::commands::session_process::VerifiedRepoBinding {
        crate::commands::session_process::VerifiedRepoBinding::for_test(
            layout.clone(),
            "http://127.0.0.1:9/test",
            "test-repo",
            None,
            std::env::var("PATH").unwrap_or_default(),
        )
    }

    fn test_session_binding(
        layout: &kin_core::KinLayout,
        session_id: uuid::Uuid,
        workspace_root: &Path,
    ) -> crate::commands::session_process::SessionProcessBinding {
        let repo = test_repo_binding(layout);
        crate::commands::session_process::SessionProcessBinding::new(
            &repo,
            session_id,
            workspace_root,
        )
    }

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 10,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// Write an executable stub script into `bin_dir` and return an env set
    /// that resolves it first on PATH.
    #[cfg(unix)]
    fn stub_tool(bin_dir: &Path, name: &str, script_body: &str) -> Vec<(String, String)> {
        std::fs::create_dir_all(bin_dir).unwrap();
        let path = bin_dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{script_body}\n")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let original_path = std::env::var("PATH").unwrap_or_default();
        vec![(
            "PATH".to_string(),
            format!("{}:{}", bin_dir.display(), original_path),
        )]
    }

    #[test]
    fn resolves_entity_id_scope_to_file_scope() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("render", "src/render.rs");
        graph.upsert_entity(&entity).unwrap();

        let scope =
            resolve_materialization_scope(&graph, Some(format!("entity:{}", entity.id))).unwrap();

        assert_eq!(scope, Some("file:src/render.rs".to_string()));
    }

    #[test]
    fn resolves_exact_entity_name_scope_to_file_scope() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("render", "src/render.rs");
        graph.upsert_entity(&entity).unwrap();

        let scope =
            resolve_materialization_scope(&graph, Some("entity:render".to_string())).unwrap();

        assert_eq!(scope, Some("file:src/render.rs".to_string()));
    }

    #[test]
    fn resolves_artifact_scope_to_file_scope() {
        let graph = kin_db::InMemoryGraph::new();

        let scope =
            resolve_materialization_scope(&graph, Some("artifact:docker-compose.yml".to_string()))
                .unwrap();

        assert_eq!(scope, Some("file:docker-compose.yml".to_string()));
    }

    #[test]
    fn detects_docker_compose_variants() {
        assert_eq!(
            detect_external_tool("docker compose up"),
            Some(ExternalToolKind::DockerCompose)
        );
        assert_eq!(
            detect_external_tool("docker-compose up"),
            Some(ExternalToolKind::DockerCompose)
        );
        assert_eq!(
            detect_external_tool("make test"),
            Some(ExternalToolKind::Make)
        );
    }

    #[test]
    fn shell_mode_requires_one_explicit_script_argument() {
        let error = ExecInvocation::parse(vec!["printf".into(), "value with spaces".into()], true)
            .unwrap_err();
        assert!(error.to_string().contains("exactly one script argument"));

        assert!(matches!(
            ExecInvocation::parse(vec!["printf '%s' 'value with spaces'".into()], true).unwrap(),
            ExecInvocation::Shell(_)
        ));
    }

    #[test]
    fn detects_docker_build_variants() {
        assert_eq!(
            detect_external_tool("docker build -f Dockerfile ."),
            Some(ExternalToolKind::DockerBuild)
        );
        assert_eq!(
            detect_external_tool("podman build -f Containerfile ."),
            Some(ExternalToolKind::DockerBuild)
        );
        assert_eq!(
            detect_external_tool("docker buildx bake"),
            Some(ExternalToolKind::DockerBuild)
        );
    }

    #[test]
    fn detects_package_manager_variants() {
        for command in [
            "npm test",
            "npm run build",
            "npx vitest",
            "pnpm install",
            "pnpx create-app",
            "yarn test",
            "bun run dev",
            "bunx tsc",
            "corepack enable",
        ] {
            let detected = detect_external_tool(command);
            assert!(
                matches!(detected, Some(ExternalToolKind::PackageManager(_))),
                "expected package-manager detection for `{command}`, got {detected:?}"
            );
        }
    }

    #[test]
    fn does_not_detect_ordinary_commands_as_external_tools() {
        assert_eq!(detect_external_tool("cargo test"), None);
        assert_eq!(detect_external_tool("python script.py"), None);
        assert_eq!(detect_external_tool("ls -la"), None);
    }

    #[test]
    fn workspace_policy_widens_scoped_external_tools() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);

        let scope = plan_materialization_scope(
            "docker compose up",
            Some("file:docker-compose.yml".to_string()),
            &config,
        )
        .unwrap();

        assert_eq!(scope, None);
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
    }

    #[test]
    fn workspace_policy_widens_scoped_package_managers() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);

        let scope =
            plan_materialization_scope("npm test", Some("file:package.json".to_string()), &config)
                .unwrap();

        assert_eq!(scope, None);
    }

    #[test]
    fn strict_policy_blocks_scoped_external_tools() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);
        // Override to strict explicitly — the default is now Workspace.
        config.execution.external_tools = ExternalToolExecutionPolicy::Strict;

        let err =
            plan_materialization_scope("make test", Some("artifact:Makefile".to_string()), &config)
                .unwrap_err();

        assert!(err.to_string().contains("will not auto-widen"));
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Strict
        );
    }

    #[test]
    fn strict_policy_blocks_scoped_package_managers() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);
        config.execution.external_tools = ExternalToolExecutionPolicy::Strict;

        let err = plan_materialization_scope(
            "pnpm install",
            Some("file:package.json".to_string()),
            &config,
        )
        .unwrap_err();

        assert!(err.to_string().contains("pnpm"));
    }

    #[cfg(unix)]
    #[test]
    fn run_command_in_session_runs_in_workspace_with_session_env() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("session-ws");
        std::fs::create_dir_all(&ws).unwrap();
        let session_id = uuid::Uuid::new_v4();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let binding = test_session_binding(&layout, session_id, &ws);

        let outcome = run_command_in_session(
            &ExecInvocation::parse(
                vec![
                    "pwd > observed-cwd.txt && printf '%s' \"$KIN_SESSION_ID\" > observed-session.txt"
                        .into(),
                ],
                true,
            )
            .unwrap(),
            &binding,
            std::iter::empty::<(&str, &str)>(),
        )
        .unwrap();

        assert_eq!(outcome.exit_code, 0);
        let observed_cwd = std::fs::read_to_string(ws.join("observed-cwd.txt")).unwrap();
        assert_eq!(
            std::fs::canonicalize(observed_cwd.trim()).unwrap(),
            std::fs::canonicalize(&ws).unwrap()
        );
        assert_eq!(
            std::fs::read_to_string(ws.join("observed-session.txt")).unwrap(),
            session_id.to_string()
        );
    }

    #[cfg(unix)]
    #[test]
    fn run_command_in_session_propagates_exit_code() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("session-ws");
        std::fs::create_dir_all(&ws).unwrap();

        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let binding = test_session_binding(&layout, uuid::Uuid::new_v4(), &ws);
        let outcome = run_command_in_session(
            &ExecInvocation::parse(vec!["exit 3".into()], true).unwrap(),
            &binding,
            std::iter::empty::<(&str, &str)>(),
        )
        .unwrap();

        assert_eq!(outcome.exit_code, 3);
    }

    #[cfg(unix)]
    #[test]
    fn direct_exec_preserves_argument_boundaries_and_metacharacters() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("session-ws");
        std::fs::create_dir_all(&ws).unwrap();

        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
        let binding = test_session_binding(&layout, uuid::Uuid::new_v4(), &ws);
        let invocation = ExecInvocation::parse(
            vec![
                "sh".into(),
                "-c".into(),
                "printf '<%s>\\n' \"$1\" \"$2\" \"$3\" \"$4\" > observed-argv.txt".into(),
                "kin-exec-test".into(),
                "value with spaces".into(),
                "literal;semicolon".into(),
                "literal-$(touch should-not-exist)".into(),
                String::new(),
            ],
            false,
        )
        .unwrap();

        let outcome =
            run_command_in_session(&invocation, &binding, std::iter::empty::<(&str, &str)>())
                .unwrap();

        assert_eq!(outcome.exit_code, 0);
        assert_eq!(
            std::fs::read_to_string(ws.join("observed-argv.txt")).unwrap(),
            "<value with spaces>\n<literal;semicolon>\n<literal-$(touch should-not-exist)>\n<>\n"
        );
        assert!(
            !ws.join("should-not-exist").exists(),
            "direct mode must not reinterpret an argument as shell syntax"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn npm_smoke_reconciles_lockfile_and_ignores_node_modules() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-npm-smoke");

        // Materialized state: the project manifest exists in both the source
        // tree and the session workspace.
        std::fs::write(repo.path().join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("package.json"), "{\"name\":\"app\"}\n").unwrap();
        crate::commands::session_base::record_materialized_base(&session_dir, None).unwrap();

        // Fake npm: emits a lockfile plus a node_modules tree, like a real install.
        let env = stub_tool(
            &repo.path().join("stub-bin"),
            "npm",
            "printf '{\"lockfileVersion\":3}' > package-lock.json\n\
             mkdir -p node_modules/left-pad\n\
             printf 'module.exports = 1' > node_modules/left-pad/index.js",
        );
        let binding = test_session_binding(&layout, uuid::Uuid::new_v4(), &session_dir);
        let outcome = run_command_in_session(
            &ExecInvocation::parse(vec!["npm".into(), "install".into()], false).unwrap(),
            &binding,
            env,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(session_dir.join("package-lock.json").exists());
        assert!(session_dir.join("node_modules/left-pad/index.js").exists());

        let mut stderr = Vec::new();
        let repo_binding = test_repo_binding(&layout);
        close_exec_session(&repo_binding, &session_dir, 0, false, false, &mut stderr)
            .await
            .unwrap();

        assert!(
            repo.path().join("package-lock.json").exists(),
            "lockfile should reconcile back into the source tree"
        );
        assert!(
            !repo.path().join("node_modules").exists(),
            "generated node_modules must be excluded by the reconcile skip policy"
        );
        assert!(
            !session_dir.exists(),
            "successful closeout should remove the session workspace"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn make_failure_preserves_workspace_with_recovery_commands() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-make-fail");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("partial.log"), "half-written output\n").unwrap();

        let env = stub_tool(&repo.path().join("stub-bin"), "make", "exit 2");
        let binding = test_session_binding(&layout, uuid::Uuid::new_v4(), &session_dir);
        let outcome = run_command_in_session(
            &ExecInvocation::parse(vec!["make".into(), "test".into()], false).unwrap(),
            &binding,
            env,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 2);

        let mut stderr = Vec::new();
        close_exec_session(
            &test_repo_binding(&layout),
            &session_dir,
            outcome.exit_code,
            false,
            false,
            &mut stderr,
        )
        .await
        .unwrap();

        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("session workspace kept"));
        assert!(output.contains("kin reconcile make-fail --cleanup"));
        assert!(output.contains("rm -rf"));
        assert!(
            session_dir.join("partial.log").exists(),
            "failed run must preserve the session workspace"
        );
        assert!(
            !repo.path().join("partial.log").exists(),
            "failed run must not reconcile into the source tree"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn docker_compose_config_smoke_runs_against_materialized_workspace() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-compose");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(
            session_dir.join("docker-compose.yml"),
            "services:\n  app:\n    image: alpine\n",
        )
        .unwrap();
        crate::commands::session_base::record_materialized_base(&session_dir, None).unwrap();

        // Fake docker: validates that the compose file is visible from the
        // workspace cwd, like `docker compose config` would.
        let env = stub_tool(
            &repo.path().join("stub-bin"),
            "docker",
            "test -f docker-compose.yml || exit 64\nprintf '%s ' \"$@\" > docker-args.txt",
        );
        let binding = test_session_binding(&layout, uuid::Uuid::new_v4(), &session_dir);
        let outcome = run_command_in_session(
            &ExecInvocation::parse(
                vec!["docker".into(), "compose".into(), "config".into()],
                false,
            )
            .unwrap(),
            &binding,
            env,
        )
        .unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(
            std::fs::read_to_string(session_dir.join("docker-args.txt"))
                .unwrap()
                .trim(),
            "compose config"
        );

        let mut stderr = Vec::new();
        close_exec_session(
            &test_repo_binding(&layout),
            &session_dir,
            0,
            false,
            false,
            &mut stderr,
        )
        .await
        .unwrap();
        assert!(!session_dir.exists());
    }

    #[tokio::test]
    async fn keep_defers_reconcile_and_preserves_workspace() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-keep");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("new-file.txt"), "kept\n").unwrap();

        let mut stderr = Vec::new();
        close_exec_session(
            &test_repo_binding(&layout),
            &session_dir,
            0,
            true,
            false,
            &mut stderr,
        )
        .await
        .unwrap();

        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("kin reconcile keep --cleanup"));
        assert!(session_dir.join("new-file.txt").exists());
        assert!(
            !repo.path().join("new-file.txt").exists(),
            "--keep must defer reconcile"
        );
    }

    #[tokio::test]
    async fn discard_removes_workspace_without_reconcile() {
        let repo = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo.path()).unwrap();
        let layout = init.layout;
        let session_dir = layout.root().join("runs/session-discard");
        std::fs::create_dir_all(&session_dir).unwrap();
        std::fs::write(session_dir.join("scratch.txt"), "throwaway\n").unwrap();

        let mut stderr = Vec::new();
        close_exec_session(
            &test_repo_binding(&layout),
            &session_dir,
            0,
            false,
            true,
            &mut stderr,
        )
        .await
        .unwrap();

        assert!(!session_dir.exists());
        assert!(!repo.path().join("scratch.txt").exists());
        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("Discarded session workspace."));
    }
}
