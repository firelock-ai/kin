// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::io::Write;
use std::path::Path;

use anyhow::Result;
use kin_core::{ExternalToolExecutionPolicy, KinConfig};
use kin_model::EntityStore;
use kin_model::{EntityFilter, EntityId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    pub command: String,
    #[serde(default)]
    pub keep: bool,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResponse {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    pub strategy_used: String,
    pub workspace_path: String,
    #[serde(default)]
    pub planned_scope: Option<String>,
    #[serde(default)]
    pub kept: bool,
}

/// `kin exec [flags] -- <command...>` (alias: `kin run`).
///
/// Runs an ordinary command through a graph-backed session workspace:
/// the daemon materializes graph truth into `.kin/runs/session-<id>`, the
/// command runs locally in that workspace with session env set, and on
/// success the changes are reconciled back into the graph (generated
/// directories like `node_modules/` are excluded by the reconcile skip
/// policy). On failure the workspace is preserved with recovery commands.
///
/// The command itself always executes in this CLI process — never through
/// the daemon's gated `/commands/exec` surface.
pub async fn run_full(
    command_parts: Vec<String>,
    keep: bool,
    discard: bool,
    strategy: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let command = command_parts.join(" ").trim().to_string();
    if command.is_empty() {
        return Err(anyhow::anyhow!(
            "no command provided. Usage: kin exec [--keep|--discard] [--scope <s>] -- <command...>"
        ));
    }

    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let config = KinConfig::load_or_default(&layout.config_path())?;
    let planned_scope = plan_materialization_scope(&command, scope, &config)?;

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
    let ws = super::session_workspace::create_session_workspace(
        &layout,
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

    let outcome = run_command_in_session(&ws.root, &command, &session_env(session_id, &ws.root))?;
    eprintln!(
        "\nCommand exited (code {}, {}ms).",
        outcome.exit_code, outcome.duration_ms
    );

    {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        close_exec_session(
            &layout,
            &session_dir,
            outcome.exit_code,
            keep,
            discard,
            &mut stderr,
        )
        .await?;
    }

    if outcome.exit_code != 0 {
        std::process::exit(outcome.exit_code);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct SessionExecOutcome {
    exit_code: i32,
    duration_ms: u64,
}

/// Session identity env for the executed command, matching the `kin shell`
/// contract: `KIN_SESSION`/`KIN_SESSION_ID` carry the session UUID (the MCP
/// daemon delegate reads `KIN_SESSION_ID` to scope forwarded tool calls) and
/// `KIN_SESSION_DIR` carries the workspace root.
fn session_env(session_id: uuid::Uuid, ws_root: &Path) -> Vec<(String, String)> {
    vec![
        ("KIN_SESSION".into(), session_id.to_string()),
        ("KIN_SESSION_ID".into(), session_id.to_string()),
        (
            "KIN_SESSION_DIR".into(),
            ws_root.to_string_lossy().into_owned(),
        ),
    ]
}

/// Run a shell command in the materialized session workspace, streaming
/// stdio to the caller's terminal.
fn run_command_in_session(
    ws_root: &Path,
    command: &str,
    extra_env: &[(String, String)],
) -> Result<SessionExecOutcome> {
    let start = std::time::Instant::now();

    let mut cmd = if cfg!(target_os = "windows") {
        let mut cmd = std::process::Command::new("cmd");
        cmd.args(["/C", command]);
        cmd
    } else {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", command]);
        cmd
    };

    let status = cmd
        .current_dir(ws_root)
        .envs(extra_env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
        .stdin(std::process::Stdio::inherit())
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
    layout: &kin_core::KinLayout,
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

    super::session_closeout::finalize_shell_session_with_writer(layout, session_dir, writer).await
}

fn session_id_hint(session_dir: &Path) -> String {
    session_dir
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(|name| name.strip_prefix("session-"))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| session_dir.display().to_string())
}

pub fn execute_exec_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &ExecRequest,
) -> Result<ExecResponse> {
    let config = KinConfig::load_or_default(&layout.config_path())?;

    let resolved_scope = resolve_materialization_scope(graph, request.scope.clone())?;
    let planned_scope = plan_materialization_scope(&request.command, resolved_scope, &config)?;

    let parsed_strategy = match &request.strategy {
        Some(strategy) => {
            let strat: kin_runtime::MaterializeStrategy =
                strategy.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            Some(strat)
        }
        None => None,
    };

    let workspace_path = layout
        .root()
        .join("runs")
        .join(format!("exec-{}", uuid::Uuid::new_v4()));
    let workspace = super::session_workspace::create_session_workspace_from_graph(
        layout,
        graph,
        &workspace_path,
        parsed_strategy,
        planned_scope.as_deref(),
    )?;

    let result = kin_runtime::exec::ExecContext {
        workspace,
        command: request.command.clone(),
        args: Vec::new(),
    }
    .run()?;

    let response = ExecResponse {
        stdout: result.stdout,
        stderr: result.stderr,
        exit_code: result.exit_code,
        duration_ms: result.duration_ms,
        workspace_path: result.workspace_path.display().to_string(),
        strategy_used: result.strategy_used.to_string(),
        planned_scope,
        kept: request.keep,
    };

    if !request.keep {
        kin_runtime::exec::cleanup_workspace(std::path::Path::new(&response.workspace_path))?;
    }

    Ok(response)
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
    use super::{
        close_exec_session, detect_external_tool, plan_materialization_scope,
        resolve_materialization_scope, run_command_in_session, session_env, ExternalToolKind,
    };
    use kin_core::{ExternalToolExecutionPolicy, KinConfig, WorldPreset};
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };
    use std::path::Path;

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

    #[test]
    fn session_env_carries_session_identity() {
        let session_id = uuid::Uuid::new_v4();
        let ws_root = Path::new("/tmp/repo/.kin/runs/session-x");

        let env = session_env(session_id, ws_root);

        for (key, expected) in [
            ("KIN_SESSION", session_id.to_string()),
            ("KIN_SESSION_ID", session_id.to_string()),
            ("KIN_SESSION_DIR", ws_root.to_string_lossy().into_owned()),
        ] {
            assert_eq!(
                env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()),
                Some(expected.as_str()),
                "missing or wrong {key}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn run_command_in_session_runs_in_workspace_with_session_env() {
        let dir = tempfile::tempdir().unwrap();
        let ws = dir.path().join("session-ws");
        std::fs::create_dir_all(&ws).unwrap();
        let session_id = uuid::Uuid::new_v4();

        let outcome = run_command_in_session(
            &ws,
            "pwd > observed-cwd.txt && printf '%s' \"$KIN_SESSION_ID\" > observed-session.txt",
            &session_env(session_id, &ws),
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

        let outcome =
            run_command_in_session(&ws, "exit 3", &session_env(uuid::Uuid::new_v4(), &ws)).unwrap();

        assert_eq!(outcome.exit_code, 3);
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
        let mut env = stub_tool(
            &repo.path().join("stub-bin"),
            "npm",
            "printf '{\"lockfileVersion\":3}' > package-lock.json\n\
             mkdir -p node_modules/left-pad\n\
             printf 'module.exports = 1' > node_modules/left-pad/index.js",
        );
        env.extend(session_env(uuid::Uuid::new_v4(), &session_dir));

        let outcome = run_command_in_session(&session_dir, "npm install", &env).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert!(session_dir.join("package-lock.json").exists());
        assert!(session_dir.join("node_modules/left-pad/index.js").exists());

        let mut stderr = Vec::new();
        close_exec_session(&layout, &session_dir, 0, false, false, &mut stderr)
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

        let mut env = stub_tool(&repo.path().join("stub-bin"), "make", "exit 2");
        env.extend(session_env(uuid::Uuid::new_v4(), &session_dir));

        let outcome = run_command_in_session(&session_dir, "make test", &env).unwrap();
        assert_eq!(outcome.exit_code, 2);

        let mut stderr = Vec::new();
        close_exec_session(
            &layout,
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
        let mut env = stub_tool(
            &repo.path().join("stub-bin"),
            "docker",
            "test -f docker-compose.yml || exit 64\nprintf '%s ' \"$@\" > docker-args.txt",
        );
        env.extend(session_env(uuid::Uuid::new_v4(), &session_dir));

        let outcome = run_command_in_session(&session_dir, "docker compose config", &env).unwrap();
        assert_eq!(outcome.exit_code, 0);
        assert_eq!(
            std::fs::read_to_string(session_dir.join("docker-args.txt"))
                .unwrap()
                .trim(),
            "compose config"
        );

        let mut stderr = Vec::new();
        close_exec_session(&layout, &session_dir, 0, false, false, &mut stderr)
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
        close_exec_session(&layout, &session_dir, 0, true, false, &mut stderr)
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
        close_exec_session(&layout, &session_dir, 0, false, true, &mut stderr)
            .await
            .unwrap();

        assert!(!session_dir.exists());
        assert!(!repo.path().join("scratch.txt").exists());
        let output = String::from_utf8(stderr).unwrap();
        assert!(output.contains("Discarded session workspace."));
    }
}
