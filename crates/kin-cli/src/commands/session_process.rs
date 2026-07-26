// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Verified repository/daemon binding and child-process isolation for
//! materialized Kin sessions.
//!
//! `kin exec`, `kin shell`, `kin open`, and `kin with --session` all cross the
//! same authority boundary: a child moves from the caller's repository
//! projection into a separately materialized session workspace. This module is
//! the only place those surfaces should construct their child environment.

use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};

pub(crate) const SESSION_CONTEXT_FILE: &str = ".kin-session.json";

/// Authority inherited from a previous repository/session that must never
/// survive into a newly bound materialized session.
const AMBIENT_AUTHORITY_ENV: &[&str] = &[
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
    "KIN_VFS_WORKSPACE",
    "KIN_VFS_WORKSPACE_ALIASES",
    "KIN_VFS_SOCK",
    "KIN_VFS_PIPE",
    "KIN_VFS_CANARY",
    "KIN_VFS_INTERPOSE_ACTIVE",
    "KIN_VFS_LAST_DIR",
    "_KIN_VFS_LAST_DIR",
    "KIN_SESSION",
    "KIN_SESSION_ID",
    "KIN_SESSION_DIR",
    "KIN_DAEMON_URL",
    "KIN_DAEMON_AUTH_TOKEN",
    "KIN_REPO_ID",
    "KIN_REPO_IDS",
    "KIN_PRIMARY_REPO_ID",
    "KIN_MCP_REPO",
    "KIN_SOURCE_ROOT",
    "KIN_WORKSPACE_ROOT",
    "KIN_WORKSPACE_DIR",
    "KIN_ORIGINAL_PATH",
    "KIN_DISCOVERY_MODE",
    "KIN_CONTENT_MODE",
    "KIN_VFS_DISABLE",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
    "COMPOSE_FILE",
    "COMPOSE_ENV_FILES",
    "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_PROJECT_NAME",
    "INIT_CWD",
    "npm_config_local_prefix",
    "MAKEFLAGS",
    "MFLAGS",
    "MAKELEVEL",
    "MESON_SOURCE_ROOT",
    "MESON_BUILD_ROOT",
    "PWD",
    "OLDPWD",
];

/// Values owned by [`SessionProcessBinding`] that projection/shim additions
/// are not allowed to override.
const SESSION_OWNED_ENV: &[&str] = &[
    "DYLD_INSERT_LIBRARIES",
    "LD_PRELOAD",
    "KIN_VFS_WORKSPACE",
    "KIN_VFS_WORKSPACE_ALIASES",
    "KIN_VFS_SOCK",
    "KIN_VFS_PIPE",
    "KIN_VFS_CANARY",
    "KIN_VFS_INTERPOSE_ACTIVE",
    "KIN_SESSION",
    "KIN_SESSION_ID",
    "KIN_SESSION_DIR",
    "KIN_DAEMON_URL",
    "KIN_DAEMON_AUTH_TOKEN",
    "KIN_REPO_ID",
    "KIN_REPO_IDS",
    "KIN_PRIMARY_REPO_ID",
    "KIN_MCP_REPO",
    "KIN_WORKSPACE_ROOT",
    "KIN_WORKSPACE_DIR",
    "KIN_VFS_DISABLE",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
    "COMPOSE_FILE",
    "COMPOSE_ENV_FILES",
    "COMPOSE_PATH_SEPARATOR",
    "COMPOSE_PROJECT_NAME",
    "INIT_CWD",
    "npm_config_local_prefix",
    "MAKEFLAGS",
    "MFLAGS",
    "MAKELEVEL",
    "MESON_SOURCE_ROOT",
    "MESON_BUILD_ROOT",
    "PWD",
    "OLDPWD",
];

/// A local repository identity paired with a daemon whose live health response
/// has been checked against that repository.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedRepoBinding {
    layout: kin_core::KinLayout,
    daemon_url: String,
    repo_id: String,
    daemon_auth_token: Option<String>,
    unshimmed_path: String,
}

impl VerifiedRepoBinding {
    /// Resolve the current repository's canonical identity and a matching live
    /// daemon. A stale ambient endpoint is rejected and replaced by the
    /// supervisor route for `layout`; it never becomes repository authority.
    pub(crate) async fn resolve(layout: &kin_core::KinLayout) -> Result<Self> {
        let repo_id = kin_core::manifest::resolve_repo_id(layout, None)
            .context("resolve repository identity from .kin/manifest.json")?;
        let initial_auth_token = crate::daemon_client::resolve_daemon_auth_token_for_layout(layout);

        let ambient_url = std::env::var("KIN_DAEMON_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());

        let (daemon_url, daemon_auth_token) = if let Some(url) = ambient_url {
            match validate_endpoint(layout, &repo_id, &url, initial_auth_token.clone()).await {
                Ok(()) => (url, initial_auth_token),
                Err(error) => {
                    eprintln!(
                        "Kin: ignoring inherited daemon endpoint that does not match {}: {error}",
                        layout.working_dir().display()
                    );
                    let resolved = crate::daemon_client::ensure_session_daemon_running(layout)
                        .await
                        .context("resolve the repository's verified daemon after rejecting an inherited endpoint")?;
                    let auth_token =
                        crate::daemon_client::resolve_daemon_auth_token_for_layout(layout);
                    validate_endpoint(layout, &repo_id, &resolved, auth_token.clone()).await?;
                    (resolved, auth_token)
                }
            }
        } else {
            let resolved = crate::daemon_client::ensure_session_daemon_running(layout)
                .await
                .context("resolve the repository's daemon")?;
            let auth_token = crate::daemon_client::resolve_daemon_auth_token_for_layout(layout);
            validate_endpoint(layout, &repo_id, &resolved, auth_token.clone()).await?;
            (resolved, auth_token)
        };

        Ok(Self {
            layout: layout.clone(),
            daemon_url,
            repo_id,
            daemon_auth_token,
            unshimmed_path: kin_core::shims::unshimmed_path(),
        })
    }

    #[cfg(test)]
    pub(crate) fn layout(&self) -> &kin_core::KinLayout {
        &self.layout
    }

    pub(crate) fn client(
        &self,
        session_id: Option<&str>,
    ) -> Result<crate::daemon_client::DaemonClient> {
        crate::daemon_client::DaemonClient::from_base_url_with_explicit_authority(
            self.daemon_url.clone(),
            self.daemon_auth_token.clone(),
            session_id,
        )
    }

    pub(crate) async fn register_session(
        &self,
        session_id: uuid::Uuid,
        workspace_root: &Path,
        client_name: &str,
    ) -> Result<DaemonSessionLease> {
        let capabilities = kin_model::SessionCapabilities {
            can_read: true,
            can_write: true,
            can_execute: true,
            can_branch: false,
            can_commit: false,
            max_concurrent_intents: 1,
        };
        let client = self.client(None)?;
        let response = client
            .register_session(&crate::daemon_client::SessionRegistrationRequest {
                vendor: "kin-cli".to_string(),
                client_name: client_name.to_string(),
                transport: "cli".to_string(),
                pid: Some(std::process::id()),
                cwd: workspace_root.display().to_string(),
                capabilities,
                session_id: Some(session_id.to_string()),
            })
            .await
            .context("register materialized session with daemon")?;
        if response.session_id != session_id.to_string() {
            anyhow::bail!(
                "daemon registered session {} instead of requested {}",
                response.session_id,
                session_id
            );
        }
        Ok(DaemonSessionLease::start(client, session_id))
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        layout: kin_core::KinLayout,
        daemon_url: impl Into<String>,
        repo_id: impl Into<String>,
        daemon_auth_token: Option<String>,
        unshimmed_path: impl Into<String>,
    ) -> Self {
        Self {
            layout,
            daemon_url: daemon_url.into(),
            repo_id: repo_id.into(),
            daemon_auth_token,
            unshimmed_path: unshimmed_path.into(),
        }
    }
}

async fn validate_endpoint(
    layout: &kin_core::KinLayout,
    expected_repo_id: &str,
    daemon_url: &str,
    auth_token: Option<String>,
) -> Result<()> {
    let client = crate::daemon_client::DaemonClient::from_base_url_with_explicit_authority(
        daemon_url, auth_token, None,
    )?;
    let health = client
        .health()
        .await
        .with_context(|| format!("probe daemon health at {daemon_url}"))?;
    validate_endpoint_health(layout, expected_repo_id, &health)
}

pub(crate) struct DaemonSessionLease {
    client: crate::daemon_client::DaemonClient,
    session_id: uuid::Uuid,
    cancel: Option<tokio::sync::oneshot::Sender<()>>,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

impl DaemonSessionLease {
    fn start(client: crate::daemon_client::DaemonClient, session_id: uuid::Uuid) -> Self {
        let (cancel, mut cancelled) = tokio::sync::oneshot::channel();
        let heartbeat_client = client.clone();
        let session_text = session_id.to_string();
        let heartbeat = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            interval.tick().await;
            loop {
                tokio::select! {
                    _ = &mut cancelled => break,
                    _ = interval.tick() => {
                        tokio::select! {
                            _ = &mut cancelled => break,
                            result = heartbeat_client.heartbeat_session(&session_text) => {
                                if let Err(error) = result {
                                    eprintln!("Kin: session heartbeat failed for {session_text}: {error}");
                                }
                            }
                        }
                    }
                }
            }
        });
        Self {
            client,
            session_id,
            cancel: Some(cancel),
            heartbeat: Some(heartbeat),
        }
    }

    pub(crate) async fn finish(mut self) -> Result<()> {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            let _ = heartbeat.await;
        }
        self.client
            .end_session(&self.session_id.to_string())
            .await
            .context("end materialized daemon session")
    }
}

impl Drop for DaemonSessionLease {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            let _ = cancel.send(());
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
        }
    }
}

fn validate_endpoint_health(
    layout: &kin_core::KinLayout,
    expected_repo_id: &str,
    health: &crate::daemon_client::HealthResponse,
) -> Result<()> {
    crate::daemon_client::validate_health_repo(&health, layout.working_dir())?;

    if health.repo_root.is_none() {
        anyhow::bail!("daemon health omitted repo root; refusing an unverifiable session binding");
    }

    match health.repo_id.as_deref() {
        Some(actual) if actual == expected_repo_id => Ok(()),
        Some(actual) => anyhow::bail!(
            "daemon repo identity mismatch: endpoint serves {actual}, expected {expected_repo_id}"
        ),
        None => anyhow::bail!(
            "daemon health omitted repo identity; refusing an unverifiable session binding"
        ),
    }
}

/// Complete, immutable authority for one materialized session child.
#[derive(Debug, Clone)]
pub(crate) struct SessionProcessBinding {
    session_id: uuid::Uuid,
    workspace_root: PathBuf,
    repo: VerifiedRepoBinding,
}

impl SessionProcessBinding {
    pub(crate) fn new(
        repo: &VerifiedRepoBinding,
        session_id: uuid::Uuid,
        workspace_root: &Path,
    ) -> Self {
        Self {
            session_id,
            workspace_root: workspace_root.to_path_buf(),
            repo: repo.clone(),
        }
    }

    /// Persist non-secret session authority for editor integrations that
    /// forward the workspace to an already-running GUI process and therefore
    /// cannot rely on launcher environment inheritance.
    pub(crate) fn persist_context(&self) -> Result<()> {
        #[derive(serde::Serialize)]
        struct ContextFile<'a> {
            schema_version: u32,
            session_id: String,
            workspace_root: &'a Path,
            repo_root: &'a Path,
            repo_id: &'a str,
            daemon_url: &'a str,
        }

        let path = self.workspace_root.join(SESSION_CONTEXT_FILE);
        let bytes = serde_json::to_vec_pretty(&ContextFile {
            schema_version: 1,
            session_id: self.session_id.to_string(),
            workspace_root: &self.workspace_root,
            repo_root: self.repo.layout.working_dir(),
            repo_id: &self.repo.repo_id,
            daemon_url: &self.repo.daemon_url,
        })
        .context("serialize persistent session context")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| {
                    format!("create fresh persistent session context {}", path.display())
                })?;
            file.write_all(&bytes)
                .with_context(|| format!("write persistent session context {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("persist session context {}", path.display()))?;
        }
        #[cfg(not(unix))]
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| {
                    format!("create fresh persistent session context {}", path.display())
                })?;
            file.write_all(&bytes)
                .with_context(|| format!("write persistent session context {}", path.display()))?;
            file.sync_all()
                .with_context(|| format!("persist session context {}", path.display()))?;
        }
        Ok(())
    }

    /// Configure a child command for this session.
    ///
    /// The caller may add session-local PATH shims and policy variables through
    /// `projection_env`. Those additions are applied only after every previous
    /// authority variable is removed, and cannot override the verified
    /// session/repo/daemon binding.
    pub(crate) fn configure_command<K, V, I>(
        &self,
        command: &mut Command,
        projection_env: I,
    ) -> Result<()>
    where
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
        I: IntoIterator<Item = (K, V)>,
    {
        let projection_env = projection_env.into_iter().collect::<Vec<_>>();
        for (key, _) in &projection_env {
            let key = key.as_ref().to_string_lossy();
            if SESSION_OWNED_ENV.iter().any(|owned| *owned == key) {
                anyhow::bail!("session projection attempted to override owned environment {key}");
            }
        }

        for key in AMBIENT_AUTHORITY_ENV {
            command.env_remove(key);
        }
        command
            .env("PATH", &self.repo.unshimmed_path)
            .env("KIN_SESSION", self.session_id.to_string())
            .env("KIN_SESSION_ID", self.session_id.to_string())
            .env("KIN_SESSION_DIR", &self.workspace_root)
            .env("KIN_DAEMON_URL", &self.repo.daemon_url)
            .env("KIN_REPO_ID", &self.repo.repo_id)
            .env("KIN_VFS_DISABLE", "1")
            .env("PWD", &self.workspace_root)
            .current_dir(&self.workspace_root);

        if let Some(token) = &self.repo.daemon_auth_token {
            command.env("KIN_DAEMON_AUTH_TOKEN", token);
        }
        command.envs(projection_env);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn environment(&self) -> Vec<(String, String)> {
        let mut env = vec![
            ("KIN_SESSION".into(), self.session_id.to_string()),
            ("KIN_SESSION_ID".into(), self.session_id.to_string()),
            (
                "KIN_SESSION_DIR".into(),
                self.workspace_root.to_string_lossy().into_owned(),
            ),
            ("KIN_DAEMON_URL".into(), self.repo.daemon_url.clone()),
            ("KIN_REPO_ID".into(), self.repo.repo_id.clone()),
            ("KIN_VFS_DISABLE".into(), "1".into()),
        ];
        if let Some(token) = &self.repo.daemon_auth_token {
            env.push(("KIN_DAEMON_AUTH_TOKEN".into(), token.clone()));
        }
        env
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_environment_is_complete() {
        let root = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(root.path().join(".kin"));
        let repo = VerifiedRepoBinding::for_test(
            layout,
            "http://127.0.0.1:4242",
            "repo-b",
            Some("repo-b-token".into()),
            "/usr/local/bin:/usr/bin",
        );
        let session_id = uuid::Uuid::new_v4();
        let binding = SessionProcessBinding::new(&repo, session_id, root.path());
        let env = binding.environment();

        for (key, expected) in [
            ("KIN_SESSION", session_id.to_string()),
            ("KIN_SESSION_ID", session_id.to_string()),
            (
                "KIN_SESSION_DIR",
                root.path().to_string_lossy().into_owned(),
            ),
            ("KIN_DAEMON_URL", "http://127.0.0.1:4242".into()),
            ("KIN_REPO_ID", "repo-b".into()),
            ("KIN_DAEMON_AUTH_TOKEN", "repo-b-token".into()),
            ("KIN_VFS_DISABLE", "1".into()),
        ] {
            assert_eq!(
                env.iter()
                    .find(|(name, _)| name == key)
                    .map(|(_, value)| value),
                Some(&expected),
                "missing or incorrect {key}"
            );
        }
    }

    #[test]
    fn projection_cannot_override_verified_authority() {
        let root = tempfile::tempdir().unwrap();
        let repo = VerifiedRepoBinding::for_test(
            kin_core::KinLayout::new(root.path().join(".kin")),
            "http://127.0.0.1:4242",
            "repo-b",
            None,
            "/usr/bin",
        );
        let binding = SessionProcessBinding::new(&repo, uuid::Uuid::new_v4(), root.path());
        let mut command = Command::new("true");
        let error = binding
            .configure_command(&mut command, [("KIN_REPO_ID", "repo-a")])
            .unwrap_err();
        assert!(error.to_string().contains("KIN_REPO_ID"));
    }

    #[test]
    fn child_drops_git_and_compose_authority_and_sets_pwd() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("session");
        std::fs::create_dir_all(&workspace).unwrap();
        let repo = VerifiedRepoBinding::for_test(
            kin_core::KinLayout::new(root.path().join(".kin")),
            "http://127.0.0.1:4242",
            "repo-b",
            None,
            "/usr/bin",
        );
        let binding = SessionProcessBinding::new(&repo, uuid::Uuid::new_v4(), &workspace);
        let mut command = Command::new("true");
        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "COMPOSE_FILE",
            "COMPOSE_ENV_FILES",
            "INIT_CWD",
            "MAKEFLAGS",
            "KIN_WORKSPACE_ROOT",
            "KIN_WORKSPACE_DIR",
            "KIN_DISCOVERY_MODE",
            "KIN_CONTENT_MODE",
            "OLDPWD",
        ] {
            command.env(key, "/wrong/repository");
        }

        binding
            .configure_command(&mut command, std::iter::empty::<(&str, &str)>())
            .unwrap();

        for key in [
            "GIT_DIR",
            "GIT_WORK_TREE",
            "GIT_INDEX_FILE",
            "COMPOSE_FILE",
            "COMPOSE_ENV_FILES",
            "INIT_CWD",
            "MAKEFLAGS",
            "KIN_WORKSPACE_ROOT",
            "KIN_WORKSPACE_DIR",
            "KIN_DISCOVERY_MODE",
            "KIN_CONTENT_MODE",
            "OLDPWD",
        ] {
            assert_eq!(
                command
                    .get_envs()
                    .find(|(name, _)| *name == OsStr::new(key))
                    .map(|(_, value)| value),
                Some(None),
                "{key} crossed the session boundary"
            );
        }
        assert_eq!(
            command
                .get_envs()
                .find(|(name, _)| *name == OsStr::new("PWD"))
                .and_then(|(_, value)| value),
            Some(workspace.as_os_str())
        );
    }

    #[test]
    fn persistent_context_contains_authority_but_no_bearer_token() {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("session");
        std::fs::create_dir_all(&workspace).unwrap();
        let repo = VerifiedRepoBinding::for_test(
            kin_core::KinLayout::new(root.path().join(".kin")),
            "http://127.0.0.1:4242",
            "repo-b",
            Some("secret-token".into()),
            "/usr/bin",
        );
        let session_id = uuid::Uuid::new_v4();
        let binding = SessionProcessBinding::new(&repo, session_id, &workspace);
        binding.persist_context().unwrap();

        let context = std::fs::read_to_string(workspace.join(SESSION_CONTEXT_FILE)).unwrap();
        assert!(context.contains(&session_id.to_string()));
        assert!(context.contains("\"repo_id\": \"repo-b\""));
        assert!(context.contains("http://127.0.0.1:4242"));
        assert!(!context.contains("secret-token"));
        assert!(
            binding.persist_context().is_err(),
            "session context must be created once and never overwrite an existing path"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(workspace.join(SESSION_CONTEXT_FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn endpoint_health_requires_both_repo_root_and_repo_id() {
        let root = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(root.path().join(".kin"));
        let root_string = root.path().canonicalize().unwrap();

        let health = |repo_root: Option<&Path>, repo_id: Option<&str>| {
            serde_json::from_value::<crate::daemon_client::HealthResponse>(serde_json::json!({
                "status": "ok",
                "version": "test",
                "uptime_seconds": 1,
                "graph_entity_count": 0,
                "graph_loaded": true,
                "reconciliation_status": "idle",
                "repo_id": repo_id,
                "repo_root": repo_root.map(|path| path.to_string_lossy().into_owned())
            }))
            .unwrap()
        };

        validate_endpoint_health(
            &layout,
            "repo-b",
            &health(Some(&root_string), Some("repo-b")),
        )
        .unwrap();
        assert!(
            validate_endpoint_health(&layout, "repo-b", &health(None, Some("repo-b")))
                .unwrap_err()
                .to_string()
                .contains("omitted repo root")
        );
        assert!(
            validate_endpoint_health(&layout, "repo-b", &health(Some(&root_string), None))
                .unwrap_err()
                .to_string()
                .contains("omitted repo identity")
        );
    }
}
